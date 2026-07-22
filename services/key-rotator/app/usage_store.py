"""Append-only PostgreSQL store for model usage and configured cost.

The caller supplies a database transaction provider. Price selection and the
usage insert happen inside that one transaction. This keeps the persistence
rules out of the service entry point and out of the general-purpose database
module.
"""

from __future__ import annotations

from contextlib import AbstractAsyncContextManager
from datetime import timezone
from decimal import Decimal
from typing import Any, Protocol

from app.pricing import PriceVersion, UsageClass
from app.usage import (
    UsageConflict,
    UsageEvent,
    UsageStoreUnavailable,
    UsageWriteResult,
    canonical_event_sha256,
    configured_cost_for_event,
)


SELECT_EVENT = """
SELECT document_sha256
FROM aigw_governance.usage_events
WHERE event_id = %s
"""

SELECT_EFFECTIVE_PRICES = """
SELECT DISTINCT ON (price.usage_class)
       price.version_id,
       price.provider_name,
       price.gateway_model_name,
       price.usage_class,
       price.token_unit,
       price.amount,
       price.currency,
       price.explicit_free,
       price.effective_at
FROM aigw_governance.governed_price_versions AS price
JOIN aigw_governance.governed_model_versions AS model
  ON model.operation_id = price.model_operation_id
WHERE price.provider_name = %s
  AND price.gateway_model_name = %s
  AND price.egress_policy_sha256 = %s
  AND model.egress_policy_sha256 = %s
  AND price.effective_at <= %s
ORDER BY price.usage_class, price.effective_at DESC, price.version_id DESC
"""

INSERT_EVENT = """
INSERT INTO aigw_governance.usage_events (
    event_id,
    document_sha256,
    request_id,
    request_id_source,
    provider_response_id,
    trace_id,
    provider_name,
    requested_model,
    actual_model,
    stable_user_id,
    project_id,
    status,
    stream,
    retry_count,
    occurred_at,
    egress_policy_sha256,
    normal_input_tokens,
    cache_creation_5m_tokens,
    cache_creation_1h_tokens,
    cache_read_tokens,
    output_tokens,
    usage_completeness,
    litellm_cost_usd,
    provider_cost_usd,
    normal_input_configured_cost_usd,
    cache_creation_5m_configured_cost_usd,
    cache_creation_1h_configured_cost_usd,
    cache_read_configured_cost_usd,
    output_configured_cost_usd,
    normal_input_price_version_id,
    cache_creation_5m_price_version_id,
    cache_creation_1h_price_version_id,
    cache_read_price_version_id,
    output_price_version_id,
    configured_total_cost_usd,
    configured_cost_status,
    source_version
)
VALUES (
    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
    %s, %s, %s, %s, %s, %s, %s
)
ON CONFLICT (event_id) DO NOTHING
RETURNING event_id
"""


class TransactionProvider(Protocol):
    """One locked database transaction yielding a dict-row cursor."""

    def transaction_cursor(self) -> AbstractAsyncContextManager[Any]: ...


def _price_from_row(row: dict[str, Any]) -> PriceVersion:
    effective_at = row["effective_at"]
    if effective_at.tzinfo is None:
        raise UsageStoreUnavailable("price time is not timezone-aware")
    return PriceVersion(
        version_id=row["version_id"],
        provider=row["provider_name"],
        model=row["gateway_model_name"],
        usage_class=UsageClass(row["usage_class"]),
        token_unit=row["token_unit"],
        amount=Decimal(row["amount"]),
        effective_at=effective_at.astimezone(timezone.utc),
        currency=row["currency"],
        explicit_free=row["explicit_free"],
    )


def _configured_columns(event: UsageEvent, prices: tuple[PriceVersion, ...]) -> tuple:
    booked = configured_cost_for_event(event, prices)
    if booked is None:
        return (*([None] * 11), "unknown")

    components = {item.usage_class: item for item in booked.components}
    ordered = tuple(components[usage_class] for usage_class in UsageClass)
    costs = tuple(item.cost for item in ordered)
    price_ids = tuple(item.price_version_id for item in ordered)
    status = "complete" if booked.total is not None else "unknown"
    return (*costs, *price_ids, booked.total, status)


def _insert_values(
    event: UsageEvent,
    document_sha256: str,
    configured: tuple,
    egress_policy_sha256: str | None,
) -> tuple:
    return (
        event.event_id,
        document_sha256,
        event.request_id,
        event.request_id_source,
        event.provider_response_id,
        event.trace_id,
        event.provider,
        event.requested_model,
        event.actual_model,
        event.stable_user_id,
        event.project_id,
        event.status,
        event.stream,
        event.retry_count,
        event.occurred_at,
        egress_policy_sha256,
        event.normal_input_tokens,
        event.cache_creation_5m_tokens,
        event.cache_creation_1h_tokens,
        event.cache_read_tokens,
        event.output_tokens,
        event.usage_completeness,
        Decimal(event.litellm_cost_usd) if event.litellm_cost_usd else None,
        Decimal(event.provider_cost_usd) if event.provider_cost_usd else None,
        *configured,
        event.source_version,
    )


class PostgresUsageStore:
    """Record terminal events against one trusted provider-policy digest."""

    def __init__(
        self,
        database: TransactionProvider,
        *,
        egress_policy_sha256: str | None,
    ) -> None:
        self._database = database
        self._egress_policy_sha256 = egress_policy_sha256

    async def record_usage(self, event: UsageEvent) -> UsageWriteResult:
        digest = canonical_event_sha256(event)
        try:
            async with self._database.transaction_cursor() as cursor:
                await cursor.execute(SELECT_EVENT, (event.event_id,))
                old = await cursor.fetchone()
                if old is not None:
                    if old["document_sha256"] != digest:
                        raise UsageConflict("event ID was reused")
                    return UsageWriteResult(event_id=event.event_id, created=False)

                prices: tuple[PriceVersion, ...] = ()
                if (
                    self._egress_policy_sha256 is not None
                    and event.requested_model is not None
                    and event.usage_completeness == "complete"
                ):
                    await cursor.execute(
                        SELECT_EFFECTIVE_PRICES,
                        (
                            event.provider,
                            event.requested_model,
                            self._egress_policy_sha256,
                            self._egress_policy_sha256,
                            event.occurred_at,
                        ),
                    )
                    prices = tuple(
                        _price_from_row(dict(row)) for row in await cursor.fetchall()
                    )

                configured = _configured_columns(event, prices)
                await cursor.execute(
                    INSERT_EVENT,
                    _insert_values(
                        event,
                        digest,
                        configured,
                        self._egress_policy_sha256,
                    ),
                )
                inserted = await cursor.fetchone()
                if inserted is not None:
                    return UsageWriteResult(event_id=event.event_id, created=True)

                # Another service instance may have won the same event-ID
                # race. The append-only row can be accepted only as an exact
                # replay of this validated document.
                await cursor.execute(SELECT_EVENT, (event.event_id,))
                raced = await cursor.fetchone()
                if raced is not None and raced["document_sha256"] == digest:
                    return UsageWriteResult(event_id=event.event_id, created=False)
                raise UsageConflict("event ID was reused")
        except UsageConflict:
            raise
        except UsageStoreUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001
            raise UsageStoreUnavailable("usage transaction failed") from exc
