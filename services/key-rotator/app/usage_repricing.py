"""Build current usage-cost rows from immutable database evidence.

This module has no database or HTTP code. It converts reviewed rows to the
pure pricing objects used by preview and confirmation.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from datetime import timezone
from decimal import Decimal
from typing import Any

from app.pricing import (
    ConfiguredCost,
    CostAdjustment,
    CostComponent,
    PriceVersion,
    UsageBreakdown,
    UsageClass,
    apply_confirmed_adjustments,
    canonical_price_digest,
)


TOKEN_COLUMNS = {
    UsageClass.NORMAL_INPUT: "normal_input_tokens",
    UsageClass.CACHE_CREATION_5M: "cache_creation_5m_tokens",
    UsageClass.CACHE_CREATION_1H: "cache_creation_1h_tokens",
    UsageClass.CACHE_READ: "cache_read_tokens",
    UsageClass.OUTPUT: "output_tokens",
}
COST_COLUMNS = {
    usage_class: f"{usage_class.value}_configured_cost_usd"
    for usage_class in UsageClass
}
PRICE_COLUMNS = {
    usage_class: f"{usage_class.value}_price_version_id"
    for usage_class in UsageClass
}


def price_from_row(row: Mapping[str, Any]) -> PriceVersion:
    """Validate one governed price returned by PostgreSQL."""

    effective_at = row["effective_at"]
    if effective_at.tzinfo is None:
        raise ValueError("governed price time must include UTC")
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


def booked_cost_from_row(
    row: Mapping[str, Any],
    prices_by_id: Mapping[str, PriceVersion],
) -> ConfiguredCost:
    """Rebuild the immutable booked value for one complete usage event."""

    if row["usage_completeness"] != "complete":
        raise ValueError("only complete usage can be repriced")
    if row["requested_model"] is None:
        raise ValueError("repriced usage needs a requested model")

    counts = {usage_class: row[column] for usage_class, column in TOKEN_COLUMNS.items()}
    usage = UsageBreakdown(
        normal_input=counts[UsageClass.NORMAL_INPUT],
        cache_creation_5m=counts[UsageClass.CACHE_CREATION_5M],
        cache_creation_1h=counts[UsageClass.CACHE_CREATION_1H],
        cache_read=counts[UsageClass.CACHE_READ],
        output=counts[UsageClass.OUTPUT],
    )
    components: list[CostComponent] = []
    unknown: list[UsageClass] = []
    for usage_class in UsageClass:
        cost_value = row[COST_COLUMNS[usage_class]]
        price_id = row[PRICE_COLUMNS[usage_class]]
        cost = None if cost_value is None else Decimal(cost_value)
        if price_id is None:
            price_digest = None
        else:
            price = prices_by_id.get(price_id)
            if price is None:
                raise ValueError("usage references a missing governed price")
            price_digest = canonical_price_digest((price,))
        if cost is None:
            unknown.append(usage_class)
        components.append(
            CostComponent(
                usage_class=usage_class,
                units=counts[usage_class],
                cost=cost,
                price_version_id=price_id,
                price_digest=price_digest,
            )
        )

    total_value = row["configured_total_cost_usd"]
    total = None if total_value is None else Decimal(total_value)
    if (unknown and total is not None) or (not unknown and total is None):
        raise ValueError("booked configured-cost status is inconsistent")
    occurred_at = row["occurred_at"]
    if occurred_at.tzinfo is None:
        raise ValueError("usage time must include UTC")
    return ConfiguredCost(
        usage_id=row["event_id"],
        provider=row["provider_name"],
        model=row["requested_model"],
        occurred_at=occurred_at.astimezone(timezone.utc),
        usage=usage,
        components=tuple(components),
        total=total,
        unknown_classes=tuple(unknown),
    )


def adjustment_from_row(
    row: Mapping[str, Any],
    prices_by_id: Mapping[str, PriceVersion],
) -> CostAdjustment:
    """Validate one immutable adjustment and its price digest."""

    new_price = prices_by_id.get(row["new_price_version_id"])
    if new_price is None:
        raise ValueError("adjustment references a missing governed price")
    expected_price_digest = canonical_price_digest((new_price,))
    if row["new_price_sha256"] != expected_price_digest:
        raise ValueError("adjustment price digest does not match")
    return CostAdjustment(
        adjustment_id=row["adjustment_id"],
        preview_id=str(row["preview_id"]),
        confirmation_operation_id=str(row["confirmation_operation_id"]),
        usage_id=row["usage_event_id"],
        usage_class=UsageClass(row["usage_class"]),
        units=row["units"],
        supersedes_adjustment_id=row["supersedes_adjustment_id"],
        previous_price_version_id=row["previous_price_version_id"],
        new_price_version_id=row["new_price_version_id"],
        previous_cost=(
            None
            if row["previous_cost_usd"] is None
            else Decimal(row["previous_cost_usd"])
        ),
        new_cost=Decimal(row["new_cost_usd"]),
        delta=(None if row["delta_usd"] is None else Decimal(row["delta_usd"])),
        new_price_digest=row["new_price_sha256"],
    )


def apply_adjustment_history(
    booked: ConfiguredCost,
    adjustments: Iterable[CostAdjustment],
) -> ConfiguredCost:
    """Apply every chain link without trusting database row order."""

    remaining = list(adjustments)
    current = booked
    while remaining:
        current_ids = {
            component.usage_class: component.adjustment_id
            for component in current.components
        }
        ready = [
            adjustment
            for adjustment in remaining
            if adjustment.usage_id == booked.usage_id
            and current_ids[adjustment.usage_class]
            == adjustment.supersedes_adjustment_id
        ]
        if not ready:
            raise ValueError("adjustment history is branched or incomplete")
        ready_keys = {
            (item.usage_class, item.supersedes_adjustment_id) for item in ready
        }
        if len(ready_keys) != len(ready):
            raise ValueError("adjustment history is branched or incomplete")
        selected = min(
            ready,
            key=lambda item: (item.usage_class.value, item.adjustment_id),
        )
        current = apply_confirmed_adjustments(current, (selected,))
        remaining.remove(selected)
    return current


def preview_row_sha256(
    *,
    preview_id: str,
    usage_event_id: str,
    usage_class: UsageClass,
    units: int,
    supersedes_adjustment_id: str | None,
    previous_price_version_id: str | None,
    new_price_version_id: str,
    previous_component_cost: Decimal | None,
    new_component_cost: Decimal,
    previous_total_cost: Decimal | None,
    new_total_cost: Decimal | None,
) -> str:
    """Hash one exact preview row before it is stored."""

    def decimal_text(value: Decimal | None) -> str | None:
        if value is None:
            return None
        text = format(value, "f")
        if "." in text:
            text = text.rstrip("0").rstrip(".")
        return text or "0"

    document = {
        "new_component_cost": decimal_text(new_component_cost),
        "new_price_version_id": new_price_version_id,
        "new_total_cost": decimal_text(new_total_cost),
        "preview_id": preview_id,
        "previous_component_cost": decimal_text(previous_component_cost),
        "previous_price_version_id": previous_price_version_id,
        "previous_total_cost": decimal_text(previous_total_cost),
        "supersedes_adjustment_id": supersedes_adjustment_id,
        "units": units,
        "usage_class": usage_class.value,
        "usage_event_id": usage_event_id,
    }
    encoded = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()
