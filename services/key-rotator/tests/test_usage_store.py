from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from decimal import Decimal

import pytest

from app.pricing import UsageClass
from app.usage import UsageConflict, UsageEvent, UsageStoreUnavailable
from app.usage_store import (
    INSERT_EVENT,
    SELECT_EFFECTIVE_PRICES,
    SELECT_EVENT,
    PostgresUsageStore,
)


NOW = datetime(2026, 7, 22, 12, 0, tzinfo=timezone.utc)
POLICY = "b" * 64


def event(**overrides) -> UsageEvent:
    document = {
        "schema_version": 1,
        "event_id": "a" * 64,
        "request_id": "call-123",
        "request_id_source": "litellm_call_id",
        "provider_response_id": "msg-123",
        "trace_id": "trace-123",
        "provider": "anthropic",
        "requested_model": "claude-sonnet-4-5",
        "actual_model": "claude-sonnet-4-5-20250929",
        "stable_user_id": "keycloak-subject-1",
        "project_id": "project-blue",
        "status": "success",
        "stream": False,
        "retry_count": 2,
        "occurred_at": NOW,
        "normal_input_tokens": 10,
        "cache_creation_5m_tokens": 20,
        "cache_creation_1h_tokens": 30,
        "cache_read_tokens": 40,
        "output_tokens": 50,
        "usage_completeness": "complete",
        "litellm_cost_usd": "0.00123",
        "provider_cost_usd": None,
        "source_version": "litellm-1.93.0",
    }
    document.update(overrides)
    return UsageEvent.model_validate(document)


def price_row(usage_class: UsageClass, amount: str, version_id: str) -> dict:
    return {
        "version_id": version_id,
        "provider_name": "anthropic",
        "gateway_model_name": "claude-sonnet-4-5",
        "usage_class": usage_class.value,
        "token_unit": 1_000_000,
        "amount": Decimal(amount),
        "currency": "USD",
        "explicit_free": False,
        "effective_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
    }


class Cursor:
    def __init__(self, *, old=None, prices=(), inserted=True, raced=None) -> None:
        self.old = old
        self.prices = list(prices)
        self.inserted = inserted
        self.raced = raced
        self.executions: list[tuple[str, tuple]] = []
        self._fetchone_count = 0

    async def execute(self, sql: str, values: tuple) -> None:
        self.executions.append((sql, values))

    async def fetchone(self):
        self._fetchone_count += 1
        if self._fetchone_count == 1:
            return self.old
        if self._fetchone_count == 2:
            return {"event_id": "a" * 64} if self.inserted else None
        return self.raced

    async def fetchall(self):
        return self.prices


class Database:
    def __init__(self, cursor: Cursor, *, fails=False) -> None:
        self.cursor = cursor
        self.fails = fails
        self.transactions = 0

    @asynccontextmanager
    async def transaction_cursor(self):
        self.transactions += 1
        if self.fails:
            raise RuntimeError("secret database detail")
        yield self.cursor


@pytest.mark.asyncio
async def test_price_selection_and_insert_share_one_transaction() -> None:
    prices = (
        price_row(UsageClass.NORMAL_INPUT, "3", "normal-v1"),
        price_row(UsageClass.CACHE_CREATION_5M, "3.75", "write-5m-v1"),
        price_row(UsageClass.CACHE_CREATION_1H, "6", "write-1h-v1"),
        price_row(UsageClass.CACHE_READ, "0.30", "read-v1"),
        price_row(UsageClass.OUTPUT, "15", "output-v1"),
    )
    cursor = Cursor(prices=prices)
    database = Database(cursor)
    store = PostgresUsageStore(database, egress_policy_sha256=POLICY)

    result = await store.record_usage(event())

    assert result.created is True
    assert database.transactions == 1
    assert [sql for sql, _ in cursor.executions] == [
        SELECT_EVENT,
        SELECT_EFFECTIVE_PRICES,
        INSERT_EVENT,
    ]
    price_values = cursor.executions[1][1]
    assert price_values == (
        "anthropic",
        "claude-sonnet-4-5",
        POLICY,
        POLICY,
        NOW,
    )
    insert = cursor.executions[2][1]
    assert insert[15] == POLICY
    assert insert[24:29] == (
        Decimal("0.00003"),
        Decimal("0.000075"),
        Decimal("0.00018"),
        Decimal("0.000012"),
        Decimal("0.00075"),
    )
    assert insert[29:34] == (
        "normal-v1",
        "write-5m-v1",
        "write-1h-v1",
        "read-v1",
        "output-v1",
    )
    assert insert[34:36] == (Decimal("0.001047"), "complete")


@pytest.mark.asyncio
async def test_missing_price_keeps_component_and_total_unknown() -> None:
    cursor = Cursor(prices=(price_row(UsageClass.OUTPUT, "15", "output-v1"),))
    store = PostgresUsageStore(Database(cursor), egress_policy_sha256=POLICY)

    await store.record_usage(event())

    insert = cursor.executions[-1][1]
    assert insert[15] == POLICY
    assert insert[24:28] == (None, None, None, None)
    assert insert[28] == Decimal("0.00075")
    assert insert[29:33] == (None, None, None, None)
    assert insert[33] == "output-v1"
    assert insert[34:36] == (None, "unknown")


@pytest.mark.asyncio
async def test_partial_usage_never_queries_or_invents_prices() -> None:
    partial = event(
        normal_input_tokens=None,
        usage_completeness="partial",
    )
    cursor = Cursor()
    store = PostgresUsageStore(Database(cursor), egress_policy_sha256=POLICY)

    await store.record_usage(partial)

    assert [sql for sql, _ in cursor.executions] == [SELECT_EVENT, INSERT_EVENT]
    insert = cursor.executions[-1][1]
    assert insert[15] == POLICY
    assert insert[24:36] == (*([None] * 11), "unknown")


@pytest.mark.asyncio
async def test_missing_policy_digest_records_usage_with_unknown_cost() -> None:
    cursor = Cursor()
    store = PostgresUsageStore(Database(cursor), egress_policy_sha256=None)

    await store.record_usage(event())

    assert [sql for sql, _ in cursor.executions] == [SELECT_EVENT, INSERT_EVENT]
    insert = cursor.executions[-1][1]
    assert insert[15] is None
    assert insert[34:36] == (None, "unknown")


@pytest.mark.asyncio
async def test_exact_replay_does_not_reprice_or_insert() -> None:
    candidate = event()
    from app.usage import canonical_event_sha256

    cursor = Cursor(old={"document_sha256": canonical_event_sha256(candidate)})
    store = PostgresUsageStore(Database(cursor), egress_policy_sha256=POLICY)

    result = await store.record_usage(candidate)

    assert result.created is False
    assert [sql for sql, _ in cursor.executions] == [SELECT_EVENT]


@pytest.mark.asyncio
async def test_changed_replay_fails_closed() -> None:
    cursor = Cursor(old={"document_sha256": "f" * 64})
    store = PostgresUsageStore(Database(cursor), egress_policy_sha256=POLICY)

    with pytest.raises(UsageConflict, match="reused"):
        await store.record_usage(event())


@pytest.mark.asyncio
async def test_insert_race_accepts_only_an_exact_replay() -> None:
    candidate = event()
    from app.usage import canonical_event_sha256

    digest = canonical_event_sha256(candidate)
    cursor = Cursor(inserted=False, raced={"document_sha256": digest})
    store = PostgresUsageStore(Database(cursor), egress_policy_sha256=POLICY)

    result = await store.record_usage(candidate)

    assert result.created is False
    assert [sql for sql, _ in cursor.executions][-1] == SELECT_EVENT


@pytest.mark.asyncio
async def test_database_details_are_wrapped() -> None:
    store = PostgresUsageStore(
        Database(Cursor(), fails=True), egress_policy_sha256=POLICY
    )

    with pytest.raises(UsageStoreUnavailable, match="transaction failed") as caught:
        await store.record_usage(event())
    assert "secret database detail" not in str(caught.value)


def test_sql_is_insert_only_and_policy_bound() -> None:
    combined = SELECT_EVENT + SELECT_EFFECTIVE_PRICES + INSERT_EVENT
    for mutation in (" UPDATE ", " DELETE ", " TRUNCATE "):
        assert mutation not in f" {combined.upper()} "
    assert "ON CONFLICT (event_id) DO NOTHING" in INSERT_EVENT
    assert SELECT_EFFECTIVE_PRICES.count("egress_policy_sha256 = %s") == 2
