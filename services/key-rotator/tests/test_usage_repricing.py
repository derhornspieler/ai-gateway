from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal

import pytest

from app.governance_store import _backdate_usage_query
from app.pricing import (
    CostAdjustment,
    PriceVersion,
    UsageClass,
    canonical_price_digest,
)
from app.usage_repricing import (
    adjustment_from_row,
    apply_adjustment_history,
    booked_cost_from_row,
    preview_row_sha256,
)


NOW = datetime(2026, 7, 22, 12, 0, tzinfo=timezone.utc)


def test_backdate_query_accepts_only_closed_enum_and_clause_inputs() -> None:
    without_upper = _backdate_usage_query(
        UsageClass.NORMAL_INPUT,
        has_effective_to=False,
    ).as_string(None)
    with_upper = _backdate_usage_query(
        UsageClass.CACHE_READ,
        has_effective_to=True,
    ).as_string(None)

    assert 'AND "normal_input_tokens" > 0' in without_upper
    assert "AND occurred_at < %s" not in without_upper
    assert 'AND "cache_read_tokens" > 0' in with_upper
    assert "AND occurred_at < %s" in with_upper
    assert "LIMIT %s" in with_upper
    for value in (
        "normal_input_tokens; DROP TABLE aigw_governance.usage_events",
        UsageClass.NORMAL_INPUT.value,
        object(),
    ):
        with pytest.raises(TypeError, match="reviewed types"):
            _backdate_usage_query(value, has_effective_to=True)
    with pytest.raises(TypeError, match="reviewed types"):
        _backdate_usage_query(UsageClass.OUTPUT, has_effective_to="true")


def price(usage_class: UsageClass, version_id: str, amount: str) -> PriceVersion:
    return PriceVersion(
        version_id=version_id,
        provider="anthropic",
        model="claude-test",
        usage_class=usage_class,
        token_unit=1,
        amount=Decimal(amount),
        effective_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


def usage_row(**overrides):
    document = {
        "event_id": "a" * 64,
        "provider_name": "anthropic",
        "requested_model": "claude-test",
        "occurred_at": NOW,
        "usage_completeness": "complete",
        "normal_input_tokens": 2,
        "cache_creation_5m_tokens": 0,
        "cache_creation_1h_tokens": 0,
        "cache_read_tokens": 0,
        "output_tokens": 3,
        "normal_input_configured_cost_usd": Decimal("2"),
        "cache_creation_5m_configured_cost_usd": Decimal("0"),
        "cache_creation_1h_configured_cost_usd": Decimal("0"),
        "cache_read_configured_cost_usd": Decimal("0"),
        "output_configured_cost_usd": Decimal("6"),
        "normal_input_price_version_id": "input-v1",
        "cache_creation_5m_price_version_id": None,
        "cache_creation_1h_price_version_id": None,
        "cache_read_price_version_id": None,
        "output_price_version_id": "output-v1",
        "configured_total_cost_usd": Decimal("8"),
    }
    document.update(overrides)
    return document


def adjustment(
    *,
    adjustment_id: str,
    usage_class: UsageClass,
    supersedes: str | None,
    previous_price: str | None,
    new_price: PriceVersion,
    previous_cost: str | None,
    new_cost: str,
) -> CostAdjustment:
    old = None if previous_cost is None else Decimal(previous_cost)
    new = Decimal(new_cost)
    return CostAdjustment(
        adjustment_id=adjustment_id,
        preview_id="123e4567-e89b-42d3-a456-426614174001",
        confirmation_operation_id="123e4567-e89b-42d3-a456-426614174002",
        usage_id="a" * 64,
        usage_class=usage_class,
        units=2 if usage_class is UsageClass.NORMAL_INPUT else 3,
        supersedes_adjustment_id=supersedes,
        previous_price_version_id=previous_price,
        new_price_version_id=new_price.version_id,
        previous_cost=old,
        new_cost=new,
        delta=None if old is None else new - old,
        new_price_digest=canonical_price_digest((new_price,)),
    )


def test_booked_row_keeps_five_components_and_exact_provenance() -> None:
    prices = {
        "input-v1": price(UsageClass.NORMAL_INPUT, "input-v1", "1"),
        "output-v1": price(UsageClass.OUTPUT, "output-v1", "2"),
    }

    booked = booked_cost_from_row(usage_row(), prices)

    assert booked.total == Decimal("8")
    assert booked.unknown_classes == ()
    assert booked.components[0].price_digest == canonical_price_digest(
        (prices["input-v1"],)
    )
    assert booked.components[-1].price_version_id == "output-v1"


def test_booked_row_preserves_unknown_instead_of_zero() -> None:
    row = usage_row(
        normal_input_configured_cost_usd=None,
        normal_input_price_version_id=None,
        configured_total_cost_usd=None,
    )
    prices = {
        "output-v1": price(UsageClass.OUTPUT, "output-v1", "2"),
    }

    booked = booked_cost_from_row(row, prices)

    assert booked.total is None
    assert booked.components[0].cost is None
    assert booked.unknown_classes == (UsageClass.NORMAL_INPUT,)


def test_adjustment_row_rechecks_the_governed_price_digest() -> None:
    new_price = price(UsageClass.NORMAL_INPUT, "input-v2", "3")
    row = {
        "adjustment_id": "b" * 64,
        "preview_id": "123e4567-e89b-42d3-a456-426614174001",
        "confirmation_operation_id": "123e4567-e89b-42d3-a456-426614174002",
        "usage_event_id": "a" * 64,
        "usage_class": "normal_input",
        "units": 2,
        "supersedes_adjustment_id": None,
        "previous_price_version_id": "input-v1",
        "new_price_version_id": "input-v2",
        "previous_cost_usd": Decimal("2"),
        "new_cost_usd": Decimal("6"),
        "delta_usd": Decimal("4"),
        "new_price_sha256": canonical_price_digest((new_price,)),
    }

    result = adjustment_from_row(row, {"input-v2": new_price})

    assert result.new_cost == Decimal("6")
    row["new_price_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="digest"):
        adjustment_from_row(row, {"input-v2": new_price})


def test_adjustment_history_is_order_independent_but_rejects_a_branch() -> None:
    prices = {
        "input-v1": price(UsageClass.NORMAL_INPUT, "input-v1", "1"),
        "output-v1": price(UsageClass.OUTPUT, "output-v1", "2"),
    }
    booked = booked_cost_from_row(usage_row(), prices)
    input_v2 = price(UsageClass.NORMAL_INPUT, "input-v2", "3")
    input_v3 = price(UsageClass.NORMAL_INPUT, "input-v3", "4")
    output_v2 = price(UsageClass.OUTPUT, "output-v2", "5")
    first = adjustment(
        adjustment_id="b" * 64,
        usage_class=UsageClass.NORMAL_INPUT,
        supersedes=None,
        previous_price="input-v1",
        new_price=input_v2,
        previous_cost="2",
        new_cost="6",
    )
    second = adjustment(
        adjustment_id="c" * 64,
        usage_class=UsageClass.NORMAL_INPUT,
        supersedes=first.adjustment_id,
        previous_price="input-v2",
        new_price=input_v3,
        previous_cost="6",
        new_cost="8",
    )
    other_class = adjustment(
        adjustment_id="d" * 64,
        usage_class=UsageClass.OUTPUT,
        supersedes=None,
        previous_price="output-v1",
        new_price=output_v2,
        previous_cost="6",
        new_cost="15",
    )

    current = apply_adjustment_history(booked, (second, other_class, first))

    assert current.total == Decimal("23")
    branch = adjustment(
        adjustment_id="e" * 64,
        usage_class=UsageClass.NORMAL_INPUT,
        supersedes=None,
        previous_price="input-v1",
        new_price=input_v3,
        previous_cost="2",
        new_cost="8",
    )
    with pytest.raises(ValueError, match="branched"):
        apply_adjustment_history(booked, (first, branch))


def test_preview_row_digest_binds_every_displayed_cost() -> None:
    values = {
        "preview_id": "123e4567-e89b-42d3-a456-426614174001",
        "usage_event_id": "a" * 64,
        "usage_class": UsageClass.NORMAL_INPUT,
        "units": 2,
        "supersedes_adjustment_id": None,
        "previous_price_version_id": "input-v1",
        "new_price_version_id": "input-v2",
        "previous_component_cost": Decimal("2"),
        "new_component_cost": Decimal("6"),
        "previous_total_cost": Decimal("8"),
        "new_total_cost": Decimal("12"),
    }

    digest = preview_row_sha256(**values)
    changed = preview_row_sha256(
        **{**values, "new_total_cost": Decimal("12.01")}
    )

    assert len(digest) == 64
    assert changed != digest
