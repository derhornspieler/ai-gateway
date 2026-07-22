from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from decimal import Decimal, ROUND_DOWN, ROUND_UP, localcontext

import pytest

from app.pricing import (
    MAX_PRICE_AMOUNT,
    MAX_TOKEN_COUNT,
    MAX_TOKEN_UNIT,
    ConfiguredCost,
    PriceVersion,
    UsageBreakdown,
    UsageClass,
    apply_confirmed_adjustments,
    book_configured_cost,
    canonical_adjustment_digest,
    canonical_price_digest,
    canonical_reprice_preview_digest,
    confirmed_adjustments,
    preview_reprice,
    select_effective_price,
)


UTC = timezone.utc
JANUARY = datetime(2026, 1, 1, tzinfo=UTC)


def price(
    usage_class: UsageClass,
    amount: str,
    *,
    version_id: str | None = None,
    effective_at: datetime = JANUARY,
    token_unit: int = 1_000_000,
    explicit_free: bool = False,
) -> PriceVersion:
    return PriceVersion(
        version_id=version_id or f"price-{usage_class.value}",
        provider="anthropic",
        model="claude-test",
        usage_class=usage_class,
        token_unit=token_unit,
        amount=Decimal(amount),
        effective_at=effective_at,
        explicit_free=explicit_free,
    )


def book(
    usage_id: str,
    usage: UsageBreakdown,
    prices: tuple[PriceVersion, ...],
    *,
    occurred_at: datetime = JANUARY,
) -> ConfiguredCost:
    return book_configured_cost(
        usage_id=usage_id,
        provider="anthropic",
        model="claude-test",
        occurred_at=occurred_at,
        usage=usage,
        prices=prices,
    )


def test_all_five_usage_classes_have_separate_exact_costs() -> None:
    prices = (
        price(UsageClass.NORMAL_INPUT, "3"),
        price(UsageClass.CACHE_CREATION_5M, "3.75"),
        price(UsageClass.CACHE_CREATION_1H, "6"),
        price(UsageClass.CACHE_READ, "0.30"),
        price(UsageClass.OUTPUT, "15"),
    )
    usage = UsageBreakdown(
        normal_input=1_000_000,
        cache_creation_5m=1_000_000,
        cache_creation_1h=1_000_000,
        cache_read=1_000_000,
        output=1_000_000,
    )

    result = book("usage-1", usage, prices)

    assert [component.usage_class for component in result.components] == list(
        UsageClass
    )
    assert [component.cost for component in result.components] == [
        Decimal("3"),
        Decimal("3.75"),
        Decimal("6"),
        Decimal("0.30"),
        Decimal("15"),
    ]
    assert result.total == Decimal("28.05")
    assert result.unknown_classes == ()


def test_decimal_math_is_not_changed_by_the_callers_context() -> None:
    rate = price(
        UsageClass.NORMAL_INPUT,
        "999999.999999999999",
        token_unit=1_000_000,
        version_id="context-rate",
    )

    results = []
    for rounding in (ROUND_DOWN, ROUND_UP):
        with localcontext() as context:
            context.prec = 4
            context.rounding = rounding
            results.append(
                book(
                    "usage-context",
                    UsageBreakdown(normal_input=123_456_789),
                    (rate,),
                )
            )

    assert results[0] == results[1]
    assert results[0].components[0].cost == Decimal("123456788.999999999876543211")


def test_nonterminating_unit_price_is_rejected_instead_of_rounded() -> None:
    with pytest.raises(ValueError, match="exact decimal"):
        price(
            UsageClass.NORMAL_INPUT,
            "1",
            token_unit=3,
            version_id="one-third",
        )


def test_missing_price_is_unknown_only_for_nonzero_usage() -> None:
    output_price = price(UsageClass.OUTPUT, "15")
    zero_missing = book(
        "usage-zero",
        UsageBreakdown(output=1_000_000),
        (output_price,),
    )

    assert zero_missing.total == Decimal("15")
    assert zero_missing.unknown_classes == ()
    assert zero_missing.components[0].cost == Decimal(0)
    assert zero_missing.components[0].price_version_id is None

    nonzero_missing = book(
        "usage-unknown",
        UsageBreakdown(normal_input=1, output=1_000_000),
        (output_price,),
    )

    assert nonzero_missing.total is None
    assert nonzero_missing.unknown_classes == (UsageClass.NORMAL_INPUT,)
    assert nonzero_missing.components[0].cost is None
    assert nonzero_missing.components[-1].cost == Decimal("15")


def test_zero_usage_does_not_consume_or_require_a_price_version() -> None:
    first = price(UsageClass.NORMAL_INPUT, "1", version_id="first")
    later = price(
        UsageClass.NORMAL_INPUT,
        "2",
        version_id="later",
        effective_at=JANUARY + timedelta(days=1),
    )

    result = book("usage-no-input", UsageBreakdown(output=0), (first, later))

    assert result.total == Decimal(0)
    assert result.unknown_classes == ()
    assert result.components[0].price_version_id is None
    assert result.components[0].price_digest is None


def test_explicit_free_price_is_known_zero_for_nonzero_usage() -> None:
    free = price(
        UsageClass.CACHE_READ,
        "0",
        explicit_free=True,
        version_id="cache-read-free",
    )

    result = book(
        "usage-free",
        UsageBreakdown(cache_read=123_456),
        (free,),
    )

    component = result.components[3]
    assert component.cost == Decimal(0)
    assert component.price_version_id == "cache-read-free"
    assert component.price_digest is not None
    assert result.total == Decimal(0)
    assert result.unknown_classes == ()


@pytest.mark.parametrize("token_unit", [0, MAX_TOKEN_UNIT + 1])
def test_price_rejects_token_units_outside_the_reviewed_bounds(token_unit: int) -> None:
    with pytest.raises(ValueError, match="token_unit"):
        price(UsageClass.NORMAL_INPUT, "1", token_unit=token_unit)


def test_price_rejects_boolean_token_unit() -> None:
    with pytest.raises(TypeError, match="token_unit"):
        price(UsageClass.NORMAL_INPUT, "1", token_unit=True)


@pytest.mark.parametrize(
    "amount",
    [
        Decimal("-0"),
        Decimal("-0.01"),
        MAX_PRICE_AMOUNT + Decimal("0.000000000001"),
        Decimal("NaN"),
        Decimal("Infinity"),
        Decimal("1.0000000000001"),
    ],
)
def test_price_rejects_amounts_outside_the_reviewed_bounds(amount: Decimal) -> None:
    with pytest.raises(ValueError, match="amount"):
        PriceVersion(
            version_id="bad-amount",
            provider="anthropic",
            model="claude-test",
            usage_class=UsageClass.NORMAL_INPUT,
            token_unit=1,
            amount=amount,
            effective_at=JANUARY,
            explicit_free=amount == 0,
        )


def test_price_requires_decimal_usd_and_unambiguous_free_flag() -> None:
    with pytest.raises(TypeError, match="Decimal"):
        PriceVersion(
            version_id="float-price",
            provider="anthropic",
            model="claude-test",
            usage_class=UsageClass.NORMAL_INPUT,
            token_unit=1,
            amount=1.5,  # type: ignore[arg-type]
            effective_at=JANUARY,
        )
    with pytest.raises(ValueError, match="currency"):
        PriceVersion(
            version_id="eur-price",
            provider="anthropic",
            model="claude-test",
            usage_class=UsageClass.NORMAL_INPUT,
            token_unit=1,
            amount=Decimal("1"),
            effective_at=JANUARY,
            currency="EUR",
        )
    with pytest.raises(ValueError, match="explicitly marked free"):
        price(UsageClass.NORMAL_INPUT, "0")
    with pytest.raises(ValueError, match="positive price"):
        price(UsageClass.NORMAL_INPUT, "1", explicit_free=True)


@pytest.mark.parametrize(
    "field_name,field_value",
    [
        ("normal_input", -1),
        ("cache_creation_5m", MAX_TOKEN_COUNT + 1),
        ("output", True),
    ],
)
def test_usage_counts_are_bounded_integers(
    field_name: str, field_value: object
) -> None:
    with pytest.raises((TypeError, ValueError), match=field_name):
        UsageBreakdown(**{field_name: field_value})  # type: ignore[arg-type]


def test_times_must_be_utc_aware() -> None:
    naive = datetime(2026, 1, 1)
    eastern = datetime(2026, 1, 1, tzinfo=timezone(timedelta(hours=-5)))

    with pytest.raises(ValueError, match="UTC-aware"):
        price(UsageClass.NORMAL_INPUT, "1", effective_at=naive)
    with pytest.raises(ValueError, match="UTC-aware"):
        price(UsageClass.NORMAL_INPUT, "1", effective_at=eastern)
    with pytest.raises(ValueError, match="UTC-aware"):
        book(
            "usage-naive",
            UsageBreakdown(),
            (),
            occurred_at=naive,
        )


def test_effective_price_uses_latest_version_at_or_before_usage() -> None:
    first = price(
        UsageClass.NORMAL_INPUT,
        "1",
        version_id="price-january",
        effective_at=JANUARY,
    )
    february = datetime(2026, 2, 1, tzinfo=UTC)
    second = price(
        UsageClass.NORMAL_INPUT,
        "2",
        version_id="price-february",
        effective_at=february,
    )

    assert (
        select_effective_price(
            (second, first),
            provider="anthropic",
            model="claude-test",
            usage_class=UsageClass.NORMAL_INPUT,
            occurred_at=february - timedelta(microseconds=1),
        )
        == first
    )
    assert (
        select_effective_price(
            (first, second),
            provider="anthropic",
            model="claude-test",
            usage_class=UsageClass.NORMAL_INPUT,
            occurred_at=february,
        )
        == second
    )
    assert (
        select_effective_price(
            (first, second),
            provider="anthropic",
            model="claude-test",
            usage_class=UsageClass.NORMAL_INPUT,
            occurred_at=JANUARY - timedelta(microseconds=1),
        )
        is None
    )


def test_duplicate_effective_time_fails_closed() -> None:
    first = price(UsageClass.NORMAL_INPUT, "1", version_id="first")
    second = price(UsageClass.NORMAL_INPUT, "2", version_id="second")
    later = price(
        UsageClass.NORMAL_INPUT,
        "3",
        version_id="later",
        effective_at=JANUARY + timedelta(days=1),
    )

    with pytest.raises(ValueError, match="multiple versions"):
        select_effective_price(
            (first, second, later),
            provider="anthropic",
            model="claude-test",
            usage_class=UsageClass.NORMAL_INPUT,
            occurred_at=JANUARY + timedelta(days=2),
        )


def test_duplicate_version_id_fails_for_the_whole_policy() -> None:
    first = price(UsageClass.NORMAL_INPUT, "1", version_id="same-id")
    second = price(UsageClass.OUTPUT, "2", version_id="same-id")

    with pytest.raises(ValueError, match="version_id"):
        canonical_price_digest((first, second))


def test_canonical_digest_is_order_independent_and_normalizes_decimals() -> None:
    input_price = price(
        UsageClass.NORMAL_INPUT,
        "1.000000000000",
        version_id="input-v1",
    )
    same_input_price = price(
        UsageClass.NORMAL_INPUT,
        "1.0",
        version_id="input-v1",
    )
    output_price = price(
        UsageClass.OUTPUT,
        "15.00",
        version_id="output-v1",
    )

    assert canonical_price_digest((input_price, output_price)) == (
        canonical_price_digest((output_price, same_input_price))
    )
    assert len(canonical_price_digest((input_price,))) == 64


def test_canonical_digest_changes_with_immutable_version_identity() -> None:
    first = price(UsageClass.NORMAL_INPUT, "1", version_id="version-1")
    second = price(UsageClass.NORMAL_INPUT, "1", version_id="version-2")

    assert canonical_price_digest((first,)) != canonical_price_digest((second,))


def test_booked_values_are_frozen() -> None:
    rate = price(UsageClass.NORMAL_INPUT, "1")
    result = book(
        "usage-frozen",
        UsageBreakdown(normal_input=1),
        (rate,),
    )

    with pytest.raises(FrozenInstanceError):
        rate.amount = Decimal("2")  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        result.total = Decimal("2")  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        result.components[0].cost = Decimal("2")  # type: ignore[misc]


def test_backdate_preview_is_pure_bounded_and_exact() -> None:
    old_price = price(
        UsageClass.NORMAL_INPUT,
        "1",
        token_unit=1,
        version_id="old-price",
        effective_at=datetime(2025, 12, 1, tzinfo=UTC),
    )
    inside_time = datetime(2026, 1, 10, tzinfo=UTC)
    outside_time = datetime(2025, 12, 20, tzinfo=UTC)
    inside = book(
        "usage-inside",
        UsageBreakdown(normal_input=2),
        (old_price,),
        occurred_at=inside_time,
    )
    outside = book(
        "usage-outside",
        UsageBreakdown(normal_input=3),
        (old_price,),
        occurred_at=outside_time,
    )
    original_snapshot = (inside, outside)
    backdated_price = price(
        UsageClass.NORMAL_INPUT,
        "2.5",
        token_unit=1,
        version_id="backdated-price",
        effective_at=JANUARY,
    )

    preview = preview_reprice(
        (outside, inside),
        (old_price,),
        candidate_price=backdated_price,
    )

    assert preview.affected_count == 1
    assert preview.changes[0].original is inside
    assert preview.changes[0].proposed.total == Decimal("5.0")
    assert preview.old_total == Decimal("2")
    assert preview.new_total == Decimal("5.0")
    assert preview.delta == Decimal("3.0")
    assert preview.old_unknown_count == 0
    assert preview.new_unknown_count == 0
    assert preview.candidate_version_id == "backdated-price"
    assert preview.effective_from == JANUARY
    assert preview.effective_to is None
    assert (inside, outside) == original_snapshot
    assert inside.total == Decimal("2")
    assert outside.total == Decimal("3")


def test_backdate_preview_reports_unknown_totals_without_calling_them_zero() -> None:
    original = book(
        "usage-unknown-preview",
        UsageBreakdown(normal_input=1),
        (),
    )
    known_price = price(
        UsageClass.NORMAL_INPUT,
        "2",
        token_unit=1,
        version_id="known-price",
    )

    preview = preview_reprice(
        (original,),
        (),
        candidate_price=known_price,
    )

    assert preview.affected_count == 1
    assert preview.old_total is None
    assert preview.new_total == Decimal("2")
    assert preview.delta is None
    assert preview.old_unknown_count == 1
    assert preview.new_unknown_count == 0


def test_confirmation_appends_deterministic_adjustment_without_mutation() -> None:
    old_price = price(
        UsageClass.NORMAL_INPUT,
        "1",
        token_unit=1,
        version_id="old-price",
        effective_at=JANUARY - timedelta(days=1),
    )
    original = book(
        "usage-adjusted",
        UsageBreakdown(normal_input=2),
        (old_price,),
    )
    candidate = price(
        UsageClass.NORMAL_INPUT,
        "2.5",
        token_unit=1,
        version_id="backdated-price",
    )
    preview = preview_reprice(
        (original,),
        (old_price,),
        candidate_price=candidate,
    )

    first = confirmed_adjustments(
        preview,
        candidate_price=candidate,
        preview_id="123e4567-e89b-42d3-a456-426614174000",
        confirmation_operation_id="123e4567-e89b-42d3-a456-426614174001",
    )
    same = confirmed_adjustments(
        preview,
        candidate_price=candidate,
        preview_id="123e4567-e89b-42d3-a456-426614174000",
        confirmation_operation_id="123e4567-e89b-42d3-a456-426614174001",
    )
    current = apply_confirmed_adjustments(original, first)

    assert first == same
    assert len(first) == 1
    assert first[0].previous_cost == Decimal("2")
    assert first[0].new_cost == Decimal("5.0")
    assert first[0].delta == Decimal("3.0")
    assert current.total == Decimal("5.0")
    assert current.components[0].adjustment_id == first[0].adjustment_id
    assert original.total == Decimal("2")
    assert original.components[0].adjustment_id is None


def test_preview_digest_binds_policy_adjustments_candidate_and_rows() -> None:
    old_price = price(
        UsageClass.CACHE_READ,
        "1",
        token_unit=1,
        version_id="old-cache-read",
        effective_at=JANUARY - timedelta(days=1),
    )
    original = book(
        "usage-preview-digest",
        UsageBreakdown(cache_read=3),
        (old_price,),
    )
    candidate = price(
        UsageClass.CACHE_READ,
        "2",
        token_unit=1,
        version_id="new-cache-read",
    )
    preview = preview_reprice(
        (original,),
        (old_price,),
        candidate_price=candidate,
    )

    first = canonical_reprice_preview_digest(
        preview,
        candidate_price=candidate,
        baseline_price_policy_sha256="a" * 64,
        baseline_adjustments_sha256="b" * 64,
    )
    same = canonical_reprice_preview_digest(
        preview,
        candidate_price=candidate,
        baseline_price_policy_sha256="a" * 64,
        baseline_adjustments_sha256="b" * 64,
    )
    changed_head = canonical_reprice_preview_digest(
        preview,
        candidate_price=candidate,
        baseline_price_policy_sha256="a" * 64,
        baseline_adjustments_sha256="c" * 64,
    )

    assert first == same
    assert len(first) == 64
    assert changed_head != first


def test_unknown_old_cost_stays_unknown_in_adjustment_delta() -> None:
    original = book(
        "usage-unknown-adjustment",
        UsageBreakdown(normal_input=2),
        (),
    )
    candidate = price(
        UsageClass.NORMAL_INPUT,
        "2.5",
        token_unit=1,
        version_id="backdated-known-price",
    )
    preview = preview_reprice(
        (original,),
        (),
        candidate_price=candidate,
    )

    adjustments = confirmed_adjustments(
        preview,
        candidate_price=candidate,
        preview_id="123e4567-e89b-42d3-a456-426614174002",
        confirmation_operation_id="123e4567-e89b-42d3-a456-426614174003",
    )
    current = apply_confirmed_adjustments(original, adjustments)

    assert adjustments[0].previous_cost is None
    assert adjustments[0].new_cost == Decimal("5.0")
    assert adjustments[0].delta is None
    assert current.total == Decimal("5.0")


def test_adjustment_chain_fails_closed_when_order_or_old_value_drifts() -> None:
    old_price = price(
        UsageClass.OUTPUT,
        "1",
        token_unit=1,
        version_id="old-output",
        effective_at=JANUARY - timedelta(days=1),
    )
    original = book(
        "usage-chain",
        UsageBreakdown(output=1),
        (old_price,),
    )
    candidate = price(
        UsageClass.OUTPUT,
        "2",
        token_unit=1,
        version_id="new-output",
    )
    preview = preview_reprice(
        (original,),
        (old_price,),
        candidate_price=candidate,
    )
    adjustments = confirmed_adjustments(
        preview,
        candidate_price=candidate,
        preview_id="123e4567-e89b-42d3-a456-426614174004",
        confirmation_operation_id="123e4567-e89b-42d3-a456-426614174005",
    )

    with pytest.raises(ValueError, match="repeats"):
        apply_confirmed_adjustments(original, (*adjustments, *adjustments))
    current = apply_confirmed_adjustments(original, adjustments)
    with pytest.raises(ValueError, match="chain"):
        apply_confirmed_adjustments(current, adjustments)


def test_adjustment_history_digest_is_order_independent_and_exact() -> None:
    old_price = price(
        UsageClass.OUTPUT,
        "1",
        token_unit=1,
        version_id="digest-old-output",
        effective_at=JANUARY - timedelta(days=1),
    )
    original = book(
        "usage-adjustment-digest",
        UsageBreakdown(output=1),
        (old_price,),
    )
    candidate = price(
        UsageClass.OUTPUT,
        "2",
        token_unit=1,
        version_id="digest-new-output",
    )
    preview = preview_reprice(
        (original,),
        (old_price,),
        candidate_price=candidate,
    )
    adjustments = confirmed_adjustments(
        preview,
        candidate_price=candidate,
        preview_id="123e4567-e89b-42d3-a456-42661417400a",
        confirmation_operation_id="123e4567-e89b-42d3-a456-42661417400b",
    )

    first = canonical_adjustment_digest(adjustments)
    same = canonical_adjustment_digest(tuple(reversed(adjustments)))

    assert len(first) == 64
    assert first == same
    with pytest.raises(ValueError, match="repeats"):
        canonical_adjustment_digest((*adjustments, *adjustments))


def test_later_backdate_appends_to_the_existing_adjustment_chain() -> None:
    old_price = price(
        UsageClass.OUTPUT,
        "1",
        token_unit=1,
        version_id="chain-old-output",
        effective_at=JANUARY - timedelta(days=2),
    )
    occurred_at = JANUARY + timedelta(days=2)
    original = book(
        "usage-two-adjustments",
        UsageBreakdown(output=2),
        (old_price,),
        occurred_at=occurred_at,
    )
    first_price = price(
        UsageClass.OUTPUT,
        "2",
        token_unit=1,
        version_id="chain-first-output",
        effective_at=JANUARY,
    )
    first_preview = preview_reprice(
        (original,),
        (old_price,),
        candidate_price=first_price,
    )
    first = confirmed_adjustments(
        first_preview,
        candidate_price=first_price,
        preview_id="123e4567-e89b-42d3-a456-426614174006",
        confirmation_operation_id="123e4567-e89b-42d3-a456-426614174007",
    )
    after_first = apply_confirmed_adjustments(original, first)

    second_price = price(
        UsageClass.OUTPUT,
        "3",
        token_unit=1,
        version_id="chain-second-output",
        effective_at=JANUARY + timedelta(days=1),
    )
    second_preview = preview_reprice(
        (after_first,),
        (old_price, first_price),
        candidate_price=second_price,
    )
    second = confirmed_adjustments(
        second_preview,
        candidate_price=second_price,
        preview_id="123e4567-e89b-42d3-a456-426614174008",
        confirmation_operation_id="123e4567-e89b-42d3-a456-426614174009",
    )
    current = apply_confirmed_adjustments(after_first, second)

    assert second[0].supersedes_adjustment_id == first[0].adjustment_id
    assert second[0].previous_cost == Decimal("4")
    assert second[0].new_cost == Decimal("6")
    assert second[0].delta == Decimal("2")
    assert current.total == Decimal("6")
    assert original.total == Decimal("2")


def test_backdate_preview_half_open_range_and_empty_result() -> None:
    old_rate = price(
        UsageClass.NORMAL_INPUT,
        "1",
        token_unit=1,
        version_id="old-rate",
        effective_at=JANUARY - timedelta(days=1),
    )
    candidate = price(
        UsageClass.NORMAL_INPUT,
        "2",
        token_unit=1,
        version_id="candidate",
    )
    later = JANUARY + timedelta(days=1)
    superseding = price(
        UsageClass.NORMAL_INPUT,
        "1",
        token_unit=1,
        version_id="superseding",
        effective_at=later,
    )
    booked = book(
        "usage-range-end",
        UsageBreakdown(normal_input=1),
        (old_rate, superseding),
        occurred_at=later,
    )

    preview = preview_reprice(
        (booked,),
        (old_rate, superseding),
        candidate_price=candidate,
    )

    assert preview.affected_count == 0
    assert preview.old_total == Decimal(0)
    assert preview.new_total == Decimal(0)
    assert preview.delta == Decimal(0)
    assert preview.effective_from == JANUARY
    assert preview.effective_to == later


def test_backdate_preview_rejects_reused_candidate_and_duplicate_usage() -> None:
    original = book("duplicate", UsageBreakdown(), ())
    candidate = price(
        UsageClass.NORMAL_INPUT,
        "1",
        version_id="candidate",
    )

    with pytest.raises(ValueError, match="version_id"):
        preview_reprice(
            (),
            (candidate,),
            candidate_price=candidate,
        )
    with pytest.raises(ValueError, match="duplicate usage_id"):
        preview_reprice(
            (original, original),
            (),
            candidate_price=candidate,
        )


def test_backdate_preview_rejects_unrelated_price_changes() -> None:
    old_input = price(
        UsageClass.NORMAL_INPUT,
        "1",
        token_unit=1,
        version_id="old-input",
        effective_at=JANUARY - timedelta(days=1),
    )
    old_output = price(
        UsageClass.OUTPUT,
        "1",
        token_unit=1,
        version_id="old-output",
        effective_at=JANUARY - timedelta(days=1),
    )
    original = book(
        "usage-unrelated",
        UsageBreakdown(normal_input=1, output=1),
        (old_input, old_output),
        occurred_at=JANUARY + timedelta(hours=1),
    )
    changed_output = price(
        UsageClass.OUTPUT,
        "9",
        token_unit=1,
        version_id="changed-output",
    )
    candidate_input = price(
        UsageClass.NORMAL_INPUT,
        "2",
        token_unit=1,
        version_id="candidate-input",
    )

    with pytest.raises(ValueError, match="unrelated price component"):
        preview_reprice(
            (original,),
            (old_input, changed_output),
            candidate_price=candidate_input,
        )
