"""Pure pricing rules for configured AI usage cost.

This module deliberately has no database, web, or logging code.  It provides
the small value objects and calculations that those layers will use later.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import (
    Context,
    Decimal,
    DivisionByZero,
    Inexact,
    InvalidOperation,
    Overflow,
    ROUND_HALF_EVEN,
    Rounded,
    localcontext,
)
from enum import StrEnum
from typing import Iterable


MIN_TOKEN_UNIT = 1
MAX_TOKEN_UNIT = 1_000_000_000
MAX_TOKEN_COUNT = 9_223_372_036_854_775_807
MAX_PRICE_AMOUNT = Decimal("1000000")
MAX_PRICE_DECIMAL_PLACES = 12
CURRENCY = "USD"
COST_PRECISION = 60

_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_./:-]{0,127}")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


class UsageClass(StrEnum):
    """The token classes that can have different provider prices."""

    NORMAL_INPUT = "normal_input"
    CACHE_CREATION_5M = "cache_creation_5m"
    CACHE_CREATION_1H = "cache_creation_1h"
    CACHE_READ = "cache_read"
    OUTPUT = "output"


USAGE_CLASSES = tuple(UsageClass)


def _require_identifier(value: str, label: str) -> None:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be a short canonical identifier")


def _require_utc(value: datetime, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"{label} must be UTC-aware")


def _decimal_places(value: Decimal) -> int:
    exponent = value.as_tuple().exponent
    return max(-exponent, 0)


def _canonical_decimal(value: Decimal) -> str:
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return "0" if text in {"", "-0"} else text


def _canonical_time(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _cost_context() -> Context:
    """Return the one reviewed context instead of inheriting caller state."""

    return Context(
        prec=COST_PRECISION,
        rounding=ROUND_HALF_EVEN,
        traps=[DivisionByZero, Inexact, InvalidOperation, Overflow, Rounded],
    )


def _has_exact_decimal_unit_price(amount: Decimal, token_unit: int) -> bool:
    """Return whether amount/token_unit has a finite decimal expansion."""

    numerator, denominator = amount.as_integer_ratio()
    denominator *= token_unit
    denominator //= math.gcd(abs(numerator), denominator)
    while denominator % 2 == 0:
        denominator //= 2
    while denominator % 5 == 0:
        denominator //= 5
    return denominator == 1


@dataclass(frozen=True, slots=True)
class PriceVersion:
    """One immutable, effective-dated price for one usage class."""

    version_id: str
    provider: str
    model: str
    usage_class: UsageClass
    token_unit: int
    amount: Decimal
    effective_at: datetime
    currency: str = CURRENCY
    explicit_free: bool = False

    def __post_init__(self) -> None:
        _require_identifier(self.version_id, "version_id")
        _require_identifier(self.provider, "provider")
        _require_identifier(self.model, "model")
        if not isinstance(self.usage_class, UsageClass):
            raise TypeError("usage_class must be a UsageClass")
        if type(self.token_unit) is not int:  # bool is not a valid unit
            raise TypeError("token_unit must be an integer")
        if not MIN_TOKEN_UNIT <= self.token_unit <= MAX_TOKEN_UNIT:
            raise ValueError(
                f"token_unit must be between {MIN_TOKEN_UNIT} and {MAX_TOKEN_UNIT}"
            )
        if not isinstance(self.amount, Decimal):
            raise TypeError("amount must be a Decimal")
        if not self.amount.is_finite():
            raise ValueError("amount must be finite")
        if self.amount < 0 or (self.amount == 0 and self.amount.is_signed()):
            raise ValueError("amount must not be negative")
        if self.amount > MAX_PRICE_AMOUNT:
            raise ValueError(f"amount must not exceed {MAX_PRICE_AMOUNT}")
        if _decimal_places(self.amount) > MAX_PRICE_DECIMAL_PLACES:
            raise ValueError(
                f"amount must have at most {MAX_PRICE_DECIMAL_PLACES} decimal places"
            )
        if self.currency != CURRENCY:
            raise ValueError(f"currency must be {CURRENCY}")
        if type(self.explicit_free) is not bool:
            raise TypeError("explicit_free must be a boolean")
        if self.amount == 0 and not self.explicit_free:
            raise ValueError("a zero price must be explicitly marked free")
        if self.amount > 0 and self.explicit_free:
            raise ValueError("a positive price cannot be marked free")
        if not _has_exact_decimal_unit_price(self.amount, self.token_unit):
            raise ValueError("amount per token_unit must have an exact decimal value")
        _require_utc(self.effective_at, "effective_at")


@dataclass(frozen=True, slots=True)
class UsageBreakdown:
    """The billable token counts for one provider attempt."""

    normal_input: int = 0
    cache_creation_5m: int = 0
    cache_creation_1h: int = 0
    cache_read: int = 0
    output: int = 0

    def __post_init__(self) -> None:
        for usage_class, units in self.items():
            if type(units) is not int:  # bool is not a valid token count
                raise TypeError(f"{usage_class.value} must be an integer")
            if not 0 <= units <= MAX_TOKEN_COUNT:
                raise ValueError(
                    f"{usage_class.value} must be between 0 and {MAX_TOKEN_COUNT}"
                )

    def items(self) -> tuple[tuple[UsageClass, int], ...]:
        return (
            (UsageClass.NORMAL_INPUT, self.normal_input),
            (UsageClass.CACHE_CREATION_5M, self.cache_creation_5m),
            (UsageClass.CACHE_CREATION_1H, self.cache_creation_1h),
            (UsageClass.CACHE_READ, self.cache_read),
            (UsageClass.OUTPUT, self.output),
        )


@dataclass(frozen=True, slots=True)
class CostComponent:
    """The booked result for one usage class."""

    usage_class: UsageClass
    units: int
    cost: Decimal | None
    price_version_id: str | None
    price_digest: str | None
    adjustment_id: str | None = None


@dataclass(frozen=True, slots=True)
class ConfiguredCost:
    """An immutable configured-cost result for one usage record."""

    usage_id: str
    provider: str
    model: str
    occurred_at: datetime
    usage: UsageBreakdown
    components: tuple[CostComponent, ...]
    total: Decimal | None
    unknown_classes: tuple[UsageClass, ...]
    currency: str = CURRENCY


@dataclass(frozen=True, slots=True)
class RepriceChange:
    """One proposed replacement result; the original remains untouched."""

    original: ConfiguredCost
    proposed: ConfiguredCost


@dataclass(frozen=True, slots=True)
class RepricePreview:
    """A read-only summary of rows changed by a candidate price policy."""

    changes: tuple[RepriceChange, ...]
    old_total: Decimal | None
    new_total: Decimal | None
    delta: Decimal | None
    old_unknown_count: int
    new_unknown_count: int
    candidate_version_id: str
    effective_from: datetime
    effective_to: datetime | None

    @property
    def affected_count(self) -> int:
        return len(self.changes)


@dataclass(frozen=True, slots=True)
class CostAdjustment:
    """One immutable replacement for one booked usage component."""

    adjustment_id: str
    preview_id: str
    confirmation_operation_id: str
    usage_id: str
    usage_class: UsageClass
    units: int
    supersedes_adjustment_id: str | None
    previous_price_version_id: str | None
    new_price_version_id: str
    previous_cost: Decimal | None
    new_cost: Decimal
    delta: Decimal | None
    new_price_digest: str

    def __post_init__(self) -> None:
        for label, value in (
            ("adjustment_id", self.adjustment_id),
            ("preview_id", self.preview_id),
            ("confirmation_operation_id", self.confirmation_operation_id),
            ("usage_id", self.usage_id),
            ("new_price_version_id", self.new_price_version_id),
            ("new_price_digest", self.new_price_digest),
        ):
            _require_identifier(value, label)
        for label, value in (
            ("supersedes_adjustment_id", self.supersedes_adjustment_id),
            ("previous_price_version_id", self.previous_price_version_id),
        ):
            if value is not None:
                _require_identifier(value, label)
        if not isinstance(self.usage_class, UsageClass):
            raise TypeError("usage_class must be a UsageClass")
        if type(self.units) is not int or self.units <= 0:
            raise ValueError("an adjustment requires a positive token count")
        for label, value in (
            ("previous_cost", self.previous_cost),
            ("new_cost", self.new_cost),
            ("delta", self.delta),
        ):
            if value is not None and (
                not isinstance(value, Decimal) or not value.is_finite()
            ):
                raise ValueError(f"{label} must be a finite Decimal or null")
        if self.previous_cost is not None and self.previous_cost < 0:
            raise ValueError("previous_cost must not be negative")
        if self.new_cost < 0:
            raise ValueError("new_cost must not be negative")
        expected_delta = (
            None
            if self.previous_cost is None
            else _subtract_costs(self.new_cost, self.previous_cost)
        )
        if self.delta != expected_delta:
            raise ValueError("adjustment delta does not match its component costs")


def _price_document(price: PriceVersion) -> dict[str, object]:
    return {
        "amount": _canonical_decimal(price.amount),
        "currency": price.currency,
        "effective_at": _canonical_time(price.effective_at),
        "explicit_free": price.explicit_free,
        "model": price.model,
        "provider": price.provider,
        "token_unit": price.token_unit,
        "usage_class": price.usage_class.value,
        "version_id": price.version_id,
    }


def _validated_policy(prices: Iterable[PriceVersion]) -> tuple[PriceVersion, ...]:
    """Freeze and validate the immutable identity of a complete price policy."""

    policy = tuple(prices)
    version_ids: set[str] = set()
    effective_keys: set[tuple[str, str, UsageClass, datetime]] = set()
    for price in policy:
        if not isinstance(price, PriceVersion):
            raise TypeError("price policy must contain PriceVersion values")
        if price.version_id in version_ids:
            raise ValueError("price policy repeats a version_id")
        key = (
            price.provider,
            price.model,
            price.usage_class,
            price.effective_at,
        )
        if key in effective_keys:
            raise ValueError(
                "price policy has multiple versions for the same effective time"
            )
        version_ids.add(price.version_id)
        effective_keys.add(key)
    return policy


def canonical_price_digest(prices: Iterable[PriceVersion]) -> str:
    """Return a stable SHA-256 digest independent of input ordering."""

    documents = [_price_document(price) for price in _validated_policy(prices)]
    documents.sort(
        key=lambda document: json.dumps(
            document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
    )
    encoded = json.dumps(
        {"schema_version": 1, "prices": documents},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def select_effective_price(
    prices: Iterable[PriceVersion],
    *,
    provider: str,
    model: str,
    usage_class: UsageClass,
    occurred_at: datetime,
) -> PriceVersion | None:
    """Select the latest price effective at or before the usage time."""

    _require_identifier(provider, "provider")
    _require_identifier(model, "model")
    if not isinstance(usage_class, UsageClass):
        raise TypeError("usage_class must be a UsageClass")
    _require_utc(occurred_at, "occurred_at")

    return _select_effective_price(
        _validated_policy(prices),
        provider=provider,
        model=model,
        usage_class=usage_class,
        occurred_at=occurred_at,
    )


def _select_effective_price(
    policy: tuple[PriceVersion, ...],
    *,
    provider: str,
    model: str,
    usage_class: UsageClass,
    occurred_at: datetime,
) -> PriceVersion | None:
    candidates = [
        price
        for price in policy
        if price.provider == provider
        and price.model == model
        and price.usage_class == usage_class
        and price.effective_at <= occurred_at
    ]
    if not candidates:
        return None

    return max(candidates, key=lambda price: price.effective_at)


def _component_cost(units: int, price: PriceVersion) -> Decimal:
    with localcontext(_cost_context()):
        return Decimal(units) * price.amount / Decimal(price.token_unit)


def _sum_costs(values: Iterable[Decimal]) -> Decimal:
    with localcontext(_cost_context()):
        return sum(values, start=Decimal(0))


def _subtract_costs(left: Decimal, right: Decimal) -> Decimal:
    with localcontext(_cost_context()):
        return left - right


def book_configured_cost(
    *,
    usage_id: str,
    provider: str,
    model: str,
    occurred_at: datetime,
    usage: UsageBreakdown,
    prices: Iterable[PriceVersion],
) -> ConfiguredCost:
    """Book one immutable result without display rounding or invented cost."""

    _require_identifier(usage_id, "usage_id")
    _require_identifier(provider, "provider")
    _require_identifier(model, "model")
    _require_utc(occurred_at, "occurred_at")
    if not isinstance(usage, UsageBreakdown):
        raise TypeError("usage must be a UsageBreakdown")

    policy = _validated_policy(prices)
    components: list[CostComponent] = []
    unknown_classes: list[UsageClass] = []
    known_costs: list[Decimal] = []

    for usage_class, units in usage.items():
        # A zero count has a known zero cost and does not consume a price.
        # Leaving its provenance blank also prevents an unrelated rate change
        # from making a zero-use row appear in a backdate preview.
        if units == 0:
            components.append(
                CostComponent(
                    usage_class=usage_class,
                    units=0,
                    cost=Decimal(0),
                    price_version_id=None,
                    price_digest=None,
                )
            )
            known_costs.append(Decimal(0))
            continue

        price = _select_effective_price(
            policy,
            provider=provider,
            model=model,
            usage_class=usage_class,
            occurred_at=occurred_at,
        )
        if price is None:
            cost = None
            unknown_classes.append(usage_class)
            components.append(
                CostComponent(
                    usage_class=usage_class,
                    units=units,
                    cost=cost,
                    price_version_id=None,
                    price_digest=None,
                )
            )
            continue

        cost = _component_cost(units, price)
        known_costs.append(cost)
        components.append(
            CostComponent(
                usage_class=usage_class,
                units=units,
                cost=cost,
                price_version_id=price.version_id,
                price_digest=canonical_price_digest((price,)),
            )
        )

    total = None if unknown_classes else _sum_costs(known_costs)
    return ConfiguredCost(
        usage_id=usage_id,
        provider=provider,
        model=model,
        occurred_at=occurred_at,
        usage=usage,
        components=tuple(components),
        total=total,
        unknown_classes=tuple(unknown_classes),
    )


def preview_reprice(
    booked_results: Iterable[ConfiguredCost],
    baseline_prices: Iterable[PriceVersion],
    *,
    candidate_price: PriceVersion,
) -> RepricePreview:
    """Preview every row affected by one effective-dated candidate version.

    The function creates new proposed values and never modifies or replaces a
    booked result. The impact window starts at the candidate and ends at the
    next version for the same provider, model, and usage class. A caller cannot
    narrow that window and hide affected rows.
    """

    if not isinstance(candidate_price, PriceVersion):
        raise TypeError("candidate_price must be a PriceVersion")
    baseline = _validated_policy(baseline_prices)
    policy = _validated_policy((*baseline, candidate_price))
    candidate = candidate_price
    effective_from = candidate.effective_at
    later_versions = [
        price.effective_at
        for price in policy
        if price.provider == candidate.provider
        and price.model == candidate.model
        and price.usage_class == candidate.usage_class
        and price.effective_at > candidate.effective_at
    ]
    effective_to = min(later_versions) if later_versions else None

    seen_usage_ids: set[str] = set()
    changes: list[RepriceChange] = []
    for original in booked_results:
        if not isinstance(original, ConfiguredCost):
            raise TypeError("booked_results must contain ConfiguredCost values")
        if original.usage_id in seen_usage_ids:
            raise ValueError("booked_results contains a duplicate usage_id")
        seen_usage_ids.add(original.usage_id)
        if original.provider != candidate.provider or original.model != candidate.model:
            continue
        if original.occurred_at < effective_from:
            continue
        if effective_to is not None and original.occurred_at >= effective_to:
            continue

        proposed = book_configured_cost(
            usage_id=original.usage_id,
            provider=original.provider,
            model=original.model,
            occurred_at=original.occurred_at,
            usage=original.usage,
            prices=policy,
        )
        if len(original.components) != len(proposed.components):
            raise ValueError("booked result has an invalid component shape")
        for old_component, new_component in zip(
            original.components, proposed.components, strict=True
        ):
            if old_component.usage_class != new_component.usage_class:
                raise ValueError("booked result has an invalid component order")
            if (
                old_component.usage_class != candidate.usage_class
                and old_component != new_component
            ):
                raise ValueError(
                    "candidate preview changed an unrelated price component"
                )
        if proposed != original:
            changes.append(RepriceChange(original=original, proposed=proposed))

    changes.sort(
        key=lambda change: (change.original.occurred_at, change.original.usage_id)
    )
    old_unknown_count = sum(change.original.total is None for change in changes)
    new_unknown_count = sum(change.proposed.total is None for change in changes)
    old_total = (
        None
        if old_unknown_count
        else _sum_costs(
            change.original.total
            for change in changes
            if change.original.total is not None
        )
    )
    new_total = (
        None
        if new_unknown_count
        else _sum_costs(
            change.proposed.total
            for change in changes
            if change.proposed.total is not None
        )
    )
    delta = (
        None
        if old_total is None or new_total is None
        else _subtract_costs(new_total, old_total)
    )
    return RepricePreview(
        changes=tuple(changes),
        old_total=old_total,
        new_total=new_total,
        delta=delta,
        old_unknown_count=old_unknown_count,
        new_unknown_count=new_unknown_count,
        candidate_version_id=candidate.version_id,
        effective_from=effective_from,
        effective_to=effective_to,
    )


def _adjustment_document(
    *,
    preview_id: str,
    confirmation_operation_id: str,
    usage_id: str,
    usage_class: UsageClass,
    units: int,
    supersedes_adjustment_id: str | None,
    previous_price_version_id: str | None,
    new_price_version_id: str,
    previous_cost: Decimal | None,
    new_cost: Decimal,
    new_price_digest: str,
) -> dict[str, object]:
    return {
        "confirmation_operation_id": confirmation_operation_id,
        "new_cost": _canonical_decimal(new_cost),
        "new_price_digest": new_price_digest,
        "new_price_version_id": new_price_version_id,
        "preview_id": preview_id,
        "previous_cost": (
            None if previous_cost is None else _canonical_decimal(previous_cost)
        ),
        "previous_price_version_id": previous_price_version_id,
        "supersedes_adjustment_id": supersedes_adjustment_id,
        "units": units,
        "usage_class": usage_class.value,
        "usage_id": usage_id,
    }


def confirmed_adjustments(
    preview: RepricePreview,
    *,
    candidate_price: PriceVersion,
    preview_id: str,
    confirmation_operation_id: str,
) -> tuple[CostAdjustment, ...]:
    """Turn an exact preview into deterministic append-only adjustments."""

    if not isinstance(preview, RepricePreview):
        raise TypeError("preview must be a RepricePreview")
    if not isinstance(candidate_price, PriceVersion):
        raise TypeError("candidate_price must be a PriceVersion")
    for label, value in (
        ("preview_id", preview_id),
        ("confirmation_operation_id", confirmation_operation_id),
    ):
        _require_identifier(value, label)
    if preview.candidate_version_id != candidate_price.version_id:
        raise ValueError("candidate price does not match the preview")

    price_digest = canonical_price_digest((candidate_price,))
    adjustments: list[CostAdjustment] = []
    for change in preview.changes:
        old = next(
            component
            for component in change.original.components
            if component.usage_class == candidate_price.usage_class
        )
        new = next(
            component
            for component in change.proposed.components
            if component.usage_class == candidate_price.usage_class
        )
        if (
            old.units <= 0
            or new.units != old.units
            or new.cost is None
            or new.price_version_id != candidate_price.version_id
            or new.price_digest != price_digest
        ):
            raise ValueError("preview does not contain the exact candidate component")
        document = _adjustment_document(
            preview_id=preview_id,
            confirmation_operation_id=confirmation_operation_id,
            usage_id=change.original.usage_id,
            usage_class=candidate_price.usage_class,
            units=old.units,
            supersedes_adjustment_id=old.adjustment_id,
            previous_price_version_id=old.price_version_id,
            new_price_version_id=candidate_price.version_id,
            previous_cost=old.cost,
            new_cost=new.cost,
            new_price_digest=price_digest,
        )
        encoded = json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        adjustment_id = hashlib.sha256(encoded).hexdigest()
        delta = (
            None
            if old.cost is None
            else _subtract_costs(new.cost, old.cost)
        )
        adjustments.append(
            CostAdjustment(
                adjustment_id=adjustment_id,
                preview_id=preview_id,
                confirmation_operation_id=confirmation_operation_id,
                usage_id=change.original.usage_id,
                usage_class=candidate_price.usage_class,
                units=old.units,
                supersedes_adjustment_id=old.adjustment_id,
                previous_price_version_id=old.price_version_id,
                new_price_version_id=candidate_price.version_id,
                previous_cost=old.cost,
                new_cost=new.cost,
                delta=delta,
                new_price_digest=price_digest,
            )
        )
    return tuple(adjustments)


def canonical_adjustment_digest(
    adjustments: Iterable[CostAdjustment],
) -> str:
    """Hash immutable adjustment history without depending on row order."""

    documents: list[dict[str, object]] = []
    seen_ids: set[str] = set()
    for adjustment in adjustments:
        if not isinstance(adjustment, CostAdjustment):
            raise TypeError("adjustments must contain CostAdjustment values")
        if adjustment.adjustment_id in seen_ids:
            raise ValueError("adjustments repeats an adjustment_id")
        seen_ids.add(adjustment.adjustment_id)
        document = _adjustment_document(
            preview_id=adjustment.preview_id,
            confirmation_operation_id=adjustment.confirmation_operation_id,
            usage_id=adjustment.usage_id,
            usage_class=adjustment.usage_class,
            units=adjustment.units,
            supersedes_adjustment_id=adjustment.supersedes_adjustment_id,
            previous_price_version_id=adjustment.previous_price_version_id,
            new_price_version_id=adjustment.new_price_version_id,
            previous_cost=adjustment.previous_cost,
            new_cost=adjustment.new_cost,
            new_price_digest=adjustment.new_price_digest,
        )
        document["adjustment_id"] = adjustment.adjustment_id
        documents.append(document)
    documents.sort(key=lambda item: str(item["adjustment_id"]))
    encoded = json.dumps(
        {"adjustments": documents, "schema_version": 1},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def canonical_reprice_preview_digest(
    preview: RepricePreview,
    *,
    candidate_price: PriceVersion,
    baseline_price_policy_sha256: str,
    baseline_adjustments_sha256: str,
) -> str:
    """Bind a preview to its candidate, policy, and exact affected rows."""

    if not isinstance(preview, RepricePreview):
        raise TypeError("preview must be a RepricePreview")
    if not isinstance(candidate_price, PriceVersion):
        raise TypeError("candidate_price must be a PriceVersion")
    for label, value in (
        ("baseline_price_policy_sha256", baseline_price_policy_sha256),
        ("baseline_adjustments_sha256", baseline_adjustments_sha256),
    ):
        if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
            raise ValueError(f"{label} must be lowercase SHA-256")
    if preview.candidate_version_id != candidate_price.version_id:
        raise ValueError("candidate price does not match the preview")

    rows: list[dict[str, object]] = []
    for change in preview.changes:
        old = next(
            component
            for component in change.original.components
            if component.usage_class == candidate_price.usage_class
        )
        new = next(
            component
            for component in change.proposed.components
            if component.usage_class == candidate_price.usage_class
        )
        rows.append(
            {
                "new_component_cost": (
                    None if new.cost is None else _canonical_decimal(new.cost)
                ),
                "new_price_version_id": new.price_version_id,
                "new_total": (
                    None
                    if change.proposed.total is None
                    else _canonical_decimal(change.proposed.total)
                ),
                "old_component_cost": (
                    None if old.cost is None else _canonical_decimal(old.cost)
                ),
                "old_price_version_id": old.price_version_id,
                "old_total": (
                    None
                    if change.original.total is None
                    else _canonical_decimal(change.original.total)
                ),
                "occurred_at": _canonical_time(change.original.occurred_at),
                "supersedes_adjustment_id": old.adjustment_id,
                "units": old.units,
                "usage_id": change.original.usage_id,
            }
        )
    rows.sort(key=lambda row: (str(row["occurred_at"]), str(row["usage_id"])))
    document = {
        "affected_rows": rows,
        "baseline_adjustments_sha256": baseline_adjustments_sha256,
        "baseline_price_policy_sha256": baseline_price_policy_sha256,
        "candidate_price": _price_document(candidate_price),
        "effective_from": _canonical_time(preview.effective_from),
        "effective_to": (
            None
            if preview.effective_to is None
            else _canonical_time(preview.effective_to)
        ),
        "schema_version": 1,
    }
    encoded = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def apply_confirmed_adjustments(
    booked: ConfiguredCost,
    adjustments: Iterable[CostAdjustment],
) -> ConfiguredCost:
    """Build the current read value while keeping the booked row unchanged."""

    if not isinstance(booked, ConfiguredCost):
        raise TypeError("booked must be a ConfiguredCost")
    components = {
        component.usage_class: component for component in booked.components
    }
    if set(components) != set(UsageClass):
        raise ValueError("booked result has an invalid component shape")

    seen_adjustments: set[str] = set()
    for adjustment in adjustments:
        if not isinstance(adjustment, CostAdjustment):
            raise TypeError("adjustments must contain CostAdjustment values")
        if adjustment.adjustment_id in seen_adjustments:
            raise ValueError("adjustments repeats an adjustment_id")
        seen_adjustments.add(adjustment.adjustment_id)
        if adjustment.usage_id != booked.usage_id:
            raise ValueError("adjustment belongs to another usage row")
        current = components[adjustment.usage_class]
        if (
            current.units != adjustment.units
            or current.adjustment_id != adjustment.supersedes_adjustment_id
            or current.price_version_id != adjustment.previous_price_version_id
            or current.cost != adjustment.previous_cost
        ):
            raise ValueError("adjustment does not continue the immutable chain")
        components[adjustment.usage_class] = CostComponent(
            usage_class=adjustment.usage_class,
            units=adjustment.units,
            cost=adjustment.new_cost,
            price_version_id=adjustment.new_price_version_id,
            price_digest=adjustment.new_price_digest,
            adjustment_id=adjustment.adjustment_id,
        )

    ordered = tuple(components[usage_class] for usage_class in UsageClass)
    unknown_classes = tuple(
        component.usage_class for component in ordered if component.cost is None
    )
    total = (
        None
        if unknown_classes
        else _sum_costs(
            component.cost for component in ordered if component.cost is not None
        )
    )
    return ConfiguredCost(
        usage_id=booked.usage_id,
        provider=booked.provider,
        model=booked.model,
        occurred_at=booked.occurred_at,
        usage=booked.usage,
        components=ordered,
        total=total,
        unknown_classes=unknown_classes,
        currency=booked.currency,
    )
