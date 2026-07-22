from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal

import pytest
from pydantic import ValidationError

from app.pricing import PriceVersion, UsageClass
from app.usage import UsageEvent, canonical_event_sha256, configured_cost_for_event


NOW = datetime(2026, 7, 22, 12, 0, tzinfo=timezone.utc)


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
        "retry_count": 0,
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


def price(usage_class: UsageClass, amount: str, version: str) -> PriceVersion:
    return PriceVersion(
        version_id=version,
        provider="anthropic",
        model="claude-sonnet-4-5",
        usage_class=usage_class,
        token_unit=1_000_000,
        amount=Decimal(amount),
        effective_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


def test_complete_anthropic_usage_books_five_exact_price_versions() -> None:
    prices = (
        price(UsageClass.NORMAL_INPUT, "3", "normal-v1"),
        price(UsageClass.CACHE_CREATION_5M, "3.75", "write-5m-v1"),
        price(UsageClass.CACHE_CREATION_1H, "6", "write-1h-v1"),
        price(UsageClass.CACHE_READ, "0.30", "read-v1"),
        price(UsageClass.OUTPUT, "15", "output-v1"),
    )

    result = configured_cost_for_event(event(), prices)

    assert result is not None
    assert [component.price_version_id for component in result.components] == [
        "normal-v1",
        "write-5m-v1",
        "write-1h-v1",
        "read-v1",
        "output-v1",
    ]
    assert result.total == Decimal("0.001047")


def test_missing_nonzero_price_keeps_total_unknown() -> None:
    prices = (price(UsageClass.OUTPUT, "15", "output-v1"),)

    result = configured_cost_for_event(event(), prices)

    assert result is not None
    assert result.total is None
    assert result.unknown_classes == (
        UsageClass.NORMAL_INPUT,
        UsageClass.CACHE_CREATION_5M,
        UsageClass.CACHE_CREATION_1H,
        UsageClass.CACHE_READ,
    )
    assert result.components[-1].cost == Decimal("0.00075")


def test_partial_usage_is_not_filled_with_invented_zeroes() -> None:
    partial = event(
        normal_input_tokens=None,
        cache_creation_1h_tokens=None,
        usage_completeness="partial",
    )

    assert configured_cost_for_event(partial, ()) is None


def test_unknown_usage_remains_unknown() -> None:
    unknown = event(
        normal_input_tokens=None,
        cache_creation_5m_tokens=None,
        cache_creation_1h_tokens=None,
        cache_read_tokens=None,
        output_tokens=None,
        usage_completeness="unknown",
    )

    assert configured_cost_for_event(unknown, ()) is None


def test_failure_without_usage_is_explicit_not_applicable() -> None:
    failed = event(
        status="failure",
        normal_input_tokens=None,
        cache_creation_5m_tokens=None,
        cache_creation_1h_tokens=None,
        cache_read_tokens=None,
        output_tokens=None,
        usage_completeness="not_applicable",
        litellm_cost_usd=None,
    )

    assert configured_cost_for_event(failed, ()) is None


@pytest.mark.parametrize(
    "overrides",
    [
        {
            "usage_completeness": "complete",
            "normal_input_tokens": 0,
            "cache_creation_5m_tokens": 0,
            "cache_creation_1h_tokens": 0,
            "cache_read_tokens": 0,
            "output_tokens": 0,
        },
        {
            "usage_completeness": "not_applicable",
            "litellm_cost_usd": "0",
        },
        {
            "usage_completeness": "not_applicable",
            "provider_cost_usd": "0",
        },
    ],
)
def test_failure_cannot_claim_placeholder_usage_or_cost(overrides) -> None:
    document = {
        "status": "failure",
        "usage_completeness": "not_applicable",
        "normal_input_tokens": None,
        "cache_creation_5m_tokens": None,
        "cache_creation_1h_tokens": None,
        "cache_read_tokens": None,
        "output_tokens": None,
        "litellm_cost_usd": None,
        "provider_cost_usd": None,
    }
    document.update(overrides)

    with pytest.raises(ValidationError, match="failed callback"):
        event(**document)


@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        ({"prompt": "secret"}, "Extra inputs"),
        ({"headers": {"Authorization": "secret"}}, "Extra inputs"),
        ({"normal_input_tokens": -1}, "greater than or equal"),
        ({"litellm_cost_usd": "NaN"}, "canonical decimal"),
        ({"litellm_cost_usd": "1000000000.01"}, "reviewed non-negative bound"),
        ({"provider_cost_usd": "0.0000000000000000001"}, "canonical decimal"),
        ({"occurred_at": datetime(2026, 7, 22)}, "UTC-aware"),
        ({"source_version": "latest"}, "litellm-1.93.0"),
        ({"provider": "Anthropic"}, "provider is not canonical"),
        ({"project_id": "Project Blue"}, "project is not canonical"),
        ({"requested_model": "x" * 129}, "model is not canonical"),
        ({"stream": "false"}, "valid boolean"),
    ],
)
def test_malformed_or_sensitive_fields_are_rejected(overrides, match) -> None:
    with pytest.raises(ValidationError, match=match):
        event(**overrides)


def test_completeness_must_match_present_counts() -> None:
    with pytest.raises(ValidationError, match="does not match"):
        event(normal_input_tokens=None, usage_completeness="complete")


def test_unknown_stream_state_remains_null() -> None:
    assert event(stream=None).stream is None


def test_event_digest_is_stable_and_changes_with_evidence() -> None:
    first = event()
    same = event()
    changed = event(output_tokens=51)

    assert canonical_event_sha256(first) == canonical_event_sha256(same)
    assert canonical_event_sha256(first) != canonical_event_sha256(changed)
