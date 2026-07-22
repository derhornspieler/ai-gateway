"""Validated, prompt-free model usage evidence.

LiteLLM sends this small document after a provider call.  The document keeps
only fields needed for audit and cost reconciliation.  It cannot carry a
prompt, response body, API key, or request header because unknown fields are
rejected.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)

from app.pricing import ConfiguredCost, PriceVersion, UsageBreakdown, book_configured_cost


SOURCE_VERSION = "litellm-1.93.0"
USAGE_TOKEN_PATH = "/run/secrets/litellm_usage_token"
MAX_TOKEN_COUNT = 9_223_372_036_854_775_807
MAX_REPORTED_COST_USD = Decimal("1000000000")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@/+-]{0,255}")
_MODEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_./:-]{0,127}")
_PROVIDER_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_PROJECT_RE = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}")
_COST_RE = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]{1,18})?")

UsageCompleteness = Literal["complete", "partial", "unknown", "not_applicable"]
UsageStatus = Literal["success", "failure"]
RequestIdSource = Literal["litellm_call_id", "trace_id", "provider_response_id"]


class UsageConflict(RuntimeError):
    """An event ID was reused with different validated evidence."""


class UsageStoreUnavailable(RuntimeError):
    """The append-only usage ledger could not accept evidence."""


@dataclass(frozen=True, slots=True)
class UsageWriteResult:
    """The small receipt returned after an append or exact replay."""

    event_id: str
    created: bool


def read_usage_token() -> str:
    """Read the fixed usage credential without following a symbolic link."""

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(USAGE_TOKEN_PATH, flags)
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise RuntimeError("LiteLLM usage token must be one regular file")
        raw_token = os.read(descriptor, 65)
    finally:
        os.close(descriptor)
    try:
        token = raw_token.decode("ascii")
    except UnicodeDecodeError as exc:
        raise RuntimeError("LiteLLM usage token must be ASCII") from exc
    if _SHA256_RE.fullmatch(token) is None:
        raise RuntimeError(
            "LiteLLM usage token must be 64 lowercase hex characters"
        )
    return token


class UsageEvent(BaseModel):
    """One terminal provider-call event accepted by the usage endpoint."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1]
    event_id: StrictStr
    request_id: StrictStr
    request_id_source: RequestIdSource
    provider_response_id: StrictStr | None = None
    trace_id: StrictStr | None = None
    provider: StrictStr
    requested_model: StrictStr | None = None
    actual_model: StrictStr | None = None
    stable_user_id: StrictStr | None = None
    project_id: StrictStr | None = None
    status: UsageStatus
    stream: StrictBool | None = None
    retry_count: StrictInt | None = Field(default=None, ge=0, le=100)
    occurred_at: datetime
    normal_input_tokens: StrictInt | None = Field(
        default=None, ge=0, le=MAX_TOKEN_COUNT
    )
    cache_creation_5m_tokens: StrictInt | None = Field(
        default=None, ge=0, le=MAX_TOKEN_COUNT
    )
    cache_creation_1h_tokens: StrictInt | None = Field(
        default=None, ge=0, le=MAX_TOKEN_COUNT
    )
    cache_read_tokens: StrictInt | None = Field(
        default=None, ge=0, le=MAX_TOKEN_COUNT
    )
    output_tokens: StrictInt | None = Field(default=None, ge=0, le=MAX_TOKEN_COUNT)
    usage_completeness: UsageCompleteness
    litellm_cost_usd: StrictStr | None = Field(default=None, max_length=64)
    provider_cost_usd: StrictStr | None = Field(default=None, max_length=64)
    source_version: Literal[SOURCE_VERSION]

    @field_validator(
        "request_id",
        "provider_response_id",
        "trace_id",
        "stable_user_id",
    )
    @classmethod
    def validate_identifiers(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if _IDENTIFIER_RE.fullmatch(value) is None:
            raise ValueError("identifier is not canonical and bounded")
        return value

    @field_validator("requested_model", "actual_model")
    @classmethod
    def validate_models(cls, value: str | None) -> str | None:
        if value is not None and _MODEL_RE.fullmatch(value) is None:
            raise ValueError("model is not canonical and bounded")
        return value

    @field_validator("provider")
    @classmethod
    def validate_provider(cls, value: str) -> str:
        if _PROVIDER_RE.fullmatch(value) is None:
            raise ValueError("provider is not canonical and bounded")
        return value

    @field_validator("project_id")
    @classmethod
    def validate_project(cls, value: str | None) -> str | None:
        if value is not None and _PROJECT_RE.fullmatch(value) is None:
            raise ValueError("project is not canonical and bounded")
        return value

    @field_validator("event_id")
    @classmethod
    def validate_event_id(cls, value: str) -> str:
        if _SHA256_RE.fullmatch(value) is None:
            raise ValueError("event_id must be lowercase SHA-256")
        return value

    @field_validator("litellm_cost_usd", "provider_cost_usd")
    @classmethod
    def validate_cost(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if _COST_RE.fullmatch(value) is None:
            raise ValueError("cost must be a non-negative canonical decimal string")
        try:
            parsed = Decimal(value)
        except InvalidOperation as exc:
            raise ValueError("cost must be a decimal") from exc
        if (
            not parsed.is_finite()
            or parsed < 0
            or parsed > MAX_REPORTED_COST_USD
        ):
            raise ValueError("cost is outside the reviewed non-negative bound")
        return value

    @field_validator("occurred_at")
    @classmethod
    def validate_occurred_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("occurred_at must be UTC-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_completeness(self) -> "UsageEvent":
        counts = (
            self.normal_input_tokens,
            self.cache_creation_5m_tokens,
            self.cache_creation_1h_tokens,
            self.cache_read_tokens,
            self.output_tokens,
        )
        present = sum(value is not None for value in counts)
        expected = (
            "complete"
            if present == len(counts)
            else "unknown"
            if present == 0
            else "partial"
        )
        if self.usage_completeness == "not_applicable":
            if self.status != "failure" or present != 0:
                raise ValueError(
                    "not_applicable usage requires a failure with no token counts"
                )
        elif self.usage_completeness != expected:
            raise ValueError("usage_completeness does not match the token fields")
        if self.status == "failure" and (
            self.usage_completeness != "not_applicable"
            or self.litellm_cost_usd is not None
            or self.provider_cost_usd is not None
        ):
            raise ValueError(
                "a failed callback cannot claim token or cost evidence"
            )
        return self


def canonical_event_sha256(event: UsageEvent) -> str:
    """Hash the exact validated event for conflict-safe idempotency."""

    document = event.model_dump(mode="json")
    encoded = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def configured_cost_for_event(
    event: UsageEvent, prices: tuple[PriceVersion, ...]
) -> ConfiguredCost | None:
    """Price complete usage only; partial provider data stays unknown."""

    if (
        event.usage_completeness != "complete"
        or event.requested_model is None
        or any(
            value is None
            for value in (
                event.normal_input_tokens,
                event.cache_creation_5m_tokens,
                event.cache_creation_1h_tokens,
                event.cache_read_tokens,
                event.output_tokens,
            )
        )
    ):
        return None

    return book_configured_cost(
        usage_id=event.event_id,
        provider=event.provider,
        model=event.requested_model,
        occurred_at=event.occurred_at,
        usage=UsageBreakdown(
            normal_input=event.normal_input_tokens,
            cache_creation_5m=event.cache_creation_5m_tokens,
            cache_creation_1h=event.cache_creation_1h_tokens,
            cache_read=event.cache_read_tokens,
            output=event.output_tokens,
        ),
        prices=prices,
    )
