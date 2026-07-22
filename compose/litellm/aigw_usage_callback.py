"""Send prompt-free LiteLLM usage evidence to key-rotator.

This callback is pinned to LiteLLM 1.93.0's ``StandardLoggingPayload``.  It
copies a small allow-list.  Prompt text, response text, credentials, and
request headers never enter the event document.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import stat
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation

import httpx
from litellm.integrations.custom_logger import CustomLogger

from aigw_openwebui_identity import read_openwebui_forward_jwt_secret
from aigw_otel_callback import _resolved_server_identity


SOURCE_VERSION = "litellm-1.93.0"
TOKEN_PATH = "/run/secrets/litellm_usage_token"
USAGE_URL = "http://key-rotator:8080/usage/events"
TOKEN_PATTERN = re.compile(r"[0-9a-f]{64}")
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@/+-]{0,255}")
MODEL_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_./:-]{0,127}")
PROVIDER_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
PROJECT_PATTERN = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}")
MAX_REPORTED_COST_USD = Decimal("1000000000")
MAX_REPORTED_COST_DECIMALS = 18
TOKEN_FIELDS = (
    "normal_input_tokens",
    "cache_creation_5m_tokens",
    "cache_creation_1h_tokens",
    "cache_read_tokens",
    "output_tokens",
)
logger = logging.getLogger("litellm.aigw_usage")


class UsageEventError(ValueError):
    """The pinned callback payload did not meet the reviewed contract."""


def _read_token() -> str:
    """Read one fixed-shape secret without following a symbolic link."""

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(TOKEN_PATH, flags)
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
    if TOKEN_PATTERN.fullmatch(token) is None:
        raise RuntimeError(
            "LiteLLM usage token must be 64 lowercase hex characters"
        )
    return token


def _mapping(value) -> dict:
    return value if isinstance(value, dict) else {}


def _identifier(value) -> str | None:
    if (
        isinstance(value, str)
        and value not in {"None", "null"}
        and IDENTIFIER_PATTERN.fullmatch(value) is not None
    ):
        return value
    return None


def _bounded_string(value, pattern: re.Pattern[str]) -> str | None:
    return value if isinstance(value, str) and pattern.fullmatch(value) else None


def _token_count(value) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if not 0 <= value <= 9_223_372_036_854_775_807:
        return None
    return value


def _decimal_text(value) -> str | None:
    """Keep an upstream numeric cost exact enough for reconciliation."""

    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    try:
        amount = Decimal(str(value))
    except InvalidOperation:
        return None
    if (
        not amount.is_finite()
        or amount < 0
        or amount > MAX_REPORTED_COST_USD
        or max(-amount.as_tuple().exponent, 0) > MAX_REPORTED_COST_DECIMALS
    ):
        return None
    text = format(amount, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


def _retry_count(payload: dict) -> int | None:
    hidden = _mapping(payload.get("hidden_params"))
    headers = _mapping(hidden.get("additional_headers"))
    value = headers.get("x-litellm-attempted-retries")
    if isinstance(value, str) and value.isascii() and value.isdigit():
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 <= value <= 100 else None


def _provider_cost(payload: dict) -> str | None:
    """Read only LiteLLM's reviewed provider-reported cost field.

    ``usage.cost`` is a LiteLLM calculation in 1.93.0, including for
    Anthropic streaming responses. Treating it as provider evidence would
    duplicate ``response_cost`` under a misleading name. LiteLLM preserves a
    real provider-reported amount under this exact hidden-header key when a
    provider supplies one. The event copies only its numeric value, never the
    response-header mapping.
    """

    hidden = _mapping(payload.get("hidden_params"))
    headers = _mapping(hidden.get("additional_headers"))
    return _decimal_text(headers.get("llm_provider-x-litellm-response-cost"))


def _usage_counts(payload: dict, status: str) -> tuple[dict[str, int | None], str]:
    if status == "failure":
        return ({field: None for field in TOKEN_FIELDS}, "not_applicable")

    metadata = _mapping(payload.get("metadata"))
    usage = _mapping(metadata.get("usage_object"))
    prompt_details = _mapping(usage.get("prompt_tokens_details"))
    cache_details = _mapping(prompt_details.get("cache_creation_token_details"))
    provider_cache_details = _mapping(usage.get("cache_creation"))

    normal_input = _token_count(usage.get("uncached_input_tokens"))
    if normal_input is None:
        normal_input = _token_count(prompt_details.get("text_tokens"))

    cache_creation_5m = _token_count(
        provider_cache_details.get("ephemeral_5m_input_tokens")
    )
    if cache_creation_5m is None:
        cache_creation_5m = _token_count(
            cache_details.get("ephemeral_5m_input_tokens")
        )

    cache_creation_1h = _token_count(
        provider_cache_details.get("ephemeral_1h_input_tokens")
    )
    if cache_creation_1h is None:
        cache_creation_1h = _token_count(
            cache_details.get("ephemeral_1h_input_tokens")
        )

    cache_read = _token_count(usage.get("cache_read_input_tokens"))
    if cache_read is None:
        cache_read = _token_count(prompt_details.get("cached_tokens"))

    output = _token_count(usage.get("output_tokens"))
    if output is None:
        output = _token_count(usage.get("completion_tokens"))

    counts = {
        "normal_input_tokens": normal_input,
        "cache_creation_5m_tokens": cache_creation_5m,
        "cache_creation_1h_tokens": cache_creation_1h,
        "cache_read_tokens": cache_read,
        "output_tokens": output,
    }
    present = sum(value is not None for value in counts.values())
    completeness = (
        "complete"
        if present == len(counts)
        else "unknown"
        if present == 0
        else "partial"
    )
    return counts, completeness


def _request_identity(payload: dict) -> tuple[str, str, str]:
    candidates = (
        ("litellm_call_id", payload.get("litellm_call_id")),
        ("trace_id", payload.get("trace_id")),
        ("provider_response_id", payload.get("id")),
    )
    for source, value in candidates:
        request_id = _identifier(value)
        if request_id is not None:
            return request_id, source, _identifier(payload.get("id")) or ""
    raise UsageEventError("standard payload has no bounded request identifier")


def _occurred_at(payload: dict, fallback: datetime) -> str:
    value = payload.get("endTime")
    try:
        occurred = datetime.fromtimestamp(float(value), tz=timezone.utc)
    except (OverflowError, TypeError, ValueError):
        occurred = fallback.astimezone(timezone.utc)
    return occurred.isoformat(timespec="microseconds").replace("+00:00", "Z")


def build_usage_event(
    kwargs: dict,
    *,
    status: str,
    end_time: datetime,
    openwebui_secret: str,
) -> dict:
    """Build the sole prompt-free wire document from a standard payload."""

    payload = _mapping(kwargs.get("standard_logging_object"))
    if not payload:
        raise UsageEventError("LiteLLM standard logging payload is missing")
    if status not in {"success", "failure"} or payload.get("status") != status:
        raise UsageEventError("LiteLLM usage status is inconsistent")

    request_id, request_id_source, provider_response_id = _request_identity(payload)
    metadata = _mapping(payload.get("metadata"))
    auth_metadata = _mapping(metadata.get("user_api_key_auth_metadata"))

    stable_user_id = _identifier(metadata.get("user_api_key_user_id"))
    resolved_identity = _resolved_server_identity(kwargs, openwebui_secret)
    if resolved_identity is not None and resolved_identity[0] is not None:
        stable_user_id = _identifier(resolved_identity[0])

    project_id = _bounded_string(
        metadata.get("user_api_key_project_id"), PROJECT_PATTERN
    )
    if project_id is None:
        project_id = _bounded_string(
            auth_metadata.get("aigw_project_id"), PROJECT_PATTERN
        )

    requested_model = _bounded_string(payload.get("model_group"), MODEL_PATTERN)
    if requested_model is None:
        requested_model = _bounded_string(kwargs.get("model"), MODEL_PATTERN)
    hidden = _mapping(payload.get("hidden_params"))
    actual_model = _bounded_string(hidden.get("litellm_model_name"), MODEL_PATTERN)
    if actual_model is None:
        actual_model = _bounded_string(payload.get("model"), MODEL_PATTERN)

    provider = _bounded_string(
        payload.get("custom_llm_provider"), PROVIDER_PATTERN
    )
    if provider is None:
        raise UsageEventError("standard payload has no bounded provider")

    counts, completeness = _usage_counts(payload, status)
    litellm_cost = (
        _decimal_text(payload.get("response_cost")) if status == "success" else None
    )
    provider_cost = _provider_cost(payload) if status == "success" else None

    stream_value = payload.get("stream")
    if not isinstance(stream_value, bool):
        stream_value = kwargs.get("stream")
    stream = stream_value if isinstance(stream_value, bool) else None
    event = {
        "schema_version": 1,
        "request_id": request_id,
        "request_id_source": request_id_source,
        "provider_response_id": provider_response_id or None,
        "trace_id": _identifier(payload.get("trace_id")),
        "provider": provider,
        "requested_model": requested_model,
        "actual_model": actual_model,
        "stable_user_id": stable_user_id,
        "project_id": project_id,
        "status": status,
        "stream": stream,
        "retry_count": _retry_count(payload),
        "occurred_at": _occurred_at(payload, end_time),
        **counts,
        "usage_completeness": completeness,
        "litellm_cost_usd": litellm_cost,
        "provider_cost_usd": provider_cost,
        "source_version": SOURCE_VERSION,
    }
    anchor = {
        "provider_response_id": provider_response_id,
        "request_id": request_id,
        "source_version": SOURCE_VERSION,
        "status": status,
    }
    encoded = json.dumps(
        anchor, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    event["event_id"] = hashlib.sha256(encoded).hexdigest()
    return event


def _delivery_failure_audit(event: dict | None) -> dict[str, object]:
    """Build one safe record when the ledger did not accept an event."""

    evidence = event if isinstance(event, dict) else {}
    event_id = evidence.get("event_id")
    if not isinstance(event_id, str) or TOKEN_PATTERN.fullmatch(event_id) is None:
        event_id = "unattributed"
    completeness = evidence.get("usage_completeness")
    if completeness not in {"complete", "partial", "unknown", "not_applicable"}:
        completeness = "unknown"
    return {
        "schema_version": 1,
        "event": "aigw.usage.audit",
        "action": "delivery_failure",
        "outcome": "failure",
        "event_id": event_id,
        "request_id": _identifier(evidence.get("request_id")) or "unattributed",
        "provider": (
            _bounded_string(evidence.get("provider"), PROVIDER_PATTERN)
            or "unattributed"
        ),
        "model": (
            _bounded_string(evidence.get("requested_model"), MODEL_PATTERN)
            or "unattributed"
        ),
        "project": (
            _bounded_string(evidence.get("project_id"), PROJECT_PATTERN)
            or "unattributed"
        ),
        "subject": _identifier(evidence.get("stable_user_id")) or "unattributed",
        "completeness": completeness,
    }


def _fallback_delivery_evidence(kwargs: dict) -> dict[str, object]:
    """Recover bounded join fields when full event validation failed."""

    payload = _mapping(kwargs.get("standard_logging_object"))
    metadata = _mapping(payload.get("metadata"))
    auth_metadata = _mapping(metadata.get("user_api_key_auth_metadata"))
    request_id = None
    for value in (
        payload.get("litellm_call_id"),
        payload.get("trace_id"),
        payload.get("id"),
    ):
        request_id = _identifier(value)
        if request_id is not None:
            break
    requested_model = _bounded_string(payload.get("model_group"), MODEL_PATTERN)
    if requested_model is None:
        requested_model = _bounded_string(kwargs.get("model"), MODEL_PATTERN)
    project_id = _bounded_string(
        metadata.get("user_api_key_project_id"), PROJECT_PATTERN
    )
    if project_id is None:
        project_id = _bounded_string(
            auth_metadata.get("aigw_project_id"), PROJECT_PATTERN
        )
    return {
        "event_id": None,
        "request_id": request_id,
        "provider": _bounded_string(
            payload.get("custom_llm_provider"), PROVIDER_PATTERN
        ),
        "requested_model": requested_model,
        "project_id": project_id,
        "stable_user_id": _identifier(metadata.get("user_api_key_user_id")),
        "usage_completeness": "unknown",
    }


class AigwUsageCallback(CustomLogger):
    """Authenticated, bounded delivery to the local usage ledger."""

    def __init__(self) -> None:
        super().__init__(turn_off_message_logging=True)
        self._token = _read_token()
        self._openwebui_secret = read_openwebui_forward_jwt_secret()

    async def _send(self, kwargs: dict, status: str, end_time: datetime) -> None:
        event = None
        try:
            event = build_usage_event(
                kwargs,
                status=status,
                end_time=end_time,
                openwebui_secret=self._openwebui_secret,
            )
            async with httpx.AsyncClient(
                timeout=2.0, trust_env=False, follow_redirects=False
            ) as client:
                response = await client.post(
                    USAGE_URL,
                    headers={"X-AIGW-Usage-Auth": self._token},
                    json=event,
                )
            if response.status_code not in {200, 201}:
                raise UsageEventError("usage endpoint rejected the event")
        except Exception:  # noqa: BLE001
            # The provider call has already ended. Do not turn an accounting
            # gap into a caller retry that could charge the provider twice.
            # The fixed event has no exception text, URL, body, or header.
            audit = _delivery_failure_audit(
                event if event is not None else _fallback_delivery_evidence(kwargs)
            )
            logger.error(
                "AIGW_SECURITY_EVENT %s",
                json.dumps(audit, sort_keys=True, separators=(",", ":")),
            )

    async def async_log_success_event(
        self, kwargs, response_obj, start_time, end_time
    ) -> None:
        await self._send(kwargs, "success", end_time)

    async def async_log_failure_event(
        self, kwargs, response_obj, start_time, end_time
    ) -> None:
        await self._send(kwargs, "failure", end_time)


aigw_usage = AigwUsageCallback()
