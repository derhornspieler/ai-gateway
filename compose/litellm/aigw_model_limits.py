"""Fail-closed per-project, per-model output limits for LiteLLM.

The portal writes one canonical policy into each managed key. Before a model
request leaves LiteLLM, :func:`enforce_model_limits` applies the request cap
and reserves the requested output against one Redis UTC-minute bucket.

Reservations are conservative. The pinned LiteLLM callback contract cannot
safely match every retry, stream, disconnect, and provider failure with a
later refund, so unused reservations expire at the end of the minute.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
from typing import Any

from fastapi import HTTPException


MODEL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./:-]{0,127}$")
MODEL_LIMITS_METADATA_KEY = "aigw_model_limits_v1"
PROJECT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
ALL_PROXY_MODELS = "all-proxy-models"
MAX_POLICY_MODELS = 32
MAX_MODEL_LIMITS_JSON_BYTES = 8192
MODEL_REQUEST_OUTPUT_MAX = 1_000_000
MODEL_MINUTE_OUTPUT_MAX = 1_000_000_000
MODEL_LIMIT_FIELDS = frozenset(
    {"max_output_tokens_per_request", "output_tokens_per_utc_minute"}
)
OUTPUT_CALL_TYPES = frozenset(
    {
        "completion",
        "acompletion",
        "text_completion",
        "atext_completion",
        "anthropic_messages",
        "responses",
        "aresponses",
    }
)
OUTPUT_TOKEN_FIELDS = (
    "max_tokens",
    "max_completion_tokens",
    "max_output_tokens",
)
LIMIT_CONTROLS = frozenset({"max_output_per_request", "output_tokens_per_utc_minute"})
LIMIT_ACTIONS = frozenset({"reserve", "deny", "fail_closed"})
LIMIT_OUTCOMES = frozenset({"success", "denied", "failure"})
LIMIT_REASONS = frozenset(
    {
        "request_cap_exceeded",
        "minute_quota_exceeded",
        "capacity_reserved",
        "policy_invalid",
        "redis_unavailable",
    }
)

logger = logging.getLogger("litellm.aigw_model_limits")

# Redis TIME is the only clock for the fixed UTC bucket. INFO runs in the same
# script so a restart cannot race an earlier health check. A Redis process that
# started after this minute began returns -1 until the next minute.
_RESERVE_OUTPUT_LUA = r"""
local now = redis.call('TIME')
local now_seconds = tonumber(now[1])
local minute = math.floor(now_seconds / 60)
local second_in_minute = now_seconds % 60
local expected_minute = tonumber(ARGV[3])
if expected_minute == nil or expected_minute ~= minute then
  return {-3, 0, minute}
end
local info = redis.call('INFO', 'server')
local uptime = tonumber(string.match(info, 'uptime_in_seconds:(%d+)'))
if uptime == nil or uptime < second_in_minute then
  return {-1, 0, minute}
end
local amount = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
if amount == nil or limit == nil or amount < 1 or limit < 1 or amount > limit then
  return {-2, 0, minute}
end
local key = KEYS[1]
local current_raw = redis.call('GET', key)
local current = tonumber(current_raw) or 0
if current + amount > limit then
  return {0, current, minute}
end
local total = redis.call('INCRBY', key, amount)
redis.call('EXPIREAT', key, (minute + 2) * 60)
return {1, total, minute}
"""


class LimitStoreUnavailable(Exception):
    """Redis could not prove that requested output capacity is available."""


def _deny(detail: str, status_code: int = 400) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"error": detail})


def _audit_limit(
    action: str,
    outcome: str,
    project: str,
    model: str,
    control: str,
    reason: str,
) -> None:
    """Write one bounded security event with no prompt or request identity."""

    if (
        action not in LIMIT_ACTIONS
        or outcome not in LIMIT_OUTCOMES
        or control not in LIMIT_CONTROLS
        or reason not in LIMIT_REASONS
        or PROJECT_ID_RE.fullmatch(project) is None
        or MODEL_NAME_RE.fullmatch(model) is None
    ):
        logger.error("model-limit security event rejected an internal value")
        return
    event = {
        "schema_version": 1,
        "event": "aigw.model.limit",
        "action": action,
        "outcome": outcome,
        "project": project,
        "model": model,
        "control": control,
        "reason": reason,
    }
    level = logging.INFO if outcome == "success" else logging.WARNING
    logger.log(
        level,
        "AIGW_SECURITY_EVENT %s",
        json.dumps(event, sort_keys=True, separators=(",", ":")),
    )


def _canonical_model_limits(raw: Any) -> dict[str, dict[str, int]]:
    """Parse one canonical, bounded model-limit metadata string."""

    if (
        not isinstance(raw, str)
        or not 1 <= len(raw.encode("utf-8")) <= MAX_MODEL_LIMITS_JSON_BYTES
    ):
        raise ValueError("model-limit metadata is invalid")
    try:
        decoded = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("model-limit metadata is invalid") from exc
    if not isinstance(decoded, dict) or not 1 <= len(decoded) <= MAX_POLICY_MODELS:
        raise ValueError("model-limit metadata is invalid")

    normalized: dict[str, dict[str, int]] = {}
    for model, limits in decoded.items():
        if (
            not isinstance(model, str)
            or MODEL_NAME_RE.fullmatch(model) is None
            or not isinstance(limits, dict)
            or set(limits) != MODEL_LIMIT_FIELDS
        ):
            raise ValueError("model-limit metadata is invalid")
        request_cap = limits["max_output_tokens_per_request"]
        minute_cap = limits["output_tokens_per_utc_minute"]
        if (
            isinstance(request_cap, bool)
            or not isinstance(request_cap, int)
            or not 1 <= request_cap <= MODEL_REQUEST_OUTPUT_MAX
            or isinstance(minute_cap, bool)
            or not isinstance(minute_cap, int)
            or not 1 <= minute_cap <= MODEL_MINUTE_OUTPUT_MAX
            or request_cap > minute_cap
        ):
            raise ValueError("model-limit metadata is invalid")
        normalized[model] = {
            "max_output_tokens_per_request": request_cap,
            "output_tokens_per_utc_minute": minute_cap,
        }

    canonical = json.dumps(
        normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    if not hmac.compare_digest(canonical, raw):
        raise ValueError("model-limit metadata is not canonical")
    return dict(sorted(normalized.items()))


class RedisOutputReservations:
    """Atomically reserve output tokens in the stack's existing Redis."""

    def __init__(self, client: Any = None) -> None:
        self._client = client

    def _redis(self) -> Any:
        if self._client is not None:
            return self._client
        host = os.environ.get("REDIS_HOST")
        password = os.environ.get("REDIS_PASSWORD")
        if host != "redis" or not isinstance(password, str) or not password:
            raise LimitStoreUnavailable
        try:
            from redis.asyncio import Redis
        except (ImportError, AttributeError) as exc:
            raise LimitStoreUnavailable from exc
        self._client = Redis(
            host=host,
            port=6379,
            password=password,
            decode_responses=False,
            socket_connect_timeout=2,
            socket_timeout=2,
            health_check_interval=30,
            max_connections=20,
        )
        return self._client

    async def reserve(
        self, project: str, model: str, amount: int, minute_limit: int
    ) -> bool:
        digest = hashlib.sha256(f"{project}\0{model}".encode("ascii")).hexdigest()
        prefix = f"aigw:model-output:v1:{digest}"
        client = self._redis()
        for attempt in range(2):
            try:
                server_time = await client.time()
                if (
                    not isinstance(server_time, (list, tuple))
                    or len(server_time) != 2
                    or isinstance(server_time[0], bool)
                    or not isinstance(server_time[0], int)
                ):
                    raise LimitStoreUnavailable
                minute = server_time[0] // 60
                result = await client.eval(
                    _RESERVE_OUTPUT_LUA,
                    1,
                    f"{prefix}:{minute}",
                    amount,
                    minute_limit,
                    minute,
                )
            except LimitStoreUnavailable:
                raise
            except Exception as exc:  # noqa: BLE001 - every Redis error denies
                raise LimitStoreUnavailable from exc
            if (
                not isinstance(result, (list, tuple))
                or len(result) != 3
                or any(
                    isinstance(value, bool) or not isinstance(value, int)
                    for value in result
                )
            ):
                raise LimitStoreUnavailable
            if result[0] == 1:
                return True
            if result[0] == 0:
                return False
            if result[0] != -3 or attempt == 1:
                raise LimitStoreUnavailable
        raise LimitStoreUnavailable


async def enforce_model_limits(
    limiter: RedisOutputReservations,
    user_api_key_dict: Any,
    data: dict[str, Any],
    call_type: Any,
) -> None:
    """Apply one key's bounded policy before provider dispatch."""

    metadata = getattr(user_api_key_dict, "metadata", None)
    if not isinstance(metadata, dict) or MODEL_LIMITS_METADATA_KEY not in metadata:
        return

    safe_project = "unknown"
    safe_model = "unknown"
    project = metadata.get("aigw_project_id")
    model = data.get("model")
    project_valid = isinstance(project, str) and PROJECT_ID_RE.fullmatch(project)
    model_valid = isinstance(model, str) and MODEL_NAME_RE.fullmatch(model)
    if project_valid:
        safe_project = project
    if model_valid:
        safe_model = model

    try:
        limits = _canonical_model_limits(metadata[MODEL_LIMITS_METADATA_KEY])
        key_models = getattr(user_api_key_dict, "models", None)
        if (
            not project_valid
            or not model_valid
            or call_type not in OUTPUT_CALL_TYPES
            or not isinstance(key_models, (list, tuple, set))
        ):
            raise ValueError("model-limit policy cannot be enforced")
        if any(
            not isinstance(item, str) or MODEL_NAME_RE.fullmatch(item) is None
            for item in key_models
        ):
            raise ValueError("model allowlist is invalid")
        allowed_models = set(key_models)
        if (
            not allowed_models
            or ALL_PROXY_MODELS in allowed_models
            or not set(limits).issubset(allowed_models)
        ):
            raise ValueError("model-limit policy is not explicitly scoped")
    except (TypeError, ValueError):
        _audit_limit(
            "fail_closed",
            "failure",
            safe_project,
            safe_model,
            "max_output_per_request",
            "policy_invalid",
        )
        raise _deny("this key's per-model output policy is invalid")

    model_limit = limits.get(safe_model)
    if model_limit is None:
        return
    request_cap = model_limit["max_output_tokens_per_request"]
    requested_caps = [
        data[field]
        for field in OUTPUT_TOKEN_FIELDS
        if field in data and data[field] is not None
    ]
    if not requested_caps:
        requested_output = request_cap
        output_field = (
            "max_output_tokens"
            if call_type in {"responses", "aresponses"}
            else "max_tokens"
        )
        data[output_field] = request_cap
    elif any(
        isinstance(value, bool) or not isinstance(value, int) or value < 1
        for value in requested_caps
    ):
        _audit_limit(
            "fail_closed",
            "failure",
            safe_project,
            safe_model,
            "max_output_per_request",
            "policy_invalid",
        )
        raise _deny("the output limit must be a positive whole number")
    else:
        requested_output = max(requested_caps)
    if requested_output > request_cap:
        _audit_limit(
            "deny",
            "denied",
            safe_project,
            safe_model,
            "max_output_per_request",
            "request_cap_exceeded",
        )
        raise _deny("requested output exceeds this project's model limit")

    try:
        reserved = await limiter.reserve(
            safe_project,
            safe_model,
            requested_output,
            model_limit["output_tokens_per_utc_minute"],
        )
    except LimitStoreUnavailable:
        _audit_limit(
            "fail_closed",
            "failure",
            safe_project,
            safe_model,
            "output_tokens_per_utc_minute",
            "redis_unavailable",
        )
        raise _deny("model output capacity is unavailable", status_code=503)
    if not reserved:
        _audit_limit(
            "deny",
            "denied",
            safe_project,
            safe_model,
            "output_tokens_per_utc_minute",
            "minute_quota_exceeded",
        )
        raise _deny("this project's model output limit is reached", status_code=429)
    _audit_limit(
        "reserve",
        "success",
        safe_project,
        safe_model,
        "output_tokens_per_utc_minute",
        "capacity_reserved",
    )
