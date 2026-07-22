"""Authenticated HTTP boundary for prompt-free usage evidence.

The LiteLLM usage token is accepted on one route only. Authentication and a
small body-size gate run before JSON parsing, so an unauthenticated caller
cannot use validation errors as an oracle. Unknown JSON keys are rejected by
``UsageEvent`` and never reach PostgreSQL or logs.
"""

from __future__ import annotations

import hmac
import json
import logging
from typing import Any, Protocol

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.usage import (
    UsageConflict,
    UsageEvent,
    UsageStoreUnavailable,
    UsageWriteResult,
)


USAGE_AUTH_HEADER = "X-AIGW-Usage-Auth"
MAX_USAGE_BODY_BYTES = 16 * 1024
logger = logging.getLogger("key_rotator.usage")
router = APIRouter()


class UsageStore(Protocol):
    """The one persistence operation needed by this HTTP boundary."""

    async def record_usage(self, event: UsageEvent) -> UsageWriteResult: ...


def _services(request: Request) -> dict[str, Any]:
    services = getattr(request.app.state, "aigw_services", None)
    if not isinstance(services, dict):
        raise HTTPException(status_code=503, detail="usage accounting is unavailable")
    return services


def _authenticate(request: Request, services: dict[str, Any]) -> None:
    """Require one exact token without parsing the request document first."""

    expected = services.get("usage_token")
    supplied = request.headers.getlist(USAGE_AUTH_HEADER)
    if (
        not isinstance(expected, str)
        or len(expected) != 64
        or len(supplied) != 1
        or len(supplied[0]) != 64
        or not hmac.compare_digest(supplied[0], expected)
    ):
        raise HTTPException(status_code=401, detail="usage authentication failed")


async def _bounded_json_object(request: Request) -> dict[str, Any]:
    """Read one duplicate-free JSON object through a hard byte limit."""

    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_USAGE_BODY_BYTES:
            raise HTTPException(status_code=413, detail="usage event is too large")
        chunks.append(chunk)

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON number: {value}")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    try:
        document = json.loads(
            b"".join(chunks),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="usage event is invalid") from exc
    if not isinstance(document, dict):
        raise HTTPException(status_code=422, detail="usage event must be an object")
    return document


def _audit(event: UsageEvent, *, action: str, outcome: str) -> None:
    """Emit one fixed, prompt-free record for Alloy's Cribl projection."""

    if action not in {"record", "replay", "write_failed", "conflict"}:
        raise RuntimeError("usage audit action is not reviewed")
    if outcome not in {"success", "failure"}:
        raise RuntimeError("usage audit outcome is not reviewed")
    audit = {
        "schema_version": 1,
        "event": "aigw.usage.audit",
        "action": action,
        "outcome": outcome,
        "event_id": event.event_id,
        "request_id": event.request_id,
        "provider": event.provider,
        "model": event.requested_model or "unattributed",
        "project": event.project_id or "unattributed",
        "subject": event.stable_user_id or "unattributed",
        "completeness": event.usage_completeness,
    }
    logger.info(
        "AIGW_SECURITY_EVENT %s",
        json.dumps(audit, sort_keys=True, separators=(",", ":")),
    )


@router.post("/usage/events")
async def record_usage(request: Request) -> JSONResponse:
    """Validate and append one terminal LiteLLM usage event."""

    services = _services(request)
    _authenticate(request, services)
    document = await _bounded_json_object(request)
    try:
        event = UsageEvent.model_validate(document)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail="usage event is invalid") from exc

    store = services.get("usage_store")
    if store is None or not callable(getattr(store, "record_usage", None)):
        raise HTTPException(status_code=503, detail="usage accounting is unavailable")
    try:
        result = await store.record_usage(event)
    except UsageConflict as exc:
        _audit(event, action="conflict", outcome="failure")
        raise HTTPException(status_code=409, detail="usage event ID was reused") from exc
    except UsageStoreUnavailable as exc:
        _audit(event, action="write_failed", outcome="failure")
        raise HTTPException(status_code=503, detail="usage accounting is unavailable") from exc
    except Exception as exc:  # noqa: BLE001
        _audit(event, action="write_failed", outcome="failure")
        raise HTTPException(status_code=503, detail="usage accounting is unavailable") from exc

    if not isinstance(result, UsageWriteResult) or result.event_id != event.event_id:
        _audit(event, action="write_failed", outcome="failure")
        raise HTTPException(status_code=503, detail="usage accounting is unavailable")

    action = "record" if result.created else "replay"
    _audit(event, action=action, outcome="success")
    response = JSONResponse(
        status_code=201 if result.created else 200,
        content={"event_id": event.event_id, "created": result.created},
    )
    response.headers["Cache-Control"] = "no-store"
    return response
