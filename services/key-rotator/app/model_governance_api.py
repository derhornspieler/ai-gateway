"""HTTP control plane for governed runtime models.

This router owns model drafts and lifecycle events.  Pricing and usage have
their own modules so the service entry point stays wiring, not business logic.
"""

from __future__ import annotations

import asyncio
import logging
import re
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictStr,
    ValidationError,
    field_validator,
)

from app.db import Database, GovernanceConflict, GovernanceNotFound
from app.identity import IdentityError
from app.model_catalog import (
    ModelCatalogError,
    ModelDraftInput,
    ProviderPolicyReceipt,
    resolve_model_draft,
)
from app.model_lifecycle import ModelLifecycleAction
from app.pricing import canonical_decimal


logger = logging.getLogger("key_rotator.model_governance")
router = APIRouter()

GOVERNANCE_ACTOR_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}")
SOURCE_REFERENCE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_./:#-]{0,255}")


class GovernedModelCreate(BaseModel):
    """The few operator-owned fields allowed in a model draft."""

    model_config = ConfigDict(extra="forbid")

    gateway_model_name: StrictStr
    provider_name: StrictStr
    provider_model_id: StrictStr
    visible_in_discovery: StrictBool
    source_reference: StrictStr = Field(min_length=1, max_length=256)
    review_note: StrictStr = Field(min_length=8, max_length=500)

    @field_validator("source_reference")
    @classmethod
    def validate_source_reference(cls, value: str) -> str:
        if "://" in value or SOURCE_REFERENCE_RE.fullmatch(value) is None:
            raise ValueError("source_reference must be a reviewed reference ID")
        return value

    @field_validator("review_note")
    @classmethod
    def validate_review_note(cls, value: str) -> str:
        if value != value.strip() or any(ord(character) < 32 for character in value):
            raise ValueError("review_note must be plain bounded text")
        return value


def governance_write_identity(request: Request) -> tuple[str, str]:
    """Read one canonical idempotency UUID and one bounded actor ID."""

    operation_values = request.headers.getlist("X-AIGW-Operation-ID")
    actor_values = request.headers.getlist("X-AIGW-Actor-ID")
    if len(operation_values) != 1:
        raise HTTPException(
            status_code=400, detail="missing or invalid governance operation ID"
        )
    try:
        parsed = uuid.UUID(operation_values[0])
    except (AttributeError, TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=400, detail="missing or invalid governance operation ID"
        ) from exc
    if (
        parsed.variant != uuid.RFC_4122
        or parsed.version != 4
        or str(parsed) != operation_values[0]
    ):
        raise HTTPException(
            status_code=400, detail="missing or invalid governance operation ID"
        )
    if (
        len(actor_values) != 1
        or GOVERNANCE_ACTOR_RE.fullmatch(actor_values[0]) is None
    ):
        raise HTTPException(
            status_code=400, detail="missing or invalid governance actor ID"
        )
    return operation_values[0], actor_values[0]


def trusted_provider_policy(services: dict[str, Any]) -> ProviderPolicyReceipt:
    """Return only the receipt verified against deployment trust at startup."""

    receipt = services.get("provider_policy")
    if not isinstance(receipt, ProviderPolicyReceipt):
        raise HTTPException(
            status_code=503,
            detail="model governance is unavailable: provider policy is not trusted",
        )
    return receipt


def governance_http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, GovernanceNotFound):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, GovernanceConflict):
        return HTTPException(status_code=409, detail=str(exc))
    logger.error("model governance persistence failed")
    return HTTPException(
        status_code=503, detail="model governance persistence failed"
    )


def governance_response(row: dict[str, Any]) -> dict[str, Any]:
    """Keep exact decimals and UTC timestamps stable at the JSON boundary."""

    result: dict[str, Any] = {}
    for key, value in row.items():
        if isinstance(value, Decimal):
            result[key] = canonical_decimal(value)
        elif isinstance(value, datetime):
            result[key] = value.astimezone(timezone.utc).isoformat().replace(
                "+00:00", "Z"
            )
        elif isinstance(value, uuid.UUID):
            result[key] = str(value)
        else:
            result[key] = value
    return result


def _services(request: Request) -> dict[str, Any]:
    services = getattr(request.app.state, "aigw_services", None)
    if not isinstance(services, dict):
        raise HTTPException(status_code=503, detail="model governance is unavailable")
    return services


def model_policy_lock(services: dict[str, Any]) -> asyncio.Lock:
    """One process-local fence for assignment and retirement decisions."""

    lock = services.get("model_policy_lock")
    if lock is None:
        lock = asyncio.Lock()
        services["model_policy_lock"] = lock
    if not isinstance(lock, asyncio.Lock):
        raise HTTPException(status_code=503, detail="model policy lock is unavailable")
    return lock


async def _run_reconciliation(services: dict[str, Any]) -> None:
    reconciler = services.get("model_reconciler")
    if reconciler is None:
        raise HTTPException(
            status_code=503, detail="model reconciliation is unavailable"
        )
    try:
        await reconciler.reconcile()
    except Exception as exc:  # noqa: BLE001
        logger.error("model reconciliation failed after a lifecycle change")
        raise HTTPException(
            status_code=503,
            detail="model change is recorded but runtime reconciliation failed",
        ) from exc


@router.post("/model-governance/models", status_code=status.HTTP_201_CREATED)
async def create_governed_model(
    body: GovernedModelCreate,
    request: Request,
) -> dict[str, Any]:
    services = _services(request)
    receipt = trusted_provider_policy(services)
    settings = services.get("settings")
    egress_origin = getattr(settings, "egress_base", None)
    if not isinstance(egress_origin, str):
        raise HTTPException(
            status_code=503,
            detail="model governance is unavailable: egress is not configured",
        )
    operation_id, actor = governance_write_identity(request)
    try:
        model = resolve_model_draft(
            ModelDraftInput(
                gateway_model_name=body.gateway_model_name,
                provider_name=body.provider_name,
                provider_model_id=body.provider_model_id,
                visible_in_discovery=body.visible_in_discovery,
            ),
            receipt,
            egress_origin=egress_origin,
        )
    except (ModelCatalogError, ValidationError) as exc:
        raise HTTPException(status_code=422, detail="model candidate is invalid") from exc

    db: Database = services["db"]
    try:
        row = await db.create_governed_model(
            model,
            operation_id=operation_id,
            actor=actor,
            source_reference=body.source_reference,
            review_note=body.review_note,
        )
    except Exception as exc:  # noqa: BLE001
        raise governance_http_error(exc) from exc
    return governance_response(row)


@router.get("/model-governance/models")
async def list_governed_models(
    request: Request,
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0, le=10_000),
) -> list[dict[str, Any]]:
    services = _services(request)
    receipt = trusted_provider_policy(services)
    db: Database = services["db"]
    try:
        rows = await db.list_governed_models(
            egress_policy_sha256=receipt.egress_policy_sha256,
            visible_only=False,
            limit=limit,
            offset=offset,
        )
    except Exception as exc:  # noqa: BLE001
        raise governance_http_error(exc) from exc
    return [governance_response(row) for row in rows]


@router.get("/model-governance/discovery")
async def list_discoverable_models(request: Request) -> dict[str, list[dict[str, str]]]:
    """Return active, visible, governed dynamic deployments only."""

    services = _services(request)
    receipt = trusted_provider_policy(services)
    db: Database = services["db"]
    try:
        rows = await db.list_governed_models(
            egress_policy_sha256=receipt.egress_policy_sha256,
            visible_only=True,
            limit=200,
            offset=0,
        )
    except Exception as exc:  # noqa: BLE001
        raise governance_http_error(exc) from exc
    return {
        "models": [
            {
                "id": row["gateway_model_name"],
                "provider": row["provider_name"],
                "deployment_id": str(row["operation_id"]),
            }
            for row in rows
        ]
    }


async def _append_lifecycle(
    request: Request,
    gateway_model_name: str,
    action: ModelLifecycleAction,
) -> dict[str, Any]:
    services = _services(request)
    receipt = trusted_provider_policy(services)
    operation_id, actor = governance_write_identity(request)
    db: Database = services["db"]
    try:
        row = await db.append_model_lifecycle_event(
            gateway_model_name,
            egress_policy_sha256=receipt.egress_policy_sha256,
            action=action,
            operation_id=operation_id,
            actor=actor,
        )
    except Exception as exc:  # noqa: BLE001
        raise governance_http_error(exc) from exc
    if action in {ModelLifecycleAction.ACTIVATE, ModelLifecycleAction.RETIRE}:
        await _run_reconciliation(services)
    return governance_response(row)


@router.post("/model-governance/models/{gateway_model_name:path}/activate")
async def activate_governed_model(
    gateway_model_name: str, request: Request
) -> dict[str, Any]:
    return await _append_lifecycle(
        request, gateway_model_name, ModelLifecycleAction.ACTIVATE
    )


@router.post("/model-governance/models/{gateway_model_name:path}/show")
async def show_governed_model(
    gateway_model_name: str, request: Request
) -> dict[str, Any]:
    return await _append_lifecycle(
        request, gateway_model_name, ModelLifecycleAction.SHOW
    )


@router.post("/model-governance/models/{gateway_model_name:path}/hide")
async def hide_governed_model(
    gateway_model_name: str, request: Request
) -> dict[str, Any]:
    return await _append_lifecycle(
        request, gateway_model_name, ModelLifecycleAction.HIDE
    )


@router.post("/model-governance/models/{gateway_model_name:path}/retire")
async def retire_governed_model(
    gateway_model_name: str, request: Request
) -> dict[str, Any]:
    services = _services(request)
    identity = services.get("identity")
    if identity is None:
        raise HTTPException(status_code=503, detail="identity policy is unavailable")
    async with model_policy_lock(services):
        try:
            assigned = await identity.projects_assigning_model(gateway_model_name)
        except IdentityError as exc:
            raise HTTPException(
                status_code=503, detail="could not verify model assignments"
            ) from exc
        if assigned:
            raise HTTPException(
                status_code=409,
                detail="model is still assigned to one or more projects",
            )
        return await _append_lifecycle(
            request, gateway_model_name, ModelLifecycleAction.RETIRE
        )
