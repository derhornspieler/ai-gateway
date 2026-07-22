"""HTTP routes for immutable governed model prices."""

from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    field_validator,
)

from app.db import Database
from app.model_catalog import MODEL_NAME_RE, ProviderPolicyReceipt
from app.model_governance_api import (
    governance_http_error,
    governance_response,
    governance_write_identity,
    trusted_provider_policy,
)
from app.pricing import PriceVersion, UsageClass, canonical_decimal


router = APIRouter()
logger = logging.getLogger("key_rotator.pricing")
SOURCE_REFERENCE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_./:#-]{0,255}")
CANONICAL_AMOUNT_RE = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]{1,12})?")
PRICE_BACKDATE_CONFIRMATION = "CONFIRM BACKDATED PRICE"
PRICE_AUDIT_ACTIONS = frozenset(
    {"create", "backdate_preview", "backdate_confirm"}
)


class GovernedPriceCreate(BaseModel):
    """One exact, immutable usage-class price candidate."""

    model_config = ConfigDict(extra="forbid")

    version_id: StrictStr
    gateway_model_name: StrictStr
    usage_class: UsageClass
    token_unit: StrictInt
    amount: StrictStr = Field(min_length=1, max_length=32)
    effective_at: datetime
    explicit_free: StrictBool
    source_reference: StrictStr = Field(min_length=1, max_length=256)
    review_note: StrictStr = Field(min_length=8, max_length=500)

    @field_validator("amount")
    @classmethod
    def validate_amount(cls, value: str) -> str:
        if CANONICAL_AMOUNT_RE.fullmatch(value) is None:
            raise ValueError("amount must be a canonical decimal string")
        return value

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


class PriceBackdateConfirm(BaseModel):
    """Confirmation binds to a stored preview, not a new price body."""

    model_config = ConfigDict(extra="forbid")

    candidate_sha256: StrictStr = Field(pattern=r"[0-9a-f]{64}")
    preview_sha256: StrictStr = Field(pattern=r"[0-9a-f]{64}")
    confirmation: StrictStr

    @field_validator("confirmation")
    @classmethod
    def validate_confirmation(cls, value: str) -> str:
        if value != PRICE_BACKDATE_CONFIRMATION:
            raise ValueError("confirmation phrase is invalid")
        return value


def _services(request: Request) -> dict[str, Any]:
    services = getattr(request.app.state, "aigw_services", None)
    if not isinstance(services, dict):
        raise HTTPException(status_code=503, detail="model governance is unavailable")
    return services


def _canonical_uuid4(value: str) -> bool:
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, TypeError, ValueError):
        return False
    return (
        parsed.variant == uuid.RFC_4122
        and parsed.version == 4
        and str(parsed) == value
    )


def _backdate_response(value: Any) -> Any:
    """Serialize nested exact decimals without converting them to floats."""

    if isinstance(value, dict):
        return {key: _backdate_response(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_backdate_response(item) for item in value]
    if isinstance(value, Decimal):
        return canonical_decimal(value)
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, uuid.UUID):
        return str(value)
    return value


def _emit_price_audit(
    row: dict[str, Any],
    *,
    action: str,
    operation_id: str,
    actor: str,
) -> None:
    """Emit one bounded event built only from the committed backend row."""

    if action not in PRICE_AUDIT_ACTIONS:
        raise RuntimeError("price audit action is not reviewed")
    model = row.get("gateway_model_name")
    provider = row.get("provider_name")
    usage_class = row.get("usage_class")
    amount = row.get("amount")
    token_unit = row.get("token_unit")
    effective_at = row.get("effective_at")
    source_reference = row.get("source_reference")
    review_note = row.get("review_note")
    old_policy_sha256 = row.get("baseline_price_policy_sha256")
    candidate_sha256 = row.get("candidate_sha256", row.get("document_sha256"))
    if isinstance(amount, Decimal):
        amount_text = canonical_decimal(amount)
    else:
        amount_text = amount
    if (
        isinstance(effective_at, datetime)
        and effective_at.tzinfo is not None
        and effective_at.utcoffset() is not None
    ):
        effective_text = effective_at.astimezone(timezone.utc).isoformat().replace(
            "+00:00", "Z"
        )
    else:
        effective_text = None
    if (
        not _canonical_uuid4(operation_id)
        or not isinstance(actor, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}", actor) is None
        or not isinstance(model, str)
        or MODEL_NAME_RE.fullmatch(model) is None
        or provider != "anthropic"
        or usage_class not in {item.value for item in UsageClass}
        or not isinstance(amount_text, str)
        or CANONICAL_AMOUNT_RE.fullmatch(amount_text) is None
        or isinstance(token_unit, bool)
        or not isinstance(token_unit, int)
        or not 1 <= token_unit <= 1_000_000_000
        or not isinstance(effective_text, str)
        or not isinstance(source_reference, str)
        or "://" in source_reference
        or SOURCE_REFERENCE_RE.fullmatch(source_reference) is None
        or not isinstance(review_note, str)
        or not 8 <= len(review_note) <= 500
        or review_note != review_note.strip()
        or any(ord(character) < 32 for character in review_note)
        or not isinstance(old_policy_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", old_policy_sha256) is None
        or not isinstance(candidate_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", candidate_sha256) is None
    ):
        raise RuntimeError("committed price audit evidence is invalid")
    event = {
        "schema_version": 1,
        "event": "aigw.price.audit",
        "action": action,
        "outcome": "success",
        "operation_id": operation_id,
        "subject": actor,
        "model": model,
        "provider": provider,
        "usage_class": usage_class,
        "amount_usd": amount_text,
        "token_unit": str(token_unit),
        "effective_at": effective_text,
        "source_reference": source_reference,
        "review_note_sha256": hashlib.sha256(
            review_note.encode("utf-8")
        ).hexdigest(),
        "old_policy_sha256": old_policy_sha256,
        "candidate_sha256": candidate_sha256,
    }
    logger.info(
        "AIGW_SECURITY_EVENT %s",
        json.dumps(event, sort_keys=True, separators=(",", ":")),
    )


def _audit_committed_price(
    row: dict[str, Any],
    *,
    action: str,
    operation_id: str,
    actor: str,
) -> None:
    replayed = row.pop("_operation_replayed", False)
    if type(replayed) is not bool:
        raise RuntimeError("price operation replay state is invalid")
    if not replayed:
        _emit_price_audit(
            row,
            action=action,
            operation_id=operation_id,
            actor=actor,
        )


def _price_from_request(
    body: GovernedPriceCreate,
    *,
    provider_name: str,
) -> PriceVersion:
    if MODEL_NAME_RE.fullmatch(body.gateway_model_name) is None:
        raise HTTPException(status_code=422, detail="gateway model name is invalid")
    try:
        amount = Decimal(body.amount)
        return PriceVersion(
            version_id=body.version_id,
            provider=provider_name,
            model=body.gateway_model_name,
            usage_class=body.usage_class,
            token_unit=body.token_unit,
            amount=amount,
            effective_at=body.effective_at,
            explicit_free=body.explicit_free,
        )
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="price candidate is invalid") from exc


async def _governed_model_for_price(
    db: Database,
    receipt: ProviderPolicyReceipt,
    gateway_model_name: str,
) -> dict[str, Any]:
    if MODEL_NAME_RE.fullmatch(gateway_model_name) is None:
        raise HTTPException(status_code=422, detail="gateway model name is invalid")
    try:
        model = await db.get_governed_model(
            gateway_model_name,
            egress_policy_sha256=receipt.egress_policy_sha256,
        )
    except Exception as exc:  # noqa: BLE001
        raise governance_http_error(exc) from exc
    if model is None:
        raise HTTPException(status_code=404, detail="governed model does not exist")
    return model


@router.post(
    "/model-governance/prices",
    status_code=status.HTTP_201_CREATED,
)
async def create_governed_price(
    body: GovernedPriceCreate,
    request: Request,
) -> dict[str, Any]:
    services = _services(request)
    receipt = trusted_provider_policy(services)
    operation_id, actor = governance_write_identity(request)
    db: Database = services["db"]
    model = await _governed_model_for_price(
        db, receipt, body.gateway_model_name
    )
    price = _price_from_request(body, provider_name=model["provider_name"])
    if price.effective_at <= datetime.now(timezone.utc):
        raise HTTPException(
            status_code=409,
            detail="a past or current effective date requires backdate preview",
        )
    try:
        row = await db.create_governed_price(
            price,
            model_operation_id=str(model["operation_id"]),
            gateway_model_name=body.gateway_model_name,
            egress_policy_sha256=receipt.egress_policy_sha256,
            operation_id=operation_id,
            actor=actor,
            source_reference=body.source_reference,
            review_note=body.review_note,
        )
    except Exception as exc:  # noqa: BLE001
        raise governance_http_error(exc) from exc
    _audit_committed_price(
        row,
        action="create",
        operation_id=operation_id,
        actor=actor,
    )
    return governance_response(row)


@router.get("/model-governance/models/{gateway_model_name}/prices")
async def list_governed_prices(
    gateway_model_name: str,
    request: Request,
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0, le=10_000),
) -> list[dict[str, Any]]:
    services = _services(request)
    receipt = trusted_provider_policy(services)
    db: Database = services["db"]
    model = await _governed_model_for_price(db, receipt, gateway_model_name)
    try:
        rows = await db.list_governed_prices(
            model_operation_id=str(model["operation_id"]),
            limit=limit,
            offset=offset,
        )
    except Exception as exc:  # noqa: BLE001
        raise governance_http_error(exc) from exc
    return [governance_response(row) for row in rows]


@router.post(
    "/model-governance/prices/backdate/preview",
    status_code=status.HTTP_201_CREATED,
)
async def preview_price_backdate(
    body: GovernedPriceCreate,
    request: Request,
) -> dict[str, Any]:
    services = _services(request)
    receipt = trusted_provider_policy(services)
    preview_id, actor = governance_write_identity(request)
    db: Database = services["db"]
    model = await _governed_model_for_price(
        db, receipt, body.gateway_model_name
    )
    price = _price_from_request(body, provider_name=model["provider_name"])
    if price.effective_at > datetime.now(timezone.utc):
        raise HTTPException(
            status_code=409,
            detail="a future effective date must use the normal price route",
        )
    try:
        row = await db.create_price_backdate_preview(
            price,
            model_operation_id=str(model["operation_id"]),
            gateway_model_name=body.gateway_model_name,
            egress_policy_sha256=receipt.egress_policy_sha256,
            preview_id=preview_id,
            actor=actor,
            source_reference=body.source_reference,
            review_note=body.review_note,
        )
    except Exception as exc:  # noqa: BLE001
        raise governance_http_error(exc) from exc
    _audit_committed_price(
        row,
        action="backdate_preview",
        operation_id=preview_id,
        actor=actor,
    )
    return _backdate_response(row)


@router.post(
    "/model-governance/prices/backdate/{preview_id}/confirm",
    status_code=status.HTTP_201_CREATED,
)
async def confirm_price_backdate(
    preview_id: str,
    body: PriceBackdateConfirm,
    request: Request,
) -> dict[str, Any]:
    if not _canonical_uuid4(preview_id):
        raise HTTPException(status_code=404, detail="backdate preview does not exist")
    services = _services(request)
    receipt = trusted_provider_policy(services)
    operation_id, actor = governance_write_identity(request)
    db: Database = services["db"]
    try:
        row = await db.confirm_price_backdate(
            preview_id=preview_id,
            candidate_sha256=body.candidate_sha256,
            preview_sha256=body.preview_sha256,
            confirmation_operation_id=operation_id,
            actor=actor,
            expected_egress_policy_sha256=receipt.egress_policy_sha256,
        )
    except Exception as exc:  # noqa: BLE001
        raise governance_http_error(exc) from exc
    _audit_committed_price(
        row,
        action="backdate_confirm",
        operation_id=operation_id,
        actor=actor,
    )
    return _backdate_response(row)


@router.get("/model-governance/audit")
async def list_governance_audit(
    request: Request,
    limit: int = Query(default=100, ge=1, le=200),
) -> list[dict[str, Any]]:
    services = _services(request)
    trusted_provider_policy(services)
    db: Database = services["db"]
    try:
        rows = await db.governance_audit(limit=limit)
    except Exception as exc:  # noqa: BLE001
        raise governance_http_error(exc) from exc
    return [governance_response(row) for row in rows]
