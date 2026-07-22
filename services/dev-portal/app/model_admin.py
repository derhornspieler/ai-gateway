"""Small admin-portal helpers for governed model lifecycle actions."""

from __future__ import annotations

import math
import re
import uuid
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Any
from urllib.parse import quote, urlencode

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

from . import auth


MODEL_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_./:-]{0,127}$"
MODEL_NAME_RE = re.compile(MODEL_NAME_PATTERN)
ANTHROPIC_MODEL_ID_PATTERN = r"^[a-z0-9](?:[a-z0-9-]{0,126}[a-z0-9])?$"
ANTHROPIC_MODEL_ID_RE = re.compile(ANTHROPIC_MODEL_ID_PATTERN)
ACTOR_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$")
SOURCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./:#-]{0,255}$")
PRICE_AMOUNT_RE = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]{1,12})?$")
SIGNED_COST_RE = re.compile(r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]{1,50})?$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
LOCAL_TIME_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}(?::[0-9]{2})?$"
)
APPROVED_PROVIDERS = frozenset({"anthropic"})
RESERVED_NAMES = frozenset({"aigw-auto", "aigw-default", "all-proxy-models"})
USAGE_CLASSES = (
    ("normal_input", "Normal input"),
    ("cache_creation_5m", "Cache write (5 minutes)"),
    ("cache_creation_1h", "Cache write (1 hour)"),
    ("cache_read", "Cache read"),
    ("output", "Output"),
)
USAGE_CLASS_NAMES = dict(USAGE_CLASSES)
AUDIT_ACTIONS = frozenset(
    {
        "model_version_created",
        "model_activate",
        "model_show",
        "model_hide",
        "model_retire",
        "price_version_created",
        "price_backdate_previewed",
        "price_backdate_confirmed",
    }
)
AUDIT_RESOURCE_TYPE = {
    "model_version_created": "model_version",
    "model_activate": "model_version",
    "model_show": "model_version",
    "model_hide": "model_version",
    "model_retire": "model_version",
    "price_version_created": "price_version",
    "price_backdate_previewed": "price_backdate_preview",
    "price_backdate_confirmed": "price_version",
}
MAX_MODELS = 64
MAX_PRICES = 100
MAX_AUDIT_ROWS = 50
MAX_BACKDATE_PREVIEW_ROWS = 100
MAX_PRICE_AMOUNT = Decimal("1000000")
MAX_TOKEN_UNIT = 1_000_000_000
PRICE_BACKDATE_CONFIRMATION = "CONFIRM BACKDATED PRICE"
ACTIONS = {
    "activate": ("model.governance.activate", "Model activated."),
    "show": ("model.governance.show", "Model is now visible in discovery."),
    "hide": ("model.governance.hide", "Model is now hidden from discovery."),
    "retire": ("model.governance.retire", "Model retired."),
}


def admin_location(model_name: str = "") -> str:
    location = "/admin"
    if model_name:
        location += "?" + urlencode({"price_model": model_name})
    return location + "#tab-models"


def _canonical_operation_id(value: Any) -> bool:
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, TypeError, ValueError):
        return False
    return (
        parsed.variant == uuid.RFC_4122
        and parsed.version == 4
        and str(parsed) == value
    )


def _governance_text(value: Any, *, minimum: int, maximum: int) -> str | None:
    """Return bounded, single-line operator text or ``None``."""

    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        return None
    if value != value.strip() or any(ord(character) < 32 for character in value):
        return None
    return value


def _governance_source_reference(value: Any) -> str | None:
    """Accept a reviewed reference ID, never a URL."""

    if (
        not isinstance(value, str)
        or "://" in value
        or SOURCE_RE.fullmatch(value) is None
    ):
        return None
    return value


def _canonical_utc_display_time(value: Any) -> str | None:
    """Normalize one bounded UTC timestamp returned by key-rotator."""

    if not isinstance(value, str) or not 1 <= len(value) <= 64:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        return None
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _price_is_exact_for_unit(amount: Decimal, token_unit: int) -> bool:
    """Mirror the controller's exact-decimal per-token rule."""

    numerator, denominator = amount.as_integer_ratio()
    denominator *= token_unit
    denominator //= math.gcd(abs(numerator), denominator)
    while denominator % 2 == 0:
        denominator //= 2
    while denominator % 5 == 0:
        denominator //= 5
    return denominator == 1


def _validated_price_amount(
    raw: str,
    *,
    token_unit: int,
    explicit_free: bool,
) -> str | None:
    """Validate an exact USD amount without converting it to binary float."""

    if PRICE_AMOUNT_RE.fullmatch(raw) is None:
        return None
    try:
        amount = Decimal(raw)
    except InvalidOperation:
        return None
    if amount > MAX_PRICE_AMOUNT:
        return None
    if (amount == 0) != explicit_free:
        return None
    if not _price_is_exact_for_unit(amount, token_unit):
        return None
    return raw


def _future_utc_price_time(raw: str) -> str | None:
    """Interpret the admin form's timezone-free value as UTC and require future."""

    if LOCAL_TIME_RE.fullmatch(raw) is None:
        return None
    try:
        parsed = datetime.fromisoformat(raw).replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    if parsed <= datetime.now(timezone.utc):
        return None
    return parsed.isoformat(timespec="seconds").replace("+00:00", "Z")


def _past_or_current_utc_price_time(raw: str) -> str | None:
    """Interpret the admin form value as UTC and reject a future time."""

    if LOCAL_TIME_RE.fullmatch(raw) is None:
        return None
    try:
        parsed = datetime.fromisoformat(raw).replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    if parsed > datetime.now(timezone.utc):
        return None
    return parsed.isoformat(timespec="seconds").replace("+00:00", "Z")


def _exact_cost(
    value: Any,
    *,
    nullable: bool = False,
    allow_negative: bool = False,
) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or SIGNED_COST_RE.fullmatch(value) is None:
        raise ValueError("backdate preview cost was invalid")
    if not allow_negative and value.startswith("-"):
        raise ValueError("backdate preview cost was invalid")
    return value


def safe_backdate_preview(raw: Any) -> dict[str, Any]:
    """Copy only the bounded preview evidence that the browser may render."""

    if not isinstance(raw, dict):
        raise ValueError("backdate preview was invalid")
    preview_id = raw.get("preview_id")
    candidate_sha256 = raw.get("candidate_sha256")
    preview_sha256 = raw.get("preview_sha256")
    model = raw.get("gateway_model_name")
    usage_class = raw.get("usage_class")
    token_unit = raw.get("token_unit")
    explicit_free = raw.get("explicit_free")
    amount = raw.get("amount")
    source_reference = _governance_source_reference(raw.get("source_reference"))
    review_note = _governance_text(
        raw.get("review_note"), minimum=8, maximum=500
    )
    affected_count = raw.get("affected_count")
    shown_count = raw.get("shown_affected_count")
    truncated = raw.get("affected_rows_truncated")
    old_unknown_count = raw.get("old_unknown_count")
    new_unknown_count = raw.get("new_unknown_count")
    effective_at = _canonical_utc_display_time(raw.get("effective_at"))
    effective_to_raw = raw.get("effective_to")
    effective_to = (
        None
        if effective_to_raw is None
        else _canonical_utc_display_time(effective_to_raw)
    )
    rows_raw = raw.get("affected_rows")
    if (
        not isinstance(preview_id, str)
        or not _canonical_operation_id(preview_id)
        or not isinstance(candidate_sha256, str)
        or SHA256_RE.fullmatch(candidate_sha256) is None
        or not isinstance(preview_sha256, str)
        or SHA256_RE.fullmatch(preview_sha256) is None
        or not isinstance(model, str)
        or MODEL_NAME_RE.fullmatch(model) is None
        or usage_class not in USAGE_CLASS_NAMES
        or isinstance(token_unit, bool)
        or not isinstance(token_unit, int)
        or not 1 <= token_unit <= MAX_TOKEN_UNIT
        or type(explicit_free) is not bool
        or not isinstance(amount, str)
        or _validated_price_amount(
            amount,
            token_unit=token_unit,
            explicit_free=explicit_free,
        )
        is None
        or source_reference is None
        or review_note is None
        or effective_at is None
        or (effective_to_raw is not None and effective_to is None)
        or isinstance(affected_count, bool)
        or not isinstance(affected_count, int)
        or not 0 <= affected_count <= 10_000
        or isinstance(shown_count, bool)
        or not isinstance(shown_count, int)
        or shown_count != min(affected_count, MAX_BACKDATE_PREVIEW_ROWS)
        or type(truncated) is not bool
        or truncated != (affected_count > shown_count)
        or isinstance(old_unknown_count, bool)
        or not isinstance(old_unknown_count, int)
        or not 0 <= old_unknown_count <= affected_count
        or isinstance(new_unknown_count, bool)
        or not isinstance(new_unknown_count, int)
        or not 0 <= new_unknown_count <= affected_count
        or not isinstance(rows_raw, list)
        or len(rows_raw) != shown_count
    ):
        raise ValueError("backdate preview was invalid")

    old_total = _exact_cost(raw.get("old_total_usd"), nullable=True)
    new_total = _exact_cost(raw.get("new_total_usd"), nullable=True)
    delta = _exact_cost(
        raw.get("delta_usd"), nullable=True, allow_negative=True
    )
    if (old_unknown_count == 0) != (old_total is not None):
        raise ValueError("backdate old total was inconsistent")
    if (new_unknown_count == 0) != (new_total is not None):
        raise ValueError("backdate new total was inconsistent")
    if (old_total is not None and new_total is not None) != (delta is not None):
        raise ValueError("backdate delta was inconsistent")
    if (
        old_total is not None
        and new_total is not None
        and Decimal(new_total) - Decimal(old_total) != Decimal(delta)
    ):
        raise ValueError("backdate delta was inconsistent")

    rows: list[dict[str, Any]] = []
    seen_events: set[str] = set()
    for item in rows_raw:
        if not isinstance(item, dict):
            raise ValueError("backdate affected row was invalid")
        event_id = item.get("usage_event_id")
        row_sha256 = item.get("row_sha256")
        units = item.get("units")
        if (
            not isinstance(event_id, str)
            or SHA256_RE.fullmatch(event_id) is None
            or event_id in seen_events
            or item.get("usage_class") != usage_class
            or isinstance(units, bool)
            or not isinstance(units, int)
            or units <= 0
            or not isinstance(row_sha256, str)
            or SHA256_RE.fullmatch(row_sha256) is None
        ):
            raise ValueError("backdate affected row was invalid")
        seen_events.add(event_id)
        previous_component = _exact_cost(
            item.get("previous_component_cost_usd"), nullable=True
        )
        new_component = _exact_cost(item.get("new_component_cost_usd"))
        component_delta = _exact_cost(
            item.get("component_delta_usd"),
            nullable=True,
            allow_negative=True,
        )
        previous_total = _exact_cost(
            item.get("previous_total_cost_usd"), nullable=True
        )
        new_total = _exact_cost(item.get("new_total_cost_usd"), nullable=True)
        if (previous_component is None) != (component_delta is None):
            raise ValueError("backdate affected row was inconsistent")
        if (
            previous_component is not None
            and Decimal(new_component) - Decimal(previous_component)
            != Decimal(component_delta)
        ):
            raise ValueError("backdate affected row was inconsistent")
        if (
            previous_total is not None
            and (new_total is None or component_delta is None)
        ):
            raise ValueError("backdate affected row was inconsistent")
        if (
            previous_total is not None
            and new_total is not None
            and Decimal(new_total) - Decimal(previous_total)
            != Decimal(component_delta)
        ):
            raise ValueError("backdate affected row was inconsistent")
        rows.append(
            {
                "usage_event_id": event_id,
                "units": units,
                "previous_component_cost_usd": previous_component,
                "new_component_cost_usd": new_component,
                "component_delta_usd": component_delta,
                "previous_total_cost_usd": previous_total,
                "new_total_cost_usd": new_total,
                "row_sha256": row_sha256,
            }
        )

    return {
        "preview_id": preview_id,
        "candidate_sha256": candidate_sha256,
        "preview_sha256": preview_sha256,
        "gateway_model_name": model,
        "usage_class": usage_class,
        "usage_class_label": USAGE_CLASS_NAMES[usage_class],
        "amount": amount,
        "token_unit": token_unit,
        "explicit_free": explicit_free,
        "source_reference": source_reference,
        "review_note": review_note,
        "effective_at": effective_at,
        "effective_to": effective_to,
        "affected_count": affected_count,
        "shown_affected_count": shown_count,
        "affected_rows_truncated": truncated,
        "old_total_usd": old_total,
        "new_total_usd": new_total,
        "delta_usd": delta,
        "old_unknown_count": old_unknown_count,
        "new_unknown_count": new_unknown_count,
        "affected_rows": rows,
    }


def safe_backdate_confirmation(
    raw: Any,
    *,
    preview_id: str,
    candidate_sha256: str,
    preview_sha256: str,
    operation_id: str,
) -> dict[str, Any]:
    """Validate the small receipt returned after append-only confirmation."""

    if not isinstance(raw, dict):
        raise ValueError("backdate confirmation was invalid")
    affected = raw.get("affected_count")
    adjustments = raw.get("adjustment_count")
    version_id = raw.get("version_id")
    model = raw.get("gateway_model_name")
    usage_class = raw.get("usage_class")
    if (
        raw.get("preview_id") != preview_id
        or raw.get("candidate_sha256") != candidate_sha256
        or raw.get("preview_sha256") != preview_sha256
        or raw.get("confirmation_operation_id") != operation_id
        or not isinstance(version_id, str)
        or MODEL_NAME_RE.fullmatch(version_id) is None
        or not isinstance(model, str)
        or MODEL_NAME_RE.fullmatch(model) is None
        or model in RESERVED_NAMES
        or usage_class not in USAGE_CLASS_NAMES
        or isinstance(affected, bool)
        or not isinstance(affected, int)
        or not 0 <= affected <= 10_000
        or adjustments != affected
    ):
        raise ValueError("backdate confirmation was invalid")
    return {
        "version_id": version_id,
        "gateway_model_name": model,
        "usage_class": usage_class,
        "affected_count": affected,
        "adjustment_count": adjustments,
        "delta_usd": _exact_cost(
            raw.get("delta_usd"), nullable=True, allow_negative=True
        ),
    }


def safe_governed_models(raw: Any) -> list[dict[str, Any]]:
    """Copy only bounded public model fields from a rotator response."""

    if not isinstance(raw, list) or len(raw) > MAX_MODELS:
        raise ValueError("governed model list was invalid")
    rows: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("governed model row was invalid")
        name = item.get("gateway_model_name")
        provider = item.get("provider_name")
        provider_model_id = item.get("provider_model_id")
        operation_id = item.get("operation_id")
        source_reference = _governance_source_reference(
            item.get("source_reference")
        )
        review_note = _governance_text(
            item.get("review_note"), minimum=8, maximum=500
        )
        document_sha256 = item.get("document_sha256")
        created_at_raw = item.get("created_at")
        created_at = (
            _canonical_utc_display_time(created_at_raw)
            if created_at_raw is not None
            else ""
        )
        initial_visible = item.get("initial_visible_in_discovery")
        visible = item.get("visible_in_discovery")
        active = item.get("active")
        lifecycle_state = item.get("lifecycle_state")
        last_event_sequence = item.get("last_event_sequence")
        valid_lifecycle = (
            lifecycle_state == "draft"
            and active is False
            and visible is False
            and last_event_sequence is None
        ) or (
            lifecycle_state == "active"
            and active is True
            and type(visible) is bool
            and type(last_event_sequence) is int
            and last_event_sequence > 0
        ) or (
            lifecycle_state == "retired"
            and active is False
            and visible is False
            and type(last_event_sequence) is int
            and last_event_sequence > 0
        )
        if (
            not isinstance(name, str)
            or MODEL_NAME_RE.fullmatch(name) is None
            or name in seen_names
            or provider not in APPROVED_PROVIDERS
            or not isinstance(provider_model_id, str)
            or ANTHROPIC_MODEL_ID_RE.fullmatch(provider_model_id) is None
            or type(initial_visible) is not bool
            or not valid_lifecycle
            or not isinstance(operation_id, str)
            or not _canonical_operation_id(operation_id)
            or source_reference is None
            or review_note is None
            or not isinstance(document_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", document_sha256) is None
            or (created_at_raw is not None and created_at is None)
        ):
            raise ValueError("governed model row was invalid")
        seen_names.add(name)
        rows.append(
            {
                "gateway_model_name": name,
                "provider_name": provider,
                "provider_model_id": provider_model_id,
                "initial_visible_in_discovery": initial_visible,
                "visible_in_discovery": visible,
                "active": active,
                "lifecycle_state": lifecycle_state,
                "last_event_sequence": last_event_sequence,
                "operation_id": operation_id,
                "source_reference": source_reference,
                "review_note": review_note,
                "document_sha256": document_sha256,
                "created_at": created_at,
            }
        )
    return sorted(rows, key=lambda row: row["gateway_model_name"])


def safe_governed_prices(
    raw: Any,
    *,
    gateway_model_name: str,
) -> list[dict[str, Any]]:
    """Copy only bounded, exact price fields for the selected model."""

    if not isinstance(raw, list) or len(raw) > MAX_PRICES:
        raise ValueError("governed price list was invalid")
    rows: list[dict[str, Any]] = []
    seen_versions: set[str] = set()
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("governed price row was invalid")
        version_id = item.get("version_id")
        operation_id = item.get("operation_id")
        provider = item.get("provider_name")
        usage_class = item.get("usage_class")
        token_unit = item.get("token_unit")
        amount = item.get("amount")
        explicit_free = item.get("explicit_free")
        effective_at = _canonical_utc_display_time(item.get("effective_at"))
        source_reference = _governance_source_reference(
            item.get("source_reference")
        )
        review_note = _governance_text(
            item.get("review_note"), minimum=8, maximum=500
        )
        document_sha256 = item.get("document_sha256")
        if (
            not isinstance(version_id, str)
            or MODEL_NAME_RE.fullmatch(version_id) is None
            or version_id in seen_versions
            or not isinstance(operation_id, str)
            or not _canonical_operation_id(operation_id)
            or item.get("gateway_model_name") != gateway_model_name
            or provider not in APPROVED_PROVIDERS
            or usage_class not in USAGE_CLASS_NAMES
            or isinstance(token_unit, bool)
            or not isinstance(token_unit, int)
            or not 1 <= token_unit <= MAX_TOKEN_UNIT
            or not isinstance(amount, str)
            or not isinstance(explicit_free, bool)
            or _validated_price_amount(
                amount,
                token_unit=token_unit,
                explicit_free=explicit_free,
            )
            is None
            or item.get("currency") != "USD"
            or effective_at is None
            or source_reference is None
            or review_note is None
            or not isinstance(document_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", document_sha256) is None
        ):
            raise ValueError("governed price row was invalid")
        seen_versions.add(version_id)
        rows.append(
            {
                "version_id": version_id,
                "gateway_model_name": gateway_model_name,
                "provider_name": provider,
                "usage_class": usage_class,
                "usage_class_label": USAGE_CLASS_NAMES[usage_class],
                "token_unit": token_unit,
                "amount": amount,
                "currency": "USD",
                "explicit_free": explicit_free,
                "effective_at": effective_at,
                "source_reference": source_reference,
                "review_note": review_note,
                "document_sha256": document_sha256,
            }
        )
    return sorted(
        rows,
        key=lambda row: (
            row["effective_at"],
            row["usage_class"],
            row["version_id"],
        ),
        reverse=True,
    )


def safe_governance_audit(raw: Any) -> list[dict[str, str]]:
    """Validate the append-only governance evidence shown to administrators."""

    if not isinstance(raw, list) or len(raw) > MAX_AUDIT_ROWS:
        raise ValueError("model-governance audit list was invalid")
    rows: list[dict[str, str]] = []
    seen_operations: set[str] = set()
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("model-governance audit row was invalid")
        operation_id = item.get("operation_id")
        actor = item.get("actor")
        action = item.get("action")
        resource_type = item.get("resource_type")
        resource_id = item.get("resource_id")
        document_sha256 = item.get("document_sha256")
        created_at = _canonical_utc_display_time(item.get("created_at"))
        if (
            not isinstance(operation_id, str)
            or not _canonical_operation_id(operation_id)
            or operation_id in seen_operations
            or not isinstance(actor, str)
            or ACTOR_RE.fullmatch(actor) is None
            or action not in AUDIT_ACTIONS
            or AUDIT_RESOURCE_TYPE.get(action) != resource_type
            or not isinstance(resource_id, str)
            or MODEL_NAME_RE.fullmatch(resource_id) is None
            or not isinstance(document_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", document_sha256) is None
            or created_at is None
        ):
            raise ValueError("model-governance audit row was invalid")
        seen_operations.add(operation_id)
        rows.append(
            {
                "operation_id": operation_id,
                "actor": actor,
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "document_sha256": document_sha256,
                "created_at": created_at,
            }
        )
    return rows
async def apply_lifecycle_action(
    *,
    request: Request,
    user: dict[str, Any],
    gateway_model_name: str,
    action: str,
    csrf_token: str,
    rotator_post: Callable[..., Awaitable[Any]],
    audit: Callable[..., None],
    mutation_result: Callable[[Exception], str],
) -> RedirectResponse:
    """Validate, audit, and send one step-up-protected lifecycle event."""

    redirect = RedirectResponse(
        admin_location(gateway_model_name), status_code=303
    )
    if not auth.verify_csrf(request, csrf_token):
        auth.flash(request, "Your session expired — please try again.", "error")
        return redirect
    if MODEL_NAME_RE.fullmatch(gateway_model_name) is None or action not in ACTIONS:
        auth.flash(request, "The model action was invalid.", "error")
        return redirect

    audit_action, success_message = ACTIONS[action]
    operation_id = str(uuid.uuid4())
    actor_id = str(user["sub"])
    audit(
        audit_action,
        "intent",
        user,
        model=gateway_model_name,
        operation_id=operation_id,
    )
    try:
        encoded_model = quote(gateway_model_name, safe="")
        await rotator_post(
            f"/model-governance/models/{encoded_model}/{action}",
            {},
            operation_id=operation_id,
            actor_id=actor_id,
        )
        audit(
            audit_action,
            "success",
            user,
            model=gateway_model_name,
            operation_id=operation_id,
        )
        auth.flash(request, success_message, "success")
    except Exception as exc:  # noqa: BLE001 - upstream details stay internal
        audit(
            audit_action,
            mutation_result(exc),
            user,
            model=gateway_model_name,
            operation_id=operation_id,
        )
        if action == "retire":
            message = "The model was not retired. Remove project assignments first."
        else:
            message = "The model action failed. Existing model state was kept."
        auth.flash(request, message, "error")
    return redirect


def build_router(
    *,
    require_recent_live_admin: Callable[..., Awaitable[dict[str, Any]]],
    rotator_post: Callable[..., Awaitable[Any]],
    render_backdate_preview: Callable[..., Any],
    audit: Callable[..., None],
    mutation_result: Callable[[Exception], str],
) -> APIRouter:
    """Build the admin-only model router with the portal's auth dependency."""

    router = APIRouter()

    @router.post("/admin/model-governance/models")
    async def create_model(
        request: Request,
        user: dict[str, Any] = Depends(require_recent_live_admin),
        gateway_model_name: str = Form(
            ..., min_length=1, max_length=128, pattern=MODEL_NAME_PATTERN
        ),
        provider_name: str = Form(..., min_length=1, max_length=63),
        provider_model_id: str = Form(
            ..., min_length=1, max_length=128, pattern=ANTHROPIC_MODEL_ID_PATTERN
        ),
        source_reference: str = Form(..., min_length=1, max_length=256),
        review_note: str = Form(..., min_length=8, max_length=500),
        csrf_token: str = Form(..., min_length=32, max_length=128),
    ) -> RedirectResponse:
        """Append a hidden model bound to one reviewed provider adapter."""

        redirect = RedirectResponse(
            admin_location(gateway_model_name), status_code=303
        )
        if not auth.verify_csrf(request, csrf_token):
            auth.flash(request, "Your session expired — please try again.", "error")
            return redirect
        clean_source = source_reference.strip()
        clean_note = review_note.strip()
        if (
            gateway_model_name in RESERVED_NAMES
            or provider_name not in APPROVED_PROVIDERS
            or ANTHROPIC_MODEL_ID_RE.fullmatch(provider_model_id) is None
            or _governance_source_reference(clean_source) is None
            or _governance_text(clean_note, minimum=8, maximum=500) is None
        ):
            auth.flash(
                request,
                "The model was not saved. Check the model IDs and reviewed source reference.",
                "error",
            )
            return redirect

        operation_id = str(uuid.uuid4())
        actor_id = str(user["sub"])
        audit(
            "model.governance.create",
            "intent",
            user,
            model=gateway_model_name,
            provider=provider_name,
            operation_id=operation_id,
        )
        try:
            await rotator_post(
                "/model-governance/models",
                {
                    "gateway_model_name": gateway_model_name,
                    "provider_name": provider_name,
                    "provider_model_id": provider_model_id,
                    "visible_in_discovery": False,
                    "source_reference": clean_source,
                    "review_note": clean_note,
                },
                operation_id=operation_id,
                actor_id=actor_id,
            )
            audit(
                "model.governance.create",
                "success",
                user,
                model=gateway_model_name,
                provider=provider_name,
                operation_id=operation_id,
            )
            auth.flash(
                request,
                "Hidden model version created. It is not available to users yet.",
                "success",
            )
        except Exception as exc:  # noqa: BLE001 - keep upstream detail internal
            audit(
                "model.governance.create",
                mutation_result(exc),
                user,
                model=gateway_model_name,
                provider=provider_name,
                operation_id=operation_id,
            )
            auth.flash(
                request,
                "The hidden model version was not created. Existing models were not changed.",
                "error",
            )
        return redirect

    @router.post("/admin/model-governance/lifecycle")
    async def change_lifecycle(
        request: Request,
        user: dict[str, Any] = Depends(require_recent_live_admin),
        gateway_model_name: str = Form(
            ..., min_length=1, max_length=128, pattern=MODEL_NAME_PATTERN
        ),
        action: str = Form(..., pattern=r"^(activate|show|hide|retire)$"),
        csrf_token: str = Form(..., min_length=32, max_length=128),
    ) -> RedirectResponse:
        return await apply_lifecycle_action(
            request=request,
            user=user,
            gateway_model_name=gateway_model_name,
            action=action,
            csrf_token=csrf_token,
            rotator_post=rotator_post,
            audit=audit,
            mutation_result=mutation_result,
        )

    @router.post("/admin/model-governance/prices")
    async def create_price(
        request: Request,
        user: dict[str, Any] = Depends(require_recent_live_admin),
        gateway_model_name: str = Form(
            ..., min_length=1, max_length=128, pattern=MODEL_NAME_PATTERN
        ),
        usage_class: str = Form(..., min_length=1, max_length=32),
        token_unit: int = Form(..., ge=1, le=MAX_TOKEN_UNIT),
        amount: str = Form(..., min_length=1, max_length=64),
        effective_at_utc: str = Form(..., min_length=16, max_length=19),
        explicit_free: str | None = Form(default=None, pattern=r"^1$"),
        source_reference: str = Form(..., min_length=1, max_length=256),
        review_note: str = Form(..., min_length=8, max_length=500),
        csrf_token: str = Form(..., min_length=32, max_length=128),
    ) -> RedirectResponse:
        """Append one future USD price version using exact decimal text."""

        redirect = RedirectResponse(
            admin_location(gateway_model_name), status_code=303
        )
        if not auth.verify_csrf(request, csrf_token):
            auth.flash(request, "Your session expired — please try again.", "error")
            return redirect

        is_free = explicit_free == "1"
        clean_source = source_reference.strip()
        clean_note = review_note.strip()
        effective_at = _future_utc_price_time(effective_at_utc)
        clean_amount = _validated_price_amount(
            amount,
            token_unit=token_unit,
            explicit_free=is_free,
        )
        if (
            gateway_model_name in RESERVED_NAMES
            or usage_class not in USAGE_CLASS_NAMES
            or clean_amount is None
            or effective_at is None
            or _governance_source_reference(clean_source) is None
            or _governance_text(clean_note, minimum=8, maximum=500) is None
        ):
            auth.flash(
                request,
                "The price was not saved. Use a future UTC time, an exact amount, and a reviewed source reference.",
                "error",
            )
            return redirect

        operation_id = str(uuid.uuid4())
        actor_id = str(user["sub"])
        version_id = f"price-{operation_id}"
        audit(
            "model.price.create",
            "intent",
            user,
            model=gateway_model_name,
            usage_class=usage_class,
            operation_id=operation_id,
        )
        try:
            await rotator_post(
                "/model-governance/prices",
                {
                    "version_id": version_id,
                    "gateway_model_name": gateway_model_name,
                    "usage_class": usage_class,
                    "token_unit": token_unit,
                    "amount": clean_amount,
                    "effective_at": effective_at,
                    "explicit_free": is_free,
                    "source_reference": clean_source,
                    "review_note": clean_note,
                },
                operation_id=operation_id,
                actor_id=actor_id,
            )
            audit(
                "model.price.create",
                "success",
                user,
                model=gateway_model_name,
                usage_class=usage_class,
                operation_id=operation_id,
            )
            auth.flash(request, "Future USD price version created.", "success")
        except Exception as exc:  # noqa: BLE001 - keep upstream detail internal
            audit(
                "model.price.create",
                mutation_result(exc),
                user,
                model=gateway_model_name,
                usage_class=usage_class,
                operation_id=operation_id,
            )
            auth.flash(
                request,
                "The price version was not created. Existing prices were not changed.",
                "error",
            )
        return redirect

    @router.post("/admin/model-governance/prices/backdate/preview")
    async def preview_backdated_price(
        request: Request,
        user: dict[str, Any] = Depends(require_recent_live_admin),
        gateway_model_name: str = Form(
            ..., min_length=1, max_length=128, pattern=MODEL_NAME_PATTERN
        ),
        usage_class: str = Form(..., min_length=1, max_length=32),
        token_unit: int = Form(..., ge=1, le=MAX_TOKEN_UNIT),
        amount: str = Form(..., min_length=1, max_length=64),
        effective_at_utc: str = Form(..., min_length=16, max_length=19),
        explicit_free: str | None = Form(default=None, pattern=r"^1$"),
        source_reference: str = Form(..., min_length=1, max_length=256),
        review_note: str = Form(..., min_length=8, max_length=500),
        csrf_token: str = Form(..., min_length=32, max_length=128),
    ) -> Any:
        """Show immutable usage impact before any historical price changes."""

        redirect = RedirectResponse(
            admin_location(gateway_model_name), status_code=303
        )
        if not auth.verify_csrf(request, csrf_token):
            auth.flash(request, "Your session expired — please try again.", "error")
            return redirect

        is_free = explicit_free == "1"
        clean_source = source_reference.strip()
        clean_note = review_note.strip()
        effective_at = _past_or_current_utc_price_time(effective_at_utc)
        clean_amount = _validated_price_amount(
            amount,
            token_unit=token_unit,
            explicit_free=is_free,
        )
        if (
            gateway_model_name in RESERVED_NAMES
            or usage_class not in USAGE_CLASS_NAMES
            or clean_amount is None
            or effective_at is None
            or _governance_source_reference(clean_source) is None
            or _governance_text(clean_note, minimum=8, maximum=500) is None
        ):
            auth.flash(
                request,
                "The preview was not created. Use a past UTC time, an exact amount, and a reviewed source reference.",
                "error",
            )
            return redirect

        preview_id = str(uuid.uuid4())
        version_id = f"price-{preview_id}"
        actor_id = str(user["sub"])
        audit(
            "model.price.backdate.preview",
            "intent",
            user,
            model=gateway_model_name,
            usage_class=usage_class,
            operation_id=preview_id,
        )
        try:
            raw = await rotator_post(
                "/model-governance/prices/backdate/preview",
                {
                    "version_id": version_id,
                    "gateway_model_name": gateway_model_name,
                    "usage_class": usage_class,
                    "token_unit": token_unit,
                    "amount": clean_amount,
                    "effective_at": effective_at,
                    "explicit_free": is_free,
                    "source_reference": clean_source,
                    "review_note": clean_note,
                },
                operation_id=preview_id,
                actor_id=actor_id,
            )
            preview = safe_backdate_preview(raw)
            if (
                preview["gateway_model_name"] != gateway_model_name
                or preview["usage_class"] != usage_class
            ):
                raise ValueError("backdate preview changed the requested target")
            audit(
                "model.price.backdate.preview",
                "success",
                user,
                model=gateway_model_name,
                usage_class=usage_class,
                operation_id=preview_id,
            )
            return render_backdate_preview(
                request=request,
                user=user,
                preview=preview,
            )
        except Exception as exc:  # noqa: BLE001 - upstream detail stays internal
            audit(
                "model.price.backdate.preview",
                mutation_result(exc),
                user,
                model=gateway_model_name,
                usage_class=usage_class,
                operation_id=preview_id,
            )
            auth.flash(
                request,
                "The backdate preview failed. No price or usage history changed.",
                "error",
            )
            return redirect

    @router.post("/admin/model-governance/prices/backdate/confirm")
    async def confirm_backdated_price(
        request: Request,
        user: dict[str, Any] = Depends(require_recent_live_admin),
        preview_id: str = Form(..., min_length=36, max_length=36),
        candidate_sha256: str = Form(..., min_length=64, max_length=64),
        preview_sha256: str = Form(..., min_length=64, max_length=64),
        confirmation: str = Form(..., min_length=23, max_length=23),
        csrf_token: str = Form(..., min_length=32, max_length=128),
    ) -> RedirectResponse:
        """Confirm only the exact stored preview after another step-up check."""

        redirect = RedirectResponse(admin_location(), status_code=303)
        if not auth.verify_csrf(request, csrf_token):
            auth.flash(request, "Your session expired — please try again.", "error")
            return redirect
        if (
            not _canonical_operation_id(preview_id)
            or SHA256_RE.fullmatch(candidate_sha256) is None
            or SHA256_RE.fullmatch(preview_sha256) is None
            or confirmation != PRICE_BACKDATE_CONFIRMATION
        ):
            auth.flash(
                request,
                "The confirmation did not match the stored preview. Run a new preview.",
                "error",
            )
            return redirect

        operation_id = str(uuid.uuid4())
        actor_id = str(user["sub"])
        audit(
            "model.price.backdate.confirm",
            "intent",
            user,
            operation_id=operation_id,
        )
        try:
            raw = await rotator_post(
                f"/model-governance/prices/backdate/{preview_id}/confirm",
                {
                    "candidate_sha256": candidate_sha256,
                    "preview_sha256": preview_sha256,
                    "confirmation": PRICE_BACKDATE_CONFIRMATION,
                },
                operation_id=operation_id,
                actor_id=actor_id,
            )
            receipt = safe_backdate_confirmation(
                raw,
                preview_id=preview_id,
                candidate_sha256=candidate_sha256,
                preview_sha256=preview_sha256,
                operation_id=operation_id,
            )
            audit(
                "model.price.backdate.confirm",
                "success",
                user,
                model=receipt["gateway_model_name"],
                usage_class=receipt["usage_class"],
                operation_id=operation_id,
            )
            redirect = RedirectResponse(
                admin_location(receipt["gateway_model_name"]), status_code=303
            )
            auth.flash(
                request,
                f"Backdated price confirmed. {receipt['adjustment_count']} immutable cost adjustments were appended.",
                "success",
            )
        except Exception as exc:  # noqa: BLE001 - upstream detail stays internal
            audit(
                "model.price.backdate.confirm",
                mutation_result(exc),
                user,
                operation_id=operation_id,
            )
            auth.flash(
                request,
                "The backdate was not confirmed. The preview may be stale; run it again.",
                "error",
            )
        return redirect

    return router
