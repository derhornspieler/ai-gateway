"""key-rotator FastAPI service — vendor API key rotation for the AI gateway.

Design ref: docs/solution-map.md §1.2, §1.7 (rotation engine, per-vendor
driver plugin interface, admin-portal control surface, OTel audit events)
and docs/anthropic-wif-bootstrap.md (Anthropic WIF Phase 1 recurring flow).

Auth: every route except /healthz requires an `X-Internal-Auth` header
matching ROTATOR_INTERNAL_TOKEN (constant-time compare). The token is
REQUIRED — startup fails if it is unset or an obvious placeholder, and
the middleware fails closed regardless. Segmented network placement
(docs/solution-map.md §3; consumed by the dev-portal admin UI, §1.4/§1.7)
is defense-in-depth on top of that, not a substitute.
"""

from __future__ import annotations

import hmac
import json
import logging
import re
import uuid
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    model_validator,
)

from app import health
from app.config import Settings, get_settings
from app.db import Database
from app.drivers.anthropic_wif import AnthropicWifDriver
from app.drivers.static_seed import StaticSeedDriver
from app.litellm_client import LiteLLMClient
from app.model_catalog import ProviderPolicyReceipt, load_provider_policy_receipt
from app.model_governance_api import (
    model_policy_lock,
    router as model_governance_router,
)
from app.model_reconciler import ModelReconciler
from app.identity import (
    IdentityConflict,
    IdentityError,
    IdentityNotFound,
    KeycloakAdmin,
)
from app.otel import setup_otel
from app.provider_auth import (
    AnthropicWifEnrollment,
    ProviderConflict,
    ProviderError,
    ProviderNotFound,
    ProviderRegistry,
    ProviderUnavailable,
)
from app.pricing_api import router as pricing_router
from app.scheduler import RotationScheduler
from app.usage import read_usage_token
from app.usage_api import router as usage_router
from app.usage_store import PostgresUsageStore
from app.vault_client import VaultClient, VaultError

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
)
logger = logging.getLogger("key_rotator.main")

app = FastAPI(title="key-rotator", version="1.0.0")

# Simple module-level app state (avoids a DI framework for a small
# internal-only service). Populated in on_startup, read by route handlers.
state: dict[str, Any] = {}
app.state.aigw_services = state
app.include_router(model_governance_router)
app.include_router(pricing_router)
app.include_router(usage_router)


def _configured_provider_policy(
    settings: Settings,
) -> ProviderPolicyReceipt | None:
    """Load deployment trust once, before any network client is created."""

    if not settings.provider_policy_receipt_file:
        return None
    return load_provider_policy_receipt(
        settings.provider_policy_receipt_file,
        expected_policy_sha256=settings.aigw_egress_policy_sha256,
    )


class SettingsUpdate(BaseModel):
    enabled: bool
    interval_seconds: int = Field(ge=0, le=365 * 86400)
    grace_seconds: int = Field(default=300, ge=0, le=86400)
    # Omission means "preserve the driver's internal state". The dev portal
    # edits cadence/enabled fields only; treating an omitted config as {}
    # erased Anthropic token-lifetime/failure bookkeeping on every admin save.
    # An explicit object (including {}) still intentionally replaces config.
    config: dict[str, Any] | None = None

    @model_validator(mode="after")
    def bound_config_size(self) -> "SettingsUpdate":
        # Config is persisted as JSONB and later returned by admin routes.
        # Bound it so a compromised authenticated peer cannot turn a single
        # scheduler update into an unbounded DB/API memory amplification.
        if self.config is None:
            return self
        encoded = json.dumps(
            self.config, separators=(",", ":"), allow_nan=False
        ).encode()
        if len(encoded) > 16 * 1024:
            raise ValueError("config must be at most 16 KiB when JSON encoded")
        return self


class IdentityBootstrapRequest(BaseModel):
    confirmation: str = Field(min_length=1, max_length=32)


class IdentityDeploymentRequest(BaseModel):
    confirmation: str = Field(min_length=1, max_length=32)


class IdentityGroupCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    capabilities: list[str] = Field(min_length=1, max_length=4)


class IdentityModelLimits(BaseModel):
    """The two conservative output controls supported in the first release."""

    model_config = ConfigDict(extra="forbid")

    max_output_tokens_per_request: StrictInt = Field(ge=1, le=1_000_000)
    output_tokens_per_utc_minute: StrictInt = Field(ge=1, le=1_000_000_000)

    @model_validator(mode="after")
    def request_cap_fits_minute_cap(self) -> "IdentityModelLimits":
        if self.max_output_tokens_per_request > self.output_tokens_per_utc_minute:
            raise ValueError("request output cap cannot exceed the minute cap")
        return self


class IdentityGroupPolicyUpdate(BaseModel):
    """Requested per-project issuance policy; null means platform default.

    The identity controller re-validates and normalizes before any Keycloak
    write — this model only bounds the transport shape.
    """

    model_config = ConfigDict(extra="forbid")

    tpm_limit: int | None = Field(default=None, ge=1, le=1_000_000_000)
    rpm_limit: int | None = Field(default=None, ge=1, le=1_000_000_000)
    allowed_models: list[str] | None = Field(
        default=None, min_length=1, max_length=32
    )
    default_model: str | None = Field(default=None, min_length=1, max_length=128)
    model_limits: dict[str, IdentityModelLimits] = Field(
        default_factory=dict, max_length=32
    )


class IdentityGroupPolicyRevision(BaseModel):
    """Expected durable policy revision for activate/complete phases."""

    model_config = ConfigDict(extra="forbid")

    policy_revision: str = Field(pattern=r"^[0-9a-f]{64}$")


class ProviderLifecycleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirmation: str = Field(min_length=1, max_length=64)


def _identity_http_error(exc: IdentityError) -> HTTPException:
    if isinstance(exc, IdentityNotFound):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, IdentityConflict):
        return HTTPException(status_code=409, detail=str(exc))
    # Treat upstream/control-plane failures as Bad Gateway. Keep the response
    # fixed as a second boundary in case a future IdentityError accidentally
    # wraps a raw LDAP, Vault, or Keycloak diagnostic.
    return HTTPException(status_code=502, detail="identity operation failed")


def _identity_operation_id(request: Request) -> str:
    values = request.headers.getlist("X-AIGW-Operation-ID")
    if len(values) != 1:
        raise HTTPException(
            status_code=400, detail="missing or invalid identity operation ID"
        )
    value = values[0]
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=400, detail="missing or invalid identity operation ID"
        ) from exc
    if (
        parsed.variant != uuid.RFC_4122
        or parsed.version != 4
        or str(parsed) != value
    ):
        raise HTTPException(
            status_code=400, detail="missing or invalid identity operation ID"
        )
    return value


def _provider_http_error(exc: ProviderError) -> HTTPException:
    if isinstance(exc, ProviderNotFound):
        return HTTPException(status_code=404, detail="provider is not supported")
    if isinstance(exc, ProviderConflict):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, ProviderUnavailable):
        return HTTPException(
            status_code=502, detail="provider control plane unavailable"
        )
    return HTTPException(status_code=502, detail="provider operation failed")


@app.middleware("http")
async def internal_auth_middleware(request: Request, call_next):
    """Enforce X-Internal-Auth == ROTATOR_INTERNAL_TOKEN. Fails closed:
    if the token is missing/placeholder (or settings aren't loaded yet),
    every request is rejected rather than waved through. /healthz is
    always open (used by container/orchestrator health checks).
    """
    if request.url.path in {"/healthz", "/readyz"}:
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        return response

    # LiteLLM has a separate write-only credential. The route performs its
    # own authentication before it parses JSON. Do not widen this exception
    # to a prefix or another method.
    if request.method == "POST" and request.url.path == "/usage/events":
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        return response

    settings: Optional[Settings] = state.get("settings")
    if (
        settings is None
        or not settings.internal_token_ok()
        or not settings.portal_token_ok()
    ):
        return JSONResponse(
            status_code=503,
            content={
                "detail": "service auth not configured (ROTATOR_INTERNAL_TOKEN unset/placeholder)"
            },
            headers={"Cache-Control": "no-store"},
        )

    supplied = request.headers.get("X-Internal-Auth") or ""
    admin_authorized = hmac.compare_digest(
        supplied.encode(), settings.rotator_internal_token.encode()
    )
    portal_route = request.method == "GET" and (
        request.url.path == "/model-governance/discovery"
        or re.fullmatch(
            r"/identity/projects/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}",
            request.url.path,
        )
        is not None
    )
    portal_authorized = portal_route and hmac.compare_digest(
        supplied.encode(), settings.portal_identity_token.encode()
    )
    if not admin_authorized and not portal_authorized:
        return JSONResponse(
            status_code=401,
            content={"detail": "missing or invalid X-Internal-Auth header"},
            headers={"Cache-Control": "no-store"},
        )
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.on_event("startup")
async def on_startup() -> None:
    settings = get_settings()

    # Fail closed on missing/placeholder auth token (the middleware also
    # rejects everything in this state, but refusing to start makes the
    # misconfiguration impossible to miss).
    if not settings.internal_token_ok() or not settings.portal_token_ok():
        raise RuntimeError(
            "ROTATOR_INTERNAL_TOKEN and PORTAL_IDENTITY_TOKEN must be distinct, "
            "strong, non-placeholder values; refusing to start with auth disabled"
        )

    state.pop("provider_policy", None)
    state.pop("model_reconciler", None)
    state.pop("usage_token", None)
    state.pop("usage_store", None)
    provider_policy = _configured_provider_policy(settings)
    if provider_policy is not None:
        state["provider_policy"] = provider_policy

    state["settings"] = settings

    db = Database(settings)
    await db.connect_with_retry(max_wait_seconds=60)
    state["db"] = db
    state["usage_token"] = read_usage_token()
    state["usage_store"] = PostgresUsageStore(
        db,
        egress_policy_sha256=(
            provider_policy.egress_policy_sha256
            if provider_policy is not None
            else None
        ),
    )

    vault = VaultClient(settings)
    await vault.connect_with_retry(max_wait_seconds=60)
    state["vault"] = vault

    litellm = LiteLLMClient(settings)
    state["litellm"] = litellm

    if provider_policy is not None:
        model_reconciler = ModelReconciler(
            db,
            litellm,
            egress_policy_sha256=provider_policy.egress_policy_sha256,
        )
        state["model_reconciler"] = model_reconciler
        try:
            await model_reconciler.reconcile()
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "initial model reconciliation failed (%s); retrying in background",
                type(exc).__name__,
            )
        model_reconciler.start()

    # Group removal must revoke static LiteLLM portal keys at the authoritative
    # identity mutation boundary, not only in the browser admin portal.
    state["identity"] = KeycloakAdmin(
        settings,
        vault,
        db,
        portal_key_revoker=litellm.revoke_portal_project_keys,
    )

    setup_otel(settings, app)

    drivers = {
        "anthropic": AnthropicWifDriver(),
        "static-anthropic": StaticSeedDriver("anthropic"),
    }
    state["drivers"] = drivers

    scheduler = RotationScheduler(
        settings,
        db,
        vault,
        litellm,
        drivers,
        identity=state["identity"],
    )
    state["scheduler"] = scheduler
    await scheduler.reload()
    state["provider_registry"] = ProviderRegistry(settings, vault, db, scheduler)

    # Seed this before the immediate reconciliation job is armed so health
    # cannot report green before its first authoritative Keycloak/LiteLLM pass.
    health.register_pending("identity.portal_key_reconciliation")
    scheduler.start()

    # Seed expected health subsystems in a "pending" (ok=False) state so
    # /healthz alerts_ok is not falsely green before each has run once.
    # The JWKS system job always runs on its interval. The per-vendor rotation
    # subsystem is only seeded when
    # that vendor is enabled (a disabled vendor is not expected to run, so
    # it should not hold health red forever).
    health.register_pending("anthropic.jwks")
    try:
        rows_by_vendor = {r["vendor"]: r for r in await db.list_settings()}
    except Exception:  # noqa: BLE001
        rows_by_vendor = {}
    if rows_by_vendor.get("anthropic", {}).get("enabled"):
        health.register_pending("anthropic.token_exchange")

    logger.info("key-rotator startup complete (db_degraded=%s)", db.degraded)


@app.on_event("shutdown")
async def on_shutdown() -> None:
    model_reconciler: Optional[ModelReconciler] = state.get("model_reconciler")
    if model_reconciler:
        await model_reconciler.shutdown()
    scheduler: Optional[RotationScheduler] = state.get("scheduler")
    if scheduler:
        await scheduler.shutdown()
    db: Optional[Database] = state.get("db")
    if db:
        await db.close()
    vault: Optional[VaultClient] = state.get("vault")
    if vault:
        vault.close()


@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    """Unauthenticated liveness plus a non-sensitive aggregate alert bit.

    Detailed subsystem error text remains available on authenticated
    ``/status``. Publishing it here exposed internal URLs, Vault paths, and
    service-account identifiers to every peer that can reach the service.
    """
    return {
        "ok": True,
        "alerts_ok": health.all_ok(),
    }


@app.get("/readyz")
async def readyz() -> JSONResponse:
    """Non-sensitive readiness for the post-bootstrap deployment gate."""
    db: Optional[Database] = state.get("db")
    vault: Optional[VaultClient] = state.get("vault")
    model_reconciler: Optional[ModelReconciler] = state.get("model_reconciler")
    models_ready = model_reconciler is None or model_reconciler.ready
    identity: Optional[KeycloakAdmin] = state.get("identity")
    try:
        policies_ready = bool(
            identity and await identity.project_policy_reconciliation_ready()
        )
    except Exception:  # noqa: BLE001 - ambiguous reconciliation is not ready
        policies_ready = False
    ready = bool(
        db
        and vault
        and await db.ready()
        and vault.ready()
        and models_ready
        and policies_ready
    )
    return JSONResponse(status_code=200 if ready else 503, content={"ready": ready})


@app.get("/vault/public-status")
async def vault_public_status() -> dict[str, bool]:
    """Expose only exact public Vault seal state to the admin application."""

    vault: Optional[VaultClient] = state.get("vault")
    if vault is None:
        raise HTTPException(status_code=503, detail="Vault public status unavailable")
    try:
        return vault.public_status()
    except VaultError as exc:
        raise HTTPException(
            status_code=503, detail="Vault public status unavailable"
        ) from exc


@app.get("/status")
async def get_status() -> list[dict[str, Any]]:
    """Per-vendor summary: enabled, interval, last rotation (from
    rotation_history), next scheduled run time.
    """
    db: Database = state["db"]
    scheduler: RotationScheduler = state["scheduler"]

    rows = await db.list_settings()
    drivers: dict[str, Any] = state["drivers"]
    result: list[dict[str, Any]] = []
    for row in rows:
        if row["vendor"] not in drivers:
            continue
        last = await db.last_history(row["vendor"])
        next_run = scheduler.next_run_time(row["vendor"])
        result.append(
            {
                "vendor": row["vendor"],
                "enabled": row["enabled"],
                "interval_seconds": row["interval_seconds"],
                "grace_seconds": row["grace_seconds"],
                "last_rotation": last,
                "next_run_time": next_run.isoformat() if next_run else None,
                "rotation_in_progress": scheduler.is_rotating(row["vendor"]),
                # Active alerts scoped to this vendor (JWKS drift, failing
                # token exchange, orphaned credentials — app/health.py).
                "alerts": health.alerts_for_vendor(row["vendor"]),
            }
        )
    return result


@app.get("/alerts")
async def get_alerts() -> list[dict[str, Any]]:
    """Authenticated detailed alert view, including system-wide flags."""
    return [
        {"name": name, **flag}
        for name, flag in sorted(health.snapshot().items())
        if not flag["ok"]
    ]


@app.get("/settings")
async def get_all_settings() -> list[dict[str, Any]]:
    db: Database = state["db"]
    drivers: dict[str, Any] = state["drivers"]
    return [
        row for row in await db.list_settings() if row["vendor"] in drivers
    ]


@app.put("/settings/{vendor}")
async def put_settings(vendor: str, body: SettingsUpdate) -> dict[str, Any]:
    """Persist per-vendor rotation config and hot-reload the scheduler."""
    db: Database = state["db"]
    scheduler: RotationScheduler = state["scheduler"]
    drivers: dict[str, Any] = state["drivers"]

    if vendor not in drivers:
        raise HTTPException(status_code=404, detail=f"unknown vendor '{vendor}'")

    async def persist_settings() -> None:
        await db.upsert_settings(
            vendor,
            enabled=body.enabled,
            interval_seconds=body.interval_seconds,
            grace_seconds=body.grace_seconds,
            config=body.config,
        )
        await scheduler.reload()

    if vendor == "anthropic":
        # Anthropic WIF has a typed lifecycle API. The legacy generic settings
        # route may tune cadence only; it must not bypass explicit enrollment,
        # disable confirmation, or the adapter's fixed Vault/network inputs.
        async with db.rotation_lock(vendor) as acquired:
            if not acquired:
                raise HTTPException(
                    status_code=409,
                    detail="another Anthropic credential lifecycle operation is active",
                )
            current = await db.get_settings(vendor)
            if not isinstance(current, dict) or not isinstance(
                current.get("enabled"), bool
            ):
                raise HTTPException(
                    status_code=502, detail="provider control plane unavailable"
                )
            if body.config is not None:
                raise HTTPException(
                    status_code=409,
                    detail="Anthropic WIF configuration is managed by /providers/anthropic",
                )
            if body.enabled is not current["enabled"]:
                raise HTTPException(
                    status_code=409,
                    detail="Anthropic WIF enable/disable is managed by /providers/anthropic",
                )
            await persist_settings()
    else:
        await persist_settings()
    # Audit the control-plane change without copying arbitrary config values
    # (which may be secrets) into a second durable store.
    audit_detail = json.dumps(
        {
            "enabled": body.enabled,
            "interval_seconds": body.interval_seconds,
            "grace_seconds": body.grace_seconds,
            "config_action": "preserved" if body.config is None else "replaced",
            "config_keys": sorted(body.config) if body.config is not None else [],
        },
        separators=(",", ":"),
    )
    await db.record_history(vendor, "settings_update", "success", audit_detail)
    return {"ok": True}


@app.post("/rotate/{vendor}", status_code=202)
async def rotate_now(vendor: str) -> dict[str, Any]:
    """Trigger an immediate rotation for `vendor` (fire-and-forget).
    Responds 409 if a rotation for this vendor is already in flight —
    concurrent rotations would race and orphan live credentials.
    """
    drivers: dict[str, Any] = state["drivers"]
    scheduler: RotationScheduler = state["scheduler"]

    if vendor not in drivers:
        raise HTTPException(status_code=404, detail=f"unknown vendor '{vendor}'")

    if vendor == "anthropic":
        db: Database = state["db"]
        row = await db.get_settings(vendor)
        if not isinstance(row, dict) or row.get("enabled") is not True:
            raise HTTPException(
                status_code=409,
                detail="Anthropic WIF refresh is disabled",
            )
        registry: ProviderRegistry = state["provider_registry"]
        try:
            provider = await registry.status(vendor)
        except ProviderError as exc:
            raise _provider_http_error(exc) from exc
        if not isinstance(provider, dict) or provider.get("state") != "configured":
            raise HTTPException(
                status_code=409,
                detail="Anthropic WIF enrollment is not ready for rotation",
            )

    if not await scheduler.trigger_now(vendor):
        raise HTTPException(
            status_code=409,
            detail=f"rotation already in progress for vendor '{vendor}'",
        )
    return {"accepted": True, "vendor": vendor}


@app.get("/history")
async def get_history(
    limit: int = Query(default=50, ge=1, le=200),
) -> list[dict[str, Any]]:
    db: Database = state["db"]
    return await db.history(limit=limit)


# --- Provider authentication control plane --------------------------------
# The only registered adapter is Anthropic WIF. These routes intentionally do
# not expose a generic provider/config surface: callers cannot choose network
# destinations, Vault paths, private keys, or arbitrary configuration fields.


@app.get("/providers/anthropic")
async def anthropic_provider_status() -> dict[str, Any]:
    registry: ProviderRegistry = state["provider_registry"]
    try:
        return await registry.status("anthropic")
    except ProviderError as exc:
        raise _provider_http_error(exc) from exc


@app.put("/providers/anthropic")
async def configure_anthropic_provider(
    body: AnthropicWifEnrollment,
) -> dict[str, Any]:
    registry: ProviderRegistry = state["provider_registry"]
    try:
        return await registry.configure("anthropic", body)
    except ProviderError as exc:
        raise _provider_http_error(exc) from exc


@app.post("/providers/anthropic/disable")
async def disable_anthropic_provider(
    body: ProviderLifecycleRequest,
) -> dict[str, Any]:
    registry: ProviderRegistry = state["provider_registry"]
    try:
        return await registry.disable("anthropic", body.confirmation)
    except ProviderError as exc:
        raise _provider_http_error(exc) from exc


@app.delete("/providers/anthropic")
async def delete_anthropic_provider(
    body: ProviderLifecycleRequest,
) -> dict[str, Any]:
    registry: ProviderRegistry = state["provider_registry"]
    try:
        return await registry.delete("anthropic", body.confirmation)
    except ProviderError as exc:
        raise _provider_http_error(exc) from exc


# --- Keycloak identity control plane ---------------------------------------
# Every route below inherits the service-wide X-Internal-Auth middleware. The
# dev portal adds a second, interactive OIDC step-up check before invoking any
# mutation. Private keys and bootstrap credentials never cross these APIs.


@app.get("/identity/status")
async def identity_status() -> dict[str, Any]:
    identity: KeycloakAdmin = state["identity"]
    try:
        return await identity.status()
    except IdentityError as exc:
        raise _identity_http_error(exc) from exc


@app.get("/identity/authorization/{user_id}")
async def identity_authorization(user_id: str) -> dict[str, bool]:
    """Return only the live admin decision needed by the trusted portal.

    No role list or user profile crosses this boundary.  The service-wide
    internal bearer token still protects the route.
    """
    identity: KeycloakAdmin = state["identity"]
    try:
        return {"admin": await identity.user_has_admin_role(user_id)}
    except IdentityError as exc:
        vault: Optional[VaultClient] = state.get("vault")
        if vault is not None:
            try:
                vault_status = vault.public_status()
            except VaultError:
                vault_status = None
            if vault_status == {"initialized": True, "sealed": True}:
                # This route reads its controller credential from Vault before
                # it can contact Keycloak. An exact sealed state therefore
                # identifies the blocking boundary without exposing the
                # wrapped Vault or identity diagnostic.
                raise HTTPException(status_code=423, detail="vault_sealed") from exc
        raise _identity_http_error(exc) from exc


@app.get("/identity/projects/{user_id}")
async def identity_projects(user_id: str) -> dict[str, Any]:
    """Live, canonical managed projects plus each project's issuance policy.

    This is the ONLY route the least-privilege portal identity token may
    call. Widening its payload with the projects' non-secret issuance policy
    (rate limits, allowed/default models) is a reviewed choice: the portal
    needs the policy to mint correctly capped keys, and no mutation authority
    or secret is added to that token's scope.
    """
    identity: KeycloakAdmin = state["identity"]
    try:
        return await identity.user_project_policies(user_id)
    except IdentityError as exc:
        raise _identity_http_error(exc) from exc


@app.post("/identity/bootstrap")
async def identity_bootstrap(body: IdentityBootstrapRequest) -> dict[str, Any]:
    if not hmac.compare_digest(body.confirmation, "INITIALIZE"):
        raise HTTPException(status_code=400, detail="confirmation must be INITIALIZE")
    identity: KeycloakAdmin = state["identity"]
    try:
        return await identity.bootstrap()
    except IdentityError as exc:
        raise _identity_http_error(exc) from exc


@app.post("/identity/deployment")
async def identity_deployment(body: IdentityDeploymentRequest) -> dict[str, str]:
    """Ansible-only, locked and idempotent Keycloak/LDAPS converge."""

    if not hmac.compare_digest(body.confirmation, "AUTO_BOOTSTRAP_IDENTITY"):
        raise HTTPException(status_code=400, detail="invalid deployment confirmation")
    identity: KeycloakAdmin = state["identity"]
    try:
        return {"result": await identity.converge_deployment_identity()}
    except IdentityError as exc:
        await identity.audit_deployment_failure(exc)
        # This endpoint exists only for unattended deployment. Keep its
        # response fixed so a wrapped directory or Vault diagnostic can never
        # become Ansible output, even if a future IdentityError is less careful.
        raise HTTPException(
            status_code=502, detail="identity deployment failed"
        ) from exc


@app.get("/identity/groups")
async def identity_groups() -> list[dict[str, Any]]:
    identity: KeycloakAdmin = state["identity"]
    try:
        return await identity.list_groups()
    except IdentityError as exc:
        raise _identity_http_error(exc) from exc


@app.get("/identity/chat-capability-health")
async def identity_chat_capability_health() -> dict[str, Any]:
    """Report whether the live realm wires the dedicated aigw-chat gate.

    Admin-token only (the portal identity token's route allowlist never
    matches this path). The verify role calls it every converge to turn a
    silent non-admin chat brick into a loud, remediable converge failure.
    """
    identity: KeycloakAdmin = state["identity"]
    try:
        return await identity.chat_capability_health()
    except IdentityError as exc:
        raise _identity_http_error(exc) from exc


@app.post("/identity/groups", status_code=201)
async def identity_create_group(
    body: IdentityGroupCreate, request: Request
) -> dict[str, Any]:
    identity: KeycloakAdmin = state["identity"]
    operation_id = _identity_operation_id(request)
    try:
        return await identity.create_group(
            body.name, body.capabilities, operation_id
        )
    except IdentityError as exc:
        await identity.audit_identity_mutation_failure(
            "group_create", operation_id, exc
        )
        raise _identity_http_error(exc) from exc
    except Exception as exc:
        await identity.audit_identity_mutation_failure(
            "group_create", operation_id, exc
        )
        raise


@app.put("/identity/groups/{group_id}/policy")
async def identity_set_group_policy(
    group_id: str, body: IdentityGroupPolicyUpdate, request: Request
) -> dict[str, Any]:
    """Write one managed group's issuance policy (admin token only).

    The portal identity token's route allowlist never matches this path, so
    only the full internal token — i.e. the admin portal — can mutate policy.
    """
    identity: KeycloakAdmin = state["identity"]
    operation_id = _identity_operation_id(request)
    try:
        async with model_policy_lock(state):
            requested = body.model_dump()
            allowed_models = requested["allowed_models"]
            if allowed_models and "all-proxy-models" in allowed_models:
                raise HTTPException(
                    status_code=422,
                    detail="wildcard model assignments are not allowed",
                )
            receipt = state.get("provider_policy")
            db: Database = state["db"]
            if isinstance(receipt, ProviderPolicyReceipt):
                for model_name in allowed_models or []:
                    governed = await db.get_governed_model(
                        model_name,
                        egress_policy_sha256=receipt.egress_policy_sha256,
                    )
                    if governed is not None and governed.get("active") is not True:
                        raise HTTPException(
                            status_code=409,
                            detail="inactive governed models cannot be assigned",
                        )
            return await identity.set_group_policy(
                group_id, requested, operation_id
            )
    except HTTPException:
        raise
    except IdentityError as exc:
        await identity.audit_identity_mutation_failure(
            "group_policy_update", operation_id, exc
        )
        raise _identity_http_error(exc) from exc
    except Exception as exc:
        await identity.audit_identity_mutation_failure(
            "group_policy_update", operation_id, exc
        )
        raise


@app.post("/identity/groups/{group_id}/policy/activate")
async def identity_activate_group_policy(
    group_id: str, body: IdentityGroupPolicyRevision, request: Request
) -> dict[str, Any]:
    """Activate a staged policy after the portal proves old keys are gated."""

    identity: KeycloakAdmin = state["identity"]
    operation_id = _identity_operation_id(request)
    try:
        async with model_policy_lock(state):
            return await identity.activate_group_policy(
                group_id, body.policy_revision, operation_id
            )
    except IdentityError as exc:
        await identity.audit_identity_mutation_failure(
            "group_policy_update", operation_id, exc
        )
        raise _identity_http_error(exc) from exc
    except Exception as exc:
        await identity.audit_identity_mutation_failure(
            "group_policy_update", operation_id, exc
        )
        raise


@app.post("/identity/groups/{group_id}/policy/complete")
async def identity_complete_group_policy(
    group_id: str, body: IdentityGroupPolicyRevision, request: Request
) -> dict[str, Any]:
    """Clear a pending marker only after every project key verifies."""

    identity: KeycloakAdmin = state["identity"]
    operation_id = _identity_operation_id(request)
    try:
        async with model_policy_lock(state):
            return await identity.complete_group_policy(
                group_id, body.policy_revision, operation_id
            )
    except IdentityError as exc:
        await identity.audit_identity_mutation_failure(
            "group_policy_update", operation_id, exc
        )
        raise _identity_http_error(exc) from exc
    except Exception as exc:
        await identity.audit_identity_mutation_failure(
            "group_policy_update", operation_id, exc
        )
        raise


@app.delete("/identity/groups/{group_id}", status_code=204)
async def identity_delete_group(group_id: str, request: Request) -> None:
    identity: KeycloakAdmin = state["identity"]
    operation_id = _identity_operation_id(request)
    try:
        await identity.delete_group(group_id, operation_id)
    except IdentityError as exc:
        await identity.audit_identity_mutation_failure(
            "group_delete", operation_id, exc
        )
        raise _identity_http_error(exc) from exc
    except Exception as exc:
        await identity.audit_identity_mutation_failure(
            "group_delete", operation_id, exc
        )
        raise


@app.get("/identity/groups/{group_id}/members")
async def identity_group_members(group_id: str) -> list[dict[str, Any]]:
    identity: KeycloakAdmin = state["identity"]
    try:
        return await identity.group_members(group_id)
    except IdentityError as exc:
        raise _identity_http_error(exc) from exc


@app.put("/identity/groups/{group_id}/members/{user_id}", status_code=204)
async def identity_add_group_member(
    group_id: str, user_id: str, request: Request
) -> None:
    identity: KeycloakAdmin = state["identity"]
    operation_id = _identity_operation_id(request)
    try:
        await identity.add_member(group_id, user_id, operation_id)
    except IdentityError as exc:
        await identity.audit_identity_mutation_failure(
            "group_member_add", operation_id, exc
        )
        raise _identity_http_error(exc) from exc
    except Exception as exc:
        await identity.audit_identity_mutation_failure(
            "group_member_add", operation_id, exc
        )
        raise


@app.delete("/identity/groups/{group_id}/members/{user_id}", status_code=204)
async def identity_remove_group_member(
    group_id: str, user_id: str, request: Request
) -> None:
    identity: KeycloakAdmin = state["identity"]
    operation_id = _identity_operation_id(request)
    try:
        await identity.remove_member(group_id, user_id, operation_id)
    except IdentityError as exc:
        await identity.audit_identity_mutation_failure(
            "group_member_remove", operation_id, exc
        )
        raise _identity_http_error(exc) from exc
    except Exception as exc:
        await identity.audit_identity_mutation_failure(
            "group_member_remove", operation_id, exc
        )
        raise


@app.get("/identity/users")
async def identity_users(
    search: str = Query(default="", max_length=64),
) -> list[dict[str, Any]]:
    identity: KeycloakAdmin = state["identity"]
    try:
        return await identity.search_users(search)
    except IdentityError as exc:
        raise _identity_http_error(exc) from exc
