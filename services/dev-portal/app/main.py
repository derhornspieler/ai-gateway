"""AI Gateway user and administrator portal applications.

See docs/solution-map.md §1.4 for design context: OIDC-gated (Keycloak)
self-service LiteLLM virtual-key issuance and a physically separate
administrator application for identity and rotation control.  The two ASGI
applications share reviewed code and an image, but run in different
containers, on different Docker networks, with different OIDC clients and
session-signing secrets.  The user application never registers an admin
route.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import json
import logging
import re
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode, urlsplit

import httpx
from fastapi import (
    Depends,
    FastAPI,
    Form,
    HTTPException,
    Path as APIPath,
    Query,
    Request,
)
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from . import auth, litellm_client, model_admin, tools
from .config import settings
from .model_discovery import router as model_discovery_router

logger = logging.getLogger("dev-portal")

TEMPLATES_DIR = str(Path(__file__).parent / "templates")


def _template_context(request: Request) -> dict[str, str]:
    return {"csp_nonce": getattr(request.state, "csp_nonce", "")}


templates = Jinja2Templates(
    directory=TEMPLATES_DIR, context_processors=[_template_context]
)

VENDOR_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$"
VENDOR_RE = re.compile(VENDOR_PATTERN)
# The portal must not turn an arbitrary syntactically valid name into a
# provider-control URL. Keep this in sync with key-rotator's registered driver
# map. Adding a provider requires the reviewed provider release workflow.
REGISTERED_ROTATION_VENDORS = frozenset({"anthropic", "static-anthropic"})
IDENTITY_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"
IDENTITY_ID_RE = re.compile(IDENTITY_ID_PATTERN)
# aigw-chat is the dedicated Open WebUI chat capability; aigw-users is
# deprecated for chat but stays assignable for existing deployments.
IDENTITY_CAPABILITIES = frozenset(
    {"aigw-users", "aigw-developers", "aigw-admins", "aigw-chat"}
)
PROVIDER_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
PROVIDER_IDENTIFIER_RE = re.compile(PROVIDER_IDENTIFIER_PATTERN)
PROVIDER_STATES = frozenset(
    {
        "identity_bootstrap_required",
        "awaiting_enrollment",
        "configured",
        "jwks_drift",
        "revocation_pending",
        "unavailable",
    }
)
PORTAL_AUDIT_ACTIONS = frozenset(
    {
        "admin.key.block",
        "admin.key.limits",
        "admin.key.unblock",
        "authorization.role.denied",
        "authorization.step_up.required",
        "egress.trust.verify",
        "identity.group.create",
        "identity.group.delete",
        "identity.group.policy",
        "identity.member.add",
        "identity.member.remove",
        "key.deactivate",
        "key.generate",
        "model.governance.create",
        "model.governance.activate",
        "model.governance.show",
        "model.governance.hide",
        "model.governance.retire",
        "model.price.create",
        "model.price.backdate.confirm",
        "model.price.backdate.preview",
        "provider.anthropic.configure",
        "provider.anthropic.delete",
        "provider.anthropic.disable",
        "rotation.settings.update",
        "rotation.trigger",
    }
)
PORTAL_AUDIT_OUTCOMES = frozenset(
    {
        "success",
        "failure",
        "indeterminate",
        "intent",
        "mismatch",
        "denied-active-key",
        "denied-membership",
        "denied-ownership",
    }
)
PROJECT_LOCK_STRIPES = 64
AMBIGUOUS_GENERATE_CLEANUP_LIMIT = 8
DEACTIVATION_POLICY_WAIT_SECONDS = 120
DEACTIVATION_POLICY_POLL_SECONDS = 1
ROTATOR_RESPONSE_MAX_BYTES = 1024 * 1024
DEFINITIVE_IDENTITY_MUTATION_STATUS_CODES = frozenset(
    {400, 401, 403, 404, 409, 422}
)

# --- egress trust pin (Anthropic) -------------------------------------------
#
# The Envoy egress proxy originates TLS to api.anthropic.com against exactly
# this reviewed two-certificate bundle (services/egress-proxy/certs/
# anthropic-ca.pem). A byte-identical copy ships inside this control-plane
# image (app/data/) so the admin console can re-verify the pin on demand
# without any egress network access. The fingerprints below are the REVIEWED
# values; a contract test recomputes them from the committed bundle.
ANTHROPIC_EGRESS_CA_BUNDLE_PATH = (
    Path(__file__).parent / "data" / "anthropic-egress-ca.pem"
)
ANTHROPIC_EGRESS_CA_PINS = (
    {
        "role": "Issuing CA",
        "label": "Google Trust Services WE1",
        "sha256": "1dfc1605fbad358d8bc844f76d15203fac9ca5c1a79fd4857ffaf2864fbebf96",
    },
    {
        "role": "Root",
        "label": "GTS Root R4",
        "sha256": "349dfa4058c5e263123b398ae795573c4e1313c83fe68f93556cd5e8031b3c7d",
    },
)
EGRESS_CA_BUNDLE_MAX_BYTES = 64 * 1024
_PEM_CERTIFICATE_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", re.S
)
_project_locks = tuple(asyncio.Lock() for _ in range(PROJECT_LOCK_STRIPES))
# The admin portal is one container with one worker. This lock serializes
# policy cutover with manual key edits inside that process. The developer
# portal is a separate container, so cross-container safety comes from the
# durable manual-block marker and the post-mutation checks below, not this
# process-local lock.
_admin_key_policy_lock = asyncio.Lock()
# A browser disconnect must not cancel a post-generation authorization check
# halfway through and leave its plaintext-bearing response path in an
# indeterminate state. Keep shielded tasks strongly referenced until they have
# completed; asyncio itself retains only weak references to scheduled tasks.
_post_generation_liveness_tasks: set[asyncio.Task[None]] = set()
_post_deactivation_liveness_tasks: set[asyncio.Task[None]] = set()


class ActiveProjectKeyExists(Exception):
    """Raised when an owner already has an active key for a portal project."""


class VaultSealedAuthorizationUnavailable(HTTPException):
    """A live-authorization failure proven to originate at sealed Vault."""

    def __init__(self) -> None:
        super().__init__(
            status_code=503,
            detail="Current administrator authorization is unavailable while Vault is sealed.",
        )


def _audit(action: str, outcome: str, user: dict[str, Any], **fields: Any) -> None:
    """Emit one-line JSON audit metadata without tokens, email, or log injection."""
    if action not in PORTAL_AUDIT_ACTIONS or outcome not in PORTAL_AUDIT_OUTCOMES:
        logger.error("portal security event rejected an internal schema value")
        return
    operation_id = fields.get("operation_id")
    if operation_id is not None and not _canonical_operation_id(operation_id):
        logger.error("portal security event rejected an operation ID")
        return
    event: dict[str, Any] = {
        "schema_version": 1,
        "event": "aigw.portal.audit",
        "action": action,
        "outcome": outcome,
        "subject": str(user.get("sub") or "")[:255],
    }
    for key, value in fields.items():
        if value is not None:
            event[key] = str(value)[:255]
    # Alloy routes only this exact marker plus the reviewed event/action fields
    # to the SOC feed. Ordinary portal logs remain local.
    logger.info(
        "AIGW_SECURITY_EVENT %s",
        json.dumps(event, separators=(",", ":"), ensure_ascii=True),
    )


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


def _identity_mutation_result(error: Exception) -> str:
    """Return failure only when a reviewed 4xx proves no mutation."""

    if isinstance(error, httpx.HTTPStatusError):
        if error.response.status_code in DEFINITIVE_IDENTITY_MUTATION_STATUS_CODES:
            return "failure"
    return "indeterminate"


def _audit_signed_session_denial(request: Request, action: str) -> None:
    """Audit a denial only when the signed session names a user."""

    user = request.session.get("user")
    if not isinstance(user, dict):
        return
    subject = user.get("sub")
    if not isinstance(subject, str) or not subject:
        return
    _audit(action, "failure", user)


FORBIDDEN_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>403 Forbidden</title>
<style>
body{background:#0f1420;color:#e6e9f0;font-family:-apple-system,sans-serif;
display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.box{background:#161d2e;border:1px solid #263048;border-radius:10px;padding:32px 40px;text-align:center;max-width:26rem}
.box p{color:#aab3c5;line-height:1.5}
a.btn{display:inline-block;margin-top:8px;background:#4f7cff;color:#fff;
text-decoration:none;padding:9px 18px;border-radius:7px;font-weight:600}
</style></head>
<body><div class="box">
<h1>403 — Access not available</h1>
<p>You are signed in, but this account does not have the role this portal
requires. If you need developer access, ask an administrator to grant it.</p>
<p><a class="btn" href="/logout">Sign out</a></p>
</div></body></html>"""


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        await auth.ensure_oauth_client()
    except Exception as exc:  # noqa: BLE001 - startup must not crash the app
        print(
            f"[dev-portal] warning: could not initialize OIDC client at startup: {exc}"
        )
    # Schedule the process-local egress-trust canary; the first check runs
    # inside the task, never inline, so startup is not blocked on it.
    _start_egress_trust_canary()
    try:
        yield
    finally:
        _stop_egress_trust_canary()


app = FastAPI(
    title="AI Gateway dev-portal",
    lifespan=lifespan,
    # This is a browser portal, not a public API. Do not expose interactive API
    # documentation or its schema as unnecessary unauthenticated surface.
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
admin_app = FastAPI(
    title="AI Gateway admin-portal",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.include_router(model_discovery_router)


def _install_session_middleware(target: FastAPI, cookie_name: str) -> None:
    target.add_middleware(
        SessionMiddleware,
        secret_key=settings.session_secret,
        session_cookie=cookie_name,
        # TLS is terminated at Traefik and both portals are reachable only
        # behind their exact edge. OIDC callbacks are cross-site top-level
        # GETs, so SameSite=Lax is required for the state/nonce cookie.
        same_site="lax",
        https_only=True,
        max_age=settings.session_max_age_seconds,
    )


_install_session_middleware(app, "aigw_portal_session")
_install_session_middleware(admin_app, "aigw_admin_session")


async def security_headers(request: Request, call_next):
    """Keep bearer-key pages out of caches and contain browser-side injection."""
    nonce = secrets.token_urlsafe(18)
    request.state.csp_nonce = nonce
    response = await call_next(request)
    response.headers["Cache-Control"] = (
        "no-store, no-cache, must-revalidate, max-age=0, private"
    )
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; "
        f"script-src 'nonce-{nonce}'; "
        "style-src 'unsafe-inline'; img-src 'self' data:; "
        "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    )
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    )
    return response


# Register the same browser hardening on two independent ASGI applications.
app.middleware("http")(security_headers)
admin_app.middleware("http")(security_headers)


@app.exception_handler(auth.NotAuthenticated)
async def handle_not_authenticated(
    request: Request, exc: auth.NotAuthenticated
) -> RedirectResponse:
    return RedirectResponse("/login", status_code=303)


@app.exception_handler(auth.NotAuthorized)
async def handle_not_authorized(
    request: Request, exc: auth.NotAuthorized
) -> HTMLResponse:
    _audit_signed_session_denial(request, "authorization.role.denied")
    return HTMLResponse(FORBIDDEN_HTML, status_code=403)


@app.exception_handler(auth.ReauthenticationRequired)
async def handle_reauthentication_required(
    request: Request, exc: auth.ReauthenticationRequired
) -> RedirectResponse:
    _audit_signed_session_denial(request, "authorization.step_up.required")
    auth.flash(
        request,
        "Please sign in to Keycloak again before changing identity access.",
        "info",
    )
    return RedirectResponse("/admin/reauth", status_code=303)


admin_app.add_exception_handler(auth.NotAuthenticated, handle_not_authenticated)
admin_app.add_exception_handler(auth.NotAuthorized, handle_not_authorized)
admin_app.add_exception_handler(
    auth.ReauthenticationRequired, handle_reauthentication_required
)


# --- health ---


@app.get("/healthz")
async def healthz() -> dict[str, bool]:
    return {"ok": True}


admin_app.add_api_route("/healthz", healthz, methods=["GET"])


# --- auth routes ---


@app.get("/login", response_class=HTMLResponse, name="login_page")
async def login_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "admin_surface": request.app is admin_app,
            "flashes": auth.pop_flash(request),
        },
    )


@app.get("/login/start")
async def login_start(request: Request):
    # This is an ordinary login/account switch, not an admin step-up.
    request.session.pop("admin_step_up_subject", None)
    try:
        await auth.ensure_oauth_client()
    except Exception:  # noqa: BLE001
        auth.flash(
            request,
            "The identity provider is temporarily unavailable. Try again shortly.",
            "error",
        )
        return RedirectResponse("/login", status_code=303)

    redirect_uri = str(request.url_for("auth_callback"))
    return await auth.oauth.keycloak.authorize_redirect(request, redirect_uri)


@app.get("/auth/callback", name="auth_callback")
async def auth_callback(request: Request):
    step_up_subject = request.session.get("admin_step_up_subject")
    try:
        await auth.ensure_oauth_client()
        token = await auth.oauth.keycloak.authorize_access_token(request)
        userinfo = auth.verified_userinfo(token)
        if step_up_subject is not None:
            if not isinstance(step_up_subject, str) or not step_up_subject:
                raise auth.InvalidIdentity("invalid step-up session state")
            auth.validate_step_up_identity(userinfo, step_up_subject)
        auth.establish_session(request, token, userinfo)
        if step_up_subject is not None:
            auth.mark_recent_admin_reauthentication(request)
    except Exception:  # noqa: BLE001 - never leak IdP error internals to the user
        # Do not leave a previously authenticated identity active after a
        # failed or invalid account-switch callback.
        request.session.clear()
        auth.flash(request, "Login failed. Please try again.", "error")
        return RedirectResponse("/login", status_code=303)

    return RedirectResponse(
        "/admin" if step_up_subject is not None else "/", status_code=303
    )


@admin_app.get("/admin/reauth")
async def admin_reauthenticate(
    request: Request, user: dict[str, Any] = Depends(auth.require_admin)
):
    try:
        await auth.ensure_oauth_client()
        request.session.pop("admin_reauth_at", None)
        request.session["admin_step_up_subject"] = user["sub"]
        redirect_uri = str(request.url_for("auth_callback"))
        return await auth.oauth.keycloak.authorize_redirect(
            request,
            redirect_uri,
            prompt="login",
            max_age=0,
        )
    except Exception:  # noqa: BLE001 - never expose IdP internals
        request.session.pop("admin_step_up_subject", None)
        auth.flash(
            request,
            "Could not start Keycloak reauthentication. Try again shortly.",
            "error",
        )
        return RedirectResponse("/admin", status_code=303)


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    end_session = auth.end_session_url()
    if end_session:
        post_logout_redirect_uri = str(request.url_for("login_page"))
        query = urlencode(
            {
                "post_logout_redirect_uri": post_logout_redirect_uri,
                "client_id": settings.oidc_client_id,
            }
        )
        return RedirectResponse(f"{end_session}?{query}", status_code=303)
    return RedirectResponse("/login", status_code=303)


# Login/logout handlers are shared implementation, but each ASGI app resolves
# callbacks against its own host, OIDC client, cookie, and session secret.
admin_app.add_api_route(
    "/login",
    login_page,
    methods=["GET"],
    response_class=HTMLResponse,
    name="login_page",
)
admin_app.add_api_route("/login/start", login_start, methods=["GET"])
admin_app.add_api_route(
    "/auth/callback", auth_callback, methods=["GET"], name="auth_callback"
)
admin_app.add_api_route("/logout", logout, methods=["GET"])


@admin_app.get("/")
async def admin_root() -> RedirectResponse:
    return RedirectResponse("/admin", status_code=303)


# --- index / key management ---


def _project_lock(user_id: str, project_id: str) -> asyncio.Lock:
    """Bounded lock striping prevents unbounded user-controlled lock growth.

    The developer portal is one container with one explicitly configured
    Uvicorn worker. This lock serializes its list/generate/deactivate checks
    for an owner+project pair. The admin portal is a separate container, so
    policy races are closed by controller revisions, durable key markers, and
    shielded post-mutation checks rather than this process-local lock.
    """
    digest = hashlib.blake2s(
        f"{user_id}\0{project_id}".encode("utf-8"), digest_size=2
    ).digest()
    return _project_locks[int.from_bytes(digest, "big") % PROJECT_LOCK_STRIPES]


def _key_metadata(entry: dict[str, Any]) -> dict[str, Any]:
    """Decode LiteLLM metadata without turning malformed portal state into none.

    The complete owner inventory controls whether another static bearer key
    may be issued.  A malformed metadata field can belong to a previously
    portal-created key, so silently treating it as an ordinary unmanaged key
    would weaken the one-active-key invariant.
    """

    raw = entry.get("metadata")
    if isinstance(raw, dict):
        return raw
    if raw in (None, ""):
        return {}
    if isinstance(raw, str) and len(raw.encode("utf-8")) <= 64 * 1024:
        try:
            parsed = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise litellm_client.LiteLLMError(
                "key inventory metadata is not valid JSON"
            ) from exc
        if isinstance(parsed, dict):
            return parsed
    raise litellm_client.LiteLLMError("key inventory metadata is not a bounded object")


def _entry_project_id(entry: dict[str, Any]) -> str | None:
    """Return a project's ID only for a key minted by this portal.

    The dev portal holds a powerful LiteLLM control credential, but it must
    only render, deactivate, or count keys whose immutable provenance it
    created.  Native ``project_id`` and arbitrary metadata also occur on
    operator-managed keys; treating either as portal provenance would let a
    user deactivate another control-plane key merely because it shares an
    owner/project label.
    """

    metadata = _key_metadata(entry)
    if (
        metadata.get(litellm_client.PORTAL_KEY_CREATOR_FIELD)
        != litellm_client.PORTAL_KEY_CREATOR_VALUE
    ):
        return None

    project_id = metadata.get(litellm_client.PORTAL_PROJECT_METADATA_KEY)
    if (
        not isinstance(project_id, str)
        or litellm_client.PROJECT_ID_RE.fullmatch(project_id) is None
    ):
        # A legacy/corrupted portal key cannot be assigned safely when a user
        # may belong to multiple managed projects.  Fail closed instead of
        # silently allowing a second active key or exposing its identifier.
        raise litellm_client.LiteLLMError(
            "portal key has no unambiguous project identifier"
        )
    return project_id


def _is_active_key(entry: dict[str, Any], *, now: datetime | None = None) -> bool:
    """Treat malformed lifecycle data as active so duplicate creation fails safe."""
    if entry.get("blocked") is True:
        return False
    expires = entry.get("expires")
    if expires is None or expires == "":
        return True
    if isinstance(expires, datetime):
        expiry = expires
    elif isinstance(expires, str):
        try:
            expiry = datetime.fromisoformat(expires.strip().replace("Z", "+00:00"))
        except ValueError:
            return True
    else:
        return True
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    reference = now or datetime.now(timezone.utc)
    return expiry > reference


def _portal_key_inventory(
    owned_keys: list[Any], expected_user_id: str, allowed_projects: tuple[str, ...]
) -> list[dict[str, Any]]:
    """Select only keys in the subject's live managed Keycloak projects."""
    inventory: list[dict[str, Any]] = []
    allowed = frozenset(allowed_projects)
    if not allowed or len(allowed) != len(allowed_projects):
        raise litellm_client.LiteLLMError(
            "live project authorization is empty or ambiguous"
        )
    for entry in owned_keys:
        if not isinstance(entry, dict):
            # litellm_client already rejects this, but keep this boundary local.
            raise litellm_client.LiteLLMError("key inventory entry is not an object")
        if entry.get("user_id") != expected_user_id:
            raise litellm_client.LiteLLMError(
                "key inventory contains a key outside the authenticated owner"
            )
        project_id = _entry_project_id(entry)
        if project_id not in allowed:
            continue
        normalized = dict(entry)
        normalized["portal_project_id"] = project_id
        normalized["portal_active"] = _is_active_key(entry)
        inventory.append(normalized)
    return inventory


def _active_project_keys(
    inventory: list[dict[str, Any]], project_id: str
) -> list[dict[str, Any]]:
    return [
        entry
        for entry in inventory
        if entry.get("portal_project_id") == project_id
        and entry.get("portal_active") is True
    ]


def _entry_delete_id(entry: dict[str, Any]) -> str | None:
    """Return the concrete token/hash for a previously authorized key object."""
    # Full `/key/list` objects store the database token hash in `token` (or the
    # legacy `key_name`). Never consume/render a `key` field on a later GET;
    # that field is reserved for the one-time generate response and could be
    # plaintext if an upstream response shape regressed.
    for field in ("token", "key_name"):
        value = entry.get(field)
        if isinstance(value, str) and value:
            return value
    return None


def _metadata_replacement_updates(
    entry: dict[str, Any], metadata: dict[str, Any], *, blocked: bool
) -> dict[str, Any]:
    """Build one provenance-safe metadata replacement for LiteLLM."""

    updates: dict[str, Any] = {"blocked": blocked, "metadata": metadata}
    if (
        litellm_client.PORTAL_DEFAULT_MODEL_METADATA_KEY in metadata
        or litellm_client.PORTAL_MODEL_LIMITS_METADATA_KEY in metadata
    ):
        models = entry.get("models")
        if not isinstance(models, list) or not models or any(
            not isinstance(model, str) for model in models
        ):
            raise litellm_client.LiteLLMError(
                "portal key model scope is invalid"
            )
        updates["models"] = sorted(models)
    return updates


async def _block_key_with_durable_intent(
    entry: dict[str, Any],
) -> dict[str, Any]:
    """Block one pre-resolved key and make a portal block survive policy retry."""

    concrete = _entry_delete_id(entry)
    if concrete is None:
        raise litellm_client.LiteLLMError(
            "key has no concrete identifier for a durable block"
        )
    project_id = _entry_project_id(entry)
    if project_id is None:
        updates: dict[str, Any] = {"blocked": True}
    else:
        metadata = dict(_key_metadata(entry))
        metadata[litellm_client.PORTAL_MANUAL_BLOCK_METADATA_KEY] = True
        metadata.pop(litellm_client.PORTAL_POLICY_GATE_METADATA_KEY, None)
        updates = _metadata_replacement_updates(entry, metadata, blocked=True)
    try:
        await litellm_client.key_update(concrete, updates)
    except litellm_client.LiteLLMError:
        # A lost response may still have committed. The exact read below is
        # the decision and keeps the operation retry-safe.
        pass
    after = await litellm_client.admin_key_lookup(concrete)
    if after.get("blocked") is not True:
        raise litellm_client.LiteLLMError("key remained active after block")
    if project_id is not None:
        after_metadata = _key_metadata(after)
        if (
            _entry_project_id(after) != project_id
            or after_metadata.get(
                litellm_client.PORTAL_MANUAL_BLOCK_METADATA_KEY
            )
            is not True
            or litellm_client.PORTAL_POLICY_GATE_METADATA_KEY in after_metadata
        ):
            raise litellm_client.LiteLLMError(
                "portal key durable block did not verify"
            )
    return after


async def _unblock_key_with_durable_intent(
    entry: dict[str, Any],
) -> dict[str, Any]:
    """Unblock one pre-resolved key and explicitly clear its manual marker."""

    concrete = _entry_delete_id(entry)
    if concrete is None:
        raise litellm_client.LiteLLMError(
            "key has no concrete identifier for unblock"
        )
    project_id = _entry_project_id(entry)
    if project_id is None:
        updates: dict[str, Any] = {"blocked": False}
    else:
        metadata = dict(_key_metadata(entry))
        metadata.pop(litellm_client.PORTAL_MANUAL_BLOCK_METADATA_KEY, None)
        metadata.pop(litellm_client.PORTAL_POLICY_GATE_METADATA_KEY, None)
        updates = _metadata_replacement_updates(entry, metadata, blocked=False)
    try:
        await litellm_client.key_update(concrete, updates)
    except litellm_client.LiteLLMError:
        pass
    after = await litellm_client.admin_key_lookup(concrete)
    if after.get("blocked") is True:
        raise litellm_client.LiteLLMError("key remained blocked after unblock")
    if project_id is not None:
        after_metadata = _key_metadata(after)
        if (
            _entry_project_id(after) != project_id
            or litellm_client.PORTAL_MANUAL_BLOCK_METADATA_KEY in after_metadata
            or litellm_client.PORTAL_POLICY_GATE_METADATA_KEY in after_metadata
        ):
            raise litellm_client.LiteLLMError(
                "portal key durable unblock did not verify"
            )
    return after


def _resolve_owned_project_key(
    inventory: list[dict[str, Any]], token: str, project_id: str
) -> str | None:
    """Resolve only an exact concrete ID inside the authenticated project."""
    for entry in inventory:
        if entry.get("portal_project_id") != project_id:
            continue
        if token in (entry.get("token"), entry.get("key_name")):
            return _entry_delete_id(entry)
    return None


def _concrete_key_ids(entries: list[Any]) -> frozenset[str]:
    """Collect concrete identifiers from a previously validated owner list."""
    return frozenset(
        concrete
        for entry in entries
        if isinstance(entry, dict) and (concrete := _entry_delete_id(entry)) is not None
    )


def _ambiguous_generate_cleanup_ids(
    before_ids: frozenset[str],
    after: list[dict[str, Any]],
    alias: str,
    project_id: str,
) -> list[str]:
    """Identify only new, manageable keys attributable to the failed request.

    An HTTP transport failure is ambiguous: LiteLLM may have committed the key
    before its response was lost.  Never guess from an alias alone.  A cleanup
    candidate must be active, explicitly portal-created, in the exact project,
    carry the requested alias, expose a concrete persisted identifier, and be
    absent from the complete pre-request owner inventory.
    """
    candidates: list[str] = []
    seen: set[str] = set()
    for entry in after:
        if (
            entry.get("portal_project_id") != project_id
            or entry.get("portal_active") is not True
            or _key_metadata(entry).get("created_via") != "dev-portal"
            or (entry.get("key_alias") or entry.get("alias")) != alias
        ):
            continue
        concrete = _entry_delete_id(entry)
        if concrete is None:
            raise litellm_client.LiteLLMError(
                "ambiguous key/generate candidate has no concrete identifier"
            )
        if concrete in before_ids or concrete in seen:
            continue
        seen.add(concrete)
        candidates.append(concrete)

    if len(candidates) > AMBIGUOUS_GENERATE_CLEANUP_LIMIT:
        raise litellm_client.LiteLLMError(
            "ambiguous key/generate produced too many cleanup candidates"
        )
    return candidates


async def _cleanup_ambiguous_generation(
    user_id: str,
    alias: str,
    project_id: str,
    before_ids: frozenset[str],
    allowed_projects: tuple[str, ...],
) -> None:
    """Best-effort bounded cleanup after an indeterminate generate outcome."""
    try:
        after = _portal_key_inventory(
            await litellm_client.key_list(user_id), user_id, allowed_projects
        )
        cleanup_ids = _ambiguous_generate_cleanup_ids(
            before_ids, after, alias, project_id
        )
    except litellm_client.LiteLLMError:
        # Do not include upstream errors or key identifiers in this log. The
        # caller will fail closed with the original generation error.
        logger.error(
            "could not safely reconcile an ambiguous key generation for subject %s",
            user_id,
        )
        return

    for cleanup_id in cleanup_ids:
        try:
            await litellm_client.key_deactivate(cleanup_id)
        except litellm_client.LiteLLMError:
            logger.error(
                "failed to deactivate an ambiguous generated key for subject %s",
                user_id,
            )


def _plaintext_key(result: dict[str, Any]) -> str:
    # LiteLLM's generate contract returns the newly issued plaintext in `key`.
    # Do not fall back to `token`: list/update responses use that name for the
    # persisted database identifier/hash, which must never be mistaken for a
    # usable credential or disclosed as one.
    value = result.get("key")
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise litellm_client.LiteLLMError(
            "key/generate returned no bounded plaintext key"
        )
    return value


async def _generate_project_key(
    user_id: str,
    alias: str,
    project_id: str,
    allowed_projects: tuple[str, ...],
    project_policy: dict[str, Any] | None = None,
    username: str | None = None,
) -> tuple[str, list[dict[str, Any]]]:
    """Serialize and verify the one-active-key invariant before disclosure."""
    async with _project_lock(user_id, project_id):
        before_owned = await litellm_client.key_list(user_id)
        before = _portal_key_inventory(before_owned, user_id, allowed_projects)
        if _active_project_keys(before, project_id):
            raise ActiveProjectKeyExists
        before_ids = _concrete_key_ids(before_owned)

        try:
            result = await litellm_client.key_generate(
                user_id, alias, project_id, project_policy, username=username
            )
        except litellm_client.LiteLLMError:
            # LiteLLM may commit before a timeout/disconnect loses the response.
            # Reconcile under the same owner/project lock and remove only exact
            # new portal-owned candidates; never disclose an indeterminate key.
            await _cleanup_ambiguous_generation(
                user_id,
                alias,
                project_id,
                before_ids,
                allowed_projects,
            )
            raise
        plaintext: str | None = None
        after: list[dict[str, Any]] = []
        active: list[dict[str, Any]] = []
        response_error: litellm_client.LiteLLMError | None = None
        if not isinstance(result, dict):
            response_error = litellm_client.LiteLLMError(
                "key/generate returned an invalid response shape"
            )
        else:
            try:
                plaintext = _plaintext_key(result)
            except litellm_client.LiteLLMError as exc:
                response_error = exc
        try:
            after = _portal_key_inventory(
                await litellm_client.key_list(user_id), user_id, allowed_projects
            )
            active = _active_project_keys(after, project_id)
            if response_error is not None:
                raise response_error
            aliases = {
                str(entry.get("key_alias") or entry.get("alias") or "")
                for entry in active
            }
            if len(active) != 1 or alias not in aliases:
                raise litellm_client.LiteLLMError(
                    "post-generate inventory violated the one-active-key invariant"
                )
            # Verify the enforced default actually landed on the minted key's
            # metadata (the LiteLLM pre-call hook reads it from there). A key
            # that cannot prove its policy stamp is never disclosed.
            if project_policy is not None and _key_metadata(active[0]).get(
                litellm_client.PORTAL_DEFAULT_MODEL_METADATA_KEY
            ) != project_policy.get("default_model"):
                raise litellm_client.LiteLLMError(
                    "minted key did not verify the project's default model"
                )
            if project_policy is not None:
                model_limits = project_policy.get("model_limits", {})
                allowed_models = project_policy.get("allowed_models") or []
                expected_revision = project_policy.get(
                    litellm_client.PROJECT_POLICY_REVISION_FIELD
                )
                if (
                    not isinstance(expected_revision, str)
                    or litellm_client.POLICY_REVISION_RE.fullmatch(
                        expected_revision
                    )
                    is None
                    or _key_metadata(active[0]).get(
                        litellm_client.PORTAL_POLICY_REVISION_METADATA_KEY
                    )
                    != expected_revision
                ):
                    raise litellm_client.LiteLLMError(
                        "minted key did not verify the project's policy revision"
                    )
                expected_limits = (
                    litellm_client.canonical_model_limits(
                        model_limits, allowed_models
                    )
                    if model_limits
                    else None
                )
                if _key_metadata(active[0]).get(
                    litellm_client.PORTAL_MODEL_LIMITS_METADATA_KEY
                ) != expected_limits:
                    raise litellm_client.LiteLLMError(
                        "minted key did not verify the project's per-model limits"
                    )
        except Exception:
            # Never disclose a key that could not be proven unique/manageable.
            # /key/update accepts either plaintext or its stored hash. If the
            # generate response itself was malformed, resolve the candidate
            # created after an inventory that was proven to contain no active
            # key before generation.
            if plaintext is not None:
                cleanup_ids = [plaintext]
            else:
                try:
                    cleanup_ids = _ambiguous_generate_cleanup_ids(
                        before_ids, after, alias, project_id
                    )
                except litellm_client.LiteLLMError:
                    # The response did not supply a plaintext identifier and
                    # inventory could not prove a small exact candidate set.
                    # Fail closed without mutating unrelated owner keys.
                    logger.error(
                        "could not safely identify an unverified generated key "
                        "for subject %s",
                        user_id,
                    )
                    cleanup_ids = []
            for cleanup_id in cleanup_ids:
                try:
                    await litellm_client.key_deactivate(cleanup_id)
                except litellm_client.LiteLLMError:
                    logger.error(
                        "failed to deactivate an unverified generated key for subject %s",
                        user_id,
                    )
            raise
        # Keep this invariant executable even under an optimized interpreter;
        # Python ``assert`` would disappear and could turn an impossible
        # malformed upstream response into a false-success response.
        if plaintext is None:
            raise litellm_client.LiteLLMError(
                "key/generate plaintext validation did not complete"
            )
        return plaintext, after


def _retain_post_generation_liveness_task(
    task: asyncio.Task[None],
) -> asyncio.Task[None]:
    """Keep a shielded post-generation check alive after client cancellation."""

    _post_generation_liveness_tasks.add(task)

    def _complete(completed: asyncio.Task[None]) -> None:
        _post_generation_liveness_tasks.discard(completed)
        if completed.cancelled():
            logger.error(
                "post-generation membership verification was cancelled; "
                "generated plaintext was not disclosed"
            )
            return
        # Retrieve any exception even when the browser disconnected before the
        # shielded waiter could observe it. The exception remains available to
        # an active waiter, but this avoids an unobserved-task warning.
        if completed.exception() is not None:
            logger.warning(
                "post-generation membership verification failed; generated "
                "plaintext was not disclosed"
            )

    task.add_done_callback(_complete)
    return task


async def _deactivate_undisclosed_generated_key(key_value: str) -> None:
    """Attempt bounded cleanup without ever logging the generated credential."""

    try:
        await litellm_client.key_deactivate(key_value)
    except Exception:  # noqa: BLE001 - cleanup must not turn into disclosure
        # The caller still fails closed. The identity controller's independent
        # reconciliation will retry any static key that survives this bounded
        # direct attempt, but the browser never receives its plaintext.
        logger.error(
            "could not deactivate a generated key after membership could not "
            "be verified"
        )


async def _verify_post_generation_liveness(
    request: Request,
    user: dict[str, Any],
    project_id: str,
    key_value: str,
    expected_policy_revision: str,
) -> None:
    """Prove membership and policy revision before disclosing a new key."""

    try:
        projects = await _live_project_ids(request, user)
        policies = await _live_project_policies(request, user, projects)
    except Exception:  # noqa: BLE001 - HTTP 503/ambiguous membership is unsafe
        await _deactivate_undisclosed_generated_key(key_value)
        raise

    current_policy = policies.get(project_id)
    try:
        current_revision = litellm_client.project_policy_revision(current_policy)
    except litellm_client.LiteLLMError:
        current_revision = ""
    if project_id not in projects or not hmac.compare_digest(
        current_revision, expected_policy_revision
    ):
        await _deactivate_undisclosed_generated_key(key_value)
        raise litellm_client.LiteLLMError(
            "project membership or policy changed during key generation"
        )


def _retain_post_deactivation_liveness_task(
    task: asyncio.Task[None],
) -> asyncio.Task[None]:
    """Keep a deactivation check alive after a browser disconnect."""

    _post_deactivation_liveness_tasks.add(task)

    def _complete(completed: asyncio.Task[None]) -> None:
        _post_deactivation_liveness_tasks.discard(completed)
        if completed.cancelled():
            logger.error("post-deactivation policy verification was cancelled")
            return
        if completed.exception() is not None:
            logger.warning("post-deactivation policy verification failed closed")

    task.add_done_callback(_complete)
    return task


async def _verify_post_deactivation_liveness(
    request: Request,
    user: dict[str, Any],
    project_id: str,
    concrete_id: str,
) -> None:
    """Keep a developer-deactivated key blocked across policy cutover.

    The policy controller and developer portal run in different containers.
    A temporary policy gate could otherwise be mistaken for the only reason a
    key is blocked and a retry could turn it back on. The durable manual marker
    is the primary control. This check waits out a pending revision and repairs
    a stale cross-process write before the route reports success.
    """

    subject = user.get("sub")
    if not isinstance(subject, str):
        raise litellm_client.LiteLLMError("deactivation owner is invalid")
    deadline = time.monotonic() + DEACTIVATION_POLICY_WAIT_SECONDS
    while True:
        try:
            before = await _live_project_policies(
                request, user, (project_id,)
            )
        except HTTPException as exc:
            if exc.status_code != 503 or time.monotonic() >= deadline:
                raise litellm_client.LiteLLMError(
                    "project policy did not settle after key deactivation"
                ) from exc
            await asyncio.sleep(DEACTIVATION_POLICY_POLL_SECONDS)
            continue
        try:
            before_revision = litellm_client.project_policy_revision(
                before[project_id]
            )
            entry = await litellm_client.admin_key_lookup(concrete_id)
            if (
                entry.get("user_id") != subject
                or _entry_project_id(entry) != project_id
            ):
                raise litellm_client.LiteLLMError(
                    "deactivated key ownership changed"
                )
            metadata = _key_metadata(entry)
            if (
                entry.get("blocked") is not True
                or metadata.get(
                    litellm_client.PORTAL_MANUAL_BLOCK_METADATA_KEY
                )
                is not True
                or litellm_client.PORTAL_POLICY_GATE_METADATA_KEY in metadata
            ):
                await _block_key_with_durable_intent(entry)
            after = await _live_project_policies(request, user, (project_id,))
            after_revision = litellm_client.project_policy_revision(
                after[project_id]
            )
        except HTTPException as exc:
            if exc.status_code != 503 or time.monotonic() >= deadline:
                raise litellm_client.LiteLLMError(
                    "project policy did not settle after key deactivation"
                ) from exc
            await asyncio.sleep(DEACTIVATION_POLICY_POLL_SECONDS)
            continue
        if hmac.compare_digest(before_revision, after_revision):
            final = await litellm_client.admin_key_lookup(concrete_id)
            final_metadata = _key_metadata(final)
            if (
                final.get("user_id") == subject
                and _entry_project_id(final) == project_id
                and final.get("blocked") is True
                and final_metadata.get(
                    litellm_client.PORTAL_MANUAL_BLOCK_METADATA_KEY
                )
                is True
                and litellm_client.PORTAL_POLICY_GATE_METADATA_KEY
                not in final_metadata
            ):
                return
        if time.monotonic() >= deadline:
            raise litellm_client.LiteLLMError(
                "key deactivation could not be verified after policy cutover"
            )
        await asyncio.sleep(DEACTIVATION_POLICY_POLL_SECONDS)


async def _project_policy_view(
    request: Request, user: dict[str, Any], project_ids: tuple[str, ...]
) -> tuple[dict[str, dict[str, Any]], list[str], str | None]:
    """Resolve the non-secret policy/model context for user-facing pages.

    Display never shows cost to users — only the token rate limits and the
    project's allowed models with the default marked. A failed policy read
    degrades to an explanatory note (minting separately fails closed).
    """
    project_policies: dict[str, dict[str, Any]] = {}
    policy_error: str | None = None
    available_models: list[str] = []
    if project_ids:
        try:
            project_policies = await _live_project_policies(
                request, user, project_ids
            )
        except HTTPException:
            policy_error = (
                "Project rate-limit/model policy is unavailable right now; "
                "key creation is paused until it can be verified."
            )
        try:
            available_models = await litellm_client.model_names()
        except litellm_client.LiteLLMError:
            available_models = []
    return project_policies, available_models, policy_error


@app.get("/", response_class=HTMLResponse)
async def index(
    request: Request, user: dict[str, Any] = Depends(auth.require_developer)
) -> HTMLResponse:
    project_ids = await _live_project_ids(request, user)
    list_error: str | None = None
    if not project_ids:
        keys = []
        list_error = (
            "Your account is not assigned to a managed developer project. "
            "Ask an AI Gateway administrator to add you to one."
        )
    else:
        try:
            keys = _portal_key_inventory(
                await litellm_client.key_list(user["sub"]),
                user["sub"],
                project_ids,
            )
        except litellm_client.LiteLLMError:
            keys = []
            list_error = "Could not safely list your keys from the gateway right now."
    project_policies, available_models, policy_error = await _project_policy_view(
        request, user, project_ids
    )

    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "user": user,
            "is_admin": False,
            "keys": keys,
            "list_error": list_error,
            "new_key": None,
            "new_tools": [],
            "project_ids": project_ids,
            "project_policies": project_policies,
            "available_models": available_models,
            "no_models_sentinel": litellm_client.NO_MODELS_SENTINEL,
            "policy_error": policy_error,
            # The "Connect a tool" tab always renders placeholder snippets;
            # a generated key exists only in its one-time POST response.
            "tools": tools.rendered_tools(settings.public_api_base, "YOUR_KEY"),
            "api_base": settings.public_api_base,
            "flashes": auth.pop_flash(request),
            "csrf_token": auth.get_csrf_token(request),
        },
    )


@app.post("/keys")
async def create_key(
    request: Request,
    user: dict[str, Any] = Depends(auth.require_developer),
    alias: str = Form(..., max_length=128),
    project_id: str = Form(..., max_length=64),
    csrf_token: str = Form(..., min_length=32, max_length=128),
):
    if not auth.verify_csrf(request, csrf_token):
        auth.flash(request, "Your session expired — please try again.", "error")
        return RedirectResponse("/", status_code=303)

    project_ids = await _live_project_ids(request, user)
    clean_alias = (alias.strip() or f"{user['name'] or user['sub']}-key")[:128]
    clean_project = project_id.strip()
    if clean_project not in project_ids:
        _audit(
            "key.generate",
            "denied-membership",
            user,
            project=clean_project,
        )
        raise HTTPException(
            status_code=403, detail="Project membership is missing or was revoked."
        )
    # The runtime per-project policy (admin-managed Keycloak group attributes)
    # decides this key's rate caps and model set. Unreadable or ambiguous
    # policy fails the mint closed (503) rather than minting unlimited.
    policies = await _live_project_policies(request, user, project_ids)
    project_policy = dict(policies[clean_project])
    try:
        policy_revision = litellm_client.project_policy_revision(project_policy)
    except litellm_client.LiteLLMError as exc:
        raise HTTPException(
            status_code=503,
            detail="Current project policy could not be verified.",
        ) from exc
    if project_policy["allowed_models"] is None:
        # Expand "all" to the exact public model set at mint time. An empty
        # LiteLLM allowlist means every present and future model, which could
        # silently authorize a later hidden model.
        try:
            public_models = await litellm_client.model_names()
        except litellm_client.LiteLLMError as exc:
            raise HTTPException(
                status_code=503,
                detail="Current model access policy could not be verified.",
            ) from exc
        if not public_models:
            raise HTTPException(
                status_code=503,
                detail="No public model is available for key creation.",
            )
        project_policy["allowed_models"] = public_models
    project_policy[litellm_client.PROJECT_POLICY_REVISION_FIELD] = policy_revision
    try:
        key_value, keys = await _generate_project_key(
            user["sub"],
            clean_alias,
            clean_project,
            project_ids,
            project_policy,
            # Telemetry attribution: the authenticated preferred_username is
            # stamped into key metadata (aigw_username) so the audit stream
            # can render a readable identity beside the subject UUID.
            username=user.get("username"),
        )
        # Close the normal group-removal race before the one-time plaintext is
        # rendered. The check is shielded so a browser disconnect cannot abort
        # its revoke path; any revoked, unavailable, or ambiguous live decision
        # leaves the key undisclosed.
        post_generation_liveness = _retain_post_generation_liveness_task(
            asyncio.create_task(
                _verify_post_generation_liveness(
                    request,
                    user,
                    clean_project,
                    key_value,
                    policy_revision,
                )
            )
        )
        await asyncio.shield(post_generation_liveness)
    except ActiveProjectKeyExists:
        _audit(
            "key.generate",
            "denied-active-key",
            user,
            alias=clean_alias,
            project=clean_project,
        )
        auth.flash(
            request,
            "This project already has an active key. Deactivate it before creating another.",
            "error",
        )
        return RedirectResponse("/", status_code=303)
    except litellm_client.LiteLLMError as exc:
        logger.warning("key_generate failed for subject %s: %s", user.get("sub"), exc)
        _audit(
            "key.generate",
            "failure",
            user,
            alias=clean_alias,
            project=clean_project,
        )
        auth.flash(
            request, "Could not create a key right now. Please try again.", "error"
        )
        return RedirectResponse("/", status_code=303)

    _audit(
        "key.generate",
        "success",
        user,
        alias=clean_alias,
        project=clean_project,
    )
    try:
        available_models = await litellm_client.model_names()
    except litellm_client.LiteLLMError:
        available_models = []
    response = templates.TemplateResponse(
        request,
        "index.html",
        {
            "user": user,
            "is_admin": False,
            "keys": keys,
            "list_error": None,
            "new_key": key_value,
            "new_tools": tools.rendered_tools(settings.public_api_base, key_value),
            "project_ids": project_ids,
            "project_policies": policies,
            "available_models": available_models,
            "no_models_sentinel": litellm_client.NO_MODELS_SENTINEL,
            "policy_error": None,
            "tools": tools.rendered_tools(settings.public_api_base, "YOUR_KEY"),
            "api_base": settings.public_api_base,
            "selected_project": clean_project,
            "flashes": auth.pop_flash(request),
            "csrf_token": auth.get_csrf_token(request),
        },
        status_code=201,
    )
    response.headers["Content-Location"] = "/"
    return response


@app.post("/keys/deactivate")
async def deactivate_key(
    request: Request,
    user: dict[str, Any] = Depends(auth.require_developer),
    token: str = Form(..., min_length=1, max_length=2048),
    project_id: str = Form(..., max_length=64),
    csrf_token: str = Form(..., min_length=32, max_length=128),
):
    if not auth.verify_csrf(request, csrf_token):
        auth.flash(request, "Your session expired — please try again.", "error")
        return RedirectResponse("/", status_code=303)

    project_ids = await _live_project_ids(request, user)
    clean_project = project_id.strip()
    if clean_project not in project_ids:
        _audit(
            "key.deactivate",
            "denied-membership",
            user,
            project=clean_project,
        )
        raise HTTPException(
            status_code=403, detail="Project membership is missing or was revoked."
        )

    try:
        async with _project_lock(user["sub"], clean_project):
            before = _portal_key_inventory(
                await litellm_client.key_list(user["sub"]),
                user["sub"],
                project_ids,
            )
            concrete_id = _resolve_owned_project_key(before, token, clean_project)
            if not concrete_id:
                _audit(
                    "key.deactivate",
                    "denied-ownership",
                    user,
                    project=clean_project,
                )
                raise HTTPException(
                    status_code=403,
                    detail="You can only deactivate a key in your own project.",
                )
            targets = [
                entry
                for entry in before
                if _entry_delete_id(entry) == concrete_id
                and entry.get("portal_project_id") == clean_project
            ]
            if len(targets) != 1:
                raise litellm_client.LiteLLMError(
                    "owned project key did not resolve exactly once"
                )
            await _block_key_with_durable_intent(targets[0])
            after = _portal_key_inventory(
                await litellm_client.key_list(user["sub"]),
                user["sub"],
                project_ids,
            )
            if _resolve_owned_project_key(
                _active_project_keys(after, clean_project),
                concrete_id,
                clean_project,
            ):
                raise litellm_client.LiteLLMError(
                    "key remained active after deactivation"
                )

        post_deactivation_liveness = _retain_post_deactivation_liveness_task(
            asyncio.create_task(
                _verify_post_deactivation_liveness(
                    request,
                    user,
                    clean_project,
                    concrete_id,
                )
            )
        )
        await asyncio.shield(post_deactivation_liveness)

        _audit("key.deactivate", "success", user, project=clean_project)
        auth.flash(request, "Key deactivated. You may now generate another.", "success")
    except litellm_client.LiteLLMError as exc:
        logger.warning(
            "key deactivation failed for subject %s: %s", user.get("sub"), exc
        )
        _audit("key.deactivate", "failure", user, project=clean_project)
        auth.flash(
            request,
            "Could not verify key deactivation. Please refresh and try again.",
            "error",
        )

    return RedirectResponse("/", status_code=303)


# --- snippets ---


@app.get("/snippets", response_class=HTMLResponse)
async def snippets_page(
    request: Request, user: dict[str, Any] = Depends(auth.require_developer)
) -> HTMLResponse:
    project_ids = await _live_project_ids(request, user)
    if not project_ids:
        raise auth.NotAuthorized()
    # Plaintext keys are never persisted for later views. Snippets reached by
    # navigation therefore always use an explicit placeholder.
    rendered = tools.rendered_tools(settings.public_api_base, "YOUR_KEY")
    # The connect surface shows the project's live model policy (allowed
    # models with the default marked) so a newly configured model appears
    # automatically; a failed policy read degrades to an explanatory note.
    project_policies, available_models, _policy_error = await _project_policy_view(
        request, user, project_ids
    )

    return templates.TemplateResponse(
        request,
        "snippets.html",
        {
            "user": user,
            "is_admin": False,
            "tools": rendered,
            "api_base": settings.public_api_base,
            "using_placeholder": True,
            "project_ids": project_ids,
            "project_policies": project_policies,
            "available_models": available_models,
            "no_models_sentinel": litellm_client.NO_MODELS_SENTINEL,
            "flashes": auth.pop_flash(request),
        },
    )


# --- admin / rotation control ---


def _rotator_headers(
    operation_id: str | None = None,
    actor_id: str | None = None,
) -> dict[str, str]:
    headers: dict[str, str] = {}
    if settings.rotator_internal_token:
        headers["X-Internal-Auth"] = settings.rotator_internal_token
    if operation_id is not None:
        if not _canonical_operation_id(operation_id):
            raise ValueError("invalid identity mutation operation ID")
        headers["X-AIGW-Operation-ID"] = operation_id
    if actor_id is not None:
        if operation_id is None or model_admin.ACTOR_RE.fullmatch(actor_id) is None:
            raise ValueError("invalid model-governance actor ID")
        headers["X-AIGW-Actor-ID"] = actor_id
    return headers


def _rotator_response(resp: httpx.Response) -> Any:
    if not resp.content:
        return None
    if len(resp.content) > ROTATOR_RESPONSE_MAX_BYTES:
        raise ValueError("rotator response exceeded the fixed size limit")
    return resp.json()


async def _rotator_get(path: str) -> Any:
    url = settings.rotator_url.rstrip("/") + path
    async with httpx.AsyncClient(
        timeout=10, trust_env=False, follow_redirects=False
    ) as client:
        resp = await client.get(url, headers=_rotator_headers())
    resp.raise_for_status()
    return _rotator_response(resp)


async def _live_project_ids(request: Request, user: dict[str, Any]) -> tuple[str, ...]:
    """Return a bounded, unambiguous live Keycloak project decision."""
    subject = user.get("sub")
    if not isinstance(subject, str) or IDENTITY_ID_RE.fullmatch(subject) is None:
        request.session.clear()
        raise auth.NotAuthorized()
    try:
        raw = await _rotator_get(f"/identity/projects/{subject}")
    except Exception as exc:  # noqa: BLE001 - fail closed without upstream detail
        raise HTTPException(
            status_code=503,
            detail="Current project membership could not be verified.",
        ) from exc
    projects = raw.get("projects") if isinstance(raw, dict) else None
    if (
        not isinstance(projects, list)
        or len(projects) > 64
        or any(
            not isinstance(project, str)
            or litellm_client.PROJECT_ID_RE.fullmatch(project) is None
            for project in projects
        )
        or len(set(projects)) != len(projects)
    ):
        raise HTTPException(
            status_code=503,
            detail="Current project membership was ambiguous.",
        )
    return tuple(sorted(projects))


def _validated_policy_object(raw: Any) -> dict[str, Any] | None:
    """Validate one non-secret per-project issuance policy from the rotator.

    The policy decides the rate caps and model set minted onto static bearer
    keys, so anything ambiguous returns ``None`` and the caller fails closed
    — a malformed restriction must never be treated as unlimited.
    """
    if not isinstance(raw, dict) or set(raw) not in (
        {
            "tpm_limit",
            "rpm_limit",
            "allowed_models",
            "default_model",
        },
        {
        "tpm_limit",
        "rpm_limit",
        "allowed_models",
        "default_model",
        "model_limits",
        },
    ):
        return None
    for knob in ("tpm_limit", "rpm_limit"):
        value = raw[knob]
        if value is not None and (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 < value <= litellm_client.RATE_LIMIT_MAX
        ):
            return None
    models = raw["allowed_models"]
    if models is not None:
        if (
            not isinstance(models, list)
            or not 1 <= len(models) <= litellm_client.MAX_POLICY_MODELS
            or any(
                not isinstance(name, str)
                or litellm_client.MODEL_NAME_RE.fullmatch(name) is None
                for name in models
            )
            or len(set(models)) != len(models)
        ):
            return None
        models = sorted(models)
    default_model = raw["default_model"]
    if default_model is not None and (
        not isinstance(default_model, str)
        or litellm_client.MODEL_NAME_RE.fullmatch(default_model) is None
        or (models is not None and default_model not in models)
    ):
        return None
    try:
        canonical_limits = litellm_client.canonical_model_limits(
            raw.get("model_limits", {}), models or []
        )
        model_limits = json.loads(canonical_limits)
    except (litellm_client.LiteLLMError, TypeError, ValueError):
        return None
    return {
        "tpm_limit": raw["tpm_limit"],
        "rpm_limit": raw["rpm_limit"],
        "allowed_models": models,
        "default_model": default_model,
        "model_limits": model_limits,
    }


async def _live_project_policies(
    request: Request, user: dict[str, Any], project_ids: tuple[str, ...]
) -> dict[str, dict[str, Any]]:
    """Fetch validated issuance policies for already-authorized projects.

    Fail-closed: the runtime policy decides the caps and model set minted
    onto a static bearer key, so a missing, ambiguous, or malformed policy
    payload is a 503 — never a silent unlimited default.
    """
    subject = user.get("sub")
    if not isinstance(subject, str) or IDENTITY_ID_RE.fullmatch(subject) is None:
        request.session.clear()
        raise auth.NotAuthorized()
    try:
        raw = await _rotator_get(f"/identity/projects/{subject}")
    except Exception as exc:  # noqa: BLE001 - fail closed without upstream detail
        raise HTTPException(
            status_code=503,
            detail="Current project policy could not be verified.",
        ) from exc
    raw_policies = raw.get("policies") if isinstance(raw, dict) else None
    raw_reconciliation = (
        raw.get("policy_reconciliation") if isinstance(raw, dict) else None
    )
    if not isinstance(raw_policies, dict) or not isinstance(
        raw_reconciliation, dict
    ):
        raise HTTPException(
            status_code=503,
            detail="Current project policy could not be verified.",
        )
    policies: dict[str, dict[str, Any]] = {}
    for project_id in project_ids:
        policy = _validated_policy_object(raw_policies.get(project_id))
        if policy is None:
            raise HTTPException(
                status_code=503,
                detail="Current project policy was ambiguous.",
            )
        state = raw_reconciliation.get(project_id)
        if (
            not isinstance(state, dict)
            or set(state) != {"ready", "revision"}
            or state.get("ready") is not True
            or not isinstance(state.get("revision"), str)
            or litellm_client.POLICY_REVISION_RE.fullmatch(state["revision"])
            is None
        ):
            raise HTTPException(
                status_code=503,
                detail="Project policy reconciliation is incomplete.",
            )
        try:
            expected_revision = litellm_client.project_policy_revision(policy)
        except litellm_client.LiteLLMError as exc:
            raise HTTPException(
                status_code=503,
                detail="Current project policy was ambiguous.",
            ) from exc
        if not hmac.compare_digest(state["revision"], expected_revision):
            raise HTTPException(
                status_code=503,
                detail="Current project policy revision was ambiguous.",
            )
        policies[project_id] = policy
    return policies


async def _managed_project_for_group(group_id: str) -> str:
    groups = _safe_identity_groups(await _rotator_get("/identity/groups"))
    matches = [group for group in groups if group["id"] == group_id]
    if len(matches) != 1:
        raise litellm_client.LiteLLMError(
            "managed group did not resolve to one canonical project"
        )
    return str(matches[0]["name"])


async def _deactivate_subject_project_keys(user_id: str, project_id: str) -> None:
    """Revoke every active portal key before/after membership removal."""
    allowed = (project_id,)
    inventory = _portal_key_inventory(
        await litellm_client.key_list(user_id), user_id, allowed
    )
    for entry in _active_project_keys(inventory, project_id):
        concrete = _entry_delete_id(entry)
        if concrete is None:
            raise litellm_client.LiteLLMError(
                "active project key has no concrete identifier"
            )
        await _block_key_with_durable_intent(entry)
    after = _portal_key_inventory(
        await litellm_client.key_list(user_id), user_id, allowed
    )
    if _active_project_keys(after, project_id):
        raise litellm_client.LiteLLMError(
            "project key remained active after membership revocation"
        )


async def _remove_member_and_deactivate_keys(
    group_id: str, user_id: str, operation_id: str
) -> str:
    """Serialize membership removal and both key passes with policy cutover."""

    async with _admin_key_policy_lock:
        project_id = await _managed_project_for_group(group_id)
        await _deactivate_subject_project_keys(user_id, project_id)
        await _rotator_delete(
            f"/identity/groups/{group_id}/members/{user_id}",
            operation_id=operation_id,
        )
        await _deactivate_subject_project_keys(user_id, project_id)
        return project_id


async def _rotator_put(
    path: str,
    payload: dict[str, Any],
    *,
    operation_id: str | None = None,
) -> Any:
    url = settings.rotator_url.rstrip("/") + path
    async with httpx.AsyncClient(
        timeout=10, trust_env=False, follow_redirects=False
    ) as client:
        resp = await client.put(
            url, headers=_rotator_headers(operation_id), json=payload
        )
    resp.raise_for_status()
    return _rotator_response(resp)


async def _rotator_post(
    path: str,
    payload: dict[str, Any] | None = None,
    *,
    operation_id: str | None = None,
    actor_id: str | None = None,
) -> Any:
    url = settings.rotator_url.rstrip("/") + path
    async with httpx.AsyncClient(
        timeout=10, trust_env=False, follow_redirects=False
    ) as client:
        kwargs: dict[str, Any] = {
            "headers": _rotator_headers(operation_id, actor_id)
        }
        if payload is not None:
            kwargs["json"] = payload
        resp = await client.post(url, **kwargs)
    resp.raise_for_status()
    return _rotator_response(resp)


async def _rotator_delete(
    path: str,
    payload: dict[str, Any] | None = None,
    *,
    operation_id: str | None = None,
) -> Any:
    url = settings.rotator_url.rstrip("/") + path
    async with httpx.AsyncClient(
        timeout=10, trust_env=False, follow_redirects=False
    ) as client:
        kwargs: dict[str, Any] = {"headers": _rotator_headers(operation_id)}
        if payload is not None:
            kwargs["json"] = payload
        resp = await client.delete(url, **kwargs)
    resp.raise_for_status()
    return _rotator_response(resp)


async def require_live_admin(
    request: Request,
    user: dict[str, Any] = Depends(auth.require_admin),
) -> dict[str, Any]:
    """Fail closed unless Keycloak still grants the current subject admin.

    The signed browser session contains a role snapshot and can outlive a
    group removal.  Every administrative mutation therefore asks the
    controller for Keycloak's current composite-role decision.  A definitive
    denial clears the stale session; an unavailable controller fails the
    mutation without logging out an otherwise-valid administrator.
    """
    subject = user.get("sub")
    if not isinstance(subject, str) or not IDENTITY_ID_RE.fullmatch(subject):
        request.session.clear()
        raise auth.NotAuthorized()
    try:
        decision = await _rotator_get(f"/identity/authorization/{subject}")
    except Exception as exc:  # noqa: BLE001 - fail closed without upstream detail
        if _is_vault_sealed_authorization_error(exc):
            raise VaultSealedAuthorizationUnavailable() from exc
        # The durable controller does not exist before the one-time bootstrap.
        # Permit only that exact recovery state (temporary bootstrap available,
        # durable controller not configured) to rely on the freshly validated
        # signed OIDC admin role.  Once configured, every request must pass the
        # live controller decision; outages fail closed.
        #
        # REVIEWED CHOICE: this narrow pre-bootstrap carve-out also covers the
        # newer admin surfaces that depend on this gate (the gateway key
        # inventory mutations and per-project policy edits), not only the
        # original rotation controls. In that state the key inventory and
        # policy store are empty or unreachable anyway, and the carve-out
        # still requires the exact configured=False/bootstrap_available=True
        # controller status — it is not a general outage bypass.
        try:
            status = _safe_identity_status(await _rotator_get("/identity/status"))
        except Exception:  # noqa: BLE001
            status = None
        if not (
            status
            and status["configured"] is False
            and status["controller_usable"] is False
            and status["bootstrap_available"] is True
        ):
            raise HTTPException(
                status_code=503,
                detail="Current administrator authorization could not be verified.",
            ) from exc
        return user
    if not isinstance(decision, dict) or decision.get("admin") is not True:
        _audit("authorization.role.denied", "failure", user)
        request.session.clear()
        raise auth.NotAuthorized()
    return user


def _is_vault_sealed_authorization_error(exc: Exception) -> bool:
    """Recognize only the controller's exact, non-secret sealed error code."""

    if not isinstance(exc, httpx.HTTPStatusError):
        return False
    response = exc.response
    if response.status_code != 423:
        return False
    try:
        payload = response.json()
    except ValueError:
        return False
    return isinstance(payload, dict) and payload == {"detail": "vault_sealed"}


async def require_recent_live_admin(
    request: Request,
    user: dict[str, Any] = Depends(require_live_admin),
) -> dict[str, Any]:
    if not auth.has_recent_admin_reauthentication(request):
        raise auth.ReauthenticationRequired()
    return user


async def _model_admin_rotator_post(*args: Any, **kwargs: Any) -> Any:
    """Late-bound adapter so tests and recovery hooks can replace the client."""

    return await _rotator_post(*args, **kwargs)


def _render_price_backdate_preview(
    *,
    request: Request,
    user: dict[str, Any],
    preview: dict[str, Any],
) -> HTMLResponse:
    """Render the stored impact receipt without putting it in a cookie."""

    return templates.TemplateResponse(
        request,
        "admin_price_backdate_preview.html",
        {
            "user": user,
            "is_admin": True,
            "admin_surface": True,
            "preview": preview,
            "identity_step_up_recent": auth.has_recent_admin_reauthentication(
                request
            ),
            "identity_step_up_expires_at": (
                auth.admin_reauthentication_expires_at(request)
            ),
            "csrf_token": auth.get_csrf_token(request),
            "flashes": auth.pop_flash(request),
        },
    )


admin_app.include_router(
    model_admin.build_router(
        require_recent_live_admin=require_recent_live_admin,
        rotator_post=_model_admin_rotator_post,
        render_backdate_preview=_render_price_backdate_preview,
        audit=_audit,
        mutation_result=_identity_mutation_result,
    )
)


def _safe_identity_status(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None

    def fingerprint(field: str) -> str:
        value = raw.get(field)
        if isinstance(value, str) and re.fullmatch(r"[a-fA-F0-9]{64}", value):
            return value.lower()
        return ""

    return {
        "configured": raw.get("configured") is True,
        "controller_usable": raw.get("controller_usable") is True,
        "bootstrap_available": raw.get("bootstrap_available") is True,
        "bootstrap_cleanup_required": (raw.get("bootstrap_cleanup_required") is True),
        "ldap_configured": raw.get("ldap_configured") is True,
        # Booleans only: the break-glass escrow document itself never crosses
        # this boundary. `readable` false means the rotator's Vault policy
        # predates the escrow path (brownfield upgrade pending).
        "break_glass_escrowed": raw.get("break_glass_escrowed") is True,
        "break_glass_escrow_readable": (
            raw.get("break_glass_escrow_readable") is not False
        ),
        # Same custody model for the `vault` OIDC relying-party secret that
        # the scripts/vault-oidc-setup.sh root ceremony consumes.
        "vault_oidc_rp_escrowed": raw.get("vault_oidc_rp_escrowed") is True,
        "vault_oidc_rp_escrow_readable": (
            raw.get("vault_oidc_rp_escrow_readable") is not False
        ),
        "controller_certificate_sha256": fingerprint("controller_certificate_sha256"),
        "broker_certificate_sha256": fingerprint("broker_certificate_sha256"),
    }


async def _confirmed_vault_sealed() -> bool:
    """Accept only the rotator's exact, public-data-only sealed state."""

    try:
        raw = await _rotator_get("/vault/public-status")
    except Exception:  # noqa: BLE001 - every ambiguous state fails closed
        return False
    return (
        isinstance(raw, dict)
        and set(raw) == {"initialized", "sealed"}
        and raw["initialized"] is True
        and raw["sealed"] is True
    )


def _safe_identity_groups(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    result: list[dict[str, Any]] = []
    for item in raw[:500]:
        if not isinstance(item, dict):
            continue
        group_id = item.get("id")
        name = item.get("name")
        capabilities = item.get("capabilities")
        count = item.get("member_count")
        if (
            not isinstance(group_id, str)
            or not IDENTITY_ID_RE.fullmatch(group_id)
            or not isinstance(name, str)
            or litellm_client.PROJECT_ID_RE.fullmatch(name) is None
            or not isinstance(capabilities, list)
            or not all(isinstance(value, str) for value in capabilities)
            or not set(capabilities) <= IDENTITY_CAPABILITIES
            or not isinstance(count, int)
            or isinstance(count, bool)
            or count < 0
        ):
            raise ValueError("identity group response was invalid or ambiguous")
        # The rotator attaches each managed group's parsed issuance policy.
        # Absence is tolerated for display compatibility (treated as the
        # unlimited platform default); a PRESENT but malformed policy is an
        # ambiguous restriction and fails the listing closed.
        if "policy" in item:
            policy = _validated_policy_object(item.get("policy"))
            if policy is None:
                raise ValueError("identity group response was invalid or ambiguous")
        else:
            policy = {
                "tpm_limit": None,
                "rpm_limit": None,
                "allowed_models": None,
                "default_model": None,
                "model_limits": {},
            }
        raw_reconciliation = item.get("policy_reconciliation")
        if raw_reconciliation is None:
            policy_reconciliation = {
                "ready": True,
                "revision": litellm_client.project_policy_revision(policy),
                "active_policy": policy,
            }
        else:
            if (
                not isinstance(raw_reconciliation, dict)
                or set(raw_reconciliation)
                != {"active_policy", "ready", "revision"}
                or not isinstance(raw_reconciliation.get("ready"), bool)
                or not isinstance(raw_reconciliation.get("revision"), str)
                or litellm_client.POLICY_REVISION_RE.fullmatch(
                    raw_reconciliation["revision"]
                )
                is None
            ):
                raise ValueError("identity group response was invalid or ambiguous")
            active_policy = _validated_policy_object(
                raw_reconciliation.get("active_policy")
            )
            if active_policy is None:
                raise ValueError("identity group response was invalid or ambiguous")
            try:
                intended_revision = litellm_client.project_policy_revision(policy)
            except litellm_client.LiteLLMError as exc:
                raise ValueError(
                    "identity group response was invalid or ambiguous"
                ) from exc
            if not hmac.compare_digest(
                intended_revision, raw_reconciliation["revision"]
            ):
                raise ValueError("identity group response was invalid or ambiguous")
            policy_reconciliation = {
                "ready": raw_reconciliation["ready"],
                "revision": raw_reconciliation["revision"],
                "active_policy": active_policy,
            }
        result.append(
            {
                "id": group_id,
                "name": name,
                "capabilities": sorted(set(capabilities)),
                "member_count": min(count, 1_000_000),
                "policy": policy,
                "policy_reconciliation": policy_reconciliation,
            }
        )
    return result


def _safe_identity_users(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    result: list[dict[str, Any]] = []
    for item in raw[:100]:
        if not isinstance(item, dict):
            continue
        user_id = item.get("id")
        username = item.get("username")
        if (
            not isinstance(user_id, str)
            or not IDENTITY_ID_RE.fullmatch(user_id)
            or not isinstance(username, str)
            or not username
            or len(username) > 255
        ):
            continue

        def text(field: str) -> str:
            value = item.get(field)
            return value[:255] if isinstance(value, str) else ""

        result.append(
            {
                "id": user_id,
                "username": username,
                "email": text("email"),
                "first_name": text("first_name"),
                "last_name": text("last_name"),
                "enabled": item.get("enabled") is True,
            }
        )
    return result


def _safe_provider_status(raw: Any) -> dict[str, Any] | None:
    """Allowlist the non-secret provider state rendered by the admin page.

    The upstream rotator holds Vault access. A compromised or accidentally
    broadened response must not turn this browser surface into a generic
    secret viewer, so unknown fields are discarded and the public JWKS bundle
    is rebuilt from a narrow schema.
    """

    if isinstance(raw, list):
        matches = [
            item
            for item in raw
            if isinstance(item, dict) and item.get("vendor") == "anthropic"
        ]
        if len(matches) != 1:
            return None
        raw = matches[0]
    elif isinstance(raw, dict) and isinstance(raw.get("providers"), list):
        return _safe_provider_status(raw["providers"])
    if not isinstance(raw, dict) or raw.get("vendor") != "anthropic":
        return None

    state_value = raw.get("state")
    state_name = state_value if state_value in PROVIDER_STATES else "unavailable"

    def fingerprint(name: str) -> str:
        value = raw.get(name)
        if isinstance(value, str) and re.fullmatch(r"[a-fA-F0-9]{64}", value):
            return value.lower()
        return ""

    identifiers: dict[str, str] = {}
    raw_identifiers = raw.get("nonsecret_ids")
    if isinstance(raw_identifiers, dict):
        for name in (
            "organization_id",
            "service_account_id",
            "federation_rule_id",
            "workspace_id",
        ):
            value = raw_identifiers.get(name)
            if (
                isinstance(value, str)
                and value
                and PROVIDER_IDENTIFIER_RE.fullmatch(value)
            ):
                identifiers[name] = value

    bundle: dict[str, Any] | None = None
    raw_bundle = raw.get("setup_bundle")
    if isinstance(raw_bundle, dict):
        issuer = raw_bundle.get("issuer")
        client_id = raw_bundle.get("client_id")
        subject = raw_bundle.get("subject")
        audience = raw_bundle.get("audience")
        try:
            parsed_issuer = urlsplit(issuer) if isinstance(issuer, str) else None
        except ValueError:
            parsed_issuer = None
        public_text = (client_id, subject, audience)
        if (
            parsed_issuer is not None
            and parsed_issuer.scheme == "https"
            and parsed_issuer.hostname
            and parsed_issuer.username is None
            and parsed_issuer.password is None
            and not parsed_issuer.query
            and not parsed_issuer.fragment
            and len(issuer) <= 512
            and all(
                isinstance(value, str)
                and 0 < len(value) <= 512
                and not any(ord(character) < 32 for character in value)
                for value in public_text
            )
        ):
            safe_keys: list[dict[str, str]] = []
            raw_jwks = raw_bundle.get("jwks")
            raw_keys = raw_jwks.get("keys") if isinstance(raw_jwks, dict) else None
            if isinstance(raw_keys, list) and len(raw_keys) <= 16:
                for raw_key in raw_keys:
                    if not isinstance(raw_key, dict):
                        safe_keys = []
                        break
                    safe_key: dict[str, str] = {}
                    for field in (
                        "kty",
                        "use",
                        "kid",
                        "alg",
                        "n",
                        "e",
                        "crv",
                        "x",
                        "y",
                    ):
                        value = raw_key.get(field)
                        if isinstance(value, str) and 0 < len(value) <= 4096:
                            safe_key[field] = value
                    if "kty" not in safe_key or "kid" not in safe_key:
                        safe_keys = []
                        break
                    safe_keys.append(safe_key)
            if safe_keys:
                bundle = {
                    "issuer": issuer,
                    "client_id": client_id,
                    "subject": subject,
                    "audience": audience,
                    "jwks": {"keys": safe_keys},
                    "jwks_json": json.dumps(
                        {"keys": safe_keys},
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                }

    pending_until = raw.get("revocation_pending_until")
    if (
        not isinstance(pending_until, str)
        or len(pending_until) > 64
        or any(ord(character) < 32 for character in pending_until)
    ):
        pending_until = ""

    return {
        "vendor": "anthropic",
        "state": state_name,
        "configured": raw.get("configured") is True,
        "enabled": raw.get("enabled") is True,
        "private_key_jwt_ready": raw.get("private_key_jwt_ready") is True,
        "nonsecret_ids": identifiers,
        "client_certificate_sha256": fingerprint("client_certificate_sha256"),
        "current_jwks_sha256": fingerprint("current_jwks_sha256"),
        "approved_jwks_sha256": fingerprint("approved_jwks_sha256"),
        "revocation_pending_until": pending_until,
        "setup_bundle": bundle,
    }


def _safe_rotator_status(raw: Any) -> dict[str, dict[str, Any]]:
    """Allowlist the rotator's per-vendor scheduler summary for display.

    Replaces the old raw ``repr`` dump on the admin page: only bounded,
    validated fields reach the template, keyed by a validated vendor id, so a
    compromised rotator cannot inject markup or unbounded data through this
    read-only view.
    """

    if not isinstance(raw, list):
        return {}

    def bounded_text(value: Any, limit: int = 64) -> str:
        return value[:limit] if isinstance(value, str) else ""

    rows: dict[str, dict[str, Any]] = {}
    for item in raw[:100]:
        if not isinstance(item, dict):
            continue
        vendor = item.get("vendor")
        if (
            not isinstance(vendor, str)
            or VENDOR_RE.fullmatch(vendor) is None
            or vendor not in REGISTERED_ROTATION_VENDORS
        ):
            continue
        interval = item.get("interval_seconds")
        if isinstance(interval, bool) or not isinstance(interval, int) or interval < 0:
            interval = None
        last = item.get("last_rotation")
        last_time = ""
        last_status = ""
        if isinstance(last, dict):
            last_time = bounded_text(last.get("timestamp") or last.get("time"))
            last_status = bounded_text(last.get("status"))
        alerts = item.get("alerts")
        rows[vendor] = {
            "vendor": vendor,
            "enabled": item.get("enabled") is True,
            "interval_seconds": interval,
            "next_run_time": bounded_text(item.get("next_run_time")),
            "rotation_in_progress": item.get("rotation_in_progress") is True,
            "last_time": last_time,
            "last_status": last_status,
            "alert_count": min(len(alerts), 100) if isinstance(alerts, list) else 0,
        }
    return rows


# --- admin / egress trust pin ------------------------------------------------


def _fingerprint_display(hex_value: str) -> str:
    """Render a SHA-256 hex digest in the conventional colon-separated form."""

    return ":".join(
        hex_value[index : index + 2].upper() for index in range(0, len(hex_value), 2)
    )


def _egress_trust_status() -> dict[str, Any]:
    """Re-verify the shipped Anthropic egress CA bundle against reviewed pins.

    On-demand and local-only by design: this control plane has no external
    network path (only Envoy does), so the verifiable property here is that
    the pinned bundle shipped in this image is byte-for-byte the reviewed
    WE1/R4 issuer set Envoy enforces at egress. Continuous monitoring of the
    live presented chain is a deliberate follow-up, not silently faked here.
    """

    pins = [
        {**pin, "display": _fingerprint_display(pin["sha256"])}
        for pin in ANTHROPIC_EGRESS_CA_PINS
    ]
    expected = [pin["sha256"] for pin in ANTHROPIC_EGRESS_CA_PINS]
    try:
        raw = ANTHROPIC_EGRESS_CA_BUNDLE_PATH.read_bytes()
    except OSError:
        return {
            "pins": pins,
            "verified": False,
            "detail": "The pinned CA bundle shipped with this image is missing "
            "or unreadable. Re-converge with Ansible to restore the reviewed "
            "bundle.",
        }
    if len(raw) > EGRESS_CA_BUNDLE_MAX_BYTES:
        return {
            "pins": pins,
            "verified": False,
            "detail": "The shipped CA bundle exceeds the reviewed size bound "
            "and was not verified.",
        }
    observed: list[str] = []
    for block in _PEM_CERTIFICATE_RE.findall(raw.decode("ascii", errors="replace")):
        try:
            der = base64.b64decode("".join(block.split()), validate=True)
        except (binascii.Error, ValueError):
            return {
                "pins": pins,
                "verified": False,
                "detail": "The shipped CA bundle contains an unparseable "
                "certificate block and was not verified.",
            }
        observed.append(hashlib.sha256(der).hexdigest())
    if observed == expected:
        return {
            "pins": pins,
            "verified": True,
            "detail": "The pinned bundle shipped in this control plane matches "
            "the reviewed WE1 and GTS Root R4 fingerprints exactly. Envoy "
            "rejects any api.anthropic.com chain not issued by this CA.",
        }
    return {
        "pins": pins,
        "verified": False,
        "detail": "The shipped CA bundle does NOT match the reviewed "
        "fingerprints. Treat egress trust as unverified and re-converge with "
        "Ansible to restore the reviewed bundle.",
    }


# --- egress-trust periodic canary -------------------------------------------
#
# A process-local background task re-runs the local egress-trust verification
# on a fixed interval so the admin console can show that the shipped Anthropic
# CA pin is *still* the reviewed one without an operator clicking "Re-verify".
# dev-portal and admin-portal each run uvicorn with exactly --workers 1 (see
# the Dockerfile CMD and the compose admin-portal command), so this module
# state and its single asyncio task are confined to one event loop in one
# process: there is no cross-worker/cross-process sharing to race, and no
# server-side coordination to get wrong. The task performs no auth — it only
# reads a file the image already ships — and never blocks startup: the first
# check runs inside the loop body, not inline in the lifespan.
_egress_trust_canary_state: dict[str, Any] = {
    "last_checked": None,  # ISO-8601 UTC string of the last completed check
    "last_checked_epoch": None,  # float epoch of the last check (for staleness)
    "verified": None,  # True / False / None(=never run yet)
    "detail": None,  # non-secret human explanation from the last check
    "last_error": None,  # non-secret failure summary, or None on success
}
_egress_trust_canary_task: "asyncio.Task[None] | None" = None


def _egress_trust_canary_snapshot() -> dict[str, Any]:
    """Return a copy of the canary's non-secret state plus a staleness verdict.

    ``stale`` is True before the first check completes, and thereafter once the
    last result is older than twice the configured interval (one interval of
    grace for a slow/blocked check). No secret ever enters this dict.
    """
    snapshot = dict(_egress_trust_canary_state)
    interval = settings.egress_trust_canary_interval_seconds
    epoch = snapshot.get("last_checked_epoch")
    if not isinstance(epoch, (int, float)):
        snapshot["age_seconds"] = None
        snapshot["stale"] = True
    else:
        age = max(0, int(datetime.now(timezone.utc).timestamp() - epoch))
        snapshot["age_seconds"] = age
        snapshot["stale"] = age > interval * 2
    snapshot["interval_seconds"] = interval
    return snapshot


def _run_egress_trust_canary_once() -> None:
    """Run the local egress-trust verification once and record non-secret state.

    Never raises: any fault is captured into ``last_error`` and logged so the
    background loop survives and the admin panel can surface it loudly, rather
    than the failure being silently swallowed.
    """
    now = datetime.now(timezone.utc)
    try:
        trust = _egress_trust_status()
    except Exception as exc:  # noqa: BLE001 - the loop must never die on a fault
        logger.error("egress-trust canary check raised: %s", exc)
        _egress_trust_canary_state.update(
            {
                "last_checked": now.isoformat(),
                "last_checked_epoch": now.timestamp(),
                "verified": False,
                "detail": None,
                "last_error": str(exc)[:500],
            }
        )
        return
    verified = bool(trust.get("verified"))
    detail = str(trust.get("detail") or "")
    _egress_trust_canary_state.update(
        {
            "last_checked": now.isoformat(),
            "last_checked_epoch": now.timestamp(),
            "verified": verified,
            "detail": detail,
            "last_error": None if verified else (detail or "pin verification failed"),
        }
    )
    if not verified:
        logger.error("egress-trust canary: pin verification FAILED: %s", detail)


async def _egress_trust_canary_loop() -> None:
    """Re-run the egress-trust verification forever on the configured interval.

    The very first check runs here (inside the task), not in the lifespan, so
    startup is never blocked on it. Process-local by construction (see the
    module note above); cancellation on shutdown propagates cleanly.
    """
    interval = settings.egress_trust_canary_interval_seconds
    jitter = secrets.SystemRandom()
    while True:
        _run_egress_trust_canary_once()
        # +/-25% jitter keeps the daily check time unpredictable while the
        # snapshot's staleness bound (2x interval) still holds.
        await asyncio.sleep(interval * jitter.uniform(0.75, 1.25))


def _start_egress_trust_canary() -> None:
    """Start the process-local canary task exactly once per process.

    Idempotent: guards against a double-start (e.g. uvicorn ``--reload`` or the
    shared lifespan being entered more than once) by refusing to launch a
    second task while one is already live.
    """
    global _egress_trust_canary_task
    if _egress_trust_canary_task is not None and not _egress_trust_canary_task.done():
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    _egress_trust_canary_task = loop.create_task(_egress_trust_canary_loop())


def _stop_egress_trust_canary() -> None:
    """Cancel the canary task on shutdown, if one is running."""
    global _egress_trust_canary_task
    task = _egress_trust_canary_task
    _egress_trust_canary_task = None
    if task is not None and not task.done():
        task.cancel()


@admin_app.post("/admin/egress-trust/verify")
async def admin_egress_trust_verify(
    request: Request,
    user: dict[str, Any] = Depends(require_live_admin),
    csrf_token: str = Form(..., min_length=32, max_length=128),
):
    """On-demand re-verification of the Anthropic egress CA pin (read-only)."""

    redirect = RedirectResponse("/admin#tab-providers", status_code=303)
    if not auth.verify_csrf(request, csrf_token):
        auth.flash(request, "Your session expired — please try again.", "error")
        return redirect
    trust = _egress_trust_status()
    if trust["verified"]:
        _audit("egress.trust.verify", "success", user)
        auth.flash(
            request,
            "Egress CA pin re-verified: the shipped Anthropic bundle matches "
            "the reviewed fingerprints.",
            "success",
        )
    else:
        _audit("egress.trust.verify", "mismatch", user)
        auth.flash(
            request,
            "Egress CA pin verification failed: " + str(trust["detail"]),
            "error",
        )
    return redirect


@admin_app.get("/admin", response_class=HTMLResponse)
async def admin_page(
    request: Request, user: dict[str, Any] = Depends(auth.require_admin)
) -> HTMLResponse:
    # This page includes directory identities, group membership, credential-
    # rotation status/history, and active settings. A signed role snapshot is
    # not enough after revocation: require the same live Keycloak composite-
    # role decision used by mutations. Viewing does not require fresh step-up;
    # destructive identity changes still do.
    try:
        await require_live_admin(request, user)
    except VaultSealedAuthorizationUnavailable:
        # A sealed Vault prevents the durable identity controller from making
        # its live authorization decision. A currently valid, signed OIDC
        # admin session may see only this data-free maintenance page so the
        # operator can proceed to the separately gated Vault UI and unseal.
        # Role denial, expired/invalid cookies, and every non-Vault outage keep
        # their existing fail-closed behavior. Mutations still depend directly
        # on require_live_admin/require_recent_live_admin and never enter here.
        if not await _confirmed_vault_sealed():
            raise HTTPException(
                status_code=503,
                detail="Current administrator authorization could not be verified.",
            )
        return templates.TemplateResponse(
            request,
            "admin_maintenance.html",
            {
                "user": None,
                "show_session_logout": True,
                "admin_surface": True,
                "flashes": [],
            },
        )

    status_data: Any = None
    vendors: list[dict[str, Any]] = []
    history: list[dict[str, Any]] = []
    anthropic_provider: dict[str, Any] | None = None
    identity_status: dict[str, Any] | None = None
    identity_groups: list[dict[str, Any]] = []
    identity_users: list[dict[str, Any]] = []
    identity_members: list[dict[str, Any]] = []
    selected_group: dict[str, Any] | None = None
    governed_models: list[dict[str, Any]] = []
    governed_prices: list[dict[str, Any]] = []
    governance_audit: list[dict[str, str]] = []
    governance_available = False
    selected_price_model = request.query_params.get("price_model", "")
    if model_admin.MODEL_NAME_RE.fullmatch(selected_price_model) is None:
        selected_price_model = ""
    selected_group_id = request.query_params.get("group_id", "")
    if not IDENTITY_ID_RE.fullmatch(selected_group_id):
        selected_group_id = ""
    user_search = request.query_params.get("user_search", "").strip()
    if len(user_search) > 64 or any(ord(ch) < 32 for ch in user_search):
        user_search = ""

    try:
        status_data = await _rotator_get("/status")
    except Exception:  # noqa: BLE001
        auth.flash(request, "Could not reach key-rotator for status.", "error")

    try:
        raw_settings = await _rotator_get("/settings")
        vendors = (
            raw_settings.get("vendors")
            if isinstance(raw_settings, dict)
            else raw_settings
        )
        if not isinstance(vendors, list):
            vendors = []
        # Vendor identifiers become downstream URL path segments. Ignore
        # malformed upstream entries instead of rendering active controls for
        # delimiter/path payloads returned by a compromised rotator.
        vendors = [
            vendor
            for vendor in vendors
            if isinstance(vendor, dict)
            and isinstance(vendor.get("vendor") or vendor.get("name"), str)
            and VENDOR_RE.fullmatch(vendor.get("vendor") or vendor.get("name"))
            and (vendor.get("vendor") or vendor.get("name"))
            in REGISTERED_ROTATION_VENDORS
        ]
    except Exception:  # noqa: BLE001
        auth.flash(request, "Could not reach key-rotator for settings.", "error")

    try:
        raw_history = await _rotator_get("/history?limit=20")
        history = (
            raw_history.get("history") if isinstance(raw_history, dict) else raw_history
        )
        if not isinstance(history, list):
            history = []
    except Exception:  # noqa: BLE001
        auth.flash(request, "Could not reach key-rotator for history.", "error")

    try:
        anthropic_provider = _safe_provider_status(
            await _rotator_get("/providers/anthropic")
        )
        if anthropic_provider is None:
            raise ValueError("provider status was invalid")
    except Exception:  # noqa: BLE001
        auth.flash(
            request, "Could not reach the provider enrollment controller.", "error"
        )

    # Configured model names gate the per-project policy form: without a
    # verified model list the form is not rendered at all, because its
    # full-replace semantics could otherwise silently clear a restriction.
    policy_models: list[str] = []
    try:
        policy_models = await litellm_client.model_names()
    except litellm_client.LiteLLMError:
        auth.flash(
            request,
            "Could not read the configured model list; project policy "
            "editing is disabled until it can be verified.",
            "error",
        )

    try:
        identity_status = _safe_identity_status(await _rotator_get("/identity/status"))
        if identity_status and identity_status["configured"]:
            identity_groups = _safe_identity_groups(
                await _rotator_get("/identity/groups")
            )
            valid_group_ids = {group["id"] for group in identity_groups}
            if selected_group_id not in valid_group_ids:
                selected_group_id = ""
            else:
                selected_group = next(
                    group
                    for group in identity_groups
                    if group["id"] == selected_group_id
                )
            identity_users = _safe_identity_users(
                await _rotator_get(
                    "/identity/users?" + urlencode({"search": user_search})
                )
            )
            if selected_group_id:
                identity_members = _safe_identity_users(
                    await _rotator_get(f"/identity/groups/{selected_group_id}/members")
                )
    except Exception:  # noqa: BLE001
        auth.flash(request, "Could not reach the identity controller.", "error")

    # Model and price records come from a separate append-only control plane.
    # Copy only the small public view models defined above. Price history is
    # loaded for one selected model so a compromised or very large catalog
    # cannot fan one page view into dozens of internal requests.
    try:
        governed_models = model_admin.safe_governed_models(
            await _rotator_get("/model-governance/models")
        )
        governance_available = True
        governed_names = {
            model["gateway_model_name"] for model in governed_models
        }
        if selected_price_model not in governed_names:
            selected_price_model = (
                governed_models[0]["gateway_model_name"]
                if governed_models
                else ""
            )
        if selected_price_model:
            encoded_model = quote(selected_price_model, safe="")
            governed_prices = model_admin.safe_governed_prices(
                await _rotator_get(
                    f"/model-governance/models/{encoded_model}/prices"
                ),
                gateway_model_name=selected_price_model,
            )
        governance_audit = model_admin.safe_governance_audit(
            await _rotator_get(
                f"/model-governance/audit?limit={model_admin.MAX_AUDIT_ROWS}"
            )
        )
    except Exception:  # noqa: BLE001 - never expose controller response detail
        governance_available = False
        governed_models = []
        governed_prices = []
        governance_audit = []
        selected_price_model = ""
        auth.flash(
            request,
            "Could not read the governed model catalog. Model and price changes are disabled.",
            "error",
        )

    # Active custom (non-discovery) governed models are deployed in LiteLLM and
    # callable by exact name, so they belong in the project-policy checklist as
    # an EXPLICIT, badged choice — but never in the implicit "all public models"
    # scope. Draft and retired models stay out of the checklist entirely. The
    # checklist only opens when the public model list verified above is present.
    policy_custom_models = sorted(
        model["gateway_model_name"]
        for model in governed_models
        if _is_active_custom_model(model)
    )
    if policy_models:
        policy_models = sorted(set(policy_models) | set(policy_custom_models))

    return templates.TemplateResponse(
        request,
        "admin.html",
        {
            "user": user,
            "is_admin": True,
            "rotator_status": _safe_rotator_status(status_data),
            "vendors": vendors,
            "history": history,
            "egress_trust": _egress_trust_status(),
            "anthropic_provider": anthropic_provider,
            "identity_status": identity_status,
            "identity_groups": identity_groups,
            "identity_users": identity_users,
            "identity_members": identity_members,
            "selected_group": selected_group,
            "selected_group_id": selected_group_id,
            "user_search": user_search,
            "identity_capabilities": sorted(IDENTITY_CAPABILITIES),
            "identity_step_up_recent": auth.has_recent_admin_reauthentication(request),
            "identity_step_up_expires_at": auth.admin_reauthentication_expires_at(
                request
            ),
            "egress_trust_canary": _egress_trust_canary_snapshot(),
            "policy_models": policy_models,
            "policy_custom_models": policy_custom_models,
            "no_models_sentinel": litellm_client.NO_MODELS_SENTINEL,
            "governance_available": governance_available,
            "governed_models": governed_models,
            "governed_prices": governed_prices,
            "governance_audit": governance_audit,
            "selected_price_model": selected_price_model,
            "governance_usage_classes": model_admin.USAGE_CLASSES,
            "approved_model_providers": sorted(model_admin.APPROVED_PROVIDERS),
            "governance_price_min": (
                datetime.now(timezone.utc) + timedelta(minutes=1)
            ).strftime("%Y-%m-%dT%H:%M"),
            "governance_backdate_max": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M"
            ),
            "admin_surface": True,
            "flashes": auth.pop_flash(request),
            "csrf_token": auth.get_csrf_token(request),
        },
    )


@admin_app.post("/admin/settings/{vendor}")
async def admin_save_settings(
    request: Request,
    vendor: str = APIPath(..., pattern=VENDOR_PATTERN),
    user: dict[str, Any] = Depends(require_live_admin),
    interval_seconds: int = Form(..., ge=60, le=365 * 86400),
    grace_seconds: int = Form(..., ge=0, le=86400),
    enabled: str | None = Form(None),
    csrf_token: str = Form(..., min_length=32, max_length=128),
):
    if vendor not in REGISTERED_ROTATION_VENDORS:
        raise HTTPException(status_code=404, detail="Provider is not registered.")
    if not auth.verify_csrf(request, csrf_token):
        auth.flash(request, "Your session expired — please try again.", "error")
        return RedirectResponse("/admin", status_code=303)

    payload = {
        "enabled": enabled is not None,
        "interval_seconds": interval_seconds,
        "grace_seconds": grace_seconds,
    }
    try:
        await _rotator_put(f"/settings/{vendor}", payload)
        _audit("rotation.settings.update", "success", user, vendor=vendor)
        auth.flash(request, f"Saved rotation settings for {vendor}.", "success")
    except Exception:  # noqa: BLE001
        _audit("rotation.settings.update", "failure", user, vendor=vendor)
        auth.flash(request, f"Could not save settings for {vendor}.", "error")

    return RedirectResponse("/admin", status_code=303)


@admin_app.post("/admin/rotate/{vendor}")
async def admin_rotate_now(
    request: Request,
    vendor: str = APIPath(..., pattern=VENDOR_PATTERN),
    user: dict[str, Any] = Depends(require_live_admin),
    csrf_token: str = Form(..., min_length=32, max_length=128),
):
    if vendor not in REGISTERED_ROTATION_VENDORS:
        raise HTTPException(status_code=404, detail="Provider is not registered.")
    if not auth.verify_csrf(request, csrf_token):
        auth.flash(request, "Your session expired — please try again.", "error")
        return RedirectResponse("/admin", status_code=303)

    try:
        await _rotator_post(f"/rotate/{vendor}")
        _audit("rotation.trigger", "success", user, vendor=vendor)
        auth.flash(request, f"Rotation triggered for {vendor}.", "success")
    except Exception:  # noqa: BLE001
        _audit("rotation.trigger", "failure", user, vendor=vendor)
        auth.flash(request, f"Could not trigger rotation for {vendor}.", "error")

    return RedirectResponse("/admin", status_code=303)


# --- admin / provider authentication enrollment ---------------------------


@admin_app.post("/admin/providers/anthropic")
async def admin_configure_anthropic_provider(
    request: Request,
    user: dict[str, Any] = Depends(require_recent_live_admin),
    organization_id: str = Form(..., pattern=PROVIDER_IDENTIFIER_PATTERN),
    service_account_id: str = Form(..., pattern=PROVIDER_IDENTIFIER_PATTERN),
    federation_rule_id: str = Form(..., pattern=PROVIDER_IDENTIFIER_PATTERN),
    workspace_id: str = Form(default="", max_length=128),
    federation_jwks_sha256: str = Form(
        ...,
        min_length=64,
        max_length=64,
        pattern=r"[0-9a-fA-F]{64}",
    ),
    enrollment_confirmation: str = Form(..., min_length=1, max_length=32),
    csrf_token: str = Form(..., min_length=32, max_length=128),
):
    if not auth.verify_csrf(request, csrf_token):
        auth.flash(request, "Your session expired — please try again.", "error")
        return RedirectResponse("/admin", status_code=303)
    if not secrets.compare_digest(enrollment_confirmation, "ENROLLED"):
        auth.flash(
            request,
            "Complete the external Anthropic enrollment and type ENROLLED exactly.",
            "error",
        )
        return RedirectResponse("/admin", status_code=303)
    clean_workspace = workspace_id.strip()
    if clean_workspace and PROVIDER_IDENTIFIER_RE.fullmatch(clean_workspace) is None:
        auth.flash(request, "Workspace ID contains unsupported characters.", "error")
        return RedirectResponse("/admin", status_code=303)
    payload = {
        "organization_id": organization_id,
        "service_account_id": service_account_id,
        "federation_rule_id": federation_rule_id,
        "workspace_id": clean_workspace or None,
        # Bind the operator's ENROLLED confirmation to the exact public JWKS
        # copied from this rendered page. The rotator refetches and compares it
        # before persisting any provider enrollment.
        "federation_jwks_sha256": federation_jwks_sha256.lower(),
        "enrollment_confirmation": enrollment_confirmation,
    }
    try:
        result = await _rotator_put("/providers/anthropic", payload)
        changed = isinstance(result, dict) and result.get("changed") is True
        _audit(
            "provider.anthropic.configure",
            "success",
            user,
            changed=changed,
        )
        auth.flash(
            request,
            "Anthropic WIF enrollment saved. No private key material was returned.",
            "success",
        )
    except Exception:  # noqa: BLE001 - upstream detail can contain identifiers
        _audit("provider.anthropic.configure", "failure", user)
        auth.flash(
            request,
            "Anthropic enrollment was not saved; existing provider state was preserved.",
            "error",
        )
    return RedirectResponse("/admin", status_code=303)


@admin_app.post("/admin/providers/anthropic/disable")
async def admin_disable_anthropic_provider(
    request: Request,
    user: dict[str, Any] = Depends(require_recent_live_admin),
    confirmation: str = Form(..., min_length=1, max_length=32),
    csrf_token: str = Form(..., min_length=32, max_length=128),
):
    if not auth.verify_csrf(request, csrf_token):
        auth.flash(request, "Your session expired — please try again.", "error")
        return RedirectResponse("/admin", status_code=303)
    if not secrets.compare_digest(confirmation, "DISABLE anthropic"):
        auth.flash(
            request,
            "Type DISABLE anthropic exactly to stop token refresh.",
            "error",
        )
        return RedirectResponse("/admin", status_code=303)
    try:
        result = await _rotator_post(
            "/providers/anthropic/disable", {"confirmation": confirmation}
        )
        state_name = result.get("state") if isinstance(result, dict) else ""
        _audit("provider.anthropic.disable", "success", user, state=state_name)
        if state_name == "revocation_pending":
            auth.flash(
                request,
                "Refresh stopped. Deletion remains blocked until the last short-lived token is provably expired.",
                "info",
            )
        else:
            auth.flash(request, "Anthropic token refresh is disabled.", "success")
    except Exception:  # noqa: BLE001
        _audit("provider.anthropic.disable", "failure", user)
        auth.flash(
            request,
            "Could not prove a safe provider disable; no deletion was attempted.",
            "error",
        )
    return RedirectResponse("/admin", status_code=303)


@admin_app.post("/admin/providers/anthropic/delete")
async def admin_delete_anthropic_provider(
    request: Request,
    user: dict[str, Any] = Depends(require_recent_live_admin),
    confirmation: str = Form(..., min_length=1, max_length=32),
    csrf_token: str = Form(..., min_length=32, max_length=128),
):
    if not auth.verify_csrf(request, csrf_token):
        auth.flash(request, "Your session expired — please try again.", "error")
        return RedirectResponse("/admin", status_code=303)
    if not secrets.compare_digest(confirmation, "DELETE anthropic"):
        auth.flash(
            request,
            "Type DELETE anthropic exactly to remove enrollment state.",
            "error",
        )
        return RedirectResponse("/admin", status_code=303)
    try:
        await _rotator_delete("/providers/anthropic", {"confirmation": confirmation})
        _audit("provider.anthropic.delete", "success", user)
        auth.flash(request, "Anthropic enrollment state deleted.", "success")
    except Exception:  # noqa: BLE001
        _audit("provider.anthropic.delete", "failure", user)
        auth.flash(
            request,
            "Provider state was retained because active-credential revocation or expiry could not be proven.",
            "error",
        )
    return RedirectResponse("/admin", status_code=303)


# --- admin / Keycloak identity control ------------------------------------


@admin_app.post("/admin/identity/groups")
async def admin_identity_create_group(
    request: Request,
    user: dict[str, Any] = Depends(require_recent_live_admin),
    name: str = Form(..., min_length=1, max_length=64),
    capabilities: list[str] = Form(default=[]),
    csrf_token: str = Form(..., min_length=32, max_length=128),
):
    if not auth.verify_csrf(request, csrf_token):
        auth.flash(request, "Your session expired — please try again.", "error")
        return RedirectResponse("/admin", status_code=303)
    clean_name = name.strip()
    if litellm_client.PROJECT_ID_RE.fullmatch(clean_name) is None:
        auth.flash(
            request,
            "Project ID must be lowercase and use only letters, numbers, dot, underscore, or hyphen.",
            "error",
        )
        return RedirectResponse("/admin", status_code=303)
    capability_set = set(capabilities)
    if not capability_set or not capability_set <= IDENTITY_CAPABILITIES:
        auth.flash(request, "Choose at least one valid capability.", "error")
        return RedirectResponse("/admin", status_code=303)
    operation_id = str(uuid.uuid4())
    _audit(
        "identity.group.create",
        "intent",
        user,
        group=clean_name,
        operation_id=operation_id,
    )
    try:
        await _rotator_post(
            "/identity/groups",
            {"name": clean_name, "capabilities": sorted(capability_set)},
            operation_id=operation_id,
        )
        _audit(
            "identity.group.create",
            "success",
            user,
            group=clean_name,
            operation_id=operation_id,
        )
        auth.flash(request, "Authorization group created.", "success")
    except Exception as exc:  # noqa: BLE001
        _audit(
            "identity.group.create",
            _identity_mutation_result(exc),
            user,
            group=clean_name,
            operation_id=operation_id,
        )
        auth.flash(request, "Could not create that authorization group.", "error")
    return RedirectResponse("/admin", status_code=303)


@admin_app.post("/admin/identity/groups/{group_id}/delete")
async def admin_identity_delete_group(
    request: Request,
    group_id: str = APIPath(..., pattern=IDENTITY_ID_PATTERN),
    user: dict[str, Any] = Depends(require_recent_live_admin),
    csrf_token: str = Form(..., min_length=32, max_length=128),
):
    if not auth.verify_csrf(request, csrf_token):
        auth.flash(request, "Your session expired — please try again.", "error")
        return RedirectResponse("/admin", status_code=303)
    operation_id = str(uuid.uuid4())
    _audit(
        "identity.group.delete",
        "intent",
        user,
        group=group_id,
        operation_id=operation_id,
    )
    try:
        await _rotator_delete(
            f"/identity/groups/{group_id}", operation_id=operation_id
        )
        _audit(
            "identity.group.delete",
            "success",
            user,
            group=group_id,
            operation_id=operation_id,
        )
        auth.flash(request, "Authorization group deleted.", "success")
    except Exception as exc:  # noqa: BLE001
        _audit(
            "identity.group.delete",
            _identity_mutation_result(exc),
            user,
            group=group_id,
            operation_id=operation_id,
        )
        auth.flash(
            request,
            "Could not delete that group. Remove all members first.",
            "error",
        )
    return RedirectResponse("/admin", status_code=303)


@admin_app.post("/admin/identity/groups/{group_id}/members")
async def admin_identity_add_member(
    request: Request,
    group_id: str = APIPath(..., pattern=IDENTITY_ID_PATTERN),
    user: dict[str, Any] = Depends(require_recent_live_admin),
    user_id: str = Form(..., pattern=IDENTITY_ID_PATTERN),
    csrf_token: str = Form(..., min_length=32, max_length=128),
):
    if not auth.verify_csrf(request, csrf_token):
        auth.flash(request, "Your session expired — please try again.", "error")
        return RedirectResponse("/admin", status_code=303)
    operation_id = str(uuid.uuid4())
    _audit(
        "identity.member.add",
        "intent",
        user,
        group=group_id,
        target_subject=user_id,
        operation_id=operation_id,
    )
    try:
        await _rotator_put(
            f"/identity/groups/{group_id}/members/{user_id}",
            {},
            operation_id=operation_id,
        )
        _audit(
            "identity.member.add",
            "success",
            user,
            group=group_id,
            target_subject=user_id,
            operation_id=operation_id,
        )
        auth.flash(request, "User assigned to the group.", "success")
    except Exception as exc:  # noqa: BLE001
        _audit(
            "identity.member.add",
            _identity_mutation_result(exc),
            user,
            group=group_id,
            target_subject=user_id,
            operation_id=operation_id,
        )
        auth.flash(request, "Could not assign that directory user.", "error")
    return RedirectResponse(
        "/admin?" + urlencode({"group_id": group_id}), status_code=303
    )


@admin_app.post("/admin/identity/groups/{group_id}/members/{user_id}/remove")
async def admin_identity_remove_member(
    request: Request,
    group_id: str = APIPath(..., pattern=IDENTITY_ID_PATTERN),
    user_id: str = APIPath(..., pattern=IDENTITY_ID_PATTERN),
    user: dict[str, Any] = Depends(require_recent_live_admin),
    csrf_token: str = Form(..., min_length=32, max_length=128),
):
    if not auth.verify_csrf(request, csrf_token):
        auth.flash(request, "Your session expired — please try again.", "error")
        return RedirectResponse("/admin", status_code=303)
    operation_id = str(uuid.uuid4())
    _audit(
        "identity.member.remove",
        "intent",
        user,
        group=group_id,
        target_subject=user_id,
        operation_id=operation_id,
    )
    mutation_confirmed = False
    try:
        # The pre-pass prevents knowingly leaving an existing key active. The
        # post-pass closes a concurrent generation window around the Keycloak
        # mutation. The helper's admin-process lock also keeps policy cutover
        # from treating either durable block as a temporary gate.
        project_id = await _remove_member_and_deactivate_keys(
            group_id, user_id, operation_id
        )
        _audit(
            "identity.member.remove",
            "success",
            user,
            group=group_id,
            project=project_id,
            target_subject=user_id,
            operation_id=operation_id,
        )
        mutation_confirmed = True
        if user_id == user.get("sub"):
            # Membership changes can revoke this administrator's own access.
            # Force a full login so a stale role-bearing cookie cannot keep
            # operating until the normal session TTL expires.
            request.session.clear()
            return RedirectResponse("/login", status_code=303)
        auth.flash(request, "User removed from the group.", "success")
    except Exception as exc:  # noqa: BLE001
        if not mutation_confirmed:
            _audit(
                "identity.member.remove",
                _identity_mutation_result(exc),
                user,
                group=group_id,
                target_subject=user_id,
                operation_id=operation_id,
            )
            message = (
                "Could not confirm that user removal; check the live group before "
                "retrying."
            )
        else:
            message = (
                "The user was removed, but project key revocation could not be "
                "verified. Check the key inventory now."
            )
        auth.flash(request, message, "error")
    return RedirectResponse(
        "/admin?" + urlencode({"group_id": group_id}), status_code=303
    )


# --- admin / gateway key inventory -----------------------------------------


ADMIN_KEY_TEXT_LIMIT = 128
ADMIN_KEY_MODELS_LIMIT = 16


def _admin_key_view(entry: dict[str, Any]) -> dict[str, Any]:
    """Build one bounded, allowlisted display row from a full key object.

    The one-time plaintext credential only ever appears in a generate
    response's ``key`` field, but a list response is never trusted to omit
    it: this view model copies exact allowlisted fields and nothing else, so
    the template can never render an unexpected upstream value.
    """

    def text(*names: str, limit: int = ADMIN_KEY_TEXT_LIMIT) -> str:
        for name in names:
            value = entry.get(name)
            if isinstance(value, str) and value:
                return value[:limit]
        return ""

    def number(name: str) -> int | float | None:
        value = entry.get(name)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        return value

    provenance = "operator"
    project = ""
    created_via = ""
    try:
        project_id = _entry_project_id(entry)
        created_via = str(_key_metadata(entry).get("created_via") or "")[:64]
    except litellm_client.LiteLLMError:
        # Renderable but never manageable through provenance shortcuts: a key
        # claiming portal provenance with malformed project data is displayed
        # as exactly that, and no mutation is derived from this label.
        provenance = "invalid-provenance"
    else:
        if project_id is not None:
            provenance = "portal"
            project = project_id

    models_raw = entry.get("models")
    models = (
        [
            str(model)[:64]
            for model in models_raw[:ADMIN_KEY_MODELS_LIMIT]
            if isinstance(model, str)
        ]
        if isinstance(models_raw, list)
        else []
    )

    concrete = _entry_delete_id(entry)
    expires = entry.get("expires")
    if isinstance(expires, datetime):
        expires_text = expires.isoformat()[:64]
    elif isinstance(expires, str):
        expires_text = expires[:64]
    else:
        expires_text = ""
    return {
        # The persisted token hash — a lookup identifier, never a credential.
        "token": concrete or "",
        "manageable": concrete is not None,
        "alias": text("key_alias", "alias"),
        "owner": text("user_id"),
        "team": text("team_id"),
        "provenance": provenance,
        "project": project,
        "created_via": created_via,
        "models": models,
        "spend": number("spend"),
        "max_budget": number("max_budget"),
        "tpm_limit": number("tpm_limit"),
        "rpm_limit": number("rpm_limit"),
        "expires": expires_text,
        "created_at": text("created_at", limit=64),
        "blocked": entry.get("blocked") is True,
        "active": _is_active_key(entry),
    }


_DURATION_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
# Tolerance for the post-update expiry property check: generous enough for
# clock skew and request latency, far too small to hide a wrong lifetime.
DURATION_VERIFY_TOLERANCE_SECONDS = 900


def _duration_seconds(duration: str) -> int:
    """Convert an already-validated LiteLLM duration (e.g. 30d) to seconds."""
    return int(duration[:-1]) * _DURATION_UNIT_SECONDS[duration[-1]]


def _expiry_matches_duration(
    expires: Any, duration: str, *, now: datetime | None = None
) -> bool:
    """Assert the PROPERTY that a key now expires ≈ now + duration.

    Tolerates the format (string or datetime, Z or offset, naive treated as
    UTC) and bounded clock skew — never a byte-exact timestamp comparison.
    """
    if isinstance(expires, datetime):
        expiry = expires
    elif isinstance(expires, str):
        try:
            expiry = datetime.fromisoformat(expires.strip().replace("Z", "+00:00"))
        except ValueError:
            return False
    else:
        return False
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    reference = now or datetime.now(timezone.utc)
    expected = reference + timedelta(seconds=_duration_seconds(duration))
    return (
        abs((expiry - expected).total_seconds()) <= DURATION_VERIFY_TOLERANCE_SECONDS
    )


def _parse_admin_limit_field(field: str, raw: str) -> tuple[bool, Any]:
    """Parse one submitted limit field: empty = unchanged, "none" = uncapped.

    Raises ValueError on anything else that is not a strictly bounded value;
    the caller turns that into a flash without contacting LiteLLM.
    """
    value = raw.strip()
    if not value:
        return False, None
    if field == "duration":
        # Clearing an expiry is deliberately not offered here; leave blank to
        # keep the current lifetime.
        if litellm_client.KEY_DURATION_RE.fullmatch(value) is None:
            raise ValueError(field)
        return True, value
    if value.lower() == "none":
        return True, None
    if field == "max_budget":
        number = float(value)
        if not 0 < number <= 1_000_000:
            raise ValueError(field)
        return True, number
    number_int = int(value, 10)
    if not 0 < number_int <= 1_000_000_000:
        raise ValueError(field)
    return True, number_int


async def _admin_update_key_limits(
    token: str, updates: dict[str, Any]
) -> dict[str, Any]:
    """Serialize and verify one key limit edit against policy cutover."""

    async with _admin_key_policy_lock:
        entry = await litellm_client.admin_key_lookup(token)
        await litellm_client.key_update(entry["token"], updates)
        after = await litellm_client.admin_key_lookup(token)
        for field in ("max_budget", "tpm_limit", "rpm_limit"):
            if field in updates and after.get(field) != updates[field]:
                raise litellm_client.LiteLLMError(
                    "key limits did not verify after update"
                )
        if "duration" in updates and not _expiry_matches_duration(
            after.get("expires"), updates["duration"]
        ):
            raise litellm_client.LiteLLMError(
                "key expiry did not verify after update"
            )
        return entry


@admin_app.get("/admin/keys", response_class=HTMLResponse)
async def admin_keys_page(
    request: Request,
    user: dict[str, Any] = Depends(require_live_admin),
    page: int = Query(1, ge=1, le=10_000),
) -> HTMLResponse:
    listing: dict[str, Any] | None = None
    rows: list[dict[str, Any]] = []
    list_error: str | None = None
    try:
        listing = await litellm_client.admin_key_list_page(page)
        rows = [_admin_key_view(entry) for entry in listing["keys"]]
    except litellm_client.LiteLLMError:
        list_error = "Could not safely read the gateway key inventory right now."

    return templates.TemplateResponse(
        request,
        "admin_keys.html",
        {
            "user": user,
            "is_admin": True,
            "admin_surface": True,
            "keys": rows,
            "list_error": list_error,
            "page": page,
            "total_pages": listing["total_pages"] if listing else 0,
            "total_count": listing["total_count"] if listing else 0,
            "identity_step_up_recent": auth.has_recent_admin_reauthentication(request),
            "identity_step_up_expires_at": auth.admin_reauthentication_expires_at(
                request
            ),
            "flashes": auth.pop_flash(request),
            "csrf_token": auth.get_csrf_token(request),
        },
    )


async def _admin_block_key(token: str) -> dict[str, Any]:
    """Serialize and verify one manual block against policy cutover."""

    async with _admin_key_policy_lock:
        entry = await litellm_client.admin_key_lookup(token)
        await _block_key_with_durable_intent(entry)
        return entry


@admin_app.post("/admin/keys/block")
async def admin_key_block(
    request: Request,
    user: dict[str, Any] = Depends(require_recent_live_admin),
    token: str = Form(..., min_length=1, max_length=2048),
    page: int = Form(1, ge=1, le=10_000),
    csrf_token: str = Form(..., min_length=32, max_length=128),
):
    redirect = RedirectResponse(f"/admin/keys?page={page}", status_code=303)
    if not auth.verify_csrf(request, csrf_token):
        auth.flash(request, "Your session expired — please try again.", "error")
        return redirect
    try:
        entry = await _admin_block_key(token)
        _audit(
            "admin.key.block",
            "success",
            user,
            alias=str(entry.get("key_alias") or "")[:128],
            owner=str(entry.get("user_id") or "")[:128],
        )
        auth.flash(request, "Key blocked. It stops working immediately.", "success")
    except litellm_client.LiteLLMError:
        _audit("admin.key.block", "failure", user)
        auth.flash(
            request,
            "Could not verify that key was blocked. Refresh and try again.",
            "error",
        )
    return redirect


class _UnblockDenied(Exception):
    """Unblocking this key would silently restore revoked project access."""


async def _require_safe_portal_key_unblock(entry: dict[str, Any]) -> None:
    """Refuse to resurrect a portal key whose owner lost live membership.

    Membership revocation deactivates portal keys with the same
    ``blocked: true`` bit a manual admin block uses, so an unblock could
    silently restore access the identity controller already revoked. For
    portal-provenance keys the owner's LIVE membership in the key's exact
    project is therefore re-proven first; every ambiguity (malformed
    provenance, invalid owner, unreachable controller) denies the unblock.
    Operator-provenance keys are untouched by membership revocation and skip
    this check.
    """
    try:
        key_project = _entry_project_id(entry)
    except litellm_client.LiteLLMError as exc:
        raise _UnblockDenied(
            "Unblock denied: this key claims portal provenance but its "
            "project binding is malformed."
        ) from exc
    if key_project is None:
        return
    owner = entry.get("user_id")
    if not isinstance(owner, str) or IDENTITY_ID_RE.fullmatch(owner) is None:
        raise _UnblockDenied(
            "Unblock denied: this portal key has no valid owner identity."
        )
    try:
        raw = await _rotator_get(f"/identity/projects/{owner}")
    except Exception as exc:  # noqa: BLE001 - ambiguity must deny, not allow
        raise _UnblockDenied(
            "Unblock denied: the owner's live project membership could not "
            "be verified."
        ) from exc
    projects = raw.get("projects") if isinstance(raw, dict) else None
    if not isinstance(projects, list) or any(
        not isinstance(project, str) for project in projects
    ):
        raise _UnblockDenied(
            "Unblock denied: the owner's live project membership could not "
            "be verified."
        )
    if key_project not in projects:
        raise _UnblockDenied(
            "Unblock denied: the owner no longer has live membership in "
            f"project '{key_project}'. Restore the membership first."
        )
    policies = raw.get("policies") if isinstance(raw, dict) else None
    reconciliation = (
        raw.get("policy_reconciliation") if isinstance(raw, dict) else None
    )
    policy = (
        _validated_policy_object(policies.get(key_project))
        if isinstance(policies, dict)
        else None
    )
    policy_state = (
        reconciliation.get(key_project)
        if isinstance(reconciliation, dict)
        else None
    )
    if (
        policy is None
        or not isinstance(policy_state, dict)
        or set(policy_state) != {"ready", "revision"}
        or policy_state.get("ready") is not True
    ):
        raise _UnblockDenied(
            "Unblock denied: the project's current key policy is not ready."
        )
    try:
        expected_revision = litellm_client.project_policy_revision(policy)
    except litellm_client.LiteLLMError as exc:
        raise _UnblockDenied(
            "Unblock denied: the project's current key policy is invalid."
        ) from exc
    metadata = _key_metadata(entry)
    if (
        not isinstance(policy_state.get("revision"), str)
        or not hmac.compare_digest(policy_state["revision"], expected_revision)
        or not hmac.compare_digest(
            str(metadata.get(litellm_client.PORTAL_POLICY_REVISION_METADATA_KEY) or ""),
            expected_revision,
        )
        or litellm_client.PORTAL_POLICY_GATE_METADATA_KEY in metadata
    ):
        raise _UnblockDenied(
            "Unblock denied: this key has not verified the current project policy."
        )


async def _admin_unblock_key(token: str) -> dict[str, Any]:
    """Serialize and verify one explicit unblock against policy cutover."""

    async with _admin_key_policy_lock:
        entry = await litellm_client.admin_key_lookup(token)
        await _require_safe_portal_key_unblock(entry)
        await _unblock_key_with_durable_intent(entry)
        return entry


@admin_app.post("/admin/keys/unblock")
async def admin_key_unblock(
    request: Request,
    user: dict[str, Any] = Depends(require_recent_live_admin),
    token: str = Form(..., min_length=1, max_length=2048),
    page: int = Form(1, ge=1, le=10_000),
    csrf_token: str = Form(..., min_length=32, max_length=128),
):
    redirect = RedirectResponse(f"/admin/keys?page={page}", status_code=303)
    if not auth.verify_csrf(request, csrf_token):
        auth.flash(request, "Your session expired — please try again.", "error")
        return redirect
    try:
        entry = await _admin_unblock_key(token)
        _audit(
            "admin.key.unblock",
            "success",
            user,
            alias=str(entry.get("key_alias") or "")[:128],
            owner=str(entry.get("user_id") or "")[:128],
        )
        auth.flash(request, "Key unblocked.", "success")
    except _UnblockDenied as denial:
        _audit("admin.key.unblock", "denied-membership", user)
        auth.flash(request, str(denial), "error")
    except litellm_client.LiteLLMError:
        _audit("admin.key.unblock", "failure", user)
        auth.flash(
            request,
            "Could not verify that key was unblocked. Refresh and try again.",
            "error",
        )
    return redirect


@admin_app.post("/admin/keys/limits")
async def admin_key_limits(
    request: Request,
    user: dict[str, Any] = Depends(require_recent_live_admin),
    token: str = Form(..., min_length=1, max_length=2048),
    max_budget: str = Form("", max_length=32),
    tpm_limit: str = Form("", max_length=32),
    rpm_limit: str = Form("", max_length=32),
    duration: str = Form("", max_length=16),
    page: int = Form(1, ge=1, le=10_000),
    csrf_token: str = Form(..., min_length=32, max_length=128),
):
    redirect = RedirectResponse(f"/admin/keys?page={page}", status_code=303)
    if not auth.verify_csrf(request, csrf_token):
        auth.flash(request, "Your session expired — please try again.", "error")
        return redirect

    updates: dict[str, Any] = {}
    try:
        for field, raw in (
            ("max_budget", max_budget),
            ("tpm_limit", tpm_limit),
            ("rpm_limit", rpm_limit),
            ("duration", duration),
        ):
            present, value = _parse_admin_limit_field(field, raw)
            if present:
                updates[field] = value
    except ValueError:
        auth.flash(
            request,
            'Limits must be positive numbers, "none" to remove a cap, or a '
            "duration like 30d.",
            "error",
        )
        return redirect
    if not updates:
        auth.flash(request, "Provide at least one limit change.", "error")
        return redirect

    try:
        entry = await _admin_update_key_limits(token, updates)
        _audit(
            "admin.key.limits",
            "success",
            user,
            alias=str(entry.get("key_alias") or "")[:128],
            owner=str(entry.get("user_id") or "")[:128],
            fields=",".join(sorted(updates)),
        )
        auth.flash(request, "Key limits updated.", "success")
    except litellm_client.LiteLLMError:
        _audit("admin.key.limits", "failure", user)
        auth.flash(
            request,
            "Could not verify the key limit change. Refresh and try again.",
            "error",
        )
    return redirect


# --- admin / per-project issuance policy ------------------------------------


RETUNE_MAX_PAGES = 40


def _retuned_key_metadata(
    entry: dict[str, Any],
    policy: dict[str, Any],
    *,
    policy_gate: str | None = None,
) -> dict[str, Any]:
    """Rebuild one portal key's metadata with exactly the policy's default.

    LiteLLM's /key/update replaces the whole metadata object, so every field
    other than the managed default is preserved byte-for-byte from the entry
    whose portal provenance the caller has just verified — dropping anything
    here would erase the provenance that authorizes later key decisions.
    """

    metadata = {
        name: value
        for name, value in _key_metadata(entry).items()
        if name
        not in {
            litellm_client.PORTAL_DEFAULT_MODEL_METADATA_KEY,
            litellm_client.PORTAL_MODEL_LIMITS_METADATA_KEY,
            litellm_client.PORTAL_POLICY_GATE_METADATA_KEY,
            litellm_client.PORTAL_POLICY_REVISION_METADATA_KEY,
        }
    }
    if policy["default_model"] is not None:
        metadata[litellm_client.PORTAL_DEFAULT_MODEL_METADATA_KEY] = policy[
            "default_model"
        ]
    if policy["model_limits"]:
        metadata[litellm_client.PORTAL_MODEL_LIMITS_METADATA_KEY] = (
            litellm_client.canonical_model_limits(
                policy["model_limits"], policy["allowed_models"] or []
            )
        )
    revision = policy.get(litellm_client.PROJECT_POLICY_REVISION_FIELD)
    if (
        not isinstance(revision, str)
        or litellm_client.POLICY_REVISION_RE.fullmatch(revision) is None
    ):
        raise litellm_client.LiteLLMError("project policy revision is invalid")
    metadata[litellm_client.PORTAL_POLICY_REVISION_METADATA_KEY] = revision
    if policy_gate is not None:
        if (
            litellm_client.POLICY_REVISION_RE.fullmatch(policy_gate) is None
            or not hmac.compare_digest(policy_gate, revision)
        ):
            raise litellm_client.LiteLLMError(
                "project policy gate revision is invalid"
            )
        metadata[litellm_client.PORTAL_POLICY_GATE_METADATA_KEY] = policy_gate
    return metadata


async def _project_key_inventory(project_id: str) -> list[dict[str, Any]]:
    """Read one counter-stable global inventory and select exact portal keys."""

    expected_total: int | None = None
    expected_pages: int | None = None
    project_keys: list[dict[str, Any]] = []
    for page in range(1, RETUNE_MAX_PAGES + 1):
        listing = await litellm_client.admin_key_list_page(page)
        total_count = listing.get("total_count")
        total_pages = listing.get("total_pages")
        if expected_total is None:
            expected_total = total_count
            expected_pages = total_pages
            if not isinstance(total_pages, int) or total_pages > RETUNE_MAX_PAGES:
                raise litellm_client.LiteLLMError(
                    "key inventory exceeded the policy re-tune safety bound"
                )
        elif total_count != expected_total or total_pages != expected_pages:
            raise litellm_client.LiteLLMError(
                "key inventory changed during policy reconciliation"
            )
        for entry in listing["keys"]:
            if _entry_project_id(entry) == project_id:
                project_keys.append(entry)
        if not total_pages or page >= total_pages:
            return project_keys
    raise litellm_client.LiteLLMError(
        "key inventory exceeded the policy re-tune safety bound"
    )


def _desired_project_models(
    policy: dict[str, Any], configured_models: list[str] | None
) -> list[str]:
    models = policy["allowed_models"]
    desired = models if models is not None else sorted(configured_models or [])
    if not desired:
        raise litellm_client.LiteLLMError(
            "project policy has no explicit runtime model scope"
        )
    return sorted(desired)


def _project_key_matches_policy(
    entry: dict[str, Any],
    project_id: str,
    policy: dict[str, Any],
    desired_models: list[str],
    *,
    blocked: bool,
    policy_gate: str | None = None,
) -> bool:
    raw_models = entry.get("models")
    if (
        not isinstance(raw_models, list)
        or any(not isinstance(model, str) for model in raw_models)
        or len(raw_models) != len(desired_models)
    ):
        return False
    expected_limits = (
        litellm_client.canonical_model_limits(
            policy["model_limits"], desired_models
        )
        if policy["model_limits"]
        else None
    )
    metadata = _key_metadata(entry)
    return (
        _entry_project_id(entry) == project_id
        and entry.get("blocked") is blocked
        and entry.get("tpm_limit") == policy["tpm_limit"]
        and entry.get("rpm_limit") == policy["rpm_limit"]
        and sorted(raw_models) == desired_models
        and metadata.get(litellm_client.PORTAL_DEFAULT_MODEL_METADATA_KEY)
        == policy["default_model"]
        and metadata.get(litellm_client.PORTAL_MODEL_LIMITS_METADATA_KEY)
        == expected_limits
        and metadata.get(litellm_client.PORTAL_POLICY_REVISION_METADATA_KEY)
        == policy[litellm_client.PROJECT_POLICY_REVISION_FIELD]
        and (
            metadata.get(litellm_client.PORTAL_POLICY_GATE_METADATA_KEY)
            == policy_gate
            if policy_gate is not None
            else litellm_client.PORTAL_POLICY_GATE_METADATA_KEY not in metadata
        )
    )


async def _gate_project_keys(project_id: str, policy_revision: str) -> int:
    """Block every stale active project key before activating new policy."""

    if litellm_client.POLICY_REVISION_RE.fullmatch(policy_revision) is None:
        raise litellm_client.LiteLLMError("project policy revision is invalid")
    gated = 0
    for _pass in range(2):
        targets: list[dict[str, Any]] = []
        for entry in await _project_key_inventory(project_id):
            metadata = _key_metadata(entry)
            manually_blocked = (
                metadata.get(litellm_client.PORTAL_MANUAL_BLOCK_METADATA_KEY)
                is True
            )
            already_current = (
                metadata.get(litellm_client.PORTAL_POLICY_REVISION_METADATA_KEY)
                == policy_revision
                and litellm_client.PORTAL_POLICY_GATE_METADATA_KEY not in metadata
                and not manually_blocked
            )
            if _is_active_key(entry) and not already_current:
                targets.append(entry)
        if not targets:
            return gated
        for entry in targets:
            concrete = _entry_delete_id(entry)
            if concrete is None:
                raise litellm_client.LiteLLMError(
                    "active project key has no concrete identifier"
                )
            metadata = dict(_key_metadata(entry))
            metadata[litellm_client.PORTAL_POLICY_GATE_METADATA_KEY] = (
                policy_revision
            )
            updates: dict[str, Any] = {"blocked": True, "metadata": metadata}
            if (
                litellm_client.PORTAL_DEFAULT_MODEL_METADATA_KEY in metadata
                or litellm_client.PORTAL_MODEL_LIMITS_METADATA_KEY in metadata
            ):
                raw_models = entry.get("models")
                if not isinstance(raw_models, list) or any(
                    not isinstance(model, str) for model in raw_models
                ):
                    raise litellm_client.LiteLLMError(
                        "active project key model scope is invalid"
                    )
                updates["models"] = sorted(raw_models)
            try:
                await litellm_client.key_update(concrete, updates)
            except litellm_client.LiteLLMError:
                # A lost response may still have committed. The exact lookup
                # below is the decision; no key identifier enters a log.
                pass
            after = await litellm_client.admin_key_lookup(concrete)
            after_metadata = _key_metadata(after)
            if (
                after.get("blocked") is not True
                or _entry_project_id(after) != project_id
                or after_metadata.get(
                    litellm_client.PORTAL_POLICY_GATE_METADATA_KEY
                )
                != policy_revision
            ):
                raise litellm_client.LiteLLMError(
                    "project key policy gate did not verify"
                )
            gated += 1

    for entry in await _project_key_inventory(project_id):
        metadata = _key_metadata(entry)
        if _is_active_key(entry) and metadata.get(
            litellm_client.PORTAL_POLICY_REVISION_METADATA_KEY
        ) != policy_revision:
            raise litellm_client.LiteLLMError(
                "an active project key escaped the policy gate"
            )
    return gated


async def _retune_project_keys(
    project_id: str,
    policy: dict[str, Any],
    configured_models: list[str] | None = None,
) -> tuple[int, int]:
    """Apply active policy to every project key and release only gated keys."""

    desired_models = _desired_project_models(policy, configured_models)
    base_updates: dict[str, Any] = {
        "tpm_limit": policy["tpm_limit"],
        "rpm_limit": policy["rpm_limit"],
        "models": desired_models,
    }
    retuned = 0
    for entry in await _project_key_inventory(project_id):
        metadata = _key_metadata(entry)
        gated = (
            metadata.get(litellm_client.PORTAL_POLICY_GATE_METADATA_KEY)
            == policy[litellm_client.PROJECT_POLICY_REVISION_FIELD]
            and metadata.get(
                litellm_client.PORTAL_MANUAL_BLOCK_METADATA_KEY
            )
            is not True
        )
        desired_blocked = (
            True
            if metadata.get(litellm_client.PORTAL_MANUAL_BLOCK_METADATA_KEY)
            is True
            else False if gated else entry.get("blocked") is True
        )
        if _is_active_key(entry) and not gated and not _project_key_matches_policy(
            entry,
            project_id,
            policy,
            desired_models,
            blocked=False,
        ):
            # The pre-activation gate must have caught every stale active key.
            # Never repair one while it remains usable under the new policy.
            continue
        if _project_key_matches_policy(
            entry,
            project_id,
            policy,
            desired_models,
            blocked=desired_blocked,
        ):
            continue
        concrete = _entry_delete_id(entry)
        if concrete is None:
            continue
        # Keep a gated key blocked while its policy fields and revision stamp
        # are written. Only a second, verified update may make it usable again.
        # This avoids exposing a stale key if LiteLLM accepts `blocked=false`
        # but silently drops another field from a multi-field update.
        updates = {
            **base_updates,
            "blocked": True,
            "metadata": _retuned_key_metadata(
                entry,
                policy,
                policy_gate=(
                    policy[litellm_client.PROJECT_POLICY_REVISION_FIELD]
                    if gated
                    else None
                ),
            ),
        }
        try:
            await litellm_client.key_update(concrete, updates)
        except litellm_client.LiteLLMError:
            pass
        after = await litellm_client.admin_key_lookup(concrete)
        if not _project_key_matches_policy(
            after,
            project_id,
            policy,
            desired_models,
            blocked=True,
            policy_gate=(
                policy[litellm_client.PROJECT_POLICY_REVISION_FIELD]
                if gated
                else None
            ),
        ):
            continue
        if gated:
            try:
                await litellm_client.key_update(concrete, {"blocked": False})
            except litellm_client.LiteLLMError:
                pass
            after = await litellm_client.admin_key_lookup(concrete)
            if not _project_key_matches_policy(
                after,
                project_id,
                policy,
                desired_models,
                blocked=False,
                policy_gate=policy[
                    litellm_client.PROJECT_POLICY_REVISION_FIELD
                ],
            ):
                continue
            cleanup_updates = {
                **base_updates,
                "metadata": _retuned_key_metadata(after, policy),
            }
            try:
                await litellm_client.key_update(concrete, cleanup_updates)
            except litellm_client.LiteLLMError:
                pass
            after = await litellm_client.admin_key_lookup(concrete)
            if not _project_key_matches_policy(
                after, project_id, policy, desired_models, blocked=False
            ):
                continue
        retuned += 1

    failed = 0
    for entry in await _project_key_inventory(project_id):
        metadata = _key_metadata(entry)
        manually_blocked = (
            metadata.get(litellm_client.PORTAL_MANUAL_BLOCK_METADATA_KEY)
            is True
        )
        expected_blocked = True if manually_blocked else entry.get("blocked") is True
        if (
            not manually_blocked
            and metadata.get(litellm_client.PORTAL_POLICY_GATE_METADATA_KEY)
            == policy[litellm_client.PROJECT_POLICY_REVISION_FIELD]
        ):
            expected_blocked = False
        if not _project_key_matches_policy(
            entry,
            project_id,
            policy,
            desired_models,
            blocked=expected_blocked,
        ):
            failed += 1
    return retuned, failed


def _is_active_custom_model(model: dict[str, Any]) -> bool:
    """A governed model that is active but excluded from user-facing discovery.

    Such a model IS deployed in LiteLLM and callable by its exact gateway name
    (docs/sop/model-lifecycle.md), so it is a legitimate EXPLICIT project-
    assignment target. It is deliberately never part of the implicit
    "all public models" scope: a project only ever gets it by an explicit
    check. (The internal state name for this is "active + not visible"; the
    admin surface calls it "custom" — presentation only, no contract change.)
    """

    return (
        model.get("lifecycle_state") == "active"
        and model.get("visible_in_discovery") is False
    )


async def _active_custom_model_names() -> set[str]:
    """Names of active custom (non-discovery) governed models, fail-closed.

    Used by the project-policy save path so an operator may assign a custom
    model by explicit check. Any failure returns an empty set: it must never
    widen the implicit "all public models" scope, and never silently drop a
    stored restriction to a model it simply could not read.
    """

    try:
        governed = model_admin.safe_governed_models(
            await _rotator_get("/model-governance/models")
        )
    except Exception:  # noqa: BLE001 - unreadable catalog fails closed to none
        return set()
    return {
        model["gateway_model_name"]
        for model in governed
        if _is_active_custom_model(model)
    }


async def _current_group_policy(group_id: str) -> dict[str, Any] | None:
    """Authoritatively re-read one managed group's stored issuance policy.

    Used at policy-save time to decide whether a full-replace form could
    faithfully represent the CURRENT model restriction. Reads the live
    controller state (never a hidden form field), so a tampered or stale
    browser cannot suppress the anti-widening guard below. Returns None only
    when the group is genuinely absent; a malformed/unreadable response
    raises so the caller fails closed.
    """
    groups = _safe_identity_groups(await _rotator_get("/identity/groups"))
    for group in groups:
        if group["id"] == group_id:
            return group.get("policy")
    return None


class _PolicyWriteFailed(Exception):
    """The controller did not confirm whether the staged write succeeded."""

    def __init__(self, error: Exception) -> None:
        super().__init__("project policy write failed")
        self.error = error


class _PolicyStageUnconfirmed(Exception):
    """The controller response did not prove one valid pending revision."""


class _PolicyReconciliationUnconfirmed(Exception):
    """A staged policy did not complete its key reconciliation."""

    def __init__(self, project_id: str) -> None:
        super().__init__("project policy reconciliation did not complete")
        self.project_id = project_id


async def _apply_project_policy(
    group_id: str,
    payload: dict[str, Any],
    operation_id: str,
    available_models: list[str],
) -> tuple[str, int, int]:
    """Stage, gate, activate, retune, and complete one policy under one lock."""

    async with _admin_key_policy_lock:
        try:
            result = await _rotator_put(
                f"/identity/groups/{group_id}/policy",
                payload,
                operation_id=operation_id,
            )
        except Exception as exc:  # noqa: BLE001 - classified by the route
            raise _PolicyWriteFailed(exc) from exc

        applied = (
            _validated_policy_object(result.get("policy"))
            if isinstance(result, dict)
            else None
        )
        project_id = result.get("name") if isinstance(result, dict) else None
        revision = (
            result.get("policy_revision") if isinstance(result, dict) else None
        )
        try:
            expected_revision = litellm_client.project_policy_revision(applied)
        except litellm_client.LiteLLMError:
            expected_revision = ""
        if (
            applied is None
            or not isinstance(project_id, str)
            or litellm_client.PROJECT_ID_RE.fullmatch(project_id) is None
            or not isinstance(revision, str)
            or litellm_client.POLICY_REVISION_RE.fullmatch(revision) is None
            or not hmac.compare_digest(revision, expected_revision)
            or not isinstance(result, dict)
            or result.get("reconciliation_pending") is not True
        ):
            raise _PolicyStageUnconfirmed

        applied[litellm_client.PROJECT_POLICY_REVISION_FIELD] = revision
        try:
            gated = await _gate_project_keys(project_id, revision)
            activated = await _rotator_post(
                f"/identity/groups/{group_id}/policy/activate",
                {"policy_revision": revision},
                operation_id=operation_id,
            )
            if (
                not isinstance(activated, dict)
                or activated.get("reconciliation_pending") is not True
                or activated.get("active_policy") != result.get("policy")
                or activated.get("policy_revision") != revision
            ):
                raise litellm_client.LiteLLMError(
                    "controller did not verify the active project policy"
                )
            retuned, failed = await _retune_project_keys(
                project_id, applied, available_models
            )
            if failed:
                raise litellm_client.LiteLLMError(
                    "one or more project keys did not verify the active policy"
                )
            completed = await _rotator_post(
                f"/identity/groups/{group_id}/policy/complete",
                {"policy_revision": revision},
                operation_id=operation_id,
            )
            if (
                not isinstance(completed, dict)
                or completed.get("reconciliation_pending") is not False
                or completed.get("active_policy") != result.get("policy")
                or completed.get("policy_revision") != revision
            ):
                raise litellm_client.LiteLLMError(
                    "controller did not complete project policy reconciliation"
                )
        except Exception as exc:  # noqa: BLE001 - route emits bounded audit
            raise _PolicyReconciliationUnconfirmed(project_id) from exc
        return project_id, gated, retuned


@admin_app.post("/admin/identity/groups/{group_id}/policy")
async def admin_identity_set_group_policy(
    request: Request,
    group_id: str = APIPath(..., pattern=IDENTITY_ID_PATTERN),
    user: dict[str, Any] = Depends(require_recent_live_admin),
    tpm_limit: str = Form("", max_length=32),
    rpm_limit: str = Form("", max_length=32),
    allowed_models: list[str] = Form(default=[]),
    default_model: str = Form("", max_length=128),
    limit_models: list[str] = Form(default=[]),
    max_output_tokens_per_request: list[str] = Form(default=[]),
    output_tokens_per_utc_minute: list[str] = Form(default=[]),
    remove_model_restrictions: str | None = Form(None),
    deny_all_models: str | None = Form(None),
    csrf_token: str = Form(..., min_length=32, max_length=128),
):
    redirect = RedirectResponse(
        "/admin?" + urlencode({"group_id": group_id}), status_code=303
    )
    if not auth.verify_csrf(request, csrf_token):
        auth.flash(request, "Your session expired — please try again.", "error")
        return redirect

    # Full-replace form semantics: blank rate limit = unlimited; no checked
    # model = every public model configured now; a checked subset is an exact
    # restriction. Portal keys always receive that explicit current set.
    limits: dict[str, int | None] = {}
    for field, raw in (("tpm_limit", tpm_limit), ("rpm_limit", rpm_limit)):
        value = raw.strip()
        if not value:
            limits[field] = None
            continue
        if not value.isdigit() or not 0 < int(value) <= litellm_client.RATE_LIMIT_MAX:
            auth.flash(
                request,
                "Rate limits must be positive integers (blank = unlimited).",
                "error",
            )
            return redirect
        limits[field] = int(value)

    try:
        available = await litellm_client.model_names()
    except litellm_client.LiteLLMError:
        auth.flash(
            request,
            "Could not verify the configured model list; the policy was not "
            "changed.",
            "error",
        )
        return redirect
    if not available:
        auth.flash(
            request,
            "No public model is configured, so the project policy was not changed.",
            "error",
        )
        return redirect
    # `available` is the public discovery set: the none-checked default and the
    # key re-tune expand to exactly it. `assignable` additionally admits active
    # custom (non-discovery) models, which an operator may assign only by an
    # explicit check — they are validated and un-flagged below, but never fold
    # into the implicit "all public models" scope.
    assignable = set(available) | await _active_custom_model_names()

    clear_restrictions = remove_model_restrictions is not None
    deny_all = deny_all_models is not None
    if clear_restrictions and deny_all:
        auth.flash(
            request, "Choose all models or no models, not both.", "error"
        )
        return redirect
    selected = sorted({model.strip() for model in allowed_models if model.strip()})
    if any(model not in assignable for model in selected):
        auth.flash(request, "Choose only configured models.", "error")
        return redirect

    if not (
        len(limit_models)
        == len(max_output_tokens_per_request)
        == len(output_tokens_per_utc_minute)
        <= litellm_client.MAX_POLICY_MODELS
    ) or len(set(limit_models)) != len(limit_models):
        auth.flash(request, "The per-model limit form was invalid.", "error")
        return redirect
    model_limits: dict[str, dict[str, int]] = {}
    for model, raw_request_cap, raw_minute_cap in zip(
        limit_models,
        max_output_tokens_per_request,
        output_tokens_per_utc_minute,
        strict=True,
    ):
        request_cap = raw_request_cap.strip()
        minute_cap = raw_minute_cap.strip()
        if not request_cap and not minute_cap:
            continue
        if (
            model not in assignable
            or model not in selected
            or not request_cap.isdigit()
            or not minute_cap.isdigit()
        ):
            auth.flash(
                request,
                "Set both output limits only for a checked, configured model.",
                "error",
            )
            return redirect
        model_limits[model] = {
            "max_output_tokens_per_request": int(request_cap),
            "output_tokens_per_utc_minute": int(minute_cap),
        }
    try:
        model_limits = json.loads(
            litellm_client.canonical_model_limits(model_limits, selected)
        )
    except litellm_client.LiteLLMError:
        auth.flash(
            request,
            "Output limits must be positive whole numbers. The request cap "
            "cannot exceed the minute cap.",
            "error",
        )
        return redirect

    # Anti-silent-widening guard. The model checkboxes render ONLY from the
    # currently assignable set (live LiteLLM discovery plus active custom
    # models), so if this project is currently restricted to a model that has
    # since been removed or retired, that model has no checkbox and the
    # full-replace form physically cannot re-express the restriction —
    # submitting (even just to change a rate limit) would silently widen it.
    # An active custom model is still assignable, so it is NOT deconfigured.
    # Re-read the authoritative stored policy and REFUSE to widen unless the
    # operator explicitly opts to remove all model restrictions. Same rule for
    # a deconfigured default model.
    try:
        stored_policy = await _current_group_policy(group_id)
    except Exception:  # noqa: BLE001 - unreadable current policy is unsafe
        _audit("identity.group.policy", "failure", user)
        auth.flash(
            request,
            "Could not read the project's current policy; it was not changed.",
            "error",
        )
        return redirect
    if stored_policy is None:
        auth.flash(request, "That project group no longer exists.", "error")
        return redirect
    stored_allowed = stored_policy.get("allowed_models")
    stored_default = stored_policy.get("default_model")
    stored_limits = stored_policy.get("model_limits")
    if not isinstance(stored_limits, dict):
        auth.flash(request, "The stored per-model limits were invalid.", "error")
        return redirect
    deconfigured = sorted(
        set(stored_allowed or [])
        .union([stored_default] if stored_default else [])
        .union(stored_limits)
        - assignable
        - {litellm_client.NO_MODELS_SENTINEL}
    )
    # Setting deny-all is a NARROWING (to nothing), never a silent widening, so
    # the deconfigured-model guard does not apply.
    if deconfigured and not clear_restrictions and not deny_all:
        auth.flash(
            request,
            "This project is restricted to model(s) "
            + ", ".join(deconfigured)
            + " which are no longer configured in LiteLLM, so this form cannot "
            "preserve the restriction. Re-add the model(s) to LiteLLM, or check "
            "'Remove all model restrictions' to widen the project deliberately.",
            "error",
        )
        return redirect

    if clear_restrictions:
        # Explicit operator decision: drop every model restriction.
        selected = []
        clean_default = None
        model_limits = {}
    elif deny_all:
        # Explicit operator decision: no model access at all. Scope the group's
        # keys to a reserved sentinel that matches no real model, so LiteLLM
        # denies every model for API/tooling. Chat is gated by the aigw-chat
        # role separately.
        selected = [litellm_client.NO_MODELS_SENTINEL]
        clean_default = None
        model_limits = {}
    else:
        clean_default = default_model.strip() or None
    if clean_default is not None and clean_default not in (selected or available):
        auth.flash(
            request,
            "The default model must be one of the project's allowed models.",
            "error",
        )
        return redirect

    payload = {
        "tpm_limit": limits["tpm_limit"],
        "rpm_limit": limits["rpm_limit"],
        "allowed_models": selected or None,
        "default_model": clean_default,
        "model_limits": model_limits,
    }
    operation_id = str(uuid.uuid4())
    _audit(
        "identity.group.policy",
        "intent",
        user,
        group=group_id,
        operation_id=operation_id,
    )
    try:
        project_id, gated, retuned = await _apply_project_policy(
            group_id, payload, operation_id, available
        )
    except _PolicyWriteFailed as exc:
        _audit(
            "identity.group.policy",
            _identity_mutation_result(exc.error),
            user,
            group=group_id,
            operation_id=operation_id,
        )
        auth.flash(request, "Could not save the project policy.", "error")
        return redirect

    except _PolicyStageUnconfirmed:
        _audit(
            "identity.group.policy",
            "indeterminate",
            user,
            group=group_id,
            operation_id=operation_id,
        )
        auth.flash(
            request,
            "The controller did not confirm the staged policy. No policy "
            "cutover was attempted. Resubmit to retry.",
            "error",
        )
        return redirect
    except _PolicyReconciliationUnconfirmed as exc:
        _audit(
            "identity.group.policy",
            "indeterminate",
            user,
            group=group_id,
            project=exc.project_id,
            operation_id=operation_id,
        )
        auth.flash(
            request,
            "Policy reconciliation is incomplete. Stale keys remain blocked "
            "or on the previous active policy. Resubmit this same policy to retry.",
            "error",
        )
        return redirect
    _audit(
        "identity.group.policy",
        "success",
        user,
        group=group_id,
        project=project_id,
        operation_id=operation_id,
    )
    auth.flash(
        request,
        f"Project policy saved; {gated} active keys gated and {retuned} keys "
        "reconciled.",
        "success",
    )
    return redirect
