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
import hashlib
import json
import logging
import re
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlsplit

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

from . import auth, litellm_client, tools
from .config import settings

logger = logging.getLogger("dev-portal")

TEMPLATES_DIR = str(Path(__file__).parent / "templates")


def _template_context(request: Request) -> dict[str, str]:
    return {"csp_nonce": getattr(request.state, "csp_nonce", "")}


templates = Jinja2Templates(
    directory=TEMPLATES_DIR, context_processors=[_template_context]
)

VENDOR_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$"
VENDOR_RE = re.compile(VENDOR_PATTERN)
IDENTITY_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"
IDENTITY_ID_RE = re.compile(IDENTITY_ID_PATTERN)
IDENTITY_CAPABILITIES = frozenset({"aigw-users", "aigw-developers", "aigw-admins"})
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
PROJECT_LOCK_STRIPES = 64
AMBIGUOUS_GENERATE_CLEANUP_LIMIT = 8
_project_locks = tuple(asyncio.Lock() for _ in range(PROJECT_LOCK_STRIPES))
# A browser disconnect must not cancel a post-generation authorization check
# halfway through and leave its plaintext-bearing response path in an
# indeterminate state. Keep shielded tasks strongly referenced until they have
# completed; asyncio itself retains only weak references to scheduled tasks.
_post_generation_liveness_tasks: set[asyncio.Task[None]] = set()


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
    event: dict[str, Any] = {
        "event": "aigw.portal.audit",
        "action": action,
        "outcome": outcome,
        "subject": str(user.get("sub") or "")[:255],
    }
    for key, value in fields.items():
        if value is not None:
            event[key] = str(value)[:255]
    logger.info("%s", json.dumps(event, separators=(",", ":"), ensure_ascii=True))


FORBIDDEN_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>403 Forbidden</title>
<style>
body{background:#0f1420;color:#e6e9f0;font-family:-apple-system,sans-serif;
display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.box{background:#161d2e;border:1px solid #263048;border-radius:10px;padding:32px 40px;text-align:center}
a{color:#4f7cff}
</style></head>
<body><div class="box">
<h1>403 — Forbidden</h1>
<p>Your account does not have the role required for this page.</p>
<p><a href="/">Back to your keys</a></p>
</div></body></html>"""


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        await auth.ensure_oauth_client()
    except Exception as exc:  # noqa: BLE001 - startup must not crash the app
        print(
            f"[dev-portal] warning: could not initialize OIDC client at startup: {exc}"
        )
    yield


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
    return HTMLResponse(FORBIDDEN_HTML, status_code=403)


@app.exception_handler(auth.ReauthenticationRequired)
async def handle_reauthentication_required(
    request: Request, exc: auth.ReauthenticationRequired
) -> RedirectResponse:
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

    The deployed portal is one container with one explicitly configured
    Uvicorn worker. This lock serializes the list/generate/verify transaction
    for an owner+project pair inside that topology; post-generate verification
    additionally fails closed if a future unsupported replica races it.
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
                user_id, alias, project_id, project_policy
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
) -> None:
    """Prove membership again, revoking an undisclosed key on every failure."""

    try:
        projects = await _live_project_ids(request, user)
    except Exception:  # noqa: BLE001 - HTTP 503/ambiguous membership is unsafe
        await _deactivate_undisclosed_generated_key(key_value)
        raise

    if project_id not in projects:
        await _deactivate_undisclosed_generated_key(key_value)
        raise litellm_client.LiteLLMError(
            "project membership changed during key generation"
        )


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
            "policy_error": policy_error,
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
        raise HTTPException(
            status_code=403, detail="Project membership is missing or was revoked."
        )
    # The runtime per-project policy (admin-managed Keycloak group attributes)
    # decides this key's rate caps and model set. Unreadable or ambiguous
    # policy fails the mint closed (503) rather than minting unlimited.
    policies = await _live_project_policies(request, user, project_ids)
    try:
        key_value, keys = await _generate_project_key(
            user["sub"],
            clean_alias,
            clean_project,
            project_ids,
            policies[clean_project],
        )
        # Close the normal group-removal race before the one-time plaintext is
        # rendered. The check is shielded so a browser disconnect cannot abort
        # its revoke path; any revoked, unavailable, or ambiguous live decision
        # leaves the key undisclosed.
        post_generation_liveness = _retain_post_generation_liveness_task(
            asyncio.create_task(
                _verify_post_generation_liveness(
                    request, user, clean_project, key_value
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
            "policy_error": None,
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
                raise HTTPException(
                    status_code=403,
                    detail="You can only deactivate a key in your own project.",
                )
            await litellm_client.key_deactivate(concrete_id)
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
    if not await _live_project_ids(request, user):
        raise auth.NotAuthorized()
    # Plaintext keys are never persisted for later views. Snippets reached by
    # navigation therefore always use an explicit placeholder.
    rendered = tools.rendered_tools(settings.public_api_base, "YOUR_KEY")

    return templates.TemplateResponse(
        request,
        "snippets.html",
        {
            "user": user,
            "is_admin": False,
            "tools": rendered,
            "api_base": settings.public_api_base,
            "using_placeholder": True,
            "flashes": auth.pop_flash(request),
        },
    )


# --- admin / rotation control ---


def _rotator_headers() -> dict[str, str]:
    headers: dict[str, str] = {}
    if settings.rotator_internal_token:
        headers["X-Internal-Auth"] = settings.rotator_internal_token
    return headers


async def _rotator_get(path: str) -> Any:
    url = settings.rotator_url.rstrip("/") + path
    async with httpx.AsyncClient(
        timeout=10, trust_env=False, follow_redirects=False
    ) as client:
        resp = await client.get(url, headers=_rotator_headers())
    resp.raise_for_status()
    return resp.json()


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
    if not isinstance(raw, dict) or set(raw) != {
        "tpm_limit",
        "rpm_limit",
        "allowed_models",
        "default_model",
    }:
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
    return {
        "tpm_limit": raw["tpm_limit"],
        "rpm_limit": raw["rpm_limit"],
        "allowed_models": models,
        "default_model": default_model,
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
    if not isinstance(raw_policies, dict):
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
        await litellm_client.key_deactivate(concrete)
    after = _portal_key_inventory(
        await litellm_client.key_list(user_id), user_id, allowed
    )
    if _active_project_keys(after, project_id):
        raise litellm_client.LiteLLMError(
            "project key remained active after membership revocation"
        )


async def _rotator_put(path: str, payload: dict[str, Any]) -> Any:
    url = settings.rotator_url.rstrip("/") + path
    async with httpx.AsyncClient(
        timeout=10, trust_env=False, follow_redirects=False
    ) as client:
        resp = await client.put(url, headers=_rotator_headers(), json=payload)
    resp.raise_for_status()
    return resp.json() if resp.content else None


async def _rotator_post(path: str, payload: dict[str, Any] | None = None) -> Any:
    url = settings.rotator_url.rstrip("/") + path
    async with httpx.AsyncClient(
        timeout=10, trust_env=False, follow_redirects=False
    ) as client:
        kwargs: dict[str, Any] = {"headers": _rotator_headers()}
        if payload is not None:
            kwargs["json"] = payload
        resp = await client.post(url, **kwargs)
    resp.raise_for_status()
    return resp.json() if resp.content else None


async def _rotator_delete(path: str, payload: dict[str, Any] | None = None) -> Any:
    url = settings.rotator_url.rstrip("/") + path
    async with httpx.AsyncClient(
        timeout=10, trust_env=False, follow_redirects=False
    ) as client:
        kwargs: dict[str, Any] = {"headers": _rotator_headers()}
        if payload is not None:
            kwargs["json"] = payload
        resp = await client.delete(url, **kwargs)
    resp.raise_for_status()
    return resp.json() if resp.content else None


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
            }
        result.append(
            {
                "id": group_id,
                "name": name,
                "capabilities": sorted(set(capabilities)),
                "member_count": min(count, 1_000_000),
                "policy": policy,
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

    return templates.TemplateResponse(
        request,
        "admin.html",
        {
            "user": user,
            "is_admin": True,
            "status": status_data,
            "vendors": vendors,
            "history": history,
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
            "policy_models": policy_models,
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


@admin_app.post("/admin/identity/bootstrap")
async def admin_identity_bootstrap(
    request: Request,
    user: dict[str, Any] = Depends(require_recent_live_admin),
    confirmation: str = Form(..., min_length=1, max_length=32),
    csrf_token: str = Form(..., min_length=32, max_length=128),
):
    if not auth.verify_csrf(request, csrf_token):
        auth.flash(request, "Your session expired — please try again.", "error")
        return RedirectResponse("/admin", status_code=303)
    if not secrets.compare_digest(confirmation, "INITIALIZE"):
        auth.flash(request, "Type INITIALIZE exactly to confirm setup.", "error")
        return RedirectResponse("/admin", status_code=303)
    try:
        await _rotator_post("/identity/bootstrap", {"confirmation": confirmation})
        # The one-use Keycloak bootstrap client is deleted only after all
        # controller keys and state have been verified in Vault.
        auth.flash(request, "Keycloak identity setup completed.", "success")
    except Exception:  # noqa: BLE001
        auth.flash(
            request,
            "Identity setup did not complete; no credential details were exposed.",
            "error",
        )
    return RedirectResponse("/admin", status_code=303)


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
    try:
        await _rotator_post(
            "/identity/groups",
            {"name": clean_name, "capabilities": sorted(capability_set)},
        )
        auth.flash(request, "Authorization group created.", "success")
    except Exception:  # noqa: BLE001
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
    try:
        await _rotator_delete(f"/identity/groups/{group_id}")
        auth.flash(request, "Authorization group deleted.", "success")
    except Exception:  # noqa: BLE001
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
    try:
        await _rotator_put(f"/identity/groups/{group_id}/members/{user_id}", {})
        auth.flash(request, "User assigned to the group.", "success")
    except Exception:  # noqa: BLE001
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
    try:
        project_id = await _managed_project_for_group(group_id)
        # Pre-pass prevents knowingly leaving an existing key active. The
        # post-pass closes a concurrent generation window around the Keycloak
        # membership mutation. Any ambiguity or LiteLLM failure fails closed.
        await _deactivate_subject_project_keys(user_id, project_id)
        await _rotator_delete(f"/identity/groups/{group_id}/members/{user_id}")
        await _deactivate_subject_project_keys(user_id, project_id)
        _audit(
            "identity.member.remove",
            "success",
            user,
            project=project_id,
            target_subject=user_id,
        )
        if user_id == user.get("sub"):
            # Membership changes can revoke this administrator's own access.
            # Force a full login so a stale role-bearing cookie cannot keep
            # operating until the normal session TTL expires.
            request.session.clear()
            return RedirectResponse("/login", status_code=303)
        auth.flash(request, "User removed from the group.", "success")
    except Exception:  # noqa: BLE001
        _audit(
            "identity.member.remove",
            "failure",
            user,
            target_subject=user_id,
        )
        auth.flash(
            request,
            "Could not remove that user; the last administrator is protected.",
            "error",
        )
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
            "flashes": auth.pop_flash(request),
            "csrf_token": auth.get_csrf_token(request),
        },
    )


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
        entry = await litellm_client.admin_key_lookup(token)
        await litellm_client.key_update(entry["token"], {"blocked": True})
        after = await litellm_client.admin_key_lookup(token)
        if after.get("blocked") is not True:
            raise litellm_client.LiteLLMError("key remained active after block")
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
        entry = await litellm_client.admin_key_lookup(token)
        await _require_safe_portal_key_unblock(entry)
        await litellm_client.key_update(entry["token"], {"blocked": False})
        after = await litellm_client.admin_key_lookup(token)
        if after.get("blocked") is True:
            raise litellm_client.LiteLLMError("key remained blocked after unblock")
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
        entry = await litellm_client.admin_key_lookup(token)
        await litellm_client.key_update(entry["token"], updates)
        after = await litellm_client.admin_key_lookup(token)
        for field in ("max_budget", "tpm_limit", "rpm_limit"):
            if field in updates and after.get(field) != updates[field]:
                raise litellm_client.LiteLLMError(
                    "key limits did not verify after update"
                )
        # Duration is effect-verified like the numeric caps: the property is
        # that the key now expires ≈ now + duration (format/skew tolerated).
        if "duration" in updates and not _expiry_matches_duration(
            after.get("expires"), updates["duration"]
        ):
            raise litellm_client.LiteLLMError(
                "key expiry did not verify after update"
            )
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


async def _retune_project_keys(
    project_id: str, policy: dict[str, Any]
) -> tuple[int, int]:
    """Retroactively re-tune every portal key in one project to its policy.

    Owner decision: a policy change is DYNAMIC — it applies to existing keys,
    not only new mints. Each key is updated through the same allowlisted
    /key/update path as manual admin edits and the effect is verified from a
    fresh exact-hash read. Returns (retuned, failed); the caller reports both
    and the operation is idempotent, so a partial failure is retried by
    simply resubmitting the policy.
    """
    updates: dict[str, Any] = {
        "tpm_limit": policy["tpm_limit"],
        "rpm_limit": policy["rpm_limit"],
        # An unrestricted policy clears the per-key model list ([] means "no
        # restriction" to LiteLLM).
        "models": (
            policy["allowed_models"] if policy["allowed_models"] is not None else []
        ),
    }
    retuned = 0
    failed = 0
    page = 1
    while True:
        listing = await litellm_client.admin_key_list_page(page)
        for entry in listing["keys"]:
            try:
                entry_project = _entry_project_id(entry)
            except litellm_client.LiteLLMError:
                # A key with malformed portal provenance cannot be attributed
                # to any project; it is surfaced (and manageable) in the key
                # inventory but deliberately not guessed at here.
                continue
            if entry_project != project_id:
                continue
            concrete = _entry_delete_id(entry)
            if concrete is None:
                failed += 1
                continue
            try:
                await litellm_client.key_update(concrete, updates)
                after = await litellm_client.admin_key_lookup(concrete)
                if (
                    after.get("tpm_limit") != updates["tpm_limit"]
                    or after.get("rpm_limit") != updates["rpm_limit"]
                    or sorted(
                        model
                        for model in (after.get("models") or [])
                        if isinstance(model, str)
                    )
                    != updates["models"]
                ):
                    raise litellm_client.LiteLLMError(
                        "key policy re-tune did not verify"
                    )
                retuned += 1
            except litellm_client.LiteLLMError:
                failed += 1
        if listing["total_pages"] <= page:
            return retuned, failed
        page += 1
        if page > RETUNE_MAX_PAGES:
            raise litellm_client.LiteLLMError(
                "key inventory exceeded the policy re-tune safety bound"
            )


@admin_app.post("/admin/identity/groups/{group_id}/policy")
async def admin_identity_set_group_policy(
    request: Request,
    group_id: str = APIPath(..., pattern=IDENTITY_ID_PATTERN),
    user: dict[str, Any] = Depends(require_recent_live_admin),
    tpm_limit: str = Form("", max_length=32),
    rpm_limit: str = Form("", max_length=32),
    allowed_models: list[str] = Form(default=[]),
    default_model: str = Form("", max_length=128),
    csrf_token: str = Form(..., min_length=32, max_length=128),
):
    redirect = RedirectResponse(
        "/admin?" + urlencode({"group_id": group_id}), status_code=303
    )
    if not auth.verify_csrf(request, csrf_token):
        auth.flash(request, "Your session expired — please try again.", "error")
        return redirect

    # Full-replace form semantics: blank rate limit = unlimited; no checked
    # model = every configured model (including future ones); a checked
    # subset is an exact restriction.
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

    selected = sorted({model.strip() for model in allowed_models if model.strip()})
    if any(model not in available for model in selected):
        auth.flash(request, "Choose only configured models.", "error")
        return redirect
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
    }
    try:
        result = await _rotator_put(f"/identity/groups/{group_id}/policy", payload)
    except Exception:  # noqa: BLE001 - upstream detail stays server-side
        _audit("identity.group.policy", "failure", user)
        auth.flash(request, "Could not save the project policy.", "error")
        return redirect

    # Re-tune from the server-normalized policy echoed by the controller, so
    # existing keys converge on exactly what was persisted and verified.
    applied = (
        _validated_policy_object(result.get("policy"))
        if isinstance(result, dict)
        else None
    )
    project_id = result.get("name") if isinstance(result, dict) else None
    if applied is None or not isinstance(project_id, str) or (
        litellm_client.PROJECT_ID_RE.fullmatch(project_id) is None
    ):
        _audit("identity.group.policy", "failure", user)
        auth.flash(
            request,
            "The controller did not confirm the saved policy; existing keys "
            "were not re-tuned. Resubmit to retry.",
            "error",
        )
        return redirect
    _audit("identity.group.policy", "success", user, project=project_id)

    try:
        retuned, failed = await _retune_project_keys(project_id, applied)
    except litellm_client.LiteLLMError:
        auth.flash(
            request,
            "Policy saved, but existing project keys could not all be "
            "re-tuned. Resubmit the policy to retry.",
            "error",
        )
        return redirect
    if failed:
        auth.flash(
            request,
            f"Policy saved; {retuned} existing keys re-tuned, {failed} could "
            "not be verified. Resubmit the policy to retry the remainder.",
            "error",
        )
    else:
        auth.flash(
            request,
            f"Project policy saved; {retuned} existing keys re-tuned.",
            "success",
        )
    return redirect
