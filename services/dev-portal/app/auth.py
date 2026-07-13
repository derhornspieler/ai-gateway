"""OIDC (Keycloak) auth for dev-portal.

Design notes (docs/solution-map.md §1.4 / §2):
  - Browser-facing redirects (authorize, end_session) must resolve on the
    client's machine, so they always use the *public* issuer host
    (OIDC_ISSUER).
  - Server-side calls (discovery, token exchange, userinfo, jwks) run from
    inside the docker network and may need OIDC_INTERNAL_ISSUER instead,
    because the public issuer hostname is frequently not resolvable inside
    the container (e.g. it's only mapped via a public/customer DNS zone).
  - We fetch discovery metadata from the internal issuer (if set) and then
    rewrite the *scheme+host* of the browser-facing endpoints to the public
    issuer's scheme+host, keeping path/query intact.

Roles are read at login from the OIDC token/userinfo claims: a flat "roles"
claim (list) and/or the Keycloak-standard "realm_access": {"roles": [...]}
claim. Both are unioned.

Admin authorization (require_admin) is decided solely from the roles carried in
the signed session cookie. The soundness of that decision rests entirely on the
session signing key, which config.py now enforces to be present, long, and
non-trivial (see config._require_real_secrets). We deliberately do NOT gate the
admin check on any client-supplied timestamp: a forged cookie can set any
timestamp it likes, so a timestamp-gated re-check protects nothing. With no
server-side session store available, the honest controls are (a) an
unforgeable signing key and (b) a short session max-age (see
SessionMiddleware config in main.py). No long-lived IdP credential is persisted
client-side.
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx
from authlib.integrations.starlette_client import OAuth
from fastapi import Depends, Request

from .config import settings

oauth = OAuth()

# Cache of rewritten OIDC discovery metadata. Populated once at startup (or
# lazily on first /login/start if startup init failed, e.g. IdP was briefly
# unreachable).
_metadata_cache: dict[str, Any] = {}
_client_registered = False


class NotAuthenticated(Exception):
    """Raised by require_user() when no session user is present."""


class NotAuthorized(Exception):
    """Raised when the session user lacks a capability's required role."""


class InvalidIdentity(Exception):
    """Raised when the OIDC response is not a fully validated user identity."""


class ReauthenticationRequired(Exception):
    """Raised when a sensitive admin mutation needs fresh OIDC authentication."""


def _rewrite_host(url: str, reference_url: str) -> str:
    """Rewrite the scheme+host of `url` to match `reference_url`; keep path/query/fragment."""
    if not url:
        return url
    ref = urlsplit(reference_url)
    parts = urlsplit(url)
    return urlunsplit((ref.scheme, ref.netloc, parts.path, parts.query, parts.fragment))


def _url_origin(url: str, label: str) -> tuple[str, str, int]:
    """Return a normalized HTTP(S) origin or reject an unsafe endpoint URL."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except (TypeError, ValueError) as exc:
        raise ValueError(f"OIDC {label} is not a valid URL") from exc

    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError(f"OIDC {label} must be an absolute HTTP(S) URL")
    if parts.username is not None or parts.password is not None:
        raise ValueError(f"OIDC {label} must not contain URL credentials")

    if port is None:
        port = 443 if parts.scheme == "https" else 80
    return parts.scheme, parts.hostname.lower(), port


def _validated_oidc_metadata(raw: Any) -> dict[str, Any]:
    """Validate discovery metadata before any endpoint is trusted.

    The portal fetches discovery from an optional docker-internal issuer.  A
    poisoned discovery document must not be able to turn the subsequent token
    exchange (which carries the client secret) or JWKS fetch into an SSRF.  For
    this Keycloak deployment, endpoints are therefore restricted to either the
    configured public issuer origin or the explicitly configured internal
    issuer origin.
    """
    if not isinstance(raw, dict):
        raise ValueError("OIDC discovery response must be a JSON object")

    expected_issuer = settings.oidc_issuer.rstrip("/")
    discovered_issuer = raw.get("issuer")
    if not isinstance(discovered_issuer, str) or discovered_issuer != expected_issuer:
        raise ValueError("OIDC discovery issuer does not exactly match OIDC_ISSUER")

    public_origin = _url_origin(expected_issuer, "issuer")
    if public_origin[0] != "https":
        raise ValueError("OIDC_ISSUER must use HTTPS")
    allowed_origins = {public_origin}
    if settings.oidc_internal_issuer:
        allowed_origins.add(
            _url_origin(settings.oidc_internal_issuer, "internal issuer")
        )

    required_endpoints = ("authorization_endpoint", "token_endpoint", "jwks_uri")
    optional_endpoints = ("userinfo_endpoint", "end_session_endpoint")
    metadata = dict(raw)
    for field in (*required_endpoints, *optional_endpoints):
        value = metadata.get(field)
        if value is None and field in required_endpoints:
            raise ValueError(f"OIDC discovery is missing {field}")
        if value is None:
            continue
        if not isinstance(value, str) or not value:
            raise ValueError(f"OIDC {field} must be a non-empty URL")
        if _url_origin(value, field) not in allowed_origins:
            raise ValueError(
                f"OIDC {field} points outside the configured issuer origins"
            )

    return metadata


async def fetch_oidc_metadata() -> dict[str, Any]:
    """Fetch (and cache) OIDC discovery metadata, with browser-facing endpoints
    rewritten to the public issuer host."""
    if _metadata_cache:
        return _metadata_cache

    fetch_issuer = settings.oidc_internal_issuer or settings.oidc_issuer
    discovery_url = fetch_issuer.rstrip("/") + "/.well-known/openid-configuration"

    # Discovery itself carries no credential, but keeping internal service
    # traffic off ambient HTTP(S)_PROXY avoids an accidental proxy becoming
    # part of the OIDC trust boundary. Redirects stay disabled so metadata is
    # accepted only from the configured discovery URL.
    async with httpx.AsyncClient(
        timeout=10, trust_env=False, follow_redirects=False
    ) as client:
        resp = await client.get(discovery_url)
        resp.raise_for_status()
        raw = resp.json()

    public_issuer = settings.oidc_issuer

    metadata = _validated_oidc_metadata(raw)

    # Keycloak is configured with its public hostname, so discovery fetched
    # over the Docker network still advertises public HTTPS endpoints. The
    # browser must use those, but the portal's token/JWKS/userinfo calls must
    # use the explicitly configured internal issuer: the container does not
    # depend on internal DNS hairpinning through Traefik or on trusting the
    # edge CA. Keep metadata["issuer"] public so Authlib validates the ID
    # token's `iss` claim against the real issuer.
    if settings.oidc_internal_issuer:
        for field in ("token_endpoint", "jwks_uri", "userinfo_endpoint"):
            if metadata.get(field):
                metadata[field] = _rewrite_host(
                    metadata[field], settings.oidc_internal_issuer
                )
    if raw.get("authorization_endpoint"):
        metadata["authorization_endpoint_public"] = _rewrite_host(
            raw["authorization_endpoint"], public_issuer
        )
    if raw.get("end_session_endpoint"):
        metadata["end_session_endpoint_public"] = _rewrite_host(
            raw["end_session_endpoint"], public_issuer
        )

    _metadata_cache.update(metadata)
    return _metadata_cache


async def init_oauth_client() -> None:
    """Register the Keycloak client with authlib using explicit endpoints
    (rather than server_metadata_url) so we can independently control which
    host each endpoint resolves against."""
    global _client_registered
    metadata = await fetch_oidc_metadata()
    oauth.register(
        name="keycloak",
        client_id=settings.oidc_client_id,
        client_secret=settings.oidc_client_secret,
        authorize_url=metadata.get("authorization_endpoint_public")
        or metadata.get("authorization_endpoint"),
        access_token_url=metadata["token_endpoint"],
        # Authlib only enforces the ID token's `iss` claim when `issuer` is in
        # server_metadata.  We register it explicitly because this app uses
        # manually split public/internal endpoints instead of metadata_url.
        issuer=metadata["issuer"],
        jwks_uri=metadata["jwks_uri"],
        userinfo_endpoint=metadata.get("userinfo_endpoint"),
        id_token_signing_alg_values_supported=metadata.get(
            "id_token_signing_alg_values_supported"
        ),
        # Authlib passes these through to its httpx.AsyncOAuth2Client. The
        # token exchange carries the OIDC client secret and must not inherit
        # an ambient HTTP(S)_PROXY or follow a credential-bearing redirect.
        client_kwargs={
            "scope": "openid profile email",
            "timeout": 10,
            "trust_env": False,
            "follow_redirects": False,
        },
    )
    _client_registered = True


async def ensure_oauth_client() -> None:
    """Idempotently make sure the Keycloak client is registered. Safe to call
    from every /login/start and /auth/callback in case startup init failed
    (e.g. IdP unreachable at container boot)."""
    if not _client_registered:
        await init_oauth_client()


def end_session_url() -> str | None:
    return _metadata_cache.get("end_session_endpoint_public") or _metadata_cache.get(
        "end_session_endpoint"
    )


def extract_roles(userinfo: dict[str, Any]) -> list[str]:
    """Union of the flat 'roles' claim and Keycloak's 'realm_access.roles'."""
    roles: set[str] = set()

    direct = userinfo.get("roles")
    if isinstance(direct, list):
        roles.update(str(r) for r in direct)

    realm_access = userinfo.get("realm_access")
    if isinstance(realm_access, dict):
        realm_roles = realm_access.get("roles")
        if isinstance(realm_roles, list):
            roles.update(str(r) for r in realm_roles)

    return sorted(roles)


def verified_userinfo(token: Any) -> dict[str, Any]:
    """Return claims only when Authlib parsed a signed OIDC ID token.

    `authorize_access_token` inserts `userinfo` after signature, audience,
    nonce, time, and (with the registered metadata above) issuer validation.
    Requiring both fields prevents silently degrading this OIDC login into a
    plain OAuth/userinfo flow if a provider returns no ID token.
    """
    if not isinstance(token, dict) or not token.get("id_token"):
        raise InvalidIdentity("OIDC token response did not contain an ID token")
    userinfo = token.get("userinfo")
    if not isinstance(userinfo, Mapping):
        raise InvalidIdentity("OIDC ID token was not validated into user claims")
    return dict(userinfo)


def validate_step_up_identity(userinfo: dict[str, Any], expected_subject: str) -> None:
    """Validate claims from an OIDC ``prompt=login,max_age=0`` response."""
    if userinfo.get("sub") != expected_subject:
        raise InvalidIdentity("step-up identity does not match the admin session")
    if not _has_role({"roles": extract_roles(userinfo)}, settings.admin_role):
        raise InvalidIdentity("step-up identity is no longer an administrator")
    auth_time = userinfo.get("auth_time")
    if not isinstance(auth_time, int) or isinstance(auth_time, bool):
        raise InvalidIdentity("step-up ID token has no valid auth_time")
    age = int(time.time()) - auth_time
    if age < -30 or age > settings.admin_step_up_seconds:
        raise InvalidIdentity("step-up authentication is not recent")


def require_user(request: Request) -> dict[str, Any]:
    user = request.session.get("user")
    if (
        not isinstance(user, dict)
        or not isinstance(user.get("sub"), str)
        or not user["sub"]
    ):
        raise NotAuthenticated()
    return user


def establish_session(
    request: Request, token: dict[str, Any], userinfo: dict[str, Any]
) -> None:
    """Populate the session after a successful OIDC login with the user's
    identity and roles.

    We deliberately do NOT persist the OIDC refresh_token (or any other
    long-lived bearer credential) in the session: the cookie is signed but not
    encrypted and is client-readable, so a refresh token stored there would be
    an exfiltratable long-lived credential. Roles are captured once here; the
    admin check trusts them on the strength of the session signing key plus a
    short cookie max-age (see config/main.py)."""
    subject = userinfo.get("sub")
    if not isinstance(subject, str) or not subject.strip() or len(subject) > 255:
        raise InvalidIdentity("OIDC subject is missing or invalid")

    def claim_text(*names: str) -> str:
        for name in names:
            value = userinfo.get(name)
            if isinstance(value, str) and value:
                return value
        return ""

    # Authlib's authorization state has already been consumed by the time this
    # function runs.  Clear every field from any previous portal identity before
    # installing the new one: otherwise account switching leaks the previous
    # any account-specific state to the new identity. Plaintext API keys are
    # never stored in this cookie-backed session.
    request.session.clear()
    request.session["user"] = {
        "email": claim_text("email", "preferred_username"),
        "name": claim_text("name", "preferred_username", "email") or subject,
        "sub": subject,
        "roles": extract_roles(userinfo),
    }


def _has_role(user: dict[str, Any] | None, *allowed: str) -> bool:
    if not user:
        return False
    roles = user.get("roles")
    if not isinstance(roles, list):
        return False
    return any(role in roles for role in allowed)


async def require_developer(
    user: dict[str, Any] = Depends(require_user),
) -> dict[str, Any]:
    """Require the developer role (administrators are explicitly included)."""
    if not _has_role(user, settings.developer_role, settings.admin_role):
        raise NotAuthorized()
    return user


async def require_admin(
    request: Request, user: dict[str, Any] = Depends(require_user)
) -> dict[str, Any]:
    # Authorization is decided purely from the session roles. Their
    # trustworthiness comes from the session signing key (enforced strong and
    # high-entropy in config.py) and a short cookie max-age, NOT from any
    # client-supplied value — a forged cookie could set any timestamp, so a
    # timestamp-gated re-check would guard nothing. Fails closed: no admin role
    # -> NotAuthorized.
    if not _has_role(user, settings.admin_role):
        raise NotAuthorized()
    return user


def mark_recent_admin_reauthentication(request: Request) -> None:
    """Mark a successfully validated, prompt=login OIDC round trip.

    The marker is integrity-protected by the session signature and contains no
    credential. A signing-key compromise already permits forging the role
    claim itself, so this is intentionally an account/session-theft mitigation,
    not a replacement for the strong SESSION_SECRET requirement.
    """
    request.session["admin_reauth_at"] = int(time.time())


def has_recent_admin_reauthentication(request: Request) -> bool:
    timestamp = request.session.get("admin_reauth_at")
    if not isinstance(timestamp, int) or isinstance(timestamp, bool):
        return False
    age = int(time.time()) - timestamp
    return -30 <= age <= settings.admin_step_up_seconds


async def require_recent_admin(
    request: Request,
    user: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    if not has_recent_admin_reauthentication(request):
        raise ReauthenticationRequired()
    return user


def is_admin_user(user: dict[str, Any] | None) -> bool:
    return _has_role(user, settings.admin_role)


# --- CSRF (simple session-token pattern) ---


def get_csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return token


def verify_csrf(request: Request, submitted: str | None) -> bool:
    expected = request.session.get("csrf_token")
    if not expected or not submitted:
        return False
    return secrets.compare_digest(expected, submitted)


# --- Flash messages (session-backed, no secrets ever flashed) ---


def flash(request: Request, message: str, category: str = "info") -> None:
    flashes = request.session.get("flash", [])
    flashes.append({"message": message, "category": category})
    request.session["flash"] = flashes


def pop_flash(request: Request) -> list[dict[str, str]]:
    return request.session.pop("flash", [])
