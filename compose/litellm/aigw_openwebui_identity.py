"""Shared fail-closed identity checks for the Open WebUI service key."""

from __future__ import annotations

import os
import re
import time

import jwt


OPENWEBUI_FORWARD_JWT_SECRET_ENV = "OPENWEBUI_FORWARD_JWT_SECRET"
OPENWEBUI_FORWARD_JWT_HEADER = "X-OpenWebUI-User-Jwt"
OPENWEBUI_IDENTITY_GATE_FIELD = "aigw_openwebui_identity_gate_v1"
OPENWEBUI_KEY_OWNER = "svc-open-webui"
OPENWEBUI_KEY_ALIAS = "aigw-open-webui-service"
OPENWEBUI_KEY_METADATA = {
    "aigw_key_kind": "service",
    "aigw_service": "open-webui",
    "aigw_project_id": "open-webui",
}
TOKEN_PATTERN = re.compile(r"[0-9a-f]{64}")
PORTAL_USERNAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}")
KEY_OWNER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}")
JWT_TOKEN_PATTERN = re.compile(
    r"[A-Za-z0-9_-]{1,1024}\.[A-Za-z0-9_-]{1,3072}\.[A-Za-z0-9_-]{1,1024}"
)
JWT_SUBJECT_PATTERN = KEY_OWNER_PATTERN
JWT_ROLE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}")
JWT_MAX_LIFETIME_SECONDS = 300
JWT_CLOCK_SKEW_SECONDS = 30


def read_openwebui_forward_jwt_secret() -> str:
    """Read the domain-separated signing key without logging it."""

    secret = os.environ.get(OPENWEBUI_FORWARD_JWT_SECRET_ENV)
    if not isinstance(secret, str) or TOKEN_PATTERN.fullmatch(secret) is None:
        raise RuntimeError(
            "OPENWEBUI_FORWARD_JWT_SECRET must be 64 lowercase hex characters"
        )
    return secret


def openwebui_jwt_from_headers(headers) -> str | None:
    """Return exactly one bounded JWT header, or fail unresolved."""

    if not isinstance(headers, dict):
        return None
    matches: list[str] = []
    for name, value in headers.items():
        if (
            isinstance(name, str)
            and name.lower() == OPENWEBUI_FORWARD_JWT_HEADER.lower()
        ):
            if not isinstance(value, str):
                return None
            matches.append(value)
    if len(matches) != 1:
        return None
    token = matches[0]
    if len(token) > 4096 or JWT_TOKEN_PATTERN.fullmatch(token) is None:
        return None
    return token


def verified_openwebui_identity(
    token: str, secret: str, *, now: int | None = None
) -> tuple[str, str] | None:
    """Verify one assertion and return its stable subject and username."""

    try:
        claims = jwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            issuer="open-webui",
            leeway=JWT_CLOCK_SKEW_SECONDS,
            options={
                "require": ["sub", "email", "name", "role", "iss", "iat", "exp"]
            },
        )
    except (jwt.InvalidTokenError, TypeError, ValueError):
        return None
    if not isinstance(claims, dict):
        return None

    subject = claims.get("sub")
    username = claims.get("email")
    name = claims.get("name")
    role = claims.get("role")
    issued_at = claims.get("iat")
    expires_at = claims.get("exp")
    if (
        not isinstance(subject, str)
        or JWT_SUBJECT_PATTERN.fullmatch(subject) is None
        or not isinstance(username, str)
        or PORTAL_USERNAME_PATTERN.fullmatch(username) is None
        or not isinstance(name, str)
        or not 1 <= len(name) <= 128
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
        or not isinstance(role, str)
        or JWT_ROLE_PATTERN.fullmatch(role) is None
        or isinstance(issued_at, bool)
        or not isinstance(issued_at, int)
        or isinstance(expires_at, bool)
        or not isinstance(expires_at, int)
    ):
        return None

    current_time = int(time.time()) if now is None else now
    if (
        expires_at <= issued_at
        or expires_at - issued_at > JWT_MAX_LIFETIME_SECONDS
        or issued_at > current_time + JWT_CLOCK_SKEW_SECONDS
        or expires_at <= current_time - JWT_CLOCK_SKEW_SECONDS
    ):
        return None
    return subject, username


def verified_openwebui_username(
    token: str, secret: str, *, now: int | None = None
) -> str | None:
    """Compatibility wrapper returning only the verified directory username."""

    identity = verified_openwebui_identity(token, secret, now=now)
    return identity[1] if identity is not None else None
