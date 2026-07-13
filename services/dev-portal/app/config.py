"""Runtime configuration for dev-portal, sourced from environment variables.

See docs/solution-map.md §1.4 for the design this implements: OIDC-gated
self-service LiteLLM virtual-key issuance plus tool-config snippet rendering,
with an admin-only rotation-control page talking to the key-rotator service.
"""

from __future__ import annotations

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Values we refuse to run with: unset secrets and well-known placeholders.
_INSECURE_PLACEHOLDERS = {
    "change-me",
    "change-me-in-production",
    "changeme",
    "placeholder",
    "secret",
    "password",
}

def _is_placeholder(value: str) -> bool:
    v = value.strip().lower()
    return not v or v in _INSECURE_PLACEHOLDERS or "change-me" in v or "changeme" in v


def _is_low_entropy(value: str) -> bool:
    """Reject secrets whose *shape* betrays low entropy even if they are long.

    A 40-character string of a single repeated char, or one drawn from a tiny
    alphabet, is trivially guessable/brute-forceable and must not be trusted to
    sign role-bearing session cookies. We require a reasonable spread of
    distinct characters and more than one character class.
    """
    v = value.strip()
    if len(set(v)) < 10:
        return True
    classes = sum(
        (
            any(c.islower() for c in v),
            any(c.isupper() for c in v),
            any(c.isdigit() for c in v),
            any(not c.isalnum() for c in v),
        )
    )
    return classes < 2


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- OIDC (Keycloak) ---
    # Public issuer: what the *browser* is redirected to for the authorize step.
    oidc_issuer: str = "https://auth.aigw.example.internal/realms/aigw"
    oidc_client_id: str = "dev-portal"
    oidc_client_secret: str = ""
    # Optional docker-internal override used for *server-side* metadata/token/
    # userinfo calls when the public issuer host isn't resolvable inside the
    # container network (e.g. http://keycloak:8080/realms/aigw).
    oidc_internal_issuer: str | None = None

    # --- Session / CSRF ---
    # No default on purpose: the session cookie is signed (not encrypted) and
    # carries roles, so a guessable signing key lets anyone forge an admin
    # session. Startup fails closed if this is unset/placeholder/too short.
    session_secret: str = ""

    # --- LiteLLM ---
    litellm_url: str = "http://litellm:4000"
    litellm_master_key: str = ""

    # --- key-rotator ---
    rotator_url: str = "http://key-rotator:8080"
    rotator_internal_token: str | None = None

    # --- Portal behavior ---
    # Base URL end users should point their coding tools at (the gateway,
    # not this portal).
    public_api_base: str = "https://api.aigw.example.internal"
    # Project authorization is never configured locally. Every request asks
    # the identity controller for the subject's live direct memberships below
    # /aigw-managed; each lowercase group name is the canonical project ID.
    # Only these Keycloak realm roles may use the corresponding portal
    # capabilities. Administrators are explicitly allowed to use developer
    # features as well; a merely authenticated realm account is not.
    developer_role: str = "aigw-developers"
    admin_role: str = "aigw-admins"

    # How long a signed session cookie is honored. Kept deliberately short: the
    # cookie carries roles and is signed (not encrypted), so bounding its
    # lifetime bounds the blast radius of any stale/forged cookie. 8h.
    session_max_age_seconds: int = Field(default=8 * 60 * 60, ge=300, le=24 * 60 * 60)

    # Destructive identity changes require a fresh OIDC prompt in addition to
    # the normal signed admin session. The resulting marker contains no token
    # or credential and is honored only for this short window.
    admin_step_up_seconds: int = Field(default=5 * 60, ge=60, le=15 * 60)

    @model_validator(mode="after")
    def _require_real_secrets(self) -> "Settings":
        """Fail closed at startup rather than run with forgeable/insecure secrets.

        The session_secret is the *primary* control against session-cookie
        forgery (the cookie is signed, not encrypted, and carries roles), so we
        require it to be present, non-placeholder, long, AND not low-entropy.
        The two bearer credentials below must also be long and non-trivial.
        """
        problems: list[str] = []
        if _is_placeholder(self.session_secret):
            problems.append("SESSION_SECRET is unset or a known placeholder")
        elif len(self.session_secret) < 32:
            problems.append("SESSION_SECRET must be at least 32 characters")
        elif _is_low_entropy(self.session_secret):
            problems.append(
                "SESSION_SECRET is too low-entropy (needs >=10 distinct chars "
                "and >=2 character classes)"
            )
        if _is_placeholder(self.litellm_master_key):
            problems.append("LITELLM_MASTER_KEY is unset or a known placeholder")
        elif len(self.litellm_master_key) < 32:
            problems.append("LITELLM_MASTER_KEY must be at least 32 characters")
        elif _is_low_entropy(self.litellm_master_key):
            problems.append("LITELLM_MASTER_KEY is too low-entropy")
        if _is_placeholder(self.oidc_client_secret):
            problems.append("OIDC_CLIENT_SECRET is unset or a known placeholder")
        elif len(self.oidc_client_secret) < 32:
            problems.append("OIDC_CLIENT_SECRET must be at least 32 characters")
        elif _is_low_entropy(self.oidc_client_secret):
            problems.append("OIDC_CLIENT_SECRET is too low-entropy")
        if not self.developer_role.strip():
            problems.append("DEVELOPER_ROLE must not be empty")
        if not self.admin_role.strip():
            problems.append("ADMIN_ROLE must not be empty")
        if problems:
            raise ValueError(
                "refusing to start with insecure configuration: " + "; ".join(problems)
            )
        return self

settings = Settings()  # type: ignore[call-arg]
