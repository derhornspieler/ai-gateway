"""Runtime configuration for dev-portal, sourced from environment variables.

See docs/solution-map.md §1.4 for the design this implements: OIDC-gated
self-service LiteLLM virtual-key issuance plus tool-config snippet rendering,
with an admin-only rotation-control page talking to the key-rotator service.
"""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import Field, PrivateAttr, model_validator
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


# Kept textually identical to litellm_client.PROJECT_ID_RE (config cannot
# import litellm_client without a cycle). A managed Keycloak project ID is the
# only accepted key of the per-project limit-override map.
_PROJECT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
# LiteLLM key-lifetime grammar (e.g. 30d, 12h, 45m, 90s), deliberately bounded.
_KEY_DURATION_RE = re.compile(r"^[1-9][0-9]{0,5}(s|m|h|d)$")
_KEY_LIMIT_KNOBS = ("max_budget", "tpm_limit", "rpm_limit", "duration")
_MAX_PROJECT_LIMIT_ENTRIES = 256


def _parse_key_limit_value(knob: str, raw: Any) -> float | int | str | None:
    """Normalize one reviewed key-issuance guardrail knob or raise ValueError.

    ``None`` (JSON null) and the literal string ``"none"`` disable the knob.
    Every accepted value is strictly typed and bounded so a config typo can
    never silently mint an uncapped or absurdly capped static bearer key.
    """
    if raw is None or (isinstance(raw, str) and raw.strip().lower() == "none"):
        return None
    if knob == "max_budget":
        if isinstance(raw, bool):
            raise ValueError("max_budget must be a number")
        if isinstance(raw, (int, float)):
            value = float(raw)
        elif isinstance(raw, str):
            value = float(raw.strip())
        else:
            raise ValueError("max_budget must be a number")
        if not (0 < value <= 1_000_000):
            raise ValueError("max_budget is out of bounds")
        return value
    if knob in ("tpm_limit", "rpm_limit"):
        if isinstance(raw, bool):
            raise ValueError(f"{knob} must be an integer")
        if isinstance(raw, int):
            value_int = raw
        elif isinstance(raw, str):
            value_int = int(raw.strip(), 10)
        else:
            raise ValueError(f"{knob} must be an integer")
        if not (0 < value_int <= 1_000_000_000):
            raise ValueError(f"{knob} is out of bounds")
        return value_int
    if knob == "duration":
        if not isinstance(raw, str) or _KEY_DURATION_RE.fullmatch(raw.strip()) is None:
            raise ValueError("duration must match the bounded LiteLLM grammar")
        return raw.strip()
    raise ValueError(f"unknown key limit knob: {knob}")


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

    # --- Key-issuance guardrails (reviewed config, never runtime-editable) ---
    # Every self-service key is minted with these caps. The deployed values
    # come from ansible/group_vars (rendered into .env by the converge); these
    # in-code defaults match that reviewed baseline so a missing variable can
    # never mint an uncapped key. The literal string "none" disables one knob.
    portal_key_default_max_budget: str = "25"
    portal_key_default_tpm_limit: str = "100000"
    portal_key_default_rpm_limit: str = "60"
    portal_key_default_duration: str = "30d"
    # Optional per-project overrides: a one-line JSON object keyed by managed
    # project ID; each entry may set max_budget/tpm_limit/rpm_limit/duration,
    # and null lifts the global default for that project.
    portal_key_project_limits: str = "{}"

    _key_limit_defaults: dict[str, float | int | str] = PrivateAttr(
        default_factory=dict
    )
    _key_project_limit_overrides: dict[str, dict[str, float | int | str | None]] = (
        PrivateAttr(default_factory=dict)
    )

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

    @model_validator(mode="after")
    def _parse_key_issuance_guardrails(self) -> "Settings":
        """Fail closed at startup on malformed key-issuance guardrails.

        A typo here changes what static bearer credentials this portal mints,
        so ambiguity is a startup error, never a silently dropped cap.
        """
        problems: list[str] = []
        defaults: dict[str, float | int | str] = {}
        for knob, raw in (
            ("max_budget", self.portal_key_default_max_budget),
            ("tpm_limit", self.portal_key_default_tpm_limit),
            ("rpm_limit", self.portal_key_default_rpm_limit),
            ("duration", self.portal_key_default_duration),
        ):
            try:
                value = _parse_key_limit_value(knob, raw)
            except ValueError:
                problems.append(f"PORTAL_KEY_DEFAULT_{knob.upper()} is invalid")
                continue
            if value is not None:
                defaults[knob] = value

        overrides: dict[str, dict[str, float | int | str | None]] = {}
        try:
            parsed = json.loads(self.portal_key_project_limits)
        except (TypeError, ValueError):
            parsed = None
        if not isinstance(parsed, dict) or len(parsed) > _MAX_PROJECT_LIMIT_ENTRIES:
            problems.append("PORTAL_KEY_PROJECT_LIMITS is not a bounded JSON object")
        else:
            for project_id, entry in parsed.items():
                if (
                    not isinstance(project_id, str)
                    or _PROJECT_ID_RE.fullmatch(project_id) is None
                    or not isinstance(entry, dict)
                    or not set(entry) <= set(_KEY_LIMIT_KNOBS)
                ):
                    problems.append(
                        "PORTAL_KEY_PROJECT_LIMITS has an invalid project entry"
                    )
                    continue
                normalized: dict[str, float | int | str | None] = {}
                for knob, raw in entry.items():
                    try:
                        normalized[knob] = _parse_key_limit_value(knob, raw)
                    except ValueError:
                        problems.append(
                            f"PORTAL_KEY_PROJECT_LIMITS has an invalid {knob}"
                        )
                overrides[project_id] = normalized

        if problems:
            raise ValueError(
                "refusing to start with invalid key-issuance guardrails: "
                + "; ".join(sorted(set(problems)))
            )
        self._key_limit_defaults = defaults
        self._key_project_limit_overrides = overrides
        return self

    def key_limits_for_project(self, project_id: str) -> dict[str, float | int | str]:
        """Resolve the reviewed issuance caps for one managed project.

        Per-project overrides win over the global defaults; an explicit null
        override removes that single knob for the project. The browser never
        influences this decision.
        """
        merged = dict(self._key_limit_defaults)
        for knob, value in self._key_project_limit_overrides.get(
            project_id, {}
        ).items():
            if value is None:
                merged.pop(knob, None)
            else:
                merged[knob] = value
        return merged

settings = Settings()  # type: ignore[call-arg]
