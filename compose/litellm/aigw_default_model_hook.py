"""Per-project model selection and output-limit enforcement for LiteLLM.

The admin portal stores each managed project's issuance policy in Keycloak
group attributes; key mint and the retroactive policy re-tune stamp the
project's ``default_model`` into every portal key's metadata as
``aigw_default_model``. LiteLLM's pinned proxy has no native per-key default for a
request that omits ``model`` (``default_key_generate_params`` only shapes
key creation and the CLI ``--model`` default is proxy-global), so this
reviewed pre-call hook is the server-side enforcement point: a request
through a portal key that does not choose a model (absent, empty, or the
explicit ``aigw-default`` sentinel) is resolved to the project's default
before routing. A request that names an ordinary model is left untouched;
LiteLLM's native key-model allowlist keeps governing it.

Fail-closed contract: a present-but-malformed default, unreadable key
metadata on an unresolved request, or a default outside the key's model
allowlist DENIES the request (HTTP 400) — it never falls through to a
looser route. Keys without the metadata (operator keys, service keys) are
treated exactly as LiteLLM would treat them natively.

``aigw-auto`` is reserved for a future reviewed automatic-routing policy.
It is denied for every key scope until that policy exists. A project default
set to the reserved name is invalid and denies every request made with that
key, including requests that explicitly name another model.

Caveat — the ``aigw-default`` sentinel is best-effort, not a uniform
guarantee: LiteLLM's own auth layer checks a request's ``model`` against
the key's model allowlist *before* this pre-call hook ever runs. For a
model-restricted key, an explicit ``"aigw-default"`` string is simply not
a member of that allowlist, so LiteLLM rejects it itself and this hook's
sentinel branch never executes. Only a request with an omitted or empty
``model`` reaches the hook regardless of a key's allowlist, so the
sentinel string only ever resolves for keys with no model restriction (no
``models`` list, or the ``all-proxy-models`` wildcard). Callers that need
the project default honored unconditionally should OMIT ``model`` from
the request rather than send the sentinel — that path is enforced here
for every key, restricted or not, and fails closed the same way.

This file is bind-mounted read-only next to ``/app/config.yaml`` and
registered via ``litellm_settings.callbacks``; its content is covered by
the litellm bind-source digest, so changing it requires an Ansible
re-converge — a manual ``compose up`` fails closed.

Per-model output limits use a canonical policy copied from Keycloak into each
portal key. Before provider dispatch, this hook applies the request cap and
atomically reserves the requested maximum against one Redis UTC-minute bucket.
Redis errors fail closed. A Redis restart during the current minute also fails
closed until the next minute, so an empty cache cannot look like unused quota.
Reservations are deliberately conservative: this pinned LiteLLM release does
not provide one callback contract that can safely correlate every retry,
stream, disconnect, and failure with this pre-dispatch reservation. Unused
tokens therefore remain reserved until the fixed minute ends.
"""

from __future__ import annotations

import hmac
import re
from typing import Any

from fastapi import HTTPException
from litellm.integrations.custom_logger import CustomLogger

from aigw_model_limits import (
    ALL_PROXY_MODELS,
    MODEL_NAME_RE,
    RedisOutputReservations,
    enforce_model_limits,
)
from aigw_openwebui_identity import (
    OPENWEBUI_IDENTITY_GATE_FIELD,
    OPENWEBUI_KEY_ALIAS,
    OPENWEBUI_KEY_METADATA,
    OPENWEBUI_KEY_OWNER,
    openwebui_jwt_from_headers,
    read_openwebui_forward_jwt_secret,
    verified_openwebui_username,
)

DEFAULT_MODEL_METADATA_KEY = "aigw_default_model"
DEFAULT_MODEL_SENTINEL = "aigw-default"
RESERVED_AUTO_ROUTER_MODEL = "aigw-auto"
PROJECT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")


def _enforce_portal_model_scope(user_api_key_dict: Any) -> None:
    """Refuse portal wildcard keys before a hidden/future model can match."""

    metadata = getattr(user_api_key_dict, "metadata", None)
    if not isinstance(metadata, dict) or metadata.get("created_via") != "dev-portal":
        return
    project = metadata.get("aigw_project_id")
    key_models = getattr(user_api_key_dict, "models", None)
    if (
        not isinstance(project, str)
        or PROJECT_ID_RE.fullmatch(project) is None
        or not isinstance(key_models, (list, tuple, set))
        or not key_models
        or ALL_PROXY_MODELS in key_models
        or any(
            not isinstance(model, str) or MODEL_NAME_RE.fullmatch(model) is None
            for model in key_models
        )
    ):
        raise _deny("portal keys require an explicit current model allowlist")


def _deny(detail: str, status_code: int = 400) -> HTTPException:
    """Build the request rejection LiteLLM's call-hook contract expects."""

    return HTTPException(status_code=status_code, detail={"error": detail})


def _has_openwebui_service_marker(user_api_key_dict: Any) -> bool:
    """Find any marker that reserves a key for Open WebUI."""

    metadata = getattr(user_api_key_dict, "metadata", None)
    return (
        getattr(user_api_key_dict, "user_id", None) == OPENWEBUI_KEY_OWNER
        or getattr(user_api_key_dict, "key_alias", None) == OPENWEBUI_KEY_ALIAS
        or (
            isinstance(metadata, dict)
            and (
                metadata.get("aigw_service") == "open-webui"
                or metadata.get("aigw_project_id") == "open-webui"
            )
        )
    )


def _is_exact_openwebui_service_key(user_api_key_dict: Any) -> bool:
    """Match the complete reconciled Open WebUI service-key tuple."""

    return (
        getattr(user_api_key_dict, "user_id", None) == OPENWEBUI_KEY_OWNER
        and getattr(user_api_key_dict, "key_alias", None) == OPENWEBUI_KEY_ALIAS
        and getattr(user_api_key_dict, "metadata", None) == OPENWEBUI_KEY_METADATA
    )


def _enforce_openwebui_identity(user_api_key_dict: Any, data: Any, secret: str) -> None:
    """Deny an unauditable Open WebUI inference before model dispatch."""

    proxy_request = data.get("proxy_server_request") if isinstance(data, dict) else None
    if isinstance(proxy_request, dict):
        # This object is shared with LiteLLM's pre-created failure logger.
        # Clear caller/stale state first, then mark only a request that passes
        # both normalized and raw-header checks below.
        proxy_request.pop(OPENWEBUI_IDENTITY_GATE_FIELD, None)
    if not _has_openwebui_service_marker(user_api_key_dict):
        return
    if not _is_exact_openwebui_service_key(user_api_key_dict):
        raise _deny("Open WebUI service key markers do not match")
    headers = proxy_request.get("headers") if isinstance(proxy_request, dict) else None
    token = openwebui_jwt_from_headers(headers)
    secret_fields = data.get("secret_fields") if isinstance(data, dict) else None
    raw_headers = (
        secret_fields.get("raw_headers") if isinstance(secret_fields, dict) else None
    )
    raw_token = openwebui_jwt_from_headers(raw_headers)
    if (
        token is None
        or raw_token is None
        or not hmac.compare_digest(token, raw_token)
        or verified_openwebui_username(token, secret) is None
    ):
        raise _deny("Open WebUI requires one valid signed user assertion")
    proxy_request[OPENWEBUI_IDENTITY_GATE_FIELD] = True


def resolve_request_model(requested: Any, metadata: Any, key_models: Any) -> str | None:
    """Decide the effective model for one request, or deny the request.

    Returns the substituted model name, or ``None`` when the request must be
    forwarded untouched. Raises ``HTTPException`` for every malformed-policy
    or unsatisfiable-default condition — never silently loosens.
    """

    if requested is not None and not isinstance(requested, str):
        raise _deny("model must be a string")
    normalized = requested.strip() if isinstance(requested, str) else None
    unresolved = normalized in (None, "", DEFAULT_MODEL_SENTINEL)

    metadata_readable = isinstance(metadata, dict)
    default_present = metadata_readable and DEFAULT_MODEL_METADATA_KEY in metadata
    default = metadata.get(DEFAULT_MODEL_METADATA_KEY) if default_present else None

    if default_present and (
        not isinstance(default, str) or MODEL_NAME_RE.fullmatch(default) is None
    ):
        # Proven policy corruption on this key. Deny every request instead of
        # serving any of them beside an unenforceable default.
        raise _deny("this key's project default-model policy is malformed")

    if default == RESERVED_AUTO_ROUTER_MODEL:
        # Automatic routing has no reviewed policy yet. Treat a project that
        # selects the reserved name as corrupt and deny every request made by
        # its key, even when the caller explicitly names another model.
        raise _deny("this key's automatic-routing policy is not enabled")

    if normalized == RESERVED_AUTO_ROUTER_MODEL:
        raise _deny("automatic model routing is not enabled")

    if not unresolved:
        # An explicit model choice stays untouched; LiteLLM's native
        # key-model allowlist enforcement governs it.
        return None

    if not metadata_readable:
        raise _deny(
            "key policy metadata is unreadable; a default model cannot be resolved"
        )
    if not default_present:
        if normalized == DEFAULT_MODEL_SENTINEL:
            raise _deny("this key's project has no default model configured")
        # No default policy and no model: leave the request for LiteLLM's
        # native missing-model rejection.
        return None

    if isinstance(key_models, (list, tuple, set)):
        models = {name for name in key_models if isinstance(name, str)}
        if models and ALL_PROXY_MODELS not in models and default not in models:
            # Defense in depth against key-state skew: the policy layer
            # guarantees default ∈ allowed_models, so a divergence here is a
            # broken re-tune — deny rather than widen the allowlist.
            raise _deny(
                "this key's project default model is outside its allowed models"
            )
    return default


class AIGWDefaultModelEnforcer(CustomLogger):
    """Fail-closed identity gate plus project default-model enforcement."""

    def __init__(self, limiter: RedisOutputReservations | None = None) -> None:
        self._openwebui_forward_jwt_secret = read_openwebui_forward_jwt_secret()
        self._limiter = limiter or RedisOutputReservations()

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        _enforce_openwebui_identity(
            user_api_key_dict, data, self._openwebui_forward_jwt_secret
        )
        if not isinstance(data, dict):
            return data
        resolved = resolve_request_model(
            data.get("model"),
            getattr(user_api_key_dict, "metadata", None),
            getattr(user_api_key_dict, "models", None),
        )
        if resolved is not None:
            data["model"] = resolved
        await enforce_model_limits(self._limiter, user_api_key_dict, data, call_type)
        _enforce_portal_model_scope(user_api_key_dict)
        return data


aigw_default_model_enforcer = AIGWDefaultModelEnforcer()
