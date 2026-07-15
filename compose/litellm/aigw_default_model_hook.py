"""Per-project default-model enforcement for the LiteLLM proxy.

The admin portal stores each managed project's issuance policy in Keycloak
group attributes; key mint and the retroactive policy re-tune stamp the
project's ``default_model`` into every portal key's metadata as
``aigw_default_model``. LiteLLM v1.91.3 has no native per-key default for a
request that omits ``model`` (``default_key_generate_params`` only shapes
key creation and the CLI ``--model`` default is proxy-global), so this
reviewed pre-call hook is the server-side enforcement point: a request
through a portal key that does not choose a model (absent, empty, or the
explicit ``aigw-default`` sentinel) is resolved to the project's default
before routing. A request that names a model is left untouched; LiteLLM's
native key-model allowlist keeps governing it.

Fail-closed contract: a present-but-malformed default, unreadable key
metadata on an unresolved request, or a default outside the key's model
allowlist DENIES the request (HTTP 400) — it never falls through to a
looser route. Keys without the metadata (operator keys, service keys) are
treated exactly as LiteLLM would treat them natively.

This file is bind-mounted read-only next to ``/app/config.yaml`` and
registered via ``litellm_settings.callbacks``; its content is covered by
the litellm bind-source digest, so changing it requires an Ansible
re-converge — a manual ``compose up`` fails closed.
"""

from __future__ import annotations

import re
from typing import Any

from fastapi import HTTPException
from litellm.integrations.custom_logger import CustomLogger

# Kept textually identical to MODEL_NAME_RE in the identity controller and
# the dev-portal LiteLLM client: model names travel from Keycloak group
# policy through portal key metadata into this hook.
MODEL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./:-]{0,127}$")
DEFAULT_MODEL_METADATA_KEY = "aigw_default_model"
DEFAULT_MODEL_SENTINEL = "aigw-default"
# LiteLLM's key-level "every proxy model" wildcard: a key carrying it has no
# model restriction, so default-membership enforcement cannot narrow it.
ALL_PROXY_MODELS = "all-proxy-models"


def _deny(detail: str) -> HTTPException:
    """Build the request rejection LiteLLM's call-hook contract expects."""

    return HTTPException(status_code=400, detail={"error": detail})


def resolve_request_model(
    requested: Any, metadata: Any, key_models: Any
) -> str | None:
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
    default_present = (
        metadata_readable and DEFAULT_MODEL_METADATA_KEY in metadata
    )
    default = metadata.get(DEFAULT_MODEL_METADATA_KEY) if default_present else None

    if default_present and (
        not isinstance(default, str) or MODEL_NAME_RE.fullmatch(default) is None
    ):
        # Proven policy corruption on this key. Deny every request instead of
        # serving any of them beside an unenforceable default.
        raise _deny("this key's project default-model policy is malformed")

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
    """Pre-call hook substituting the project's default model server-side."""

    async def async_pre_call_hook(
        self, user_api_key_dict, cache, data, call_type
    ):
        if not isinstance(data, dict):
            return data
        resolved = resolve_request_model(
            data.get("model"),
            getattr(user_api_key_dict, "metadata", None),
            getattr(user_api_key_dict, "models", None),
        )
        if resolved is not None:
            data["model"] = resolved
        return data


aigw_default_model_enforcer = AIGWDefaultModelEnforcer()
