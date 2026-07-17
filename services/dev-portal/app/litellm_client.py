"""Async HTTP client helpers for the LiteLLM proxy's virtual-key API.

All calls are server-side (master key), 10s timeout, and never log the master
key or any generated virtual key value.
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from .config import settings


class LiteLLMError(Exception):
    """Raised on any non-2xx response or transport failure talking to LiteLLM."""


KEY_LIST_PAGE_SIZE = 100
KEY_LIST_MAX_PAGES = 10
# The admin key inventory is a page-at-a-time browse of EVERY owner's keys; it
# never merges pages into an authorization decision, so it may page far beyond
# the owner-scoped safety cap while still requiring native counters per page.
ADMIN_KEY_LIST_PAGE_SIZE = 50
ADMIN_KEY_LIST_MAX_PAGE = 10_000
PORTAL_KEY_CREATOR_FIELD = "created_via"
PORTAL_KEY_CREATOR_VALUE = "dev-portal"
PORTAL_PROJECT_METADATA_KEY = "aigw_project_id"
# Carries the project's admin-set default model on every portal key; the
# LiteLLM pre-call hook (compose/litellm/aigw_default_model_hook.py) reads it
# to resolve requests that omit a model. Kept textually identical there.
PORTAL_DEFAULT_MODEL_METADATA_KEY = "aigw_default_model"
MAX_KEY_METADATA_FIELDS = 32
MAX_KEY_METADATA_STRING_LENGTH = 512
MAX_KEY_METADATA_LIST_ITEMS = 32
PROJECT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
# LiteLLM key-lifetime grammar (e.g. 30d, 12h). Kept textually identical to
# config._KEY_DURATION_RE (config cannot import this module without a cycle).
KEY_DURATION_RE = re.compile(r"^[1-9][0-9]{0,5}(s|m|h|d)$")
# Kept textually identical to the identity controller's MODEL_NAME_RE: model
# names travel from Keycloak group policy through this client into LiteLLM.
MODEL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./:-]{0,127}$")
# Reserved model name for the explicit "no model access" group policy. It is a
# valid model name (rides through every 1-element-list validator unchanged) but
# is never a real served model, so a key scoped to it can call nothing — LiteLLM
# denies every real model. This is the deny-all-tooling state, distinct from an
# unset policy (all models). Chat access stays governed by the aigw-chat role.
NO_MODELS_SENTINEL = "aigw-no-models"
MAX_POLICY_MODELS = 32
RATE_LIMIT_MAX = 1_000_000_000
# The only /key/update fields this portal may ever send. Everything else on
# that endpoint (owner, team, aliases, rotation) is reserved for the operator
# path; widening this set is a reviewed security decision.
# `models` joined the set with the runtime per-project policy so an admin
# policy change can re-tune the model set on existing keys. `metadata` joined
# it with default-model enforcement so the same re-tune can re-stamp the
# project's default; it is guarded by _validated_retune_metadata, which only
# admits a provenance-preserving portal payload.
KEY_UPDATE_MUTABLE_FIELDS = frozenset(
    {"blocked", "max_budget", "tpm_limit", "rpm_limit", "duration", "models",
     "metadata"}
)


def _validated_retune_metadata(metadata: Any, updates: dict[str, Any]) -> None:
    """Admit only a provenance-preserving portal metadata replacement.

    LiteLLM's /key/update REPLACES the whole metadata object, and that object
    carries the portal's immutable provenance (created_via + aigw_project_id)
    that every later authorization decision reads. This gate refuses any
    payload that could strip provenance, exceed reviewed bounds, or stamp a
    default model that the same update's model allowlist does not contain.
    """

    if (
        not isinstance(metadata, dict)
        or len(metadata) > MAX_KEY_METADATA_FIELDS
        or metadata.get(PORTAL_KEY_CREATOR_FIELD) != PORTAL_KEY_CREATOR_VALUE
    ):
        raise LiteLLMError("key metadata update is invalid")
    project_id = metadata.get(PORTAL_PROJECT_METADATA_KEY)
    if not isinstance(project_id, str) or PROJECT_ID_RE.fullmatch(project_id) is None:
        raise LiteLLMError("key metadata update is invalid")
    for name, value in metadata.items():
        if not isinstance(name, str) or not 1 <= len(name) <= 128:
            raise LiteLLMError("key metadata update is invalid")
        if isinstance(value, str):
            if len(value) > MAX_KEY_METADATA_STRING_LENGTH:
                raise LiteLLMError("key metadata update is invalid")
        elif isinstance(value, list):
            if len(value) > MAX_KEY_METADATA_LIST_ITEMS or any(
                not isinstance(item, str)
                or len(item) > MAX_KEY_METADATA_STRING_LENGTH
                for item in value
            ):
                raise LiteLLMError("key metadata update is invalid")
        elif value is not None and not isinstance(value, (bool, int, float)):
            raise LiteLLMError("key metadata update is invalid")
    if PORTAL_DEFAULT_MODEL_METADATA_KEY in metadata:
        default_model = metadata[PORTAL_DEFAULT_MODEL_METADATA_KEY]
        if (
            not isinstance(default_model, str)
            or MODEL_NAME_RE.fullmatch(default_model) is None
        ):
            raise LiteLLMError("key metadata default model is invalid")
        # A default may only be (re-)stamped together with the model list it
        # must be a member of; validating them as one update keeps the
        # policy invariant (default ∈ allowed_models) checkable right here.
        models = updates.get("models")
        if "models" not in updates or not isinstance(models, list):
            raise LiteLLMError(
                "a default-model update requires the same update's model list"
            )
        if models and default_model not in models:
            raise LiteLLMError(
                "key default model is outside the updated model allowlist"
            )


def _validated_model_list(models: Any, *, allow_empty: bool) -> list[str]:
    """Accept only a bounded, deduplicated list of well-formed model names."""
    if (
        not isinstance(models, list)
        or len(models) > MAX_POLICY_MODELS
        or (not models and not allow_empty)
        or any(
            not isinstance(name, str) or MODEL_NAME_RE.fullmatch(name) is None
            for name in models
        )
        or len(set(models)) != len(models)
    ):
        raise LiteLLMError("model list is invalid")
    return sorted(models)


def _headers() -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if settings.litellm_master_key:
        headers["Authorization"] = f"Bearer {settings.litellm_master_key}"
    return headers


def _response_json(resp: httpx.Response, operation: str) -> Any:
    try:
        return resp.json()
    except ValueError as exc:
        raise LiteLLMError(f"{operation} returned invalid JSON") from exc


def _page_number(data: dict[str, Any], field: str) -> int | None:
    value = data.get(field)
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def _declared_page_number(data: dict[str, Any], field: str) -> int | None:
    """Read an optional pagination field without silently accepting garbage.

    The owner-scoped inventory is an authorization input for the one-active-
    key invariant.  Treating a malformed counter as "not supplied" would let
    a partial LiteLLM page be mistaken for a complete inventory.
    """

    if field not in data:
        return None
    value = _page_number(data, field)
    if value is None:
        raise LiteLLMError(f"key/list returned an invalid {field}")
    return value


async def key_list(user_id: str) -> list[Any]:
    """GET /key/list for exactly one OIDC subject, with bounded pagination.

    The portal holds the LiteLLM proxy-admin key, so this exact-subject query is
    the authorization source used before a revoke.  `return_full_object=true`
    is required so callers can resolve an alias to a concrete token hash.
    """
    if not isinstance(user_id, str) or not user_id:
        raise LiteLLMError("user_id is required for key/list")

    url = settings.litellm_url.rstrip("/") + "/key/list"
    all_keys: list[Any] = []
    try:
        # These calls carry the proxy-admin credential and, for generate,
        # plaintext virtual keys. Never hand them to an ambient container
        # proxy because NO_PROXY was omitted; never follow an off-origin
        # redirect with credentials.
        async with httpx.AsyncClient(
            timeout=10, trust_env=False, follow_redirects=False
        ) as client:
            for page in range(1, KEY_LIST_MAX_PAGES + 1):
                resp = await client.get(
                    url,
                    headers=_headers(),
                    params={
                        "user_id": user_id,
                        "return_full_object": "true",
                        "page": page,
                        "size": KEY_LIST_PAGE_SIZE,
                    },
                )
                if resp.status_code >= 400:
                    raise LiteLLMError(f"key/list failed: HTTP {resp.status_code}")

                data = _response_json(resp, "key/list")
                total_count: int | None = None
                if isinstance(data, dict):
                    page_keys = data.get("keys")
                    if page_keys is None:
                        # Defensive compatibility with older response wrappers.
                        page_keys = data.get("data", [])
                    current_page = _declared_page_number(data, "current_page")
                    total_pages = _declared_page_number(data, "total_pages")
                    total_count = _declared_page_number(data, "total_count")
                elif isinstance(data, list):
                    page_keys = data
                    current_page = total_pages = None
                else:
                    raise LiteLLMError("key/list returned an invalid response shape")

                if not isinstance(page_keys, list):
                    raise LiteLLMError("key/list returned a non-list keys field")
                if current_page is not None and current_page != page:
                    raise LiteLLMError("key/list returned an unexpected page")
                if total_pages is not None and total_pages < 0:
                    raise LiteLLMError("key/list returned an invalid total_pages")
                if total_count is not None and total_count < 0:
                    raise LiteLLMError("key/list returned an invalid total_count")

                # LiteLLM v1.91.3 supplies all of these counters.  Validate
                # them when present so an empty/short non-final page cannot
                # hide an active portal key and permit a second credential.
                if total_count is not None:
                    expected_total_pages = (
                        total_count + KEY_LIST_PAGE_SIZE - 1
                    ) // KEY_LIST_PAGE_SIZE
                    if total_pages is not None and total_pages != expected_total_pages:
                        raise LiteLLMError("key/list returned inconsistent page counters")
                    total_pages = expected_total_pages

                if total_pages is not None:
                    if total_pages == 0:
                        if page != 1 or page_keys:
                            raise LiteLLMError(
                                "key/list returned inconsistent page counters"
                            )
                    elif page > total_pages:
                        raise LiteLLMError("key/list returned an unexpected page")
                    elif total_count is not None:
                        expected_items = min(
                            KEY_LIST_PAGE_SIZE,
                            total_count - ((page - 1) * KEY_LIST_PAGE_SIZE),
                        )
                        if len(page_keys) != expected_items:
                            raise LiteLLMError(
                                "key/list ended before its declared final page"
                            )
                    elif page < total_pages and len(page_keys) != KEY_LIST_PAGE_SIZE:
                        raise LiteLLMError(
                            "key/list ended before its declared final page"
                        )
                # Do not make the upstream filter the sole authorization
                # boundary. v1.91.3 returns full key objects here; every one
                # must independently attest the exact immutable owner that
                # was requested. A malformed or cross-user result fails the
                # entire list closed instead of being rendered/revocable.
                if any(
                    not isinstance(entry, dict) or entry.get("user_id") != user_id
                    for entry in page_keys
                ):
                    raise LiteLLMError(
                        "key/list returned a key outside the requested owner"
                    )
                all_keys.extend(page_keys)

                if total_pages is not None:
                    if page >= total_pages:
                        return all_keys
                    # A counter-declared next page must be read even if this
                    # response happens to be short. The validation above has
                    # already rejected a short non-final page.
                    continue

                # Legacy LiteLLM responses without pagination counters can
                # only be considered complete after a short page. The hard
                # page cap below keeps a full-but-unbounded response fail
                # closed rather than using a partial inventory for key minting.
                if len(page_keys) < KEY_LIST_PAGE_SIZE:
                    return all_keys

            # A partial owner list is unsafe for authorization decisions and is
            # misleading in the UI. Fail closed at the hard cap.
            raise LiteLLMError("key/list exceeded the pagination safety limit")
    except httpx.HTTPError as exc:
        raise LiteLLMError(f"could not reach LiteLLM: {exc}") from exc


async def key_generate(
    user_id: str,
    alias: str,
    project_id: str,
    project_policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Mint a portal-owned virtual key for one immutable owner/project pair.

    LiteLLM's native project_id is a foreign key to a separately provisioned
    project/team. The portal has no authority to invent that hierarchy, so its
    stable project is stored in namespaced metadata and verified locally from
    full key objects on every subsequent decision.
    """
    if not isinstance(user_id, str) or not user_id:
        raise LiteLLMError("user_id is required for key/generate")
    if not isinstance(alias, str) or not alias or len(alias) > 128:
        raise LiteLLMError("key alias is invalid")
    if not isinstance(project_id, str) or PROJECT_ID_RE.fullmatch(project_id) is None:
        raise LiteLLMError("project_id is invalid")
    url = settings.litellm_url.rstrip("/") + "/key/generate"
    payload: dict[str, Any] = {
        "user_id": user_id,
        "key_alias": alias,
        "metadata": {
            "created_via": "dev-portal",
            PORTAL_PROJECT_METADATA_KEY: project_id,
        },
    }
    # Two reviewed guardrail layers, neither reachable from the browser:
    # 1. Static deployment config (group_vars → env). The platform default is
    #    now UNLIMITED — cost/budget is an admin-only concept, so no default
    #    max_budget is applied here.
    # 2. The runtime per-project policy (Keycloak group attributes via the
    #    identity controller) wins over the static layer for rate limits and
    #    the allowed model set. Its values were validated by the caller; they
    #    are re-validated here so a route bug cannot smuggle garbage into a
    #    master-key request.
    limits: dict[str, Any] = dict(settings.key_limits_for_project(project_id))
    if project_policy is not None:
        if not isinstance(project_policy, dict):
            raise LiteLLMError("project policy is invalid")
        for knob in ("tpm_limit", "rpm_limit"):
            value = project_policy.get(knob)
            if value is None:
                continue
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 < value <= RATE_LIMIT_MAX
            ):
                raise LiteLLMError("project policy rate limit is invalid")
            limits[knob] = value
        models = project_policy.get("allowed_models")
        if models is not None:
            limits["models"] = _validated_model_list(models, allow_empty=False)
        default_model = project_policy.get("default_model")
        if default_model is not None:
            # The default is enforced server-side by the LiteLLM pre-call
            # hook, which reads it from this key metadata field. It must be
            # well-formed and inside the same mint's model restriction, or
            # the mint fails closed.
            if (
                not isinstance(default_model, str)
                or MODEL_NAME_RE.fullmatch(default_model) is None
            ):
                raise LiteLLMError("project policy default model is invalid")
            if "models" in limits and default_model not in limits["models"]:
                raise LiteLLMError(
                    "project default model is outside its allowed models"
                )
            payload["metadata"][PORTAL_DEFAULT_MODEL_METADATA_KEY] = default_model
    payload.update(limits)
    try:
        async with httpx.AsyncClient(
            timeout=10, trust_env=False, follow_redirects=False
        ) as client:
            resp = await client.post(url, headers=_headers(), json=payload)
    except httpx.HTTPError as exc:
        raise LiteLLMError(f"could not reach LiteLLM: {exc}") from exc

    if resp.status_code >= 400:
        raise LiteLLMError(f"key/generate failed: HTTP {resp.status_code}")

    data = _response_json(resp, "key/generate")
    if not isinstance(data, dict):
        raise LiteLLMError("key/generate returned an invalid response shape")
    return data


async def key_deactivate(key: str) -> dict[str, Any]:
    """Block one pre-authorized key by concrete token/hash.

    LiteLLM authenticates the portal as proxy admin and does not enforce the
    browser user's ownership. Callers must first resolve this exact identifier
    from a locally owner+project-validated `/key/list` response.
    """
    if not isinstance(key, str) or not key or len(key) > 2048:
        raise LiteLLMError("key identifier is invalid")
    url = settings.litellm_url.rstrip("/") + "/key/update"
    payload = {"key": key, "blocked": True}

    try:
        async with httpx.AsyncClient(
            timeout=10, trust_env=False, follow_redirects=False
        ) as client:
            resp = await client.post(url, headers=_headers(), json=payload)
    except httpx.HTTPError as exc:
        raise LiteLLMError(f"could not reach LiteLLM: {exc}") from exc

    if resp.status_code >= 400:
        raise LiteLLMError(f"key/update failed: HTTP {resp.status_code}")

    data = _response_json(resp, "key/update")
    if not isinstance(data, dict):
        raise LiteLLMError("key/update returned an invalid response shape")
    return data


def _validated_key_identifier(value: Any) -> str:
    """Accept only a bounded, control-character-free persisted identifier."""
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 2048
        or any(ord(character) < 32 for character in value)
    ):
        raise LiteLLMError("key identifier is invalid")
    return value


async def _admin_key_query(params: dict[str, Any]) -> dict[str, Any]:
    """One master-key GET /key/list with the fixed outbound boundary."""
    url = settings.litellm_url.rstrip("/") + "/key/list"
    try:
        async with httpx.AsyncClient(
            timeout=10, trust_env=False, follow_redirects=False
        ) as client:
            resp = await client.get(url, headers=_headers(), params=params)
    except httpx.HTTPError as exc:
        raise LiteLLMError(f"could not reach LiteLLM: {exc}") from exc
    if resp.status_code >= 400:
        raise LiteLLMError(f"key/list failed: HTTP {resp.status_code}")
    data = _response_json(resp, "key/list")
    if not isinstance(data, dict):
        raise LiteLLMError("key/list returned an invalid response shape")
    return data


def _admin_page_rows(data: dict[str, Any]) -> list[dict[str, Any]]:
    rows = data.get("keys")
    if rows is None:
        rows = data.get("data", [])
    if not isinstance(rows, list) or any(
        not isinstance(entry, dict) for entry in rows
    ):
        raise LiteLLMError("key/list returned a non-object key entry")
    return rows


async def admin_key_list_page(page: int) -> dict[str, Any]:
    """Read one counter-checked GLOBAL /key/list page for the admin inventory.

    Unlike ``key_list`` this deliberately has no owner filter: it exists so an
    administrator can review every static bearer credential the gateway has
    issued. It requires LiteLLM's native pagination counters (v1.91.3 always
    supplies them) so a short or repeated page cannot silently hide keys, and
    it is display-only — mutations re-resolve their exact target through
    ``admin_key_lookup`` instead of trusting anything rendered from here.
    """
    if (
        not isinstance(page, int)
        or isinstance(page, bool)
        or not 1 <= page <= ADMIN_KEY_LIST_MAX_PAGE
    ):
        raise LiteLLMError("key inventory page is invalid")

    data = await _admin_key_query(
        {
            "return_full_object": "true",
            "page": page,
            "size": ADMIN_KEY_LIST_PAGE_SIZE,
        }
    )
    rows = _admin_page_rows(data)
    current_page = _declared_page_number(data, "current_page")
    total_pages = _declared_page_number(data, "total_pages")
    total_count = _declared_page_number(data, "total_count")
    if current_page is None or total_pages is None or total_count is None:
        raise LiteLLMError("global key/list returned no pagination counters")
    if current_page != page:
        raise LiteLLMError("key/list returned an unexpected page")
    expected_total_pages = (
        total_count + ADMIN_KEY_LIST_PAGE_SIZE - 1
    ) // ADMIN_KEY_LIST_PAGE_SIZE
    if total_pages != expected_total_pages:
        raise LiteLLMError("key/list returned inconsistent page counters")
    if total_pages == 0:
        if page != 1 or rows:
            raise LiteLLMError("key/list returned inconsistent page counters")
    elif page > total_pages:
        raise LiteLLMError("key/list returned an unexpected page")
    elif (
        len(rows)
        != min(
            ADMIN_KEY_LIST_PAGE_SIZE,
            total_count - ((page - 1) * ADMIN_KEY_LIST_PAGE_SIZE),
        )
    ):
        raise LiteLLMError("key/list ended before its declared final page")

    return {
        "keys": rows,
        "page": page,
        "total_pages": total_pages,
        "total_count": total_count,
    }


async def admin_key_lookup(key_hash: str) -> dict[str, Any]:
    """Resolve exactly one full key object by its persisted token hash.

    Every admin mutation authorizes against this exact-hash lookup rather
    than a rendered listing, so a stale or tampered form field can only ever
    name a key that still exists — and the effect of a mutation is verified
    with the same query afterwards.
    """
    identifier = _validated_key_identifier(key_hash)
    data = await _admin_key_query(
        {
            "return_full_object": "true",
            "key_hash": identifier,
            "page": 1,
            "size": ADMIN_KEY_LIST_PAGE_SIZE,
        }
    )
    rows = _admin_page_rows(data)
    total_count = _declared_page_number(data, "total_count")
    if total_count != 1 or len(rows) != 1:
        raise LiteLLMError("key lookup did not resolve exactly one key")
    entry = rows[0]
    if entry.get("token") != identifier:
        raise LiteLLMError("key lookup returned a different key")
    return entry


async def key_update(key: str, updates: dict[str, Any]) -> dict[str, Any]:
    """Apply an allowlisted admin mutation to one pre-resolved key.

    Callers must first resolve ``key`` via ``admin_key_lookup`` (or the
    owner-validated inventory). Only the reviewed budget/rate/lifetime/block
    fields may ever be sent; every value is re-validated here so a route bug
    cannot smuggle an unreviewed field to the master-key endpoint.
    """
    identifier = _validated_key_identifier(key)
    if not isinstance(updates, dict) or not updates:
        raise LiteLLMError("key/update requires at least one field")
    if not set(updates) <= KEY_UPDATE_MUTABLE_FIELDS:
        raise LiteLLMError("key/update field is not allowlisted")
    for field, value in updates.items():
        if field == "blocked":
            if not isinstance(value, bool):
                raise LiteLLMError("blocked must be a boolean")
        elif field == "duration":
            if not isinstance(value, str) or KEY_DURATION_RE.fullmatch(value) is None:
                raise LiteLLMError("duration is invalid")
        elif field == "max_budget":
            if value is not None and (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not 0 < value <= 1_000_000
            ):
                raise LiteLLMError("max_budget is invalid")
        elif field == "models":
            # An empty list is LiteLLM's "no model restriction" and is the
            # deliberate re-tune value when a project policy clears its
            # allowed-models set.
            _validated_model_list(value, allow_empty=True)
        elif field == "metadata":
            _validated_retune_metadata(value, updates)
        else:  # tpm_limit / rpm_limit
            if value is not None and (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 < value <= RATE_LIMIT_MAX
            ):
                raise LiteLLMError(f"{field} is invalid")

    url = settings.litellm_url.rstrip("/") + "/key/update"
    payload = {"key": identifier, **updates}
    try:
        async with httpx.AsyncClient(
            timeout=10, trust_env=False, follow_redirects=False
        ) as client:
            resp = await client.post(url, headers=_headers(), json=payload)
    except httpx.HTTPError as exc:
        raise LiteLLMError(f"could not reach LiteLLM: {exc}") from exc

    if resp.status_code >= 400:
        raise LiteLLMError(f"key/update failed: HTTP {resp.status_code}")

    data = _response_json(resp, "key/update")
    if not isinstance(data, dict):
        raise LiteLLMError("key/update returned an invalid response shape")
    return data


async def model_names() -> list[str]:
    """List the gateway's configured model names from LiteLLM.

    Server-side only (master key). Used to render and validate the
    per-project policy forms and to show developers which models exist when
    a project carries no restriction. Response entries are strictly bounded
    so a compromised upstream cannot inject markup or unbounded data.
    """
    url = settings.litellm_url.rstrip("/") + "/v1/models"
    try:
        async with httpx.AsyncClient(
            timeout=10, trust_env=False, follow_redirects=False
        ) as client:
            resp = await client.get(url, headers=_headers())
    except httpx.HTTPError as exc:
        raise LiteLLMError(f"could not reach LiteLLM: {exc}") from exc
    if resp.status_code >= 400:
        raise LiteLLMError(f"v1/models failed: HTTP {resp.status_code}")
    data = _response_json(resp, "v1/models")
    rows = data.get("data") if isinstance(data, dict) else None
    if not isinstance(rows, list) or len(rows) > 256:
        raise LiteLLMError("v1/models returned an invalid response shape")
    names: set[str] = set()
    for row in rows:
        name = row.get("id") if isinstance(row, dict) else None
        if not isinstance(name, str) or MODEL_NAME_RE.fullmatch(name) is None:
            raise LiteLLMError("v1/models returned an invalid model name")
        names.add(name)
    return sorted(names)
