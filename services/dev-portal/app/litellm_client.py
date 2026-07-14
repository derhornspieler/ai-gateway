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
PORTAL_KEY_CREATOR_FIELD = "created_via"
PORTAL_KEY_CREATOR_VALUE = "dev-portal"
PORTAL_PROJECT_METADATA_KEY = "aigw_project_id"
PROJECT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")


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


async def key_generate(user_id: str, alias: str, project_id: str) -> dict[str, Any]:
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
    payload = {
        "user_id": user_id,
        "key_alias": alias,
        "metadata": {
            "created_via": "dev-portal",
            PORTAL_PROJECT_METADATA_KEY: project_id,
        },
    }
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
