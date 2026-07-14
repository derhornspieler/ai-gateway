"""LiteLLM credential and portal-key client for key-rotator.

Design ref: docs/solution-map.md §1.2/§1.7 — rotation is pushed into
LiteLLM via its OSS `/credentials` API, which hot-swaps the credential
in-process (no restart, takes effect next request). LiteLLM auto-detects
`sk-ant-oat*` values and applies Bearer auth + the required beta header
automatically, so this client stays vendor-agnostic: it only ever sends
`{"api_key": "..."}`-shaped credential_values.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

import httpx

from app.config import Settings
from app.security import path_segment
from app.vault_client import mask_secret

logger = logging.getLogger("key_rotator.litellm")


class LiteLLMError(RuntimeError):
    """A fail-closed LiteLLM control-plane operation failed."""


# Portal virtual keys are deliberately tagged at issuance.  The identity
# controller uses these immutable namespaced fields when revoking access after
# a project-membership removal; it must never infer ownership from a mutable
# alias or block an operator-managed key merely because it shares an owner.
PORTAL_KEY_CREATOR_FIELD = "created_via"
PORTAL_KEY_CREATOR_VALUE = "dev-portal"
PORTAL_PROJECT_METADATA_KEY = "aigw_project_id"
PROJECT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
IDENTITY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$")
KEY_LIST_PAGE_SIZE = 100
KEY_LIST_MAX_PAGES = 10
MAX_KEY_METADATA_BYTES = 64 * 1024
MAX_KEY_IDENTIFIER_BYTES = 2048


@dataclass(frozen=True)
class PortalKeyBinding:
    """One active portal key, retained only for the current scan page.

    ``key_token`` is LiteLLM's persisted token hash, not a plaintext bearer
    credential. It is deliberately never logged or written to scheduler
    state; it exists only long enough to block and verify this exact row.
    """

    user_id: str
    project_id: str
    key_token: str


@dataclass(frozen=True)
class PortalKeyInventoryPage:
    """A counter-checked global portal-key inventory page.

    ``inventory_digest`` is a one-way digest of the ordered persisted token
    hashes in this response. It lets the scheduler compare two full scans
    without persisting any token, owner, or project value.
    """

    page: int
    total_count: int
    total_pages: int
    bindings: tuple[PortalKeyBinding, ...]
    inventory_digest: str


@dataclass(frozen=True)
class _KeyListPage:
    """Internal parsed `/key/list` response with optional legacy counters."""

    page: int
    total_count: int | None
    total_pages: int | None
    entries: tuple[dict[str, Any], ...]


class LiteLLMClient:
    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._settings = settings
        self._transport = transport

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._settings.litellm_master_key}"}

    def _client_kwargs(self) -> dict[str, Any]:
        """Return the fixed outbound boundary for master-key requests."""

        kwargs: dict[str, Any] = {
            "timeout": 30.0,
            "trust_env": False,
            "follow_redirects": False,
        }
        if self._transport is not None:
            kwargs["transport"] = self._transport
        return kwargs

    async def upsert_credential(self, name: str, values: dict[str, Any]) -> None:
        """Try PATCH /credentials/{name}; on 404, POST /credentials to
        create it. `values` typically contains {"api_key": "..."} — never
        logged in full, only a masked prefix.
        """
        masked = {k: (mask_secret(v) if isinstance(v, str) else v) for k, v in values.items()}
        base = self._settings.litellm_url.rstrip("/")
        safe_name = path_segment(name, label="LiteLLM credential name")

        # Do not inherit HTTP(S)_PROXY from the container environment. These
        # requests carry the LiteLLM master key and plaintext vendor keys;
        # a missing NO_PROXY entry would otherwise hand both to an ambient
        # proxy. Redirects are also kept off so credentials stay on-origin.
        async with httpx.AsyncClient(**self._client_kwargs()) as client:
            resp = await client.patch(
                f"{base}/credentials/{safe_name}",
                json={"credential_values": values},
                headers=self._headers(),
            )

            if resp.status_code == 404:
                logger.info("litellm credential name=%s not found, creating", name)
                resp = await client.post(
                    f"{base}/credentials",
                    json={
                        "credential_name": name,
                        "credential_values": values,
                        "credential_info": {"managed_by": "key-rotator"},
                    },
                    headers=self._headers(),
                )
                resp.raise_for_status()
                logger.info("created litellm credential name=%s values=%s", name, masked)
                return

            resp.raise_for_status()
            logger.info("updated litellm credential name=%s values=%s", name, masked)

    @staticmethod
    def _key_metadata(entry: dict[str, Any]) -> dict[str, Any]:
        """Decode bounded LiteLLM metadata without accepting ambiguous data."""

        raw = entry.get("metadata")
        if isinstance(raw, dict):
            return raw
        if raw in (None, ""):
            return {}
        if not isinstance(raw, str) or len(raw.encode("utf-8")) > MAX_KEY_METADATA_BYTES:
            raise LiteLLMError("LiteLLM key metadata is invalid or too large")
        try:
            parsed = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise LiteLLMError("LiteLLM key metadata is not valid JSON") from exc
        if not isinstance(parsed, dict):
            raise LiteLLMError("LiteLLM key metadata is not an object")
        return parsed

    @staticmethod
    def _key_identifier(entry: dict[str, Any]) -> str:
        """Return LiteLLM's persisted token hash for a key update.

        ``key_name`` is a mutable display label rather than an update target.
        Falling back to it could make a failed revocation look verified while
        the actual portal key remained active.
        """

        value = entry.get("token")
        if (
            isinstance(value, str)
            and value
            and len(value.encode("utf-8")) <= MAX_KEY_IDENTIFIER_BYTES
            and not any(ord(character) < 32 for character in value)
        ):
            return value
        raise LiteLLMError("a portal key has no safe persisted identifier")

    @staticmethod
    def _portal_project(entry: dict[str, Any]) -> str | None:
        """Return the exact project for one portal-created key.

        Operator-managed and legacy keys are intentionally outside this narrow
        revocation scope.  A malformed entry claiming portal provenance is a
        hard stop: silently skipping it could leave a usable bearer credential
        after group membership has been removed.
        """

        metadata = LiteLLMClient._key_metadata(entry)
        if metadata.get(PORTAL_KEY_CREATOR_FIELD) != PORTAL_KEY_CREATOR_VALUE:
            return None
        project = metadata.get(PORTAL_PROJECT_METADATA_KEY)
        if not isinstance(project, str) or PROJECT_ID_RE.fullmatch(project) is None:
            raise LiteLLMError("a portal key has an invalid project binding")
        return project

    @staticmethod
    def _pagination_value(value: Any) -> int | None:
        """Accept only non-boolean pagination integers."""

        if isinstance(value, int) and not isinstance(value, bool):
            return value
        return None

    @classmethod
    def _key_page_digest(cls, entries: Iterable[dict[str, Any]]) -> str:
        """Return a domain-separated digest of this ordered response page.

        LiteLLM v1.91.3 uses deterministic ``created_at, token`` ordering,
        but exposes no snapshot token. The digest is therefore used only as a
        no-secret consistency witness across a second complete scan; it is not
        itself treated as an inventory cursor.
        """

        digest = hashlib.sha256(b"aigw-portal-key-page-v1\0")
        for entry in entries:
            token = cls._key_identifier(entry).encode("utf-8")
            digest.update(len(token).to_bytes(4, byteorder="big"))
            digest.update(token)
        return digest.hexdigest()

    async def _get_key_page(
        self,
        page: int,
        *,
        user_id: str | None = None,
        key_hash: str | None = None,
        require_page_counters: bool = False,
    ) -> _KeyListPage:
        """Read one bounded `/key/list` page and validate its shape.

        Global reconciliation requires LiteLLM's native counters, allowing
        the scheduler to checkpoint exactly one page at a time. Owner-scoped
        revocation retains compatibility with older responses that omit those
        counters, but remains capped by its caller.
        """

        if not isinstance(page, int) or isinstance(page, bool) or page < 1:
            raise LiteLLMError("LiteLLM key inventory page is invalid")

        if user_id is not None and (
            not isinstance(user_id, str) or IDENTITY_ID_RE.fullmatch(user_id) is None
        ):
            raise LiteLLMError("subject identifier is invalid")
        if key_hash is not None:
            # Reuse the persisted-token validation without accepting a display
            # label as an update or lookup target.
            self._key_identifier({"token": key_hash})
        if user_id is not None and key_hash is not None:
            raise LiteLLMError("LiteLLM key inventory filters are ambiguous")

        url = self._settings.litellm_url.rstrip("/") + "/key/list"
        try:
            async with httpx.AsyncClient(**self._client_kwargs()) as client:
                params: dict[str, str | int] = {
                    "return_full_object": "true",
                    "page": page,
                    "size": KEY_LIST_PAGE_SIZE,
                }
                if user_id is not None:
                    params["user_id"] = user_id
                if key_hash is not None:
                    params["key_hash"] = key_hash
                response = await client.get(
                    url,
                    headers=self._headers(),
                    params=params,
                )
        except httpx.HTTPError as exc:
            raise LiteLLMError("could not reach LiteLLM key inventory") from exc

        if response.status_code >= 400:
            raise LiteLLMError("LiteLLM key inventory request failed")
        try:
            payload = response.json()
        except ValueError as exc:
            raise LiteLLMError("LiteLLM key inventory was not JSON") from exc

        current_page: int | None = None
        total_pages: int | None = None
        total_count: int | None = None
        if isinstance(payload, dict):
            rows = payload.get("keys")
            if rows is None:
                rows = payload.get("data", [])
            current_page = self._pagination_value(payload.get("current_page"))
            total_pages = self._pagination_value(payload.get("total_pages"))
            total_count = self._pagination_value(payload.get("total_count"))
        elif isinstance(payload, list):
            rows = payload
        else:
            raise LiteLLMError("LiteLLM key inventory has an invalid shape")

        if require_page_counters and (
            current_page is None or total_pages is None or total_count is None
        ):
            raise LiteLLMError(
                "LiteLLM global key inventory has no pagination counters"
            )
        if current_page is not None and current_page != page:
            raise LiteLLMError("LiteLLM key inventory returned an unexpected page")
        if total_pages is not None and total_pages < 0:
            raise LiteLLMError("LiteLLM key inventory has an invalid page count")
        if total_count is not None and total_count < 0:
            raise LiteLLMError("LiteLLM key inventory has an invalid item count")
        if not isinstance(rows, list):
            raise LiteLLMError("LiteLLM key inventory is not a list")

        entries: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict):
                raise LiteLLMError("LiteLLM key inventory contains an invalid key")
            if user_id is not None and row.get("user_id") != user_id:
                raise LiteLLMError("LiteLLM key inventory contains another owner")
            entries.append(row)

        # LiteLLM v1.91.3 reports all three counters. Enforce their internal
        # consistency before using a page as a durable scan checkpoint: a
        # short non-final response or changing count would otherwise skip
        # unexamined static bearer keys.
        if total_pages is not None and total_count is not None:
            expected_total_pages = (
                total_count + KEY_LIST_PAGE_SIZE - 1
            ) // KEY_LIST_PAGE_SIZE
            if total_pages != expected_total_pages:
                raise LiteLLMError("LiteLLM key inventory has inconsistent page counters")
            if total_pages == 0:
                if page != 1 or entries:
                    raise LiteLLMError(
                        "LiteLLM key inventory has inconsistent page counters"
                    )
            elif page > total_pages:
                raise LiteLLMError("LiteLLM key inventory has inconsistent page counters")
            else:
                expected_entries = min(
                    KEY_LIST_PAGE_SIZE,
                    total_count - ((page - 1) * KEY_LIST_PAGE_SIZE),
                )
                if len(entries) != expected_entries:
                    raise LiteLLMError(
                        "LiteLLM key inventory ended before its final page"
                    )
        elif total_pages is not None:
            if total_pages == 0:
                if page != 1 or entries:
                    raise LiteLLMError(
                        "LiteLLM key inventory has inconsistent page counters"
                    )
            elif total_pages < page:
                raise LiteLLMError("LiteLLM key inventory has inconsistent page counters")
            elif page < total_pages and len(entries) != KEY_LIST_PAGE_SIZE:
                raise LiteLLMError("LiteLLM key inventory ended before its final page")

        return _KeyListPage(
            page=page,
            total_count=total_count,
            total_pages=total_pages,
            entries=tuple(entries),
        )

    async def _list_keys(self, user_id: str) -> list[dict[str, Any]]:
        """Read a complete, exact-owner virtual-key inventory."""

        all_keys: list[dict[str, Any]] = []
        for page_number in range(1, KEY_LIST_MAX_PAGES + 1):
            page = await self._get_key_page(page_number, user_id=user_id)
            all_keys.extend(page.entries)
            if page.total_pages is not None:
                if page_number >= page.total_pages:
                    return all_keys
            elif len(page.entries) < KEY_LIST_PAGE_SIZE:
                return all_keys

        # A complete owner inventory is mandatory before a direct membership
        # removal. Do not block only the first 1,000 keys and claim success.
        raise LiteLLMError("LiteLLM key inventory exceeded the safety limit")

    async def _list_user_keys(self, user_id: str) -> list[dict[str, Any]]:
        """Read a complete, exact-owner virtual-key inventory."""

        return await self._list_keys(user_id)

    async def _block_key(self, key_identifier: str) -> None:
        """Request a block without exposing the identifier in diagnostics."""

        url = self._settings.litellm_url.rstrip("/") + "/key/update"
        try:
            async with httpx.AsyncClient(**self._client_kwargs()) as client:
                response = await client.post(
                    url,
                    headers={**self._headers(), "Content-Type": "application/json"},
                    json={"key": key_identifier, "blocked": True},
                )
        except httpx.HTTPError as exc:
            raise LiteLLMError("could not reach LiteLLM key update") from exc
        if response.status_code >= 400:
            raise LiteLLMError("LiteLLM key update failed")

    @classmethod
    def _active_portal_key_ids(
        cls, entries: Iterable[dict[str, Any]], project_id: str
    ) -> list[str]:
        """Resolve only active portal keys for the exact removed project."""

        identifiers: list[str] = []
        seen: set[str] = set()
        for entry in entries:
            if cls._portal_project(entry) != project_id:
                continue
            # Treat every non-boolean-true value as potentially active. A
            # malformed lifecycle response must never preserve access merely
            # because a serializer changed a bool to a string.
            if entry.get("blocked") is True:
                continue
            identifier = cls._key_identifier(entry)
            if identifier not in seen:
                seen.add(identifier)
                identifiers.append(identifier)
        return identifiers

    @classmethod
    def _active_portal_key_bindings(
        cls, entries: Iterable[dict[str, Any]]
    ) -> tuple[PortalKeyBinding, ...]:
        """Return active portal keys from one global inventory page only."""

        bindings_by_token: dict[str, PortalKeyBinding] = {}
        for entry in entries:
            project = cls._portal_project(entry)
            if project is None or entry.get("blocked") is True:
                continue
            user_id = entry.get("user_id")
            if not isinstance(user_id, str) or IDENTITY_ID_RE.fullmatch(user_id) is None:
                raise LiteLLMError("a portal key has an invalid owner")
            token = cls._key_identifier(entry)
            binding = PortalKeyBinding(user_id, project, token)
            previous = bindings_by_token.setdefault(token, binding)
            if previous != binding:
                raise LiteLLMError("LiteLLM key inventory has a duplicate key identity")
        return tuple(bindings_by_token.values())

    async def active_portal_key_inventory_page(
        self, page: int
    ) -> PortalKeyInventoryPage:
        """Read one global page for durable portal-key reconciliation."""

        result = await self._get_key_page(page, require_page_counters=True)
        if result.total_count is None or result.total_pages is None:
            # Kept explicit for type checkers and to defend future changes to
            # `_get_key_page`'s counter contract.
            raise LiteLLMError("LiteLLM global key inventory has no pagination counters")
        return PortalKeyInventoryPage(
            page=result.page,
            total_count=result.total_count,
            total_pages=result.total_pages,
            bindings=self._active_portal_key_bindings(result.entries),
            inventory_digest=self._key_page_digest(result.entries),
        )

    async def revoke_portal_key_binding(self, binding: PortalKeyBinding) -> None:
        """Block and prove revocation of exactly one current-page portal key."""

        if not isinstance(binding, PortalKeyBinding):
            raise LiteLLMError("portal key binding is invalid")
        if IDENTITY_ID_RE.fullmatch(binding.user_id) is None:
            raise LiteLLMError("subject identifier is invalid")
        if PROJECT_ID_RE.fullmatch(binding.project_id) is None:
            raise LiteLLMError("project identifier is invalid")
        self._key_identifier({"token": binding.key_token})

        try:
            await self._block_key(binding.key_token)
        except LiteLLMError:
            # A lost update response may have committed. The exact-hash lookup
            # below distinguishes that safe outcome from an active key.
            pass

        result = await self._get_key_page(
            1,
            key_hash=binding.key_token,
            require_page_counters=True,
        )
        if result.total_count != 1 or len(result.entries) != 1:
            raise LiteLLMError("could not verify portal-key revocation")
        entry = result.entries[0]
        if (
            self._key_identifier(entry) != binding.key_token
            or entry.get("user_id") != binding.user_id
            or self._portal_project(entry) != binding.project_id
            or entry.get("blocked") is not True
        ):
            raise LiteLLMError("could not verify portal-key revocation")

    async def revoke_portal_project_keys(self, user_id: str, project_id: str) -> None:
        """Block and verify every active portal key for one owner/project.

        Membership removal calls this once before the Keycloak mutation and
        once after it.  Each pass is independently convergent so an ambiguous
        timeout after ``/key/update`` is resolved by a fresh full inventory,
        never by assuming that a bearer credential was revoked.
        """

        if not isinstance(project_id, str) or PROJECT_ID_RE.fullmatch(project_id) is None:
            raise LiteLLMError("project identifier is invalid")

        # A second bounded pass handles an update that committed after a lost
        # response and a concurrent portal generation that was visible during
        # this same membership-removal transaction.  More retries would hide a
        # control-plane outage and leave the caller unable to decide safely.
        for _ in range(2):
            before = await self._list_user_keys(user_id)
            target_ids = self._active_portal_key_ids(before, project_id)
            if not target_ids:
                return

            for identifier in target_ids:
                try:
                    await self._block_key(identifier)
                except LiteLLMError:
                    # The next complete inventory decides whether the update
                    # actually committed. Do not leak a key identifier in logs
                    # or turn an ambiguous transport result into a false pass.
                    pass

            after = await self._list_user_keys(user_id)
            if not self._active_portal_key_ids(after, project_id):
                return

        raise LiteLLMError("could not verify portal-key revocation")
