"""LiteLLM credential client for key-rotator.

Design ref: docs/solution-map.md §1.2/§1.7 — rotation is pushed into
LiteLLM via its OSS `/credentials` API, which hot-swaps the credential
in-process (no restart, takes effect next request). LiteLLM auto-detects
`sk-ant-oat*` values and applies Bearer auth + the required beta header
automatically, so this client stays vendor-agnostic: it only ever sends
`{"api_key": "..."}`-shaped credential_values.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from app.config import Settings
from app.security import path_segment
from app.vault_client import mask_secret

logger = logging.getLogger("key_rotator.litellm")


class LiteLLMClient:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._settings.litellm_master_key}"}

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
        async with httpx.AsyncClient(
            timeout=30.0, trust_env=False, follow_redirects=False
        ) as client:
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
