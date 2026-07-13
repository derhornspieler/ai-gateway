"""Anthropic WIF JWKS-rotation watcher.

Design ref: docs/anthropic-wif-bootstrap.md Phase 1a — the Anthropic
federation issuer holds an INLINE copy of the Keycloak realm JWKS with no
auto-refresh: if Keycloak rotates its realm signing keys and nobody
re-pushes the new `keys` array, every token exchange fails signature
verification (surfacing only as opaque HTTP 400 invalid_grant).

This watcher runs as a recurring APScheduler job (see app/scheduler.py,
job id "sys_jwks_watch", interval JWKS_WATCH_INTERVAL_SECONDS):

  1. Fetch the realm JWKS from Keycloak (certs URL derived from the
     bootstrap doc's kc_token_url — INTERNAL call, not via egress).
  2. Compare (canonicalized) against the last operator-approved key set,
     persisted in rotator_settings under the pseudo-vendor row
     "anthropic-jwks" (app/db.py state store; no driver is registered for
     it, so the scheduler reconcile ignores the row).
  3. On drift: persist the candidate public JWKS/hash and alert (health flag
     "anthropic.jwks" + rotation_history "jwks" rows). A human organization
     administrator must replace the inline JWKS in Anthropic and then record
     that exact hash as `federation_jwks_sha256` in the bootstrap Vault doc.

The inference broker intentionally has only workspace:developer. Anthropic's
federation-issuer mutation API requires an org:admin OAuth token, so this
service MUST NOT mint or retain that credential and makes zero Anthropic
issuer-mutation calls. Elevating the inference path to automate key publishing
would collapse the intended privilege separation.

The first observation is accepted only when its hash matches the explicit
operator-approved Vault value. This avoids silently trusting a new Keycloak
key after a database restore or watcher-state loss.
"""
from __future__ import annotations

import hashlib
import json
import logging
from typing import Any, Optional

import httpx

from app import health
from app.config import Settings
from app.db import Database
from app.vault_client import VaultError

logger = logging.getLogger("key_rotator.jwks_watcher")

STATE_VENDOR = "anthropic-jwks"
BOOTSTRAP_VAULT_PATH = "ai-gateway/anthropic-wif"

KC_TOKEN_SUFFIX = "/protocol/openid-connect/token"
KC_CERTS_SUFFIX = "/protocol/openid-connect/certs"


def _canonical_jwks(keys: list[dict[str, Any]]) -> str:
    """Deterministic serialization of a `keys` array (sorted by kid, keys
    sorted within each JWK) so semantically-equal sets hash identically.
    """
    ordered = sorted(keys, key=lambda k: (str(k.get("kid", "")), str(k.get("alg", ""))))
    return json.dumps(ordered, sort_keys=True, separators=(",", ":"))


def _jwks_sha256(keys: list[dict[str, Any]]) -> str:
    return hashlib.sha256(_canonical_jwks(keys).encode()).hexdigest()


class AnthropicJwksWatcher:
    """Detect Keycloak signing-key drift without holding org-admin power."""

    def __init__(self, settings: Settings, db: Database, vault: Any, litellm: Any, driver: Any) -> None:
        self._settings = settings
        self._db = db
        self._vault = vault
        # Keep the constructor ABI used by RotationScheduler, but deliberately
        # retain neither the inference-token driver nor LiteLLM client. They
        # are not valid credentials for Anthropic issuer administration.
        del litellm, driver

    async def check(self) -> None:
        """One watch pass. Never raises — all failure modes land in the
        health registry + rotation_history instead.
        """
        try:
            bootstrap = self._vault.read(BOOTSTRAP_VAULT_PATH)
        except VaultError as exc:
            # Vault unreachable — cannot tell if we still hold the right
            # baseline. Alert (do not silently pass) and retry next pass.
            health.set_alert(
                "anthropic.jwks",
                f"vault read error reading {BOOTSTRAP_VAULT_PATH}: {exc} — "
                "cannot check for signing-key rotation while this persists",
            )
            return
        if not bootstrap or not bootstrap.get("kc_token_url"):
            # Phase 0 not done yet — nothing to watch, and not an alert.
            health.set_ok("anthropic.jwks")
            return

        try:
            token_url = self._settings.validated_keycloak_token_url(bootstrap["kc_token_url"])
        except (TypeError, ValueError) as exc:
            health.set_alert("anthropic.jwks", f"invalid Keycloak token endpoint: {exc}")
            return
        certs_url = self._certs_url(token_url)
        try:
            keys = await self._fetch_jwks(certs_url)
        except Exception as exc:  # noqa: BLE001
            health.set_alert(
                "anthropic.jwks",
                f"failed to fetch Keycloak realm JWKS from {certs_url}: {exc} — "
                "cannot detect signing-key rotation while this persists",
            )
            return

        current_sha = _jwks_sha256(keys)
        state_row = await self._db.get_settings(STATE_VENDOR)
        state = dict((state_row or {}).get("config") or {})
        last_sha: Optional[str] = state.get("last_jwks_sha256")
        approved_sha = bootstrap.get("federation_jwks_sha256")
        approved_sha = (
            approved_sha.lower()
            if isinstance(approved_sha, str)
            and len(approved_sha) == 64
            and all(ch in "0123456789abcdefABCDEF" for ch in approved_sha)
            else None
        )

        if last_sha is None:
            if approved_sha != current_sha:
                await self._record_pending(
                    state,
                    keys,
                    current_sha,
                    "baseline_unconfirmed",
                    (
                        "Keycloak JWKS has no matching operator-approved Anthropic "
                        f"baseline (sha256={current_sha}). Replace the issuer's full "
                        "inline keys array using an interactive org:admin session, then "
                        "write this exact hash as federation_jwks_sha256 in Vault path "
                        f"{BOOTSTRAP_VAULT_PATH}. No automatic issuer mutation was attempted."
                    ),
                )
                return
            state.update({"last_jwks_sha256": current_sha, "last_jwks_keys": keys})
            state.pop("pending_jwks_sha256", None)
            state.pop("pending_jwks_keys", None)
            await self._persist_state(state)
            logger.info(
                "jwks_watcher: recorded operator-approved baseline (%d key(s), sha256=%s)",
                len(keys),
                current_sha[:16],
            )
            health.set_ok("anthropic.jwks")
            return

        if current_sha == last_sha:
            health.set_ok("anthropic.jwks")
            return

        if approved_sha == current_sha:
            previous_sha = last_sha
            state.update({"last_jwks_sha256": current_sha, "last_jwks_keys": keys})
            state.pop("pending_jwks_sha256", None)
            state.pop("pending_jwks_keys", None)
            await self._persist_state(state)
            detail = (
                "operator-approved Anthropic inline JWKS now matches Keycloak "
                f"(sha256 {previous_sha[:16]} -> {current_sha[:16]})"
            )
            await self._db.record_history(
                STATE_VENDOR, "jwks", "manual_update_confirmed", detail
            )
            health.set_ok("anthropic.jwks")
            return

        # Drift: Keycloak's published keys differ from what Anthropic holds.
        detail = (
            f"Keycloak realm JWKS changed (now {len(keys)} key(s), sha256 "
            f"{last_sha[:16]} -> {current_sha}); replace the Anthropic federation "
            "issuer's FULL inline keys array with an interactive org:admin session, "
            "then write the exact new hash as federation_jwks_sha256 in Vault path "
            f"{BOOTSTRAP_VAULT_PATH}. No automatic issuer mutation was attempted; "
            "token exchange can fail once the new key starts signing"
        )
        await self._record_pending(
            state, keys, current_sha, "drift_detected", detail
        )

    @staticmethod
    def _certs_url(kc_token_url: str) -> str:
        """Derive the realm JWKS endpoint from the configured token URL."""
        base = kc_token_url.rstrip("/")
        if base.endswith(KC_TOKEN_SUFFIX.strip("/")):
            return base[: -len(KC_TOKEN_SUFFIX.strip("/"))] + KC_CERTS_SUFFIX.strip("/")
        return base + KC_CERTS_SUFFIX

    async def _fetch_jwks(self, certs_url: str) -> list[dict[str, Any]]:
        async with httpx.AsyncClient(
            timeout=15.0, trust_env=False, follow_redirects=False
        ) as client:
            resp = await client.get(certs_url)
            resp.raise_for_status()
            keys = resp.json().get("keys")
            if not isinstance(keys, list) or not keys:
                raise RuntimeError(f"JWKS response from {certs_url} has no keys array")
            return keys

    async def _record_pending(
        self,
        state: dict[str, Any],
        keys: list[dict[str, Any]],
        current_sha: str,
        status: str,
        detail: str,
    ) -> None:
        """Persist one alert per newly observed candidate, without log spam."""
        is_new = state.get("pending_jwks_sha256") != current_sha
        state.update(
            {"pending_jwks_sha256": current_sha, "pending_jwks_keys": keys}
        )
        if is_new:
            await self._persist_state(state)
            await self._db.record_history(STATE_VENDOR, "jwks", status, detail)
        health.set_alert("anthropic.jwks", detail)

    async def _persist_state(self, state: dict[str, Any]) -> None:
        await self._db.upsert_settings(
            STATE_VENDOR, enabled=False, interval_seconds=0, grace_seconds=0, config=state
        )
