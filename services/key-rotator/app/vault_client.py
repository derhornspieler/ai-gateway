"""Vault KV v2 client for key-rotator.

Design ref: docs/solution-map.md §1.3 (Vault CE, KV v2 secrets engine) and
§1.7 / docs/anthropic-wif-bootstrap.md (bootstrap material + rotation state
live under the "ai-gateway/..." logical KV v2 path space, mounted at "kv").

Read helpers are tolerant of missing paths (return None) rather than
raising: "no secret written yet" is an expected state before an operator
completes bootstrap (Phase 0) or before local/dev seeding happens (see
drivers/static_seed.py), and drivers treat that as "disabled", not an
error.

No secret value is ever logged in full — see `mask_secret`.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Optional

import hvac
import requests
from hvac.exceptions import InvalidPath

from app.config import Settings

logger = logging.getLogger("key_rotator.vault")

MOUNT_POINT = "kv"
TOKEN_CHECK_INTERVAL_SECONDS = 3600
TOKEN_RENEW_BEFORE_SECONDS = 7 * 86400
PUBLIC_HEALTH_STATUSES = {200, 429, 472, 473, 501, 503}


class VaultError(Exception):
    """An actual Vault read/write failure (transport, auth, permission,
    sealed vault, ...), as distinct from a *missing path*.

    `read()` returns None for a missing path (an expected pre-bootstrap
    state) but raises VaultError on a real error, so callers never mistake
    a transient outage for "no secret written yet". Treating a read error
    as "empty" during rotation is exactly how a live old-credential
    reference gets silently forgotten (no teardown, no orphan record).
    """


def mask_secret(value: Optional[str], keep: int = 8) -> str:
    """Redact a secret for logging/telemetry without exposing a prefix.

    Prefixes are often structured, but not always; retaining eight bytes in
    every log and audit row unnecessarily turns the logging system into a
    partial-secret store. ``keep`` remains for call compatibility and is
    intentionally ignored.
    """
    if not value:
        return "<empty>"
    return "<redacted>"


class VaultClient:
    """hvac-backed KV v2 client.

    hvac has no native asyncio support; calls are synchronous/blocking.
    Rotation cadence here is minutes and API traffic is low-volume internal
    admin calls, so blocking calls are accepted rather than adding a
    thread-pool wrapper or an extra dependency.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client: Optional[hvac.Client] = None
        self._next_token_check = 0.0

    def _get_client(self) -> hvac.Client:
        if self._client is None:
            # requests.Session honors HTTP_PROXY by default. Vault traffic
            # carries X-Vault-Token and plaintext secret values on writes, so
            # it must never be diverted by ambient container proxy variables.
            # hvac also follows redirects by default and requests does not
            # strip custom X-Vault-Token headers cross-origin; disable both.
            session = requests.Session()
            session.trust_env = False
            self._client = hvac.Client(
                url=self._settings.vault_addr,
                token=self._settings.vault_token,
                session=session,
                allow_redirects=False,
                timeout=10,
            )
        return self._client

    def _ensure_authenticated(self, *, force: bool = False) -> None:
        """Verify the Vault token and renew a renewable lease before expiry.

        The deployed rotator token is periodic. Merely checking Vault's
        unauthenticated initialization endpoint reports a false ready state
        for a missing/expired token, and never renewing it makes rotations
        fail after the token period. Check at most hourly on normal I/O.
        """
        now = time.monotonic()
        if not force and now < self._next_token_check:
            return

        client = self._get_client()
        if not self._settings.vault_token:
            raise VaultError("VAULT_TOKEN is unset")
        try:
            response = client.auth.token.lookup_self()
            data = response.get("data") or {}
            if not data:
                raise RuntimeError("lookup-self response had no token data")
            ttl = int(data.get("ttl") or 0)
            if data.get("renewable") and ttl <= TOKEN_RENEW_BEFORE_SECONDS:
                client.auth.token.renew_self()
                logger.info("renewed renewable Vault token lease")
            self._next_token_check = now + TOKEN_CHECK_INTERVAL_SECONDS
        except Exception as exc:  # noqa: BLE001
            # Retry authentication on the very next operation rather than
            # caching a failed probe for an hour.
            self._next_token_check = 0.0
            raise VaultError(
                f"Vault token authentication/renewal failed: {exc}"
            ) from exc

    async def connect_with_retry(self, max_wait_seconds: int = 60) -> bool:
        """Best-effort readiness probe with backoff, capped at
        `max_wait_seconds`. Vault being unreachable at boot is not fatal —
        drivers already treat "no secret" as "disabled", so the service
        starts degraded and picks Vault back up on the next scheduled run.
        """
        delay = 1.0
        waited = 0.0
        while waited < max_wait_seconds:
            try:
                client = self._get_client()
                if client.sys.is_initialized() and not client.sys.is_sealed():
                    self._ensure_authenticated(force=True)
                    logger.info("connected to vault")
                    return True
            except Exception as exc:  # noqa: BLE001
                logger.warning("vault not ready (%s), retrying in %.1fs", exc, delay)
            await asyncio.sleep(delay)
            waited += delay
            delay = min(delay * 2, 10.0)
        logger.error(
            "vault still unreachable after %ss; continuing in degraded mode",
            max_wait_seconds,
        )
        return False

    def read(self, path: str) -> Optional[dict[str, Any]]:
        """Read a KV v2 secret's data dict at logical `path` (e.g.
        "ai-gateway/vendors/anthropic" -> served over the wire at
        kv/data/ai-gateway/vendors/anthropic; hvac handles the "data/"
        prefix).

        Returns None ONLY when the path does not exist (an expected
        pre-bootstrap state). Raises VaultError on any actual error
        (transport/auth/sealed/...) so callers can distinguish "no secret
        written yet" from "vault is unreachable" — the latter must never be
        silently treated as empty during rotation.
        """
        self._ensure_authenticated()
        try:
            client = self._get_client()
            resp = client.secrets.kv.v2.read_secret_version(
                path=path, mount_point=MOUNT_POINT
            )
            return resp.get("data", {}).get("data")
        except InvalidPath:
            return None
        except Exception as exc:  # noqa: BLE001
            logger.warning("vault read failed for path=%s: %s", path, exc)
            raise VaultError(f"vault read failed for path={path}: {exc}") from exc

    def write(self, path: str, data: dict[str, Any]) -> bool:
        """Create-or-update a KV v2 secret at logical `path`. Returns True
        on success, False (logged) on any Vault error.

        Callers whose durability matters (rotation state, orphan records)
        MUST check the return value — a dropped write here silently forgets
        a live credential. Prefer `write_verified` for those paths.
        """
        try:
            self._ensure_authenticated()
        except VaultError as exc:
            logger.warning(
                "vault write authentication failed for path=%s: %s", path, exc
            )
            return False
        try:
            client = self._get_client()
            client.secrets.kv.v2.create_or_update_secret(
                path=path, secret=data, mount_point=MOUNT_POINT
            )
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("vault write failed for path=%s: %s", path, exc)
            return False

    def write_verified(
        self, path: str, data: dict[str, Any], attempts: int = 3
    ) -> bool:
        """Durably write `data`, then read it back to confirm it landed,
        retrying up to `attempts` times.

        Returns True only when a subsequent read shows every field that was
        written. Used for state whose loss would orphan a live credential
        (e.g. the openai rotation-state doc: the old service-account id +
        the pending-revocation orphan list). A plain `write()` returning
        True is not sufficient proof of durability under a flaky vault, so
        this closes the loop with a read-back.
        """
        last_problem = ""
        for attempt in range(1, attempts + 1):
            if not self.write(path, data):
                last_problem = "write returned False"
                logger.warning(
                    "vault write_verified: write failed for path=%s (attempt %s/%s)",
                    path,
                    attempt,
                    attempts,
                )
                continue
            try:
                readback = self.read(path)
            except VaultError as exc:
                last_problem = f"read-back error: {exc}"
                logger.warning(
                    "vault write_verified: read-back failed for path=%s (attempt %s/%s): %s",
                    path,
                    attempt,
                    attempts,
                    exc,
                )
                continue
            if readback is not None and all(
                readback.get(k) == v for k, v in data.items()
            ):
                return True
            last_problem = "read-back did not match written data"
            logger.warning(
                "vault write_verified: read-back mismatch for path=%s (attempt %s/%s)",
                path,
                attempt,
                attempts,
            )
        logger.error(
            "vault write_verified: giving up on path=%s (%s)", path, last_problem
        )
        return False

    def delete_verified(self, path: str, attempts: int = 3) -> bool:
        """Permanently delete a KV v2 document and verify it is absent.

        Provider enrollment deletion is a security lifecycle transition, not
        a recoverable edit.  Remove metadata and every version so an old
        enrollment cannot be undeleted later, then prove a normal read sees a
        missing path.  As with :meth:`write_verified`, callers must treat a
        ``False`` result as a failed transition.
        """
        last_problem = ""
        for attempt in range(1, attempts + 1):
            try:
                self._ensure_authenticated()
                client = self._get_client()
                client.secrets.kv.v2.delete_metadata_and_all_versions(
                    path=path, mount_point=MOUNT_POINT
                )
            except Exception as exc:  # noqa: BLE001
                last_problem = f"delete error: {exc}"
                logger.warning(
                    "vault delete_verified: delete failed for path=%s (attempt %s/%s): %s",
                    path,
                    attempt,
                    attempts,
                    exc,
                )
                continue
            try:
                if self.read(path) is None:
                    return True
                last_problem = "read-back still found the deleted path"
            except VaultError as exc:
                # An unavailable/auth-failed read cannot prove deletion.
                last_problem = f"read-back error: {exc}"
            logger.warning(
                "vault delete_verified: deletion not verified for path=%s "
                "(attempt %s/%s)",
                path,
                attempt,
                attempts,
            )
        logger.error(
            "vault delete_verified: giving up on path=%s (%s)", path, last_problem
        )
        return False

    def ready(self) -> bool:
        """Return true only for initialized, unsealed, authenticated Vault.

        ``/healthz`` remains process liveness; this readiness boundary is what
        lets the deployment distinguish a legitimate first-boot bootstrap gate
        from a fully operational rotator.
        """
        try:
            client = self._get_client()
            if not client.sys.is_initialized() or client.sys.is_sealed():
                return False
            self._ensure_authenticated()
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("vault readiness probe failed: %s", exc)
            return False

    def public_status(self) -> dict[str, bool]:
        """Return only Vault's authenticated-data-free initialization state.

        This deliberately uses the public ``sys/health`` response without the
        rotator token.  The admin portal consumes it only to render a bounded
        sealed-maintenance page when the live identity decision is impossible;
        every other transport, status, or payload inconsistency fails closed.
        """

        session = requests.Session()
        session.trust_env = False
        try:
            response = session.get(
                self._settings.vault_addr.rstrip("/") + "/v1/sys/health",
                params={"standbyok": "true", "perfstandbyok": "true"},
                headers={"User-Agent": "aigw-key-rotator-vault-status"},
                allow_redirects=False,
                timeout=5,
            )
        except requests.RequestException as exc:
            raise VaultError("Vault public status unavailable") from exc
        finally:
            session.close()

        if response.status_code not in PUBLIC_HEALTH_STATUSES:
            raise VaultError("Vault public status unavailable")
        try:
            payload = response.json()
        except ValueError as exc:
            raise VaultError("Vault public status unavailable") from exc
        if not isinstance(payload, dict):
            raise VaultError("Vault public status unavailable")
        initialized = payload.get("initialized")
        sealed = payload.get("sealed")
        if not isinstance(initialized, bool) or not isinstance(sealed, bool):
            raise VaultError("Vault public status unavailable")

        if response.status_code == 501:
            valid = not initialized and sealed
        elif response.status_code == 503:
            valid = initialized and sealed
        else:
            valid = initialized and not sealed
        if not valid:
            raise VaultError("Vault public status unavailable")
        return {"initialized": initialized, "sealed": sealed}

    def close(self) -> None:
        """Close the underlying requests session without revoking the token."""
        if self._client is not None:
            self._client.adapter.close()
