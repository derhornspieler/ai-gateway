"""OpenAI driver — blue/green service-account rotation.

Design ref: docs/solution-map.md §1.7 ("OpenAI — blue/green service-account
rotation (static keys, fully automated)"):

  1. Create a new service account via
     POST {EGRESS_BASE}/openai/v1/organization/projects/{project_id}/service_accounts
     (Authorization: Bearer <admin key>) — capture the unredacted
     api_key.value (only moment the plaintext exists).
  2. Canary-verify the new key: GET {EGRESS_BASE}/openai/v1/models,
     expect 200.
  3. Write the new key to Vault + record the new service account id,
     PATCH the "openai-primary" LiteLLM credential.
  4. Soak for grace_seconds.
  5. DELETE the *previous* run's service account (id read from Vault
     "ai-gateway/openai-state" before this run's writes), then verify the
     previous key now 401s (retry with backoff — revocation propagation
     is not documented as guaranteed-instant).
  6. Promote this run's service account id into "ai-gateway/openai-state"
     for the next rotation to clean up.

If step 5 fails (delete error, or the old key still authenticates after
grace+retries), the rotation does NOT report "success": it returns
status "rotated_pending_revocation" and records the old service account
id + key under "orphans" in the openai-state Vault doc. The scheduler's
recurring cleanup job (app/scheduler.py "sys_openai_orphan_cleanup",
interval OPENAI_ORPHAN_CLEANUP_INTERVAL_SECONDS) retries delete +
revocation-verification until each orphan is confirmed dead, and raises
the "openai.orphaned_credentials" health alert while any live-key orphan
remains.

Long-lived credential: the OpenAI admin key itself (read from Vault
"ai-gateway/openai-admin"), which is out of scope for this driver to
rotate (docs/solution-map.md §1.7 notes it is separately rotatable via
`/v1/organization/admin_api_keys`, not implemented here).
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx

from app import health
from app.drivers.base import BaseDriver, DriverContext, RotationResult
from app.security import path_segment
from app.vault_client import VaultError, mask_secret

logger = logging.getLogger("key_rotator.drivers.openai_svcacct")

STATE_VAULT_PATH = "ai-gateway/openai-state"
PENDING_PROMOTION_FIELD = "pending_promotion"

DEFAULT_GRACE_SECONDS = 300
# NOTE: the default grace/soak window is 300s per design. For local/manual
# testing, set a shorter grace_seconds via PUT /settings/openai (e.g. 30s)
# rather than hardcoding a cap here — production should keep the
# admin-configured value from rotator_settings.

MAX_REVOKE_VERIFY_ATTEMPTS = 5


class OpenAISvcAcctDriver(BaseDriver):
    name = "openai"

    async def rotate(self, ctx: DriverContext) -> RotationResult:
        # Preflight reads. A missing path is fine (returns None => disabled/
        # first-rotation), but an actual Vault READ error must NOT be
        # treated as "empty": doing so makes prev-state look absent and the
        # old, still-live service account gets forgotten with no teardown
        # and no orphan record. Fail loudly and keep the old credential.
        try:
            admin_cfg = ctx.vault.read("ai-gateway/openai-admin")
            # Capture the currently-active key + service account id *before*
            # we overwrite anything, so we can verify revocation later.
            prev_vendor_doc = ctx.vault.read("ai-gateway/vendors/openai") or {}
            prev_state = ctx.vault.read(STATE_VAULT_PATH) or {}
        except VaultError as exc:
            detail = (
                f"vault read error during rotation preflight ({exc}); aborting so the "
                "old service-account reference is not lost — will retry next interval"
            )
            logger.error("openai_svcacct: %s", detail)
            health.set_alert("openai.rotation", detail)
            await ctx.db.record_history(self.name, "rotate", "failed", detail)
            return RotationResult(status="failed", detail=detail)

        if not admin_cfg or "admin_api_key" not in admin_cfg or "project_id" not in admin_cfg:
            detail = "openai-admin config (admin_api_key/project_id) missing in vault"
            logger.info("openai_svcacct: %s", detail)
            return RotationResult(status="disabled", detail=detail)

        admin_key = admin_cfg["admin_api_key"]
        configured_project_id = admin_cfg["project_id"]

        # Orphans left by earlier failed teardowns MUST be carried forward,
        # never dropped — each holds a possibly-still-live key.
        orphans: list[dict[str, Any]] = list(prev_state.get("orphans") or [])

        configured_grace = ctx.vendor_settings.get("grace_seconds")
        grace_seconds = (
            DEFAULT_GRACE_SECONDS if configured_grace is None else max(0, int(configured_grace))
        )

        # Promotion is a resumable state machine. In the old flow the vendor
        # doc was overwritten and then LiteLLM was called. A timeout at that
        # exact point left the new account live but its id absent from state;
        # the next run paired its key with the *previous* account id and could
        # delete/track the wrong credential. Persist both sides of the swap
        # first, then replay the same candidate until promotion is certain.
        pending = prev_state.get(PENDING_PROMOTION_FIELD)
        if pending is not None:
            if not isinstance(pending, dict) or not all(
                isinstance(pending.get(field), str) and pending.get(field)
                for field in ("new_service_account_id", "new_api_key", "project_id")
            ):
                detail = "malformed pending OpenAI promotion state in vault; refusing to mint another account"
                logger.error("openai_svcacct: %s", detail)
                health.set_alert("openai.rotation", detail)
                return RotationResult(status="failed", detail=detail)
            new_sa_id = pending["new_service_account_id"]
            new_key = pending["new_api_key"]
            project_id = pending["project_id"]
            old_sa_id = pending.get("previous_service_account_id") or None
            old_key = pending.get("previous_api_key") or None
            old_project_id = (
                pending.get("previous_project_id") or project_id
            )
            logger.warning(
                "openai_svcacct: resuming durable pending promotion for service account=%s",
                new_sa_id,
            )
            if not await self._canary_check(ctx, new_key):
                detail = (
                    f"pending service account {new_sa_id} failed canary; leaving it tracked "
                    "without minting a replacement because an earlier LiteLLM timeout may have applied"
                )
                logger.error("openai_svcacct: %s", detail)
                health.set_alert("openai.rotation", detail)
                return RotationResult(status="failed", detail=detail)
        else:
            project_id = configured_project_id
            old_key = prev_vendor_doc.get("api_key")
            old_sa_id = prev_state.get("service_account_id")
            old_project_id = (
                prev_state.get("project_id")
                or prev_vendor_doc.get("project_id")
                or project_id
            )
            try:
                new_sa_id, new_key = await self._create_service_account(ctx, admin_key, project_id)
            except Exception as exc:  # noqa: BLE001
                detail = f"service account creation failed: {exc}"
                logger.error("openai_svcacct: %s", detail)
                await ctx.db.record_history(self.name, "rotate", "failed", detail)
                return RotationResult(status="failed", detail=detail)

            if not await self._canary_check(ctx, new_key):
                detail = f"canary check (GET /v1/models) failed for new service account {new_sa_id}"
                logger.error("openai_svcacct: %s", detail)
                # Don't leak the just-created (never-promoted) account. A 2xx
                # DELETE alone is not enough: this driver already treats key
                # revocation as eventually consistent, so verify the key is
                # dead or durably track it for cleanup.
                rollback_deleted = False
                try:
                    await self._delete_service_account(ctx, admin_key, project_id, new_sa_id)
                    rollback_deleted = True
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code == 404:
                        rollback_deleted = True
                    else:
                        logger.error(
                            "openai_svcacct: failed to delete canary-failed service account %s: %s",
                            new_sa_id,
                            exc,
                        )
                except Exception as exc:  # noqa: BLE001
                    logger.error(
                        "openai_svcacct: failed to delete canary-failed service account %s: %s",
                        new_sa_id,
                        exc,
                    )

                rollback_revoked = rollback_deleted and await self._verify_old_key_revoked(
                    ctx, new_key
                )
                if not rollback_revoked:
                    orphans.append(
                        {
                            "service_account_id": new_sa_id,
                            "api_key": new_key,
                            "project_id": project_id,
                            "deleted": rollback_deleted,
                            "first_seen": datetime.now(timezone.utc).isoformat(),
                        }
                    )
                    if not ctx.vault.write_verified(
                        STATE_VAULT_PATH, {**prev_state, "orphans": orphans}
                    ):
                        crit = (
                            f"CRITICAL: could not durably record orphan for canary-failed service "
                            f"account {new_sa_id}; it may remain live and untracked — manual cleanup required"
                        )
                        logger.error("openai_svcacct: %s", crit)
                        health.set_alert("openai.rotation", crit)
                    health.set_alert(
                        "openai.orphaned_credentials",
                        f"{len(orphans)} old service account(s) pending revocation "
                        f"(latest: {new_sa_id}); cleanup job will retry",
                    )
                await ctx.db.record_history(self.name, "rotate", "failed", detail)
                return RotationResult(status="failed", detail=detail)

            pending = {
                "new_service_account_id": new_sa_id,
                "new_api_key": new_key,
                "previous_service_account_id": old_sa_id,
                "previous_api_key": old_key,
                "previous_project_id": old_project_id,
                "project_id": project_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            pending_state = {
                **prev_state,
                "orphans": orphans,
                PENDING_PROMOTION_FIELD: pending,
            }
            if not ctx.vault.write_verified(STATE_VAULT_PATH, pending_state):
                detail = (
                    f"CRITICAL: could not durably record pending service account {new_sa_id}; "
                    "not promoting it"
                )
                logger.error("openai_svcacct: %s", detail)
                health.set_alert("openai.rotation", detail)
                try:
                    await self._delete_service_account(ctx, admin_key, project_id, new_sa_id)
                except Exception as exc:  # noqa: BLE001
                    logger.critical(
                        "openai_svcacct: untracked service account %s may remain live after "
                        "Vault and rollback failure: %s; manual cleanup required",
                        new_sa_id,
                        exc,
                    )
                return RotationResult(status="failed", detail=detail)

        # The pending state above is the recovery anchor. The active vendor
        # document may now be updated without losing the old id/key pairing.
        if not ctx.vault.write_verified(
            "ai-gateway/vendors/openai",
            {
                "api_key": new_key,
                "service_account_id": new_sa_id,
                "project_id": project_id,
            },
        ):
            detail = (
                f"could not update the OpenAI vendor document for pending service account {new_sa_id}; "
                "the durable pending marker is retained and the same account will be retried"
            )
            logger.error("openai_svcacct: %s", detail)
            health.set_alert("openai.rotation", detail)
            return RotationResult(status="failed", detail=detail)

        try:
            await ctx.litellm.upsert_credential("openai-primary", {"api_key": new_key})
        except Exception as exc:  # noqa: BLE001
            detail = (
                f"LiteLLM promotion failed for pending service account {new_sa_id}: {exc}; "
                "the durable pending marker is retained and the same account will be retried"
            )
            logger.error("openai_svcacct: %s", detail)
            health.set_alert("openai.rotation", detail)
            return RotationResult(status="failed", detail=detail)
        logger.info(
            "openai_svcacct: promoted new service account=%s, soaking for grace_seconds=%s",
            new_sa_id,
            grace_seconds,
        )

        await asyncio.sleep(grace_seconds)

        detail_parts = [f"created+promoted service account {new_sa_id}"]
        teardown_clean = True

        if old_sa_id:
            old_deleted = False
            try:
                await self._delete_service_account(
                    ctx, admin_key, old_project_id, old_sa_id
                )
                old_deleted = True
                detail_parts.append(f"deleted old service account {old_sa_id}")
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 404:
                    old_deleted = True  # already gone — nothing left to kill
                    detail_parts.append(f"old service account {old_sa_id} already deleted (404)")
                else:
                    teardown_clean = False
                    err = f"failed to delete old service account {old_sa_id}: {exc}"
                    logger.error("openai_svcacct: %s", err)
                    detail_parts.append(err)
            except Exception as exc:  # noqa: BLE001
                teardown_clean = False
                err = f"failed to delete old service account {old_sa_id}: {exc}"
                logger.error("openai_svcacct: %s", err)
                detail_parts.append(err)

            if old_key:
                if old_deleted and await self._verify_old_key_revoked(ctx, old_key):
                    detail_parts.append("old key confirmed revoked (401)")
                else:
                    teardown_clean = False
                    err = (
                        f"old key ({mask_secret(old_key)}) for service account {old_sa_id} "
                        "NOT confirmed revoked"
                    )
                    logger.error("openai_svcacct: %s", err)
                    detail_parts.append(err)

            if not teardown_clean:
                # Remember the still-live (or unverified) old credential so
                # the cleanup job can retry — forgetting it here is exactly
                # the leak this driver exists to prevent.
                orphans.append(
                    {
                        "service_account_id": old_sa_id,
                        "api_key": old_key,
                        "project_id": old_project_id,
                        "deleted": old_deleted,
                        "first_seen": datetime.now(timezone.utc).isoformat(),
                    }
                )
        else:
            detail_parts.append("no previous service account recorded (first rotation)")

        # Persist the new sa id + carried-forward orphans. This is the
        # single most important durable write in the rotation: if it is
        # lost, the account we just made "old" is forgotten and never torn
        # down. Verify it landed; on failure this is a rotation FAILURE
        # (pending revocation), not a silent success.
        state_doc = {
            **prev_state,
            "service_account_id": new_sa_id,
            "project_id": project_id,
            "orphans": orphans,
        }
        state_doc.pop(PENDING_PROMOTION_FIELD, None)
        if not ctx.vault.write_verified(STATE_VAULT_PATH, state_doc):
            crit = (
                f"rotated to new service account {new_sa_id} but could not finalize rotation "
                "state in vault; the durable pending marker retains both account/key pairs "
                "and the same transition will be retried"
            )
            logger.error("openai_svcacct: %s", crit)
            health.set_alert("openai.rotation", crit)
            if orphans:
                health.set_alert(
                    "openai.orphaned_credentials",
                    f"{len(orphans)} old service account(s) pending revocation "
                    f"but rotation state write failed (latest: {old_sa_id})",
                )
            detail_parts.append(crit)
            detail = "; ".join(detail_parts)
            await ctx.db.record_history(self.name, "alert", "rotated_pending_revocation", detail)
            return RotationResult(status="rotated_pending_revocation", detail=detail)

        detail = "; ".join(detail_parts)
        if orphans:
            health.set_alert(
                "openai.orphaned_credentials",
                f"{len(orphans)} old service account(s) pending revocation "
                f"(latest: {old_sa_id}); cleanup job will retry",
            )
        if not teardown_clean:
            logger.error("openai_svcacct: %s", detail)
            await ctx.db.record_history(self.name, "alert", "rotated_pending_revocation", detail)
            return RotationResult(status="rotated_pending_revocation", detail=detail)

        # Rotation mechanics healthy: state durably persisted, old key
        # confirmed revoked, no orphans introduced.
        health.set_ok("openai.rotation")
        logger.info("openai_svcacct: %s", detail)
        return RotationResult(status="success", detail=detail)

    async def cleanup_orphans(self, ctx: DriverContext) -> None:
        """Retry teardown of orphaned service accounts recorded by earlier
        failed rotations: DELETE any not-yet-deleted account, then verify
        its key 401s. Confirmed-dead orphans are dropped from the state
        doc; anything still live keeps the health alert raised. Runs from
        the scheduler's recurring "sys_openai_orphan_cleanup" job (which
        holds the openai vendor lock, so it never races a rotation).
        """
        try:
            state = ctx.vault.read(STATE_VAULT_PATH) or {}
        except VaultError as exc:
            # Do not clear the alert on a read error — we can't prove the
            # orphans are gone, so keep them "pending" and retry next pass.
            logger.error("openai_svcacct: orphan cleanup vault read failed: %s", exc)
            health.set_alert(
                "openai.orphaned_credentials",
                f"orphan cleanup could not read rotation state from vault: {exc}",
            )
            return
        orphans: list[dict[str, Any]] = list(state.get("orphans") or [])
        if not orphans:
            health.set_ok("openai.orphaned_credentials")
            return

        try:
            admin_cfg = ctx.vault.read("ai-gateway/openai-admin")
        except VaultError as exc:
            logger.error("openai_svcacct: orphan cleanup vault read (admin) failed: %s", exc)
            return
        if not admin_cfg or "admin_api_key" not in admin_cfg or "project_id" not in admin_cfg:
            logger.error(
                "openai_svcacct: %d orphan(s) pending but openai-admin config missing in vault",
                len(orphans),
            )
            return
        admin_key = admin_cfg["admin_api_key"]
        project_id = admin_cfg["project_id"]

        remaining: list[dict[str, Any]] = []
        for orphan in orphans:
            sa_id = orphan.get("service_account_id")
            orphan_project_id = orphan.get("project_id") or project_id
            if not orphan.get("deleted") and sa_id:
                try:
                    await self._delete_service_account(
                        ctx, admin_key, orphan_project_id, sa_id
                    )
                    orphan["deleted"] = True
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code == 404:
                        orphan["deleted"] = True
                    else:
                        logger.error(
                            "openai_svcacct: orphan cleanup delete failed for %s: %s", sa_id, exc
                        )
                except Exception as exc:  # noqa: BLE001
                    logger.error(
                        "openai_svcacct: orphan cleanup delete failed for %s: %s", sa_id, exc
                    )

            old_key = orphan.get("api_key")
            if old_key:
                revoked = bool(orphan.get("deleted")) and await self._verify_old_key_revoked(
                    ctx, old_key
                )
            else:
                revoked = bool(orphan.get("deleted"))
            if revoked:
                msg = f"orphaned service account {sa_id} confirmed dead"
                logger.info("openai_svcacct: %s", msg)
                await ctx.db.record_history(self.name, "cleanup", "success", msg)
            else:
                remaining.append(orphan)

        state["orphans"] = remaining
        if not ctx.vault.write_verified(STATE_VAULT_PATH, state):
            # Couldn't persist the shortened orphan list. Keep the alert
            # raised (do NOT claim success) — a dropped write here would
            # re-introduce already-torn-down orphans, but more importantly
            # must not report the still-pending ones as resolved.
            crit = "orphan cleanup could not persist updated rotation state to vault"
            logger.error("openai_svcacct: %s", crit)
            health.set_alert("openai.orphaned_credentials", crit)
            await ctx.db.record_history(self.name, "cleanup", "failed", crit)
            return

        if remaining:
            health.set_alert(
                "openai.orphaned_credentials",
                f"{len(remaining)} old service account(s) still pending revocation after cleanup pass",
            )
            await ctx.db.record_history(
                self.name,
                "cleanup",
                "failed",
                f"{len(remaining)} orphan(s) still pending revocation",
            )
        else:
            health.set_ok("openai.orphaned_credentials")

    async def _create_service_account(
        self, ctx: DriverContext, admin_key: str, project_id: str
    ) -> tuple[str, str]:
        name = f"aigw-{datetime.now(timezone.utc):%Y%m%d}-{uuid.uuid4().hex[:8]}"
        safe_project_id = path_segment(project_id, label="OpenAI project id")
        url = (
            f"{ctx.settings.openai_base}/v1/organization/projects/"
            f"{safe_project_id}/service_accounts"
        )
        async with httpx.AsyncClient(
            timeout=30.0, trust_env=False, follow_redirects=False
        ) as client:
            resp = await client.post(
                url, json={"name": name}, headers={"Authorization": f"Bearer {admin_key}"}
            )
            resp.raise_for_status()
            payload: dict[str, Any] = resp.json()
            sa_id = payload.get("id")
            api_key = (payload.get("api_key") or {}).get("value")
            if not sa_id or not api_key:
                raise RuntimeError("service account creation response missing id/api_key.value")
            return sa_id, api_key

    async def _canary_check(self, ctx: DriverContext, api_key: str) -> bool:
        url = f"{ctx.settings.openai_base}/v1/models"
        async with httpx.AsyncClient(
            timeout=15.0, trust_env=False, follow_redirects=False
        ) as client:
            try:
                resp = await client.get(url, headers={"Authorization": f"Bearer {api_key}"})
                return resp.status_code == 200
            except Exception as exc:  # noqa: BLE001
                logger.warning("openai_svcacct: canary request error: %s", exc)
                return False

    async def _delete_service_account(
        self, ctx: DriverContext, admin_key: str, project_id: str, sa_id: str
    ) -> None:
        safe_project_id = path_segment(project_id, label="OpenAI project id")
        safe_sa_id = path_segment(sa_id, label="OpenAI service account id")
        url = (
            f"{ctx.settings.openai_base}/v1/organization/projects/{safe_project_id}/"
            f"service_accounts/{safe_sa_id}"
        )
        async with httpx.AsyncClient(
            timeout=30.0, trust_env=False, follow_redirects=False
        ) as client:
            resp = await client.delete(url, headers={"Authorization": f"Bearer {admin_key}"})
            resp.raise_for_status()

    async def _verify_old_key_revoked(
        self, ctx: DriverContext, old_key: str, max_attempts: int = MAX_REVOKE_VERIFY_ATTEMPTS
    ) -> bool:
        """Poll GET /v1/models with the old key until it 401s, retrying
        with backoff since revocation propagation is not documented as
        guaranteed-instant. Returns False (logged by caller as a warning)
        if the key is still accepted after all attempts.
        """
        url = f"{ctx.settings.openai_base}/v1/models"
        delay = 2.0
        async with httpx.AsyncClient(
            timeout=15.0, trust_env=False, follow_redirects=False
        ) as client:
            for attempt in range(1, max_attempts + 1):
                try:
                    resp = await client.get(url, headers={"Authorization": f"Bearer {old_key}"})
                    if resp.status_code == 401:
                        return True
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "openai_svcacct: old-key verify request error (attempt %s/%s): %s",
                        attempt,
                        max_attempts,
                        exc,
                    )
                await asyncio.sleep(delay)
                delay = min(delay * 2, 30.0)
        return False
