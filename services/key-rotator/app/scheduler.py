"""Rotation scheduler for key-rotator (APScheduler AsyncIOScheduler).

Design ref: docs/solution-map.md §1.7 "Rotation control from the admin
portal" — per-vendor rotation interval + grace/soak windows stored in
Postgres (rotator_settings), hot-applied to the scheduler; "rotate now"
per vendor; pause/resume. Also implements the Anthropic driver's dynamic
next-run request (refresh at ~80% of token lifetime, see
docs/anthropic-wif-bootstrap.md Phase 1 step 3 / app/drivers/anthropic_wif.py).

Job semantics:
  - enabled=false            -> no job scheduled (removed if present).
  - enabled=true, interval>0 -> IntervalTrigger(seconds=interval).
  - enabled=true, interval==0 -> Vault-gated DateTrigger lifecycle. Run once
    after readiness unless the driver explicitly requests a dynamic next run
    (used for static-* seeds and supported for drivers such as anthropic).
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import math
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from apscheduler.jobstores.base import JobLookupError
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.date import DateTrigger
from apscheduler.triggers.interval import IntervalTrigger
from opentelemetry.trace import Status, StatusCode

from app import health
from app.config import Settings
from app.db import Database
from app.drivers.base import DriverContext, RotationResult
from app.jwks_watcher import AnthropicJwksWatcher
from app.litellm_client import (
    KEY_LIST_PAGE_SIZE,
    LiteLLMClient,
    PortalKeyBinding,
    PortalKeyInventoryPage,
)
from app.vault_client import VaultClient

logger = logging.getLogger("key_rotator.scheduler")

JOB_PREFIX = "rotate_"
# System (non-vendor) recurring jobs — outside JOB_PREFIX so reload()'s
# vendor-row reconcile never touches them.
JWKS_WATCH_JOB_ID = "sys_jwks_watch"
OPENAI_CLEANUP_JOB_ID = "sys_openai_orphan_cleanup"
SETTINGS_RECOVERY_JOB_ID = "sys_settings_recovery"
PORTAL_KEY_RECONCILE_JOB_ID = "sys_portal_key_reconciliation"
PORTAL_KEY_RECONCILE_LOCK = "portal-key-reconciliation"
PORTAL_KEY_RECONCILE_HEALTH = "identity.portal_key_reconciliation"
# A pseudo-vendor row in the existing durable settings table. It is never a
# schedulable credential driver; it only holds a no-secret global scan cursor.
PORTAL_KEY_RECONCILE_STATE_VENDOR = "portal-key-reconciliation-state"
# Match the former 10,000-key inventory bound without making it an alert-only
# cap. Additional pages resume from the durable cursor on the next cadence.
PORTAL_KEY_RECONCILE_PAGES_PER_RUN = 100
PORTAL_KEY_RECONCILE_DIGEST_SEED = hashlib.sha256(
    b"aigw-portal-key-reconcile-v1\0"
).hexdigest()

# A zero-interval job is a process-lifetime one-shot, but a sealed/unavailable
# Vault is a deployment state rather than a completed attempt. Poll readiness
# slowly enough to avoid a boot-time tight loop. Once a driver runs, only an
# explicit ``next_run_seconds`` requests another attempt; generic failures are
# terminal so permanent provider/auth faults cannot flood rotation_history.
ONESHOT_READINESS_RETRY_SECONDS = 30.0
MIN_DYNAMIC_DELAY_SECONDS = 5.0
MAX_DYNAMIC_DELAY_SECONDS = 365.0 * 86400.0


@dataclass(frozen=True)
class _PortalKeyReconcileCursor:
    """Durable, non-sensitive checkpoint for a global LiteLLM scan."""

    phase: str
    next_page: int
    expected_total_count: int
    expected_total_pages: int
    scan_digest: str
    reference_digest: str | None
    had_access_error: bool

    def as_config(self) -> dict[str, int | bool | str | None]:
        return {
            "phase": self.phase,
            "next_page": self.next_page,
            "expected_total_count": self.expected_total_count,
            "expected_total_pages": self.expected_total_pages,
            "scan_digest": self.scan_digest,
            "reference_digest": self.reference_digest,
            "had_access_error": self.had_access_error,
        }


class _NullSpan:
    """No-op context manager used when the OTel tracer is unavailable."""

    def __enter__(self) -> None:
        return None

    def __exit__(self, *exc: Any) -> bool:
        return False


class RotationScheduler:
    def __init__(
        self,
        settings: Settings,
        db: Database,
        vault: VaultClient,
        litellm: LiteLLMClient,
        drivers: dict[str, Any],
        *,
        identity: Any | None = None,
    ) -> None:
        self._settings = settings
        self._db = db
        self._vault = vault
        self._litellm = litellm
        self._drivers = drivers
        self._identity = identity
        self._scheduler = AsyncIOScheduler()
        # Per-vendor mutual exclusion: manual (POST /rotate/{vendor}) and
        # scheduled runs both execute run_rotation in this one process, so
        # an asyncio.Lock per vendor is sufficient. A second concurrent
        # attempt fails fast (skip/409), it does not queue.
        self._vendor_locks: dict[str, asyncio.Lock] = {}
        # Vendors whose interval==0 lifecycle has been armed this process
        # lifetime.  The canonical DateTrigger is absent while APScheduler is
        # executing it, so this latch -- not job-store presence -- prevents a
        # concurrent settings reload from creating a duplicate.  It remains
        # set after a terminal outcome and is cleared on disable or when the
        # row leaves zero-interval mode, allowing a genuine later re-entry.
        self._oneshot_scheduled: set[str] = set()
        self._jwks_watcher: Optional[AnthropicJwksWatcher] = None
        if "anthropic" in drivers:
            self._jwks_watcher = AnthropicJwksWatcher(
                settings, db, vault, litellm, drivers["anthropic"]
            )

    def _lock_for(self, vendor: str) -> asyncio.Lock:
        domain = self._lock_domain(vendor)
        lock = self._vendor_locks.get(domain)
        if lock is None:
            lock = self._vendor_locks[domain] = asyncio.Lock()
        return lock

    @staticmethod
    def _lock_domain(vendor: str) -> str:
        """Map static seed and real drivers that own the same credential to
        one exclusion domain.

        ``static-openai`` and ``openai`` both write ``openai-primary`` (and
        likewise for Anthropic). Separate locks allowed an enable/rotation
        race to put the stale static key back after a successful rotation.
        """
        return vendor.removeprefix("static-")

    def is_rotating(self, vendor: str) -> bool:
        """True while a rotation (or the openai cleanup pass) holds the
        vendor's lock — used by POST /rotate/{vendor} to 409 fast.
        """
        return self._lock_for(vendor).locked()

    def start(self) -> None:
        self._scheduler.start()
        self._add_system_jobs()

    def _add_system_jobs(self) -> None:
        """Recurring non-vendor control-plane jobs.

        Alongside vendor credential maintenance, this reconciles portal-issued
        static LiteLLM keys against live Keycloak membership.  That covers
        out-of-band Keycloak ADM-console group changes, which cannot flow
        through the key-rotator's authoritative mutation path.
        """
        if self._jwks_watcher is not None:
            self._scheduler.add_job(
                self._jwks_watcher.check,
                trigger=IntervalTrigger(
                    seconds=max(30, self._settings.jwks_watch_interval_seconds)
                ),
                id=JWKS_WATCH_JOB_ID,
                replace_existing=True,
                max_instances=1,
                coalesce=True,
                misfire_grace_time=60,
            )
        if "openai" in self._drivers:
            self._scheduler.add_job(
                self._run_openai_orphan_cleanup,
                trigger=IntervalTrigger(
                    seconds=max(
                        60, self._settings.openai_orphan_cleanup_interval_seconds
                    )
                ),
                id=OPENAI_CLEANUP_JOB_ID,
                replace_existing=True,
                max_instances=1,
                coalesce=True,
                misfire_grace_time=300,
            )
        if self._identity is None:
            # Do not silently start a production scheduler without the direct
            # Keycloak ADM-console safety net. Unit callers that do not start
            # the scheduler remain free to exercise vendor scheduling alone.
            health.set_alert(
                PORTAL_KEY_RECONCILE_HEALTH,
                "portal-key reconciliation is not configured",
            )
        else:
            self._scheduler.add_job(
                self._run_portal_key_reconciliation,
                trigger=IntervalTrigger(
                    seconds=self._settings.portal_key_reconcile_interval_seconds
                ),
                id=PORTAL_KEY_RECONCILE_JOB_ID,
                replace_existing=True,
                max_instances=1,
                coalesce=True,
                misfire_grace_time=300,
                # Reconcile promptly after boot; interval-trigger defaults
                # would otherwise leave an out-of-band ADM change usable for
                # a full cadence after every restart.
                next_run_time=datetime.now(timezone.utc),
            )
        # Postgres may be unavailable during initial boot. Reconcile again
        # periodically so the service does not remain alive forever with no
        # vendor jobs after the DB recovers.
        self._scheduler.add_job(
            self._recover_schedule,
            trigger=IntervalTrigger(seconds=60),
            id=SETTINGS_RECOVERY_JOB_ID,
            replace_existing=True,
            max_instances=1,
            coalesce=True,
            misfire_grace_time=60,
        )
        logger.info(
            "system jobs scheduled (settings recovery, jwks watch, openai orphan cleanup, "
            "portal-key reconciliation)"
        )

    async def _recover_schedule(self) -> None:
        """Retry an empty boot schedule without perturbing healthy jobs.

        Calling ``reload`` every minute would replace interval jobs and move
        their next run forward forever. Only reconcile when no canonical
        vendor job currently exists; normal API settings updates still call
        ``reload`` immediately.
        """
        managed_job_ids = {f"{JOB_PREFIX}{vendor}" for vendor in self._drivers}
        if any(job.id in managed_job_ids for job in self._scheduler.get_jobs()):
            return
        await self.reload()

    async def _run_openai_orphan_cleanup(self) -> None:
        driver = self._drivers.get("openai")
        if driver is None or not hasattr(driver, "cleanup_orphans"):
            return
        lock = self._lock_for("openai")
        if lock.locked():
            # A rotation is in flight; it rewrites the same state doc.
            # Skip — the next cleanup interval retries.
            return
        async with lock:
            async with self._db.rotation_lock("openai") as acquired:
                if not acquired:
                    logger.info(
                        "openai orphan cleanup skipped; another instance holds the lock"
                    )
                    return
                row = await self._db.get_settings("openai") or {}
                ctx = DriverContext(
                    settings=self._settings,
                    vault=self._vault,
                    litellm=self._litellm,
                    db=self._db,
                    vendor_settings=row,
                )
                try:
                    await driver.cleanup_orphans(ctx)
                except Exception:  # noqa: BLE001
                    logger.exception("openai orphan cleanup pass failed")

    @staticmethod
    def _valid_reconcile_integer(value: Any) -> bool:
        return isinstance(value, int) and not isinstance(value, bool) and value >= 0

    @staticmethod
    def _valid_reconcile_digest(value: Any) -> bool:
        if not isinstance(value, str) or len(value) != 64 or value != value.lower():
            return False
        try:
            bytes.fromhex(value)
        except ValueError:
            return False
        return True

    @staticmethod
    def _roll_portal_key_inventory_digest(previous: str, page_digest: str) -> str:
        """Extend an ordered, no-secret inventory consistency witness."""

        if not (
            RotationScheduler._valid_reconcile_digest(previous)
            and RotationScheduler._valid_reconcile_digest(page_digest)
        ):
            raise RuntimeError("portal-key reconciliation inventory digest is invalid")
        digest = hashlib.sha256(b"aigw-portal-key-sweep-v1\0")
        digest.update(bytes.fromhex(previous))
        digest.update(bytes.fromhex(page_digest))
        return digest.hexdigest()

    @classmethod
    def _read_portal_key_reconcile_cursor(
        cls, row: dict[str, Any] | None
    ) -> _PortalKeyReconcileCursor | None:
        """Parse a pseudo-vendor state row without trusting a stale cursor."""

        if row is None:
            return None
        config = row.get("config")
        if config == {}:
            return None
        if not isinstance(config, dict) or set(config) != {
            "phase",
            "next_page",
            "expected_total_count",
            "expected_total_pages",
            "scan_digest",
            "reference_digest",
            "had_access_error",
        }:
            raise RuntimeError("portal-key reconciliation cursor is invalid")

        phase = config["phase"]
        next_page = config["next_page"]
        total_count = config["expected_total_count"]
        total_pages = config["expected_total_pages"]
        scan_digest = config["scan_digest"]
        reference_digest = config["reference_digest"]
        had_access_error = config["had_access_error"]
        if (
            phase not in {"scan", "verify"}
            or not cls._valid_reconcile_integer(next_page)
            or not cls._valid_reconcile_integer(total_count)
            or not cls._valid_reconcile_integer(total_pages)
            or not cls._valid_reconcile_digest(scan_digest)
            or not isinstance(had_access_error, bool)
        ):
            raise RuntimeError("portal-key reconciliation cursor is invalid")

        expected_pages = (total_count + KEY_LIST_PAGE_SIZE - 1) // KEY_LIST_PAGE_SIZE
        if total_pages != expected_pages:
            raise RuntimeError("portal-key reconciliation cursor is invalid")
        if phase == "scan":
            if reference_digest is not None or next_page < 2 or next_page > total_pages:
                raise RuntimeError("portal-key reconciliation cursor is invalid")
        elif (
            not cls._valid_reconcile_digest(reference_digest)
            or (total_pages == 0 and next_page != 1)
            or (total_pages > 0 and (next_page < 1 or next_page > total_pages))
        ):
            raise RuntimeError("portal-key reconciliation cursor is invalid")
        return _PortalKeyReconcileCursor(
            phase=phase,
            next_page=next_page,
            expected_total_count=total_count,
            expected_total_pages=total_pages,
            scan_digest=scan_digest,
            reference_digest=reference_digest,
            had_access_error=had_access_error,
        )

    async def _save_portal_key_reconcile_state(
        self, state: _PortalKeyReconcileCursor | None
    ) -> None:
        """Persist a cursor only after a page's safe work has completed."""

        await self._db.upsert_settings(
            PORTAL_KEY_RECONCILE_STATE_VENDOR,
            False,
            0,
            0,
            {} if state is None else state.as_config(),
        )

    @staticmethod
    def _validate_portal_key_inventory_page(
        inventory: PortalKeyInventoryPage, requested_page: int
    ) -> None:
        """Defend the durable cursor against malformed LiteLLM responses."""

        if (
            not isinstance(inventory, PortalKeyInventoryPage)
            or inventory.page != requested_page
            or not RotationScheduler._valid_reconcile_integer(inventory.total_count)
            or not RotationScheduler._valid_reconcile_integer(inventory.total_pages)
            or not RotationScheduler._valid_reconcile_digest(inventory.inventory_digest)
        ):
            raise RuntimeError("portal-key reconciliation inventory is invalid")

        expected_pages = (
            inventory.total_count + KEY_LIST_PAGE_SIZE - 1
        ) // KEY_LIST_PAGE_SIZE
        if inventory.total_pages != expected_pages:
            raise RuntimeError("portal-key reconciliation inventory counters changed")
        if inventory.total_pages == 0:
            if requested_page != 1 or inventory.bindings:
                raise RuntimeError("portal-key reconciliation inventory is invalid")
        elif requested_page > inventory.total_pages:
            raise RuntimeError("portal-key reconciliation inventory is invalid")

    async def _reconcile_portal_key_page(
        self, bindings: tuple[PortalKeyBinding, ...]
    ) -> tuple[int, bool]:
        """Reconcile one page after positively resolving every owner's access.

        An identity lookup failure is an availability/control-plane uncertainty,
        not proof that a static key is unauthorized. Resolve all owners before
        blocking anything so a transient Keycloak, database, or network outage
        cannot turn one reconciliation page into a mass credential outage.
        """

        bindings_by_user: dict[str, list[PortalKeyBinding]] = {}
        for binding in bindings:
            bindings_by_user.setdefault(binding.user_id, []).append(binding)

        target_bindings: list[PortalKeyBinding] = []
        for user_id, user_bindings in bindings_by_user.items():
            try:
                live_projects = await self._identity.user_projects(user_id)
                if not isinstance(live_projects, list) or any(
                    not isinstance(project, str) for project in live_projects
                ):
                    raise RuntimeError(
                        "identity project lookup returned an invalid result"
                    )
            except Exception as exc:  # noqa: BLE001
                # Do not treat an unknown result as an empty project set. The
                # caller keeps the durable cursor at this page and the outer
                # handler alerts without logging customer identity data.
                raise RuntimeError(
                    "portal-key reconciliation could not verify identity access"
                ) from exc
            target_bindings.extend(
                binding
                for binding in user_bindings
                if binding.project_id not in live_projects
            )

        revoked_keys = 0
        revocation_failed = False
        for binding in target_bindings:
            try:
                await self._litellm.revoke_portal_key_binding(binding)
                revoked_keys += 1
            except Exception:  # noqa: BLE001
                # Continue attempting independent keys, but never checkpoint
                # this page unless each required block was positively verified.
                revocation_failed = True

        if revocation_failed:
            raise RuntimeError("portal-key reconciliation could not revoke every key")
        return revoked_keys, False

    async def _run_portal_key_reconciliation(self) -> None:
        """Revoke keys missing live Keycloak access in durable bounded chunks.

        A direct Keycloak ADM-console removal bypasses portal mutation hooks.
        The cursor uses the existing settings table and stores only pagination
        numbers, opaque consistency digests, and a health bit—never owners,
        projects, or key hashes. A page is checkpointed only after its per-key
        revoke/verify work ends.

        LiteLLM's offset endpoint has deterministic ordering but no snapshot
        token. A completed scan therefore starts a second full scan and marks
        health green only when their ordered opaque digests match. This keeps a
        same-count reorder across a persisted offset from becoming a false
        "complete" result.
        """

        if self._identity is None:
            health.set_alert(
                PORTAL_KEY_RECONCILE_HEALTH,
                "portal-key reconciliation is not configured",
            )
            return

        try:
            async with self._db.rotation_lock(PORTAL_KEY_RECONCILE_LOCK) as acquired:
                if not acquired:
                    health.set_alert(
                        PORTAL_KEY_RECONCILE_HEALTH,
                        "portal-key reconciliation lock was unavailable",
                    )
                    logger.warning(
                        "portal-key reconciliation skipped; lock unavailable"
                    )
                    return

                try:
                    cursor = self._read_portal_key_reconcile_cursor(
                        await self._db.get_settings(PORTAL_KEY_RECONCILE_STATE_VENDOR)
                    )
                except Exception:  # noqa: BLE001
                    # A malformed state must not be allowed to skip unknown
                    # pages. Persist a clean start point, then alert rather
                    # than falsely treating the reset as a healthy sweep.
                    await self._save_portal_key_reconcile_state(None)
                    raise RuntimeError("portal-key reconciliation cursor was reset")

                phase = "scan" if cursor is None else cursor.phase
                page = 1 if cursor is None else cursor.next_page
                scan_digest = (
                    PORTAL_KEY_RECONCILE_DIGEST_SEED
                    if cursor is None
                    else cursor.scan_digest
                )
                reference_digest = None if cursor is None else cursor.reference_digest
                had_access_error = False if cursor is None else cursor.had_access_error
                # A persisted cursor has already established the snapshot
                # counters. A new sweep must establish them from its first
                # page and enforce them for every later page in this same
                # invocation as well. Without these in-memory expectations,
                # a count change between page 1 and page 2 of a fresh chunk
                # could create a mixed-snapshot checkpoint and advance an
                # offset past rows that were never observed together.
                expected_total_count = (
                    None if cursor is None else cursor.expected_total_count
                )
                expected_total_pages = (
                    None if cursor is None else cursor.expected_total_pages
                )
                revoked_keys = 0
                for _ in range(PORTAL_KEY_RECONCILE_PAGES_PER_RUN):
                    try:
                        inventory = (
                            await self._litellm.active_portal_key_inventory_page(page)
                        )
                        self._validate_portal_key_inventory_page(inventory, page)
                        if expected_total_count is None:
                            expected_total_count = inventory.total_count
                            expected_total_pages = inventory.total_pages
                        elif (
                            inventory.total_count != expected_total_count
                            or inventory.total_pages != expected_total_pages
                        ):
                            raise RuntimeError(
                                "portal-key reconciliation inventory counters changed"
                            )
                    except Exception:  # noqa: BLE001
                        # A changed/malformed global inventory makes an offset
                        # checkpoint unsafe. Restart at page one next run;
                        # previous pages may be repeated, never skipped.
                        await self._save_portal_key_reconcile_state(None)
                        raise

                    (
                        page_revocations,
                        page_access_error,
                    ) = await self._reconcile_portal_key_page(inventory.bindings)
                    revoked_keys += page_revocations
                    had_access_error = had_access_error or page_access_error
                    scan_digest = self._roll_portal_key_inventory_digest(
                        scan_digest, inventory.inventory_digest
                    )

                    if inventory.total_pages == 0 or page == inventory.total_pages:
                        if phase == "scan":
                            # A stable count is not a snapshot invariant. Save
                            # the first ordered sweep as an opaque reference,
                            # then begin a second complete verification sweep.
                            await self._save_portal_key_reconcile_state(
                                _PortalKeyReconcileCursor(
                                    phase="verify",
                                    next_page=1,
                                    expected_total_count=expected_total_count,
                                    expected_total_pages=expected_total_pages,
                                    scan_digest=PORTAL_KEY_RECONCILE_DIGEST_SEED,
                                    reference_digest=scan_digest,
                                    had_access_error=had_access_error,
                                )
                            )
                            health.set_alert(
                                PORTAL_KEY_RECONCILE_HEALTH,
                                "portal-key reconciliation consistency verification is in progress",
                            )
                            logger.info(
                                "portal-key reconciliation initial sweep completed "
                                "revoked_keys=%d",
                                revoked_keys,
                            )
                            return

                        if scan_digest != reference_digest:
                            # The source reordered or changed while offset
                            # pages were being resumed. A fresh scan is safer
                            # than claiming all active keys were observed.
                            await self._save_portal_key_reconcile_state(None)
                            raise RuntimeError(
                                "portal-key reconciliation inventory changed during verification"
                            )

                        # Always write the empty state, including an empty
                        # first page, so a database outage cannot turn a scan
                        # into a false-green health result.
                        await self._save_portal_key_reconcile_state(None)
                        if had_access_error:
                            health.set_alert(
                                PORTAL_KEY_RECONCILE_HEALTH,
                                "portal-key reconciliation could not verify access",
                            )
                            logger.warning(
                                "portal-key reconciliation completed with unverified access "
                                "revoked_keys=%d",
                                revoked_keys,
                            )
                        else:
                            health.set_ok(PORTAL_KEY_RECONCILE_HEALTH)
                            logger.info(
                                "portal-key reconciliation completed revoked_keys=%d",
                                revoked_keys,
                            )
                        return

                    cursor = _PortalKeyReconcileCursor(
                        phase=phase,
                        next_page=page + 1,
                        expected_total_count=expected_total_count,
                        expected_total_pages=expected_total_pages,
                        scan_digest=scan_digest,
                        reference_digest=reference_digest,
                        had_access_error=had_access_error,
                    )
                    await self._save_portal_key_reconcile_state(cursor)
                    page += 1

                # A clean chunk is not a clean sweep. Keep readiness red until
                # the durable cursor reaches the final LiteLLM page.
                health.set_alert(
                    PORTAL_KEY_RECONCILE_HEALTH,
                    "portal-key reconciliation is in progress",
                )
                logger.info(
                    "portal-key reconciliation checkpointed pages=%d revoked_keys=%d",
                    PORTAL_KEY_RECONCILE_PAGES_PER_RUN,
                    revoked_keys,
                )
        except Exception:  # noqa: BLE001
            # No user/key identifiers in health or logs: they are customer
            # identity data, while operators only need to know the pass failed.
            logger.error("portal-key reconciliation failed")
            health.set_alert(
                PORTAL_KEY_RECONCILE_HEALTH,
                "portal-key reconciliation could not verify access",
            )

    async def shutdown(self) -> None:
        self._scheduler.shutdown(wait=False)

    async def reload(self) -> None:
        """Rebuild jobs from the current rotator_settings rows. Called at
        startup and whenever PUT /settings/{vendor} changes config.
        """
        rows = await self._db.list_settings()
        if not rows:
            # DEFAULT_SETTINGS guarantees a healthy initialized DB is never
            # empty. Database.list_settings() returns [] while unavailable;
            # treating that as authoritative previously removed every live
            # job and silently stopped rotation. Preserve last-known-good.
            detail = (
                "database returned no rotation settings; preserving the last-known-good "
                "schedule and retrying reconciliation"
            )
            logger.error("scheduler reload: %s", detail)
            health.set_alert("system.scheduler_config", detail)
            return

        health.set_ok("system.scheduler_config")
        managed_job_ids = {f"{JOB_PREFIX}{vendor}" for vendor in self._drivers}
        # Reconcile only canonical recurring/one-shot jobs. Manual job ids
        # deliberately share the prefix but carry a suffix; treating every
        # prefix match as managed let a concurrent settings PUT cancel a
        # just-accepted POST /rotate before it ran.
        current_job_ids = {
            job.id for job in self._scheduler.get_jobs() if job.id in managed_job_ids
        }
        wanted_job_ids: set[str] = set()

        for row in rows:
            vendor = row["vendor"]
            if vendor not in self._drivers:
                continue

            job_id = f"{JOB_PREFIX}{vendor}"

            if not row["enabled"]:
                # Not added to wanted_job_ids — the single removal loop
                # below drops any existing job exactly once. (Removing it
                # here too used to double-remove -> JobLookupError, which
                # aborted the reconcile mid-way and broke "pause vendor".)
                # Clearing the one-shot latch lets a later re-enable run the
                # run-once job again.
                self._oneshot_scheduled.discard(vendor)
                continue

            interval = row["interval_seconds"] or 0
            if interval > 0:
                # Leaving zero-interval mode ends that process-lifetime
                # lifecycle. A later switch back to zero is a new one-shot,
                # even without an intervening disabled row.
                self._oneshot_scheduled.discard(vendor)
                wanted_job_ids.add(job_id)
                self._scheduler.add_job(
                    self.run_rotation,
                    trigger=IntervalTrigger(seconds=interval),
                    args=[vendor],
                    id=job_id,
                    replace_existing=True,
                    max_instances=1,
                    coalesce=True,
                    misfire_grace_time=60,
                )
            else:
                # interval == 0 => run ONCE, not once-per-reload.
                if vendor in self._oneshot_scheduled:
                    # Already scheduled its single run this lifetime. If the
                    # job is still pending (hasn't fired), keep it so the
                    # removal loop doesn't cancel it; if it already fired and
                    # auto-removed, do NOT recreate it.
                    if job_id in current_job_ids:
                        wanted_job_ids.add(job_id)
                    continue
                self._oneshot_scheduled.add(vendor)
                wanted_job_ids.add(job_id)
                self._schedule_oneshot(
                    vendor,
                    delay_seconds=0.0,
                    reason="initial zero-interval arm",
                )

        for job_id in current_job_ids - wanted_job_ids:
            # Tolerate already-gone jobs (e.g. a DateTrigger one-shot that
            # fired and auto-removed itself since get_jobs() was called).
            try:
                self._scheduler.remove_job(job_id)
            except JobLookupError:
                logger.debug("reload: job %s already removed", job_id)

        logger.info("scheduler reload complete, active jobs=%s", sorted(wanted_job_ids))

    def _schedule_oneshot(
        self, vendor: str, *, delay_seconds: float, reason: str
    ) -> bool:
        """Arm/re-arm the canonical zero-interval DateTrigger.

        APScheduler removes a DateTrigger from its job store immediately
        after submitting it, before this service's async driver has returned.
        Re-adding the canonical id is therefore required for both readiness
        deferrals and driver-requested dynamic next runs. The process latch
        prevents settings reloads from creating a second job in that gap.
        """
        if vendor not in self._oneshot_scheduled:
            logger.info(
                "not scheduling zero-interval vendor=%s; lifecycle is no longer armed",
                vendor,
            )
            return False
        try:
            delay = float(delay_seconds)
        except (TypeError, ValueError):
            logger.error(
                "invalid zero-interval delay for vendor=%s: %r", vendor, delay_seconds
            )
            return False
        if not math.isfinite(delay):
            logger.error(
                "non-finite zero-interval delay for vendor=%s: %r",
                vendor,
                delay_seconds,
            )
            return False

        run_time = datetime.now(timezone.utc) + timedelta(seconds=max(0.0, delay))
        self._scheduler.add_job(
            self._run_oneshot,
            trigger=DateTrigger(run_date=run_time),
            args=[vendor],
            id=f"{JOB_PREFIX}{vendor}",
            replace_existing=True,
            max_instances=1,
            coalesce=True,
            misfire_grace_time=60,
        )
        logger.info(
            "scheduled zero-interval vendor=%s at %s (%s)",
            vendor,
            run_time.isoformat(),
            reason,
        )
        return True

    async def _run_oneshot(self, vendor: str) -> Optional[RotationResult]:
        """Run one canonical zero-interval attempt when dependencies permit.

        A sealed/unavailable Vault defers before the driver, distributed lock,
        tracing, or audit-history path is entered. This keeps a normal manual-
        unseal boot from consuming the process-lifetime one-shot or producing
        false failed-rotation history. Once a driver actually runs, another
        attempt is scheduled only when it explicitly returns
        ``next_run_seconds``.
        """
        if vendor not in self._oneshot_scheduled:
            return None

        row = await self._db.get_settings(vendor)
        if row is None:
            self._schedule_oneshot(
                vendor,
                delay_seconds=ONESHOT_READINESS_RETRY_SECONDS,
                reason="settings unavailable before zero-interval attempt",
            )
            return None

        interval = int(row.get("interval_seconds") or 0)
        if not row.get("enabled") or interval != 0:
            self._oneshot_scheduled.discard(vendor)
            return None

        if not self._vault.ready():
            self._schedule_oneshot(
                vendor,
                delay_seconds=ONESHOT_READINESS_RETRY_SECONDS,
                reason="Vault not ready; deferred without driver/audit attempt",
            )
            return None

        return await self.run_rotation(vendor)

    async def run_rotation(self, vendor: str) -> RotationResult:
        """Execute one rotation for `vendor`: build a DriverContext, run
        the driver inside an OTel span ("rotation.{vendor}"), persist a
        rotation_history row regardless of outcome, and honor any
        driver-requested dynamic reschedule.
        """
        driver = self._drivers.get(vendor)
        if driver is None:
            logger.warning("run_rotation: no driver registered for vendor=%s", vendor)
            return RotationResult(status="failed", detail="no driver registered")

        # Per-vendor mutual exclusion (manual vs scheduled): a second
        # attempt is skipped fast and audited — never queued behind the
        # in-flight run, which would double-rotate and orphan the account
        # the first run just created.
        lock = self._lock_for(vendor)
        if lock.locked():
            detail = (
                "rotation already in progress for this vendor; concurrent run skipped"
            )
            logger.warning("run_rotation: vendor=%s %s", vendor, detail)
            await self._db.record_history(vendor, "rotate", "skipped", detail)
            return RotationResult(status="skipped", detail=detail)

        async with lock:
            async with self._db.rotation_lock(self._lock_domain(vendor)) as acquired:
                if not acquired:
                    detail = (
                        "another key-rotator instance holds the distributed vendor lock"
                    )
                    logger.warning("run_rotation: vendor=%s %s", vendor, detail)
                    await self._db.record_history(vendor, "rotate", "skipped", detail)
                    return RotationResult(status="skipped", detail=detail)
                result = await self._run_rotation_locked(vendor, driver)
        await self._reconcile_oneshot_lifecycle(vendor, result)
        return result

    async def _reconcile_oneshot_lifecycle(
        self, vendor: str, result: RotationResult
    ) -> None:
        """Finish zero-interval lifecycle state after any execution path.

        Both the canonical callback and a manual ``Rotate now`` job invoke
        :meth:`run_rotation`. Static seed drivers explicitly report that they
        persisted ``enabled=false`` so a manual success cannot leave a stale
        process latch that suppresses a later re-enable. Re-read after clearing
        the latch to close the self-disable/re-enable race: if an operator has
        already re-enabled the row, arm exactly one new canonical job.
        """
        if vendor not in self._oneshot_scheduled:
            return

        if result.settings_self_disabled:
            self._oneshot_scheduled.discard(vendor)
            job_id = f"{JOB_PREFIX}{vendor}"
            if self._scheduler.get_job(job_id) is not None:
                try:
                    self._scheduler.remove_job(job_id)
                except JobLookupError:
                    # A due DateTrigger can disappear between get/remove.
                    pass
            latest = await self._db.get_settings(vendor)
            if latest is None:
                # A concurrent re-enable/reload may have observed the old
                # latch while this authoritative read was unavailable. Keep
                # the lifecycle recoverable through the gated wrapper: it
                # will clear without a driver/audit attempt if the row is
                # still disabled, or run exactly once if it was re-enabled.
                self._oneshot_scheduled.add(vendor)
                self._schedule_oneshot(
                    vendor,
                    delay_seconds=ONESHOT_READINESS_RETRY_SECONDS,
                    reason="settings unavailable after driver self-disable",
                )
                return
            if latest.get("enabled") and int(latest.get("interval_seconds") or 0) == 0:
                self._oneshot_scheduled.add(vendor)
                if self._scheduler.get_job(job_id) is None:
                    self._schedule_oneshot(
                        vendor,
                        delay_seconds=0.0,
                        reason="row re-enabled during one-shot self-disable completion",
                    )
            return

        if result.next_run_seconds is not None:
            return

        latest = await self._db.get_settings(vendor)
        if latest is not None and (
            not latest.get("enabled") or int(latest.get("interval_seconds") or 0) != 0
        ):
            self._oneshot_scheduled.discard(vendor)

    async def _run_rotation_locked(self, vendor: str, driver: Any) -> RotationResult:
        row = await self._db.get_settings(vendor) or {}
        # Anthropic WIF uses an explicit confirmed disable lifecycle. A manual
        # DateTrigger accepted just before disable can survive scheduler.reload;
        # re-check the authoritative row under the distributed lock so that
        # queued work cannot mint a fresh short-lived credential afterward.
        if vendor == "anthropic" and row.get("enabled") is not True:
            result = RotationResult(
                status="skipped",
                detail="Anthropic WIF refresh is disabled; rotation skipped",
            )
            await self._db.record_history(
                vendor, "rotate", result.status, result.detail
            )
            return result
        ctx = DriverContext(
            settings=self._settings,
            vault=self._vault,
            litellm=self._litellm,
            db=self._db,
            vendor_settings=row,
        )

        try:
            from app.otel import get_tracer

            tracer = get_tracer()
        except Exception:  # noqa: BLE001
            tracer = None

        span_cm = (
            tracer.start_as_current_span(f"rotation.{vendor}")
            if tracer
            else _NullSpan()
        )
        with span_cm as span:
            caught_exc: Exception | None = None
            try:
                result = await driver.rotate(ctx)
            except Exception as exc:  # noqa: BLE001
                caught_exc = exc
                logger.exception(
                    "run_rotation: unhandled exception for vendor=%s", vendor
                )
                result = RotationResult(
                    status="failed", detail=f"unhandled exception: {exc}"
                )

            if span is not None:
                try:
                    span.set_attribute("rotation.vendor", vendor)
                    span.set_attribute("rotation.status", result.status)
                    if result.status not in {"success", "skipped"}:
                        span.set_status(Status(StatusCode.ERROR, "rotation failed"))
                    if caught_exc is not None:
                        span.record_exception(caught_exc)
                except Exception:  # noqa: BLE001
                    pass

        await self._db.record_history(vendor, "rotate", result.status, result.detail)

        if result.next_run_seconds is not None:
            await self._reschedule_dynamic(vendor, result.next_run_seconds)

        return result

    async def _reschedule_dynamic(self, vendor: str, seconds: float) -> bool:
        """Driver-requested dynamic next-run override (e.g. Anthropic's
        "refresh at 80% of expires_in").

        For an IntervalTrigger, move the existing canonical job. For a
        zero-interval DateTrigger, APScheduler has already removed that job
        before the async driver returns, so recreate it through the gated
        one-shot wrapper. Re-read the control row first so an in-flight
        disable cannot be undone by a stale driver result.
        """
        try:
            requested_delay = float(seconds)
        except (TypeError, ValueError):
            logger.error(
                "driver returned an invalid next_run_seconds for vendor=%s: %r",
                vendor,
                seconds,
            )
            return False
        if not math.isfinite(requested_delay):
            logger.error(
                "driver returned non-finite next_run_seconds for vendor=%s: %r",
                vendor,
                seconds,
            )
            return False

        delay = min(
            MAX_DYNAMIC_DELAY_SECONDS,
            max(MIN_DYNAMIC_DELAY_SECONDS, requested_delay),
        )
        if delay != requested_delay:
            logger.warning(
                "bounded next_run_seconds for vendor=%s from %r to %.1f",
                vendor,
                seconds,
                delay,
            )

        row = await self._db.get_settings(vendor)
        if row is None:
            if vendor in self._oneshot_scheduled:
                # Preserve the driver's explicit request without trusting a
                # stale enabled state. The gated wrapper re-reads the row
                # before invoking the driver, and the requested delay is not
                # shortened merely because this safety read was unavailable.
                return self._schedule_oneshot(
                    vendor,
                    delay_seconds=max(ONESHOT_READINESS_RETRY_SECONDS, delay),
                    reason="settings unavailable; deferred gated dynamic recheck",
                )
            logger.error(
                "cannot safely reschedule vendor=%s; latest settings are unavailable",
                vendor,
            )
            return False
        if not row.get("enabled"):
            self._oneshot_scheduled.discard(vendor)
            logger.info("not rescheduling disabled vendor=%s", vendor)
            return False

        interval = int(row.get("interval_seconds") or 0)
        job_id = f"{JOB_PREFIX}{vendor}"
        job = self._scheduler.get_job(job_id)
        if job is None and interval == 0:
            return self._schedule_oneshot(
                vendor,
                delay_seconds=delay,
                reason="driver-requested dynamic next run",
            )
        if job is None:
            logger.warning(
                "cannot dynamically reschedule vendor=%s; canonical recurring job is absent",
                vendor,
            )
            return False

        next_time = datetime.now(timezone.utc) + timedelta(seconds=delay)
        try:
            self._scheduler.modify_job(job_id, next_run_time=next_time)
            logger.info(
                "rescheduled %s to run at %s (driver override)",
                vendor,
                next_time.isoformat(),
            )
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("failed to reschedule %s: %s", vendor, exc)
            return False

    def next_run_time(self, vendor: str) -> Optional[datetime]:
        job = self._scheduler.get_job(f"{JOB_PREFIX}{vendor}")
        return job.next_run_time if job else None

    async def trigger_now(self, vendor: str) -> bool:
        """Schedule an immediate one-off run without disturbing the
        recurring job — used by POST /rotate/{vendor}. Returns False
        (caller responds 409) if a rotation for `vendor` is already in
        flight; the per-vendor lock in run_rotation also skips any run
        that slips past this check, so nothing ever queues silently.
        """
        if self.is_rotating(vendor):
            return False
        job_id = f"{JOB_PREFIX}{vendor}_manual_{uuid.uuid4().hex}"
        self._scheduler.add_job(
            self.run_rotation,
            trigger=DateTrigger(run_date=datetime.now(timezone.utc)),
            args=[vendor],
            id=job_id,
            max_instances=1,
        )
        return True
