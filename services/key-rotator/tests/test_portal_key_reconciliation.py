from __future__ import annotations

import hashlib
from contextlib import asynccontextmanager

import pytest

from app import health
import app.scheduler as scheduler_module
from app.config import Settings
from app.litellm_client import PortalKeyBinding, PortalKeyInventoryPage
from app.scheduler import (
    PORTAL_KEY_RECONCILE_HEALTH,
    PORTAL_KEY_RECONCILE_JOB_ID,
    PORTAL_KEY_RECONCILE_DIGEST_SEED,
    PORTAL_KEY_RECONCILE_STATE_VENDOR,
    RotationScheduler,
)


def settings(**overrides) -> Settings:
    values = {
        "ROTATOR_INTERNAL_TOKEN": "0123456789abcdef0123456789abcdef",
        "PORTAL_IDENTITY_TOKEN": "abcdef0123456789abcdef0123456789",
        "VAULT_TOKEN": "vault-token",
        "LITELLM_MASTER_KEY": "litellm-master-key",
    }
    values.update(overrides)
    return Settings(**values)


def scan_cursor(next_page: int, total_count: int, total_pages: int) -> dict[str, object]:
    """A syntactically valid checkpoint after an earlier scan page."""

    return {
        "phase": "scan",
        "next_page": next_page,
        "expected_total_count": total_count,
        "expected_total_pages": total_pages,
        "scan_digest": PORTAL_KEY_RECONCILE_DIGEST_SEED,
        "reference_digest": None,
        "had_access_error": False,
    }


class ReconciliationDB:
    def __init__(
        self, *, acquired: bool = True, reconcile_state: dict[str, object] | None = None
    ) -> None:
        self.acquired = acquired
        self.lock_names: list[str] = []
        self.reconcile_state = reconcile_state
        self.state_reads: list[str] = []
        self.state_writes: list[dict[str, object]] = []

    @asynccontextmanager
    async def rotation_lock(self, name: str):
        self.lock_names.append(name)
        yield self.acquired

    async def get_settings(self, vendor: str):
        self.state_reads.append(vendor)
        if self.reconcile_state is None:
            return None
        return {"vendor": vendor, "config": dict(self.reconcile_state)}

    async def upsert_settings(
        self,
        vendor: str,
        enabled: bool,
        interval_seconds: int,
        grace_seconds: int,
        config: dict[str, object],
    ) -> None:
        assert vendor == PORTAL_KEY_RECONCILE_STATE_VENDOR
        assert enabled is False
        assert interval_seconds == 0
        assert grace_seconds == 0
        self.reconcile_state = dict(config)
        self.state_writes.append(dict(config))


class ReconciliationLiteLLM:
    def __init__(
        self,
        binding_pages: list[set[tuple[str, str]]],
        *,
        total_count: int | None = None,
        failing_tokens: set[str] | None = None,
        sweep_page_digests: list[list[str]] | None = None,
    ) -> None:
        self.binding_pages = binding_pages
        self.revocations: list[tuple[str, str]] = []
        self.page_calls: list[int] = []
        self.failing_tokens = failing_tokens or set()
        self.blocked_tokens: set[str] = set()
        minimum_total_count = max(
            sum(len(bindings) for bindings in binding_pages),
            (len(binding_pages) - 1) * 100 + max(1, len(binding_pages[-1])),
        )
        self.total_count = (
            total_count
            if total_count is not None
            else minimum_total_count
        )
        self.sweep_page_digests = sweep_page_digests

    async def active_portal_key_inventory_page(self, page: int) -> PortalKeyInventoryPage:
        self.page_calls.append(page)
        bindings_list: list[PortalKeyBinding] = []
        for index, (user_id, project_id) in enumerate(
            sorted(self.binding_pages[page - 1])
        ):
            binding = PortalKeyBinding(user_id, project_id, f"hash-{page}-{index}")
            if binding.key_token not in self.blocked_tokens:
                bindings_list.append(binding)
        bindings = tuple(bindings_list)
        sweep = (len(self.page_calls) - 1) // len(self.binding_pages)
        if self.sweep_page_digests is None:
            inventory_digest = hashlib.sha256(
                f"stable-page-{page}".encode()
            ).hexdigest()
        else:
            inventory_digest = self.sweep_page_digests[
                min(sweep, len(self.sweep_page_digests) - 1)
            ][page - 1]
        return PortalKeyInventoryPage(
            page=page,
            total_count=self.total_count,
            total_pages=len(self.binding_pages),
            bindings=bindings,
            inventory_digest=inventory_digest,
        )

    async def revoke_portal_key_binding(self, binding: PortalKeyBinding) -> None:
        self.revocations.append((binding.user_id, binding.project_id))
        if binding.key_token in self.failing_tokens:
            raise RuntimeError("LiteLLM update failed")
        self.blocked_tokens.add(binding.key_token)


class ReconciliationIdentity:
    def __init__(self, projects: dict[str, list[str] | Exception]) -> None:
        self.projects = projects
        self.calls: list[str] = []

    async def user_projects(self, user_id: str) -> list[str]:
        self.calls.append(user_id)
        result = self.projects[user_id]
        if isinstance(result, Exception):
            raise result
        return result


@pytest.mark.asyncio
async def test_reconciliation_revokes_only_projects_absent_from_live_keycloak() -> None:
    old_flags = health.snapshot()
    health._flags.clear()
    try:
        db = ReconciliationDB()
        litellm = ReconciliationLiteLLM(
            [
                {
                    ("subject-a", "project-a"),
                    ("subject-a", "project-b"),
                    ("subject-b", "project-c"),
                }
            ]
        )
        identity = ReconciliationIdentity(
            {"subject-a": ["project-a"], "subject-b": []}
        )
        scheduler = RotationScheduler(
            settings(), db, object(), litellm, {}, identity=identity
        )

        await scheduler._run_portal_key_reconciliation()
        await scheduler._run_portal_key_reconciliation()

        assert db.lock_names == ["portal-key-reconciliation", "portal-key-reconciliation"]
        assert set(identity.calls) == {"subject-a", "subject-b"}
        assert set(litellm.revocations) == {
            ("subject-a", "project-b"),
            ("subject-b", "project-c"),
        }
        assert db.reconcile_state == {}
        assert health.snapshot()[PORTAL_KEY_RECONCILE_HEALTH]["ok"] is True
    finally:
        health._flags.clear()
        health._flags.update(old_flags)


@pytest.mark.asyncio
async def test_reconciliation_preserves_keys_when_identity_lookup_is_unknown() -> None:
    """An outage must not reinterpret live membership as an empty project set."""

    old_flags = health.snapshot()
    health._flags.clear()
    try:
        cursor = scan_cursor(2, 101, 2)
        db = ReconciliationDB(reconcile_state=cursor)
        litellm = ReconciliationLiteLLM(
            [
                set(),
                {
                    # This first owner has a positive no-project result and
                    # would normally be revoked. The second owner's unknown
                    # result must abort before either mutation occurs.
                    ("subject-a", "project-revoked"),
                    ("subject-b", "project-live"),
                },
            ],
            total_count=101,
        )
        identity = ReconciliationIdentity(
            {"subject-a": [], "subject-b": RuntimeError("unavailable")}
        )
        scheduler = RotationScheduler(
            settings(), db, object(), litellm, {}, identity=identity
        )

        await scheduler._run_portal_key_reconciliation()

        assert identity.calls == ["subject-a", "subject-b"]
        assert litellm.revocations == []
        assert litellm.page_calls == [2]
        assert db.reconcile_state == cursor
        flag = health.snapshot()[PORTAL_KEY_RECONCILE_HEALTH]
        assert flag["ok"] is False
        assert "subject-a" not in flag["detail"]
    finally:
        health._flags.clear()
        health._flags.update(old_flags)


@pytest.mark.asyncio
async def test_reconciliation_processes_bindings_after_the_old_global_page_cap() -> None:
    old_flags = health.snapshot()
    health._flags.clear()
    try:
        # Only page 101 contains a stale binding. The previous 100-page cap
        # stopped here and merely alerted; the durable cursor must checkpoint
        # pages 1-100, finish page 101, then verify the full ordered sweep.
        pages = [set() for _ in range(100)]
        pages.append({("subject-after-cap", "project-revoked")})
        db = ReconciliationDB()
        litellm = ReconciliationLiteLLM(pages, total_count=10_001)
        identity = ReconciliationIdentity({"subject-after-cap": []})
        scheduler = RotationScheduler(
            settings(), db, object(), litellm, {}, identity=identity
        )

        await scheduler._run_portal_key_reconciliation()

        assert litellm.page_calls == list(range(1, 101))
        assert db.reconcile_state is not None
        assert db.reconcile_state["phase"] == "scan"
        assert db.reconcile_state["next_page"] == 101
        assert db.reconcile_state["expected_total_count"] == 10_001
        assert db.reconcile_state["expected_total_pages"] == 101
        assert db.reconcile_state["reference_digest"] is None
        assert isinstance(db.reconcile_state["scan_digest"], str)
        assert len(db.reconcile_state["scan_digest"]) == 64
        assert health.snapshot()[PORTAL_KEY_RECONCILE_HEALTH]["ok"] is False

        await scheduler._run_portal_key_reconciliation()

        assert litellm.page_calls == list(range(1, 102))
        assert db.reconcile_state is not None
        assert db.reconcile_state["phase"] == "verify"
        assert db.reconcile_state["next_page"] == 1
        assert db.reconcile_state["scan_digest"] == PORTAL_KEY_RECONCILE_DIGEST_SEED
        assert isinstance(db.reconcile_state["reference_digest"], str)
        assert health.snapshot()[PORTAL_KEY_RECONCILE_HEALTH]["ok"] is False

        await scheduler._run_portal_key_reconciliation()

        assert litellm.page_calls == list(range(1, 102)) + list(range(1, 101))
        assert db.reconcile_state is not None
        assert db.reconcile_state["phase"] == "verify"
        assert db.reconcile_state["next_page"] == 101
        assert health.snapshot()[PORTAL_KEY_RECONCILE_HEALTH]["ok"] is False

        await scheduler._run_portal_key_reconciliation()

        assert identity.calls == ["subject-after-cap"]
        assert litellm.revocations == [("subject-after-cap", "project-revoked")]
        assert litellm.page_calls == list(range(1, 102)) * 2
        assert db.reconcile_state == {}
        assert health.snapshot()[PORTAL_KEY_RECONCILE_HEALTH]["ok"] is True
    finally:
        health._flags.clear()
        health._flags.update(old_flags)


@pytest.mark.asyncio
async def test_reconciliation_does_not_advance_cursor_when_targeted_revocation_fails() -> None:
    old_flags = health.snapshot()
    health._flags.clear()
    try:
        cursor = scan_cursor(2, 101, 2)
        db = ReconciliationDB(reconcile_state=cursor)
        litellm = ReconciliationLiteLLM(
            [set(), {("subject-a", "project-revoked")}],
            total_count=101,
            failing_tokens={"hash-2-0"},
        )
        identity = ReconciliationIdentity({"subject-a": []})
        scheduler = RotationScheduler(
            settings(), db, object(), litellm, {}, identity=identity
        )

        await scheduler._run_portal_key_reconciliation()

        assert litellm.page_calls == [2]
        assert db.reconcile_state == cursor
        assert health.snapshot()[PORTAL_KEY_RECONCILE_HEALTH]["ok"] is False
    finally:
        health._flags.clear()
        health._flags.update(old_flags)


@pytest.mark.asyncio
async def test_reconciliation_resets_cursor_when_inventory_counters_drift() -> None:
    old_flags = health.snapshot()
    health._flags.clear()
    try:
        db = ReconciliationDB(
            reconcile_state=scan_cursor(2, 101, 2)
        )
        litellm = ReconciliationLiteLLM([set(), set(), set()], total_count=201)
        scheduler = RotationScheduler(
            settings(), db, object(), litellm, {}, identity=ReconciliationIdentity({})
        )

        await scheduler._run_portal_key_reconciliation()

        assert litellm.page_calls == [2]
        assert db.reconcile_state == {}
        assert health.snapshot()[PORTAL_KEY_RECONCILE_HEALTH]["ok"] is False
    finally:
        health._flags.clear()
        health._flags.update(old_flags)


@pytest.mark.asyncio
async def test_reconciliation_rejects_counter_drift_within_a_fresh_sweep() -> None:
    """Do not form a durable offset cursor from two different inventories."""

    class InitialSweepDriftLiteLLM(ReconciliationLiteLLM):
        async def active_portal_key_inventory_page(
            self, page: int
        ) -> PortalKeyInventoryPage:
            inventory = await super().active_portal_key_inventory_page(page)
            if page == 2:
                # Page 1 reported 101 keys/two pages, then a concurrent write
                # changed the global offset inventory before page 2 arrived.
                return PortalKeyInventoryPage(
                    page=inventory.page,
                    total_count=201,
                    total_pages=3,
                    bindings=inventory.bindings,
                    inventory_digest=inventory.inventory_digest,
                )
            return inventory

    old_flags = health.snapshot()
    health._flags.clear()
    try:
        db = ReconciliationDB()
        litellm = InitialSweepDriftLiteLLM([set(), set()], total_count=101)
        scheduler = RotationScheduler(
            settings(), db, object(), litellm, {}, identity=ReconciliationIdentity({})
        )

        await scheduler._run_portal_key_reconciliation()

        assert litellm.page_calls == [1, 2]
        assert db.reconcile_state == {}
        assert health.snapshot()[PORTAL_KEY_RECONCILE_HEALTH]["ok"] is False
    finally:
        health._flags.clear()
        health._flags.update(old_flags)


@pytest.mark.asyncio
async def test_reconciliation_rejects_same_count_reordering_across_resumed_offsets(
    monkeypatch,
) -> None:
    old_flags = health.snapshot()
    health._flags.clear()
    try:
        # Keep this focused two-page fixture at one page/run. The second sweep
        # has identical counters but a different ordered page digest, modeling
        # LiteLLM offset rows shifting after a delete/create pair.
        monkeypatch.setattr(
            scheduler_module, "PORTAL_KEY_RECONCILE_PAGES_PER_RUN", 1
        )
        first_sweep = [
            hashlib.sha256(b"first-page-1").hexdigest(),
            hashlib.sha256(b"first-page-2").hexdigest(),
        ]
        second_sweep = [
            hashlib.sha256(b"second-page-1").hexdigest(),
            hashlib.sha256(b"first-page-2").hexdigest(),
        ]
        db = ReconciliationDB()
        litellm = ReconciliationLiteLLM(
            [set(), set()],
            total_count=101,
            sweep_page_digests=[first_sweep, second_sweep],
        )
        scheduler = RotationScheduler(
            settings(), db, object(), litellm, {}, identity=ReconciliationIdentity({})
        )

        for _ in range(4):
            await scheduler._run_portal_key_reconciliation()

        assert litellm.page_calls == [1, 2, 1, 2]
        assert db.reconcile_state == {}
        assert health.snapshot()[PORTAL_KEY_RECONCILE_HEALTH]["ok"] is False
    finally:
        health._flags.clear()
        health._flags.update(old_flags)


def test_reconciliation_runs_immediately_then_at_bounded_one_minute_cadence() -> None:
    assert settings().portal_key_reconcile_interval_seconds == 60
    scheduler = RotationScheduler(
        settings(), ReconciliationDB(), object(), object(), {}, identity=object()
    )
    scheduler._add_system_jobs()

    job = scheduler._scheduler.get_job(PORTAL_KEY_RECONCILE_JOB_ID)
    assert job is not None
    assert job.trigger.interval.total_seconds() == 60
