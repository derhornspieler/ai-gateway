from __future__ import annotations

import copy
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from apscheduler.triggers.date import DateTrigger
from pydantic import ValidationError

from app import health
from app.config import Settings
from app.db import Database
from app.drivers.anthropic_wif import AnthropicWifDriver
from app.drivers.base import DriverContext, RotationResult
from app.drivers.openai_svcacct import (
    PENDING_PROMOTION_FIELD,
    OpenAISvcAcctDriver,
)
from app.drivers.static_seed import StaticSeedDriver, VAULT_RETRY_SECONDS
from app.main import SettingsUpdate, app, readyz, state
from app.security import path_segment
from app.scheduler import RotationScheduler
from app.vault_client import VaultClient, VaultError, mask_secret


AUTH_TOKEN = "0123456789abcdef0123456789abcdef"


class ReadinessDB:
    def __init__(self, value: bool):
        self.value = value

    async def ready(self) -> bool:
        return self.value


class ReadinessVault:
    def __init__(self, value: bool):
        self.value = value

    def ready(self) -> bool:
        return self.value


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("database_ready", "vault_ready", "expected"),
    [(True, True, 200), (False, True, 503), (True, False, 503)],
)
async def test_readyz_requires_database_and_authenticated_unsealed_vault(
    monkeypatch, database_ready: bool, vault_ready: bool, expected: int
) -> None:
    monkeypatch.setitem(state, "db", ReadinessDB(database_ready))
    monkeypatch.setitem(state, "vault", ReadinessVault(vault_ready))
    response = await readyz()
    assert response.status_code == expected


def settings(**overrides) -> Settings:
    values = {
        "ROTATOR_INTERNAL_TOKEN": AUTH_TOKEN,
        "VAULT_TOKEN": "vault-token",
        "LITELLM_MASTER_KEY": "litellm-master-key",
    }
    values.update(overrides)
    return Settings(**values)


def test_service_urls_reject_ambiguous_or_credentialed_values() -> None:
    with pytest.raises(ValidationError):
        settings(EGRESS_BASE="http://envoy-egress:8080/base")
    with pytest.raises(ValidationError):
        settings(LITELLM_URL="http://user:password@litellm:4000")
    with pytest.raises(ValidationError):
        settings(VAULT_ADDR="file:///tmp/vault.sock")


def test_keycloak_bootstrap_url_is_same_origin_and_canonical() -> None:
    cfg = settings(KEYCLOAK_URL="https://keycloak.internal:8443")
    valid = "https://keycloak.internal:8443/realms/anthropic/protocol/openid-connect/token"
    assert cfg.validated_keycloak_token_url(valid) == valid

    for invalid in (
        "http://keycloak.internal:8443/realms/anthropic/protocol/openid-connect/token",
        "https://169.254.169.254/realms/anthropic/protocol/openid-connect/token",
        "https://keycloak.internal:8443/admin/serverinfo",
        "https://keycloak.internal:8443/realms/../protocol/openid-connect/token",
        "https://keycloak.internal:8443/realms/%2e%2e/protocol/openid-connect/token",
    ):
        with pytest.raises(ValueError):
            cfg.validated_keycloak_token_url(invalid)


def test_keycloak_assertion_audiences_follow_each_realm_frontend() -> None:
    cfg = settings(
        KEYCLOAK_PUBLIC_URL="https://auth.aigw.internal",
        WIF_KEYCLOAK_PUBLIC_URL="https://idp.wif-a.example.invalid",
    )
    assert cfg.keycloak_assertion_audience("aigw") == (
        "https://auth.aigw.internal/realms/aigw/protocol/openid-connect/token"
    )
    internal = (
        "http://keycloak:8080/realms/anthropic-wif/protocol/openid-connect/token"
    )
    assert cfg.keycloak_assertion_audience_for_token_url(internal) == (
        "https://idp.wif-a.example.invalid/realms/anthropic-wif/"
        "protocol/openid-connect/token"
    )


def test_lab_directory_defaults_to_dedicated_human_users_ou() -> None:
    cfg = settings()
    assert cfg.lab_samba_users_dn == "OU=AIGWUsers,DC=lab,DC=aigw,DC=internal"
    assert "CN=Users" not in cfg.lab_samba_users_dn


def test_outbound_path_segments_cannot_escape_endpoint() -> None:
    assert path_segment("proj_abc-123", label="project") == "proj_abc-123"
    for invalid in ("../admin", "abc/keys", "abc?x=1", "#fragment", ""):
        with pytest.raises(ValueError):
            path_segment(invalid, label="project")


def test_secret_redaction_never_retains_a_prefix() -> None:
    assert mask_secret("sk-super-secret-value") == "<redacted>"
    assert "sk-super" not in mask_secret("sk-super-secret-value")
    assert mask_secret(None) == "<empty>"


def test_vault_transport_ignores_ambient_proxies_and_redirects() -> None:
    vault = VaultClient(settings())
    client = vault._get_client()
    assert client.session.trust_env is False
    assert client.allow_redirects is False
    assert client.adapter._kwargs["verify"] is True
    vault.close()


@pytest.mark.asyncio
async def test_auth_fails_closed_and_public_health_redacts_details() -> None:
    old_state = dict(state)
    old_flags = health.snapshot()
    try:
        state.clear()
        health._flags.clear()
        health.set_alert(
            "openai.rotation",
            "vault=http://vault:8200 account=svcacct_sensitive internal-only detail",
        )
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://rotator") as client:
            health_response = await client.get("/healthz")
            assert health_response.status_code == 200
            assert health_response.json() == {"ok": True, "alerts_ok": False}
            assert "svcacct_sensitive" not in health_response.text
            assert health_response.headers["cache-control"] == "no-store"

            # Before startup has installed valid settings, protected routes
            # fail closed even if a caller supplies a header.
            response = await client.get(
                "/status", headers={"X-Internal-Auth": AUTH_TOKEN}
            )
            assert response.status_code == 503

            state["settings"] = settings()
            response = await client.get("/status")
            assert response.status_code == 401
    finally:
        state.clear()
        state.update(old_state)
        health._flags.clear()
        health._flags.update(old_flags)


class FakeVault:
    def __init__(self) -> None:
        self.docs = {
            "ai-gateway/openai-admin": {
                "admin_api_key": "admin-key",
                "project_id": "proj_test",
            },
            "ai-gateway/vendors/openai": {
                "api_key": "old-key",
                "service_account_id": "svcacct_old",
                "project_id": "proj_test",
            },
            "ai-gateway/openai-state": {
                "service_account_id": "svcacct_old",
                "project_id": "proj_test",
                "orphans": [],
            },
        }

    def read(self, path):
        value = self.docs.get(path)
        return copy.deepcopy(value) if value is not None else None

    def write_verified(self, path, data, attempts=3):
        self.docs[path] = copy.deepcopy(data)
        return True

    def write(self, path, data):
        self.docs[path] = copy.deepcopy(data)
        return True


class FlakyLiteLLM:
    def __init__(self) -> None:
        self.calls = 0

    async def upsert_credential(self, name, values):
        self.calls += 1
        if self.calls == 1:
            # A timeout is ambiguous: LiteLLM may have applied the PATCH.
            raise httpx.ReadTimeout("ambiguous promotion timeout")


class FakeDB:
    def __init__(self) -> None:
        self.history = []

    async def record_history(self, *args):
        self.history.append(args)


class DeterministicOpenAIDriver(OpenAISvcAcctDriver):
    def __init__(self) -> None:
        self.created = 0
        self.deleted = []

    async def _create_service_account(self, ctx, admin_key, project_id):
        self.created += 1
        return "svcacct_new", "new-key"

    async def _canary_check(self, ctx, api_key):
        return True

    async def _delete_service_account(self, ctx, admin_key, project_id, sa_id):
        self.deleted.append((project_id, sa_id))

    async def _verify_old_key_revoked(self, ctx, old_key, max_attempts=5):
        return True


@pytest.mark.asyncio
async def test_openai_ambiguous_promotion_resumes_same_tracked_account() -> None:
    vault = FakeVault()
    litellm = FlakyLiteLLM()
    driver = DeterministicOpenAIDriver()
    ctx = DriverContext(
        settings=settings(),
        vault=vault,
        litellm=litellm,
        db=FakeDB(),
        vendor_settings={"enabled": True, "interval_seconds": 3600, "grace_seconds": 0},
    )

    first = await driver.rotate(ctx)
    assert first.status == "failed"
    pending = vault.docs["ai-gateway/openai-state"][PENDING_PROMOTION_FIELD]
    assert pending["new_service_account_id"] == "svcacct_new"
    assert pending["previous_service_account_id"] == "svcacct_old"
    assert pending["previous_api_key"] == "old-key"

    second = await driver.rotate(ctx)
    assert second.status == "success"
    assert driver.created == 1, "retry must not mint a second live account"
    assert driver.deleted == [("proj_test", "svcacct_old")]
    final_state = vault.docs["ai-gateway/openai-state"]
    assert final_state["service_account_id"] == "svcacct_new"
    assert PENDING_PROMOTION_FIELD not in final_state


class SettingsDB:
    def __init__(self):
        self.available = True

    async def list_settings(self):
        if not self.available:
            return []
        return [
            {
                "vendor": "openai",
                "enabled": True,
                "interval_seconds": 3600,
                "grace_seconds": 0,
                "config": {},
            }
        ]


@pytest.mark.asyncio
async def test_scheduler_reload_does_not_cancel_accepted_manual_job() -> None:
    db = SettingsDB()
    scheduler = RotationScheduler(
        settings(), db, object(), object(), {"openai": object()}
    )
    manual_id = "rotate_openai_manual_test"
    scheduler._scheduler.add_job(
        scheduler.run_rotation,
        trigger=DateTrigger(run_date=datetime.now(timezone.utc) + timedelta(minutes=5)),
        args=["openai"],
        id=manual_id,
    )

    await scheduler.reload()

    assert scheduler._scheduler.get_job(manual_id) is not None
    assert scheduler._scheduler.get_job("rotate_openai") is not None
    assert scheduler._lock_for("static-openai") is scheduler._lock_for("openai")

    db.available = False
    await scheduler.reload()
    assert scheduler._scheduler.get_job("rotate_openai") is not None


class SchedulerVault:
    def __init__(self, ready: bool) -> None:
        self.is_ready = ready
        self.ready_calls = 0

    def ready(self) -> bool:
        self.ready_calls += 1
        return self.is_ready


class SchedulerDB:
    def __init__(self, *rows: dict) -> None:
        self.rows = {row["vendor"]: copy.deepcopy(row) for row in rows}
        self.history: list[tuple] = []
        self.unavailable_lookups = 0

    async def list_settings(self) -> list[dict]:
        return [copy.deepcopy(self.rows[key]) for key in sorted(self.rows)]

    async def get_settings(self, vendor: str):
        if self.unavailable_lookups:
            self.unavailable_lookups -= 1
            return None
        row = self.rows.get(vendor)
        return copy.deepcopy(row) if row is not None else None

    @asynccontextmanager
    async def rotation_lock(self, vendor: str):
        yield True

    async def record_history(self, *values) -> None:
        self.history.append(values)

    async def upsert_settings(
        self,
        vendor: str,
        enabled: bool,
        interval_seconds: int,
        grace_seconds: int,
        config,
    ) -> None:
        current = self.rows.get(vendor, {"vendor": vendor, "config": {}})
        current.update(
            {
                "enabled": enabled,
                "interval_seconds": interval_seconds,
                "grace_seconds": grace_seconds,
            }
        )
        if config is not None:
            current["config"] = copy.deepcopy(config)
        self.rows[vendor] = current


class SequenceDriver:
    def __init__(self, *results: RotationResult) -> None:
        self.results = list(results)
        self.calls = 0

    async def rotate(self, ctx: DriverContext) -> RotationResult:
        result = self.results[min(self.calls, len(self.results) - 1)]
        self.calls += 1
        return result


class SelfDisablingDriver(SequenceDriver):
    async def rotate(self, ctx: DriverContext) -> RotationResult:
        self.calls += 1
        await ctx.db.upsert_settings(
            "static-openai",
            enabled=False,
            interval_seconds=0,
            grace_seconds=0,
            config={},
        )
        return RotationResult(
            status="success",
            detail="seed complete",
            settings_self_disabled=True,
        )


def zero_interval_row(vendor: str = "static-openai") -> dict:
    return {
        "vendor": vendor,
        "enabled": True,
        "interval_seconds": 0,
        "grace_seconds": 0,
        "config": {},
    }


def remove_canonical_job(scheduler: RotationScheduler, vendor: str) -> None:
    """Model APScheduler's DateTrigger removal before async execution."""
    scheduler._scheduler.remove_job(f"rotate_{vendor}")


@pytest.mark.asyncio
async def test_zero_interval_defers_while_vault_sealed_then_runs_once() -> None:
    vendor = "static-openai"
    db = SchedulerDB(zero_interval_row(vendor))
    vault = SchedulerVault(ready=False)
    driver = SequenceDriver(RotationResult(status="success", detail="seeded"))
    scheduler = RotationScheduler(settings(), db, vault, object(), {vendor: driver})

    await scheduler.reload()
    remove_canonical_job(scheduler, vendor)
    assert await scheduler._run_oneshot(vendor) is None
    assert driver.calls == 0
    assert db.history == []
    deferred = scheduler._scheduler.get_job(f"rotate_{vendor}")
    assert deferred is not None
    assert isinstance(deferred.trigger, DateTrigger)
    assert deferred.trigger.run_date >= datetime.now(timezone.utc) + timedelta(seconds=25)

    vault.is_ready = True
    remove_canonical_job(scheduler, vendor)
    result = await scheduler._run_oneshot(vendor)
    assert result is not None and result.status == "success"
    assert driver.calls == 1
    assert len(db.history) == 1
    assert scheduler._scheduler.get_job(f"rotate_{vendor}") is None

    # A normal settings reload after a terminal outcome must not consume the
    # process-lifetime one-shot a second time.
    await scheduler.reload()
    assert scheduler._scheduler.get_job(f"rotate_{vendor}") is None
    assert driver.calls == 1


@pytest.mark.asyncio
async def test_zero_interval_explicit_transient_retry_is_bounded_and_rearmed() -> None:
    vendor = "static-openai"
    db = SchedulerDB(zero_interval_row(vendor))
    vault = SchedulerVault(ready=True)
    driver = SequenceDriver(
        RotationResult(status="failed", detail="transient", next_run_seconds=0.01),
        RotationResult(status="success", detail="recovered"),
    )
    scheduler = RotationScheduler(settings(), db, vault, object(), {vendor: driver})

    await scheduler.reload()
    remove_canonical_job(scheduler, vendor)
    first = await scheduler._run_oneshot(vendor)
    assert first is not None and first.status == "failed"
    assert len(db.history) == 1
    retry = scheduler._scheduler.get_job(f"rotate_{vendor}")
    assert retry is not None
    # Driver-selected retries cannot become a tight loop.
    assert retry.trigger.run_date >= datetime.now(timezone.utc) + timedelta(seconds=4)

    remove_canonical_job(scheduler, vendor)
    second = await scheduler._run_oneshot(vendor)
    assert second is not None and second.status == "success"
    assert driver.calls == 2
    assert len(db.history) == 2
    assert scheduler._scheduler.get_job(f"rotate_{vendor}") is None


@pytest.mark.asyncio
async def test_zero_interval_generic_failure_does_not_retry_forever() -> None:
    vendor = "static-openai"
    db = SchedulerDB(zero_interval_row(vendor))
    vault = SchedulerVault(ready=True)
    driver = SequenceDriver(RotationResult(status="failed", detail="permanent auth error"))
    scheduler = RotationScheduler(settings(), db, vault, object(), {vendor: driver})

    await scheduler.reload()
    remove_canonical_job(scheduler, vendor)
    result = await scheduler._run_oneshot(vendor)

    assert result is not None and result.status == "failed"
    assert len(db.history) == 1
    assert scheduler._scheduler.get_job(f"rotate_{vendor}") is None
    await scheduler.reload()
    assert scheduler._scheduler.get_job(f"rotate_{vendor}") is None


@pytest.mark.asyncio
async def test_zero_interval_reload_does_not_duplicate_deferred_job() -> None:
    vendor = "static-openai"
    db = SchedulerDB(zero_interval_row(vendor))
    vault = SchedulerVault(ready=False)
    driver = SequenceDriver(RotationResult(status="success"))
    scheduler = RotationScheduler(settings(), db, vault, object(), {vendor: driver})

    await scheduler.reload()
    remove_canonical_job(scheduler, vendor)
    await scheduler._run_oneshot(vendor)
    before = scheduler._scheduler.get_job(f"rotate_{vendor}").trigger.run_date

    await scheduler.reload()
    matching = [
        job for job in scheduler._scheduler.get_jobs() if job.id == f"rotate_{vendor}"
    ]
    assert len(matching) == 1
    assert matching[0].trigger.run_date == before
    assert driver.calls == 0
    assert db.history == []


@pytest.mark.asyncio
async def test_zero_interval_success_self_disable_allows_later_reenable() -> None:
    vendor = "static-openai"
    db = SchedulerDB(zero_interval_row(vendor))
    vault = SchedulerVault(ready=True)
    driver = SelfDisablingDriver(RotationResult(status="success"))
    scheduler = RotationScheduler(settings(), db, vault, object(), {vendor: driver})

    await scheduler.reload()
    remove_canonical_job(scheduler, vendor)
    result = await scheduler._run_oneshot(vendor)
    assert result is not None and result.status == "success"
    assert vendor not in scheduler._oneshot_scheduled
    assert scheduler._scheduler.get_job(f"rotate_{vendor}") is None

    db.rows[vendor]["enabled"] = True
    await scheduler.reload()
    assert vendor in scheduler._oneshot_scheduled
    assert scheduler._scheduler.get_job(f"rotate_{vendor}") is not None


@pytest.mark.asyncio
async def test_manual_self_disable_clears_latch_before_later_reenable() -> None:
    vendor = "static-openai"
    db = SchedulerDB(zero_interval_row(vendor))
    vault = SchedulerVault(ready=True)
    driver = SelfDisablingDriver(RotationResult(status="success"))
    scheduler = RotationScheduler(settings(), db, vault, object(), {vendor: driver})

    # Model a previously completed canonical one-shot: its process latch
    # remains, but its DateTrigger is gone. Rotate now uses run_rotation
    # directly rather than _run_oneshot.
    await scheduler.reload()
    remove_canonical_job(scheduler, vendor)
    assert await scheduler.trigger_now(vendor)
    manual = next(
        job
        for job in scheduler._scheduler.get_jobs()
        if job.id.startswith(f"rotate_{vendor}_manual_")
    )
    scheduler._scheduler.remove_job(manual.id)
    result = await manual.func(*manual.args, **manual.kwargs)

    assert result.settings_self_disabled is True
    assert db.rows[vendor]["enabled"] is False
    assert vendor not in scheduler._oneshot_scheduled

    db.rows[vendor]["enabled"] = True
    await scheduler.reload()
    assert scheduler._scheduler.get_job(f"rotate_{vendor}") is not None


@pytest.mark.asyncio
async def test_self_disable_settings_read_loss_defers_gated_reconciliation() -> None:
    vendor = "static-openai"
    db = SchedulerDB(zero_interval_row(vendor))
    vault = SchedulerVault(ready=True)

    class SelfDisableThenLoseSettingsDriver:
        def __init__(self) -> None:
            self.calls = 0

        async def rotate(self, ctx: DriverContext) -> RotationResult:
            self.calls += 1
            await ctx.db.upsert_settings(
                vendor,
                enabled=False,
                interval_seconds=0,
                grace_seconds=0,
                config={},
            )
            ctx.db.unavailable_lookups = 1
            return RotationResult(
                status="success",
                detail="seed complete",
                settings_self_disabled=True,
            )

    driver = SelfDisableThenLoseSettingsDriver()
    scheduler = RotationScheduler(settings(), db, vault, object(), {vendor: driver})
    await scheduler.reload()
    remove_canonical_job(scheduler, vendor)
    result = await scheduler._run_oneshot(vendor)

    assert result is not None and result.settings_self_disabled is True
    assert driver.calls == 1
    assert vendor in scheduler._oneshot_scheduled
    deferred = scheduler._scheduler.get_job(f"rotate_{vendor}")
    assert deferred is not None
    assert deferred.trigger.run_date >= datetime.now(timezone.utc) + timedelta(seconds=25)

    # The gated recheck sees the still-disabled row and clears the lifecycle
    # without a second driver invocation or history row.
    remove_canonical_job(scheduler, vendor)
    assert await scheduler._run_oneshot(vendor) is None
    assert driver.calls == 1
    assert len(db.history) == 1
    assert vendor not in scheduler._oneshot_scheduled
    assert scheduler._scheduler.get_job(f"rotate_{vendor}") is None


@pytest.mark.asyncio
async def test_zero_interval_dynamic_result_recreates_removed_date_trigger() -> None:
    vendor = "anthropic"
    db = SchedulerDB(zero_interval_row(vendor))
    vault = SchedulerVault(ready=True)
    driver = SequenceDriver(
        RotationResult(status="success", detail="minted", next_run_seconds=120)
    )
    scheduler = RotationScheduler(settings(), db, vault, object(), {vendor: driver})

    await scheduler.reload()
    remove_canonical_job(scheduler, vendor)
    result = await scheduler._run_oneshot(vendor)
    assert result is not None and result.next_run_seconds == 120
    dynamic = scheduler._scheduler.get_job(f"rotate_{vendor}")
    assert dynamic is not None
    assert isinstance(dynamic.trigger, DateTrigger)
    assert dynamic.func == scheduler._run_oneshot
    assert dynamic.trigger.run_date >= datetime.now(timezone.utc) + timedelta(seconds=115)


@pytest.mark.asyncio
async def test_dynamic_rearm_survives_transient_latest_settings_failure() -> None:
    vendor = "anthropic"
    db = SchedulerDB(zero_interval_row(vendor))
    vault = SchedulerVault(ready=True)
    driver = SequenceDriver(RotationResult(status="success", detail="recovered"))
    scheduler = RotationScheduler(settings(), db, vault, object(), {vendor: driver})

    await scheduler.reload()
    remove_canonical_job(scheduler, vendor)
    db.unavailable_lookups = 1
    assert await scheduler._reschedule_dynamic(vendor, 120) is True
    deferred = scheduler._scheduler.get_job(f"rotate_{vendor}")
    assert deferred is not None
    assert deferred.func == scheduler._run_oneshot
    assert deferred.trigger.run_date >= datetime.now(timezone.utc) + timedelta(seconds=115)
    assert db.history == []

    remove_canonical_job(scheduler, vendor)
    result = await scheduler._run_oneshot(vendor)
    assert result is not None and result.status == "success"
    assert driver.calls == 1
    assert len(db.history) == 1


@pytest.mark.asyncio
async def test_zero_interval_dynamic_result_cannot_undo_inflight_disable() -> None:
    vendor = "static-openai"
    db = SchedulerDB(zero_interval_row(vendor))
    vault = SchedulerVault(ready=True)

    class DisableThenRetryDriver:
        async def rotate(self, ctx: DriverContext) -> RotationResult:
            ctx.db.rows[vendor]["enabled"] = False
            return RotationResult(
                status="failed", detail="disabled concurrently", next_run_seconds=60
            )

    scheduler = RotationScheduler(
        settings(), db, vault, object(), {vendor: DisableThenRetryDriver()}
    )
    await scheduler.reload()
    remove_canonical_job(scheduler, vendor)
    result = await scheduler._run_oneshot(vendor)

    assert result is not None and result.status == "failed"
    assert scheduler._scheduler.get_job(f"rotate_{vendor}") is None
    assert vendor not in scheduler._oneshot_scheduled


@pytest.mark.asyncio
async def test_static_seed_marks_only_vault_error_for_bounded_retry() -> None:
    class SealedVault:
        def read(self, path: str):
            raise VaultError("sealed")

    db = SchedulerDB(zero_interval_row("static-openai"))
    ctx = DriverContext(
        settings=settings(),
        vault=SealedVault(),
        litellm=object(),
        db=db,
        vendor_settings=zero_interval_row("static-openai"),
    )
    result = await StaticSeedDriver("openai").rotate(ctx)

    assert result.status == "failed"
    assert result.next_run_seconds == VAULT_RETRY_SECONDS
    assert result.settings_self_disabled is False


@pytest.mark.asyncio
async def test_static_seed_success_explicitly_reports_self_disable() -> None:
    class SeedVault:
        def read(self, path: str):
            return {"api_key": "static-test-key"}

    class RecordingLiteLLM:
        async def upsert_credential(self, name: str, values: dict) -> None:
            assert name == "openai-primary"
            assert values == {"api_key": "static-test-key"}

    db = SchedulerDB(zero_interval_row("static-openai"))
    ctx = DriverContext(
        settings=settings(),
        vault=SeedVault(),
        litellm=RecordingLiteLLM(),
        db=db,
        vendor_settings=zero_interval_row("static-openai"),
    )
    result = await StaticSeedDriver("openai").rotate(ctx)

    assert result.status == "success"
    assert result.settings_self_disabled is True
    assert db.rows["static-openai"]["enabled"] is False


def test_settings_update_omission_preserves_driver_config_contract() -> None:
    omitted = SettingsUpdate(enabled=True, interval_seconds=3600, grace_seconds=300)
    explicit_reset = SettingsUpdate(
        enabled=True, interval_seconds=3600, grace_seconds=300, config={}
    )
    assert omitted.config is None
    assert explicit_reset.config == {}


class RecordingCursor:
    def __init__(self):
        self.calls = []
        self.rowcount = 1

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def execute(self, sql, params=()):
        self.calls.append((" ".join(sql.split()), params))


class RecordingConnection:
    def __init__(self):
        self.cursor_obj = RecordingCursor()

    def cursor(self):
        return self.cursor_obj


@pytest.mark.asyncio
async def test_database_writers_own_disjoint_settings_columns(monkeypatch) -> None:
    db = Database(settings())
    conn = RecordingConnection()

    async def ensure_conn():
        return conn

    monkeypatch.setattr(db, "_ensure_conn", ensure_conn)

    await db.upsert_settings("anthropic", True, 1800, 120, None)
    control_sql = conn.cursor_obj.calls[-1][0]
    assert "config = EXCLUDED.config" not in control_sql
    assert "interval_seconds = EXCLUDED.interval_seconds" in control_sql

    await db.update_settings_config("anthropic", {"_fail_count": 2})
    state_sql = conn.cursor_obj.calls[-1][0]
    assert "SET config = %s::jsonb" in state_sql
    assert "interval_seconds" not in state_sql
    assert "enabled" not in state_sql


class FailingStateDB(FakeDB):
    async def update_settings_config(self, vendor, config):
        raise RuntimeError("postgres unavailable")


@pytest.mark.asyncio
async def test_anthropic_failure_keeps_retry_deadline_when_state_db_is_down() -> None:
    ctx = DriverContext(
        settings=settings(),
        vault=FakeVault(),
        litellm=object(),
        db=FailingStateDB(),
        vendor_settings={
            "enabled": True,
            "interval_seconds": 3000,
            "config": {"_last_issued_at": 1, "_last_expires_in": 3600},
        },
    )

    result = await AnthropicWifDriver()._handle_failure(
        ctx, dict(ctx.vendor_settings["config"]), RuntimeError("exchange failed")
    )

    assert result.status == "failed"
    assert result.next_run_seconds is not None
    assert 0 < result.next_run_seconds <= 1800


@pytest.mark.asyncio
async def test_openai_project_change_revokes_old_account_in_original_project() -> None:
    vault = FakeVault()
    vault.docs["ai-gateway/openai-admin"]["project_id"] = "proj_new"
    vault.docs["ai-gateway/vendors/openai"]["project_id"] = "proj_old"
    vault.docs["ai-gateway/openai-state"]["project_id"] = "proj_old"
    driver = DeterministicOpenAIDriver()
    ctx = DriverContext(
        settings=settings(),
        vault=vault,
        litellm=FlakyLiteLLM(),
        db=FakeDB(),
        vendor_settings={"enabled": True, "interval_seconds": 3600, "grace_seconds": 0},
    )
    # This test is about project ownership, not an ambiguous LiteLLM timeout.
    ctx.litellm.calls = 1

    result = await driver.rotate(ctx)

    assert result.status == "success"
    assert driver.deleted == [("proj_old", "svcacct_old")]
    assert vault.docs["ai-gateway/openai-state"]["project_id"] == "proj_new"


class CanaryFailureDriver(DeterministicOpenAIDriver):
    async def _canary_check(self, ctx, api_key):
        return False

    async def _verify_old_key_revoked(self, ctx, old_key, max_attempts=5):
        return False


@pytest.mark.asyncio
async def test_canary_failed_key_is_tracked_until_revocation_is_verified() -> None:
    vault = FakeVault()
    driver = CanaryFailureDriver()
    ctx = DriverContext(
        settings=settings(),
        vault=vault,
        litellm=object(),
        db=FakeDB(),
        vendor_settings={"enabled": True, "interval_seconds": 3600, "grace_seconds": 0},
    )

    result = await driver.rotate(ctx)

    assert result.status == "failed"
    orphan = vault.docs["ai-gateway/openai-state"]["orphans"][-1]
    assert orphan == {
        "service_account_id": "svcacct_new",
        "api_key": "new-key",
        "project_id": "proj_test",
        "deleted": True,
        "first_seen": orphan["first_seen"],
    }
