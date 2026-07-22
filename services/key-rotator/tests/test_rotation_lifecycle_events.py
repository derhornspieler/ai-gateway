from __future__ import annotations

import copy
import json
from contextlib import asynccontextmanager
from uuid import UUID

import httpx
import pytest

from app import health
from app.config import Settings
from app.drivers.anthropic_wif import AnthropicWifDriver
from app.drivers.base import DriverContext, RotationResult
from app.scheduler import MAX_ROTATION_ATTEMPTS, RotationScheduler
from app.vault_client import VaultError


AUTH_TOKEN = "0123456789abcdef0123456789abcdef"
SECURITY_EVENT_PREFIX = "AIGW_SECURITY_EVENT "


def settings() -> Settings:
    return Settings(
        ROTATOR_INTERNAL_TOKEN=AUTH_TOKEN,
        PORTAL_IDENTITY_TOKEN="abcdef0123456789abcdef0123456789",
        VAULT_TOKEN="vault-token",
        LITELLM_MASTER_KEY="litellm-master-key",
    )


def rotation_row(*, fail_count: int = 0) -> dict:
    config = {"_fail_count": fail_count} if fail_count else {}
    return {
        "vendor": "anthropic",
        "enabled": True,
        "interval_seconds": 3000,
        "grace_seconds": 300,
        "config": config,
    }


class RotationDB:
    def __init__(self, row: dict | None = None) -> None:
        self.row = copy.deepcopy(row or rotation_row())
        self.history: list[tuple[str, str, str, str]] = []

    async def list_settings(self) -> list[dict]:
        return [copy.deepcopy(self.row)]

    async def get_settings(self, vendor: str) -> dict | None:
        if vendor != self.row["vendor"]:
            return None
        return copy.deepcopy(self.row)

    @asynccontextmanager
    async def rotation_lock(self, vendor: str):
        assert vendor == "anthropic"
        yield True

    async def record_history(
        self, vendor: str, action: str, status: str, detail: str
    ) -> None:
        self.history.append((vendor, action, status, detail))

    async def update_settings_config(self, vendor: str, config: dict) -> None:
        assert vendor == "anthropic"
        self.row["config"] = copy.deepcopy(config)


class LockDeniedDB(RotationDB):
    @asynccontextmanager
    async def rotation_lock(self, vendor: str):
        assert vendor == "anthropic"
        yield False


class HistoryFailingDB(RotationDB):
    async def record_history(
        self, _vendor: str, _action: str, _status: str, _detail: str
    ) -> None:
        raise RuntimeError("password=do-not-export-history-secret")


class SettingsFailingDB(RotationDB):
    async def get_settings(self, _vendor: str) -> dict | None:
        raise RuntimeError("password=do-not-export-settings-secret")


class ReconcileSettingsFailingDB(RotationDB):
    def __init__(self) -> None:
        super().__init__()
        self.settings_reads = 0

    async def get_settings(self, vendor: str) -> dict | None:
        self.settings_reads += 1
        if self.settings_reads > 1:
            raise RuntimeError("password=do-not-export-reconcile-secret")
        return await super().get_settings(vendor)


class LockExitFailingDB(RotationDB):
    @asynccontextmanager
    async def rotation_lock(self, vendor: str):
        assert vendor == "anthropic"
        yield True
        raise RuntimeError("token=do-not-export-lock-secret")


class SequenceDriver:
    def __init__(self, *results: RotationResult) -> None:
        self.results = list(results)
        self.calls = 0

    async def rotate(self, _ctx: DriverContext) -> RotationResult:
        result = self.results[min(self.calls, len(self.results) - 1)]
        self.calls += 1
        return result


class RaisingDriver:
    async def rotate(self, _ctx: DriverContext) -> RotationResult:
        raise RuntimeError("api_key=do-not-export-this-secret")


class RecoveringDriver:
    async def rotate(self, ctx: DriverContext) -> RotationResult:
        await ctx.db.update_settings_config("anthropic", {"_fail_count": 0})
        return RotationResult(status="success")


class FailingVault:
    def read(self, _path: str):
        raise VaultError("access_token=do-not-export-this-secret")


class SecretFailingStateDB(RotationDB):
    async def update_settings_config(self, _vendor: str, _config: dict) -> None:
        raise RuntimeError("client_secret=do-not-export-state-secret")


class AssertionVault:
    def read(self, _path: str) -> dict:
        return {
            "kc_token_url": (
                "http://keycloak:8080/realms/anthropic-wif/"
                "protocol/openid-connect/token"
            ),
            "kc_client_id": "anthropic-token-broker",
            "federation_rule_id": "fed_123",
            "organization_id": "org_123",
            "service_account_id": "svc_123",
        }


class SecretAssertionFailureDriver(AnthropicWifDriver):
    def _build_client_assertion(self, _ctx, _bootstrap) -> str:
        raise RuntimeError("private_key=do-not-export-assertion-secret")


class ProviderPayloadFailureDriver(AnthropicWifDriver):
    async def _get_keycloak_jwt(self, _ctx, _bootstrap) -> str:
        return "fixed-test-assertion"

    async def _exchange_anthropic_token(self, _ctx, _bootstrap, _assertion):
        request = httpx.Request(
            "POST", "http://envoy-egress:8080/anthropic/v1/oauth/token"
        )
        response = httpx.Response(
            400,
            request=request,
            json={"error_description": "access_token=provider-response-secret"},
        )
        raise httpx.HTTPStatusError(
            "access_token=provider-response-secret",
            request=request,
            response=response,
        )


class SuccessfulAnthropicDriver(AnthropicWifDriver):
    async def _get_keycloak_jwt(self, _ctx, _bootstrap) -> str:
        return "fixed-test-assertion"

    async def _exchange_anthropic_token(self, _ctx, _bootstrap, _assertion):
        return "access-token-success-fragment", 3600


class CredentialSink:
    def __init__(self) -> None:
        self.values: dict | None = None

    async def upsert_credential(self, name: str, values: dict) -> None:
        assert name == "anthropic-primary"
        self.values = copy.deepcopy(values)


def security_events(caplog) -> list[dict]:
    return [
        json.loads(record.message.removeprefix(SECURITY_EVENT_PREFIX))
        for record in caplog.records
        if record.name == "key_rotator.scheduler"
        and record.message.startswith(SECURITY_EVENT_PREFIX)
    ]


def assert_canonical_rotation_id(value: str) -> None:
    parsed = UUID(value)
    assert parsed.version == 4
    assert str(parsed) == value


def assert_closed_pre_attempt_lifecycle(
    events: list[dict], terminal_status: str
) -> None:
    assert [event["action"] for event in events] == ["start", "rotate"]
    assert [event["rotation_status"] for event in events] == [
        "started",
        terminal_status,
    ]
    assert events[0]["rotation_id"] == events[1]["rotation_id"]
    assert_canonical_rotation_id(events[0]["rotation_id"])
    assert "attempt" not in events[0]
    assert events[1]["attempt"] == 1


@pytest.mark.asyncio
async def test_no_driver_closes_started_lifecycle_with_bounded_attempt(caplog) -> None:
    scheduler = RotationScheduler(settings(), RotationDB(), object(), object(), {})

    with caplog.at_level("INFO", logger="key_rotator.scheduler"):
        result = await scheduler.run_rotation("anthropic")

    assert result.status == "failed"
    assert_closed_pre_attempt_lifecycle(security_events(caplog), "failed")


@pytest.mark.asyncio
async def test_process_lock_skip_closes_started_lifecycle_with_bounded_attempt(
    caplog,
) -> None:
    db = RotationDB()
    scheduler = RotationScheduler(
        settings(), db, object(), object(), {"anthropic": SequenceDriver()}
    )
    lock = scheduler._lock_for("anthropic")
    await lock.acquire()
    try:
        with caplog.at_level("INFO", logger="key_rotator.scheduler"):
            result = await scheduler.run_rotation("anthropic")
    finally:
        lock.release()

    assert result.status == "skipped"
    assert len(db.history) == 1
    assert_closed_pre_attempt_lifecycle(security_events(caplog), "skipped")


@pytest.mark.asyncio
async def test_process_lock_history_failure_still_closes_audit_lifecycle(
    caplog,
) -> None:
    db = HistoryFailingDB()
    scheduler = RotationScheduler(
        settings(), db, object(), object(), {"anthropic": SequenceDriver()}
    )
    lock = scheduler._lock_for("anthropic")
    await lock.acquire()
    try:
        with (
            caplog.at_level("INFO", logger="key_rotator.scheduler"),
            pytest.raises(RuntimeError, match="^rotation history persistence failed$"),
        ):
            await scheduler.run_rotation("anthropic")
    finally:
        lock.release()

    assert_closed_pre_attempt_lifecycle(security_events(caplog), "skipped")
    assert "do-not-export-history-secret" not in caplog.text


@pytest.mark.asyncio
async def test_distributed_lock_skip_closes_started_lifecycle_with_bounded_attempt(
    caplog,
) -> None:
    db = LockDeniedDB()
    scheduler = RotationScheduler(
        settings(), db, object(), object(), {"anthropic": SequenceDriver()}
    )

    with caplog.at_level("INFO", logger="key_rotator.scheduler"):
        result = await scheduler.run_rotation("anthropic")

    assert result.status == "skipped"
    assert len(db.history) == 1
    assert_closed_pre_attempt_lifecycle(security_events(caplog), "skipped")


@pytest.mark.asyncio
async def test_successful_rotation_history_failure_emits_truthful_terminal_result(
    caplog,
) -> None:
    db = HistoryFailingDB()
    scheduler = RotationScheduler(
        settings(),
        db,
        object(),
        object(),
        {"anthropic": SequenceDriver(RotationResult(status="success"))},
    )

    with (
        caplog.at_level("INFO", logger="key_rotator.scheduler"),
        pytest.raises(RuntimeError, match="^rotation history persistence failed$"),
    ):
        await scheduler.run_rotation("anthropic")

    events = security_events(caplog)
    assert [event["action"] for event in events] == ["start", "attempt", "rotate"]
    assert [event["rotation_status"] for event in events] == [
        "started",
        "success",
        "success",
    ]
    assert events[0]["rotation_id"] == events[-1]["rotation_id"]
    assert "do-not-export-history-secret" not in caplog.text


@pytest.mark.asyncio
async def test_settings_failure_after_start_closes_with_fixed_terminal_event(
    caplog,
) -> None:
    scheduler = RotationScheduler(
        settings(),
        SettingsFailingDB(),
        object(),
        object(),
        {"anthropic": SequenceDriver(RotationResult(status="success"))},
    )

    with (
        caplog.at_level("INFO", logger="key_rotator.scheduler"),
        pytest.raises(RuntimeError, match="^provider rotation control failed$"),
    ):
        await scheduler.run_rotation("anthropic")

    events = security_events(caplog)
    assert [event["action"] for event in events] == ["start", "attempt", "rotate"]
    assert [event["rotation_status"] for event in events] == [
        "started",
        "failed",
        "failed",
    ]
    assert "do-not-export-settings-secret" not in caplog.text


@pytest.mark.asyncio
async def test_lock_exit_failure_keeps_one_truthful_terminal_result(caplog) -> None:
    scheduler = RotationScheduler(
        settings(),
        LockExitFailingDB(),
        object(),
        object(),
        {"anthropic": SequenceDriver(RotationResult(status="success"))},
    )

    with (
        caplog.at_level("INFO", logger="key_rotator.scheduler"),
        pytest.raises(RuntimeError, match="^provider rotation control failed$"),
    ):
        await scheduler.run_rotation("anthropic")

    events = security_events(caplog)
    assert [event["action"] for event in events] == ["start", "attempt", "rotate"]
    assert [event["rotation_status"] for event in events] == [
        "started",
        "success",
        "success",
    ]
    assert "do-not-export-lock-secret" not in caplog.text


@pytest.mark.asyncio
async def test_reschedule_failure_closes_retry_lifecycle_without_secret(
    caplog, monkeypatch
) -> None:
    scheduler = RotationScheduler(
        settings(),
        RotationDB(),
        object(),
        object(),
        {
            "anthropic": SequenceDriver(
                RotationResult(
                    status="failed",
                    detail="token=driver-secret",
                    next_run_seconds=30,
                )
            )
        },
    )

    async def fail_reschedule(_vendor: str, _seconds: float) -> bool:
        raise RuntimeError("api_key=do-not-export-reschedule-secret")

    monkeypatch.setattr(scheduler, "_reschedule_dynamic", fail_reschedule)
    with (
        caplog.at_level("INFO", logger="key_rotator.scheduler"),
        pytest.raises(RuntimeError, match="^provider rotation control failed$"),
    ):
        await scheduler.run_rotation("anthropic")

    events = security_events(caplog)
    assert [event["action"] for event in events] == ["start", "attempt", "rotate"]
    assert events[-1]["rotation_status"] == "failed"
    assert "anthropic" not in scheduler._rotation_lifecycles
    assert "do-not-export-reschedule-secret" not in caplog.text
    assert "driver-secret" not in caplog.text


@pytest.mark.asyncio
async def test_oneshot_reconcile_failure_preserves_provider_truth_and_is_sanitized(
    caplog,
) -> None:
    scheduler = RotationScheduler(
        settings(),
        ReconcileSettingsFailingDB(),
        object(),
        object(),
        {"anthropic": SequenceDriver(RotationResult(status="success"))},
    )
    scheduler._oneshot_scheduled.add("anthropic")

    with (
        caplog.at_level("INFO", logger="key_rotator.scheduler"),
        pytest.raises(
            RuntimeError,
            match="^provider rotation lifecycle reconciliation failed$",
        ),
    ):
        await scheduler.run_rotation("anthropic")

    events = security_events(caplog)
    assert [event["action"] for event in events] == ["start", "attempt", "rotate"]
    assert [event["rotation_status"] for event in events] == [
        "started",
        "success",
        "success",
    ]
    assert "do-not-export-reconcile-secret" not in caplog.text


@pytest.mark.asyncio
async def test_retry_lifecycle_has_one_start_ordered_attempts_and_one_recovery(
    caplog,
) -> None:
    db = RotationDB()
    driver = SequenceDriver(
        RotationResult(
            status="failed",
            detail="access_token=first-secret",
            next_run_seconds=30,
        ),
        RotationResult(status="success", detail="api_key=second-secret"),
        RotationResult(status="success", detail="api_key=third-secret"),
    )
    scheduler = RotationScheduler(
        settings(), db, object(), object(), {"anthropic": driver}
    )
    await scheduler.reload()

    with caplog.at_level("INFO", logger="key_rotator.scheduler"):
        first = await scheduler.run_rotation("anthropic")
        second = await scheduler.run_rotation("anthropic")
        third = await scheduler.run_rotation("anthropic")

    assert first.status == "failed"
    assert second.status == "success"
    assert third.status == "success"
    assert len(db.history) == 3

    events = security_events(caplog)
    assert [event["action"] for event in events] == [
        "start",
        "attempt",
        "attempt",
        "rotate",
        "recovery",
        "start",
        "attempt",
        "rotate",
    ]
    assert [event["rotation_status"] for event in events] == [
        "started",
        "failed",
        "success",
        "success",
        "recovered",
        "started",
        "success",
        "success",
    ]
    first_rotation_id = events[0]["rotation_id"]
    assert_canonical_rotation_id(first_rotation_id)
    assert {event["rotation_id"] for event in events[:5]} == {first_rotation_id}
    assert [event.get("attempt") for event in events[:5]] == [None, 1, 2, 2, 2]

    second_rotation_id = events[5]["rotation_id"]
    assert_canonical_rotation_id(second_rotation_id)
    assert second_rotation_id != first_rotation_id
    assert {event["rotation_id"] for event in events[5:]} == {second_rotation_id}
    assert not any(event["action"] == "recovery" for event in events[5:])

    exported = "\n".join(json.dumps(event, sort_keys=True) for event in events)
    assert "first-secret" not in exported
    assert "second-secret" not in exported
    assert "third-secret" not in exported
    assert "rollback" not in exported


@pytest.mark.asyncio
async def test_attempt_limit_closes_id_but_keeps_the_scheduled_safety_retry(
    caplog,
) -> None:
    db = RotationDB()
    driver = SequenceDriver(
        RotationResult(status="failed", detail="safe", next_run_seconds=30)
    )
    scheduler = RotationScheduler(
        settings(), db, object(), object(), {"anthropic": driver}
    )
    await scheduler.reload()

    with caplog.at_level("INFO", logger="key_rotator.scheduler"):
        old_lifecycle = scheduler._start_rotation_lifecycle(
            "anthropic", keep_for_retry=True
        )
        old_lifecycle.attempt = MAX_ROTATION_ATTEMPTS - 1
        assert (await scheduler.run_rotation("anthropic")).status == "failed"

        # The telemetry ID is complete at the field limit, but credential
        # safety still gets the retry the driver requested.
        assert scheduler._scheduler.get_job("rotate_anthropic") is not None
        assert "anthropic" not in scheduler._rotation_lifecycles
        assert (await scheduler.run_rotation("anthropic")).status == "failed"

    events = security_events(caplog)
    assert [event["action"] for event in events] == [
        "start",
        "attempt",
        "rotate",
        "start",
        "attempt",
    ]
    assert [event.get("attempt") for event in events] == [
        None,
        MAX_ROTATION_ATTEMPTS,
        MAX_ROTATION_ATTEMPTS,
        None,
        1,
    ]
    assert events[0]["rotation_id"] == events[1]["rotation_id"]
    assert events[0]["rotation_id"] == events[2]["rotation_id"]
    assert events[3]["rotation_id"] == events[4]["rotation_id"]
    assert events[3]["rotation_id"] != events[0]["rotation_id"]
    for event in events:
        if event["action"] != "start":
            assert 1 <= event["attempt"] <= MAX_ROTATION_ATTEMPTS


@pytest.mark.asyncio
async def test_terminal_failure_event_normalizes_status_and_excludes_error_text(
    caplog,
) -> None:
    db = RotationDB()
    scheduler = RotationScheduler(
        settings(), db, object(), object(), {"anthropic": RaisingDriver()}
    )

    with caplog.at_level("INFO", logger="key_rotator.scheduler"):
        result = await scheduler.run_rotation("anthropic")

    assert result.status == "failed"
    assert len(db.history) == 1
    assert db.history[0][3] == "provider rotation failed"
    events = security_events(caplog)
    assert [event["action"] for event in events] == ["start", "attempt", "rotate"]
    assert [event["rotation_status"] for event in events] == [
        "started",
        "failed",
        "failed",
    ]
    assert events[-1]["outcome"] == "failure"
    exported = "\n".join(json.dumps(event, sort_keys=True) for event in events)
    assert "do-not-export-this-secret" not in exported
    assert "RuntimeError" not in exported
    assert "error" not in exported.lower()
    assert "do-not-export-this-secret" not in caplog.text


@pytest.mark.asyncio
async def test_durable_failure_count_emits_recovery_after_scheduler_restart(
    caplog,
) -> None:
    db = RotationDB(rotation_row(fail_count=2))
    scheduler = RotationScheduler(
        settings(),
        db,
        object(),
        object(),
        {"anthropic": RecoveringDriver()},
    )

    with caplog.at_level("INFO", logger="key_rotator.scheduler"):
        result = await scheduler.run_rotation("anthropic")

    assert result.status == "success"
    events = security_events(caplog)
    assert [event["action"] for event in events] == [
        "start",
        "attempt",
        "rotate",
        "recovery",
    ]
    assert events[-1]["rotation_status"] == "recovered"

    caplog.clear()
    restarted = RotationScheduler(
        settings(), db, object(), object(), {"anthropic": RecoveringDriver()}
    )
    with caplog.at_level("INFO", logger="key_rotator.scheduler"):
        assert (await restarted.run_rotation("anthropic")).status == "success"
    assert [event["action"] for event in security_events(caplog)] == [
        "start",
        "attempt",
        "rotate",
    ]


@pytest.mark.asyncio
async def test_anthropic_driver_failure_has_one_scheduler_owned_history_row(
    caplog,
) -> None:
    db = SecretFailingStateDB()
    scheduler = RotationScheduler(
        settings(), db, FailingVault(), object(), {"anthropic": AnthropicWifDriver()}
    )

    with caplog.at_level("INFO", logger="key_rotator.scheduler"):
        result = await scheduler.run_rotation("anthropic")

    assert result.status == "failed"
    assert len(db.history) == 1
    assert db.history[0][:3] == ("anthropic", "rotate", "failed")
    assert db.history[0][3] == "provider rotation failed"
    events = security_events(caplog)
    assert [event["action"] for event in events] == ["start", "attempt", "rotate"]
    exported = "\n".join(json.dumps(event, sort_keys=True) for event in events)
    assert "do-not-export-this-secret" not in exported
    assert "do-not-export-this-secret" not in caplog.text
    assert "do-not-export-state-secret" not in caplog.text
    health_detail = health.snapshot()["anthropic.token_exchange"]["detail"]
    assert "do-not-export" not in health_detail
    assert health_detail == (
        "rotation failed: stage=failure_state reason=internal_failure"
    )


@pytest.mark.asyncio
async def test_client_assertion_failure_uses_only_fixed_safe_diagnostics(caplog) -> None:
    db = RotationDB()
    scheduler = RotationScheduler(
        settings(),
        db,
        AssertionVault(),
        object(),
        {"anthropic": SecretAssertionFailureDriver()},
    )

    with caplog.at_level("INFO"):
        result = await scheduler.run_rotation("anthropic")

    assert result.status == "failed"
    assert db.history[0][3] == "provider rotation failed"
    assert "do-not-export-assertion-secret" not in caplog.text
    assert "do-not-export-assertion-secret" not in json.dumps(health.snapshot())


@pytest.mark.asyncio
async def test_provider_error_payload_never_enters_log_health_or_history(caplog) -> None:
    db = RotationDB()
    scheduler = RotationScheduler(
        settings(),
        db,
        AssertionVault(),
        object(),
        {"anthropic": ProviderPayloadFailureDriver()},
    )

    with caplog.at_level("INFO"):
        result = await scheduler.run_rotation("anthropic")

    assert result.status == "failed"
    assert db.history[0][3] == "provider rotation failed"
    assert "provider-response-secret" not in caplog.text
    assert "provider-response-secret" not in json.dumps(health.snapshot())
    assert "provider-response-secret" not in json.dumps(db.history)


@pytest.mark.asyncio
async def test_success_log_and_history_do_not_mention_the_access_token(caplog) -> None:
    db = RotationDB()
    litellm = CredentialSink()
    scheduler = RotationScheduler(
        settings(),
        db,
        AssertionVault(),
        litellm,
        {"anthropic": SuccessfulAnthropicDriver()},
    )

    with caplog.at_level("INFO"):
        result = await scheduler.run_rotation("anthropic")

    assert result.status == "success"
    assert litellm.values == {"api_key": "access-token-success-fragment"}
    assert db.history == [
        (
            "anthropic",
            "rotate",
            "success",
            "provider rotation completed",
        )
    ]
    audit_surface = caplog.text + json.dumps(db.history)
    assert "access-token-success-fragment" not in audit_surface
    assert "new token" not in audit_surface.lower()
    assert "<redacted>" not in audit_surface


@pytest.mark.asyncio
async def test_hostile_driver_detail_never_enters_rotation_history_or_logs(
    caplog,
) -> None:
    db = RotationDB()
    scheduler = RotationScheduler(
        settings(),
        db,
        object(),
        object(),
        {
            "anthropic": SequenceDriver(
                RotationResult(
                    status="success",
                    detail=(
                        "api_key=do-not-export token=do-not-export "
                        "assertion=do-not-export secret=do-not-export"
                    ),
                )
            )
        },
    )

    with caplog.at_level("INFO", logger="key_rotator.scheduler"):
        assert (await scheduler.run_rotation("anthropic")).status == "success"

    assert db.history == [
        ("anthropic", "rotate", "success", "provider rotation completed")
    ]
    assert "do-not-export" not in caplog.text
