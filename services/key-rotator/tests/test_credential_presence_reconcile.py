"""Part 2 of the LiteLLM-credential-loss fix: the scheduler's
credential-presence reconcile (re)mints a PRIMARY credential missing from
LiteLLM's in-memory list — LiteLLM does not reload runtime credentials from
Postgres on restart, and the router reads only memory — bounding the
inference outage to one cadence for BOTH a still-running key-rotator whose
LiteLLM restarted and a fresh key-rotator boot after a full converge, while
never spuriously minting a disabled or non-primary (static-seed) credential.
"""

from __future__ import annotations

import pytest

from app.config import Settings
from app.drivers.base import BaseDriver, RotationResult
from app.scheduler import RotationScheduler


def settings(**overrides) -> Settings:
    values = {
        "ROTATOR_INTERNAL_TOKEN": "0123456789abcdef0123456789abcdef",
        "PORTAL_IDENTITY_TOKEN": "abcdef0123456789abcdef0123456789",
        "VAULT_TOKEN": "vault-token",
        "LITELLM_MASTER_KEY": "litellm-master-key",
    }
    values.update(overrides)
    return Settings(**values)


class FakeLiteLLM:
    def __init__(self, present, *, fail: bool = False) -> None:
        self._present = set(present)
        self._fail = fail

    async def in_memory_credential_names(self) -> set[str]:
        if self._fail:
            raise RuntimeError("litellm unreachable")
        return set(self._present)


class FakeDb:
    def __init__(self, enabled: dict[str, bool]) -> None:
        self._enabled = enabled

    async def get_settings(self, vendor: str):
        return {"enabled": self._enabled.get(vendor, False)}


class PrimaryDriver(BaseDriver):
    ensure_credential_present = True

    def __init__(self, name: str, credential_name: str) -> None:
        self.name = name
        self.credential_name = credential_name


class StaticDriver(BaseDriver):
    """One-shot seed fallback: owns a credential but must never be proactively
    (re)minted by the reconcile."""

    ensure_credential_present = False

    def __init__(self, name: str, credential_name: str) -> None:
        self.name = name
        self.credential_name = credential_name


def _scheduler(litellm, db, drivers) -> RotationScheduler:
    sched = RotationScheduler(settings(), db, object(), litellm, drivers, identity=None)
    calls: list[str] = []

    async def fake_run_rotation(vendor: str) -> RotationResult:
        calls.append(vendor)
        return RotationResult(status="success")

    sched.run_rotation = fake_run_rotation  # type: ignore[assignment]
    sched._reminted = calls  # type: ignore[attr-defined]
    return sched


DRIVERS = {
    "anthropic": PrimaryDriver("anthropic", "anthropic-primary"),
    "static-anthropic": StaticDriver("static-anthropic", "anthropic-primary"),
    "openai": PrimaryDriver("openai", "openai-primary"),
    "static-openai": StaticDriver("static-openai", "openai-primary"),
}


@pytest.mark.asyncio
async def test_present_primary_credential_is_not_reminted() -> None:
    sched = _scheduler(
        FakeLiteLLM(["anthropic-primary"]),
        FakeDb({"anthropic": True}),
        DRIVERS,
    )
    await sched._reconcile_litellm_credentials()
    assert sched._reminted == []


@pytest.mark.asyncio
async def test_missing_primary_credential_is_minted_on_fresh_boot() -> None:
    """Full-converge / first-boot case: anthropic-primary was never seen by
    this process and is absent from memory — mint it now, don't wait for the
    scheduled rotation."""
    sched = _scheduler(
        FakeLiteLLM([]),
        FakeDb({"anthropic": True}),
        DRIVERS,
    )
    await sched._reconcile_litellm_credentials()
    assert sched._reminted == ["anthropic"]


@pytest.mark.asyncio
async def test_missing_credential_of_disabled_driver_is_not_minted() -> None:
    """openai is a primary driver but disabled (no key) — its credential is
    legitimately absent and must not be minted (no churn)."""
    sched = _scheduler(
        FakeLiteLLM([]),
        FakeDb({"anthropic": True, "openai": False}),
        DRIVERS,
    )
    await sched._reconcile_litellm_credentials()
    assert sched._reminted == ["anthropic"]  # openai skipped


@pytest.mark.asyncio
async def test_static_seed_credential_is_never_reminted() -> None:
    """Even if a static seed's settings row were enabled, the reconcile must
    not proactively mint through it — only ensure_credential_present drivers."""
    sched = _scheduler(
        FakeLiteLLM([]),  # anthropic-primary missing
        FakeDb({"anthropic": False, "static-anthropic": True}),
        DRIVERS,
    )
    await sched._reconcile_litellm_credentials()
    assert sched._reminted == []


@pytest.mark.asyncio
async def test_probe_failure_is_swallowed_without_minting() -> None:
    sched = _scheduler(
        FakeLiteLLM([], fail=True),
        FakeDb({"anthropic": True}),
        DRIVERS,
    )
    await sched._reconcile_litellm_credentials()  # must not raise
    assert sched._reminted == []
