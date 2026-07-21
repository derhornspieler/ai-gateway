"""Driver base class + shared types for key-rotator vendor plugins.

Design ref: docs/solution-map.md §9.4 — the key-rotator uses a per-vendor
driver interface. Anthropic WIF is the only registered driver today. A future
provider requires a reviewed driver, catalog entry, release, and tests.
"""
from __future__ import annotations

import dataclasses
from typing import Any, Optional


@dataclasses.dataclass
class RotationResult:
    """Outcome of a single driver.rotate() call.

    status: one of "success" | "skipped" | "disabled" | "failed".
    next_run_seconds: optional dynamic next-run override, honored by
        app.scheduler.RotationScheduler (used by the Anthropic WIF driver
        to reschedule at 80% of the minted token's lifetime — see
        docs/anthropic-wif-bootstrap.md Phase 1 step 3).
    settings_self_disabled: the driver durably set its own settings row to
        enabled=false. The scheduler uses this explicit signal to complete a
        zero-interval lifecycle even when the run came from Rotate now rather
        than the canonical one-shot callback.
    """

    status: str
    detail: str = ""
    next_run_seconds: Optional[float] = None
    settings_self_disabled: bool = False


@dataclasses.dataclass
class DriverContext:
    """Dependencies handed to every driver on each rotate() call.

    Typed as `Any` for the client objects to avoid import cycles between
    drivers/, db.py, litellm_client.py, and vault_client.py; each concrete
    driver knows the real types (app.config.Settings, app.vault_client.
    VaultClient, app.litellm_client.LiteLLMClient, app.db.Database).
    """

    settings: Any
    vault: Any
    litellm: Any
    db: Any
    vendor_settings: dict[str, Any]


class BaseDriver:
    """Base class for all vendor rotation drivers."""

    name: str = "base"
    # The LiteLLM credential this driver keeps current. The scheduler's
    # credential-presence reconcile uses it to detect a credential that
    # LiteLLM dropped from memory on a restart and re-mint it promptly.
    # None means "declares no managed credential" and the reconcile skips it.
    credential_name: Optional[str] = None
    # True for a PRIMARY driver whose credential inference depends on and which
    # therefore must be present whenever the driver is enabled. The presence
    # reconcile proactively (re)mints such a credential within one cadence if it
    # is missing from LiteLLM's memory — after a restart, or a first boot before
    # the scheduled rotation — bounding the inference outage. False for one-shot
    # static seed fallbacks, which the reconcile must never spuriously trigger.
    ensure_credential_present: bool = False

    async def rotate(self, ctx: DriverContext) -> RotationResult:
        """Perform one rotation cycle. Must not raise for expected/handled
        failure modes (return RotationResult(status="failed"/"disabled"/
        "skipped", ...) instead) — the scheduler treats an unhandled
        exception as an additional bug-level failure and records it, but
        drivers should prefer returning a structured result.
        """
        raise NotImplementedError
