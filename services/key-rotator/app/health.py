"""In-process health/alert flag registry for key-rotator.

Small shared surface so drivers and background watchers (e.g. the
Anthropic JWKS watcher, docs/anthropic-wif-bootstrap.md Phase 1a) can
raise loud, queryable alerts without knowing about FastAPI. main.py
exposes the snapshot on /healthz and per-vendor on /status.

Flag naming convention: "{vendor}.{subsystem}", for example
"anthropic.token_exchange" and "anthropic.jwks".
"""
from __future__ import annotations

import logging
import time
from typing import Any

logger = logging.getLogger("key_rotator.health")

_flags: dict[str, dict[str, Any]] = {}


def register_pending(name: str) -> None:
    """Seed a subsystem flag in a 'pending / never run' state (ok=False) so
    `all_ok()` is not falsely green before that subsystem has affirmatively
    succeeded at least once. Never overwrites an existing flag — a
    subsystem that has already reported keeps its real state.
    """
    if name not in _flags:
        _flags[name] = {
            "ok": False,
            "detail": "pending: has not run yet",
            "since": time.time(),
            "pending": True,
        }


def set_ok(name: str) -> None:
    """Mark a subsystem healthy (clears a previous alert or pending state)."""
    prev = _flags.get(name)
    if prev is not None and not prev["ok"] and not prev.get("pending"):
        logger.info("health flag %s recovered", name)
    _flags[name] = {"ok": True, "detail": "", "since": time.time()}


def set_alert(name: str, detail: str) -> None:
    """Raise (or refresh) an alert for a subsystem. Logged at ERROR so it
    lands in Loki/Cribl alerting even if nobody polls the API.
    """
    prev = _flags.get(name)
    since = prev["since"] if prev is not None and not prev["ok"] else time.time()
    _flags[name] = {"ok": False, "detail": detail, "since": since}
    logger.error("health ALERT %s: %s", name, detail)


def snapshot() -> dict[str, dict[str, Any]]:
    """Copy of all flags: {name: {ok, detail, since}}."""
    return {name: dict(flag) for name, flag in _flags.items()}


def all_ok() -> bool:
    """True only if every registered subsystem has affirmatively succeeded.

    An empty registry is NOT ok: reporting green before any subsystem has
    run is exactly the false-positive this guards against. Pending flags
    (registered but never run) carry ok=False and hold this red until they
    succeed.
    """
    if not _flags:
        return False
    return all(flag["ok"] for flag in _flags.values())


def alerts_for_vendor(vendor: str) -> list[dict[str, Any]]:
    """Active (not-ok) flags whose name is scoped to `vendor`."""
    return [
        {"name": name, **flag}
        for name, flag in sorted(_flags.items())
        if not flag["ok"] and name.split(".", 1)[0] == vendor
    ]
