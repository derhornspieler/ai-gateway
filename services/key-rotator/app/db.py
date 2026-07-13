"""Postgres access layer for key-rotator (plain SQL via psycopg3, async).

Design ref: docs/solution-map.md §1.7 — "Schedules/grace windows are
admin-configurable from the dev-portal admin section" (rotator_settings)
and "every rotation ... emits an OTel event" (rotation_history is the
durable audit trail backing that, independent of whether the OTel exporter
is reachable — see app/otel.py fail-open behavior).

Startup is tolerant of Postgres not being ready yet: key-rotator and
postgres both start concurrently on their isolated database network with no guaranteed
ordering (docs/solution-map.md §3), so connect_with_retry backs off for up
to ~60s and then continues in a degraded mode rather than crash-looping.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from typing import Any, Optional

import psycopg
from psycopg.rows import dict_row

from app.config import Settings

logger = logging.getLogger("key_rotator.db")

CREATE_SETTINGS_SQL = """
CREATE TABLE IF NOT EXISTS rotator_settings (
    vendor text PRIMARY KEY,
    enabled boolean NOT NULL DEFAULT false,
    interval_seconds integer NOT NULL DEFAULT 0,
    grace_seconds integer NOT NULL DEFAULT 300,
    config jsonb NOT NULL DEFAULT '{}'::jsonb,
    updated_at timestamptz NOT NULL DEFAULT now()
);
"""

CREATE_HISTORY_SQL = """
CREATE TABLE IF NOT EXISTS rotation_history (
    id bigserial PRIMARY KEY,
    vendor text NOT NULL,
    action text NOT NULL,
    status text NOT NULL,
    detail text,
    created_at timestamptz NOT NULL DEFAULT now()
);
"""

# (vendor, enabled, interval_seconds, grace_seconds, config)
# anthropic / openai start disabled until Vault bootstrap material exists
# (docs/anthropic-wif-bootstrap.md Phase 0; solution-map.md §1.7 OpenAI
# admin-key setup). The static-* rows seed LiteLLM creds once at boot
# (interval_seconds == 0 => run-once) for local/dev testing.
DEFAULT_SETTINGS: list[tuple[str, bool, int, int, dict[str, Any]]] = [
    ("anthropic", False, 3000, 300, {}),
    ("openai", False, 30 * 86400, 300, {}),
    ("static-anthropic", True, 0, 0, {}),
    ("static-openai", True, 0, 0, {}),
]


class Database:
    """Thin async wrapper around a single psycopg3 AsyncConnection.

    A single shared connection + asyncio.Lock is sufficient here: rotation
    cadence is minutes, and API traffic is low-volume internal admin
    calls (dev-portal), not a high-throughput workload.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._conn: Optional[psycopg.AsyncConnection] = None
        self._lock = asyncio.Lock()
        self._connect_lock = asyncio.Lock()
        self.degraded = False

    async def connect_with_retry(self, max_wait_seconds: int = 60) -> None:
        """Retry connecting with exponential backoff for up to
        `max_wait_seconds`, then continue in degraded mode. Later calls
        will keep trying to (re)connect lazily via `_ensure_conn`.
        """
        delay = 1.0
        waited = 0.0
        while waited < max_wait_seconds:
            try:
                await self._connect()
                self.degraded = False
                logger.info("connected to postgres")
                return
            except Exception as exc:  # noqa: BLE001
                logger.warning("postgres not ready (%s), retrying in %.1fs", exc, delay)
                await asyncio.sleep(delay)
                waited += delay
                delay = min(delay * 2, 10.0)
        logger.error(
            "postgres still unreachable after %ss; continuing in degraded mode", max_wait_seconds
        )
        self.degraded = True

    async def _connect(self) -> None:
        if self._conn is not None and not self._conn.closed:
            await self._conn.close()
        self._conn = await psycopg.AsyncConnection.connect(
            self._settings.database_url,
            autocommit=True,
            row_factory=dict_row,
            connect_timeout=10,
        )
        try:
            await self._init_schema()
        except Exception:
            await self._conn.close()
            self._conn = None
            raise

    @asynccontextmanager
    async def rotation_lock(self, vendor: str) -> AsyncIterator[bool]:
        """Hold a Postgres advisory lock on a dedicated connection.

        The in-process asyncio lock prevents duplicate jobs in one Uvicorn
        process only. During rolling restarts or accidental replica scaling,
        two schedulers otherwise create and revoke credentials concurrently.
        Fail closed when Postgres cannot provide the distributed lock.
        """
        digest = hashlib.sha256(f"key-rotator:{vendor}".encode()).digest()
        lock_id = int.from_bytes(digest[:8], byteorder="big", signed=True)
        conn: Optional[psycopg.AsyncConnection] = None
        acquired = False
        try:
            conn = await psycopg.AsyncConnection.connect(
                self._settings.database_url,
                autocommit=True,
                row_factory=dict_row,
                connect_timeout=10,
            )
            async with conn.cursor() as cur:
                await cur.execute("SELECT pg_try_advisory_lock(%s) AS acquired", (lock_id,))
                row = await cur.fetchone()
                acquired = bool(row and row["acquired"])
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "could not acquire distributed rotation lock for vendor=%s: %s",
                vendor,
                exc,
            )
            if conn is not None:
                await conn.close()
            yield False
            return

        try:
            yield acquired
        finally:
            if conn is not None:
                if acquired and not conn.closed:
                    try:
                        async with conn.cursor() as cur:
                            await cur.execute("SELECT pg_advisory_unlock(%s)", (lock_id,))
                    except Exception as exc:  # noqa: BLE001
                        # Closing the dedicated session below releases the
                        # advisory lock even if the explicit unlock failed.
                        logger.warning(
                            "distributed rotation unlock failed for vendor=%s: %s",
                            vendor,
                            exc,
                        )
                await conn.close()

    async def _ensure_conn(self) -> psycopg.AsyncConnection:
        if self._conn is None or self._conn.closed:
            # Double-checked under a separate lock: concurrent API and
            # scheduler calls must not both reconnect and leak/overwrite one
            # another's sessions.
            async with self._connect_lock:
                if self._conn is None or self._conn.closed:
                    await self._connect()
                    self.degraded = False
        if self._conn is None:
            raise RuntimeError("database connection was not initialized")
        return self._conn

    async def _init_schema(self) -> None:
        if self._conn is None:
            raise RuntimeError("database connection was not initialized")
        async with self._conn.cursor() as cur:
            await cur.execute(CREATE_SETTINGS_SQL)
            await cur.execute(CREATE_HISTORY_SQL)
        await self._seed_defaults()

    async def _seed_defaults(self) -> None:
        if self._conn is None:
            raise RuntimeError("database connection was not initialized")
        async with self._conn.cursor() as cur:
            for vendor, enabled, interval, grace, config in DEFAULT_SETTINGS:
                await cur.execute(
                    """
                    INSERT INTO rotator_settings
                        (vendor, enabled, interval_seconds, grace_seconds, config, updated_at)
                    VALUES (%s, %s, %s, %s, %s::jsonb, now())
                    ON CONFLICT (vendor) DO NOTHING
                    """,
                    (vendor, enabled, interval, grace, json.dumps(config)),
                )

    async def list_settings(self) -> list[dict[str, Any]]:
        try:
            conn = await self._ensure_conn()
        except Exception as exc:  # noqa: BLE001
            logger.warning("list_settings: db unavailable: %s", exc)
            return []
        async with self._lock:
            async with conn.cursor() as cur:
                await cur.execute("SELECT * FROM rotator_settings ORDER BY vendor")
                return list(await cur.fetchall())

    async def get_settings(self, vendor: str) -> Optional[dict[str, Any]]:
        try:
            conn = await self._ensure_conn()
        except Exception as exc:  # noqa: BLE001
            logger.warning("get_settings: db unavailable: %s", exc)
            return None
        async with self._lock:
            async with conn.cursor() as cur:
                await cur.execute("SELECT * FROM rotator_settings WHERE vendor = %s", (vendor,))
                return await cur.fetchone()

    async def upsert_settings(
        self,
        vendor: str,
        enabled: bool,
        interval_seconds: int,
        grace_seconds: int,
        config: Optional[dict[str, Any]],
    ) -> None:
        """Upsert control-plane settings without losing driver state.

        ``config=None`` deliberately preserves the existing JSONB document on
        conflict. Browser admins change cadence/enabled fields without seeing
        the driver's internal state, so interpreting omission as an empty
        object destroyed refresh/retry bookkeeping. An explicit dict replaces
        config, preserving the API's ability to intentionally reset it.
        """
        conn = await self._ensure_conn()
        async with self._lock:
            async with conn.cursor() as cur:
                if config is None:
                    await cur.execute(
                        """
                        INSERT INTO rotator_settings
                            (vendor, enabled, interval_seconds, grace_seconds, config, updated_at)
                        VALUES (%s, %s, %s, %s, '{}'::jsonb, now())
                        ON CONFLICT (vendor) DO UPDATE SET
                            enabled = EXCLUDED.enabled,
                            interval_seconds = EXCLUDED.interval_seconds,
                            grace_seconds = EXCLUDED.grace_seconds,
                            updated_at = now()
                        """,
                        (vendor, enabled, interval_seconds, grace_seconds),
                    )
                else:
                    await cur.execute(
                        """
                        INSERT INTO rotator_settings
                            (vendor, enabled, interval_seconds, grace_seconds, config, updated_at)
                        VALUES (%s, %s, %s, %s, %s::jsonb, now())
                        ON CONFLICT (vendor) DO UPDATE SET
                            enabled = EXCLUDED.enabled,
                            interval_seconds = EXCLUDED.interval_seconds,
                            grace_seconds = EXCLUDED.grace_seconds,
                            config = EXCLUDED.config,
                            updated_at = now()
                        """,
                        (
                            vendor,
                            enabled,
                            interval_seconds,
                            grace_seconds,
                            json.dumps(config, allow_nan=False),
                        ),
                    )

    async def update_settings_config(
        self, vendor: str, config: dict[str, Any]
    ) -> None:
        """Atomically update driver bookkeeping without reverting admin edits.

        A rotation captures a settings row before doing network I/O. Writing
        that whole stale row afterward raced an admin cadence change and could
        restore the old enabled/interval/grace values. Drivers use this narrow
        update so the two writers own disjoint columns.
        """
        conn = await self._ensure_conn()
        async with self._lock:
            async with conn.cursor() as cur:
                await cur.execute(
                    """
                    UPDATE rotator_settings
                    SET config = %s::jsonb, updated_at = now()
                    WHERE vendor = %s
                    """,
                    (json.dumps(config, allow_nan=False), vendor),
                )
                if cur.rowcount != 1:
                    raise RuntimeError(
                        f"rotation settings row disappeared for vendor={vendor}"
                    )

    async def record_history(self, vendor: str, action: str, status: str, detail: str = "") -> None:
        """Best-effort audit row. Never raises — a failed history write
        must not block a rotation from completing.
        """
        try:
            conn = await self._ensure_conn()
            async with self._lock:
                async with conn.cursor() as cur:
                    await cur.execute(
                        """
                        INSERT INTO rotation_history (vendor, action, status, detail, created_at)
                        VALUES (%s, %s, %s, %s, now())
                        """,
                        (vendor, action, status, detail),
                    )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "failed to record history (vendor=%s action=%s status=%s): %s",
                vendor,
                action,
                status,
                exc,
            )

    async def last_history(self, vendor: str) -> Optional[dict[str, Any]]:
        try:
            conn = await self._ensure_conn()
        except Exception:  # noqa: BLE001
            return None
        async with self._lock:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT * FROM rotation_history WHERE vendor = %s ORDER BY created_at DESC LIMIT 1",
                    (vendor,),
                )
                return await cur.fetchone()

    async def history(self, limit: int = 50) -> list[dict[str, Any]]:
        try:
            conn = await self._ensure_conn()
        except Exception:  # noqa: BLE001
            return []
        async with self._lock:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT * FROM rotation_history ORDER BY created_at DESC LIMIT %s", (limit,)
                )
                return list(await cur.fetchall())

    async def ready(self) -> bool:
        """Return whether the control-plane database can execute a query.

        This is intentionally stricter than process liveness: a rotator that
        cannot persist locks/settings must not be reported ready after the
        bootstrap phase.
        """
        try:
            conn = await self._ensure_conn()
            async with self._lock:
                async with conn.cursor() as cur:
                    await cur.execute("SELECT 1 AS ready")
                    row = await cur.fetchone()
            self.degraded = not bool(row and row["ready"] == 1)
            return not self.degraded
        except Exception as exc:  # noqa: BLE001
            self.degraded = True
            logger.warning("database readiness probe failed: %s", exc)
            return False

    async def close(self) -> None:
        if self._conn is not None and not self._conn.closed:
            await self._conn.close()
