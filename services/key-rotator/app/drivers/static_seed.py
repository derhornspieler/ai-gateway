"""static_seed driver — seeds an initial vendor API key into LiteLLM from a
static secret held in Vault.

This exists purely to bootstrap local/dev testing before the real
Anthropic WIF (app/drivers/anthropic_wif.py) or OpenAI blue/green
(app/drivers/openai_svcacct.py) drivers are configured and enabled — see
docs/solution-map.md §1.7 fallback note ("static sk-ant-api key in Vault")
and §9.4 (driver plugin interface). It is registered under the
"static-anthropic" / "static-openai" vendor rows (rotator_settings,
interval_seconds=0 => run once at boot).

Reads Vault KV v2 at logical path "ai-gateway/vendors/{vendor}"
(kv/data/ai-gateway/vendors/{vendor} on the wire), field "api_key", and
upserts a LiteLLM credential named "{vendor}-primary".
"""
from __future__ import annotations

import logging

from app.drivers.base import BaseDriver, DriverContext, RotationResult
from app.vault_client import VaultError, mask_secret

logger = logging.getLogger("key_rotator.drivers.static_seed")

# A static seed is otherwise a process-lifetime one-shot. Mark only the
# explicitly transient Vault-error path for a bounded scheduler retry; missing
# bootstrap material remains a terminal skip until an operator uses Rotate now.
VAULT_RETRY_SECONDS = 60.0


class StaticSeedDriver(BaseDriver):
    def __init__(self, vendor: str) -> None:
        # `vendor` is the underlying vendor name (e.g. "anthropic"), while
        # self.name is the rotator_settings row this driver is registered
        # under (e.g. "static-anthropic").
        self.vendor = vendor
        self.name = f"static-{vendor}"

    async def _self_disable(self, ctx: DriverContext, config: dict | None = None) -> None:
        """Persist enabled=False for this static-{vendor} row so the seed is
        a true one-shot: it never re-runs on a later scheduler reload (every
        PUT /settings/{vendor} calls reload()). Without this, the seed
        re-fired on every settings change and could revert the real
        {vendor}-primary credential to the stale static key.
        """
        await ctx.db.upsert_settings(
            self.name,
            enabled=False,
            interval_seconds=0,
            grace_seconds=0,
            config=config or {},
        )

    async def rotate(self, ctx: DriverContext) -> RotationResult:
        # Never clobber a live rotated key. The real vendor driver
        # (anthropic_wif / openai_svcacct) owns the SAME vault path
        # (ai-gateway/vendors/{vendor}) and the SAME litellm credential
        # ({vendor}-primary). If the real driver is enabled, this static
        # seed must do nothing — otherwise a reload triggered by any
        # settings change would overwrite the real, freshly-rotated key
        # with a stale static one.
        real_row = await ctx.db.get_settings(self.vendor)
        if real_row is not None and real_row.get("enabled"):
            detail = (
                f"real {self.vendor} driver is enabled and owns {self.vendor}-primary; "
                "static seed disabled to avoid clobbering the live rotated key"
            )
            logger.info("static_seed: %s", detail)
            await self._self_disable(ctx)
            return RotationResult(
                status="skipped",
                detail=detail,
                settings_self_disabled=True,
            )

        try:
            secret = ctx.vault.read(f"ai-gateway/vendors/{self.vendor}")
        except VaultError as exc:
            # Transient vault error — do NOT self-disable, so a later run
            # can still seed once vault recovers.
            detail = f"vault read error seeding {self.vendor}: {exc}"
            logger.error("static_seed: %s", detail)
            return RotationResult(
                status="failed",
                detail=detail,
                next_run_seconds=VAULT_RETRY_SECONDS,
            )
        api_key = (secret or {}).get("api_key")

        if not api_key:
            detail = f"no static api_key present in vault at ai-gateway/vendors/{self.vendor}"
            logger.info("static_seed: %s, skipping", detail)
            return RotationResult(status="skipped", detail=detail)

        cred_name = f"{self.vendor}-primary"
        await ctx.litellm.upsert_credential(cred_name, {"api_key": api_key})
        detail = f"seeded litellm credential={cred_name} from vault key={mask_secret(api_key)}"
        logger.info("static_seed: %s", detail)
        # One-shot: self-disable so subsequent reloads never re-seed (and
        # never overwrite a key the real driver later rotates in).
        await self._self_disable(ctx)
        return RotationResult(
            status="success",
            detail=detail,
            settings_self_disabled=True,
        )
