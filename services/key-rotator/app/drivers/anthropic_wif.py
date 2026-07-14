"""Anthropic driver — Workload Identity Federation token broker.

Design ref: docs/solution-map.md §1.7 ("Anthropic — short-lived tokens
minted from our own Keycloak") and the full runbook in
docs/anthropic-wif-bootstrap.md. This driver implements Phase 1
("recurring automated flow, no human"):

  1. Read bootstrap config from Vault (written once, by hand, during the
     Phase 0 manual bootstrap — see the runbook). If missing/incomplete,
     the vendor is treated as not-yet-bootstrapped ("disabled"), not an
     error.
  2. POST client_credentials to the Keycloak token URL — INTERNAL call,
     direct (not via egress; Keycloak is not a vendor). Client auth is
     private_key_jwt (RFC 7523 client assertion) signed with the
     Vault-PKI-issued key — NO static client secret (runbook Phase 0
     step 2). A static-secret fallback exists ONLY behind
     ANTHROPIC_WIF_ALLOW_INSECURE_CLIENT_SECRET (default off) and logs an
     ERROR on every use.
  3. Exchange the resulting JWT at Anthropic's
     POST {EGRESS_BASE}/anthropic/v1/oauth/token (RFC 7523 jwt-bearer),
     via the pinned envoy-egress path — never api.anthropic.com directly.
  4. PATCH the "anthropic-primary" LiteLLM credential with the new
     short-lived sk-ant-oat01-... token.
  5. Request a dynamic reschedule at ~80% of the token's expires_in
     (runbook: "Refresh at ~80% of lifetime").

Failure handling: exponential backoff with jitter on failure (the runbook
notes there's no documented rate limit on the token endpoint, so backoff
is defensive, not compliance with a published limit). If a failure occurs
and the currently-active token is already past 90% of its lifetime, this
raises an explicit alert (ERROR log + "alert" history row) since inference
is at risk of going dark.
"""
from __future__ import annotations

import logging
import random
import time
import uuid
from pathlib import Path
from typing import Any, Optional

import httpx
import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from app import health
from app.drivers.base import BaseDriver, DriverContext, RotationResult
from app.provider_state import (
    CREDENTIAL_ISSUED,
    CREDENTIAL_LIFECYCLE_FIELD,
    CREDENTIAL_PROMOTION_PENDING,
)
from app.security import validate_wif_token_claims
from app.vault_client import VaultError, mask_secret

logger = logging.getLogger("key_rotator.drivers.anthropic_wif")

REQUIRED_BOOTSTRAP_FIELDS = [
    "kc_token_url",
    "kc_client_id",
    "federation_rule_id",
    "organization_id",
    "service_account_id",
]

MIN_BACKOFF_SECONDS = 15.0
MAX_BACKOFF_SECONDS = 1800.0

# Lifetime of the private_key_jwt client assertion we present to Keycloak.
# Short by design (RFC 7523 §3: exp is the only required time claim).
CLIENT_ASSERTION_LIFETIME_SECONDS = 60


def _assertion_alg_for_key(key: Any) -> str:
    """Pick the JWS alg matching the loaded private key type. Anthropic
    rejects HS*/none; Keycloak's private_key_jwt supports RS*/ES*/PS*.
    """
    if isinstance(key, rsa.RSAPrivateKey):
        return "RS256"
    if isinstance(key, ec.EllipticCurvePrivateKey):
        if key.curve.name == "secp384r1":
            return "ES384"
        if key.curve.name == "secp521r1":
            return "ES512"
        return "ES256"
    raise RuntimeError(f"unsupported client-assertion key type: {type(key).__name__}")


class AnthropicWifDriver(BaseDriver):
    name = "anthropic"

    async def rotate(self, ctx: DriverContext) -> RotationResult:
        try:
            bootstrap = ctx.vault.read("ai-gateway/anthropic-wif")
        except VaultError as exc:
            # A vault read error is NOT "not bootstrapped" — do not claim
            # disabled and silently stop refreshing a live token.
            detail = f"vault read error reading anthropic-wif bootstrap ({exc}); not rotating"
            logger.error("anthropic_wif: %s", detail)
            health.set_alert("anthropic.token_exchange", detail)
            return await self._handle_failure(ctx, dict(ctx.vendor_settings.get("config") or {}), exc)
        if not bootstrap or any(f not in bootstrap for f in REQUIRED_BOOTSTRAP_FIELDS):
            detail = "anthropic-wif bootstrap config missing/incomplete in vault (Phase 0 not yet done)"
            logger.info("anthropic_wif: %s", detail)
            return RotationResult(status="disabled", detail=detail)

        state = dict(ctx.vendor_settings.get("config") or {})

        try:
            assertion = await self._get_keycloak_jwt(ctx, bootstrap)
            access_token, expires_in = await self._exchange_anthropic_token(ctx, bootstrap, assertion)
        except Exception as exc:  # noqa: BLE001
            return await self._handle_failure(ctx, state, exc)

        try:
            # Persist an indeterminate marker before handing a newly minted
            # credential to LiteLLM.  A successful promotion followed by a
            # lost/failed state write must never leave an older expired
            # timestamp that provider deletion could mistake for proof that
            # the active credential is gone.
            state[CREDENTIAL_LIFECYCLE_FIELD] = CREDENTIAL_PROMOTION_PENDING
            await self._persist_state(ctx, state)
            await ctx.litellm.upsert_credential("anthropic-primary", {"api_key": access_token})

            now = time.time()
            state[CREDENTIAL_LIFECYCLE_FIELD] = CREDENTIAL_ISSUED
            state["_last_issued_at"] = now
            state["_last_expires_in"] = expires_in
            state["_fail_count"] = 0
            await self._persist_state(ctx, state)
        except Exception as exc:  # noqa: BLE001
            # A successful vendor exchange is not a healthy rotation until
            # the gateway actually holds the token and its refresh deadline
            # is durable. Previously this flag went green before promotion,
            # hiding a LiteLLM failure while the active token expired.
            health.set_alert(
                "anthropic.token_exchange",
                f"token minted but gateway promotion/state persistence failed: {exc}",
            )
            return await self._handle_failure(ctx, state, exc)

        health.set_ok("anthropic.token_exchange")

        next_run = max(30.0, expires_in * 0.8)
        detail = (
            f"rotated anthropic-primary, new token={mask_secret(access_token)}, "
            f"expires_in={expires_in}s, next refresh in {next_run:.0f}s"
        )
        logger.info("anthropic_wif: %s", detail)
        return RotationResult(status="success", detail=detail, next_run_seconds=next_run)

    async def _handle_failure(
        self, ctx: DriverContext, state: dict[str, Any], exc: Exception
    ) -> RotationResult:
        detail = f"rotation failed: {exc}"
        logger.error("anthropic_wif: %s", detail)
        await ctx.db.record_history(self.name, "rotate", "failed", detail)

        # Anthropic returns opaque 400 invalid_grant for ALL exchange
        # failures — including signature verification against a stale
        # inline JWKS (docs/anthropic-wif-bootstrap.md Phase 1 step 4 /
        # Phase 1a). Surface that loudly: if Keycloak rotated its realm
        # signing keys and the new JWKS wasn't re-pushed, every exchange
        # fails exactly like this. The JWKS watcher (app/jwks_watcher.py)
        # re-pushes on drift; this alert makes the failure visible on
        # /healthz + /status in the meantime.
        if (
            isinstance(exc, httpx.HTTPStatusError)
            and exc.response.status_code in (400, 401)
            and "/oauth/token" in str(exc.request.url)
        ):
            health.set_alert(
                "anthropic.token_exchange",
                f"token exchange rejected (HTTP {exc.response.status_code}) — possible "
                "signature/JWKS mismatch after a Keycloak realm key rotation; check "
                "Console -> Workload identity -> History and the anthropic.jwks flag",
            )

        last_issued_at = state.get("_last_issued_at")
        last_expires_in = state.get("_last_expires_in")
        if last_issued_at and last_expires_in:
            age = time.time() - float(last_issued_at)
            if age > 0.9 * float(last_expires_in):
                alert = (
                    f"ALERT: anthropic token is past 90% of its lifetime "
                    f"(age={age:.0f}s, lifetime={last_expires_in}s) and refresh is failing — "
                    f"inference is at risk of going dark"
                )
                logger.error("anthropic_wif: %s", alert)
                await ctx.db.record_history(self.name, "alert", "failed", alert)

        fail_count = int(state.get("_fail_count", 0)) + 1
        state["_fail_count"] = fail_count
        try:
            await self._persist_state(ctx, state)
        except Exception as persist_exc:  # noqa: BLE001
            # State persistence being down must not discard the calculated
            # retry deadline. The scheduler can still retry before the active
            # token expires even while Postgres is degraded.
            logger.error(
                "anthropic_wif: could not persist failure state: %s",
                persist_exc,
            )
            health.set_alert(
                "anthropic.token_exchange",
                f"rotation failed and retry state could not be persisted: {persist_exc}",
            )

        # Bound the failure backoff so persistent failure does NOT push the
        # next attempt out past the normal refresh cadence — otherwise the
        # recurring job idles at the max backoff while the active token
        # expires (inference goes dark). Cap to the smaller of the max
        # backoff, the configured interval, and 80% of the last token
        # lifetime (the point we'd normally refresh at), whichever we know.
        cadence_candidates = [MAX_BACKOFF_SECONDS]
        if last_expires_in:
            cadence_candidates.append(0.8 * float(last_expires_in))
        interval_seconds = int(ctx.vendor_settings.get("interval_seconds") or 0)
        if interval_seconds > 0:
            cadence_candidates.append(float(interval_seconds))
        cadence_cap = max(MIN_BACKOFF_SECONDS, min(cadence_candidates))

        backoff = min(cadence_cap, MIN_BACKOFF_SECONDS * (2 ** min(fail_count, 6)))
        backoff = backoff * (0.5 + random.random())  # +/- jitter to avoid thundering herd
        backoff = min(backoff, cadence_cap)  # jitter must not exceed the cadence cap
        return RotationResult(status="failed", detail=detail, next_run_seconds=backoff)

    async def _persist_state(self, ctx: DriverContext, state: dict[str, Any]) -> None:
        """Persist internal bookkeeping (last token issuance, failure
        count) back into rotator_settings.config so it survives restarts.
        """
        await ctx.db.update_settings_config(self.name, state)

    def _load_client_assertion_key(self, ctx: DriverContext) -> tuple[Any, Optional[str]]:
        """Load the Vault-PKI-issued private key used to sign the
        private_key_jwt client assertion. Source order:

          1. KC_CLIENT_ASSERTION_KEY_FILE — a mounted PEM path (e.g. a
             Vault-agent-rendered file), if set.
          2. Vault KV v2 at KC_CLIENT_ASSERTION_KEY_VAULT_PATH — fields
             `private_key_pem` (required) and `kid` (optional; set it to
             the certificate's key id registered on the Keycloak client).

        Returns (private_key, kid). Raises on any missing/invalid key —
        this is a hard failure, NOT a fall-back-to-secret situation.
        """
        settings = ctx.settings
        kid: Optional[str] = None

        if settings.kc_client_assertion_key_file:
            pem = Path(settings.kc_client_assertion_key_file).read_bytes()
        else:
            doc = ctx.vault.read(settings.kc_client_assertion_key_vault_path)
            if not doc or not doc.get("private_key_pem"):
                raise RuntimeError(
                    "client-assertion private key not found: set "
                    "KC_CLIENT_ASSERTION_KEY_FILE or write private_key_pem to vault path "
                    f"'{settings.kc_client_assertion_key_vault_path}'"
                )
            pem = str(doc["private_key_pem"]).encode()
            kid = doc.get("kid") or None

        return load_pem_private_key(pem, password=None), kid

    def _build_client_assertion(self, ctx: DriverContext, bootstrap: dict[str, Any]) -> str:
        """RFC 7523 §2.2 client authentication JWT for Keycloak's
        private_key_jwt method: iss = sub = client_id, aud = token
        endpoint, unique jti, short exp.
        """
        token_url = ctx.settings.validated_keycloak_token_url(bootstrap["kc_token_url"])
        token_audience = ctx.settings.keycloak_assertion_audience_for_token_url(
            token_url
        )
        key, kid = self._load_client_assertion_key(ctx)
        now = int(time.time())
        claims = {
            "iss": bootstrap["kc_client_id"],
            "sub": bootstrap["kc_client_id"],
            "aud": token_audience,
            "jti": uuid.uuid4().hex,
            "iat": now,
            "exp": now + CLIENT_ASSERTION_LIFETIME_SECONDS,
        }
        headers = {"kid": kid} if kid else None
        return pyjwt.encode(claims, key, algorithm=_assertion_alg_for_key(key), headers=headers)

    async def _get_keycloak_jwt(self, ctx: DriverContext, bootstrap: dict[str, Any]) -> str:
        """Client-credentials exchange against our own Keycloak realm,
        authenticating with a private_key_jwt client assertion (RFC 7523)
        signed by the Vault-PKI-issued key — no static client secret.

        INTERNAL call — direct to Keycloak, NOT via envoy-egress. Keycloak
        lives on an internal application network; it is not an internet vendor.
        docs/anthropic-wif-bootstrap.md Phase 1 step 1 / Phase 0 step 2.
        """
        token_url = ctx.settings.validated_keycloak_token_url(bootstrap["kc_token_url"])
        data: dict[str, str] = {
            "grant_type": "client_credentials",
            "client_id": bootstrap["kc_client_id"],
        }

        try:
            data["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            data["client_assertion"] = self._build_client_assertion(ctx, bootstrap)
        except Exception as exc:  # noqa: BLE001
            if not (
                ctx.settings.anthropic_wif_allow_insecure_client_secret
                and bootstrap.get("kc_client_secret")
            ):
                # FAIL CLOSED: private_key_jwt is the only sanctioned client
                # auth. If the signing key isn't provisioned (no PEM file,
                # no vault key) we do NOT fall back to a static secret unless
                # the explicit insecure flag is set. Raise a loud health
                # alert so the missing provisioning is visible on /healthz +
                # /status, then re-raise (caller records a failed rotation).
                health.set_alert(
                    "anthropic.token_exchange",
                    "private_key_jwt client assertion unavailable "
                    f"({exc}) and insecure static-secret fallback is disabled — "
                    "cannot authenticate to Keycloak. Provision the signing key: set "
                    "KC_CLIENT_ASSERTION_KEY_FILE or write private_key_pem to vault path "
                    f"'{ctx.settings.kc_client_assertion_key_vault_path}', and set the "
                    "Keycloak client's clientAuthenticatorType to 'client-jwt'.",
                )
                raise
            logger.error(
                "anthropic_wif: INSECURE — private_key_jwt client assertion unavailable (%s) "
                "and ANTHROPIC_WIF_ALLOW_INSECURE_CLIENT_SECRET=true: falling back to the "
                "static kc_client_secret. This violates the WIF design "
                "(docs/anthropic-wif-bootstrap.md Phase 0 step 2) and must NEVER be enabled "
                "in production.",
                exc,
            )
            data.pop("client_assertion_type", None)
            data.pop("client_assertion", None)
            data["client_secret"] = bootstrap["kc_client_secret"]

        async with httpx.AsyncClient(
            timeout=15.0, trust_env=False, follow_redirects=False
        ) as client:
            resp = await client.post(
                token_url,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
            payload = resp.json()
            token = payload.get("access_token")
            if not token:
                raise RuntimeError("keycloak token response missing access_token")
            validate_wif_token_claims(token, client_id=bootstrap["kc_client_id"])
            return token

    async def mint_access_token(self, ctx: DriverContext, bootstrap: dict[str, Any]) -> str:
        """Mint a fresh short-lived Anthropic access token (Keycloak
        assertion -> Anthropic exchange) WITHOUT touching LiteLLM or the
        driver's persisted state. This remains available for the normal
        workspace-scoped inference flow; it is never used for issuer
        administration, which requires a separate interactive org:admin.
        """
        assertion = await self._get_keycloak_jwt(ctx, bootstrap)
        access_token, _ = await self._exchange_anthropic_token(ctx, bootstrap, assertion)
        return access_token

    async def _exchange_anthropic_token(
        self, ctx: DriverContext, bootstrap: dict[str, Any], assertion: str
    ) -> tuple[str, int]:
        """Exchange the Keycloak-issued JWT for a short-lived Anthropic
        sk-ant-oat01 token, via the pinned egress proxy — never call
        api.anthropic.com directly. docs/anthropic-wif-bootstrap.md
        Phase 1 step 2.
        """
        url = f"{ctx.settings.anthropic_base}/v1/oauth/token"
        body: dict[str, Any] = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion,
            "federation_rule_id": bootstrap["federation_rule_id"],
            "organization_id": bootstrap["organization_id"],
            "service_account_id": bootstrap["service_account_id"],
        }
        if bootstrap.get("workspace_id"):
            body["workspace_id"] = bootstrap["workspace_id"]

        async with httpx.AsyncClient(
            timeout=15.0, trust_env=False, follow_redirects=False
        ) as client:
            resp = await client.post(url, json=body)
            resp.raise_for_status()
            payload = resp.json()
            token = payload.get("access_token")
            expires_in = payload.get("expires_in")
            if not token or not expires_in:
                raise RuntimeError("anthropic token response missing access_token/expires_in")
            return token, int(expires_in)
