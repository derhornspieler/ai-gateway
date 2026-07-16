"""Bounded provider-authentication enrollment and lifecycle controls.

This module is deliberately narrower than a generic provider settings API.
Every provider owns a typed adapter, fixed network destinations, and fixed
Vault paths.  Browser/API callers cannot supply URLs, Vault paths, arbitrary
configuration dictionaries, or private-key material.
"""

from __future__ import annotations

import hmac
import json
import math
import re
import time
from collections.abc import Callable
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.config import Settings
from app.jwks_watcher import _jwks_sha256
from app.provider_state import (
    CREDENTIAL_ISSUED,
    CREDENTIAL_LIFECYCLE_FIELD,
    CREDENTIAL_NEVER_ISSUED,
    CREDENTIAL_PROMOTION_PENDING,
)
from app.security import service_account_subject

ANTHROPIC_VENDOR = "anthropic"
ANTHROPIC_WIF_VAULT_PATH = "ai-gateway/anthropic-wif"
ANTHROPIC_AUDIENCE = "https://api.anthropic.com"
DISABLE_CONFIRMATION = "DISABLE anthropic"
DELETE_CONFIRMATION = "DELETE anthropic"

_BOOTSTRAP_SCHEMA_VERSION = 1
_MAX_JWKS_BYTES = 256 * 1024
_MAX_JWK_BYTES = 32 * 1024
_MAX_JWKS_KEYS = 16
_MAX_SHORT_LIVED_CREDENTIAL_SECONDS = 24 * 60 * 60
_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_PUBLIC_JWK_FIELDS = frozenset(
    {
        "alg",
        "crv",
        "e",
        "key_ops",
        "kid",
        "kty",
        "n",
        "use",
        "x",
        "x5c",
        "x5t",
        "x5t#S256",
        "y",
    }
)
_PRIVATE_JWK_FIELDS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})
_BOOTSTRAP_FIELDS = frozenset(
    {
        "schema_version",
        "kc_token_url",
        "kc_client_id",
        "organization_id",
        "service_account_id",
        "federation_rule_id",
        "workspace_id",
        "federation_jwks_sha256",
    }
)


class ProviderError(RuntimeError):
    """A safe provider control-plane error that contains no secret value."""


class ProviderConflict(ProviderError):
    """The requested lifecycle transition is unsafe in the current state."""


class ProviderNotFound(ProviderError):
    """The requested provider has no explicitly registered adapter."""


class ProviderUnavailable(ProviderError):
    """A required internal control-plane dependency is unavailable."""


class AnthropicWifEnrollment(BaseModel):
    """The complete, non-secret Anthropic WIF enrollment input.

    ``enrollment_confirmation`` records that the operator installed the
    returned public issuer/JWKS bundle at Anthropic.  It is a transition
    guard only and is never written to Vault or returned by status.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    organization_id: str = Field(min_length=1, max_length=256)
    service_account_id: str = Field(min_length=1, max_length=256)
    federation_rule_id: str = Field(min_length=1, max_length=256)
    workspace_id: str | None = Field(default=None, min_length=1, max_length=256)
    federation_jwks_sha256: str = Field(
        min_length=64,
        max_length=64,
        pattern=r"[0-9a-fA-F]{64}",
    )
    enrollment_confirmation: Literal["ENROLLED"]

    @field_validator(
        "organization_id",
        "service_account_id",
        "federation_rule_id",
        "workspace_id",
    )
    @classmethod
    def validate_provider_identifier(cls, value: str | None) -> str | None:
        if value is not None and _ID_PATTERN.fullmatch(value) is None:
            raise ValueError("provider identifier contains unsupported characters")
        return value

    @field_validator("federation_jwks_sha256")
    @classmethod
    def normalize_jwks_sha256(cls, value: str) -> str:
        return value.lower()

    def persisted_ids(self) -> dict[str, str]:
        values = {
            "organization_id": self.organization_id,
            "service_account_id": self.service_account_id,
            "federation_rule_id": self.federation_rule_id,
        }
        if self.workspace_id is not None:
            values["workspace_id"] = self.workspace_id
        return values


class ProviderSetupBundle(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    issuer: str
    client_id: str
    subject: str
    audience: str
    jwks: dict[str, list[dict[str, Any]]]


class ProviderStatus(BaseModel):
    """Strict response boundary; all fields are intentionally non-secret."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    vendor: Literal["anthropic"] = ANTHROPIC_VENDOR
    state: Literal[
        "identity_bootstrap_required",
        "awaiting_enrollment",
        "configured",
        "jwks_drift",
        "revocation_pending",
        "unavailable",
    ]
    configured: bool
    enabled: bool
    private_key_jwt_ready: bool
    nonsecret_ids: dict[str, str]
    client_certificate_sha256: str
    current_jwks_sha256: str
    approved_jwks_sha256: str
    revocation_pending_until: str | None
    setup_bundle: dict[str, Any]


def _status_dict(status: ProviderStatus) -> dict[str, Any]:
    return status.model_dump(mode="json")


class AnthropicWifAdapter:
    """Anthropic WIF adapter with no caller-controlled network/path inputs."""

    vendor = ANTHROPIC_VENDOR

    def __init__(
        self,
        settings: Settings,
        vault: Any,
        db: Any,
        scheduler: Any,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._settings = settings
        self._vault = vault
        self._db = db
        self._scheduler = scheduler
        self._transport = transport
        self._clock = clock

    @property
    def _internal_token_url(self) -> str:
        return (
            f"{self._settings.keycloak_url}/realms/{self._settings.wif_realm}"
            "/protocol/openid-connect/token"
        )

    @property
    def _internal_jwks_url(self) -> str:
        return (
            f"{self._settings.keycloak_url}/realms/{self._settings.wif_realm}"
            "/protocol/openid-connect/certs"
        )

    @property
    def _public_issuer(self) -> str:
        return (
            f"{self._settings.wif_keycloak_public_url}"
            f"/realms/{self._settings.wif_realm}"
        )

    def _private_key_status(self, key_doc: Any) -> tuple[bool, str]:
        if not isinstance(key_doc, dict):
            return False, ""
        fingerprint = key_doc.get("certificate_sha256")
        pem = key_doc.get("private_key_pem")
        ready = (
            key_doc.get("schema_version") == _BOOTSTRAP_SCHEMA_VERSION
            and key_doc.get("client_id") == self._settings.wif_broker_client_id
            and key_doc.get("realm") == self._settings.wif_realm
            and isinstance(pem, str)
            and 1 <= len(pem.encode()) <= 32 * 1024
            and pem.startswith("-----BEGIN PRIVATE KEY-----")
            and isinstance(fingerprint, str)
            and _SHA256_PATTERN.fullmatch(fingerprint.lower()) is not None
        )
        return ready, fingerprint.lower() if ready else ""

    @staticmethod
    def _validated_bootstrap(doc: Any) -> tuple[dict[str, str], str, bool]:
        if not isinstance(doc, dict) or not set(doc).issubset(_BOOTSTRAP_FIELDS):
            return {}, "", False
        approved = doc.get("federation_jwks_sha256")
        if (
            not isinstance(approved, str)
            or _SHA256_PATTERN.fullmatch(approved.lower()) is None
        ):
            return {}, "", False
        raw_ids = {
            name: doc.get(name)
            for name in (
                "organization_id",
                "service_account_id",
                "federation_rule_id",
                "workspace_id",
            )
            if doc.get(name) is not None
        }
        try:
            enrollment = AnthropicWifEnrollment(
                **raw_ids,
                federation_jwks_sha256=approved,
                enrollment_confirmation="ENROLLED",
            )
        except Exception:  # Pydantic validation detail is not an API response.
            return {}, "", False
        valid = (
            doc.get("schema_version") == _BOOTSTRAP_SCHEMA_VERSION
            and isinstance(doc.get("kc_token_url"), str)
            and isinstance(doc.get("kc_client_id"), str)
        )
        return (
            enrollment.persisted_ids(),
            approved.lower() if valid else "",
            valid,
        )

    @staticmethod
    def _sanitize_jwks(payload: Any, body_size: int) -> list[dict[str, Any]]:
        if body_size > _MAX_JWKS_BYTES or not isinstance(payload, dict):
            raise ProviderUnavailable("Keycloak returned an invalid WIF JWKS")
        keys = payload.get("keys")
        if not isinstance(keys, list) or not 1 <= len(keys) <= _MAX_JWKS_KEYS:
            raise ProviderUnavailable("Keycloak returned an invalid WIF JWKS")

        sanitized: list[dict[str, Any]] = []
        for raw in keys:
            if (
                not isinstance(raw, dict)
                or set(raw) - _PUBLIC_JWK_FIELDS
                or set(raw) & _PRIVATE_JWK_FIELDS
            ):
                raise ProviderUnavailable("Keycloak returned a non-public WIF JWK")
            kty = raw.get("kty")
            if kty == "RSA":
                required = ("n", "e")
            elif kty == "EC":
                required = ("crv", "x", "y")
            elif kty == "OKP":
                required = ("crv", "x")
            else:
                raise ProviderUnavailable("Keycloak returned an unsupported WIF JWK")
            if any(
                not isinstance(raw.get(name), str) or not raw[name] for name in required
            ):
                raise ProviderUnavailable("Keycloak returned an invalid WIF JWK")
            # The realm legitimately publishes both an RS256 signing key and an
            # RSA-OAEP encryption key. Both are public and must pass through:
            # inline-JWKS verification selects the signing key, while hash
            # consistency requires every published key.
            if "key_ops" in raw and (
                not isinstance(raw["key_ops"], list)
                or any(op != "verify" for op in raw["key_ops"])
            ):
                raise ProviderUnavailable(
                    "Keycloak returned invalid WIF JWK operations"
                )
            if "x5c" in raw and (
                not isinstance(raw["x5c"], list)
                or len(raw["x5c"]) > 8
                or any(not isinstance(cert, str) for cert in raw["x5c"])
            ):
                raise ProviderUnavailable(
                    "Keycloak returned an invalid WIF certificate chain"
                )
            try:
                encoded_size = len(
                    json.dumps(raw, separators=(",", ":"), allow_nan=False).encode()
                )
            except (TypeError, ValueError) as exc:
                raise ProviderUnavailable(
                    "Keycloak returned an invalid WIF JWK"
                ) from exc
            if encoded_size > _MAX_JWK_BYTES:
                raise ProviderUnavailable("Keycloak returned an oversized WIF JWK")
            sanitized.append(dict(raw))
        return sanitized

    async def _fetch_public_jwks(self) -> tuple[list[dict[str, Any]], str]:
        try:
            async with httpx.AsyncClient(
                timeout=15.0,
                trust_env=False,
                follow_redirects=False,
                transport=self._transport,
            ) as client:
                async with client.stream("GET", self._internal_jwks_url) as response:
                    response.raise_for_status()
                    declared_size = response.headers.get("Content-Length")
                    if declared_size is not None:
                        try:
                            if int(declared_size) > _MAX_JWKS_BYTES:
                                raise ProviderUnavailable(
                                    "Keycloak returned an oversized WIF JWKS"
                                )
                        except ValueError as exc:
                            raise ProviderUnavailable(
                                "Keycloak returned an invalid WIF JWKS length"
                            ) from exc
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > _MAX_JWKS_BYTES:
                            raise ProviderUnavailable(
                                "Keycloak returned an oversized WIF JWKS"
                            )
                    keys = self._sanitize_jwks(json.loads(body), len(body))
        except ProviderError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise ProviderUnavailable("could not read the internal WIF JWKS") from exc
        return keys, _jwks_sha256(keys)

    def _setup_bundle(self, keys: list[dict[str, Any]]) -> dict[str, Any]:
        return ProviderSetupBundle(
            issuer=self._public_issuer,
            client_id=self._settings.wif_broker_client_id,
            subject=service_account_subject(self._settings.wif_broker_client_id),
            audience=ANTHROPIC_AUDIENCE,
            jwks={"keys": keys},
        ).model_dump(mode="json")

    @staticmethod
    def _proven_expiry(config: Any) -> float | None:
        if (
            not isinstance(config, dict)
            or config.get(CREDENTIAL_LIFECYCLE_FIELD) != CREDENTIAL_ISSUED
        ):
            return None
        issued = config.get("_last_issued_at")
        lifetime = config.get("_last_expires_in")
        if (
            isinstance(issued, bool)
            or isinstance(lifetime, bool)
            or not isinstance(issued, (int, float))
            or not isinstance(lifetime, (int, float))
            or not math.isfinite(float(issued))
            or not math.isfinite(float(lifetime))
            or float(issued) <= 0
            or not 0 < float(lifetime) <= _MAX_SHORT_LIVED_CREDENTIAL_SECONDS
        ):
            return None
        expiry = float(issued) + float(lifetime)
        return expiry if math.isfinite(expiry) else None

    @staticmethod
    def _proven_never_issued(config: Any) -> bool:
        """Accept only the explicit post-enrollment no-promotion marker."""

        return (
            isinstance(config, dict)
            and config.get(CREDENTIAL_LIFECYCLE_FIELD) == CREDENTIAL_NEVER_ISSUED
            and "_last_issued_at" not in config
            and "_last_expires_in" not in config
        )

    @staticmethod
    def _expiry_text(expiry: float | None) -> str | None:
        if expiry is None:
            return None
        try:
            return datetime.fromtimestamp(expiry, timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            return None

    def _unavailable_status(self) -> dict[str, Any]:
        return _status_dict(
            ProviderStatus(
                state="unavailable",
                configured=False,
                enabled=False,
                private_key_jwt_ready=False,
                nonsecret_ids={},
                client_certificate_sha256="",
                current_jwks_sha256="",
                approved_jwks_sha256="",
                revocation_pending_until=None,
                setup_bundle={},
            )
        )

    async def status(self) -> dict[str, Any]:
        try:
            bootstrap = self._vault.read(ANTHROPIC_WIF_VAULT_PATH)
            key_doc = self._vault.read(
                self._settings.kc_client_assertion_key_vault_path
            )
            row = await self._db.get_settings(ANTHROPIC_VENDOR)
            if not isinstance(row, dict) or not isinstance(row.get("enabled"), bool):
                return self._unavailable_status()
            keys, current_sha = await self._fetch_public_jwks()
        except Exception:  # Dependency details remain server-side.
            return self._unavailable_status()

        key_ready, fingerprint = self._private_key_status(key_doc)
        ids, approved_sha, bootstrap_valid = self._validated_bootstrap(bootstrap)
        configured = (
            bootstrap_valid
            and bootstrap.get("kc_token_url") == self._internal_token_url
            and bootstrap.get("kc_client_id") == self._settings.wif_broker_client_id
        )
        enabled = row["enabled"]
        credential_config = row.get("config")
        expiry = self._proven_expiry(credential_config)
        pending_until = (
            self._expiry_text(expiry)
            if configured
            and not enabled
            and expiry is not None
            and expiry > self._clock()
            else None
        )
        deletion_proven_safe = self._proven_never_issued(credential_config) or (
            expiry is not None and expiry <= self._clock()
        )
        revocation_unproven = configured and not enabled and not deletion_proven_safe

        if not key_ready:
            state = "identity_bootstrap_required"
        elif pending_until is not None or revocation_unproven:
            state = "revocation_pending"
        elif configured and approved_sha != current_sha:
            state = "jwks_drift"
        elif configured:
            state = "configured"
        else:
            state = "awaiting_enrollment"

        return _status_dict(
            ProviderStatus(
                state=state,
                configured=configured,
                enabled=enabled,
                private_key_jwt_ready=key_ready,
                nonsecret_ids=ids if configured else {},
                client_certificate_sha256=fingerprint,
                current_jwks_sha256=current_sha,
                approved_jwks_sha256=approved_sha if configured else "",
                revocation_pending_until=pending_until,
                setup_bundle=self._setup_bundle(keys) if key_ready else {},
            )
        )

    @asynccontextmanager
    async def _lifecycle_lock(self) -> AsyncIterator[None]:
        try:
            lock = self._db.rotation_lock(ANTHROPIC_VENDOR)
            async with lock as acquired:
                if not acquired:
                    raise ProviderConflict(
                        "another Anthropic credential lifecycle operation is active"
                    )
                yield
        except ProviderError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise ProviderUnavailable(
                "could not acquire the Anthropic credential lifecycle lock"
            ) from exc

    async def _reload_and_verify_disabled(self) -> None:
        try:
            await self._scheduler.reload()
            if self._scheduler.next_run_time(ANTHROPIC_VENDOR) is not None:
                raise RuntimeError("scheduler retained the disabled provider job")
        except Exception as exc:  # noqa: BLE001
            raise ProviderUnavailable(
                "could not verify that Anthropic credential refresh is disabled"
            ) from exc

    async def configure(self, enrollment: AnthropicWifEnrollment) -> dict[str, Any]:
        if not isinstance(enrollment, AnthropicWifEnrollment):
            raise ProviderError("Anthropic enrollment must use the typed input model")

        async with self._lifecycle_lock():
            if self._scheduler.is_rotating(ANTHROPIC_VENDOR):
                raise ProviderConflict("Anthropic credential rotation is in progress")
            key_doc = self._vault.read(
                self._settings.kc_client_assertion_key_vault_path
            )
            key_ready, _ = self._private_key_status(key_doc)
            if not key_ready:
                raise ProviderConflict(
                    "identity bootstrap must generate the Anthropic private_key_jwt key first"
                )
            row = await self._db.get_settings(ANTHROPIC_VENDOR)
            if not isinstance(row, dict):
                raise ProviderUnavailable("Anthropic rotation settings are unavailable")

            existing = self._vault.read(ANTHROPIC_WIF_VAULT_PATH)
            existing_ids, _, existing_valid = self._validated_bootstrap(existing)
            desired_ids = enrollment.persisted_ids()
            if existing is not None and not existing_valid:
                raise ProviderConflict(
                    "existing Anthropic enrollment is invalid; preserve it for recovery before replacement"
                )
            if existing_valid and existing_ids != desired_ids:
                raise ProviderConflict(
                    "Anthropic enrollment already exists; disable and delete it before replacement"
                )

            keys, current_sha = await self._fetch_public_jwks()
            del keys  # The public keys are returned by status, never persisted here.
            if not hmac.compare_digest(
                enrollment.federation_jwks_sha256, current_sha
            ):
                raise ProviderConflict(
                    "Keycloak WIF JWKS changed after the enrollment bundle was shown; reload and repeat the external enrollment"
                )
            bootstrap: dict[str, Any] = {
                "schema_version": _BOOTSTRAP_SCHEMA_VERSION,
                "kc_token_url": self._internal_token_url,
                "kc_client_id": self._settings.wif_broker_client_id,
                **desired_ids,
                "federation_jwks_sha256": current_sha,
            }

            # Establish the durable no-promotion proof before making a new
            # enrollment visible to the rotation driver.  If either the Vault
            # write or the later enable fails, a retry sees either no public
            # enrollment or an idempotent enrollment paired with the same
            # disabled never-issued marker; it cannot become stuck with an
            # enrollment document and ambiguous credential history.
            is_new_enrollment = existing is None
            initial_credential_state = (
                {CREDENTIAL_LIFECYCLE_FIELD: CREDENTIAL_NEVER_ISSUED}
                if is_new_enrollment
                else None
            )
            if is_new_enrollment:
                try:
                    await self._db.upsert_settings(
                        ANTHROPIC_VENDOR,
                        False,
                        int(row.get("interval_seconds") or 3000),
                        int(row.get("grace_seconds") or 300),
                        initial_credential_state,
                    )
                except Exception as exc:  # noqa: BLE001
                    raise ProviderUnavailable(
                        "could not initialize Anthropic credential lifecycle state"
                    ) from exc
            if not self._vault.write_verified(ANTHROPIC_WIF_VAULT_PATH, bootstrap):
                raise ProviderUnavailable(
                    "Vault did not verify the Anthropic enrollment write"
                )

            try:
                await self._db.upsert_settings(
                    ANTHROPIC_VENDOR,
                    True,
                    int(row.get("interval_seconds") or 3000),
                    int(row.get("grace_seconds") or 300),
                    initial_credential_state,
                )
                await self._scheduler.reload()
            except Exception as exc:  # noqa: BLE001
                # The public enrollment may remain durable, but fail closed by
                # restoring the control row to disabled before returning.
                try:
                    await self._db.upsert_settings(
                        ANTHROPIC_VENDOR,
                        False,
                        int(row.get("interval_seconds") or 3000),
                        int(row.get("grace_seconds") or 300),
                        initial_credential_state,
                    )
                    await self._scheduler.reload()
                except Exception:
                    pass
                raise ProviderUnavailable(
                    "could not enable Anthropic credential refresh"
                ) from exc
            await self._db.record_history(
                ANTHROPIC_VENDOR,
                "provider_configure",
                "success",
                "Anthropic WIF enrollment configured from bounded non-secret identifiers",
            )
        return await self.status()

    async def disable(self, confirmation: str) -> dict[str, Any]:
        if confirmation != DISABLE_CONFIRMATION:
            raise ProviderConflict(
                f"confirmation must exactly equal {DISABLE_CONFIRMATION!r}"
            )
        async with self._lifecycle_lock():
            if self._scheduler.is_rotating(ANTHROPIC_VENDOR):
                raise ProviderConflict("Anthropic credential rotation is in progress")
            row = await self._db.get_settings(ANTHROPIC_VENDOR)
            if not isinstance(row, dict):
                raise ProviderUnavailable("Anthropic rotation settings are unavailable")
            await self._db.upsert_settings(
                ANTHROPIC_VENDOR,
                False,
                int(row.get("interval_seconds") or 3000),
                int(row.get("grace_seconds") or 300),
                None,
            )
            await self._reload_and_verify_disabled()
            await self._db.record_history(
                ANTHROPIC_VENDOR,
                "provider_disable",
                "success",
                "Anthropic refresh disabled; active short-lived credential allowed to expire",
            )
        return await self.status()

    async def delete(self, confirmation: str) -> dict[str, Any]:
        if confirmation != DELETE_CONFIRMATION:
            raise ProviderConflict(
                f"confirmation must exactly equal {DELETE_CONFIRMATION!r}"
            )
        async with self._lifecycle_lock():
            if self._scheduler.is_rotating(ANTHROPIC_VENDOR):
                raise ProviderConflict("Anthropic credential rotation is in progress")
            row = await self._db.get_settings(ANTHROPIC_VENDOR)
            if not isinstance(row, dict):
                raise ProviderUnavailable("Anthropic rotation settings are unavailable")
            if row.get("enabled") is not False:
                raise ProviderConflict("disable Anthropic refresh before deletion")
            await self._reload_and_verify_disabled()

            credential_config = row.get("config")
            if not self._proven_never_issued(credential_config):
                expiry = self._proven_expiry(credential_config)
                if expiry is None:
                    lifecycle = (
                        credential_config.get(CREDENTIAL_LIFECYCLE_FIELD)
                        if isinstance(credential_config, dict)
                        else None
                    )
                    if lifecycle == CREDENTIAL_PROMOTION_PENDING:
                        raise ProviderConflict(
                            "cannot prove expiry while Anthropic credential promotion is indeterminate"
                        )
                    raise ProviderConflict(
                        "cannot prove expiry of the last Anthropic short-lived credential"
                    )
                if expiry > self._clock():
                    pending = self._expiry_text(expiry)
                    raise ProviderConflict(
                        f"the active Anthropic credential has not expired; retry after {pending}"
                    )
            if not self._vault.delete_verified(ANTHROPIC_WIF_VAULT_PATH):
                raise ProviderUnavailable(
                    "Vault did not verify deletion of the Anthropic enrollment"
                )
            await self._db.record_history(
                ANTHROPIC_VENDOR,
                "provider_delete",
                "success",
                "expired Anthropic WIF enrollment deleted",
            )
        return await self.status()


class ProviderRegistry:
    """Explicit provider registry; unknown vendors never get a generic path."""

    def __init__(
        self,
        settings: Settings,
        vault: Any,
        db: Any,
        scheduler: Any,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._adapters: dict[str, AnthropicWifAdapter] = {
            ANTHROPIC_VENDOR: AnthropicWifAdapter(
                settings, vault, db, scheduler, transport=transport
            )
        }

    def _adapter(self, vendor: str) -> AnthropicWifAdapter:
        adapter = self._adapters.get(vendor)
        if adapter is None:
            raise ProviderNotFound("provider is not supported")
        return adapter

    async def status(self, vendor: str) -> dict[str, Any]:
        return await self._adapter(vendor).status()

    async def configure(
        self, vendor: str, enrollment: AnthropicWifEnrollment
    ) -> dict[str, Any]:
        return await self._adapter(vendor).configure(enrollment)

    async def disable(self, vendor: str, confirmation: str) -> dict[str, Any]:
        return await self._adapter(vendor).disable(confirmation)

    async def delete(self, vendor: str, confirmation: str) -> dict[str, Any]:
        return await self._adapter(vendor).delete(confirmation)
