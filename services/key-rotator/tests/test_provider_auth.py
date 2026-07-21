from __future__ import annotations

import json
from contextlib import asynccontextmanager

import httpx
import pytest
from pydantic import ValidationError

from app.config import Settings
from app.jwks_watcher import _jwks_sha256
from app.main import app as api_app
from app.main import state as api_state
from app.provider_auth import (
    ANTHROPIC_WIF_VAULT_PATH,
    DELETE_CONFIRMATION,
    DISABLE_CONFIRMATION,
    AnthropicWifAdapter,
    AnthropicWifEnrollment,
    ProviderConflict,
    ProviderNotFound,
    ProviderRegistry,
    ProviderUnavailable,
    _jwks_sha256 as provider_auth_jwks_sha256,
)
from app.provider_state import (
    CREDENTIAL_ISSUED,
    CREDENTIAL_LIFECYCLE_FIELD,
    CREDENTIAL_NEVER_ISSUED,
    CREDENTIAL_PROMOTION_PENDING,
)
from app.vault_client import VaultClient


NOW = 2_000_000_000.0
JWKS = {
    "keys": [
        {
            "kid": "realm-signing-key",
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "n": "public-modulus",
            "e": "AQAB",
        }
    ]
}
JWKS_SHA256 = _jwks_sha256(JWKS["keys"])

KEYCLOAK_DEFAULT_JWKS = {
    "keys": [
        {
            "kid": "realm-signing-key",
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "x5c": ["MIIC-signing-certificate"],
            "x5t": "signing-certificate-thumbprint",
            "n": "signing-public-modulus",
            "e": "AQAB",
        },
        {
            "kid": "realm-encryption-key",
            "kty": "RSA",
            "alg": "RSA-OAEP",
            "use": "enc",
            "x5c": ["MIIC-encryption-certificate"],
            "x5t": "encryption-certificate-thumbprint",
            "n": "encryption-public-modulus",
            "e": "AQAB",
        },
    ]
}


def settings() -> Settings:
    return Settings(
        ROTATOR_INTERNAL_TOKEN="0123456789abcdef0123456789abcdef",
        PORTAL_IDENTITY_TOKEN="abcdef0123456789abcdef0123456789",
        VAULT_TOKEN="vault-token",
        KEYCLOAK_URL="http://keycloak:8080",
        WIF_KEYCLOAK_PUBLIC_URL="https://idp.wif.aigw.example.internal",
    )


def server_key_doc() -> dict[str, object]:
    return {
        "schema_version": 1,
        "private_key_pem": "-----BEGIN PRIVATE KEY-----\nnever-return-me\n",
        "kid": "broker-key",
        "certificate_sha256": "a" * 64,
        "client_id": "anthropic-token-broker",
        "realm": "anthropic-wif",
    }


def enrollment(**overrides) -> AnthropicWifEnrollment:
    values = {
        "organization_id": "org_123",
        "service_account_id": "svc_123",
        "federation_rule_id": "fed_123",
        "workspace_id": "ws_123",
        "federation_jwks_sha256": JWKS_SHA256,
        "enrollment_confirmation": "ENROLLED",
    }
    values.update(overrides)
    return AnthropicWifEnrollment(**values)


class FakeVault:
    def __init__(self, *, bootstrap=None, key_doc=None):
        self.docs = {}
        if bootstrap is not None:
            self.docs[ANTHROPIC_WIF_VAULT_PATH] = dict(bootstrap)
        if key_doc is not None:
            self.docs[settings().kc_client_assertion_key_vault_path] = dict(key_doc)
        self.writes = []
        self.deletes = []

    def read(self, path):
        doc = self.docs.get(path)
        return dict(doc) if isinstance(doc, dict) else None

    def write_verified(self, path, data):
        self.docs[path] = dict(data)
        self.writes.append((path, dict(data)))
        return True

    def delete_verified(self, path):
        self.docs.pop(path, None)
        self.deletes.append(path)
        return True


class FakeDB:
    def __init__(self, *, enabled=False, config=None):
        self.row = {
            "vendor": "anthropic",
            "enabled": enabled,
            "interval_seconds": 3000,
            "grace_seconds": 300,
            "config": dict(config or {}),
        }
        self.history = []
        self.lock_available = True

    async def get_settings(self, vendor):
        assert vendor == "anthropic"
        return dict(self.row) if self.row is not None else None

    async def upsert_settings(
        self, vendor, enabled, interval_seconds, grace_seconds, config
    ):
        assert vendor == "anthropic"
        previous_config = dict(self.row.get("config") or {})
        self.row = {
            "vendor": vendor,
            "enabled": enabled,
            "interval_seconds": interval_seconds,
            "grace_seconds": grace_seconds,
            "config": previous_config if config is None else dict(config),
        }

    async def record_history(self, *args):
        self.history.append(args)

    @asynccontextmanager
    async def rotation_lock(self, vendor):
        assert vendor == "anthropic"
        yield self.lock_available


class FakeScheduler:
    def __init__(self, db):
        self.db = db
        self.rotating = False
        self.next_run = None
        self.reload_count = 0

    def is_rotating(self, vendor):
        assert vendor == "anthropic"
        return self.rotating

    async def reload(self):
        self.reload_count += 1
        self.next_run = object() if self.db.row["enabled"] else None

    def next_run_time(self, vendor):
        assert vendor == "anthropic"
        return self.next_run


def transport(jwks=JWKS, *, status_code=200):
    def handle(request: httpx.Request) -> httpx.Response:
        assert request.url == (
            "http://keycloak:8080/realms/anthropic-wif/protocol/openid-connect/certs"
        )
        return httpx.Response(status_code, json=jwks)

    return httpx.MockTransport(handle)


def adapter(vault, db, scheduler, *, jwks=JWKS):
    return AnthropicWifAdapter(
        settings(),
        vault,
        db,
        scheduler,
        transport=transport(jwks),
        clock=lambda: NOW,
    )


def configured_bootstrap(jwks=JWKS) -> dict[str, object]:
    return {
        "schema_version": 1,
        "kc_token_url": (
            "http://keycloak:8080/realms/anthropic-wif/protocol/openid-connect/token"
        ),
        "kc_client_id": "anthropic-token-broker",
        "organization_id": "org_123",
        "service_account_id": "svc_123",
        "federation_rule_id": "fed_123",
        "workspace_id": "ws_123",
        "federation_jwks_sha256": _jwks_sha256(jwks["keys"]),
    }


def test_enrollment_rejects_arbitrary_fields_urls_and_private_material():
    for extra in (
        {"token_url": "https://attacker.invalid/token"},
        {"vault_path": "arbitrary/path"},
        {"private_key_pem": "secret"},
        {"client_secret": "secret"},
        {"config": {"anything": "goes"}},
    ):
        with pytest.raises(ValidationError):
            AnthropicWifEnrollment(
                organization_id="org_123",
                service_account_id="svc_123",
                federation_rule_id="fed_123",
                federation_jwks_sha256=JWKS_SHA256,
                enrollment_confirmation="ENROLLED",
                **extra,
            )

    with pytest.raises(ValidationError):
        enrollment(enrollment_confirmation="ENROLLED ")


@pytest.mark.asyncio
async def test_status_returns_only_public_allowlisted_material():
    vault = FakeVault(bootstrap=configured_bootstrap(), key_doc=server_key_doc())
    db = FakeDB(enabled=True)
    subject = adapter(vault, db, FakeScheduler(db))

    result = await subject.status()

    assert result["state"] == "configured"
    assert result["private_key_jwt_ready"] is True
    assert result["client_certificate_sha256"] == "a" * 64
    assert result["nonsecret_ids"] == enrollment().persisted_ids()
    assert result["setup_bundle"] == {
        "issuer": "https://idp.wif.aigw.example.internal/realms/anthropic-wif",
        "client_id": "anthropic-token-broker",
        "subject": "service-account-anthropic-token-broker",
        "audience": "https://api.anthropic.com",
        "jwks": JWKS,
    }
    encoded = json.dumps(result)
    assert "PRIVATE KEY" not in encoded
    assert "never-return-me" not in encoded
    assert "protocol/openid-connect/token" not in encoded


@pytest.mark.asyncio
async def test_status_requires_server_generated_broker_key():
    client_supplied_shape = server_key_doc()
    client_supplied_shape.pop("schema_version")
    vault = FakeVault(bootstrap=configured_bootstrap(), key_doc=client_supplied_shape)
    db = FakeDB(enabled=False)

    result = await adapter(vault, db, FakeScheduler(db)).status()

    assert result["state"] == "identity_bootstrap_required"
    assert result["private_key_jwt_ready"] is False
    assert result["client_certificate_sha256"] == ""
    assert result["setup_bundle"] == {}


@pytest.mark.asyncio
async def test_configure_derives_fixed_urls_hash_and_enables_scheduler():
    vault = FakeVault(key_doc=server_key_doc())
    db = FakeDB(enabled=False)
    scheduler = FakeScheduler(db)
    subject = adapter(vault, db, scheduler)

    result = await subject.configure(enrollment())

    written = vault.writes[0][1]
    assert set(written) == {
        "schema_version",
        "kc_token_url",
        "kc_client_id",
        "organization_id",
        "service_account_id",
        "federation_rule_id",
        "workspace_id",
        "federation_jwks_sha256",
    }
    assert written["kc_token_url"] == (
        "http://keycloak:8080/realms/anthropic-wif/protocol/openid-connect/token"
    )
    assert written["kc_client_id"] == "anthropic-token-broker"
    assert written["federation_jwks_sha256"] == _jwks_sha256(JWKS["keys"])
    assert "enrollment_confirmation" not in written
    assert db.row["enabled"] is True
    assert db.row["config"] == {
        CREDENTIAL_LIFECYCLE_FIELD: CREDENTIAL_NEVER_ISSUED
    }
    assert scheduler.reload_count == 1
    assert result["state"] == "configured"
    assert db.history[-1][1:3] == ("provider_configure", "success")


@pytest.mark.asyncio
async def test_new_configure_persists_never_issued_before_vault_and_is_retryable():
    events: list[tuple[str, object]] = []

    class OrderedVault(FakeVault):
        def write_verified(self, path, data):
            events.append(("vault", path))
            return super().write_verified(path, data)

    class FailFirstEnableDB(FakeDB):
        def __init__(self):
            super().__init__(enabled=False)
            self.fail_enable_once = True

        async def upsert_settings(
            self, vendor, enabled, interval_seconds, grace_seconds, config
        ):
            lifecycle = (
                config.get(CREDENTIAL_LIFECYCLE_FIELD)
                if isinstance(config, dict)
                else None
            )
            events.append(("db", (enabled, lifecycle)))
            if enabled and self.fail_enable_once:
                self.fail_enable_once = False
                raise RuntimeError("simulated enable failure")
            await super().upsert_settings(
                vendor, enabled, interval_seconds, grace_seconds, config
            )

    vault = OrderedVault(key_doc=server_key_doc())
    db = FailFirstEnableDB()
    scheduler = FakeScheduler(db)
    subject = adapter(vault, db, scheduler)

    with pytest.raises(ProviderUnavailable, match="could not enable"):
        await subject.configure(enrollment())

    assert events[:3] == [
        ("db", (False, CREDENTIAL_NEVER_ISSUED)),
        ("vault", ANTHROPIC_WIF_VAULT_PATH),
        ("db", (True, CREDENTIAL_NEVER_ISSUED)),
    ]
    assert db.row["enabled"] is False
    assert db.row["config"] == {
        CREDENTIAL_LIFECYCLE_FIELD: CREDENTIAL_NEVER_ISSUED
    }
    assert vault.read(ANTHROPIC_WIF_VAULT_PATH) == configured_bootstrap()

    result = await subject.configure(enrollment())

    assert result["configured"] is True
    assert db.row["enabled"] is True
    assert db.row["config"] == {
        CREDENTIAL_LIFECYCLE_FIELD: CREDENTIAL_NEVER_ISSUED
    }


@pytest.mark.asyncio
async def test_new_configure_does_not_write_vault_when_lifecycle_init_fails():
    class FailingLifecycleDB(FakeDB):
        async def upsert_settings(self, *args, **kwargs):
            raise RuntimeError("postgres unavailable")

    vault = FakeVault(key_doc=server_key_doc())
    db = FailingLifecycleDB(enabled=False)
    subject = adapter(vault, db, FakeScheduler(db))

    with pytest.raises(ProviderUnavailable, match="initialize.*lifecycle"):
        await subject.configure(enrollment())

    assert vault.writes == []
    assert vault.read(ANTHROPIC_WIF_VAULT_PATH) is None


@pytest.mark.asyncio
async def test_configure_is_idempotent_but_replacement_requires_delete():
    vault = FakeVault(bootstrap=configured_bootstrap(), key_doc=server_key_doc())
    db = FakeDB(enabled=True)
    scheduler = FakeScheduler(db)
    subject = adapter(vault, db, scheduler)

    assert (await subject.configure(enrollment()))["configured"] is True
    with pytest.raises(ProviderConflict, match="already exists"):
        await subject.configure(enrollment(organization_id="org_different"))


@pytest.mark.asyncio
async def test_configure_binds_confirmation_to_rendered_jwks_digest():
    changed = {
        "keys": [
            {
                "kid": "changed-after-render",
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "n": "changed-public-modulus",
                "e": "AQAB",
            }
        ]
    }
    vault = FakeVault(key_doc=server_key_doc())
    db = FakeDB(enabled=False)
    subject = adapter(vault, db, FakeScheduler(db), jwks=changed)

    with pytest.raises(ProviderConflict, match="changed after the enrollment bundle"):
        await subject.configure(enrollment(federation_jwks_sha256=JWKS_SHA256))

    assert vault.writes == []
    assert db.row["enabled"] is False


@pytest.mark.asyncio
async def test_configure_fails_closed_without_identity_generated_key():
    vault = FakeVault()
    db = FakeDB(enabled=False)
    subject = adapter(vault, db, FakeScheduler(db))

    with pytest.raises(ProviderConflict, match="identity bootstrap"):
        await subject.configure(enrollment())
    assert vault.writes == []
    assert db.row["enabled"] is False


@pytest.mark.asyncio
async def test_status_reports_jwks_drift_against_approved_baseline():
    changed = {
        "keys": [
            {
                "kid": "new-key",
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "n": "new-public-modulus",
                "e": "AQAB",
            }
        ]
    }
    vault = FakeVault(bootstrap=configured_bootstrap(), key_doc=server_key_doc())
    db = FakeDB(enabled=True)

    result = await adapter(vault, db, FakeScheduler(db), jwks=changed).status()

    assert result["state"] == "jwks_drift"
    assert result["approved_jwks_sha256"] == _jwks_sha256(JWKS["keys"])
    assert result["current_jwks_sha256"] == _jwks_sha256(changed["keys"])


def test_sanitize_jwks_preserves_keycloak_signing_and_encryption_keys():
    sanitized = AnthropicWifAdapter._sanitize_jwks(
        KEYCLOAK_DEFAULT_JWKS,
        len(json.dumps(KEYCLOAK_DEFAULT_JWKS).encode()),
    )

    assert sanitized == KEYCLOAK_DEFAULT_JWKS["keys"]
    assert len(sanitized) == 2
    assert provider_auth_jwks_sha256(sanitized) == _jwks_sha256(sanitized)


def test_sanitize_jwks_rejects_private_key_fields():
    private_jwks = {
        "keys": [
            {
                "kid": "bad",
                "kty": "RSA",
                "n": "public",
                "e": "AQAB",
                "d": "private-exponent",
            }
        ]
    }

    with pytest.raises(ProviderUnavailable, match="non-public WIF JWK"):
        AnthropicWifAdapter._sanitize_jwks(private_jwks, 1)


def test_sanitize_jwks_rejects_unsupported_key_type():
    unsupported_jwks = {"keys": [{"kid": "bad", "kty": "DSA"}]}

    with pytest.raises(ProviderUnavailable, match="unsupported WIF JWK"):
        AnthropicWifAdapter._sanitize_jwks(unsupported_jwks, 1)


def test_sanitize_jwks_rejects_oversized_jwks():
    with pytest.raises(ProviderUnavailable, match="invalid WIF JWKS"):
        AnthropicWifAdapter._sanitize_jwks(JWKS, 256 * 1024 + 1)


@pytest.mark.asyncio
async def test_private_or_oversized_jwks_is_never_returned():
    private_jwks = {
        "keys": [
            {
                "kid": "bad",
                "kty": "RSA",
                "n": "public",
                "e": "AQAB",
                "d": "private-exponent",
            }
        ]
    }
    vault = FakeVault(bootstrap=configured_bootstrap(), key_doc=server_key_doc())
    db = FakeDB(enabled=True)

    result = await adapter(vault, db, FakeScheduler(db), jwks=private_jwks).status()

    assert result["state"] == "unavailable"
    assert result["setup_bundle"] == {}
    assert "private-exponent" not in json.dumps(result)


@pytest.mark.asyncio
async def test_disable_stops_refresh_before_reporting_pending_expiry():
    vault = FakeVault(bootstrap=configured_bootstrap(), key_doc=server_key_doc())
    db = FakeDB(
        enabled=True,
        config={
            CREDENTIAL_LIFECYCLE_FIELD: CREDENTIAL_ISSUED,
            "_last_issued_at": NOW - 100,
            "_last_expires_in": 3600,
        },
    )
    scheduler = FakeScheduler(db)
    scheduler.next_run = object()
    subject = adapter(vault, db, scheduler)

    with pytest.raises(ProviderConflict):
        await subject.disable("yes")
    with pytest.raises(ProviderConflict):
        await subject.disable(f"{DISABLE_CONFIRMATION} ")
    result = await subject.disable(DISABLE_CONFIRMATION)

    assert db.row["enabled"] is False
    assert scheduler.next_run is None
    assert result["state"] == "revocation_pending"
    assert result["revocation_pending_until"] is not None


@pytest.mark.asyncio
async def test_delete_requires_disabled_proven_and_expired_credential():
    vault = FakeVault(bootstrap=configured_bootstrap(), key_doc=server_key_doc())
    db = FakeDB(
        enabled=False,
        config={
            CREDENTIAL_LIFECYCLE_FIELD: CREDENTIAL_ISSUED,
            "_last_issued_at": NOW - 100,
            "_last_expires_in": 3600,
        },
    )
    scheduler = FakeScheduler(db)
    subject = adapter(vault, db, scheduler)

    with pytest.raises(ProviderConflict):
        await subject.delete("DELETE")
    with pytest.raises(ProviderConflict):
        await subject.delete(f"{DELETE_CONFIRMATION} ")
    with pytest.raises(ProviderConflict, match="has not expired"):
        await subject.delete(DELETE_CONFIRMATION)
    assert vault.deletes == []

    db.row["config"] = {
        CREDENTIAL_LIFECYCLE_FIELD: CREDENTIAL_ISSUED,
        "_last_issued_at": NOW - 7200,
        "_last_expires_in": 3600,
    }
    result = await subject.delete(DELETE_CONFIRMATION)

    assert vault.deletes == [ANTHROPIC_WIF_VAULT_PATH]
    assert result["state"] == "awaiting_enrollment"
    assert result["configured"] is False


@pytest.mark.asyncio
async def test_delete_fails_closed_when_expiry_cannot_be_proven():
    vault = FakeVault(bootstrap=configured_bootstrap(), key_doc=server_key_doc())
    db = FakeDB(enabled=False, config={})
    subject = adapter(vault, db, FakeScheduler(db))

    with pytest.raises(ProviderConflict, match="cannot prove expiry"):
        await subject.delete(DELETE_CONFIRMATION)
    assert vault.deletes == []


@pytest.mark.asyncio
async def test_delete_allows_explicitly_proven_never_issued_enrollment():
    vault = FakeVault(bootstrap=configured_bootstrap(), key_doc=server_key_doc())
    db = FakeDB(
        enabled=False,
        config={CREDENTIAL_LIFECYCLE_FIELD: CREDENTIAL_NEVER_ISSUED},
    )
    subject = adapter(vault, db, FakeScheduler(db))

    result = await subject.delete(DELETE_CONFIRMATION)

    assert vault.deletes == [ANTHROPIC_WIF_VAULT_PATH]
    assert result["configured"] is False


@pytest.mark.asyncio
async def test_delete_rejects_indeterminate_promotion_even_with_stale_expiry():
    vault = FakeVault(bootstrap=configured_bootstrap(), key_doc=server_key_doc())
    db = FakeDB(
        enabled=False,
        config={
            CREDENTIAL_LIFECYCLE_FIELD: CREDENTIAL_PROMOTION_PENDING,
            "_last_issued_at": NOW - 7200,
            "_last_expires_in": 3600,
        },
    )
    subject = adapter(vault, db, FakeScheduler(db))

    with pytest.raises(ProviderConflict, match="promotion is indeterminate"):
        await subject.delete(DELETE_CONFIRMATION)
    assert vault.deletes == []


@pytest.mark.asyncio
async def test_registry_rejects_unknown_provider_and_untyped_config():
    vault = FakeVault(key_doc=server_key_doc())
    db = FakeDB(enabled=False)
    registry = ProviderRegistry(
        settings(), vault, db, FakeScheduler(db), transport=transport()
    )

    with pytest.raises(ProviderNotFound):
        await registry.status("future-provider")
    with pytest.raises(ProviderConflict):
        await registry.disable("anthropic", "DISABLE future-provider")
    with pytest.raises(Exception, match="typed input model"):
        await registry.configure("anthropic", {"config": "arbitrary"})


def test_vault_delete_verified_permanently_deletes_all_versions(monkeypatch):
    calls = []

    class KV2:
        def delete_metadata_and_all_versions(self, *, path, mount_point):
            calls.append((path, mount_point))

    class Secrets:
        kv = type("KV", (), {"v2": KV2()})()

    class Client:
        secrets = Secrets()

    subject = VaultClient(settings())
    monkeypatch.setattr(subject, "_ensure_authenticated", lambda: None)
    monkeypatch.setattr(subject, "_get_client", lambda: Client())
    monkeypatch.setattr(subject, "read", lambda path: None)

    assert subject.delete_verified("ai-gateway/anthropic-wif") is True
    assert calls == [("ai-gateway/anthropic-wif", "kv")]


def test_vault_delete_verified_fails_when_readback_still_exists(monkeypatch):
    class KV2:
        def delete_metadata_and_all_versions(self, **_kwargs):
            return None

    class Secrets:
        kv = type("KV", (), {"v2": KV2()})()

    class Client:
        secrets = Secrets()

    subject = VaultClient(settings())
    monkeypatch.setattr(subject, "_ensure_authenticated", lambda: None)
    monkeypatch.setattr(subject, "_get_client", lambda: Client())
    monkeypatch.setattr(subject, "read", lambda path: {"still": "present"})

    assert subject.delete_verified("ai-gateway/anthropic-wif", attempts=2) is False


@pytest.mark.asyncio
async def test_provider_routes_are_internal_typed_and_bounded():
    class Registry:
        def __init__(self):
            self.calls = []

        async def status(self, vendor):
            self.calls.append(("status", vendor))
            return {"vendor": vendor, "state": "awaiting_enrollment"}

        async def configure(self, vendor, body):
            assert isinstance(body, AnthropicWifEnrollment)
            self.calls.append(("configure", vendor, body.persisted_ids()))
            return {"vendor": vendor, "state": "configured"}

        async def disable(self, vendor, confirmation):
            self.calls.append(("disable", vendor, confirmation))
            return {"vendor": vendor, "state": "revocation_pending"}

        async def delete(self, vendor, confirmation):
            self.calls.append(("delete", vendor, confirmation))
            return {"vendor": vendor, "state": "awaiting_enrollment"}

    previous = dict(api_state)
    registry = Registry()
    try:
        cfg = settings()
        api_state.clear()
        api_state.update({"settings": cfg, "provider_registry": registry})
        auth = {"X-Internal-Auth": cfg.rotator_internal_token}
        client_transport = httpx.ASGITransport(app=api_app)
        async with httpx.AsyncClient(
            transport=client_transport, base_url="http://rotator"
        ) as client:
            assert (await client.get("/providers/anthropic")).status_code == 401
            assert (
                await client.put(
                    "/providers/anthropic",
                    headers=auth,
                    json={
                        "organization_id": "org_123",
                        "service_account_id": "svc_123",
                        "federation_rule_id": "fed_123",
                        "federation_jwks_sha256": JWKS_SHA256,
                        "enrollment_confirmation": "ENROLLED",
                        "token_url": "https://attacker.invalid/token",
                    },
                )
            ).status_code == 422
            assert (
                await client.post(
                    "/providers/anthropic/disable",
                    headers=auth,
                    json={
                        "confirmation": DISABLE_CONFIRMATION,
                        "vault_path": "arbitrary/path",
                    },
                )
            ).status_code == 422

            configured = await client.put(
                "/providers/anthropic",
                headers=auth,
                json={
                    "organization_id": "org_123",
                    "service_account_id": "svc_123",
                    "federation_rule_id": "fed_123",
                    "workspace_id": "ws_123",
                    "federation_jwks_sha256": JWKS_SHA256,
                    "enrollment_confirmation": "ENROLLED",
                },
            )
            assert configured.status_code == 200
            assert configured.json()["state"] == "configured"

            disabled = await client.post(
                "/providers/anthropic/disable",
                headers=auth,
                json={"confirmation": DISABLE_CONFIRMATION},
            )
            assert disabled.status_code == 200
            deleted = await client.request(
                "DELETE",
                "/providers/anthropic",
                headers=auth,
                json={"confirmation": DELETE_CONFIRMATION},
            )
            assert deleted.status_code == 200

        assert registry.calls == [
            ("configure", "anthropic", enrollment().persisted_ids()),
            ("disable", "anthropic", DISABLE_CONFIRMATION),
            ("delete", "anthropic", DELETE_CONFIRMATION),
        ]
    finally:
        api_state.clear()
        api_state.update(previous)


@pytest.mark.asyncio
async def test_provider_route_redacts_upstream_failure_detail():
    class Registry:
        async def status(self, _vendor):
            raise ProviderUnavailable("private-key=never-return-me")

    previous = dict(api_state)
    try:
        cfg = settings()
        api_state.clear()
        api_state.update({"settings": cfg, "provider_registry": Registry()})
        client_transport = httpx.ASGITransport(app=api_app)
        async with httpx.AsyncClient(
            transport=client_transport, base_url="http://rotator"
        ) as client:
            response = await client.get(
                "/providers/anthropic",
                headers={"X-Internal-Auth": cfg.rotator_internal_token},
            )
        assert response.status_code == 502
        assert response.json() == {"detail": "provider control plane unavailable"}
        assert "never-return-me" not in response.text
    finally:
        api_state.clear()
        api_state.update(previous)


@pytest.mark.asyncio
async def test_legacy_routes_cannot_bypass_anthropic_typed_lifecycle():
    class DB:
        def __init__(self):
            self.row = {
                "vendor": "anthropic",
                "enabled": True,
                "interval_seconds": 3000,
                "grace_seconds": 300,
                "config": {},
            }
            self.upserts = []
            self.lock_available = True

        async def get_settings(self, vendor):
            assert vendor == "anthropic"
            return dict(self.row)

        async def upsert_settings(
            self, vendor, enabled, interval_seconds, grace_seconds, config
        ):
            self.upserts.append(
                (vendor, enabled, interval_seconds, grace_seconds, config)
            )
            self.row.update(
                enabled=enabled,
                interval_seconds=interval_seconds,
                grace_seconds=grace_seconds,
            )

        async def record_history(self, *_args):
            return None

        @asynccontextmanager
        async def rotation_lock(self, vendor):
            assert vendor == "anthropic"
            yield self.lock_available

    class Scheduler:
        def __init__(self):
            self.triggers = 0

        async def reload(self):
            return None

        async def trigger_now(self, vendor):
            assert vendor == "anthropic"
            self.triggers += 1
            return True

    class Registry:
        state = "configured"

        async def status(self, vendor):
            assert vendor == "anthropic"
            return {"vendor": vendor, "state": self.state}

    previous = dict(api_state)
    db = DB()
    scheduler = Scheduler()
    registry = Registry()
    try:
        cfg = settings()
        api_state.clear()
        api_state.update(
            {
                "settings": cfg,
                "db": db,
                "drivers": {"anthropic": object()},
                "scheduler": scheduler,
                "provider_registry": registry,
            }
        )
        auth = {"X-Internal-Auth": cfg.rotator_internal_token}
        client_transport = httpx.ASGITransport(app=api_app)
        async with httpx.AsyncClient(
            transport=client_transport, base_url="http://rotator"
        ) as client:
            arbitrary = await client.put(
                "/settings/anthropic",
                headers=auth,
                json={
                    "enabled": True,
                    "interval_seconds": 3600,
                    "grace_seconds": 300,
                    "config": {"token_url": "https://attacker.invalid"},
                },
            )
            assert arbitrary.status_code == 409

            disabled = await client.put(
                "/settings/anthropic",
                headers=auth,
                json={
                    "enabled": False,
                    "interval_seconds": 3600,
                    "grace_seconds": 300,
                },
            )
            assert disabled.status_code == 409

            cadence = await client.put(
                "/settings/anthropic",
                headers=auth,
                json={
                    "enabled": True,
                    "interval_seconds": 3600,
                    "grace_seconds": 300,
                },
            )
            assert cadence.status_code == 200
            assert db.upserts == [("anthropic", True, 3600, 300, None)]

            db.lock_available = False
            locked = await client.put(
                "/settings/anthropic",
                headers=auth,
                json={
                    "enabled": True,
                    "interval_seconds": 7200,
                    "grace_seconds": 300,
                },
            )
            assert locked.status_code == 409
            db.lock_available = True

            rotated = await client.post("/rotate/anthropic", headers=auth)
            assert rotated.status_code == 202

            db.row["enabled"] = False
            assert (
                await client.post("/rotate/anthropic", headers=auth)
            ).status_code == 409
            db.row["enabled"] = True
            registry.state = "jwks_drift"
            assert (
                await client.post("/rotate/anthropic", headers=auth)
            ).status_code == 409

        assert scheduler.triggers == 1
    finally:
        api_state.clear()
        api_state.update(previous)
