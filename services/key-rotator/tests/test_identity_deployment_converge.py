from __future__ import annotations

import asyncio
import copy

import httpx
import pytest

from app.config import Settings
from app.identity import (
    IDENTITY_STATE_SCHEMA,
    KEYCLOAK_SECURITY_EVENT_REALMS,
    KEYCLOAK_SECURITY_EVENT_TYPES,
    IdentityConflict,
    IdentityError,
    KeycloakAdmin,
    ldap_federation_spec,
)


BIND_PASSWORD = "Directory-Bind-Secret-9"


def settings(**overrides) -> Settings:
    values = {
        "ROTATOR_INTERNAL_TOKEN": "0123456789abcdef0123456789abcdef",
        "PORTAL_IDENTITY_TOKEN": "abcdef0123456789abcdef0123456789",
        "VAULT_TOKEN": "vault-token",
        "LITELLM_MASTER_KEY": "litellm-master-key",
        "KC_BOOTSTRAP_ADMIN_CLIENT_SECRET": (
            "Bootstrap-Secret!0123456789-ABCDEFGHIJKLMN"
        ),
        "IDENTITY_LDAP_ENABLED": True,
        "IDENTITY_LDAP_PROVIDER_NAME": "corp-ad",
        "IDENTITY_LDAP_URL": "ldaps://dc1.corp.example.com:636",
        "IDENTITY_LDAP_USERS_DN": "OU=Users,DC=corp,DC=example,DC=com",
        "IDENTITY_LDAP_BIND_DN": (
            "CN=svc-aigw-ldap,OU=Service Accounts,DC=corp,DC=example,DC=com"
        ),
        "IDENTITY_LDAP_USER_FILTER": (
            "(&(objectCategory=person)(objectClass=user)"
            "(!(sAMAccountName=svc-aigw-ldap)))"
        ),
    }
    values.update(overrides)
    return Settings(**values)


def complete_status() -> dict[str, bool]:
    return {
        "configured": True,
        "controller_usable": True,
        "bootstrap_available": False,
        "bootstrap_cleanup_required": False,
        "ldap_configured": True,
        "break_glass_escrow_readable": True,
        "break_glass_escrowed": True,
        "vault_oidc_rp_escrow_readable": True,
        "vault_oidc_rp_escrowed": True,
    }


def incomplete_status() -> dict[str, bool]:
    return {
        "configured": False,
        "controller_usable": False,
        "bootstrap_available": True,
        "bootstrap_cleanup_required": False,
        "ldap_configured": False,
        "break_glass_escrow_readable": True,
        "break_glass_escrowed": False,
        "vault_oidc_rp_escrow_readable": True,
        "vault_oidc_rp_escrowed": False,
    }


class MemoryVault:
    def __init__(self, path: str, state_doc: dict) -> None:
        self.path = path
        self.state_doc = copy.deepcopy(state_doc)
        self.writes = 0

    def read(self, path: str):
        if path == self.path:
            return copy.deepcopy(self.state_doc)
        return None

    def write_verified(self, path: str, value: dict) -> bool:
        assert path == self.path
        self.state_doc = copy.deepcopy(value)
        self.writes += 1
        return True


class DeploymentHarness(KeycloakAdmin):
    def __init__(
        self,
        *,
        configured: bool = True,
        component: str = "current",
        provider_id: str = "ldap-provider-1",
        bad_bind: bool = False,
        wif_changed: bool = False,
        callback_changed: bool = False,
        cleanup_changed: bool = False,
        event_logging_changed: bool = False,
    ) -> None:
        cfg = settings()
        spec = ldap_federation_spec(cfg)
        assert spec is not None
        state_doc = {
            "schema_version": IDENTITY_STATE_SCHEMA,
            "managed_root_group_id": "managed-root",
            "identity_controller_client_id": cfg.identity_controller_client_id,
            "federation_provider_id": provider_id,
            "federation_provider_name": spec.provider_name,
        }
        vault = MemoryVault(cfg.identity_state_vault_path, state_doc)
        super().__init__(cfg, vault, object())
        self.complete = configured
        self.provider_id = provider_id
        self.bad_bind = bad_bind
        self.wif_changed = wif_changed
        self.callback_changed = callback_changed
        self.cleanup_changed = cleanup_changed
        self.event_logging_changed = event_logging_changed
        self.bootstrap_calls = 0
        self.ensure_calls = 0
        self.proof_calls = 0
        self.wif_calls = 0
        self.callback_calls = 0
        self.cleanup_calls = 0
        self.event_logging_calls = 0
        self.audit_calls: list[tuple[str, str, dict]] = []
        self.bootstrap_started: asyncio.Event | None = None
        self.bootstrap_release: asyncio.Event | None = None
        desired = {
            name: [value] for name, value in self._managed_ldap_config(spec).items()
        }
        if component == "missing":
            self.component = None
        else:
            self.component = {
                "id": provider_id,
                "name": spec.provider_name,
                "config": desired,
            }
            if component == "drifted":
                self.component["config"]["connectionUrl"] = [
                    "ldaps://old.corp.example.com:636"
                ]

    async def status(self):
        return complete_status() if self.complete else incomplete_status()

    async def _bootstrap_locked(self):
        self.bootstrap_calls += 1
        if self.bootstrap_started is not None:
            self.bootstrap_started.set()
        if self.bootstrap_release is not None:
            await self.bootstrap_release.wait()
        self.complete = True
        spec = ldap_federation_spec(self.settings)
        assert spec is not None
        self.component = {
            "id": self.provider_id,
            "name": spec.provider_name,
            "config": {
                name: [value]
                for name, value in self._managed_ldap_config(spec).items()
            },
        }
        return complete_status()

    async def _break_glass_admin_token(self):
        return "break-glass-token"

    def _ldap_bind_password(self):
        return BIND_PASSWORD

    async def _find_component(self, realm, name, admin_token):
        assert realm == self.settings.identity_realm
        assert name == ldap_federation_spec(self.settings).provider_name
        assert admin_token == "break-glass-token"
        return copy.deepcopy(self.component)

    async def _ensure_ldap_federation(self, admin_token, bind_password):
        self.ensure_calls += 1
        assert admin_token == "break-glass-token"
        assert bind_password == BIND_PASSWORD
        if self.bad_bind:
            raise IdentityConflict(
                "the directory connection or bind credential failed verification"
            )
        spec = ldap_federation_spec(self.settings)
        assert spec is not None
        await self._prove_ldap_directory(spec, admin_token, bind_password)
        self.component = {
            "id": self.provider_id,
            "name": spec.provider_name,
            "config": {
                name: [value]
                for name, value in self._managed_ldap_config(spec).items()
            },
        }
        return self.provider_id

    async def _prove_ldap_directory(self, spec, admin_token, bind_password):
        assert spec == ldap_federation_spec(self.settings)
        assert admin_token == "break-glass-token"
        assert bind_password == BIND_PASSWORD
        self.proof_calls += 1

    async def _reconcile_relying_party_redirect_uris(self, admin_token):
        assert admin_token == "break-glass-token"
        self.callback_calls += 1
        return self.callback_changed

    async def _reconcile_wif_frontend_url(self, admin_token):
        assert admin_token == "break-glass-token"
        self.wif_calls += 1
        return self.wif_changed

    async def _reconcile_security_event_logging(self, admin_token):
        assert admin_token == "break-glass-token"
        self.event_logging_calls += 1
        return self.event_logging_changed

    async def _reconcile_deployment_bootstrap_cleanup(self, admin_token):
        assert admin_token == "break-glass-token"
        self.cleanup_calls += 1
        return self.cleanup_changed

    async def _audit(self, action, status, detail):
        self.audit_calls.append((action, status, detail))


@pytest.mark.asyncio
async def test_complete_deployment_is_live_proved_and_idempotent() -> None:
    admin = DeploymentHarness()

    assert await admin.converge_deployment_identity() == "verified"

    assert admin.bootstrap_calls == 0
    assert admin.ensure_calls == 1
    assert admin.proof_calls == 1
    assert admin.wif_calls == 1
    assert admin.event_logging_calls == 1
    assert admin.callback_calls == 1
    assert admin.cleanup_calls == 1
    assert admin.vault.writes == 0
    assert admin.audit_calls[-1] == (
        "deployment_converge",
        "success",
        {"changed": False, "ldap_provider": "corp-ad"},
    )


@pytest.mark.asyncio
async def test_managed_ldap_drift_is_repaired_and_reported() -> None:
    admin = DeploymentHarness(component="drifted")

    assert await admin.converge_deployment_identity() == "applied"
    assert admin.ensure_calls == 1
    assert admin.proof_calls == 1


@pytest.mark.asyncio
async def test_wif_frontend_domain_drift_is_repaired_and_reported() -> None:
    admin = DeploymentHarness(wif_changed=True)

    assert await admin.converge_deployment_identity() == "applied"
    assert admin.wif_calls == 1


@pytest.mark.asyncio
async def test_security_event_logging_drift_is_repaired_and_reported() -> None:
    admin = DeploymentHarness(event_logging_changed=True)

    assert await admin.converge_deployment_identity() == "applied"
    assert admin.event_logging_calls == 1


class EventLoggingHarness(KeycloakAdmin):
    def __init__(self, drifted: bool) -> None:
        super().__init__(settings(), object(), object())
        self.drifted = drifted
        self.realms = {
            realm: {
                "realm": realm,
                "eventsEnabled": not drifted,
                "eventsExpiration": 86400,
                "eventsListeners": ["jboss-logging"],
                "enabledEventTypes": list(KEYCLOAK_SECURITY_EVENT_TYPES),
                "adminEventsEnabled": False,
                "adminEventsDetailsEnabled": False,
            }
            for realm in KEYCLOAK_SECURITY_EVENT_REALMS
        }
        self.puts: list[str] = []

    async def _request(self, method, path, **kwargs):
        realm = path.rsplit("/", 1)[-1]
        if method == "PUT":
            self.puts.append(realm)
            self.realms[realm] = copy.deepcopy(kwargs["json_body"])
            return httpx.Response(204)
        return httpx.Response(200, json=copy.deepcopy(self.realms[realm]))


@pytest.mark.asyncio
async def test_security_event_logging_reconciles_and_verifies_every_realm() -> None:
    admin = EventLoggingHarness(drifted=True)

    assert await admin._reconcile_security_event_logging("admin-token") is True
    assert admin.puts == list(KEYCLOAK_SECURITY_EVENT_REALMS)
    for realm in admin.realms.values():
        assert realm["eventsEnabled"] is True
        assert realm["eventsListeners"] == ["jboss-logging"]
        assert realm["enabledEventTypes"] == list(KEYCLOAK_SECURITY_EVENT_TYPES)
        assert realm["adminEventsEnabled"] is False
        assert realm["adminEventsDetailsEnabled"] is False


@pytest.mark.asyncio
async def test_security_event_logging_is_idempotent() -> None:
    admin = EventLoggingHarness(drifted=False)

    assert await admin._reconcile_security_event_logging("admin-token") is False
    assert admin.puts == []


@pytest.mark.asyncio
async def test_deleted_ldap_provider_is_recreated_and_vault_pointer_is_updated() -> None:
    admin = DeploymentHarness(component="missing", provider_id="ldap-provider-new")
    admin.vault.state_doc["federation_provider_id"] = "ldap-provider-old"

    assert await admin.converge_deployment_identity() == "applied"
    assert admin.vault.writes == 1
    assert admin.vault.state_doc["federation_provider_id"] == "ldap-provider-new"


@pytest.mark.asyncio
async def test_bad_bind_stops_before_callbacks_cleanup_or_success_audit() -> None:
    admin = DeploymentHarness(bad_bind=True)

    with pytest.raises(IdentityConflict, match="bind credential failed"):
        await admin.converge_deployment_identity()

    assert admin.callback_calls == 0
    assert admin.cleanup_calls == 0
    assert admin.audit_calls == []


@pytest.mark.asyncio
async def test_legacy_bootstrap_and_deployment_share_one_race_lock() -> None:
    admin = DeploymentHarness(configured=False)
    admin.bootstrap_started = asyncio.Event()
    admin.bootstrap_release = asyncio.Event()

    bootstrap = asyncio.create_task(admin.bootstrap())
    await admin.bootstrap_started.wait()
    deployment = asyncio.create_task(admin.converge_deployment_identity())
    await asyncio.sleep(0)
    assert admin.bootstrap_calls == 1

    admin.bootstrap_release.set()
    bootstrap_result, deployment_result = await asyncio.gather(bootstrap, deployment)

    assert bootstrap_result == complete_status()
    assert deployment_result == "verified"
    assert admin.bootstrap_calls == 1


@pytest.mark.asyncio
async def test_final_status_must_still_be_strictly_complete(monkeypatch) -> None:
    admin = DeploymentHarness()
    calls = 0

    async def status():
        nonlocal calls
        calls += 1
        return complete_status() if calls == 1 else incomplete_status()

    monkeypatch.setattr(admin, "status", status)

    with pytest.raises(IdentityError, match="did not verify"):
        await admin.converge_deployment_identity()
    assert admin.audit_calls == []


class CleanupHarness(KeycloakAdmin):
    def __init__(self, attributes: dict[str, object]) -> None:
        super().__init__(settings(), object(), object())
        self.attributes = attributes
        self.client_present = True
        self.deleted = False

    async def _bootstrap_admin_users(self, admin_token):
        assert admin_token == "break-glass-token"
        return []

    async def _find_client(self, realm, client_id, admin_token):
        assert realm == "master"
        assert client_id == self.settings.keycloak_bootstrap_admin_client_id
        assert admin_token == "break-glass-token"
        return {"id": "temporary-client"} if self.client_present else None

    async def _request(self, method, path, **kwargs):
        if method == "GET":
            return httpx.Response(200, json={"attributes": self.attributes})
        assert method == "DELETE"
        assert path.endswith("/clients/temporary-client")
        self.deleted = True
        self.client_present = False
        return httpx.Response(204)


@pytest.mark.asyncio
async def test_cleanup_deletes_only_the_exact_marked_temporary_client() -> None:
    admin = CleanupHarness({"is_temporary_admin": "true"})

    assert await admin._reconcile_deployment_bootstrap_cleanup(
        "break-glass-token"
    )
    assert admin.deleted is True


@pytest.mark.asyncio
async def test_cleanup_refuses_an_unmarked_lookalike_client() -> None:
    admin = CleanupHarness({"is_temporary_admin": "false"})

    with pytest.raises(IdentityConflict, match="unmarked"):
        await admin._reconcile_deployment_bootstrap_cleanup("break-glass-token")
    assert admin.deleted is False
