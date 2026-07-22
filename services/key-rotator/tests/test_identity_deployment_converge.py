from __future__ import annotations

import asyncio
import copy
from uuid import UUID

import httpx
import pytest

from app.config import Settings
from app.identity import (
    IDENTITY_STATE_SCHEMA,
    KEYCLOAK_SECURITY_EVENT_REALMS,
    KEYCLOAK_SECURITY_EVENT_TYPES,
    MANAGED_IDENTITY_PENDING_KEY,
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
        "WEBUI_OIDC_CLIENT_SECRET": "webui-secret-0123456789-ABCDEFGHIJ",
        "PORTAL_OIDC_CLIENT_SECRET": "portal-secret-0123456789-ABCDEFGHI",
        "ADMIN_PORTAL_OIDC_CLIENT_SECRET": (
            "admin-portal-secret-0123456789-ABCDE"
        ),
        "OAUTH2_PROXY_CLIENT_SECRET": "oauth2-secret-0123456789-ABCDEFGHI",
        "VAULT_OIDC_CLIENT_SECRET": "vault-oidc-secret-0123456789-ABCDEFG",
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
        "identity_state_absent": False,
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
        "identity_state_absent": True,
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
        self.write_attempts = 0
        self.fail_write_attempts: set[int] = set()

    def read(self, path: str):
        if path == self.path:
            return copy.deepcopy(self.state_doc)
        return None

    def write_verified(self, path: str, value: dict) -> bool:
        assert path == self.path
        self.write_attempts += 1
        if self.write_attempts in self.fail_write_attempts:
            return False
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
        broker_changed: bool = False,
        callback_changed: bool = False,
        cleanup_changed: bool = False,
        event_logging_changed: bool = False,
        bind_password: str = BIND_PASSWORD,
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
            "managed_ldap_policy_sha256": (
                KeycloakAdmin._managed_ldap_policy_sha256(spec)
            ),
        }
        vault = MemoryVault(cfg.identity_state_vault_path, state_doc)
        super().__init__(cfg, vault, object())
        vault.state_doc["managed_identity_policy_sha256"] = (
            self._managed_identity_policy_sha256(spec, BIND_PASSWORD)
        )
        vault.state_doc["managed_ldap_bind_credential_hmac_sha256"] = (
            self._ldap_bind_credential_hmac_sha256(BIND_PASSWORD)
        )
        self.complete = configured
        self.provider_id = provider_id
        self.bad_bind = bad_bind
        self.wif_changed = wif_changed
        self.broker_changed = broker_changed
        self.callback_changed = callback_changed
        self.cleanup_changed = cleanup_changed
        self.event_logging_changed = event_logging_changed
        self.bind_password = bind_password
        self.bootstrap_calls = 0
        self.ensure_calls = 0
        self.proof_calls = 0
        self.wif_calls = 0
        self.broker_calls = 0
        self.callback_calls = 0
        self.cleanup_calls = 0
        self.event_logging_calls = 0
        self.refresh_bind_calls: list[bool] = []
        self.audit_calls: list[tuple[str, str, dict]] = []
        self.execution_order: list[str] = []
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
                "providerId": "ldap",
                "providerType": "org.keycloak.storage.UserStorageProvider",
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
            "providerId": "ldap",
            "providerType": "org.keycloak.storage.UserStorageProvider",
            "config": {
                name: [value]
                for name, value in self._managed_ldap_config(spec).items()
            },
        }
        return complete_status()

    async def _break_glass_admin_token(self):
        return "break-glass-token"

    def _ldap_bind_password(self):
        return self.bind_password

    async def _find_component(self, realm, name, admin_token):
        assert realm == self.settings.identity_realm
        assert name == ldap_federation_spec(self.settings).provider_name
        assert admin_token == "break-glass-token"
        return copy.deepcopy(self.component)

    async def _ensure_ldap_federation(
        self,
        admin_token,
        bind_password,
        *,
        refresh_bind_credential=True,
        before_change=None,
    ):
        self.execution_order.append("ensure_ldap")
        self.ensure_calls += 1
        assert admin_token == "break-glass-token"
        assert bind_password == self.bind_password
        self.refresh_bind_calls.append(refresh_bind_credential)
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
            "providerId": "ldap",
            "providerType": "org.keycloak.storage.UserStorageProvider",
            "config": {
                name: [value]
                for name, value in self._managed_ldap_config(spec).items()
            },
        }
        return self.provider_id

    async def _prove_ldap_directory(self, spec, admin_token, bind_password):
        assert spec == ldap_federation_spec(self.settings)
        assert admin_token == "break-glass-token"
        assert bind_password == self.bind_password
        self.proof_calls += 1

    async def _ensure_relying_parties(
        self, admin_token, *, preserve_unmanaged=False, before_change=None
    ):
        assert admin_token == "break-glass-token"
        assert preserve_unmanaged is False
        self.callback_calls += 1
        if self.callback_changed and before_change is not None:
            await before_change("relying_party")
        return self.callback_changed

    async def _reconcile_broker(self, admin_token, before_change=None):
        assert admin_token == "break-glass-token"
        self.wif_calls += 1
        self.broker_calls += 1
        if (self.wif_changed or self.broker_changed) and before_change is not None:
            await before_change("wif_broker")
        return (
            {"certificate_sha256": "b" * 64},
            self.wif_changed or self.broker_changed,
        )

    async def _reconcile_security_event_logging(
        self, admin_token, before_change=None
    ):
        assert admin_token == "break-glass-token"
        self.event_logging_calls += 1
        if self.event_logging_changed and before_change is not None:
            await before_change("security_event_logging")
        return self.event_logging_changed

    async def _reconcile_deployment_bootstrap_cleanup(
        self, admin_token, before_change=None
    ):
        assert admin_token == "break-glass-token"
        self.cleanup_calls += 1
        if self.cleanup_changed and before_change is not None:
            await before_change("bootstrap_cleanup")
        return self.cleanup_changed

    async def _verify_ldap_mappers(self, component_id, admin_token):
        assert component_id == self.provider_id
        assert admin_token == "break-glass-token"

    def _vault_oidc_rp_escrow_doc(self):
        return {
            "schema_version": 1,
            "client_id": "vault",
            "client_secret": self.settings.vault_oidc_client_secret,
        }

    async def _audit(self, action, status, detail):
        self.execution_order.append(f"audit:{action}:{status}")
        self.audit_calls.append((action, status, detail))


@pytest.mark.asyncio
async def test_complete_deployment_is_live_proved_and_idempotent() -> None:
    admin = DeploymentHarness()

    assert await admin.converge_deployment_identity() == "verified"

    assert admin.bootstrap_calls == 0
    assert admin.ensure_calls == 1
    assert admin.proof_calls == 1
    assert admin.wif_calls == 1
    assert admin.broker_calls == 1
    assert admin.event_logging_calls == 1
    assert admin.callback_calls == 1
    assert admin.cleanup_calls == 1
    assert admin.refresh_bind_calls == [False]
    assert admin.vault.writes == 0
    assert admin.audit_calls[-1] == (
        "deployment_converge",
        "success",
        {"changed": False, "ldap_provider": "corp-ad"},
    )
    assert (
        "break_glass_use",
        "success",
        {"purpose": "deployment_converge"},
    ) in admin.audit_calls


@pytest.mark.asyncio
async def test_converge_persists_the_managed_ldap_policy_digest() -> None:
    admin = DeploymentHarness()
    del admin.vault.state_doc["managed_ldap_policy_sha256"]
    spec = ldap_federation_spec(admin.settings)
    assert spec is not None

    assert await admin.converge_deployment_identity() == "applied"

    # pending planned change, verified policy commit, terminal pending clear
    assert admin.vault.writes == 3
    assert admin.vault.state_doc["managed_ldap_policy_sha256"] == (
        admin._managed_ldap_policy_sha256(spec)
    )


@pytest.mark.asyncio
async def test_managed_ldap_drift_is_repaired_and_reported() -> None:
    admin = DeploymentHarness(component="drifted")

    assert await admin.converge_deployment_identity() == "applied"
    assert admin.ensure_calls == 1
    assert admin.proof_calls == 1
    operation_id = admin.audit_calls[1][2]["operation_id"]
    assert str(UUID(operation_id)) == operation_id
    assert admin.execution_order.index(
        "audit:managed_identity_drift_detected:failed"
    ) < admin.execution_order.index("ensure_ldap")
    assert admin.audit_calls == [
        (
            "break_glass_use",
            "success",
            {"purpose": "deployment_converge"},
        ),
        (
            "managed_identity_drift_detected",
            "failed",
            {
                "changed": True,
                "change_kind": "security_drift",
                "operation_id": operation_id,
            },
        ),
        (
            "ldap_drift_detected",
            "failed",
            {"ldap_provider": "corp-ad", "operation_id": operation_id},
        ),
        (
            "ldap_recovery",
            "success",
            {"ldap_provider": "corp-ad", "operation_id": operation_id},
        ),
        (
            "managed_identity_recovery",
            "success",
            {
                "changed": True,
                "change_kind": "security_drift",
                "operation_id": operation_id,
            },
        ),
        (
            "deployment_converge",
            "success",
            {"changed": True, "ldap_provider": "corp-ad"},
        ),
    ]


@pytest.mark.asyncio
async def test_reviewed_policy_change_is_not_reported_as_security_drift() -> None:
    admin = DeploymentHarness(component="drifted")
    admin.vault.state_doc["managed_ldap_policy_sha256"] = "0" * 64

    assert await admin.converge_deployment_identity() == "applied"

    planned = next(
        entry
        for entry in admin.audit_calls
        if entry[0] == "managed_identity_change_planned"
    )
    applied = next(
        entry
        for entry in admin.audit_calls
        if entry[0] == "managed_identity_change_applied"
    )
    operation_id = planned[2]["operation_id"]
    assert str(UUID(operation_id)) == operation_id
    assert planned == (
        "managed_identity_change_planned",
        "success",
        {
            "changed": True,
            "change_kind": "planned_change",
            "operation_id": operation_id,
        },
    )
    assert applied == (
        "managed_identity_change_applied",
        "success",
        {
            "changed": True,
            "change_kind": "planned_change",
            "operation_id": operation_id,
        },
    )
    assert admin.execution_order.index(
        "audit:managed_identity_change_planned:success"
    ) < admin.execution_order.index("ensure_ldap")
    assert not any("drift" in action for action, _status, _detail in admin.audit_calls)


@pytest.mark.asyncio
async def test_wif_frontend_domain_drift_is_repaired_and_reported() -> None:
    admin = DeploymentHarness(wif_changed=True)

    assert await admin.converge_deployment_identity() == "applied"
    assert admin.wif_calls == 1
    detected = next(
        entry for entry in admin.audit_calls
        if entry[0] == "managed_identity_drift_detected"
    )
    recovered = next(
        entry for entry in admin.audit_calls
        if entry[0] == "managed_identity_recovery"
    )
    assert detected[2]["operation_id"] == recovered[2]["operation_id"]


@pytest.mark.asyncio
async def test_complete_brownfield_deployment_reconciles_broker_policy() -> None:
    admin = DeploymentHarness(broker_changed=True)

    assert await admin.converge_deployment_identity() == "applied"
    assert admin.bootstrap_calls == 0
    assert admin.broker_calls == 1


@pytest.mark.asyncio
async def test_security_event_logging_drift_is_repaired_and_reported() -> None:
    admin = DeploymentHarness(event_logging_changed=True)

    assert await admin.converge_deployment_identity() == "applied"
    assert admin.event_logging_calls == 1
    detected = next(
        entry for entry in admin.audit_calls
        if entry[0] == "managed_identity_drift_detected"
    )
    recovered = next(
        entry for entry in admin.audit_calls
        if entry[0] == "managed_identity_recovery"
    )
    assert detected[2]["operation_id"] == recovered[2]["operation_id"]


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
async def test_security_event_logging_accepts_keycloak_event_order() -> None:
    admin = EventLoggingHarness(drifted=False)
    for realm in admin.realms.values():
        realm["enabledEventTypes"] = list(reversed(realm["enabledEventTypes"]))

    assert await admin._reconcile_security_event_logging("admin-token") is False
    assert admin.puts == []


@pytest.mark.asyncio
@pytest.mark.parametrize("event_types", [
    [*KEYCLOAK_SECURITY_EVENT_TYPES, KEYCLOAK_SECURITY_EVENT_TYPES[0]],
    list(KEYCLOAK_SECURITY_EVENT_TYPES[:-1]),
    [*KEYCLOAK_SECURITY_EVENT_TYPES[:-1], "UNREVIEWED_EVENT"],
])
async def test_security_event_logging_repairs_non_exact_event_sets(
    event_types: list[str],
) -> None:
    admin = EventLoggingHarness(drifted=False)
    admin.realms["master"]["enabledEventTypes"] = event_types

    assert await admin._reconcile_security_event_logging("admin-token") is True
    assert admin.puts == ["master"]
    assert admin.realms["master"]["enabledEventTypes"] == list(
        KEYCLOAK_SECURITY_EVENT_TYPES
    )


@pytest.mark.asyncio
async def test_deleted_ldap_provider_is_recreated_and_vault_pointer_is_updated() -> None:
    admin = DeploymentHarness(component="missing", provider_id="ldap-provider-new")
    admin.vault.state_doc["federation_provider_id"] = "ldap-provider-old"

    assert await admin.converge_deployment_identity() == "applied"
    assert admin.vault.writes == 4
    assert admin.vault.state_doc["federation_provider_id"] == "ldap-provider-new"


@pytest.mark.asyncio
async def test_bad_bind_stops_before_callbacks_cleanup_or_success_audit() -> None:
    admin = DeploymentHarness(bad_bind=True)

    with pytest.raises(IdentityConflict, match="bind credential failed"):
        await admin.converge_deployment_identity()

    assert admin.callback_calls == 0
    assert admin.cleanup_calls == 0
    operation_id = admin.audit_calls[1][2]["operation_id"]
    assert str(UUID(operation_id)) == operation_id
    assert admin.audit_calls == [
        (
            "break_glass_use",
            "success",
            {"purpose": "deployment_converge"},
        ),
        (
            "managed_identity_drift_detected",
            "failed",
            {
                "changed": True,
                "change_kind": "security_drift",
                "operation_id": operation_id,
            },
        ),
        (
            "ldap_check",
            "failed",
            {"error_type": "IdentityConflict", "ldap_provider": "corp-ad"},
        ),
        (
            "managed_identity_recovery",
            "failed",
            {
                "changed": True,
                "change_kind": "security_drift",
                "operation_id": operation_id,
            },
        ),
    ]


@pytest.mark.asyncio
async def test_deployment_failure_audit_contains_only_the_error_type() -> None:
    admin = DeploymentHarness()

    await admin.audit_deployment_failure(
        IdentityConflict("secret LDAP bind password from upstream")
    )

    assert admin.audit_calls == [
        (
            "deployment_converge",
            "failed",
            {"error_type": "IdentityConflict"},
        )
    ]


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
    assert admin.audit_calls == [
        (
            "break_glass_use",
            "success",
            {"purpose": "deployment_converge"},
        )
    ]


@pytest.mark.asyncio
async def test_ldap_recovery_waits_for_the_final_deployment_gate(monkeypatch) -> None:
    admin = DeploymentHarness(component="drifted")
    calls = 0

    async def status():
        nonlocal calls
        calls += 1
        return complete_status() if calls == 1 else incomplete_status()

    monkeypatch.setattr(admin, "status", status)

    with pytest.raises(IdentityError, match="did not verify"):
        await admin.converge_deployment_identity()

    actions = [action for action, _status, _detail in admin.audit_calls]
    assert "ldap_drift_detected" in actions
    assert "ldap_recovery" not in actions
    recovery = next(
        entry
        for entry in admin.audit_calls
        if entry[0] == "managed_identity_recovery"
    )
    assert recovery[1] == "failed"
    assert recovery[2]["operation_id"] == admin.audit_calls[1][2]["operation_id"]


@pytest.mark.asyncio
async def test_ldap_recovery_waits_for_durable_state_verification(monkeypatch) -> None:
    admin = DeploymentHarness(component="drifted")
    spec = ldap_federation_spec(admin.settings)
    assert spec is not None

    monkeypatch.setattr(
        admin,
        "_identity_state",
        lambda: {
            "federation_provider_id": "wrong-provider",
            "federation_provider_name": "corp-ad",
            "managed_ldap_policy_sha256": admin._managed_ldap_policy_sha256(spec),
            "managed_identity_policy_sha256": (
                admin._managed_identity_policy_sha256(spec, BIND_PASSWORD)
            ),
        },
    )

    with pytest.raises(IdentityError, match="durable identity state"):
        await admin.converge_deployment_identity()

    actions = [action for action, _status, _detail in admin.audit_calls]
    assert "ldap_drift_detected" in actions
    assert "ldap_recovery" not in actions
    assert (
        "managed_identity_recovery",
        "failed",
    ) in [(action, status) for action, status, _detail in admin.audit_calls]


@pytest.mark.asyncio
async def test_failed_repair_retry_reuses_operation_id_and_clears_pending(
    monkeypatch,
) -> None:
    admin = DeploymentHarness(component="drifted")
    statuses = iter(
        [complete_status(), incomplete_status(), complete_status(), complete_status()]
    )

    async def status():
        return next(statuses)

    monkeypatch.setattr(admin, "status", status)

    with pytest.raises(IdentityError, match="did not verify"):
        await admin.converge_deployment_identity()
    pending = admin.vault.state_doc[MANAGED_IDENTITY_PENDING_KEY]
    operation_id = pending["operation_id"]

    assert await admin.converge_deployment_identity() == "applied"
    starts = [
        detail["operation_id"]
        for action, _status, detail in admin.audit_calls
        if action == "managed_identity_drift_detected"
    ]
    terminals = [
        (status_value, detail["operation_id"])
        for action, status_value, detail in admin.audit_calls
        if action == "managed_identity_recovery"
    ]
    assert starts == [operation_id, operation_id]
    assert terminals == [("failed", operation_id), ("success", operation_id)]
    assert MANAGED_IDENTITY_PENDING_KEY not in admin.vault.state_doc


@pytest.mark.asyncio
async def test_terminal_audit_failure_keeps_pending_for_same_id_retry(
    monkeypatch,
) -> None:
    admin = DeploymentHarness(component="drifted")
    original_audit = admin._audit
    fail_once = True

    async def audit(action, status_value, detail):
        nonlocal fail_once
        if (
            fail_once
            and action == "managed_identity_recovery"
            and status_value == "success"
        ):
            fail_once = False
            raise IdentityError("audit path unavailable")
        await original_audit(action, status_value, detail)

    monkeypatch.setattr(admin, "_audit", audit)

    with pytest.raises(IdentityError, match="audit path unavailable"):
        await admin.converge_deployment_identity()
    operation_id = admin.vault.state_doc[MANAGED_IDENTITY_PENDING_KEY][
        "operation_id"
    ]

    assert await admin.converge_deployment_identity() == "applied"
    starts = [
        detail["operation_id"]
        for action, _status, detail in admin.audit_calls
        if action == "managed_identity_drift_detected"
    ]
    assert starts == [operation_id, operation_id]
    assert MANAGED_IDENTITY_PENDING_KEY not in admin.vault.state_doc


@pytest.mark.asyncio
async def test_pending_clear_write_failure_retries_same_terminal_id() -> None:
    admin = DeploymentHarness(component="drifted")
    admin.vault.fail_write_attempts.add(3)

    with pytest.raises(IdentityError, match="did not clear pending"):
        await admin.converge_deployment_identity()
    operation_id = admin.vault.state_doc[MANAGED_IDENTITY_PENDING_KEY][
        "operation_id"
    ]

    assert await admin.converge_deployment_identity() == "applied"
    successes = [
        detail["operation_id"]
        for action, status_value, detail in admin.audit_calls
        if action == "managed_identity_recovery" and status_value == "success"
    ]
    assert successes == [operation_id, operation_id]
    assert MANAGED_IDENTITY_PENDING_KEY not in admin.vault.state_doc


@pytest.mark.asyncio
async def test_bind_credential_rotation_is_planned_and_refreshes_once() -> None:
    admin = DeploymentHarness(
        bind_password="Rotated-Directory-Bind-Secret-0123456789"
    )

    assert await admin.converge_deployment_identity() == "applied"

    planned = next(
        entry for entry in admin.audit_calls
        if entry[0] == "managed_identity_change_planned"
    )
    applied = next(
        entry for entry in admin.audit_calls
        if entry[0] == "managed_identity_change_applied"
    )
    assert planned[2]["operation_id"] == applied[2]["operation_id"]
    assert admin.refresh_bind_calls == [True]


@pytest.mark.asyncio
async def test_stored_bind_credential_sync_failure_blocks_verification(
    monkeypatch,
) -> None:
    admin = KeycloakAdmin(settings(), object(), object())
    spec = ldap_federation_spec(admin.settings)
    assert spec is not None
    component = {
        "id": "ldap-provider-1",
        "name": spec.provider_name,
        "providerId": "ldap",
        "providerType": "org.keycloak.storage.UserStorageProvider",
        "config": {
            name: [value]
            for name, value in admin._managed_ldap_config(spec).items()
        },
    }
    calls: list[tuple[str, str]] = []

    async def request(method, path, **_kwargs):
        calls.append((method, path))
        if path.endswith("/sync"):
            raise IdentityError("stored provider sync failed")
        return httpx.Response(204)

    async def find_component(_realm, _name, _token):
        return copy.deepcopy(component)

    async def verify_component(_component, _token):
        return "ldap-provider-1"

    monkeypatch.setattr(admin, "_request", request)
    monkeypatch.setattr(admin, "_find_component", find_component)
    monkeypatch.setattr(admin, "_verify_bound_ldap_component", verify_component)

    with pytest.raises(IdentityError, match="stored provider sync failed"):
        await admin._refresh_ldap_bind_credential(
            component, spec, "admin-token", BIND_PASSWORD
        )

    assert calls == [
        (
            "PUT",
            "/admin/realms/aigw/components/ldap-provider-1",
        ),
        (
            "POST",
            "/admin/realms/aigw/user-storage/ldap-provider-1/sync",
        ),
    ]


@pytest.mark.asyncio
async def test_ldap_provider_rename_fails_before_live_mutation() -> None:
    admin = DeploymentHarness()
    admin.vault.state_doc["federation_provider_name"] = "old-corp-ad"

    with pytest.raises(IdentityConflict, match="reviewed migration"):
        await admin.converge_deployment_identity()

    assert admin.event_logging_calls == 0
    assert admin.broker_calls == 0
    assert admin.ensure_calls == 0
    assert admin.callback_calls == 0


@pytest.mark.asyncio
async def test_legacy_blank_provider_name_refuses_a_different_live_id() -> None:
    admin = DeploymentHarness()
    admin.vault.state_doc["federation_provider_name"] = ""
    admin.vault.state_doc["federation_provider_id"] = "different-provider"

    with pytest.raises(IdentityConflict, match="reviewed migration"):
        await admin.converge_deployment_identity()

    assert admin.event_logging_calls == 0
    assert admin.ensure_calls == 0


@pytest.mark.asyncio
async def test_legacy_blank_provider_name_adopts_only_the_same_live_id() -> None:
    admin = DeploymentHarness()
    admin.vault.state_doc["federation_provider_name"] = ""

    assert await admin.converge_deployment_identity() == "applied"

    assert admin.vault.state_doc["federation_provider_name"] == "corp-ad"
    detected = next(
        detail for action, _status, detail in admin.audit_calls
        if action == "managed_identity_drift_detected"
    )
    recovered = next(
        detail for action, _status, detail in admin.audit_calls
        if action == "managed_identity_recovery"
    )
    assert detected["operation_id"] == recovered["operation_id"]


def test_managed_identity_hmac_changes_with_secret_and_private_key() -> None:
    baseline = DeploymentHarness()
    spec = ldap_federation_spec(baseline.settings)
    assert spec is not None
    baseline_digest = baseline._managed_identity_policy_sha256(
        spec, BIND_PASSWORD
    )
    assert baseline_digest == baseline._managed_identity_policy_sha256(
        spec, BIND_PASSWORD
    )

    changed_secret = KeycloakAdmin(
        settings(
            PORTAL_OIDC_CLIENT_SECRET=(
                "changed-portal-secret-0123456789-ABCDEFG"
            )
        ),
        object(),
        object(),
    )
    changed_key = KeycloakAdmin(
        settings(ROTATOR_INTERNAL_TOKEN="fedcba9876543210fedcba9876543210"),
        object(),
        object(),
    )
    assert changed_secret._managed_identity_policy_sha256(
        spec, BIND_PASSWORD
    ) != baseline_digest
    assert changed_key._managed_identity_policy_sha256(
        spec, BIND_PASSWORD
    ) != baseline_digest


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "pending",
    [
        {"unexpected": True},
        {
            "schema_version": 1,
            "operation_id": "00000000-0000-0000-0000-000000000000",
            "change_kind": "security_drift",
            "desired_policy_sha256": "a" * 64,
            "ldap_drift_detected": False,
        },
    ],
)
async def test_malformed_pending_fails_before_any_live_mutation(pending) -> None:
    admin = DeploymentHarness()
    admin.vault.state_doc[MANAGED_IDENTITY_PENDING_KEY] = pending

    with pytest.raises(IdentityConflict, match="pending"):
        await admin.converge_deployment_identity()

    assert admin.event_logging_calls == 0
    assert admin.broker_calls == 0
    assert admin.ensure_calls == 0
    assert admin.callback_calls == 0


class CleanupHarness(KeycloakAdmin):
    def __init__(self, attributes: dict[str, object]) -> None:
        super().__init__(settings(), object(), object())
        self.attributes = attributes
        self.client_present = True
        self.deleted = False
        self.audit_calls: list[tuple[str, str, dict]] = []

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

    async def _audit(self, action, status, detail):
        self.audit_calls.append((action, status, detail))


@pytest.mark.asyncio
async def test_cleanup_deletes_only_the_exact_marked_temporary_client() -> None:
    admin = CleanupHarness({"is_temporary_admin": "true"})

    assert await admin._reconcile_deployment_bootstrap_cleanup(
        "break-glass-token"
    )
    assert admin.deleted is True
    assert admin.audit_calls == []


@pytest.mark.asyncio
async def test_cleanup_refuses_an_unmarked_lookalike_client() -> None:
    admin = CleanupHarness({"is_temporary_admin": "false"})

    with pytest.raises(IdentityConflict, match="unmarked"):
        await admin._reconcile_deployment_bootstrap_cleanup("break-glass-token")
    assert admin.deleted is False
