"""Production external directory (LDAPS) federation contract.

The security claims proved here are:

* plaintext ``ldap://`` and every malformed directory input is refused before
  the service can start;
* the reserved lab provider name can never be adopted by a production converge,
  and the lab federation spec stays byte-identical to today's representation
  (a drift there would silently reprovision the lab directory);
* a wrong CA bundle, a certificate that fails hostname verification, or wrong
  bind credentials make Keycloak's ``testLDAPConnection`` fail, and no
  federation component is ever written;
* the persisted provider is READ_ONLY with ``syncRegistrations=false`` and uses
  the mounted truststore.
"""

from __future__ import annotations

import os
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from app.config import LAB_LDAP_PROVIDER_NAME, Settings
from app.identity import (
    LAB_LDAP_USER_FILTER,
    IdentityConflict,
    IdentityError,
    KeycloakAdmin,
    LdapFederationSpec,
    ldap_federation_spec,
)


GENERIC_LDAP = {
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
BIND_PASSWORD = "Directory-Bind-Secret-9"


def settings(**overrides) -> Settings:
    values = {
        "ROTATOR_INTERNAL_TOKEN": "0123456789abcdef0123456789abcdef",
        "PORTAL_IDENTITY_TOKEN": "abcdef0123456789abcdef0123456789",
        "VAULT_TOKEN": "",
        "LITELLM_MASTER_KEY": "litellm-master-key",
        "KC_BOOTSTRAP_ADMIN_CLIENT_SECRET": (
            "Bootstrap-Secret!0123456789-ABCDEFGHIJKLMN"
        ),
    }
    values.update(overrides)
    return Settings(**values)


def generic_settings(**overrides) -> Settings:
    values = dict(GENERIC_LDAP)
    values.update(overrides)
    return settings(**values)


# ── Settings rejection matrix ──────────────────────────────────────────────


@pytest.mark.parametrize(
    ("label", "overrides"),
    [
        ("plaintext_ldap", {"IDENTITY_LDAP_URL": "ldap://dc1.corp.example.com"}),
        (
            "userinfo",
            {"IDENTITY_LDAP_URL": "ldaps://user:pass@dc1.corp.example.com:636"},
        ),
        ("path", {"IDENTITY_LDAP_URL": "ldaps://dc1.corp.example.com:636/o=corp"}),
        ("query", {"IDENTITY_LDAP_URL": "ldaps://dc1.corp.example.com:636?x=1"}),
        ("ip_literal", {"IDENTITY_LDAP_URL": "ldaps://10.20.5.10:636"}),
        ("port_389", {"IDENTITY_LDAP_URL": "ldaps://dc1.corp.example.com:389"}),
        ("port_3269", {"IDENTITY_LDAP_URL": "ldaps://dc1.corp.example.com:3269"}),
        ("reserved_lab_name", {"IDENTITY_LDAP_PROVIDER_NAME": LAB_LDAP_PROVIDER_NAME}),
        ("empty_provider_name", {"IDENTITY_LDAP_PROVIDER_NAME": ""}),
        ("empty_users_dn", {"IDENTITY_LDAP_USERS_DN": ""}),
        ("empty_bind_dn", {"IDENTITY_LDAP_BIND_DN": ""}),
        ("empty_filter", {"IDENTITY_LDAP_USER_FILTER": ""}),
        ("users_dn_not_a_dn", {"IDENTITY_LDAP_USERS_DN": "corp.example.com"}),
        ("bind_dn_without_dc", {"IDENTITY_LDAP_BIND_DN": "CN=svc,OU=Service"}),
        ("unbalanced_filter", {"IDENTITY_LDAP_USER_FILTER": "((a=b)"}),
        ("closing_first_filter", {"IDENTITY_LDAP_USER_FILTER": "()a=b(x=y)"}),
        ("filter_with_dollar", {"IDENTITY_LDAP_USER_FILTER": "(sAMAccountName=a$)"}),
        ("filter_with_nul", {"IDENTITY_LDAP_USER_FILTER": "(cn=a\x00b)"}),
        ("overlong_filter", {"IDENTITY_LDAP_USER_FILTER": "(cn=" + "a" * 520 + ")"}),
        ("vendor_openldap", {"IDENTITY_LDAP_VENDOR": "openldap"}),
        ("attribute_leading_digit", {"IDENTITY_LDAP_USERNAME_ATTRIBUTE": "1bad"}),
        ("object_classes_bad", {"IDENTITY_LDAP_USER_OBJECT_CLASSES": "person,user"}),
        (
            "bind_password_file_outside_secrets",
            {"IDENTITY_LDAP_BIND_PASSWORD_FILE": "/tmp/operator-controlled"},
        ),
    ],
)
def test_settings_refuse_unsafe_directory_inputs(label, overrides) -> None:
    with pytest.raises(ValidationError):
        generic_settings(**overrides)


def test_settings_refuse_two_simultaneous_federation_sources() -> None:
    with pytest.raises(ValidationError, match="exactly one LDAP federation source"):
        generic_settings(LAB_SAMBA_LDAP_ENABLED=True)


def test_settings_accept_a_bounded_production_directory() -> None:
    resolved = generic_settings()
    assert resolved.identity_ldap_enabled is True
    assert resolved.identity_ldap_url == "ldaps://dc1.corp.example.com:636"
    assert (
        resolved.identity_ldap_bind_password_file
        == "/run/secrets/identity_ldap_bind_password"
    )


def test_a_disabled_feature_tolerates_empty_directory_inputs() -> None:
    resolved = settings()
    assert resolved.identity_ldap_enabled is False
    assert resolved.identity_ldap_users_dn == ""
    assert ldap_federation_spec(resolved) is None


# ── Provider-identity preservation (the lab regression gate) ───────────────


def test_lab_spec_is_byte_identical_to_the_deployed_lab_representation() -> None:
    """A drift here silently reprovisions the live lab directory."""
    resolved = settings(LAB_SAMBA_LDAP_ENABLED=True)
    assert ldap_federation_spec(resolved) == LdapFederationSpec(
        provider_name="lab-samba-ad",
        # FQDN under the lab domain — the only name the customer-CA-signed leaf
        # can bear (a bare-hostname SAN violates the Aegis name constraints).
        connection_url="ldaps://samba-ad.aigw.aegisgroup.ch:636",
        users_dn="OU=AIGWUsers,DC=lab,DC=aigw,DC=internal",
        bind_dn="CN=svc-keycloak-ldap,CN=Users,DC=lab,DC=aigw,DC=internal",
        bind_password_file="/run/secrets/samba_keycloak_bind_password",
        vendor="ad",
        username_attribute="sAMAccountName",
        rdn_attribute="cn",
        uuid_attribute="objectGUID",
        user_object_classes="person, organizationalPerson, user",
        user_filter=(
            "(&(objectCategory=person)(objectClass=user)"
            "(!(sAMAccountName=svc-keycloak-ldap)))"
        ),
        # The lab's creation path must stay exactly as it is today: the DC is an
        # in-stack healthcheck-gated dependency, so no new admin-API call is
        # introduced into a lab converge.
        prove_directory_before_create=False,
    )
    assert LAB_LDAP_USER_FILTER == (
        "(&(objectCategory=person)(objectClass=user)"
        "(!(sAMAccountName=svc-keycloak-ldap)))"
    )


def test_generic_spec_maps_every_inventory_field() -> None:
    spec = ldap_federation_spec(generic_settings())
    assert spec == LdapFederationSpec(
        provider_name="corp-ad",
        connection_url="ldaps://dc1.corp.example.com:636",
        users_dn="OU=Users,DC=corp,DC=example,DC=com",
        bind_dn="CN=svc-aigw-ldap,OU=Service Accounts,DC=corp,DC=example,DC=com",
        bind_password_file="/run/secrets/identity_ldap_bind_password",
        vendor="ad",
        username_attribute="sAMAccountName",
        rdn_attribute="cn",
        uuid_attribute="objectGUID",
        user_object_classes="person, organizationalPerson, user",
        user_filter=(
            "(&(objectCategory=person)(objectClass=user)"
            "(!(sAMAccountName=svc-aigw-ldap)))"
        ),
        prove_directory_before_create=True,
    )


@pytest.mark.asyncio
async def test_creating_the_lab_provider_issues_no_new_admin_call() -> None:
    """The lab creation path is byte-for-byte what it was before this feature."""
    keycloak = RecordingKeycloak()
    admin = admin_for(keycloak, settings(LAB_SAMBA_LDAP_ENABLED=True))

    component_id = await admin._ensure_ldap_federation("bootstrap-token", BIND_PASSWORD)

    assert component_id == "component-uuid"
    assert keycloak.probe_actions == []
    assert not any(path.endswith("/testLDAPConnection") for _, path in keycloak.calls)
    assert keycloak.created["name"] == "lab-samba-ad"
    assert keycloak.created["config"]["editMode"] == ["READ_ONLY"]
    assert keycloak.created["config"]["customUserSearchFilter"] == [
        "(&(objectCategory=person)(objectClass=user)(!(sAMAccountName=svc-keycloak-ldap)))"
    ]


# ── Reconciliation against a mocked Keycloak admin API ─────────────────────


class RecordingKeycloak:
    """Minimal Keycloak admin API with configurable LDAP-probe behavior."""

    MAPPER_TYPE = "org.keycloak.storage.ldap.mappers.LDAPStorageMapper"

    def __init__(
        self,
        *,
        probe_status: int = 204,
        sync_status: int = 200,
        delete_status: int = 204,
        existing: dict | None = None,
        mappers: list[dict] | None = None,
    ) -> None:
        self.probe_status = probe_status
        self.sync_status = sync_status
        self.delete_status = delete_status
        self.existing = existing
        self.mappers = mappers or []
        self.calls: list[tuple[str, str]] = []
        self.probe_actions: list[str] = []
        self.created: dict | None = None
        self.deleted: list[str] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.calls.append((request.method, path))
        if request.method == "POST" and path.endswith("/testLDAPConnection"):
            import json

            self.probe_actions.append(json.loads(request.content)["action"])
            if self.probe_status != 204:
                return httpx.Response(self.probe_status, json={"error": "denied"})
            return httpx.Response(204)
        if request.method == "GET" and path.endswith("/components"):
            # The mapper enumeration is a parent+type filtered lookup; keep it
            # separate from the provider lookup so both can be asserted.
            if request.url.params.get("type") == self.MAPPER_TYPE:
                return httpx.Response(200, json=self.mappers)
            if self.created is not None:
                return httpx.Response(200, json=[self.created])
            return httpx.Response(200, json=[self.existing] if self.existing else [])
        if request.method == "GET" and path == "/admin/realms/aigw":
            return httpx.Response(200, json={"id": "realm-uuid"})
        if request.method == "POST" and path.endswith("/components"):
            import json

            body = json.loads(request.content)
            self.created = {
                "id": "component-uuid",
                "name": body["name"],
                "providerId": body["providerId"],
                "providerType": body["providerType"],
                "config": body["config"],
            }
            return httpx.Response(201)
        if request.method == "POST" and "/user-storage/" in path:
            return httpx.Response(self.sync_status)
        if request.method == "DELETE" and "/components/" in path:
            self.deleted.append(path.rsplit("/", 1)[-1])
            return httpx.Response(self.delete_status)
        raise AssertionError(f"unexpected call: {request.method} {path}")


def admin_for(keycloak: RecordingKeycloak, resolved: Settings) -> KeycloakAdmin:
    return KeycloakAdmin(
        resolved,
        None,
        None,
        transport=httpx.MockTransport(keycloak.handler),
    )


@pytest.mark.asyncio
async def test_a_new_production_provider_is_proved_before_it_is_persisted() -> None:
    keycloak = RecordingKeycloak()
    admin = admin_for(keycloak, generic_settings())

    component_id = await admin._ensure_ldap_federation("bootstrap-token", BIND_PASSWORD)

    assert component_id == "component-uuid"
    # Both directory probes must run before the component POST.
    assert keycloak.probe_actions == ["testConnection", "testAuthentication"]
    probe_index = keycloak.calls.index(
        ("POST", "/admin/realms/aigw/testLDAPConnection")
    )
    create_index = keycloak.calls.index(("POST", "/admin/realms/aigw/components"))
    assert probe_index < create_index
    config = keycloak.created["config"]
    assert keycloak.created["name"] == "corp-ad"
    assert config["editMode"] == ["READ_ONLY"]
    assert config["syncRegistrations"] == ["false"]
    assert config["useTruststoreSpi"] == ["always"]
    assert config["startTls"] == ["false"]
    assert config["importEnabled"] == ["true"]
    assert config["connectionUrl"] == ["ldaps://dc1.corp.example.com:636"]
    assert config["usersDn"] == ["OU=Users,DC=corp,DC=example,DC=com"]
    assert config["customUserSearchFilter"] == [
        "(&(objectCategory=person)(objectClass=user)(!(sAMAccountName=svc-aigw-ldap)))"
    ]


@pytest.mark.parametrize("probe_status", [400, 401, 500])
@pytest.mark.asyncio
async def test_wrong_ca_hostname_or_credentials_persist_no_provider(
    probe_status,
) -> None:
    """Keycloak reports a failed LDAPS handshake or bind identically here.

    A wrong CA bundle (PKIX failure), a certificate whose SANs do not cover the
    configured host (hostname verification), and a wrong bind DN/password all
    surface as a non-204 testLDAPConnection. None of them may leave a component.
    """
    keycloak = RecordingKeycloak(probe_status=probe_status)
    admin = admin_for(keycloak, generic_settings())

    with pytest.raises(IdentityConflict, match="failed verification"):
        await admin._ensure_ldap_federation("bootstrap-token", BIND_PASSWORD)

    assert keycloak.created is None
    assert ("POST", "/admin/realms/aigw/components") not in keycloak.calls


def _existing_generic_component() -> dict:
    return {
        "id": "existing-uuid",
        "name": "corp-ad",
        "providerId": "ldap",
        "providerType": "org.keycloak.storage.UserStorageProvider",
        "config": {
            "enabled": ["true"],
            "editMode": ["READ_ONLY"],
            "importEnabled": ["true"],
            "syncRegistrations": ["false"],
            "authType": ["simple"],
            "searchScope": ["2"],
            "useTruststoreSpi": ["always"],
            "startTls": ["false"],
            "allowKerberosAuthentication": ["false"],
            "useKerberosForPasswordAuthentication": ["false"],
            "vendor": ["ad"],
            "usernameLDAPAttribute": ["sAMAccountName"],
            "rdnLDAPAttribute": ["cn"],
            "uuidLDAPAttribute": ["objectGUID"],
            "userObjectClasses": ["person, organizationalPerson, user"],
            "connectionUrl": ["ldaps://dc1.corp.example.com:636"],
            "usersDn": ["OU=Users,DC=corp,DC=example,DC=com"],
            "bindDn": [
                "CN=svc-aigw-ldap,OU=Service Accounts,DC=corp,DC=example,DC=com"
            ],
            "bindCredential": ["**********"],
            "customUserSearchFilter": [
                "(&(objectCategory=person)(objectClass=user)"
                "(!(sAMAccountName=svc-aigw-ldap)))"
            ],
        },
    }


# The Keycloak defaults a READ_ONLY provider carries (verified against the live
# lab directory): every user-attribute / full-name mapper is read.only=true, and
# there is no group/role mapper carrying a write-back ``mode``.
KEYCLOAK_DEFAULT_READONLY_MAPPERS = [
    {
        "id": f"{name}-uuid",
        "name": name,
        "providerId": provider_id,
        "providerType": "org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
        "parentId": "existing-uuid",
        "config": config,
    }
    for name, provider_id, config in (
        ("username", "user-attribute-ldap-mapper", {"read.only": ["true"]}),
        ("email", "user-attribute-ldap-mapper", {"read.only": ["true"]}),
        ("last name", "user-attribute-ldap-mapper", {"read.only": ["true"]}),
        ("full name", "full-name-ldap-mapper", {"read.only": ["true"]}),
        # Keycloak does not emit a read.only for these; absence must be accepted.
        ("MSAD account controls", "msad-user-account-control-mapper", {}),
        ("Kerberos principal", "kerberos-principal-attribute-mapper", {}),
    )
]


@pytest.mark.asyncio
async def test_an_existing_production_provider_is_reproved_and_not_rewritten() -> None:
    """An EXISTING external provider must still re-exercise the live LDAPS
    proof on reconcile; matching config is not proof a login will succeed."""
    keycloak = RecordingKeycloak(
        existing=_existing_generic_component(),
        mappers=KEYCLOAK_DEFAULT_READONLY_MAPPERS,
    )
    admin = admin_for(keycloak, generic_settings())

    assert (
        await admin._ensure_ldap_federation("bootstrap-token", BIND_PASSWORD)
        == "existing-uuid"
    )
    # The read-only live proof runs against the EXISTING provider ...
    assert keycloak.probe_actions == ["testConnection", "testAuthentication"]
    # ... and the component is adopted, never rewritten.
    assert ("POST", "/admin/realms/aigw/components") not in keycloak.calls
    assert keycloak.deleted == []


@pytest.mark.asyncio
async def test_an_existing_production_provider_requires_a_bind_password() -> None:
    """The existing-path live proof cannot run without a bind credential, so a
    reconcile that never supplies one must fail closed rather than skip it."""
    keycloak = RecordingKeycloak(
        existing=_existing_generic_component(),
        mappers=KEYCLOAK_DEFAULT_READONLY_MAPPERS,
    )
    admin = admin_for(keycloak, generic_settings())

    with pytest.raises(IdentityConflict, match="bind password is required"):
        await admin._ensure_ldap_federation("bootstrap-token", None)

    assert ("POST", "/admin/realms/aigw/components") not in keycloak.calls


@pytest.mark.parametrize("probe_status", [400, 401, 500])
@pytest.mark.asyncio
async def test_an_existing_provider_with_a_rotated_cert_fails_closed(
    probe_status,
) -> None:
    """The core #3 scenario: the persisted config still equals the inventory
    contract, but the live LDAPS handshake / CA / bind now fails. The converge
    must fail here instead of converging green and failing at first login."""
    keycloak = RecordingKeycloak(
        probe_status=probe_status,
        existing=_existing_generic_component(),
        mappers=KEYCLOAK_DEFAULT_READONLY_MAPPERS,
    )
    admin = admin_for(keycloak, generic_settings())

    with pytest.raises(IdentityConflict, match="failed verification"):
        await admin._ensure_ldap_federation("bootstrap-token", BIND_PASSWORD)

    assert ("POST", "/admin/realms/aigw/components") not in keycloak.calls
    assert keycloak.deleted == []


@pytest.mark.asyncio
async def test_an_existing_lab_provider_is_not_reproved() -> None:
    """Preserve the lab byte-for-byte: the in-stack DC stays exempt from the
    live proof on the existing path, exactly as on its creation path."""
    resolved = settings(LAB_SAMBA_LDAP_ENABLED=True)
    existing = {
        "id": "existing-uuid",
        "name": LAB_LDAP_PROVIDER_NAME,
        "providerId": "ldap",
        "providerType": "org.keycloak.storage.UserStorageProvider",
        "config": {
            "enabled": ["true"],
            "editMode": ["READ_ONLY"],
            "importEnabled": ["true"],
            "syncRegistrations": ["false"],
            "authType": ["simple"],
            "searchScope": ["2"],
            "useTruststoreSpi": ["always"],
            "startTls": ["false"],
            "allowKerberosAuthentication": ["false"],
            "useKerberosForPasswordAuthentication": ["false"],
            "vendor": ["ad"],
            "usernameLDAPAttribute": ["sAMAccountName"],
            "rdnLDAPAttribute": ["cn"],
            "uuidLDAPAttribute": ["objectGUID"],
            "userObjectClasses": ["person, organizationalPerson, user"],
            "connectionUrl": [resolved.lab_samba_ldap_url],
            "usersDn": [resolved.lab_samba_users_dn],
            "bindDn": [resolved.lab_samba_bind_dn],
            "bindCredential": ["**********"],
            "customUserSearchFilter": [
                "(&(objectCategory=person)(objectClass=user)"
                "(!(sAMAccountName=svc-keycloak-ldap)))"
            ],
        },
    }
    keycloak = RecordingKeycloak(
        existing=existing, mappers=KEYCLOAK_DEFAULT_READONLY_MAPPERS
    )
    admin = admin_for(keycloak, resolved)

    assert await admin._ensure_ldap_federation("bootstrap-token", None) == "existing-uuid"
    assert keycloak.probe_actions == []
    assert not any(path.endswith("/testLDAPConnection") for _, path in keycloak.calls)
    assert ("POST", "/admin/realms/aigw/components") not in keycloak.calls


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("connectionUrl", ["ldaps://attacker.corp.example.com:636"]),
        ("editMode", ["WRITABLE"]),
        ("syncRegistrations", ["true"]),
        ("useTruststoreSpi", ["never"]),
        ("startTls", ["true"]),
        ("usersDn", ["OU=Everyone,DC=corp,DC=example,DC=com"]),
    ],
)
@pytest.mark.asyncio
async def test_a_drifted_existing_provider_is_refused(key, value) -> None:
    keycloak = RecordingKeycloak()
    admin = admin_for(keycloak, generic_settings())
    component = {
        "id": "existing-uuid",
        "name": "corp-ad",
        "providerId": "ldap",
        "providerType": "org.keycloak.storage.UserStorageProvider",
        "config": {
            "enabled": ["true"],
            "editMode": ["READ_ONLY"],
            "importEnabled": ["true"],
            "syncRegistrations": ["false"],
            "authType": ["simple"],
            "searchScope": ["2"],
            "useTruststoreSpi": ["always"],
            "startTls": ["false"],
            "allowKerberosAuthentication": ["false"],
            "useKerberosForPasswordAuthentication": ["false"],
            "vendor": ["ad"],
            "usernameLDAPAttribute": ["sAMAccountName"],
            "rdnLDAPAttribute": ["cn"],
            "uuidLDAPAttribute": ["objectGUID"],
            "userObjectClasses": ["person, organizationalPerson, user"],
            "connectionUrl": ["ldaps://dc1.corp.example.com:636"],
            "usersDn": ["OU=Users,DC=corp,DC=example,DC=com"],
            "bindDn": [
                "CN=svc-aigw-ldap,OU=Service Accounts,DC=corp,DC=example,DC=com"
            ],
            "customUserSearchFilter": [
                "(&(objectCategory=person)(objectClass=user)"
                "(!(sAMAccountName=svc-aigw-ldap)))"
            ],
        },
    }
    component["config"][key] = value

    with pytest.raises(IdentityConflict, match="inventory-bound"):
        admin._verify_ldap_component(component)


@pytest.mark.asyncio
async def test_a_failed_full_sync_removes_the_new_component() -> None:
    keycloak = RecordingKeycloak(sync_status=500)
    admin = admin_for(keycloak, generic_settings())

    with pytest.raises(Exception):
        await admin._ensure_ldap_federation("bootstrap-token", BIND_PASSWORD)

    assert keycloak.deleted == ["component-uuid"]


@pytest.mark.asyncio
async def test_a_failed_sync_and_failed_cleanup_raises_a_stranded_fatal() -> None:
    """#14: if the compensating delete ALSO fails, the just-created (already
    credentialed) provider must not be left behind on a green converge. Raise a
    clear fatal naming the component and the realm for manual removal."""
    keycloak = RecordingKeycloak(sync_status=500, delete_status=500)
    admin = admin_for(keycloak, generic_settings())

    with pytest.raises(IdentityError) as excinfo:
        await admin._ensure_ldap_federation("bootstrap-token", BIND_PASSWORD)

    message = str(excinfo.value)
    assert "component-uuid" in message
    assert "manually" in message
    # The delete was attempted (and failed) rather than silently skipped.
    assert keycloak.deleted == ["component-uuid"]


# ── LDAP mapper sub-component write-back gate (#6) ─────────────────────────


@pytest.mark.asyncio
async def test_verify_ldap_mappers_accepts_the_keycloak_default_readonly_set() -> None:
    """The live-lab default mapper set (read.only=true, no write-back mode)
    must pass, so the gate is not vacuous and does not churn a real provider."""
    keycloak = RecordingKeycloak(mappers=KEYCLOAK_DEFAULT_READONLY_MAPPERS)
    admin = admin_for(keycloak, generic_settings())

    await admin._verify_ldap_mappers("existing-uuid", "bootstrap-token")


@pytest.mark.parametrize(
    "writable_mapper",
    [
        {
            "id": "email-uuid",
            "name": "email",
            "providerId": "user-attribute-ldap-mapper",
            "providerType": "org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
            "parentId": "existing-uuid",
            "config": {"read.only": ["false"]},
        },
        {
            "id": "groups-uuid",
            "name": "groups",
            "providerId": "group-ldap-mapper",
            "providerType": "org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
            "parentId": "existing-uuid",
            "config": {"mode": ["LDAP_ONLY"]},
        },
        {
            "id": "roles-uuid",
            "name": "roles",
            "providerId": "role-ldap-mapper",
            "providerType": "org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
            "parentId": "existing-uuid",
            "config": {"mode": ["IMPORT"]},
        },
    ],
)
@pytest.mark.asyncio
async def test_a_write_capable_mapper_is_refused(writable_mapper) -> None:
    """A mapper added out-of-band that writes back to the directory (a writable
    user-attribute mapper, or a group/role mapper whose mode is not READ_ONLY)
    must be refused even though the top-level provider config is untouched."""
    keycloak = RecordingKeycloak(mappers=[*KEYCLOAK_DEFAULT_READONLY_MAPPERS, writable_mapper])
    admin = admin_for(keycloak, generic_settings())

    with pytest.raises(IdentityConflict, match="write-capable mapper"):
        await admin._verify_ldap_mappers("existing-uuid", "bootstrap-token")


@pytest.mark.asyncio
async def test_an_existing_provider_with_a_writable_mapper_is_refused() -> None:
    """End-to-end: the reconcile of an existing provider whose top-level config
    matches the inventory contract still fails if a writable mapper hides under
    it, and the failure occurs before the live directory probe."""
    writable = {
        "id": "email-uuid",
        "name": "email",
        "providerId": "user-attribute-ldap-mapper",
        "providerType": "org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
        "parentId": "existing-uuid",
        "config": {"read.only": ["false"]},
    }
    keycloak = RecordingKeycloak(
        existing=_existing_generic_component(),
        mappers=[*KEYCLOAK_DEFAULT_READONLY_MAPPERS, writable],
    )
    admin = admin_for(keycloak, generic_settings())

    with pytest.raises(IdentityConflict, match="write-capable mapper"):
        await admin._ensure_ldap_federation("bootstrap-token", BIND_PASSWORD)

    assert keycloak.probe_actions == []
    assert ("POST", "/admin/realms/aigw/components") not in keycloak.calls


# ── Pre-Vault federation binding (#13) ─────────────────────────────────────


def _pre_vault_admin(component: dict, user: dict) -> KeycloakAdmin:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "GET" and path.endswith("/components"):
            if request.url.params.get("type") == RecordingKeycloak.MAPPER_TYPE:
                return httpx.Response(200, json=[])
            return httpx.Response(200, json=[component])
        if request.method == "GET" and path == "/admin/realms/aigw/users":
            return httpx.Response(200, json=[user])
        raise AssertionError(f"unexpected call: {request.method} {path}")

    return KeycloakAdmin(
        generic_settings(), None, None, transport=httpx.MockTransport(handler)
    )


@pytest.mark.asyncio
async def test_pre_vault_federated_user_binds_by_inventory_contract() -> None:
    """The inventory-bound provider resolves and its enabled federated user is
    returned — the positive baseline the negative case is measured against."""
    user = {
        "id": "user-uuid",
        "username": "corp-user",
        "enabled": True,
        "federationLink": "existing-uuid",
    }
    admin = _pre_vault_admin(_existing_generic_component(), user)

    resolved = await admin._pre_vault_federated_user(
        "corp-user", "corp-ad", "bootstrap-token"
    )
    assert resolved["id"] == "user-uuid"


@pytest.mark.asyncio
async def test_pre_vault_federated_user_refuses_a_spoofed_same_name_provider() -> None:
    """#13: a provider that merely reuses the configured display name but points
    at a different directory must be refused, not resolved by name alone. A
    federated user linked to that spoofed provider must not cross the gate."""
    component = _existing_generic_component()
    component["config"]["connectionUrl"] = ["ldaps://attacker.corp.example.com:636"]
    user = {
        "id": "user-uuid",
        "username": "corp-user",
        "enabled": True,
        "federationLink": "existing-uuid",
    }
    admin = _pre_vault_admin(component, user)

    with pytest.raises(IdentityConflict, match="inventory-bound"):
        await admin._pre_vault_federated_user(
            "corp-user", "corp-ad", "bootstrap-token"
        )


@pytest.mark.asyncio
async def test_a_missing_bind_password_never_reaches_the_directory() -> None:
    keycloak = RecordingKeycloak()
    admin = admin_for(keycloak, generic_settings())

    with pytest.raises(IdentityConflict, match="bind password is required"):
        await admin._ensure_ldap_federation("bootstrap-token", None)

    assert keycloak.probe_actions == []
    assert keycloak.created is None


# ── Bind-secret file boundary ──────────────────────────────────────────────
#
# The bind-password FILE path is validated to /run/secrets/* at construction,
# so the tests point the resolved instance attribute at a temp file after the
# fact (pydantic BaseSettings does not re-validate on assignment). The read
# path is the O_NOFOLLOW fstat-bounded flow shared with the lab federation.


def _admin_reading(path: Path) -> KeycloakAdmin:
    admin = KeycloakAdmin(generic_settings(), None, None)
    admin.settings.identity_ldap_bind_password_file = str(path)
    return admin


def test_the_bind_secret_file_is_read_with_a_trailing_newline_stripped(
    tmp_path,
) -> None:
    secret = tmp_path / "identity_ldap_bind_password"
    secret.write_text(f"{BIND_PASSWORD}\n", encoding="utf-8")

    assert _admin_reading(secret)._ldap_bind_password() == BIND_PASSWORD


def test_a_missing_bind_secret_file_fails_closed(tmp_path) -> None:
    with pytest.raises(IdentityConflict, match="unavailable"):
        _admin_reading(tmp_path / "absent")._ldap_bind_password()


def test_an_oversized_bind_secret_file_fails_closed(tmp_path) -> None:
    oversized = tmp_path / "oversized"
    oversized.write_bytes(b"a" * 600)

    with pytest.raises(IdentityConflict, match="invalid"):
        _admin_reading(oversized)._ldap_bind_password()


def test_a_symlinked_bind_secret_file_fails_closed(tmp_path) -> None:
    real = tmp_path / "real"
    real.write_text(f"{BIND_PASSWORD}\n", encoding="utf-8")
    link = tmp_path / "link"
    os.symlink(real, link)

    with pytest.raises(IdentityConflict, match="unavailable"):
        _admin_reading(link)._ldap_bind_password()


def test_a_disabled_feature_reads_no_bind_secret() -> None:
    assert KeycloakAdmin(settings(), None, None)._ldap_bind_password() is None
