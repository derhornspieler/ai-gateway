from __future__ import annotations

import copy

import httpx
import pytest

from app.config import Settings
from app.identity import (
    CAPABILITY_ROLES,
    RELYING_PARTY_CLIENT_IDS,
    IdentityConflict,
    KeycloakAdmin,
)


def settings(**overrides) -> Settings:
    values = {
        "ROTATOR_INTERNAL_TOKEN": "0123456789abcdef0123456789abcdef",
        "PORTAL_IDENTITY_TOKEN": "abcdef0123456789abcdef0123456789",
        "VAULT_TOKEN": "",
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


RP_SECRETS = {
    "WEBUI_OIDC_CLIENT_SECRET": "WebuiOIDCSecret!0123456789-ABCDEFGHI",
    "PORTAL_OIDC_CLIENT_SECRET": "PortalOIDCSecret!0123456789-ABCDEFGH",
    "ADMIN_PORTAL_OIDC_CLIENT_SECRET": ("AdminPortalOIDCSecret!0123456789-ABCDE"),
    "OAUTH2_PROXY_CLIENT_SECRET": "OAuth2ProxySecret!0123456789-ABCDEFGHI",
    "VAULT_OIDC_CLIENT_SECRET": "VaultOIDCSecret!0123456789-ABCDEFGHIJ",
}


def baseline_spec() -> dict:
    # A production directory administrator can be placed into a reviewed set of
    # managed groups before Vault is available. The input is inventory-owned.
    return {
        "schema": 1,
        "groups": [
            {"name": "platform-admins", "roles": ["aigw-admins", "aigw-chat"]},
            {
                "name": "platform-developers",
                "roles": ["aigw-chat", "aigw-developers"],
            },
            {"name": "platform-users", "roles": ["aigw-chat", "aigw-users"]},
        ],
        "bootstrap_admin_identities": [
            {
                "username": "directory-admin",
                "group": "platform-admins",
                "federation_provider": "corp-ad",
            }
        ],
    }


def ldap_component(admin: KeycloakAdmin) -> dict:
    return {
        "id": "ldap-uuid",
        "name": "corp-ad",
        "providerId": "ldap",
        "providerType": "org.keycloak.storage.UserStorageProvider",
        "config": {
            "enabled": ["true"],
            "editMode": ["READ_ONLY"],
            "importEnabled": ["true"],
            "syncRegistrations": ["false"],
            "vendor": ["ad"],
            "usernameLDAPAttribute": ["sAMAccountName"],
            "rdnLDAPAttribute": ["cn"],
            "uuidLDAPAttribute": ["objectGUID"],
            "userObjectClasses": ["person, organizationalPerson, user"],
            "connectionUrl": [admin.settings.identity_ldap_url],
            "usersDn": [admin.settings.identity_ldap_users_dn],
            "authType": ["simple"],
            "bindDn": [admin.settings.identity_ldap_bind_dn],
            # Keycloak returns a masked value here. Its contents must never be
            # used as proof of the rest of the provider configuration.
            "bindCredential": ["**********"],
            "searchScope": ["2"],
            "useTruststoreSpi": ["always"],
            "startTls": ["false"],
            "allowKerberosAuthentication": ["false"],
            "useKerberosForPasswordAuthentication": ["false"],
            "customUserSearchFilter": [
                "(&(objectCategory=person)(objectClass=user)"
                "(!(sAMAccountName=svc-aigw-ldap)))"
            ],
        },
    }


class VaultMustNotBeUsed:
    def __getattr__(self, name):
        raise AssertionError(f"pre-Vault reconciliation touched Vault: {name}")


class FakePreVaultAdmin(KeycloakAdmin):
    def __init__(self, *, extra_client_scope: bool = False) -> None:
        super().__init__(settings(), VaultMustNotBeUsed(), None)
        self.root = {
            "id": "root-uuid",
            "name": "aigw-managed",
            "path": "/aigw-managed",
            "attributes": {"aigw.managed-root": ["true"]},
        }
        self.groups: dict[str, dict] = {
            # An unrelated managed project must remain byte-for-byte untouched.
            "operator-project": {
                "id": "operator-project-uuid",
                "name": "operator-project",
                "path": "/aigw-managed/operator-project",
                "roles": {"aigw-users"},
                "members": {"operator-user"},
                "children": [],
            }
        }
        self.clients = {
            client_id: {
                "id": f"{client_id}-uuid",
                "clientId": client_id,
                "fullScopeAllowed": False,
                "protocolMappers": [self._realm_roles_mapper()],
                "scopes": set(CAPABILITY_ROLES),
            }
            for client_id in RELYING_PARTY_CLIENT_IDS
        }
        if extra_client_scope:
            self.clients["admin-ui"]["scopes"].add("offline_access")
        self.mutations: list[tuple[str, str]] = []

    async def _bootstrap_token(self):
        return "bootstrap-token"

    async def _ensure_relying_parties(self, admin_token, *, preserve_unmanaged=False):
        assert preserve_unmanaged is True
        changed = False
        for client_id, client in self.clients.items():
            extras = client["scopes"] - CAPABILITY_ROLES
            if extras:
                raise IdentityConflict("unmanaged realm-role scope mappings")
            missing = CAPABILITY_ROLES - client["scopes"]
            if missing:
                self.mutations.append(("POST", f"client:{client_id}:scopes"))
                client["scopes"].update(missing)
                changed = True
        return changed

    async def _capability_role_representations(self, realm, admin_token):
        return [
            {"id": f"role-{name}", "name": name} for name in sorted(CAPABILITY_ROLES)
        ]

    async def _find_client(self, realm, client_id, admin_token):
        client = self.clients.get(client_id)
        return copy.deepcopy(client) if client else None

    async def _get_client(self, realm, client, admin_token):
        return copy.deepcopy(self.clients[client["clientId"]])

    async def _client_realm_role_scope_mappings(self, realm, client, admin_token):
        return [
            {"id": f"role-{name}", "name": name}
            for name in sorted(self.clients[client["clientId"]]["scopes"])
        ]

    async def _reconcile_client_realm_role_scope_mappings(
        self,
        realm,
        client,
        desired_roles,
        admin_token,
        *,
        remove_extras=True,
    ):
        assert remove_extras is False
        current = self.clients[client["clientId"]]["scopes"]
        extras = current - CAPABILITY_ROLES
        if extras:
            raise IdentityConflict("unmanaged realm-role scope mappings")
        missing = CAPABILITY_ROLES - current
        if missing:
            self.mutations.append(("POST", f"client:{client['clientId']}:scopes"))
            current.update(missing)

    async def _root_group(self, admin_token, *, create):
        return copy.deepcopy(self.root)

    async def _pre_vault_direct_child(self, root_id, group_name, admin_token):
        value = self.groups.get(group_name)
        return copy.deepcopy(value) if value else None

    async def _pre_vault_require_leaf_group(self, group, admin_token):
        if group.get("children"):
            raise IdentityConflict("baseline group is not a leaf")

    async def _pre_vault_group_roles(self, group_id, admin_token):
        group = next(value for value in self.groups.values() if value["id"] == group_id)
        return [{"id": f"role-{name}", "name": name} for name in sorted(group["roles"])]

    async def _pre_vault_federated_user(
        self, username, federation_provider, admin_token
    ):
        assert federation_provider == "corp-ad"
        return {
            "id": "directory-admin-uuid",
            "username": username,
            "enabled": True,
            "federationLink": "ldap-uuid",
        }

    async def _pre_vault_user_has_group(
        self, user_id, group_id, group_name, admin_token
    ):
        return user_id in self.groups[group_name]["members"]

    async def _pre_vault_group_members(self, group_id, admin_token):
        group = next(value for value in self.groups.values() if value["id"] == group_id)
        return [
            {"id": user_id, "username": user_id, "enabled": True}
            for user_id in sorted(group["members"])
        ]

    async def _request(self, method, path, **kwargs):
        assert method != "DELETE"
        if method == "POST" and path.endswith("/root-uuid/children"):
            name = kwargs["json_body"]["name"]
            self.groups[name] = {
                "id": f"{name}-uuid",
                "name": name,
                "path": f"/aigw-managed/{name}",
                "roles": set(),
                "members": set(),
                "children": [],
            }
            self.mutations.append((method, f"group:{name}"))
            return object()
        if method == "POST" and path.endswith("/role-mappings/realm"):
            group_id = path.split("/groups/", 1)[1].split("/", 1)[0]
            group = next(
                value for value in self.groups.values() if value["id"] == group_id
            )
            group["roles"].update(role["name"] for role in kwargs["json_body"])
            self.mutations.append((method, f"roles:{group['name']}"))
            return object()
        if method == "PUT" and "/groups/" in path:
            user_id = path.split("/users/", 1)[1].split("/", 1)[0]
            group_id = path.rsplit("/groups/", 1)[1]
            group = next(
                value for value in self.groups.values() if value["id"] == group_id
            )
            group["members"].add(user_id)
            self.mutations.append((method, f"member:{group['name']}"))
            return object()
        raise AssertionError((method, path))


class FakeRelyingPartyAdmin(KeycloakAdmin):
    def __init__(self, *, extra_mapper: bool = False) -> None:
        super().__init__(settings(**RP_SECRETS), VaultMustNotBeUsed(), None)
        self.clients = {}
        self.secrets = {}
        for desired in self._relying_party_specs():
            client_id = desired["clientId"]
            current = copy.deepcopy(desired)
            current["id"] = f"{client_id}-uuid"
            # Keycloak never returns a confidential client secret in the
            # client representation; it is read from /client-secret below.
            current.pop("secret", None)
            current["attributes"]["operator.keep"] = "true"
            current["scopes"] = set(CAPABILITY_ROLES)
            self.clients[client_id] = current
            self.secrets[client_id] = desired["secret"]
        # Model the exact legacy callback that caused the admin-host deadlock.
        self.clients["admin-portal"]["redirectUris"] = [
            "https://admin-portal.aigw.example.internal/auth/callback"
        ]
        self.clients["admin-portal"]["webOrigins"] = [
            "https://admin-portal.aigw.example.internal"
        ]
        if extra_mapper:
            self.clients["open-webui"]["protocolMappers"].append(
                {
                    "name": "operator-mapper",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-hardcoded-claim-mapper",
                    "config": {"claim.name": "operator"},
                }
            )
        self.puts: list[str] = []

    async def _capability_role_representations(self, realm, admin_token):
        return [
            {"id": f"role-{name}", "name": name} for name in sorted(CAPABILITY_ROLES)
        ]

    async def _find_client(self, realm, client_id, admin_token):
        return copy.deepcopy(self.clients[client_id])

    async def _get_client(self, realm, client, admin_token):
        return copy.deepcopy(self.clients[client["clientId"]])

    async def _put_client(self, realm, client, admin_token):
        client_id = client["clientId"]
        self.clients[client_id] = copy.deepcopy(client)
        if "secret" in client:
            self.secrets[client_id] = client["secret"]
        self.puts.append(client_id)

    async def _reconcile_client_realm_role_scope_mappings(
        self,
        realm,
        client,
        desired_roles,
        admin_token,
        *,
        remove_extras=True,
    ):
        assert remove_extras is False
        extras = self.clients[client["clientId"]]["scopes"] - CAPABILITY_ROLES
        if extras:
            raise IdentityConflict("unmanaged realm-role scope mappings")
        missing = CAPABILITY_ROLES - self.clients[client["clientId"]]["scopes"]
        self.clients[client["clientId"]]["scopes"].update(missing)
        return bool(missing)

    async def _request(self, method, path, **kwargs):
        assert method == "GET"
        assert path.endswith("/client-secret")
        client_uuid = path.split("/clients/", 1)[1].split("/", 1)[0]
        client_id = client_uuid.removesuffix("-uuid")
        return httpx.Response(200, json={"value": self.secrets[client_id]})


@pytest.mark.asyncio
async def test_pre_vault_baseline_is_narrow_idempotent_and_never_uses_vault() -> None:
    admin = FakePreVaultAdmin()
    unrelated_before = copy.deepcopy(admin.groups["operator-project"])

    assert await admin.reconcile_pre_vault_identity_baseline(baseline_spec()) is True
    assert admin.groups["platform-admins"]["roles"] == {"aigw-admins", "aigw-chat"}
    assert admin.groups["platform-developers"]["roles"] == {
        "aigw-chat",
        "aigw-developers",
    }
    assert admin.groups["platform-users"]["roles"] == {"aigw-chat", "aigw-users"}
    assert admin.groups["platform-admins"]["members"] == {"directory-admin-uuid"}
    assert admin.groups["operator-project"] == unrelated_before
    assert all(method != "DELETE" for method, _ in admin.mutations)

    mutations = list(admin.mutations)
    assert await admin.reconcile_pre_vault_identity_baseline(baseline_spec()) is False
    assert admin.mutations == mutations


@pytest.mark.asyncio
async def test_pre_vault_rp_reconciliation_migrates_managed_urls_idempotently() -> None:
    admin = FakeRelyingPartyAdmin()
    assert (
        await admin._ensure_relying_parties("bootstrap-token", preserve_unmanaged=True)
        is True
    )
    migrated = admin.clients["admin-portal"]
    assert migrated["redirectUris"] == [
        "https://admin.aigw.example.internal/auth/callback"
    ]
    assert migrated["webOrigins"] == ["https://admin.aigw.example.internal"]
    assert migrated["attributes"]["operator.keep"] == "true"
    assert admin.puts == ["admin-portal"]

    assert (
        await admin._ensure_relying_parties("bootstrap-token", preserve_unmanaged=True)
        is False
    )
    assert admin.puts == ["admin-portal"]


@pytest.mark.asyncio
async def test_pre_vault_rp_reconciliation_accepts_keycloak_url_ordering() -> None:
    admin = FakeRelyingPartyAdmin()
    assert (
        await admin._ensure_relying_parties(
            "bootstrap-token", preserve_unmanaged=True
        )
        is True
    )
    admin.puts.clear()
    admin.clients["admin-ui"]["redirectUris"].reverse()
    admin.clients["admin-ui"]["webOrigins"].reverse()

    assert (
        await admin._ensure_relying_parties(
            "bootstrap-token", preserve_unmanaged=True
        )
        is False
    )
    assert admin.puts == []


@pytest.mark.asyncio
async def test_pre_vault_rp_reconciliation_refuses_unmanaged_mapper() -> None:
    admin = FakeRelyingPartyAdmin(extra_mapper=True)
    with pytest.raises(IdentityConflict, match="unmanaged protocol mappers"):
        await admin._ensure_relying_parties("bootstrap-token", preserve_unmanaged=True)
    assert admin.puts == []


def test_ldap_provider_is_bound_to_exact_nonsecret_inventory_config() -> None:
    admin = KeycloakAdmin(settings(), None, None)
    component = ldap_component(admin)

    assert admin._verify_ldap_component(component) == "ldap-uuid"

    component["config"]["connectionUrl"] = ["ldaps://untrusted-directory:636"]
    with pytest.raises(IdentityConflict, match="inventory-bound"):
        admin._verify_ldap_component(component)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("providerId", "custom"),
        ("providerType", "org.keycloak.storage.UserStorageProviderFactory"),
        ("name", "operator-ldap"),
    ],
)
def test_ldap_provider_refuses_wrong_component_identity(field, value) -> None:
    admin = KeycloakAdmin(settings(), None, None)
    component = ldap_component(admin)
    component[field] = value

    with pytest.raises(IdentityConflict, match="inventory-bound"):
        admin._verify_ldap_component(component)


@pytest.mark.asyncio
async def test_pre_vault_baseline_refuses_unmanaged_client_scope_without_deleting() -> (
    None
):
    admin = FakePreVaultAdmin(extra_client_scope=True)
    with pytest.raises(IdentityConflict, match="unmanaged"):
        await admin.reconcile_pre_vault_identity_baseline(baseline_spec())
    assert admin.mutations == []
    assert set(admin.groups) == {"operator-project"}


@pytest.mark.asyncio
async def test_pre_vault_baseline_refuses_undeclared_group_role_without_deleting() -> (
    None
):
    admin = FakePreVaultAdmin()
    admin.groups["platform-admins"] = {
        "id": "platform-admins-uuid",
        "name": "platform-admins",
        "path": "/aigw-managed/platform-admins",
        "roles": {"aigw-admins", "manage-realm"},
        "members": set(),
        "children": [],
    }
    with pytest.raises(IdentityConflict, match="undeclared"):
        await admin.reconcile_pre_vault_identity_baseline(baseline_spec())
    assert all(method != "DELETE" for method, _ in admin.mutations)
    assert "manage-realm" in admin.groups["platform-admins"]["roles"]


@pytest.mark.asyncio
async def test_pre_vault_baseline_refuses_undeclared_admin_without_deleting() -> None:
    admin = FakePreVaultAdmin()
    admin.groups["platform-admins"] = {
        "id": "platform-admins-uuid",
        "name": "platform-admins",
        "path": "/aigw-managed/platform-admins",
        "roles": {"aigw-admins"},
        "members": {"undeclared-admin-uuid"},
        "children": [],
    }

    with pytest.raises(IdentityConflict, match="undeclared members"):
        await admin.reconcile_pre_vault_identity_baseline(baseline_spec())

    assert admin.groups["platform-admins"]["members"] == {"undeclared-admin-uuid"}
    assert all(method != "DELETE" for method, _ in admin.mutations)


@pytest.mark.asyncio
async def test_pre_vault_baseline_does_not_grant_roles_to_undeclared_members() -> None:
    admin = FakePreVaultAdmin()
    admin.groups["platform-developers"] = {
        "id": "platform-developers-uuid",
        "name": "platform-developers",
        "path": "/aigw-managed/platform-developers",
        "roles": set(),
        "members": {"undeclared-developer-uuid"},
        "children": [],
    }

    with pytest.raises(IdentityConflict, match="undeclared members"):
        await admin.reconcile_pre_vault_identity_baseline(baseline_spec())

    assert admin.groups["platform-developers"]["roles"] == set()
    assert admin.groups["platform-developers"]["members"] == {
        "undeclared-developer-uuid"
    }
    assert all(method != "DELETE" for method, _ in admin.mutations)


def test_pre_vault_spec_accepts_inventory_admin_group() -> None:
    groups, identities = KeycloakAdmin._validate_pre_vault_identity_spec(
        baseline_spec()
    )
    assert [group["name"] for group in groups] == [
        "platform-admins",
        "platform-developers",
        "platform-users",
    ]
    assert groups[0]["roles"] == ["aigw-admins", "aigw-chat"]
    assert identities == [
        {
            "username": "directory-admin",
            "group": "platform-admins",
            "federation_provider": "corp-ad",
        }
    ]


@pytest.mark.parametrize(
    "admin_group_roles",
    [
        # Chat alone is not an admin gate.
        ["aigw-chat"],
        # Only the dedicated chat capability may accompany aigw-admins on the
        # bootstrap identity's group; any other capability stays rejected.
        ["aigw-admins", "aigw-developers"],
        ["aigw-admins", "aigw-users"],
        ["aigw-admins", "aigw-chat", "aigw-developers"],
    ],
)
def test_pre_vault_bootstrap_admin_group_must_stay_a_pure_admin_gate(
    admin_group_roles,
) -> None:
    spec = baseline_spec()
    spec["groups"][0]["roles"] = sorted(admin_group_roles)
    with pytest.raises(IdentityConflict, match="bootstrap identity is invalid"):
        KeycloakAdmin._validate_pre_vault_identity_spec(spec)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.update({"unexpected": True}),
        lambda value: value.update({"groups": []}),
        lambda value: value["groups"][0].update({"roles": ["manage-realm"]}),
        lambda value: value["groups"][0].update(
            {"roles": ["aigw-admins", "aigw-developers"]}
        ),
        lambda value: value["bootstrap_admin_identities"][0].update(
            {"group": "platform-users"}
        ),
        lambda value: value["bootstrap_admin_identities"].append(
            copy.deepcopy(value["bootstrap_admin_identities"][0])
        ),
        lambda value: value["bootstrap_admin_identities"][0].update(
            {"federation_provider": "../operator-provider"}
        ),
    ],
)
async def test_invalid_pre_vault_spec_is_rejected_before_bootstrap_authority(
    mutate,
) -> None:
    admin = FakePreVaultAdmin()

    async def forbidden_token():
        raise AssertionError("invalid spec obtained bootstrap authority")

    admin._bootstrap_token = forbidden_token
    spec = baseline_spec()
    mutate(spec)
    with pytest.raises(IdentityConflict):
        await admin.reconcile_pre_vault_identity_baseline(spec)
    assert admin.mutations == []
