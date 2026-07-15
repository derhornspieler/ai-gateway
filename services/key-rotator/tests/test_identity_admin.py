from __future__ import annotations

import asyncio
import copy
import json
import time
from datetime import datetime, timedelta, timezone

import httpx
import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from app.config import Settings
from app.identity import (
    CAPABILITY_ROLES,
    RELYING_PARTY_CLIENT_IDS,
    IdentityConflict,
    IdentityError,
    IdentityNotFound,
    KeycloakAdmin,
)
from app.security import validate_wif_token_claims


AUTH_TOKEN = "0123456789abcdef0123456789abcdef"
RP_SECRETS = {
    "WEBUI_OIDC_CLIENT_SECRET": "WebuiOIDCSecret!0123456789-ABCDEFGHI",
    "PORTAL_OIDC_CLIENT_SECRET": "PortalOIDCSecret!0123456789-ABCDEFGH",
    "ADMIN_PORTAL_OIDC_CLIENT_SECRET": (
        "AdminPortalOIDCSecret!0123456789-ABCDE"
    ),
    "OAUTH2_PROXY_CLIENT_SECRET": "OAuth2ProxySecret!0123456789-ABCDEFGHI",
    "VAULT_OIDC_CLIENT_SECRET": "VaultOIDCSecret!0123456789-ABCDEFGHIJ",
}


def settings(**overrides) -> Settings:
    values = {
        "ROTATOR_INTERNAL_TOKEN": AUTH_TOKEN,
        "PORTAL_IDENTITY_TOKEN": "abcdef0123456789abcdef0123456789",
        "VAULT_TOKEN": "vault-token",
        "LITELLM_MASTER_KEY": "litellm-master-key",
        "KC_BOOTSTRAP_ADMIN_CLIENT_SECRET": (
            "Bootstrap-Secret!0123456789-ABCDEFGHIJKLMN"
        ),
    }
    values.update(overrides)
    return Settings(**values)


class FakeVault:
    def __init__(self, docs=None, events=None) -> None:
        self.docs = copy.deepcopy(docs or {})
        self.events = events if events is not None else []

    def read(self, path):
        value = self.docs.get(path)
        return copy.deepcopy(value) if value is not None else None

    def write_verified(self, path, data, attempts=3):
        self.events.append(("vault_write", path))
        self.docs[path] = copy.deepcopy(data)
        return True


class FakeDB:
    def __init__(self) -> None:
        self.history = []

    async def record_history(self, *args):
        self.history.append(args)


async def no_op_portal_key_revoker(user_id: str, project_id: str) -> None:
    """Test double for successful, already-verified LiteLLM revocation."""


def private_key_pem() -> tuple[str, rsa.RSAPrivateKey]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    return pem, key


def test_private_key_assertion_has_exact_short_lived_rfc7523_claims() -> None:
    pem, key = private_key_pem()
    token_url = "http://keycloak:8080/realms/aigw/protocol/openid-connect/token"
    encoded = KeycloakAdmin._private_key_assertion(
        "identity-controller", token_url, {"private_key_pem": pem, "kid": "kid-1"}
    )
    claims = jwt.decode(
        encoded,
        key.public_key(),
        algorithms=["RS256"],
        audience=token_url,
    )
    assert claims["iss"] == "identity-controller"
    assert claims["sub"] == "identity-controller"
    assert claims["aud"] == token_url
    assert 0 < claims["exp"] - claims["iat"] <= 60
    assert claims["jti"]
    assert jwt.get_unverified_header(encoded)["kid"] == "kid-1"


def test_relying_party_specs_require_distinct_strong_secrets() -> None:
    admin = KeycloakAdmin(settings(**RP_SECRETS), FakeVault(), FakeDB())
    specs = admin._relying_party_specs()

    assert [spec["clientId"] for spec in specs] == [
        "open-webui",
        "dev-portal",
        "admin-portal",
        "admin-ui",
        "vault",
    ]
    assert tuple(spec["clientId"] for spec in specs) == RELYING_PARTY_CLIENT_IDS
    assert len({spec["secret"] for spec in specs}) == 5
    assert all(spec["fullScopeAllowed"] is False for spec in specs)
    vault_spec = next(spec for spec in specs if spec["clientId"] == "vault")
    domain = admin.settings.aigw_domain
    assert vault_spec["redirectUris"] == [
        f"https://vault.{domain}/ui/vault/auth/oidc/oidc/callback",
        "http://localhost:8250/oidc/callback",
    ]
    assert vault_spec["webOrigins"] == [f"https://vault.{domain}"]
    assert vault_spec["directAccessGrantsEnabled"] is False
    assert vault_spec["serviceAccountsEnabled"] is False


@pytest.mark.asyncio
async def test_relying_party_reconciliation_verifies_logout_redirect_allowlist() -> None:
    """A 204 client update is insufficient when Keycloak drops RP logout URLs."""

    class ReconcileAdmin(KeycloakAdmin):
        def __init__(
            self,
            *args,
            drop_logout_attribute: bool,
            drop_role_mapper: bool = False,
            **kwargs,
        ):
            super().__init__(*args, **kwargs)
            self.drop_logout_attribute = drop_logout_attribute
            self.drop_role_mapper = drop_role_mapper

        async def _capability_role_representations(self, realm, admin_token):
            return [
                {"id": f"role-{name}", "name": name}
                for name in sorted(CAPABILITY_ROLES)
            ]

        async def _reconcile_client_realm_role_scope_mappings(
            self, realm, client, desired_roles, admin_token
        ):
            return None

        async def _find_client(self, realm, client_id, admin_token):
            return {"id": f"{client_id}-uuid", "clientId": client_id}

        async def _get_client(self, realm, client, admin_token):
            desired = next(
                spec
                for spec in self._relying_party_specs()
                if spec["clientId"] == client["clientId"]
            )
            result = copy.deepcopy(desired)
            result["id"] = client["id"]
            if (
                self.drop_logout_attribute
                and result["clientId"] == "dev-portal"
            ):
                result["attributes"] = {}
            if self.drop_role_mapper and result["clientId"] == "dev-portal":
                result["protocolMappers"] = []
            return result

        async def _put_client(self, realm, client, admin_token):
            return None

        async def _request(self, method, path, **kwargs):
            client_uuid = path.rsplit("/", 2)[-2]
            client_id = client_uuid.removesuffix("-uuid")
            secret = next(
                spec["secret"]
                for spec in self._relying_party_specs()
                if spec["clientId"] == client_id
            )
            return httpx.Response(200, json={"value": secret})

    cfg = settings(**RP_SECRETS)
    await ReconcileAdmin(
        cfg, FakeVault(), FakeDB(), drop_logout_attribute=False
    )._ensure_relying_parties("bootstrap-token")

    with pytest.raises(IdentityError, match="dev-portal.*logout URLs"):
        await ReconcileAdmin(
            cfg, FakeVault(), FakeDB(), drop_logout_attribute=True
        )._ensure_relying_parties("bootstrap-token")

    with pytest.raises(IdentityError, match="dev-portal.*role mapper"):
        await ReconcileAdmin(
            cfg,
            FakeVault(),
            FakeDB(),
            drop_logout_attribute=False,
            drop_role_mapper=True,
        )._ensure_relying_parties("bootstrap-token")


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("WEBUI_OIDC_CLIENT_SECRET", ""),
        ("PORTAL_OIDC_CLIENT_SECRET", "too-short"),
        (
            "ADMIN_PORTAL_OIDC_CLIENT_SECRET",
            "change-me-admin-portal-secret-0123456789",
        ),
        (
            "OAUTH2_PROXY_CLIENT_SECRET",
            RP_SECRETS["WEBUI_OIDC_CLIENT_SECRET"],
        ),
        ("VAULT_OIDC_CLIENT_SECRET", ""),
        (
            "VAULT_OIDC_CLIENT_SECRET",
            RP_SECRETS["OAUTH2_PROXY_CLIENT_SECRET"],
        ),
    ],
)
def test_relying_party_specs_reject_missing_weak_placeholder_or_reused_secret(
    field: str, invalid: str
) -> None:
    values = dict(RP_SECRETS)
    values[field] = invalid

    with pytest.raises(
        IdentityConflict,
        match="missing, weak, reused, or placeholders",
    ):
        KeycloakAdmin(settings(**values), FakeVault(), FakeDB())._relying_party_specs()


@pytest.mark.parametrize(
    "mappers",
    [
        [],
        [
            {
                "name": "realm-roles-to-roles-claim",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-usermodel-realm-role-mapper",
                "config": {"claim.name": "roles"},
            }
        ],
        [KeycloakAdmin._realm_roles_mapper(), KeycloakAdmin._realm_roles_mapper()],
    ],
)
def test_relying_party_role_mapper_readback_must_be_exact(mappers) -> None:
    with pytest.raises(IdentityError, match="open-webui.*role mapper"):
        KeycloakAdmin._verify_realm_roles_mapper(
            {"protocolMappers": mappers}, "open-webui"
        )


@pytest.mark.asyncio
async def test_relying_party_scope_reconciliation_converges_exact_role_ids() -> None:
    """Unexpected mappings are removed before missing capability roles are added."""

    class ScopeAdmin(KeycloakAdmin):
        def __init__(self, *args, role_id_drift: bool = False, **kwargs):
            super().__init__(*args, **kwargs)
            self.role_id_drift = role_id_drift
            self.mapping_reads = 0
            self.calls: list[tuple[str, list[str]]] = []
            self.roles = {
                name: {"id": f"role-{name}", "name": name}
                for name in CAPABILITY_ROLES
            }
            self.mappings = [
                copy.deepcopy(self.roles["aigw-users"]),
                {"id": "role-legacy", "name": "legacy-broad-role"},
            ]

        async def _request(self, method, path, **kwargs):
            if path.startswith("/admin/realms/aigw/roles/"):
                name = path.rsplit("/", 1)[-1]
                return httpx.Response(200, json=copy.deepcopy(self.roles[name]))
            endpoint = (
                "/admin/realms/aigw/clients/open-webui-uuid/"
                "scope-mappings/realm"
            )
            assert path == endpoint
            if method == "GET":
                self.mapping_reads += 1
                response = copy.deepcopy(self.mappings)
                if self.role_id_drift and self.mapping_reads >= 2:
                    for role in response:
                        if role["name"] == "aigw-admins":
                            role["id"] = "wrong-admin-role-id"
                return httpx.Response(200, json=response)
            payload = kwargs["json_body"]
            self.calls.append((method, [role["name"] for role in payload]))
            if method == "DELETE":
                names = {role["name"] for role in payload}
                self.mappings = [
                    role for role in self.mappings if role["name"] not in names
                ]
            elif method == "POST":
                self.mappings.extend(copy.deepcopy(payload))
            else:
                raise AssertionError(method)
            return httpx.Response(204)

    admin = ScopeAdmin(settings(), FakeVault(), FakeDB())
    desired_roles = await admin._capability_role_representations("aigw", "token")
    client = {
        "id": "open-webui-uuid",
        "clientId": "open-webui",
        "fullScopeAllowed": False,
    }

    await admin._reconcile_client_realm_role_scope_mappings(
        "aigw", client, desired_roles, "token"
    )

    assert admin.calls == [
        ("DELETE", ["legacy-broad-role"]),
        ("POST", ["aigw-admins", "aigw-developers"]),
    ]
    assert {
        (role["name"], role["id"])
        for role in admin.mappings
    } == {
        (name, f"role-{name}") for name in CAPABILITY_ROLES
    }

    converged = ScopeAdmin(settings(), FakeVault(), FakeDB())
    converged.mappings = [
        copy.deepcopy(converged.roles[name]) for name in sorted(CAPABILITY_ROLES)
    ]
    await converged._reconcile_client_realm_role_scope_mappings(
        "aigw",
        client,
        await converged._capability_role_representations("aigw", "token"),
        "token",
    )
    assert converged.calls == []

    drifted = ScopeAdmin(settings(), FakeVault(), FakeDB(), role_id_drift=True)
    with pytest.raises(IdentityError, match="role scope mappings"):
        await drifted._reconcile_client_realm_role_scope_mappings(
            "aigw",
            client,
            await drifted._capability_role_representations("aigw", "token"),
            "token",
        )


@pytest.mark.asyncio
async def test_prebootstrap_scope_reconciliation_is_gated_and_scope_only() -> None:
    class PrebootstrapAdmin(KeycloakAdmin):
        def __init__(self, *args, applicable: bool, state_absent: bool = True, **kwargs):
            super().__init__(*args, **kwargs)
            self.applicable = applicable
            self.state_absent = state_absent
            self.calls: list[str] = []

        async def status(self):
            return {
                "configured": False if self.applicable else True,
                "identity_state_absent": self.state_absent,
                "controller_usable": False,
                "bootstrap_available": True,
            }

        async def _bootstrap_token(self):
            self.calls.append("bootstrap-token")
            return "bootstrap-token"

        async def _capability_role_representations(self, realm, admin_token):
            self.calls.append("capability-roles")
            return [
                {"id": f"role-{name}", "name": name}
                for name in sorted(CAPABILITY_ROLES)
            ]

        async def _find_client(self, realm, client_id, admin_token):
            self.calls.append(f"find:{client_id}")
            return {"id": f"{client_id}-uuid", "clientId": client_id}

        async def _get_client(self, realm, client, admin_token):
            self.calls.append(f"get:{client['clientId']}")
            return {
                "id": client["id"],
                "clientId": client["clientId"],
                "fullScopeAllowed": False,
                "protocolMappers": [self._realm_roles_mapper()],
            }

        async def _reconcile_client_realm_role_scope_mappings(
            self, realm, client, desired_roles, admin_token
        ):
            self.calls.append(f"scope:{client['clientId']}")

        async def _put_client(self, realm, client, admin_token):
            raise AssertionError("pre-bootstrap scope repair must not PUT clients")

        async def _delete_bootstrap_principals(self, admin_token):
            raise AssertionError("pre-bootstrap scope repair must not consume bootstrap")

    applicable = PrebootstrapAdmin(
        settings(), FakeVault(), FakeDB(), applicable=True
    )
    assert await applicable.reconcile_prebootstrap_relying_party_role_scopes() is True
    assert applicable.calls == [
        "bootstrap-token",
        "capability-roles",
        *[
            entry
            for client_id in RELYING_PARTY_CLIENT_IDS
            for entry in (
                f"find:{client_id}",
                f"get:{client_id}",
                f"scope:{client_id}",
                f"get:{client_id}",
            )
        ],
    ]

    inapplicable = PrebootstrapAdmin(
        settings(), FakeVault(), FakeDB(), applicable=False
    )
    assert (
        await inapplicable.reconcile_prebootstrap_relying_party_role_scopes()
        is False
    )
    assert inapplicable.calls == []

    # `configured` becomes false if a durable controller cannot issue a token.
    # Its existing state document must still permanently close this narrow
    # master-bootstrap recovery path.
    postbootstrap_controller_outage = PrebootstrapAdmin(
        settings(), FakeVault(), FakeDB(), applicable=True, state_absent=False
    )
    assert (
        await postbootstrap_controller_outage.reconcile_prebootstrap_relying_party_role_scopes()
        is False
    )
    assert postbootstrap_controller_outage.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status",
    [
        {"configured": True, "controller_usable": False, "bootstrap_available": True},
        {"configured": False, "controller_usable": True, "bootstrap_available": True},
        {"configured": False, "controller_usable": False, "bootstrap_available": False},
        {"configured": 0, "controller_usable": False, "bootstrap_available": True},
    ],
)
async def test_prebootstrap_scope_reconciliation_requires_the_exact_status_gate(
    monkeypatch, status
) -> None:
    admin = KeycloakAdmin(settings(), FakeVault(), FakeDB())

    async def status_check():
        return status

    async def forbidden_bootstrap_token():
        raise AssertionError("inapplicable recovery must not obtain a bootstrap token")

    monkeypatch.setattr(admin, "status", status_check)
    monkeypatch.setattr(admin, "_bootstrap_token", forbidden_bootstrap_token)

    assert await admin.reconcile_prebootstrap_relying_party_role_scopes() is False


@pytest.mark.asyncio
async def test_private_key_jwt_uses_public_audience_over_internal_transport() -> None:
    pem, _ = private_key_pem()
    expected_audience = (
        "https://auth.aigw.aegisgroup.ch/realms/aigw/protocol/openid-connect/token"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == (
            "http://keycloak:8080/realms/aigw/protocol/openid-connect/token"
        )
        form = dict(item.split("=", 1) for item in request.content.decode().split("&"))
        assertion = form["client_assertion"]
        claims = jwt.decode(assertion, options={"verify_signature": False})
        assert claims["aud"] == expected_audience
        return httpx.Response(200, json={"access_token": "controller-token"})

    admin = KeycloakAdmin(
        settings(KEYCLOAK_PUBLIC_URL="https://auth.aigw.aegisgroup.ch"),
        FakeVault(),
        FakeDB(),
        transport=httpx.MockTransport(handler),
    )
    token = await admin._client_credentials_with_key(
        "aigw",
        "aigw-identity-controller",
        {"private_key_pem": pem, "kid": "controller-kid"},
    )
    assert token == "controller-token"


@pytest.mark.asyncio
async def test_keycloak_redirect_is_not_followed_and_error_body_is_redacted() -> None:
    secret_echo = "CN=svc-keycloak,DC=lab,DC=internal"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            302,
            headers={"location": "https://attacker.test/collect"},
            text=secret_echo,
        )

    admin = KeycloakAdmin(
        settings(), FakeVault(), FakeDB(), transport=httpx.MockTransport(handler)
    )
    with pytest.raises(IdentityError) as caught:
        await admin._request("GET", "/admin/realms/aigw", token="admin")
    assert secret_echo not in str(caught.value)


@pytest.mark.asyncio
async def test_generated_pkcs12_uses_one_use_password_and_vault_only_key() -> None:
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            body = json.loads(request.content)
            assert body["format"] == "PKCS12"
            assert body["keyPassword"] == body["storePassword"]
            captured["password"] = body["storePassword"]
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = issuer = x509.Name(
                [x509.NameAttribute(NameOID.COMMON_NAME, "identity-controller")]
            )
            certificate = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
                .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
                .sign(key, hashes.SHA256())
            )
            archive = pkcs12.serialize_key_and_certificates(
                b"identity-controller",
                key,
                certificate,
                None,
                serialization.BestAvailableEncryption(body["storePassword"].encode()),
            )
            return httpx.Response(200, content=archive)
        return httpx.Response(200, json={"kid": "controller-kid"})

    vault = FakeVault()
    admin = KeycloakAdmin(
        settings(), vault, FakeDB(), transport=httpx.MockTransport(handler)
    )
    key_doc = await admin._generate_client_key(
        "aigw",
        {"id": "client-uuid", "clientId": "identity-controller"},
        "admin-token",
        "ai-gateway/keycloak/identity-controller-key",
    )

    assert "BEGIN PRIVATE KEY" in vault.docs[
        "ai-gateway/keycloak/identity-controller-key"
    ]["private_key_pem"]
    assert key_doc["certificate_sha256"]
    assert captured["password"] not in json.dumps(vault.docs)


@pytest.mark.asyncio
async def test_status_returns_fingerprints_never_private_key_material(monkeypatch) -> None:
    pem, _ = private_key_pem()
    cfg = settings(KC_BOOTSTRAP_ADMIN_CLIENT_SECRET="")
    vault = FakeVault(
        {
            cfg.identity_state_vault_path: {"managed_root_group_id": "root-id"},
            cfg.identity_controller_key_vault_path: {
                "private_key_pem": pem,
                "certificate_sha256": "a" * 64,
            },
            cfg.kc_client_assertion_key_vault_path: {
                "private_key_pem": pem,
                "certificate_sha256": "b" * 64,
            },
        }
    )
    admin = KeycloakAdmin(cfg, vault, FakeDB())

    async def controller_token():
        return "token"

    monkeypatch.setattr(admin, "_controller_token", controller_token)
    result = await admin.status()
    encoded = json.dumps(result)
    assert result["configured"] is True
    assert result["controller_certificate_sha256"] == "a" * 64
    assert "PRIVATE KEY" not in encoded
    assert pem not in encoded


@pytest.mark.asyncio
async def test_bootstrap_deletes_temporary_admin_only_after_verified_state() -> None:
    events: list[tuple[str, str]] = []
    vault = FakeVault(events=events)

    class OrderedAdmin(KeycloakAdmin):
        async def _bootstrap_token(self):
            events.append(("keycloak", "bootstrap_token"))
            return "master-token"

        async def _ensure_controller(self, admin_token):
            events.append(("keycloak", "controller"))
            return {"certificate_sha256": "a" * 64}

        async def _ensure_relying_parties(self, admin_token):
            events.append(("keycloak", "relying_parties"))

        async def _client_credentials_with_key(self, realm, client_id, key_doc):
            return "controller-token"

        async def _root_group(self, admin_token, *, create):
            return {"id": "managed-root"}

        async def _ensure_ldap_federation(self, admin_token, bind_password):
            return None

        async def _ensure_broker(self, admin_token):
            return {"certificate_sha256": "b" * 64}

        async def _ensure_break_glass_admin(self, admin_token):
            events.append(("keycloak", "break_glass_ensured"))
            return {
                "username": "break-glass-admin",
                "group": "keycloak-admins",
                "escrowed_at": "2026-01-01T00:00:00+00:00",
            }

        async def _delete_bootstrap_principals(self, admin_token):
            events.append(("keycloak", "bootstrap_deleted"))

        async def status(self):
            return {"configured": True}

    result = await OrderedAdmin(settings(**RP_SECRETS), vault, FakeDB()).bootstrap()
    assert result == {"configured": True}
    break_glass = events.index(("keycloak", "break_glass_ensured"))
    vault_rp_escrow = events.index(
        ("vault_write", "ai-gateway/keycloak/vault-oidc-rp")
    )
    state_write = events.index(
        ("vault_write", "ai-gateway/keycloak/identity-state")
    )
    admin_delete = events.index(("keycloak", "bootstrap_deleted"))
    # The durable break-glass administrator and the vault RP escrow must be
    # proven before the state write, and the temporary admin destroyed only
    # after all of them.
    assert break_glass < vault_rp_escrow < state_write < admin_delete
    escrow = vault.docs["ai-gateway/keycloak/vault-oidc-rp"]
    assert escrow["schema_version"] == 1
    assert escrow["client_id"] == "vault"
    assert escrow["client_secret"] == RP_SECRETS["VAULT_OIDC_CLIENT_SECRET"]


@pytest.mark.asyncio
async def test_live_user_projects_are_sorted_and_ambiguity_fails_closed() -> None:
    cfg = settings()
    vault = FakeVault(
        {
            cfg.identity_state_vault_path: {
                "federation_provider_id": "ldap-provider",
                "managed_root_group_id": "managed-root",
            }
        }
    )

    class ProjectsAdmin(KeycloakAdmin):
        memberships = [
            {"id": "group-b", "path": "/aigw-managed/project-b"},
            {"id": "group-a", "path": "/aigw-managed/project-a"},
        ]

        async def _controller_token(self):
            return "controller-token"

        async def _request(self, method, path, **kwargs):
            if path.endswith("/users/user-1"):
                payload = {
                    "id": "user-1",
                    "enabled": True,
                    "federationLink": "ldap-provider",
                }
            elif path.endswith("/users/user-1/groups"):
                payload = self.memberships
            else:
                raise AssertionError(path)
            return httpx.Response(200, json=payload)

        async def _group_capabilities(self, group_id, token):
            return ["aigw-developers"]

    admin = ProjectsAdmin(cfg, vault, FakeDB())
    assert await admin.user_projects("user-1") == ["project-a", "project-b"]

    admin.memberships = [
        {"id": "group-1", "path": "/aigw-managed/project-a"},
        {"id": "group-2", "path": "/aigw-managed/project-a"},
    ]
    with pytest.raises(IdentityConflict, match="multiple managed groups"):
        await admin.user_projects("user-1")

    admin.memberships = [
        {"id": "group-1", "path": "/aigw-managed/project-a/nested"}
    ]
    with pytest.raises(IdentityConflict, match="nested or has an invalid ID"):
        await admin.user_projects("user-1")


@pytest.mark.asyncio
async def test_group_outside_managed_tree_is_rejected() -> None:
    cfg = settings()
    vault = FakeVault(
        {cfg.identity_state_vault_path: {"managed_root_group_id": "root-id"}}
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"id": "other-group", "path": "/unmanaged/other-group"}
        )

    admin = KeycloakAdmin(
        cfg, vault, FakeDB(), transport=httpx.MockTransport(handler)
    )
    with pytest.raises(IdentityConflict, match="outside"):
        await admin._managed_group("other-group", "token")


@pytest.mark.asyncio
async def test_last_managed_administrator_cannot_be_removed(monkeypatch) -> None:
    admin = KeycloakAdmin(
        settings(), FakeVault(), FakeDB(), portal_key_revoker=no_op_portal_key_revoker
    )

    async def token():
        return "token"

    async def group(group_id, supplied_token):
        return {"id": group_id, "path": f"/aigw-managed/{group_id}"}

    async def user(user_id, supplied_token):
        return {"id": user_id}

    async def capabilities(group_id, supplied_token):
        return ["aigw-admins"]

    async def members(group_id, supplied_token):
        return [{"id": "only-admin"}]

    async def admin_ids(
        supplied_token, *, excluded_group_id="", excluded_user_id=""
    ):
        assert excluded_group_id == "admin-group"
        assert excluded_user_id == "only-admin"
        return set()

    monkeypatch.setattr(admin, "_controller_token", token)
    monkeypatch.setattr(admin, "_managed_group", group)
    monkeypatch.setattr(admin, "_federated_user", user)
    monkeypatch.setattr(admin, "_group_capabilities", capabilities)
    monkeypatch.setattr(admin, "_members", members)
    monkeypatch.setattr(admin, "_managed_admin_user_ids", admin_ids)

    with pytest.raises(IdentityConflict, match="last managed administrator"):
        await admin.remove_member("admin-group", "only-admin")


@pytest.mark.asyncio
async def test_last_admin_candidates_use_current_enabled_federated_keycloak_state(
    monkeypatch,
) -> None:
    cfg = settings()
    vault = FakeVault(
        {
            cfg.identity_state_vault_path: {
                "managed_root_group_id": "root-id",
                "federation_provider_id": "ldap-provider",
            }
        }
    )
    admin = KeycloakAdmin(cfg, vault, FakeDB())

    async def groups():
        return [
            {
                "id": "recovery-admins",
                "name": "recovery-admins",
                "capabilities": ["aigw-admins"],
                "member_count": 5,
            }
        ]

    async def members(group_id, supplied_token):
        assert group_id == "recovery-admins"
        assert supplied_token == "controller-token"
        return [
            {"id": "disabled-directory-user"},
            {"id": "enabled-local-user"},
            {"id": "stale-directory-user"},
            {"id": "directory-user-without-live-admin-role"},
            {"id": "current-directory-admin"},
        ]

    requests: list[str] = []

    async def request(method, path, **kwargs):
        assert method == "GET"
        assert kwargs["token"] == "controller-token"
        assert kwargs["expected"] == (200, 404)
        requests.append(path)
        user_id = path.split("/users/", 1)[1].split("/", 1)[0]
        if "/role-mappings/realm/composite" in path:
            roles = (
                [{"name": "aigw-users"}, {"name": "aigw-admins"}]
                if user_id == "current-directory-admin"
                else [{"name": "aigw-users"}]
            )
            return httpx.Response(200, json=roles)
        if user_id == "stale-directory-user":
            return httpx.Response(404)
        if user_id == "disabled-directory-user":
            return httpx.Response(
                200,
                json={
                    "id": user_id,
                    "enabled": False,
                    "federationLink": "ldap-provider",
                },
            )
        if user_id == "enabled-local-user":
            return httpx.Response(200, json={"id": user_id, "enabled": True})
        return httpx.Response(
            200,
            json={
                "id": user_id,
                "enabled": True,
                "federationLink": "ldap-provider",
            },
        )

    monkeypatch.setattr(admin, "list_groups", groups)
    monkeypatch.setattr(admin, "_members", members)
    monkeypatch.setattr(admin, "_request", request)

    assert await admin._managed_admin_user_ids("controller-token") == {
        "current-directory-admin"
    }
    assert not any(
        path.endswith(
            (
                "disabled-directory-user/role-mappings/realm/composite",
                "enabled-local-user/role-mappings/realm/composite",
                "stale-directory-user/role-mappings/realm/composite",
            )
        )
        for path in requests
    )


@pytest.mark.asyncio
async def test_last_admin_candidate_ambiguity_fails_closed(monkeypatch) -> None:
    cfg = settings()
    vault = FakeVault(
        {
            cfg.identity_state_vault_path: {
                "managed_root_group_id": "root-id",
                "federation_provider_id": "ldap-provider",
            }
        }
    )
    admin = KeycloakAdmin(cfg, vault, FakeDB())

    async def groups():
        return [
            {
                "id": "recovery-admins",
                "name": "recovery-admins",
                "capabilities": ["aigw-admins"],
                "member_count": 1,
            }
        ]

    async def members(group_id, supplied_token):
        return [{"id": "ambiguous-directory-user"}]

    async def request(method, path, **kwargs):
        if path.endswith("/users/ambiguous-directory-user"):
            return httpx.Response(
                200,
                json={
                    "id": "ambiguous-directory-user",
                    "enabled": True,
                    "federationLink": "ldap-provider",
                },
            )
        return httpx.Response(200, json=[{"name": "aigw-admins"}, "malformed"])

    monkeypatch.setattr(admin, "list_groups", groups)
    monkeypatch.setattr(admin, "_members", members)
    monkeypatch.setattr(admin, "_request", request)

    with pytest.raises(IdentityError, match="composite roles were invalid"):
        await admin._managed_admin_user_ids("controller-token")


@pytest.mark.asyncio
async def test_disabled_federated_user_cannot_be_added_to_managed_group(
    monkeypatch,
) -> None:
    admin = KeycloakAdmin(settings(), FakeVault(), FakeDB())

    async def token():
        return "controller-token"

    async def group(group_id, supplied_token):
        return {"id": group_id, "path": f"/aigw-managed/{group_id}"}

    async def disabled_user(user_id, supplied_token):
        return {
            "id": user_id,
            "enabled": False,
            "federationLink": "ldap-provider",
        }

    monkeypatch.setattr(admin, "_controller_token", token)
    monkeypatch.setattr(admin, "_managed_group", group)
    monkeypatch.setattr(admin, "_federated_user", disabled_user)

    with pytest.raises(IdentityConflict, match="enabled federated user"):
        await admin.add_member("project-admins", "disabled-user")


@pytest.mark.asyncio
async def test_admin_can_leave_one_group_when_another_admin_membership_remains(
    monkeypatch,
) -> None:
    calls: list[tuple[str, str]] = []
    admin = KeycloakAdmin(
        settings(), FakeVault(), FakeDB(), portal_key_revoker=no_op_portal_key_revoker
    )

    async def token():
        return "token"

    async def group(group_id, supplied_token):
        return {"id": group_id, "path": f"/aigw-managed/{group_id}"}

    async def user(user_id, supplied_token):
        return {"id": user_id}

    async def capabilities(group_id, supplied_token):
        return ["aigw-admins"]

    async def members(group_id, supplied_token):
        return [{"id": "same-admin"}]

    async def admin_ids(
        supplied_token, *, excluded_group_id="", excluded_user_id=""
    ):
        assert excluded_group_id == "old-admin-group"
        assert excluded_user_id == "same-admin"
        return {"same-admin"}

    async def request(method, path, **kwargs):
        calls.append((method, path))
        return httpx.Response(204)

    monkeypatch.setattr(admin, "_controller_token", token)
    monkeypatch.setattr(admin, "_managed_group", group)
    monkeypatch.setattr(admin, "_federated_user", user)
    monkeypatch.setattr(admin, "_group_capabilities", capabilities)
    monkeypatch.setattr(admin, "_members", members)
    monkeypatch.setattr(admin, "_managed_admin_user_ids", admin_ids)
    monkeypatch.setattr(admin, "_request", request)

    await admin.remove_member("old-admin-group", "same-admin")

    assert calls == [
        (
            "DELETE",
            "/admin/realms/aigw/users/same-admin/groups/old-admin-group",
        ),
        ("POST", "/admin/realms/aigw/users/same-admin/logout"),
    ]


@pytest.mark.asyncio
async def test_admin_group_delete_add_remove_race_cannot_leave_zero_admins(
    monkeypatch,
) -> None:
    """All topology writers must share the last-admin transaction lock.

    Without one lock, deletion can observe an empty recovery group and pause,
    an add can put a recovery admin into it, removal can rely on that admin,
    and the original deletion can then erase the recovery group.
    """
    admin = KeycloakAdmin(
        settings(), FakeVault(), FakeDB(), portal_key_revoker=no_op_portal_key_revoker
    )
    groups: dict[str, set[str]] = {
        "old-admin-group": {"last-admin"},
        "recovery-admin-group": set(),
    }
    delete_waiting = asyncio.Event()
    allow_delete = asyncio.Event()

    async def token():
        return "token"

    async def group(group_id, supplied_token):
        if group_id not in groups:
            raise IdentityNotFound("managed group was not found")
        return {"id": group_id, "path": f"/aigw-managed/{group_id}"}

    async def user(user_id, supplied_token):
        return {"id": user_id}

    async def capabilities(group_id, supplied_token):
        return ["aigw-admins"]

    async def members(group_id, supplied_token):
        return [{"id": user_id} for user_id in sorted(groups[group_id])]

    async def admin_ids(
        supplied_token, *, excluded_group_id="", excluded_user_id=""
    ):
        return {
            user_id
            for group_id, user_ids in groups.items()
            for user_id in user_ids
            if not (
                group_id == excluded_group_id and user_id == excluded_user_id
            )
        }

    async def request(method, path, **kwargs):
        if method == "DELETE" and path.endswith("/groups/recovery-admin-group"):
            delete_waiting.set()
            await allow_delete.wait()
            groups.pop("recovery-admin-group", None)
        elif method == "PUT" and path.endswith(
            "/users/recovery-admin/groups/recovery-admin-group"
        ):
            groups["recovery-admin-group"].add("recovery-admin")
        elif method == "DELETE" and path.endswith(
            "/users/last-admin/groups/old-admin-group"
        ):
            groups["old-admin-group"].discard("last-admin")
        return httpx.Response(204)

    monkeypatch.setattr(admin, "_controller_token", token)
    monkeypatch.setattr(admin, "_managed_group", group)
    monkeypatch.setattr(admin, "_federated_user", user)
    monkeypatch.setattr(admin, "_group_capabilities", capabilities)
    monkeypatch.setattr(admin, "_members", members)
    monkeypatch.setattr(admin, "_managed_admin_user_ids", admin_ids)
    monkeypatch.setattr(admin, "_request", request)

    delete_task = asyncio.create_task(
        admin.delete_group("recovery-admin-group")
    )
    await delete_waiting.wait()
    add_task = asyncio.create_task(
        admin.add_member("recovery-admin-group", "recovery-admin")
    )
    remove_task = asyncio.create_task(
        admin.remove_member("old-admin-group", "last-admin")
    )
    await asyncio.sleep(0)

    # The deletion owns the topology lock; neither competing mutation may
    # observe or change the in-between state.
    assert groups == {
        "old-admin-group": {"last-admin"},
        "recovery-admin-group": set(),
    }
    assert not add_task.done()
    assert not remove_task.done()

    allow_delete.set()
    await delete_task
    results = await asyncio.gather(add_task, remove_task, return_exceptions=True)

    assert groups == {"old-admin-group": {"last-admin"}}
    assert any(isinstance(result, IdentityNotFound) for result in results)
    assert any(isinstance(result, IdentityConflict) for result in results)


@pytest.mark.asyncio
async def test_live_admin_decision_uses_enabled_user_and_composite_roles(
    monkeypatch,
) -> None:
    requests: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append((request.method, request.url.path))
        if request.url.path.endswith("/users/user-123"):
            return httpx.Response(200, json={"id": "user-123", "enabled": True})
        if request.url.path.endswith("/role-mappings/realm/composite"):
            return httpx.Response(
                200,
                json=[
                    {"name": "aigw-users"},
                    {"name": "aigw-admins"},
                ],
            )
        raise AssertionError(request.url.path)

    admin = KeycloakAdmin(
        settings(), FakeVault(), FakeDB(), transport=httpx.MockTransport(handler)
    )

    async def controller_token():
        return "controller-token"

    monkeypatch.setattr(admin, "_controller_token", controller_token)

    assert await admin.user_has_admin_role("user-123") is True
    assert requests == [
        ("GET", "/admin/realms/aigw/users/user-123"),
        (
            "GET",
            "/admin/realms/aigw/users/user-123/role-mappings/realm/composite",
        ),
    ]


@pytest.mark.asyncio
async def test_role_removal_invalidates_target_keycloak_sessions(monkeypatch) -> None:
    calls: list[tuple[str, str]] = []
    admin = KeycloakAdmin(
        settings(), FakeVault(), FakeDB(), portal_key_revoker=no_op_portal_key_revoker
    )

    async def controller_token():
        return "controller-token"

    async def managed_group(group_id, supplied_token):
        return {"id": group_id, "path": f"/aigw-managed/{group_id}"}

    async def federated_user(user_id, supplied_token):
        return {"id": user_id}

    async def capabilities(group_id, supplied_token):
        return ["aigw-developers"]

    async def request(method, path, **kwargs):
        calls.append((method, path))
        return httpx.Response(204)

    monkeypatch.setattr(admin, "_controller_token", controller_token)
    monkeypatch.setattr(admin, "_managed_group", managed_group)
    monkeypatch.setattr(admin, "_federated_user", federated_user)
    monkeypatch.setattr(admin, "_group_capabilities", capabilities)
    monkeypatch.setattr(admin, "_request", request)

    await admin.remove_member("developers", "user-123")

    assert calls == [
        ("DELETE", "/admin/realms/aigw/users/user-123/groups/developers"),
        ("POST", "/admin/realms/aigw/users/user-123/logout"),
    ]


@pytest.mark.asyncio
async def test_authoritative_member_removal_revokes_portal_keys_before_and_after(
    monkeypatch,
) -> None:
    events: list[tuple[str, ...]] = []

    async def revoker(user_id: str, project_id: str) -> None:
        events.append(("revoke", user_id, project_id))

    admin = KeycloakAdmin(
        settings(), FakeVault(), FakeDB(), portal_key_revoker=revoker
    )

    async def controller_token():
        return "controller-token"

    async def managed_group(group_id, supplied_token):
        return {"id": group_id, "path": "/aigw-managed/project-a"}

    async def federated_user(user_id, supplied_token):
        return {"id": user_id}

    async def capabilities(group_id, supplied_token):
        return ["aigw-developers"]

    async def request(method, path, **kwargs):
        events.append((method.lower(), path))
        return httpx.Response(204)

    monkeypatch.setattr(admin, "_controller_token", controller_token)
    monkeypatch.setattr(admin, "_managed_group", managed_group)
    monkeypatch.setattr(admin, "_federated_user", federated_user)
    monkeypatch.setattr(admin, "_group_capabilities", capabilities)
    monkeypatch.setattr(admin, "_request", request)

    await admin.remove_member("developers", "user-123")

    assert events == [
        ("revoke", "user-123", "project-a"),
        ("delete", "/admin/realms/aigw/users/user-123/groups/developers"),
        ("revoke", "user-123", "project-a"),
        ("post", "/admin/realms/aigw/users/user-123/logout"),
    ]


@pytest.mark.asyncio
async def test_ambiguous_member_delete_runs_post_revocation_then_returns_safe_error(
    monkeypatch,
) -> None:
    events: list[tuple[str, ...]] = []
    db = FakeDB()

    async def revoker(user_id: str, project_id: str) -> None:
        events.append(("revoke", user_id, project_id))

    admin = KeycloakAdmin(settings(), FakeVault(), db, portal_key_revoker=revoker)

    async def controller_token():
        return "controller-token"

    async def managed_group(group_id, supplied_token):
        return {"id": group_id, "path": "/aigw-managed/project-a"}

    async def federated_user(user_id, supplied_token):
        return {"id": user_id}

    async def capabilities(group_id, supplied_token):
        return ["aigw-developers"]

    async def request(method, path, **kwargs):
        events.append((method.lower(), path))
        if method == "DELETE":
            # The request may have committed server-side before its response
            # was lost. The caller must get a safe error, but only after the
            # second LiteLLM revoke-and-verify pass has run.
            raise httpx.ReadTimeout("response lost after Keycloak mutation")
        return httpx.Response(204)

    monkeypatch.setattr(admin, "_controller_token", controller_token)
    monkeypatch.setattr(admin, "_managed_group", managed_group)
    monkeypatch.setattr(admin, "_federated_user", federated_user)
    monkeypatch.setattr(admin, "_group_capabilities", capabilities)
    monkeypatch.setattr(admin, "_request", request)

    with pytest.raises(IdentityError, match="could not verify Keycloak membership removal"):
        await admin.remove_member("developers", "user-123")

    assert events == [
        ("revoke", "user-123", "project-a"),
        ("delete", "/admin/realms/aigw/users/user-123/groups/developers"),
        ("revoke", "user-123", "project-a"),
        ("post", "/admin/realms/aigw/users/user-123/logout"),
    ]
    assert db.history == []


@pytest.mark.asyncio
async def test_member_removal_refuses_mutation_without_verified_portal_key_revocation(
    monkeypatch,
) -> None:
    requests: list[tuple[str, str]] = []
    admin = KeycloakAdmin(settings(), FakeVault(), FakeDB())

    async def controller_token():
        return "controller-token"

    async def managed_group(group_id, supplied_token):
        return {"id": group_id, "path": "/aigw-managed/project-a"}

    async def federated_user(user_id, supplied_token):
        return {"id": user_id}

    async def capabilities(group_id, supplied_token):
        return ["aigw-developers"]

    async def request(method, path, **kwargs):
        requests.append((method, path))
        return httpx.Response(204)

    monkeypatch.setattr(admin, "_controller_token", controller_token)
    monkeypatch.setattr(admin, "_managed_group", managed_group)
    monkeypatch.setattr(admin, "_federated_user", federated_user)
    monkeypatch.setattr(admin, "_group_capabilities", capabilities)
    monkeypatch.setattr(admin, "_request", request)

    with pytest.raises(IdentityError, match="revocation control is unavailable"):
        await admin.remove_member("developers", "user-123")

    assert requests == []


@pytest.mark.asyncio
async def test_member_removal_fails_closed_before_delete_when_revocation_fails(
    monkeypatch,
) -> None:
    requests: list[tuple[str, str]] = []

    async def failing_revoker(user_id: str, project_id: str) -> None:
        raise RuntimeError("LiteLLM timeout")

    admin = KeycloakAdmin(
        settings(), FakeVault(), FakeDB(), portal_key_revoker=failing_revoker
    )

    async def controller_token():
        return "controller-token"

    async def managed_group(group_id, supplied_token):
        return {"id": group_id, "path": "/aigw-managed/project-a"}

    async def federated_user(user_id, supplied_token):
        return {"id": user_id}

    async def capabilities(group_id, supplied_token):
        return ["aigw-developers"]

    async def request(method, path, **kwargs):
        requests.append((method, path))
        return httpx.Response(204)

    monkeypatch.setattr(admin, "_controller_token", controller_token)
    monkeypatch.setattr(admin, "_managed_group", managed_group)
    monkeypatch.setattr(admin, "_federated_user", federated_user)
    monkeypatch.setattr(admin, "_group_capabilities", capabilities)
    monkeypatch.setattr(admin, "_request", request)

    with pytest.raises(IdentityError, match="could not verify portal-key revocation"):
        await admin.remove_member("developers", "user-123")

    assert requests == []


@pytest.mark.asyncio
async def test_cleanup_refuses_unmarked_master_administrator() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/admin/realms/master/users"
        return httpx.Response(
            200,
            json=[{"id": "permanent-admin", "username": "admin", "attributes": {}}],
        )

    admin = KeycloakAdmin(
        settings(), FakeVault(), FakeDB(), transport=httpx.MockTransport(handler)
    )
    with pytest.raises(IdentityConflict, match="unmarked"):
        await admin._delete_bootstrap_principals("master-token")


@pytest.mark.asyncio
async def test_cleanup_deletes_only_marked_temporary_bootstrap_principals() -> None:
    """A normal post-bootstrap cleanup removes both Keycloak temporary grants.

    The master realm also holds the durable, marked break-glass administrator
    by this point. Teardown looks up only the exact bootstrap username, so the
    break-glass user must never even be queried, let alone deleted.
    """

    calls: list[tuple[str, str]] = []
    directory = [
        {
            "id": "temporary-user",
            "username": "admin",
            "attributes": {"is_temporary_admin": ["true"]},
        },
        {
            "id": "break-glass-user",
            "username": "break-glass-admin",
            "attributes": {"aigw.break-glass": ["true"]},
        },
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        assert "break-glass-user" not in request.url.path
        if request.url.path == "/admin/realms/master/users":
            requested = request.url.params.get("username")
            return httpx.Response(
                200,
                json=[
                    user for user in directory if user["username"] == requested
                ],
            )
        if request.url.path == "/admin/realms/master/users/temporary-user":
            assert request.method == "DELETE"
            return httpx.Response(204)
        if request.url.path == "/admin/realms/master/clients":
            return httpx.Response(
                200,
                json=[
                    {
                        "id": "temporary-client",
                        "clientId": "aigw-bootstrap-controller",
                    }
                ],
            )
        if request.url.path == "/admin/realms/master/clients/temporary-client":
            if request.method == "GET":
                return httpx.Response(
                    200,
                    json={"attributes": {"is_temporary_admin": "true"}},
                )
            assert request.method == "DELETE"
            return httpx.Response(204)
        raise AssertionError((request.method, request.url.path))

    admin = KeycloakAdmin(
        settings(RETAIN_BOOTSTRAP_ADMIN_USER=False),
        FakeVault(),
        FakeDB(),
        transport=httpx.MockTransport(handler),
    )

    assert await admin._delete_bootstrap_principals("master-token") is False
    assert calls == [
        ("GET", "/admin/realms/master/users"),
        ("DELETE", "/admin/realms/master/users/temporary-user"),
        ("GET", "/admin/realms/master/clients"),
        ("GET", "/admin/realms/master/clients/temporary-client"),
        ("DELETE", "/admin/realms/master/clients/temporary-client"),
    ]


@pytest.mark.asyncio
async def test_lab_retention_fails_closed_if_keycloak_keeps_temporary_marker() -> None:
    """Do not claim a durable recovery admin when Keycloak ignores its update."""

    calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        temporary = {
            "id": "temporary-user",
            "username": "admin",
            "attributes": {"is_temporary_admin": ["true"]},
        }
        if request.url.path == "/admin/realms/master/users":
            return httpx.Response(200, json=[temporary])
        if request.url.path == "/admin/realms/master/users/temporary-user":
            if request.method == "PUT":
                return httpx.Response(204)
            if request.method == "GET":
                # Keycloak v26 preserves this internal marker; retaining the
                # account would leave an unverified temporary master admin.
                return httpx.Response(200, json=temporary)
        raise AssertionError((request.method, request.url.path))

    admin = KeycloakAdmin(
        settings(RETAIN_BOOTSTRAP_ADMIN_USER=True),
        FakeVault(),
        FakeDB(),
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(IdentityError, match="did not verify the lab recovery operator"):
        await admin._delete_bootstrap_principals("master-token")
    assert calls == [
        ("GET", "/admin/realms/master/users"),
        ("PUT", "/admin/realms/master/users/temporary-user"),
        ("GET", "/admin/realms/master/users/temporary-user"),
    ]


def test_lab_bind_secret_path_is_confined_to_docker_secrets() -> None:
    with pytest.raises(ValueError, match="/run/secrets"):
        settings(LAB_SAMBA_BIND_PASSWORD_FILE="/tmp/operator-controlled")


def test_assertion_expiration_is_not_derived_from_caller_input() -> None:
    pem, _ = private_key_pem()
    before = int(time.time())
    encoded = KeycloakAdmin._private_key_assertion(
        "controller", "http://keycloak/token", {"private_key_pem": pem}
    )
    claims = jwt.decode(encoded, options={"verify_signature": False})
    assert before <= claims["iat"] <= int(time.time())
    assert claims["exp"] == claims["iat"] + 60


def test_wif_token_requires_explicit_stable_subject_and_audience() -> None:
    valid = jwt.encode(
        {
            "sub": "service-account-anthropic-token-broker",
            "aud": ["https://api.anthropic.com"],
        },
        "test-only-secret-with-at-least-32-bytes",
        algorithm="HS256",
    )
    assert validate_wif_token_claims(
        valid, client_id="anthropic-token-broker"
    )["sub"] == "service-account-anthropic-token-broker"

    unstable = jwt.encode(
        {"sub": "2f7581c5-random-service-user-uuid", "aud": "https://api.anthropic.com"},
        "test-only-secret-with-at-least-32-bytes",
        algorithm="HS256",
    )
    with pytest.raises(ValueError, match="unstable subject"):
        validate_wif_token_claims(
            unstable, client_id="anthropic-token-broker"
        )


@pytest.mark.asyncio
async def test_broker_reconciles_supported_hardcoded_subject_mapper() -> None:
    created = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=[])
        created.update(json.loads(request.content))
        return httpx.Response(201)

    admin = KeycloakAdmin(
        settings(), FakeVault(), FakeDB(), transport=httpx.MockTransport(handler)
    )
    await admin._ensure_broker_subject_mapper(
        {"id": "broker-uuid", "clientId": "anthropic-token-broker"},
        "master-token",
    )

    assert created["protocolMapper"] == "oidc-hardcoded-claim-mapper"
    assert created["config"]["claim.name"] == "sub"
    assert (
        created["config"]["claim.value"]
        == "service-account-anthropic-token-broker"
    )
    assert created["config"]["access.token.claim"] == "true"
