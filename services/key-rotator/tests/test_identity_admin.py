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
from app.identity import IdentityConflict, IdentityError, IdentityNotFound, KeycloakAdmin
from app.security import validate_wif_token_claims


AUTH_TOKEN = "0123456789abcdef0123456789abcdef"


def settings(**overrides) -> Settings:
    values = {
        "ROTATOR_INTERNAL_TOKEN": AUTH_TOKEN,
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


@pytest.mark.asyncio
async def test_private_key_jwt_uses_public_audience_over_internal_transport() -> None:
    pem, _ = private_key_pem()
    expected_audience = (
        "https://auth.aigw.internal/realms/aigw/protocol/openid-connect/token"
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
        settings(KEYCLOAK_PUBLIC_URL="https://auth.aigw.internal"),
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

        async def _client_credentials_with_key(self, realm, client_id, key_doc):
            return "controller-token"

        async def _root_group(self, admin_token, *, create):
            return {"id": "managed-root"}

        async def _ensure_lab_ldap(self, admin_token, bind_password):
            return None

        async def _ensure_broker(self, admin_token):
            return {"certificate_sha256": "b" * 64}

        async def _delete_bootstrap_principals(self, admin_token):
            events.append(("keycloak", "bootstrap_deleted"))

        async def status(self):
            return {"configured": True}

    result = await OrderedAdmin(settings(), vault, FakeDB()).bootstrap()
    assert result == {"configured": True}
    state_write = events.index(
        ("vault_write", "ai-gateway/keycloak/identity-state")
    )
    admin_delete = events.index(("keycloak", "bootstrap_deleted"))
    assert state_write < admin_delete


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
    admin = KeycloakAdmin(settings(), FakeVault(), FakeDB())

    async def token():
        return "token"

    async def group(group_id, supplied_token):
        return {"id": group_id}

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
async def test_admin_can_leave_one_group_when_another_admin_membership_remains(
    monkeypatch,
) -> None:
    calls: list[tuple[str, str]] = []
    admin = KeycloakAdmin(settings(), FakeVault(), FakeDB())

    async def token():
        return "token"

    async def group(group_id, supplied_token):
        return {"id": group_id}

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
    admin = KeycloakAdmin(settings(), FakeVault(), FakeDB())
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
        return {"id": group_id}

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
    admin = KeycloakAdmin(settings(), FakeVault(), FakeDB())

    async def controller_token():
        return "controller-token"

    async def managed_group(group_id, supplied_token):
        return {"id": group_id}

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
