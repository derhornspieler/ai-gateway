"""Durable group-gated master-realm administration (break-glass).

These tests drive the real ``_ensure_break_glass_admin`` flow against a
stateful fake of Keycloak's master-realm admin API, proving the fail-closed
credential ordering (create disabled → set password → verified Vault escrow →
enable), marker-gated adoption, idempotency, and the master brute-force
policy reconcile.
"""

from __future__ import annotations

import copy
import json
import re

import httpx
import pytest

from app.config import Settings
from app.identity import (
    BREAK_GLASS_ATTRIBUTE,
    MANAGED_ADMIN_GROUP_ATTRIBUTE,
    MASTER_ADMIN_ROLE,
    MASTER_BRUTE_FORCE_POLICY,
    IdentityConflict,
    IdentityError,
    KeycloakAdmin,
)

AUTH_TOKEN = "0123456789abcdef0123456789abcdef"
BG_VAULT_PATH = "ai-gateway/keycloak/break-glass-admin"


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
    def __init__(self, docs=None, events=None, refuse_paths=()) -> None:
        self.docs = copy.deepcopy(docs or {})
        self.events = events if events is not None else []
        self.refuse_paths = set(refuse_paths)

    def read(self, path):
        value = self.docs.get(path)
        return copy.deepcopy(value) if value is not None else None

    def write_verified(self, path, data, attempts=3):
        self.events.append(("vault_write", path))
        if path in self.refuse_paths:
            return False
        self.docs[path] = copy.deepcopy(data)
        return True


class FakeDB:
    async def record_history(self, *args):
        pass


class FakeMasterRealm:
    """Stateful fake of the master-realm admin API surface the ensure uses."""

    def __init__(self, *, events=None, ignore_realm_put: bool = False) -> None:
        self.events = events if events is not None else []
        self.groups: dict[str, dict] = {}
        self.group_roles: dict[str, list[dict]] = {}
        self.users: dict[str, dict] = {}
        self.user_groups: dict[str, set[str]] = {}
        self.passwords: dict[str, str] = {}
        self.realm: dict = {"realm": "master", "bruteForceProtected": False}
        self.ignore_realm_put = ignore_realm_put
        self.calls: list[tuple[str, str]] = []

    def seed_group(self, name: str, *, marked: bool, admin_role: bool) -> str:
        group_id = f"group-{name}"
        attributes = {MANAGED_ADMIN_GROUP_ATTRIBUTE: ["true"]} if marked else {}
        self.groups[name] = {
            "id": group_id,
            "name": name,
            "path": "/" + name,
            "attributes": attributes,
        }
        self.group_roles[group_id] = (
            [{"id": "master-admin-role", "name": MASTER_ADMIN_ROLE}]
            if admin_role
            else []
        )
        return group_id

    def seed_user(self, username: str, *, marked: bool, enabled: bool) -> str:
        user_id = f"user-{username}"
        attributes = {BREAK_GLASS_ATTRIBUTE: ["true"]} if marked else {}
        self.users[username] = {
            "id": user_id,
            "username": username,
            "enabled": enabled,
            "attributes": attributes,
        }
        self.user_groups.setdefault(user_id, set())
        return user_id

    def user_by_id(self, user_id: str) -> dict:
        for user in self.users.values():
            if user["id"] == user_id:
                return user
        raise AssertionError(f"unknown user id {user_id}")

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.calls.append((request.method, path))
        assert path.startswith("/admin/realms/master")
        sub = path.removeprefix("/admin/realms/master")

        if sub == "":
            if request.method == "GET":
                return httpx.Response(200, json=copy.deepcopy(self.realm))
            assert request.method == "PUT"
            if not self.ignore_realm_put:
                self.realm = json.loads(request.content)
            self.events.append(("keycloak", "realm_updated"))
            return httpx.Response(204)

        if sub == "/groups":
            if request.method == "GET":
                wanted = request.url.params.get("search")
                found = [
                    copy.deepcopy(group)
                    for name, group in self.groups.items()
                    if name == wanted
                ]
                return httpx.Response(200, json=found)
            assert request.method == "POST"
            body = json.loads(request.content)
            group_id = f"group-{body['name']}"
            self.groups[body["name"]] = {
                "id": group_id,
                "name": body["name"],
                "path": "/" + body["name"],
                "attributes": body.get("attributes") or {},
            }
            self.group_roles.setdefault(group_id, [])
            self.events.append(("keycloak", "group_created"))
            return httpx.Response(201)

        if sub == f"/roles/{MASTER_ADMIN_ROLE}":
            return httpx.Response(
                200, json={"id": "master-admin-role", "name": MASTER_ADMIN_ROLE}
            )

        mapping = re.fullmatch(r"/groups/([^/]+)/role-mappings/realm", sub)
        if mapping:
            group_id = mapping.group(1)
            if request.method == "GET":
                return httpx.Response(
                    200, json=copy.deepcopy(self.group_roles.get(group_id, []))
                )
            assert request.method == "POST"
            self.group_roles.setdefault(group_id, []).extend(
                json.loads(request.content)
            )
            self.events.append(("keycloak", "group_role_mapped"))
            return httpx.Response(204)

        if sub == "/users":
            if request.method == "GET":
                wanted = request.url.params.get("username")
                found = [
                    copy.deepcopy(user)
                    for username, user in self.users.items()
                    if username == wanted
                ]
                return httpx.Response(200, json=found)
            assert request.method == "POST"
            body = json.loads(request.content)
            assert body.get("enabled") is False, (
                "break-glass users must be created disabled"
            )
            user_id = f"user-{body['username']}"
            self.users[body["username"]] = {
                "id": user_id,
                "username": body["username"],
                "enabled": False,
                "attributes": body.get("attributes") or {},
            }
            self.user_groups.setdefault(user_id, set())
            self.events.append(("keycloak", "user_created_disabled"))
            return httpx.Response(201)

        reset = re.fullmatch(r"/users/([^/]+)/reset-password", sub)
        if reset:
            assert request.method == "PUT"
            body = json.loads(request.content)
            assert body["type"] == "password"
            assert body["temporary"] is False
            self.passwords[reset.group(1)] = body["value"]
            self.events.append(("keycloak", "password_set"))
            return httpx.Response(204)

        membership = re.fullmatch(r"/users/([^/]+)/groups/([^/]+)", sub)
        if membership:
            assert request.method == "PUT"
            self.user_groups.setdefault(membership.group(1), set()).add(
                membership.group(2)
            )
            return httpx.Response(204)

        member_list = re.fullmatch(r"/users/([^/]+)/groups", sub)
        if member_list:
            assert request.method == "GET"
            return httpx.Response(
                200,
                json=[
                    {"id": group_id}
                    for group_id in sorted(self.user_groups.get(member_list.group(1), set()))
                ],
            )

        user_update = re.fullmatch(r"/users/([^/]+)", sub)
        if user_update:
            assert request.method == "PUT"
            body = json.loads(request.content)
            user = self.user_by_id(user_update.group(1))
            user["enabled"] = body.get("enabled")
            self.events.append(
                (
                    "keycloak",
                    "user_enabled" if body.get("enabled") else "user_disabled",
                )
            )
            return httpx.Response(204)

        raise AssertionError((request.method, path))


def admin_with(
    master: FakeMasterRealm, vault: FakeVault, **setting_overrides
) -> KeycloakAdmin:
    return KeycloakAdmin(
        settings(**setting_overrides),
        vault,
        FakeDB(),
        transport=httpx.MockTransport(master),
    )


@pytest.mark.asyncio
async def test_fresh_provision_creates_disabled_escrows_then_enables() -> None:
    events: list[tuple[str, str]] = []
    master = FakeMasterRealm(events=events)
    vault = FakeVault(events=events)

    result = await admin_with(master, vault)._ensure_break_glass_admin(
        "master-token"
    )

    assert result == {
        "username": "break-glass-admin",
        "group": "keycloak-admins",
        "escrowed_at": vault.docs[BG_VAULT_PATH]["created_at"],
    }
    user = master.users["break-glass-admin"]
    assert user["enabled"] is True
    assert user["attributes"] == {BREAK_GLASS_ATTRIBUTE: ["true"]}
    group = master.groups["keycloak-admins"]
    assert group["attributes"] == {MANAGED_ADMIN_GROUP_ATTRIBUTE: ["true"]}
    assert {role["name"] for role in master.group_roles[group["id"]]} == {
        MASTER_ADMIN_ROLE
    }
    assert group["id"] in master.user_groups[user["id"]]

    escrow = vault.docs[BG_VAULT_PATH]
    assert escrow["schema_version"] == 1
    assert escrow["username"] == "break-glass-admin"
    assert len(escrow["password"]) >= 32
    assert master.passwords[user["id"]] == escrow["password"]

    for key, value in MASTER_BRUTE_FORCE_POLICY.items():
        assert master.realm.get(key) == value, key

    created = events.index(("keycloak", "user_created_disabled"))
    password_set = events.index(("keycloak", "password_set"))
    escrow_write = events.index(("vault_write", BG_VAULT_PATH))
    enabled = events.index(("keycloak", "user_enabled"))
    assert created < password_set < escrow_write < enabled
    assert ("keycloak", "user_disabled") not in events


@pytest.mark.asyncio
async def test_vault_escrow_failure_disables_the_user_and_fails() -> None:
    events: list[tuple[str, str]] = []
    master = FakeMasterRealm(events=events)
    vault = FakeVault(events=events, refuse_paths={BG_VAULT_PATH})

    with pytest.raises(IdentityError, match="did not verify the break-glass escrow"):
        await admin_with(master, vault)._ensure_break_glass_admin("master-token")

    assert master.users["break-glass-admin"]["enabled"] is False
    assert ("keycloak", "user_enabled") not in events
    assert BG_VAULT_PATH not in vault.docs


@pytest.mark.asyncio
async def test_idempotent_rerun_reuses_the_escrowed_credential() -> None:
    events: list[tuple[str, str]] = []
    master = FakeMasterRealm(events=events)
    group_id = master.seed_group("keycloak-admins", marked=True, admin_role=True)
    user_id = master.seed_user("break-glass-admin", marked=True, enabled=True)
    master.user_groups[user_id].add(group_id)
    master.realm.update(MASTER_BRUTE_FORCE_POLICY)
    escrow = {
        "schema_version": 1,
        "username": "break-glass-admin",
        "password": "escrowed-password-0123456789-ABCDEFGH",
        "created_at": "2026-01-01T00:00:00+00:00",
    }
    vault = FakeVault({BG_VAULT_PATH: escrow}, events=events)

    result = await admin_with(master, vault)._ensure_break_glass_admin(
        "master-token"
    )

    assert result["escrowed_at"] == "2026-01-01T00:00:00+00:00"
    assert ("keycloak", "password_set") not in events
    assert ("vault_write", BG_VAULT_PATH) not in events
    assert ("keycloak", "user_disabled") not in events
    assert ("keycloak", "user_enabled") not in events
    assert ("keycloak", "group_created") not in events
    assert ("keycloak", "user_created_disabled") not in events
    assert ("keycloak", "realm_updated") not in events


@pytest.mark.asyncio
async def test_unmarked_master_objects_are_never_adopted_or_mutated() -> None:
    unmarked_group = FakeMasterRealm()
    unmarked_group.seed_group("keycloak-admins", marked=False, admin_role=False)
    with pytest.raises(IdentityConflict, match="unmarked master-realm administrators"):
        await admin_with(unmarked_group, FakeVault())._ensure_break_glass_admin(
            "master-token"
        )

    unmarked_user = FakeMasterRealm()
    unmarked_user.seed_group("keycloak-admins", marked=True, admin_role=True)
    unmarked_user.realm.update(MASTER_BRUTE_FORCE_POLICY)
    unmarked_user.seed_user("break-glass-admin", marked=False, enabled=True)
    with pytest.raises(IdentityConflict, match="unmarked master-realm user"):
        await admin_with(unmarked_user, FakeVault())._ensure_break_glass_admin(
            "master-token"
        )
    # The refusal must not have touched the pre-existing operator object.
    assert unmarked_user.users["break-glass-admin"]["enabled"] is True
    assert unmarked_user.passwords == {}


def test_break_glass_username_collision_is_refused_at_configuration() -> None:
    with pytest.raises(ValueError, match="must differ"):
        settings(BREAK_GLASS_ADMIN_USERNAME="admin")
    with pytest.raises(ValueError, match="must differ"):
        settings(
            BREAK_GLASS_ADMIN_USERNAME="operator",
            KC_BOOTSTRAP_ADMIN_USERNAME="operator",
        )


def test_admin_realm_ldap_overlay_is_a_loud_stub() -> None:
    with pytest.raises(ValueError, match="not implemented"):
        settings(ADMIN_REALM_LDAP_ENABLED=True)


@pytest.mark.asyncio
async def test_master_brute_force_policy_drift_after_put_fails_closed() -> None:
    master = FakeMasterRealm(ignore_realm_put=True)
    with pytest.raises(IdentityError, match="master brute-force policy"):
        await admin_with(master, FakeVault())._ensure_break_glass_admin(
            "master-token"
        )
    # Fail-closed: no user may exist yet when the policy cannot be proven.
    assert "break-glass-admin" not in master.users


@pytest.mark.asyncio
async def test_disabled_feature_makes_no_master_realm_calls() -> None:
    def forbidden(request: httpx.Request) -> httpx.Response:
        raise AssertionError("disabled break-glass must not contact Keycloak")

    admin = KeycloakAdmin(
        settings(BREAK_GLASS_ADMIN_ENABLED=False),
        FakeVault(),
        FakeDB(),
        transport=httpx.MockTransport(forbidden),
    )
    assert await admin._ensure_break_glass_admin("master-token") is None


@pytest.mark.asyncio
async def test_status_reports_break_glass_escrow_without_leaking_it(
    monkeypatch,
) -> None:
    cfg = settings(KC_BOOTSTRAP_ADMIN_CLIENT_SECRET="")
    escrow = {
        "schema_version": 1,
        "username": "break-glass-admin",
        "password": "escrowed-password-0123456789-ABCDEFGH",
    }
    vault = FakeVault(
        {
            cfg.identity_state_vault_path: {"managed_root_group_id": "root-id"},
            BG_VAULT_PATH: escrow,
        }
    )
    admin = KeycloakAdmin(cfg, vault, FakeDB())

    async def controller_token():
        return "token"

    monkeypatch.setattr(admin, "_controller_token", controller_token)
    result = await admin.status()
    assert result["break_glass_escrowed"] is True
    assert escrow["password"] not in json.dumps(result)

    missing = KeycloakAdmin(
        cfg,
        FakeVault({cfg.identity_state_vault_path: {"managed_root_group_id": "r"}}),
        FakeDB(),
    )
    monkeypatch.setattr(missing, "_controller_token", controller_token)
    assert (await missing.status())["break_glass_escrowed"] is False
