"""Durable group-gated master-realm administration (break-glass).

These tests drive the real ``_ensure_break_glass_admin`` flow against a
stateful fake of Keycloak's master-realm admin API. The fake models the
Keycloak 24+ declarative user profile: a custom user attribute that is not
declared in the realm's user profile is SILENTLY DROPPED on admin create and
update — exactly the behavior that would brick a marker-based ownership
check. It also models the credential store faithfully, so an escrow document
with no corresponding installed password is detectable.

Proven invariants: brute-force policy before any authority-restoring
mutation; profile marker declared (and verified) before any user exists;
membership granted only after the account is disabled-or-escrowed; create
disabled → set password → verified Vault escrow → enable; stale escrow
(recreated or credential-less account) forces rotation; unmarked objects are
never adopted or mutated; a disabled feature can never consume the bootstrap.
"""

from __future__ import annotations

import copy
import json
import re
import urllib.parse

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
    def __init__(self, docs=None, events=None, refuse_paths=(), deny_reads=()) -> None:
        self.docs = copy.deepcopy(docs or {})
        self.events = events if events is not None else []
        self.refuse_paths = set(refuse_paths)
        self.deny_reads = set(deny_reads)

    def read(self, path):
        if path in self.deny_reads:
            raise RuntimeError("permission denied")
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
    """Stateful fake of the master-realm admin API surface the ensure uses.

    Faithfulness notes: user attributes not declared in the realm user
    profile are dropped on POST/PUT (Keycloak 24+ default unmanaged-attribute
    policy); the credential store only holds passwords that reset-password
    actually installed; the admin composite is served from ``composites``.
    """

    def __init__(
        self,
        *,
        events=None,
        ignore_realm_put: bool = False,
        ignore_profile_put: bool = False,
        stripped_composite: bool = False,
    ) -> None:
        self.events = events if events is not None else []
        self.groups: dict[str, dict] = {}
        self.group_roles: dict[str, list[dict]] = {}
        self.users: dict[str, dict] = {}
        self.user_groups: dict[str, set[str]] = {}
        self.passwords: dict[str, str] = {}
        self.realm: dict = {"realm": "master", "bruteForceProtected": False}
        self.profile: dict = {
            "attributes": [{"name": "username"}, {"name": "email"}]
        }
        self.composites: list[dict] = (
            []
            if stripped_composite
            else [
                {"name": "create-realm", "clientRole": False},
                {"name": "manage-users", "clientRole": True},
            ]
        )
        self.ignore_realm_put = ignore_realm_put
        self.ignore_profile_put = ignore_profile_put
        self.calls: list[tuple[str, str]] = []

    def declare_break_glass_attribute(self) -> None:
        self.profile["attributes"].append({"name": BREAK_GLASS_ATTRIBUTE})

    def _declared_names(self) -> set[str]:
        return {
            entry.get("name")
            for entry in self.profile.get("attributes", [])
            if isinstance(entry, dict)
        }

    def _filter_attributes(self, attributes: dict | None) -> dict:
        declared = self._declared_names()
        return {
            name: value
            for name, value in (attributes or {}).items()
            if name in declared
        }

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

    def seed_user(
        self,
        username: str,
        *,
        marked: bool,
        enabled: bool,
        password: str | None = None,
    ) -> str:
        user_id = f"user-{username}"
        attributes = {BREAK_GLASS_ATTRIBUTE: ["true"]} if marked else {}
        self.users[username] = {
            "id": user_id,
            "username": username,
            "enabled": enabled,
            "attributes": attributes,
        }
        self.user_groups.setdefault(user_id, set())
        if password is not None:
            self.passwords[user_id] = password
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

        if sub == "/users/profile":
            if request.method == "GET":
                return httpx.Response(200, json=copy.deepcopy(self.profile))
            assert request.method == "PUT"
            if not self.ignore_profile_put:
                self.profile = json.loads(request.content)
            self.events.append(("keycloak", "profile_updated"))
            return httpx.Response(200, json=copy.deepcopy(self.profile))

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

        if sub == f"/roles/{MASTER_ADMIN_ROLE}/composites":
            return httpx.Response(200, json=copy.deepcopy(self.composites))

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
                # Keycloak drops undeclared attributes on admin create.
                "attributes": self._filter_attributes(body.get("attributes")),
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

        credentials = re.fullmatch(r"/users/([^/]+)/credentials", sub)
        if credentials:
            assert request.method == "GET"
            user_id = credentials.group(1)
            listed = (
                [{"id": "cred-1", "type": "password"}]
                if user_id in self.passwords
                else []
            )
            return httpx.Response(200, json=listed)

        membership = re.fullmatch(r"/users/([^/]+)/groups/([^/]+)", sub)
        if membership:
            assert request.method == "PUT"
            self.user_groups.setdefault(membership.group(1), set()).add(
                membership.group(2)
            )
            self.events.append(("keycloak", "membership_put"))
            return httpx.Response(204)

        member_list = re.fullmatch(r"/users/([^/]+)/groups", sub)
        if member_list:
            assert request.method == "GET"
            return httpx.Response(
                200,
                json=[
                    {"id": group_id}
                    for group_id in sorted(
                        self.user_groups.get(member_list.group(1), set())
                    )
                ],
            )

        user_update = re.fullmatch(r"/users/([^/]+)", sub)
        if user_update:
            assert request.method == "PUT"
            body = json.loads(request.content)
            user = self.user_by_id(user_update.group(1))
            user["enabled"] = body.get("enabled")
            if "attributes" in body:
                # Undeclared attributes are dropped on update too.
                user["attributes"] = self._filter_attributes(body["attributes"])
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


def seeded_converged_master(events: list) -> tuple[FakeMasterRealm, str, str]:
    """A master realm exactly as a prior successful run leaves it."""
    master = FakeMasterRealm(events=events)
    master.declare_break_glass_attribute()
    master.realm.update(MASTER_BRUTE_FORCE_POLICY)
    group_id = master.seed_group("keycloak-admins", marked=True, admin_role=True)
    user_id = master.seed_user(
        "break-glass-admin",
        marked=True,
        enabled=True,
        password="escrowed-password-0123456789-ABCDEFGH",
    )
    master.user_groups[user_id].add(group_id)
    return master, group_id, user_id


VALID_ESCROW = {
    "schema_version": 1,
    "username": "break-glass-admin",
    "password": "escrowed-password-0123456789-ABCDEFGH",
    "created_at": "2026-01-01T00:00:00+00:00",
}


@pytest.mark.asyncio
async def test_fresh_provision_orders_policy_profile_credential_and_enable() -> None:
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
    # The marker persisted only because the profile declared it first.
    assert user["attributes"] == {BREAK_GLASS_ATTRIBUTE: ["true"]}
    group = master.groups["keycloak-admins"]
    assert group["attributes"] == {MANAGED_ADMIN_GROUP_ATTRIBUTE: ["true"]}
    assert {role["name"] for role in master.group_roles[group["id"]]} == {
        MASTER_ADMIN_ROLE
    }
    assert group["id"] in master.user_groups[user["id"]]

    escrow = vault.docs[BG_VAULT_PATH]
    assert escrow["schema_version"] == 1
    assert len(escrow["password"]) >= 32
    assert master.passwords[user["id"]] == escrow["password"]

    for key, value in MASTER_BRUTE_FORCE_POLICY.items():
        assert master.realm.get(key) == value, key

    order = [
        events.index(("keycloak", "realm_updated")),
        events.index(("keycloak", "profile_updated")),
        events.index(("keycloak", "group_created")),
        events.index(("keycloak", "user_created_disabled")),
        events.index(("keycloak", "membership_put")),
        events.index(("keycloak", "password_set")),
        events.index(("vault_write", BG_VAULT_PATH)),
        events.index(("keycloak", "user_enabled")),
    ]
    assert order == sorted(order), events
    assert ("keycloak", "user_disabled") not in events


@pytest.mark.asyncio
async def test_undeclared_profile_marker_fails_loudly_not_silently() -> None:
    """If Keycloak drops the profile declaration, bootstrap must brick loudly
    BEFORE any user exists — never create-then-refuse on its own marker."""
    master = FakeMasterRealm(ignore_profile_put=True)
    with pytest.raises(IdentityError, match="master user profile marker"):
        await admin_with(master, FakeVault())._ensure_break_glass_admin(
            "master-token"
        )
    assert master.users == {}
    assert master.groups == {}


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
    master, _, _ = seeded_converged_master(events)
    vault = FakeVault({BG_VAULT_PATH: VALID_ESCROW}, events=events)

    result = await admin_with(master, vault)._ensure_break_glass_admin(
        "master-token"
    )

    assert result["escrowed_at"] == "2026-01-01T00:00:00+00:00"
    for forbidden in (
        ("keycloak", "password_set"),
        ("vault_write", BG_VAULT_PATH),
        ("keycloak", "user_disabled"),
        ("keycloak", "user_enabled"),
        ("keycloak", "group_created"),
        ("keycloak", "user_created_disabled"),
        ("keycloak", "realm_updated"),
        ("keycloak", "profile_updated"),
    ):
        assert forbidden not in events, forbidden


@pytest.mark.asyncio
async def test_recreated_user_with_stale_escrow_forces_rotation() -> None:
    """A shape-valid escrow must never vouch for a user created this run."""
    events: list[tuple[str, str]] = []
    master = FakeMasterRealm(events=events)
    vault = FakeVault({BG_VAULT_PATH: VALID_ESCROW}, events=events)

    await admin_with(master, vault)._ensure_break_glass_admin("master-token")

    user = master.users["break-glass-admin"]
    assert user["enabled"] is True
    assert ("keycloak", "password_set") in events
    assert ("vault_write", BG_VAULT_PATH) in events
    fresh = vault.docs[BG_VAULT_PATH]["password"]
    assert fresh != VALID_ESCROW["password"]
    assert master.passwords[user["id"]] == fresh


@pytest.mark.asyncio
async def test_credential_less_restored_user_forces_rotation() -> None:
    """Escrow + existing user but NO installed password: rotate, don't adopt."""
    events: list[tuple[str, str]] = []
    master = FakeMasterRealm(events=events)
    master.declare_break_glass_attribute()
    master.realm.update(MASTER_BRUTE_FORCE_POLICY)
    master.seed_group("keycloak-admins", marked=True, admin_role=True)
    master.seed_user(
        "break-glass-admin", marked=True, enabled=True, password=None
    )
    vault = FakeVault({BG_VAULT_PATH: VALID_ESCROW}, events=events)

    await admin_with(master, vault)._ensure_break_glass_admin("master-token")

    user = master.users["break-glass-admin"]
    assert user["enabled"] is True
    fresh = vault.docs[BG_VAULT_PATH]["password"]
    assert fresh != VALID_ESCROW["password"]
    assert master.passwords[user["id"]] == fresh
    # The pre-existing enabled account was disabled BEFORE it received the
    # authority-granting group membership.
    disabled = events.index(("keycloak", "user_disabled"))
    membership = events.index(("keycloak", "membership_put"))
    password_set = events.index(("keycloak", "password_set"))
    escrow_write = events.index(("vault_write", BG_VAULT_PATH))
    enabled = events.index(("keycloak", "user_enabled"))
    assert disabled < membership < password_set < escrow_write < enabled


@pytest.mark.asyncio
async def test_enabled_unescrowed_user_is_disabled_before_membership() -> None:
    events: list[tuple[str, str]] = []
    master = FakeMasterRealm(events=events)
    master.declare_break_glass_attribute()
    master.realm.update(MASTER_BRUTE_FORCE_POLICY)
    master.seed_group("keycloak-admins", marked=True, admin_role=True)
    master.seed_user(
        "break-glass-admin",
        marked=True,
        enabled=True,
        password="operator-set-password-0123456789",
    )
    vault = FakeVault(events=events)  # no escrow at all

    await admin_with(master, vault)._ensure_break_glass_admin("master-token")

    disabled = events.index(("keycloak", "user_disabled"))
    membership = events.index(("keycloak", "membership_put"))
    assert disabled < membership
    assert master.users["break-glass-admin"]["enabled"] is True
    assert BG_VAULT_PATH in vault.docs


@pytest.mark.asyncio
async def test_unmarked_master_objects_are_never_adopted_or_mutated() -> None:
    unmarked_group = FakeMasterRealm()
    unmarked_group.seed_group("keycloak-admins", marked=False, admin_role=False)
    with pytest.raises(IdentityConflict, match="unmarked master-realm administrators"):
        await admin_with(unmarked_group, FakeVault())._ensure_break_glass_admin(
            "master-token"
        )

    unmarked_user = FakeMasterRealm()
    unmarked_user.declare_break_glass_attribute()
    unmarked_user.seed_group("keycloak-admins", marked=True, admin_role=True)
    unmarked_user.realm.update(MASTER_BRUTE_FORCE_POLICY)
    unmarked_user.seed_user(
        "break-glass-admin",
        marked=False,
        enabled=True,
        password="operator-password-0123456789abcd",
    )
    with pytest.raises(IdentityConflict, match="unmarked master-realm user"):
        await admin_with(unmarked_user, FakeVault())._ensure_break_glass_admin(
            "master-token"
        )
    # The refusal must not have touched the pre-existing operator object.
    assert unmarked_user.users["break-glass-admin"]["enabled"] is True
    assert (
        unmarked_user.passwords["user-break-glass-admin"]
        == "operator-password-0123456789abcd"
    )


@pytest.mark.asyncio
async def test_stripped_admin_composite_fails_closed() -> None:
    master = FakeMasterRealm(stripped_composite=True)
    with pytest.raises(IdentityError, match="stripped"):
        await admin_with(master, FakeVault())._ensure_break_glass_admin(
            "master-token"
        )
    assert master.users == {}


def test_break_glass_username_collision_is_refused_at_configuration() -> None:
    with pytest.raises(ValueError, match="must differ"):
        settings(BREAK_GLASS_ADMIN_USERNAME="admin")
    with pytest.raises(ValueError, match="must differ"):
        settings(
            BREAK_GLASS_ADMIN_USERNAME="operator",
            KC_BOOTSTRAP_ADMIN_USERNAME="operator",
        )


def test_identity_vault_paths_must_be_distinct_and_never_deletable() -> None:
    with pytest.raises(ValueError, match="pairwise distinct"):
        settings(
            BREAK_GLASS_ADMIN_VAULT_PATH="ai-gateway/keycloak/identity-state"
        )
    with pytest.raises(ValueError, match="pairwise distinct"):
        settings(
            IDENTITY_CONTROLLER_KEY_VAULT_PATH=(
                "ai-gateway/keycloak/identity-state"
            )
        )
    with pytest.raises(ValueError, match="deletable reserved"):
        settings(BREAK_GLASS_ADMIN_VAULT_PATH="ai-gateway/anthropic-wif")
    with pytest.raises(ValueError, match="deletable reserved"):
        settings(BREAK_GLASS_ADMIN_VAULT_PATH="ai-gateway/anthropic-wif/escrow")


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
    # Policy is proven FIRST: nothing that restores authority may exist yet.
    assert master.users == {}
    assert master.groups == {}


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
async def test_disabled_feature_can_never_consume_the_bootstrap() -> None:
    """The flag may park bootstrap; it must never yield an admin-less box."""
    events: list[tuple[str, str]] = []
    vault = FakeVault(events=events)

    class StubbedAdmin(KeycloakAdmin):
        async def _bootstrap_token(self):
            return "master-token"

        async def _ensure_relying_parties(self, admin_token):
            return None

        async def _ensure_controller(self, admin_token):
            return {"certificate_sha256": "a" * 64}

        async def _client_credentials_with_key(self, realm, client_id, key_doc):
            return "controller-token"

        async def _root_group(self, admin_token, *, create):
            return {"id": "managed-root"}

        async def _ensure_ldap_federation(self, admin_token, bind_password):
            return None

        async def _ensure_broker(self, admin_token):
            return {"certificate_sha256": "b" * 64}

        async def _delete_bootstrap_principals(self, admin_token):
            events.append(("keycloak", "bootstrap_deleted"))

    admin = StubbedAdmin(
        settings(BREAK_GLASS_ADMIN_ENABLED=False), vault, FakeDB()
    )
    with pytest.raises(IdentityConflict, match="BREAK_GLASS_ADMIN_ENABLED"):
        await admin.bootstrap()
    assert ("keycloak", "bootstrap_deleted") not in events
    assert (
        "vault_write",
        "ai-gateway/keycloak/identity-state",
    ) not in events


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
    assert result["break_glass_escrow_readable"] is True
    assert escrow["password"] not in json.dumps(result)

    missing = KeycloakAdmin(
        cfg,
        FakeVault({cfg.identity_state_vault_path: {"managed_root_group_id": "r"}}),
        FakeDB(),
    )
    monkeypatch.setattr(missing, "_controller_token", controller_token)
    missing_result = await missing.status()
    assert missing_result["break_glass_escrowed"] is False
    assert missing_result["break_glass_escrow_readable"] is True


@pytest.mark.asyncio
async def test_status_degrades_when_the_escrow_path_is_unreadable(
    monkeypatch,
) -> None:
    """A pre-feature rotator Vault policy (brownfield host) denies the escrow
    read; status must stay serviceable instead of failing the endpoint."""
    cfg = settings(KC_BOOTSTRAP_ADMIN_CLIENT_SECRET="")
    vault = FakeVault(
        {cfg.identity_state_vault_path: {"managed_root_group_id": "root-id"}},
        deny_reads={BG_VAULT_PATH},
    )
    admin = KeycloakAdmin(cfg, vault, FakeDB())

    async def controller_token():
        return "token"

    monkeypatch.setattr(admin, "_controller_token", controller_token)
    result = await admin.status()
    assert result["break_glass_escrowed"] is False
    assert result["break_glass_escrow_readable"] is False


@pytest.mark.asyncio
async def test_deployment_repair_can_use_the_escrowed_break_glass_admin() -> None:
    password = "escrowed-password-0123456789-ABCDEFGH"
    vault = FakeVault(
        {
            BG_VAULT_PATH: {
                "schema_version": 1,
                "username": "break-glass-admin",
                "password": password,
            }
        }
    )

    def token_endpoint(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/realms/master/protocol/openid-connect/token"
        form = urllib.parse.parse_qs(request.content.decode("utf-8"))
        assert form == {
            "grant_type": ["password"],
            "client_id": ["admin-cli"],
            "username": ["break-glass-admin"],
            "password": [password],
        }
        return httpx.Response(200, json={"access_token": "repair-token"})

    admin = KeycloakAdmin(
        settings(KC_BOOTSTRAP_ADMIN_CLIENT_SECRET=""),
        vault,
        FakeDB(),
        transport=httpx.MockTransport(token_endpoint),
    )

    assert await admin._break_glass_admin_token() == "repair-token"
