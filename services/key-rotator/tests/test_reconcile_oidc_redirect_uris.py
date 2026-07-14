"""Contracts for the automatic managed-OIDC redirect-URI domain reconciliation.

These prove the narrow repair realigns only the managed callback allow-lists to
the configured domain while the temporary bootstrap client exists, fails closed
toward the re-bootstrap ceremony once that client is consumed, never touches
Vault, and never disturbs unmanaged clients, secrets, mappers, or scopes.
"""

from __future__ import annotations

import copy
import sys

import pytest

from app import reconcile_oidc_redirect_uris
from app.config import Settings
from app.identity import (
    CAPABILITY_ROLES,
    RELYING_PARTY_CLIENT_IDS,
    IdentityError,
    KeycloakAdmin,
)


RP_SECRETS = {
    "WEBUI_OIDC_CLIENT_SECRET": "WebuiOIDCSecret!0123456789-ABCDEFGHI",
    "PORTAL_OIDC_CLIENT_SECRET": "PortalOIDCSecret!0123456789-ABCDEFGH",
    "ADMIN_PORTAL_OIDC_CLIENT_SECRET": "AdminPortalOIDCSecret!0123456789-ABCDE",
    "OAUTH2_PROXY_CLIENT_SECRET": "OAuth2ProxySecret!0123456789-ABCDEFGHI",
}


def settings(**overrides) -> Settings:
    values = {
        "ROTATOR_INTERNAL_TOKEN": "0123456789abcdef0123456789abcdef",
        "PORTAL_IDENTITY_TOKEN": "abcdef0123456789abcdef0123456789",
        "VAULT_TOKEN": "",
        "LITELLM_MASTER_KEY": "litellm-master-key",
        "KC_BOOTSTRAP_ADMIN_CLIENT_SECRET": "Bootstrap-Secret!0123456789-ABCDEFGHIJKLMN",
    }
    values.update(RP_SECRETS)
    values.update(overrides)
    return Settings(**values)


class VaultMustNotBeUsed:
    def __getattr__(self, name):
        raise AssertionError(f"redirect-URI reconciliation touched Vault: {name}")


STALE = "old.internal"
LIVE = "aigw.example.internal"


class FakeRedirectAdmin(KeycloakAdmin):
    """Model the four managed clients plus an unmanaged built-in.

    The managed clients start on the *old* domain to reproduce the migration
    bug.  Each carries an operator-owned attribute and an out-of-band secret
    marker so a test can prove the narrow reconciliation leaves everything but
    the domain-derived callbacks byte-for-byte untouched.
    """

    def __init__(self, *, bootstrap_available: bool = True, stale: bool = True) -> None:
        super().__init__(settings(), VaultMustNotBeUsed(), None)
        self._bootstrap_available = bootstrap_available
        self.clients: dict[str, dict] = {}
        for desired in self._relying_party_specs():
            client_id = desired["clientId"]
            current = copy.deepcopy(desired)
            current["id"] = f"{client_id}-uuid"
            # Keycloak never returns a confidential secret in the client body.
            current.pop("secret", None)
            current["attributes"]["operator.keep"] = "true"
            current["out_of_band_secret"] = f"secret-of-{client_id}"
            current["scopes"] = set(CAPABILITY_ROLES)
            current["protocolMappers"] = [self._realm_roles_mapper()]
            if stale:
                current["redirectUris"] = [
                    uri.replace(LIVE, STALE) for uri in current["redirectUris"]
                ]
                current["webOrigins"] = [
                    origin.replace(LIVE, STALE) for origin in current["webOrigins"]
                ]
                logout = current["attributes"].get("post.logout.redirect.uris")
                if logout is not None:
                    current["attributes"]["post.logout.redirect.uris"] = logout.replace(
                        LIVE, STALE
                    )
            self.clients[client_id] = current
        # A built-in Keycloak client the reconciliation must never open.
        self.clients["account"] = {
            "id": "account-uuid",
            "clientId": "account",
            "redirectUris": ["/realms/aigw/account/*"],
            "webOrigins": [],
        }
        self.account_snapshot = copy.deepcopy(self.clients["account"])
        self.puts: list[str] = []

    async def _bootstrap_token(self) -> str:
        if not self._bootstrap_available:
            raise IdentityError("temporary bootstrap client is unavailable")
        return "bootstrap-token"

    async def _find_client(self, realm, client_id, admin_token):
        client = self.clients.get(client_id)
        return copy.deepcopy(client) if client else None

    async def _get_client(self, realm, client, admin_token):
        return copy.deepcopy(self.clients[client["clientId"]])

    async def _put_client(self, realm, client, admin_token):
        self.clients[client["clientId"]] = copy.deepcopy(client)
        self.puts.append(client["clientId"])


def _desired(admin: FakeRedirectAdmin) -> dict[str, dict]:
    return {spec["clientId"]: spec for spec in admin._relying_party_specs()}


@pytest.mark.asyncio
async def test_reconciliation_migrates_only_managed_callbacks_idempotently() -> None:
    admin = FakeRedirectAdmin(stale=True)
    desired = _desired(admin)

    assert (
        await admin.reconcile_prebootstrap_relying_party_redirect_uris() == "applied"
    )
    for client_id in RELYING_PARTY_CLIENT_IDS:
        client = admin.clients[client_id]
        assert client["redirectUris"] == desired[client_id]["redirectUris"]
        assert client["webOrigins"] == desired[client_id]["webOrigins"]
        # Unmanaged fields must survive the PUT untouched.
        assert client["attributes"]["operator.keep"] == "true"
        assert client["out_of_band_secret"] == f"secret-of-{client_id}"
        assert client["scopes"] == set(CAPABILITY_ROLES)
        logout = desired[client_id]["attributes"].get("post.logout.redirect.uris")
        if logout is not None:
            assert client["attributes"]["post.logout.redirect.uris"] == logout
    # Only dev-portal and admin-portal carry a managed logout allow-list.
    assert "post.logout.redirect.uris" not in admin.clients["open-webui"]["attributes"]
    assert "post.logout.redirect.uris" not in admin.clients["admin-ui"]["attributes"]
    # The unmanaged built-in was never opened.
    assert "account" not in admin.puts
    assert admin.clients["account"] == admin.account_snapshot
    assert sorted(admin.puts) == sorted(RELYING_PARTY_CLIENT_IDS)

    admin.puts.clear()
    assert (
        await admin.reconcile_prebootstrap_relying_party_redirect_uris() == "verified"
    )
    assert admin.puts == []


@pytest.mark.asyncio
async def test_reconciliation_tolerates_keycloak_url_reordering() -> None:
    admin = FakeRedirectAdmin(stale=False)
    assert (
        await admin.reconcile_prebootstrap_relying_party_redirect_uris() == "verified"
    )
    admin.clients["admin-ui"]["redirectUris"].reverse()
    admin.clients["admin-ui"]["webOrigins"].reverse()
    assert (
        await admin.reconcile_prebootstrap_relying_party_redirect_uris() == "verified"
    )
    assert admin.puts == []


@pytest.mark.asyncio
async def test_reconciliation_fails_closed_when_bootstrap_client_consumed() -> None:
    admin = FakeRedirectAdmin(bootstrap_available=False, stale=True)
    before = copy.deepcopy(admin.clients)

    assert (
        await admin.reconcile_prebootstrap_relying_party_redirect_uris()
        == "rebootstrap_required"
    )
    # No privileged mutation on a post-bootstrap host.
    assert admin.puts == []
    assert admin.clients == before


@pytest.mark.asyncio
async def test_reconciliation_fails_closed_when_bootstrap_secret_absent() -> None:
    admin = FakeRedirectAdmin(stale=True)
    # An unset/placeholder bootstrap secret must be detected, not assumed usable.
    admin.settings.keycloak_bootstrap_admin_client_secret = ""
    before = copy.deepcopy(admin.clients)

    assert (
        await admin.reconcile_prebootstrap_relying_party_redirect_uris()
        == "rebootstrap_required"
    )
    assert admin.puts == []
    assert admin.clients == before


@pytest.mark.asyncio
async def test_missing_managed_client_fails_loudly_not_silently() -> None:
    admin = FakeRedirectAdmin(stale=True)
    del admin.clients["admin-ui"]
    with pytest.raises(IdentityError, match="admin-ui is missing"):
        await admin.reconcile_prebootstrap_relying_party_redirect_uris()


def test_post_bootstrap_controller_never_gains_manage_clients() -> None:
    from app.identity import CONTROLLER_ADMIN_ROLES

    assert "manage-clients" not in CONTROLLER_ADMIN_ROLES
    assert "manage-realm" not in CONTROLLER_ADMIN_ROLES
    assert "manage-users" in CONTROLLER_ADMIN_ROLES


def test_runner_maps_each_outcome_to_a_fixed_marker(monkeypatch, capsys) -> None:
    for outcome, marker in reconcile_oidc_redirect_uris._MARKERS.items():

        async def _outcome(value=outcome):
            return value

        monkeypatch.setattr(reconcile_oidc_redirect_uris, "reconcile", _outcome)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "reconcile_oidc_redirect_uris.py",
                "--confirm",
                reconcile_oidc_redirect_uris.CONFIRMATION,
            ],
        )
        assert reconcile_oidc_redirect_uris.main() == 0
        captured = capsys.readouterr()
        assert captured.out == f"{marker}\n"
        assert captured.err == ""


def test_runner_unexpected_failure_has_only_a_fixed_redacted_marker(
    monkeypatch, capsys
) -> None:
    async def unexpected_failure() -> str:
        raise RuntimeError("sensitive topology and bootstrap credential detail")

    monkeypatch.setattr(reconcile_oidc_redirect_uris, "reconcile", unexpected_failure)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "reconcile_oidc_redirect_uris.py",
            "--confirm",
            reconcile_oidc_redirect_uris.CONFIRMATION,
        ],
    )

    assert reconcile_oidc_redirect_uris.main() == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "OIDC_REDIRECT_URI_PREBOOTSTRAP_RECONCILIATION_FAILED\n"
    assert "RuntimeError" not in captured.err
    assert "sensitive topology" not in captured.err


def test_runner_requires_the_exact_confirmation(monkeypatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["reconcile_oidc_redirect_uris.py", "--confirm", "WRONG"],
    )
    with pytest.raises(SystemExit):
        reconcile_oidc_redirect_uris.main()
