"""Escrow of the `vault` relying-party client secret for the OIDC ceremony.

Vault's own OIDC login (scripts/vault-oidc-setup.sh, a root-token ceremony)
cannot read Compose environment, so the rotator escrows the reconciled client
secret in Vault with the same schema-versioned verified-write custody model
as the break-glass administrator credential. These tests prove the escrow is
fail-closed, idempotent, never weaker than the relying-party secret policy,
and honestly reported by /identity/status without ever leaking the secret.
"""

from __future__ import annotations

import copy
import json

import pytest

from app.config import Settings
from app.identity import (
    VAULT_OIDC_RP_SCHEMA,
    VAULT_RP_CLIENT_ID,
    IdentityConflict,
    IdentityError,
    KeycloakAdmin,
)

AUTH_TOKEN = "0123456789abcdef0123456789abcdef"
VAULT_RP_PATH = "ai-gateway/keycloak/vault-oidc-rp"
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
        **RP_SECRETS,
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


def valid_escrow() -> dict:
    return {
        "schema_version": VAULT_OIDC_RP_SCHEMA,
        "client_id": VAULT_RP_CLIENT_ID,
        "client_secret": RP_SECRETS["VAULT_OIDC_CLIENT_SECRET"],
        "realm": "aigw",
        "created_at": "2026-01-01T00:00:00+00:00",
    }


def test_escrow_writes_a_schema_versioned_document() -> None:
    events: list[tuple[str, str]] = []
    vault = FakeVault(events=events)
    admin = KeycloakAdmin(settings(), vault, FakeDB())

    escrowed_at = admin._escrow_vault_oidc_rp_secret()

    assert events == [("vault_write", VAULT_RP_PATH)]
    doc = vault.docs[VAULT_RP_PATH]
    assert doc["schema_version"] == VAULT_OIDC_RP_SCHEMA
    assert doc["client_id"] == VAULT_RP_CLIENT_ID
    assert doc["client_secret"] == RP_SECRETS["VAULT_OIDC_CLIENT_SECRET"]
    assert doc["realm"] == "aigw"
    assert escrowed_at == doc["created_at"]


def test_matching_escrow_is_left_untouched_to_avoid_version_churn() -> None:
    events: list[tuple[str, str]] = []
    vault = FakeVault({VAULT_RP_PATH: valid_escrow()}, events=events)
    admin = KeycloakAdmin(settings(), vault, FakeDB())

    escrowed_at = admin._escrow_vault_oidc_rp_secret()

    assert events == []
    assert escrowed_at == "2026-01-01T00:00:00+00:00"


def test_changed_secret_supersedes_the_stale_escrow() -> None:
    stale = valid_escrow()
    stale["client_secret"] = "SupersededVaultOIDCSecret!0123456789-AB"
    vault = FakeVault({VAULT_RP_PATH: stale})
    admin = KeycloakAdmin(settings(), vault, FakeDB())

    admin._escrow_vault_oidc_rp_secret()

    assert vault.docs[VAULT_RP_PATH]["client_secret"] == (
        RP_SECRETS["VAULT_OIDC_CLIENT_SECRET"]
    )


def test_unverified_escrow_write_fails_closed() -> None:
    vault = FakeVault(refuse_paths={VAULT_RP_PATH})
    admin = KeycloakAdmin(settings(), vault, FakeDB())

    with pytest.raises(IdentityError, match="did not verify the vault OIDC"):
        admin._escrow_vault_oidc_rp_secret()
    assert VAULT_RP_PATH not in vault.docs


def test_weak_or_missing_secret_is_never_escrowed() -> None:
    admin = KeycloakAdmin(
        settings(VAULT_OIDC_CLIENT_SECRET=""), FakeVault(), FakeDB()
    )
    with pytest.raises(IdentityConflict, match="missing or weak vault OIDC"):
        admin._escrow_vault_oidc_rp_secret()

    reused = KeycloakAdmin(
        settings(
            VAULT_OIDC_CLIENT_SECRET=RP_SECRETS["OAUTH2_PROXY_CLIENT_SECRET"]
        ),
        FakeVault(),
        FakeDB(),
    )
    with pytest.raises(IdentityConflict, match="missing or weak vault OIDC"):
        reused._escrow_vault_oidc_rp_secret()


@pytest.mark.asyncio
async def test_status_reports_the_escrow_without_leaking_it(monkeypatch) -> None:
    cfg = settings(KC_BOOTSTRAP_ADMIN_CLIENT_SECRET="")
    escrow = valid_escrow()
    vault = FakeVault(
        {
            cfg.identity_state_vault_path: {"managed_root_group_id": "root-id"},
            VAULT_RP_PATH: escrow,
        }
    )
    admin = KeycloakAdmin(cfg, vault, FakeDB())

    async def controller_token():
        return "token"

    monkeypatch.setattr(admin, "_controller_token", controller_token)
    result = await admin.status()
    assert result["vault_oidc_rp_escrowed"] is True
    assert result["vault_oidc_rp_escrow_readable"] is True
    assert escrow["client_secret"] not in json.dumps(result)

    missing = KeycloakAdmin(
        cfg,
        FakeVault({cfg.identity_state_vault_path: {"managed_root_group_id": "r"}}),
        FakeDB(),
    )
    monkeypatch.setattr(missing, "_controller_token", controller_token)
    missing_result = await missing.status()
    assert missing_result["vault_oidc_rp_escrowed"] is False
    assert missing_result["vault_oidc_rp_escrow_readable"] is True


@pytest.mark.asyncio
async def test_status_degrades_when_the_escrow_path_is_unreadable(
    monkeypatch,
) -> None:
    """A pre-feature rotator Vault policy (brownfield host) denies the escrow
    read; status must stay serviceable instead of failing the endpoint."""
    cfg = settings(KC_BOOTSTRAP_ADMIN_CLIENT_SECRET="")
    vault = FakeVault(
        {cfg.identity_state_vault_path: {"managed_root_group_id": "root-id"}},
        deny_reads={VAULT_RP_PATH},
    )
    admin = KeycloakAdmin(cfg, vault, FakeDB())

    async def controller_token():
        return "token"

    monkeypatch.setattr(admin, "_controller_token", controller_token)
    result = await admin.status()
    assert result["vault_oidc_rp_escrowed"] is False
    assert result["vault_oidc_rp_escrow_readable"] is False


def test_vault_oidc_rp_path_joins_the_pairwise_distinct_boundary() -> None:
    with pytest.raises(ValueError, match="pairwise distinct"):
        settings(VAULT_OIDC_RP_VAULT_PATH="ai-gateway/keycloak/identity-state")
    with pytest.raises(ValueError, match="pairwise distinct"):
        settings(
            BREAK_GLASS_ADMIN_VAULT_PATH="ai-gateway/keycloak/vault-oidc-rp"
        )
    with pytest.raises(ValueError, match="deletable reserved"):
        settings(VAULT_OIDC_RP_VAULT_PATH="ai-gateway/anthropic-wif")
    with pytest.raises(ValueError, match="deletable reserved"):
        settings(VAULT_OIDC_RP_VAULT_PATH="ai-gateway/anthropic-wif/escrow")
    with pytest.raises(ValueError, match="canonical Vault KV path"):
        settings(VAULT_OIDC_RP_VAULT_PATH="ai-gateway/keycloak/../oops")
