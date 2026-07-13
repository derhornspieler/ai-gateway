from __future__ import annotations

import copy

import pytest

from app import health
from app.config import Settings
from app.jwks_watcher import (
    BOOTSTRAP_VAULT_PATH,
    STATE_VENDOR,
    AnthropicJwksWatcher,
    _jwks_sha256,
)


AUTH_TOKEN = "0123456789abcdef0123456789abcdef"


def settings() -> Settings:
    return Settings(
        ROTATOR_INTERNAL_TOKEN=AUTH_TOKEN,
        VAULT_TOKEN="vault-token",
        LITELLM_MASTER_KEY="litellm-master-key",
    )


class FakeVault:
    def __init__(self, bootstrap):
        self.bootstrap = copy.deepcopy(bootstrap)

    def read(self, path):
        assert path == BOOTSTRAP_VAULT_PATH
        return copy.deepcopy(self.bootstrap)


class FakeDB:
    def __init__(self, config=None):
        self.config = copy.deepcopy(config)
        self.history = []

    async def get_settings(self, vendor):
        assert vendor == STATE_VENDOR
        return {"config": copy.deepcopy(self.config)} if self.config else None

    async def upsert_settings(
        self, vendor, enabled, interval_seconds, grace_seconds, config
    ):
        assert vendor == STATE_VENDOR
        assert enabled is False
        self.config = copy.deepcopy(config)

    async def record_history(self, *args):
        self.history.append(args)


class ForbiddenInferenceDriver:
    async def mint_access_token(self, *args, **kwargs):
        raise AssertionError("JWKS watcher must never mint an inference token")


def watcher(db, vault):
    return AnthropicJwksWatcher(
        settings(), db, vault, object(), ForbiddenInferenceDriver()
    )


@pytest.mark.asyncio
async def test_first_jwks_requires_explicit_operator_approved_hash(monkeypatch):
    keys = [{"kid": "key-1", "kty": "RSA", "n": "abc", "e": "AQAB"}]
    db = FakeDB()
    subject = watcher(
        db,
        FakeVault(
            {
                "kc_token_url": (
                    "http://keycloak:8080/realms/anthropic-wif/"
                    "protocol/openid-connect/token"
                )
            }
        ),
    )

    async def fetch(_url):
        return keys

    monkeypatch.setattr(subject, "_fetch_jwks", fetch)
    await subject.check()

    digest = _jwks_sha256(keys)
    assert db.config["pending_jwks_sha256"] == digest
    assert "last_jwks_sha256" not in db.config
    assert db.history[0][2] == "baseline_unconfirmed"
    assert health.snapshot()["anthropic.jwks"]["ok"] is False


@pytest.mark.asyncio
async def test_drift_persists_alert_and_makes_no_anthropic_mutation(monkeypatch):
    old_keys = [{"kid": "old", "kty": "RSA", "n": "old", "e": "AQAB"}]
    new_keys = old_keys + [
        {"kid": "new", "kty": "RSA", "n": "new", "e": "AQAB"}
    ]
    old_sha = _jwks_sha256(old_keys)
    db = FakeDB(
        {"last_jwks_sha256": old_sha, "last_jwks_keys": old_keys}
    )
    subject = watcher(
        db,
        FakeVault(
            {
                "kc_token_url": (
                    "http://keycloak:8080/realms/anthropic-wif/"
                    "protocol/openid-connect/token"
                ),
                "federation_jwks_sha256": old_sha,
            }
        ),
    )

    async def fetch(_url):
        return new_keys

    monkeypatch.setattr(subject, "_fetch_jwks", fetch)
    await subject.check()

    new_sha = _jwks_sha256(new_keys)
    assert db.config["last_jwks_sha256"] == old_sha
    assert db.config["pending_jwks_sha256"] == new_sha
    assert db.history == [
        (
            STATE_VENDOR,
            "jwks",
            "drift_detected",
            db.history[0][3],
        )
    ]
    assert "org:admin" in db.history[0][3]
    assert "No automatic issuer mutation" in db.history[0][3]

    # Rechecking the same candidate keeps the alert live without adding a
    # history row every five minutes.
    await subject.check()
    assert len(db.history) == 1


@pytest.mark.asyncio
async def test_operator_approved_hash_advances_baseline(monkeypatch):
    old_keys = [{"kid": "old", "kty": "RSA", "n": "old", "e": "AQAB"}]
    new_keys = [{"kid": "new", "kty": "RSA", "n": "new", "e": "AQAB"}]
    old_sha = _jwks_sha256(old_keys)
    new_sha = _jwks_sha256(new_keys)
    db = FakeDB(
        {
            "last_jwks_sha256": old_sha,
            "last_jwks_keys": old_keys,
            "pending_jwks_sha256": new_sha,
            "pending_jwks_keys": new_keys,
        }
    )
    subject = watcher(
        db,
        FakeVault(
            {
                "kc_token_url": (
                    "http://keycloak:8080/realms/anthropic-wif/"
                    "protocol/openid-connect/token"
                ),
                "federation_jwks_sha256": new_sha,
            }
        ),
    )

    async def fetch(_url):
        return new_keys

    monkeypatch.setattr(subject, "_fetch_jwks", fetch)
    await subject.check()

    assert db.config["last_jwks_sha256"] == new_sha
    assert "pending_jwks_sha256" not in db.config
    assert db.history[0][2] == "manual_update_confirmed"
    assert health.snapshot()["anthropic.jwks"]["ok"] is True
