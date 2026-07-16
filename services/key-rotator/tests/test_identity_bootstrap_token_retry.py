"""Bounded retry/backoff around the first Keycloak admin-token acquisition.

Ansible starts the pre-Vault identity reconcile the instant the Keycloak
*container* reports health-green, but the admin REST API can still lag a
freshly-imported realm by a few seconds. ``KeycloakAdmin._bootstrap_token``
retries only conditions that cannot possibly be a genuine credential refusal
(a network-level failure reaching Keycloak, or a 5xx). A 4xx (bad
client_id/client_secret) must fail on the first attempt, loudly, and never be
retried into a slower, quieter failure. These tests drive the real
``_request`` -> ``_bootstrap_token`` chain over a mock transport so the
classification is exercised end to end, not re-implemented in the test.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from app.config import Settings
from app.identity import (
    BOOTSTRAP_TOKEN_MAX_ATTEMPTS,
    IdentityError,
    KeycloakAdmin,
    TransientIdentityError,
)


BOOTSTRAP_SECRET = "Bootstrap-Secret!0123456789-ABCDEFGHIJKLMN"


def settings(**overrides) -> Settings:
    values = {
        "ROTATOR_INTERNAL_TOKEN": "0123456789abcdef0123456789abcdef",
        "PORTAL_IDENTITY_TOKEN": "abcdef0123456789abcdef0123456789",
        "VAULT_TOKEN": "",
        "LITELLM_MASTER_KEY": "litellm-master-key",
        "KC_BOOTSTRAP_ADMIN_CLIENT_SECRET": BOOTSTRAP_SECRET,
        "WEBUI_OIDC_CLIENT_SECRET": "WebuiOIDCSecret!0123456789-ABCDEFGHI",
        "PORTAL_OIDC_CLIENT_SECRET": "PortalOIDCSecret!0123456789-ABCDEFGH",
        "ADMIN_PORTAL_OIDC_CLIENT_SECRET": "AdminPortalOIDCSecret!0123456789-ABCDE",
        "OAUTH2_PROXY_CLIENT_SECRET": "OAuth2ProxySecret!0123456789-ABCDEFGHI",
        "VAULT_OIDC_CLIENT_SECRET": "VaultOIDCSecret!0123456789-ABCDEFGHIJ",
    }
    values.update(overrides)
    return Settings(**values)


def _admin(handler, monkeypatch=None) -> KeycloakAdmin:
    admin = KeycloakAdmin(
        settings(), None, None, transport=httpx.MockTransport(handler)
    )
    if monkeypatch is not None:
        # Retries are proven by call count / outcome, not by wall-clock time.
        # Collapse the backoff to keep the suite fast and deterministic.
        async def instant_sleep(_delay: float) -> None:
            return None

        monkeypatch.setattr(asyncio, "sleep", instant_sleep)
    return admin


@pytest.mark.asyncio
async def test_retries_transient_503_then_succeeds(monkeypatch) -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/protocol/openid-connect/token")
        calls["n"] += 1
        if calls["n"] < 3:
            return httpx.Response(503, json={"error": "server_error"})
        return httpx.Response(200, json={"access_token": "bootstrap-token"})

    admin = _admin(handler, monkeypatch)
    token = await admin._bootstrap_token()

    assert token == "bootstrap-token"
    assert calls["n"] == 3


@pytest.mark.asyncio
async def test_retries_connection_error_then_succeeds(monkeypatch) -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 2:
            raise httpx.ConnectError("connection refused", request=request)
        return httpx.Response(200, json={"access_token": "bootstrap-token"})

    admin = _admin(handler, monkeypatch)
    token = await admin._bootstrap_token()

    assert token == "bootstrap-token"
    assert calls["n"] == 2


@pytest.mark.asyncio
async def test_fails_immediately_on_401_no_retry(monkeypatch) -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(401, json={"error": "invalid_client"})

    admin = _admin(handler, monkeypatch)
    with pytest.raises(IdentityError) as excinfo:
        await admin._bootstrap_token()

    assert not isinstance(excinfo.value, TransientIdentityError)
    assert calls["n"] == 1
    assert BOOTSTRAP_SECRET not in str(excinfo.value)


@pytest.mark.asyncio
async def test_fails_immediately_on_403_no_retry(monkeypatch) -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(403, json={"error": "forbidden"})

    admin = _admin(handler, monkeypatch)
    with pytest.raises(IdentityError) as excinfo:
        await admin._bootstrap_token()

    assert not isinstance(excinfo.value, TransientIdentityError)
    assert calls["n"] == 1
    assert BOOTSTRAP_SECRET not in str(excinfo.value)


@pytest.mark.asyncio
async def test_total_attempts_are_bounded_then_raises_transient(monkeypatch) -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(503, json={"error": "server_error"})

    admin = _admin(handler, monkeypatch)
    with pytest.raises(TransientIdentityError) as excinfo:
        await admin._bootstrap_token()

    assert calls["n"] == BOOTSTRAP_TOKEN_MAX_ATTEMPTS
    assert BOOTSTRAP_SECRET not in str(excinfo.value)


@pytest.mark.asyncio
async def test_no_secret_in_raised_message_across_retries(monkeypatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        # The client_secret travels only in the outgoing form body, never in
        # a Keycloak error response; assert the body the caller can observe
        # (the raised exception's message) never carries it either.
        assert BOOTSTRAP_SECRET not in request.url.path
        return httpx.Response(503, json={"error": "server_error"})

    admin = _admin(handler, monkeypatch)
    with pytest.raises(TransientIdentityError) as excinfo:
        await admin._bootstrap_token()

    assert BOOTSTRAP_SECRET not in str(excinfo.value)
