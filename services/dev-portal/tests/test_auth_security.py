from __future__ import annotations

import time
from types import SimpleNamespace

import httpx
import pytest
from authlib.integrations.starlette_client import OAuth
from authlib.jose import JsonWebKey, jwt
from authlib.jose.errors import InvalidClaimError

from app import auth
from app.config import settings


def _metadata(**overrides):
    issuer = "https://idp.test/realms/aigw"
    data = {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/protocol/openid-connect/auth",
        "token_endpoint": f"{issuer}/protocol/openid-connect/token",
        "jwks_uri": f"{issuer}/protocol/openid-connect/certs",
        "userinfo_endpoint": f"{issuer}/protocol/openid-connect/userinfo",
        "id_token_signing_alg_values_supported": ["RS256"],
    }
    data.update(overrides)
    return data


def test_discovery_requires_exact_issuer(monkeypatch):
    monkeypatch.setattr(settings, "oidc_issuer", "https://idp.test/realms/aigw")
    monkeypatch.setattr(settings, "oidc_internal_issuer", None)

    with pytest.raises(ValueError, match="exactly match"):
        auth._validated_oidc_metadata(_metadata(issuer="https://evil.test/realms/aigw"))
    missing = _metadata()
    missing.pop("issuer")
    with pytest.raises(ValueError, match="exactly match"):
        auth._validated_oidc_metadata(missing)


def test_public_oidc_issuer_must_use_https(monkeypatch):
    monkeypatch.setattr(settings, "oidc_issuer", "http://idp.test/realms/aigw")
    monkeypatch.setattr(settings, "oidc_internal_issuer", None)
    metadata = _metadata(issuer="http://idp.test/realms/aigw")
    metadata.update(
        {
            "authorization_endpoint": "http://idp.test/realms/aigw/auth",
            "token_endpoint": "http://idp.test/realms/aigw/token",
            "jwks_uri": "http://idp.test/realms/aigw/certs",
            "userinfo_endpoint": "http://idp.test/realms/aigw/userinfo",
        }
    )

    with pytest.raises(ValueError, match="HTTPS"):
        auth._validated_oidc_metadata(metadata)


def test_discovery_cannot_redirect_secret_bearing_endpoints(monkeypatch):
    monkeypatch.setattr(settings, "oidc_issuer", "https://idp.test/realms/aigw")
    monkeypatch.setattr(
        settings, "oidc_internal_issuer", "http://keycloak:8080/realms/aigw"
    )

    with pytest.raises(ValueError, match="outside"):
        auth._validated_oidc_metadata(
            _metadata(token_endpoint="http://attacker.test/collect-client-secret")
        )


@pytest.mark.asyncio
async def test_discovery_splits_public_browser_and_internal_server_endpoints(
    monkeypatch,
):
    monkeypatch.setattr(settings, "oidc_issuer", "https://idp.test/realms/aigw")
    monkeypatch.setattr(
        settings, "oidc_internal_issuer", "http://keycloak:8080/realms/aigw"
    )
    auth._metadata_cache.clear()
    raw = _metadata(
        end_session_endpoint=(
            "https://idp.test/realms/aigw/protocol/openid-connect/logout"
        )
    )

    def handler(request: httpx.Request):
        assert request.url == (
            "http://keycloak:8080/realms/aigw/.well-known/openid-configuration"
        )
        return httpx.Response(200, json=raw)

    real_client = httpx.AsyncClient

    def factory(*args, **kwargs):
        assert kwargs["trust_env"] is False
        assert kwargs["follow_redirects"] is False
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(auth.httpx, "AsyncClient", factory)
    metadata = await auth.fetch_oidc_metadata()

    assert metadata["issuer"] == "https://idp.test/realms/aigw"
    assert metadata["authorization_endpoint_public"].startswith("https://idp.test/")
    assert metadata["end_session_endpoint_public"].startswith("https://idp.test/")
    for field in ("token_endpoint", "jwks_uri", "userinfo_endpoint"):
        assert metadata[field].startswith("http://keycloak:8080/")


@pytest.mark.asyncio
async def test_oauth_registration_preserves_issuer_for_authlib(monkeypatch):
    captured = {}

    class OAuthRecorder:
        def register(self, **kwargs):
            captured.update(kwargs)

    async def fake_metadata():
        return _metadata()

    monkeypatch.setattr(auth, "oauth", OAuthRecorder())
    monkeypatch.setattr(auth, "fetch_oidc_metadata", fake_metadata)
    monkeypatch.setattr(auth, "_client_registered", False)

    await auth.init_oauth_client()

    assert captured["issuer"] == "https://idp.test/realms/aigw"
    assert captured["jwks_uri"].startswith("https://idp.test/")
    assert captured["client_kwargs"]["trust_env"] is False
    assert captured["client_kwargs"]["follow_redirects"] is False


@pytest.mark.asyncio
async def test_authlib_rejects_a_signed_id_token_from_the_wrong_issuer():
    key = JsonWebKey.generate_key(
        "RSA", 2048, is_private=True, options={"kid": "issuer-regression-key"}
    )
    oauth = OAuth()
    client = oauth.register(
        name="issuer-regression",
        client_id="portal-client",
        client_secret="unused-for-rs256",
        issuer="https://idp.test/realms/aigw",
        jwks={"keys": [key.as_dict(is_private=False)]},
        id_token_signing_alg_values_supported=["RS256"],
    )
    now = int(time.time())
    encoded = jwt.encode(
        {"alg": "RS256", "kid": "issuer-regression-key"},
        {
            "iss": "https://other-realm.test/realms/aigw",
            "sub": "attacker",
            "aud": "portal-client",
            "iat": now,
            "exp": now + 300,
            "nonce": "expected-nonce",
        },
        key,
    ).decode()

    with pytest.raises(InvalidClaimError, match="iss"):
        await client.parse_id_token({"id_token": encoded}, nonce="expected-nonce")


def test_verified_userinfo_requires_validated_id_token_claims():
    with pytest.raises(auth.InvalidIdentity, match="ID token"):
        auth.verified_userinfo({"access_token": "oauth-only"})
    with pytest.raises(auth.InvalidIdentity, match="validated"):
        auth.verified_userinfo({"id_token": "unparsed"})

    assert auth.verified_userinfo(
        {"id_token": "signed-token", "userinfo": {"sub": "subject-123"}}
    ) == {"sub": "subject-123"}


def test_new_identity_clears_previous_accounts_secret_state():
    request = SimpleNamespace(
        session={
            "user": {"sub": "old-subject"},
            "stale_account_state": "must-be-cleared",
            "csrf_token": "old-csrf-token",
        }
    )

    auth.establish_session(
        request,
        {"id_token": "validated"},
        {
            "sub": "new-subject",
            "email": "new@example.test",
            "realm_access": {"roles": [settings.developer_role]},
        },
    )

    assert request.session == {
        "user": {
            "sub": "new-subject",
            "email": "new@example.test",
            "name": "new@example.test",
            "roles": [settings.developer_role],
        }
    }


def test_oidc_subject_is_mandatory():
    request = SimpleNamespace(session={})
    with pytest.raises(auth.InvalidIdentity, match="subject"):
        auth.establish_session(
            request, {"id_token": "validated"}, {"email": "a@b.test"}
        )


@pytest.mark.asyncio
async def test_developer_role_is_explicit_and_admins_are_intentionally_allowed():
    developer = {"sub": "dev", "roles": [settings.developer_role]}
    admin = {"sub": "admin", "roles": [settings.admin_role]}
    ordinary = {"sub": "ordinary", "roles": ["default-roles-aigw"]}

    assert await auth.require_developer(user=developer) is developer
    assert await auth.require_developer(user=admin) is admin
    with pytest.raises(auth.NotAuthorized):
        await auth.require_developer(user=ordinary)


def test_key_resolution_never_accepts_an_unowned_token():
    owned = [
        {
            "token": "attacker-hash",
            "key_alias": "shared-name",
            "user_id": "attacker",
            "metadata": {
                "created_via": "dev-portal",
                "aigw_project_id": "ai-gateway",
            },
        },
        {
            "token": "other-project-hash",
            "key_alias": "other",
            "user_id": "attacker",
            "metadata": {
                "created_via": "dev-portal",
                "aigw_project_id": "other-project",
            },
        },
    ]

    assert (
        auth.verify_csrf(SimpleNamespace(session={"csrf_token": "x" * 43}), "y" * 43)
        is False
    )

    # Imported here to keep the helper's web-route module out of auth unit setup.
    from app.main import _portal_key_inventory, _resolve_owned_project_key

    inventory = _portal_key_inventory(owned, "attacker", ("ai-gateway",))
    assert _resolve_owned_project_key(inventory, "victim-hash", "ai-gateway") is None
    assert (
        _resolve_owned_project_key(inventory, "attacker-hash", "ai-gateway")
        == "attacker-hash"
    )
    assert (
        _resolve_owned_project_key(inventory, "other-project-hash", "ai-gateway")
        is None
    )


def test_admin_step_up_requires_same_admin_and_recent_auth_time(monkeypatch):
    now = int(time.time())
    valid = {
        "sub": "admin-subject",
        "auth_time": now,
        "realm_access": {"roles": [settings.admin_role]},
    }
    auth.validate_step_up_identity(valid, "admin-subject")

    with pytest.raises(auth.InvalidIdentity, match="does not match"):
        auth.validate_step_up_identity(valid, "other-subject")
    with pytest.raises(auth.InvalidIdentity, match="no longer"):
        auth.validate_step_up_identity(
            {**valid, "realm_access": {"roles": [settings.developer_role]}},
            "admin-subject",
        )
    with pytest.raises(auth.InvalidIdentity, match="not recent"):
        auth.validate_step_up_identity(
            {**valid, "auth_time": now - settings.admin_step_up_seconds - 1},
            "admin-subject",
        )


def test_recent_admin_marker_is_bounded_and_not_a_bearer_credential(monkeypatch):
    request = SimpleNamespace(session={})
    monkeypatch.setattr(auth.time, "time", lambda: 10_000)
    auth.mark_recent_admin_reauthentication(request)
    assert request.session == {"admin_reauth_at": 10_000}
    assert auth.has_recent_admin_reauthentication(request) is True

    monkeypatch.setattr(
        auth.time,
        "time",
        lambda: 10_001 + settings.admin_step_up_seconds,
    )
    assert auth.has_recent_admin_reauthentication(request) is False


def test_step_up_expiry_is_a_fixed_absolute_target(monkeypatch):
    # The countdown must render against a FIXED server-computed target, not a
    # client clock: expiry is the marker time plus the configured window.
    request = SimpleNamespace(session={})
    monkeypatch.setattr(auth.time, "time", lambda: 10_000)
    auth.mark_recent_admin_reauthentication(request)

    expires = auth.admin_reauthentication_expires_at(request)
    assert expires == 10_000 + settings.admin_step_up_seconds

    # The value does not move as the clock advances — it is an absolute target.
    monkeypatch.setattr(auth.time, "time", lambda: 10_123)
    assert auth.admin_reauthentication_expires_at(request) == expires


def test_step_up_expiry_is_none_without_a_valid_marker():
    assert auth.admin_reauthentication_expires_at(SimpleNamespace(session={})) is None
    # A forged/garbage marker (non-int, or a bool) yields no target.
    assert (
        auth.admin_reauthentication_expires_at(
            SimpleNamespace(session={"admin_reauth_at": "soon"})
        )
        is None
    )
    assert (
        auth.admin_reauthentication_expires_at(
            SimpleNamespace(session={"admin_reauth_at": True})
        )
        is None
    )
