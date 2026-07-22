from __future__ import annotations

import copy
import json
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from uuid import UUID

import httpx
import pytest
from apscheduler.triggers.date import DateTrigger
from pydantic import ValidationError

from app import health
from app import vault_client as vault_client_module
from app.config import Settings
from app.db import Database, RETIRED_SETTINGS_VENDORS
from app.drivers.anthropic_wif import AnthropicWifDriver
from app.drivers.base import DriverContext, RotationResult
from app.drivers.static_seed import StaticSeedDriver, VAULT_RETRY_SECONDS
from app.identity import IdentityError
from app.main import SettingsUpdate, app, readyz, state
from app.provider_state import (
    CREDENTIAL_ISSUED,
    CREDENTIAL_LIFECYCLE_FIELD,
    CREDENTIAL_PROMOTION_PENDING,
)
from app.security import path_segment
from app.scheduler import RotationScheduler
from app.vault_client import VaultClient, VaultError, mask_secret


AUTH_TOKEN = "0123456789abcdef0123456789abcdef"


class ReadinessDB:
    def __init__(self, value: bool):
        self.value = value

    async def ready(self) -> bool:
        return self.value


class ReadinessVault:
    def __init__(self, value: bool):
        self.value = value

    def ready(self) -> bool:
        return self.value


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("database_ready", "vault_ready", "expected"),
    [(True, True, 200), (False, True, 503), (True, False, 503)],
)
async def test_readyz_requires_database_and_authenticated_unsealed_vault(
    monkeypatch, database_ready: bool, vault_ready: bool, expected: int
) -> None:
    monkeypatch.setitem(state, "db", ReadinessDB(database_ready))
    monkeypatch.setitem(state, "vault", ReadinessVault(vault_ready))
    response = await readyz()
    assert response.status_code == expected


def settings(**overrides) -> Settings:
    values = {
        "ROTATOR_INTERNAL_TOKEN": AUTH_TOKEN,
        "PORTAL_IDENTITY_TOKEN": "abcdef0123456789abcdef0123456789",
        "VAULT_TOKEN": "vault-token",
        "LITELLM_MASTER_KEY": "litellm-master-key",
    }
    values.update(overrides)
    return Settings(**values)


def test_service_urls_reject_ambiguous_or_credentialed_values() -> None:
    with pytest.raises(ValidationError):
        settings(EGRESS_BASE="http://envoy-egress:8080/base")
    with pytest.raises(ValidationError):
        settings(LITELLM_URL="http://user:password@litellm:4000")
    with pytest.raises(ValidationError):
        settings(VAULT_ADDR="file:///tmp/vault.sock")


def test_keycloak_bootstrap_url_is_same_origin_and_canonical() -> None:
    cfg = settings(KEYCLOAK_URL="https://keycloak.internal:8443")
    valid = (
        "https://keycloak.internal:8443/realms/anthropic/protocol/openid-connect/token"
    )
    assert cfg.validated_keycloak_token_url(valid) == valid

    for invalid in (
        "http://keycloak.internal:8443/realms/anthropic/protocol/openid-connect/token",
        "https://169.254.169.254/realms/anthropic/protocol/openid-connect/token",
        "https://keycloak.internal:8443/admin/serverinfo",
        "https://keycloak.internal:8443/realms/../protocol/openid-connect/token",
        "https://keycloak.internal:8443/realms/%2e%2e/protocol/openid-connect/token",
    ):
        with pytest.raises(ValueError):
            cfg.validated_keycloak_token_url(invalid)


def test_keycloak_assertion_audiences_follow_each_realm_frontend() -> None:
    cfg = settings(
        KEYCLOAK_PUBLIC_URL="https://auth.aigw.internal",
        WIF_KEYCLOAK_PUBLIC_URL="https://idp.wif.aigw.example.internal",
    )
    assert cfg.keycloak_assertion_audience("aigw") == (
        "https://auth.aigw.internal/realms/aigw/protocol/openid-connect/token"
    )
    internal = "http://keycloak:8080/realms/anthropic-wif/protocol/openid-connect/token"
    assert cfg.keycloak_assertion_audience_for_token_url(internal) == (
        "https://idp.wif.aigw.example.internal/realms/anthropic-wif/"
        "protocol/openid-connect/token"
    )


def test_outbound_path_segments_cannot_escape_endpoint() -> None:
    assert path_segment("proj_abc-123", label="project") == "proj_abc-123"
    for invalid in ("../admin", "abc/keys", "abc?x=1", "#fragment", ""):
        with pytest.raises(ValueError):
            path_segment(invalid, label="project")


def test_secret_redaction_never_retains_a_prefix() -> None:
    assert mask_secret("sk-super-secret-value") == "<redacted>"
    assert "sk-super" not in mask_secret("sk-super-secret-value")
    assert mask_secret(None) == "<empty>"


def test_vault_transport_ignores_ambient_proxies_and_redirects() -> None:
    vault = VaultClient(settings())
    client = vault._get_client()
    assert client.session.trust_env is False
    assert client.allow_redirects is False
    assert client.adapter._kwargs["verify"] is True
    vault.close()


@pytest.mark.asyncio
async def test_vault_public_status_route_is_admin_internal_only_and_bounded() -> None:
    old_state = dict(state)

    class PublicVault:
        def public_status(self):
            return {"initialized": True, "sealed": True}

    try:
        cfg = settings()
        state.clear()
        state.update({"settings": cfg, "vault": PublicVault()})
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://rotator"
        ) as client:
            assert (await client.get("/vault/public-status")).status_code == 401
            portal = await client.get(
                "/vault/public-status",
                headers={"X-Internal-Auth": cfg.portal_identity_token},
            )
            assert portal.status_code == 401

            admin = await client.get(
                "/vault/public-status",
                headers={"X-Internal-Auth": cfg.rotator_internal_token},
            )
            assert admin.status_code == 200
            assert admin.json() == {"initialized": True, "sealed": True}
            assert admin.headers["cache-control"] == "no-store"
    finally:
        state.clear()
        state.update(old_state)


@pytest.mark.asyncio
async def test_vault_public_status_route_sanitizes_upstream_failure() -> None:
    old_state = dict(state)

    class BrokenVault:
        def public_status(self):
            raise VaultError("sensitive upstream diagnostic")

    try:
        cfg = settings()
        state.clear()
        state.update({"settings": cfg, "vault": BrokenVault()})
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://rotator"
        ) as client:
            response = await client.get(
                "/vault/public-status",
                headers={"X-Internal-Auth": cfg.rotator_internal_token},
            )
            assert response.status_code == 503
            assert response.json() == {"detail": "Vault public status unavailable"}
            assert "sensitive" not in response.text
    finally:
        state.clear()
        state.update(old_state)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("vault_status", "expected"),
    [
        ({"initialized": True, "sealed": True}, 423),
        ({"initialized": True, "sealed": False}, 502),
        ({"initialized": False, "sealed": True}, 502),
    ],
)
async def test_identity_authorization_emits_typed_error_only_for_exact_sealed_vault(
    vault_status, expected
) -> None:
    old_state = dict(state)

    class BrokenIdentity:
        async def user_has_admin_role(self, _user_id):
            raise IdentityError("wrapped authorization failure")

    class PublicVault:
        def public_status(self):
            return vault_status

    try:
        cfg = settings()
        state.clear()
        state.update(
            {
                "settings": cfg,
                "identity": BrokenIdentity(),
                "vault": PublicVault(),
            }
        )
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://rotator"
        ) as client:
            response = await client.get(
                "/identity/authorization/user-1",
                headers={"X-Internal-Auth": cfg.rotator_internal_token},
            )
        assert response.status_code == expected
        if expected == 423:
            assert response.json() == {"detail": "vault_sealed"}
        else:
            assert "vault_sealed" not in response.text
    finally:
        state.clear()
        state.update(old_state)


@pytest.mark.parametrize(
    ("status_code", "payload", "expected"),
    [
        (200, {"initialized": True, "sealed": False}, {"initialized": True, "sealed": False}),
        (429, {"initialized": True, "sealed": False}, {"initialized": True, "sealed": False}),
        (472, {"initialized": True, "sealed": False}, {"initialized": True, "sealed": False}),
        (473, {"initialized": True, "sealed": False}, {"initialized": True, "sealed": False}),
        (503, {"initialized": True, "sealed": True}, {"initialized": True, "sealed": True}),
        (501, {"initialized": False, "sealed": True}, {"initialized": False, "sealed": True}),
    ],
)
def test_vault_public_status_accepts_only_status_consistent_boolean_state(
    monkeypatch, status_code, payload, expected
) -> None:
    calls: list[dict] = []

    class Response:
        def __init__(self):
            self.status_code = status_code

        def json(self):
            return payload

    class Session:
        def __init__(self):
            self.trust_env = True

        def get(self, url, **kwargs):
            calls.append({"url": url, "trust_env": self.trust_env, **kwargs})
            return Response()

        def close(self):
            return None

    monkeypatch.setattr(vault_client_module.requests, "Session", Session)
    result = VaultClient(settings(VAULT_ADDR="http://vault:8200")).public_status()

    assert result == expected
    assert calls == [
        {
            "url": "http://vault:8200/v1/sys/health",
            "trust_env": False,
            "params": {"standbyok": "true", "perfstandbyok": "true"},
            "headers": {"User-Agent": "aigw-key-rotator-vault-status"},
            "allow_redirects": False,
            "timeout": 5,
        }
    ]


@pytest.mark.parametrize(
    ("status_code", "payload"),
    [
        (501, {"initialized": False, "sealed": False}),
        (501, {"initialized": True, "sealed": True}),
        (503, {"initialized": True, "sealed": False}),
        (200, {"initialized": True, "sealed": True}),
        (302, {"initialized": True, "sealed": False}),
        (501, {"initialized": "false", "sealed": True}),
    ],
)
def test_vault_public_status_rejects_impossible_or_ambiguous_health(
    monkeypatch, status_code, payload
) -> None:
    class Response:
        def __init__(self):
            self.status_code = status_code

        def json(self):
            return payload

    class Session:
        trust_env = True

        def get(self, *_args, **_kwargs):
            return Response()

        def close(self):
            return None

    monkeypatch.setattr(vault_client_module.requests, "Session", Session)

    with pytest.raises(VaultError, match="public status unavailable"):
        VaultClient(settings()).public_status()


@pytest.mark.asyncio
async def test_auth_fails_closed_and_public_health_redacts_details() -> None:
    old_state = dict(state)
    old_flags = health.snapshot()
    try:
        state.clear()
        health._flags.clear()
        health.set_alert(
            "anthropic.rotation",
            "vault=http://vault:8200 token=credential_sensitive internal-only detail",
        )
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://rotator"
        ) as client:
            health_response = await client.get("/healthz")
            assert health_response.status_code == 200
            assert health_response.json() == {"ok": True, "alerts_ok": False}
            assert "credential_sensitive" not in health_response.text
            assert health_response.headers["cache-control"] == "no-store"

            # Before startup has installed valid settings, protected routes
            # fail closed even if a caller supplies a header.
            response = await client.get(
                "/status", headers={"X-Internal-Auth": AUTH_TOKEN}
            )
            assert response.status_code == 503

            state["settings"] = settings()
            response = await client.get("/status")
            assert response.status_code == 401
    finally:
        state.clear()
        state.update(old_state)
        health._flags.clear()
        health._flags.update(old_flags)


@pytest.mark.asyncio
async def test_portal_token_is_limited_to_exact_project_membership_reads() -> None:
    old_state = dict(state)

    project_policies = {
        "projects": ["project-a"],
        "policies": {
            "project-a": {
                "tpm_limit": None,
                "rpm_limit": None,
                "allowed_models": None,
                "default_model": None,
            }
        },
    }

    class Identity:
        async def user_project_policies(self, user_id):
            assert user_id == "user-1"
            return project_policies

    try:
        cfg = settings()
        state.clear()
        state.update({"settings": cfg, "identity": Identity()})
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://rotator"
        ) as client:
            headers = {"X-Internal-Auth": cfg.portal_identity_token}
            allowed = await client.get("/identity/projects/user-1", headers=headers)
            assert allowed.status_code == 200
            assert allowed.json() == project_policies

            assert (await client.get("/status", headers=headers)).status_code == 401
            assert (
                await client.post("/identity/projects/user-1", headers=headers)
            ).status_code == 401
            # The membership+policy READ is the portal token's entire scope:
            # the policy WRITE route must stay admin-token-only.
            assert (
                await client.put(
                    "/identity/groups/group-1/policy",
                    headers=headers,
                    json={"tpm_limit": 1000},
                )
            ).status_code == 401
            # The chat-capability health route is admin-token-only too.
            assert (
                await client.get(
                    "/identity/chat-capability-health", headers=headers
                )
            ).status_code == 401

            admin = {"X-Internal-Auth": cfg.rotator_internal_token}
            assert (
                await client.get("/identity/projects/user-1", headers=admin)
            ).status_code == 200
    finally:
        state.clear()
        state.update(old_state)


@pytest.mark.asyncio
async def test_identity_deployment_route_is_admin_only_confirmed_and_redacted() -> None:
    old_state = dict(state)

    class Identity:
        def __init__(self) -> None:
            self.calls = 0
            self.fail = False
            self.failure_types = []

        async def converge_deployment_identity(self):
            self.calls += 1
            if self.fail:
                raise IdentityError("secret LDAP bind password from upstream")
            return "verified"

        async def audit_deployment_failure(self, error):
            self.failure_types.append(type(error).__name__)

    identity = Identity()
    try:
        cfg = settings()
        state.clear()
        state.update({"settings": cfg, "identity": identity})
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://rotator"
        ) as client:
            body = {"confirmation": "AUTO_BOOTSTRAP_IDENTITY"}
            assert (
                await client.post("/identity/deployment", json=body)
            ).status_code == 401
            portal = await client.post(
                "/identity/deployment",
                headers={"X-Internal-Auth": cfg.portal_identity_token},
                json=body,
            )
            assert portal.status_code == 401

            admin_headers = {"X-Internal-Auth": cfg.rotator_internal_token}
            invalid = await client.post(
                "/identity/deployment",
                headers=admin_headers,
                json={"confirmation": "INITIALIZE"},
            )
            assert invalid.status_code == 400
            assert identity.calls == 0

            verified = await client.post(
                "/identity/deployment", headers=admin_headers, json=body
            )
            assert verified.status_code == 200
            assert verified.json() == {"result": "verified"}
            assert verified.headers["cache-control"] == "no-store"

            identity.fail = True
            failed = await client.post(
                "/identity/deployment", headers=admin_headers, json=body
            )
            assert failed.status_code == 502
            assert failed.json() == {"detail": "identity deployment failed"}
            assert "password" not in failed.text
            assert identity.failure_types == ["IdentityError"]
    finally:
        state.clear()
        state.update(old_state)


@pytest.mark.asyncio
async def test_identity_mutation_requires_one_canonical_operation_id() -> None:
    old_state = dict(state)
    operation_id = "123e4567-e89b-42d3-a456-426614174000"

    class Identity:
        def __init__(self) -> None:
            self.calls: list[tuple[str, list[str], str]] = []

        async def create_group(self, name, capabilities, received_operation_id):
            self.calls.append((name, capabilities, received_operation_id))
            return {"id": "group-1", "name": name}

    identity = Identity()
    try:
        cfg = settings()
        state.clear()
        state.update({"settings": cfg, "identity": identity})
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://rotator"
        ) as client:
            body = {"name": "platform-team", "capabilities": ["aigw-users"]}
            auth_header = ("X-Internal-Auth", cfg.rotator_internal_token)
            invalid_headers = [
                [auth_header],
                [auth_header, ("X-AIGW-Operation-ID", "not-a-uuid")],
                [
                    auth_header,
                    (
                        "X-AIGW-Operation-ID",
                        operation_id.upper(),
                    ),
                ],
                [
                    auth_header,
                    ("X-AIGW-Operation-ID", operation_id),
                    ("X-AIGW-Operation-ID", operation_id),
                ],
                [
                    auth_header,
                    ("X-AIGW-Operation-ID", operation_id),
                    (
                        "X-AIGW-Operation-ID",
                        "550e8400-e29b-41d4-a716-446655440000",
                    ),
                ],
            ]
            for headers in invalid_headers:
                response = await client.post(
                    "/identity/groups", headers=headers, json=body
                )
                assert response.status_code == 400
                assert response.json() == {
                    "detail": "missing or invalid identity operation ID"
                }

            accepted = await client.post(
                "/identity/groups",
                headers=[
                    auth_header,
                    ("X-AIGW-Operation-ID", operation_id),
                ],
                json=body,
            )

        assert accepted.status_code == 201
        assert identity.calls == [
            ("platform-team", ["aigw-users"], operation_id)
        ]
    finally:
        state.clear()
        state.update(old_state)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure", "expected_status", "expected_type"),
    [
        (IdentityError("password=upstream-identity-secret"), 502, "IdentityError"),
        (RuntimeError("token=unexpected-internal-secret"), 500, "RuntimeError"),
    ],
)
async def test_identity_mutation_failure_keeps_operation_id_and_fixed_audit(
    failure, expected_status, expected_type
) -> None:
    old_state = dict(state)
    operation_id = "123e4567-e89b-42d3-a456-426614174000"

    class Identity:
        def __init__(self) -> None:
            self.failures: list[tuple[str, str, str]] = []

        async def create_group(self, _name, _capabilities, _operation_id):
            raise failure

        async def audit_identity_mutation_failure(
            self, action, received_operation_id, error
        ):
            self.failures.append(
                (action, received_operation_id, type(error).__name__)
            )

    identity = Identity()
    try:
        cfg = settings()
        state.clear()
        state.update({"settings": cfg, "identity": identity})
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://rotator"
        ) as client:
            response = await client.post(
                "/identity/groups",
                headers={
                    "X-Internal-Auth": cfg.rotator_internal_token,
                    "X-AIGW-Operation-ID": operation_id,
                },
                json={
                    "name": "platform-team",
                    "capabilities": ["aigw-users"],
                },
            )

        assert response.status_code == expected_status
        assert identity.failures == [
            ("group_create", operation_id, expected_type)
        ]
        assert "upstream-identity-secret" not in response.text
        assert "unexpected-internal-secret" not in response.text
    finally:
        state.clear()
        state.update(old_state)


@pytest.mark.asyncio
async def test_openai_provider_is_hidden_and_rejected_for_brownfield_rows() -> None:
    class BrownfieldDB:
        async def list_settings(self):
            return [
                {
                    "vendor": "anthropic",
                    "enabled": False,
                    "interval_seconds": 3000,
                    "grace_seconds": 300,
                    "config": {},
                },
                {
                    "vendor": "openai",
                    "enabled": True,
                    "interval_seconds": 3600,
                    "grace_seconds": 300,
                    "config": {"legacy": True},
                },
            ]

        async def last_history(self, _vendor):
            return None

    class BrownfieldScheduler:
        def next_run_time(self, _vendor):
            return None

        def is_rotating(self, _vendor):
            return False

    old_state = dict(state)
    try:
        state.clear()
        state.update(
            {
                "settings": settings(),
                "db": BrownfieldDB(),
                "scheduler": BrownfieldScheduler(),
                "drivers": {"anthropic": object()},
            }
        )
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://test"
        ) as client:
            headers = {"X-Internal-Auth": AUTH_TOKEN}
            listed = await client.get("/settings", headers=headers)
            status = await client.get("/status", headers=headers)
            update = await client.put(
                "/settings/openai",
                headers=headers,
                json={
                    "enabled": True,
                    "interval_seconds": 3600,
                    "grace_seconds": 300,
                },
            )
            rotate = await client.post("/rotate/openai", headers=headers)

        assert [row["vendor"] for row in listed.json()] == ["anthropic"]
        assert [row["vendor"] for row in status.json()] == ["anthropic"]
        assert update.status_code == 404
        assert rotate.status_code == 404
    finally:
        state.clear()
        state.update(old_state)


class FakeVault:
    def __init__(self) -> None:
        self.docs = {}

    def read(self, path):
        value = self.docs.get(path)
        return copy.deepcopy(value) if value is not None else None

    def write_verified(self, path, data, attempts=3):
        self.docs[path] = copy.deepcopy(data)
        return True

    def write(self, path, data):
        self.docs[path] = copy.deepcopy(data)
        return True


class FakeDB:
    def __init__(self) -> None:
        self.history = []

    async def record_history(self, *args):
        self.history.append(args)


class SettingsDB:
    def __init__(self):
        self.available = True

    async def list_settings(self):
        if not self.available:
            return []
        return [
            {
                "vendor": "anthropic",
                "enabled": True,
                "interval_seconds": 3600,
                "grace_seconds": 0,
                "config": {},
            }
        ]


@pytest.mark.asyncio
async def test_scheduler_reload_does_not_cancel_accepted_manual_job() -> None:
    db = SettingsDB()
    scheduler = RotationScheduler(
        settings(), db, object(), object(), {"anthropic": object()}
    )
    manual_id = "rotate_anthropic_manual_test"
    scheduler._scheduler.add_job(
        scheduler.run_rotation,
        trigger=DateTrigger(run_date=datetime.now(timezone.utc) + timedelta(minutes=5)),
        args=["anthropic"],
        id=manual_id,
    )

    await scheduler.reload()

    assert scheduler._scheduler.get_job(manual_id) is not None
    assert scheduler._scheduler.get_job("rotate_anthropic") is not None
    assert scheduler._lock_for("static-anthropic") is scheduler._lock_for("anthropic")

    db.available = False
    await scheduler.reload()
    assert scheduler._scheduler.get_job("rotate_anthropic") is not None


@pytest.mark.asyncio
async def test_queued_anthropic_manual_rotation_rechecks_confirmed_disable() -> None:
    vendor = "anthropic"
    db = SchedulerDB(
        {
            "vendor": vendor,
            "enabled": False,
            "interval_seconds": 3000,
            "grace_seconds": 300,
            "config": {},
        }
    )
    driver = SequenceDriver(RotationResult(status="success", detail="rotated"))
    scheduler = RotationScheduler(
        settings(), db, SchedulerVault(ready=True), object(), {vendor: driver}
    )

    result = await scheduler.run_rotation(vendor)

    assert result.status == "skipped"
    assert driver.calls == 0
    assert db.history == [
        (
            vendor,
            "rotate",
            "skipped",
            "provider rotation skipped",
        )
    ]


class SchedulerVault:
    def __init__(self, ready: bool) -> None:
        self.is_ready = ready
        self.ready_calls = 0

    def ready(self) -> bool:
        self.ready_calls += 1
        return self.is_ready


def test_provider_rotation_security_event_is_bounded(caplog) -> None:
    scheduler = RotationScheduler(
        settings(), object(), object(), object(), {"anthropic": object()}
    )

    with caplog.at_level("INFO", logger="key_rotator.scheduler"):
        scheduler._audit_rotation_result(
            "anthropic",
            RotationResult(status="success", detail="secret provider response"),
            rotation_id=scheduler._new_rotation_id(),
            attempt=1,
        )
        scheduler._audit_rotation_result(
            "unreviewed-vendor",
            RotationResult(status="unexpected", detail="another secret"),
            rotation_id=scheduler._new_rotation_id(),
            attempt=1,
        )

    security_events = [
        json.loads(record.message.removeprefix("AIGW_SECURITY_EVENT "))
        for record in caplog.records
        if record.message.startswith("AIGW_SECURITY_EVENT ")
    ]
    assert [
        {key: value for key, value in event.items() if key != "rotation_id"}
        for event in security_events
    ] == [
        {
            "action": "rotate",
            "attempt": 1,
            "event": "aigw.provider.rotation",
            "outcome": "success",
            "rotation_status": "success",
            "schema_version": 1,
            "vendor": "anthropic",
        },
        {
            "action": "rotate",
            "attempt": 1,
            "event": "aigw.provider.rotation",
            "outcome": "failure",
            "rotation_status": "failed",
            "schema_version": 1,
            "vendor": "unknown",
        },
    ]
    for event in security_events:
        rotation_id = event["rotation_id"]
        assert UUID(rotation_id).version == 4
        assert str(UUID(rotation_id)) == rotation_id
    assert "provider response" not in caplog.text
    assert "another secret" not in caplog.text
    assert "unreviewed-vendor" not in caplog.text


@pytest.mark.asyncio
async def test_vault_state_security_event_emits_only_transitions(caplog) -> None:
    class VaultStates:
        def __init__(self) -> None:
            self.states = [
                {"initialized": False, "sealed": True},
                {"initialized": False, "sealed": True},
                {"initialized": True, "sealed": True},
                {"initialized": True, "sealed": False},
                VaultError("secret transport detail"),
            ]

        def public_status(self):
            state = self.states.pop(0)
            if isinstance(state, Exception):
                raise state
            return state

    scheduler = RotationScheduler(
        settings(), object(), VaultStates(), object(), {}
    )
    with caplog.at_level("INFO", logger="key_rotator.scheduler"):
        for _ in range(5):
            await scheduler._observe_vault_state()

    security_lines = [
        record.message
        for record in caplog.records
        if record.message.startswith("AIGW_SECURITY_EVENT ")
    ]
    assert len(security_lines) == 4
    assert '"state":"uninitialized"' in security_lines[0]
    assert '"state":"sealed"' in security_lines[1]
    assert '"state":"unsealed"' in security_lines[2]
    assert '"state":"unavailable"' in security_lines[3]
    assert "secret transport detail" not in caplog.text


class SchedulerDB:
    def __init__(self, *rows: dict) -> None:
        self.rows = {row["vendor"]: copy.deepcopy(row) for row in rows}
        self.history: list[tuple] = []
        self.unavailable_lookups = 0

    async def list_settings(self) -> list[dict]:
        return [copy.deepcopy(self.rows[key]) for key in sorted(self.rows)]

    async def get_settings(self, vendor: str):
        if self.unavailable_lookups:
            self.unavailable_lookups -= 1
            return None
        row = self.rows.get(vendor)
        return copy.deepcopy(row) if row is not None else None

    @asynccontextmanager
    async def rotation_lock(self, vendor: str):
        yield True

    async def record_history(self, *values) -> None:
        self.history.append(values)

    async def upsert_settings(
        self,
        vendor: str,
        enabled: bool,
        interval_seconds: int,
        grace_seconds: int,
        config,
    ) -> None:
        current = self.rows.get(vendor, {"vendor": vendor, "config": {}})
        current.update(
            {
                "enabled": enabled,
                "interval_seconds": interval_seconds,
                "grace_seconds": grace_seconds,
            }
        )
        if config is not None:
            current["config"] = copy.deepcopy(config)
        self.rows[vendor] = current


class SequenceDriver:
    def __init__(self, *results: RotationResult) -> None:
        self.results = list(results)
        self.calls = 0

    async def rotate(self, ctx: DriverContext) -> RotationResult:
        result = self.results[min(self.calls, len(self.results) - 1)]
        self.calls += 1
        return result


class SelfDisablingDriver(SequenceDriver):
    async def rotate(self, ctx: DriverContext) -> RotationResult:
        self.calls += 1
        await ctx.db.upsert_settings(
            "static-anthropic",
            enabled=False,
            interval_seconds=0,
            grace_seconds=0,
            config={},
        )
        return RotationResult(
            status="success",
            detail="seed complete",
            settings_self_disabled=True,
        )


def zero_interval_row(vendor: str = "static-anthropic") -> dict:
    return {
        "vendor": vendor,
        "enabled": True,
        "interval_seconds": 0,
        "grace_seconds": 0,
        "config": {},
    }


def remove_canonical_job(scheduler: RotationScheduler, vendor: str) -> None:
    """Model APScheduler's DateTrigger removal before async execution."""
    scheduler._scheduler.remove_job(f"rotate_{vendor}")


@pytest.mark.asyncio
async def test_zero_interval_defers_while_vault_sealed_then_runs_once() -> None:
    vendor = "static-anthropic"
    db = SchedulerDB(zero_interval_row(vendor))
    vault = SchedulerVault(ready=False)
    driver = SequenceDriver(RotationResult(status="success", detail="seeded"))
    scheduler = RotationScheduler(settings(), db, vault, object(), {vendor: driver})

    await scheduler.reload()
    remove_canonical_job(scheduler, vendor)
    assert await scheduler._run_oneshot(vendor) is None
    assert driver.calls == 0
    assert db.history == []
    deferred = scheduler._scheduler.get_job(f"rotate_{vendor}")
    assert deferred is not None
    assert isinstance(deferred.trigger, DateTrigger)
    assert deferred.trigger.run_date >= datetime.now(timezone.utc) + timedelta(
        seconds=25
    )

    vault.is_ready = True
    remove_canonical_job(scheduler, vendor)
    result = await scheduler._run_oneshot(vendor)
    assert result is not None and result.status == "success"
    assert driver.calls == 1
    assert len(db.history) == 1
    assert scheduler._scheduler.get_job(f"rotate_{vendor}") is None

    # A normal settings reload after a terminal outcome must not consume the
    # process-lifetime one-shot a second time.
    await scheduler.reload()
    assert scheduler._scheduler.get_job(f"rotate_{vendor}") is None
    assert driver.calls == 1


@pytest.mark.asyncio
async def test_zero_interval_explicit_transient_retry_is_bounded_and_rearmed() -> None:
    vendor = "static-anthropic"
    db = SchedulerDB(zero_interval_row(vendor))
    vault = SchedulerVault(ready=True)
    driver = SequenceDriver(
        RotationResult(status="failed", detail="transient", next_run_seconds=0.01),
        RotationResult(status="success", detail="recovered"),
    )
    scheduler = RotationScheduler(settings(), db, vault, object(), {vendor: driver})

    await scheduler.reload()
    remove_canonical_job(scheduler, vendor)
    first = await scheduler._run_oneshot(vendor)
    assert first is not None and first.status == "failed"
    assert len(db.history) == 1
    retry = scheduler._scheduler.get_job(f"rotate_{vendor}")
    assert retry is not None
    # Driver-selected retries cannot become a tight loop.
    assert retry.trigger.run_date >= datetime.now(timezone.utc) + timedelta(seconds=4)

    remove_canonical_job(scheduler, vendor)
    second = await scheduler._run_oneshot(vendor)
    assert second is not None and second.status == "success"
    assert driver.calls == 2
    assert len(db.history) == 2
    assert scheduler._scheduler.get_job(f"rotate_{vendor}") is None


@pytest.mark.asyncio
async def test_zero_interval_generic_failure_does_not_retry_forever() -> None:
    vendor = "static-anthropic"
    db = SchedulerDB(zero_interval_row(vendor))
    vault = SchedulerVault(ready=True)
    driver = SequenceDriver(
        RotationResult(status="failed", detail="permanent auth error")
    )
    scheduler = RotationScheduler(settings(), db, vault, object(), {vendor: driver})

    await scheduler.reload()
    remove_canonical_job(scheduler, vendor)
    result = await scheduler._run_oneshot(vendor)

    assert result is not None and result.status == "failed"
    assert len(db.history) == 1
    assert scheduler._scheduler.get_job(f"rotate_{vendor}") is None
    await scheduler.reload()
    assert scheduler._scheduler.get_job(f"rotate_{vendor}") is None


@pytest.mark.asyncio
async def test_zero_interval_reload_does_not_duplicate_deferred_job() -> None:
    vendor = "static-anthropic"
    db = SchedulerDB(zero_interval_row(vendor))
    vault = SchedulerVault(ready=False)
    driver = SequenceDriver(RotationResult(status="success"))
    scheduler = RotationScheduler(settings(), db, vault, object(), {vendor: driver})

    await scheduler.reload()
    remove_canonical_job(scheduler, vendor)
    await scheduler._run_oneshot(vendor)
    before = scheduler._scheduler.get_job(f"rotate_{vendor}").trigger.run_date

    await scheduler.reload()
    matching = [
        job for job in scheduler._scheduler.get_jobs() if job.id == f"rotate_{vendor}"
    ]
    assert len(matching) == 1
    assert matching[0].trigger.run_date == before
    assert driver.calls == 0
    assert db.history == []


@pytest.mark.asyncio
async def test_zero_interval_success_self_disable_allows_later_reenable() -> None:
    vendor = "static-anthropic"
    db = SchedulerDB(zero_interval_row(vendor))
    vault = SchedulerVault(ready=True)
    driver = SelfDisablingDriver(RotationResult(status="success"))
    scheduler = RotationScheduler(settings(), db, vault, object(), {vendor: driver})

    await scheduler.reload()
    remove_canonical_job(scheduler, vendor)
    result = await scheduler._run_oneshot(vendor)
    assert result is not None and result.status == "success"
    assert vendor not in scheduler._oneshot_scheduled
    assert scheduler._scheduler.get_job(f"rotate_{vendor}") is None

    db.rows[vendor]["enabled"] = True
    await scheduler.reload()
    assert vendor in scheduler._oneshot_scheduled
    assert scheduler._scheduler.get_job(f"rotate_{vendor}") is not None


@pytest.mark.asyncio
async def test_manual_self_disable_clears_latch_before_later_reenable() -> None:
    vendor = "static-anthropic"
    db = SchedulerDB(zero_interval_row(vendor))
    vault = SchedulerVault(ready=True)
    driver = SelfDisablingDriver(RotationResult(status="success"))
    scheduler = RotationScheduler(settings(), db, vault, object(), {vendor: driver})

    # Model a previously completed canonical one-shot: its process latch
    # remains, but its DateTrigger is gone. Rotate now uses run_rotation
    # directly rather than _run_oneshot.
    await scheduler.reload()
    remove_canonical_job(scheduler, vendor)
    assert await scheduler.trigger_now(vendor)
    manual = next(
        job
        for job in scheduler._scheduler.get_jobs()
        if job.id.startswith(f"rotate_{vendor}_manual_")
    )
    scheduler._scheduler.remove_job(manual.id)
    result = await manual.func(*manual.args, **manual.kwargs)

    assert result.settings_self_disabled is True
    assert db.rows[vendor]["enabled"] is False
    assert vendor not in scheduler._oneshot_scheduled

    db.rows[vendor]["enabled"] = True
    await scheduler.reload()
    assert scheduler._scheduler.get_job(f"rotate_{vendor}") is not None


@pytest.mark.asyncio
async def test_self_disable_settings_read_loss_defers_gated_reconciliation() -> None:
    vendor = "static-anthropic"
    db = SchedulerDB(zero_interval_row(vendor))
    vault = SchedulerVault(ready=True)

    class SelfDisableThenLoseSettingsDriver:
        def __init__(self) -> None:
            self.calls = 0

        async def rotate(self, ctx: DriverContext) -> RotationResult:
            self.calls += 1
            await ctx.db.upsert_settings(
                vendor,
                enabled=False,
                interval_seconds=0,
                grace_seconds=0,
                config={},
            )
            ctx.db.unavailable_lookups = 1
            return RotationResult(
                status="success",
                detail="seed complete",
                settings_self_disabled=True,
            )

    driver = SelfDisableThenLoseSettingsDriver()
    scheduler = RotationScheduler(settings(), db, vault, object(), {vendor: driver})
    await scheduler.reload()
    remove_canonical_job(scheduler, vendor)
    result = await scheduler._run_oneshot(vendor)

    assert result is not None and result.settings_self_disabled is True
    assert driver.calls == 1
    assert vendor in scheduler._oneshot_scheduled
    deferred = scheduler._scheduler.get_job(f"rotate_{vendor}")
    assert deferred is not None
    assert deferred.trigger.run_date >= datetime.now(timezone.utc) + timedelta(
        seconds=25
    )

    # The gated recheck sees the still-disabled row and clears the lifecycle
    # without a second driver invocation or history row.
    remove_canonical_job(scheduler, vendor)
    assert await scheduler._run_oneshot(vendor) is None
    assert driver.calls == 1
    assert len(db.history) == 1
    assert vendor not in scheduler._oneshot_scheduled
    assert scheduler._scheduler.get_job(f"rotate_{vendor}") is None


@pytest.mark.asyncio
async def test_zero_interval_dynamic_result_recreates_removed_date_trigger() -> None:
    vendor = "anthropic"
    db = SchedulerDB(zero_interval_row(vendor))
    vault = SchedulerVault(ready=True)
    driver = SequenceDriver(
        RotationResult(status="success", detail="minted", next_run_seconds=120)
    )
    scheduler = RotationScheduler(settings(), db, vault, object(), {vendor: driver})

    await scheduler.reload()
    remove_canonical_job(scheduler, vendor)
    result = await scheduler._run_oneshot(vendor)
    assert result is not None and result.next_run_seconds == 120
    dynamic = scheduler._scheduler.get_job(f"rotate_{vendor}")
    assert dynamic is not None
    assert isinstance(dynamic.trigger, DateTrigger)
    assert dynamic.func == scheduler._run_oneshot
    assert dynamic.trigger.run_date >= datetime.now(timezone.utc) + timedelta(
        seconds=115
    )


@pytest.mark.asyncio
async def test_dynamic_rearm_survives_transient_latest_settings_failure() -> None:
    vendor = "anthropic"
    db = SchedulerDB(zero_interval_row(vendor))
    vault = SchedulerVault(ready=True)
    driver = SequenceDriver(RotationResult(status="success", detail="recovered"))
    scheduler = RotationScheduler(settings(), db, vault, object(), {vendor: driver})

    await scheduler.reload()
    remove_canonical_job(scheduler, vendor)
    db.unavailable_lookups = 1
    assert await scheduler._reschedule_dynamic(vendor, 120) is True
    deferred = scheduler._scheduler.get_job(f"rotate_{vendor}")
    assert deferred is not None
    assert deferred.func == scheduler._run_oneshot
    assert deferred.trigger.run_date >= datetime.now(timezone.utc) + timedelta(
        seconds=115
    )
    assert db.history == []

    remove_canonical_job(scheduler, vendor)
    result = await scheduler._run_oneshot(vendor)
    assert result is not None and result.status == "success"
    assert driver.calls == 1
    assert len(db.history) == 1


@pytest.mark.asyncio
async def test_zero_interval_dynamic_result_cannot_undo_inflight_disable() -> None:
    vendor = "static-anthropic"
    db = SchedulerDB(zero_interval_row(vendor))
    vault = SchedulerVault(ready=True)

    class DisableThenRetryDriver:
        async def rotate(self, ctx: DriverContext) -> RotationResult:
            ctx.db.rows[vendor]["enabled"] = False
            return RotationResult(
                status="failed", detail="disabled concurrently", next_run_seconds=60
            )

    scheduler = RotationScheduler(
        settings(), db, vault, object(), {vendor: DisableThenRetryDriver()}
    )
    await scheduler.reload()
    remove_canonical_job(scheduler, vendor)
    result = await scheduler._run_oneshot(vendor)

    assert result is not None and result.status == "failed"
    assert scheduler._scheduler.get_job(f"rotate_{vendor}") is None
    assert vendor not in scheduler._oneshot_scheduled


@pytest.mark.asyncio
async def test_static_seed_marks_only_vault_error_for_bounded_retry() -> None:
    class SealedVault:
        def read(self, path: str):
            raise VaultError("token=do-not-export-vault-error")

    db = SchedulerDB(zero_interval_row("static-anthropic"))
    ctx = DriverContext(
        settings=settings(),
        vault=SealedVault(),
        litellm=object(),
        db=db,
        vendor_settings=zero_interval_row("static-anthropic"),
    )
    result = await StaticSeedDriver("anthropic").rotate(ctx)

    assert result.status == "failed"
    assert result.detail == "vault read failed while seeding anthropic"
    assert "do-not-export-vault-error" not in result.detail
    assert result.next_run_seconds == VAULT_RETRY_SECONDS
    assert result.settings_self_disabled is False


@pytest.mark.asyncio
async def test_static_seed_success_explicitly_reports_self_disable() -> None:
    class SeedVault:
        def read(self, path: str):
            return {"api_key": "static-test-key"}

    class RecordingLiteLLM:
        async def upsert_credential(self, name: str, values: dict) -> None:
            assert name == "anthropic-primary"
            assert values == {"api_key": "static-test-key"}

    db = SchedulerDB(zero_interval_row("static-anthropic"))
    ctx = DriverContext(
        settings=settings(),
        vault=SeedVault(),
        litellm=RecordingLiteLLM(),
        db=db,
        vendor_settings=zero_interval_row("static-anthropic"),
    )
    result = await StaticSeedDriver("anthropic").rotate(ctx)

    assert result.status == "success"
    assert result.detail == (
        "seeded LiteLLM credential=anthropic-primary from reviewed Vault path"
    )
    assert "static-test-key" not in result.detail
    assert result.settings_self_disabled is True
    assert db.rows["static-anthropic"]["enabled"] is False


def test_settings_update_omission_preserves_driver_config_contract() -> None:
    omitted = SettingsUpdate(enabled=True, interval_seconds=3600, grace_seconds=300)
    explicit_reset = SettingsUpdate(
        enabled=True, interval_seconds=3600, grace_seconds=300, config={}
    )
    assert omitted.config is None
    assert explicit_reset.config == {}


class RecordingCursor:
    def __init__(self):
        self.calls = []
        self.rowcount = 1

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def execute(self, sql, params=()):
        self.calls.append((" ".join(sql.split()), params))


class RecordingConnection:
    def __init__(self):
        self.cursor_obj = RecordingCursor()

    def cursor(self):
        return self.cursor_obj


@pytest.mark.asyncio
async def test_brownfield_openai_rows_are_disabled_without_deletion() -> None:
    db = Database(settings())
    conn = RecordingConnection()
    db._conn = conn

    await db._disable_retired_settings()

    sql, params = conn.cursor_obj.calls[-1]
    assert sql.startswith("UPDATE rotator_settings")
    assert "SET enabled = false" in sql
    assert "DELETE" not in sql
    assert params == (list(RETIRED_SETTINGS_VENDORS),)


@pytest.mark.asyncio
async def test_database_writers_own_disjoint_settings_columns(monkeypatch) -> None:
    db = Database(settings())
    conn = RecordingConnection()

    async def ensure_conn():
        return conn

    monkeypatch.setattr(db, "_ensure_conn", ensure_conn)

    await db.upsert_settings("anthropic", True, 1800, 120, None)
    control_sql = conn.cursor_obj.calls[-1][0]
    assert "config = EXCLUDED.config" not in control_sql
    assert "interval_seconds = EXCLUDED.interval_seconds" in control_sql

    await db.update_settings_config("anthropic", {"_fail_count": 2})
    state_sql = conn.cursor_obj.calls[-1][0]
    assert "SET config = %s::jsonb" in state_sql
    assert "interval_seconds" not in state_sql
    assert "enabled" not in state_sql


class FailingStateDB(FakeDB):
    async def update_settings_config(self, vendor, config):
        raise RuntimeError("postgres unavailable")


class DeterministicAnthropicDriver(AnthropicWifDriver):
    async def _get_keycloak_jwt(self, ctx, bootstrap):
        return "keycloak-assertion"

    async def _exchange_anthropic_token(self, ctx, bootstrap, assertion):
        assert assertion == "keycloak-assertion"
        return "short-lived-anthropic-token", 3600


class AnthropicLifecycleDB(FakeDB):
    def __init__(self, events, *, fail_issued=False) -> None:
        super().__init__()
        self.events = events
        self.fail_issued = fail_issued
        self.durable_config = {}

    async def update_settings_config(self, vendor, config):
        assert vendor == "anthropic"
        lifecycle = config.get(CREDENTIAL_LIFECYCLE_FIELD)
        self.events.append(("state", lifecycle))
        if self.fail_issued and lifecycle == CREDENTIAL_ISSUED:
            raise RuntimeError("issued-state persistence failed")
        self.durable_config = copy.deepcopy(config)


class AnthropicLifecycleLiteLLM:
    def __init__(self, events, db) -> None:
        self.events = events
        self.db = db

    async def upsert_credential(self, name, values):
        assert name == "anthropic-primary"
        assert values == {"api_key": "short-lived-anthropic-token"}
        assert (
            self.db.durable_config.get(CREDENTIAL_LIFECYCLE_FIELD)
            == CREDENTIAL_PROMOTION_PENDING
        )
        self.events.append(("promotion", name))


def anthropic_lifecycle_context(db, litellm) -> DriverContext:
    vault = FakeVault()
    vault.docs["ai-gateway/anthropic-wif"] = {
        "kc_token_url": (
            "http://keycloak:8080/realms/anthropic-wif/"
            "protocol/openid-connect/token"
        ),
        "kc_client_id": "anthropic-token-broker",
        "federation_rule_id": "fed_123",
        "organization_id": "org_123",
        "service_account_id": "svc_123",
    }
    return DriverContext(
        settings=settings(),
        vault=vault,
        litellm=litellm,
        db=db,
        vendor_settings={
            "enabled": True,
            "interval_seconds": 3000,
            "config": {
                CREDENTIAL_LIFECYCLE_FIELD: CREDENTIAL_ISSUED,
                "_last_issued_at": 1,
                "_last_expires_in": 1,
            },
        },
    )


@pytest.mark.asyncio
async def test_anthropic_persists_pending_before_promotion_then_issued() -> None:
    events: list[tuple[str, object]] = []
    db = AnthropicLifecycleDB(events)
    litellm = AnthropicLifecycleLiteLLM(events, db)

    result = await DeterministicAnthropicDriver().rotate(
        anthropic_lifecycle_context(db, litellm)
    )

    assert result.status == "success"
    assert events == [
        ("state", CREDENTIAL_PROMOTION_PENDING),
        ("promotion", "anthropic-primary"),
        ("state", CREDENTIAL_ISSUED),
    ]
    assert db.durable_config[CREDENTIAL_LIFECYCLE_FIELD] == CREDENTIAL_ISSUED
    assert db.durable_config["_last_expires_in"] == 3600


@pytest.mark.asyncio
async def test_anthropic_promotion_state_failure_remains_durably_pending() -> None:
    events: list[tuple[str, object]] = []
    db = AnthropicLifecycleDB(events, fail_issued=True)
    litellm = AnthropicLifecycleLiteLLM(events, db)

    result = await DeterministicAnthropicDriver().rotate(
        anthropic_lifecycle_context(db, litellm)
    )

    assert result.status == "failed"
    assert ("promotion", "anthropic-primary") in events
    assert db.durable_config[CREDENTIAL_LIFECYCLE_FIELD] == (
        CREDENTIAL_PROMOTION_PENDING
    )
    # Both the post-promotion proof write and the failure-state retry reject;
    # neither can overwrite the durable pre-promotion ambiguity marker.
    assert events.count(("state", CREDENTIAL_ISSUED)) == 2


@pytest.mark.asyncio
async def test_anthropic_failure_keeps_retry_deadline_when_state_db_is_down() -> None:
    ctx = DriverContext(
        settings=settings(),
        vault=FakeVault(),
        litellm=object(),
        db=FailingStateDB(),
        vendor_settings={
            "enabled": True,
            "interval_seconds": 3000,
            "config": {"_last_issued_at": 1, "_last_expires_in": 3600},
        },
    )

    result = await AnthropicWifDriver()._handle_failure(
        ctx,
        dict(ctx.vendor_settings["config"]),
        RuntimeError("exchange failed"),
        stage="token_exchange",
    )

    assert result.status == "failed"
    assert result.detail == (
        "rotation failed: stage=token_exchange reason=internal_failure"
    )
    assert result.next_run_seconds is not None
    assert 0 < result.next_run_seconds <= 1800
