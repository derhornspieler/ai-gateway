from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import runpy
import stat
import sys
import time
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
CALLBACK = ROOT / "compose/litellm/aigw_otel_callback.py"
IDENTITY_HELPER = ROOT / "compose/litellm/aigw_openwebui_identity.py"
COMPOSE = ROOT / "compose/docker-compose.yml"
ENV_TEMPLATE = ROOT / "ansible/roles/docker_stack/templates/env.j2"
PREPROD = ROOT / "scripts/preprod.py"
SECRET = "a" * 64


class InvalidTokenError(Exception):
    pass


def _encoded(value: dict) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def signed_token(claims: dict, *, secret: str = SECRET, algorithm: str = "HS256") -> str:
    header = _encoded({"alg": algorithm, "typ": "JWT"})
    payload = _encoded(claims)
    signing_input = f"{header}.{payload}"
    signature = hmac.new(
        secret.encode(), signing_input.encode(), hashlib.sha256
    ).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
    return f"{signing_input}.{encoded_signature}"


def fake_jwt_decode(
    token: str,
    key: str,
    *,
    algorithms: list[str],
    issuer: str,
    leeway: int,
    options: dict,
) -> dict:
    del leeway
    try:
        header_text, payload_text, supplied_signature = token.split(".")
        header = json.loads(
            base64.urlsafe_b64decode(header_text + "=" * (-len(header_text) % 4))
        )
        claims = json.loads(
            base64.urlsafe_b64decode(payload_text + "=" * (-len(payload_text) % 4))
        )
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InvalidTokenError from error
    if header.get("alg") != "HS256" or header.get("alg") not in algorithms:
        raise InvalidTokenError
    signing_input = f"{header_text}.{payload_text}"
    expected = base64.urlsafe_b64encode(
        hmac.new(key.encode(), signing_input.encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    if not hmac.compare_digest(expected, supplied_signature):
        raise InvalidTokenError
    if claims.get("iss") != issuer:
        raise InvalidTokenError
    if any(name not in claims for name in options.get("require", [])):
        raise InvalidTokenError
    return claims


class FakeOpenTelemetryConfig:
    def __init__(self, **values) -> None:
        self.values = values


class FakeOpenTelemetry:
    def __init__(self, config) -> None:
        self.config = config

    def set_attributes(self, span, kwargs, response_obj) -> None:
        del kwargs, response_obj
        span.parent_called = True

    def safe_set_attribute(self, span, key, value) -> None:
        span.set_attribute(key, value)


class FakeExporter:
    def __init__(self, **values) -> None:
        self.values = values


class FakeBatchSpanProcessor:
    def __init__(self, exporter) -> None:
        self.exporter = exporter


class FakeSpan:
    def __init__(self) -> None:
        self.attributes: dict[str, str] = {}
        self.parent_called = False

    def set_attribute(self, key: str, value: str) -> None:
        self.attributes[key] = value


def stub_modules() -> dict[str, types.ModuleType]:
    jwt_module = types.ModuleType("jwt")
    jwt_module.InvalidTokenError = InvalidTokenError
    jwt_module.decode = fake_jwt_decode

    litellm = types.ModuleType("litellm")
    integrations = types.ModuleType("litellm.integrations")
    otel = types.ModuleType("litellm.integrations.opentelemetry")
    otel.OpenTelemetry = FakeOpenTelemetry
    otel.OpenTelemetryConfig = FakeOpenTelemetryConfig

    opentelemetry = types.ModuleType("opentelemetry")
    exporter = types.ModuleType("opentelemetry.exporter")
    exporter_otlp = types.ModuleType("opentelemetry.exporter.otlp")
    exporter_proto = types.ModuleType("opentelemetry.exporter.otlp.proto")
    exporter_http = types.ModuleType("opentelemetry.exporter.otlp.proto.http")
    trace_exporter = types.ModuleType(
        "opentelemetry.exporter.otlp.proto.http.trace_exporter"
    )
    trace_exporter.OTLPSpanExporter = FakeExporter
    sdk = types.ModuleType("opentelemetry.sdk")
    sdk_trace = types.ModuleType("opentelemetry.sdk.trace")
    sdk_trace_export = types.ModuleType("opentelemetry.sdk.trace.export")
    sdk_trace_export.BatchSpanProcessor = FakeBatchSpanProcessor

    return {
        "jwt": jwt_module,
        "litellm": litellm,
        "litellm.integrations": integrations,
        "litellm.integrations.opentelemetry": otel,
        "opentelemetry": opentelemetry,
        "opentelemetry.exporter": exporter,
        "opentelemetry.exporter.otlp": exporter_otlp,
        "opentelemetry.exporter.otlp.proto": exporter_proto,
        "opentelemetry.exporter.otlp.proto.http": exporter_http,
        "opentelemetry.exporter.otlp.proto.http.trace_exporter": trace_exporter,
        "opentelemetry.sdk": sdk,
        "opentelemetry.sdk.trace": sdk_trace,
        "opentelemetry.sdk.trace.export": sdk_trace_export,
    }


def request_kwargs(
    *,
    owner: object = "subject-123",
    alias: object = "laptop",
    auth_metadata: object = None,
    headers: object = None,
    end_user: object = "caller-controlled",
    identity_verified: bool = False,
) -> dict:
    proxy_request = {"headers": headers or {}}
    if identity_verified:
        proxy_request["aigw_openwebui_identity_gate_v1"] = True
    return {
        "standard_logging_object": {
            "metadata": {
                "user_api_key_user_id": owner,
                "user_api_key_alias": alias,
                "user_api_key_auth_metadata": auth_metadata,
                "user_api_key_end_user_id": end_user,
            }
        },
        "litellm_params": {
            "proxy_server_request": proxy_request,
            "metadata": {},
        },
    }


def valid_claims(now: int) -> dict:
    return {
        "sub": "openwebui-user-123",
        "email": "directory.user",
        "name": "Directory User",
        "role": "user",
        "iss": "open-webui",
        "iat": now,
        "exp": now + 120,
    }


class LiteLLMOtelIdentityContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        modules = stub_modules()
        regular_file = SimpleNamespace(st_mode=stat.S_IFREG | 0o400, st_nlink=1)
        with (
            patch.dict(sys.modules, modules),
            patch.dict(
                os.environ,
                {
                    "AIGW_DEPLOYMENT_ENVIRONMENT": "preprod",
                    "OPENWEBUI_FORWARD_JWT_SECRET": SECRET,
                },
            ),
            patch("os.open", return_value=9),
            patch("os.fstat", return_value=regular_file),
            patch("os.read", return_value=b"b" * 64),
            patch("os.close"),
        ):
            identity_module = types.ModuleType("aigw_openwebui_identity")
            identity_module.__dict__.update(runpy.run_path(str(IDENTITY_HELPER)))
            sys.modules["aigw_openwebui_identity"] = identity_module
            cls.identity = identity_module.__dict__
            cls.callback = runpy.run_path(str(CALLBACK))

    def test_startup_secret_is_exact_lowercase_hex(self) -> None:
        reader = self.identity["read_openwebui_forward_jwt_secret"]
        with patch.dict(os.environ, {"OPENWEBUI_FORWARD_JWT_SECRET": SECRET}):
            self.assertEqual(reader(), SECRET)
        for invalid in ("", "A" * 64, "a" * 63, "a" * 65, "a" * 63 + "\n"):
            with self.subTest(invalid=repr(invalid)):
                with patch.dict(
                    os.environ,
                    {"OPENWEBUI_FORWARD_JWT_SECRET": invalid},
                ):
                    with self.assertRaises(RuntimeError):
                        reader()
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(RuntimeError):
                reader()

    def test_one_domain_separated_key_is_wired_to_both_services(self) -> None:
        compose = COMPOSE.read_text(encoding="utf-8")
        mapping = (
            "${OPENWEBUI_FORWARD_JWT_SECRET:?"
            "OPENWEBUI_FORWARD_JWT_SECRET must be set}"
        )
        self.assertIn(f"OPENWEBUI_FORWARD_JWT_SECRET: {mapping}", compose)
        self.assertIn(f"FORWARD_USER_INFO_HEADER_JWT_SECRET: {mapping}", compose)
        self.assertIn(
            "FORWARD_USER_INFO_HEADER_JWT: X-OpenWebUI-User-Jwt", compose
        )
        self.assertIn(
            'FORWARD_USER_INFO_HEADER_JWT_EXPIRES_SECONDS: "120"', compose
        )

        env_template = ENV_TEMPLATE.read_text(encoding="utf-8")
        self.assertIn(
            "OPENWEBUI_FORWARD_JWT_SECRET={{ "
            "('aigw-openwebui-forward-jwt-v1:' ~ webui_secret_key) "
            "| hash('sha256') }}",
            env_template,
        )
        self.assertNotIn("OPENWEBUI_FORWARD_JWT_SECRET={{ webui_secret_key", env_template)

        preprod = PREPROD.read_text(encoding="utf-8")
        self.assertIn('"OPENWEBUI_FORWARD_JWT_SECRET": static_hex(', preprod)
        self.assertIn('"openwebui-forward-jwt", 64', preprod)

        callback = CALLBACK.read_text(encoding="utf-8")
        self.assertIn('litellm_params.get("proxy_server_request")', callback)
        self.assertIn('proxy_request.get("headers")', callback)
        self.assertNotIn('for metadata_name in ("metadata", "litellm_metadata")', callback)

        shared = IDENTITY_HELPER.read_text(encoding="utf-8")
        self.assertIn("def openwebui_jwt_from_headers(headers)", shared)
        self.assertIn("def verified_openwebui_username(", shared)
        self.assertIn("def verified_openwebui_identity(", shared)

    def test_portal_key_metadata_wins_over_every_caller_claim(self) -> None:
        resolver = self.callback["_resolved_server_identity"]
        kwargs = request_kwargs(
            auth_metadata={
                "created_via": "dev-portal",
                "aigw_project_id": "ai-gateway",
                "aigw_username": "directory.user",
            },
            headers={
                "X-OpenWebUI-User-Email": "spoofed-header",
                "X-LiteLLM-Customer-Id": "spoofed-customer",
            },
            end_user="spoofed-body-user",
        )
        self.assertEqual(
            resolver(kwargs, SECRET),
            (None, "directory.user", "portal_key_metadata"),
        )

    def test_portal_conflict_or_bad_username_falls_back_to_key_owner(self) -> None:
        resolver = self.callback["_resolved_server_identity"]
        cases = (
            {
                "created_via": "dev-portal",
                "aigw_username": "bad user",
            },
            {
                "created_via": "dev-portal",
                "aigw_username": "directory.user",
                "aigw_service": "open-webui",
            },
            {
                "created_via": "dev-portal",
                "aigw_username": "directory.user",
                "aigw_key_kind": "service",
            },
        )
        for auth_metadata in cases:
            with self.subTest(auth_metadata=auth_metadata):
                self.assertEqual(
                    resolver(
                        request_kwargs(auth_metadata=auth_metadata), SECRET
                    ),
                    (None, "subject-123", "key_subject"),
                )

    def test_signed_openwebui_identity_requires_the_exact_service_key(self) -> None:
        resolver = self.callback["_resolved_server_identity"]
        now = int(time.time())
        token = signed_token(valid_claims(now))
        exact = request_kwargs(
            owner="svc-open-webui",
            alias="aigw-open-webui-service",
            auth_metadata={
                "aigw_key_kind": "service",
                "aigw_service": "open-webui",
                "aigw_project_id": "open-webui",
            },
            headers={"X-OpenWebUI-User-Jwt": token},
            identity_verified=True,
        )
        self.assertEqual(
            resolver(exact, SECRET, now=now),
            (
                "openwebui-user-123",
                "directory.user",
                "open_webui_signed_oidc",
            ),
        )
        ungated = request_kwargs(
            owner="svc-open-webui",
            alias="aigw-open-webui-service",
            auth_metadata={
                "aigw_key_kind": "service",
                "aigw_service": "open-webui",
                "aigw_project_id": "open-webui",
            },
            headers={"X-OpenWebUI-User-Jwt": token},
        )
        self.assertIsNone(resolver(ungated, SECRET, now=now))

        fabricated_metadata_path = request_kwargs(
            owner="svc-open-webui",
            alias="aigw-open-webui-service",
            auth_metadata={
                "aigw_key_kind": "service",
                "aigw_service": "open-webui",
                "aigw_project_id": "open-webui",
            },
            identity_verified=True,
        )
        fabricated_metadata_path["litellm_params"]["metadata"] = {
            "headers": {"X-OpenWebUI-User-Jwt": token}
        }
        self.assertEqual(
            resolver(fabricated_metadata_path, SECRET, now=now),
            None,
        )

        for changed in (
            request_kwargs(headers={"X-OpenWebUI-User-Jwt": token}),
            request_kwargs(
                owner="svc-open-webui",
                alias="wrong-alias",
                auth_metadata={
                    "aigw_key_kind": "service",
                    "aigw_service": "open-webui",
                    "aigw_project_id": "open-webui",
                },
                headers={"X-OpenWebUI-User-Jwt": token},
                identity_verified=True,
            ),
            request_kwargs(
                owner="svc-open-webui",
                alias="aigw-open-webui-service",
                auth_metadata={
                    "aigw_key_kind": "service",
                    "aigw_service": "open-webui",
                },
                headers={"X-OpenWebUI-User-Jwt": token},
                identity_verified=True,
            ),
        ):
            with self.subTest(changed=changed):
                expected_owner = changed["standard_logging_object"]["metadata"][
                    "user_api_key_user_id"
                ]
                self.assertEqual(
                    resolver(changed, SECRET, now=now),
                    (None, expected_owner, "key_subject"),
                )

    def test_invalid_openwebui_assertions_fall_back_without_claims(self) -> None:
        resolver = self.callback["_resolved_server_identity"]
        now = int(time.time())
        base = valid_claims(now)
        bad_claim_sets = []
        for required in ("sub", "email", "name", "role", "iss", "iat", "exp"):
            claims = dict(base)
            claims.pop(required)
            bad_claim_sets.append(claims)
        for name, value in (
            ("sub", "bad subject"),
            ("email", "bad username"),
            ("name", "bad\nname"),
            ("role", "bad role"),
            ("iat", True),
            ("exp", True),
        ):
            claims = dict(base)
            claims[name] = value
            bad_claim_sets.append(claims)
        for issued_at, expires_at in (
            (now, now),
            (now, now + 301),
            (now + 31, now + 60),
            (now - 400, now - 31),
        ):
            claims = dict(base, iat=issued_at, exp=expires_at)
            bad_claim_sets.append(claims)

        tokens = [signed_token(claims) for claims in bad_claim_sets]
        tokens.extend(
            (
                signed_token(base, secret="c" * 64),
                signed_token(base, algorithm="none"),
                signed_token(dict(base, iss="not-open-webui")),
                "not-a-jwt",
            )
        )
        for token in tokens:
            with self.subTest(token=token[:32]):
                kwargs = request_kwargs(
                    owner="svc-open-webui",
                    alias="aigw-open-webui-service",
                    auth_metadata={
                        "aigw_key_kind": "service",
                        "aigw_service": "open-webui",
                        "aigw_project_id": "open-webui",
                    },
                    headers={"X-OpenWebUI-User-Jwt": token},
                    identity_verified=True,
                )
                self.assertIsNone(resolver(kwargs, SECRET, now=now))

        unicode_name = dict(base, name="María 用户")
        unicode_kwargs = request_kwargs(
            owner="svc-open-webui",
            alias="aigw-open-webui-service",
            auth_metadata={
                "aigw_key_kind": "service",
                "aigw_service": "open-webui",
                "aigw_project_id": "open-webui",
            },
            headers={"X-OpenWebUI-User-Jwt": signed_token(unicode_name)},
            identity_verified=True,
        )
        self.assertEqual(
            resolver(unicode_kwargs, SECRET, now=now),
            (
                "openwebui-user-123",
                "directory.user",
                "open_webui_signed_oidc",
            ),
        )

    def test_signed_subjects_remain_distinct_despite_spoofed_body_identity(self) -> None:
        resolver = self.callback["_resolved_server_identity"]
        now = int(time.time())
        resolved = []
        for subject in ("openwebui-user-123", "openwebui-user-456"):
            kwargs = request_kwargs(
                owner="svc-open-webui",
                alias="aigw-open-webui-service",
                auth_metadata={
                    "aigw_key_kind": "service",
                    "aigw_service": "open-webui",
                    "aigw_project_id": "open-webui",
                },
                headers={
                    "X-OpenWebUI-User-Jwt": signed_token(
                        dict(valid_claims(now), sub=subject)
                    ),
                    "X-OpenWebUI-User-Email": "spoofed-header-user",
                },
                end_user="spoofed-body-user",
                identity_verified=True,
            )
            kwargs["optional_params"] = {"user": "spoofed-body-user"}
            resolved.append(resolver(kwargs, SECRET, now=now))

        self.assertEqual(
            resolved,
            [
                (
                    "openwebui-user-123",
                    "directory.user",
                    "open_webui_signed_oidc",
                ),
                (
                    "openwebui-user-456",
                    "directory.user",
                    "open_webui_signed_oidc",
                ),
            ],
        )

    def test_conflicting_jwt_headers_and_plain_identity_are_never_authority(self) -> None:
        resolver = self.callback["_resolved_server_identity"]
        now = int(time.time())
        token = signed_token(valid_claims(now))
        service = request_kwargs(
            owner="svc-open-webui",
            alias="aigw-open-webui-service",
            auth_metadata={
                "aigw_key_kind": "service",
                "aigw_service": "open-webui",
                "aigw_project_id": "open-webui",
            },
            headers={
                "X-OpenWebUI-User-Jwt": token,
                "x-openwebui-user-jwt": signed_token(
                    dict(valid_claims(now), email="other.user")
                ),
                "X-OpenWebUI-User-Email": "plain-header-user",
            },
            end_user="plain-end-user",
            identity_verified=True,
        )
        self.assertIsNone(resolver(service, SECRET, now=now))
        self.assertEqual(
            resolver(
                request_kwargs(
                    alias="friendly-alias",
                    headers={"X-OpenWebUI-User-Email": "plain-header-user"},
                    end_user="plain-end-user",
                ),
                SECRET,
                now=now,
            ),
            (None, "subject-123", "key_subject"),
        )

    def test_caller_body_metadata_cannot_override_server_key_identity(self) -> None:
        resolver = self.callback["_resolved_server_identity"]
        kwargs = request_kwargs(
            alias="friendly-alias",
            headers={"X-OpenWebUI-User-Email": "plain-header-user"},
            end_user="plain-end-user",
        )
        kwargs["optional_params"] = {"user": "plain-body-user"}
        kwargs["litellm_params"]["metadata"].update(
            {
                "user": "spoofed-metadata-user",
                "user_api_key_user_id": "spoofed-owner",
                "user_api_key_alias": "spoofed-alias",
                "user_api_key_auth_metadata": {
                    "created_via": "dev-portal",
                    "aigw_username": "spoofed-portal-user",
                },
            }
        )
        self.assertEqual(
            resolver(kwargs, SECRET),
            (None, "subject-123", "key_subject"),
        )

    def test_callback_stamps_only_bounded_server_fields(self) -> None:
        now = int(time.time())
        token = signed_token(valid_claims(now))
        callback = self.callback["aigw_otel"]
        span = FakeSpan()
        callback.set_attributes(
            span,
            request_kwargs(
                owner="svc-open-webui",
                alias="aigw-open-webui-service",
                auth_metadata={
                    "aigw_key_kind": "service",
                    "aigw_service": "open-webui",
                    "aigw_project_id": "open-webui",
                },
                headers={"X-OpenWebUI-User-Jwt": token},
                identity_verified=True,
            ),
            None,
        )
        self.assertTrue(span.parent_called)
        self.assertEqual(
            span.attributes,
            {
                "aigw.server.user.id": "openwebui-user-123",
                "aigw.server.user.name": "directory.user",
                "aigw.server.user.name_source": "open_webui_signed_oidc",
            },
        )
        serialized = json.dumps(span.attributes, sort_keys=True)
        self.assertNotIn(token, serialized)
        self.assertNotIn(SECRET, serialized)
        self.assertNotIn("X-OpenWebUI", serialized)

    def test_unbounded_key_owner_produces_no_identity(self) -> None:
        resolver = self.callback["_resolved_server_identity"]
        self.assertIsNone(
            resolver(
                request_kwargs(owner="bad owner", alias="friendly-alias"), SECRET
            )
        )

    def test_unresolved_identity_overwrites_preexisting_server_fields(self) -> None:
        callback = self.callback["aigw_otel"]
        span = FakeSpan()
        span.attributes = {
            "aigw.server.user.id": "spoofed-id",
            "aigw.server.user.name": "spoofed-user",
            "aigw.server.user.name_source": "portal_key_metadata",
        }
        callback.set_attributes(
            span,
            request_kwargs(owner="bad owner", alias="spoofed-alias"),
            None,
        )
        self.assertEqual(
            span.attributes,
            {
                "aigw.server.user.id": "",
                "aigw.server.user.name": "",
                "aigw.server.user.name_source": "unresolved",
            },
        )


if __name__ == "__main__":
    unittest.main()
