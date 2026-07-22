"""Contract + behavioral coverage for per-project default-model enforcement.

Two halves:

* Exact-string pins prove the reviewed enforcement wiring stays in place:
  the pre-call hook is bind-mounted read-only into LiteLLM, registered in
  ``litellm_settings.callbacks``, covered by the litellm bind-source digest,
  shipped by the docker_stack sync allowlist, inside the SELinux read-only
  bind boundary, and textually aligned with the portal/identity model-name
  grammar and metadata key.
* Behavioral tests load the hook with stubbed ``fastapi``/``litellm``
  modules (the real ones only exist inside the LiteLLM image) and assert the
  full request-resolution matrix: a request without a model resolves to the
  key's project default; explicit allowed models pass untouched; and every
  malformed-policy or out-of-allowlist condition denies — never loosens.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
from pathlib import Path
import re
import sys
import types
import unittest


ROOT = Path(__file__).resolve().parents[2]
HOOK = ROOT / "compose" / "litellm" / "aigw_default_model_hook.py"
LITELLM_CONFIG = ROOT / "compose" / "litellm" / "config.yaml"
COMPOSE = ROOT / "compose" / "docker-compose.yml"
DIGEST_INPUTS = ROOT / "compose" / "bind-source-digest-inputs.json"
DOCKER_STACK = ROOT / "ansible" / "roles" / "docker_stack" / "tasks" / "main.yml"
PORTAL_CLIENT = ROOT / "services" / "dev-portal" / "app" / "litellm_client.py"
IDENTITY = ROOT / "services" / "key-rotator" / "app" / "identity.py"

MODEL_NAME_RE_LITERAL = 're.compile(r"^[A-Za-z0-9][A-Za-z0-9_./:-]{0,127}$")'
# identity.py compiles the same grammar without anchors (it only ever uses
# fullmatch); the character-class body is the shared contract.
MODEL_NAME_GRAMMAR = "[A-Za-z0-9][A-Za-z0-9_./:-]{0,127}"
METADATA_KEY_LITERAL = '"aigw_default_model"'

_STUBBED_MODULES = (
    "aigw_openwebui_identity",
    "fastapi",
    "litellm",
    "litellm.integrations",
    "litellm.integrations.custom_logger",
    "aigw_default_model_hook",
)


class _StubHTTPException(Exception):
    def __init__(self, status_code: int, detail=None):
        super().__init__(status_code, detail)
        self.status_code = status_code
        self.detail = detail


def _load_hook_module():
    """Import the hook exactly as LiteLLM would, with stubbed dependencies.

    The stubs are registered before the import and removed afterwards so the
    rest of the suite never observes a fake ``fastapi``/``litellm``.
    """

    saved = {name: sys.modules.get(name) for name in _STUBBED_MODULES}

    fastapi_stub = types.ModuleType("fastapi")
    fastapi_stub.HTTPException = _StubHTTPException

    litellm_stub = types.ModuleType("litellm")
    integrations_stub = types.ModuleType("litellm.integrations")
    custom_logger_stub = types.ModuleType("litellm.integrations.custom_logger")
    callback_stub = types.ModuleType("aigw_openwebui_identity")
    callback_stub.OPENWEBUI_KEY_OWNER = "svc-open-webui"
    callback_stub.OPENWEBUI_KEY_ALIAS = "aigw-open-webui-service"
    callback_stub.OPENWEBUI_KEY_METADATA = {
        "aigw_key_kind": "service",
        "aigw_service": "open-webui",
        "aigw_project_id": "open-webui",
    }

    def read_secret():
        return "a" * 64

    def assertion_from_headers(headers):
        if not isinstance(headers, dict):
            return None
        matches = [
            value
            for name, value in headers.items()
            if isinstance(name, str)
            and name.lower() == "x-openwebui-user-jwt"
            and isinstance(value, str)
        ]
        return matches[0] if len(matches) == 1 else None

    def verified_username(token, secret):
        return (
            "directory.user"
            if token == "valid.jwt.token" and secret == "a" * 64
            else None
        )

    callback_stub.read_openwebui_forward_jwt_secret = read_secret
    callback_stub.openwebui_jwt_from_headers = assertion_from_headers
    callback_stub.verified_openwebui_username = verified_username

    class CustomLogger:  # minimal stand-in for the proxy base class
        pass

    custom_logger_stub.CustomLogger = CustomLogger
    litellm_stub.integrations = integrations_stub
    integrations_stub.custom_logger = custom_logger_stub

    sys.modules["aigw_openwebui_identity"] = callback_stub
    sys.modules["fastapi"] = fastapi_stub
    sys.modules["litellm"] = litellm_stub
    sys.modules["litellm.integrations"] = integrations_stub
    sys.modules["litellm.integrations.custom_logger"] = custom_logger_stub
    try:
        spec = importlib.util.spec_from_file_location(
            "aigw_default_model_hook", HOOK
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules["aigw_default_model_hook"] = module
        spec.loader.exec_module(module)
        return module
    finally:
        for name, original in saved.items():
            if original is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = original


class _KeyStub:
    def __init__(
        self, metadata=None, models=None, *, user_id=None, key_alias=None
    ):
        self.metadata = metadata
        self.models = models
        self.user_id = user_id
        self.key_alias = key_alias


class DefaultModelHookWiringContract(unittest.TestCase):
    """The enforcement wiring must never silently disappear."""

    def test_hook_is_bind_mounted_read_only_into_litellm(self) -> None:
        compose = COMPOSE.read_text(encoding="utf-8")
        self.assertIn(
            "- ./litellm/aigw_default_model_hook.py:"
            "/app/aigw_default_model_hook.py:ro,Z",
            compose,
        )
        self.assertIn(
            "- ./litellm/aigw_openwebui_identity.py:"
            "/app/aigw_openwebui_identity.py:ro,Z",
            compose,
        )
        # The hook must sit next to the config it is resolved relative to.
        self.assertIn("- ./litellm/config.yaml:/app/config.yaml:ro,Z", compose)

    def test_hook_is_registered_in_litellm_callbacks(self) -> None:
        config = LITELLM_CONFIG.read_text(encoding="utf-8")
        self.assertEqual(
            len(
                re.findall(
                    r"(?m)^  callbacks: \[\"aigw_otel_callback\.aigw_otel\", "
                    r"\"aigw_default_model_hook\."
                    r"aigw_default_model_enforcer\"\]$",
                    config,
                )
            ),
            1,
        )

    def test_hook_is_a_digested_bind_source(self) -> None:
        manifest = json.loads(DIGEST_INPUTS.read_text(encoding="utf-8"))
        self.assertEqual(
            manifest["base"]["litellm"],
            [
                "litellm/config.yaml",
                "litellm/aigw_default_model_hook.py",
                "litellm/aigw_openwebui_identity.py",
                "litellm/aigw_otel_callback.py",
                "secrets/litellm_otel_token",
            ],
        )

    def test_hook_ships_via_sync_allowlist_and_selinux_boundary(self) -> None:
        source = DOCKER_STACK.read_text(encoding="utf-8")
        sync = source.split(
            "- name: Sync allow-listed compose configuration files", 1
        )[1].split("- name: Render plane-specific container resolver lists", 1)[0]
        self.assertIn("- litellm/aigw_default_model_hook.py", sync)
        self.assertIn("- litellm/aigw_openwebui_identity.py", sync)
        self.assertIn("- litellm/aigw_otel_callback.py", sync)
        boundary = source.split(
            "- name: Define the exact SELinux read-only bind-source boundary", 1
        )[1]
        self.assertIn(
            "{'path': stack_dir ~ '/litellm/aigw_default_model_hook.py', "
            "'recursive': false},",
            boundary,
        )
        self.assertIn(
            "{'path': stack_dir ~ '/litellm/aigw_openwebui_identity.py', "
            "'recursive': false},",
            boundary,
        )
        self.assertIn(
            "{'path': stack_dir ~ '/litellm/aigw_otel_callback.py', "
            "'recursive': false},",
            boundary,
        )
        self.assertIn(
            "{'path': stack_dir ~ '/secrets/litellm_otel_token', "
            "'recursive': false},",
            boundary,
        )

    def test_model_grammar_and_metadata_key_stay_textually_identical(self) -> None:
        hook = HOOK.read_text(encoding="utf-8")
        portal = PORTAL_CLIENT.read_text(encoding="utf-8")
        identity = IDENTITY.read_text(encoding="utf-8")
        for source in (hook, portal):
            self.assertIn(MODEL_NAME_RE_LITERAL, source)
        for source in (hook, portal, identity):
            self.assertIn(MODEL_NAME_GRAMMAR, source)
        # The metadata field the hook reads is exactly the one the portal
        # stamps at mint and re-stamps on the retroactive policy re-tune.
        self.assertIn(
            f"DEFAULT_MODEL_METADATA_KEY = {METADATA_KEY_LITERAL}", hook
        )
        self.assertIn(
            f"PORTAL_DEFAULT_MODEL_METADATA_KEY = {METADATA_KEY_LITERAL}",
            portal,
        )

    def test_docstring_pins_the_sentinel_restricted_key_caveat(self) -> None:
        hook = HOOK.read_text(encoding="utf-8")
        self.assertIn(
            "Caveat — the ``aigw-default`` sentinel is best-effort, not a "
            "uniform\nguarantee: LiteLLM's own auth layer checks a "
            "request's ``model`` against\nthe key's model allowlist "
            "*before* this pre-call hook ever runs.",
            hook,
        )
        self.assertIn(
            "the\nsentinel string only ever resolves for keys with no "
            "model restriction (no\n``models`` list, or the "
            "``all-proxy-models`` wildcard). Callers that need\nthe "
            "project default honored unconditionally should OMIT "
            "``model`` from\nthe request rather than send the sentinel",
            hook,
        )

    def test_config_comment_pins_the_sentinel_restricted_key_caveat(self) -> None:
        config = LITELLM_CONFIG.read_text(encoding="utf-8")
        self.assertIn(
            "  # malformed default or one outside the key's model allowlist. "
            "Caveat: the\n"
            "  # `aigw-default` sentinel only reaches this hook for keys "
            "with no model\n"
            "  # allowlist (or the all-proxy-models wildcard) -- LiteLLM's "
            "own auth\n"
            "  # layer rejects an explicit \"aigw-default\" string on a "
            "restricted key\n"
            "  # before this hook runs. Callers should OMIT `model` to "
            "get the project\n"
            "  # default; that path is enforced here for every key.",
            config,
        )

    def test_hook_keeps_a_minimal_import_surface(self) -> None:
        hook = HOOK.read_text(encoding="utf-8")
        compile(hook, str(HOOK), "exec")
        for forbidden in ("subprocess", "socket", "urllib", "requests", "os"):
            self.assertNotIn(f"import {forbidden}", hook)


class DefaultModelResolutionBehavior(unittest.TestCase):
    """Request-time enforcement matrix for the pre-call hook."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.hook = _load_hook_module()

    def _run_hook(
        self,
        data,
        metadata=None,
        models=None,
        *,
        user_id=None,
        key_alias=None,
    ):
        key = _KeyStub(
            metadata=metadata,
            models=models,
            user_id=user_id,
            key_alias=key_alias,
        )
        return asyncio.run(
            self.hook.aigw_default_model_enforcer.async_pre_call_hook(
                key, None, data, "completion"
            )
        )

    def test_missing_model_resolves_to_the_projects_default(self) -> None:
        metadata = {
            "created_via": "dev-portal",
            "aigw_project_id": "ai-gateway",
            "aigw_default_model": "claude-haiku",
        }
        for request in (
            {},
            {"model": None},
            {"model": ""},
            {"model": "   "},
            {"model": "aigw-default"},
        ):
            data = self._run_hook(
                dict(request), metadata=metadata, models=["claude-haiku"]
            )
            self.assertEqual(data["model"], "claude-haiku")

    def test_explicit_model_choice_is_left_untouched(self) -> None:
        metadata = {"aigw_default_model": "claude-haiku"}
        data = self._run_hook(
            {"model": "claude-sonnet"},
            metadata=metadata,
            models=["claude-haiku", "claude-sonnet"],
        )
        self.assertEqual(data["model"], "claude-sonnet")

    def test_keys_without_a_default_are_treated_natively(self) -> None:
        # No portal default: a missing model stays missing so LiteLLM's own
        # rejection applies, and an explicit model passes through.
        data = self._run_hook({}, metadata={"created_via": "dev-portal"})
        self.assertNotIn("model", data)
        data = self._run_hook({"model": "gpt"}, metadata={})
        self.assertEqual(data["model"], "gpt")

    def test_sentinel_without_a_default_is_denied(self) -> None:
        with self.assertRaises(_StubHTTPException) as denied:
            self._run_hook({"model": "aigw-default"}, metadata={})
        self.assertEqual(denied.exception.status_code, 400)

    def test_malformed_default_denies_every_request(self) -> None:
        for bad_default in (None, 7, "", "bad model", "x" * 200):
            metadata = {"aigw_default_model": bad_default}
            for request in ({}, {"model": "claude-sonnet"}):
                with self.assertRaises(_StubHTTPException) as denied:
                    self._run_hook(dict(request), metadata=metadata)
                self.assertEqual(denied.exception.status_code, 400)

    def test_default_outside_the_key_allowlist_is_denied(self) -> None:
        metadata = {"aigw_default_model": "claude-haiku"}
        with self.assertRaises(_StubHTTPException) as denied:
            self._run_hook({}, metadata=metadata, models=["claude-sonnet"])
        self.assertEqual(denied.exception.status_code, 400)

    def test_unrestricted_and_wildcard_keys_accept_the_default(self) -> None:
        metadata = {"aigw_default_model": "claude-haiku"}
        for models in (None, [], ["all-proxy-models"]):
            data = self._run_hook({}, metadata=metadata, models=models)
            self.assertEqual(data["model"], "claude-haiku")

    def test_unreadable_metadata_fails_closed_when_a_default_is_needed(
        self,
    ) -> None:
        with self.assertRaises(_StubHTTPException) as denied:
            self._run_hook({}, metadata="not-a-dict")
        self.assertEqual(denied.exception.status_code, 400)
        # An explicit model on the same key stays governed by LiteLLM's
        # native allowlist enforcement instead.
        data = self._run_hook({"model": "claude-sonnet"}, metadata="not-a-dict")
        self.assertEqual(data["model"], "claude-sonnet")

    def test_non_string_model_is_denied(self) -> None:
        with self.assertRaises(_StubHTTPException):
            self._run_hook({"model": ["claude-sonnet"]}, metadata={})

    def test_non_dict_payloads_pass_through_unchanged(self) -> None:
        payload = ["not", "a", "dict"]
        self.assertIs(self._run_hook(payload, metadata={}), payload)

    def test_exact_openwebui_key_requires_one_valid_signed_assertion(self) -> None:
        metadata = {
            "aigw_key_kind": "service",
            "aigw_service": "open-webui",
            "aigw_project_id": "open-webui",
        }
        request = {
            "model": "claude-sonnet",
            "proxy_server_request": {
                "headers": {"X-OpenWebUI-User-Jwt": "valid.jwt.token"}
            },
            "secret_fields": {
                "raw_headers": {"X-OpenWebUI-User-Jwt": "valid.jwt.token"}
            },
        }
        result = self._run_hook(
            request,
            metadata=metadata,
            user_id="svc-open-webui",
            key_alias="aigw-open-webui-service",
        )
        self.assertIs(result, request)

    def test_openwebui_missing_invalid_expired_and_conflicting_assertions_deny(
        self,
    ) -> None:
        metadata = {
            "aigw_key_kind": "service",
            "aigw_service": "open-webui",
            "aigw_project_id": "open-webui",
        }
        cases = (
            ({}, {}),
            (
                {"X-OpenWebUI-User-Jwt": "invalid.jwt.token"},
                {"X-OpenWebUI-User-Jwt": "invalid.jwt.token"},
            ),
            (
                {"X-OpenWebUI-User-Jwt": "expired.jwt.token"},
                {"X-OpenWebUI-User-Jwt": "expired.jwt.token"},
            ),
            (
                {"X-OpenWebUI-User-Jwt": "other.jwt.token"},
                {"X-OpenWebUI-User-Jwt": "valid.jwt.token"},
            ),
        )
        for cleaned_headers, raw_headers in cases:
            with self.subTest(
                cleaned_headers=cleaned_headers, raw_headers=raw_headers
            ):
                with self.assertRaises(_StubHTTPException) as denied:
                    self._run_hook(
                        {
                            "model": "claude-sonnet",
                            "proxy_server_request": {
                                "headers": cleaned_headers
                            },
                            "secret_fields": {"raw_headers": raw_headers},
                        },
                        metadata=metadata,
                        user_id="svc-open-webui",
                        key_alias="aigw-open-webui-service",
                    )
                self.assertEqual(denied.exception.status_code, 400)

    def test_any_partial_openwebui_key_marker_denies(self) -> None:
        exact_metadata = {
            "aigw_key_kind": "service",
            "aigw_service": "open-webui",
            "aigw_project_id": "open-webui",
        }
        keys = (
            {
                "metadata": {},
                "user_id": "svc-open-webui",
                "key_alias": "other",
            },
            {
                "metadata": {},
                "user_id": "other",
                "key_alias": "aigw-open-webui-service",
            },
            {
                "metadata": {"aigw_service": "open-webui"},
                "user_id": "other",
                "key_alias": "other",
            },
            {
                "metadata": {"aigw_project_id": "open-webui"},
                "user_id": "other",
                "key_alias": "other",
            },
            {
                "metadata": {**exact_metadata, "unexpected": "drift"},
                "user_id": "svc-open-webui",
                "key_alias": "aigw-open-webui-service",
            },
        )
        for key in keys:
            with self.subTest(key=key):
                with self.assertRaises(_StubHTTPException) as denied:
                    self._run_hook({"model": "claude-sonnet"}, **key)
                self.assertEqual(denied.exception.status_code, 400)

    def test_openwebui_gate_does_not_apply_to_portal_or_operator_keys(self) -> None:
        for key in (
            {
                "metadata": {
                    "created_via": "dev-portal",
                    "aigw_username": "directory.user",
                },
                "user_id": "directory.user",
                "key_alias": "portal-key",
            },
            {"metadata": {}, "user_id": "operator", "key_alias": "operator"},
        ):
            request = {"model": "claude-sonnet"}
            result = self._run_hook(request, **key)
            self.assertIs(result, request)


if __name__ == "__main__":
    unittest.main()
