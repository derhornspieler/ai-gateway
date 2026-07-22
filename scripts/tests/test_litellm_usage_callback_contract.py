from __future__ import annotations

import copy
import json
import sys
import types
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch


ROOT = Path(__file__).resolve().parents[2]
CALLBACK_PATH = ROOT / "compose/litellm/aigw_usage_callback.py"
FIXTURE_PATH = (
    ROOT
    / "services/key-rotator/tests/fixtures/litellm-1.93.0-anthropic-usage.json"
)
COMPOSE_PATH = ROOT / "compose/docker-compose.yml"
PREPROD_COMPOSE_PATH = ROOT / "compose/docker-compose.preprod.yml"
LITELLM_CONFIG_PATH = ROOT / "compose/litellm/config.yaml"
BIND_MANIFEST_PATH = ROOT / "compose/bind-source-digest-inputs.json"
STACK_TASKS_PATH = ROOT / "ansible/roles/docker_stack/tasks/main.yml"
PREPROD_SCRIPT_PATH = ROOT / "scripts/preprod.py"


class _CustomLogger:
    def __init__(self, **kwargs) -> None:
        self.options = kwargs


def _load_callback_module():
    litellm = types.ModuleType("litellm")
    integrations = types.ModuleType("litellm.integrations")
    custom_logger = types.ModuleType("litellm.integrations.custom_logger")
    custom_logger.CustomLogger = _CustomLogger

    identity = types.ModuleType("aigw_openwebui_identity")
    identity.read_openwebui_forward_jwt_secret = lambda: "b" * 64
    otel = types.ModuleType("aigw_otel_callback")
    otel._resolved_server_identity = lambda kwargs, secret: None
    httpx = types.ModuleType("httpx")
    httpx.AsyncClient = object

    module = types.ModuleType("aigw_usage_callback_test")
    source = CALLBACK_PATH.read_text().replace(
        "aigw_usage = AigwUsageCallback()", ""
    )
    with patch.dict(
        sys.modules,
        {
            "litellm": litellm,
            "litellm.integrations": integrations,
            "litellm.integrations.custom_logger": custom_logger,
            "aigw_openwebui_identity": identity,
            "aigw_otel_callback": otel,
            "httpx": httpx,
        },
    ):
        exec(compile(source, str(CALLBACK_PATH), "exec"), module.__dict__)
    return module


class LiteLLMUsageCallbackContractTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.callback = _load_callback_module()
        cls.fixture = json.loads(FIXTURE_PATH.read_text())

    def _event(self, kwargs=None, *, status="success"):
        return self.callback.build_usage_event(
            kwargs or copy.deepcopy(self.fixture["kwargs"]),
            status=status,
            end_time=datetime(2026, 7, 22, 12, 0, tzinfo=timezone.utc),
            openwebui_secret="b" * 64,
        )

    def test_fixture_pins_exact_upstream_release_and_primary_sources(self) -> None:
        source = self.fixture["source"]
        self.assertEqual(source["litellm_tag"], "v1.93.0")
        self.assertEqual(
            source["litellm_commit"],
            "052b5a2169d8d3082e1d66e69f200a72b0c1e274",
        )
        self.assertEqual(source["captured_on"], "2026-07-22")
        self.assertTrue(source["litellm_standard_payload_url"].startswith("https://docs.litellm.ai/"))
        self.assertIn(source["litellm_commit"], source["litellm_payload_source_url"])
        self.assertIn(source["litellm_commit"], source["litellm_anthropic_source_url"])
        self.assertTrue(source["anthropic_prompt_caching_url"].startswith("https://platform.claude.com/"))
        self.assertTrue(source["anthropic_pricing_url"].startswith("https://platform.claude.com/"))

    def test_callback_is_registered_and_both_consumers_get_one_private_mount(self) -> None:
        config = LITELLM_CONFIG_PATH.read_text()
        compose = COMPOSE_PATH.read_text()
        self.assertIn(
            'callbacks: ["aigw_otel_callback.aigw_otel", '
            '"aigw_usage_callback.aigw_usage", '
            '"aigw_default_model_hook.aigw_default_model_enforcer"]',
            config,
        )
        litellm = compose.split("  litellm:\n", 1)[1].split(
            "\n  open-webui:", 1
        )[0]
        rotator = compose.split("  key-rotator:\n", 1)[1].split(
            "\n  keycloak:", 1
        )[0]
        self.assertIn('group_add: ["65532"]', litellm)
        for block in (litellm, rotator):
            self.assertIn(
                "./secrets/litellm_usage_token:"
                "/run/secrets/litellm_usage_token:ro,z",
                block,
            )
            self.assertNotIn("LITELLM_USAGE_TOKEN:", block)
        self.assertIn(
            "./litellm/aigw_usage_callback.py:"
            "/app/aigw_usage_callback.py:ro,Z",
            litellm,
        )

    def test_usage_sources_are_in_the_bind_digest_and_sync_boundaries(self) -> None:
        manifest = json.loads(BIND_MANIFEST_PATH.read_text())
        self.assertIn(
            "litellm/aigw_usage_callback.py", manifest["base"]["litellm"]
        )
        self.assertIn(
            "secrets/litellm_usage_token", manifest["base"]["litellm"]
        )
        self.assertEqual(
            manifest["base"]["key-rotator"],
            [
                "secrets/provider_policy_receipt.json",
                "secrets/litellm_usage_token",
            ],
        )
        stack = STACK_TASKS_PATH.read_text()
        self.assertIn("- litellm/aigw_usage_callback.py", stack)
        self.assertIn(
            "{'path': stack_dir ~ '/litellm/aigw_usage_callback.py', "
            "'recursive': false},",
            stack,
        )
        self.assertIn(
            "{'path': stack_dir ~ '/secrets/litellm_usage_token', "
            "'recursive': false},",
            stack,
        )

    def test_production_usage_token_is_stable_private_and_not_inventory_owned(self) -> None:
        stack = STACK_TASKS_PATH.read_text()
        section = stack.split(
            "- name: Inspect the stable LiteLLM usage token", 1
        )[1].split("- name: Materialize Redis authentication files", 1)[0]
        for required in (
            "O_EXCL",
            "O_NOFOLLOW",
            "secrets.token_hex(32)",
            "os.fchown(descriptor, 0, 65532)",
            "os.fchmod(descriptor, 0o440)",
            "litellm_usage_token_before.stat.gid in [0, 65532]",
            "stat.nlink | int) == 1",
            "stat.size | int) == 64",
            're.fullmatch(rb"[0-9a-f]{64}", payload)',
            "no_log: true",
        ):
            self.assertIn(required, section)
        self.assertNotIn("{{ litellm_usage", section)

    def test_preprod_derives_a_separate_stable_local_usage_token(self) -> None:
        preprod = PREPROD_SCRIPT_PATH.read_text()
        overlay = PREPROD_COMPOSE_PATH.read_text()
        self.assertIn(
            'SECRETS_DIR / "litellm_usage_token",\n'
            '        credential_hex("litellm-usage", 64),\n'
            "        0o600,",
            preprod,
        )
        self.assertIn('"secrets/litellm_usage_token",', preprod)
        litellm = overlay.split("  litellm:\n", 1)[1].split(
            "\n  # Build paths", 1
        )[0]
        self.assertIn(
            "./secrets/litellm_usage_token:"
            "/run/secrets/litellm_usage_token:ro,z",
            litellm,
        )

    def test_anthropic_five_class_usage_and_identity_are_exact(self) -> None:
        event = self._event()

        self.assertEqual(event["normal_input_tokens"], 10)
        self.assertEqual(event["cache_creation_5m_tokens"], 20)
        self.assertEqual(event["cache_creation_1h_tokens"], 30)
        self.assertEqual(event["cache_read_tokens"], 40)
        self.assertEqual(event["output_tokens"], 50)
        self.assertEqual(event["usage_completeness"], "complete")
        self.assertEqual(event["requested_model"], "claude-sonnet-4-5")
        self.assertEqual(event["actual_model"], "claude-sonnet-4-5-20250929")
        self.assertEqual(event["stable_user_id"], "keycloak-subject-1")
        self.assertEqual(event["project_id"], "project-blue")
        self.assertEqual(event["retry_count"], 2)
        self.assertEqual(event["litellm_cost_usd"], "0.00123")
        self.assertIsNone(event["provider_cost_usd"])

    def test_signed_openwebui_subject_replaces_the_shared_service_owner(self) -> None:
        kwargs = copy.deepcopy(self.fixture["kwargs"])
        metadata = kwargs["standard_logging_object"]["metadata"]
        metadata["user_api_key_user_id"] = "svc-open-webui"

        with patch.object(
            self.callback,
            "_resolved_server_identity",
            return_value=("keycloak-subject-9", "browser-user", "open_webui_signed_oidc"),
        ):
            event = self._event(kwargs)

        self.assertEqual(event["stable_user_id"], "keycloak-subject-9")

    def test_untrusted_identity_or_project_shape_stays_unknown(self) -> None:
        kwargs = copy.deepcopy(self.fixture["kwargs"])
        metadata = kwargs["standard_logging_object"]["metadata"]
        metadata["user_api_key_user_id"] = "bad user"
        metadata["user_api_key_auth_metadata"]["aigw_project_id"] = "Bad Project"

        event = self._event(kwargs)

        self.assertIsNone(event["stable_user_id"])
        self.assertIsNone(event["project_id"])

    def test_provider_cost_uses_only_the_reviewed_provider_cost_field(self) -> None:
        kwargs = copy.deepcopy(self.fixture["kwargs"])
        payload = kwargs["standard_logging_object"]
        payload["metadata"]["usage_object"]["cost"] = 999

        event = self._event(kwargs)

        self.assertIsNone(event["provider_cost_usd"])
        payload["hidden_params"]["additional_headers"][
            "llm_provider-x-litellm-response-cost"
        ] = "0.0012"
        event = self._event(kwargs)
        self.assertEqual(event["provider_cost_usd"], "0.0012")

    def test_unbounded_or_over_precise_cost_stays_unknown(self) -> None:
        for unsafe in ("1000000000.01", "0.0000000000000000001"):
            kwargs = copy.deepcopy(self.fixture["kwargs"])
            kwargs["standard_logging_object"]["response_cost"] = unsafe
            event = self._event(kwargs)
            self.assertIsNone(event["litellm_cost_usd"])

    def test_official_usage_report_field_names_are_supported(self) -> None:
        kwargs = copy.deepcopy(self.fixture["kwargs"])
        usage = kwargs["standard_logging_object"]["metadata"]["usage_object"]
        usage.clear()
        usage.update(
            {
                "uncached_input_tokens": 11,
                "cache_creation": {
                    "ephemeral_5m_input_tokens": 22,
                    "ephemeral_1h_input_tokens": 33,
                },
                "cache_read_input_tokens": 44,
                "output_tokens": 55,
            }
        )

        event = self._event(kwargs)

        self.assertEqual(
            [event[field] for field in self.callback.TOKEN_FIELDS],
            [11, 22, 33, 44, 55],
        )
        self.assertEqual(event["usage_completeness"], "complete")

    def test_aggregate_cache_write_is_not_guessed_as_five_minutes(self) -> None:
        kwargs = copy.deepcopy(self.fixture["kwargs"])
        details = kwargs["standard_logging_object"]["metadata"]["usage_object"]
        details["prompt_tokens_details"].pop("cache_creation_token_details")

        event = self._event(kwargs)

        self.assertIsNone(event["cache_creation_5m_tokens"])
        self.assertIsNone(event["cache_creation_1h_tokens"])
        self.assertEqual(event["usage_completeness"], "partial")

    def test_patched_unusable_provider_usage_stays_unknown(self) -> None:
        kwargs = copy.deepcopy(self.fixture["kwargs"])
        usage = kwargs["standard_logging_object"]["metadata"]["usage_object"]
        usage["aigw_provider_usage_unusable"] = True

        event = self._event(kwargs)

        self.assertEqual(event["usage_completeness"], "unknown")
        self.assertTrue(
            all(event[field] is None for field in self.callback.TOKEN_FIELDS)
        )
        self.assertIsNone(event["litellm_cost_usd"])

    def test_provider_header_cannot_spoof_the_internal_usage_receipt(self) -> None:
        kwargs = copy.deepcopy(self.fixture["kwargs"])
        headers = kwargs["standard_logging_object"]["hidden_params"][
            "additional_headers"
        ]
        headers["llm_provider-aigw-provider-usage-unusable"] = "true"

        event = self._event(kwargs)

        self.assertEqual(event["usage_completeness"], "complete")

    def test_streaming_and_retry_values_are_recorded_without_labels(self) -> None:
        kwargs = copy.deepcopy(self.fixture["kwargs"])
        kwargs["stream"] = True
        kwargs["standard_logging_object"]["stream"] = True

        event = self._event(kwargs)

        self.assertTrue(event["stream"])
        self.assertEqual(event["retry_count"], 2)
        self.assertNotIn("prometheus_labels", event)

    def test_router_owned_retry_metadata_precedes_the_response_header(self) -> None:
        kwargs = copy.deepcopy(self.fixture["kwargs"])
        kwargs["litellm_params"] = {
            "litellm_metadata": {"attempted_retries": 1},
            "metadata": {"attempted_retries": 99},
        }

        event = self._event(kwargs)

        self.assertEqual(event["retry_count"], 1)

    def test_caller_retry_metadata_is_not_usage_evidence(self) -> None:
        kwargs = copy.deepcopy(self.fixture["kwargs"])
        kwargs["standard_logging_object"]["hidden_params"][
            "additional_headers"
        ].pop("x-litellm-attempted-retries")
        kwargs["litellm_params"] = {
            "metadata": {"attempted_retries": 99},
        }

        event = self._event(kwargs)

        self.assertIsNone(event["retry_count"])

    def test_missing_or_malformed_stream_state_stays_unknown(self) -> None:
        kwargs = copy.deepcopy(self.fixture["kwargs"])
        kwargs["standard_logging_object"].pop("stream", None)
        kwargs.pop("stream", None)
        missing = self._event(kwargs)
        self.assertIsNone(missing["stream"])

        kwargs["standard_logging_object"]["stream"] = "false"
        kwargs["stream"] = "true"
        malformed = self._event(kwargs)
        self.assertIsNone(malformed["stream"])

    def test_failure_has_no_invented_usage_or_cost(self) -> None:
        kwargs = copy.deepcopy(self.fixture["kwargs"])
        kwargs["standard_logging_object"]["status"] = "failure"

        event = self._event(kwargs, status="failure")

        self.assertEqual(event["usage_completeness"], "not_applicable")
        self.assertTrue(all(event[field] is None for field in self.callback.TOKEN_FIELDS))
        self.assertIsNone(event["litellm_cost_usd"])
        self.assertIsNone(event["provider_cost_usd"])

    def test_repeated_callback_build_is_idempotent(self) -> None:
        first = self._event()
        second = self._event()

        self.assertEqual(first, second)
        self.assertRegex(first["event_id"], r"^[0-9a-f]{64}$")

    def test_event_has_only_the_reviewed_prompt_free_allowlist(self) -> None:
        event = self._event()
        self.assertEqual(
            set(event),
            {
                "schema_version",
                "event_id",
                "request_id",
                "request_id_source",
                "provider_response_id",
                "trace_id",
                "provider",
                "requested_model",
                "actual_model",
                "stable_user_id",
                "project_id",
                "status",
                "stream",
                "retry_count",
                "occurred_at",
                "normal_input_tokens",
                "cache_creation_5m_tokens",
                "cache_creation_1h_tokens",
                "cache_read_tokens",
                "output_tokens",
                "usage_completeness",
                "litellm_cost_usd",
                "provider_cost_usd",
                "source_version",
            },
        )
        serialized = json.dumps(event).lower()
        for forbidden in (
            "authorization",
            "api_key",
            "messages",
            "prompt",
            "response_body",
            "request_headers",
        ):
            self.assertNotIn(forbidden, serialized)

    async def test_delivery_uses_only_fixed_local_endpoint_and_separate_token(self) -> None:
        callback = object.__new__(self.callback.AigwUsageCallback)
        callback._token = "c" * 64
        callback._openwebui_secret = "b" * 64
        response = types.SimpleNamespace(status_code=201)
        client = AsyncMock()
        client.post.return_value = response
        context = AsyncMock()
        context.__aenter__.return_value = client
        context.__aexit__.return_value = None

        with patch.object(self.callback.httpx, "AsyncClient", return_value=context) as factory:
            await callback._send(
                copy.deepcopy(self.fixture["kwargs"]),
                "success",
                datetime(2026, 7, 22, 12, 0, tzinfo=timezone.utc),
            )

        factory.assert_called_once_with(
            timeout=2.0, trust_env=False, follow_redirects=False
        )
        client.post.assert_awaited_once()
        args, kwargs = client.post.await_args
        self.assertEqual(args, ("http://key-rotator:8080/usage/events",))
        self.assertEqual(kwargs["headers"], {"X-AIGW-Usage-Auth": "c" * 64})
        self.assertNotIn("X-Internal-Auth", kwargs["headers"])

    async def test_delivery_failure_is_auditable_without_retry_or_secrets(self) -> None:
        callback = object.__new__(self.callback.AigwUsageCallback)
        callback._token = "c" * 64
        callback._openwebui_secret = "b" * 64
        context = AsyncMock()
        context.__aenter__.side_effect = RuntimeError(
            "Authorization: Bearer never-log-this"
        )

        with (
            patch.object(self.callback.httpx, "AsyncClient", return_value=context),
            self.assertLogs("litellm.aigw_usage", level="ERROR") as captured,
        ):
            result = await callback._send(
                copy.deepcopy(self.fixture["kwargs"]),
                "success",
                datetime(2026, 7, 22, 12, 0, tzinfo=timezone.utc),
            )

        self.assertIsNone(result)
        line = captured.records[0].getMessage()
        self.assertTrue(line.startswith("AIGW_SECURITY_EVENT "))
        audit = json.loads(line.removeprefix("AIGW_SECURITY_EVENT "))
        self.assertEqual(
            set(audit),
            {
                "schema_version",
                "event",
                "action",
                "outcome",
                "event_id",
                "request_id",
                "provider",
                "model",
                "project",
                "subject",
                "completeness",
            },
        )
        self.assertEqual(audit["action"], "delivery_failure")
        self.assertEqual(audit["outcome"], "failure")
        self.assertNotIn("never-log-this", line)
        self.assertNotIn("authorization", line.lower())

    async def test_event_build_failure_keeps_only_safe_available_join_fields(self) -> None:
        callback = object.__new__(self.callback.AigwUsageCallback)
        callback._token = "c" * 64
        callback._openwebui_secret = "b" * 64
        kwargs = copy.deepcopy(self.fixture["kwargs"])
        kwargs["standard_logging_object"]["custom_llm_provider"] = (
            "bad provider with secret text"
        )
        kwargs["messages"] = [{"role": "user", "content": "never-log-prompt"}]

        with self.assertLogs("litellm.aigw_usage", level="ERROR") as captured:
            result = await callback._send(
                kwargs,
                "success",
                datetime(2026, 7, 22, 12, 0, tzinfo=timezone.utc),
            )

        self.assertIsNone(result)
        line = captured.records[0].getMessage()
        audit = json.loads(line.removeprefix("AIGW_SECURITY_EVENT "))
        self.assertEqual(audit["event_id"], "unattributed")
        self.assertEqual(audit["provider"], "unattributed")
        self.assertEqual(audit["request_id"], "call-123")
        self.assertEqual(audit["model"], "claude-sonnet-4-5")
        self.assertEqual(audit["project"], "project-blue")
        self.assertEqual(audit["subject"], "keycloak-subject-1")
        self.assertEqual(audit["completeness"], "unknown")
        self.assertNotIn("never-log", line)
        self.assertNotIn("secret text", line)

    def test_unknown_provider_and_missing_request_id_fail_closed(self) -> None:
        kwargs = copy.deepcopy(self.fixture["kwargs"])
        kwargs["standard_logging_object"]["custom_llm_provider"] = "bad provider"
        with self.assertRaisesRegex(self.callback.UsageEventError, "provider"):
            self._event(kwargs)

        kwargs = copy.deepcopy(self.fixture["kwargs"])
        payload = kwargs["standard_logging_object"]
        payload.update({"id": None, "litellm_call_id": None, "trace_id": None})
        with self.assertRaisesRegex(self.callback.UsageEventError, "identifier"):
            self._event(kwargs)


if __name__ == "__main__":
    unittest.main()
