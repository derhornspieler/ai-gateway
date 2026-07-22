from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import socket
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
LOGIN = ROOT / "scripts/test-portal-login.py"
E2E = ROOT / "scripts/test-e2e-preprod.py"
MODEL_LIMIT_E2E = ROOT / "scripts/test-preprod-model-limits.py"
MODEL_LIFECYCLE_E2E = ROOT / "scripts/test-preprod-model-lifecycle.py"
USAGE_ACCOUNTING_E2E = ROOT / "scripts/test-preprod-usage-accounting.py"
PORTAL_PRICE_E2E = ROOT / "scripts/test-portal-price-backdate.py"


def load_login_module():
    spec = importlib.util.spec_from_file_location("aigw_preprod_portal_login", LOGIN)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_e2e_module():
    spec = importlib.util.spec_from_file_location("aigw_preprod_e2e", E2E)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_model_limit_e2e_module():
    spec = importlib.util.spec_from_file_location(
        "aigw_preprod_model_limit_e2e", MODEL_LIMIT_E2E
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_model_lifecycle_e2e_module():
    spec = importlib.util.spec_from_file_location(
        "aigw_preprod_model_lifecycle_e2e", MODEL_LIFECYCLE_E2E
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_usage_accounting_e2e_module():
    spec = importlib.util.spec_from_file_location(
        "aigw_preprod_usage_accounting_e2e", USAGE_ACCOUNTING_E2E
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PreprodPortalAcceptanceTests(unittest.TestCase):
    def test_resolution_is_exact_and_preserves_the_tls_hostname_boundary(self) -> None:
        module = load_login_module()
        resolver = mock.Mock(return_value=[("resolved",)])
        with mock.patch.object(module, "_SYSTEM_GETADDRINFO", resolver):
            self.assertEqual(
                module.preprod_getaddrinfo(
                    "portal.aigw.internal", 443, socket.AF_INET, socket.SOCK_STREAM
                ),
                [("resolved",)],
            )
        resolver.assert_called_once_with(
            "127.0.2.1", 443, socket.AF_INET, socket.SOCK_STREAM, 0, 0
        )
        self.assertEqual(
            module.PREPROD_HOST_ADDRESSES,
            {
                "api.aigw.internal": "127.0.2.1",
                "portal.aigw.internal": "127.0.2.1",
                "admin.aigw.internal": "127.0.3.1",
                "auth.aigw.internal": "127.0.3.1",
            },
        )
        with self.assertRaises(socket.gaierror):
            module.preprod_getaddrinfo("unreviewed.aigw.internal", 443)

    def test_e2e_proves_each_private_users_authorization_boundary(self) -> None:
        module = load_e2e_module()
        source = E2E.read_text(encoding="utf-8")
        self.assertEqual(
            module.ENABLED_ADM_OIDC_TARGETS,
            ("litellm-admin", "grafana", "prometheus"),
        )
        for username in ("preprod-admin", "preprod-developer", "preprod-user"):
            self.assertIn(f'"{username}"', source)
        self.assertIn("password = directory_password(username)", source)
        self.assertIn("metadata.st_gid != os.getegid()", source)
        self.assertNotIn("OnlyForTesting", source)
        self.assertIn('"PORTAL_DIRECTORY_ADMIN_DENIED_PASS"', source)
        self.assertIn('"PORTAL_DIRECTORY_ADMIN_PASS"', source)
        self.assertIn('"forbidden",', source)
        self.assertIn('"/admin",', source)
        self.assertIn('"--target",\n                "chat"', source)
        self.assertIn('"OIDC_CALLBACK_PASS target=chat username={username}"', source)
        self.assertIn("for target in ENABLED_ADM_OIDC_TARGETS:", source)
        self.assertIn(
            'f"OIDC_CALLBACK_PASS target={target} username={username}"', source
        )
        self.assertIn(
            'f"ADMIN_DENIAL_PASS target={target} username={username}"', source
        )

    def test_e2e_curl_ignores_user_configuration(self) -> None:
        module = load_e2e_module()
        with mock.patch.object(module, "run", return_value='{"ok":true}\n200') as run:
            self.assertEqual(
                module.curl_json("auth.aigw.internal", "127.0.3.1", "/health"),
                {"ok": True},
            )
        command = run.call_args.args[0]
        self.assertEqual(command[:2], ["curl", "--disable"])
        self.assertNotIn("--fail-with-body", command)
        self.assertIn("--write-out", command)

    def test_e2e_requires_the_reserved_router_to_fail_closed(self) -> None:
        source = E2E.read_text(encoding="utf-8")
        self.assertIn('"model": "aigw-auto"', source)
        self.assertIn("expected_status=400", source)
        self.assertIn("automatic model routing is not enabled", source)
        self.assertIn("PREPROD_AUTO_ROUTER_DENIAL_PASSED", source)

    def test_e2e_runs_the_live_fail_closed_model_limit_gate(self) -> None:
        source = E2E.read_text(encoding="utf-8")
        limits = MODEL_LIMIT_E2E.read_text(encoding="utf-8")
        self.assertIn('str(ROOT / "scripts/test-preprod-model-limits.py")', source)
        for marker in (
            "PREPROD_MODEL_REQUEST_CAP_PASSED",
            "PREPROD_MODEL_MINUTE_RESERVATION_PASSED",
            "PREPROD_MODEL_REDIS_FAILURE_PASSED",
            "PREPROD_MODEL_REDIS_RECOVERY_PASSED",
            "PREPROD_MODEL_LIMITS_PASSED",
        ):
            self.assertIn(marker, source)
            self.assertIn(marker, limits)

        # The temporary key has one explicit model and a canonical policy.
        self.assertIn('"models": [MODEL]', limits)
        self.assertIn('"created_via": "dev-portal"', limits)
        self.assertIn('"aigw_model_limits_v1": policy', limits)
        self.assertNotIn('"key": virtual_key', limits)
        self.assertIn('generated_key = response.get("key")', limits)
        self.assertIn('generated_key == preprod.master_key', limits)
        self.assertIn('sort_keys=True,\n        separators=(",", ":")', limits)
        # Two real calls run in parallel. Exactly one may reach the provider.
        self.assertIn("ThreadPoolExecutor(max_workers=2)", limits)
        self.assertIn("if statuses != [200, 429]:", limits)
        self.assertIn("if provider_count(preprod) != before + 1:", limits)
        # Redis is stopped only after its exact project/service labels pass,
        # and the finally block always starts it before deleting the test key.
        self.assertIn('labels.get("com.docker.compose.service") != service', limits)
        self.assertIn(
            'redis_stopped = True\n        preprod.docker("stop", "--time", "10", redis_id)',
            limits,
        )
        self.assertIn('redis_state.get("Status") != "exited"', limits)
        self.assertNotIn('stopped = preprod.docker("stop"', limits)
        self.assertIn("finally:\n        if redis_stopped:", limits)
        self.assertIn('preprod.wait_healthy("redis")', limits)

    def test_live_model_limit_safe_error_contract_is_exact(self) -> None:
        module = load_model_limit_e2e_module()
        module.expect_error(
            503,
            {"detail": {"error": "model output capacity is unavailable"}},
            503,
            "model output capacity is unavailable",
        )
        with self.assertRaisesRegex(SystemExit, "safe HTTP 503 denial"):
            module.expect_error(
                500,
                {"detail": "unexpected"},
                503,
                "model output capacity is unavailable",
            )

    def test_seed_e2e_runs_the_governed_model_lifecycle(self) -> None:
        source = E2E.read_text(encoding="utf-8")
        lifecycle = MODEL_LIFECYCLE_E2E.read_text(encoding="utf-8")
        module = load_model_lifecycle_e2e_module()
        compile(module.LIFECYCLE_HELPER, str(MODEL_LIFECYCLE_E2E), "exec")
        self.assertIn('if args.image_mode == "seed":', source)
        self.assertIn(
            'str(ROOT / "scripts/test-preprod-model-lifecycle.py")', source
        )
        for marker in (
            "PREPROD_MODEL_DRAFT_HIDDEN_PASSED",
            "PREPROD_MODEL_HIDDEN_CALL_PASSED",
            "PREPROD_MODEL_DISCOVERY_PASSED",
            "PREPROD_MODEL_ASSIGNMENT_GATE_PASSED",
            "PREPROD_MODEL_RETIREMENT_PASSED",
            "PREPROD_MODEL_LIFECYCLE_PASSED",
        ):
            self.assertIn(marker, source)
            self.assertIn(marker, lifecycle)

        self.assertIn('"visible_in_discovery": False', lifecycle)
        self.assertIn('"/model-governance/models/" + model + "/activate"', lifecycle)
        self.assertIn('"/v1/messages"', lifecycle)
        self.assertIn('"allowed_models": [model]', lifecycle)
        self.assertIn('policy_operation_id = str(uuid.uuid4())', lifecycle)
        self.assertEqual(lifecycle.count("operation_id=policy_operation_id"), 3)
        self.assertIn(
            '"/identity/groups/" + group_id + "/policy/activate"', lifecycle
        )
        self.assertIn(
            '"/identity/groups/" + group_id + "/policy/complete"', lifecycle
        )
        self.assertIn('policy.get("reconciliation_pending") is not True', lifecycle)
        self.assertIn(
            'completed.get("reconciliation_pending") is not False', lifecycle
        )
        self.assertNotIn("write=True,\n        write=True", lifecycle)
        self.assertIn("if status != 409", lifecycle)
        self.assertIn('control("DELETE", "/identity/groups/" + group_id', lifecycle)
        self.assertIn('"/model-governance/models/" + model + "/retire"', lifecycle)
        self.assertIn("finally:", lifecycle)

    def test_seed_e2e_runs_live_usage_cost_and_backdate_acceptance(self) -> None:
        source = E2E.read_text(encoding="utf-8")
        usage = USAGE_ACCOUNTING_E2E.read_text(encoding="utf-8")
        self.assertIn('if args.image_mode == "seed":', source)
        self.assertIn(
            'str(ROOT / "scripts/test-preprod-usage-accounting.py")', source
        )
        for marker in (
            "PREPROD_PRICE_PORTAL_STEP_UP_PASSED",
            "PREPROD_PRICE_PORTAL_PREVIEW_PASSED",
            "PREPROD_PRICE_PORTAL_CSRF_PASSED",
            "PREPROD_PRICE_PORTAL_CONFIRM_PASSED",
            "PREPROD_PRICE_PORTAL_CLEANUP_PASSED",
            "PREPROD_PRICE_PORTAL_PASSED",
            "PREPROD_PRICE_AUDIT_SOURCE_PASSED",
            "PREPROD_PRICE_AUDIT_EXPORT_PASSED",
            "PREPROD_USAGE_REPLAY_GUARD_PASSED",
            "PREPROD_USAGE_UNKNOWN_PASSED",
            "PREPROD_USAGE_BACKDATE_PASSED",
            "PREPROD_USAGE_REPORTING_PASSED",
            "PREPROD_USAGE_GRAFANA_RO_PASSED",
            "PREPROD_USAGE_APPEND_ONLY_PASSED",
            "PREPROD_USAGE_REAL_REQUEST_PASSED",
            "PREPROD_USAGE_STREAM_PASSED",
            "PREPROD_USAGE_RETRY_PASSED",
            "PREPROD_USAGE_FAILURE_PASSED",
            "PREPROD_USAGE_ACCOUNTING_CORE_PASSED",
            "PREPROD_USAGE_AUDIT_EXPORT_PASSED",
            "PREPROD_USAGE_DELIVERY_GAP_REQUEST_PASSED",
            "PREPROD_USAGE_DELIVERY_GAP_PASSED",
            "PREPROD_USAGE_ACCOUNTING_PASSED",
        ):
            self.assertIn(marker, source)
            self.assertIn(marker, usage)

        self.assertIn('choices=("seed",)', usage)
        self.assertIn('str(ROOT / "scripts/test-portal-price-backdate.py")', usage)
        self.assertIn('body=directory_password("preprod-admin") + "\\n"', source)
        self.assertIn('"stream": stream', usage)
        self.assertIn("AIGW_PREPROD_RETRY_ONCE_", usage)
        self.assertIn("AIGW_PREPROD_FAIL_ALWAYS_", usage)
        self.assertIn("AIGW_PREPROD_NO_USAGE_", usage)
        self.assertIn("usage_component_reporting", usage)
        self.assertIn("usage_reporting", usage)
        self.assertIn('user="grafana_ro"', usage)
        self.assertIn("psycopg.errors.InsufficientPrivilege", usage)
        self.assertIn('"grafana_password": preprod.values.get(', usage)
        self.assertIn('"CONFIRM BACKDATED PRICE"', usage)
        self.assertIn("output_preview[\"affected_rows\"]", usage)
        self.assertIn("a changed usage replay did not fail closed", usage)
        self.assertIn("a stale backdate preview did not fail closed", usage)
        self.assertIn("UPDATE aigw_governance.usage_events", usage)

        # The delivery-gap test may stop only the exact owned key-rotator
        # container, always restarts it, then validates the real producer line.
        # PreProd passes that exact bounded line through its owned empty-volume
        # source; it never mounts the local Docker log root.
        self.assertIn('labels.get(OWNER_LABEL) != PROJECT', usage)
        self.assertIn(
            'preprod.docker("stop", "--time", "10", key_rotator_id)', usage
        )
        self.assertIn("finally:\n        started, _ = preprod.docker", usage)
        self.assertIn('"litellm",\n        gap_started_at', usage)
        self.assertIn("FIXTURE_VOLUME = \"preprod_empty_docker_logs\"", usage)
        self.assertIn('"--network",\n        "none"', usage)
        self.assertIn('"--read-only"', usage)
        self.assertIn('"--cap-drop",\n        "ALL"', usage)
        self.assertIn('"--entrypoint",\n        "/bin/sh"', usage)
        self.assertIn("finally:\n        if created:", usage)
        self.assertNotIn("type=bind,src=/var/lib/docker", usage)

    def test_usage_audit_bridge_preserves_the_validated_docker_envelope(self) -> None:
        module = load_usage_accounting_e2e_module()
        timestamp = "2026-07-22T12:34:56.123456Z"
        event = {
            "action": "record",
            "completeness": "complete",
            "event": "aigw.usage.audit",
            "event_id": "a" * 64,
            "model": "claude-test",
            "outcome": "success",
            "project": "test-project",
            "provider": "anthropic",
            "request_id": "test-request",
            "schema_version": 1,
            "subject": "test-user",
        }
        payload = "AIGW_SECURITY_EVENT " + json.dumps(
            event, sort_keys=True, separators=(",", ":")
        )
        content = module.docker_log_fixture(
            [
                {
                    "event": event,
                    "message": payload,
                    "stream": "stderr",
                    "timestamp": timestamp,
                }
            ],
            "key-rotator",
        )
        envelope = json.loads(content)
        self.assertEqual(envelope["log"], payload + "\n")
        self.assertEqual(envelope["stream"], "stderr")
        self.assertEqual(envelope["time"], timestamp)
        self.assertEqual(
            envelope["attrs"],
            {
                "com.docker.compose.project": "aigw-preprod",
                "com.docker.compose.service": "key-rotator",
            },
        )
        with self.assertRaisesRegex(SystemExit, "producer is not reviewed"):
            module.docker_log_fixture(
                [
                    {
                        "event": event,
                        "message": payload,
                        "stream": "stderr",
                        "timestamp": timestamp,
                    }
                ],
                "unreviewed-service",
            )

    def test_usage_audit_fixture_writer_creates_and_removes_one_owned_file(
        self,
    ) -> None:
        module = load_usage_accounting_e2e_module()
        volume_name = "aigw-preprod_preprod_empty_docker_logs"
        model = {
            "volumes": {
                "preprod_empty_docker_logs": {"name": volume_name},
            },
            "services": {
                "volume-init": {"image": "aigw-preprod/volume-init:test"},
            },
        }

        class FakePreprod:
            config_digest = "d" * 64

            def __init__(self) -> None:
                self.calls: list[tuple[tuple[str, ...], str | None]] = []

            def docker(
                self, *arguments: str, input_text: str | None = None
            ) -> tuple[str, str]:
                self.calls.append((arguments, input_text))
                if arguments[:2] == ("volume", "inspect"):
                    return (
                        json.dumps(
                            [
                                {
                                    "Labels": {
                                        "com.aigw.preprod.project": "aigw-preprod",
                                        "com.docker.compose.project": "aigw-preprod",
                                    }
                                }
                            ]
                        ),
                        "",
                    )
                if arguments[:3] == ("container", "ls", "-a"):
                    return "", ""
                if arguments[0] == "run":
                    return "", ""
                raise AssertionError(f"unexpected Docker call: {arguments}")

        preprod = FakePreprod()
        token = "0123456789abcdef"
        content = '{"log":"safe\\n"}\n'
        module.set_security_fixture(preprod, model, token, content)
        module.set_security_fixture(preprod, model, token, None)
        run_calls = [call for call in preprod.calls if call[0][0] == "run"]
        self.assertEqual(len(run_calls), 2)
        self.assertEqual(run_calls[0][1], content)
        self.assertIsNone(run_calls[1][1])
        for arguments, _input_text in run_calls:
            self.assertIn("none", arguments)
            self.assertIn("--read-only", arguments)
            self.assertIn("ALL", arguments)
            self.assertIn(
                f"type=volume,src={volume_name},dst=/fixtures", arguments
            )

    def test_usage_preprod_docker_passes_fixture_input_on_stdin(self) -> None:
        module = load_usage_accounting_e2e_module()
        preprod = object.__new__(module.Preprod)
        preprod.docker_prefix = ["docker", "--host", "unix:///safe.sock"]
        with mock.patch.object(module, "run", return_value=("", "")) as runner:
            preprod.docker("run", "image", input_text="fixture\n")
        runner.assert_called_once_with(
            ["docker", "--host", "unix:///safe.sock", "run", "image"],
            input_text="fixture\n",
        )

    def test_portal_price_gate_uses_real_step_up_csrf_and_trusted_receipts(self) -> None:
        portal = PORTAL_PRICE_E2E.read_text(encoding="utf-8")
        compile(portal, str(PORTAL_PRICE_E2E), "exec")
        for required in (
            'flow.ADMIN_PORTAL_ORIGIN + "/login/start"',
            'flow.ADMIN_PORTAL_ORIGIN + "/admin/reauth"',
            '"/admin/model-governance/prices/backdate/preview"',
            '"/admin/model-governance/prices/backdate/confirm"',
            '"csrf_token": "x" * 43',
            '"CONFIRM BACKDATED PRICE"',
            '"gateway_model_name",\n        "usage_class",',
            '"9.75 USD per 1000000 tokens"',
            '"Affected usage rows</th><td class=\\"tnum\\">0</td>"',
        ):
            self.assertIn(required, portal)
        self.assertNotIn("password=", portal)


if __name__ == "__main__":
    unittest.main()
