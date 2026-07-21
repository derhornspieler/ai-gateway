from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
COMPOSE = (ROOT / "compose/docker-compose.yml").read_text(encoding="utf-8")
ALLOY = (ROOT / "compose/alloy/config.alloy").read_text(encoding="utf-8")
IDENTITY = (ROOT / "services/key-rotator/app/identity.py").read_text(encoding="utf-8")
PREPROD_OVERLAY = (ROOT / "compose/docker-compose.preprod.yml").read_text(
    encoding="utf-8"
)
PREPROD_RECEIPT = (
    ROOT / "scripts/test-preprod-cribl-security.py"
).read_text(encoding="utf-8")
PREPROD_TASKS = (
    ROOT / "ansible/roles/preprod_stack/tasks/present.yml"
).read_text(encoding="utf-8")
CRIBL_MOCK = (ROOT / "compose/cribl-mock/config.yaml").read_text(encoding="utf-8")

EVENTS = (
    "CLIENT_LOGIN",
    "CLIENT_LOGIN_ERROR",
    "CODE_TO_TOKEN",
    "CODE_TO_TOKEN_ERROR",
    "IDENTITY_PROVIDER_FIRST_LOGIN",
    "IDENTITY_PROVIDER_FIRST_LOGIN_ERROR",
    "IDENTITY_PROVIDER_LOGIN",
    "IDENTITY_PROVIDER_LOGIN_ERROR",
    "IDENTITY_PROVIDER_POST_LOGIN",
    "IDENTITY_PROVIDER_POST_LOGIN_ERROR",
    "IMPERSONATE",
    "IMPERSONATE_ERROR",
    "LOGIN",
    "LOGIN_ERROR",
    "LOGOUT",
    "LOGOUT_ERROR",
    "REFRESH_TOKEN",
    "REFRESH_TOKEN_ERROR",
    "USER_DISABLED_BY_PERMANENT_LOCKOUT",
    "USER_DISABLED_BY_PERMANENT_LOCKOUT_ERROR",
    "USER_DISABLED_BY_TEMPORARY_LOCKOUT",
    "USER_DISABLED_BY_TEMPORARY_LOCKOUT_ERROR",
)


class CriblSecurityFeedContractTests(unittest.TestCase):
    def test_keycloak_imports_have_the_exact_user_event_policy(self) -> None:
        for name in ("aigw-realm.json", "anthropic-wif-realm.json"):
            realm = json.loads(
                (ROOT / "compose/keycloak/realms" / name).read_text(encoding="utf-8")
            )
            self.assertIs(realm["eventsEnabled"], True)
            self.assertEqual(realm["eventsExpiration"], 86400)
            self.assertEqual(realm["eventsListeners"], ["jboss-logging"])
            self.assertEqual(tuple(realm["enabledEventTypes"]), EVENTS)
            self.assertIs(realm["adminEventsEnabled"], False)
            self.assertIs(realm["adminEventsDetailsEnabled"], False)

        for name in ("aigw-realm.json.j2", "anthropic-wif-realm.json.j2"):
            template = (
                ROOT / "ansible/roles/docker_stack/templates/keycloak-realms" / name
            ).read_text(encoding="utf-8")
            for event in EVENTS:
                self.assertEqual(template.count(f'"{event}"'), 1)
            for fragment in (
                '"eventsEnabled": true',
                '"eventsListeners": ["jboss-logging"]',
                '"adminEventsEnabled": false',
                '"adminEventsDetailsEnabled": false',
            ):
                self.assertIn(fragment, template)

    def test_keycloak_runtime_emits_sanitized_json_events(self) -> None:
        keycloak = COMPOSE.split("  keycloak:\n", 1)[1].split("\n  dev-portal:", 1)[0]
        for option in (
            "--log-console-output=json",
            "--log-console-json-format=ecs",
            "--log-service-name=keycloak",
            "--spi-events-listener--jboss-logging--success-level=info",
            "--spi-events-listener--jboss-logging--error-level=warn",
            "--spi-events-listener--jboss-logging--sanitize=true",
            "--spi-events-listener--jboss-logging--include-representation=false",
        ):
            self.assertIn(option, keycloak)

    def test_existing_realms_are_reconciled_and_read_back(self) -> None:
        for fragment in (
            "KEYCLOAK_SECURITY_EVENT_TYPES = (",
            'KEYCLOAK_SECURITY_EVENT_REALMS = ("master", "aigw", "anthropic-wif")',
            "async def _reconcile_security_event_logging",
            '"eventsListeners": ["jboss-logging"]',
            '"adminEventsEnabled": False',
            '"adminEventsDetailsEnabled": False',
            '"Keycloak did not verify the security event logging policy"',
            "await self._reconcile_security_event_logging(admin_token)",
        ):
            self.assertIn(fragment, IDENTITY)
        constant = IDENTITY.split("KEYCLOAK_SECURITY_EVENT_TYPES = (", 1)[1].split(
            ")\n", 1
        )[0]
        self.assertEqual(tuple(re.findall(r'^    "([A-Z_]+)",$', constant, re.M)), EVENTS)

    def test_alloy_keycloak_allowlist_matches_the_realm_policy(self) -> None:
        match = re.search(
            r"\(\?P<keycloak_event>([A-Z_|]+)\)\(\?:,\|\$\)", ALLOY
        )
        self.assertIsNotNone(match)
        self.assertEqual(tuple(match.group(1).split("|")), EVENTS)

    def test_prometheus_retention_is_local_and_size_bounded(self) -> None:
        prometheus = COMPOSE.split("  prometheus:\n", 1)[1].split(
            "\n  node-exporter:", 1
        )[0]
        self.assertIn("--storage.tsdb.retention.time=30d", prometheus)
        self.assertIn(
            "--storage.tsdb.retention.size=${PROMETHEUS_RETENTION_SIZE:-5GB}",
            prometheus,
        )
        self.assertNotIn("--storage.tsdb.retention.time=7d", prometheus)

    def test_seeded_preprod_has_record_level_allow_deny_and_recovery_proof(self) -> None:
        self.assertIn("preprod_empty_docker_logs:", PREPROD_OVERLAY)
        self.assertIn(
            "preprod_empty_docker_logs:/var/lib/docker/containers:ro",
            PREPROD_OVERLAY,
        )
        self.assertNotIn("${DOCKER_DATA_ROOT}", PREPROD_OVERLAY)
        self.assertIn("verbosity: detailed", CRIBL_MOCK)
        for marker in (
            "OTLP_FIXTURES_ACCEPTED",
            "DENIED_RAW_TRACE_",
            "denied_raw_metric_",
            "DENIED_RAW_LOG_",
            "DENIED_ORDINARY_LOG_",
            "DENIED_SCHEMA_",
            "DENIED_ACTION_",
            "DENIED_MALFORMED_",
            "<redacted-authorization>",
            "wait_for_queue(preprod, model, populated=True)",
            'preprod.docker("restart", "--time", "10", alloy)',
            "PREPROD_CRIBL_SECURITY_FEED_PASSED",
        ):
            self.assertIn(marker, PREPROD_RECEIPT)
        self.assertIn(
            "Prove the curated Cribl security feed and persistent recovery queue",
            PREPROD_TASKS,
        )
        self.assertIn("scripts/test-preprod-cribl-security.py", PREPROD_TASKS)


if __name__ == "__main__":
    unittest.main()
