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
CRIBL_PREPROD_TLS = (
    ROOT / "compose/cribl-mock/config.preprod-tls.yaml"
).read_text(encoding="utf-8")
PREPROD_SCRIPT = (ROOT / "scripts/preprod.py").read_text(encoding="utf-8")

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
        self.assertIn(
            "logs:\n      sampling:\n        enabled: false",
            CRIBL_MOCK,
        )
        for marker in (
            "OTLP_FIXTURES_ACCEPTED",
            "DENIED_RAW_TRACE_",
            "denied_raw_metric_",
            "DENIED_RAW_LOG_",
            "DENIED_ORDINARY_LOG_",
            "DENIED_SCHEMA_",
            "DENIED_ACTION_",
            "DENIED_VENDOR_",
            "DENIED_VAULT_STATE_",
            "DENIED_MALFORMED_",
            "event=aigw.provider.rotation action=rotate outcome=success",
            "event=aigw.vault.state action=state_observed outcome=success",
            "event=aigw.vault.audit",
            "action=upstream_tls_failure",
            "provider=anthropic reason=tls_transport_failure",
            "hmac_protected=true",
            '"action":"break_glass_use"',
            "UNAPPROVED_FIELD_",
            "NESTED_SECRET_",
            "wait_for_queue(preprod, model, populated=True)",
            "exercise_tls_server_name_failure(preprod, model, tls_token)",
            "Alloy accepted a Cribl certificate with the wrong server name",
            'preprod.docker("restart", "--time", "10", alloy)',
            "PREPROD_CRIBL_SECURITY_FEED_PASSED",
        ):
            self.assertIn(marker, PREPROD_RECEIPT)
        self.assertIn(
            "Prove the curated Cribl security feed and persistent recovery queue",
            PREPROD_TASKS,
        )
        self.assertIn("scripts/test-preprod-cribl-security.py", PREPROD_TASKS)

    def test_structured_security_events_use_a_fixed_field_projection(self) -> None:
        structured = ALLOY.split(
            'loki.process "cribl_structured_security"', 1
        )[1].split('loki.source.file "vault_audit"', 1)[0]
        self.assertIn('source = "aigw_security_line"', structured)
        self.assertIn(
            'stage.output { source = "aigw_security_line" }', structured
        )
        self.assertNotIn('stage.output { source = "aigw_security_json" }', structured)
        self.assertIn(
            'template = `{{ if eq .Value true }}true{{ else if eq .Value false }}false{{ end }}`',
            structured,
        )
        for field in (
            "security_subject",
            "security_project",
            "security_rotation_status",
            "security_policy_sha256",
            "security_providers",
            "security_sni",
            "security_exact_sans",
            "security_ca_fingerprints",
            "security_reason",
        ):
            self.assertIn(field, structured)
        for reason in (
            "missing_portal_subject",
            "missing_rotation_vendor",
            "missing_vault_state",
            "missing_egress_policy_digest",
            "missing_egress_ca_fingerprints",
            "missing_egress_failure_reason",
        ):
            self.assertIn(reason, structured)

    def test_preprod_uses_verified_tls_for_the_cribl_mock(self) -> None:
        for fragment in (
            "cert_file: /run/preprod/cribl.crt",
            "key_file: /run/preprod/cribl.key",
        ):
            self.assertIn(fragment, CRIBL_PREPROD_TLS)
        for fragment in (
            '"cribl_key": SECRETS_DIR / "preprod-cribl.key"',
            '"cribl_cert": SECRETS_DIR / "preprod-cribl.crt"',
            'generate_leaf(paths, "cribl_key", "cribl_cert", "cribl-mock", ["cribl-mock"])',
            '"CRIBL_OTLP_INSECURE": "false"',
            'server_name          = "cribl-mock"',
            "insecure_skip_verify = false",
            'render_preprod_alloy_config()',
        ):
            self.assertIn(fragment, PREPROD_SCRIPT)
        cribl = PREPROD_OVERLAY.split("  cribl-mock:\n", 1)[1].split(
            "\n  samba-ad:", 1
        )[0]
        self.assertIn("config.preprod-tls.yaml", cribl)
        self.assertIn("./secrets/preprod-cribl.crt:/run/preprod/cribl.crt:ro,Z", cribl)
        self.assertIn("./secrets/preprod-cribl.key:/run/preprod/cribl.key:ro,Z", cribl)


if __name__ == "__main__":
    unittest.main()
