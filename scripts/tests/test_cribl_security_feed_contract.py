from __future__ import annotations

import json
import re
import runpy
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
            "await self._reconcile_security_event_logging(",
            "admin_token, mark_live_change",
        ):
            self.assertIn(fragment, IDENTITY)
        constant = IDENTITY.split("KEYCLOAK_SECURITY_EVENT_TYPES = (", 1)[1].split(
            ")\n", 1
        )[0]
        self.assertEqual(tuple(re.findall(r'^    "([A-Z_]+)",$', constant, re.M)), EVENTS)

    def test_alloy_keycloak_allowlist_matches_the_realm_policy(self) -> None:
        match = re.search(
            r'\^type="\(\?P<keycloak_event>([A-Z_|]+)\)"\(\?:,\|\$\)',
            ALLOY,
        )
        self.assertIsNotNone(match)
        self.assertEqual(tuple(match.group(1).split("|")), EVENTS)

    def test_alloy_keycloak_parser_requires_quoted_sanitized_fields(self) -> None:
        keycloak = ALLOY.split('loki.process "cribl_keycloak_auth"', 1)[1].split(
            'loki.process "cribl_envoy_tls"', 1
        )[0]
        for required in (
            'expression = `^type="(?P<keycloak_event>',
            'realmId="(?P<keycloak_realm_id>[A-Za-z0-9_.:@-]{1,128})"',
            'clientId="(?P<keycloak_client_id>[A-Za-z0-9_.:@/-]{1,128})"',
            'userId="(?P<keycloak_user_id>[A-Za-z0-9_.:@-]{1,128})"',
        ):
            self.assertIn(required, keycloak)
        for unquoted in (
            "expression = `^type=(?P<keycloak_event>",
            "realmId=(?P<keycloak_realm_id>",
            "clientId=(?P<keycloak_client_id>",
            "userId=(?P<keycloak_user_id>",
        ):
            self.assertNotIn(unquoted, keycloak)
        self.assertIn(
            "'type=\"LOGIN\", realmId=\"aigw\", clientId=\"portal\", '",
            PREPROD_RECEIPT,
        )
        self.assertIn(
            '"type=LOGIN, realmId=aigw, clientId=portal, "',
            PREPROD_RECEIPT,
        )
        self.assertIn("DENIED_KEYCLOAK_UNQUOTED_", PREPROD_RECEIPT)

    def test_natural_keycloak_receipt_parser_matches_live_26_7_shape(self) -> None:
        module = runpy.run_path(str(ROOT / "scripts/test-preprod-cribl-security.py"))
        parser = module["natural_keycloak_receipts"]
        realm_id = "123e4567-e89b-42d3-a456-426614174100"
        user_id = "123e4567-e89b-42d3-a456-426614174101"

        def event(name: str, *, user: str = user_id) -> str:
            return json.dumps(
                {
                    "log.logger": "org.keycloak.events",
                    "message": (
                        f'type="{name}", realmId="{realm_id}", '
                        'realmName="aigw", clientId="dev-portal", '
                        f'userId="{user}", ipAddress="172.29.1.130", '
                        'username="must-not-be-projected"'
                    ),
                },
                separators=(",", ":"),
            )

        raw = "\n".join(event(name) for name in ("LOGIN", "LOGIN_ERROR", "LOGOUT"))
        self.assertEqual(
            parser(raw),
            tuple(
                "schema_version=1 event=aigw.keycloak.authentication "
                f"event_type={name} realm_id={realm_id} "
                f"client_id=dev-portal user_id={user_id}"
                for name in ("LOGIN", "LOGIN_ERROR", "LOGOUT")
            ),
        )
        self.assertIsNone(
            parser(
                "\n".join(
                    json.dumps(
                        {
                            "log.logger": "org.keycloak.events",
                            "message": (
                                f"type={name}, realmId={realm_id}, "
                                "realmName=aigw, clientId=dev-portal, "
                                f"userId={user_id}"
                            ),
                        },
                        separators=(",", ":"),
                    )
                    for name in ("LOGIN", "LOGIN_ERROR", "LOGOUT")
                )
            )
        )
        with self.assertRaisesRegex(SystemExit, "one user and realm"):
            parser(
                "\n".join(
                    event(name, user="different" if name == "LOGIN" else user_id)
                    for name in ("LOGIN", "LOGIN_ERROR", "LOGOUT")
                )
            )

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

    def test_seeded_preprod_has_all_signal_scope_redaction_and_recovery_proof(self) -> None:
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
            "OTLP_SPOOF_REJECTED",
            "LITELLM_REAL_REQUEST_ACCEPTED",
            "OPENWEBUI_HEADER_RUNTIME_REQUEST_ACCEPTED",
            "OPENWEBUI_INVALID_IDENTITY_REQUESTS_REJECTED",
            "ADMITTED_SANITIZED_TRACE_",
            "ADMITTED_UNATTRIBUTED_TRACE_",
            "DENIED_UNTRUSTED_SOURCE_",
            "REJECTED_OPENWEBUI_MISSING_JWT_",
            "REJECTED_OPENWEBUI_INVALID_JWT_",
            "REJECTED_OPENWEBUI_EXPIRED_JWT_",
            "REJECTED_OPENWEBUI_CONFLICTING_JWT_",
            "REJECTED_OPENWEBUI_PARTIAL_MARKER_",
            "FORGED_AUTH_MARKER_",
            "FORGED_PRODUCER_",
            "FORGED_LOG_ENV_",
            "FORGED_LOG_SERVICE_",
            "FORGED_RESOURCE_ENV_",
            "FORGED_BODY_PRODUCER_",
            "FORGED_BODY_ENV_",
            "FORGED_BODY_SERVICE_",
            "DENIED_ZERO_TIMESTAMP_",
            "DENIED_STALE_TIMESTAMP_",
            "DENIED_FUTURE_TIMESTAMP_",
            "ALLOWED_RECENT_PAST_TIMESTAMP_",
            "ALLOWED_CLOCK_SKEW_TIMESTAMP_",
            "denied-changed-string-",
            "denied-changed-null-",
            "denied-changed-number-",
            "real-ai-input-",
            "runtime-openwebui-ai-input-",
            "DENIED_KEYCLOAK_MISSING_USER_",
            "DENIED_KEYCLOAK_UNQUOTED_",
            "DENIED_KEYCLOAK_IP_",
            "DENIED_KEYCLOAK_USERNAME_",
            "DENIED_KEYCLOAK_EMAIL_",
            "PROMPT_PASSWORD_",
            "PROMPT_BEARER_",
            "sk-ant-",
            "SESSION_TOKEN_SECRET_",
            "VAULT_UNSEAL_SECRET_",
            "CLIENT_ASSERTION_SECRET_",
            "QUOTED_MULTIWORD_INPUT_",
            "ESCAPED_MULTIWORD_INPUT_",
            "QUOTED_MULTIWORD_OUTPUT_",
            "QUOTED_MULTIWORD_LEGACY_PROMPT_",
            "ESCAPED_MULTIWORD_LEGACY_COMPLETION_",
            "PEM_SECRET_",
            "TRUNCATED_PEM_SECRET_",
            "SAFE_SESSION_COUNT_",
            "SAFE_VAULT_STATUS_",
            "SAFE_CLIENT_ASSERTIVENESS_",
            "SAFE_PUBLIC_KEY_",
            "SAFE_PRIVATE_KEY_WORDS_",
            "SAFE_PASSWORD_POLICY_",
            "SAFE_VAULT_WORDS_",
            "admitted_metric_",
            "ADMITTED_LOG_",
            "FORGED_METRIC_ENV_",
            "METRIC_RESOURCE_SECRET_",
            "METRIC_SCOPE_SECRET_",
            "METRIC_POINT_SECRET_",
            "FORGED_OTLP_LOG_ENV_",
            "OTLP_LOG_RESOURCE_SECRET_",
            "OTLP_LOG_BODY_SECRET_",
            "ADMITTED_ORDINARY_LOG_",
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
            "DOCKER_SESSION_SECRET_",
            "DOCKER_PEM_SECRET_",
            "<redacted-credential>",
            "<redacted-authorization>",
            "<redacted-vendor-key>",
            "<redacted-jwt>",
            "<redacted-vault-token>",
            "<redacted-private-key>",
            '"verify",',
            "the live Vault audit receipt could not be generated",
            "wait_for_queue(preprod, model, populated=True)",
            "assert_otel_token_is_file_only(preprod)",
            "send_real_litellm_request(preprod, token)",
            "send_openwebui_header_runtime_request(preprod, token)",
            "exercise_natural_keycloak_auth(preprod, model)",
            "set_natural_keycloak_fixture(preprod, model, fixture_token, fixture)",
            "KEYCLOAK_NATURAL_AUTH_EVENTS_ACCEPTED",
            "natural Keycloak success/logout flow",
            "natural Keycloak failed-login flow",
            "a raw Keycloak authentication field reached Cribl",
            "write_controller_lifecycle_fixtures(token)",
            "exercise_tls_server_name_failure(preprod, model, tls_token)",
            "Alloy accepted a Cribl certificate with the wrong server name",
            'preprod.docker("restart", "--time", "10", alloy)',
            "cribl_queue_sizes",
            'for candidate in ("logs", "metrics", "traces")',
            "if f'data_type=\"{candidate}\"' in labels",
            "PREPROD_CRIBL_TELEMETRY_PASSED",
        ):
            self.assertIn(marker, PREPROD_RECEIPT)

        module = runpy.run_path(str(ROOT / "scripts/test-preprod-cribl-security.py"))
        helpers = {
            name: module[name]
            for name in ("OTLP_FIXTURE_HELPER", "OTLP_SPOOF_HELPER")
        }
        self.assertEqual(
            set(helpers), {"OTLP_FIXTURE_HELPER", "OTLP_SPOOF_HELPER"}
        )
        for name, helper in helpers.items():
            compile(helper, name, "exec")
        openwebui_helper = module["OPENWEBUI_HEADER_RUNTIME_REQUEST_HELPER"]
        compile(openwebui_helper, "OPENWEBUI_HEADER_RUNTIME_REQUEST_HELPER", "exec")
        self.assertIn(
            "from open_webui.utils.headers import include_user_info_headers",
            openwebui_helper,
        )
        self.assertIn("headers = include_user_info_headers(", openwebui_helper)
        self.assertIn("except urllib.error.HTTPError as error:", openwebui_helper)
        self.assertIn("not 400 <= rejected_status < 500", openwebui_helper)
        self.assertIn("expired_token = jwt.encode(", openwebui_helper)
        self.assertIn("duplicate_connection.putrequest(", openwebui_helper)
        self.assertIn(
            'duplicate_connection.putheader("X-OpenWebUI-User-Jwt", "not-a-jwt")',
            openwebui_helper,
        )
        self.assertIn(
            'duplicate_connection.putheader("x-openwebui-user-jwt", valid_token)',
            openwebui_helper,
        )
        for hand_rolled in ("hmac.new", "urlsafe_b64encode"):
            self.assertNotIn(hand_rolled, openwebui_helper)
        self.assertIn("wif_provider_request_count(preprod)", PREPROD_RECEIPT)
        self.assertIn('"metadata": {"aigw_service": "open-webui"}', PREPROD_RECEIPT)
        self.assertIn("REJECTED_OPENWEBUI_PARTIAL_MARKER_", PREPROD_RECEIPT)
        self.assertIn(
            'fail("an invalid Open WebUI identity request reached the provider")',
            PREPROD_RECEIPT,
        )
        self.assertIn(
            "Prove the full Cribl telemetry mirror and persistent recovery queue",
            PREPROD_TASKS,
        )
        self.assertIn("scripts/test-preprod-cribl-security.py", PREPROD_TASKS)
        main = PREPROD_RECEIPT.split("def main() -> int:", 1)[1]
        self.assertIn(
            "finally:\n        empty_controller_lifecycle_fixtures()", main
        )
        self.assertLess(
            main.index("write_controller_lifecycle_fixtures(token)"),
            main.index("finally:\n        empty_controller_lifecycle_fixtures()"),
        )
        self.assertLess(
            main.index("finally:\n        empty_controller_lifecycle_fixtures()"),
            main.index('print("PREPROD_CRIBL_TELEMETRY_PASSED")'),
        )

    def test_keycloak_projection_requires_complete_attribution(self) -> None:
        keycloak = ALLOY.split('loki.process "cribl_keycloak_auth"', 1)[1].split(
            'loki.process "cribl_envoy_tls"', 1
        )[0]
        attribution_labels = keycloak.index(
            "  stage.labels {", keycloak.index("?P<keycloak_user_id>")
        )
        for field, reason in (
            ("keycloak_realm_id", "missing_keycloak_realm"),
            ("keycloak_client_id", "missing_keycloak_client"),
            ("keycloak_user_id", "missing_keycloak_user"),
        ):
            self.assertIn(field, keycloak)
            self.assertIn(reason, keycloak)
            self.assertLess(keycloak.index(f"?P<{field}>"), attribution_labels)
            self.assertIn(
                field,
                keycloak[attribution_labels : keycloak.index(
                    "  stage.static_labels", attribution_labels
                )],
            )

    def test_structured_security_events_use_a_fixed_field_projection(self) -> None:
        structured = ALLOY.split(
            'loki.process "cribl_structured_security"', 1
        )[1].split('loki.source.file "controller_lifecycle"', 1)[0]
        self.assertIn('source = "aigw_security_line"', structured)
        self.assertIn(
            'stage.output { source = "aigw_security_line" }', structured
        )
        self.assertNotIn('stage.output { source = "aigw_security_json" }', structured)
        self.assertIn(
            'security_changed_type            = "type(changed)"',
            structured,
        )
        self.assertIn(
            'security_changed_present         = '
            '"contains(keys(@), \'changed\')"',
            structured,
        )
        self.assertIn(
            'template = `{{ if and (eq .security_changed_type "boolean") '
            '(eq .Value "true") }}true{{ else if and '
            '(eq .security_changed_type "boolean") (eq .Value "false") '
            '}}false{{ end }}`',
            structured,
        )
        self.assertNotIn("eq .Value true", structured)
        self.assertNotIn("eq .Value false", structured)
        self.assertIn(
            'source   = "security_changed_present"\n'
            '    template = `{{ if eq .Value "true" }}present{{ end }}`',
            structured,
        )
        self.assertIn(
            'selector            = '
            '"{security_changed_present!=\\"\\",security_changed=\\"\\"}"',
            structured,
        )
        self.assertIn('"security_changed_present",', structured)
        for raw_value, expected in (("true", True), ("false", False)):
            document = json.loads('{"changed":' + raw_value + "}")
            self.assertIs(type(document["changed"]), bool)
            self.assertIs(document["changed"], expected)
        for raw_value in ('"true"', '"false"', "null", "0", "1"):
            document = json.loads('{"changed":' + raw_value + "}")
            self.assertIsNot(type(document["changed"]), bool, raw_value)
        for field in (
            "security_subject",
            "security_project",
            "security_attempt",
            "security_rotation_id",
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
            "malformed_rotation_id",
            "malformed_rotation_attempt",
            "unexpected_rotation_attempt",
            "mismatched_rotation_status",
            "mismatched_rotation_outcome",
            "missing_vault_state",
            "missing_egress_policy_digest",
            "missing_egress_ca_fingerprints",
            "missing_egress_failure_reason",
        ):
            self.assertIn(reason, structured)

    def test_rotation_lifecycle_projection_is_bounded_and_correlated(self) -> None:
        structured = ALLOY.split(
            'loki.process "cribl_structured_security"', 1
        )[1].split('loki.source.file "controller_lifecycle"', 1)[0]
        attempt_pattern = (
            r'^(?:\{"action":"(?:attempt|recovery|rotate)",|'
            r'\{"schema_version":1,"event":"aigw\.provider\.rotation",'
            r'"action":"(?:attempt|recovery|rotate)",'
            r'"outcome":"(?:success|failure|failed)",'
            r'"vendor":"(?:anthropic|static-anthropic)",'
            r'"rotation_id":"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-'
            r'[89ab][0-9a-f]{3}-[0-9a-f]{12}",)'
            r'"attempt":(?P<security_attempt>[1-9][0-9]{0,2})(?:,|\})'
        )
        for required in (
            'security_attempt_present         = "contains(keys(@), \'attempt\')"',
            'security_rotation_id             = "rotation_id"',
            'template = `{{ if eq .Value "true" }}present{{ end }}`',
            'source     = "aigw_security_json"',
            f'expression = `{attempt_pattern}`',
            'security_action!~\\"start|attempt|rotate|recovery\\"',
            'security_rotation_status!~\\"started|success|failed|skipped|disabled|recovered\\"',
            'security_rotation_id!~\\"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\\"',
            'security_action=~\\"attempt|rotate|recovery\\",security_attempt!~\\"[1-9][0-9]{0,2}\\"',
            'security_action=\\"start\\",security_attempt_present!=\\"\\"',
            'security_event!=\\"aigw.provider.rotation\\",security_attempt_present!=\\"\\"',
            'security_action=\\"start\\",security_rotation_status=\\"started\\",security_outcome!=\\"success\\"',
            'security_action=\\"recovery\\",security_rotation_status=\\"recovered\\",security_outcome!=\\"success\\"',
            'security_action=~\\"attempt|rotate\\",security_rotation_status=\\"success\\",security_outcome!=\\"success\\"',
            'security_action=~\\"attempt|rotate\\",security_rotation_status=~\\"failed|skipped|disabled\\",security_outcome!=\\"failure\\"',
            'rotation_id={{ .security_rotation_id }}',
            'attempt={{ .security_attempt }}',
        ):
            self.assertIn(required, structured)
        self.assertNotIn('kindIs "float64"', structured)
        self.assertNotIn("rollback", structured)

        valid_attempts = (
            '{"action":"attempt","attempt":1,"event":"aigw.provider.rotation"}',
            '{"schema_version":1,"event":"aigw.provider.rotation",'
            '"action":"rotate","outcome":"success","vendor":"anthropic",'
            '"rotation_id":"123e4567-e89b-42d3-a456-426614174000",'
            '"attempt":999,"rotation_status":"success"}',
        )
        for document in valid_attempts:
            match = re.match(attempt_pattern, document)
            self.assertIsNotNone(match, document)
            self.assertRegex(match.group("security_attempt"), r"^[1-9][0-9]{0,2}$")

        rejected_attempts = (
            '{"action":"attempt","attempt":"1","event":"aigw.provider.rotation"}',
            '{"action":"attempt","attempt":1.5,"event":"aigw.provider.rotation"}',
            '{"action":"attempt","attempt":0,"event":"aigw.provider.rotation"}',
            '{"action":"attempt","attempt":1000,"event":"aigw.provider.rotation"}',
            '{"action":"attempt","attempt":false,"event":"aigw.provider.rotation"}',
            '{"action":"attempt","attempt":"","event":"aigw.provider.rotation"}',
            '{"action":"attempt","attempt":null,"event":"aigw.provider.rotation"}',
            '{"action":"attempt","event":"aigw.provider.rotation"}',
            '{"action":"attempt","detail":{"attempt":1},'
            '"event":"aigw.provider.rotation"}',
            '{"action":"start","attempt":1,"event":"aigw.provider.rotation"}',
        )
        for document in rejected_attempts:
            self.assertIsNone(re.match(attempt_pattern, document), document)

        for value in ("0", "false", '""', "null", '"1"', "1.5"):
            document = json.loads(
                '{"action":"start","attempt":'
                + value
                + ',"event":"aigw.provider.rotation"}'
            )
            self.assertIn("attempt", document, value)
        nested_only = json.loads(
            '{"action":"start","detail":{"attempt":1},'
            '"event":"aigw.provider.rotation"}'
        )
        self.assertNotIn("attempt", nested_only)

        for marker in (
            '"action":"start"',
            '"action":"attempt"',
            '"action":"rotate"',
            '"action":"recovery"',
            '"attempt":1',
            '"attempt":2',
            '"attempt":"1"',
            "DENIED_ROTATION_ID_",
            "DENIED_ROTATION_ATTEMPT_TYPE_",
            "DENIED_ROTATION_START_ATTEMPT_",
            "DENIED_ROTATION_START_OUTCOME_",
            "DENIED_ROTATION_RECOVERY_OUTCOME_",
            "DENIED_ROTATION_SUCCESS_OUTCOME_",
            "DENIED_ROTATION_FAILURE_OUTCOME_",
            "rotation_id=123e4567-e89b-42d3-a456-426614174000",
            "rotation_status=recovered",
        ):
            self.assertIn(marker, PREPROD_RECEIPT)

    def test_natural_portal_and_identity_events_have_exact_schemas(self) -> None:
        structured = ALLOY.split(
            'loki.process "cribl_structured_security"', 1
        )[1].split('loki.source.file "controller_lifecycle"', 1)[0]
        for action in (
            "authorization[.](role[.]denied|step_up[.]required)",
            "identity[.]group[.](create|delete)|identity[.]member[.]add",
            "bootstrap_cleanup",
            "break_glass_activate|break_glass_disable",
            "ldap_check",
            "ldap_drift_detected|ldap_recovery",
            "managed_identity_change_applied|managed_identity_change_planned",
            "managed_identity_drift_detected|managed_identity_recovery",
        ):
            self.assertIn(action, structured)
        for reason in (
            "mismatched_portal_event_schema",
            "unexpected_portal_event_detail",
            "mismatched_identity_event_schema",
            "unexpected_identity_event_detail",
        ):
            self.assertIn(reason, structured)
        for detail_flag in (
            "security_detail_any",
            "security_detail_except_changed",
            "security_detail_except_error",
            "security_detail_except_ldap",
            "security_detail_except_ldap_error",
            "security_detail_except_ldap_operation",
            "security_detail_except_managed_change",
            "security_detail_except_error_operation",
        ):
            self.assertIn(detail_flag, structured)
            self.assertIn(f'"{detail_flag}",', structured)

        for marker in (
            '"action":"authorization.role.denied","outcome":"failure"',
            '"action":"authorization.step_up.required","outcome":"failure"',
            '"action":"identity.group.create","outcome":"intent"',
            '"action":"identity.group.create","outcome":"success"',
            '"action":"identity.group.delete","outcome":"failure"',
            '"action":"identity.member.add","outcome":"indeterminate"',
            '"action":"identity.group.policy","outcome":"success"',
            '"action":"bootstrap_cleanup","outcome":"success","changed":true',
            '"action":"break_glass_activate","outcome":"failed","error_type":"IdentityConflict"',
            '"action":"ldap_check","outcome":"failed","error_type":"IdentityConflict"',
            '"action":"ldap_drift_detected","outcome":"failed","ldap_provider":"corp-ad","operation_id"',
            '"action":"ldap_recovery","outcome":"success","ldap_provider":"corp-ad","operation_id"',
            '"action":"managed_identity_change_planned","outcome":"success","changed":true,"change_kind":"planned_change","operation_id"',
            '"action":"managed_identity_change_applied","outcome":"success","changed":true,"change_kind":"planned_change","operation_id"',
            '"action":"managed_identity_drift_detected","outcome":"failed","changed":true,"change_kind":"security_drift","operation_id"',
            '"action":"managed_identity_recovery","outcome":"success","changed":true,"change_kind":"security_drift","operation_id"',
            "DENIED_PORTAL_OUTCOME_",
            "DENIED_PORTAL_DETAIL_",
            "DENIED_BOOTSTRAP_OUTCOME_",
            "DENIED_BREAK_GLASS_SCHEMA_",
            "DENIED_LDAP_CHECK_OUTCOME_",
            "DENIED_LDAP_RECOVERY_OUTCOME_",
            "DENIED_MANAGED_RECOVERY_",
        ):
            self.assertIn(marker, PREPROD_RECEIPT)

    def test_model_governance_events_have_a_fixed_cribl_projection(self) -> None:
        structured = ALLOY.split(
            'loki.process "cribl_structured_security"', 1
        )[1].split('loki.source.file "controller_lifecycle"', 1)[0]
        for required in (
            'security_model                   = "model"',
            'security_provider                = "provider"',
            'security_usage_class             = "usage_class"',
            'model[.]governance[.](create|activate|show|hide|retire)',
            'model[.]price[.](create|backdate[.](preview|confirm))',
            'security_outcome!~\\"intent|success|failure|indeterminate\\"',
            'security_model=\\"\\"',
            'security_provider=\\"\\"',
            'security_usage_class=\\"\\"',
            'security_detail_except_operation!=\\"\\"',
            'security_action=~\\"model[.]governance[.]create|model[.]price[.](create|backdate[.]preview)\\",security_field_count!=\\"8\\"',
            'security_action=\\"model.price.backdate.confirm\\",security_outcome=\\"success\\",security_field_count!=\\"8\\"',
            'security_action=\\"model.price.backdate.confirm\\",security_outcome!=\\"success\\",security_field_count!=\\"6\\"',
            'security_action=~\\"model[.]governance[.](activate|show|hide|retire)\\",security_field_count!=\\"7\\"',
            'security_model!~\\"|[A-Za-z0-9][A-Za-z0-9_./:-]{0,127}\\"',
            'security_provider!~\\"|anthropic|unattributed\\"',
            'security_event!=\\"aigw.usage.audit\\",security_provider=\\"unattributed\\"',
            'security_usage_class!~\\"|normal_input|cache_creation_5m|cache_creation_1h|cache_read|output\\"',
            'model={{ .security_model }}',
            'provider={{ .security_provider }}',
            'usage_class={{ .security_usage_class }}',
            '"security_model",',
            '"security_provider",',
            '"security_usage_class",',
        ):
            self.assertIn(required, structured)

        for marker in (
            '"action":"model.governance.create","outcome":"intent"',
            '"action":"model.governance.create","outcome":"success"',
            '"action":"model.governance.activate","outcome":"intent"',
            '"action":"model.governance.activate","outcome":"success"',
            '"action":"model.price.create","outcome":"intent"',
            '"action":"model.price.create","outcome":"success"',
            '"action":"model.price.backdate.preview","outcome":"intent"',
            '"action":"model.price.backdate.preview","outcome":"success"',
            '"action":"model.price.backdate.confirm","outcome":"intent"',
            '"action":"model.price.backdate.confirm","outcome":"success"',
            "DENIED_MODEL_PROVIDER_",
            "DENIED_MODEL_USAGE_CLASS_",
            "DENIED_UNEXPECTED_MODEL_",
            "event=aigw.portal.audit action=model.governance.create",
            "event=aigw.portal.audit action=model.governance.activate",
            "event=aigw.portal.audit action=model.price.create",
            "event=aigw.portal.audit action=model.price.backdate.preview",
            "event=aigw.portal.audit action=model.price.backdate.confirm",
        ):
            self.assertIn(marker, PREPROD_RECEIPT)

    def test_backend_price_events_have_a_fixed_cribl_projection(self) -> None:
        structured = ALLOY.split(
            'loki.process "cribl_structured_security"', 1
        )[1].split('loki.source.file "controller_lifecycle"', 1)[0]
        for required in (
            'aigw[.]price[.]audit',
            'security_action!~\\"create|backdate_preview|backdate_confirm\\"',
            'security_event=\\"aigw.price.audit\\",security_outcome!=\\"success\\"',
            'security_event=\\"aigw.price.audit\\",security_field_count!=\\"16\\"',
            'security_detail_except_price!=\\"\\"',
            'security_event!=\\"aigw.price.audit\\",security_price_detail!=\\"\\"',
            'security_amount_usd              = "amount_usd"',
            'security_token_unit              = "token_unit"',
            'security_effective_at            = "effective_at"',
            'security_source_reference        = "source_reference"',
            'security_review_note_sha256       = "review_note_sha256"',
            'security_old_policy_sha256        = "old_policy_sha256"',
            'security_candidate_sha256        = "candidate_sha256"',
            'amount_usd={{ .security_amount_usd }}',
            'token_unit={{ .security_token_unit }}',
            'effective_at={{ .security_effective_at }}',
            'source_reference={{ .security_source_reference }}',
            'review_note_sha256={{ .security_review_note_sha256 }}',
            'old_policy_sha256={{ .security_old_policy_sha256 }}',
            'candidate_sha256={{ .security_candidate_sha256 }}',
            'security_review_note_sha256!~\\"[0-9a-f]{64}\\"',
            'security_old_policy_sha256!~\\"[0-9a-f]{64}\\"',
            'security_candidate_sha256!~\\"[0-9a-f]{64}\\"',
        ):
            self.assertIn(required, structured)

        label_drop = structured.rsplit("stage.label_drop {", 1)[1]
        for field in (
            "security_amount_usd",
            "security_token_unit",
            "security_effective_at",
            "security_source_reference",
            "security_review_note_sha256",
            "security_old_policy_sha256",
            "security_candidate_sha256",
        ):
            self.assertIn(f'"{field}",', label_drop)

        # Free-form review text stays in PostgreSQL. Only its integrity digest
        # is allowed into the outbound SOC record.
        output = structured.split('source = "aigw_security_line"', 1)[1]
        self.assertNotIn("{{ .security_review_note }}", output)

    def test_litellm_model_limit_events_have_a_fixed_cribl_projection(self) -> None:
        structured = ALLOY.split(
            'loki.process "cribl_structured_security"', 1
        )[1].split('loki.source.file "controller_lifecycle"', 1)[0]
        for required in (
            'security_control                 = "control"',
            'service=\\"litellm\\",security_event!~\\"aigw[.]model[.]limit|aigw[.]usage[.]audit\\"',
            'security_action!~\\"reserve|deny|fail_closed\\"',
            'security_outcome!~\\"success|denied|failure\\"',
            'security_control!~\\"|max_output_per_request|output_tokens_per_utc_minute\\"',
            'security_reason!~\\"|config_override_rejected|',
            'capacity_reserved|request_cap_exceeded|minute_quota_exceeded|policy_invalid|redis_unavailable',
            'security_detail_except_model_limit!=\\"\\"',
            'security_event=\\"aigw.model.limit\\",security_field_count!=\\"8\\"',
            'security_action=\\"reserve\\",security_reason!=\\"capacity_reserved\\"',
            'security_action=\\"reserve\\",security_control!=\\"output_tokens_per_utc_minute\\"',
            'security_action=\\"fail_closed\\",security_control=\\"max_output_per_request\\",security_reason!=\\"policy_invalid\\"',
            'security_action=\\"fail_closed\\",security_control=\\"output_tokens_per_utc_minute\\",security_reason!=\\"redis_unavailable\\"',
            'control={{ .security_control }}',
            '"security_control",',
            '"security_detail_except_model_limit",',
        ):
            self.assertIn(required, structured)

        for marker in (
            '"event":"aigw.model.limit"',
            '"action":"reserve","outcome":"success"',
            '"action":"deny","outcome":"denied"',
            '"action":"fail_closed","outcome":"failure"',
            "MODEL_LIMIT_PROMPT_SECRET_",
            "DENIED_MODEL_LIMIT_EXTRA_",
            "DENIED_MODEL_LIMIT_OUTCOME_",
            "event=aigw.model.limit action=reserve outcome=success",
            "reason=capacity_reserved",
            "event=aigw.model.limit action=deny outcome=denied",
            "event=aigw.model.limit action=fail_closed outcome=failure",
        ):
            self.assertIn(marker, PREPROD_RECEIPT)

    def test_usage_events_have_a_fixed_prompt_free_cribl_projection(self) -> None:
        structured = ALLOY.split(
            'loki.process "cribl_structured_security"', 1
        )[1].split('loki.source.file "controller_lifecycle"', 1)[0]
        for required in (
            'security_completeness            = "completeness"',
            'security_event_id                = "event_id"',
            'security_request_id              = "request_id"',
            'aigw[.]usage[.]audit',
            'security_action!~\\"record|replay|write_failed|conflict|delivery_failure\\"',
            'security_action=~\\"record|replay\\",security_outcome!=\\"success\\"',
            'security_action=~\\"write_failed|conflict|delivery_failure\\",security_outcome!=\\"failure\\"',
            'security_field_count!=\\"11\\"',
            'security_detail_except_usage!=\\"\\"',
            'security_event_id!~\\"|unattributed|[0-9a-f]{64}\\"',
            'security_request_id!~\\"|[A-Za-z0-9][A-Za-z0-9_.:@/+-]{0,255}\\"',
            'security_completeness!~\\"|complete|partial|unknown|not_applicable\\"',
            'event_id={{ .security_event_id }}',
            'request_id={{ .security_request_id }}',
            'completeness={{ .security_completeness }}',
            '"security_event_id",',
            '"security_request_id",',
            '"security_completeness",',
        ):
            self.assertIn(required, structured)

        # Join identifiers are body fields only, never Loki labels.
        label_drop = structured.rsplit("stage.label_drop {", 1)[1]
        self.assertIn('"security_event_id",', label_drop)
        self.assertIn('"security_request_id",', label_drop)

    def test_request_span_source_time_is_restored_before_the_common_gate(self) -> None:
        request_filter = ALLOY.split(
            'otelcol.processor.filter "aigw_request_spans"', 1
        )[1].split('otelcol.processor.transform "aigw_request_event_time"', 1)[0]
        time_bridge = ALLOY.split(
            'otelcol.processor.transform "aigw_request_event_time"', 1
        )[1].split('otelcol.connector.spanlogs "aigw_requests"', 1)[0]
        request_stream = ALLOY.split(
            'otelcol.processor.transform "aigw_request_stream"', 1
        )[1].split('otelcol.processor.attributes "aigw_request_stream_labels"', 1)[0]
        self.assertIn(
            "traces = [otelcol.processor.transform.aigw_request_event_time.input]",
            request_filter,
        )
        self.assertIn(
            'set(attributes["aigw.security.source_time_unix_nano"], start_time_unix_nano)',
            time_bridge,
        )
        spanlogs = ALLOY.split(
            'otelcol.connector.spanlogs "aigw_requests"', 1
        )[1].split('otelcol.processor.transform "aigw_request_stream"', 1)[0]
        labels = spanlogs.split("  labels = [", 1)[1].split("  ]", 1)[0]
        span_attributes = spanlogs.split("  span_attributes = [", 1)[1].split(
            "  ]", 1
        )[0]
        self.assertIn('"aigw.user.name_source",', labels)
        self.assertIn('"aigw.security.source_time_unix_nano",', labels)
        self.assertIn('"aigw.security.source_time_unix_nano",', span_attributes)
        self.assertTrue(
            span_attributes.lstrip().startswith(
                '"aigw.security.source_time_unix_nano",'
            )
        )
        restore = (
            'set(time_unix_nano, '
            'attributes["aigw.security.source_time_unix_nano"])'
        )
        scrub = (
            r'replace_pattern(body, "^(span=litellm_request dur=[0-9]+ns'
            r'(?: status=[^[:space:]]+)?) aigw\\.security\\.'
            r'source_time_unix_nano=[0-9]+", "$1") where IsString(body)'
        )
        delete = 'delete_key(attributes, "aigw.security.source_time_unix_nano")'
        for statement in (restore, scrub, delete):
            self.assertIn(statement, request_stream)
        self.assertLess(request_stream.index(restore), request_stream.index(scrub))
        self.assertLess(request_stream.index(scrub), request_stream.index(delete))
        scrub_pattern = re.compile(
            r"^(span=litellm_request dur=[0-9]+ns(?: status=\S+)?) "
            r"aigw\.security\.source_time_unix_nano=[0-9]+"
        )
        generated = (
            "span=litellm_request dur=42ns "
            "aigw.security.source_time_unix_nano=1000 "
            'gen_ai.input.messages="hello"'
        )
        self.assertEqual(
            scrub_pattern.sub(r"\1", generated),
            'span=litellm_request dur=42ns gen_ai.input.messages="hello"',
        )
        prompt_evidence = (
            "span=litellm_request dur=42ns aigw.user.id=user-1 "
            'gen_ai.input.messages="say '
            'aigw.security.source_time_unix_nano=1000"'
        )
        self.assertEqual(scrub_pattern.sub(r"\1", prompt_evidence), prompt_evidence)

    def test_common_security_record_fields_are_server_owned_before_log_batch(self) -> None:
        alloy = COMPOSE.split("  alloy:\n", 1)[1].split("\n  prometheus:", 1)[0]
        preprod_alloy = PREPROD_OVERLAY.split("  alloy:\n", 1)[1].split(
            "\n  prometheus:", 1
        )[0]
        self.assertIn("AIGW_DEPLOYMENT_ENVIRONMENT: production", alloy)
        self.assertNotIn("${AIGW_DEPLOYMENT_ENVIRONMENT", alloy)
        self.assertIn("AIGW_DEPLOYMENT_ENVIRONMENT: preprod", preprod_alloy)

        contract = ALLOY.split(
            'otelcol.processor.transform "cribl_security_contract"', 1
        )[1].split('otelcol.processor.filter "cribl_common_record"', 1)[0]
        for required in (
            'set(attributes["aigw.security.event_class"], attributes["aigw_security_event_class"])',
            'delete_matching_keys(attributes, "^(?:deployment\\\\.environment|service\\\\.name|aigw\\\\.security\\\\.producer|aigw_security_event_class)$")',
            'set(attributes["aigw.security.schema_version"], 1)',
            'set(resource.attributes["deployment.environment"], "` + '
            'sys.env("AIGW_DEPLOYMENT_ENVIRONMENT") + `")',
            'set(attributes["aigw.security.producer"], "")',
            'set(resource.attributes["service.name"], "")',
        ):
            self.assertIn(required, contract)

        mappings = {
            "ai_request_audit": "litellm",
            "keycloak_event": "keycloak",
            "egress_tls": "envoy-egress",
            "vault_audit": "vault",
            "controller_lifecycle": "controller",
        }
        for event_class, producer in mappings.items():
            condition = (
                f'attributes["aigw.security.event_class"] == "{event_class}"'
            )
            self.assertIn(
                f'set(attributes["aigw.security.producer"], "{producer}") where {condition}',
                contract,
            )
            self.assertIn(
                f'set(resource.attributes["service.name"], "{producer}") where {condition}',
                contract,
            )
        for producer in (
            "dev-portal",
            "admin-portal",
            "key-rotator",
            "envoy-egress",
            "litellm",
        ):
            condition = (
                'attributes["aigw.security.event_class"] == "security_event" '
                f'and attributes["service"] == "{producer}"'
            )
            self.assertIn(
                f'set(attributes["aigw.security.producer"], "{producer}") where {condition}',
                contract,
            )
            self.assertIn(
                f'set(resource.attributes["service.name"], "{producer}") where {condition}',
                contract,
            )

        self.assertIn(
            "logs = [otelcol.processor.filter.cribl_common_record.input]", contract
        )
        for signal in ("logs", "metrics", "traces"):
            self.assertEqual(
                ALLOY.count(f'otelcol.processor.batch "cribl_{signal}"'), 1
            )
        self.assertEqual(
            ALLOY.count("logs = [otelcol.processor.batch.cribl_logs.input]"), 2
        )
        self.assertEqual(ALLOY.count("otelcol.exporter.otlp.cribl.input"), 3)

    def test_common_record_gate_rejects_bad_identity_and_event_time(self) -> None:
        gate = ALLOY.split(
            'otelcol.processor.filter "cribl_common_record"', 1
        )[1].split('otelcol.processor.batch "cribl_logs"', 1)[0]
        for required in (
            'error_mode = "propagate"',
            'attributes["aigw.security.schema_version"] != 1',
            'resource.attributes["deployment.environment"] != "preprod"',
            'resource.attributes["deployment.environment"] != "production"',
            'not IsString(attributes["aigw.security.producer"])',
            'resource.attributes["service.name"] != attributes["aigw.security.producer"]',
            'time_unix_nano == 0',
            'time_unix_nano < UnixNano(Now()) - 86400000000000',
            'time_unix_nano > UnixNano(Now()) + 60000000000',
            "logs = [otelcol.processor.batch.cribl_logs.input]",
        ):
            self.assertIn(required, gate)
        for event_class in (
            "ai_request_audit",
            "keycloak_event",
            "egress_tls",
            "vault_audit",
            "security_event",
            "controller_lifecycle",
        ):
            self.assertIn(
                f'attributes["aigw.security.event_class"] == "{event_class}"',
                gate,
            )

    def test_controller_lifecycle_source_is_exact_rotated_and_fixed_projection(self) -> None:
        source = ALLOY.split(
            'loki.source.file "controller_lifecycle"', 1
        )[1].split('loki.process "cribl_controller_lifecycle"', 1)[0]
        process = ALLOY.split(
            'loki.process "cribl_controller_lifecycle"', 1
        )[1].split('loki.source.file "vault_audit"', 1)[0]
        for path in (
            "/var/log/aigw/controller/lifecycle.jsonl",
            "/var/log/aigw/controller/lifecycle.jsonl.1",
        ):
            self.assertIn(path, source)
        for required in (
            "upgrade|rollback",
            "started|success|failed",
            "[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab]",
            "(?:[0-9a-f]{40}|[0-9a-f]{64})",
            "sha256:[0-9a-f]{64}",
            'drop_counter_reason = "malformed_controller_lifecycle_record"',
            "schema_version=1 event=aigw.controller.lifecycle",
            'aigw_security_event_class = "controller_lifecycle"',
            "otelcol.receiver.loki.cribl_security_logs.receiver",
        ):
            self.assertIn(required, process)
        self.assertIn(
            "/var/log/ai-gateway-controller:/var/log/aigw/controller:ro",
            COMPOSE,
        )
        self.assertIn(
            "./secrets/preprod-controller-lifecycle:/var/log/aigw/controller:ro",
            PREPROD_OVERLAY,
        )

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
