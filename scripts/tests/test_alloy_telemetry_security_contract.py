from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ALLOY = ROOT / "compose/alloy/config.alloy"
COMPOSE = ROOT / "compose/docker-compose.yml"


def managed(text: str, label: str) -> str:
    begin = f"// BEGIN AIGW MANAGED {label}"
    end = f"// END AIGW MANAGED {label}"
    if text.count(begin) != 1 or text.count(end) != 1:
        raise AssertionError(f"invalid managed block: {label}")
    return text.split(begin, 1)[1].split(end, 1)[0]


def deletion_patterns(sanitizer: str) -> list[re.Pattern[str]]:
    encoded = re.findall(
        r'delete_matching_keys\(attributes, "((?:\\.|[^"\\])*)"\)',
        sanitizer,
    )
    # Alloy raw strings still contain an OTTL double-quoted string. JSON
    # decoding mirrors the OTTL string escape layer before Python evaluates
    # the same RE2-compatible expressions against representative keys.
    return [re.compile(json.loads(f'"{value}"')) for value in dict.fromkeys(encoded)]


class AlloyTelemetrySecurityContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.alloy = ALLOY.read_text(encoding="utf-8")
        cls.compose = COMPOSE.read_text(encoding="utf-8")
        cls.correlation = managed(cls.alloy, "TRACE CORRELATION")
        cls.sanitizer = managed(cls.alloy, "SENSITIVE ATTRIBUTE FILTER")
        cls.patterns = deletion_patterns(cls.sanitizer)

    def test_only_server_authenticated_identity_is_promoted(self) -> None:
        expected = {
            "aigw.user.id": "metadata.user_api_key_user_id",
            "aigw.api_key.id": "metadata.user_api_key_hash",
            "aigw.request.id": "litellm.call_id",
            "aigw.project.id": "metadata.user_api_key_project_id",
            "aigw.enduser.id": "metadata.user_api_key_end_user_id",
            "aigw.user.name": "metadata.user_api_key_alias",
        }
        for canonical, source in expected.items():
            self.assertIn(f'attributes["{canonical}"]', self.correlation)
            self.assertIn(f'attributes["{source}"]', self.correlation)

        # LiteLLM OSS 1.91.3 cannot create native projects. Portal keys carry
        # the project in server-issued auth metadata, so that narrow fallback
        # remains until project management is available, but can never
        # overwrite a future native project_id.
        self.assertIn("metadata.user_api_key_auth_metadata", self.correlation)
        self.assertIn('attributes["aigw.project.id"] == nil', self.correlation)
        self.assertIn("^[0-9a-f]{64}$", self.correlation)
        self.assertNotIn("aigw.api_key.alias", self.correlation)
        self.assertNotIn("llm.user", self.correlation)

    def test_readable_identity_is_prioritized_bounded_and_always_present(self) -> None:
        """aigw.user.name resolution order (first match wins): the header-
        forwarded chat end user, the portal-stamped aigw_username, the key
        alias, then the opaque aigw.user.id so the field (and its Loki label)
        never goes missing. Every source is regex-bounded because these become
        log fields and a stream label."""
        statements = self.correlation.split("statements = [", 1)[1]
        order = [
            'set(attributes["aigw.enduser.id"], attributes["metadata.user_api_key_end_user_id"])',
            'set(attributes["aigw.user.name"], attributes["aigw.enduser.id"])',
            "aigw_username",
            'set(attributes["aigw.user.name"], attributes["metadata.user_api_key_alias"])',
            'set(attributes["aigw.user.name"], attributes["aigw.user.id"])',
        ]
        positions = [statements.index(fragment) for fragment in order]
        self.assertEqual(positions, sorted(positions))
        # Every fallback except the seed rule is nil-guarded so a higher-
        # priority identity is never overwritten.
        self.assertEqual(
            statements.count('attributes["aigw.user.name"] == nil'), 3
        )
        # Bounded charsets: the end-user/alias rule and the portal-username
        # extraction (kept textually identical to the dev-portal stamper).
        self.assertEqual(
            statements.count("^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$"), 3
        )
        self.assertIn(
            "(?P<username>[A-Za-z0-9][A-Za-z0-9_.@-]{0,63})", statements
        )

    def test_every_otlp_signal_is_sanitized_before_batch_and_export(self) -> None:
        memory = self.alloy.split(
            'otelcol.processor.memory_limiter "default"', 1
        )[1].split("// Promote only", 1)[0]
        self.assertIn(
            "traces  = [otelcol.processor.transform.aigw_correlation.input]",
            memory,
        )
        for signal in ("logs", "metrics"):
            self.assertIn(
                f"{signal}    = [otelcol.processor.transform.aigw_sensitive_attributes.input]"
                if signal == "logs"
                else f"{signal} = [otelcol.processor.transform.aigw_sensitive_attributes.input]",
                memory,
            )
        self.assertIn(
            "traces = [otelcol.processor.transform.aigw_sensitive_attributes.input]",
            self.correlation,
        )
        for context in ('context = "span"', 'context = "spanevent"', 'context = "datapoint"', 'context = "log"'):
            self.assertIn(context, self.sanitizer)
        self.assertEqual(self.sanitizer.count('context = "resource"'), 3)
        self.assertEqual(self.sanitizer.count('context = "scope"'), 3)
        self.assertIn('error_mode = "propagate"', self.sanitizer)
        self.assertNotIn('error_mode = "ignore"', self.sanitizer)
        for signal in ("traces", "logs", "metrics"):
            self.assertRegex(
                self.sanitizer,
                rf"{signal}\s+= \[otelcol\.processor\.batch\.default\.input\]",
            )

    def test_sensitive_attributes_are_deleted_and_required_content_is_retained(self) -> None:
        sensitive = (
            "authorization",
            "api_key",
            "x-api-key",
            "access_token",
            "client_secret",
            "password",
            "headers",
            "hidden_params",
            "proxy_server_request",
            "metadata.user_api_key_hash",
            "metadata.user_api_key_alias",
            "metadata.user_api_key_user_id",
            "metadata.user_api_key_project_id",
            "metadata.user_api_key_auth_metadata",
            "metadata.user_api_key_user_email",
            "metadata.requester_ip_address",
            "metadata.requester_metadata",
            "requester_metadata",
            "http.request.header.authorization",
            "http.request.header.x-forwarded-for",
            "http.response.header.set-cookie",
            "client.address",
            "network.peer.address",
            "net.peer.ip",
            "http.client_ip",
            "url.query",
            "enduser.email",
        )
        for key in sensitive:
            self.assertTrue(
                any(pattern.search(key) for pattern in self.patterns),
                f"sensitive attribute is not removed: {key}",
            )

        retained = (
            "aigw.user.id",
            "aigw.user.name",
            "aigw.enduser.id",
            "aigw.project.id",
            "aigw.api_key.id",
            "aigw.request.id",
            "gen_ai.input.messages",
            "gen_ai.output.messages",
            "gen_ai.prompt.0.content",
            "gen_ai.completion.0.content",
            "gen_ai.request.model",
            "gen_ai.usage.input_tokens",
            "http.response.status_code",
        )
        for key in retained:
            self.assertFalse(
                any(pattern.search(key) for pattern in self.patterns),
                f"required attribute would be removed: {key}",
            )

        for body_contract in (
            'delete_matching_keys(body,',
            '<redacted-structured-log-body>',
            '<redacted-credential>',
            '<redacted-authorization>',
            '<redacted-vendor-key>',
            'where IsMap(body)',
            'where IsString(body)',
        ):
            self.assertIn(body_contract, self.sanitizer)

        docker_logs = self.alloy.split('loki.process "docker"', 1)[1].split(
            'loki.process "external_file_logs"', 1
        )[0]
        self.assertIn('(?:(?:bearer|basic)\\s+)?([^"\'\\s,}]{8,})', docker_logs)
        self.assertIn('(?:bearer|basic)\\s+([A-Za-z0-9._~+/-]{8,})', docker_logs)
        self.assertNotIn('${1}<redacted>', docker_logs)
        # Grafana Logs Drilldown keys on the OTel-semantic service_name label;
        # dropping it silently empties that whole UI (observed live).
        self.assertIn('service_name = "service"', docker_logs)

    def test_cribl_queue_is_durable_bounded_and_sized_for_a_day_of_outage(self) -> None:
        storage = self.alloy.split(
            'otelcol.storage.file "cribl_queue"', 1
        )[1].split("}\n\n", 1)[0]
        self.assertIn('directory             = "/var/lib/alloy/queues/cribl"', storage)
        self.assertIn("fsync                  = true", storage)
        self.assertIn("on_start                      = true", storage)
        self.assertIn("on_rebound                    = true", storage)
        self.assertIn("rebound_needed_threshold_mib  = 2048", storage)
        self.assertIn("rebound_trigger_threshold_mib = 512", storage)

        exporter = self.alloy.split(
            'otelcol.exporter.otlp "cribl"', 1
        )[1].split("\n}\n", 1)[0]
        # Owner decision: the persistent queue is the ~24h Cribl-outage
        # buffer; 2 GiB byte-bounded, never an unbounded batch count.
        self.assertIn("queue_size        = 2147483648", exporter)
        self.assertIn('sizer             = "bytes"', exporter)
        self.assertIn(
            "storage           = otelcol.storage.file.cribl_queue.handler",
            exporter,
        )
        self.assertIn('max_elapsed_time = "24h"', exporter)
        self.assertNotIn('max_elapsed_time = "0s"', exporter)

        # Tempo was removed: no second OTLP exporter, no tempo queue, and no
        # TEMPO_INGEST_IP contract may survive anywhere in the pipeline.
        self.assertNotRegex(
            self.alloy,
            r'(?m)^(?:otelcol|loki|prometheus)\.[^{\n]+\s+"tempo"',
        )
        self.assertNotIn("TEMPO_INGEST_IP", self.compose)

        alloy_service = self.compose.split("  alloy:\n", 1)[1].split(
            "  loki:\n", 1
        )[0]
        self.assertIn("- alloy_data:/var/lib/alloy", alloy_service)
        self.assertIn("- --stability.level=public-preview", alloy_service)
        self.assertIn("- --disable-reporting", alloy_service)

    def test_request_stream_is_filtered_allowlisted_and_labeled_for_drilldown(self) -> None:
        # The Loki request stream must be fed from the SANITIZED trace path.
        # Raw traces stay local to span-derived metrics and the exact request
        # converter; the default batch must never reference Cribl.
        batch = self.alloy.split('otelcol.processor.batch "default"', 1)[1].split(
            "\n}\n", 1
        )[0]
        self.assertNotIn("otelcol.exporter.otlp.cribl.input", batch)
        self.assertIn("otelcol.connector.spanmetrics.default.input", batch)
        self.assertIn("otelcol.processor.filter.aigw_request_spans.input", batch)

        # Only the exact litellm_request span may become a log line; sibling
        # spans (raw vendor payload, proxy request) and same-name spans from a
        # different service are dropped before the external log queue.
        span_filter = self.alloy.split(
            'otelcol.processor.filter "aigw_request_spans"', 1
        )[1].split("\n}\n", 1)[0]
        self.assertIn(
            '`resource.attributes["service.name"] != "litellm" or name != "litellm_request"`',
            span_filter,
        )
        self.assertIn('error_mode = "propagate"', span_filter)
        self.assertIn(
            "traces = [otelcol.connector.spanlogs.aigw_requests.input]", span_filter
        )

        spanlogs = self.alloy.split(
            'otelcol.connector.spanlogs "aigw_requests"', 1
        )[1].split("\n}\n", 1)[0]
        self.assertIn("spans  = true", spanlogs)
        # Bounded-cardinality attribution labels only: user/project populations
        # are small and this is one dedicated stream. Request-id and key-id are
        # unbounded/high-churn and must never become labels.
        self.assertIn(
            'labels = [\n    "aigw.user.name",\n    "aigw.project.id",\n  ]',
            spanlogs,
        )
        for forbidden_label in ("aigw.request.id", "aigw.api_key.id"):
            self.assertNotIn(
                forbidden_label,
                spanlogs.split("labels = [", 1)[1].split("]", 1)[0],
            )
        for attribute in (
            "aigw.user.id",
            "aigw.user.name",
            "aigw.enduser.id",
            "aigw.api_key.id",
            "aigw.project.id",
            "aigw.request.id",
            "gen_ai.request.model",
            "gen_ai.response.model",
            "litellm.model_group",
            "gen_ai.usage.input_tokens",
            "gen_ai.usage.output_tokens",
            "gen_ai.usage.total_tokens",
            "gen_ai.cost.total_cost",
            "gen_ai.response.finish_reasons",
            "llm.is_streaming",
            "http.route",
            "litellm.call_id",
            "gen_ai.input.messages",
            "gen_ai.output.messages",
        ):
            self.assertIn(f'"{attribute}",', spanlogs)
        # Allow-list only: never a raw credential/identity source.
        for forbidden in ("authorization", "metadata.user_api_key", "headers"):
            self.assertNotIn(forbidden, spanlogs)
        self.assertIn(
            "logs = [otelcol.processor.transform.aigw_request_stream.input]",
            spanlogs,
        )

        # Grafana Logs Drilldown keys on service_name; the stream identity is
        # pinned on the resource and promoted via the documented Loki hint.
        transform = self.alloy.split(
            'otelcol.processor.transform "aigw_request_stream"', 1
        )[1].split("\n}\n", 1)[0]
        self.assertIn('error_mode = "propagate"', transform)
        self.assertNotIn('error_mode = "ignore"', transform)
        self.assertIn(
            '`set(attributes["service.name"], "aigw-requests")`', transform
        )
        self.assertIn(
            "logs = [otelcol.processor.attributes.aigw_request_stream_labels.input]",
            transform,
        )
        labels = self.alloy.split(
            'otelcol.processor.attributes "aigw_request_stream_labels"', 1
        )[1].split("\n}\n", 1)[0]
        self.assertIn('key    = "loki.resource.labels"', labels)
        self.assertIn('value  = "service.name"', labels)
        # The documented hint promotes exactly the two bounded attribution
        # attributes into aigw_user_name / aigw_project_id stream labels.
        self.assertIn('key    = "loki.attribute.labels"', labels)
        self.assertIn('value  = "aigw.user.name, aigw.project.id"', labels)
        self.assertIn("otelcol.exporter.loki.local.input", labels)
        self.assertIn(
            "otelcol.processor.transform.cribl_security_contract.input", labels
        )

    def test_cribl_has_one_logs_only_fail_closed_queue_ingress(self) -> None:
        self.assertEqual(
            self.alloy.count("otelcol.exporter.otlp.cribl.input"), 1
        )
        security_batch = self.alloy.split(
            'otelcol.processor.batch "cribl_security"', 1
        )[1].split("\n}\n", 1)[0]
        self.assertIn("logs = [otelcol.exporter.otlp.cribl.input]", security_batch)
        self.assertNotIn("traces", security_batch)
        self.assertNotIn("metrics", security_batch)
        self.assertNotIn('otelcol.receiver.loki "file_logs"', self.alloy)
        self.assertNotIn('otelcol.processor.batch "file_logs"', self.alloy)
        contract = self.alloy.split(
            'otelcol.processor.transform "cribl_security_contract"', 1
        )[1].split("\n}\n", 1)[0]
        self.assertIn('error_mode = "propagate"', contract)
        self.assertIn(
            '`set(attributes["aigw.security.schema_version"], 1)`', contract
        )
        self.assertIn("otelcol.processor.batch.cribl_security.input", contract)

        default_batch = self.alloy.split(
            'otelcol.processor.batch "default"', 1
        )[1].split("\n}\n", 1)[0]
        self.assertNotIn("cribl", default_batch.lower())

        vault = self.alloy.split('loki.source.file "vault_audit"', 1)[1].split(
            "\n}\n", 1
        )[0]
        self.assertIn("loki.write.local.receiver", vault)
        self.assertNotIn("cribl", vault.lower())
        self.assertNotIn("otelcol.receiver", vault)

    def test_security_classifiers_are_exact_and_non_recursive(self) -> None:
        keycloak = self.alloy.split(
            'loki.process "cribl_keycloak_auth"', 1
        )[1].split('\nloki.process "cribl_structured_security"', 1)[0]
        for required in (
            'project!~\\"ai-gateway|aigw-preprod\\"',
            'service!=\\"keycloak\\"',
            'keycloak_logger!=\\"org.keycloak.events\\"',
            'keycloak_event=\\"\\"',
            "USER_DISABLED_BY_PERMANENT_LOCKOUT",
            "USER_DISABLED_BY_TEMPORARY_LOCKOUT",
        ):
            self.assertIn(required, keycloak)
        self.assertIn(
            "otelcol.receiver.loki.cribl_security_logs.receiver", keycloak
        )

        structured = self.alloy.split(
            'loki.process "cribl_structured_security"', 1
        )[1].split('loki.source.file "vault_audit"', 1)[0]
        for event in (
            "aigw.portal.audit",
            "aigw.identity.audit",
            "aigw.egress.trust",
        ):
            self.assertIn(event, structured)
        self.assertIn('source   = "security_schema"', structured)
        self.assertIn('template = "{{ .Value }}"', structured)
        self.assertIn('aigw_security_schema      = "security_schema"', structured)
        self.assertIn("AIGW_SECURITY_EVENT", structured)
        self.assertNotIn('service=~\\"alloy|cribl-mock\\"', structured)
        # Use RE2 character classes for literal dots. A backslash here must
        # survive both Alloy and LogQL string parsing, and a single escaped
        # dot makes Alloy fail at startup.
        self.assertIn('security_action!~\\"key[.]generate|key[.]deactivate|', structured)
        self.assertNotIn('security_action!~\\"key\\\\.generate', structured)

        # Alloy and the mock sink never enter either positive classifier, so
        # exporter failure/debug logs cannot recurse into their own queue.
        docker = self.alloy.split('loki.process "docker"', 1)[1].split(
            'loki.process "cribl_keycloak_auth"', 1
        )[0]
        self.assertIn("loki.write.local.receiver", docker)
        self.assertIn("loki.process.cribl_keycloak_auth.receiver", docker)
        self.assertIn("loki.process.cribl_structured_security.receiver", docker)


if __name__ == "__main__":
    unittest.main()
