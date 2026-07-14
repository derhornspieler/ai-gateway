from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DASHBOARD_ROOT = ROOT / "compose/grafana/provisioning/dashboards"


def panels(dashboard: dict) -> list[dict]:
    result: list[dict] = []
    pending = list(dashboard.get("panels", []))
    while pending:
        panel = pending.pop()
        result.append(panel)
        pending.extend(panel.get("panels", []))
    return result


class GrafanaProvisioningContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.provider = (DASHBOARD_ROOT / "dashboards.yml").read_text()
        cls.dashboard_files = sorted((DASHBOARD_ROOT / "json").glob("*.json"))
        cls.dashboards = [json.loads(path.read_text()) for path in cls.dashboard_files]
        cls.stack = (ROOT / "ansible/roles/docker_stack/tasks/main.yml").read_text()
        cls.verify = (ROOT / "ansible/roles/verify/tasks/main.yml").read_text()
        cls.compose = (ROOT / "compose/docker-compose.yml").read_text()

    def test_provider_is_immutable_and_scans_only_the_reviewed_json_directory(self) -> None:
        self.assertIn("name: AI Gateway", self.provider)
        self.assertIn("folderUid: aigw", self.provider)
        self.assertIn("allowUiUpdates: false", self.provider)
        self.assertIn("disableDeletion: false", self.provider)
        self.assertIn(
            "path: /etc/grafana/provisioning/dashboards/json", self.provider
        )
        for directory in ("alerting", "plugins"):
            self.assertTrue((DASHBOARD_ROOT.parent / directory).is_dir())
            self.assertTrue((DASHBOARD_ROOT.parent / directory / "empty.yml").is_file())

    def test_exact_dashboard_inventory_is_deterministic(self) -> None:
        self.assertEqual(
            {dashboard["uid"]: dashboard["title"] for dashboard in self.dashboards},
            {
                "aigw-live-logs": "AI Gateway Live Logs",
                "aigw-overview": "AI Gateway Overview",
                "aigw-request-audit": "AI Gateway Request Audit",
                "aigw-edge-identity": "Edge, Egress and Identity Services",
                "aigw-grafana-lgtm": "Grafana LGTM Stack",
                "aigw-rocky9-host": "Rocky 9 Host (Node Exporter)",
            },
        )
        for dashboard in self.dashboards:
            self.assertIs(dashboard["editable"], False)
            self.assertIsNone(dashboard["id"])
            self.assertGreaterEqual(dashboard["schemaVersion"], 41)

    def test_panels_use_only_the_provisioned_builtin_datasource_uids(self) -> None:
        allowed = {("prometheus", "prometheus"), ("loki", "loki"), ("tempo", "tempo")}
        observed: set[tuple[str, str]] = set()
        for dashboard in self.dashboards:
            for panel in panels(dashboard):
                references = [panel.get("datasource")]
                references.extend(target.get("datasource") for target in panel.get("targets", []))
                for reference in references:
                    if reference is None:
                        continue
                    pair = (reference.get("type"), reference.get("uid"))
                    self.assertIn(pair, allowed)
                    observed.add(pair)
            for variable in dashboard.get("templating", {}).get("list", []):
                reference = variable.get("datasource")
                if reference is not None:
                    pair = (reference.get("type"), reference.get("uid"))
                    self.assertIn(pair, allowed)
                    observed.add(pair)
        self.assertIn(("prometheus", "prometheus"), observed)
        self.assertIn(("loki", "loki"), observed)
        self.assertIn(("tempo", "tempo"), observed)

    def test_request_audit_keeps_required_fields_on_one_tempo_span(self) -> None:
        dashboard = next(
            item for item in self.dashboards if item["uid"] == "aigw-request-audit"
        )
        tempo_targets = [
            target
            for panel in panels(dashboard)
            for target in panel.get("targets", [])
            if target.get("datasource", {}).get("uid") == "tempo"
        ]
        self.assertEqual(len(tempo_targets), 3)
        self.assertTrue(all(target["queryType"] == "traceql" for target in tempo_targets))
        self.assertTrue(all(target["tableType"] == "spans" for target in tempo_targets))
        rendered = "\n".join(target["query"] for target in tempo_targets)
        for field in (
            "span:name = \"litellm_request\"",
            "span.aigw.user.id",
            "span.aigw.project.id",
            "span.aigw.api_key.id",
            "span.aigw.request.id",
            "span.gen_ai.input.messages",
            "span.gen_ai.output.messages",
        ):
            self.assertIn(field, rendered)
        self.assertNotIn("aigw.api_key.alias", rendered)

    def test_overview_queries_match_the_live_metric_schema(self) -> None:
        overview = next(item for item in self.dashboards if item["uid"] == "aigw-overview")
        expressions = {
            target["expr"]
            for panel in panels(overview)
            for target in panel.get("targets", [])
        }
        required_fragments = (
            "up",
            "traefik_service_requests_total",
            "traces_span_metrics_calls_total",
            "status_code",
            "service_name",
            "span_name",
            "traces_span_metrics_duration_milliseconds_bucket",
            "otelcol_exporter_sent_log_records_total",
            "loki_write_sent_entries_total",
        )
        rendered = "\n".join(expressions)
        for fragment in required_fragments:
            self.assertIn(fragment, rendered)

    def test_component_dashboards_use_scraped_native_metric_contracts(self) -> None:
        expected = {
            "aigw-rocky9-host": (
                "node_boot_time_seconds",
                "node_cpu_seconds_total",
                "node_memory_MemAvailable_bytes",
                "node_memory_MemTotal_bytes",
                "node_selinux_enabled",
                "node_load1",
                "node_load5",
                "node_load15",
                "node_network_receive_bytes_total",
                "node_network_transmit_bytes_total",
                "node_filesystem_avail_bytes",
                "node_filesystem_size_bytes",
            ),
            "aigw-grafana-lgtm": (
                "loki_distributor_lines_received_total",
                "tempo_distributor_spans_received_total",
                "otelcol_exporter_send_failed_log_records_total",
                "otelcol_exporter_send_failed_spans_total",
                "prometheus_tsdb_head_samples_appended_total",
                "otelcol_exporter_queue_size",
                "otelcol_exporter_queue_capacity",
                "loki_request_duration_seconds_bucket",
                "tempo_request_duration_seconds_bucket",
                "grafana_datasource_request_duration_seconds_bucket",
                "process_resident_memory_bytes",
            ),
            "aigw-edge-identity": (
                "traefik_service_requests_total",
                "traefik_tls_certs_not_after",
                "keycloak_credentials_password_hashing_validations_total",
                "envoy_cluster_upstream_rq_xx",
                "jvm_memory_used_bytes",
                "jvm_memory_max_bytes",
            ),
        }
        for uid, metrics in expected.items():
            dashboard = next(item for item in self.dashboards if item["uid"] == uid)
            expressions = "\n".join(
                target["expr"]
                for panel in panels(dashboard)
                for target in panel.get("targets", [])
            )
            for metric in metrics:
                self.assertIn(metric, expressions)
            self.assertNotIn("cadvisor", expressions.lower())
            self.assertNotIn("container_", expressions.lower())
        lgtm = next(item for item in self.dashboards if item["uid"] == "aigw-grafana-lgtm")
        lgtm_queries = "\n".join(
            target["expr"]
            for panel in panels(lgtm)
            for target in panel.get("targets", [])
        )
        self.assertIn('== bool 5', lgtm_queries)
        edge = next(item for item in self.dashboards if item["uid"] == "aigw-edge-identity")
        edge_queries = "\n".join(
            target["expr"]
            for panel in panels(edge)
            for target in panel.get("targets", [])
        )
        self.assertIn('== bool 4', edge_queries)

    def test_logs_dashboard_has_bounded_operational_filters_and_no_secret_query(self) -> None:
        dashboard = next(item for item in self.dashboards if item["uid"] == "aigw-live-logs")
        log_panels = [panel for panel in panels(dashboard) if panel.get("type") == "logs"]
        self.assertEqual(len(log_panels), 1)
        expression = log_panels[0]["targets"][0]["expr"]
        for label in ("service", "job", "project", "stream"):
            self.assertIn(f'{label}=~"${{{label}:regex}}"', expression)
        lowered = expression.lower()
        for forbidden in ("api_key", "authorization", "bearer", "prompt"):
            self.assertNotIn(forbidden, lowered)
        variables = {
            variable["name"]: variable
            for variable in dashboard["templating"]["list"]
        }
        # Loki rejects a selector in which every matcher can match an empty
        # string. Service is present on both Docker and Vault-audit streams,
        # while project is absent from Vault audit records. Keep service as
        # the non-empty matcher so the All view includes both data classes.
        self.assertEqual(variables["service"]["allValue"], ".+")
        self.assertEqual(variables["project"]["allValue"], ".*")

    def test_ansible_deploy_and_verify_contract_tracks_every_file(self) -> None:
        expected = {
            "grafana/provisioning/alerting/empty.yml",
            "grafana/provisioning/dashboards/dashboards.yml",
            "grafana/provisioning/dashboards/json/ai-gateway-live-logs.json",
            "grafana/provisioning/dashboards/json/ai-gateway-overview.json",
            "grafana/provisioning/dashboards/json/ai-gateway-request-audit.json",
            "grafana/provisioning/dashboards/json/edge-identity-services.json",
            "grafana/provisioning/dashboards/json/grafana-lgtm-stack.json",
            "grafana/provisioning/dashboards/json/rocky9-host.json",
            "grafana/provisioning/plugins/empty.yml",
        }
        for relative in expected:
            self.assertIn(relative, self.stack)
            self.assertIn(relative, self.verify)
        for uid in (
            "aigw-overview",
            "aigw-live-logs",
            "aigw-request-audit",
            "aigw-edge-identity",
            "aigw-grafana-lgtm",
            "aigw-rocky9-host",
        ):
            self.assertIn(uid, self.verify)

    def test_ansible_removes_only_unmanaged_dashboard_artifacts_before_copy(self) -> None:
        cleanup = self.stack.split(
            "- name: Find existing Grafana dashboard artifacts", 1
        )[1].split("- name: Sync allow-listed compose configuration files", 1)[0]
        self.assertIn(
            'paths: "{{ stack_dir }}/grafana/provisioning/dashboards/json"',
            cleanup,
        )
        self.assertIn("recurse: false", cleanup)
        self.assertIn("hidden: true", cleanup)
        self.assertIn("file_type: any", cleanup)
        self.assertIn("- name: Remove unmanaged Grafana dashboard artifacts", cleanup)
        self.assertIn("state: absent", cleanup)
        self.assertIn("not (item.isreg | default(false) | bool)", cleanup)
        self.assertIn("(item.path | basename) not in", cleanup)
        for name in (
            "ai-gateway-live-logs.json",
            "ai-gateway-overview.json",
            "ai-gateway-request-audit.json",
            "edge-identity-services.json",
            "grafana-lgtm-stack.json",
            "rocky9-host.json",
        ):
            self.assertIn(name, cleanup)
        self.assertIn("FROM resource", self.verify)
        self.assertIn("WHERE namespace = 'default'", self.verify)
        self.assertIn("\"group\" = 'dashboard.grafana.app'", self.verify)
        self.assertNotIn("FROM dashboard JOIN dashboard_provisioning", self.verify)

    def test_offline_grafana_never_runtime_downloads_optional_apps(self) -> None:
        grafana = self.compose.split("  grafana:\n", 1)[1].split(
            "  cribl-mock:\n", 1
        )[0]
        for setting in (
            "GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH: /etc/grafana/provisioning/dashboards/json/ai-gateway-overview.json",
            'GF_PLUGINS_PREINSTALL_DISABLED: "true"',
            'GF_PLUGINS_PLUGIN_ADMIN_ENABLED: "false"',
            'GF_PLUGINS_PUBLIC_KEY_RETRIEVAL_DISABLED: "true"',
            'GF_ANALYTICS_REPORTING_ENABLED: "false"',
            'GF_ANALYTICS_CHECK_FOR_UPDATES: "false"',
            'GF_ANALYTICS_CHECK_FOR_PLUGIN_UPDATES: "false"',
        ):
            self.assertIn(setting, grafana)
        self.assertIn(
            "/var/lib/grafana/plugins:uid=65532,gid=65532,mode=0700,noexec,nosuid,nodev",
            grafana,
        )
        volume_init = self.compose.split("  volume-init:\n", 1)[1].split(
            "  traefik-int:\n", 1
        )[0]
        self.assertNotIn("/state/grafana/plugins", volume_init)

    def test_runtime_plugin_tmpfs_contract_is_engine_normalization_neutral(self) -> None:
        """Compose v5 / Engine 29 echo the reviewed tmpfs option string
        verbatim, while older Engines normalized an implicit "rw" token into
        HostConfig.Tmpfs. The runtime verifier must therefore require every
        security-bearing plugin tmpfs option plus the absence of "ro" (which
        proves writability on both renderings) and must never require an
        Engine-normalized "rw" literal."""
        plugin_contract = self.verify.split("required_plugin_options = {", 1)[1].split(
            "hardened ephemeral plugin tmpfs contract is missing", 1
        )[0]
        for required in (
            '"noexec",',
            '"nosuid",',
            '"nodev",',
            '"uid=65532",',
            '"gid=65532",',
            '"mode=0700",',
            'or "ro" in plugin_options',
        ):
            self.assertIn(required, plugin_contract)
        self.assertNotIn('"rw"', plugin_contract)
        # No runtime assertion in the verify role may require a literal
        # normalized "rw" set element again.
        self.assertNotIn('"rw",', self.verify)


if __name__ == "__main__":
    unittest.main()
