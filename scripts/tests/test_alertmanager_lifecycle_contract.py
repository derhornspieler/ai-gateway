from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "compose/docker-compose.yml"
PREPROD_COMPOSE = ROOT / "compose/docker-compose.preprod.yml"
ALERTMANAGER = ROOT / "compose/alertmanager/alertmanager.yml"
PROMETHEUS = ROOT / "compose/prometheus/prometheus.yml"
DATASOURCES = ROOT / "compose/grafana/provisioning/datasources/datasources.yml"
DASHBOARD = (
    ROOT
    / "compose/grafana/provisioning/dashboards/json/ai-gateway-alerts-capacity.json"
)
STACK = ROOT / "ansible/roles/docker_stack/tasks/main.yml"
VERIFY = ROOT / "ansible/roles/verify/tasks/main.yml"
ENV_TEMPLATE = ROOT / "ansible/roles/docker_stack/templates/env.j2"
GROUP_VARS = ROOT / "ansible/group_vars/all.yml"
PREPROD = ROOT / "scripts/preprod.py"
STATE_BACKUP = ROOT / "scripts/state-backup.sh"
RESTORE_ARCHIVE = ROOT / "scripts/restore_archive.py"


def service_block(compose: str, name: str) -> str:
    start = compose.index(f"  {name}:\n")
    match = re.search(r"\n  [a-z0-9][a-z0-9-]*:\n", compose[start + 1 :])
    end = len(compose) if match is None else start + 1 + match.start()
    return compose[start:end]


def all_panels(dashboard: dict) -> list[dict]:
    result: list[dict] = []
    pending = list(dashboard.get("panels", []))
    while pending:
        panel = pending.pop()
        result.append(panel)
        pending.extend(panel.get("panels", []))
    return result


class AlertmanagerLifecycleContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.compose = COMPOSE.read_text(encoding="utf-8")
        cls.preprod_compose = PREPROD_COMPOSE.read_text(encoding="utf-8")
        cls.alertmanager = ALERTMANAGER.read_text(encoding="utf-8")
        cls.prometheus = PROMETHEUS.read_text(encoding="utf-8")
        cls.datasources = DATASOURCES.read_text(encoding="utf-8")
        cls.dashboard = json.loads(DASHBOARD.read_text(encoding="utf-8"))
        cls.stack = STACK.read_text(encoding="utf-8")
        cls.verify = VERIFY.read_text(encoding="utf-8")
        cls.env_template = ENV_TEMPLATE.read_text(encoding="utf-8")
        cls.group_vars = GROUP_VARS.read_text(encoding="utf-8")
        cls.preprod = PREPROD.read_text(encoding="utf-8")
        cls.state_backup = STATE_BACKUP.read_text(encoding="utf-8")
        cls.restore_archive = RESTORE_ARCHIVE.read_text(encoding="utf-8")

    def test_alertmanager_is_private_pinned_nonroot_and_stateful(self) -> None:
        block = service_block(self.compose, "alertmanager")
        for required in (
            "BASE_IMAGE: dhi.io/alertmanager:0.33.1@sha256:"
            "137ab07843ffd9879e904c8eb0d8cca0a147c6232ed401802e5d7cf03a926c47",
            "image: ai-gateway/dhi-alertmanager:0.33.1-probe",
            'user: "65532:65532"',
            "read_only: true",
            "pids_limit: 256",
            'limits: { memory: 256M, cpus: "0.5", pids: 256 }',
            "--cluster.listen-address=",
            "--web.listen-address=${ALERTMANAGER_OBSERVABILITY_IP:"
            "?ALERTMANAGER_OBSERVABILITY_IP must be set}:9093",
            "./alertmanager/alertmanager.yml:/etc/alertmanager/alertmanager.yml:ro,Z",
            "alertmanager_data:/alertmanager",
            "net-observability:",
            "ipv4_address: ${ALERTMANAGER_OBSERVABILITY_IP:"
            "?ALERTMANAGER_OBSERVABILITY_IP must be set}",
        ):
            self.assertIn(required, block)
        self.assertNotRegex(block, r"(?m)^    (ports|expose):")
        for forbidden_network in (
            "plane-egress",
            "plane-adm",
            "plane-internal",
            "net-internal",
            "net-metrics",
            "net-telemetry",
        ):
            self.assertNotIn(forbidden_network, block)

        initializer = service_block(self.compose, "volume-init")
        self.assertIn(
            "chown 65532:65532 /state/alertmanager && chmod 0700 /state/alertmanager",
            initializer,
        )
        self.assertIn("alertmanager_data:/state/alertmanager", initializer)
        self.assertIn("alertmanager_data:", self.compose.rsplit("\nvolumes:\n", 1)[1])

    def test_lifecycle_config_has_one_safe_receiver_grouping_and_inhibition(self) -> None:
        for required in (
            "resolve_timeout: 5m",
            "receiver: aigw-local-dashboard",
            "group_by: [alertname, alert_class, severity, owner]",
            "group_wait: 30s",
            "group_interval: 5m",
            "repeat_interval: 12h",
            'source_matchers:\n      - severity="critical"',
            'target_matchers:\n      - severity="warning"',
            "equal: [alert_class, instance, device, mountpoint, service]",
            "receivers:\n  - name: aigw-local-dashboard",
        ):
            self.assertIn(required, self.alertmanager)
        self.assertEqual(self.alertmanager.count("  - name: aigw-local-dashboard"), 1)
        for external_integration in (
            "webhook_configs:",
            "email_configs:",
            "slack_configs:",
            "pagerduty_configs:",
            "opsgenie_configs:",
            "victorops_configs:",
            "sns_configs:",
            "msteams_configs:",
            "telegram_configs:",
        ):
            self.assertNotIn(external_integration, self.alertmanager)

    def test_prometheus_is_the_only_evaluator_and_grafana_is_a_private_view(self) -> None:
        for required in (
            "evaluation_interval: 15s",
            "rule_files:\n  - /etc/prometheus/rules.yml",
            "alerting:\n  alertmanagers:",
            "api_version: v2",
            "- targets: [alertmanager:9093]",
            "scrape_configs: []",
        ):
            self.assertIn(required, self.prometheus)
        for required in (
            "- name: Alertmanager",
            "type: alertmanager",
            "uid: alertmanager",
            "url: http://alertmanager:9093",
            "implementation: prometheus",
            "handleGrafanaManagedAlerts: false",
            "editable: false",
        ):
            self.assertIn(required, self.datasources)
        self.assertEqual(
            (ROOT / "compose/grafana/provisioning/alerting/empty.yml").read_text(
                encoding="utf-8"
            ),
            "apiVersion: 1\n",
        )
        grafana = service_block(self.compose, "grafana")
        self.assertIn('GF_UNIFIED_ALERTING_ENABLED: "false"', grafana)

    def test_dashboard_is_summary_first_and_uses_only_retained_prometheus_data(self) -> None:
        self.assertEqual(self.dashboard["uid"], "aigw-alerts-capacity")
        self.assertEqual(self.dashboard["title"], "AI Gateway Alerts and Capacity")
        self.assertIs(self.dashboard["editable"], False)
        self.assertIn("Prometheus-evaluated", self.dashboard["description"])
        panels = all_panels(self.dashboard)
        self.assertEqual({panel["id"] for panel in panels}, set(range(1, 18)))
        self.assertEqual(
            [panel["title"] for panel in self.dashboard["panels"][:7]],
            [
                "Prometheus → Alertmanager → Grafana Watchdog",
                "Active Critical Alerts",
                "Active Warning Alerts",
                "Recently Resolved (24h)",
                "Active Alerts",
                "Recently Resolved Alerts",
                "Alert Lifecycle Timeline",
            ],
        )
        expressions = "\n".join(
            target["expr"]
            for panel in panels
            for target in panel.get("targets", [])
        )
        for required in (
            'ALERTS{alertname="AIGatewayWatchdog",alertstate="firing"}',
            "prometheus_notifications_alertmanagers_discovered",
            'up{job="alertmanager"}',
            'alertmanager_alerts{state="active"}',
            "max_over_time(ALERTS",
            "unless ALERTS",
            "node_cpu_seconds_total",
            "node_memory_MemAvailable_bytes",
            "node_filesystem_avail_bytes",
            "node_filesystem_files_free",
            "node_disk_io_time_seconds_total",
            "traefik_service_request_duration_seconds_bucket",
            "traefik_service_requests_total",
            "traefik_tls_certs_not_after",
            "otelcol_exporter_queue_size",
        ):
            self.assertIn(required, expressions)
        for panel in panels:
            self.assertEqual(
                panel.get("datasource"), {"type": "prometheus", "uid": "prometheus"}
            )
        links = {link["url"] for link in self.dashboard["links"]}
        self.assertIn(
            "/d/aigw-alerts-capacity/ai-gateway-alerts-and-capacity?viewPanel=17",
            links,
        )
        self.assertNotIn("/alerting/list", links)
        rendered = json.dumps(self.dashboard).lower()
        self.assertIn("docs/observability-operations.md#alert-response-runbooks", rendered)
        self.assertNotIn("docs.aigw.internal", rendered)
        self.assertNotIn("iframe", rendered)
        self.assertNotIn("grafana-managed", expressions.lower())
        overview = json.loads(
            (
                ROOT
                / "compose/grafana/provisioning/dashboards/json/ai-gateway-overview.json"
            ).read_text(encoding="utf-8")
        )
        self.assertIn(
            "/d/aigw-alerts-capacity/ai-gateway-alerts-and-capacity",
            {link["url"] for link in overview["links"]},
        )

    def test_ansible_and_preprod_track_the_same_private_artifacts(self) -> None:
        for required in (
            "alertmanager_observability_ip: 172.28.15.4",
            "ALERTMANAGER_OBSERVABILITY_IP={{ alertmanager_observability_ip }}",
            "AIGW_BIND_DIGEST_ALERTMANAGER={{ "
            "aigw_bind_source_digests['alertmanager'] }}",
        ):
            haystack = "\n".join((self.group_vars, self.env_template))
            self.assertIn(required, haystack)
        for required in (
            "alertmanager/alertmanager.yml",
            "alertmanager_data",
            "ai-gateway-alerts-capacity.json",
        ):
            self.assertIn(required, self.stack)
        for required in (
            "alertmanager/alertmanager.yml",
            "aigw-alerts-capacity",
        ):
            self.assertIn(required, self.verify)
        for required in (
            '"ALERTMANAGER_OBSERVABILITY_IP": f"172.{subnet}.15.4"',
            "PREPROD_BIND_DIGEST_NAMES = (",
            '"ALERTMANAGER",',
            '"alertmanager/alertmanager.yml"',
        ):
            self.assertIn(required, self.preprod)
        overlay = service_block(self.preprod_compose, "alertmanager")
        self.assertIn("build:", overlay)
        self.assertIn('image: "${PREPROD_PROJECT}/alertmanager:local"', overlay)
        self.assertIn("alertmanager_data loki_data grafana_data", self.state_backup)
        self.assertIn(".env alertmanager alloy", self.state_backup)
        self.assertIn('"alertmanager_data",', self.restore_archive)
        self.assertIn('"alertmanager",', self.restore_archive)

    def test_live_verifier_proves_config_receiver_watchdog_and_metric_inputs(self) -> None:
        for required in (
            "Prove Alertmanager loaded the exact private lifecycle graph and watchdog",
            'status.get("versionInfo", {}).get("version") != "0.33.1"',
            'status.get("cluster", {}).get("status") != "disabled"',
            '"labels": {"name": "aigw-local-dashboard"}',
            'alertname="AIGatewayWatchdog"',
            'watchdog.get("status", {}).get("state") != "active"',
            'watchdog.get("receivers") != [{"name": "aigw-local-dashboard"}]',
            'node_cpu_seconds_total{job="node-exporter",mode="idle"}',
            'node_memory_MemAvailable_bytes{job="node-exporter"}',
            'node_vmstat_oom_kill{job="node-exporter"}',
            'node_disk_io_time_seconds_total{job="node-exporter"}',
            'node_filesystem_files_free{job="node-exporter"}',
        ):
            self.assertIn(required, self.verify)

    def test_preprod_verifier_proves_the_live_dashboard_and_watchdog_privately(self) -> None:
        for required in (
            "def verify_alerting_graph(args: argparse.Namespace) -> None:",
            'network = f"{args.prefix}-net-observability"',
            '"--volumes-from", f"{identifiers[\'grafana\']}:ro"',
            '"--read-only", "--tmpfs"',
            '"--cap-drop", "ALL", "--security-opt", "no-new-privileges:true"',
            '"--user", "65532:65532", "--log-driver", "none"',
            '"--network", "none"',
            '"--entrypoint", "promtool"',
            'prometheus_image, "test", "rules", "rules.test.yml"',
            "PREPROD_ALERT_RULE_UNIT_TEST_PASS",
            "aigw-alerts-capacity",
            "AIGatewayWatchdog",
            "PREPROD_ALERTING_GRAPH_PASS",
            "AIGatewayPreprodAcceptance",
            'matches[0].get("datasource") != expected_datasource',
            'target.get("datasource") not in (None, expected_datasource)',
            "PREPROD_ALERT_LIVE_FIRING_PASS",
            "PREPROD_ALERT_CRIBL_EXPORT_PASS",
            "PREPROD_ALERT_LIVE_RESOLVED_PASS",
            '"fixture-state"',
            'f"last check: {last_reason}"',
            "verify_alerting_graph(args)",
        ):
            self.assertIn(required, self.preprod)
        verifier = self.preprod.split("def verify_alerting_graph", 1)[1].split(
            "\ndef ", 1
        )[0]
        self.assertNotIn("docker.sock", verifier)
        self.assertNotIn("--publish", verifier)
        self.assertNotIn("--env", verifier)


if __name__ == "__main__":
    unittest.main()
