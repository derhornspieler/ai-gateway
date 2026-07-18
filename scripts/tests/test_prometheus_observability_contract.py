from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROMETHEUS = ROOT / "compose/prometheus/prometheus.yml"
RULES = ROOT / "compose/prometheus/rules.yml"
COMPOSE = ROOT / "compose/docker-compose.yml"
VERIFY = ROOT / "ansible/roles/verify/tasks/main.yml"


def service_block(compose: str, name: str) -> str:
    start = compose.index(f"  {name}:\n")
    match = re.search(r"\n  [a-z0-9][a-z0-9-]*:\n", compose[start + 1 :])
    end = len(compose) if match is None else start + 1 + match.start()
    return compose[start:end]


def alert_block(rules: str, name: str) -> str:
    start = rules.index(f"      - alert: {name}\n")
    match = re.search(r"\n      - alert: ", rules[start + 1 :])
    end = len(rules) if match is None else start + 1 + match.start()
    return rules[start:end]


class PrometheusObservabilityContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.prometheus = PROMETHEUS.read_text(encoding="utf-8")
        cls.rules = RULES.read_text(encoding="utf-8")
        cls.compose = COMPOSE.read_text(encoding="utf-8")
        cls.verify = VERIFY.read_text(encoding="utf-8")

    def test_scrape_inventory_is_exact_and_reachable_on_private_planes(self) -> None:
        job_blocks = re.findall(
            r"^  - job_name: ([a-z0-9-]+)(.*?)(?=^  - job_name: |\Z)",
            self.prometheus,
            flags=re.MULTILINE | re.DOTALL,
        )
        targets: set[tuple[str, str]] = set()
        for job, block in job_blocks:
            for rendered in re.findall(r"targets: (\[[^\n]+\])", block):
                for target in ast.literal_eval(rendered):
                    targets.add((job, target))
        expected = {
            ("traefik", "traefik-int:9100"),
            ("traefik", "traefik-adm:9100"),
            ("envoy-egress", "envoy-egress:9902"),
            ("keycloak", "keycloak:9000"),
            ("alloy", "alloy:12345"),
            ("grafana", "grafana:3000"),
            ("prometheus", "prometheus-observability:9090"),
            ("loki", "loki:3100"),
            ("node-exporter", "node-exporter:9100"),
        }
        self.assertEqual(targets, expected)

        shared_plane = {
            "traefik-int": "net-metrics",
            "traefik-adm": "net-metrics",
            "envoy-egress": "net-metrics",
            "keycloak": "net-metrics",
            "alloy": "net-observability",
            "grafana": "net-observability",
            "prometheus": "net-observability",
            "loki": "net-observability",
            "node-exporter": "net-metrics",
        }
        prometheus_service = service_block(self.compose, "prometheus")
        self.assertIn("aliases: [prometheus-observability]", prometheus_service)
        for service_name, network in shared_plane.items():
            self.assertIn(network, prometheus_service)
            self.assertIn(network, service_block(self.compose, service_name))
        for forbidden in ("vault", "litellm", "postgres", "redis", "tempo"):
            self.assertFalse(any(job == forbidden for job, _target in targets))

    def test_alerts_cover_reviewed_restart_safe_failure_signals(self) -> None:
        alerts = set(re.findall(r"^      - alert: (\S+)$", self.rules, re.MULTILINE))
        expected = {
            "AIGatewayScrapeTargetDown",
            "AIGatewayAlloyExporterSendFailures",
            "AIGatewayAlloyExporterEnqueueFailures",
            "AIGatewayAlloyExporterQueueSaturation",
            "AIGatewayLokiWriteDrops",
            "AIGatewayLokiWriteRetriesHigh",
            "AIGatewayPrometheusRemoteWriteFailures",
            "AIGatewayPrometheusRemoteWriteBacklog",
            "AIGatewayFilesystemSpaceLow",
            "AIGatewayFilesystemSpaceCritical",
            "AIGatewayFilesystemPredictedFull",
        }
        self.assertEqual(alerts, expected)

        fragments = {
            "AIGatewayScrapeTargetDown": ("up == 0",),
            "AIGatewayAlloyExporterSendFailures": (
                "increase(",
                "otelcol_exporter_send_failed_spans_total",
                "otelcol_exporter_send_failed_log_records_total",
                "otelcol_exporter_send_failed_metric_points_total",
                '"data_type", "traces"',
                '"data_type", "logs"',
                '"data_type", "metrics"',
                "component_id=~\"otelcol\\\\.exporter\\\\.otlp\\\\..+\"",
                "[2m]",
            ),
            "AIGatewayAlloyExporterEnqueueFailures": (
                "otelcol_exporter_enqueue_failed_spans_total",
                "otelcol_exporter_enqueue_failed_log_records_total",
                "otelcol_exporter_enqueue_failed_metric_points_total",
                '"data_type", "traces"',
                '"data_type", "logs"',
                '"data_type", "metrics"',
                "component_id=~\"otelcol\\\\.exporter\\\\.otlp\\\\..+\"",
            ),
            "AIGatewayAlloyExporterQueueSaturation": (
                "otelcol_exporter_queue_size",
                "otelcol_exporter_queue_capacity",
                "> 0.80",
            ),
            "AIGatewayLokiWriteDrops": (
                "increase(loki_write_dropped_entries_total",
                "[5m]) > 0",
            ),
            "AIGatewayLokiWriteRetriesHigh": (
                "increase(loki_write_batch_retries_total",
                "[5m]) >= 3",
            ),
            "AIGatewayPrometheusRemoteWriteFailures": (
                "increase(prometheus_remote_storage_samples_failed_total",
                "[5m]) > 0",
            ),
            "AIGatewayPrometheusRemoteWriteBacklog": (
                "prometheus_remote_storage_samples_pending",
                "prometheus_remote_storage_max_samples_per_send",
            ),
        }
        for name, required in fragments.items():
            expression = alert_block(self.rules, name)
            for fragment in required:
                self.assertIn(fragment, expression, name)
            self.assertRegex(expression, r"(?m)^        for: \S+", name)

        send_failures = alert_block(
            self.rules, "AIGatewayAlloyExporterSendFailures"
        )
        self.assertIn("for: 5m", send_failures)
        self.assertIn("severity: warning", send_failures)
        self.assertIn("persistent queue", send_failures)

        enqueue_failures = alert_block(
            self.rules, "AIGatewayAlloyExporterEnqueueFailures"
        )
        self.assertIn("for: 0m", enqueue_failures)
        self.assertIn("severity: critical", enqueue_failures)
        self.assertIn("audit data was lost", enqueue_failures)
        self.assertNotIn("increase(", enqueue_failures)
        self.assertIn(") > 0", enqueue_failures)

        self.assertNotIn("\nalerting:", self.prometheus)

    def test_deploy_verifier_requires_exact_targets_and_healthy_rules(self) -> None:
        self.assertIn(
            "Prove Prometheus loaded the exact reviewed scrape and alert graph",
            self.verify,
        )
        for target in (
            "prometheus-observability:9090",
            "loki:3100",
            "node-exporter:9100",
            "alloy:12345",
        ):
            self.assertIn(target, self.verify)
        for alert in (
            "AIGatewayScrapeTargetDown",
            "AIGatewayAlloyExporterSendFailures",
            "AIGatewayAlloyExporterEnqueueFailures",
            "AIGatewayAlloyExporterQueueSaturation",
            "AIGatewayLokiWriteDrops",
            "AIGatewayPrometheusRemoteWriteFailures",
            "AIGatewayPrometheusRemoteWriteBacklog",
        ):
            self.assertIn(alert, self.verify)
        self.assertNotIn("AIGatewayTempoRefusedSpans", self.verify)
        self.assertIn('rule.get("health") != "ok"', self.verify)

    def test_volume_initializer_logs_have_exact_compose_routing_labels(self) -> None:
        initializer = service_block(self.compose, "volume-init")
        for required in (
            "    logging:\n",
            "      driver: json-file\n",
            '        max-size: "20m"\n',
            '        max-file: "5"\n',
            '        labels: "com.docker.compose.project,com.docker.compose.service"\n',
        ):
            self.assertIn(required, initializer)

    def test_node_exporter_filesystem_exclude_covers_the_masked_run_mount(
        self,
    ) -> None:
        """The docker.sock-masking tmpfs and the host's own /run collapse to
        one stripped mountpoint; without /run in the exclude the filesystem
        collector emits duplicate series and errors on EVERY scrape
        (observed live: 8 duplicate node_filesystem_* errors per gather)."""
        exporter = service_block(self.compose, "node-exporter")
        self.assertIn(
            "--collector.filesystem.mount-points-exclude="
            "^/(dev|proc|sys|run|var/lib/docker/(containers|overlay2)/.+)($|/)",
            exporter,
        )


if __name__ == "__main__":
    unittest.main()
