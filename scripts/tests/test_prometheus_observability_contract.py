from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROMETHEUS = ROOT / "compose/prometheus/prometheus.yml"
ALLOY = ROOT / "compose/alloy/config.alloy"
RULES = ROOT / "compose/prometheus/rules.yml"
RULE_TESTS = ROOT / "compose/prometheus/rules.test.yml"
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
        cls.alloy = ALLOY.read_text(encoding="utf-8")
        cls.rules = RULES.read_text(encoding="utf-8")
        cls.rule_tests = RULE_TESTS.read_text(encoding="utf-8")
        cls.compose = COMPOSE.read_text(encoding="utf-8")
        cls.verify = VERIFY.read_text(encoding="utf-8")

    def test_alloy_owns_the_exact_private_scrape_inventory(self) -> None:
        self.assertIn("scrape_configs: []", self.prometheus)
        scrape = self.alloy.split('prometheus.scrape "gateway"', 1)[1].split(
            'otelcol.receiver.prometheus "gateway"', 1
        )[0]
        targets = {
            line.strip().removesuffix(",")
            for line in scrape.splitlines()
            if line.strip().startswith('{ "__address__"')
        }
        expected = {
            '{ "__address__" = "traefik-int:9100", "job" = "traefik" }',
            '{ "__address__" = "traefik-adm:9100", "job" = "traefik" }',
            '{ "__address__" = "envoy-egress:9902", "__metrics_path__" = "/stats/prometheus", "job" = "envoy-egress" }',
            '{ "__address__" = "keycloak:9000", "__metrics_path__" = "/metrics", "job" = "keycloak" }',
            '{ "__address__" = sys.env("ALLOY_OBSERVABILITY_IP") + ":12345", "job" = "alloy" }',
            '{ "__address__" = "grafana:3000", "job" = "grafana" }',
            '{ "__address__" = "prometheus-observability:9090", "job" = "prometheus" }',
            '{ "__address__" = "alertmanager:9093", "job" = "alertmanager" }',
            '{ "__address__" = "loki:3100", "job" = "loki" }',
            '{ "__address__" = "node-exporter:9100", "job" = "node-exporter" }',
        }
        self.assertEqual(targets, expected)
        self.assertIn("scrape_interval = \"15s\"", scrape)
        self.assertIn(
            "forward_to = [otelcol.receiver.prometheus.gateway.receiver]", scrape
        )
        receiver = self.alloy.split(
            'otelcol.receiver.prometheus "gateway"', 1
        )[1].split('otelcol.exporter.loki "local"', 1)[0]
        self.assertIn(
            "metrics = [otelcol.processor.memory_limiter.default.input]", receiver
        )

        shared_plane = {
            "traefik-int": "net-metrics",
            "traefik-adm": "net-metrics",
            "envoy-egress": "net-metrics",
            "keycloak": "net-metrics",
            "alloy": "net-observability",
            "grafana": "net-observability",
            "prometheus": "net-observability",
            "alertmanager": "net-observability",
            "loki": "net-observability",
            "node-exporter": "net-metrics",
        }
        alloy_service = service_block(self.compose, "alloy")
        prometheus_service = service_block(self.compose, "prometheus")
        self.assertIn("aliases: [prometheus-observability]", prometheus_service)
        for service_name, network in shared_plane.items():
            self.assertIn(network, service_block(self.compose, service_name))
        self.assertIn("net-metrics: {}", alloy_service)
        self.assertNotIn("net-metrics", prometheus_service)
        for forbidden in ("vault", "litellm", "postgres", "redis", "tempo"):
            self.assertNotIn(f'"job" = "{forbidden}"', scrape)

    def test_alerts_cover_the_exact_collectable_lifecycle_and_capacity_signals(self) -> None:
        alerts = set(re.findall(r"^      - alert: (\S+)$", self.rules, re.MULTILINE))
        expected = {
            "AIGatewayWatchdog",
            "AIGatewayScrapeTargetDown",
            "AIGatewayAlertmanagerUnavailable",
            "AIGatewayAlertmanagerDeliveryFailures",
            "AIGatewayAlloyExporterSendFailures",
            "AIGatewayAlloyExporterEnqueueFailures",
            "AIGatewayAlloyExporterQueueSaturation",
            "AIGatewayLokiWriteDrops",
            "AIGatewayLokiWriteRetriesHigh",
            "AIGatewayPrometheusRemoteWriteFailures",
            "AIGatewayPrometheusRemoteWriteBacklog",
            "AIGatewayHostCPUHigh",
            "AIGatewayHostCPUCritical",
            "AIGatewayHostLoadHigh",
            "AIGatewayHostLoadCritical",
            "AIGatewayHostMemoryLow",
            "AIGatewayHostMemoryCritical",
            "AIGatewayHostSwapHigh",
            "AIGatewayHostOOMKill",
            "AIGatewayFilesystemSpaceLow",
            "AIGatewayFilesystemSpaceCritical",
            "AIGatewayFilesystemPredictedFull",
            "AIGatewayFilesystemInodesLow",
            "AIGatewayFilesystemInodesCritical",
            "AIGatewayHostDiskLatencyHigh",
            "AIGatewayHostDiskIOSaturation",
            "AIGatewayHostFileDescriptorsHigh",
            "AIGatewayHostFileDescriptorsCritical",
            "AIGatewayServiceLatencyHigh",
            "AIGatewayServiceLatencyCritical",
            "AIGatewayServiceErrorRateHigh",
            "AIGatewayServiceErrorRateCritical",
            "AIGatewayCertificateExpiresSoon",
            "AIGatewayCertificateExpiryCritical",
        }
        self.assertEqual(alerts, expected)

        for name in expected:
            rule = alert_block(self.rules, name)
            self.assertIn("owner: platform-operations", rule, name)
            self.assertIn("alert_class:", rule, name)
            self.assertIn(
                'runbook_url: "/d/aigw-alerts-capacity/'
                'ai-gateway-alerts-and-capacity?viewPanel=17"',
                rule,
                name,
            )
            self.assertIn("runbook_source: \"docs/observability-operations.md#", rule, name)
            self.assertNotIn("docs.aigw.internal", rule, name)
            self.assertRegex(rule, r"severity: (none|warning|critical)", name)

        fragments = {
            "AIGatewayScrapeTargetDown": ("up == 0",),
            "AIGatewayAlloyExporterSendFailures": (
                "increase(",
                "otelcol_exporter_send_failed_log_records_total",
                'component_id="otelcol.exporter.otlp.cribl"',
                "[2m]",
            ),
            "AIGatewayAlloyExporterEnqueueFailures": (
                "otelcol_exporter_enqueue_failed_log_records_total",
                'component_id="otelcol.exporter.otlp.cribl"',
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
        self.assertIn("send_failed_spans", send_failures)
        self.assertIn("send_failed_metric_points", send_failures)

        enqueue_failures = alert_block(
            self.rules, "AIGatewayAlloyExporterEnqueueFailures"
        )
        self.assertIn("for: 0m", enqueue_failures)
        self.assertIn("severity: critical", enqueue_failures)
        self.assertIn("delivery data was lost", enqueue_failures)
        self.assertNotIn("increase(", enqueue_failures)
        self.assertIn('component_id="otelcol.exporter.otlp.cribl"} > 0', enqueue_failures)
        self.assertIn("enqueue_failed_spans", enqueue_failures)
        self.assertIn("enqueue_failed_metric_points", enqueue_failures)

        self.assertIn("\nalerting:\n", self.prometheus)
        self.assertIn("- targets: [alertmanager:9093]", self.prometheus)
        self.assertIn("api_version: v2", self.prometheus)
        self.assertIn("evaluation_interval: 15s", self.prometheus)

        # No rule may claim a signal this deployment does not continuously
        # collect. Docker lifecycle/health needs the Docker API, Vault seal
        # state needs a reliable live exporter, backup state needs a producer,
        # and host networking is not truthful from the container namespace.
        lowered = self.rules.lower()
        for unsupported in (
            "container_last_seen",
            "container_start_time_seconds",
            "docker_container",
            "vault_core_unsealed",
            "backup_last_success",
            "node_network_",
            "node_nf_conntrack_",
        ):
            self.assertNotIn(unsupported, lowered)

    def test_alert_state_returns_to_cribl_only_over_private_mtls(self) -> None:
        alert_names = set(
            re.findall(r"^      - alert: (\S+)$", self.rules, re.MULTILINE)
        )
        prometheus_allowlist = re.search(
            r"(?m)^        regex: (AIGateway\S+)$", self.prometheus
        )
        alloy_allowlist = re.search(
            r'(?m)^    regex         = "(AIGateway[^"]+)"$', self.alloy
        )
        self.assertIsNotNone(prometheus_allowlist)
        self.assertIsNotNone(alloy_allowlist)
        self.assertEqual(set(prometheus_allowlist.group(1).split("|")), alert_names)
        self.assertEqual(set(alloy_allowlist.group(1).split("|")), alert_names)
        self.assertNotIn("AIGatewayPreprodAcceptance", alert_names)

        for required in (
            "url: https://alloy-alert-state:12346/api/v1/metrics/write",
            "ca_file: /run/secrets/alert_state_ca.pem",
            "cert_file: /run/secrets/alert_state_prometheus.crt",
            "key_file: /run/secrets/alert_state_prometheus.key",
            "server_name: alloy-alert-state",
            "min_version: TLS13",
            "regex: ALERTS|ALERTS_FOR_STATE",
            "action: labelkeep",
        ):
            self.assertIn(required, self.prometheus)

        branch = self.alloy.split(
            'prometheus.receive_http "alert_state"', 1
        )[1].split('prometheus.scrape "gateway"', 1)[0]
        for required in (
            'listen_address       = sys.env("ALLOY_OBSERVABILITY_IP")',
            "listen_port          = 12346",
            'client_auth_type = "RequireAndVerifyClientCert"',
            'client_ca_file   = "/run/secrets/alert_state_ca.pem"',
            'min_version      = "VersionTLS13"',
            'regex         = "ALERTS|ALERTS_FOR_STATE"',
            'regex  = "__name__|alertname|alertstate|severity|owner|alert_class|instance|job|device|mountpoint|service|component_id|remote_name"',
            'replacement  = "alert-state"',
            "max_cache_size = 128",
            "metrics = [otelcol.processor.batch.cribl_metrics.input]",
        ):
            self.assertIn(required, branch)
        self.assertNotIn("prometheus.remote_write.local", branch)
        self.assertNotIn("otelcol.exporter.prometheus.local", branch)

        alloy = service_block(self.compose, "alloy")
        prometheus = service_block(self.compose, "prometheus")
        self.assertIn("aliases: [alloy-alert-state]", alloy)
        for path in (
            "alert_state_ca.pem",
            "alert_state_alloy.crt",
            "alert_state_alloy.key",
        ):
            self.assertIn(path, alloy)
        for path in (
            "alert_state_ca.pem",
            "alert_state_prometheus.crt",
            "alert_state_prometheus.key",
        ):
            self.assertIn(path, prometheus)

    def test_deploy_verifier_requires_exact_targets_and_healthy_rules(self) -> None:
        self.assertIn(
            "Prove Prometheus received the exact Alloy scrape and alert graph",
            self.verify,
        )
        for target in (
            "prometheus-observability:9090",
            "alertmanager:9093",
            "loki:3100",
            "node-exporter:9100",
            'f"{sys.argv[2]}:12345"',
        ):
            self.assertIn(target, self.verify)
        self.assertIn('fetch("/query?query=up")["result"]', self.verify)
        self.assertNotIn('/targets?state=active', self.verify)
        for alert in (
            "AIGatewayWatchdog",
            "AIGatewayAlertmanagerUnavailable",
            "AIGatewayHostCPUCritical",
            "AIGatewayFilesystemInodesCritical",
            "AIGatewayHostDiskIOSaturation",
            "AIGatewayServiceLatencyCritical",
            "AIGatewayServiceErrorRateCritical",
            "AIGatewayCertificateExpiryCritical",
        ):
            self.assertIn(alert, self.verify)
        self.assertNotIn("AIGatewayTempoRefusedSpans", self.verify)
        self.assertIn('rule.get("health") != "ok"', self.verify)

    def test_fault_inputs_cover_collectable_pressure_and_recovery(self) -> None:
        for required in (
            "watchdog-is-always-firing",
            "cpu-memory-and-disk-pressure-fire-and-recover",
            "cribl-queue-pressure-fires-and-recovers",
            "filesystem-space-pressure-fires-and-recovers",
            "node_cpu_seconds_total",
            "node_memory_MemAvailable_bytes",
            "node_disk_io_time_seconds_total",
            "otelcol_exporter_queue_size",
            "node_filesystem_avail_bytes",
            "node_filesystem_size_bytes",
            "node_filesystem_readonly",
            "AIGatewayHostCPUHigh",
            "AIGatewayHostMemoryLow",
            "AIGatewayHostDiskIOSaturation",
            "AIGatewayAlloyExporterQueueSaturation",
            "AIGatewayFilesystemSpaceLow",
        ):
            self.assertIn(required, self.rule_tests)
        # The empty expected sets are explicit recovery checks after each
        # injected pressure series disappears or returns below threshold.
        self.assertGreaterEqual(self.rule_tests.count("exp_alerts: []"), 5)
        for unsupported in (
            "node_network_",
            "node_nf_conntrack_",
            "docker_container",
            "vault_core_unsealed",
            "backup_last_success",
        ):
            self.assertNotIn(unsupported, self.rule_tests)

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
