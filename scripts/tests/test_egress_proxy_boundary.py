"""Static regressions for Envoy's vendor-request network boundary."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "compose" / "docker-compose.yml"
ENVOY = ROOT / "services" / "egress-proxy" / "envoy.yaml"


class EgressProxyBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.compose = COMPOSE.read_text(encoding="utf-8")
        cls.envoy = ENVOY.read_text(encoding="utf-8")

    def test_only_vendor_plane_peers_are_authorized_for_vendor_requests(self) -> None:
        egress_listener = self.envoy.split("- name: egress_http", 1)[1].split(
            "- name: read_only_metrics", 1
        )[0]
        for required in (
            "name: envoy.filters.http.rbac",
            "type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBAC",
            "action: ALLOW",
            "net_vendor_only:",
            "direct_remote_ip:",
            "address_prefix: 172.28.7.0",
            "prefix_len: 24",
        ):
            self.assertIn(required, egress_listener)
        self.assertLess(
            egress_listener.index("name: envoy.filters.http.rbac"),
            egress_listener.index("name: envoy.filters.http.router"),
        )

    def test_metrics_scraping_does_not_require_sharing_the_vendor_plane(self) -> None:
        envoy_networks = self.compose.split("  envoy-egress:\n", 1)[1].split(
            "  key-rotator:\n", 1
        )[0]
        self.assertIn("net-vendor: {}", envoy_networks)
        self.assertIn("net-metrics: {}", envoy_networks)
        self.assertIn("- targets: [\"envoy-egress:9902\"]", (ROOT / "compose" / "prometheus" / "prometheus.yml").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
