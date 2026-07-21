from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = (ROOT / ".github/workflows/go-security.yml").read_text(encoding="utf-8")
CODEQL = (ROOT / ".github/workflows/codeql.yml").read_text(encoding="utf-8")


class GoSecurityWorkflowTests(unittest.TestCase):
    def test_all_go_modules_run_test_race_and_vet(self) -> None:
        self.assertIn(
            "module: [dhi-health-probe, egress-proxy, vault-ui-proxy, wif-provider-mock]",
            WORKFLOW,
        )
        self.assertIn("run: go test -race ./...", WORKFLOW)
        self.assertIn("run: go vet ./...", WORKFLOW)
        self.assertIn("language: [python, go, actions]", CODEQL)
        self.assertIn(
            "matrix.language == 'go' && 'manual' || 'none'", CODEQL
        )
        self.assertIn(
            "for module in dhi-health-probe egress-proxy vault-ui-proxy wif-provider-mock",
            CODEQL,
        )
        self.assertIn("services/wif-provider-mock/go.mod", CODEQL)

    def test_final_dhi_images_are_main_only_and_fail_without_credentials(self) -> None:
        for image in (
            "dhi-health-probe",
            "egress-proxy",
            "vault-ui-proxy",
            "wif-provider-mock",
        ):
            self.assertIn(f"- image: {image}", WORKFLOW)
        self.assertIn(
            "DHI authentication is required for every main or scheduled final-image run",
            WORKFLOW,
        )
        self.assertNotIn("workflow_dispatch:", WORKFLOW)
        self.assertIn("github.ref == 'refs/heads/main'", WORKFLOW)
        self.assertIn("github.event_name == 'push' || github.event_name == 'schedule'", WORKFLOW)
        self.assertNotIn("require_dhi_auth", WORKFLOW)
        self.assertIn("format: cyclonedx", WORKFLOW)
        self.assertIn("if-no-files-found: error", WORKFLOW)
        self.assertNotIn("continue-on-error", WORKFLOW)
        self.assertIn("docker logout dhi.io", WORKFLOW)
        self.assertIn("environment: release-container-security", WORKFLOW)
        self.assertLess(
            WORKFLOW.index("docker logout dhi.io"),
            WORKFLOW.index("uses: aquasecurity/trivy-action@"),
        )

    def test_envoy_build_is_provider_bound_and_reproducible(self) -> None:
        for required in (
            "--provider anthropic",
            "--network=none",
            "--provenance=false --sbom=false",
            "--build-arg SOURCE_DATE_EPOCH=0",
            "--build-arg AIGW_EGRESS_PROVIDERS=anthropic",
            'AIGW_EGRESS_POLICY_SHA256=$policy_sha',
            "rewrite-timestamp=true",
            'cmp --silent "$first" "$second"',
            'docker image load --input "$first"',
            '"$final" receipt',
            'test "$live_receipt" = "$receipt"',
        ):
            self.assertIn(required, WORKFLOW)


if __name__ == "__main__":
    unittest.main()
