from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = (ROOT / ".github/workflows/go-security.yml").read_text(encoding="utf-8")
CODEQL = (ROOT / ".github/workflows/codeql.yml").read_text(encoding="utf-8")


class GoSecurityWorkflowTests(unittest.TestCase):
    def test_all_go_modules_run_test_race_and_vet(self) -> None:
        self.assertIn(
            "module: [dhi-health-probe, egress-proxy, vault-ui-proxy]", WORKFLOW
        )
        self.assertIn("run: go test -race ./...", WORKFLOW)
        self.assertIn("run: go vet ./...", WORKFLOW)
        self.assertIn("language: [python, go, actions]", CODEQL)
        self.assertIn(
            "matrix.language == 'go' && 'manual' || 'none'", CODEQL
        )
        self.assertIn(
            "for module in dhi-health-probe egress-proxy vault-ui-proxy", CODEQL
        )

    def test_final_dhi_images_have_an_explicit_fail_or_skip_contract(self) -> None:
        for image in ("dhi-health-probe", "egress-proxy", "vault-ui-proxy"):
            self.assertIn(f"- image: {image}", WORKFLOW)
        self.assertIn('"$EVENT_NAME" == "schedule"', WORKFLOW)
        self.assertIn('"$REQUIRE_DHI_AUTH" == "true"', WORKFLOW)
        self.assertIn(
            "Final-image build and SBOM explicitly skipped because DHI auth is unavailable",
            WORKFLOW,
        )
        self.assertIn("format: cyclonedx", WORKFLOW)
        self.assertIn("if-no-files-found: error", WORKFLOW)
        self.assertNotIn("continue-on-error", WORKFLOW)


if __name__ == "__main__":
    unittest.main()
