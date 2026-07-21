from __future__ import annotations

from datetime import date, timedelta
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = (ROOT / ".github/workflows/trivy.yml").read_text(encoding="utf-8")
PLAN_SOURCE = (
    ROOT / ".github/scripts/plan-release-container-security.py"
).read_text(encoding="utf-8")
BUILD_SOURCE = (ROOT / ".github/scripts/build-release-image.py").read_text(
    encoding="utf-8"
)
PROVENANCE_SOURCE = (
    ROOT / ".github/scripts/write-image-provenance.py"
).read_text(encoding="utf-8")
CONFIG = json.loads(
    (ROOT / ".github/release-container-security.json").read_text(encoding="utf-8")
)


def load(relative: str, name: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


PLAN = load(
    ".github/scripts/plan-release-container-security.py",
    "_test_release_container_plan",
)
WAIVERS = load(
    ".github/scripts/validate-trivy-waivers.py",
    "_test_trivy_waivers",
)
COMMON = load(
    ".github/scripts/release_security_common.py",
    "_test_release_security_common",
)
EVIDENCE = load(
    ".github/scripts/validate-image-security-evidence.py",
    "_test_image_security_evidence",
)
SEED = load(
    "scripts/rebuild-offline-image-seed.py",
    "_test_release_container_seed_builder",
)


class ReleaseContainerSecurityWorkflowTests(unittest.TestCase):
    def test_full_release_scan_runs_on_main_push_only(self) -> None:
        self.assertIn("push:\n    branches: [main]", WORKFLOW)
        self.assertNotIn("workflow_dispatch:", WORKFLOW)
        self.assertIn("github.ref == 'refs/heads/main'", WORKFLOW)
        self.assertIn("github.event_name == 'push'", WORKFLOW)
        self.assertIn("needs: release-plan", WORKFLOW)
        self.assertIn("matrix: ${{ fromJSON(needs.release-plan.outputs.external_matrix) }}", WORKFLOW)
        self.assertIn("matrix: ${{ fromJSON(needs.release-plan.outputs.custom_matrix) }}", WORKFLOW)
        self.assertIn("max-parallel: 6", WORKFLOW)
        self.assertIn("max-parallel: 4", WORKFLOW)
        self.assertEqual(WORKFLOW.count("environment: release-container-security"), 3)

    def test_committed_release_selection_is_explicit_and_canonical(self) -> None:
        self.assertEqual(
            CONFIG,
            {
                "schema": 1,
                "platform": "linux/amd64",
                "providers": ["anthropic"],
            },
        )
        self.assertIn(".github/release-container-security.json", WORKFLOW)
        self.assertIn("list(config.providers)", PLAN_SOURCE)
        self.assertIn("list(config.providers)", BUILD_SOURCE)

    def test_release_config_rejects_duplicate_keys_and_bom(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.json"
            path.write_text(
                '{"schema":1,"schema":1,"platform":"linux/amd64","providers":["anthropic"]}',
                encoding="utf-8",
            )
            with self.assertRaises(COMMON.ReleaseSecurityError):
                COMMON.load_config(path)
            path.write_bytes(
                b"\xef\xbb\xbf"
                b'{"schema":1,"platform":"linux/amd64","providers":["anthropic"]}'
            )
            with self.assertRaises(COMMON.ReleaseSecurityError):
                COMMON.load_config(path)

    def test_each_custom_job_recomputes_and_binds_its_planned_build_inputs(self) -> None:
        for required in (
            "--input-digest",
            "planner.plan_compose_builds",
            'build_record.get("digest") != expected_input_digest',
            'build_record.get("image") != expected_image',
            '"image_id": image_id',
        ):
            self.assertIn(required, BUILD_SOURCE if required != "--input-digest" else WORKFLOW)
        self.assertEqual(BUILD_SOURCE.count('"--provenance=false"'), 2)
        self.assertEqual(BUILD_SOURCE.count('"--sbom=false"'), 2)
        self.assertIn("steps.acquire.outputs.image_id", WORKFLOW)
        self.assertIn("--expected-image-id", WORKFLOW)
        self.assertIn("expected_build_id_matches", PROVENANCE_SOURCE)

    def test_missing_dhi_credentials_fail_instead_of_skipping(self) -> None:
        self.assertIn(
            "DHI_USERNAME and DHI_PASSWORD are required for every main release scan",
            WORKFLOW,
        )
        self.assertIn('[[ -z "$DHI_USERNAME" || -z "$DHI_PASSWORD" ]]', WORKFLOW)
        release_workflow = WORKFLOW.split("  release-plan:", 1)[1]
        self.assertNotIn("explicitly skipped", release_workflow.lower())
        self.assertNotIn("available=false", release_workflow)

    def test_plan_uses_the_authoritative_full_seed_union(self) -> None:
        scopes = SEED.collect_project_image_reference_scopes(ROOT)
        self.assertTrue(scopes[SEED.RELEASE_SCOPE_PRODUCTION])
        self.assertGreaterEqual(
            len(scopes[SEED.RELEASE_SCOPE_PREPROD]),
            len(scopes[SEED.RELEASE_SCOPE_PRODUCTION]),
        )
        self.assertEqual(len(scopes[SEED.RELEASE_SCOPE_PRODUCTION]), 23)
        self.assertEqual(len(scopes[SEED.RELEASE_SCOPE_PREPROD]), 24)
        for required in (
            "plan_egress_policy",
            "render_deployable_compose_model",
            "add_preprod_build_services",
            "plan_compose_builds",
            "collect_project_image_reference_scopes",
            "RELEASE_SCOPE_PREPROD",
            "PREPROD_ONLY_SERVICES",
        ):
            self.assertIn(required, PLAN_SOURCE)

    def test_shared_tags_are_scanned_once_and_must_have_one_build_digest(self) -> None:
        digest = "a" * 64
        manifest = {
            "schema": 1,
            "services": {
                "one": {"image": "ai-gateway/shared:1", "digest": digest},
                "two": {"image": "ai-gateway/shared:1", "digest": digest},
                "mock": {"image": "ai-gateway/mock:1", "digest": "b" * 64},
            },
        }
        matrix = PLAN.custom_matrix(manifest, {"mock"}, "linux/amd64")
        self.assertEqual(len(matrix), 2)
        shared = next(item for item in matrix if item["image"] == "ai-gateway/shared:1")
        self.assertEqual(shared["service"], "one")
        self.assertEqual(shared["services"], ["one", "two"])
        self.assertEqual(shared["scope"], "production")
        self.assertEqual(shared["platform"], "linux/amd64")

        manifest["services"]["two"]["digest"] = "c" * 64
        with self.assertRaises(PLAN.ReleaseSecurityError):
            PLAN.custom_matrix(manifest, {"mock"}, "linux/amd64")

    def test_every_image_gets_a_blocking_high_critical_scan_and_evidence(self) -> None:
        self.assertEqual(WORKFLOW.count("Scan high and critical vulnerabilities"), 2)
        self.assertEqual(WORKFLOW.count("severity: HIGH,CRITICAL"), 3)
        self.assertEqual(WORKFLOW.count('ignore-unfixed: "false"'), 3)
        self.assertEqual(WORKFLOW.count('exit-code: "1"'), 3)
        self.assertEqual(WORKFLOW.count("format: cyclonedx"), 2)
        self.assertEqual(WORKFLOW.count("trivy-vulnerabilities.json"), 2)
        self.assertEqual(WORKFLOW.count("provenance.json"), 2)
        self.assertEqual(WORKFLOW.count("if-no-files-found: error"), 3)
        self.assertIn("Enforce exact pull and vulnerability gate", WORKFLOW)
        self.assertIn("Enforce exact build and vulnerability gate", WORKFLOW)
        self.assertIn('[[ "$SCAN_OUTCOME" != "success" ]]', WORKFLOW)
        self.assertEqual(WORKFLOW.count("validate-image-security-evidence.py"), 2)
        self.assertEqual(WORKFLOW.count('[[ "$EVIDENCE_OUTCOME" != "success" ]]'), 2)
        self.assertIn("build_input_sha256", PROVENANCE_SOURCE)
        self.assertIn("runtime_and_database_metadata", PROVENANCE_SOURCE)
        self.assertIn("not signed SLSA provenance", PROVENANCE_SOURCE)
        self.assertIn("did not receive or inspect the operator's local offline archive", PROVENANCE_SOURCE)

    def test_evidence_validator_rejects_findings_missing_files_and_id_drift(self) -> None:
        with self.assertRaises(EVIDENCE.EvidenceError):
            EVIDENCE.validate_vulnerability_report(
                {
                    "SchemaVersion": 2,
                    "Results": [{"Vulnerabilities": [{"Severity": "HIGH"}]}],
                }
            )
        with self.assertRaises(EVIDENCE.EvidenceError):
            EVIDENCE.validate_sbom({"bomFormat": "not-cyclonedx"})
        provenance = {
            "schema": 1,
            "outcomes": {
                "pull_or_build": "success",
                "high_critical_scan": "success",
                "sbom": "success",
            },
            "scanner": {"waiver_file_sha256": "a" * 64},
            "image": {
                "available": True,
                "id": "sha256:" + "a" * 64,
                "expected_build_id": "sha256:" + "b" * 64,
                "expected_build_id_matches": False,
                "os": "linux",
                "architecture": "amd64",
            },
        }
        with self.assertRaises(EVIDENCE.EvidenceError):
            EVIDENCE.validate_provenance(
                provenance, "linux/amd64", "sha256:" + "b" * 64
            )
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(EVIDENCE.EvidenceError):
                EVIDENCE.read_json(Path(temporary) / "missing.json")

    def test_all_actions_are_pinned_and_checkouts_drop_credentials(self) -> None:
        references = re.findall(r"uses: (\S+)", WORKFLOW)
        self.assertTrue(references)
        for reference in references:
            with self.subTest(reference=reference):
                self.assertRegex(reference, r"^[\w.\-]+/[\w./\-]+@[0-9a-f]{40}$")
        self.assertEqual(
            WORKFLOW.count("uses: actions/checkout@"),
            WORKFLOW.count("persist-credentials: false"),
        )

    def test_registry_credentials_are_removed_before_third_party_evidence_steps(self) -> None:
        release_plan = WORKFLOW.split("  release-plan:", 1)[1].split(
            "  external-images:", 1
        )[0]
        external = WORKFLOW.split("  external-images:", 1)[1].split(
            "  custom-images:", 1
        )[0]
        custom = WORKFLOW.split("  custom-images:", 1)[1]
        for job in (release_plan, external, custom):
            with self.subTest(job=job.splitlines()[1].strip()):
                self.assertIn("docker logout dhi.io", job)
                action_offsets = [
                    job.index(action)
                    for action in (
                        "uses: actions/upload-artifact@",
                        "uses: aquasecurity/trivy-action@",
                    )
                    if action in job
                ]
                self.assertLess(
                    job.index("docker logout dhi.io"),
                    min(action_offsets),
                )


class TrivyWaiverContractTests(unittest.TestCase):
    def test_committed_waivers_are_reviewed_and_unexpired(self) -> None:
        result = subprocess.run(
            ["python3", "-I", ".github/scripts/validate-trivy-waivers.py"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((ROOT / ".trivyignore").exists())
        self.assertEqual(
            (ROOT / ".github/trivyignore-images.yaml").read_text(encoding="utf-8"),
            "vulnerabilities: []\n",
        )
        self.assertEqual(WORKFLOW.count("trivyignores: .trivyignore.yaml"), 1)
        self.assertEqual(
            WORKFLOW.count("trivyignores: .github/trivyignore-images.yaml"), 2
        )
        self.assertIn("Validate reviewed Trivy waivers", WORKFLOW)
        self.assertIn("timedelta(days=366)", (
            ROOT / ".github/scripts/validate-trivy-waivers.py"
        ).read_text(encoding="utf-8"))

    def test_waiver_without_owner_or_with_bad_expiry_fails(self) -> None:
        future = (date.today() + timedelta(days=30)).isoformat()
        missing_owner = [
            "  - id: CVE-2099-0001",
            f"    expired_at: {future}",
            "    statement: >-",
            "      This explanation is deliberately long but has no named owner at all.",
        ]
        with self.assertRaises(WAIVERS.WaiverError):
            WAIVERS.validate_block("vulnerabilities", missing_owner, date.today())

        expired = [
            "  - id: CVE-2099-0001",
            f"    expired_at: {(date.today() - timedelta(days=1)).isoformat()}",
            "    statement: >-",
            "      Owner: platform security. This is a clear but expired waiver reason.",
        ]
        with self.assertRaises(WAIVERS.WaiverError):
            WAIVERS.validate_block("vulnerabilities", expired, date.today())

    def test_vulnerability_waiver_requires_a_versioned_purl(self) -> None:
        future = (date.today() + timedelta(days=30)).isoformat()
        unscoped = [
            "  - id: CVE-2099-0001",
            f"    expired_at: {future}",
            "    statement: >-",
            "      Owner: platform security. This global vulnerability waiver is forbidden.",
        ]
        with self.assertRaises(WAIVERS.WaiverError):
            WAIVERS.validate_block("vulnerabilities", unscoped, date.today())

        scoped = [
            "  - id: CVE-2099-0001",
            "    purls:",
            "      - pkg:golang/example.org/module@v1.2.3",
            f"    expired_at: {future}",
            "    statement: >-",
            "      Owner: platform security. This waiver is limited to one exact package version.",
        ]
        WAIVERS.validate_block("vulnerabilities", scoped, date.today())


if __name__ == "__main__":
    unittest.main()
