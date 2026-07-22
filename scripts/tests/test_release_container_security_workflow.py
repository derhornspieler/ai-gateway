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
VEX = load(
    ".github/scripts/manage-dhi-vex.py",
    "_test_manage_dhi_vex",
)
REVIEWED_VEX = load(
    ".github/scripts/manage-reviewed-vex.py",
    "_test_manage_reviewed_vex",
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

    def test_docker_scout_receives_protected_backend_credentials(self) -> None:
        fetch = WORKFLOW.split(
            "      - name: Fetch and verify exact DHI VEX statements", 1
        )[1].split("      - name: Remove DHI registry credentials", 1)[0]
        self.assertIn(
            "DOCKER_SCOUT_HUB_USER: ${{ secrets.DHI_USERNAME }}", fetch
        )
        self.assertIn(
            "DOCKER_SCOUT_HUB_PASSWORD: ${{ secrets.DHI_PASSWORD }}", fetch
        )
        self.assertNotIn("--username", fetch)
        self.assertNotIn("--password", fetch)
        self.assertEqual(
            WORKFLOW.count("dockerhub-user: ${{ secrets.DHI_USERNAME }}"), 2
        )
        self.assertEqual(
            WORKFLOW.count("dockerhub-password: ${{ secrets.DHI_PASSWORD }}"), 2
        )
        self.assertEqual(
            WORKFLOW.count("registry-user: ${{ secrets.DHI_USERNAME }}"), 2
        )
        self.assertEqual(
            WORKFLOW.count("registry-password: ${{ secrets.DHI_PASSWORD }}"), 2
        )

    def test_custom_builds_pin_the_production_compose_and_buildkit(self) -> None:
        custom = WORKFLOW.split("  custom-images:", 1)[1]
        self.assertIn(
            "uses: docker/setup-compose-action@"
            "4eb059ff7f16592f9c84d5ca339c53cb7c5064e2 # v2.3.0",
            custom,
        )
        self.assertIn("version: v5.3.1", custom)
        self.assertIn(
            "uses: docker/setup-buildx-action@"
            "bb05f3f5519dd87d3ba754cc423b652a5edd6d2c # v4.2.0",
            custom,
        )
        self.assertIn("driver: docker-container", custom)
        self.assertIn(
            "image=moby/buildkit:v0.31.2@sha256:"
            "2f5adac4ecd194d9f8c10b7b5d7bceb5186853db1b26e5abd3a657af0b7e26ec",
            custom,
        )

    def test_plan_uses_the_authoritative_full_seed_union(self) -> None:
        scopes = SEED.collect_project_image_reference_scopes(ROOT)
        self.assertTrue(scopes[SEED.RELEASE_SCOPE_PRODUCTION])
        self.assertGreaterEqual(
            len(scopes[SEED.RELEASE_SCOPE_PREPROD]),
            len(scopes[SEED.RELEASE_SCOPE_PRODUCTION]),
        )
        self.assertEqual(len(scopes[SEED.RELEASE_SCOPE_PRODUCTION]), 23)
        self.assertEqual(len(scopes[SEED.RELEASE_SCOPE_PREPROD]), 25)
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
        self.assertEqual(shared["dhi_bases"], [])

        manifest["services"]["two"]["digest"] = "c" * 64
        with self.assertRaises(PLAN.ReleaseSecurityError):
            PLAN.custom_matrix(manifest, {"mock"}, "linux/amd64")

    def test_every_image_gets_a_blocking_high_critical_scan_and_evidence(self) -> None:
        self.assertEqual(WORKFLOW.count("Record raw Trivy high and critical findings"), 2)
        self.assertEqual(WORKFLOW.count("Enforce VEX-aware high and critical gate"), 2)
        self.assertEqual(WORKFLOW.count("severity: HIGH,CRITICAL"), 3)
        self.assertEqual(WORKFLOW.count('ignore-unfixed: "false"'), 3)
        self.assertEqual(WORKFLOW.count('exit-code: "1"'), 1)
        self.assertEqual(WORKFLOW.count('exit-code: "0"'), 2)
        self.assertEqual(WORKFLOW.count("exit-code: true"), 2)
        self.assertEqual(WORKFLOW.count("format: cyclonedx"), 2)
        self.assertEqual(WORKFLOW.count("trivy-vulnerabilities.json"), 2)
        self.assertEqual(WORKFLOW.count("scout-vulnerabilities.sarif"), 2)
        self.assertEqual(WORKFLOW.count("provenance.json"), 2)
        self.assertEqual(WORKFLOW.count("if-no-files-found: error"), 4)
        self.assertIn("Enforce exact pull and vulnerability gate", WORKFLOW)
        self.assertIn("Enforce exact build and vulnerability gate", WORKFLOW)
        self.assertIn('[[ "$SCAN_OUTCOME" != "success" ]]', WORKFLOW)
        self.assertEqual(WORKFLOW.count("validate-image-security-evidence.py"), 2)
        self.assertEqual(WORKFLOW.count('[[ "$EVIDENCE_OUTCOME" != "success" ]]'), 2)
        self.assertNotIn("trivy-config:", WORKFLOW)
        self.assertEqual(WORKFLOW.count("--vex-receipt"), 2)
        self.assertEqual(WORKFLOW.count("manage-dhi-vex.py select"), 2)
        self.assertIn("build_input_sha256", PROVENANCE_SOURCE)
        self.assertIn("runtime_and_database_metadata", PROVENANCE_SOURCE)
        self.assertIn("not signed SLSA provenance", PROVENANCE_SOURCE)
        self.assertIn("did not receive or inspect the operator's local offline archive", PROVENANCE_SOURCE)

    def test_evidence_validator_rejects_findings_missing_files_and_id_drift(self) -> None:
        # Raw Trivy results stay in the evidence even when DHI VEX later proves
        # a finding is not exploitable. Docker Scout is the VEX-aware gate.
        EVIDENCE.validate_vulnerability_report(
            {
                "SchemaVersion": 2,
                "Results": [{"Vulnerabilities": [{"Severity": "HIGH"}]}],
            }
        )
        with self.assertRaises(EVIDENCE.EvidenceError):
            EVIDENCE.validate_scout_sarif(
                {
                    "version": "2.1.0",
                    "runs": [
                        {
                            "tool": {"driver": {"name": "docker scout"}},
                            "results": [{"ruleId": "CVE-2099-0001"}],
                        }
                    ],
                }
            )
        with self.assertRaises(EVIDENCE.EvidenceError):
            EVIDENCE.validate_sbom({"bomFormat": "not-cyclonedx"})
        provenance = {
            "schema": 1,
            "outcomes": {
                "pull_or_build": "success",
                "raw_trivy_scan": "success",
                "high_critical_scan": "success",
                "sbom": "success",
            },
            "scanner": {
                "waiver_file_sha256": "a" * 64,
                "vex": {
                    "receipt_file": "selected-dhi-vex.json",
                    "receipt_sha256": "c" * 64,
                    "signature_verified": True,
                    "transparency_log_verified": False,
                    "references": [],
                    "document_sha256s": [],
                    "statuses": [],
                    "reviewed_records": [],
                },
            },
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
                provenance,
                "linux/amd64",
                "sha256:" + "b" * 64,
                ("c" * 64, [], [], [], []),
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

    def test_dhi_vex_is_exact_signed_and_bound_to_each_build(self) -> None:
        policy_path = ROOT / ".github/dhi-vex-policy.json"
        policy = VEX.load_policy(policy_path)
        self.assertEqual(policy["docker_scout"]["version"], "1.23.1")
        self.assertTrue(policy["verification"]["skip_transparency_log"])
        self.assertGreater(
            len(policy["verification"]["skip_transparency_log_reason"]), 40
        )
        manager = (ROOT / ".github/scripts/manage-dhi-vex.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('"--verify"', manager)
        self.assertIn('"--skip-tlog"', manager)
        self.assertIn('"--key"', manager)
        self.assertEqual(WORKFLOW.count("actions/download-artifact@"), 2)
        self.assertEqual(WORKFLOW.count("Download signature-verified DHI VEX evidence"), 2)

    def test_dockerfile_dhi_base_discovery_is_exact_and_reviewed(self) -> None:
        open_webui = {
            "build": {
                "context": "services/dhi-health-probe",
                "dockerfile": "Dockerfile.open-webui",
                "args": {
                    "BASE_IMAGE": (
                        "ghcr.io/open-webui/open-webui:v0.10.2@sha256:"
                        "9fcea9c6e32ab60b0498f3986c6cdf651ddbe61db48d2213a3d28048ddd673d4"
                    )
                },
            }
        }
        self.assertEqual(
            PLAN.dockerfile_dhi_bases(ROOT, "open-webui", open_webui),
            [],
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            context = root / "services/example"
            context.mkdir(parents=True)
            (context / "Dockerfile").write_text(
                "FROM dhi.io/python:3.14.6\n", encoding="utf-8"
            )
            with self.assertRaises(PLAN.ReleaseSecurityError):
                PLAN.dockerfile_dhi_bases(
                    root,
                    "example",
                    {"build": {"context": "services/example"}},
                )

    def test_vex_selector_rejects_unknown_and_copies_only_requested_base(self) -> None:
        reference = (
            "dhi.io/python:3.14.6@sha256:"
            "c82da5a1a30a6214f45c42def5b6f5b85981c7dc7a1802015a6ebf264675436d"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            vex_directory = source / "vex"
            vex_directory.mkdir(parents=True)
            filename = "0" * 24 + ".openvex.json"
            vex_path = vex_directory / filename
            vex_payload = {
                "@context": "https://openvex.dev/ns/v0.2.0",
                "@id": "https://scout.docker.com/public/vex-test",
                "author": "Docker Hardened Images <dhi@docker.com>",
                "role": "Document Creator",
                "tooling": "Docker Scout",
                "statements": [
                    {
                        "products": [{"@id": reference.split("@", 1)[0]}],
                        "status": "not_affected",
                    }
                ],
            }
            vex_path.write_text(json.dumps(vex_payload), encoding="utf-8")
            policy_path = ROOT / ".github/dhi-vex-policy.json"
            policy = VEX.load_policy(policy_path)
            receipt = {
                "schema": 1,
                "platform": "linux/amd64",
                "policy_sha256": VEX.sha256_file(policy_path),
                "public_key_sha256": policy["verification"]["public_key_sha256"],
                "docker_scout_version": "v1.23.1",
                "signature_verified": True,
                "transparency_log_verified": False,
                "transparency_log_note": policy["verification"][
                    "skip_transparency_log_reason"
                ],
                "records": [
                    {
                        "document_id": vex_payload["@id"],
                        "file": f"vex/{filename}",
                        "reason": None,
                        "reference": reference,
                        "sha256": VEX.sha256_file(vex_path),
                        "statements": 1,
                        "status": "verified",
                    }
                ],
            }
            VEX.write_json(source / "receipt.json", receipt)
            output = root / "selected"
            VEX.select_vex(
                policy_path,
                source,
                json.dumps([reference]),
                "linux/amd64",
                output,
            )
            selected = json.loads(
                (output / "selected-dhi-vex.json").read_text(encoding="utf-8")
            )
            self.assertEqual([record["reference"] for record in selected["records"]], [reference])
            self.assertTrue((output / "vex" / filename).is_file())
            _, references, document_sha256s, statuses, reviewed = EVIDENCE.validate_vex_receipt(
                selected, output, "linux/amd64"
            )
            self.assertEqual(references, [reference])
            self.assertEqual(document_sha256s, [VEX.sha256_file(vex_path)])
            self.assertEqual(statuses, ["verified"])
            self.assertEqual(reviewed, [])
            with self.assertRaises(VEX.VexError):
                VEX.select_vex(
                    policy_path,
                    source,
                    json.dumps([reference.replace("python", "unknown")]),
                    "linux/amd64",
                    root / "rejected",
                )

    def test_missing_dhi_vex_stays_recorded_and_unsuppressed(self) -> None:
        reference = (
            "dhi.io/busybox:1.38.0-alpine@sha256:"
            "69a25015bda2c7dfac5d3a88990b56bc0f38539b313c448b171edef1497193ad"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            policy_path = ROOT / ".github/dhi-vex-policy.json"
            policy = VEX.load_policy(policy_path)
            receipt = {
                "schema": 1,
                "platform": "linux/amd64",
                "policy_sha256": VEX.sha256_file(policy_path),
                "public_key_sha256": policy["verification"]["public_key_sha256"],
                "docker_scout_version": "v1.23.1",
                "signature_verified": True,
                "transparency_log_verified": False,
                "transparency_log_note": policy["verification"][
                    "skip_transparency_log_reason"
                ],
                "records": [
                    {
                        "document_id": None,
                        "file": None,
                        "reason": VEX.NO_VEX_REASON,
                        "reference": reference,
                        "sha256": None,
                        "statements": 0,
                        "status": "unavailable",
                    }
                ],
            }
            VEX.write_json(source / "receipt.json", receipt)
            output = root / "selected"
            VEX.select_vex(
                policy_path,
                source,
                json.dumps([reference]),
                "linux/amd64",
                output,
            )
            selected = EVIDENCE.read_json(output / "selected-dhi-vex.json")
            _, references, document_sha256s, statuses, reviewed = EVIDENCE.validate_vex_receipt(
                selected, output, "linux/amd64"
            )
            self.assertEqual(references, [reference])
            self.assertEqual(document_sha256s, [])
            self.assertEqual(statuses, ["unavailable"])
            self.assertEqual(reviewed, [])
            self.assertEqual(list((output / "vex").iterdir()), [])

    def test_local_openwebui_vex_is_exact_expiring_and_never_claimed_signed(self) -> None:
        self.assertIn("manage-reviewed-vex.py", WORKFLOW)
        self.assertIn(
            "Docker Hardened Images <dhi@docker.com>,AI Gateway platform security "
            "<security@aigw.internal>",
            WORKFLOW,
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            (output / "vex").mkdir()
            receipt = {
                "schema": 1,
                "platform": "linux/amd64",
                "policy_sha256": "a" * 64,
                "public_key_sha256": "b" * 64,
                "docker_scout_version": "v1.23.1",
                "signature_verified": True,
                "transparency_log_verified": False,
                "transparency_log_note": "Signature verification used the reviewed Docker key; transparency proof was unavailable.",
                "records": [],
                "reviewed_records": [],
            }
            receipt_path = output / "selected-dhi-vex.json"
            VEX.write_json(receipt_path, receipt)
            REVIEWED_VEX.attach(
                ROOT,
                "open-webui",
                "ai-gateway/open-webui:0.10.2-aigw2",
                receipt_path,
            )
            selected = EVIDENCE.read_json(receipt_path)
            _, references, signed_hashes, statuses, reviewed = (
                EVIDENCE.validate_vex_receipt(selected, output, "linux/amd64")
            )
            self.assertEqual(references, [])
            self.assertEqual(signed_hashes, [])
            self.assertEqual(statuses, [])
            self.assertEqual(len(reviewed), 1)
            self.assertFalse(reviewed[0]["signature_verified"])
            self.assertEqual(reviewed[0]["vulnerability"], "CVE-2026-45829")
            with self.assertRaises(REVIEWED_VEX.ReviewedVexError):
                REVIEWED_VEX.attach(
                    ROOT,
                    "open-webui",
                    "ai-gateway/open-webui:wrong",
                    receipt_path,
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
