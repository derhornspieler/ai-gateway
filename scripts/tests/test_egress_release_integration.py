"""Cross-layer contracts for one immutable Envoy policy release."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class EgressReleaseIntegrationTests(unittest.TestCase):
    def test_ansible_uses_the_loaded_policy_before_rendering_the_environment(self) -> None:
        offline = (
            ROOT / "ansible/roles/docker_stack/tasks/offline_image_seed.yml"
        ).read_text(encoding="utf-8")
        tasks = (ROOT / "ansible/roles/docker_stack/tasks/main.yml").read_text(
            encoding="utf-8"
        )
        environment = (
            ROOT / "ansible/roles/docker_stack/templates/env.j2"
        ).read_text(encoding="utf-8")

        self.assertIn("loaded-egress-policy-receipt", offline)
        self.assertIn("aigw_release_egress_policy.selected_providers", offline)
        self.assertIn("aigw_release_egress_policy.egress_policy_sha256", offline)
        self.assertIn("aigw_release_egress_policy.envoy_image_id", offline)
        self.assertLess(
            tasks.index("Process optional offline external-image seed before Compose"),
            tasks.index("Validate immutable Envoy release build inputs"),
        )
        self.assertIn(
            "AIGW_EGRESS_PROVIDERS={{ aigw_egress_providers | join(',') }}",
            environment,
        )
        self.assertIn(
            "AIGW_EGRESS_POLICY_SHA256={{ aigw_egress_policy_sha256 }}",
            environment,
        )

    def test_live_verification_binds_policy_image_and_selected_routes(self) -> None:
        verify = (ROOT / "ansible/roles/verify/tasks/main.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("Read the live immutable Envoy policy receipt", verify)
        self.assertIn("/usr/local/bin/aigw-envoy-entrypoint", verify)
        self.assertIn("live_envoy_policy_raw.stdout | from_json", verify)
        self.assertIn("aigw_expected_envoy_image_id", verify)
        self.assertIn("loop: \"{{ live_envoy_policy.providers }}\"", verify)
        self.assertNotIn("/anthropic/v1/models", verify)

    def test_seeded_preprod_reuses_and_executes_the_exact_policy_image(self) -> None:
        preprod = (ROOT / "scripts/preprod.py").read_text(encoding="utf-8")

        self.assertIn("def seed_egress_policy", preprod)
        self.assertIn('values["AIGW_EGRESS_PROVIDERS"]', preprod)
        self.assertIn('values["AIGW_EGRESS_POLICY_SHA256"]', preprod)
        self.assertIn('envoy["archive_reference"]', preprod)
        self.assertIn('"receipt",', preprod)
        self.assertIn(
            "the seeded Envoy image policy differs from the release receipt",
            preprod,
        )


if __name__ == "__main__":
    unittest.main()
