"""LiteLLM admin UI break-glass credential: cross-file contract pins.

Owner decision: the native LiteLLM admin UI stays ACTIVE (behind the ADM-only
oauth2-proxy OIDC gate), but browser sign-in uses a DEDICATED break-glass
credential generated into the encrypted inventory — never the master key,
which is a server-side bearer credential and must never be typed into a
browser. That control spans the Compose environment, the Ansible-rendered
.env, the generic/production inventory contract, the docker_stack secret
gate, and the deploy-end custody notice. These pins keep those surfaces in
lockstep so no single edit can silently disable the UI, reuse the master key
for it, or leak the credential into converge output.
"""

from __future__ import annotations

import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


class LiteLLMUiBreakGlassContractTest(unittest.TestCase):
    def test_compose_keeps_ui_active_with_a_dedicated_credential(self) -> None:
        compose = (ROOT / "compose/docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn("UI_USERNAME: litellm-breakglass", compose)
        self.assertIn(
            "UI_PASSWORD: ${LITELLM_UI_BREAKGLASS_PASSWORD:?"
            "LITELLM_UI_BREAKGLASS_PASSWORD must be set}",
            compose,
        )
        # The UI stays active: no kill switch, and exactly one service carries
        # the break-glass login.
        self.assertNotIn("DISABLE_ADMIN_UI", compose)
        self.assertEqual(compose.count("UI_USERNAME:"), 1)
        self.assertEqual(compose.count("UI_PASSWORD:"), 1)
        # The master key must never double as the browser credential.
        self.assertNotIn("UI_PASSWORD: ${LITELLM_MASTER_KEY", compose)

    def test_env_template_renders_the_secret_fail_closed(self) -> None:
        env = (
            ROOT / "ansible/roles/docker_stack/templates/env.j2"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "LITELLM_UI_BREAKGLASS_PASSWORD="
            "{{ litellm_ui_breakglass_password | mandatory(",
            env,
        )
        # Never render the master key under the UI credential's name.
        self.assertNotIn("LITELLM_UI_BREAKGLASS_PASSWORD={{ litellm_master_key", env)
        self.assertEqual(env.count("LITELLM_UI_BREAKGLASS_PASSWORD="), 1)

    def test_generic_contract_generates_and_gates_the_secret(self) -> None:
        contract = json.loads(
            (ROOT / "ansible/generic-rocky9-contract.json").read_text(
                encoding="utf-8"
            )
        )
        entries = [
            entry
            for entry in contract["required_secret_keys"]
            if entry["name"] == "litellm_ui_breakglass_password"
        ]
        self.assertEqual(
            entries,
            [
                {
                    "name": "litellm_ui_breakglass_password",
                    "min_length": 32,
                    "alphabet": "safe",
                }
            ],
        )
        stack = (
            ROOT / "ansible/roles/docker_stack/tasks/main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "- { name: litellm_ui_breakglass_password, min_length: 32 }", stack
        )
        # Reusing either LiteLLM secret as the browser credential would
        # collapse the exact boundary this feature exists to create.
        self.assertIn(
            "litellm_ui_breakglass_password not in "
            "[litellm_master_key, litellm_salt_key]",
            stack,
        )

    def test_deploy_end_notice_points_at_custody_without_the_value(self) -> None:
        finalize = (
            ROOT / "ansible/roles/host_finalize/tasks/main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "Finalize — surface the LiteLLM UI break-glass credential custody pointer",
            finalize,
        )
        self.assertIn("'litellm_ui_breakglass_password'", finalize)
        self.assertIn("litellm-breakglass", finalize)
        self.assertIn("litellm-admin.{{ aigw_domain }}/ui", finalize)
        # The notice is a pointer: the secret itself is never interpolated
        # into converge output by this role.
        self.assertNotIn("{{ litellm_ui_breakglass_password", finalize)

    def test_validator_asserts_the_rendered_boundary(self) -> None:
        validator = (ROOT / "scripts/validate-compose.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('litellm_env["UI_USERNAME"] == "litellm-breakglass"', validator)
        self.assertIn(
            'litellm_env["UI_PASSWORD"] != litellm_env["LITELLM_MASTER_KEY"]',
            validator,
        )
        self.assertIn('"DISABLE_ADMIN_UI" not in litellm_env', validator)


if __name__ == "__main__":
    unittest.main()
