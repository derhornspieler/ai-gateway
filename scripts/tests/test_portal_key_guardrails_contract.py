"""Portal key-issuance guardrails: cross-file contract pins.

The dev portal mints every self-service LiteLLM virtual key with reviewed
budget/rate/lifetime caps. Those caps live in reviewed configuration
(group_vars → Ansible-rendered .env → the dev-portal environment) — never in
runtime-editable state and never chosen by the browser. These pins keep the
group_vars defaults, the env template, the Compose wiring, the converge-time
shape gate, and the portal's own in-code fallback defaults in lockstep.
"""

from __future__ import annotations

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]

# One reviewed baseline, asserted identically on every surface. Owner
# decision: the platform default is UNLIMITED — restrictions come from the
# runtime per-project policy, and budgets are admin-set per key only.
EXPECTED_DEFAULTS = {
    "max_budget": "none",
    "tpm_limit": "none",
    "rpm_limit": "none",
    "duration": "none",
}


class PortalKeyGuardrailsContractTest(unittest.TestCase):
    def test_group_vars_carry_the_reviewed_defaults(self) -> None:
        group_vars = (ROOT / "ansible/group_vars/all.yml").read_text(
            encoding="utf-8"
        )
        for knob, value in EXPECTED_DEFAULTS.items():
            self.assertIn(f'portal_key_default_{knob}: "{value}"', group_vars)
        self.assertIn("portal_key_project_limits: {}", group_vars)

    def test_env_template_renders_each_guardrail_exactly_once(self) -> None:
        env = (
            ROOT / "ansible/roles/docker_stack/templates/env.j2"
        ).read_text(encoding="utf-8")
        for line in (
            "PORTAL_KEY_DEFAULT_MAX_BUDGET={{ portal_key_default_max_budget }}",
            "PORTAL_KEY_DEFAULT_TPM_LIMIT={{ portal_key_default_tpm_limit }}",
            "PORTAL_KEY_DEFAULT_RPM_LIMIT={{ portal_key_default_rpm_limit }}",
            "PORTAL_KEY_DEFAULT_DURATION={{ portal_key_default_duration }}",
            "PORTAL_KEY_PROJECT_LIMITS={{ portal_key_project_limits | to_json }}",
        ):
            self.assertEqual(env.count(line), 1, line)

    def test_compose_feeds_exactly_the_key_minting_portal(self) -> None:
        compose = (ROOT / "compose/docker-compose.yml").read_text(encoding="utf-8")
        for name in (
            "PORTAL_KEY_DEFAULT_MAX_BUDGET",
            "PORTAL_KEY_DEFAULT_TPM_LIMIT",
            "PORTAL_KEY_DEFAULT_RPM_LIMIT",
            "PORTAL_KEY_DEFAULT_DURATION",
            "PORTAL_KEY_PROJECT_LIMITS",
        ):
            # Only the dev portal mints keys; the admin portal retunes
            # existing keys and deliberately receives no issuance defaults,
            # so each guardrail is wired exactly once.
            self.assertEqual(
                compose.count(f"{name}: ${{{name}:?{name} must be set}}"), 1, name
            )

    def test_converge_gates_the_guardrail_shapes(self) -> None:
        stack = (
            ROOT / "ansible/roles/docker_stack/tasks/main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("Validate portal key-issuance guardrail shapes", stack)
        self.assertIn("portal_key_project_limits is mapping", stack)
        self.assertIn(
            "portal_key_default_duration is match('^(none|[1-9][0-9]{0,5}(s|m|h|d))$')",
            stack,
        )

    def test_portal_fallback_defaults_match_the_reviewed_baseline(self) -> None:
        config = (ROOT / "services/dev-portal/app/config.py").read_text(
            encoding="utf-8"
        )
        for knob, value in EXPECTED_DEFAULTS.items():
            self.assertIn(f'portal_key_default_{knob}: str = "{value}"', config)
        self.assertIn('portal_key_project_limits: str = "{}"', config)
        # The portal fails closed on ambiguity instead of minting an
        # uncapped or absurdly capped static bearer credential.
        self.assertIn("refusing to start with invalid key-issuance guardrails", config)

    def test_validator_renders_and_asserts_the_guardrails(self) -> None:
        validator = (ROOT / "scripts/validate-compose.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'portal_env["PORTAL_KEY_DEFAULT_MAX_BUDGET"] == "none"', validator
        )
        self.assertIn(
            'portal_env["PORTAL_KEY_DEFAULT_DURATION"] == "none"', validator
        )
        self.assertIn(
            '"PORTAL_KEY_PROJECT_LIMITS" not in services["admin-portal"]',
            validator,
        )


if __name__ == "__main__":
    unittest.main()
