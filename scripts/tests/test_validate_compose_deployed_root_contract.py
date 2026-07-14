"""scripts/validate-compose.sh runs in TWO contexts: a controller checkout and
the deployed stack root (/opt/ai-gateway), where Ansible invokes it before any
container is created. Only the scripts in the deployed manifest exist in the
second context. Any unguarded `$ROOT/scripts/<name>` read therefore has to be a
deployed script, or the converge dies inside docker_stack.

This regression exists because scripts/sign-vault-intermediate.sh — the OFFLINE
CA-side signing ceremony, which validate-compose.sh itself asserts must never be
deployed — was also read unguarded, so the validator demanded a file its own
deployment contract forbids shipping.
"""

from __future__ import annotations

import re
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = (ROOT / "scripts" / "validate-compose.sh").read_text(encoding="utf-8")


def deployed_scripts() -> set[str]:
    """The exact script manifest validate-compose.sh pins for the gateway host."""
    block = re.search(
        r"deployed_scripts\s*=\s*\{(.*?)\}", VALIDATOR, re.DOTALL
    ) or re.search(r"expected_scripts\s*=\s*\((.*?)\)", VALIDATOR, re.DOTALL)
    assert block is not None, "deployed-script manifest moved in validate-compose.sh"
    return set(re.findall(r'"([^"]+\.(?:sh|py))"', block.group(1)))


class ValidatorNeverReadsAnUndeployedScript(unittest.TestCase):
    def test_every_undeployed_script_read_is_existence_guarded(self) -> None:
        manifest = deployed_scripts()
        self.assertTrue(manifest, "deployed-script manifest parsed empty")

        # A controller-only script may be referenced, but ONLY behind an
        # existence guard — either literally, or via the established
        # variable+guard idiom (see SAFE_INVENTORY).
        variables = dict(
            re.findall(
                r'^([A-Z_]+)="\$ROOT/scripts/([A-Za-z0-9._-]+)"', VALIDATOR, re.MULTILINE
            )
        )
        guarded: set[str] = set(
            re.findall(r'\[\[ -f "\$ROOT/scripts/([A-Za-z0-9._-]+)" \]\]', VALIDATOR)
        )
        for variable, script in variables.items():
            if re.search(rf'\[\[ -f "\${variable}" \]\]', VALIDATOR):
                guarded.add(script)

        referenced = set(re.findall(r'\$ROOT/scripts/([A-Za-z0-9._-]+\.(?:sh|py))', VALIDATOR))
        unprotected = sorted(referenced - manifest - guarded)
        self.assertEqual(
            unprotected,
            [],
            "validate-compose.sh reads these scripts without an existence guard, "
            "but they are not in the deployed manifest — the converge runs this "
            "validator from the deployed stack root, where they do not exist, so "
            "it will fail inside docker_stack: " + ", ".join(unprotected),
        )

    def test_the_ca_side_signing_script_stays_undeployed_and_guarded(self) -> None:
        # The security property: the offline CA ceremony never ships to the host.
        self.assertIn('assert "sign-vault-intermediate.sh" not in deployed_scripts', VALIDATOR)
        self.assertNotIn("sign-vault-intermediate.sh", deployed_scripts())
        # ...and consequently its source checks must be guarded on file existence,
        # using the same variable+guard idiom as SAFE_INVENTORY.
        self.assertIn('SIGN_INTERMEDIATE="$ROOT/scripts/sign-vault-intermediate.sh"', VALIDATOR)
        self.assertIn('if [[ -f "$SIGN_INTERMEDIATE" ]]; then', VALIDATOR)


if __name__ == "__main__":
    unittest.main()
