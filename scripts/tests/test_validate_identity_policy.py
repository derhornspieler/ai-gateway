from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "scripts" / "validate-identity-policy.py"


class DeployedIdentityPolicyValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "scripts").mkdir()
        (self.root / "keycloak").mkdir()
        (self.root / "services" / "samba-ad-lab").mkdir(parents=True)
        shutil.copy2(VALIDATOR, self.root / "scripts" / VALIDATOR.name)
        shutil.copytree(
            ROOT / "compose" / "keycloak" / "realms",
            self.root / "keycloak" / "realms",
        )
        shutil.copy2(
            ROOT / "services" / "samba-ad-lab" / "samba-ad-entrypoint",
            self.root / "services" / "samba-ad-lab" / "samba-ad-entrypoint",
        )

    def run_validator(self, domain: str | None) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.pop("AIGW_VALIDATION_DOMAIN", None)
        if domain is not None:
            environment["AIGW_VALIDATION_DOMAIN"] = domain
        return subprocess.run(
            [sys.executable, "-I", str(self.root / "scripts" / VALIDATOR.name)],
            text=True,
            capture_output=True,
            check=False,
            env=environment,
        )

    def test_pristine_deployed_layout_accepts_explicit_reviewed_domain(self) -> None:
        result = self.run_validator("aigw.example.internal")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_pristine_deployed_layout_requires_explicit_domain(self) -> None:
        result = self.run_validator(None)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("AIGW_VALIDATION_DOMAIN", result.stderr)

    def test_existing_env_must_match_explicit_inventory_domain(self) -> None:
        (self.root / ".env").write_text("DOMAIN=aigw.example.internal\n")
        matching = self.run_validator("aigw.example.internal")
        self.assertEqual(matching.returncode, 0, matching.stderr)
        mismatched = self.run_validator("other.example.internal")
        self.assertNotEqual(mismatched.returncode, 0)
        self.assertIn("disagree", mismatched.stderr)

    def test_unsafe_explicit_domain_is_rejected(self) -> None:
        result = self.run_validator("aigw.internal\nINJECTED=value")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("safe DNS name", result.stderr)


if __name__ == "__main__":
    unittest.main()
