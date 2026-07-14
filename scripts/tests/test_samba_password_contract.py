"""Regression contract for Samba AD bootstrap credential policy."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
TASKS = ROOT / "ansible" / "roles" / "docker_stack" / "tasks" / "main.yml"


class SambaPasswordContractTests(unittest.TestCase):
    def test_samba_bootstrap_requires_default_ad_password_complexity(self) -> None:
        source = TASKS.read_text(encoding="utf-8")
        start = source.index("- name: Fail closed on missing or unsafe Samba lab secrets")
        end = source.index(
            "- name: Validate per-gate oauth2-proxy cookie secret shapes", start
        )
        block = source[start:end]

        for requirement in (
            "| length >= 16",
            "is regex('^[A-Za-z0-9_-]+$')",
            "is regex('.*[A-Z].*')",
            "is regex('.*[a-z].*')",
            "is regex('.*[0-9].*')",
            "samba_ad_admin_password",
            "samba_ad_bind_password",
            "samba_user_lab_admin_password",
            "samba_user_lab_developer_password",
            "samba_user_lab_user_password",
            "| unique | length == 5",
        ):
            self.assertIn(requirement, block)

        self.assertIn("no_log: true", block)


if __name__ == "__main__":
    unittest.main()
