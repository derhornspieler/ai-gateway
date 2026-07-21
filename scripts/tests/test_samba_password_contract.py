"""Regression contracts for disposable preprod directory credentials."""

from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
PREPROD = ROOT / "scripts" / "preprod.py"
ENTRYPOINT = ROOT / "services" / "samba-ad-preprod" / "samba-ad-entrypoint"
SECRET_TOOL = ROOT / "services" / "samba-ad-preprod" / "samba-ad-secret-tool"


class SambaPasswordContractTests(unittest.TestCase):
    def test_static_preprod_passwords_are_strong_distinct_and_explicitly_test_only(
        self,
    ) -> None:
        source = PREPROD.read_text(encoding="utf-8")
        values = re.findall(
            r'write_file\(SECRETS_DIR / "(?:preprod-samba-(?:admin|bind)-password|'
            r'samba_user_preprod-(?:admin|developer|user)_password)", '
            r'"([^"\\]+)\\n", 0o600, replace=False\)',
            source,
        )
        self.assertEqual(len(values), 5)
        self.assertEqual(len(set(values)), 5)
        for value in values:
            with self.subTest(value=value):
                self.assertGreaterEqual(len(value), 16)
                self.assertRegex(value, r"[A-Z]")
                self.assertRegex(value, r"[a-z]")
                self.assertRegex(value, r"[0-9]")
                self.assertRegex(value, r"[^A-Za-z0-9]")
                self.assertTrue(value.startswith("OnlyForTesting1!"))

    def test_static_credentials_are_created_once_with_owner_only_permissions(self) -> None:
        source = PREPROD.read_text(encoding="utf-8")
        self.assertEqual(source.count("0o600, replace=False)"), 5)
        self.assertIn("existing static preprod file differs", source)

    def test_entrypoint_passes_only_secret_file_paths_to_the_helper(self) -> None:
        source = ENTRYPOINT.read_text(encoding="utf-8")
        for operation in (
            "domain-provision",
            "bind-user-create",
            "user-create",
            "user-setpassword",
        ):
            self.assertIn(f"samba-ad-secret-tool {operation}", source)
        self.assertIn('"/run/secrets/samba_user_${seed_user}_password"', source)

    def test_helper_reads_bounded_nofollow_secret_files_without_child_processes(
        self,
    ) -> None:
        source = SECRET_TOOL.read_text(encoding="utf-8")
        for requirement in (
            "SECRET_PATH_RE",
            "os.O_RDONLY",
            'getattr(os, "O_NOFOLLOW", 0)',
            "stat.S_ISREG",
            "metadata.st_size > 513",
            "samba_tool(*tool_args)",
        ):
            self.assertIn(requirement, source)
        self.assertNotIn("subprocess", source)
        self.assertNotIn("os.environ[", source)


if __name__ == "__main__":
    unittest.main()
