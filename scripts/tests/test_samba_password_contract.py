"""Regression contracts for disposable preprod directory credentials."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
PREPROD = ROOT / "scripts" / "preprod.py"
ENTRYPOINT = ROOT / "services" / "samba-ad-preprod" / "samba-ad-entrypoint"
SECRET_TOOL = ROOT / "services" / "samba-ad-preprod" / "samba-ad-secret-tool"


def load_preprod_module():
    spec = importlib.util.spec_from_file_location("aigw_preprod_passwords", PREPROD)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SambaPasswordContractTests(unittest.TestCase):
    def test_private_preprod_passwords_are_strong_distinct_and_seeded(
        self,
    ) -> None:
        source = PREPROD.read_text(encoding="utf-8")
        labels = re.findall(
            r'\("(?:preprod-samba-(?:admin|bind)-password|'
            r'samba_user_preprod-(?:admin|developer|user)_password)", '
            r'"(samba-[a-z-]+)"\)',
            source,
        )
        self.assertEqual(len(labels), 5)
        self.assertEqual(len(set(labels)), 5)
        module = load_preprod_module()
        with tempfile.TemporaryDirectory() as directory:
            seed = Path(directory) / "seed"
            seed.write_bytes(b"s" * module.PREPROD_CREDENTIAL_SEED_BYTES)
            seed.chmod(0o600)
            with mock.patch.object(module, "PREPROD_CREDENTIAL_SEED", seed):
                values = [module.credential_password(label) for label in labels]
        self.assertEqual(len(set(values)), 5)
        for value in values:
            with self.subTest(length=len(value)):
                self.assertGreaterEqual(len(value), 16)
                self.assertRegex(value, r"[A-Z]")
                self.assertRegex(value, r"[a-z]")
                self.assertRegex(value, r"[0-9]")
                self.assertRegex(value, r"[^A-Za-z0-9]")
        self.assertNotIn("OnlyForTesting", source)

    def test_private_credentials_are_rebuilt_with_owner_only_permissions(self) -> None:
        source = PREPROD.read_text(encoding="utf-8")
        password_loop = source.split("for filename, label in (", 1)[1].split(
            "redis_password =", 1
        )[0]
        self.assertIn("credential_password(label)", password_loop)
        self.assertIn("0o600", password_loop)
        self.assertNotIn("replace=False", password_loop)

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
