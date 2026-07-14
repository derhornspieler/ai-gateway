"""Contracts for first-init Vault share custody in controller Ansible Vault."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts/store-vault-unseal-key.py"
BOOTSTRAP = ROOT / "scripts/vault-bootstrap.sh"
GENERATOR = ROOT / "scripts/bootstrap-generic-rocky9.py"
CONTRACT = ROOT / "ansible/generic-rocky9-contract.json"
EXAMPLES = ROOT / "ansible/inventory/examples"
FAKE_SHARE = "A" * 43 + "="


class VaultCustodyContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ansible_vault = shutil.which("ansible-vault")
        self.assertIsNotNone(self.ansible_vault, "ansible-vault is required")

    @staticmethod
    def password_file(root: Path) -> Path:
        path = root / "vault-password"
        path.write_text("test-only-controller-password\n", encoding="utf-8")
        path.chmod(0o600)
        return path

    def invoke(
        self, root: Path, share: str = FAKE_SHARE, destination: Path | None = None
    ) -> tuple[subprocess.CompletedProcess[str], Path]:
        vault_file = destination or root / "group_vars/production/vault-unseal.yml"
        vault_file.parent.mkdir(parents=True, exist_ok=True)
        vault_file.parent.chmod(0o700)
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                str(HELPER),
                "--vault-file",
                str(vault_file),
                "--vault-id",
                "production",
                "--vault-password-file",
                str(self.password_file(root)),
                "--ansible-vault",
                str(self.ansible_vault),
            ],
            input=share + "\n",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        return result, vault_file

    def test_stdin_share_is_inline_encrypted_verified_and_never_printed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result, vault_file = self.invoke(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn(FAKE_SHARE, result.stdout)
            self.assertNotIn(FAKE_SHARE, result.stderr)
            self.assertIn("Stored and verified", result.stdout)
            self.assertIn("Encrypted controller custody is verified", result.stdout)
            self.assertIn("post-bootstrap Ansible converge", result.stdout)

            content = vault_file.read_text(encoding="utf-8")
            self.assertNotIn(FAKE_SHARE, content)
            self.assertEqual(content.count("vault_unseal_key: !vault |"), 1)
            self.assertIn("$ANSIBLE_VAULT;1.2;AES256;production", content)
            self.assertEqual(stat.S_IMODE(vault_file.stat().st_mode), 0o600)

            # Independent structural/decryption proof. Keep the decrypted test
            # fixture captured in process memory; never print it.
            lines = content.split("vault_unseal_key: !vault |\n", 1)[1].splitlines()
            ciphertext = root / "ciphertext-only"
            ciphertext.write_text(
                "\n".join(line.lstrip() for line in lines) + "\n",
                encoding="ascii",
            )
            viewed = subprocess.run(
                [
                    str(self.ansible_vault),
                    "view",
                    "--vault-id",
                    f"production@{root / 'vault-password'}",
                    str(ciphertext),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(viewed.returncode, 0, viewed.stderr)
            self.assertEqual(viewed.stdout.rstrip("\n"), FAKE_SHARE)

    def test_existing_key_and_whole_file_vault_are_refused_without_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result, vault_file = self.invoke(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            before = vault_file.read_bytes()
            result, _ = self.invoke(root, share="Z" * 43 + "=", destination=vault_file)
            self.assertEqual(result.returncode, 2)
            self.assertIn("already exists", result.stderr)
            self.assertEqual(vault_file.read_bytes(), before)

            whole = root / "group_vars/production/whole-file.yml"
            whole.write_text("$ANSIBLE_VAULT;1.1;AES256\n012345\n", encoding="ascii")
            whole.chmod(0o600)
            result, _ = self.invoke(root, destination=whole)
            self.assertEqual(result.returncode, 2)
            self.assertIn("whole-file encrypted", result.stderr)
            self.assertNotIn(FAKE_SHARE, result.stderr)

    def test_inline_value_retains_ansible_vault_encrypted_type(self) -> None:
        ansible_playbook = shutil.which("ansible-playbook")
        self.assertIsNotNone(ansible_playbook, "ansible-playbook is required")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            vault_file = root / "group_vars/all/vault-unseal.yml"
            result, _ = self.invoke(root, destination=vault_file)
            self.assertEqual(result.returncode, 0, result.stderr)
            (root / "hosts.yml").write_text(
                "all:\n  hosts:\n    localhost:\n      ansible_connection: local\n",
                encoding="utf-8",
            )
            (root / "verify.yml").write_text(
                """---
- hosts: all
  gather_facts: false
  tasks:
    - ansible.builtin.assert:
        that:
          - vault_unseal_key is vault_encrypted
          - vault_unseal_key | length == 44
          - vault_unseal_key is match('^[A-Za-z0-9+/]{43}=$')
      no_log: true
""",
                encoding="utf-8",
            )
            verified = subprocess.run(
                [
                    str(ansible_playbook),
                    "-i",
                    str(root / "hosts.yml"),
                    str(root / "verify.yml"),
                    "--vault-id",
                    f"production@{root / 'vault-password'}",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertNotIn(FAKE_SHARE, verified.stdout)
            self.assertNotIn(FAKE_SHARE, verified.stderr)

    def test_invalid_share_and_unsafe_files_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result, vault_file = self.invoke(root, share="too-short")
            self.assertEqual(result.returncode, 2)
            self.assertFalse(vault_file.exists())
            self.assertNotIn("too-short", result.stderr)

            password = root / "vault-password"
            password.chmod(0o640)
            vault_file.parent.mkdir(parents=True, exist_ok=True)
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(HELPER),
                    "--vault-file",
                    str(vault_file),
                    "--vault-id",
                    "production",
                    "--vault-password-file",
                    str(password),
                ],
                input=FAKE_SHARE + "\n",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("must not grant group or world access", result.stderr)

    def test_bootstrap_reserves_captured_stdout_and_retains_recovery_copy(self) -> None:
        source = BOOTSTRAP.read_text(encoding="utf-8")
        subprocess.run(["bash", "-n", str(BOOTSTRAP)], check=True)
        for required in (
            "--emit-unseal-key",
            'if [[ -t 1 ]]',
            "exec 3>&1",
            "exec 1>&2",
            'printf \'%s\\n\' "$UNSEAL_KEY" >&3',
            "retaining secrets/vault-init.json",
            "controller helper has",
        ):
            self.assertIn(required, source)
        self.assertLess(
            source.index('printf \'%s\\n\' "$UNSEAL_KEY" |'),
            source.index('printf \'%s\\n\' "$UNSEAL_KEY" >&3'),
        )
        self.assertLess(
            source.index('"$STACK_DIR/scripts/aigw-runtime-up.sh" -d'),
            source.index('printf \'%s\\n\' "$UNSEAL_KEY" >&3'),
        )
        # The controller share is never accepted from argv or environment.
        helper = HELPER.read_text(encoding="utf-8")
        self.assertIn("sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)", helper)
        self.assertNotIn("--unseal-key", helper)
        self.assertNotRegex(helper, r"os\.environ\[[\"'].*UNSEAL")

    def test_contract_and_generator_never_randomly_create_unseal_key(self) -> None:
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        generated = [entry["name"] for entry in contract["required_secret_keys"]]
        operator = contract["operator_supplied_secret_keys"]
        self.assertNotIn("vault_unseal_key", generated)
        self.assertEqual(
            operator,
            [
                {
                    "name": "vault_unseal_key",
                    "source": "hashicorp-vault-operator-init",
                    "generated_by_inventory_bootstrap": False,
                }
            ],
        )
        generator = GENERATOR.read_text(encoding="utf-8")
        self.assertIn("vault_unseal_key was NOT generated", generator)
        self.assertIn("store-vault-unseal-key.py", generator)
        self.assertIn("Created production Rocky 9 inventory", generator)
        self.assertIn("production_rocky9", generator)
        random_region = generator.split("def random_secret", 1)[1].split(
            "def encrypted_value", 1
        )[0]
        self.assertNotIn("vault_unseal_key", random_region)

    def test_safe_lab_and_production_templates_have_exact_secret_boundaries(self) -> None:
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        base = {entry["name"] for entry in contract["required_secret_keys"]}
        lab = base | set(contract["lab_only_secret_keys"])
        for name, expected in (
            ("production-rocky9.vault.yml.example", base),
            ("rocky9-lab.vault.yml.example", lab),
        ):
            source = (EXAMPLES / name).read_text(encoding="utf-8")
            actual = set(re.findall(r"^([a-z0-9_]+):", source, re.MULTILINE))
            self.assertEqual(actual, expected | {"vault_unseal_key"})
            self.assertIn("<OPERATOR_INIT_OUTPUT;", source)
            self.assertNotIn("$ANSIBLE_VAULT;", source)
        production_host = (
            EXAMPLES / "production-rocky9.host-vars.yml.example"
        ).read_text(encoding="utf-8")
        self.assertIn("deployment_profile: generic-rocky9", production_host)
        self.assertIn("backwards-compatible", production_host)
        lab_host = (EXAMPLES / "rocky9-lab.host-vars.yml.example").read_text(
            encoding="utf-8"
        )
        self.assertIn("deployment_profile: rocky9-lab", lab_host)

        lab_flow = (EXAMPLES / "rocky9-lab.first-init.sh.example").read_text(
            encoding="utf-8"
        )
        first_converge = lab_flow.index("ansible-playbook")
        bootstrap = lab_flow.index("vault-bootstrap.sh --emit-unseal-key")
        custody = lab_flow.index("store-vault-unseal-key.py")
        second_converge = lab_flow.index("ansible-playbook", first_converge + 1)
        cleanup = lab_flow.index("securely delete")
        self.assertLess(first_converge, bootstrap)
        self.assertLess(bootstrap, custody)
        self.assertLess(custody, second_converge)
        self.assertLess(second_converge, cleanup)

        production_flow = (
            EXAMPLES / "production-rocky9.first-init.sh.example"
        ).read_text(encoding="utf-8")
        self.assertIn("reviewed production Vault init", production_flow)
        self.assertIn("read -rsp 'Vault unseal share: '", production_flow)
        self.assertIn(
            'printf \'%s\\n\' "$AIGW_UNSEAL_SHARE" |', production_flow
        )
        self.assertNotIn("--unseal-key", production_flow)
        self.assertLess(
            production_flow.index("store-vault-unseal-key.py"),
            production_flow.index("ansible-playbook"),
        )


if __name__ == "__main__":
    unittest.main()
