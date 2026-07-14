"""Contracts for controller-owned automatic HashiCorp Vault unseal."""

from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
STACK_TASKS = ROOT / "ansible/roles/docker_stack/tasks/main.yml"
VERIFY_TASKS = ROOT / "ansible/roles/verify/tasks/main.yml"
GROUP_VARS = ROOT / "ansible/group_vars/all.yml"
ENV_TEMPLATE = ROOT / "ansible/roles/docker_stack/templates/env.j2"
COMPOSE = ROOT / "compose/docker-compose.yml"
SITE = ROOT / "ansible/site.yml"
LAB_INVENTORY = ROOT / "ansible/inventory/lab.yml"
GENERIC_INVENTORY = ROOT / "ansible/inventory/hosts.yml"


def task_block(source: str, name: str, next_name: str) -> str:
    return source.split(f"- name: {name}\n", 1)[1].split(
        f"- name: {next_name}\n", 1
    )[0]


class VaultAnsibleUnsealContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.stack = STACK_TASKS.read_text(encoding="utf-8")
        cls.verify = VERIFY_TASKS.read_text(encoding="utf-8")

    def test_initialized_vault_requires_strict_controller_secret_shape(self) -> None:
        block = task_block(
            self.stack,
            "Require the encrypted controller Vault unseal key after initialization",
            "Automatically unseal initialized Vault from controller inventory",
        )
        for required in (
            "vault_unseal_key is defined",
            "vault_unseal_key is vault_encrypted",
            "vault_unseal_key is string",
            "vault_unseal_key | length == 44",
            "vault_unseal_key is match('^[A-Za-z0-9+/]{43}=$')",
            "(vault_status_before_unseal.stdout | from_json).initialized | bool",
            "no_log: true",
            "from the encrypted\n      controller inventory",
        ):
            self.assertIn(required, block)

        # There is intentionally no plaintext/default value. The encrypted
        # inventory supplies it only after the one-time initialization.
        group_vars = GROUP_VARS.read_text(encoding="utf-8")
        active_definitions = [
            line
            for line in group_vars.splitlines()
            if re.match(r"^vault_unseal_key\s*:", line)
        ]
        self.assertEqual(active_definitions, [])
        self.assertIn(
            "vault_unseal_key:           <vault overlay only>",
            group_vars,
        )

    def test_actual_inline_ansible_vault_value_passes_deployment_assert(self) -> None:
        ansible_vault = shutil.which("ansible-vault")
        ansible_playbook = shutil.which("ansible-playbook")
        self.assertIsNotNone(ansible_vault, "ansible-vault is required")
        self.assertIsNotNone(ansible_playbook, "ansible-playbook is required")
        fake_share = "A" * 43 + "="

        block = task_block(
            self.stack,
            "Require the encrypted controller Vault unseal key after initialization",
            "Automatically unseal initialized Vault from controller inventory",
        )
        assertions = [
            line.removeprefix("      - ")
            for line in block.splitlines()
            if line.startswith("      - ")
        ]
        self.assertIn("vault_unseal_key is vault_encrypted", assertions)
        self.assertIn("vault_unseal_key is string", assertions)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            password_file = root / "vault-password"
            password_file.write_text("test-only-vault-password\n", encoding="utf-8")
            password_file.chmod(0o600)
            encrypted = subprocess.run(
                [
                    str(ansible_vault),
                    "encrypt_string",
                    "--vault-id",
                    f"test@{password_file}",
                    "--stdin-name",
                    "vault_unseal_key",
                ],
                input=fake_share,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(encrypted.returncode, 0, encrypted.stderr)
            self.assertNotIn(fake_share, encrypted.stdout)
            vault_file = root / "vault.yml"
            vault_file.write_text(encrypted.stdout, encoding="utf-8")
            playbook = root / "verify.yml"
            rendered_assertions = "\n".join(
                f"          - {condition}" for condition in assertions
            )
            playbook.write_text(
                "---\n"
                "- hosts: localhost\n"
                "  connection: local\n"
                "  gather_facts: false\n"
                "  vars_files:\n"
                f"    - {json.dumps(str(vault_file))}\n"
                "  tasks:\n"
                "    - name: Exercise the deployed unseal-key assertion\n"
                "      ansible.builtin.assert:\n"
                "        that:\n"
                f"{rendered_assertions}\n"
                "        quiet: true\n"
                "      no_log: true\n",
                encoding="utf-8",
            )
            verified = subprocess.run(
                [
                    str(ansible_playbook),
                    "-i",
                    "localhost,",
                    str(playbook),
                    "--vault-id",
                    f"test@{password_file}",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertNotIn(fake_share, verified.stdout)
            self.assertNotIn(fake_share, verified.stderr)
            self.assertEqual(
                verified.returncode,
                0,
                f"stdout={verified.stdout}\nstderr={verified.stderr}",
            )

    def test_initialized_vault_must_retain_one_of_one_shamir_contract(self) -> None:
        block = task_block(
            self.stack,
            "Require the reviewed 1-of-1 Shamir seal contract after initialization",
            "Require the encrypted controller Vault unseal key after initialization",
        )
        for required in (
            ".type == 'shamir'",
            ".t | int == 1",
            ".n | int == 1",
            "singular vault_unseal_key cannot safely unseal it",
            "(vault_status_before_unseal.stdout | from_json).initialized | bool",
        ):
            self.assertIn(required, block)

    def test_unseal_key_is_streamed_only_to_hardened_script_stdin(self) -> None:
        block = task_block(
            self.stack,
            "Automatically unseal initialized Vault from controller inventory",
            "Re-read public Vault state after the automatic-unseal decision",
        )
        self.assertIn('- "{{ stack_dir }}/scripts/vault-unseal.sh"', block)
        self.assertIn('stdin: "{{ vault_unseal_key }}"', block)
        self.assertIn("stdin_add_newline: false", block)
        self.assertIn("no_log: true", block)
        self.assertIn(".initialized | bool", block)
        self.assertIn(".sealed | bool", block)
        self.assertNotIn("environment:", block)
        argv = block.split("argv:", 1)[1].split("    stdin:", 1)[0]
        self.assertNotIn("vault_unseal_key", argv)

        # The secret must never enter a generated target file or Compose
        # environment. Its sole runtime data-plane use is command stdin.
        self.assertNotIn("vault_unseal_key", ENV_TEMPLATE.read_text(encoding="utf-8"))
        self.assertNotIn("vault_unseal_key", COMPOSE.read_text(encoding="utf-8"))

    def test_initialized_deploy_rechecks_state_and_full_dependency_readiness(self) -> None:
        initial = self.stack.index(
            "Read public Vault initialization and seal state before automatic unseal"
        )
        seal_contract = self.stack.index(
            "Require the reviewed 1-of-1 Shamir seal contract after initialization"
        )
        key_contract = self.stack.index(
            "Require the encrypted controller Vault unseal key after initialization"
        )
        unseal = self.stack.index(
            "Automatically unseal initialized Vault from controller inventory"
        )
        reread = self.stack.index(
            "Re-read public Vault state after the automatic-unseal decision"
        )
        final_assert = self.stack.index(
            "Require automatic unseal for every initialized Vault deployment"
        )
        vault_ready = self.stack.index(
            "Probe strict Vault readiness after the automatic-unseal decision"
        )
        rotator_ready = self.stack.index(
            "Probe strict key-rotator dependency readiness after stack start"
        )
        full_wait = self.stack.index("Wait for the complete post-bootstrap stack")
        self.assertLess(initial, seal_contract)
        self.assertLess(seal_contract, key_contract)
        self.assertLess(key_contract, unseal)
        self.assertLess(unseal, reread)
        self.assertLess(reread, final_assert)
        self.assertLess(final_assert, vault_ready)
        self.assertLess(vault_ready, rotator_ready)
        self.assertLess(rotator_ready, full_wait)

        final = task_block(
            self.stack,
            "Require automatic unseal for every initialized Vault deployment",
            "Prove a fresh deployment was not initialized implicitly",
        )
        self.assertIn("not ((vault_public_status.stdout | from_json).sealed | bool)", final)
        self.assertIn("vault_public_status.rc == 0", final)
        self.assertIn("no_log: true", final)

        boundary = task_block(
            self.stack,
            "Bound the Vault bootstrap health exception to fresh uninitialized state",
            "Require restored Vault state instead of replacement initialization",
        )
        for required in (
            "not ((vault_public_status.stdout | from_json).initialized | bool)",
            "not ((vault_public_status.stdout | from_json).sealed | bool)",
            "vault_strict_readiness.rc == 0",
            "key_rotator_strict_readiness.rc == 0",
            "every initialized deployment fails closed here",
        ):
            self.assertIn(required, boundary)

        self.assertIn("Refuse a sealed or dependency-unready initialized Vault deployment", self.verify)
        verifier = task_block(
            self.verify,
            "Refuse a sealed or dependency-unready initialized Vault deployment",
            "Read Docker daemon state-root configuration",
        )
        self.assertIn("vault_public_status.rc == 0", verifier)
        self.assertIn("vault_strict_readiness.rc == 0", verifier)
        self.assertIn("key_rotator_strict_readiness.rc == 0", verifier)

    def test_fresh_state_remains_explicit_and_non_destructive(self) -> None:
        fresh = task_block(
            self.stack,
            "Prove a fresh deployment was not initialized implicitly",
            "Probe strict Vault readiness after the automatic-unseal decision",
        )
        self.assertIn("not ((vault_public_status.stdout | from_json).initialized | bool)", fresh)
        self.assertIn("(vault_public_status.stdout | from_json).sealed | bool", fresh)
        self.assertIn("must never be", fresh)
        self.assertIn("inferred or made destructive", fresh)

        automatic = task_block(
            self.stack,
            "Automatically unseal initialized Vault from controller inventory",
            "Re-read public Vault state after the automatic-unseal decision",
        )
        self.assertNotIn("operator init", automatic)
        self.assertNotIn("vault-bootstrap.sh", automatic)
        self.assertIn("Report the fresh Vault bootstrap gate", self.stack)

    def test_lab_and_generic_inventory_paths_share_the_same_role_contract(self) -> None:
        site = SITE.read_text(encoding="utf-8")
        lab = LAB_INVENTORY.read_text(encoding="utf-8")
        generic = GENERIC_INVENTORY.read_text(encoding="utf-8")
        self.assertIn("hosts: gateway:generic_rocky9", site)
        self.assertIn("- role: docker_stack", site)
        self.assertIn("- role: verify", site)
        self.assertIn("gateway:", lab)
        self.assertIn("deployment_profile: rocky9-lab", lab)
        self.assertIn("generic_rocky9:", generic)

        # The unseal decision is intentionally state-based, not tied to a lab,
        # generic_rocky9, or future production group/profile name.
        unseal_region = self.stack.split(
            "Read public Vault initialization and seal state before automatic unseal",
            1,
        )[1].split(
            "Require restored Vault state instead of replacement initialization",
            1,
        )[0]
        self.assertNotIn("deployment_profile", unseal_region)
        self.assertNotIn("generic_rocky9", unseal_region)
        self.assertNotIn("rocky9-lab", unseal_region)

    def test_only_fresh_uninitialized_vaults_are_runtime_health_exceptions(self) -> None:
        allowed = self.verify.split(
            "- \"{{ aigw_bind_source_digests | to_json }}\"", 1
        )[1].split('- "{{ docker_data_root }}"', 1)[0]
        self.assertIn("not ((vault_public_status.stdout | from_json).initialized | bool)", allowed)
        self.assertNotIn("vault_strict_readiness.rc != 0", allowed)
        self.assertNotIn(".sealed | bool", allowed)


if __name__ == "__main__":
    unittest.main()
