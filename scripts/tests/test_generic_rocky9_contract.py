"""Regression coverage for the separate generic Rocky 9 inventory contract."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "ansible" / "generic-rocky9-contract.json"
BOOTSTRAP = ROOT / "scripts" / "bootstrap-generic-rocky9.py"
PREFLIGHT = ROOT / "ansible" / "preflight-generic-rocky9.yml"
ALL_VARS = ROOT / "ansible" / "group_vars" / "all.yml"
GENERIC_GROUP_VARS = ROOT / "ansible" / "inventory" / "group_vars" / "generic_rocky9.yml"
GENERIC_INVENTORY = ROOT / "ansible" / "inventory" / "hosts.yml"
LAB_VARS = ROOT / "ansible" / "inventory" / "host_vars" / "lab-aigw01.yml"
LAB_INVENTORY = ROOT / "ansible" / "inventory" / "lab.yml"
LAB_VAULT = ROOT / "ansible" / "inventory" / "group_vars" / "gateway" / "vault.yml"
STACK_ONLY = ROOT / "ansible" / "deploy-stack-only.yml"
SITE = ROOT / "ansible" / "site.yml"
STACK_TASKS = ROOT / "ansible" / "roles" / "docker_stack" / "tasks" / "main.yml"


class GenericRocky9ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))

    def test_contract_is_the_complete_generic_secret_key_manifest(self) -> None:
        self.assertEqual(self.contract["schema"], "aigw.generic-rocky9/v1")
        self.assertEqual(self.contract["profile"], "generic-rocky9")
        self.assertEqual(self.contract["host_vars_filename"], "{inventory_alias}.yml")
        names = [entry["name"] for entry in self.contract["required_secret_keys"]]
        self.assertEqual(len(names), len(set(names)))
        self.assertNotIn("rotator_vault_token", names)
        self.assertEqual(
            names,
            [
                "pg_super_password",
                "pg_litellm_password",
                "pg_keycloak_password",
                "pg_rotator_password",
                "kc_admin_password",
                "litellm_master_key",
                "litellm_salt_key",
                "redis_password",
                "webui_litellm_key",
                "webui_secret_key",
                "webui_oidc_client_secret",
                "portal_oidc_client_secret",
                "admin_portal_oidc_client_secret",
                "oauth2_proxy_client_secret",
                "oauth2_proxy_litellm_cookie_secret",
                "oauth2_proxy_grafana_cookie_secret",
                "oauth2_proxy_prometheus_cookie_secret",
                "oauth2_proxy_vault_cookie_secret",
                "portal_session_secret",
                "admin_portal_session_secret",
                "rotator_internal_token",
                "portal_identity_token",
                "grafana_admin_password",
                "kc_bootstrap_admin_client_secret",
            ],
        )
        source = STACK_TASKS.read_text(encoding="utf-8")
        for name in names:
            if name.startswith("oauth2_proxy_") and name.endswith("_cookie_secret"):
                self.assertIn("Validate per-gate oauth2-proxy cookie secret shapes", source)
                self.assertIn(f"- {name}", source)
            else:
                self.assertIn(f"name: {name}", source)
        self.assertEqual(
            self.contract["lab_only_secret_keys"],
            [
                "samba_ad_admin_password",
                "samba_ad_bind_password",
                "samba_user_lab_admin_password",
                "samba_user_lab_developer_password",
                "samba_user_lab_user_password",
            ],
        )

    def test_generic_and_lab_profiles_are_explicit_and_encryption_is_fail_closed(self) -> None:
        inventory = GENERIC_INVENTORY.read_text(encoding="utf-8")
        generic = GENERIC_GROUP_VARS.read_text(encoding="utf-8")
        lab = LAB_INVENTORY.read_text(encoding="utf-8")
        lab_host_vars = LAB_VARS.read_text(encoding="utf-8")
        defaults = ALL_VARS.read_text(encoding="utf-8")

        self.assertIn("generic_rocky9:", inventory)
        self.assertIn("gateway:\n      hosts: {}", inventory)
        self.assertNotIn("gateway:\n      children:", inventory)
        self.assertTrue(LAB_VAULT.is_file())
        for required in (
            "deployment_profile: generic-rocky9",
            "require_encrypted_state: true",
            "require_preupgrade_backup: true",
            "aigw_vault_ui_enabled: false",
            "aigw_ssh_password_authentication: false",
            "aigw_adm_socks_enabled: false",
        ):
            self.assertIn(required, generic)
        self.assertIn("deployment_profile: rocky9-lab", lab)
        self.assertIn("require_encrypted_state: false", lab)
        self.assertNotIn("deployment_profile:", lab_host_vars)
        self.assertNotIn("require_encrypted_state:", lab_host_vars)
        self.assertIn("aigw_encrypted_state_preflight_required:", defaults)
        self.assertIn("(deployment_profile | default('')) != 'rocky9-lab'", defaults)
        self.assertIn("(require_encrypted_state | bool)", defaults)
        for source in (STACK_ONLY, SITE):
            self.assertIn(
                "when: aigw_encrypted_state_preflight_required | bool",
                source.read_text(encoding="utf-8"),
            )

    def test_ansible_precedence_keeps_only_lab_false_unencrypted(self) -> None:
        """Exercise the inline lab exception without a Vault or host_vars."""
        ansible_playbook = shutil.which("ansible-playbook")
        self.assertIsNotNone(ansible_playbook, "ansible-playbook is required")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "group_vars").mkdir()
            (root / "inventory" / "host_vars").mkdir(parents=True)
            (root / "group_vars" / "all.yml").write_text(
                """---
require_encrypted_state: true
aigw_encrypted_state_preflight_required: >-
  {{ (deployment_profile | default('')) != 'rocky9-lab' or
     (require_encrypted_state | bool) }}
""",
                encoding="utf-8",
            )
            (root / "inventory" / "hosts.yml").write_text(
                """---
all:
  children:
    gateway:
      hosts:
        lab-aigw01:
          deployment_profile: rocky9-lab
          require_encrypted_state: false
          expected_encryption_preflight: false
        customer-aigw01:
""",
                encoding="utf-8",
            )
            (root / "inventory" / "host_vars" / "customer-aigw01.yml").write_text(
                """---
deployment_profile: generic-rocky9
require_encrypted_state: false
expected_encryption_preflight: true
""",
                encoding="utf-8",
            )
            playbook = root / "precedence.yml"
            playbook.write_text(
                """---
- hosts: gateway
  gather_facts: false
  tasks:
    - ansible.builtin.assert:
        that:
          - (aigw_encrypted_state_preflight_required | bool) == expected_encryption_preflight
""",
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    str(ansible_playbook),
                    "-i",
                    str(root / "inventory" / "hosts.yml"),
                    str(playbook),
                ],
                cwd=root,
                env={"PATH": os.environ["PATH"], "ANSIBLE_NOCOLOR": "1"},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_bootstrap_creates_alias_matched_layout_and_ciphertext_only_vault(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            password_file = root / "vault-password"
            password_file.write_text("test-only-password\n", encoding="utf-8")
            password_file.chmod(0o600)
            fake_vault = root / "fake-ansible-vault"
            fake_vault.write_text(
                """#!/usr/bin/env python3
import sys

arguments = sys.argv[1:]
if arguments[:1] != ["encrypt_string"] or "--vault-id" not in arguments or "--stdin-name" not in arguments:
    raise SystemExit(2)
name = arguments[arguments.index("--stdin-name") + 1]
if not sys.stdin.buffer.read():
    raise SystemExit(3)
print(f"{name}: !vault |")
print("          $ANSIBLE_VAULT;1.2;AES256;test")
print("          0123456789abcdef")
""",
                encoding="utf-8",
            )
            fake_vault.chmod(fake_vault.stat().st_mode | stat.S_IXUSR)
            layout = root / "customer-inventory"
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(BOOTSTRAP),
                    "--inventory-dir",
                    str(layout),
                    "--inventory-alias",
                    "customer-aigw01",
                    "--vault-id",
                    "customer-prod",
                    "--vault-password-file",
                    str(password_file),
                    "--ansible-vault",
                    str(fake_vault),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            host_vars = layout / "host_vars" / "customer-aigw01.yml"
            vault = layout / "group_vars" / "generic_rocky9" / "vault.yml"
            self.assertTrue((layout / "hosts.yml").is_file())
            self.assertTrue(host_vars.is_file())
            self.assertTrue(vault.is_file())
            self.assertIn("customer-aigw01:", (layout / "hosts.yml").read_text())
            host_text = host_vars.read_text(encoding="utf-8")
            self.assertIn("aigw_generic_inventory_alias: customer-aigw01", host_text)
            self.assertIn("deployment_profile: generic-rocky9", host_text)
            self.assertIn("require_encrypted_state: true", host_text)
            self.assertIn("aigw_vault_ui_enabled: false", host_text)
            self.assertIn("Mode A -- use existing corporate DNS", host_text)
            self.assertIn("Mode B -- let this gateway answer only its own aigw_domain", host_text)
            self.assertIn(
                'internal_dns_servers: ["{{ eth1_ip }}", "{{ eth2_ip }}"]',
                host_text,
            )
            self.assertIn("must not replace a client's general", host_text)
            self.assertIn("only Envoy gets", host_text)
            self.assertIn("keep service discovery but have no", host_text)
            for entry in self.contract["required_secret_keys"]:
                self.assertNotIn(entry["name"], host_text)
            vault_text = vault.read_text(encoding="utf-8")
            self.assertIn("$ANSIBLE_VAULT;", vault_text)
            for entry in self.contract["required_secret_keys"]:
                self.assertIn(f"{entry['name']}: !vault |", vault_text)
            self.assertFalse(any(path.suffix == ".tmp" for path in layout.rglob("*")))

    def test_bootstrap_rejects_unsafe_vault_password_files(self) -> None:
        source = BOOTSTRAP.read_text(encoding="utf-8")
        self.assertIn("metadata.st_uid != os.geteuid()", source)
        self.assertIn("metadata.st_nlink != 1", source)
        self.assertIn("stat.S_IMODE(metadata.st_mode) & 0o077", source)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def invoke(password_file: Path) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        str(BOOTSTRAP),
                        "--inventory-dir",
                        str(root / f"output-{password_file.name}"),
                        "--inventory-alias",
                        "customer-aigw01",
                        "--vault-id",
                        "customer-prod",
                        "--vault-password-file",
                        str(password_file),
                        "--ansible-vault",
                        "/not-needed-for-input-validation",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )

            group_readable = root / "group-readable"
            group_readable.write_text("test-only-password\n", encoding="utf-8")
            group_readable.chmod(0o640)
            result = invoke(group_readable)
            self.assertEqual(result.returncode, 2)
            self.assertIn("must not grant group or world access", result.stderr)

            regular = root / "regular"
            regular.write_text("test-only-password\n", encoding="utf-8")
            regular.chmod(0o600)
            symlink = root / "password-link"
            symlink.symlink_to(regular)
            result = invoke(symlink)
            self.assertEqual(result.returncode, 2)
            self.assertIn("non-symlink regular file", result.stderr)

            not_a_file = root / "not-a-file"
            not_a_file.mkdir()
            result = invoke(not_a_file)
            self.assertEqual(result.returncode, 2)
            self.assertIn("non-symlink regular file", result.stderr)

            hard_link = root / "password-hard-link"
            os.link(regular, hard_link)
            result = invoke(regular)
            self.assertEqual(result.returncode, 2)
            self.assertIn("exactly one hard link", result.stderr)

    def test_generic_preflight_is_controller_only_and_reports_both_missing_lists(self) -> None:
        source = PREFLIGHT.read_text(encoding="utf-8")
        self.assertIn("hosts: generic_rocky9", source)
        self.assertIn("connection: local", source)
        self.assertIn("delegate_to: localhost", source)
        self.assertIn("host_vars/{{ inventory_hostname }}.yml", source)
        self.assertIn("AIGW_GENERIC_PREFLIGHT=", source)
        self.assertIn("'missing_nonsecret': aigw_generic_missing_nonsecret_keys", source)
        self.assertIn("'invalid_nonsecret': aigw_generic_invalid_nonsecret", source)
        self.assertIn("'missing_secret': aigw_generic_missing_secret_keys", source)
        self.assertIn("'invalid_secret': aigw_generic_invalid_secret_keys", source)
        self.assertIn("'duplicate_secret_boundaries': aigw_generic_duplicate_secret_boundaries", source)
        self.assertIn("'forbidden_lab_options': aigw_generic_forbidden_lab_options", source)
        self.assertIn("validate generic Vault values without emitting values", source)
        self.assertIn("canonical lowercase FQDN without emitting its value", source)
        self.assertIn("canonical_lowercase_fqdn", source)
        self.assertIn("no_log: true", source)
        self.assertIn("samba_lab_enabled", source)
        self.assertIn("aigw_seed_test_users", source)
        self.assertIn("aigw_prebootstrap_oidc_scope_reconciliation", source)
        self.assertNotIn("roles:", source)
        for mutation_entrypoint in (SITE, STACK_ONLY):
            entrypoint_source = mutation_entrypoint.read_text(encoding="utf-8")
            self.assertIn("bounded canonical lowercase", entrypoint_source)
            self.assertIn("(?=.{1,253}$)", entrypoint_source)

        ansible_playbook = shutil.which("ansible-playbook")
        self.assertIsNotNone(ansible_playbook, "ansible-playbook is required")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "hosts.yml").write_text(
                """---
all:
  children:
    generic_rocky9:
      hosts:
        customer-aigw01:
""",
                encoding="utf-8",
            )
            result = subprocess.run(
                [str(ansible_playbook), "-i", str(root / "hosts.yml"), str(PREFLIGHT), "--syntax-check"],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_generic_inventory_does_not_load_the_committed_lab_vault(self) -> None:
        """No Vault ID is supplied; success proves generic selection skips it."""
        ansible_inventory = shutil.which("ansible-inventory")
        self.assertIsNotNone(ansible_inventory, "ansible-inventory is required")
        self.assertTrue(LAB_VAULT.is_file())
        environment = os.environ.copy()
        environment.update(
            {
                "AIGW_ANSIBLE_HOST": "192.0.2.10",
                "AIGW_ANSIBLE_USER": "ansible",
                "ANSIBLE_NOCOLOR": "1",
            }
        )
        result = subprocess.run(
            [str(ansible_inventory), "-i", str(GENERIC_INVENTORY), "--host", "aigw", "--yaml"],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("Attempting to decrypt", result.stderr)

    def test_generic_preflight_reports_all_missing_key_names_without_a_vault(self) -> None:
        ansible_playbook = shutil.which("ansible-playbook")
        self.assertIsNotNone(ansible_playbook, "ansible-playbook is required")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "host_vars").mkdir()
            (root / "hosts.yml").write_text(
                """---
all:
  children:
    generic_rocky9:
      hosts:
        customer-aigw01:
""",
                encoding="utf-8",
            )
            (root / "host_vars" / "customer-aigw01.yml").write_text(
                """---
aigw_generic_inventory_alias: customer-aigw01
deployment_profile: generic-rocky9
require_encrypted_state: true
samba_lab_enabled: false
aigw_seed_test_users: false
retain_bootstrap_admin_user: false
aigw_prebootstrap_oidc_scope_reconciliation: false
aigw_prebootstrap_oidc_scope_reconciliation_ack: ""
platform_authoritative_dns_enabled: false
aigw_vault_ui_enabled: false
aigw_lab_reset_handoff_drop_interfaces: []
""",
                encoding="utf-8",
            )
            result = subprocess.run(
                [str(ansible_playbook), "-i", str(root / "hosts.yml"), str(PREFLIGHT)],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            combined = result.stdout + result.stderr
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("AIGW_GENERIC_PREFLIGHT=", combined)
            self.assertIn('"missing_secret": [', combined)
            self.assertIn("pg_super_password", combined)
            self.assertIn("oauth2_proxy_litellm_cookie_secret", combined)
            self.assertNotIn("test-only-password", combined)

    def test_generic_preflight_rejects_noncanonical_domains_without_echoing_them(self) -> None:
        ansible_playbook = shutil.which("ansible-playbook")
        self.assertIsNotNone(ansible_playbook, "ansible-playbook is required")
        invalid_domains = {
            "uppercase": "AiGw.example.internal",
            "argument_like": "aigw.example.internal --limit all",
            "empty_label": "aigw..example.internal",
            "overlong_label": f"{'a' * 64}.example.internal",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "host_vars").mkdir()
            (root / "hosts.yml").write_text(
                """---
all:
  children:
    generic_rocky9:
      hosts:
        customer-aigw01:
""",
                encoding="utf-8",
            )
            host_vars = root / "host_vars" / "customer-aigw01.yml"

            def run_preflight(domain: str) -> str:
                host_vars.write_text(
                    """---
aigw_generic_inventory_alias: customer-aigw01
deployment_profile: generic-rocky9
aigw_domain: """
                    + json.dumps(domain)
                    + """
require_encrypted_state: true
samba_lab_enabled: false
aigw_seed_test_users: false
retain_bootstrap_admin_user: false
aigw_prebootstrap_oidc_scope_reconciliation: false
aigw_prebootstrap_oidc_scope_reconciliation_ack: ""
platform_authoritative_dns_enabled: false
aigw_vault_ui_enabled: false
aigw_lab_reset_handoff_drop_interfaces: []
""",
                    encoding="utf-8",
                )
                result = subprocess.run(
                    [str(ansible_playbook), "-i", str(root / "hosts.yml"), str(PREFLIGHT)],
                    cwd=ROOT,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                return result.stdout + result.stderr

            canonical_domain = "aigw.example.internal"
            canonical_output = run_preflight(canonical_domain)
            self.assertIn('"invalid_nonsecret": {}', canonical_output)
            self.assertNotIn(canonical_domain, canonical_output)

            for label, domain in invalid_domains.items():
                with self.subTest(label=label):
                    combined = run_preflight(domain)
                    self.assertIn('"invalid_nonsecret"', combined)
                    self.assertIn('"aigw_domain"', combined)
                    self.assertIn('"canonical_lowercase_fqdn"', combined)
                    self.assertNotIn(domain, combined)


if __name__ == "__main__":
    unittest.main()
