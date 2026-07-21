"""Coverage for the canonical rocky9-production terminology and its shared use
of the deprecated generic-rocky9 compatibility implementation."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "ansible" / "generic-rocky9-contract.json"
LEGACY_BOOTSTRAP = ROOT / "scripts" / "bootstrap-generic-rocky9.py"
PROD_BOOTSTRAP = ROOT / "scripts" / "bootstrap-rocky9-production.py"
LEGACY_PREFLIGHT = ROOT / "ansible" / "preflight-generic-rocky9.yml"
PROD_PREFLIGHT = ROOT / "ansible" / "preflight-rocky9-production.yml"
COMMITTED_INVENTORY = ROOT / "ansible" / "inventory" / "hosts.yml"
PROD_GROUP_VARS = ROOT / "ansible" / "inventory" / "group_vars" / "production_rocky9.yml"
GENERIC_GROUP_VARS = ROOT / "ansible" / "inventory" / "group_vars" / "generic_rocky9.yml"
HOSTS_EXAMPLE = ROOT / "ansible" / "inventory" / "examples" / "production-rocky9.hosts.yml.example"
RECONCILE_OPENWEBUI_KEY = ROOT / "scripts" / "reconcile-openwebui-key.py"

FAKE_VAULT = """#!/usr/bin/env python3
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
"""


def _write_fake_vault(root: Path) -> Path:
    fake_vault = root / "fake-ansible-vault"
    fake_vault.write_text(FAKE_VAULT, encoding="utf-8")
    fake_vault.chmod(fake_vault.stat().st_mode | stat.S_IXUSR)
    return fake_vault


def _write_password_file(root: Path) -> Path:
    password_file = root / "vault-password"
    password_file.write_text("test-only-password\n", encoding="utf-8")
    password_file.chmod(0o600)
    return password_file


def _load_bootstrap_module():
    spec = importlib.util.spec_from_file_location("_aigw_bootstrap_under_test", LEGACY_BOOTSTRAP)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_reconcile_openwebui_key_module():
    spec = importlib.util.spec_from_file_location(
        "_aigw_reconcile_openwebui_key_under_test", RECONCILE_OPENWEBUI_KEY
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Rocky9ProductionTerminologyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))

    # ── contract ────────────────────────────────────────────────────────
    def test_contract_declares_canonical_and_compatibility_terminology(self) -> None:
        # The pinned schema id and legacy profile are unchanged for consumers.
        self.assertEqual(self.contract["schema"], "aigw.generic-rocky9/v1")
        self.assertEqual(self.contract["profile"], "generic-rocky9")
        # Canonical terminology is added additively.
        self.assertEqual(self.contract["canonical_profile"], "rocky9-production")
        self.assertEqual(self.contract["canonical_group"], "production_rocky9")
        self.assertEqual(self.contract["compatibility_profile"], "generic-rocky9")
        self.assertEqual(self.contract["compatibility_group"], "generic_rocky9")

    # ── shared implementation, not fork ─────────────────────────────────
    def test_entry_points_share_one_implementation(self) -> None:
        prod_src = PROD_BOOTSTRAP.read_text(encoding="utf-8")
        # The canonical generator is a thin shim over the shared module and
        # defaults to the canonical profile — it never re-implements secret
        # generation.
        self.assertIn("bootstrap-generic-rocky9.py", prod_src)
        self.assertIn('default_profile="rocky9-production"', prod_src)
        self.assertNotIn("encrypt_string", prod_src)
        self.assertNotIn("required_secret_keys", prod_src)
        # The canonical preflight only imports the shared implementation.
        prod_pf = PROD_PREFLIGHT.read_text(encoding="utf-8")
        self.assertIn("import_playbook: preflight-generic-rocky9.yml", prod_pf)
        self.assertNotIn("required_secret_keys", prod_pf)
        self.assertNotIn("AIGW_GENERIC_PREFLIGHT", prod_pf)
        # The shared implementation accepts both profile names, and its
        # AIGW_GENERIC_PREFLIGHT receipt / aigw_generic_* fact names stay
        # deliberately unrenamed (a pinned machine-readable interface).
        legacy_pf = LEGACY_PREFLIGHT.read_text(encoding="utf-8")
        self.assertIn("aigw_generic_rocky9_contract.canonical_profile", legacy_pf)
        self.assertIn("AIGW_GENERIC_PREFLIGHT=", legacy_pf)
        self.assertIn("deliberately unrenamed", legacy_pf)

    def test_no_argument_noninteractive_run_lists_every_required_flag(self) -> None:
        result = subprocess.run(
            [sys.executable, "-I", str(PROD_BOOTSTRAP)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 2)
        for flag in (
            "--inventory-alias",
            "--vault-id",
            "--vault-password-file",
        ):
            self.assertIn(flag, result.stderr)
        self.assertIn("guided setup", result.stderr)
        self.assertIn("interactive example", result.stderr)
        self.assertIn("mygateway.vault-password", result.stderr)

    def test_guided_setup_creates_a_private_vault_password_file(self) -> None:
        bootstrap = _load_bootstrap_module()
        with tempfile.TemporaryDirectory() as temporary:
            password_file = Path(temporary) / "guided.vault-password"
            answers = ["preprod-controller", "", str(password_file), ""]
            with mock.patch("builtins.input", side_effect=answers):
                arguments = bootstrap.guided_arguments(
                    default_profile="rocky9-production"
                )

            self.assertEqual(
                arguments,
                [
                    "--deployment-profile",
                    "rocky9-production",
                    "--inventory-alias",
                    "preprod-controller",
                    "--vault-id",
                    "preprod-controller",
                    "--vault-password-file",
                    str(password_file),
                ],
            )
            self.assertTrue(password_file.is_file())
            self.assertEqual(stat.S_IMODE(password_file.stat().st_mode), 0o600)
            self.assertGreaterEqual(len(password_file.read_text().strip()), 48)

    # ── generator output ────────────────────────────────────────────────
    def test_generated_webui_litellm_key_matches_its_real_consumer_contract(self) -> None:
        bootstrap = _load_bootstrap_module()
        reconcile = _load_reconcile_openwebui_key_module()
        entry = next(
            entry
            for entry in self.contract["required_secret_keys"]
            if entry["name"] == "webui_litellm_key"
        )

        generated = bootstrap.random_secret(entry, set())

        self.assertIsNotNone(reconcile.KEY_RE.fullmatch(generated))
        self.assertTrue(generated.startswith(entry["prefix"]))
        self.assertGreaterEqual(
            len(generated.removeprefix(entry["prefix"])), entry["min_length"]
        )

    def test_production_bootstrap_emits_canonical_layout_and_five_sections(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            password_file = _write_password_file(root)
            fake_vault = _write_fake_vault(root)
            layout = root / "prod-inventory"
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(PROD_BOOTSTRAP),
                    "--inventory-dir",
                    str(layout),
                    "--inventory-alias",
                    "customer-prod01",
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
            # The canonical path is not deprecated.
            self.assertNotIn("DEPRECATION", result.stderr)
            self.assertNotIn("DEPRECATION", result.stdout)
            self.assertIn("Created rocky9-production inventory", result.stdout)
            # The canonical preflight and the two-phase Vault custody flow are
            # printed with the production overlay path.
            self.assertIn("ansible/preflight-rocky9-production.yml", result.stdout)
            self.assertIn("TWO-PHASE DEPLOYMENT BOUNDARY", result.stdout)
            self.assertIn("vault_unseal_key was NOT generated", result.stdout)
            self.assertIn("store-vault-unseal-key.py", result.stdout)
            self.assertIn("group_vars/production_rocky9/vault-unseal.yml", result.stdout)

            inventory = (layout / "hosts.yml").read_text(encoding="utf-8")
            host_vars = layout / "host_vars" / "customer-prod01.yml"
            vault = layout / "group_vars" / "production_rocky9" / "vault.yml"
            self.assertTrue(host_vars.is_file())
            self.assertTrue(vault.is_file())
            # production_rocky9 is a child of the deprecated generic_rocky9 group.
            self.assertIn("generic_rocky9:", inventory)
            self.assertIn("children:", inventory)
            self.assertIn("production_rocky9:", inventory)
            self.assertIn("customer-prod01:", inventory)
            self.assertNotIn("gateway:\n      hosts: {}", inventory)

            host_text = host_vars.read_text(encoding="utf-8")
            self.assertIn("deployment_profile: rocky9-production", host_text)
            self.assertIn("require_encrypted_state: true", host_text)
            self.assertIn("aigw_vault_ui_enabled: false", host_text)
            # Five clearly separated sections.
            self.assertIn("SECTION 1 — non-secret host / interface / routing / DNS inputs", host_text)
            self.assertIn("SECTION 2 — generated encrypted application secrets", host_text)
            self.assertIn("SECTION 3 — operator-supplied vault_unseal_key", host_text)
            self.assertIn("SECTION 4 — external AD / LDAPS inputs (optional, ships disabled)", host_text)
            self.assertIn("SECTION 5 — edge TLS / PKI inputs (choose exactly one mode)", host_text)
            # SECTION 5 now carries the real edge-TLS contract: a required mode
            # plus the two customer file-path trios (customer-supplied leaf and
            # customer-intermediate CA), all shipped empty and fail-closed.
            for edge_tls_key in (
                'aigw_edge_tls_mode: ""',
                'aigw_edge_tls_intermediate_cert_file: ""',
                'aigw_edge_tls_intermediate_key_file: ""',
                'aigw_edge_tls_intermediate_chain_file: ""',
            ):
                self.assertIn(edge_tls_key, host_text)
            # SECTION 3 documents the real controller-custody machinery: the
            # dedicated inline-encrypted sibling overlay written by the
            # stdin-only helper — never a randomly generated value.
            self.assertIn("vault_unseal_key is the SOLE operator-supplied secret", host_text)
            self.assertIn("NEVER randomly", host_text)
            self.assertIn("store-vault-unseal-key.py", host_text)
            self.assertIn("group_vars/production_rocky9/vault-unseal.yml", host_text)
            self.assertIn("never to group_vars/all.yml", host_text)
            self.assertIn("production-rocky9.first-init.sh.example", host_text)
            # SECTION 4 carries the real, fail-closed external AD/LDAPS contract:
            # shipped disabled, every conditional input present and empty, and
            # the bind credential delegated to the stdin-only helper + overlay.
            self.assertIn("identity_ldap_enabled: false", host_text)
            for key in self.contract["conditional_feature_keys"]["identity_ldap"][
                "required_nonsecret_keys"
            ]:
                self.assertIn(f"{key}:", host_text)
            self.assertIn("store-identity-ldap-bind-password.py", host_text)
            self.assertIn("group_vars/production_rocky9/identity-ldap.yml", host_text)
            self.assertNotIn("identity_ldap_bind_password:", host_text)

            # No stack secret value or name appears in host_vars.
            for entry in self.contract["required_secret_keys"]:
                self.assertNotIn(entry["name"], host_text)

            vault_text = vault.read_text(encoding="utf-8")
            self.assertIn("$ANSIBLE_VAULT;", vault_text)
            for entry in self.contract["required_secret_keys"]:
                self.assertIn(f"{entry['name']}: !vault |", vault_text)

            # The emitted host_vars is valid, loadable YAML (drop the ciphertext
            # overlay so no decryption is attempted).
            ansible_inventory = shutil.which("ansible-inventory")
            if ansible_inventory is not None:
                shutil.rmtree(layout / "group_vars")
                dump = subprocess.run(
                    [ansible_inventory, "-i", str(layout / "hosts.yml"), "--host", "customer-prod01"],
                    cwd=ROOT,
                    env={"PATH": os.environ["PATH"], "ANSIBLE_NOCOLOR": "1"},
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
                self.assertEqual(dump.returncode, 0, dump.stderr)
                self.assertEqual(
                    json.loads(dump.stdout)["deployment_profile"], "rocky9-production"
                )

    def test_section_3_is_comment_only_and_section_5_owns_the_edge_tls_keys(self) -> None:
        """SECTION 3 stays comment-only; SECTION 4 owns identity_ldap_*; SECTION 5
        now owns the edge-TLS contract.

        Workstream C (external AD/LDAPS) owns SECTION 4's conditional
        identity_ldap_* keys — shipped disabled. Workstream D (production TLS/PKI)
        has landed and owns SECTION 5's edge-TLS keys: a required mode plus the
        two customer file-path trios (customer-supplied leaf, customer-intermediate
        CA), all shipped empty and fail-closed. SECTION 3's vault_unseal_key stays
        an operator-ceremony value (store-vault-unseal-key.py) and never an active
        key here; the directory bind credential likewise never appears in any
        section: it belongs to a dedicated inline-encrypted overlay from stdin.
        """
        module = _load_bootstrap_module()
        host_text = module.production_host_vars_document("customer-prod01")
        lines = host_text.splitlines()

        def _marker(needle: str) -> int:
            return next(index for index, line in enumerate(lines) if needle in line)

        def _active(start: int, end: int | None = None) -> list[str]:
            return [
                line.strip()
                for line in lines[start : end if end is not None else len(lines)]
                if line.strip() and not line.lstrip().startswith("#")
            ]

        section_3 = _marker("SECTION 3 —")
        section_4 = _marker("SECTION 4 —")
        section_5 = _marker("SECTION 5 —")
        self.assertLess(section_3, section_4)
        self.assertLess(section_4, section_5)

        # SECTION 3 (vault_unseal_key ceremony) is still documentation only.
        self.assertEqual(_active(section_3, section_4), [])

        # SECTION 4 carries exactly the contract's conditional feature keys plus
        # its off-by-default flag, in the contract's own order.
        expected = ["identity_ldap_enabled: false"] + [
            key
            for key in self.contract["conditional_feature_keys"]["identity_ldap"][
                "required_nonsecret_keys"
            ]
        ]
        emitted = _active(section_4, section_5)
        self.assertEqual(emitted[0], expected[0])
        self.assertEqual([line.split(":", 1)[0] for line in emitted[1:]], expected[1:])

        # SECTION 5 carries exactly the edge-TLS keys: the required mode, the two
        # customer file-path trios, and the min-days window. Nothing else.
        self.assertEqual(
            [line.split(":", 1)[0] for line in _active(section_5)],
            [
                "aigw_edge_tls_mode",
                "aigw_edge_tls_leaf_cert_file",
                "aigw_edge_tls_private_key_file",
                "aigw_edge_tls_chain_file",
                "aigw_edge_tls_intermediate_cert_file",
                "aigw_edge_tls_intermediate_key_file",
                "aigw_edge_tls_intermediate_chain_file",
                "aigw_edge_tls_min_days_remaining",
            ],
        )

        for line in host_text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            self.assertFalse(stripped.startswith("pki_"), stripped)
            self.assertFalse(stripped.startswith("vault_unseal_key"), stripped)
            self.assertFalse(
                stripped.startswith("identity_ldap_bind_password"), stripped
            )
            # The intermediate PRIVATE KEY is a file-path input, never a secret.
            self.assertFalse(
                stripped.startswith("aigw_edge_tls_intermediate_key:"), stripped
            )

    def test_legacy_bootstrap_still_works_and_prints_deprecation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            password_file = _write_password_file(root)
            fake_vault = _write_fake_vault(root)
            layout = root / "legacy-inventory"
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(LEGACY_BOOTSTRAP),
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
            # The one-line notice goes to stderr only; stdout stays
            # byte-compatible with the pre-terminology tool.
            self.assertIn("DEPRECATION", result.stderr)
            self.assertIn("bootstrap-rocky9-production.py", result.stderr)
            self.assertNotIn("DEPRECATION", result.stdout)
            self.assertIn("Created production Rocky 9 inventory", result.stdout)
            self.assertIn("ansible/preflight-generic-rocky9.yml", result.stdout)
            self.assertIn("group_vars/generic_rocky9/vault-unseal.yml", result.stdout)
            # The legacy layout is unchanged: generic_rocky9 group + profile.
            self.assertTrue((layout / "group_vars" / "generic_rocky9" / "vault.yml").is_file())
            host_text = (layout / "host_vars" / "customer-aigw01.yml").read_text(encoding="utf-8")
            self.assertIn("deployment_profile: generic-rocky9", host_text)

    # ── committed inventory ─────────────────────────────────────────────
    def test_committed_inventory_uses_canonical_child_group(self) -> None:
        self.assertIn("deployment_profile: rocky9-production", PROD_GROUP_VARS.read_text(encoding="utf-8"))
        # The generic parent group_vars keep the deprecated profile name.
        self.assertIn("deployment_profile: generic-rocky9", GENERIC_GROUP_VARS.read_text(encoding="utf-8"))
        # The committed examples document the same canonical hierarchy.
        hosts_example = HOSTS_EXAMPLE.read_text(encoding="utf-8")
        self.assertIn("generic_rocky9:", hosts_example)
        self.assertIn("production_rocky9:", hosts_example)
        self.assertIn("bootstrap-rocky9-production.py", hosts_example)

        ansible_inventory = shutil.which("ansible-inventory")
        self.assertIsNotNone(ansible_inventory, "ansible-inventory is required")
        environment = os.environ.copy()
        environment.update(
            {
                "AIGW_ANSIBLE_HOST": "192.0.2.10",
                "AIGW_ANSIBLE_USER": "ansible",
                "ANSIBLE_NOCOLOR": "1",
            }
        )
        graph = subprocess.run(
            [str(ansible_inventory), "-i", str(COMMITTED_INVENTORY), "--graph"],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(graph.returncode, 0, graph.stderr)
        # production_rocky9 is nested under generic_rocky9 (a child appears
        # after its parent in the graph, and gateway keeps no children).
        self.assertIn("@generic_rocky9:", graph.stdout)
        self.assertIn("@production_rocky9:", graph.stdout)
        self.assertLess(
            graph.stdout.index("@generic_rocky9:"),
            graph.stdout.index("@production_rocky9:"),
        )

        dump = subprocess.run(
            [str(ansible_inventory), "-i", str(COMMITTED_INVENTORY), "--host", "aigw"],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(dump.returncode, 0, dump.stderr)
        # A production host never loads an unrelated encrypted group overlay:
        # no Vault password was supplied, so any decryption attempt would fail.
        self.assertNotIn("Attempting to decrypt", dump.stderr)
        resolved = json.loads(dump.stdout)
        self.assertEqual(resolved["deployment_profile"], "rocky9-production")
        self.assertTrue(resolved["require_encrypted_state"])

    # ── preflight ───────────────────────────────────────────────────────
    def test_both_preflight_entry_points_syntax_check(self) -> None:
        ansible_playbook = shutil.which("ansible-playbook")
        self.assertIsNotNone(ansible_playbook, "ansible-playbook is required")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "hosts.yml").write_text(_production_hosts_yaml(), encoding="utf-8")
            for playbook in (LEGACY_PREFLIGHT, PROD_PREFLIGHT):
                result = subprocess.run(
                    [str(ansible_playbook), "-i", str(root / "hosts.yml"), str(playbook), "--syntax-check"],
                    cwd=ROOT,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, f"{playbook.name}: {result.stderr}")

    def test_production_preflight_accepts_canonical_and_rejects_unknown_profile(self) -> None:
        ansible_playbook = shutil.which("ansible-playbook")
        self.assertIsNotNone(ansible_playbook, "ansible-playbook is required")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "host_vars").mkdir()
            (root / "hosts.yml").write_text(_production_hosts_yaml(), encoding="utf-8")
            host_vars = root / "host_vars" / "prod-aigw01.yml"

            def run(profile: str) -> subprocess.CompletedProcess[str]:
                host_vars.write_text(_full_valid_host_vars(self.contract, profile), encoding="utf-8")
                return subprocess.run(
                    [str(ansible_playbook), "-i", str(root / "hosts.yml"), str(PROD_PREFLIGHT)],
                    cwd=ROOT,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )

            ok = run("rocky9-production")
            combined = ok.stdout + ok.stderr
            self.assertEqual(ok.returncode, 0, combined)
            # The success receipt is emitted through ansible's debug callback,
            # which renders the embedded JSON with escaped quotes; normalize
            # backslashes before matching.
            normalized = combined.replace("\\", "")
            self.assertIn('"status": "ok"', normalized)
            self.assertIn('"profile": "rocky9-production"', normalized)
            # The canonical profile is not deprecated.
            self.assertNotIn("DEPRECATION", combined)

            rejected = run("not-a-real-profile")
            self.assertNotEqual(rejected.returncode, 0)

    def test_production_preflight_reports_wrong_webui_key_prefix(self) -> None:
        ansible_playbook = shutil.which("ansible-playbook")
        self.assertIsNotNone(ansible_playbook, "ansible-playbook is required")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "host_vars").mkdir()
            (root / "hosts.yml").write_text(_production_hosts_yaml(), encoding="utf-8")
            host_vars = root / "host_vars" / "prod-aigw01.yml"
            valid = _full_valid_host_vars(self.contract, "rocky9-production")

            host_vars.write_text(valid, encoding="utf-8")
            accepted = subprocess.run(
                [str(ansible_playbook), "-i", str(root / "hosts.yml"), str(PROD_PREFLIGHT)],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)

            host_vars.write_text(
                valid.replace("webui_litellm_key: sk-", "webui_litellm_key: bad-", 1),
                encoding="utf-8",
            )
            rejected = subprocess.run(
                [str(ansible_playbook), "-i", str(root / "hosts.yml"), str(PROD_PREFLIGHT)],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            combined = (rejected.stdout + rejected.stderr).replace("\\", "")
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn('"invalid_secret": ["webui_litellm_key"]', combined)

    def test_production_preflight_fails_before_mutation_on_missing_values(self) -> None:
        ansible_playbook = shutil.which("ansible-playbook")
        self.assertIsNotNone(ansible_playbook, "ansible-playbook is required")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "host_vars").mkdir()
            (root / "hosts.yml").write_text(_production_hosts_yaml(), encoding="utf-8")
            (root / "host_vars" / "prod-aigw01.yml").write_text(
                _minimal_host_vars("rocky9-production"), encoding="utf-8"
            )
            result = subprocess.run(
                [str(ansible_playbook), "-i", str(root / "hosts.yml"), str(PROD_PREFLIGHT)],
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
            self.assertIn('"profile": "rocky9-production"', combined)
            self.assertNotIn("DEPRECATION", combined)
            self.assertNotIn("test-only-password", combined)

    def test_legacy_profile_triggers_preflight_deprecation_notice(self) -> None:
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
                _minimal_host_vars("generic-rocky9", alias="customer-aigw01"), encoding="utf-8"
            )
            result = subprocess.run(
                [str(ansible_playbook), "-i", str(root / "hosts.yml"), str(LEGACY_PREFLIGHT)],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            combined = result.stdout + result.stderr
            self.assertIn("DEPRECATION", combined)
            self.assertIn("rocky9-production", combined)
            self.assertIn("AIGW_GENERIC_PREFLIGHT=", combined)


def _production_hosts_yaml() -> str:
    return """---
all:
  children:
    generic_rocky9:
      children:
        production_rocky9:
          hosts:
            prod-aigw01:
"""


def _minimal_host_vars(profile: str, alias: str = "prod-aigw01") -> str:
    return f"""---
aigw_generic_inventory_alias: {alias}
deployment_profile: {profile}
require_encrypted_state: true
aigw_seed_test_users: false
platform_authoritative_dns_enabled: false
aigw_vault_ui_enabled: false
"""


def _full_valid_host_vars(contract: dict, profile: str) -> str:
    filler = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" * 3
    lines = [
        "---",
        "aigw_generic_inventory_alias: prod-aigw01",
        f"deployment_profile: {profile}",
        'ansible_host: "192.0.2.10"',
        "ansible_user: ansible",
        "aigw_domain: aigw.example.internal",
        'nic_egress: "eth0"',
        'nic_adm: "eth1"',
        'nic_internal: "eth2"',
        'eth0_ip: "192.0.2.10"',
        'eth0_gateway: "192.0.2.1"',
        'eth1_ip: "198.51.100.10"',
        'eth1_gateway: "198.51.100.1"',
        'eth2_ip: "203.0.113.10"',
        'eth2_gateway: "203.0.113.1"',
        'vpn_client_cidr: "198.51.100.0/24"',
        'internal_cidr: "203.0.113.0/24"',
        'internal_dns_servers: ["203.0.113.53"]',
        'egress_dns_servers: ["192.0.2.53"]',
        "aigw_management_ssh_port: 22",
        "manage_networking: true",
        "pbr_tables: [{name: adm, id: 101}, {name: internal, id: 102}]",
        "require_encrypted_state: true",
        "require_preupgrade_backup: true",
        "platform_authoritative_dns_enabled: false",
        "aigw_vault_ui_enabled: false",
        "aigw_seed_test_users: false",
        # Edge TLS mode is a required production input. 'vault-intermediate'
        # is the mode that needs no operator-supplied file paths, so it keeps
        # this fixture to the contract's own required-key set.
        "aigw_edge_tls_mode: vault-intermediate",
    ]
    for index, entry in enumerate(contract["required_secret_keys"]):
        length = entry.get("exact_length") or entry["min_length"]
        if entry.get("prefix"):
            # Match the consumer token's shape: sk- plus 64 safe random
            # characters. The fixture contains no real secret.
            value = entry["prefix"] + (f"K{index:03d}" + filler)[: max(length, 64)]
        else:
            value = (f"K{index:03d}" + filler)[:length]
        lines.append(f"{entry['name']}: {value}")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    unittest.main()
