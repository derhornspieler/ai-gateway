"""Fail-closed contracts for the optional pre-Vault Keycloak recovery bridge."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
ALL_VARS = ROOT / "ansible/group_vars/all.yml"
GENERIC_VARS = ROOT / "ansible/inventory/group_vars/generic_rocky9.yml"
TASKS = ROOT / "ansible/roles/docker_stack/tasks/main.yml"
IDENTITY = ROOT / "services/key-rotator/app/identity.py"
RUNNER = ROOT / "services/key-rotator/app/reconcile_pre_vault_identity.py"


class PreVaultIdentityReconciliationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.all_vars = ALL_VARS.read_text(encoding="utf-8")
        cls.generic_vars = GENERIC_VARS.read_text(encoding="utf-8")
        cls.tasks = TASKS.read_text(encoding="utf-8")
        cls.identity = IDENTITY.read_text(encoding="utf-8")
        cls.runner = RUNNER.read_text(encoding="utf-8")
        start = cls.tasks.index(
            "# A sealed/fresh Vault must not make its own UI administratively unreachable."
        )
        end = cls.tasks.index(
            "# Once the LDAPS bind credential is mounted, deployment owns identity setup.",
            start,
        )
        cls.migration = cls.tasks[start:end]
        method_start = cls.identity.index(
            "    async def reconcile_pre_vault_identity_baseline("
        )
        method_end = cls.identity.index(
            "    def _relying_party_specs(", method_start
        )
        cls.method = cls.identity[method_start:method_end]

    def test_generic_profiles_have_no_identity_mutation_defaults(self) -> None:
        for required in (
            "aigw_pre_vault_identity_baseline_reconciliation: false",
            'aigw_pre_vault_identity_baseline_reconciliation_ack: ""',
            "aigw_pre_vault_identity_baseline_groups: []",
            "aigw_pre_vault_identity_bootstrap_admin_identities: []",
        ):
            self.assertIn(required, self.all_vars)
        self.assertNotIn("preprod-admin", self.generic_vars)
        self.assertNotIn("preprod-samba-ad", self.generic_vars)

    def test_ansible_uses_stdin_fixed_confirmation_and_a_private_receipt(self) -> None:
        for required in (
            "services: [keycloak]",
            "dependencies: false",
            "wait: true",
            "wait_timeout: 600",
            "- app.reconcile_pre_vault_identity",
            "- --confirm",
            "- RECONCILE_PRE_VAULT_MANAGED_IDENTITY_BASELINE",
            'stdin: "{{ aigw_pre_vault_identity_baseline_spec | to_json }}"',
            "stdin_add_newline: false",
            "pre-vault-identity-baseline.json",
            'mode: "0600"',
            "PRE_VAULT_IDENTITY_BASELINE_RECONCILIATION_APPLIED",
            "PRE_VAULT_IDENTITY_BASELINE_RECONCILIATION_VERIFIED",
        ):
            self.assertIn(required, self.migration)
        self.assertEqual(
            self.migration.count("- app.reconcile_pre_vault_identity"), 2
        )
        self.assertGreaterEqual(self.migration.count("no_log: true"), 7)
        self.assertNotIn("KC_BOOTSTRAP_ADMIN_CLIENT_SECRET", self.migration)
        self.assertNotIn("VAULT_TOKEN", self.migration)
        self.assertNotIn("vault_strict_readiness", self.migration)

    def test_runner_is_bounded_redacted_and_does_not_construct_vault(self) -> None:
        for required in (
            "MAX_SPEC_BYTES = 64 * 1024",
            "sys.stdin.buffer.read(MAX_SPEC_BYTES + 1)",
            "KeycloakAdmin(settings, None, None)",
            "PRE_VAULT_IDENTITY_BASELINE_RECONCILIATION_APPLIED",
            "PRE_VAULT_IDENTITY_BASELINE_RECONCILIATION_VERIFIED",
            "PRE_VAULT_IDENTITY_BASELINE_RECONCILIATION_FAILED",
            "except Exception",
        ):
            self.assertIn(required, self.runner)
        self.assertNotIn("VaultClient", self.runner)
        self.assertNotIn("traceback", self.runner.lower())

    def test_validator_admits_an_admin_group_with_the_chat_capability(self) -> None:
        validator_start = self.identity.index(
            "    def _validate_pre_vault_identity_spec("
        )
        validator_end = self.identity.index(
            "    async def _pre_vault_direct_child(", validator_start
        )
        validator = self.identity[validator_start:validator_end]
        self.assertIn('"aigw-admins" not in group_roles[group]', validator)
        self.assertIn('{"aigw-admins", CHAT_CAPABILITY_ROLE}', validator)
        self.assertNotIn(
            'group_roles[group] != frozenset({"aigw-admins"})', validator
        )

    def test_mutator_never_reads_vault_or_deletes_keycloak_state(self) -> None:
        for required in (
            "_validate_pre_vault_identity_spec(spec)",
            "preserve_unmanaged=True",
            "_root_group(admin_token, create=True)",
            "_pre_vault_group_members(",
            "pre-Vault managed baseline group has undeclared members",
            "exact pre-Vault baseline membership",
            '"PUT",',
            "/groups/{group_id}",
        ):
            self.assertIn(required, self.method)
        self.assertNotIn("self.vault", self.method)
        self.assertNotIn('"DELETE"', self.method)
        self.assertNotIn("_delete_bootstrap_principals", self.method)
        self.assertNotIn("_ensure_controller", self.method)


if __name__ == "__main__":
    unittest.main()
