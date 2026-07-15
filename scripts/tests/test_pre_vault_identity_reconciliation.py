"""Fail-closed contracts for the sealed-Vault Keycloak recovery bridge."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
ALL_VARS = ROOT / "ansible/group_vars/all.yml"
LAB_VARS = ROOT / "ansible/inventory/host_vars/lab-aigw01.yml"
GENERIC_VARS = ROOT / "ansible/inventory/group_vars/generic_rocky9.yml"
TASKS = ROOT / "ansible/roles/docker_stack/tasks/main.yml"
IDENTITY = ROOT / "services/key-rotator/app/identity.py"
RUNNER = ROOT / "services/key-rotator/app/reconcile_pre_vault_identity.py"


class PreVaultIdentityReconciliationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.all_vars = ALL_VARS.read_text(encoding="utf-8")
        cls.lab_vars = LAB_VARS.read_text(encoding="utf-8")
        cls.generic_vars = GENERIC_VARS.read_text(encoding="utf-8")
        cls.tasks = TASKS.read_text(encoding="utf-8")
        cls.identity = IDENTITY.read_text(encoding="utf-8")
        cls.runner = RUNNER.read_text(encoding="utf-8")
        start = cls.tasks.index(
            "# A sealed/fresh Vault must not make its own UI administratively unreachable."
        )
        end = cls.tasks.index(
            "# Do not make the legacy OIDC repair part of the fresh-Vault bootstrap path:",
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

    def test_generic_profiles_have_no_lab_or_identity_defaults(self) -> None:
        for required in (
            "aigw_pre_vault_identity_baseline_reconciliation: false",
            'aigw_pre_vault_identity_baseline_reconciliation_ack: ""',
            "aigw_pre_vault_identity_ensure_lab_federation: false",
            "aigw_pre_vault_identity_baseline_groups: []",
            "aigw_pre_vault_identity_bootstrap_admin_identities: []",
        ):
            self.assertIn(required, self.all_vars)
        recovery_defaults = self.all_vars.split(
            "aigw_pre_vault_identity_baseline_reconciliation: false", 1
        )[1].split("samba_lab_seed_users:", 1)[0]
        self.assertNotIn("lab-admin", recovery_defaults)
        self.assertNotIn("lab-samba-ad", recovery_defaults)
        self.assertNotIn("lab-admin", self.generic_vars)
        self.assertNotIn("lab-samba-ad", self.generic_vars)

    def test_lab_declares_the_only_bootstrap_identity_and_exact_admin_group(self) -> None:
        for required in (
            "aigw_pre_vault_identity_baseline_reconciliation: true",
            "aigw_pre_vault_identity_baseline_reconciliation_ack: "
            "RECONCILE_PRE_VAULT_MANAGED_IDENTITY_BASELINE",
            "- { name: lab-admins, roles: [aigw-admins, aigw-chat] }",
            "- { name: lab-developers, roles: [aigw-chat, aigw-developers] }",
            "- { name: lab-users, roles: [aigw-chat, aigw-users] }",
            "- username: lab-admin",
            "group: lab-admins",
            "federation_provider: lab-samba-ad",
        ):
            self.assertIn(required, self.lab_vars)
        baseline = self.lab_vars.split(
            "aigw_pre_vault_identity_bootstrap_admin_identities:", 1
        )[1].split("nic_egress:", 1)[0]
        self.assertEqual(baseline.count("- username:"), 1)

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

    def test_validator_admits_the_pinned_lab_admin_group_capability_set(self) -> None:
        """The runner-side validator must accept the inventory pinned above.

        The lab bootstrap-admin group carries [aigw-admins, aigw-chat] since
        the dedicated chat capability landed (b5bcb96). The validator's rule is
        therefore: aigw-admins mandatory, only the dedicated chat capability
        may accompany it. The previous exact-set pin {aigw-admins} rejected the
        shipped inventory during pure spec validation, so every fresh lab
        converge failed before its first Keycloak request.
        """
        validator_start = self.identity.index(
            "    def _validate_pre_vault_identity_spec("
        )
        validator_end = self.identity.index(
            "    async def _pre_vault_direct_child(", validator_start
        )
        validator = self.identity[validator_start:validator_end]
        self.assertIn('"aigw-admins" not in group_roles[group]', validator)
        self.assertIn('{"aigw-admins", CHAT_CAPABILITY_ROLE}', validator)
        # The pre-aigw-chat exact-set pin must not silently return: it is
        # value-incompatible with the lab inventory lines asserted above.
        self.assertNotIn(
            'group_roles[group] != frozenset({"aigw-admins"})', validator
        )

    def test_mutator_never_reads_vault_or_deletes_keycloak_state(self) -> None:
        for required in (
            "_validate_pre_vault_identity_spec(spec)",
            "preserve_unmanaged=True",
            "_root_group(admin_token, create=True)",
            "_ensure_ldap_federation(admin_token, self._ldap_bind_password())",
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
