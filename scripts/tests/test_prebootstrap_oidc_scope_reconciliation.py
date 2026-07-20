"""Regression contracts for the narrowly scoped legacy OIDC repair path."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
ALL_VARS = ROOT / "ansible" / "group_vars" / "all.yml"
LAB_VARS = ROOT / "ansible" / "inventory" / "host_vars" / "lab-aigw01.yml"
TASKS = ROOT / "ansible" / "roles" / "docker_stack" / "tasks" / "main.yml"
RUNNER = ROOT / "services" / "key-rotator" / "app" / "reconcile_oidc_role_scopes.py"


class PrebootstrapOidcScopeReconciliationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.all_vars = ALL_VARS.read_text(encoding="utf-8")
        cls.lab_vars = LAB_VARS.read_text(encoding="utf-8")
        cls.tasks = TASKS.read_text(encoding="utf-8")
        cls.runner = RUNNER.read_text(encoding="utf-8")
        start = cls.tasks.index("# A previous fresh realm import")
        end = cls.tasks.index(
            "- name: Wait for the complete post-bootstrap stack", start
        )
        cls.migration = cls.tasks[start:end]

    def test_generic_profiles_are_off_and_lab_requires_a_literal_acknowledgement(self) -> None:
        self.assertIn("aigw_prebootstrap_oidc_scope_reconciliation: false", self.all_vars)
        self.assertIn("aigw_prebootstrap_oidc_scope_reconciliation: true", self.lab_vars)
        self.assertIn(
            "aigw_prebootstrap_oidc_scope_reconciliation_ack: "
            "RECONCILE_PREBOOTSTRAP_OIDC_ROLE_SCOPES",
            self.lab_vars,
        )
        self.assertIn(
            "aigw_prebootstrap_oidc_scope_reconciliation_ack == "
            "'RECONCILE_PREBOOTSTRAP_OIDC_ROLE_SCOPES'",
            self.migration,
        )

    def test_root_owned_runner_has_no_credential_argv_or_task_log(self) -> None:
        for required in (
            "services: [keycloak]",
            "dependencies: false",
            "wait: true",
            "wait_timeout: 600",
            "vault_strict_readiness.rc == 0",
            "vault_public_status.rc == 0",
            "(vault_public_status.stdout | from_json).initialized | bool",
            "not ((vault_public_status.stdout | from_json).sealed | bool)",
            "- exec",
            "- -T",
            "- key-rotator",
            "- /opt/venv/bin/python",
            "- -m",
            "- app.reconcile_oidc_role_scopes",
            "- --confirm",
            "- RECONCILE_PREBOOTSTRAP_OIDC_ROLE_SCOPES",
        ):
            self.assertIn(required, self.migration)
        self.assertNotIn("services: [keycloak, vault]", self.migration)
        self.assertGreaterEqual(self.migration.count("no_log: true"), 2)
        self.assertNotIn("KC_BOOTSTRAP_ADMIN_CLIENT_SECRET", self.migration)
        self.assertNotIn("VAULT_TOKEN", self.migration)

    def test_runner_is_ordered_after_the_bounded_public_vault_probe(self) -> None:
        self.assertIn(
            "failed_when: vault_public_status.rc not in [0, 2]", self.tasks
        )
        self.assertLess(
            self.tasks.index("register: vault_public_status"),
            self.tasks.index(
                "- name: Reconcile only applicable pre-bootstrap Keycloak OIDC role scopes"
            ),
        )

    def test_runner_uses_fixed_markers_and_the_exact_runtime_status_gate(self) -> None:
        for required in (
            'status.get("identity_state_absent") is True',
            'status.get("configured") is False',
            'status.get("controller_usable") is False',
            'status.get("bootstrap_available") is True',
            "OIDC_ROLE_SCOPE_PREBOOTSTRAP_RECONCILIATION_APPLIED",
            "OIDC_ROLE_SCOPE_PREBOOTSTRAP_RECONCILIATION_NOT_APPLICABLE",
            "OIDC_ROLE_SCOPE_PREBOOTSTRAP_RECONCILIATION_FAILED",
            "except Exception",
        ):
            self.assertIn(required, self.runner if required.startswith("OIDC") or required == "except Exception" else (ROOT / "services" / "key-rotator" / "app" / "identity.py").read_text(encoding="utf-8"))
        self.assertNotIn("traceback.print_exc", self.runner)


if __name__ == "__main__":
    unittest.main()
