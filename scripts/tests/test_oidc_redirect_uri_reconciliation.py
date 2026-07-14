"""Contracts for the automatic managed-OIDC redirect-URI domain reconciliation.

A domain migration on an already-seeded realm cannot be repaired by a realm
re-import (Keycloak imports realm JSON only into an empty database), so a
converge must realign the managed clients' callbacks to ``aigw_domain`` while
the temporary bootstrap client still exists, and fail closed toward the
re-bootstrap ceremony once it has been consumed. These pins keep that converge
path, its runner markers, and the preserved security model exact.
"""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
TASKS = ROOT / "ansible" / "roles" / "docker_stack" / "tasks" / "main.yml"
RUNNER = ROOT / "services" / "key-rotator" / "app" / "reconcile_oidc_redirect_uris.py"
IDENTITY = ROOT / "services" / "key-rotator" / "app" / "identity.py"

RECONCILE_TASK = (
    "- name: Reconcile managed OIDC client redirect URIs to the configured domain"
)


class OidcRedirectUriReconciliationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tasks = TASKS.read_text(encoding="utf-8")
        cls.runner = RUNNER.read_text(encoding="utf-8")
        cls.identity = IDENTITY.read_text(encoding="utf-8")
        start = cls.tasks.index("# A previous fresh realm import")
        end = cls.tasks.index(
            "- name: Wait for the complete post-bootstrap stack", start
        )
        cls.migration = cls.tasks[start:end]

    def test_converge_runs_the_reconciler_via_the_reviewed_bootstrap_service(
        self,
    ) -> None:
        for required in (
            RECONCILE_TASK,
            "- app.reconcile_oidc_redirect_uris",
            "- --confirm",
            "- RECONCILE_PREBOOTSTRAP_OIDC_REDIRECT_URIS",
            "- key-rotator",
            "- run",
            "- --rm",
            "- --no-deps",
            "- -T",
            "services: [keycloak]",
        ):
            self.assertIn(required, self.migration)
        # The runner is given neither Vault nor the bootstrap secret in its env.
        self.assertNotIn("VAULT_TOKEN", self.migration)
        self.assertNotIn("KC_BOOTSTRAP_ADMIN_CLIENT_SECRET", self.migration)
        self.assertNotIn("services: [keycloak, vault]", self.migration)
        # The privileged runner task suppresses its own log like its siblings.
        reconcile_block = self.migration[self.migration.index(RECONCILE_TASK) :]
        self.assertIn("no_log: true", reconcile_block.split("- name:", 2)[1])

    def test_reconciliation_is_ordered_after_the_bounded_public_vault_probe(
        self,
    ) -> None:
        self.assertLess(
            self.tasks.index("register: vault_public_status"),
            self.tasks.index(RECONCILE_TASK),
        )

    def test_reconciliation_is_gated_on_an_initialized_unsealed_vault(self) -> None:
        block = self.migration[self.migration.index(RECONCILE_TASK) :]
        block = block[: block.index("- name:", 1)]
        for required in (
            "vault_strict_readiness.rc == 0",
            "(vault_public_status.stdout | from_json).initialized | bool",
            "not ((vault_public_status.stdout | from_json).sealed | bool)",
            "failed_when: managed_oidc_redirect_reconciliation.rc != 0",
            "OIDC_REDIRECT_URI_PREBOOTSTRAP_RECONCILIATION_APPLIED",
        ):
            self.assertIn(required, block)

    def test_post_bootstrap_hosts_get_a_clear_report_not_a_failed_converge(
        self,
    ) -> None:
        # rc==0 fail-closed marker: the converge must not hard-fail on it.
        self.assertIn(
            "OIDC_REDIRECT_URI_PREBOOTSTRAP_RECONCILIATION_REBOOTSTRAP_REQUIRED",
            self.migration,
        )
        self.assertIn(
            "- name: Report when an OIDC domain migration needs the "
            "identity bootstrap ceremony",
            self.migration,
        )
        self.assertIn("re-runs the identity bootstrap ceremony", self.migration)

    def test_runner_uses_fixed_redacted_markers_and_no_traceback(self) -> None:
        for required in (
            'CONFIRMATION = "RECONCILE_PREBOOTSTRAP_OIDC_REDIRECT_URIS"',
            "OIDC_REDIRECT_URI_PREBOOTSTRAP_RECONCILIATION_APPLIED",
            "OIDC_REDIRECT_URI_PREBOOTSTRAP_RECONCILIATION_VERIFIED",
            "OIDC_REDIRECT_URI_PREBOOTSTRAP_RECONCILIATION_REBOOTSTRAP_REQUIRED",
            "OIDC_REDIRECT_URI_PREBOOTSTRAP_RECONCILIATION_FAILED",
            "except Exception",
            "KeycloakAdmin(settings, None, None)",
        ):
            self.assertIn(required, self.runner)
        self.assertNotIn("import traceback", self.runner)
        self.assertNotIn("traceback.print_exc", self.runner)

    def test_narrow_method_touches_only_managed_callback_fields(self) -> None:
        method = self.identity[
            self.identity.index(
                "async def _reconcile_relying_party_redirect_uris"
            ) : self.identity.index(
                "async def reconcile_prebootstrap_relying_party_redirect_uris"
            )
        ]
        for managed in ("redirectUris", "webOrigins", "post.logout.redirect.uris"):
            self.assertIn(managed, method)
        # The narrow reconciler must not read/rewrite secrets or reconcile
        # scope mappings — those API surfaces belong to the full bootstrap only.
        for forbidden in (
            "/client-secret",
            "_reconcile_client_realm_role_scope_mappings(",
            "scope-mappings/realm",
            "generate-and-download",
        ):
            self.assertNotIn(forbidden, method)

    def test_post_bootstrap_controller_holds_no_manage_clients_role(self) -> None:
        block = self.identity[
            self.identity.index("CONTROLLER_ADMIN_ROLES = (") : self.identity.index(
                ")", self.identity.index("CONTROLLER_ADMIN_ROLES = (")
            )
        ]
        self.assertNotIn("manage-clients", block)
        self.assertNotIn("manage-realm", block)
        self.assertIn("manage-users", block)


if __name__ == "__main__":
    unittest.main()
