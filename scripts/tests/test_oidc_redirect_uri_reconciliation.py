"""Contracts for domain-derived OIDC callback reconciliation.

Keycloak imports realm JSON only into an empty database. Every later Ansible
converge must therefore repair the managed callback allow-lists through the
same locked deployment route that owns bootstrap and LDAPS verification.
"""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
TASKS = ROOT / "ansible" / "roles" / "docker_stack" / "tasks" / "main.yml"
IDENTITY = ROOT / "services" / "key-rotator" / "app" / "identity.py"

AUTO_TASK = "- name: Automatically configure Keycloak identity control from LDAPS"


class OidcRedirectUriReconciliationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tasks = TASKS.read_text(encoding="utf-8")
        cls.identity = IDENTITY.read_text(encoding="utf-8")
        start = cls.tasks.index(AUTO_TASK)
        end = cls.tasks.index(
            "- name: Wait for the complete post-bootstrap stack", start
        )
        cls.deployment = cls.tasks[start:end]

    def test_converge_uses_only_the_locked_identity_deployment_runner(self) -> None:
        for required in (
            AUTO_TASK,
            "- app.auto_bootstrap_identity",
            "- --confirm",
            "- AUTO_BOOTSTRAP_IDENTITY",
            "- key-rotator",
            "- exec",
            "- -T",
            "IDENTITY_AUTO_BOOTSTRAP_APPLIED",
            "IDENTITY_AUTO_BOOTSTRAP_VERIFIED",
        ):
            self.assertIn(required, self.deployment)
        self.assertNotIn("app.reconcile_oidc_redirect_uris", self.tasks)
        self.assertNotIn("managed_oidc_redirect_reconciliation", self.tasks)
        self.assertNotIn("KC_BOOTSTRAP_ADMIN_CLIENT_SECRET", self.deployment)
        self.assertIn("no_log: true", self.deployment)

    def test_deployment_route_is_ordered_after_the_bounded_public_vault_probe(
        self,
    ) -> None:
        self.assertLess(
            self.tasks.index("register: vault_public_status"),
            self.tasks.index(AUTO_TASK),
        )

    def test_deployment_route_requires_initialized_unsealed_vault(self) -> None:
        for required in (
            "vault_strict_readiness.rc == 0",
            "(vault_public_status.stdout | from_json).initialized | bool",
            "not ((vault_public_status.stdout | from_json).sealed | bool)",
            "identity_ldap_enabled | bool",
        ):
            self.assertIn(required, self.deployment)

    def test_locked_deployment_path_reads_back_managed_callback_fields(self) -> None:
        method = self.identity[
            self.identity.index(
                "async def _reconcile_relying_party_redirect_uris"
            ) : self.identity.index(
                "async def reconcile_prebootstrap_relying_party_redirect_uris"
            )
        ]
        for managed in ("redirectUris", "webOrigins", "post.logout.redirect.uris"):
            self.assertIn(managed, method)
        for proof in (
            "verified = await self._get_client",
            "Keycloak did not verify OIDC client",
        ):
            self.assertIn(proof, method)

    def test_deployment_uses_escrowed_admin_without_widening_controller(self) -> None:
        converge = self.identity[
            self.identity.index("async def converge_deployment_identity(") :
            self.identity.index("def _identity_state(")
        ]
        self.assertIn("await self._break_glass_admin_token()", converge)
        self.assertIn(
            "relying_party_changed = await self._ensure_relying_parties(",
            converge,
        )
        self.assertIn("admin_token, before_change=mark_live_change", converge)
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
