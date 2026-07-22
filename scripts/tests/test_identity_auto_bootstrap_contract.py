from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
TASKS = ROOT / "ansible/roles/docker_stack/tasks/main.yml"
RUNNER = ROOT / "services/key-rotator/app/auto_bootstrap_identity.py"
MAIN = ROOT / "services/key-rotator/app/main.py"
IDENTITY = ROOT / "services/key-rotator/app/identity.py"
PORTAL = ROOT / "services/dev-portal/app/main.py"
ADMIN_TEMPLATE = ROOT / "services/dev-portal/app/templates/admin.html"
REALM = ROOT / "ansible/roles/docker_stack/templates/keycloak-realms/aigw-realm.json.j2"


class IdentityAutoBootstrapContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tasks = TASKS.read_text(encoding="utf-8")
        cls.runner = RUNNER.read_text(encoding="utf-8")
        cls.main = MAIN.read_text(encoding="utf-8")
        cls.identity = IDENTITY.read_text(encoding="utf-8")
        cls.portal = PORTAL.read_text(encoding="utf-8")
        cls.admin_template = ADMIN_TEMPLATE.read_text(encoding="utf-8")
        cls.realm = REALM.read_text(encoding="utf-8")

    def test_ansible_runs_the_idempotent_identity_command_after_vault_is_ready(self) -> None:
        start = self.tasks.index(
            "- name: Automatically configure Keycloak identity control from LDAPS"
        )
        end = self.tasks.index("- name: Wait for the complete post-bootstrap stack", start)
        block = self.tasks[start:end]
        for text in (
            "- app.auto_bootstrap_identity",
            "- AUTO_BOOTSTRAP_IDENTITY",
            "IDENTITY_AUTO_BOOTSTRAP_APPLIED",
            "IDENTITY_AUTO_BOOTSTRAP_VERIFIED",
            "identity_ldap_enabled | bool",
            "vault_strict_readiness.rc == 0",
            "not ((vault_public_status.stdout | from_json).sealed | bool)",
            "no_log: true",
        ):
            self.assertIn(text, block)
        self.assertNotIn("IDENTITY_AUTO_BOOTSTRAP_SKIPPED_NO_LDAP' in", block)

    def test_runner_is_a_bounded_redacted_loopback_client(self) -> None:
        for text in (
            'CONFIRMATION = "AUTO_BOOTSTRAP_IDENTITY"',
            'APPLIED_MARKER = "IDENTITY_AUTO_BOOTSTRAP_APPLIED"',
            'VERIFIED_MARKER = "IDENTITY_AUTO_BOOTSTRAP_VERIFIED"',
            'FAILED_MARKER = "IDENTITY_AUTO_BOOTSTRAP_FAILED"',
            'DEPLOYMENT_URL = "http://127.0.0.1:8080/identity/deployment"',
            'os.environ.get("ROTATOR_INTERNAL_TOKEN", "")',
            "urllib.request.ProxyHandler({})",
            "NoRedirects()",
            "MAX_RESPONSE_BYTES = 16 * 1024",
            "response.read(MAX_RESPONSE_BYTES + 1)",
            "except Exception",
        ):
            self.assertIn(text, self.runner)
        for forbidden in (
            "from app.config import Settings",
            "VaultClient",
            "Database",
            "KeycloakAdmin",
            "import traceback",
        ):
            self.assertNotIn(forbidden, self.runner)

    def test_internal_route_uses_one_shared_lock_and_live_proofs(self) -> None:
        route = self.main[
            self.main.index('@app.post("/identity/deployment")') :
            self.main.index('@app.get("/identity/groups")')
        ]
        for text in (
            'hmac.compare_digest(body.confirmation, "AUTO_BOOTSTRAP_IDENTITY")',
            "await identity.converge_deployment_identity()",
            'detail="identity deployment failed"',
        ):
            self.assertIn(text, route)

        bootstrap = self.identity[
            self.identity.index("async def bootstrap(") :
            self.identity.index("async def status(")
        ]
        converge = self.identity[
            self.identity.index("async def converge_deployment_identity(") :
            self.identity.index("def _identity_state(")
        ]
        self.assertIn("async with self._bootstrap_lock", bootstrap)
        for text in (
            "async with self._bootstrap_lock",
            "await self._ensure_ldap_federation(",
            "await self._ensure_relying_parties(",
            "await self._reconcile_deployment_bootstrap_cleanup(",
            "self._escrow_vault_oidc_rp_secret()",
            "if not self._deployment_status_verified(after)",
        ):
            self.assertIn(text, converge)
        ensure_ldap = self.identity[
            self.identity.index("async def _ensure_ldap_federation(") :
            self.identity.index("def _managed_ldap_config(")
        ]
        self.assertGreaterEqual(
            ensure_ldap.count("await self._prove_ldap_directory("), 2
        )

    def test_admin_portal_has_no_manual_initialization_action(self) -> None:
        self.assertNotIn('@admin_app.post("/admin/identity/bootstrap")', self.portal)
        self.assertNotIn('action="/admin/identity/bootstrap"', self.admin_template)
        self.assertNotIn(">setup required<", self.admin_template)
        self.assertIn("there is no browser initialization step", self.admin_template)
        self.assertIn("deployment incomplete", self.admin_template)
        self.assertIn("automatic deployment incomplete", self.admin_template)

    def test_realm_callbacks_are_rendered_from_the_ansible_domain(self) -> None:
        for callback in (
            "chat.{{ aigw_domain }}/oauth/oidc/callback",
            "portal.{{ aigw_domain }}/auth/callback",
            "admin.{{ aigw_domain }}/auth/callback",
            "litellm-admin.{{ aigw_domain }}/oauth2/callback",
            "grafana.{{ aigw_domain }}/oauth2/callback",
            "prometheus.{{ aigw_domain }}/oauth2/callback",
            "vault.{{ aigw_domain }}/oauth2/callback",
            "vault.{{ aigw_domain }}/ui/vault/auth/oidc/oidc/callback",
        ):
            self.assertIn(callback, self.realm)
        self.assertNotIn("aigw.example.internal", self.realm)


if __name__ == "__main__":
    unittest.main()
