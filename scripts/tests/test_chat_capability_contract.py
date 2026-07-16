"""Dedicated aigw-chat capability: cross-file contract pins.

Owner decision: Open WebUI chat access is gated by the DEDICATED `aigw-chat`
realm role, not by aigw-users/-developers/-admins membership. The capability
spans the Compose gate, the realm template and its static dev default, the
identity-policy parity validator, both services' assignable capability sets,
the Open WebUI build-time OAuth verification harness, and the lab baseline /
live-lab acceptance. These pins keep those surfaces in lockstep so no single
edit can silently re-widen chat access or brick it.
"""

from __future__ import annotations

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]

CAPABILITY_SCOPE = '"aigw-admins", "aigw-chat", "aigw-developers", "aigw-users"'


class ChatCapabilityContractTest(unittest.TestCase):
    def test_compose_gates_chat_on_the_dedicated_role_only(self) -> None:
        compose = (ROOT / "compose/docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn('OAUTH_ALLOWED_ROLES: "aigw-chat"', compose)
        self.assertIn('OAUTH_ADMIN_ROLES: "aigw-admins"', compose)
        # The pre-aigw-chat gate must not silently return.
        self.assertNotIn('OAUTH_ALLOWED_ROLES: "aigw-users', compose)

    def test_compose_bypasses_openwebui_internal_model_acl(self) -> None:
        """Model authorization is the gateway's job (scoped workload key +
        per-project runtime policy). Open WebUI 0.10's own model access
        control defaults connection-derived models to admin-only visibility,
        which locks every non-admin aigw-chat user out of chat — proven live
        2026-07-16 (role=user saw zero models). The bypass must stay pinned
        so an upgrade or edit cannot silently re-brick user chat."""
        compose = (ROOT / "compose/docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn('BYPASS_MODEL_ACCESS_CONTROL: "true"', compose)

    def test_compose_disables_the_ollama_backend_for_all_users(self) -> None:
        """The gateway's only model backend is LiteLLM over the OpenAI-
        compatible API. Open WebUI 0.10 defaults ENABLE_OLLAMA_API=true, which
        exposes the Ollama connection UI and /ollama/* surface to every user.
        Pin it off so no user can reach or configure an out-of-band backend."""
        compose = (ROOT / "compose/docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn('ENABLE_OLLAMA_API: "false"', compose)
        self.assertNotIn('ENABLE_OLLAMA_API: "true"', compose)

    def test_realm_sources_define_and_scope_the_chat_role(self) -> None:
        for path in (
            ROOT
            / "ansible/roles/docker_stack/templates/keycloak-realms/aigw-realm.json.j2",
            ROOT / "compose/keycloak/realms/aigw-realm.json",
        ):
            source = path.read_text(encoding="utf-8")
            self.assertIn(
                '{ "name": "aigw-chat", "description": "Open WebUI chat access" }',
                source,
                path.name,
            )
            # Every first-party client carries the identical four-role
            # capability scope (validate-identity-policy.py asserts parity).
            self.assertEqual(
                source.count(f'"roles": [{CAPABILITY_SCOPE}]'), 5, path.name
            )
            # aigw-users is retained but deprecated for chat.
            self.assertIn("DEPRECATED — no longer gates chat", source, path.name)

    def test_policy_validator_pins_the_four_role_scope(self) -> None:
        validator = (ROOT / "scripts/validate-identity-policy.py").read_text(
            encoding="utf-8"
        )
        for role in ("aigw-admins", "aigw-chat", "aigw-developers", "aigw-users"):
            self.assertIn(f'"{role}",', validator)

    def test_both_services_offer_the_chat_capability_to_admins(self) -> None:
        rotator = (ROOT / "services/key-rotator/app/identity.py").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            '{"aigw-users", "aigw-developers", "aigw-admins", "aigw-chat"}', rotator
        )
        portal = (ROOT / "services/dev-portal/app/main.py").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            '{"aigw-users", "aigw-developers", "aigw-admins", "aigw-chat"}', portal
        )

    def test_openwebui_build_verifier_proves_the_new_gate(self) -> None:
        verifier = (
            ROOT / "services/dhi-health-probe/verify_openwebui_oauth.py"
        ).read_text(encoding="utf-8")
        self.assertIn('OAUTH_ALLOWED_ROLES=["aigw-chat"]', verifier)
        self.assertIn('OAUTH_ADMIN_ROLES=["aigw-admins"]', verifier)
        # The harness must prove the LEGACY roles no longer admit a session,
        # and that aigw-chat maps to an ordinary (non-admin) local user.
        self.assertIn('{"roles": ["aigw-users"]}', verifier)
        self.assertIn('{"roles": ["aigw-developers"]}', verifier)
        self.assertIn('{"roles": ["aigw-chat"]}', verifier)

    def test_lab_baseline_and_acceptance_reflect_the_migration(self) -> None:
        lab_vars = (ROOT / "ansible/inventory/host_vars/lab-aigw01.yml").read_text(
            encoding="utf-8"
        )
        for line in (
            "- { name: lab-admins, roles: [aigw-admins, aigw-chat] }",
            "- { name: lab-developers, roles: [aigw-chat, aigw-developers] }",
            "- { name: lab-users, roles: [aigw-chat, aigw-users] }",
        ):
            self.assertIn(line, lab_vars)
        acceptance = (ROOT / "scripts/verify-live-lab-identity.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('["aigw-admins", "aigw-chat"]', acceptance)
        self.assertIn('["aigw-chat", "aigw-developers"]', acceptance)
        self.assertIn('["aigw-chat", "aigw-users"]', acceptance)

    def test_migration_procedure_is_documented(self) -> None:
        operations = (ROOT / "docs/identity-operations.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("Migrating an existing realm to `aigw-chat`", operations)
        self.assertIn("BEFORE the converge", operations)
        self.assertIn("break-glass master administrator", operations)

    def test_verify_role_fails_loud_on_a_missing_chat_migration(self) -> None:
        verify = (ROOT / "ansible/roles/verify/tasks/main.yml").read_text(
            encoding="utf-8"
        )
        # Runs on every converge, both profiles (no profile guard), gated only
        # on an initialized Vault so a genuinely fresh pre-bootstrap converge
        # is skipped.
        self.assertIn(
            "Verify — prove the dedicated aigw-chat gate is wired "
            "(no silent chat brick)",
            verify,
        )
        self.assertIn("/identity/chat-capability-health", verify)
        self.assertIn("AIGW_CHAT_GATE_BRICK", verify)
        # The loud failure must point the operator at the break-glass SOP.
        self.assertIn("Migrating an existing realm to ", verify)
        self.assertIn(
            "(vault_public_status.stdout | from_json).initialized | bool", verify
        )
        # The health read must be an admin-token surface, never in the portal
        # identity token's route allowlist.
        rotator_main = (
            ROOT / "services/key-rotator/app/main.py"
        ).read_text(encoding="utf-8")
        self.assertIn('@app.get("/identity/chat-capability-health")', rotator_main)
        self.assertIn(
            "def chat_capability_health", (
                ROOT / "services/key-rotator/app/identity.py"
            ).read_text(encoding="utf-8")
        )


if __name__ == "__main__":
    unittest.main()
