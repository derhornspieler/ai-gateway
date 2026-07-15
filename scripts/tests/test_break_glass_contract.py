"""Durable break-glass Keycloak administration: cross-file contract pins.

The rotator provisions a marked master-realm administrators group plus a
break-glass user whose generated password is escrowed in Vault during the
one-time identity bootstrap. That control spans the rotator service, the
Compose environment, the Ansible-rendered .env, and the Vault policy written
by the bootstrap ceremony. These pins keep the five surfaces in lockstep so
no single edit can silently drop the durable administrator or widen the
rotator's Vault authority.
"""

from __future__ import annotations

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


class BreakGlassContractTest(unittest.TestCase):
    def test_compose_passes_defaulted_break_glass_environment(self) -> None:
        compose = (ROOT / "compose/docker-compose.yml").read_text()
        self.assertIn(
            "BREAK_GLASS_ADMIN_ENABLED: ${BREAK_GLASS_ADMIN_ENABLED:-true}",
            compose,
        )
        self.assertIn(
            "BREAK_GLASS_ADMIN_VAULT_PATH: "
            "${BREAK_GLASS_ADMIN_VAULT_PATH:-ai-gateway/keycloak/break-glass-admin}",
            compose,
        )
        # No secret may ride this feature through Compose: the password is
        # rotator-generated and lives only in Vault.
        self.assertNotIn("BREAK_GLASS_ADMIN_PASSWORD", compose)

    def test_env_template_renders_the_nonsecret_break_glass_keys(self) -> None:
        env = (
            ROOT / "ansible/roles/docker_stack/templates/env.j2"
        ).read_text()
        self.assertIn(
            "BREAK_GLASS_ADMIN_ENABLED="
            "{{ break_glass_admin_enabled | bool | lower }}",
            env,
        )
        self.assertIn(
            "BREAK_GLASS_ADMIN_VAULT_PATH={{ break_glass_admin_vault_path }}",
            env,
        )
        self.assertNotIn("BREAK_GLASS_ADMIN_PASSWORD", env)

    def test_group_vars_default_break_glass_on_for_every_profile(self) -> None:
        group_vars = (ROOT / "ansible/group_vars/all.yml").read_text()
        self.assertIn("break_glass_admin_enabled: true", group_vars)
        self.assertIn(
            'break_glass_admin_vault_path: "ai-gateway/keycloak/break-glass-admin"',
            group_vars,
        )

    def test_vault_bootstrap_grants_only_the_exact_escrow_path(self) -> None:
        bootstrap = (ROOT / "scripts/vault-bootstrap.sh").read_text()
        self.assertIn(
            'validate_vault_path BREAK_GLASS_ADMIN_VAULT_PATH '
            '"$BREAK_GLASS_ADMIN_VAULT_PATH"',
            bootstrap,
        )
        self.assertIn(
            'path "kv/data/${BREAK_GLASS_ADMIN_VAULT_PATH}" '
            '{ capabilities = ["create", "read", "update"] }',
            bootstrap,
        )
        # The rotator must not be able to destroy its own escrow record.
        self.assertNotIn(
            'path "kv/data/${BREAK_GLASS_ADMIN_VAULT_PATH}" '
            '{ capabilities = ["create", "read", "update", "delete"] }',
            bootstrap,
        )

    def test_rotator_defaults_match_the_deployment_contract(self) -> None:
        config = (
            ROOT / "services/key-rotator/app/config.py"
        ).read_text()
        self.assertIn('default="break-glass-admin"', config)
        self.assertIn('default="keycloak-admins"', config)
        self.assertIn(
            'default="ai-gateway/keycloak/break-glass-admin"', config
        )
        identity = (
            ROOT / "services/key-rotator/app/identity.py"
        ).read_text()
        # The ensure step must run before the verified state write inside
        # bootstrap(); the service test suite proves the event ordering, this
        # pin keeps the call from being deleted outright.
        self.assertIn(
            "break_glass = await self._ensure_break_glass_admin(admin_token)",
            identity,
        )
        self.assertIn('MANAGED_ADMIN_GROUP_ATTRIBUTE = "aigw.managed-admin-group"', identity)
        self.assertIn('BREAK_GLASS_ATTRIBUTE = "aigw.break-glass"', identity)

    def test_live_lab_acceptance_requires_the_escrow(self) -> None:
        verifier = (ROOT / "scripts/verify-live-lab-identity.py").read_text()
        self.assertIn('"break_glass_escrowed": True,', verifier)


if __name__ == "__main__":
    unittest.main()
