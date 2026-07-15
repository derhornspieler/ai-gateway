"""Vault OIDC login: cross-file contract pins.

The `vault` relying party (Keycloak realm aigw) plus the root-token ceremony
scripts/vault-oidc-setup.sh retire routine root-token logins. That control
spans the rotator service (client reconcile + secret escrow), the Compose
environment, the Ansible-rendered .env, the Vault rotator policy written by
the bootstrap ceremony, and the ceremony script itself. These pins keep the
surfaces in lockstep so no single edit can silently break the login flow or
widen either the rotator's or the vault-admins policy's Vault authority.
"""

from __future__ import annotations

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
CEREMONY = ROOT / "scripts/vault-oidc-setup.sh"


class VaultOidcSetupContractTest(unittest.TestCase):
    def test_compose_routes_the_secret_to_exactly_two_consumers(self) -> None:
        compose = (ROOT / "compose/docker-compose.yml").read_text()
        # Keycloak (realm-import ${VAR} substitution) and the rotator
        # (reconcile + escrow). Vault itself never sees the secret via
        # environment: the ceremony reads the rotator's escrow root-side.
        self.assertEqual(
            compose.count(
                "VAULT_OIDC_CLIENT_SECRET: "
                "${VAULT_OIDC_CLIENT_SECRET:?VAULT_OIDC_CLIENT_SECRET must be set}"
            ),
            2,
        )
        self.assertIn(
            "VAULT_OIDC_RP_VAULT_PATH: "
            "${VAULT_OIDC_RP_VAULT_PATH:-ai-gateway/keycloak/vault-oidc-rp}",
            compose,
        )
        # Vault reaches the public issuer through one scoped edge alias on
        # net-vault — the same reviewed pattern as Open WebUI on net-chat.
        self.assertIn('aliases: ["auth.${DOMAIN}"]', compose)

    def test_env_template_renders_the_secret_and_the_escrow_path(self) -> None:
        env = (ROOT / "ansible/roles/docker_stack/templates/env.j2").read_text()
        self.assertIn(
            "VAULT_OIDC_CLIENT_SECRET={{ vault_oidc_client_secret | mandatory(",
            env,
        )
        self.assertIn(
            "VAULT_OIDC_RP_VAULT_PATH={{ vault_oidc_rp_vault_path }}", env
        )

    def test_group_vars_pin_the_default_escrow_path(self) -> None:
        group_vars = (ROOT / "ansible/group_vars/all.yml").read_text()
        self.assertIn(
            'vault_oidc_rp_vault_path: "ai-gateway/keycloak/vault-oidc-rp"',
            group_vars,
        )

    def test_vault_bootstrap_grants_only_the_exact_escrow_path(self) -> None:
        bootstrap = (ROOT / "scripts/vault-bootstrap.sh").read_text()
        self.assertIn(
            'validate_vault_path VAULT_OIDC_RP_VAULT_PATH '
            '"$VAULT_OIDC_RP_VAULT_PATH"',
            bootstrap,
        )
        policy_match = re.search(
            r"vlt policy write rotator - <<HCL\n(.*?)\nHCL", bootstrap, re.DOTALL
        )
        self.assertIsNotNone(policy_match, "rotator policy heredoc is missing")
        policy = policy_match.group(1)
        escrow_stanzas = re.findall(
            r'^path\s+"([^"]*VAULT_OIDC_RP_VAULT_PATH[^"]*)"\s*'
            r"\{\s*capabilities\s*=\s*\[([^\]]*)\]\s*\}",
            policy,
            re.MULTILINE,
        )
        self.assertEqual(
            len(escrow_stanzas),
            1,
            "the escrow path must appear in exactly one policy stanza",
        )
        stanza_path, capabilities = escrow_stanzas[0]
        self.assertEqual(stanza_path, "kv/data/${VAULT_OIDC_RP_VAULT_PATH}")
        granted = {
            token.strip().strip('"') for token in capabilities.split(",")
        }
        self.assertEqual(granted, {"create", "read", "update"})
        mentions = [
            line
            for line in policy.splitlines()
            if "VAULT_OIDC_RP_VAULT_PATH" in line
        ]
        self.assertEqual(len(mentions), 1, mentions)

    def test_ceremony_takes_the_root_token_on_stdin_only(self) -> None:
        ceremony = CEREMONY.read_text()
        self.assertIn("if [[ -t 0 ]]; then", ceremony)
        self.assertIn('IFS= read -r VAULT_TOKEN || die "no Vault token on stdin"', ceremony)
        # The token is forwarded by NAME only; it must never be interpolated
        # onto a docker/compose command line.
        self.assertIn("-e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN vault vault", ceremony)
        self.assertNotIn('VAULT_TOKEN="$1"', ceremony)
        self.assertNotIn("-e VAULT_TOKEN=", ceremony)
        # The escrowed client secret likewise stays off every command line:
        # the auth/oidc configuration is written as JSON on stdin.
        self.assertIn("vlt write auth/oidc/config -", ceremony)
        self.assertNotIn("oidc_client_secret=$", ceremony)

    def test_ceremony_pins_the_issuer_role_and_group_contract(self) -> None:
        ceremony = CEREMONY.read_text()
        # Discovery must target the exact public issuer (OIDC issuer equality)
        # with trust pinned to the deployment CA bundle.
        self.assertIn('f"https://auth.{sys.argv[2]}/realms/aigw"', ceremony)
        self.assertIn('CA_BUNDLE="$STACK_DIR/certs/ca.pem"', ceremony)
        self.assertIn('"oidc_discovery_ca_pem": ca_pem,', ceremony)
        self.assertIn('"oidc_client_id": "vault",', ceremony)
        self.assertIn('"default_role": "aigw",', ceremony)
        # Role: preferred_username / roles claims, bound to the vault audience
        # and the aigw-admins capability role, with only the two reviewed
        # redirect URIs.
        self.assertIn('"user_claim": "preferred_username",', ceremony)
        self.assertIn('"groups_claim": "roles",', ceremony)
        self.assertIn('"bound_audiences": ["vault"],', ceremony)
        self.assertIn('"bound_claims": {"roles": ["aigw-admins"]},', ceremony)
        self.assertIn(
            'f"https://vault.{sys.argv[1]}/ui/vault/auth/oidc/oidc/callback",',
            ceremony,
        )
        self.assertIn('"http://localhost:8250/oidc/callback",', ceremony)
        self.assertIn("vlt write auth/oidc/role/aigw -", ceremony)
        # External group mapping and the ceremony's own functional proof.
        self.assertIn("identity/group name=aigw-admins type=external policies=vault-admins", ceremony)
        self.assertIn("identity/group-alias name=aigw-admins", ceremony)
        self.assertIn("auth/oidc/oidc/auth_url", ceremony)

    def test_vault_admins_policy_is_scoped_and_never_root_shaped(self) -> None:
        ceremony = CEREMONY.read_text()
        policy_match = re.search(
            r"vlt policy write vault-admins - <<HCL\n(.*?)\nHCL",
            ceremony,
            re.DOTALL,
        )
        self.assertIsNotNone(policy_match, "vault-admins policy heredoc is missing")
        policy = policy_match.group(1)
        # The four credential/private-key records stay root-ceremony-only.
        for denied in (
            "${BREAK_GLASS_ADMIN_VAULT_PATH}",
            "${VAULT_OIDC_RP_VAULT_PATH}",
            "${IDENTITY_CONTROLLER_KEY_VAULT_PATH}",
            "${KC_CLIENT_ASSERTION_KEY_VAULT_PATH}",
        ):
            self.assertIn(
                f'path "kv/data/{denied}" {{ capabilities = ["deny"] }}',
                policy,
            )
            self.assertIn(
                f'path "kv/metadata/{denied}" {{ capabilities = ["deny"] }}',
                policy,
            )
        # No authority over auth methods, policies, identity, audit devices,
        # seal state, raw storage, or mount creation — the root token stays
        # reserved for ceremonies.
        for forbidden in (
            "sys/auth",
            "sys/polic",
            "identity/",
            "sys/audit",
            'path "sys/seal"',
            "sys/unseal",
            "sys/rekey",
            "sys/raw",
            "sys/remount",
            "sys/step-down",
            "auth/token/create",
            'path "sys/mounts/*"',
            'path "pki/',
            'path "kv/data/ai-gateway/*"',
            'path "kv/metadata/ai-gateway/*"',
        ):
            self.assertNotIn(forbidden, policy, forbidden)
        # seal-status is read-only introspection, asserted separately from the
        # sys/seal exclusion above.
        self.assertIn(
            'path "sys/seal-status" { capabilities = ["read"] }', policy
        )

    def test_ceremony_ships_and_is_linted(self) -> None:
        tasks = (ROOT / "ansible/roles/docker_stack/tasks/main.yml").read_text()
        validator = (ROOT / "scripts/validate-compose.sh").read_text()
        shellcheck = (ROOT / ".github/scripts/run-shellcheck.sh").read_text()
        self.assertIn("      - vault-oidc-setup.sh\n", tasks)
        self.assertIn('        "vault-oidc-setup.sh",\n', validator)
        self.assertIn("  scripts/vault-oidc-setup.sh\n", shellcheck)

    def test_rotator_defaults_and_escrow_match_the_deployment_contract(self) -> None:
        config = (ROOT / "services/key-rotator/app/config.py").read_text()
        self.assertIn('default="ai-gateway/keycloak/vault-oidc-rp"', config)
        self.assertIn('"VAULT_OIDC_RP_VAULT_PATH": self.vault_oidc_rp_vault_path,', config)
        identity = (ROOT / "services/key-rotator/app/identity.py").read_text()
        self.assertIn('VAULT_RP_CLIENT_ID = "vault"', identity)
        # Escrowed before the verified state write inside bootstrap(); the
        # service test suite proves the ordering, this pin keeps the call
        # from being deleted outright.
        self.assertIn(
            "vault_oidc_rp_escrowed_at = self._escrow_vault_oidc_rp_secret()",
            identity,
        )
        self.assertIn('    "vault",\n)', identity)

    def test_live_lab_acceptance_requires_the_escrow(self) -> None:
        verifier = (ROOT / "scripts/verify-live-lab-identity.py").read_text()
        self.assertIn('"vault_oidc_rp_escrowed": True,', verifier)


if __name__ == "__main__":
    unittest.main()
