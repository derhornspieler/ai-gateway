from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class WifDomainContractTests(unittest.TestCase):
    def test_fresh_realm_and_runtime_use_the_ansible_domain(self) -> None:
        realm = (
            ROOT
            / "ansible/roles/docker_stack/templates/keycloak-realms/anthropic-wif-realm.json.j2"
        ).read_text(encoding="utf-8")
        compose = (ROOT / "compose/docker-compose.yml").read_text(encoding="utf-8")

        self.assertIn(
            '"frontendUrl": "https://idp.wif.{{ aigw_domain }}"', realm
        )
        self.assertIn(
            'WIF_KEYCLOAK_PUBLIC_URL: "https://idp.wif.${DOMAIN:?DOMAIN must be set}"',
            compose,
        )
        self.assertNotIn("idp.wif-a.example.invalid", realm)
        self.assertNotIn("idp.wif-a.example.invalid", compose)

    def test_brownfield_converge_repairs_and_verifies_the_wif_realm(self) -> None:
        identity = (
            ROOT / "services/key-rotator/app/identity.py"
        ).read_text(encoding="utf-8")
        method = identity[
            identity.index("async def _reconcile_wif_frontend_url(") :
            identity.index(
                "async def reconcile_prebootstrap_relying_party_redirect_uris("
            )
        ]
        for required in (
            'desired = f"https://idp.wif.{self.settings.aigw_domain}"',
            '"GET",',
            '"PUT",',
            '"Keycloak did not verify the WIF realm frontend URL"',
        ):
            self.assertIn(required, method)

        broker = identity[
            identity.index("async def _ensure_broker(") :
            identity.index("async def _ensure_broker_subject_mapper(")
        ]
        converge = identity[
            identity.index("async def converge_deployment_identity(") :
            identity.index("def _identity_state(")
        ]
        self.assertIn("await self._reconcile_wif_frontend_url(", broker)
        self.assertIn("admin_token, before_change", broker)
        self.assertIn("await self._reconcile_broker(", converge)
        self.assertIn("admin_token, mark_live_change", converge)

    def test_every_fresh_broker_starts_without_inherited_scopes(self) -> None:
        sources = (
            ROOT / "compose/keycloak/realms/anthropic-wif-realm.json",
            ROOT
            / "ansible/roles/docker_stack/templates/keycloak-realms/anthropic-wif-realm.json.j2",
        )
        for source in sources:
            rendered = source.read_text(encoding="utf-8").replace(
                "{{ aigw_domain }}", "aigw.internal"
            )
            realm = json.loads(rendered)
            broker = next(
                client
                for client in realm["clients"]
                if client["clientId"] == "anthropic-token-broker"
            )
            self.assertIs(broker["fullScopeAllowed"], False, source)
            self.assertEqual(broker["defaultClientScopes"], [], source)
            self.assertEqual(broker["optionalClientScopes"], [], source)


if __name__ == "__main__":
    unittest.main()
