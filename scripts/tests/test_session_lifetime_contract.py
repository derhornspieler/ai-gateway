"""Gateway-wide session-lifetime policy (owner decision, 2026-07-17).

Every interactive session is bounded by ONE policy: 8 hours idle, 10 hours
absolute. Keycloak is the only layer with a real idle concept, so it carries
both realm-side knobs; every app-held cookie/token is then capped at the 10h
absolute ceiling so no app session can outlive the SSO session that minted it
by more than the cap:

- Keycloak realm: ssoSessionIdleTimeout=28800 (8h), ssoSessionMaxLifespan=36000
  (10h) in BOTH realm sources (the Ansible template that converges the lab and
  the compose example copy that validate-compose renders).
- oauth2-proxy apps (litellm-admin, grafana, prometheus, vault): cookie expires
  at 10h; the 5m cookie refresh re-validates against Keycloak, which is what
  makes the 8h idle limit bite on these apps.
- Open WebUI: JWT_EXPIRES_IN=10h. The upstream default is UNLIMITED, which is
  the one token that would otherwise survive SSO logout forever.
- dev-portal/admin-portal: session_max_age_seconds defaults to 10h.

NOTE: the realm JSON only imports into an empty database — the live realm was
updated to the same values via kcadm. These pins keep the sources canonical so
the next fresh import lands on the same policy.
"""

from __future__ import annotations

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = (ROOT / "compose/docker-compose.yml").read_text(encoding="utf-8")
REALM_SOURCES = (
    ROOT / "ansible/roles/docker_stack/templates/keycloak-realms/aigw-realm.json.j2",
    ROOT / "compose/keycloak/realms/aigw-realm.json",
)


class SessionLifetimeContractTest(unittest.TestCase):
    def test_realm_sources_pin_idle_and_max_sso_lifetimes(self) -> None:
        for path in REALM_SOURCES:
            source = path.read_text(encoding="utf-8")
            self.assertIn('"ssoSessionIdleTimeout": 28800,', source, path.name)
            self.assertIn('"ssoSessionMaxLifespan": 36000,', source, path.name)

    def test_every_oauth2_proxy_cookie_expires_at_the_absolute_cap(self) -> None:
        self.assertEqual(COMPOSE.count("OAUTH2_PROXY_COOKIE_EXPIRE: 10h"), 4)
        self.assertNotIn("OAUTH2_PROXY_COOKIE_EXPIRE: 8h", COMPOSE)
        # The refresh interval is what ties these cookies back to the realm's
        # idle timeout — a proxy that never re-validates would turn the 10h
        # cookie into a 10h bearer credential detached from SSO state.
        self.assertEqual(COMPOSE.count("OAUTH2_PROXY_COOKIE_REFRESH: 5m"), 4)

    def test_open_webui_token_lifetime_is_bounded(self) -> None:
        self.assertIn("JWT_EXPIRES_IN: 10h", COMPOSE)

    def test_dev_portal_session_defaults_to_the_absolute_cap(self) -> None:
        config = (ROOT / "services/dev-portal/app/config.py").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "session_max_age_seconds: int = Field("
            "default=10 * 60 * 60, ge=300, le=24 * 60 * 60)",
            config,
        )

    def test_validator_asserts_the_same_lifetimes(self) -> None:
        validator = (ROOT / "scripts/validate-compose.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'assert env["OAUTH2_PROXY_COOKIE_EXPIRE"] == "10h", name', validator
        )
        self.assertIn(
            'assert services["open-webui"]["environment"]["JWT_EXPIRES_IN"]'
            ' == "10h"',
            validator,
        )


if __name__ == "__main__":
    unittest.main()
