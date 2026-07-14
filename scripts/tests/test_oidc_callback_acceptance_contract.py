from __future__ import annotations

import http.cookiejar
import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
HARNESS_PATH = ROOT / "scripts/test-oidc-callbacks.py"
REALM_TEMPLATE = ROOT / "ansible/roles/docker_stack/templates/keycloak-realms/aigw-realm.json.j2"
SPEC = importlib.util.spec_from_file_location("aigw_oidc_callback_harness", HARNESS_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the OIDC callback acceptance harness")
harness = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = harness
SPEC.loader.exec_module(harness)


class OidcCallbackAcceptanceContractTests(unittest.TestCase):
    def test_closed_target_contract_matches_registered_callback_boundaries(self) -> None:
        observed = {
            target.name: (
                target.host,
                target.start_path,
                target.callback_path,
                target.requested_path,
                target.probe_path,
                target.session_cookie,
            )
            for target in harness.TARGETS
        }
        self.assertEqual(
            observed,
            {
                "litellm-admin": (
                    "litellm-admin.aigw.aegisgroup.ch",
                    "/oauth2/start",
                    "/oauth2/callback",
                    "/ui",
                    "/oauth2/auth",
                    "_aigw_litellm_admin_oauth",
                ),
                "grafana": (
                    "grafana.aigw.aegisgroup.ch",
                    "/oauth2/start",
                    "/oauth2/callback",
                    "/",
                    "/oauth2/auth",
                    "_aigw_grafana_oauth",
                ),
                "prometheus": (
                    "prometheus.aigw.aegisgroup.ch",
                    "/oauth2/start",
                    "/oauth2/callback",
                    "/",
                    "/oauth2/auth",
                    "_aigw_prometheus_oauth",
                ),
                "vault": (
                    "vault.aigw.aegisgroup.ch",
                    "/oauth2/start",
                    "/oauth2/callback",
                    "/ui/",
                    "/oauth2/auth",
                    "_aigw_vault_oauth",
                ),
                "chat": (
                    "chat.aigw.aegisgroup.ch",
                    "/oauth/oidc/login",
                    "/oauth/oidc/callback",
                    "/auth",
                    "/api/v1/auths/",
                    "token",
                ),
            },
        )
        self.assertEqual(
            harness.start_url(harness.TARGET_BY_NAME["litellm-admin"]),
            "https://litellm-admin.aigw.aegisgroup.ch/oauth2/start?rd=/ui",
        )
        self.assertEqual(
            harness.start_url(harness.TARGET_BY_NAME["chat"]),
            "https://chat.aigw.aegisgroup.ch/oauth/oidc/login",
        )
        self.assertEqual(
            harness.TARGET_BY_NAME["litellm-admin"].denied_paths,
            (
                "/openapi.json",
                "/openapi.json/",
                "/docs",
                "/docs/",
                "/redoc",
                "/redoc/",
            ),
        )
        self.assertTrue(
            all(
                not target.denied_paths
                for target in harness.TARGETS
                if target.name != "litellm-admin"
            )
        )
        realm = REALM_TEMPLATE.read_text(encoding="utf-8")
        for target in harness.TARGETS:
            template_origin = target.origin.replace(
                ".aigw.aegisgroup.ch", ".{{ aigw_domain }}"
            )
            self.assertIn(template_origin + target.callback_path, realm)

    def test_only_reviewed_https_origins_and_default_ports_are_accepted(self) -> None:
        target = harness.TARGET_BY_NAME["grafana"]
        valid = harness.reviewed_https_url(
            "https://auth.aigw.aegisgroup.ch/realms/aigw/protocol/openid-connect/auth",
            target.allowed_hosts,
        )
        self.assertEqual(valid.hostname, harness.AUTH_HOST)

        for url in (
            "http://auth.aigw.aegisgroup.ch/realms/aigw/protocol/openid-connect/auth",
            "https://evil.example/",
            "https://auth.aigw.aegisgroup.ch:444/",
            "https://user@auth.aigw.aegisgroup.ch/",
            "https://auth.aigw.aegisgroup.ch@evil.example/",
            "https://admin.aigw.aegisgroup.ch/",
        ):
            with self.subTest(url=url):
                with self.assertRaises(harness.AcceptanceError):
                    harness.reviewed_https_url(url, target.allowed_hosts)

    def test_redirect_handler_rejects_a_caller_supplied_target(self) -> None:
        target = harness.TARGET_BY_NAME["litellm-admin"]
        copied = harness.OidcTarget(
            name=target.name,
            host=target.host,
            start_path=target.start_path,
            callback_path=target.callback_path,
            requested_path=target.requested_path,
            final_paths=target.final_paths,
            probe_path=target.probe_path,
            probe_statuses=target.probe_statuses,
            session_cookie=target.session_cookie,
        )
        with self.assertRaises(ValueError):
            harness.RestrictedRedirects(copied)

    def test_completion_requires_the_exact_callback_and_a_clean_target_return(self) -> None:
        target = harness.TARGET_BY_NAME["chat"]
        harness.verify_callback_completion(
            target,
            [
                (harness.AUTH_HOST, "/realms/aigw/protocol/openid-connect/auth"),
                (target.host, target.callback_path),
            ],
            target.origin + "/auth",
            "<html>chat</html>",
        )

        for redirects, final_url, html in (
            ([], target.origin + "/auth", "ok"),
            ([(target.host, target.callback_path)], "https://auth.aigw.aegisgroup.ch/", "ok"),
            ([(target.host, target.callback_path)], target.origin + "/auth?error=bad", "ok"),
            ([(target.host, target.callback_path)], target.origin + "/auth?code=leaked", "ok"),
            ([(target.host, target.callback_path)], target.origin + "/auth", "invalid_scope"),
        ):
            with self.subTest(final_url=final_url):
                with self.assertRaises(harness.AcceptanceError):
                    harness.verify_callback_completion(target, redirects, final_url, html)

    def test_password_can_only_be_posted_to_the_keycloak_login_action(self) -> None:
        target = harness.TARGET_BY_NAME["vault"]
        valid = {
            "action": "/realms/aigw/login-actions/authenticate?session_code=opaque",
            "method": "post",
            "inputs": {},
        }
        self.assertEqual(
            harness.reviewed_login_action(
                "https://auth.aigw.aegisgroup.ch/realms/aigw/protocol/openid-connect/auth",
                valid,
                target,
            ),
            "https://auth.aigw.aegisgroup.ch/realms/aigw/login-actions/authenticate?session_code=opaque",
        )
        for action in (
            "https://vault.aigw.aegisgroup.ch/login-actions/authenticate",
            "https://evil.example/realms/aigw/login-actions/authenticate",
            "https://auth.aigw.aegisgroup.ch/realms/aigw/account/",
        ):
            with self.subTest(action=action):
                with self.assertRaises(harness.AcceptanceError):
                    harness.reviewed_login_action(
                        "https://auth.aigw.aegisgroup.ch/realms/aigw/protocol/openid-connect/auth",
                        {"action": action, "method": "post", "inputs": {}},
                        target,
                    )

    def test_session_cookie_must_be_secure_and_scoped_to_the_target(self) -> None:
        target = harness.TARGET_BY_NAME["chat"]
        cookies = http.cookiejar.CookieJar()
        cookies.set_cookie(
            http.cookiejar.Cookie(
                version=0,
                name="token",
                value="not-inspected",
                port=None,
                port_specified=False,
                domain="chat.aigw.aegisgroup.ch",
                domain_specified=False,
                domain_initial_dot=False,
                path="/",
                path_specified=True,
                secure=True,
                expires=None,
                discard=True,
                comment=None,
                comment_url=None,
                rest={},
                rfc2109=False,
            )
        )
        harness.require_session_cookie(cookies, target)

        insecure = http.cookiejar.CookieJar()
        insecure.set_cookie(
            http.cookiejar.Cookie(
                version=0,
                name="token",
                value="not-inspected",
                port=None,
                port_specified=False,
                domain="chat.aigw.aegisgroup.ch",
                domain_specified=False,
                domain_initial_dot=False,
                path="/",
                path_specified=True,
                secure=False,
                expires=None,
                discard=True,
                comment=None,
                comment_url=None,
                rest={},
                rfc2109=False,
            )
        )
        with self.assertRaises(harness.AcceptanceError):
            harness.require_session_cookie(insecure, target)

    def test_no_unreviewed_host_or_return_url_cli_option_exists(self) -> None:
        source = HARNESS_PATH.read_text(encoding="utf-8")
        self.assertNotIn('add_argument("--host"', source)
        self.assertNotIn('add_argument("--origin"', source)
        self.assertNotIn('add_argument("--redirect', source)
        self.assertIn("pipe the disposable lab password on stdin", source)
        self.assertIn("ProxyHandler({})", source)
        self.assertIn("OIDC_CALLBACK_FAIL target={target.name}", source)


if __name__ == "__main__":
    unittest.main()
