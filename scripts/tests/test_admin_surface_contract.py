from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class AdminSurfaceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.traefik = (ROOT / "compose/traefik/dynamic-adm.yml").read_text()
        cls.internal_traefik = (
            ROOT / "compose/traefik/dynamic-int.yml"
        ).read_text()
        cls.compose = (ROOT / "compose/docker-compose.yml").read_text()
        cls.realm = json.loads(
            (ROOT / "compose/keycloak/realms/aigw-realm.json").read_text()
        )
        cls.adm_zone = (
            ROOT
            / "ansible/roles/docker_stack/templates/db.aigw.aegisgroup.ch.adm.j2"
        ).read_text()
        cls.internal_zone = (
            ROOT / "ansible/roles/docker_stack/templates/db.aigw.aegisgroup.ch.j2"
        ).read_text()
        cls.verify = (ROOT / "ansible/roles/verify/tasks/main.yml").read_text()

    def _router(self, name: str, following: str) -> str:
        return self.traefik.split(f"    {name}:\n", 1)[1].split(
            f"    {following}:\n", 1
        )[0]

    def test_custom_console_owns_admin_and_alias_is_redirect_only(self) -> None:
        admin = self._router("admin", "admin-portal")
        self.assertIn("service: admin-portal", admin)
        self.assertNotIn("service: oauth2-proxy", admin)

        alias = self._router("admin-portal", "litellm-admin-root")
        self.assertIn("middlewares: [admin-portal-canonical]", alias)
        self.assertIn("https://admin.", self.traefik)
        self.assertIn("permanent: true", self.traefik)
        self.assertIn(
            'hostname: "admin-portal.{{ aigw_domain }}", path: /healthz, status: "301"',
            self.verify,
        )

    def test_native_litellm_ui_has_distinct_oidc_host_and_safe_root(self) -> None:
        root = self._router("litellm-admin-root", "litellm-admin")
        native = self._router("litellm-admin", "grafana")
        self.assertIn("Path(`/`)", root)
        self.assertIn("middlewares: [litellm-admin-root]", root)
        self.assertIn("service: oauth2-proxy", native)
        self.assertIn("permanent: false", self.traefik)
        self.assertIn(
            'hostname: "litellm-admin.{{ aigw_domain }}", path: /, status: "302"',
            self.verify,
        )
        self.assertIn(
            'OAUTH2_PROXY_REDIRECT_URL: "https://litellm-admin.${DOMAIN:',
            self.compose,
        )
        self.assertIn(
            "OAUTH2_PROXY_COOKIE_NAME: _aigw_litellm_admin_oauth", self.compose
        )
        self.assertIn("OAUTH2_PROXY_UPSTREAMS: http://litellm:4000", self.compose)
        self.assertIn(
            "ipv4_address: ${OAUTH2_PROXY_LITELLM_IP:", self.compose
        )
        self.assertIn(
            "FORWARDED_ALLOW_IPS: ${OAUTH2_PROXY_LITELLM_IP:", self.compose
        )
        self.assertIn("${TRAEFIK_INT_CHAT_IP:", self.compose)

    def test_litellm_schema_surfaces_are_exactly_denied_before_oauth(self) -> None:
        denied = self._router("litellm-admin-docs-deny", "litellm-admin-root")
        for path in (
            "/openapi.json",
            "/openapi.json/",
            "/docs",
            "/docs/",
            "/redoc",
            "/redoc/",
        ):
            self.assertIn(f"Path(`{path}`)", denied)
        self.assertNotIn("PathPrefix", denied)
        self.assertIn("priority: 120", denied)
        self.assertIn("middlewares: [deny-all]", denied)
        self.assertIn('sourceRange: ["0.0.0.0/32"]', self.traefik)
        self.assertIn(
            'hostname: "litellm-admin.{{ aigw_domain }}", path: /openapi.json, status: "403"',
            self.verify,
        )

        # Keep the user-plane API on its independent, inference-only
        # allow-list with a lower-priority catch-all denial.
        self.assertIn("Path(`/v1/chat/completions`)", self.internal_traefik)
        self.assertIn("api-deny:", self.internal_traefik)
        self.assertNotIn("Path(`/openapi.json`)", self.internal_traefik)

    def test_each_oauth_gate_has_an_isolated_cookie_key_and_path_free_logs(self) -> None:
        expected = {
            "oauth2-proxy": "OAUTH2_PROXY_LITELLM_COOKIE_SECRET",
            "oauth2-proxy-grafana": "OAUTH2_PROXY_GRAFANA_COOKIE_SECRET",
            "oauth2-proxy-prometheus": "OAUTH2_PROXY_PROMETHEUS_COOKIE_SECRET",
            "oauth2-proxy-vault": "OAUTH2_PROXY_VAULT_COOKIE_SECRET",
        }
        service_order = (
            "oauth2-proxy",
            "oauth2-proxy-grafana",
            "oauth2-proxy-prometheus",
            "oauth2-proxy-vault",
            "open-webui",
        )
        cookie_vars: list[str] = []
        for index, service in enumerate(service_order[:-1]):
            block = self.compose.split(f"  {service}:\n", 1)[1].split(
                f"  {service_order[index + 1]}:\n", 1
            )[0]
            cookie_var = expected[service]
            cookie_vars.append(cookie_var)
            self.assertIn(
                f"OAUTH2_PROXY_COOKIE_SECRET: ${{{cookie_var}:?", block
            )
            request_format = re.search(
                r"OAUTH2_PROXY_REQUEST_LOGGING_FORMAT:\s*'([^']+)'", block
            )
            auth_format = re.search(
                r"OAUTH2_PROXY_AUTH_LOGGING_FORMAT:\s*'([^']+)'", block
            )
            self.assertIsNotNone(request_format)
            self.assertIsNotNone(auth_format)
            for rendered_format in (
                request_format.group(1),
                auth_format.group(1),
            ):
                for forbidden in (
                    "RequestURI",
                    "Upstream",
                    "Message",
                    "Path",
                    "Query",
                    "URL",
                ):
                    self.assertNotIn(forbidden, rendered_format)
        self.assertEqual(len(cookie_vars), len(set(cookie_vars)))

    def test_keycloak_callbacks_follow_the_split_without_a_second_console_origin(self) -> None:
        clients = {client["clientId"]: client for client in self.realm["clients"]}
        self.assertEqual(
            clients["admin-portal"]["redirectUris"],
            ["https://admin.aigw.example.internal/auth/callback"],
        )
        self.assertEqual(
            clients["admin-portal"]["webOrigins"],
            ["https://admin.aigw.example.internal"],
        )
        self.assertIn(
            "https://litellm-admin.aigw.example.internal/oauth2/callback",
            clients["admin-ui"]["redirectUris"],
        )
        self.assertNotIn(
            "https://admin.aigw.example.internal/oauth2/callback",
            clients["admin-ui"]["redirectUris"],
        )

    def test_litellm_admin_dns_is_adm_only_and_wildcard_certificate_covers_it(self) -> None:
        self.assertRegex(
            self.adm_zone,
            r"(?m)^litellm-admin\s+IN A \{\{ eth1_ip \}\}$",
        )
        self.assertNotRegex(self.internal_zone, r"(?m)^litellm-admin\s+IN A")
        stack = (ROOT / "ansible/roles/docker_stack/tasks/main.yml").read_text()
        self.assertIn("subjectAltName=DNS:*.{{ aigw_domain }}", stack)

    def test_provider_enrollment_vault_policy_is_exact_path_only(self) -> None:
        bootstrap = (ROOT / "scripts/vault-bootstrap.sh").read_text()
        self.assertIn(
            'path "kv/data/ai-gateway/anthropic-wif" { capabilities = '
            '["create", "read", "update", "delete"] }',
            bootstrap,
        )
        self.assertIn(
            'path "kv/metadata/ai-gateway/anthropic-wif" { capabilities = '
            '["read", "delete"] }',
            bootstrap,
        )
        self.assertNotIn('path "kv/data/ai-gateway/*"', bootstrap)
        self.assertNotIn('path "kv/metadata/ai-gateway/*"', bootstrap)


if __name__ == "__main__":
    unittest.main()
