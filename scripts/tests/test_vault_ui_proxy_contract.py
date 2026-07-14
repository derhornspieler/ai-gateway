"""Security and deployment contracts for the DHI Vault UI companion."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
COMPOSE = (ROOT / "compose/docker-compose.yml").read_text(encoding="utf-8")
PROXY = (ROOT / "services/vault-ui-proxy/main.go").read_text(encoding="utf-8")
STACK = (
    ROOT / "ansible/roles/docker_stack/tasks/main.yml"
).read_text(encoding="utf-8")
DNS_OVERLAY = (
    ROOT / "ansible/roles/docker_stack/templates/docker-compose.dns.yml.j2"
).read_text(encoding="utf-8")
VERIFY = (ROOT / "ansible/roles/verify/tasks/main.yml").read_text(
    encoding="utf-8"
)


def service_block(name: str, next_name: str) -> str:
    return COMPOSE.split(f"  {name}:\n", 1)[1].split(f"  {next_name}:\n", 1)[0]


class VaultUIProxyContractTests(unittest.TestCase):
    def test_oauth_fronts_same_origin_proxy_not_the_ui_less_vault_binary(self) -> None:
        oauth = service_block("oauth2-proxy-vault", "litellm")
        self.assertIn("OAUTH2_PROXY_UPSTREAMS: http://vault-ui-proxy:8080", oauth)
        self.assertIn("vault-ui-proxy: { condition: service_healthy }", oauth)
        self.assertNotIn("OAUTH2_PROXY_UPSTREAMS: http://vault:8200", oauth)

    def test_proxy_is_nonroot_readonly_and_isolated_to_vault_plane(self) -> None:
        proxy = service_block("vault-ui-proxy", "vault")
        self.assertIn("image: ai-gateway/dhi-vault-ui-proxy:2.0.3", proxy)
        self.assertIn('user: "1000:1000"', proxy)
        self.assertIn("read_only: true", proxy)
        self.assertIn("cap_drop: [ALL]", COMPOSE.split("x-hardening:", 1)[1].split("services:", 1)[0])
        self.assertIn("networks: [net-vault]", proxy)
        self.assertNotIn("ports:", proxy)
        self.assertNotIn("environment:", proxy)
        self.assertNotIn("net-adm", proxy)
        self.assertNotIn("net-internal", proxy)
        self.assertNotIn("net-egress", proxy)
        self.assertIn(
            "test: [CMD, /usr/local/bin/vault-ui-proxy, check]", proxy
        )

    def test_backend_cannot_be_selected_by_environment_or_request(self) -> None:
        self.assertRegex(PROXY, r'vaultUpstream\s*=\s*"http://vault:8200"')
        self.assertNotIn("os.Getenv", PROXY)
        self.assertNotIn("os.LookupEnv", PROXY)
        self.assertIn('request.URL.Path == "/v1"', PROXY)
        self.assertIn('strings.HasPrefix(request.URL.Path, "/v1/")', PROXY)
        self.assertIn("http.NotFound(writer, request)", PROXY)
        self.assertIn("request.Out.Header.Del(\"Forwarded\")", PROXY)
        self.assertIn("request.Out.Header.Del(\"Cookie\")", PROXY)
        self.assertIn("X-Vault-Token", PROXY)
        self.assertIn("X-Vault-Namespace", PROXY)
        self.assertIn('log.Print("Vault upstream unavailable")', PROXY)
        self.assertNotIn("request.URL.Path)", PROXY)

    def test_ui_privacy_is_structural_and_csp_denies_external_connect(self) -> None:
        self.assertIn('app["ANALYTICS_CONFIG"] = map[string]any{"enabled": false}', PROXY)
        self.assertIn('analytics["enabled"].(bool)', PROXY)
        self.assertIn("len(analytics) != 1", PROXY)
        self.assertIn("connect-src 'self'", PROXY)
        self.assertNotIn("connect-src 'self' https:", PROXY)
        self.assertIn('header.Set("Content-Security-Policy", uiCSP)', PROXY)
        self.assertIn("Service-Worker-Allowed", PROXY)
        self.assertIn("worker-src 'self'", PROXY)
        self.assertIn(
            'serviceWorkerScope        = "/v1/sys/storage/raft/snapshot"', PROXY
        )
        self.assertNotIn('header.Set("Service-Worker-Allowed", "/")', PROXY)

    def test_proxy_is_direct_pid1_and_dormant_vault_cannot_run(self) -> None:
        dockerfile = (ROOT / "services/vault-ui-proxy/Dockerfile").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "FROM dhi.io/vault:2.0.3@sha256:"
            "743791e1bf99025aae045b3155fecf0542e7fd1bde7bbfbaf76eb4b9ff2555a6",
            dockerfile,
        )
        self.assertIn(
            "FROM hashicorp/vault:2.0.3@sha256:"
            "a296a888b118615dc01d5f1a6846e6d4a7277946caaed5b447008fff5fe06b54",
            dockerfile,
        )
        self.assertIn('ENTRYPOINT ["/usr/local/bin/vault-ui-proxy"]', dockerfile)
        self.assertIn("CMD []", dockerfile)
        self.assertIn("verifyDirectRuntimeProcess()", PROXY)
        self.assertIn("os.Getpid() != 1", PROXY)
        self.assertIn('os.Readlink("/proc/1/exe")', PROXY)
        self.assertIn('os.ReadDir("/proc")', PROXY)

    def test_no_stub_and_sealed_vault_are_part_of_health_contract(self) -> None:
        self.assertIn("vault ui is not available in this binary", PROXY.lower())
        self.assertIn("http.StatusServiceUnavailable", PROXY)
        self.assertIn("http.StatusNotImplemented", PROXY)
        self.assertIn('Initialized *bool `json:"initialized"`', PROXY)
        self.assertIn('Sealed      *bool `json:"sealed"`', PROXY)
        self.assertIn("verifyRuntimeConfig(body) != nil", PROXY)

    def test_ansible_deploys_and_exercises_the_companion(self) -> None:
        self.assertIn("vault-ui-proxy", DNS_OVERLAY)
        self.assertIn(
            "Prove the Vault UI proxy serves the reviewed UI and reaches only Vault",
            STACK,
        )
        self.assertIn(
            "Vault UI proxy directly replaces the dormant DHI Vault entrypoint",
            STACK,
        )
        self.assertIn("vault_ui_proxy_startup.container.Config.User == '1000:1000'", STACK)
        self.assertIn(
            "vault_ui_proxy_startup.container.Path == '/usr/local/bin/vault-ui-proxy'",
            STACK,
        )
        self.assertIn('"{{ compose_project_name }}-vault-ui-proxy-1"', STACK)
        self.assertIn("- vault-ui-proxy\n", STACK)
        self.assertIn("'oauth2-proxy-vault', 'vault-ui-proxy'", VERIFY)
        probe = STACK.split(
            "- name: Prove the Vault UI proxy serves the reviewed UI and reaches only Vault",
            1,
        )[1].split("- name: Inspect DHI Alloy after Compose start", 1)[0]
        self.assertIn("retries: 42", probe)
        self.assertIn("delay: 5", probe)

    def test_dhi_vault_server_binary_and_state_contract_are_unchanged(self) -> None:
        vault = service_block("vault", "postgres")
        self.assertIn(
            "BASE_IMAGE: dhi.io/vault:2.0.3@sha256:"
            "743791e1bf99025aae045b3155fecf0542e7fd1bde7bbfbaf76eb4b9ff2555a6",
            vault,
        )
        self.assertIn("vault_data:/vault/data", vault)
        self.assertIn("vault_audit:/vault/logs", vault)
        self.assertNotIn("operator init", proxy := service_block("vault-ui-proxy", "vault"))
        self.assertNotIn("vault_data", proxy)


if __name__ == "__main__":
    unittest.main()
