"""Security and deployment contracts for the DHI Vault UI companion."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
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
ALL_VARS = (ROOT / "ansible/group_vars/all.yml").read_text(encoding="utf-8")
GENERIC_VARS = (
    ROOT / "ansible/inventory/group_vars/generic_rocky9.yml"
).read_text(encoding="utf-8")
LAB_VARS = (
    ROOT / "ansible/inventory/host_vars/lab-aigw01.yml"
).read_text(encoding="utf-8")
SITE = (ROOT / "ansible/site.yml").read_text(encoding="utf-8")
ENV_TEMPLATE = (
    ROOT / "ansible/roles/docker_stack/templates/env.j2"
).read_text(encoding="utf-8")
TRAEFIK_ADM = (ROOT / "compose/traefik/dynamic-adm.yml").read_text(
    encoding="utf-8"
)
ADM_ZONE = (
    ROOT / "ansible/roles/docker_stack/templates/db.aigw.aegisgroup.ch.adm.j2"
).read_text(encoding="utf-8")
COMPOSE_WRAPPER = (ROOT / "scripts/aigw-compose.sh").read_text(encoding="utf-8")
VALIDATE_COMPOSE = (ROOT / "scripts/validate-compose.sh").read_text(encoding="utf-8")
STACK_ONLY = (ROOT / "ansible/deploy-stack-only.yml").read_text(encoding="utf-8")


def service_block(name: str, next_name: str) -> str:
    return COMPOSE.split(f"  {name}:\n", 1)[1].split(f"  {next_name}:\n", 1)[0]


class VaultUIProxyContractTests(unittest.TestCase):
    def test_ansible_flag_is_strictly_boolean_default_off_and_lab_on(self) -> None:
        self.assertRegex(ALL_VARS, r"(?m)^aigw_vault_ui_enabled: false$")
        self.assertRegex(GENERIC_VARS, r"(?m)^aigw_vault_ui_enabled: false$")
        self.assertRegex(LAB_VARS, r"(?m)^aigw_vault_ui_enabled: true$")
        self.assertIn("aigw_vault_ui_enabled is boolean", SITE)
        self.assertIn("aigw_vault_ui_enabled is boolean", STACK_ONLY)

    def test_positive_profile_gates_only_the_two_browser_services(self) -> None:
        oauth = service_block("oauth2-proxy-vault", "litellm")
        proxy = service_block("vault-ui-proxy", "vault")
        self.assertIn("profiles: [vault-ui]", oauth)
        self.assertIn("profiles: [vault-ui]", proxy)
        self.assertEqual(COMPOSE.count("profiles: [vault-ui]"), 2)
        self.assertIn("['vault-ui'] if (aigw_vault_ui_enabled | bool) else []", STACK)
        self.assertIn("+ (['--profile', 'vault-ui']", STACK)
        self.assertNotIn("aigw_compose_build_cli_overlay_args", STACK)
        self.assertGreaterEqual(STACK.count("+ aigw_compose_cli_overlay_args"), 4)
        self.assertNotIn("docker-compose.vault-ui-disabled.yml", ENV_TEMPLATE)
        self.assertNotIn("COMPOSE_PROFILES=", ENV_TEMPLATE)
        self.assertIn(
            "VAULT_UI_ENABLED={{ aigw_vault_ui_enabled | bool | lower }}",
            ENV_TEMPLATE,
        )
        self.assertIn("invalid Vault UI selector", COMPOSE_WRAPPER)
        self.assertIn("expected exactly one VAULT_UI_ENABLED selector", COMPOSE_WRAPPER)
        self.assertIn("COMPOSE_FILE COMPOSE_PROFILES", COMPOSE_WRAPPER)
        self.assertIn('export VAULT_UI_ENABLED="$vault_ui"', COMPOSE_WRAPPER)
        self.assertIn("compose+=(--profile vault-ui)", COMPOSE_WRAPPER)

    def test_compose_validation_uses_consistent_on_and_off_graphs(self) -> None:
        self.assertIn("COMPOSE_PROFILES=vault-ui", VALIDATE_COMPOSE)
        self.assertIn("VAULT_UI_ENABLED=true", VALIDATE_COMPOSE)
        self.assertIn("COMPOSE_PROFILES= VAULT_UI_ENABLED=false", VALIDATE_COMPOSE)
        self.assertIn(
            'model["traefik-adm"]["environment"]["VAULT_UI_ENABLED"] == "false"',
            VALIDATE_COMPOSE,
        )
        self.assertIn(
            'services["traefik-adm"]["environment"]["VAULT_UI_ENABLED"] == "true"',
            VALIDATE_COMPOSE,
        )
        self.assertIn('test "$vault_hash_enabled" = "$vault_hash_disabled"', VALIDATE_COMPOSE)
        self.assertIn(
            'test "$vault_volumes_enabled" = "$vault_volumes_disabled"',
            VALIDATE_COMPOSE,
        )
        self.assertIn('("vault_data", "vault_audit")', VALIDATE_COMPOSE)
        self.assertNotIn(
            'environment"]["VAULT_UI_ENABLED"] in {"true", "false"}',
            VALIDATE_COMPOSE,
        )

    def test_operator_wrapper_rejects_duplicate_toggle_and_clears_ambient_profiles(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            root = Path(raw_dir)
            for name in (
                "docker-compose.yml",
                "docker-compose.dns.yml",
            ):
                (root / name).touch()
            (root / ".env").write_text(
                "DEPLOYMENT_PROFILE=generic-rocky9\n"
                "PLATFORM_AUTHORITATIVE_DNS_ENABLED=false\n"
                "VAULT_UI_ENABLED=false\n"
                "VAULT_UI_ENABLED=true\n"
                "IDENTITY_LDAP_ENABLED=false\n",
                encoding="utf-8",
            )
            duplicate = subprocess.run(
                ["bash", str(ROOT / "scripts/aigw-compose.sh"), "config"],
                env={**os.environ, "STACK_DIR": str(root)},
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(duplicate.returncode, 2)
            self.assertIn(
                "expected exactly one VAULT_UI_ENABLED selector",
                duplicate.stderr,
            )

            (root / ".env").write_text(
                "DEPLOYMENT_PROFILE=generic-rocky9\n"
                "PLATFORM_AUTHORITATIVE_DNS_ENABLED=false\n"
                "VAULT_UI_ENABLED=false\n"
                "IDENTITY_LDAP_ENABLED=false\n",
                encoding="utf-8",
            )
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_docker = fake_bin / "docker"
            fake_docker.write_text(
                "#!/usr/bin/env bash\n"
                "printf 'profiles=%s file=%s vault=%s\\n' "
                "\"${COMPOSE_PROFILES-unset}\" \"${COMPOSE_FILE-unset}\" "
                "\"${VAULT_UI_ENABLED-unset}\"\n"
                "printf '%s\\n' \"$@\"\n",
                encoding="utf-8",
            )
            fake_docker.chmod(0o755)

            def invoke(*arguments: str, ambient_selector: str = "true") -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    ["bash", str(ROOT / "scripts/aigw-compose.sh"), *arguments],
                    env={
                    **os.environ,
                    "STACK_DIR": str(root),
                    "PATH": f"{fake_bin}:{os.environ['PATH']}",
                    "COMPOSE_PROFILES": "vault-ui",
                    "COMPOSE_FILE": "unreviewed.yml",
                    "VAULT_UI_ENABLED": ambient_selector,
                    },
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )

            clean = invoke("config")
            self.assertEqual(clean.returncode, 0, clean.stderr)
            self.assertIn("profiles=unset file=unset vault=false", clean.stdout)
            self.assertNotIn("vault-ui", clean.stdout)

            unrelated_profile = invoke("--profile", "diagnostics", "config")
            self.assertEqual(unrelated_profile.returncode, 0, unrelated_profile.stderr)
            self.assertIn("diagnostics", unrelated_profile.stdout)

            for arguments in (
                ("--profile", "vault-ui", "config"),
                ("--profile=vault-ui", "config"),
                ("--profile", "*", "config"),
                ("--profile=*", "config"),
                ("up", "oauth2-proxy-vault"),
                ("run", "--rm", "vault-ui-proxy", "check"),
                ("run", "--hostname", "foo", "vault-ui-proxy", "check"),
                ("up", "--scale=vault-ui-proxy=1"),
            ):
                rejected = invoke(*arguments)
                self.assertEqual(rejected.returncode, 2, arguments)
                self.assertIn("disabled by the deployed selector", rejected.stderr)

            read_only = invoke("logs", "vault-ui-proxy")
            self.assertEqual(read_only.returncode, 0, read_only.stderr)
            for arguments in (
                ("exec", "vault-ui-proxy", "check"),
                ("cp", "vault-ui-proxy:/tmp/a", "/tmp/a"),
                ("build", "vault-ui-proxy"),
                ("pull", "oauth2-proxy-vault"),
                ("push", "vault-ui-proxy"),
                ("pause", "vault-ui-proxy"),
                ("stop", "oauth2-proxy-vault"),
                ("kill", "vault-ui-proxy"),
                ("rm", "oauth2-proxy-vault"),
            ):
                allowed = invoke(*arguments)
                self.assertEqual(allowed.returncode, 0, arguments)

            (root / ".env").write_text(
                "DEPLOYMENT_PROFILE=generic-rocky9\n"
                "PLATFORM_AUTHORITATIVE_DNS_ENABLED=false\n"
                "VAULT_UI_ENABLED=true\n"
                "IDENTITY_LDAP_ENABLED=false\n",
                encoding="utf-8",
            )
            enabled = invoke("config", ambient_selector="false")
            self.assertEqual(enabled.returncode, 0, enabled.stderr)
            self.assertIn("profiles=unset file=unset vault=true", enabled.stdout)
            self.assertIn("vault-ui", enabled.stdout)

    def test_disabled_transition_removes_exact_ui_containers_only(self) -> None:
        removal = STACK.split(
            "- name: Inspect stale Vault browser-surface containers when disabled",
            1,
        )[1].split("\n- name: Read the effective Compose service set", 1)[0]
        self.assertIn('name: "{{ compose_project_name }}-{{ item }}-1"', removal)
        self.assertIn("- oauth2-proxy-vault", removal)
        self.assertIn("- vault-ui-proxy", removal)
        self.assertLess(
            removal.index("- oauth2-proxy-vault"),
            removal.index("- vault-ui-proxy"),
        )
        self.assertIn("com.docker.compose.project.working_dir", removal)
        self.assertIn("item.container.Id is match('^[0-9a-f]{64}$')", removal)
        self.assertIn("com.docker.compose.config-hash", removal)
        self.assertIn("com.docker.compose.oneoff", removal)
        self.assertIn("com.docker.compose.container-number", removal)
        self.assertIn("state: absent", removal)
        self.assertIn('name: "{{ item.container.Id }}"', removal)
        self.assertIn("keep_volumes: true", removal)
        self.assertNotIn("force_kill:", removal)
        self.assertIn("not (aigw_vault_ui_enabled | bool)", removal)
        self.assertNotIn("- vault\n", removal)
        self.assertLess(
            removal.index("Reconcile the ADM edge before removing stale Vault UI backends"),
            removal.index("Remove verified stale Vault browser-surface containers when disabled"),
        )
        self.assertLess(
            removal.index("Prove the disabled Vault host has no router before backend removal"),
            removal.index("Remove verified stale Vault browser-surface containers when disabled"),
        )
        self.assertIn('fields[1] != "404"', removal)
        self.assertIn('COMPOSE_PROFILES: ""', removal)
        compose_profile_pin = (
            'COMPOSE_PROFILES: ""\n'
            '    VAULT_UI_ENABLED: "{{ aigw_vault_ui_enabled | bool | lower }}"'
        )
        self.assertEqual(
            STACK.count('COMPOSE_PROFILES: ""'),
            STACK.count(compose_profile_pin),
        )
        # Exactly the removal reconciliation plus the explicit-argv/module
        # tasks keep an empty ambient profile set; every raw live-project
        # exec/query carries the reviewed joined profile set instead
        # (test_compose_profiles_exec_contract.py pins the full split).
        self.assertEqual(STACK.count('COMPOSE_PROFILES: ""'), 13)
        self.assertIn(
            "Prove disabled Vault browser-surface containers are absent, not stopped",
            VERIFY,
        )

    def test_route_and_platform_dns_follow_the_toggle(self) -> None:
        # Keep Traefik's Go-template actions inside YAML comments: Go still
        # executes the actions, while source-level YAML linters can parse the
        # unrendered file used by CI and offline review.
        condition = '# {{ if eq (env "VAULT_UI_ENABLED") "true" }}'
        self.assertEqual(TRAEFIK_ADM.count(condition), 2)
        self.assertEqual(TRAEFIK_ADM.count("# {{ end }}"), 2)
        self.assertIn("VAULT_UI_ENABLED: ${VAULT_UI_ENABLED:-false}", COMPOSE)
        vault_record = "vault        IN A {{ eth1_ip }}"
        self.assertIn(vault_record, ADM_ZONE)
        record_prefix = ADM_ZONE.split(vault_record, 1)[0]
        self.assertTrue(record_prefix.rstrip().endswith("{% if aigw_vault_ui_enabled | bool %}"))
        self.assertIn("Verify disabled Vault UI is absent from the ADM DNS view", VERIFY)
        self.assertIn("'status: NXDOMAIN'", VERIFY)
        self.assertGreaterEqual(VERIFY.count("loop: [udp, tcp]"), 2)
        self.assertGreaterEqual(VERIFY.count("'+tcp' if item == 'tcp' else '+notcp'"), 2)
        restricted = VERIFY.split(
            "Verify the restricted platform DNS view does not disclose ADM-only names",
            1,
        )[1].split("Prove the restricted DNS view cannot recurse public names", 1)[0]
        self.assertIn(
            '{ name: "vault.{{ aigw_domain }}", transport: +notcp }',
            restricted,
        )
        self.assertIn(
            '{ name: "vault.{{ aigw_domain }}", transport: +tcp }',
            restricted,
        )
        self.assertIn(
            "'302' if (aigw_vault_ui_enabled | bool) else '404'", VERIFY
        )

    def test_internal_vault_api_is_not_feature_gated(self) -> None:
        vault = service_block("vault", "postgres")
        self.assertNotIn("profiles:", vault)
        self.assertIn("networks: [net-vault]", vault)
        self.assertIn("vault_data:/vault/data", vault)
        self.assertIn("vault_audit:/vault/logs", vault)

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
