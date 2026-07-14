"""Regression contract for local-only Compose validation on Linux and macOS."""

from __future__ import annotations

from pathlib import Path
import subprocess
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "validate-compose.sh"
COMPOSE = SOURCE.parents[1] / "compose" / "docker-compose.yml"
DOCKER_STACK_TASKS = (
    SOURCE.parents[1] / "ansible" / "roles" / "docker_stack" / "tasks" / "main.yml"
)


class ValidateComposeSocketContractTests(unittest.TestCase):
    def test_platform_selected_unix_socket_cannot_inherit_a_remote_context(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn(
            "unset DOCKER_CONTEXT DOCKER_HOST DOCKER_TLS DOCKER_TLS_VERIFY DOCKER_CERT_PATH DOCKER_API_VERSION",
            source,
        )
        self.assertIn('Linux) docker_local_host=unix:///run/docker.sock ;;', source)
        self.assertIn('Darwin) docker_local_host=unix:///var/run/docker.sock ;;', source)
        self.assertIn('export AIGW_LOCAL_DOCKER_HOST="$docker_local_host"', source)
        self.assertIn(
            'docker --host "$AIGW_LOCAL_DOCKER_HOST" compose', source
        )

        runtime = source.split("env \\\n", 1)[1].split("  ' sh \"$ROOT\" \"$COMPOSE_DIR\"", 1)[0]
        self.assertNotIn("docker --host unix:///run/docker.sock compose", runtime)
        self.assertNotIn("docker --host unix:///var/run/docker.sock compose", runtime)
        self.assertNotIn("$DOCKER_HOST", runtime)

    def test_script_remains_parseable(self) -> None:
        result = subprocess.run(
            ["bash", "-n", str(SOURCE)], text=True, capture_output=True, check=False
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_deployed_render_gate_runs_after_env_and_before_container_work(self) -> None:
        tasks = DOCKER_STACK_TASKS.read_text(encoding="utf-8")
        env = tasks.index("- name: Template .env only after every bind-source digest is final")
        gate = tasks.index(
            "- name: Validate render-only Compose and restricted build-network contracts"
        )
        first_container_boundary = tasks.index(
            "- name: Inventory every existing Docker container before persistent relabeling"
        )
        first_compose_start = tasks.index(
            "- name: Deploy stack without implicitly rebuilding custom images"
        )
        self.assertLess(env, gate)
        self.assertLess(gate, first_container_boundary)
        self.assertLess(gate, first_compose_start)

    def test_acl_validator_tracks_the_selinux_compatible_socket_boundary(self) -> None:
        validator = SOURCE.read_text(encoding="utf-8")
        tasks = DOCKER_STACK_TASKS.read_text(encoding="utf-8")
        self.assertIn('assert "BindReadOnlyPaths=/run/docker.sock" not in unit', validator)
        self.assertNotIn("BindReadOnlyPaths=/run/docker.sock\n", tasks)

    def test_lab_dns_administrative_view_is_rendered_and_bound_read_only(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        for required in (
            "LAB_DNS_ADM_CIDR=10.8.10.0/24",
            'dns["environment"] == {"LAB_DNS_ADM_CIDR": "10.8.10.0/24"}',
            'if mount["target"] == "/etc/coredns/zones/db.aigw.aegisgroup.ch.adm"',
            'assert adm_zone["read_only"] is True',
            'assert adm_zone["bind"]["selinux"] == "Z"',
            "LAB_DNS_ADM_CIDR: ${LAB_DNS_ADM_CIDR:?LAB_DNS_ADM_CIDR must be set}",
            "expr incidr(client_ip(), '{$LAB_DNS_ADM_CIDR}')",
            'SERVICES_DIR="$ROOT/services"',
            '"$SERVICES_DIR/lab-dns/Corefile"',
            're.search(r"(?m)^\\s*forward(?:\\s|$)", corefile) is None',
        ):
            self.assertIn(required, source)
        self.assertNotIn('"$COMPOSE_DIR/services/lab-dns/Corefile"', source)

    def test_openwebui_secure_cookie_flags_are_rendered_exactly(self) -> None:
        validator = SOURCE.read_text(encoding="utf-8")
        compose = COMPOSE.read_text(encoding="utf-8")
        for flag in ("WEBUI_SESSION_COOKIE_SECURE", "WEBUI_AUTH_COOKIE_SECURE"):
            self.assertIn(f'{flag}: "true"', compose)
            self.assertIn(
                f'services["open-webui"]["environment"]["{flag}"] == "true"',
                validator,
            )
        for required in (
            "dockerfile: Dockerfile.open-webui",
            "image: ai-gateway/open-webui:0.10.2-aigw1",
            "BASE_IMAGE: ghcr.io/open-webui/open-webui:v0.10.2@sha256:9fcea9c6e32ab60b0498f3986c6cdf651ddbe61db48d2213a3d28048ddd673d4",
        ):
            self.assertIn(required, compose)
        for required in (
            'services["open-webui"]["build"]["dockerfile"] == "Dockerfile.open-webui"',
            'services["open-webui"]["image"] == "ai-gateway/open-webui:0.10.2-aigw1"',
            'services["open-webui"]["build"]["args"]["BASE_IMAGE"] == (',
            "9fcea9c6e32ab60b0498f3986c6cdf651ddbe61db48d2213a3d28048ddd673d4",
        ):
            self.assertIn(required, validator)

    def test_openwebui_nonroot_readonly_contract_is_rendered_and_validated(self) -> None:
        validator = SOURCE.read_text(encoding="utf-8")
        compose = COMPOSE.read_text(encoding="utf-8")
        for required in (
            'user: "65532:65532"',
            "read_only: true",
            'tmpfs: ["/tmp:rw,noexec,nosuid,nodev,mode=1777,size=256m"]',
            "HOME: /app/backend/data",
            'PYTHONNOUSERSITE: "1"',
            'PYTHONDONTWRITEBYTECODE: "1"',
            "STATIC_DIR: /tmp/static",
            "openwebui_data:/app/backend/data",
            "openwebui_data:/state/openwebui",
            "chown -hR 65532:65532 /state/openwebui && chmod 0700 /state/openwebui",
            "volume-init: { condition: service_completed_successfully }",
        ):
            self.assertIn(required, compose)
        for required in (
            'open_webui["user"] == "65532:65532"',
            'open_webui["read_only"] is True',
            'open_webui["tmpfs"] == ["/tmp:rw,noexec,nosuid,nodev,mode=1777,size=256m"]',
            'open_webui["environment"]["STATIC_DIR"] == "/tmp/static"',
            'volume_init_mounts["/state/openwebui"]',
        ):
            self.assertIn(required, validator)


if __name__ == "__main__":
    unittest.main()
