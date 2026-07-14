"""Regression tests for Docker health probes that gate a deployment."""

from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "compose" / "docker-compose.yml"
DOCKER_STACK_TASKS = ROOT / "ansible" / "roles" / "docker_stack" / "tasks" / "main.yml"
VAULT_BOOTSTRAP = ROOT / "scripts" / "vault-bootstrap.sh"


class HealthcheckContractTests(unittest.TestCase):
    @staticmethod
    def _service_block(compose: str, name: str, next_name: str) -> str:
        return compose.split(f"  {name}:\n", 1)[1].split(
            f"  {next_name}:\n", 1
        )[0]

    @staticmethod
    def _duration_seconds(block: str, field: str) -> int:
        match = re.search(rf"^      {field}: (\d+)s$", block, re.MULTILINE)
        if match is None:
            raise AssertionError(f"missing {field} duration")
        return int(match.group(1))

    def test_litellm_uses_database_readiness_not_process_liveness(self) -> None:
        compose = COMPOSE.read_text(encoding="utf-8")
        service = self._service_block(compose, "litellm", "open-webui")

        self.assertIn("http://127.0.0.1:4000/health/readiness", service)
        self.assertNotIn("http://127.0.0.1:4000/health/liveliness", service)

    def test_first_vault_bootstrap_does_not_deadlock_admin_portal_startup(self) -> None:
        compose = COMPOSE.read_text(encoding="utf-8")
        admin_portal = self._service_block(compose, "admin-portal", "envoy-egress")

        # key-rotator intentionally remains unready while a fresh Vault is
        # uninitialized. The portal's application routes still authorize each
        # controller operation, so Compose may wait only for the process to
        # start and must not block the approved bootstrap ceremony.
        self.assertIn("key-rotator: { condition: service_started }", admin_portal)
        self.assertNotIn("key-rotator: { condition: service_healthy }", admin_portal)

    def test_rotator_liveness_and_dependency_readiness_are_separate(self) -> None:
        compose = COMPOSE.read_text(encoding="utf-8")
        service = self._service_block(compose, "key-rotator", "vault-ui-proxy")
        tasks = DOCKER_STACK_TASKS.read_text(encoding="utf-8")

        self.assertIn("http://127.0.0.1:8080/healthz", service)
        self.assertNotIn("http://127.0.0.1:8080/readyz", service)
        self.assertIn(
            "Probe strict key-rotator dependency readiness after stack start",
            tasks,
        )
        self.assertIn("http://127.0.0.1:8080/readyz", tasks)
        self.assertIn("key_rotator_strict_readiness.rc == 0", tasks)
        self.assertIn("key_rotator_strict_readiness.rc != 0", tasks)

    def test_automated_wait_gates_cover_the_longest_health_window(self) -> None:
        compose = COMPOSE.read_text(encoding="utf-8")
        open_webui = self._service_block(compose, "open-webui", "keycloak")
        budget = (
            self._duration_seconds(open_webui, "start_period")
            + self._duration_seconds(open_webui, "interval")
            * int(re.search(r"^      retries: (\d+)$", open_webui, re.MULTILINE).group(1))
        )
        # The clean-deploy gate must allow the service's complete health window
        # and at least one full health interval for scheduling jitter.
        minimum_timeout = budget + self._duration_seconds(open_webui, "interval")
        self.assertEqual(budget, 450)

        task_timeouts = [
            int(value)
            for value in re.findall(
                r"^    wait_timeout: (\d+)$",
                DOCKER_STACK_TASKS.read_text(encoding="utf-8"),
                re.MULTILINE,
            )
        ]
        self.assertGreaterEqual(len(task_timeouts), 2)
        self.assertTrue(all(value >= minimum_timeout for value in task_timeouts))
        self.assertIn(
            f"--wait-timeout {max(task_timeouts)}",
            VAULT_BOOTSTRAP.read_text(encoding="utf-8"),
        )

    def test_vault_bootstrap_refuses_existing_state_and_commits_init_atomically(self) -> None:
        source = VAULT_BOOTSTRAP.read_text(encoding="utf-8")

        # Vault status returns exit code 2 for both sealed and uninitialized
        # states. The lab bootstrap must parse the public JSON and allow only a
        # genuinely fresh Vault, never accidentally initialize an existing one.
        self.assertIn('vlt status -format=json', source)
        self.assertIn('false:true)', source)
        self.assertIn('true:*)', source)
        self.assertIn('Vault is already initialized', source)
        self.assertIn('scripts/vault-unseal.sh', source)

        # A failed `operator init` must not leave a partial secret response at
        # the durable path. Keep it private in the same directory, validate it,
        # then use the same-filesystem rename as the sole durable commit.
        self.assertIn('mktemp "secrets/.vault-init.json.XXXXXX"', source)
        self.assertIn('trap cleanup_vault_init_tmp EXIT', source)
        self.assertIn('trap abort_vault_init_tmp HUP INT TERM', source)
        self.assertIn(
            'vlt operator init -key-shares=1 -key-threshold=1 -format=json > "$vault_init_tmp"',
            source,
        )
        self.assertIn('Vault init response was incomplete', source)
        self.assertIn('mv -f -- "$vault_init_tmp" secrets/vault-init.json', source)
        self.assertIn('vault_init_tmp=""', source)
        self.assertNotIn(
            'vlt operator init -key-shares=1 -key-threshold=1 -format=json > secrets/vault-init.json',
            source,
        )


if __name__ == "__main__":
    unittest.main()
