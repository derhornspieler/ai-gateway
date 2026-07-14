"""Ambient Compose-profile contracts for raw `docker compose` Ansible tasks.

Modern Docker Compose validates the complete project model even for `exec`
and other live-project queries. A raw `docker compose exec` task resolves the
project only from the deployed .env (whose COMPOSE_FILE includes the lab
overlay on lab hosts) plus the process environment, so a task that empties
COMPOSE_PROFILES excludes the profile-gated samba-ad service while the lab
overlay's keycloak depends_on still references it, and Compose rejects the
whole project: `service "keycloak" depends on undefined service "samba-ad"`.

Live-project exec/query tasks must therefore carry the reviewed joined
profile set. An empty ambient COMPOSE_PROFILES stays legal only where the
task already passes files and profiles explicitly (docker_compose_v2
`profiles:` or aigw_compose_cli_overlay_args) — including the Vault UI
removal reconciliation, where profile-gated services must remain removable
orphans.
"""

from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
STACK = (
    ROOT / "ansible/roles/docker_stack/tasks/main.yml"
).read_text(encoding="utf-8")
VERIFY = (ROOT / "ansible/roles/verify/tasks/main.yml").read_text(
    encoding="utf-8"
)

JOINED_PROFILES = (
    "COMPOSE_PROFILES: \"{{ aigw_compose_profiles | join(',') }}\""
)
EMPTY_PROFILES = 'COMPOSE_PROFILES: ""'
VAULT_UI_SELECTOR = (
    'VAULT_UI_ENABLED: "{{ aigw_vault_ui_enabled | bool | lower }}"'
)

# Raw `docker ... compose exec` argv tasks with no explicit --file/--profile
# arguments: the live project is resolved from the deployed .env, so the
# reviewed profile set must stay active in the task environment.
STACK_EXEC_TASKS = (
    "Wait for PostgreSQL local-socket readiness",
    "Reconcile PostgreSQL roles, passwords, databases, and CONNECT ACLs",
    "Read the exact PostgreSQL service-role security matrix",
    "Read public Vault initialization and seal state before automatic unseal",
    "Re-read public Vault state after the automatic-unseal decision",
    "Probe strict Vault readiness after the automatic-unseal decision",
    "Probe strict key-rotator dependency readiness after stack start",
)

# Reviewed empty-ambient-profile sites. Every one of these supplies the
# profile set explicitly (module `profiles:` parameter or
# aigw_compose_cli_overlay_args), so emptying the ambient variable only
# prevents implicit reactivation of optional services — it never redefines
# the project model an exec-style command must validate. The ADM edge
# reconciliation is additionally pinned by the Vault UI removal contract in
# test_vault_ui_proxy_contract.py.
STACK_EMPTY_PROFILE_TASKS = (
    "Reconcile the ADM edge before removing stale Vault UI backends",
    "Read the effective Compose service set",
    "Read the desired volume initializer configuration hash",
    "Run the versioned volume initializer when required",
    "Start PostgreSQL before credential reconciliation",
    "Render effective Compose model for the custom-image build planner",
    "Build only missing or build-input-changed custom images",
    "Deploy stack without implicitly rebuilding custom images",
    "Wait for Keycloak before first pre-Vault identity recovery",
    "Wait for Keycloak before applicable pre-bootstrap OIDC scope reconciliation",
    "Wait for Keycloak before managed OIDC redirect-URI reconciliation",
    "Wait for the complete post-bootstrap stack",
    "Wait only for bootstrap-independent core on first converge",
)

VERIFY_EXEC_TASKS = (
    "Samba lab directory database is internally consistent",
)


def split_tasks(source: str) -> dict[str, str]:
    """Map top-level task names to their body text (nested blocks included)."""
    chunks = re.split(r"(?m)^- name: ", source)[1:]
    tasks: dict[str, str] = {}
    for chunk in chunks:
        name, _, body = chunk.partition("\n")
        assert name.strip() not in tasks, f"duplicate task name: {name!r}"
        tasks[name.strip()] = body
    return tasks


def raw_compose_exec_tasks(tasks: dict[str, str]) -> set[str]:
    """Task names whose argv invokes the raw `docker ... compose exec` CLI."""
    return {
        name
        for name, body in tasks.items()
        if re.search(r"(?m)^\s+- docker$", body)
        and re.search(r"(?m)^\s+- compose$", body)
        and re.search(r"(?m)^\s+- exec$", body)
    }


class ComposeProfilesExecContractTests(unittest.TestCase):
    def test_stack_live_project_execs_carry_the_reviewed_profile_set(self) -> None:
        tasks = split_tasks(STACK)
        self.assertEqual(raw_compose_exec_tasks(tasks), set(STACK_EXEC_TASKS))
        for name in STACK_EXEC_TASKS:
            body = tasks[name]
            self.assertIn(JOINED_PROFILES, body, name)
            self.assertIn(VAULT_UI_SELECTOR, body, name)
            self.assertNotIn(EMPTY_PROFILES, body, name)
        self.assertEqual(
            STACK.count(JOINED_PROFILES), len(STACK_EXEC_TASKS)
        )

    def test_stack_empty_ambient_profiles_only_at_explicit_profile_sites(self) -> None:
        tasks = split_tasks(STACK)
        empty_sites = {
            name for name, body in tasks.items() if EMPTY_PROFILES in body
        }
        self.assertEqual(empty_sites, set(STACK_EMPTY_PROFILE_TASKS))
        self.assertEqual(
            STACK.count(EMPTY_PROFILES), len(STACK_EMPTY_PROFILE_TASKS)
        )
        for name in STACK_EMPTY_PROFILE_TASKS:
            body = tasks[name]
            self.assertTrue(
                'profiles: "{{ aigw_compose_profiles }}"' in body
                or "+ aigw_compose_cli_overlay_args" in body,
                f"{name}: empty ambient COMPOSE_PROFILES without an explicit "
                "module/argv profile selection",
            )

    def test_verify_lab_exec_carries_the_reviewed_profile_set(self) -> None:
        tasks = split_tasks(VERIFY)
        self.assertEqual(raw_compose_exec_tasks(tasks), set(VERIFY_EXEC_TASKS))
        for name in VERIFY_EXEC_TASKS:
            body = tasks[name]
            self.assertIn(JOINED_PROFILES, body, name)
            self.assertIn(VAULT_UI_SELECTOR, body, name)
        self.assertNotIn(EMPTY_PROFILES, VERIFY)


if __name__ == "__main__":
    unittest.main()
