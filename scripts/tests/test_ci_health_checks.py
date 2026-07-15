"""Contracts for the CI health checks that guard runtime and shell defects.

The runtime canary is only worth running if it asserts *the same* live-container
contracts the Ansible verify role asserts. If the verify role tightens its tmpfs
token set and the canary does not, CI reports green while a converge fails on the
customer host — the exact failure the canary exists to predict. These tests tie
the two together, and tie the ShellCheck target list to the shell that actually
ships, so a new script cannot quietly escape the linter.
"""

from __future__ import annotations

import ast
import importlib.util
import re
import subprocess
import unittest
from pathlib import Path
from types import ModuleType


ROOT = Path(__file__).resolve().parents[2]

VERIFY = (ROOT / "ansible/roles/verify/tasks/main.yml").read_text(encoding="utf-8")
COMPOSE = (ROOT / "compose/docker-compose.yml").read_text(encoding="utf-8")
SHELLCHECK = (ROOT / ".github/scripts/run-shellcheck.sh").read_text(encoding="utf-8")
SKEW = (ROOT / ".github/workflows/runtime-skew.yml").read_text(encoding="utf-8")
HYGIENE = (ROOT / ".github/workflows/repo-hygiene.yml").read_text(encoding="utf-8")
SCORECARD = (ROOT / ".github/workflows/scorecard.yml").read_text(encoding="utf-8")

NEW_WORKFLOWS = {
    ".github/workflows/runtime-skew.yml": SKEW,
    ".github/workflows/repo-hygiene.yml": HYGIENE,
    ".github/workflows/scorecard.yml": SCORECARD,
}

# Python's import system cannot import a hyphenated path as a module.
def load(relative: str) -> ModuleType:
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(path.stem.replace("-", "_"), path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CANARY = load(".github/scripts/compose-engine-canary.py")
DRIFT = load(".github/scripts/contract-drift-guard.py")


def literal_set(pattern: str, text: str) -> set[str]:
    match = re.search(pattern, text, re.DOTALL)
    assert match is not None, f"contract source moved: {pattern}"
    return set(ast.literal_eval(match.group(1)))


class RuntimeCanaryMatchesTheVerifyRole(unittest.TestCase):
    """The canary must predict exactly the assertions the converge will make."""

    def test_open_webui_tmpfs_tokens_match_the_verify_role(self) -> None:
        required = literal_set(
            r"not (\{[^}]*\}) <= tmpfs_options\s*\n\s*or \"ro\" in tmpfs_options",
            VERIFY,
        )
        self.assertEqual(CANARY.OPEN_WEBUI_REQUIRED_TOKENS, required)

    def test_grafana_plugin_tmpfs_tokens_match_the_verify_role(self) -> None:
        required = literal_set(
            r"required_plugin_options = (\{[^}]*\})", VERIFY
        )
        self.assertEqual(CANARY.GRAFANA_REQUIRED_TOKENS, required)

    def test_verify_role_proves_writability_by_the_absence_of_ro(self) -> None:
        # A tmpfs is read-write unless "ro" is present. The verify role must
        # never require a literal "rw" (an Engine may not normalize it in) and
        # must reject "ro" — which also catches a pathological "rw,ro", where
        # the kernel honours the last token and mounts read-only.
        self.assertIn('or "ro" in tmpfs_options', VERIFY)
        self.assertIn('or "ro" in plugin_options', VERIFY)
        self.assertEqual(CANARY.FORBIDDEN_TMPFS_TOKEN, "ro")
        self.assertNotIn("rw", CANARY.GRAFANA_REQUIRED_TOKENS)
        self.assertNotIn("rw", CANARY.OPEN_WEBUI_REQUIRED_TOKENS)

    def test_canary_replays_the_real_compose_tmpfs_specs(self) -> None:
        # The grafana spec deliberately omits `rw`: older engines added it
        # implicitly. Replaying the spec verbatim is what makes the canary able
        # to detect a change in what the Engine materialises.
        self.assertIn(f'tmpfs: ["{CANARY.OPEN_WEBUI_TMPFS_SPEC}"]', COMPOSE)
        self.assertIn(f"- {CANARY.GRAFANA_TMPFS_SPEC}", COMPOSE)
        self.assertNotIn("rw", CANARY.GRAFANA_TMPFS_SPEC)

    def test_canary_exercises_the_joined_profile_exec_contract(self) -> None:
        # Contract A: the emptied-COMPOSE_PROFILES trap that broke exec-style
        # tasks. The canary must drive profiles through the *environment*, exactly
        # as an Ansible task does. Passing --profile would resolve the project a
        # different way and would not reproduce the failure at all.
        source = (ROOT / ".github/scripts/compose-engine-canary.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('env={"COMPOSE_PROFILES": profiles}', source)
        # `--profile` may be discussed in a comment, but must never be an argv token.
        self.assertNotIn('"--profile"', source)
        # A default service whose overlay dependency is profile-gated: the exact
        # shape of the lab overlay's keycloak -> samba-ad edge.
        self.assertIn(f"profiles: [{CANARY.GATED_PROFILE}]", CANARY.OVERLAY_COMPOSE)
        self.assertIn("condition: service_started", CANARY.OVERLAY_COMPOSE)

    def test_canary_pulls_no_base_image_in_ci(self) -> None:
        # A registry-dependent canary is a rate-limited canary. The probe image
        # is FROM scratch, and CI supplies Go so the pinned builder never runs.
        self.assertIn("FROM scratch", CANARY.PROBE_DOCKERFILE)
        self.assertIn("pull_policy: never", CANARY.BASE_COMPOSE)
        self.assertRegex(CANARY.GO_BUILDER_IMAGE, r"^golang:[\w.\-]+@sha256:[0-9a-f]{64}$")


class ShellCheckCoversEveryShippedShell(unittest.TestCase):
    # ShellCheck cannot parse Jinja: `{{ }}` is a syntax error to it. These
    # templates render into root-run firewall and policy-routing scripts on the
    # customer VM, so this is a real coverage gap, not a shrug — it is recorded
    # here so adding a new .j2 is a deliberate choice, and the rendered contracts
    # stay pinned by the exact-string tests elsewhere in scripts/tests.
    UNLINTABLE_JINJA = {
        "ansible/roles/firewalld_zones/templates/91-aigw-firewalld-zones.j2",
        "ansible/roles/firewalld_zones/templates/aigw-host-input-rules.sh.j2",
        "ansible/roles/firewalld_zones/templates/docker-user-rules.sh.j2",
        "ansible/roles/network_routing/templates/aigw-policy-routing.sh.j2",
    }

    def tracked_shell(self) -> set[str]:
        listed = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.split()
        shell: set[str] = set()
        for name in listed:
            path = ROOT / name
            if not path.is_file():
                continue
            if name.endswith(".sh"):
                shell.add(name)
                continue
            try:
                first = path.read_text(encoding="utf-8", errors="strict").split(
                    "\n", 1
                )[0]
            except (UnicodeDecodeError, OSError):
                continue
            if re.match(r"^#!.*\b(ba)?sh\b", first):
                shell.add(name)
        return shell

    def test_every_tracked_shell_file_is_linted_or_explicitly_excluded(self) -> None:
        # A linter that silently stops covering a file is worse than no linter:
        # a new root-run script must be linted or consciously excluded, never
        # merely forgotten.
        targets = set(
            re.findall(r"^  (\S+)$", SHELLCHECK.split("TARGETS=(", 1)[1], re.MULTILINE)
        )
        unaccounted = self.tracked_shell() - targets - self.UNLINTABLE_JINJA
        self.assertEqual(unaccounted, set())

    def test_the_jinja_exclusions_still_exist_and_are_still_unparseable(self) -> None:
        # If a template stops being Jinja, it must come back under the linter.
        for excluded in self.UNLINTABLE_JINJA:
            path = ROOT / excluded
            with self.subTest(template=excluded):
                self.assertTrue(path.is_file())
                self.assertIn("{{", path.read_text(encoding="utf-8"))

    def test_shellcheck_is_pinned_by_tag_and_digest(self) -> None:
        self.assertRegex(
            SHELLCHECK,
            r'SHELLCHECK_IMAGE="koalaman/shellcheck:v[\d.]+@sha256:[0-9a-f]{64}"',
        )

    def test_error_severity_blocks_and_info_severity_only_reports(self) -> None:
        self.assertIn("run: bash .github/scripts/run-shellcheck.sh error", HYGIENE)
        self.assertIn('findings="$(bash .github/scripts/run-shellcheck.sh info)"', HYGIENE)
        self.assertIn("::warning title=ShellCheck::", HYGIENE)


class ContractDriftGuardStaysAdvisory(unittest.TestCase):
    def test_guarded_surfaces_are_the_contract_pinned_surfaces(self) -> None:
        self.assertEqual(
            set(DRIFT.GUARDED_SURFACES),
            {"ansible/", "compose/", "scripts/", ".github/workflows/"},
        )

    def test_a_reviewed_edit_without_a_contract_update_is_reported(self) -> None:
        touched, evidence = DRIFT.classify(
            ["ansible/roles/verify/tasks/main.yml", "compose/docker-compose.yml"]
        )
        self.assertEqual(sorted(touched), ["ansible/", "compose/"])
        self.assertEqual(evidence, [])

    def test_a_contract_test_or_validator_change_clears_the_guard(self) -> None:
        for proof in (
            "scripts/tests/test_selinux_contract.py",
            "scripts/validate-compose.sh",
            "scripts/validate-identity-policy.py",
        ):
            _, evidence = DRIFT.classify(["ansible/roles/verify/tasks/main.yml", proof])
            self.assertEqual(evidence, [proof])

    def test_documentation_only_changes_are_silent(self) -> None:
        touched, _ = DRIFT.classify(["docs/test-runbook.md", "README.md"])
        self.assertEqual(touched, {})

    def test_the_guard_never_blocks_a_merge(self) -> None:
        source = (ROOT / ".github/scripts/contract-drift-guard.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("Always exits 0.", source)
        self.assertNotIn("exit(1)", source)
        self.assertIn("::warning title=Contract-test drift::", source)


class NewWorkflowsFollowTheHouseSupplyChainStyle(unittest.TestCase):
    def test_every_action_reference_is_pinned_to_a_full_commit_sha(self) -> None:
        for name, text in NEW_WORKFLOWS.items():
            for reference in re.findall(r"uses: (\S+)", text):
                with self.subTest(workflow=name, uses=reference):
                    self.assertRegex(reference, r"^[\w.\-]+/[\w./\-]+@[0-9a-f]{40}$")

    def test_top_level_permissions_are_read_only(self) -> None:
        for name, text in NEW_WORKFLOWS.items():
            with self.subTest(workflow=name):
                self.assertIn("permissions:\n  contents: read\n", text)

    def test_checkouts_never_persist_credentials(self) -> None:
        for name, text in NEW_WORKFLOWS.items():
            with self.subTest(workflow=name):
                self.assertEqual(
                    text.count("uses: actions/checkout@"),
                    text.count("persist-credentials: false"),
                )

    def test_every_workflow_has_a_concurrency_group(self) -> None:
        for name, text in NEW_WORKFLOWS.items():
            with self.subTest(workflow=name):
                self.assertIn("concurrency:\n  group: ", text)
                self.assertIn("cancel-in-progress: true", text)

    def test_the_skew_canary_is_advisory_but_can_be_run_strict(self) -> None:
        # Upstream must not be able to red-wall unrelated pull requests, but a
        # harness fault is our own bug and still fails.
        self.assertIn("strict:", SKEW)
        self.assertIn("if: steps.canary.outputs.code == '1' && inputs.strict", SKEW)
        self.assertIn("::error title=Canary harness fault::", SKEW)
        self.assertIn("channel: [runner, upstream]", SKEW)
        # The upstream leg fetches a release binary over the network (the version
        # a future pin bump would adopt), so it must verify what it downloads.
        self.assertIn('sha256sum -c "$asset.sha256"', SKEW)

    def test_scorecard_does_not_publish_this_prototype_externally(self) -> None:
        self.assertIn("publish_results: false", SCORECARD)
        self.assertNotIn("id-token: write", SCORECARD)


if __name__ == "__main__":
    unittest.main()
