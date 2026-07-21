"""Static regressions for the host/container SELinux hand-off."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
STACK_TASKS = ROOT / "ansible/roles/docker_stack/tasks/main.yml"
VERIFY_TASKS = ROOT / "ansible/roles/verify/tasks/main.yml"
ENV_TEMPLATE = ROOT / "ansible/roles/docker_stack/templates/env.j2"
COMPOSE = ROOT / "compose/docker-compose.yml"
FULL_SITE = ROOT / "ansible/site.yml"
OS_PREP = ROOT / "ansible/os-prep.yml"
STACK_ONLY_PLAYBOOK = ROOT / "ansible/deploy-stack-only.yml"
SELINUX_BASELINE = ROOT / "ansible/roles/selinux_baseline/tasks/main.yml"
VAULT_VALIDATOR = ROOT / "scripts/validate-vault-config.sh"


class VaultConfigValidationTests(unittest.TestCase):
    def run_validator(self, docker_script: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            stack_dir = temp_path / "stack"
            config_dir = stack_dir / "vault"
            fake_bin = temp_path / "bin"
            config_dir.mkdir(parents=True)
            fake_bin.mkdir()
            (config_dir / "config.hcl").write_text("storage \"file\" {}\n", encoding="utf-8")

            fake_stat = fake_bin / "stat"
            fake_stat.write_text("#!/bin/sh\nprintf '%s\\n' '0:0:644:1'\n", encoding="utf-8")
            fake_stat.chmod(0o755)
            fake_docker = fake_bin / "docker"
            fake_docker.write_text(docker_script, encoding="utf-8")
            fake_docker.chmod(0o755)

            env = os.environ.copy()
            env["PATH"] = f"{fake_bin}{os.pathsep}{env['PATH']}"
            env["STACK_DIR"] = str(stack_dir)
            return subprocess.run(
                ["bash", str(VAULT_VALIDATOR)],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )

    def test_docker_failure_reports_stderr_and_pinned_image(self) -> None:
        result = self.run_validator(
            "#!/bin/sh\n"
            "echo 'failed to fetch anonymous token: 401 Unauthorized' >&2\n"
            "exit 1\n"
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("failed to fetch anonymous token: 401 Unauthorized", result.stderr)
        self.assertIn(
            "dhi.io/vault:2.0.3@sha256:2c0ef85b70b3b643d71593ecfcb4a5292a51b25b69c52c4457962762f2152f0e",
            result.stderr,
        )
        self.assertIn("image, registry, or Docker daemon problem", result.stderr)
        self.assertIn("docs/offline-image-seed.md", result.stderr)
        self.assertNotIn("JSONDecodeError", result.stderr)

    def test_valid_report_succeeds_despite_nonzero_docker_exit(self) -> None:
        result = self.run_validator(
            "#!/bin/sh\n"
            "printf '%s\\n' '{\"children\":[{\"name\":\"Parse Configuration\",\"status\":\"ok\"}]}'\n"
            "echo 'unrelated telemetry diagnostic failed' >&2\n"
            "exit 2\n"
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Static Vault configuration parses successfully", result.stdout)
        self.assertNotIn("unrelated telemetry diagnostic failed", result.stderr)

    def test_missing_successful_parse_configuration_fails(self) -> None:
        result = self.run_validator(
            "#!/bin/sh\n"
            "printf '%s\\n' '{\"children\":[{\"name\":\"Parse Configuration\",\"status\":\"error\"}]}'\n"
            "exit 0\n"
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "Vault configuration parse did not report status=ok", result.stderr
        )
        self.assertNotIn("image, registry, or Docker daemon problem", result.stderr)


class SelinuxContractTests(unittest.TestCase):
    def test_restorecon_never_erases_an_existing_containers_mcs_range(self) -> None:
        source = STACK_TASKS.read_text(encoding="utf-8")
        inventory = source.split(
            "- name: Inventory every existing Docker container before persistent relabeling",
            1,
        )[1].split(
            "- name: Define the exact SELinux read-only bind-source boundary", 1
        )[0]
        self.assertIn(
            "docker\n      - --host\n      - unix:///run/docker.sock\n      - ps\n      - -aq",
            inventory,
        )
        self.assertNotIn("--filter", inventory)

        restore = source.split(
            "- name: Apply the reviewed read-only container contexts before Compose", 1
        )[1].split("- name: Read effective SELinux contexts", 1)[0]
        self.assertIn("restorecon", restore)
        self.assertIn(
            "when: aigw_containers_before_selinux.stdout_lines | length == 0",
            restore,
        )

    def test_live_verifier_checks_private_and_shared_bind_contexts(self) -> None:
        source = VERIFY_TASKS.read_text(encoding="utf-8")
        for required in (
            'container.get("Mounts")',
            'mount.get("Type") != "bind"',
            'mount.get("Mode")',
            'mount.get("RW") is not False',
            'relabel == {"Z"}',
            'expected_context = mount_label',
            "private bind MCS drift",
            "shared bind context drift",
            "bind-objects=",
        ):
            self.assertIn(required, source)

    def test_full_verify_requires_active_docker_selinux_and_live_mcs_labels(self) -> None:
        source = VERIFY_TASKS.read_text(encoding="utf-8")
        for required in (
            "DockerRootDir == docker_data_root",
            "'name=selinux' in (docker_info_json.stdout | from_json).SecurityOptions",
            "missing container_t MCS ProcessLabel",
            "missing container_file_t MCS MountLabel",
            "live process label differs from Docker metadata",
            'proc_label != "system_u:system_r:spc_t:s0"',
            "bounded spc_t MountLabel metadata drift",
            "mount_label and not mount_pattern.fullmatch(mount_label)",
            "label-disable bind requested relabel",
            "label-disable bind must be absolute and read-only",
            "HostConfig.Binds",
            "aigw_recent_selinux_denials.stdout | trim == ''",
            "aigw_recent_selinux_denials.stderr | trim == '<no matches>'",
        ):
            self.assertIn(required, source)

    def test_live_verifier_preserves_openwebui_nonroot_readonly_boundary(self) -> None:
        source = VERIFY_TASKS.read_text(encoding="utf-8")
        for required in (
            "def normalized_container_mounts(container):",
            "HostConfig.Tmpfs but omits them from the top-level Mounts list",
            '"open-webui": "65532:65532"',
            '"open-webui": "65532"',
            'host.get("ReadonlyRootfs") is not True',
            'tmpfs.get("/tmp")',
            # The /tmp writability proof must be Engine-normalization
            # neutral: require the security-bearing options and the absence
            # of "ro" instead of a literal Engine-normalized "rw" token.
            'not {"noexec", "nosuid", "nodev", "mode=1777", "size=256m"} <= tmpfs_options',
            'or "ro" in tmpfs_options',
            '"/app/backend/data"',
            '"PYTHONNOUSERSITE": "1"',
            '"STATIC_DIR": "/tmp/static"',
            "node-exporter: malformed Docker mount metadata",
            "open-webui: malformed Docker mount metadata",
        ):
            self.assertIn(required, source)

    def test_live_verifier_rejects_extra_host_root_binds_for_node_exporter(self) -> None:
        source = VERIFY_TASKS.read_text(encoding="utf-8")
        for required in (
            "def is_host_root_bind(mount):",
            "all_host_root_binds",
            "len(all_host_root_binds) != 1",
        ):
            self.assertIn(required, source)

    def test_bind_recreation_markers_use_a_dedicated_stable_private_key(self) -> None:
        source = STACK_TASKS.read_text(encoding="utf-8")
        key_section = source.split(
            "- name: Create the private bind-digest state directory", 1
        )[1].split("- name: Define exact per-service bind-source digest inputs", 1)[0]
        for required in (
            ".state/bind-digest.key",
            "O_EXCL",
            "O_NOFOLLOW",
            "mode == '0600'",
            "stat.nlink | int) == 1",
            "stat.size | int) == 64",
            "no_log: true",
        ):
            self.assertIn(required, key_section)

        compute = source.split(
            "- name: Compute keyed bind-source content digests", 1
        )[1].split("- name: Record the exact bind-source recreation contract", 1)[0]
        self.assertIn("aigw_bind_digest_key.content | b64decode", compute)
        self.assertIn("stdin_add_newline: false", compute)
        self.assertIn("no_log: true", compute)
        self.assertNotIn("portal_session_secret", compute)

        template = ENV_TEMPLATE.read_text(encoding="utf-8")
        compose = COMPOSE.read_text(encoding="utf-8")
        self.assertIn("AIGW_BIND_DIGEST_VAULT=", template)
        self.assertIn("AIGW_BIND_DIGEST_REDIS=", template)
        self.assertIn("com.aigw.contract.bind-source-digest", compose)
        volume_init = compose.split("  volume-init:", 1)[1].split(
            "  traefik-int:", 1
        )[0]
        self.assertNotIn("bind-source-digest", volume_init)
        backup = (ROOT / "scripts/state-backup.sh").read_text(encoding="utf-8")
        self.assertIn("--exclude='.state'", backup)
        self.assertNotIn("bind-digest.key", backup)

    def test_transient_private_relabels_never_steal_persistent_sources(self) -> None:
        stack = STACK_TASKS.read_text(encoding="utf-8")
        vault_validator = (ROOT / "scripts/validate-vault-config.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("$validation_dir/config.hcl:/vault/config/aigw.hcl:ro,Z", vault_validator)
        self.assertNotIn(
            "$STACK_DIR/vault/config.hcl:/vault/config/aigw.hcl", vault_validator
        )
        self.assertIn("trap cleanup EXIT HUP INT TERM", vault_validator)

        self.assertIn(
            "openwebui_reconcile_staging.path }}/reconcile.py:/reconcile.py:ro,Z",
            stack,
        )
        self.assertNotIn(
            "{{ stack_dir }}/scripts/reconcile-openwebui-key.py:/reconcile.py",
            stack,
        )
        self.assertIn("Remove private reconciliation staging directory", stack)

        alloy_verifier = stack.split(
            "- name: Prove Alloy can read mounted logs and write only its state volume",
            1,
        )[1].split("- name: Probe strict Vault readiness", 1)[0]
        self.assertIn("- label=disable", alloy_verifier)
        self.assertIn("{{ docker_data_root }}/containers:/logs:ro", alloy_verifier)
        self.assertNotIn("/logs:ro,z", alloy_verifier)
        self.assertNotIn("/logs:ro,Z", alloy_verifier)

        # Every other helper uses named volumes only; unseal uses no mount.
        expected_named_volume_mounts = {
            "rotate-vault-audit.sh": '-v "$audit_volume:/audit"',
            "state-backup.sh": '-v "${matches[0]}:/source:ro"',
            "state-restore.sh": '-v "$volume_name:/destination"',
        }
        for name, expected in expected_named_volume_mounts.items():
            helper = (ROOT / "scripts" / name).read_text(encoding="utf-8")
            self.assertIn(expected, helper)
            self.assertNotIn("/var/lib/docker", helper)
        unseal = (ROOT / "scripts/vault-unseal.sh").read_text(encoding="utf-8")
        self.assertNotIn("--volume", unseal)
        self.assertNotRegex(unseal, r"(^|\s)-v(\s|$)")

    def test_restore_rotates_digest_epoch_without_running_volume_init(self) -> None:
        restore = (ROOT / "scripts/state-restore.sh").read_text(encoding="utf-8")
        self.assertIn("rm -f -- .state/bind-digest.key", restore)
        self.assertIn("unsafe .state boundary after restore", restore)
        self.assertIn("the captured graph is intentionally stopped", restore)
        self.assertNotIn("docker compose start", restore)

    def test_vault_bootstrap_health_exception_is_fresh_state_only(self) -> None:
        stack = STACK_TASKS.read_text(encoding="utf-8")
        boundary = stack.split(
            "- name: Bound the Vault bootstrap health exception to fresh uninitialized state",
            1,
        )[1].split(
            "- name: Require restored Vault state instead of replacement initialization",
            1,
        )[0]
        self.assertIn("vault_strict_readiness.rc == 0", boundary)
        self.assertIn(".initialized | bool", boundary)
        self.assertIn(".sealed | bool", boundary)
        self.assertIn("Only a genuinely uninitialized first bootstrap", boundary)
        self.assertNotIn("or\n        ((vault_public_status.stdout | from_json).sealed", boundary)

    def test_stack_only_deploy_cannot_bypass_selinux_or_runtime_verify(self) -> None:
        source = (ROOT / "ansible/deploy-stack-only.yml").read_text(
            encoding="utf-8"
        )
        preflight = source.split("pre_tasks:", 1)[1].split("  roles:", 1)[0]
        for required in (
            "ansible_facts.selinux.status == 'enabled'",
            "ansible_facts.selinux.mode == 'enforcing'",
            "ansible_facts.selinux.type == 'targeted'",
            "preflight_selinux_mode.stdout | trim == 'Enforcing'",
            "'name=selinux' in (stack_only_docker_info.stdout | from_json).SecurityOptions",
            "DockerRootDir == docker_data_root",
            "aigw_selinux_audit_window_start",
            "date +'%m/%d/%y %H:%M:%S'",
        ):
            self.assertIn(required, preflight)
        roles = source.split("  roles:", 1)[1]
        self.assertLess(roles.index("role: docker_stack"), roles.index("role: verify"))

    def test_full_converge_delegates_and_enforces_the_selinux_runtime_contract(self) -> None:
        site = FULL_SITE.read_text(encoding="utf-8")
        os_prep = OS_PREP.read_text(encoding="utf-8")
        stack_only = STACK_ONLY_PLAYBOOK.read_text(encoding="utf-8")
        role = SELINUX_BASELINE.read_text(encoding="utf-8")

        # site.yml is the exact host-prep-then-stack composition; the SELinux
        # runtime transition therefore always precedes any container start.
        self.assertIn("- import_playbook: os-prep.yml", site)
        self.assertIn("- import_playbook: deploy-stack-only.yml", site)
        self.assertLess(
            site.index("- import_playbook: os-prep.yml"),
            site.index("- import_playbook: deploy-stack-only.yml"),
        )
        for required in (
            "aigw_selinux_policy == 'targeted'",
            "aigw_selinux_state == 'enforcing'",
            "- role: selinux_baseline",
            "- role: network_routing",
            "- role: firewalld_zones",
            "- role: os_baseline",
        ):
            self.assertIn(required, os_prep)
        for required in (
            "- role: docker_stack",
            "- role: verify",
            "- role: host_finalize",
        ):
            self.assertIn(required, stack_only)
            self.assertNotIn(required, os_prep)
        self.assertLess(
            os_prep.index("- role: selinux_baseline"),
            os_prep.index("- role: network_routing"),
        )
        self.assertLess(
            os_prep.index("- role: selinux_baseline"),
            os_prep.index("- role: firewalld_zones"),
        )
        self.assertLess(
            os_prep.index("- role: selinux_baseline"),
            os_prep.index("- role: os_baseline"),
        )
        for required in (
            "ansible.builtin.command: getenforce",
            "ansible.posix.selinux",
            'policy: "{{ aigw_selinux_policy }}"',
            'state: "{{ aigw_selinux_state }}"',
            "ansible_facts.selinux.status | default('disabled') == 'enabled'",
            "ansible_facts.selinux.mode | default('') == aigw_selinux_state",
            "ansible_facts.selinux.type | default('') == aigw_selinux_policy",
            "aigw_selinux_mode_after.stdout | trim == 'Enforcing'",
            "aigw_selinux_audit_window_start",
            "date +'%m/%d/%y %H:%M:%S'",
            "SELinux did not reach the required targeted/enforcing runtime state",
        ):
            self.assertIn(required, role)


if __name__ == "__main__":
    unittest.main()
