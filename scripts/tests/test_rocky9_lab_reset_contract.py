#!/usr/bin/env python3
"""Static safety contracts for the one legacy Rocky 9 lab teardown."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PLAYBOOK = ROOT / "ansible" / "reset-rocky9-lab.yml"
BASE_COMPOSE = ROOT / "compose" / "docker-compose.yml"
LAB_COMPOSE = ROOT / "compose" / "docker-compose.lab.yml"
PLATFORM_DNS_COMPOSE = ROOT / "compose" / "docker-compose.platform-dns.yml"
ALL_VARS = ROOT / "ansible" / "group_vars" / "all.yml"
SITE = ROOT / "ansible" / "site.yml"
STACK_ONLY = ROOT / "ansible" / "deploy-stack-only.yml"


def mapping_names(path: Path, section: str) -> set[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    start = next(index for index, line in enumerate(lines) if line == f"{section}:")
    names: set[str] = set()
    for line in lines[start + 1 :]:
        if line and not line.startswith((" ", "\t")):
            break
        match = re.fullmatch(r"  ([A-Za-z0-9_-]+):", line)
        if match:
            names.add(match.group(1))
    return names


def playbook_list(source: str, variable: str) -> list[str]:
    match = re.search(
        rf"^    {re.escape(variable)}:\n(?P<body>(?:      - [A-Za-z0-9_.\-/]+\n)+)",
        source,
        re.MULTILINE,
    )
    if match is None:
        raise AssertionError(f"missing playbook list {variable}")
    return re.findall(r"^      - ([A-Za-z0-9_.\-/]+)$", match.group("body"), re.MULTILINE)


def playbook_image_mapping(source: str, variable: str) -> dict[str, str]:
    match = re.search(
        rf"^    {re.escape(variable)}:\n(?P<body>(?:      [^\n]+\n)+)",
        source,
        re.MULTILINE,
    )
    if match is None:
        raise AssertionError(f"missing playbook image mapping {variable}")
    return dict(
        re.findall(
            r"^      ([a-z0-9][a-z0-9._/-]*:[A-Za-z0-9_.-]+): (sha256:[0-9a-f]{64})$",
            match.group("body"),
            re.MULTILINE,
        )
    )


def python_blocks(source: str) -> list[str]:
    blocks: list[str] = []
    for remainder in source.split("          - |\n")[1:]:
        lines: list[str] = []
        for line in remainder.splitlines():
            if line.startswith("          - ") and not line.startswith("            "):
                break
            if line.startswith("            "):
                lines.append(line[12:])
            elif not line:
                lines.append("")
            else:
                break
        block = "\n".join(lines)
        if block.lstrip().startswith("import "):
            blocks.append(block)
    return blocks


class Rocky9LabResetContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = PLAYBOOK.read_text(encoding="utf-8")

    def test_is_separate_exact_lab_only_and_dual_confirmed(self) -> None:
        required = (
            "hosts: lab-aigw01",
            "inventory_hostname == 'lab-aigw01'",
            "(inventory_file | default('')) == (playbook_dir ~ '/inventory/lab.yml')",
            "deployment_profile == 'rocky9-lab'",
            "ansible_facts.hostname | default('') == 'aigw01'",
            "ansible_host == '10.8.10.10'",
            "aigw_lab_reset_confirmation_token: DESTROY_AIGW01_LAB_STATE",
            "aigw_lab_legacy_host_confirmation_token: REMOVE_AIGW01_LEGACY_HOST_ARTIFACTS",
            "aigw_lab_legacy_reset_snapshot_name",
            "prlctl, snapshot-list, aigw01, --json",
            "prlctl, list, -i, aigw01, --json",
            "^aigw(?:01)?-[A-Za-z0-9._-]{8,96}$",
            "aigw_lab_reset_parallels_vm_uuid",
            "guest DMI UUID does not match the Parallels VM",
            "guest main default route is not the reviewed egress route",
            "not (aigw_lab_reset_markers.results[0].stat.exists | default(false))",
            "not (aigw_lab_reset_markers.results[1].stat.exists | default(false))",
        )
        for text in required:
            self.assertIn(text, self.source)
        self.assertNotIn(PLAYBOOK.name, SITE.read_text(encoding="utf-8"))
        self.assertNotIn(PLAYBOOK.name, STACK_ONLY.read_text(encoding="utf-8"))

    def test_legacy_cleanup_is_pinned_to_snapshot_artifact_and_filter_bytes(self) -> None:
        listed_files = set(playbook_list(self.source, "aigw_lab_legacy_reset_host_files"))
        artifact_section = self.source.split("    aigw_lab_legacy_artifact_sha256:\n", 1)[1].split(
            "    # ``nft list``", 1
        )[0]
        artifact_hashes = dict(
            re.findall(r"^      (/[^:]+): ([0-9a-f]{64})$", artifact_section, re.MULTILINE)
        )
        self.assertEqual(listed_files, set(artifact_hashes))
        self.assertGreaterEqual(len(artifact_hashes), 30)
        self.assertIn("legacy artifact digest differs", self.source)
        self.assertIn("legacy nft table differs", self.source)
        self.assertIn("legacy DOCKER-USER rules differ", self.source)
        self.assertIn("aigw_lab_legacy_nft_sha256", self.source)
        self.assertIn("aigw_lab_legacy_docker_user_sha256", self.source)

    def test_graph_allowlists_track_current_compose_and_network_contract(self) -> None:
        services = set(playbook_list(self.source, "aigw_lab_reset_expected_services"))
        self.assertEqual(
            services,
            mapping_names(BASE_COMPOSE, "services")
            | mapping_names(PLATFORM_DNS_COMPOSE, "services")
            | mapping_names(LAB_COMPOSE, "services"),
        )
        self.assertEqual(len(services), len(playbook_list(self.source, "aigw_lab_reset_expected_services")))
        volumes = set(playbook_list(self.source, "aigw_lab_reset_expected_volumes"))
        self.assertEqual(volumes, mapping_names(BASE_COMPOSE, "volumes") | mapping_names(LAB_COMPOSE, "volumes"))
        self.assertEqual(len(volumes), len(playbook_list(self.source, "aigw_lab_reset_expected_volumes")))
        configured_networks = re.findall(
            r"^  - \{ name: (net-[a-z0-9-]+),", ALL_VARS.read_text(encoding="utf-8"), re.MULTILINE
        )
        self.assertEqual(playbook_list(self.source, "aigw_lab_reset_expected_networks"), configured_networks)

    def test_no_broad_prune_or_generic_reset_and_docker_root_is_graph_proven(self) -> None:
        lowered = self.source.lower()
        for forbidden in (
            "docker system prune",
            "docker image prune",
            "docker volume prune",
            "docker network prune",
            "ansible.builtin.shell",
            "ansible.builtin.raw",
            "aigw_adopt_dedicated_docker_host",
        ):
            self.assertNotIn(forbidden, lowered)
        self.assertIn("dangling Docker image", self.source)
        self.assertIn("foreign or unrecognized Docker container", self.source)
        self.assertIn("foreign or unrecognized Docker network", self.source)
        self.assertIn("foreign or unrecognized Docker volume", self.source)
        self.assertIn("Docker service graph is not exact one-per reviewed legacy service", self.source)
        self.assertIn("Docker network graph is not the exact reviewed legacy set", self.source)
        self.assertIn("Docker volume graph is not the exact reviewed legacy set", self.source)
        self.assertIn('"image", "ls", "--all", "--no-trunc"', self.source)
        self.assertIn("Docker seed RepoDigest changed after the reset plan", self.source)
        self.assertNotIn('repository.startswith("ai-gateway/")', self.source)
        self.assertNotIn('repository.startswith("ai-gateway-")', self.source)
        self.assertIn("aigw_lab_reset_legacy_local_image_tags", self.source)
        self.assertIn("aigw_lab_reset_legacy_seed_image_tags", self.source)
        self.assertIn("staged seed manifest is not the exact legacy seed-image contract", self.source)
        self.assertNotIn("aigw_lab_reset_expected_local_image_repositories", self.source)
        self.assertNotIn("aigw_lab_reset_legacy_seed_dangling_image_ids", self.source)
        self.assertIn("stop and disable Docker service before Docker root removal", self.source)
        self.assertIn("Docker socket path remains after stale-socket remediation", self.source)
        self.assertIn("dockerd process remains after stop", self.source)
        self.assertIn("Docker root or a child is a mountpoint", self.source)
        self.assertIn("path: /var/lib/docker\n        state: absent", self.source)
        self.assertIn("['volume', 'rm', item]", self.source)
        self.assertNotIn("['volume', 'rm', '-f'", self.source)

    def test_archive_only_seed_absence_is_exact_and_scoped(self) -> None:
        seed_tags = playbook_image_mapping(self.source, "aigw_lab_reset_legacy_seed_image_tags")
        archive_only_tags = playbook_image_mapping(
            self.source, "aigw_lab_reset_legacy_archive_only_seed_image_tags"
        )
        self.assertEqual(
            archive_only_tags,
            {
                "debian:13-slim": "sha256:28de0877c2189802884ccd20f15ee41c203573bd87bb6b883f5f46362d24c5c2",
                "docker/dockerfile:1.7": "sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e",
            },
        )
        self.assertTrue(archive_only_tags.items() <= seed_tags.items())
        self.assertEqual(
            self.source.count("aigw_lab_reset_legacy_archive_only_seed_image_tags | to_json"),
            2,
        )
        for required in (
            "not set(archive_only_seed_tags).issubset(legacy_seed_tags)",
            "any(legacy_seed_tags[tag] != image_id for tag, image_id in archive_only_seed_tags.items())",
            "required_seed_tags = set(legacy_seed_tags) - set(archive_only_seed_tags)",
            "not required_seed_tags.issubset(seen_legacy_seed_tags)",
            "archive-only seed image is not in the exact staged manifest",
            "required_seed_tags = set(seed_tags) - set(archive_only_seed_tags)",
            "not required_seed_tags.issubset(seen_seed_tags)",
            "tag in archive_only_seed_tags and tag not in seen_seed_tags",
        ):
            self.assertIn(required, self.source)

    def test_preserves_seed_and_physical_network_contracts(self) -> None:
        self.assertIn("offline_image_seed_remote_path is match('^/var/tmp/", self.source)
        self.assertGreaterEqual(self.source.count("checksum_algorithm: sha256"), 2)
        self.assertIn("aigw_lab_reset_seed_before", self.source)
        self.assertIn("aigw_lab_reset_seed_after", self.source)
        self.assertIn("aigw_lab_reset_physical_network_before", self.source)
        self.assertIn("aigw_lab_reset_physical_network_after", self.source)
        self.assertIn(
            "aigw_lab_reset_physical_network_before.stdout == aigw_lab_reset_physical_network_after.stdout",
            self.source,
        )
        self.assertIn("pbr_rules", self.source)
        self.assertIn('("inet", "-4"), ("inet6", "-6")', self.source)
        self.assertIn("aigw_lab_reset_zone_migrations", self.source)
        self.assertIn('{ nic: "{{ nic_egress }}", zone: drop }', self.source)
        self.assertIn('{ nic: "{{ nic_adm }}", zone: public }', self.source)
        self.assertIn('{ nic: "{{ nic_internal }}", zone: drop }', self.source)
        self.assertIn("require fail-closed physical runtime zones", self.source)
        self.assertIn("fresh key-only ADM SSH connection still works", self.source)

    def test_only_ephemeral_seed_proof_mutates_before_destructive_tasks(self) -> None:
        graph_gate = self.source.index("Reset preflight — inventory only known AIGW Docker graph")
        artifact_gate = self.source.index("Reset preflight — validate recognized legacy host artifacts only")
        stack_gate = self.source.index("Reset preflight — require the exact bounded legacy stack inventory")
        nm_gate = self.source.index("Reset preflight — require exactly one reviewed zone migration")
        proof = self.source.index("Reset gate — prove the exact staged image seed loads")
        task_section = self.source.index("\n  tasks:\n")
        destructive = self.source.index("Reset legacy — stop and disable only loaded AIGW units")
        self.assertLess(graph_gate, artifact_gate)
        self.assertLess(artifact_gate, stack_gate)
        self.assertLess(stack_gate, nm_gate)
        self.assertLess(nm_gate, proof)
        self.assertLess(proof, task_section)
        self.assertLess(task_section, destructive)
        self.assertIn("aigw_lab_reset_seed_proof_marker_dir", self.source)
        self.assertIn("load-offline-image-seed.py", self.source)
        self.assertIn("always:\n        - name: Reset gate — remove the ephemeral seed-loader proof marker", self.source)

    def test_stack_recursive_removal_is_preceded_by_an_exact_bounded_inventory(self) -> None:
        gate = self.source.index("Reset preflight — require the exact bounded legacy stack inventory")
        removal = self.source.index("Reset legacy — remove exact AIGW stack directory")
        self.assertLess(gate, removal)
        for required in (
            "aigw_lab_reset_legacy_stack_entry_count",
            "aigw_lab_reset_legacy_stack_total_bytes",
            "aigw_lab_reset_legacy_stack_manifest_sha256",
            "aigw_lab_reset_legacy_stack_sensitive_paths",
            "legacy stack contains a symlink",
            "O_NOFOLLOW",
            "legacy stack inventory does not exactly match the reviewed tree",
            "legacy stack exceeds bounded reviewed entry count",
            "legacy stack sensitive-path allowlist does not match the reviewed tree",
        ):
            self.assertIn(required, self.source)
        self.assertRegex(
            self.source,
            r"aigw_lab_reset_legacy_stack_manifest_sha256: [0-9a-f]{64}",
        )

    def test_stale_docker_socket_remediation_is_exact_and_fail_closed(self) -> None:
        units = self.source.index("Reset legacy — require Docker service and socket to be inactive")
        no_dockerd = self.source.index("Reset legacy — prove no dockerd process remains before socket remediation")
        remediation = self.source.index("Reset legacy — remove only a verified stale Docker Unix socket")
        final_guard = self.source.index("Reset legacy — prove Docker is unreachable and its root has no mount boundary")
        firewall_cleanup = self.source.index("Reset legacy — remove exact legacy nftables tables after Docker stops")
        self.assertLess(units, no_dockerd)
        self.assertLess(no_dockerd, remediation)
        self.assertLess(remediation, final_guard)
        self.assertLess(final_guard, firewall_cleanup)
        scope = self.source[remediation:final_guard]
        for required in (
            'socket_path = "/run/docker.sock"',
            "os.lstat(socket_path)",
            "stat.S_ISSOCK",
            'grp.getgrnam("docker")',
            "stat.S_IMODE(initial_metadata.st_mode) != 0o660",
            "initial_metadata.st_uid != 0",
            "initial_metadata.st_gid != docker_gid",
            'pathlib.Path("/proc/net/unix")',
            "require_no_bound_socket_path",
            'os.unlink("docker.sock", dir_fd=run_fd)',
            "DOCKER_SOCKET_ABSENT",
            "REMOVED_STALE_DOCKER_SOCKET",
            "Docker socket metadata changed before stale-socket remediation",
        ):
            self.assertIn(required, scope)
        self.assertNotIn("ansible.builtin.file", scope)
        self.assertNotIn("state: absent", scope)
        final_scope = self.source[final_guard:firewall_cleanup]
        self.assertIn('os.lstat("/run/docker.sock")', final_scope)
        self.assertIn("Docker socket path remains after stale-socket remediation", final_scope)

    def test_exact_legacy_host_cleanup_includes_current_unmarked_blockers(self) -> None:
        required = (
            "/etc/systemd/system/docker.service.d/90-aigw-maintenance-boot-guard.conf",
            "/etc/aigw-maintenance-boot-guard.nft",
            "aigw-maintenance-boot-guard.service",
            "aigw_guard",
            "aigw_maintenance",
            "DOCKER-USER",
            "aigw-adm.xml.old",
            "aigw-egress.xml.old",
            "aigw-internal.xml.old",
            "/etc/firewalld/zones/public.xml",
            "/etc/firewalld/zones/docker.xml",
            "/etc/firewalld/policies/docker-forwarding.xml",
            "00-ai-gateway-hardening.conf",
            "90-aigw-policy-routing",
            "91-aigw-firewalld-zones",
        )
        for text in required:
            self.assertIn(text, self.source)

    def test_embedded_python_compiles(self) -> None:
        blocks = python_blocks(self.source)
        self.assertEqual(len(blocks), 13)
        for index, block in enumerate(blocks, 1):
            compile(block, f"<reset block {index}>", "exec")


if __name__ == "__main__":
    unittest.main()
