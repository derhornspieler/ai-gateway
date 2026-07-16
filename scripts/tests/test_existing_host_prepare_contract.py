"""Static contracts for safe convergence of an existing dedicated Rocky 9 VM."""

from __future__ import annotations

import copy
from pathlib import Path
import sys
import textwrap
from types import SimpleNamespace
import unittest


ROOT = Path(__file__).resolve().parents[2]
GROUP_VARS = ROOT / "ansible" / "group_vars" / "all.yml"
LAB_VARS = ROOT / "ansible" / "inventory" / "host_vars" / "lab-aigw01.yml"
SITE = ROOT / "ansible" / "site.yml"
OS_PREP = ROOT / "ansible" / "os-prep.yml"
HOST_PREFLIGHT = ROOT / "ansible" / "roles" / "host_preflight" / "tasks" / "main.yml"
FIREWALL_PREFLIGHT = ROOT / "ansible" / "roles" / "firewall_preflight" / "tasks" / "main.yml"
FIREWALL_ROLE = ROOT / "ansible" / "roles" / "firewalld_zones" / "tasks" / "main.yml"
OS_BASELINE = ROOT / "ansible" / "roles" / "os_baseline" / "tasks" / "main.yml"
NETWORK_ROUTING = ROOT / "ansible" / "roles" / "network_routing" / "tasks" / "main.yml"
DOCKER_NETWORKS = ROOT / "ansible" / "roles" / "docker_networks" / "tasks" / "main.yml"
NFT_GUARD = ROOT / "ansible" / "roles" / "firewalld_zones" / "templates" / "aigw-host-input-rules.sh.j2"
VERIFY = ROOT / "ansible" / "roles" / "verify" / "tasks" / "main.yml"
STACK_ONLY = ROOT / "ansible" / "deploy-stack-only.yml"


class ExistingRockyHostPrepareContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.group = GROUP_VARS.read_text(encoding="utf-8")
        cls.lab = LAB_VARS.read_text(encoding="utf-8")
        cls.site = SITE.read_text(encoding="utf-8")
        cls.os_prep = OS_PREP.read_text(encoding="utf-8")
        cls.host = HOST_PREFLIGHT.read_text(encoding="utf-8")
        cls.firewall_preflight = FIREWALL_PREFLIGHT.read_text(encoding="utf-8")
        cls.firewall = FIREWALL_ROLE.read_text(encoding="utf-8")
        cls.os_baseline = OS_BASELINE.read_text(encoding="utf-8")
        cls.network_routing = NETWORK_ROUTING.read_text(encoding="utf-8")
        cls.docker_networks = DOCKER_NETWORKS.read_text(encoding="utf-8")
        cls.nft_guard = NFT_GUARD.read_text(encoding="utf-8")
        cls.verify = VERIFY.read_text(encoding="utf-8")
        cls.stack_only = STACK_ONLY.read_text(encoding="utf-8")
        runtime_checker_start = cls.host.index(
            "        import json\n",
            cls.host.index(
                "Preflight — reject active non-Docker container workloads on a dedicated host"
            ),
        )
        runtime_checker_end = cls.host.index(
            "  changed_when: false", runtime_checker_start
        )
        cls.runtime_checker = textwrap.dedent(
            cls.host[runtime_checker_start:runtime_checker_end]
        )
        endpoint_validator_start = cls.host.index(
            "        import json\n",
            cls.host.index(
                "Preflight — require Docker service and socket to expose only the local Unix endpoint"
            ),
        )
        endpoint_validator_end = cls.host.index(
            "\n    # Keep systemd show output off the process argv:",
            endpoint_validator_start,
        )
        cls.endpoint_validator = textwrap.dedent(
            cls.host[endpoint_validator_start:endpoint_validator_end]
        )
        socket_mount_checker_start = cls.host.index(
            "            def bind_exposes_docker_socket(mount, mounts, seen=frozenset()):",
            cls.host.index("Preflight — inspect a live Docker host for foreign containers and networks"),
        )
        socket_mount_checker_end = cls.host.index(
            "\n            for container in containers:", socket_mount_checker_start
        )
        cls.socket_mount_checker = textwrap.dedent(
            cls.host[socket_mount_checker_start:socket_mount_checker_end]
        )
        docker_networks_socket_mount_checker_start = cls.docker_networks.index(
            "            def bind_exposes_docker_socket(mount, mounts, seen=frozenset()):",
            cls.docker_networks.index(
                "Preflight — reject live Docker network drift before reconciliation"
            ),
        )
        docker_networks_socket_mount_checker_end = cls.docker_networks.index(
            "\n            for container in containers:",
            docker_networks_socket_mount_checker_start,
        )
        cls.docker_networks_socket_mount_checker = textwrap.dedent(
            cls.docker_networks[
                docker_networks_socket_mount_checker_start:
                docker_networks_socket_mount_checker_end
            ]
        )
        verify_mount_normalizer_start = cls.verify.index(
            "        def normalized_container_mounts(container):"
        )
        verify_mount_normalizer_end = cls.verify.index(
            "\n        for service, container in sorted(actual.items()):",
            verify_mount_normalizer_start,
        )
        cls.verify_mount_normalizer = textwrap.dedent(
            cls.verify[verify_mount_normalizer_start:verify_mount_normalizer_end]
        )
        firewall_ownership_checker_start = cls.firewall_preflight.index(
            "        def has_reviewed_aigw_firewall_ownership("
        )
        firewall_ownership_checker_end = cls.firewall_preflight.index(
            "\n        reviewed_aigw_firewall_ownership =",
            firewall_ownership_checker_start,
        )
        cls.firewall_ownership_checker = textwrap.dedent(
            cls.firewall_preflight[
                firewall_ownership_checker_start:firewall_ownership_checker_end
            ]
        )
        artifact_gate_start = cls.host.index(
            "        import json\n",
            cls.host.index(
                "Preflight — reject unsafe or unowned existing AIGW-managed host artifacts"
            ),
        )
        artifact_gate_end = cls.host.index(
            '      - "{{ aigw_managed_host_artifacts | to_json }}"',
            artifact_gate_start,
        )
        cls.artifact_adoption_gate = textwrap.dedent(
            cls.host[artifact_gate_start:artifact_gate_end]
        )
        docker_zone_checker_start = cls.firewall_preflight.index(
            "        docker_firewalld_zone_path ="
        )
        docker_zone_checker_end = cls.firewall_preflight.index(
            "\n        # Inspect only administrator-owned /etc firewalld files.",
            docker_zone_checker_start,
        )
        cls.docker_zone_checker = textwrap.dedent(
            cls.firewall_preflight[
                docker_zone_checker_start:docker_zone_checker_end
            ]
        )
        validator_start = cls.os_prep.index("            import ipaddress\n")
        validator_end = cls.os_prep.index(
            "          - \"{{ deployment_profile | default('') }}\"",
            validator_start,
        )
        cls.socks_validator = textwrap.dedent(
            cls.os_prep[validator_start:validator_end]
        )

    def run_socks_validator(self, *arguments: str) -> None:
        original_argv = sys.argv
        try:
            sys.argv = ["validator", *arguments]
            exec(self.socks_validator, {"__name__": "__validator__"})
        finally:
            sys.argv = original_argv

    def run_runtime_checker(self, process_inventory: str) -> None:
        """Execute the inline preflight scanner against a controlled ps view."""
        import shutil
        import subprocess

        def fake_run(command: list[str], **_kwargs: object) -> SimpleNamespace:
            self.assertEqual(
                command, ["ps", "-eo", "pid=,user=,comm=,args="]
            )
            return SimpleNamespace(
                returncode=0, stdout=process_inventory, stderr=""
            )

        original_run = subprocess.run
        original_which = shutil.which
        try:
            subprocess.run = fake_run  # type: ignore[assignment]
            shutil.which = lambda *_args, **_kwargs: None  # type: ignore[assignment]
            exec(self.runtime_checker, {"__name__": "__runtime_checker__"})
        finally:
            subprocess.run = original_run  # type: ignore[assignment]
            shutil.which = original_which  # type: ignore[assignment]

    def run_endpoint_validator(self, payload: dict[str, str]) -> None:
        """Execute the inline Docker endpoint validator with its real stdin contract."""
        import io
        import json

        original_stdin = sys.stdin
        try:
            sys.stdin = io.StringIO(json.dumps(payload))
            exec(self.endpoint_validator, {"__name__": "__endpoint_validator__"})
        finally:
            sys.stdin = original_stdin

    def run_artifact_adoption_gate(
        self,
        has_ownership: bool,
        docker_adoption: bool = False,
        firewall_adoption: bool = False,
        ssh_adoption: bool = False,
    ) -> None:
        """Execute the embedded artifact-adoption gate against a root-owned artifact.

        os.lstat is mocked to a root-owned 0600 regular file so the "unsafe"
        branch never fires; the only remaining decision is whether proven
        ownership (completed OR validated pending marker) or an explicit
        adoption flag authorizes the retained managed artifact.
        """
        import json
        import os
        import stat
        from unittest.mock import patch

        artifacts = [
            {"path": "/usr/local/sbin/aigw-policy-routing", "adoption": "docker"}
        ]

        def fake_lstat(_path: str) -> SimpleNamespace:
            return SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0)

        original_argv = sys.argv
        try:
            sys.argv = [
                "gate",
                json.dumps(artifacts),
                "true" if has_ownership else "false",
                "true" if docker_adoption else "false",
                "true" if firewall_adoption else "false",
                "true" if ssh_adoption else "false",
            ]
            with patch.object(os, "lstat", side_effect=fake_lstat):
                exec(self.artifact_adoption_gate, {"__name__": "__artifact_gate__"})
        finally:
            sys.argv = original_argv

    def mount_checker_namespace(self, checker: str) -> dict[str, object]:
        import os

        namespace: dict[str, object] = {
            "__name__": "__socket_mount_checker__",
            "os": os,
            "docker_socket_path": "/run/docker.sock",
        }
        exec(checker, namespace)
        return namespace

    def docker_socket_is_exposed(self, mount: dict[str, object], mounts: list[dict[str, object]]) -> bool:
        namespace = self.mount_checker_namespace(self.socket_mount_checker)
        return namespace["bind_exposes_docker_socket"](mount, mounts)

    def node_exporter_rootfs_is_approved(
        self, container: dict[str, object], mounts: list[dict[str, object]]
    ) -> bool:
        namespace = self.mount_checker_namespace(self.socket_mount_checker)
        return namespace["has_approved_node_exporter_rootfs"](container, mounts)

    def run_policy_table_validator(self, routes_by_command: dict[tuple[str, ...], list[dict[str, object]]]) -> None:
        """Run the embedded collision guard against a deterministic `ip -j` view."""
        validator_start = self.os_prep.index(
            "            import ipaddress\n",
            self.os_prep.index("Preflight — reject live policy-table and rule collisions before replacement"),
        )
        validator_end = self.os_prep.index(
            '          - "{{ pbr_tables | to_json }}"', validator_start
        )
        validator = textwrap.dedent(self.os_prep[validator_start:validator_end])

        import json
        import subprocess

        def fake_run(command: list[str], **_kwargs: object) -> SimpleNamespace:
            self.assertEqual(command[0], "ip")
            key = tuple(command[1:])
            self.assertIn(key, routes_by_command, f"unexpected ip invocation: {key!r}")
            return SimpleNamespace(returncode=0, stdout=json.dumps(routes_by_command[key]), stderr="")

        original_argv = sys.argv
        original_run = subprocess.run
        try:
            subprocess.run = fake_run  # type: ignore[assignment]
            sys.argv = [
                "validator",
                '[{"id":101,"name":"adm","priority":10101,"dev":"enp0s7","gw":"10.8.10.2","src":"10.8.10.10"},'
                '{"id":102,"name":"internal","priority":10102,"dev":"enp0s8","gw":"10.20.0.2","src":"10.20.0.10"}]',
            ]
            exec(validator, {"__name__": "__validator__"})
        finally:
            subprocess.run = original_run  # type: ignore[assignment]
            sys.argv = original_argv

    def test_generic_ssh_and_socks_defaults_are_secure_while_lab_is_explicit(self) -> None:
        for required in (
            "aigw_ssh_password_authentication: false",
            "aigw_adm_socks_enabled: false",
            "aigw_adm_socks_users: []",
            "aigw_adm_socks_groups: []",
            "aigw_adm_socks_source_cidrs: []",
            "aigw_adm_socks_trusted_operator_ack: \"\"",
        ):
            self.assertIn(required, self.group)
        for required in (
            "aigw_ssh_password_authentication: true",
            "aigw_adm_socks_enabled: true",
            "aigw_adm_socks_users: [ansible]",
            "aigw_adm_socks_source_cidrs: [\"{{ vpn_client_cidr }}\"]",
            "aigw_adm_socks_trusted_operator_ack: I_UNDERSTAND_SOCKS_REACHES_ALL_HOST_ROUTES",
        ):
            self.assertIn(required, self.lab)
        self.assertIn(
            "aigw_adm_socks_trusted_operator_ack is string", self.os_prep
        )
        self.assertIn(
            "PermitOpen any reaches every host-routable destination", self.os_prep
        )
        self.assertIn("or trusted_operator_ack", self.os_prep)

    def test_ssh_password_and_socks_exceptions_are_lab_profile_gated(self) -> None:
        self.assertIn(
            "Preflight — restrict SSH password and SOCKS exceptions to rocky9-lab",
            self.os_prep,
        )
        self.assertIn(
            "(deployment_profile | default('')) == 'rocky9-lab' or",
            self.os_prep,
        )
        for required in (
            "password SSH authentication is allowed only in deployment_profile=rocky9-lab",
            "SSH SOCKS is allowed only in deployment_profile=rocky9-lab",
            "- \"{{ deployment_profile | default('') }}\"",
            "- \"{{ 'true' if (aigw_ssh_password_authentication | bool) else 'false' }}\"",
        ):
            self.assertIn(required, self.os_prep)
        for required in (
            "PasswordAuthentication {{ 'yes' if ((deployment_profile | default('')) == 'rocky9-lab' and (aigw_ssh_password_authentication | bool)) else 'no' }}",
            "{% if ((deployment_profile | default('')) == 'rocky9-lab') and (aigw_adm_socks_enabled | bool) %}",
            "('yes' if ((deployment_profile | default('')) == 'rocky9-lab' and (aigw_ssh_password_authentication | bool)) else 'no') ~ '$'",
        ):
            self.assertIn(required, self.os_baseline)

    def test_embedded_ssh_exception_validator_rejects_generic_opt_in(self) -> None:
        valid_lab_socks = (
            "rocky9-lab",
            "true",
            "true",
            '["ansible"]',
            "[]",
            '["10.23.0.0/24"]',
            "{}",
            "I_UNDERSTAND_SOCKS_REACHES_ALL_HOST_ROUTES",
            "10.23.0.0/24",
        )
        self.run_socks_validator(*valid_lab_socks)

        with self.assertRaises(SystemExit) as password_error:
            self.run_socks_validator(
                "generic-rocky9", "true", "false", "[]", "[]", "[]", "{}", "", "10.23.0.0/24"
            )
        self.assertIn("password SSH authentication is allowed only", str(password_error.exception))

        with self.assertRaises(SystemExit) as socks_error:
            self.run_socks_validator(
                "generic-rocky9",
                "false",
                "true",
                '["ansible"]',
                "[]",
                '["10.23.0.0/24"]',
                "{}",
                "I_UNDERSTAND_SOCKS_REACHES_ALL_HOST_ROUTES",
                "10.23.0.0/24",
            )
        self.assertIn("SSH SOCKS is allowed only", str(socks_error.exception))

    def test_sshd_default_deny_and_source_scoped_socks_contracts_are_rendered_and_tested(self) -> None:
        for required in (
            "DisableForwarding yes",
            "AllowTcpForwarding no",
            "AllowStreamLocalForwarding no",
            "AllowAgentForwarding no",
            "PermitTunnel no",
            "GatewayPorts no",
            "PermitOpen none",
            "PermitListen none",
            "Match User {{ aigw_adm_socks_users | join(',') }} Address",
            "Match Group {{ aigw_adm_socks_groups | join(',') }} Address",
            "AllowTcpForwarding local",
            "PermitOpen any",
            "Match all",
            "- /usr/sbin/sshd\n      - -T\n      - -C",
            "inventory acknowledgement",
        ):
            self.assertIn(required, self.os_baseline)
        self.assertIn("Preflight — require a safe sshd include and forwarding precedence boundary", self.os_baseline)
        for required in (
            "is_verified_late_redhat_fragment",
            'entry.name != "50-redhat.conf"',
            'owner.stdout.strip() != "openssh-server"',
            '["/usr/bin/rpm", "-Vf", entry.path]',
            "opensshserver.config",
            "read_verified_crypto_policy_backend",
            'owner.stdout.strip() != "crypto-policies"',
            "crypto_policy_directives",
            '"gssapikeyexchange"',
            "unreviewed crypto-policy sshd directive",
            "verified_late_redhat and key == \"x11forwarding\"",
        ):
            self.assertIn(required, self.os_baseline)
        self.assertIn("does not byte-match the current /etc/docker/daemon.json", self.os_baseline)
        self.assertIn("force: false", self.os_baseline)

    def test_docker_engine_and_compose_plugin_are_nevra_pinned(self) -> None:
        # An unpinned docker-ce-stable install twice adopted a Compose-v5 release
        # that broke a live converge. The exact NEVRA proven green by the
        # verify/e2e suite is the single source of truth in group_vars/all.yml,
        # consumed by the os_baseline install task via a name-version spec.
        for pin in (
            'aigw_docker_ce_version: "29.6.1-1.el9"',
            'aigw_docker_ce_cli_version: "29.6.1-1.el9"',
            'aigw_containerd_version: "2.2.6-1.el9"',
            'aigw_docker_compose_plugin_version: "5.3.1-1.el9"',
        ):
            self.assertIn(pin, self.group)
        for spec in (
            '- "docker-ce-{{ aigw_docker_ce_version }}"',
            '- "docker-ce-cli-{{ aigw_docker_ce_cli_version }}"',
            '- "containerd.io-{{ aigw_containerd_version }}"',
            '- "docker-compose-plugin-{{ aigw_docker_compose_plugin_version }}"',
        ):
            self.assertIn(spec, self.os_baseline)
        # state: present on an exact version fails closed if the mirror lacks the
        # pin; allow_downgrade: false refuses to auto-downgrade a drifted host.
        self.assertIn("allow_downgrade: false", self.os_baseline)
        # The bare unpinned package names must be gone from the install list, so
        # a converge can never silently resolve the newest Docker/Compose.
        for bare in (
            "      - docker-ce\n",
            "      - docker-ce-cli\n",
            "      - containerd.io\n",
            "      - docker-compose-plugin\n",
        ):
            self.assertNotIn(bare, self.os_baseline)

    def test_existing_docker_daemon_requires_local_reviewed_systemd_boundary(self) -> None:
        for required in (
            "canonical root-owned /usr/bin/docker binary",
            "resolve the discovered Docker CLI to its canonical filesystem path",
            "/usr/bin/readlink, -f",
            "aigw_docker_cli_resolved",
            "unix:///run/docker.sock",
            "plugin\n      - ls",
            "rootlesskit",
            "podman system service",
            '[ctr, "namespaces", "list", "--quiet"]',
            "docker.socket",
            "Preflight — reject local or transient Docker systemd overrides before adoption",
            "Preflight — require Docker service and socket to expose only the local Unix endpoint",
            "Preflight — enforce the Docker Unix-socket privilege boundary",
            "Preflight — reject dockerd processes not owned by the reviewed Docker service",
            "Preflight — reject auxiliary systemd sockets that can trigger Docker",
            "active process references the Docker Unix socket",
            "Preflight — inspect an already-active reviewed Docker daemon without socket activation",
            "Preflight — require an active Docker service to be owned by the reviewed local systemd endpoint",
            "aigw_docker_systemd_service_active",
            "aigw_docker_systemd_socket_active",
        ):
            self.assertIn(required, self.host)
        self.assertIn('if normalized_hosts != {"fd://"}:', self.host)
        self.assertIn(
            "(aigw_docker_cli_resolved.stdout | trim) == '/usr/bin/docker'",
            self.host,
        )
        self.assertIn("listener_directives = (", self.host)
        self.assertIn("socket_section = re.search", self.host)
        self.assertIn("resolved_listeners = [", self.host)
        self.assertIn("SocketMode", self.host)
        self.assertIn('[("ListenStream", "/run/docker.sock")]', self.host)
        self.assertIn(
            'set(service_properties.get("TriggeredBy", "").split()) != {"docker.socket"}',
            self.host,
        )
        self.assertNotIn(
            're.search(r"(?:tcp|http|https)://|0\\.0\\.0\\.0|\\[::\\]", service_text',
            self.host,
        )
        daemon_probe = self.host.split("Preflight — inspect an already-active reviewed Docker daemon without socket activation", 1)[1].split(
            "Preflight — record whether", 1
        )[0]
        self.assertIn("- DOCKER_HOST", daemon_probe)
        self.assertIn(
            '- "{{ aigw_docker_cli_resolved.stdout | trim }}"', daemon_probe
        )
        self.assertIn("- --host\n      - unix:///run/docker.sock", daemon_probe)
        self.assertGreater(
            self.host.index("Preflight — inspect an already-active reviewed Docker daemon without socket activation"),
            self.host.index("Preflight — enforce the Docker Unix-socket privilege boundary"),
        )

    def test_docker_socket_cannot_be_mounted_into_a_retained_project_container(self) -> None:
        for source in (self.host, self.docker_networks):
            self.assertIn("bind_exposes_docker_socket", source)
            self.assertIn("docker_socket_path = \"/run/docker.sock\"", source)
            self.assertIn("os.path.commonpath", source)
            self.assertIn("all_host_root_binds", source)
        self.assertIn("docker_socket_mounts", self.host)
        self.assertIn("unapproved_host_root_mounts", self.host)
        self.assertIn("has_approved_node_exporter_rootfs", self.host)
        self.assertIn("has_approved_node_exporter_rootfs", self.docker_networks)
        self.assertIn(
            "bind-mounts the Docker Unix socket", self.docker_networks
        )

        root_bind = {"Type": "bind", "Source": "/", "Destination": "/host"}
        direct_socket = {
            "Type": "bind",
            "Source": "/run/docker.sock",
            "Destination": "/socket",
        }
        self.assertTrue(self.docker_socket_is_exposed(root_bind, [root_bind]))
        self.assertTrue(
            self.docker_socket_is_exposed(direct_socket, [direct_socket])
        )

        masked_root = [
            root_bind,
            {"Type": "tmpfs", "Destination": "/host/run"},
        ]
        self.assertFalse(self.docker_socket_is_exposed(root_bind, masked_root))
        rebound_root = [
            root_bind,
            {"Type": "bind", "Source": "/run", "Destination": "/host/run"},
        ]
        self.assertTrue(self.docker_socket_is_exposed(root_bind, rebound_root))
        volume_mask = [
            root_bind,
            {"Type": "volume", "Destination": "/host/run"},
        ]
        self.assertTrue(self.docker_socket_is_exposed(root_bind, volume_mask))

        approved_root = {
            "Type": "bind",
            "Source": "/",
            "Destination": "/host",
            "RW": False,
            "Propagation": "rslave",
        }
        approved_container = {
            "Config": {
                "Labels": {"com.docker.compose.service": "node-exporter"},
                "User": "65532:65532",
            },
            "HostConfig": {"Tmpfs": {"/host/run": "mode=0555"}},
        }
        approved_mounts = [
            approved_root,
            {"Type": "tmpfs", "Destination": "/host/run"},
        ]
        self.assertTrue(
            self.node_exporter_rootfs_is_approved(approved_container, approved_mounts)
        )
        self.assertFalse(
            self.node_exporter_rootfs_is_approved(
                approved_container,
                approved_mounts
                + [{"Type": "bind", "Source": "/", "Destination": "/unexpected"}],
            )
        )

    def test_docker_engine_29_tmpfs_metadata_preserves_the_node_exporter_boundary(self) -> None:
        """Docker 29 reports tmpfs only under HostConfig.Tmpfs on this host."""
        docker29_node_exporter = {
            "Config": {
                "Labels": {"com.docker.compose.service": "node-exporter"},
                "User": "65532:65532",
            },
            "HostConfig": {
                "Tmpfs": {
                    "/host/run": "uid=65532,gid=65532,mode=0555,noexec,nosuid,nodev,size=1m",
                    "/tmp": "",
                },
            },
            "Mounts": [
                {
                    "Type": "bind",
                    "Source": "/",
                    "Destination": "/host",
                    "RW": False,
                    "Propagation": "rslave",
                },
            ],
        }

        for checker in (
            self.socket_mount_checker,
            self.docker_networks_socket_mount_checker,
        ):
            namespace = self.mount_checker_namespace(checker)
            effective = namespace["normalized_container_mounts"](
                copy.deepcopy(docker29_node_exporter)
            )
            self.assertIsNotNone(effective)
            assert effective is not None
            root_bind = next(
                mount for mount in effective if mount.get("Destination") == "/host"
            )
            self.assertIn(
                {"Type": "tmpfs", "Destination": "/host/run"}, effective
            )
            self.assertFalse(
                namespace["bind_exposes_docker_socket"](root_bind, effective)
            )
            self.assertTrue(
                namespace["has_approved_node_exporter_rootfs"](
                    docker29_node_exporter, effective
                )
            )

            conflicting_mount = copy.deepcopy(docker29_node_exporter)
            conflicting_mount["Mounts"].append(
                {"Type": "bind", "Source": "/run", "Destination": "/host/run"}
            )
            self.assertIsNone(
                namespace["normalized_container_mounts"](conflicting_mount)
            )

            malformed_tmpfs = copy.deepcopy(docker29_node_exporter)
            malformed_tmpfs["HostConfig"]["Tmpfs"] = {"relative": "mode=0555"}
            self.assertIsNone(
                namespace["normalized_container_mounts"](malformed_tmpfs)
            )

        verify_namespace = self.mount_checker_namespace(self.verify_mount_normalizer)
        verify_effective = verify_namespace["normalized_container_mounts"](
            copy.deepcopy(docker29_node_exporter)
        )
        self.assertIsNotNone(verify_effective)
        assert verify_effective is not None
        self.assertIn(
            {"Type": "tmpfs", "Destination": "/host/run"}, verify_effective
        )
        verify_conflicting_mount = copy.deepcopy(docker29_node_exporter)
        verify_conflicting_mount["Mounts"].append(
            {"Type": "bind", "Source": "/run", "Destination": "/host/run"}
        )
        self.assertIsNone(
            verify_namespace["normalized_container_mounts"](verify_conflicting_mount)
        )

    def test_dynamic_docker_pool_renders_the_expected_upper_half_of_each_subnet(self) -> None:
        import json
        import shutil
        import subprocess

        ansible = shutil.which("ansible")
        self.assertIsNotNone(ansible, "Ansible is required to render role templates")
        result = subprocess.run(
            [
                ansible,
                "localhost",
                "-i",
                "localhost,",
                "-c",
                "local",
                "-m",
                "ansible.builtin.debug",
                "-a",
                "msg={{ item.subnet | replace('.0/24', '.128/25') }}",
                "-e",
                json.dumps({"item": {"subnet": "172.28.1.0/24"}}),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"msg": "172.28.1.128/25"', result.stdout)
        for source in (self.host, self.docker_networks):
            self.assertIn("replace('.0/24', '.128/25')", source)
            self.assertNotIn(
                "regex_replace('\\\\.0/24$', '.128/25')", source
            )
        self.assertIn(
            '"iprange": entry["subnet"].replace(".0/24", ".128/25")',
            self.docker_networks,
        )

    def test_clean_host_socket_preflight_does_not_require_uninstalled_docker(self) -> None:
        self.assertIn("unit_names = set()", self.host)
        self.assertNotIn('unit_names = {"docker.socket"}', self.host)

    def test_docker_endpoint_validator_uses_stdin_and_rejects_tcp_listeners(self) -> None:
        stock_payload = {
            "service_unit": (
                "[Unit]\nDocumentation=https://docs.docker.com\n"
                "[Service]\nExecStart=/usr/bin/dockerd -H fd:// "
                "--containerd=/run/containerd/containerd.sock\n"
            ),
            "service_show": (
                "ExecStart={ path=/usr/bin/dockerd ; argv[]=/usr/bin/dockerd -H fd:// "
                "--containerd=/run/containerd/containerd.sock ; }\n"
                "FragmentPath=/usr/lib/systemd/system/docker.service\n"
                "DropInPaths=\nRequires=system.slice docker.socket sysinit.target\n"
                "TriggeredBy=docker.socket\n"
            ),
            "socket_unit": (
                "[Unit]\nDescription=Docker Socket for the API\n"
                "[Socket]\nListenStream=/run/docker.sock\nSocketMode=0660\n"
                "[Install]\nWantedBy=sockets.target\n"
            ),
            "socket_show": (
                "SocketUser=root\nSocketGroup=docker\nSocketMode=0660\n"
                "DirectoryMode=0755\nAccept=no\n"
                "Listen=/run/docker.sock (Stream)\nId=docker.socket\n"
                "Triggers=docker.service\n"
                "FragmentPath=/usr/lib/systemd/system/docker.socket\n"
                "DropInPaths=\nRequiredBy=docker.service\n"
            ),
        }
        self.run_endpoint_validator(stock_payload)

        tcp_service = dict(stock_payload)
        tcp_service["service_unit"] = (
            "[Service]\nExecStart=/usr/bin/dockerd -H tcp://0.0.0.0:2375\n"
        )
        with self.assertRaises(SystemExit) as service_error:
            self.run_endpoint_validator(tcp_service)
        self.assertIn("reviewed fd:// endpoint", str(service_error.exception))

        tcp_socket = dict(stock_payload)
        tcp_socket["socket_unit"] = (
            "[Socket]\nListenStream=/run/docker.sock\n"
            "ListenStream=0.0.0.0:2375\n"
        )
        with self.assertRaises(SystemExit) as socket_error:
            self.run_endpoint_validator(tcp_socket)
        self.assertIn("exactly ListenStream=/run/docker.sock", str(socket_error.exception))

        resolved_tcp_socket = dict(stock_payload)
        resolved_tcp_socket["socket_show"] = "Listen=0.0.0.0:2375 (Stream)\n"
        with self.assertRaises(SystemExit) as resolved_error:
            self.run_endpoint_validator(resolved_tcp_socket)
        self.assertIn("resolved listener", str(resolved_error.exception))

    def test_runtime_preflight_ignores_its_own_marker_bearing_argv_only(self) -> None:
        import os

        checker_pid = os.getpid()
        own_checker = (
            f"{checker_pid} root python3 python3 -I -c "
            "import subprocess; marker = 'rootlesskit'"
        )
        self.run_runtime_checker(own_checker + "\n")

        live_runtime = (
            f"{checker_pid + 1} root rootlesskit "
            "/usr/bin/rootlesskit --state-dir /run/user/0/docker"
        )
        with self.assertRaises(SystemExit) as runtime_error:
            self.run_runtime_checker(own_checker + "\n" + live_runtime + "\n")
        self.assertIn(
            "active rootless/container runtime process", str(runtime_error.exception)
        )
        self.assertIn("rootlesskit", str(runtime_error.exception))

        socket_proxy = (
            f"{checker_pid + 2} root socat "
            "socat TCP-LISTEN:2375,fork UNIX-CONNECT:/run/docker.sock"
        )
        with self.assertRaises(SystemExit) as proxy_error:
            self.run_runtime_checker(own_checker + "\n" + socket_proxy + "\n")
        self.assertIn("references the Docker Unix socket", str(proxy_error.exception))
        self.assertNotIn("UNIX-CONNECT", str(proxy_error.exception))

    def test_fresh_controller_ssh_probes_keep_each_remote_command_in_one_argv_element(self) -> None:
        """OpenSSH joins remote argv after the destination without quoting it."""
        transport_probe = (
            "/usr/bin/sudo -n /usr/bin/true && exec "
            "/usr/bin/printenv SSH_CONNECTION"
        )
        for source, argv_name in (
            (self.host, "aigw_controller_ssh_argv"),
            (self.network_routing, "aigw_post_pbr_ssh_argv"),
            (self.os_baseline, "controller_key_only_ssh_argv"),
        ):
            self.assertIn(
                f"{argv_name} + ['{transport_probe}']",
                source,
            )

        self.assertIn(
            "controller_key_only_ssh_argv + ['/usr/bin/sudo -n /usr/bin/true']",
            self.os_baseline,
        )
        for source in (self.host, self.network_routing, self.os_baseline):
            self.assertNotIn("['/usr/bin/bash', '-c',", source)
            self.assertIn("OpenSSH joins", source)

    def test_lab_dns_verifier_keeps_bridge_and_adm_views_distinct(self) -> None:
        """A Docker-bridge source is restricted, not an ADM DNS client."""
        restricted = self.verify.split(
            "Query the restricted platform DNS view over UDP and TCP from the host bridge", 1
        )[1].split(
            "Verify the restricted platform DNS view does not disclose ADM-only names", 1
        )[0]
        self.assertIn('"portal.{{ aigw_domain }}"', restricted)
        self.assertIn('"auth.{{ aigw_domain }}"', restricted)
        self.assertIn('"api.{{ aigw_domain }}"', restricted)
        # Owner decision: the internal view serves the dual-homed chat name.
        self.assertIn('"chat.{{ aigw_domain }}"', restricted)
        self.assertNotIn('"admin.{{ aigw_domain }}"', restricted)
        self.assertIn("lab_dns_restricted_queries.stdout | trim != eth2_ip", restricted)

        negative = self.verify.split(
            "Verify the restricted platform DNS view does not disclose ADM-only names", 1
        )[1].split(
            "Query the published ADM platform DNS view over UDP and TCP from the controller", 1
        )[0]
        self.assertIn('"admin-portal.{{ aigw_domain }}"', negative)
        self.assertIn('"litellm-admin.{{ aigw_domain }}"', negative)
        self.assertIn(
            '{ name: "vault.{{ aigw_domain }}", transport: +notcp }',
            negative,
        )
        self.assertIn(
            '{ name: "vault.{{ aigw_domain }}", transport: +tcp }',
            negative,
        )
        self.assertIn("status: NXDOMAIN", negative)

        adm = self.verify.split(
            "Query the published ADM platform DNS view over UDP and TCP from the controller", 1
        )[1].split(
            "Prove the platform DNS process cannot originate DNS", 1
        )[0]
        self.assertIn("delegate_to: localhost", adm)
        self.assertIn("become: false", adm)
        self.assertIn('"@{{ eth1_ip }}"', adm)
        self.assertIn('"admin.{{ aigw_domain }}"', adm)
        self.assertIn('"chat.{{ aigw_domain }}"', adm)
        self.assertIn('"portal.{{ aigw_domain }}"', adm)
        self.assertIn("source-policy routing", self.verify)

    def test_firewall_adoption_rejects_unmodeled_policy_before_mutation(self) -> None:
        self.assertIn("unreviewed /etc firewalld policy exists; remove it before converge", self.firewall_preflight)
        self.assertIn("active firewalld direct runtime state must be removed before converge", self.firewall_preflight)
        self.assertIn("unowned runtime zone", self.firewall_preflight)
        self.assertIn("aigw_adopt_firewalld_state", self.firewall_preflight)
        self.assertIn("has_reviewed_aigw_firewall_ownership", self.firewall_preflight)
        self.assertIn("aigw_host_pending_marker_valid", self.host)
        self.assertNotIn("explicit_adoption", self.firewall)
        self.assertIn("no inventory flag authorizes replacement", self.firewall)

    def test_firewall_adoption_can_resume_only_a_validated_pending_converge(self) -> None:
        namespace: dict[str, object] = {"__name__": "__firewall_ownership__"}
        exec(self.firewall_ownership_checker, namespace)
        ownership = namespace["has_reviewed_aigw_firewall_ownership"]

        self.assertTrue(ownership(True, False, False))
        # A byte-exact pending marker now resumes an interrupted converge on its
        # own — the same trust deploy-stack-only.yml already grants — so no
        # firewall adoption flag is required.
        self.assertTrue(ownership(False, True, False))
        self.assertTrue(ownership(False, True, True))
        # Fail-closed invariant: a genuinely foreign host has no valid marker,
        # so a bare adoption flag never grants ownership, and neither does an
        # entirely unmarked host.
        self.assertFalse(ownership(False, False, True))
        self.assertFalse(ownership(False, False, False))

        # The narrow recovery function must protect only the generated AIGW
        # objects; arbitrary direct/NM/firewalld state remains on `unowned`.
        for required in (
            "require_reviewed_aigw_firewall_ownership(",
            "unmarked inet/aigw_guard nftables policy",
            "DOCKER-USER policy",
            "unowned(\n                \"unreviewed /etc firewalld policy",
            "active firewalld direct runtime state must be removed",
            "set(project_zones) - managed_zones",
            "unexpected active AI Gateway firewalld zones",
        ):
            self.assertIn(required, self.firewall_preflight)

    def test_site_preflight_resumes_from_validated_pending_marker_without_adoption_flags(self) -> None:
        # host_preflight now proves ownership from a completed OR a byte-exact
        # pending marker, and records that as aigw_host_ownership_proven.
        self.assertIn("aigw_host_ownership_proven: >-", self.host)
        self.assertIn(
            "{{ (aigw_host_marker_stat.exists | default(false) | bool) or",
            self.host,
        )
        self.assertIn(
            "(aigw_host_pending_marker_stat.exists | default(false) | bool) }}",
            self.host,
        )
        # The marker shape and content asserts are relocated to run BEFORE the
        # artifact-adoption gate, so the proven fact is genuinely validated at
        # every consumer (a foreign/malformed marker aborts first; host_preflight
        # is the first, read-only role, so nothing has mutated).
        gate = self.host.index(
            "Preflight — reject unsafe or unowned existing AIGW-managed host artifacts"
        )
        for earlier in (
            "Preflight — reject symlinked or non-root host-boundary objects",
            "Preflight — require an existing marker to describe this exact host contract",
            "Preflight — require an in-progress marker to describe this exact host contract",
            "Preflight — record a validated dedicated-Docker-host ownership contract",
        ):
            self.assertLess(self.host.index(earlier), gate, earlier)
        # The old unconditional "require adoption to resume" assert is gone; a
        # validated pending marker now resumes with only an informational note,
        # never a demand for aigw_adopt_dedicated_docker_host.
        self.assertNotIn(
            "Preflight — require explicit adoption to resume an incomplete host converge",
            self.host,
        )
        self.assertIn(
            "Preflight — note resuming an interrupted converge from a validated pending marker",
            self.host,
        )
        self.assertIn(
            "resuming an interrupted converge from a validated pending marker; no",
            self.host,
        )
        resume = self.host.split(
            "Preflight — note resuming an interrupted converge from a validated pending marker",
            1,
        )[1].split("\n- name:", 1)[0]
        self.assertIn("ansible.builtin.debug:", resume)
        self.assertIn(
            "when: aigw_host_pending_marker_stat.exists | default(false)", resume
        )
        self.assertNotIn("ansible.builtin.assert:", resume)
        self.assertNotIn("aigw_adopt_dedicated_docker_host | bool", resume)

    def test_site_preflight_still_requires_adoption_for_unmarked_managed_artifacts(self) -> None:
        # Foreign/unmarked host: ownership false, no adoption flag → the gate
        # must still refuse a retained managed artifact.
        with self.assertRaises(SystemExit) as unmarked:
            self.run_artifact_adoption_gate(has_ownership=False)
        self.assertIn(
            "requires explicit docker adoption", str(unmarked.exception)
        )
        # A validated pending (or completed) marker proves ownership → the gate
        # passes with no adoption flag, exactly as a completed marker would.
        self.run_artifact_adoption_gate(has_ownership=True)
        # The explicit adoption flag still works for a genuinely unmarked host.
        self.run_artifact_adoption_gate(has_ownership=False, docker_adoption=True)
        # The gate consumes the proven-ownership fact, not raw completed-marker
        # existence, so a byte-exact pending marker is trusted here too.
        self.assertIn(
            "'true' if (aigw_host_ownership_proven | default(false) | bool) else 'false'",
            self.host,
        )

    def test_completed_marker_gates_accept_a_validated_pending_marker(self) -> None:
        # The three ownership gates that previously trusted only a completed
        # marker now consume aigw_host_ownership_proven, so a validated pending
        # marker (a resumed first converge) satisfies them without adoption.
        for gate in (
            "Preflight — reject an unmarked nonempty stack directory without explicit adoption",
            "Preflight — require a non-running Docker root to be empty unless this is a marked AIGW host",
            "Preflight — require explicit adoption for retained named volumes on an unmarked Docker host",
        ):
            block = self.host.split(gate, 1)[1].split("\n- name:", 1)[0]
            self.assertIn(
                "(aigw_host_ownership_proven | default(false) | bool) or", block
            )
            self.assertNotIn("aigw_host_marker_stat.exists", block)
        # Exactly those three gates flipped to the proven-ownership fact.
        self.assertEqual(
            3,
            self.host.count(
                "(aigw_host_ownership_proven | default(false) | bool) or"
            ),
        )
        # The daemon.json adoption gate is deliberately LEFT on the completed
        # marker only: a resumed pending converge must not silently adopt a
        # foreign /etc/docker/daemon.json.
        daemon = self.host.split(
            "Preflight — allow only a clean, marked, legacy-AIGW-only, or explicitly adopted daemon configuration",
            1,
        )[1]
        self.assertIn("(aigw_host_marker_stat.exists | default(false)) or", daemon)
        self.assertNotIn("aigw_host_ownership_proven", daemon)

    def test_site_and_stack_only_agree_on_pending_marker_ownership(self) -> None:
        # Both entrypoints accept the identical byte-exact pending-marker
        # contract as an ownership signal with no adoption flag. site.yml runs
        # host_preflight (ownership from completed OR pending); stack-only runs
        # its own marker gate that trusts either marker's existence.
        for source in (self.host, self.stack_only):
            self.assertIn("format=aigw-dedicated-docker-host-v1", source)
            self.assertIn("project={{ compose_project_name }}", source)
            self.assertIn("docker_data_root={{ docker_data_root }}", source)
        self.assertIn("aigw_host_ownership_proven: >-", self.host)
        self.assertIn(
            "(aigw_host_pending_marker_stat.exists | default(false) | bool) }}",
            self.host,
        )
        self.assertIn(
            "(stack_only_host_markers.results[0].stat.exists | default(false)) or\n"
            "            (stack_only_host_markers.results[1].stat.exists | default(false))",
            self.stack_only,
        )
        # Neither entrypoint demands an adoption flag to trust a byte-exact
        # pending marker.
        self.assertNotIn(
            "Preflight — require explicit adoption to resume an incomplete host converge",
            self.host,
        )
        self.assertNotIn("aigw_adopt_dedicated_docker_host", self.stack_only)

    def test_firewall_preflight_accepts_only_the_exact_docker_engine_29_zone(self) -> None:
        import os
        import stat
        import tempfile
        import xml.etree.ElementTree as ET

        namespace: dict[str, object] = {
            "__name__": "__docker_zone_checker__",
            "os": os,
            "stat": stat,
            "ET": ET,
            "managed_zones": set(),
            "interfaces": {},
        }
        exec(self.docker_zone_checker, namespace)
        zone_content = namespace["docker_firewalld_zone_content"]
        is_exact_zone = namespace["is_exact_docker_firewalld_zone"]

        self.assertIn('docker_firewalld_zone_path = "/etc/firewalld/zones/docker.xml"', self.firewall_preflight)
        self.assertIn('b\'<zone version="1.0" target="ACCEPT">\\n\'', self.firewall_preflight)
        self.assertIn("elif entry.path == docker_firewalld_zone_path:", self.firewall_preflight)
        self.assertNotIn('entry.path.endswith("docker.xml")', self.firewall_preflight)

        with tempfile.NamedTemporaryFile(mode="wb") as source:
            source.write(zone_content)
            source.flush()
            namespace["docker_firewalld_zone_path"] = source.name
            metadata = SimpleNamespace(
                st_mode=stat.S_IFREG | 0o644,
                st_uid=0,
                st_gid=0,
                st_size=len(zone_content),
            )
            self.assertTrue(is_exact_zone(source.name, metadata))
            self.assertFalse(
                is_exact_zone(
                    source.name,
                    SimpleNamespace(
                        st_mode=stat.S_IFREG | 0o600,
                        st_uid=0,
                        st_gid=0,
                        st_size=len(zone_content),
                    ),
                )
            )
            self.assertFalse(
                is_exact_zone(
                    source.name,
                    SimpleNamespace(
                        st_mode=stat.S_IFREG | 0o644,
                        st_uid=1000,
                        st_gid=0,
                        st_size=len(zone_content),
                    ),
                )
            )
            source.seek(0)
            source.write(zone_content.replace(b'target="ACCEPT"', b'target="REJECT"'))
            source.truncate()
            source.flush()
            self.assertFalse(is_exact_zone(source.name, metadata))
            source.seek(0)
            source.truncate()
            source.flush()
            self.assertFalse(
                is_exact_zone(
                    source.name,
                    SimpleNamespace(
                        st_mode=stat.S_IFREG | 0o644,
                        st_uid=0,
                        st_gid=0,
                        st_size=0,
                    ),
                )
            )

    def test_firewall_preflight_accepts_only_the_exact_docker_engine_29_policy(self) -> None:
        import os
        import stat
        import tempfile
        import xml.etree.ElementTree as ET

        namespace: dict[str, object] = {
            "__name__": "__docker_policy_checker__",
            "os": os,
            "stat": stat,
            "ET": ET,
            "managed_zones": set(),
            "interfaces": {},
        }
        exec(self.docker_zone_checker, namespace)
        policy_content = namespace["docker_firewalld_policy_content"]
        is_exact_policy = namespace["is_exact_docker_firewalld_policy"]

        with tempfile.NamedTemporaryFile(mode="wb") as source:
            source.write(policy_content)
            source.flush()
            namespace["docker_firewalld_policy_path"] = source.name
            metadata = SimpleNamespace(
                st_mode=stat.S_IFREG | 0o644,
                st_uid=0,
                st_gid=0,
                st_size=len(policy_content),
            )
            self.assertTrue(is_exact_policy(source.name, metadata))
            self.assertFalse(
                is_exact_policy(
                    source.name,
                    SimpleNamespace(
                        st_mode=stat.S_IFREG | 0o644,
                        st_uid=0,
                        st_gid=0,
                        st_size=len(policy_content) - 1,
                    ),
                )
            )
            source.seek(0)
            source.write(
                policy_content.replace(b'name="docker"', b'name="untrusted"')
            )
            source.truncate()
            source.flush()
            self.assertFalse(is_exact_policy(source.name, metadata))

    def test_firewall_preflight_accepts_only_generated_managed_zone_backups(self) -> None:
        import os
        import stat
        import tempfile
        import xml.etree.ElementTree as ET
        from unittest.mock import patch

        namespace: dict[str, object] = {
            "__name__": "__aigw_zone_backup_checker__",
            "os": os,
            "stat": stat,
            "ET": ET,
            "managed_zones": {"aigw-adm"},
            "interfaces": {"enp0s7": "aigw-adm"},
        }
        exec(self.docker_zone_checker, namespace)
        is_generated_backup = namespace["is_generated_aigw_zone_backup"]

        current = (
            b'<zone target="%%REJECT%%">\n'
            b'  <rule family="ipv4"><source address="10.8.10.0/24"/>'
            b'<port port="443" protocol="tcp"/><accept/></rule>\n'
            b'  <interface name="enp0s7"/>\n'
            b'</zone>\n'
        )
        backup = current.replace(b'  <interface name="enp0s7"/>\n', b"")

        with tempfile.TemporaryDirectory() as directory:
            current_path = os.path.join(directory, "aigw-adm.xml")
            backup_path = current_path + ".old"
            with open(current_path, "wb") as source:
                source.write(current)
            with open(backup_path, "wb") as source:
                source.write(backup)

            real_lstat = os.lstat

            def root_owned_lstat(path: str):
                metadata = real_lstat(path)
                return SimpleNamespace(
                    st_mode=metadata.st_mode,
                    st_uid=0,
                    st_gid=0,
                    st_size=metadata.st_size,
                )

            metadata = root_owned_lstat(backup_path)
            with patch.object(os, "lstat", side_effect=root_owned_lstat):
                self.assertTrue(
                    is_generated_backup(
                        backup_path, metadata, zone_directory=directory
                    )
                )
                with open(backup_path, "wb") as source:
                    source.write(
                        backup.replace(
                            b"</zone>", b'<service name="ssh"/></zone>'
                        )
                    )
                self.assertFalse(
                    is_generated_backup(
                        backup_path,
                        root_owned_lstat(backup_path),
                        zone_directory=directory,
                    )
                )

    def test_firewall_preflight_accepts_only_the_pristine_rpm_default_whitelist(self) -> None:
        for required in (
            "is_pristine_firewalld_package_default",
            'path != "/etc/firewalld/lockdown-whitelist.xml"',
            'owner.stdout.strip() != "firewalld"',
            "%{FILEDIGESTS}",
            'content = source.read(65537)',
            'actual = hashlib.sha256(content).hexdigest()',
            'mode != stat.filemode(metadata.st_mode)',
            'owner_name != "root"',
            'group_name != "root"',
            'records = [line.split("\\t") for line in query.stdout.splitlines()]',
        ):
            self.assertIn(required, self.firewall_preflight)
        self.assertIn(
            "and not is_pristine_firewalld_package_default(path, metadata)",
            self.firewall_preflight,
        )
        self.assertNotIn(
            'records = [line.split("\\\\t") for line in query.stdout.splitlines()]',
            self.firewall_preflight,
        )

    def test_only_the_exact_rocky9_lab_reset_handoff_may_retain_drop(self) -> None:
        self.assertIn("aigw_lab_reset_handoff_drop_interfaces: []", self.group)
        self.assertIn(
            'aigw_lab_reset_handoff_drop_interfaces: ["{{ nic_egress }}", "{{ nic_internal }}"]',
            self.lab,
        )
        for source in (self.firewall_preflight, self.firewall):
            self.assertIn(
                "derive the exact fail-closed Rocky 9 lab reset handoff", source
            )
            self.assertIn("(deployment_profile | default('')) == 'rocky9-lab'", source)
            self.assertIn("aigw_lab_reset_handoff_drop_interfaces", source)
            self.assertIn("aigw_lab_reset_handoff_drop_bindings", source)
            self.assertIn("{'interface': nic_egress, 'zone': 'aigw-egress'}", source)
            self.assertIn("{'interface': nic_internal, 'zone': 'aigw-internal'}", source)
        self.assertIn('saved_zone == "drop"', self.firewall_preflight)
        self.assertIn('runtime_zone == "drop"', self.firewall_preflight)
        self.assertGreaterEqual(self.firewall.count("(item.stdout | trim) == 'drop'"), 2)
        self.assertIn("lab reset drop-zone handoff does not match reviewed interfaces", self.firewall_preflight)
        self.assertNotIn("expected_zone, 'drop'", self.firewall_preflight)

    def test_native_guard_drops_internal_egress_both_directions_before_replies(self) -> None:
        forward = self.nft_guard.split("chain container_forward {", 1)[1]
        reply = forward.index("ct state established,related ct direction reply accept")
        internal_to_egress = (
            'iifname "{{ nic_internal }}" oifname "{{ nic_egress }}" drop'
        )
        egress_to_internal = (
            'iifname "{{ nic_egress }}" oifname "{{ nic_internal }}" drop'
        )
        self.assertLess(forward.index(internal_to_egress), reply)
        self.assertLess(forward.index(egress_to_internal), reply)
        for source in (self.verify, self.stack_only):
            self.assertIn("cross-plane drop occurs after reply allowance", source)
            self.assertIn("physical cross-plane accept exists", source)

    def test_site_is_exactly_the_host_prep_then_stack_composition(self) -> None:
        """site.yml composes os-prep.yml and deploy-stack-only.yml, nothing else."""
        imports = [
            line for line in self.site.splitlines()
            if line.startswith("- import_playbook:")
        ]
        self.assertEqual(
            imports,
            [
                "- import_playbook: os-prep.yml",
                "- import_playbook: deploy-stack-only.yml",
            ],
        )
        # The composition holds no play of its own; every gate and role lives
        # in the two imported playbooks.
        for forbidden in ("hosts:", "pre_tasks:", "roles:", "tasks:"):
            self.assertNotIn(forbidden, self.site)
        # Host preparation stops at the Docker bridges; the stack phase owns
        # docker_stack, verify, and the marker promotion.
        self.assertIn("- role: docker_networks", self.os_prep)
        for stack_role in ("- role: docker_stack", "- role: verify", "- role: host_finalize"):
            self.assertNotIn(stack_role, self.os_prep)
            self.assertIn(stack_role, self.stack_only)
        roles = self.stack_only.split("  roles:", 1)[1]
        self.assertLess(roles.index("- role: docker_stack"), roles.index("- role: verify"))
        self.assertLess(roles.index("- role: verify"), roles.index("- role: host_finalize"))

    def test_stack_only_marker_gate_accepts_host_prep_and_refuses_unprepared_hosts(self) -> None:
        """First deploy trusts os-prep's pending marker; no marker is refused.

        The completed marker still attests a verified full converge; the
        pending marker is the sanctioned host-prep-done ownership signal that
        os_baseline writes during os-prep.yml. Either must byte-match the
        exact dedicated-Docker-host contract; a host with neither never ran
        host preparation.
        """
        self.assertIn(
            "Preflight — require an exact completed or host-prep dedicated-host marker",
            self.stack_only,
        )
        # Both markers are shape- and content-checked against the exact contract.
        self.assertIn(
            "(stack_only_docker_host_marker_raw.content | b64decode) == aigw_docker_host_marker_content",
            self.stack_only,
        )
        self.assertIn(
            "(stack_only_docker_host_pending_marker_raw.content | b64decode) == aigw_docker_host_marker_content",
            self.stack_only,
        )
        # At least one marker must exist; an unprepared host is refused toward
        # os-prep.yml, never silently adopted.
        self.assertIn(
            "(stack_only_host_markers.results[0].stat.exists | default(false)) or\n"
            "            (stack_only_host_markers.results[1].stat.exists | default(false))",
            self.stack_only,
        )
        self.assertIn("run ansible/os-prep.yml", self.stack_only)
        self.assertIn(
            "never prepared as a dedicated AI Gateway Docker host", self.stack_only
        )
        # The marker contract is one definition shared with host_preflight and
        # host_finalize: same format string, same 0600 root:root shape.
        self.assertIn("format=aigw-dedicated-docker-host-v1", self.stack_only)
        self.assertIn("format=aigw-dedicated-docker-host-v1", self.host)
        self.assertIn("aigw_docker_host_marker_content: |", self.stack_only)
        self.assertEqual(2, self.stack_only.count("stat.mode == '0600'"))
        # os_baseline still records the pending ownership contract during host
        # prep, and only host_finalize promotes the completed marker.
        self.assertIn(
            "Record an in-progress dedicated-Docker-host ownership contract before daemon mutation",
            self.os_baseline,
        )
        finalize = (
            ROOT / "ansible" / "roles" / "host_finalize" / "tasks" / "main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("Finalize — promote the verified dedicated-Docker-host marker", finalize)
        self.assertIn("Finalize — remove the in-progress dedicated-Docker-host marker", finalize)
        # Composed converges keep selinux_baseline's wider AVC audit window;
        # only a standalone stack-only run opens its own.
        self.assertIn(
            "when: aigw_selinux_audit_window_start is not defined", self.stack_only
        )
        self.assertIn(
            'aigw_selinux_audit_window_start: "{{ stack_only_selinux_audit_window_start }}"',
            self.stack_only,
        )

    def test_site_preflight_requires_firewall_and_only_declared_policy_routing(self) -> None:
        for required in (
            "manage_firewalld | bool",
            "(manage_networking | bool) or pbr_tables | length == 0",
            "not (manage_networking | bool) or pbr_tables | length == 2",
            "pbr_tables | map(attribute='id') | unique",
            "vpn_client_cidr",
            "internal_cidr",
        ):
            self.assertIn(required, self.os_prep)

    def test_policy_table_guard_accepts_only_main_connected_routes_on_the_target_nic(self) -> None:
        # `ip -j route show ... dev enp0s7` suppresses the `dev` key on Rocky
        # 9.  The guard must instead inspect all link routes and explicitly
        # filter the target NIC, otherwise its own copied connected routes are
        # falsely classified as foreign immediately after a clean deploy.
        self.assertIn(
            'invoke("-j", "-4", "route", "show", "table", "main")', self.os_prep
        )
        self.assertIn('if route.get("dev") == device', self.os_prep)
        self.assertIn('route.get("scope") != "link"', self.os_prep)
        self.assertIn('route.get("gateway") is not None', self.os_prep)
        self.assertNotIn(
            '"table", "main", "dev", device, "scope", "link"', self.os_prep
        )

        routes = {
                ("-j", "-4", "rule", "show"): [
                    {"priority": 0, "src": "all", "table": "local"},
                    {"priority": 10101, "src": "10.8.10.10", "table": "adm"},
                    {"priority": 10102, "src": "10.20.0.10", "table": "internal"},
                    {"priority": 32766, "src": "all", "table": "main"},
                ],
                ("-j", "-4", "route", "show", "table", "101"): [
                    {"dst": "default", "gateway": "10.8.10.2", "dev": "enp0s7", "prefsrc": "10.8.10.10"},
                    {"dst": "10.8.10.0/24", "dev": "enp0s7", "scope": "link"},
                ],
                ("-j", "-4", "route", "show", "table", "102"): [
                    {"dst": "default", "gateway": "10.20.0.2", "dev": "enp0s8", "prefsrc": "10.20.0.10"},
                    {"dst": "10.20.0.0/24", "dev": "enp0s8", "scope": "link"},
                ],
                ("-j", "-4", "route", "show", "table", "main"): [
                    {"dst": "10.8.10.0/24", "dev": "enp0s7", "scope": "link"},
                    {"dst": "10.20.0.0/24", "dev": "enp0s8", "scope": "link"},
                    {"dst": "10.211.55.0/24", "dev": "enp0s5", "scope": "link"},
                ],
            }
        self.run_policy_table_validator(routes)

        # A foreign non-link route must not pass simply because it uses the
        # same destination and NIC as the host's connected route.
        foreign_routes = copy.deepcopy(routes)
        foreign_routes[("-j", "-4", "route", "show", "table", "101")][1] = {
            "dst": "10.8.10.0/24",
            "gateway": "10.8.10.2",
            "dev": "enp0s7",
            "protocol": "static",
            "prefsrc": "10.8.10.10",
            "metric": 101,
        }
        with self.assertRaises(SystemExit) as foreign_error:
            self.run_policy_table_validator(foreign_routes)
        self.assertIn("table 101 has a non-AIGW route", str(foreign_error.exception))


if __name__ == "__main__":
    unittest.main()
