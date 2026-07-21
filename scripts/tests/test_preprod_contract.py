from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import tempfile
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]


def load_preprod_module():
    path = ROOT / "scripts/preprod.py"
    spec = importlib.util.spec_from_file_location("aigw_preprod", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PreprodContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.script = (ROOT / "scripts/preprod.py").read_text()
        self.compose = (ROOT / "compose/docker-compose.preprod.yml").read_text()
        self.tasks = (ROOT / "ansible/roles/preprod_stack/tasks/present.yml").read_text()

    def test_operator_entry_point_is_local_and_does_not_call_host_roles(self) -> None:
        inventory = (ROOT / "ansible/inventory/preprod.yml").read_text()
        playbook = (ROOT / "ansible/preprod.yml").read_text()
        self.assertIn("ansible_connection: local", inventory)
        self.assertIn("aigw_domain: aigw.internal", inventory)
        self.assertIn("aigw_domain: aigw.internal", playbook)
        self.assertIn("preprod_project_name: aigw-preprod", playbook)
        self.assertIn("preprod_resource_prefix: aigw-preprod", playbook)
        self.assertIn("preprod_subnet_octet: 29", playbook)
        self.assertIn("- preprod_stack", playbook)
        self.assertIn("preprod_state == 'present'", playbook)
        destroy_playbook = (ROOT / "ansible/preprod-destroy.yml").read_text()
        absent_tasks = (
            ROOT / "ansible/roles/preprod_stack/tasks/absent.yml"
        ).read_text()
        self.assertIn("preprod_state == 'absent'", destroy_playbook)
        self.assertIn("DESTROY_AIGW_PREPROD", destroy_playbook)
        self.assertIn("DESTROY_AIGW_PREPROD", absent_tasks)
        self.assertLess(
            absent_tasks.index("DESTROY_AIGW_PREPROD"),
            absent_tasks.index("preprod.py"),
        )
        for role in (
            "host_preflight",
            "firewalld_zones",
            "os_baseline",
            "docker_networks",
            "docker_stack",
        ):
            self.assertNotIn(f"- {role}", playbook)

    def test_preprod_has_no_retired_runtime_dependency(self) -> None:
        public_runtime = "\n".join(
            [
                self.script,
                self.compose,
                self.tasks,
                (ROOT / "ansible/preprod.yml").read_text(),
                (ROOT / "ansible/preprod-destroy.yml").read_text(),
                (ROOT / "ansible/inventory/preprod.yml").read_text(),
            ]
        )
        for forbidden in (
            "docker-compose.lab.yml",
            "samba-ad-" + "lab",
            "lab-ad",
            "lab-aigw01",
            "reset-rocky9-lab",
            "Parallels",
        ):
            self.assertNotIn(forbidden, public_runtime)
        self.assertIn("profiles: [preprod]", self.compose)
        self.assertIn("../services/samba-ad-preprod", self.compose)

    def test_three_plane_names_and_loopback_publication_are_exact(self) -> None:
        for name in (
            '${PREPROD_PREFIX}-plane-egress',
            '${PREPROD_PREFIX}-plane-adm',
            '${PREPROD_PREFIX}-plane-internal',
        ):
            self.assertIn(name, self.compose)
        self.assertIn('"ETH1_IP": "127.0.3.1"', self.script)
        self.assertIn('"ETH2_IP": "127.0.2.1"', self.script)
        self.assertIn('"PG_DATA_VOLUME_NAME": f"{args.project}_pg18_data"', self.script)
        self.assertIn("com.aigw.preprod.project", self.script)
        self.assertIn("local Unix-socket Docker context", self.script)

    def test_dynamic_ipam_cannot_steal_reviewed_fixed_addresses(self) -> None:
        module = load_preprod_module()
        self.assertEqual(
            module.dynamic_ip_range("172.29.5.0/24"),
            "172.29.5.128/25",
        )
        self.assertIn('"--ip-range", dynamic_ip_range(subnet)', self.script)

        args = types.SimpleNamespace(project="aigw-preprod")
        existing_without_reserved_range = {
            "aigw-preprod-net-admin-app": {
                "IPAM": {"Config": [{"Subnet": "172.29.5.0/24"}]},
                "Internal": True,
                "Labels": {"com.aigw.preprod.project": "aigw-preprod"},
                "Driver": "bridge",
                "Scope": "local",
                "Containers": {},
            }
        }
        with (
            mock.patch.object(module, "check_context"),
            mock.patch.object(
                module, "existing_networks", return_value=existing_without_reserved_range
            ),
            mock.patch.object(
                module,
                "desired_networks",
                return_value={"aigw-preprod-net-admin-app": ("172.29.5.0/24", True)},
            ),
        ):
            with self.assertRaisesRegex(SystemExit, "wrong ownership or settings"):
                module.create_networks(args)

    def test_postgres18_volume_uses_its_explicit_preprod_physical_name(self) -> None:
        module = load_preprod_module()
        args = types.SimpleNamespace(project="aigw-preprod")
        labels = {
            "com.aigw.preprod.project": args.project,
            "com.aigw.preprod.config-digest": "a" * 64,
        }
        model = {
            "services": {
                "alloy": {
                    "labels": labels,
                    "volumes": [
                        {
                            "type": "volume",
                            "source": "preprod_empty_docker_logs",
                            "target": "/var/lib/docker/containers",
                            "read_only": True,
                        }
                    ],
                }
            },
            "networks": {},
            "volumes": {
                "pg_data": {
                    "name": "aigw-preprod_pg18_data",
                    "labels": labels,
                },
                "vault_data": {
                    "name": "aigw-preprod_vault_data",
                    "labels": labels,
                },
            },
        }

        def env_value(name: str) -> str:
            if name == "AIGW_PREPROD_CONFIG_DIGEST":
                return "a" * 64
            if name == "PG_DATA_VOLUME_NAME":
                return "aigw-preprod_pg18_data"
            return ""

        with (
            mock.patch.object(module, "PREPROD_BIND_SOURCES", ()),
            mock.patch.object(module, "desired_networks", return_value={}),
            mock.patch.object(module, "preprod_env_value", side_effect=env_value),
        ):
            names = module.verify_rendered_resource_ownership(args, model)
        self.assertEqual(
            names,
            {"aigw-preprod_pg18_data", "aigw-preprod_vault_data"},
        )

    def test_macos_seed_loader_runs_as_the_recorded_docker_user(self) -> None:
        module = load_preprod_module()
        args = types.SimpleNamespace(
            archive="/private/release.preprod.docker.tar.zst",
            archive_sha256="a" * 64,
            manifest="/private/release.preprod.manifest.json",
            manifest_sha256="b" * 64,
        )
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            secrets = Path(directory) / "secrets"
            secrets.mkdir()
            uid = os.geteuid()
            gid = os.getegid()
            completed = subprocess.CompletedProcess(
                [], 0, "LOADED " + "a" * 64 + "\n", ""
            )
            with (
                mock.patch.object(module, "SECRETS_DIR", secrets),
                mock.patch.object(module, "recorded_preprod_owner", return_value=(uid, gid)),
                mock.patch.object(module, "check_context"),
                mock.patch.object(
                    module,
                    "local_docker_endpoint",
                    return_value="unix:///private/tmp/preprod-docker.sock",
                ),
                mock.patch.object(module, "run", return_value=completed) as runner,
                mock.patch("sys.stdout", new_callable=io.StringIO) as stdout,
            ):
                module.load_local_preprod_seed(args)
            command = runner.call_args.args[0]
            self.assertIn("local-preprod-load", command)
            self.assertIn(args.archive_sha256, command)
            self.assertIn(args.manifest_sha256, command)
            self.assertEqual(
                command[-1], "unix:///private/tmp/preprod-docker.sock"
            )
            self.assertFalse(Path(command[-2]).exists())
            self.assertIn("PREPROD_LOCAL_SEED_LOADED", stdout.getvalue())

    def test_macos_loopback_alias_tasks_are_bounded_and_ordered(self) -> None:
        present = self.tasks
        absent = (
            ROOT / "ansible/roles/preprod_stack/tasks/absent.yml"
        ).read_text()
        role = (ROOT / "ansible/roles/preprod_stack/tasks/main.yml").read_text()
        self.assertIn("/usr/bin/uname", role)
        self.assertIn("['Darwin', 'Linux']", role)

        ensure = present.index(
            "- name: Create only missing macOS preprod loopback aliases"
        )
        start = present.index("- name: Start the isolated preprod project")
        self.assertLess(ensure, start)
        ensure_task = present[ensure:start]
        self.assertIn("ensure-loopback-aliases", ensure_task)
        self.assertIn("become: true", ensure_task)
        self.assertIn("== 'Darwin'", ensure_task)

        destroy = absent.index(
            "- name: Remove only the named preprod containers, volumes, and networks"
        )
        remove = absent.index(
            "- name: Remove only macOS loopback aliases owned by this preprod"
        )
        self.assertLess(destroy, remove)
        remove_task = absent[remove:]
        self.assertIn("remove-loopback-aliases", remove_task)
        self.assertIn("become: true", remove_task)
        self.assertIn("== 'Darwin'", remove_task)

    def test_macos_loopback_preserves_preexisting_aliases_on_teardown(self) -> None:
        module = load_preprod_module()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            state_dir = Path(directory) / "state"
            state_file = state_dir / "loopback-aliases-v1.json"
            addresses = [
                {"127.0.2.1"},
                {"127.0.2.1", "127.0.3.1"},
                {"127.0.2.1", "127.0.3.1"},
                {"127.0.2.1"},
            ]
            with (
                mock.patch.object(module.sys, "platform", "darwin"),
                mock.patch.object(module.os, "geteuid", return_value=os.geteuid()),
                mock.patch.multiple(
                    module,
                    ROOT_UID=os.geteuid(),
                    ROOT_GID=os.getegid(),
                    LOOPBACK_STATE_DIR=state_dir,
                    LOOPBACK_STATE_FILE=state_file,
                ),
                mock.patch.object(
                    module,
                    "darwin_loopback_addresses",
                    side_effect=addresses,
                ),
                mock.patch.object(
                    module,
                    "darwin_boot_session",
                    return_value="11111111-2222-3333-4444-555555555555",
                ),
                mock.patch.object(module, "run") as runner,
                mock.patch("sys.stdout", new_callable=io.StringIO),
            ):
                module.ensure_loopback_aliases(mock.Mock())
                state = json.loads(state_file.read_text(encoding="utf-8"))
                self.assertEqual(state["owned_aliases"], ["127.0.3.1"])
                module.remove_loopback_aliases(mock.Mock())

            self.assertFalse(state_file.exists())
            self.assertEqual(
                [call.args[0] for call in runner.call_args_list],
                [
                    [
                        "/sbin/ifconfig", "lo0", "alias", "127.0.3.1",
                        "netmask", "255.255.255.0",
                    ],
                    ["/sbin/ifconfig", "lo0", "-alias", "127.0.3.1"],
                ],
            )

    def test_macos_loopback_does_not_claim_existing_aliases(self) -> None:
        module = load_preprod_module()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            state_dir = Path(directory) / "state"
            state_file = state_dir / "loopback-aliases-v1.json"
            with (
                mock.patch.object(module.sys, "platform", "darwin"),
                mock.patch.object(module.os, "geteuid", return_value=os.geteuid()),
                mock.patch.multiple(
                    module,
                    ROOT_UID=os.geteuid(),
                    ROOT_GID=os.getegid(),
                    LOOPBACK_STATE_DIR=state_dir,
                    LOOPBACK_STATE_FILE=state_file,
                ),
                mock.patch.object(
                    module,
                    "darwin_loopback_addresses",
                    return_value={"127.0.2.1", "127.0.3.1"},
                ),
                mock.patch.object(
                    module,
                    "darwin_boot_session",
                    return_value="11111111-2222-3333-4444-555555555555",
                ),
                mock.patch.object(module, "run") as runner,
                mock.patch("sys.stdout", new_callable=io.StringIO),
            ):
                module.ensure_loopback_aliases(mock.Mock())
                module.remove_loopback_aliases(mock.Mock())

            runner.assert_not_called()
            self.assertFalse(state_dir.exists())

    def test_macos_loopback_ignores_a_stale_boot_ownership_record(self) -> None:
        module = load_preprod_module()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            state_dir = Path(directory) / "state"
            state_file = state_dir / "loopback-aliases-v1.json"
            state_dir.mkdir(mode=0o700)
            state_file.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "project": "aigw-preprod",
                        "interface": "lo0",
                        "boot_session": "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
                        "owned_aliases": ["127.0.2.1", "127.0.3.1"],
                    }
                ),
                encoding="utf-8",
            )
            state_file.chmod(0o600)
            with (
                mock.patch.object(module.sys, "platform", "darwin"),
                mock.patch.object(module.os, "geteuid", return_value=os.geteuid()),
                mock.patch.multiple(
                    module,
                    ROOT_UID=os.geteuid(),
                    ROOT_GID=os.getegid(),
                    LOOPBACK_STATE_DIR=state_dir,
                    LOOPBACK_STATE_FILE=state_file,
                ),
                mock.patch.object(
                    module,
                    "darwin_boot_session",
                    return_value="11111111-2222-3333-4444-555555555555",
                ),
                mock.patch.object(
                    module,
                    "darwin_loopback_addresses",
                    return_value={"127.0.2.1", "127.0.3.1"},
                ),
                mock.patch.object(module, "run") as runner,
                mock.patch("sys.stdout", new_callable=io.StringIO),
            ):
                module.ensure_loopback_aliases(mock.Mock())

            runner.assert_not_called()
            self.assertFalse(state_file.exists())

    def test_macos_loopback_rolls_back_when_ownership_record_fails(self) -> None:
        module = load_preprod_module()
        with (
            mock.patch.object(module.sys, "platform", "darwin"),
            mock.patch.object(module.os, "geteuid", return_value=0),
            mock.patch.object(module, "read_loopback_state", return_value=set()),
            mock.patch.object(
                module,
                "darwin_loopback_addresses",
                side_effect=[set(), {"127.0.2.1"}, set()],
            ),
            mock.patch.object(
                module,
                "write_loopback_state",
                side_effect=SystemExit("state failed"),
            ),
            mock.patch.object(module, "run") as runner,
        ):
            with self.assertRaisesRegex(SystemExit, "state failed"):
                module.ensure_loopback_aliases(mock.Mock())
        self.assertEqual(
            [call.args[0] for call in runner.call_args_list],
            [
                [
                    "/sbin/ifconfig", "lo0", "alias", "127.0.2.1",
                    "netmask", "255.255.255.0",
                ],
                ["/sbin/ifconfig", "lo0", "-alias", "127.0.2.1"],
            ],
        )

    def test_macos_loopback_rolls_back_when_post_add_inspection_fails(self) -> None:
        module = load_preprod_module()
        with (
            mock.patch.object(module.sys, "platform", "darwin"),
            mock.patch.object(module.os, "geteuid", return_value=0),
            mock.patch.object(module, "read_loopback_state", return_value=set()),
            mock.patch.object(
                module,
                "darwin_loopback_addresses",
                side_effect=[set(), SystemExit("inspection failed"), set()],
            ),
            mock.patch.object(module, "write_loopback_state") as write_state,
            mock.patch.object(module, "run") as runner,
        ):
            with self.assertRaisesRegex(SystemExit, "inspection failed"):
                module.ensure_loopback_aliases(mock.Mock())
        write_state.assert_not_called()
        self.assertEqual(
            [call.args[0] for call in runner.call_args_list],
            [
                [
                    "/sbin/ifconfig", "lo0", "alias", "127.0.2.1",
                    "netmask", "255.255.255.0",
                ],
                ["/sbin/ifconfig", "lo0", "-alias", "127.0.2.1"],
            ],
        )

    def test_macos_loopback_parser_requires_each_alias_at_most_once(self) -> None:
        module = load_preprod_module()
        output = subprocess.CompletedProcess(
            [],
            0,
            "lo0: flags=8049<UP,LOOPBACK,RUNNING>\n"
            "\tinet 127.0.0.1 netmask 0xff000000\n"
            "\tinet 127.0.2.1 netmask 0xffffff00\n"
            "\tinet 127.0.3.1 netmask 0xffffff00\n",
            "",
        )
        with mock.patch.object(module, "run", return_value=output):
            self.assertEqual(
                module.darwin_loopback_addresses(),
                {"127.0.2.1", "127.0.3.1"},
            )

        duplicate = subprocess.CompletedProcess(
            [],
            0,
            output.stdout + "\tinet 127.0.2.1 netmask 0xffffff00\n",
            "",
        )
        with mock.patch.object(module, "run", return_value=duplicate):
            with self.assertRaisesRegex(SystemExit, "appears more than once"):
                module.darwin_loopback_addresses()

    def test_loopback_alias_state_and_linux_path_fail_closed(self) -> None:
        module = load_preprod_module()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            state_dir = Path(directory) / "state"
            state_file = state_dir / "loopback-aliases-v1.json"
            state_dir.mkdir(mode=0o700)
            state_file.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "project": "aigw-preprod",
                        "interface": "lo0",
                        "boot_session": "11111111-2222-3333-4444-555555555555",
                        "owned_aliases": ["127.0.2.1"],
                    }
                ),
                encoding="utf-8",
            )
            state_file.chmod(0o644)
            with mock.patch.multiple(
                module,
                ROOT_UID=os.geteuid(),
                ROOT_GID=os.getegid(),
                LOOPBACK_STATE_DIR=state_dir,
                LOOPBACK_STATE_FILE=state_file,
            ):
                with self.assertRaisesRegex(SystemExit, "ownership record is unsafe"):
                    module.read_loopback_state()

            with (
                mock.patch.object(module.sys, "platform", "linux"),
                mock.patch.object(module.os, "geteuid", return_value=501),
                mock.patch.object(module, "run") as runner,
                mock.patch("sys.stdout", new_callable=io.StringIO),
            ):
                module.ensure_loopback_aliases(mock.Mock())
                module.remove_loopback_aliases(mock.Mock())
            runner.assert_not_called()

    def test_project_namespace_is_fixed_and_every_mutable_resource_is_labeled(self) -> None:
        module = load_preprod_module()
        good = types.SimpleNamespace(
            domain="aigw.internal",
            project="aigw-preprod",
            prefix="aigw-preprod",
            subnet_octet=29,
        )
        module.validate_inputs(good)
        for field, value in (
            ("project", "localgateway"),
            ("prefix", "localgateway"),
            ("subnet_octet", 200),
        ):
            bad = types.SimpleNamespace(**vars(good))
            setattr(bad, field, value)
            with self.assertRaises(SystemExit):
                module.validate_inputs(bad)
        self.assertIn("x-preprod-labels: &preprod-labels", self.compose)
        self.assertIn("com.aigw.preprod.project", self.compose)
        self.assertIn("verify_existing_project_boundary", self.script)
        role = (ROOT / "ansible/roles/preprod_stack/tasks/main.yml").read_text()
        self.assertIn("preprod_project_name == 'aigw-preprod'", role)
        self.assertIn("preprod_resource_prefix == 'aigw-preprod'", role)
        self.assertIn("preprod_subnet_octet | int == 29", role)
        self.assertIn("inventory_hostname == 'localhost'", role)
        self.assertIn("ansible_connection | default('')) == 'local'", role)
        self.assertIn('document.get("Driver") != "bridge"', self.script)
        self.assertIn('document.get("Scope") != "local"', self.script)
        self.assertIn("has an unowned endpoint", self.script)

    def test_existing_unowned_project_container_fails_closed(self) -> None:
        module = load_preprod_module()
        args = types.SimpleNamespace(project="aigw-preprod")
        responses = [
            subprocess.CompletedProcess([], 0, "container-id\n", ""),
            subprocess.CompletedProcess(
                [],
                0,
                json.dumps(
                    [
                        {
                            "Name": "/aigw-preprod-keycloak-1",
                            "Config": {
                                "Labels": {
                                    "com.docker.compose.project": "aigw-preprod"
                                }
                            },
                        }
                    ]
                ),
                "",
            ),
        ]
        with mock.patch.object(module, "docker", side_effect=responses):
            with self.assertRaisesRegex(SystemExit, "refusing unowned container"):
                module.verify_existing_project_boundary(args, set())

    def test_implicit_custom_images_use_the_release_planners_canonical_tags(self) -> None:
        module = load_preprod_module()
        self.assertEqual(
            module.canonical_seed_image("envoy-egress", {"build": {}}),
            "ai-gateway-envoy-egress",
        )
        self.assertEqual(
            module.canonical_seed_image("key-rotator", {"build": {}}),
            "ai-gateway-key-rotator",
        )
        self.assertEqual(
            module.canonical_seed_image("vault", {"image": "ai-gateway/vault:1"}),
            "ai-gateway/vault:1",
        )

    def test_exact_envoy_image_is_separate_from_the_preprod_wif_proxy(self) -> None:
        module = load_preprod_module()
        runtime_reference = module.envoy_base_image_reference()
        self.assertRegex(
            runtime_reference,
            r"^dhi\.io/envoy:[A-Za-z0-9_.-]+@sha256:[0-9a-f]{64}$",
        )
        self.assertIn(runtime_reference, (ROOT / "services/egress-proxy/Dockerfile").read_text())

        production_block = self.compose.split("  envoy-egress:\n", 1)[1].split(
            "\n  # The WIF exchange", 1
        )[0]
        self.assertIn("volumes: !override []", production_block)
        self.assertNotIn("entrypoint:", production_block)
        self.assertNotIn("preprod-root-ca.pem", production_block)
        self.assertNotIn("preprod-wif-envoy.yaml", production_block)

        mock_block = self.compose.split("  wif-egress-mock:\n", 1)[1].split(
            "\n  key-rotator:\n", 1
        )[0]
        self.assertIn("${PREPROD_WIF_ENVOY_IMAGE", mock_block)
        self.assertIn("entrypoint: [/usr/local/bin/envoy]", mock_block)
        self.assertIn("preprod-wif-envoy.yaml", mock_block)
        self.assertIn("EGRESS_BASE: http://wif-egress-mock:8080", self.compose)

    def test_seed_activation_disables_pull_for_every_runtime_image(self) -> None:
        module = load_preprod_module()
        external_reference = (
            "dhi.io/hashicorp/vault:1.20.4@sha256:" + "d" * 64
        )
        envoy_base_reference = (
            "dhi.io/envoy:1.38.3@sha256:" + "9" * 64
        )
        model = {
            "services": {
                "envoy-egress": {
                    "build": {"context": "../services/egress-proxy"},
                    "image": module.ENVOY_EGRESS_IMAGE,
                },
                "key-rotator": {"build": {"context": "../services/key-rotator"}},
                "vault": {"image": external_reference},
            }
        }
        receipt = {
            "schema_version": 2,
            "external_images": {
                external_reference: "sha256:" + "e" * 64,
                envoy_base_reference: "sha256:" + "9" * 64,
            },
            "custom_images": {
                module.ENVOY_EGRESS_IMAGE: {
                    "image_id": "sha256:" + "a" * 64,
                    "archive_reference": (
                        "ai-gateway/envoy-egress:aigw-seed-" + "a" * 64
                    ),
                    "deployment_scope": "production",
                    "target_activation": "active-compose",
                },
                "ai-gateway-key-rotator": {
                    "image_id": "sha256:" + "b" * 64,
                    "archive_reference": (
                        "ai-gateway-key-rotator:aigw-seed-" + "b" * 64
                    ),
                    "deployment_scope": "production",
                    "target_activation": "active-compose",
                },
                "ai-gateway/samba-ad:preprod": {
                    "image_id": "sha256:" + "c" * 64,
                    "archive_reference": (
                        "ai-gateway/samba-ad:aigw-seed-" + "c" * 64
                    ),
                    "deployment_scope": "preprod-only",
                    "target_activation": "archive-only",
                },
                "ai-gateway/wif-provider-mock:preprod": {
                    "image_id": "sha256:" + "f" * 64,
                    "archive_reference": (
                        "ai-gateway/wif-provider-mock:aigw-seed-" + "f" * 64
                    ),
                    "deployment_scope": "preprod-only",
                    "target_activation": "archive-only",
                },
            },
            "egress_policy": {
                "schema_version": 1,
                "egress_policy_sha256": "4" * 64,
                "envoy_config_sha256": "5" * 64,
                "selected_providers": ["anthropic"],
                "providers": [{"name": "anthropic"}],
                "envoy_image_id": "sha256:" + "a" * 64,
            },
        }
        args = types.SimpleNamespace(
            archive="seed.tar.zst",
            manifest="seed.manifest.json",
            manifest_sha256="1" * 64,
        )
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            receipt_path = temporary / "receipt.json"
            overlay_path = temporary / "images.yml"
            environment_path = temporary / "preprod.env"
            with (
                mock.patch.object(module, "SEED_RECEIPT", receipt_path),
                mock.patch.object(module, "SEED_OVERLAY", overlay_path),
                mock.patch.object(module, "ENV_FILE", environment_path),
                mock.patch.object(module, "check_context"),
                mock.patch.object(
                    module,
                    "run",
                    return_value=subprocess.CompletedProcess(
                        [], 0, json.dumps(receipt), ""
                    ),
                ),
                mock.patch.object(
                    module,
                    "environment_values",
                    return_value={
                        "AIGW_EGRESS_SOURCE_DATE_EPOCH": "0",
                        "AIGW_EGRESS_PROVIDERS": "anthropic,synthetic",
                        "AIGW_EGRESS_POLICY_SHA256": "0" * 64,
                    },
                ),
                mock.patch.object(module, "base_compose_model", return_value=model),
                mock.patch.object(
                    module,
                    "preprod_env_value",
                    return_value=envoy_base_reference,
                ),
                mock.patch.object(module, "verify_seed_images"),
                mock.patch("sys.stdout", new_callable=io.StringIO),
            ):
                module._activate_seed(args)
            overlay = overlay_path.read_text(encoding="utf-8")

        self.assertEqual(overlay.count("pull_policy: never"), 7)
        self.assertEqual(overlay.count("build: !reset null"), 4)
        self.assertIn(f"image: {external_reference}", overlay)
        vault_block = overlay.split("  vault:\n", 1)[1].split("\n  ", 1)[0]
        self.assertNotIn("build: !reset null", vault_block)
        self.assertIn(
            "image: ai-gateway/envoy-egress:aigw-seed-" + "a" * 64,
            overlay,
        )
        self.assertIn(
            "image: ai-gateway-key-rotator:aigw-seed-" + "b" * 64,
            overlay,
        )
        self.assertIn("  wif-egress-mock:\n", overlay)
        self.assertIn("  preprod-edge-forwarder:\n", overlay)
        self.assertIn(f"image: {envoy_base_reference}", overlay)

        missing_external = {**receipt, "external_images": {}}
        with self.assertRaisesRegex(SystemExit, "no external image for service vault"):
            module.seed_service_images(model, missing_external)

    def test_preprod_observability_cannot_read_host_or_other_project_data(self) -> None:
        self.assertIn(
            "preprod_empty_docker_logs:/var/lib/docker/containers:ro",
            self.compose,
        )
        self.assertIn("security_opt: !override [no-new-privileges:true]", self.compose)
        self.assertIn("SELinux process isolation enabled", self.script)
        self.assertIn("volumes: !override []", self.compose)
        self.assertIn("preprod node-exporter must not mount the local host root", self.script)
        self.assertNotIn("${DOCKER_DATA_ROOT}", self.compose)

    def test_preprod_binds_are_selinux_labeled_and_fully_digested(self) -> None:
        module = load_preprod_module()
        self.assertIn("com.aigw.preprod.config-digest", self.compose)
        self.assertIn("complete preprod digest inventory", self.script)
        self.assertIn("wrong SELinux relabel", self.script)
        for shared_source in (
            "./secrets/preprod-edge-certs:/certs:ro,z",
            "./secrets/preprod-root-ca.pem:/run/preprod/ca.pem:ro,z",
            "./secrets/preprod-samba-bind-password:/run/secrets/samba_ad_bind_password:ro,z",
        ):
            self.assertIn(shared_source, self.compose)
        for private_source in (
            "./secrets/preprod-wif-envoy.yaml:/etc/envoy/preprod-wif.yaml:ro,Z",
            "./secrets/preprod-samba.key:/run/secrets/samba_ad_tls_key:ro,Z",
            "./secrets/preprod-wif.key:/run/preprod/wif.key:ro,Z",
        ):
            self.assertIn(private_source, self.compose)

        envoy_block = self.compose.split("  envoy-egress:\n", 1)[1].split(
            "\n  wif-egress-mock:\n", 1
        )[0]
        self.assertIn("volumes: !override []", envoy_block)
        self.assertNotIn("preprod-root-ca.pem", envoy_block)
        self.assertNotIn("preprod-wif-envoy.yaml", envoy_block)

        for changed_name in (
            "docker-compose.yml",
            "docker-compose.preprod.yml",
            "one.txt",
            "nested",
        ):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                (root / "docker-compose.yml").write_text("base\n", encoding="utf-8")
                (root / "docker-compose.preprod.yml").write_text(
                    "overlay\n", encoding="utf-8"
                )
                (root / "one.txt").write_text("one\n", encoding="utf-8")
                (root / "nested").mkdir()
                (root / "nested/two.txt").write_text("two\n", encoding="utf-8")
                with (
                    mock.patch.object(module, "COMPOSE_DIR", root),
                    mock.patch.object(
                        module, "PREPROD_BIND_SOURCES", ("one.txt", "nested")
                    ),
                ):
                    before = module.digest_inputs()
                    target = root / changed_name
                    if target.is_dir():
                        target = target / "two.txt"
                    target.write_text(target.read_text(encoding="utf-8") + "changed\n")
                    after = module.digest_inputs()
                self.assertNotEqual(before, after, changed_name)

    def test_runtime_jwks_is_tracked_but_not_immutable_configuration(self) -> None:
        module = load_preprod_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "docker-compose.yml").write_text("base\n", encoding="utf-8")
            (root / "docker-compose.preprod.yml").write_text(
                "overlay\n", encoding="utf-8"
            )
            (root / "immutable.txt").write_text("fixed\n", encoding="utf-8")
            (root / "runtime.json").write_text('{"keys":[]}\n', encoding="utf-8")
            with (
                mock.patch.object(module, "COMPOSE_DIR", root),
                mock.patch.object(
                    module,
                    "PREPROD_BIND_SOURCES",
                    ("immutable.txt", "runtime.json"),
                ),
                mock.patch.object(
                    module,
                    "PREPROD_RUNTIME_BIND_SOURCES",
                    frozenset({"runtime.json"}),
                ),
            ):
                before = module.digest_inputs()
                (root / "runtime.json").write_text('{"keys":[1]}\n', encoding="utf-8")
                self.assertEqual(module.digest_inputs(), before)
                (root / "immutable.txt").write_text("changed\n", encoding="utf-8")
                self.assertNotEqual(module.digest_inputs(), before)

    def test_source_build_images_reserve_and_verify_the_preprod_namespace(self) -> None:
        module = load_preprod_module()
        args = types.SimpleNamespace(project="aigw-preprod")
        model = {
            "services": {
                "one": {
                    "image": "aigw-preprod/example:local",
                    "build": {
                        "context": "example",
                        "labels": {
                            "com.aigw.preprod.image-owner": "aigw-preprod"
                        },
                    },
                }
            }
        }
        self.assertEqual(
            module.source_build_targets(args, model),
            {"aigw-preprod/example:local"},
        )
        with mock.patch.object(
            module,
            "docker",
            side_effect=[
                subprocess.CompletedProcess(
                    [], 0, "aigw-preprod/example:local\n", ""
                ),
                subprocess.CompletedProcess(
                    [],
                    0,
                    '{"com.aigw.preprod.image-owner":"aigw-preprod"}\n',
                    "",
                ),
            ],
        ):
            module.verify_source_image_boundary(args, model, require_all=True)

        unowned = subprocess.CompletedProcess([], 0, '{}\n', "")
        with mock.patch.object(
            module,
            "docker",
            side_effect=[
                subprocess.CompletedProcess(
                    [], 0, "aigw-preprod/example:local\n", ""
                ),
                unowned,
            ],
        ):
            with self.assertRaisesRegex(SystemExit, "refusing an unowned image"):
                module.verify_source_image_boundary(args, model, require_all=False)

        bad_model = json.loads(json.dumps(model))
        bad_model["services"]["one"]["build"]["labels"] = {}
        with self.assertRaisesRegex(SystemExit, "no source-image owner label"):
            module.source_build_targets(args, bad_model)

    def test_prepare_creates_the_redis_bind_files_needed_on_a_clean_checkout(self) -> None:
        self.assertIn('SECRETS_DIR / "redis_password"', self.script)
        self.assertIn('SECRETS_DIR / "redis_users.acl"', self.script)
        self.assertIn("user default reset on #", self.script)

    def test_compose_render_scrubs_hostile_shell_interpolation(self) -> None:
        module = load_preprod_module()
        hostile = {
            "AIGW_BIND_DIGEST_TRAEFIK_INT": "hostile-digest",
            "COMPOSE_FILE": "/tmp/hostile-compose.yml",
            "DOMAIN": "hostile.example",
            "DOCKER_CONFIG": "/private/docker-config",
            "DOCKER_HOST": "tcp://hostile.example:2375",
            "HOME": "/private/test-home",
            "LITELLM_IMAGE": "hostile/image:latest",
            "PATH": "/usr/bin:/bin",
            "PG_SUPER_PASSWORD": "hostile-password",
        }
        completed = subprocess.CompletedProcess(
            [], 0, json.dumps({"services": {"example": {}}}), ""
        )
        with (
            mock.patch.dict(module.os.environ, hostile, clear=True),
            mock.patch.object(
                module, "local_docker_endpoint", return_value="unix:///private/docker.sock"
            ),
            mock.patch.object(module.subprocess, "run", return_value=completed) as runner,
        ):
            module.base_compose_model(mock.Mock(project="aigw-preprod"))
        environment = runner.call_args.kwargs["env"]
        self.assertEqual(
            environment,
            {
                "DOCKER_CONFIG": "/private/docker-config",
                "HOME": "/private/test-home",
                "PATH": "/usr/bin:/bin",
            },
        )

    def test_root_seed_commands_use_the_prepared_callers_exact_docker_socket(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("the preprod checkout deliberately requires a non-root owner")
        module = load_preprod_module()
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory).resolve() / "repo"
            secrets = repo / "compose/secrets"
            secrets.mkdir(parents=True)
            socket_path = repo / "docker.sock"
            endpoint = f"unix://{socket_path}"
            env_file = secrets / "preprod.env"
            env_file.write_text(
                f"PREPROD_HOST_UID={os.geteuid()}\n"
                f"PREPROD_HOST_GID={os.getegid()}\n"
                f"PREPROD_DOCKER_ENDPOINT={endpoint}\n",
                encoding="utf-8",
            )
            env_file.chmod(0o600)
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(socket_path))
            try:
                with (
                    mock.patch.object(module, "REPO_ROOT", repo),
                    mock.patch.object(module, "ENV_FILE", env_file),
                    mock.patch.object(module, "_LOCAL_DOCKER_CONTEXT", ""),
                    mock.patch.object(module, "_LOCAL_DOCKER_ENDPOINT", ""),
                    mock.patch.object(module.os, "geteuid", return_value=0),
                    mock.patch.object(module.shutil, "which", return_value="/usr/bin/docker"),
                    mock.patch.object(module, "run") as runner,
                ):
                    self.assertEqual(module.local_docker_endpoint(), endpoint)
                runner.assert_not_called()
            finally:
                listener.close()

    def test_root_seed_load_requires_the_operators_exact_docker_engine(self) -> None:
        module = load_preprod_module()
        socket_metadata = types.SimpleNamespace(
            st_mode=stat.S_IFSOCK | 0o660,
            st_uid=0,
        )
        with (
            mock.patch.object(module, "check_context"),
            mock.patch.object(
                module,
                "local_docker_endpoint",
                return_value="unix:///var/run/docker.sock",
            ),
            mock.patch.object(module.Path, "lstat", return_value=socket_metadata),
            mock.patch.object(module.os.path, "samefile", return_value=True) as same,
            mock.patch("sys.stdout", new_callable=io.StringIO) as output,
        ):
            module.check_root_seed_engine(mock.Mock())
        same.assert_called_once_with(
            Path("/var/run/docker.sock"), Path("/run/docker.sock")
        )
        self.assertIn("PREPROD_ROOT_SEED_ENGINE_OK", output.getvalue())

        with (
            mock.patch.object(module, "check_context"),
            mock.patch.object(
                module,
                "local_docker_endpoint",
                return_value="unix:///home/operator/.docker/run/docker.sock",
            ),
            mock.patch.object(module.Path, "lstat", return_value=socket_metadata),
            mock.patch.object(module.os.path, "samefile", return_value=False),
        ):
            with self.assertRaisesRegex(SystemExit, "different Docker engines"):
                module.check_root_seed_engine(mock.Mock())

    def test_hosts_fragment_uses_loopback_and_bounded_markers(self) -> None:
        module = load_preprod_module()
        fragment = module.hosts_fragment(None)
        self.assertEqual(fragment.count(module.HOSTS_BEGIN), 1)
        self.assertEqual(fragment.count(module.HOSTS_END), 1)
        self.assertIn("127.0.2.1 api.aigw.internal portal.aigw.internal", fragment)
        self.assertIn("127.0.3.1 auth.aigw.internal", fragment)
        self.assertNotIn("172.", fragment)
        self.assertIn("refusing to overwrite it", self.script)

    def test_samba_uses_preprod_profile_and_hostname_verified_ldaps(self) -> None:
        self.assertIn("SAMBA_REALM: PREPROD.AIGW.INTERNAL", self.compose)
        self.assertIn('SAMBA_LDAPS_FQDN: "samba-ad.${DOMAIN}"', self.compose)
        self.assertIn("KC_TLS_HOSTNAME_VERIFIER: DEFAULT", self.compose)
        self.assertIn("IDENTITY_LDAP_PROVIDER_NAME: preprod-samba-ad", self.compose)
        self.assertIn('IDENTITY_LDAP_URL: "ldaps://samba-ad.${DOMAIN}:636"', self.compose)
        self.assertIn(
            'IDENTITY_LDAP_USER_FILTER: "(&(objectCategory=person)(objectClass=user)'
            '(!(sAMAccountName=svc-keycloak-ldap)))"',
            self.compose,
        )
        self.assertNotIn("KC_TLS_HOSTNAME_VERIFIER: ANY", self.compose)
        start = self.script.split("def start(", 1)[1].split("def container_state", 1)[0]
        self.assertLess(
            start.index('wait_for_container(args, "samba-ad"'),
            start.index('wait_for_container(args, "keycloak"'),
        )

    def test_start_reconciles_postgres_before_direct_consumers(self) -> None:
        module = load_preprod_module()
        args = types.SimpleNamespace(image_mode="source")
        events: list[tuple[str, tuple[object, ...]]] = []

        def compose(_args, *arguments, **_kwargs):
            events.append(("compose", arguments))
            stdout = ""
            if arguments[:4] == (
                "exec", "-T", "postgres", module.POSTGRES_RECONCILE_SCRIPT
            ):
                stdout = "AIGW_POSTGRES_CHANGED\n"
            return subprocess.CompletedProcess([], 0, stdout, "")

        def wait(_args, service, wanted, timeout):
            events.append(("wait", (service, wanted, timeout)))

        with (
            mock.patch.object(module, "check_context"),
            mock.patch.object(module, "rendered_compose_model", return_value={}),
            mock.patch.object(module, "verify_source_image_boundary"),
            mock.patch.object(
                module,
                "verify_rendered_resource_ownership",
                return_value={"aigw-preprod_pg_data"},
            ),
            mock.patch.object(module, "verify_existing_project_boundary"),
            mock.patch.object(module, "compose", side_effect=compose),
            mock.patch.object(module, "wait_for_container", side_effect=wait),
            mock.patch("sys.stdout", new_callable=io.StringIO),
        ):
            module.start(args)

        stop = events.index(
            (
                "compose",
                (
                    "stop", "--timeout", "30",
                    "litellm", "keycloak", "key-rotator", "grafana",
                ),
            )
        )
        postgres_up = events.index(("compose", ("up", "-d", "postgres")))
        postgres_ready = events.index(("wait", ("postgres", "healthy", 300)))
        reconciles = [
            index
            for index, event in enumerate(events)
            if event
            == (
                "compose",
                (
                    "exec", "-T", "postgres",
                    module.POSTGRES_RECONCILE_SCRIPT,
                ),
            )
        ]
        full_up = events.index(
            ("compose", ("up", "-d", "--remove-orphans"))
        )
        litellm_ready = events.index(("wait", ("litellm", "healthy", 600)))
        self.assertEqual(len(reconciles), 2)
        self.assertLess(stop, postgres_up)
        self.assertLess(postgres_up, postgres_ready)
        self.assertLess(postgres_ready, reconciles[0])
        self.assertLess(reconciles[0], full_up)
        self.assertLess(full_up, litellm_ready)
        self.assertLess(litellm_ready, reconciles[1])

    def test_postgres_reconcile_receipt_is_fail_closed(self) -> None:
        module = load_preprod_module()
        args = mock.Mock()
        result = subprocess.CompletedProcess(
            [], 0, "AIGW_POSTGRES_CHANGED\nAIGW_POSTGRES_OK\n", ""
        )
        with (
            mock.patch.object(module, "compose", return_value=result) as compose,
            mock.patch("sys.stderr", new_callable=io.StringIO),
        ):
            with self.assertRaisesRegex(SystemExit, "invalid receipt"):
                module.reconcile_postgres(args, "before-consumers")
        compose.assert_called_once_with(
            args,
            "exec", "-T", "postgres", module.POSTGRES_RECONCILE_SCRIPT,
            capture=True,
            sensitive=True,
        )

    def test_realms_are_rendered_from_the_playbook_domain(self) -> None:
        module = load_preprod_module()
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            source = temporary / "keycloak/realms"
            output = temporary / "rendered"
            source.mkdir(parents=True)
            output.mkdir()
            for name in ("aigw-realm.json", "anthropic-wif-realm.json"):
                shutil.copyfile(ROOT / "compose/keycloak/realms" / name, source / name)
            with mock.patch.object(module, "COMPOSE_DIR", temporary), mock.patch.object(
                module, "REALMS_DIR", output
            ):
                module.render_realms("preprod.test.internal")
            aigw = json.loads((output / "aigw-realm.json").read_text())
            wif = json.loads((output / "anthropic-wif-realm.json").read_text())
        clients = {client["clientId"]: client for client in aigw["clients"]}
        self.assertEqual(
            clients["open-webui"]["redirectUris"],
            ["https://chat.preprod.test.internal/oauth/oidc/callback"],
        )
        self.assertEqual(
            clients["vault"]["webOrigins"],
            ["https://vault.preprod.test.internal"],
        )
        self.assertEqual(
            wif["attributes"]["frontendUrl"],
            "https://idp.wif.preprod.test.internal",
        )

    def test_auto_initialization_does_not_use_the_admin_portal(self) -> None:
        self.assertIn("app.auto_bootstrap_identity", self.script)
        self.assertIn("IDENTITY_AUTO_BOOTSTRAP_APPLIED", self.script)
        self.assertIn("IDENTITY_AUTO_BOOTSTRAP_VERIFIED", self.script)
        self.assertNotIn("IDENTITY_AUTO_BOOTSTRAP_SKIPPED_NO_LDAP", self.script)
        auto_task = self.tasks.split(
            "- name: Auto-initialize Keycloak identity control without the admin portal", 1
        )[1].split("- name: Create and verify", 1)[0]
        self.assertNotIn("admin-portal", auto_task)

    def test_verify_checks_every_rendered_service_and_completed_volume_init(self) -> None:
        module = load_preprod_module()
        model = {
            "services": {
                "volume-init": {"restart": "no"},
                "alpha": {"healthcheck": {"test": ["CMD", "true"]}},
                "beta": {"healthcheck": {"test": ["CMD", "true"]}},
            }
        }
        identity = {
            "configured": True,
            "controller_usable": True,
            "bootstrap_available": False,
            "bootstrap_cleanup_required": False,
            "ldap_configured": True,
            "break_glass_escrow_readable": True,
            "break_glass_escrowed": True,
            "vault_oidc_rp_escrow_readable": True,
            "vault_oidc_rp_escrowed": True,
        }
        provider = {"state": "configured", "enabled": True}
        with (
            mock.patch.object(module, "rendered_compose_model", return_value=model),
            mock.patch.object(module, "verify_volume_init") as volume_init,
            mock.patch.object(module, "wait_for_container") as wait,
            mock.patch.object(
                module, "container_state", return_value=("running", "healthy")
            ),
            mock.patch.object(
                module,
                "internal_call",
                side_effect=[(200, identity), (200, provider)],
            ),
            mock.patch("sys.stdout", new_callable=io.StringIO),
        ):
            module.verify(mock.Mock())
        volume_init.assert_called_once()
        self.assertEqual(
            [call.args[1:] for call in wait.call_args_list],
            [("alpha", "healthy", 120), ("beta", "healthy", 120)],
        )

    def test_ansible_runs_full_acceptance_after_internal_verification(self) -> None:
        internal_verify = self.tasks.index(
            "Verify LDAP, OIDC, identity controller, escrow, and WIF state"
        )
        acceptance = self.tasks.index(
            "Run the full local preprod edge and identity acceptance gate"
        )
        report = self.tasks.index("Report the full local preprod acceptance result")
        self.assertLess(internal_verify, acceptance)
        self.assertLess(acceptance, report)
        acceptance_block = self.tasks[acceptance:report]
        self.assertIn("scripts/test-e2e-preprod.py", acceptance_block)
        self.assertIn("--image-mode", acceptance_block)
        self.assertIn('"{{ preprod_image_mode }}"', acceptance_block)
        self.assertIn("PREPROD_E2E_PASSED", acceptance_block)

    def test_seed_mode_uses_exact_transfer_ids_and_cannot_build_or_pull(self) -> None:
        self.assertIn('"ai-gateway/samba-ad:preprod"', self.script)
        self.assertIn('"ai-gateway/wif-provider-mock:preprod"', self.script)
        self.assertIn('"    pull_policy: never"', self.script)
        self.assertIn('"    build: !reset null"', self.script)
        self.assertIn("seed image mode never rebuilds images", self.script)
        self.assertIn("seed image mode never pulls images", self.script)
        self.assertIn("result.stdout.strip() != expected_id", self.script)
        self.assertIn('"local-release-receipt"', self.script)
        self.assertIn("preprod_seed_load_archive", self.tasks)
        linux_loader = self.tasks.split(
            "- name: Load the exact offline image seed", 1
        )[1].split(
            "- name: Load the exact offline image seed through the Docker Desktop operator",
            1,
        )[0]
        self.assertIn("root-preprod-load", linux_loader)
        self.assertIn("become: true", linux_loader)
        self.assertLess(
            self.tasks.index("Prove the root loader uses the operator's exact Docker engine"),
            self.tasks.index("Load the exact offline image seed"),
        )
        self.assertLess(
            self.tasks.index("Load the exact offline image seed"),
            self.tasks.index("Bind preprod to immutable transfer image references"),
        )
        desktop_task = self.tasks.split(
            "- name: Load the exact offline image seed through the Docker Desktop operator",
            1,
        )[1].split("- name: Bind preprod", 1)[0]
        self.assertIn("load-local-preprod-seed", desktop_task)
        self.assertIn("become: false", desktop_task)
        self.assertIn("== 'Darwin'", desktop_task)

    def test_seed_activation_runs_only_as_the_recorded_nonroot_owner(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("the preprod checkout deliberately requires a non-root owner")
        module = load_preprod_module()
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
            secrets = repo / "compose/secrets"
            secrets.mkdir(parents=True)
            env_file = secrets / "preprod.env"
            receipt = secrets / "preprod-seed-receipt.json"
            overlay = secrets / "preprod-seed-images.yml"
            uid = os.geteuid()
            gid = os.getegid()
            env_file.write_text(
                f"PREPROD_HOST_UID={uid}\nPREPROD_HOST_GID={gid}\n",
                encoding="utf-8",
            )
            env_file.chmod(0o600)

            with (
                mock.patch.object(module, "REPO_ROOT", repo),
                mock.patch.object(module, "ENV_FILE", env_file),
                mock.patch.object(module, "SEED_RECEIPT", receipt),
                mock.patch.object(module, "SEED_OVERLAY", overlay),
                mock.patch.object(module.os, "geteuid", return_value=0),
            ):
                with self.assertRaisesRegex(SystemExit, "recorded non-root operator"):
                    module.activate_seed(None)

            def write_caller_outputs(_args) -> None:
                module.write_file(receipt, "caller activation\n", 0o644)
                module.write_file(overlay, "caller overlay\n", 0o644)

            with (
                mock.patch.object(module, "REPO_ROOT", repo),
                mock.patch.object(module, "ENV_FILE", env_file),
                mock.patch.object(module, "SEED_RECEIPT", receipt),
                mock.patch.object(module, "SEED_OVERLAY", overlay),
                mock.patch.object(module, "_activate_seed", side_effect=write_caller_outputs),
                mock.patch.object(module.os, "geteuid", return_value=uid),
                mock.patch.object(module.os, "getegid", return_value=gid),
            ):
                module.activate_seed(None)
                module.remove_seed_output_files()
            self.assertFalse(receipt.exists())
            self.assertFalse(overlay.exists())

    def test_root_loader_marker_stays_in_digest_scoped_temporary_stage(self) -> None:
        defaults = (ROOT / "ansible/roles/preprod_stack/defaults/main.yml").read_text()
        self.assertIn("/var/tmp/ai-gateway-preprod-seeds/", defaults)
        self.assertIn("preprod_seed_manifest_sha256[:16]", defaults)
        self.assertIn("/loader-marker", defaults)
        self.assertNotIn("compose/secrets/preprod-seed-marker", defaults)
        self.assertIn("remove_seed_output_files()", self.script)

    def test_wif_mock_verifies_real_rs256_claims_and_tls(self) -> None:
        source = (ROOT / "services/wif-provider-mock/main.go").read_text()
        dockerfile = (ROOT / "services/wif-provider-mock/Dockerfile").read_text()
        for required in (
            'header.Alg != "RS256"',
            "rsa.VerifyPKCS1v15",
            "claims.Issuer != cfg.issuer",
            "claims.Subject != cfg.subject",
            "exactAudience",
            "expires <= now.Unix()",
            'POST /v1/oauth/token',
            'POST /v1/messages',
            "tls.VersionTLS13",
        ):
            self.assertIn(required, source)
        self.assertRegex(dockerfile.splitlines()[0], r"^# syntax=.*@sha256:[0-9a-f]{64}$")
        self.assertIn("RUN --network=none go test ./...", dockerfile)
        self.assertIn("USER 65532:65532", dockerfile)

    def test_wif_rotation_requires_success_after_the_pre_call_history_boundary(self) -> None:
        module = load_preprod_module()
        wanted_ids = {
            "organization_id": "preprod-org",
            "service_account_id": "preprod-service-account",
            "federation_rule_id": "preprod-federation-rule",
            "workspace_id": "preprod-workspace",
        }
        provider = {
            "configured": True,
            "state": "configured",
            "setup_bundle": {"jwks": {"keys": []}},
            "current_jwks_sha256": "a" * 64,
            "nonsecret_ids": wanted_ids,
        }
        old_success = {
            "id": 7,
            "vendor": "anthropic",
            "action": "rotate",
            "status": "success",
        }
        new_success = {**old_success, "id": 8}
        responses = [
            (200, provider),
            (200, [old_success]),
            (202, {"accepted": True, "vendor": "anthropic"}),
            (200, [new_success, old_success]),
        ]
        with tempfile.TemporaryDirectory() as directory:
            secrets = Path(directory).resolve()
            with (
                mock.patch.object(module, "SECRETS_DIR", secrets),
                mock.patch.object(
                    module, "internal_call", side_effect=responses
                ) as internal,
                mock.patch("sys.stdout", new_callable=io.StringIO) as output,
            ):
                module.configure_wif(mock.Mock())
        calls = [(call.args[1], call.args[2]) for call in internal.call_args_list]
        self.assertEqual(
            calls,
            [
                ("GET", "/providers/anthropic"),
                ("GET", "/history?limit=50"),
                ("POST", "/rotate/anthropic"),
                ("GET", "/history?limit=50"),
            ],
        )
        self.assertIn("PREPROD_WIF_CONFIGURED", output.getvalue())

    def test_generated_pki_and_credentials_are_ignored(self) -> None:
        gitignore = (ROOT / ".gitignore").read_text()
        self.assertIn("compose/secrets/", gitignore)
        self.assertIn("preprod-root-ca.key", self.script)
        self.assertIn("preprod-edge-certs", self.script)
        self.assertIn("OnlyForTesting1!PreprodAdmin", self.script)


if __name__ == "__main__":
    unittest.main()
