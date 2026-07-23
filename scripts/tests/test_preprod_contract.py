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
from uuid import UUID


ROOT = Path(__file__).resolve().parents[2]


def load_preprod_module():
    path = ROOT / "scripts/preprod.py"
    spec = importlib.util.spec_from_file_location("aigw_preprod", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_seed_loader_module():
    path = ROOT / "scripts/load-offline-image-seed.py"
    spec = importlib.util.spec_from_file_location("aigw_seed_loader_for_preprod", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def clean_room_plan(module):
    image_id = "sha256:" + "a" * 64
    repository = "ai-gateway/clean-room-test"
    aliases = [
        {
            "kind": "custom-archive-reference",
            "value": f"{repository}:aigw-seed-{'a' * 64}",
        },
        {"kind": "custom-image", "value": f"{repository}:1"},
    ]
    return {
        "groups": [{"aliases": aliases, "image_id": image_id}],
        "manifest_sha256": "b" * 64,
        "record_count": 1,
        "schema_version": module.CLEAN_ROOM_PLAN_SCHEMA,
        "unique_image_id_count": 1,
    }


class PreprodContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.script = (ROOT / "scripts/preprod.py").read_text()
        self.compose = (ROOT / "compose/docker-compose.preprod.yml").read_text()
        self.tasks = (ROOT / "ansible/roles/preprod_stack/tasks/present.yml").read_text()

    def test_command_parser_registers_each_subcommand_once(self) -> None:
        module = load_preprod_module()
        parser = module.parser()
        parsed = parser.parse_args(
            [
                "--image-mode",
                "seed",
                "clean-room-seed",
                "--archive",
                "/tmp/release.tar",
                "--archive-sha256",
                "a" * 64,
                "--manifest",
                "/tmp/release.json",
                "--manifest-sha256",
                "b" * 64,
                "--confirm",
                module.CLEAN_ROOM_CONFIRMATION,
            ]
        )
        self.assertEqual(parsed.command, "clean-room-seed")

    def test_vault_token_update_preserves_the_verified_seed_policy(self) -> None:
        module = load_preprod_module()
        policy_values = {
            name: f"verified-{index}"
            for index, name in enumerate(module.SEED_POLICY_ENVIRONMENT_NAMES)
        }
        base = {
            "ROTATOR_VAULT_TOKEN": "old-token",
            **{name: "" for name in module.SEED_POLICY_ENVIRONMENT_NAMES},
        }
        with (
            mock.patch.object(module, "environment_values", return_value=base.copy()),
            mock.patch.object(
                module,
                "preprod_env_value",
                side_effect=policy_values.__getitem__,
            ),
        ):
            updated = module.environment_with_vault_token(
                types.SimpleNamespace(image_mode="seed"), "new-token"
            )
        self.assertEqual(updated["ROTATOR_VAULT_TOKEN"], "new-token")
        for name, value in policy_values.items():
            self.assertEqual(updated[name], value)

        with (
            mock.patch.object(module, "environment_values", return_value=base.copy()),
            mock.patch.object(module, "preprod_env_value") as read_seed_value,
        ):
            source = module.environment_with_vault_token(
                types.SimpleNamespace(image_mode="source"), "source-token"
            )
        self.assertEqual(source["ROTATOR_VAULT_TOKEN"], "source-token")
        self.assertEqual(source["KEY_ROTATOR_EGRESS_POLICY_SHA256"], "")
        read_seed_value.assert_not_called()

    def test_reprepare_regenerates_the_activated_seed_policy(self) -> None:
        module = load_preprod_module()
        image_id = "sha256:" + "a" * 64
        policy = {
            "schema_version": 1,
            "egress_policy_sha256": "b" * 64,
            "envoy_config_sha256": "c" * 64,
            "selected_providers": ["anthropic"],
            "providers": [
                {
                    "name": "anthropic",
                    "api_hostname": "api.anthropic.com",
                    "route_prefix": "/anthropic/",
                    "sni": "api.anthropic.com",
                    "exact_sans": ["api.anthropic.com"],
                    "ca_file": "anthropic-ca.pem",
                    "ca_bundle_sha256": "d" * 64,
                    "ca_sha256_fingerprints": ["e" * 64],
                    "provenance_sha256": "f" * 64,
                }
            ],
            "envoy_image_id": image_id,
        }
        receipt = {
            "schema_version": 2,
            "release_scope": "preprod",
            "manifest_sha256": "1" * 64,
            "custom_images": {
                module.ENVOY_EGRESS_IMAGE: {"image_id": image_id}
            },
            "egress_policy": policy,
        }
        args = types.SimpleNamespace(image_mode="seed")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt_path = root / "receipt.json"
            environment_path = root / "preprod.env"
            provider_policy_path = root / "provider-policy.json"
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            receipt_path.chmod(0o644)
            base = {
                name: "" for name in module.SEED_POLICY_ENVIRONMENT_NAMES
            }
            base["PG_DATA_VOLUME_NAME"] = "aigw-preprod_pg18_data"
            with (
                mock.patch.object(module, "SEED_RECEIPT", receipt_path),
                mock.patch.object(module, "ENV_FILE", environment_path),
                mock.patch.object(
                    module, "PROVIDER_POLICY_RECEIPT", provider_policy_path
                ),
                mock.patch.object(
                    module, "environment_values", return_value=base.copy()
                ),
            ):
                activated = module.prepare_seed_policy(args)
                module.render_environment(args, activated)

            values = dict(
                line.split("=", 1)
                for line in environment_path.read_text(encoding="utf-8").splitlines()
                if "=" in line
            )
            provider_policy = provider_policy_path.read_text(encoding="utf-8")

        self.assertEqual(activated, policy)
        self.assertEqual(values["AIGW_EGRESS_PROVIDERS"], "anthropic")
        self.assertEqual(values["AIGW_EGRESS_POLICY_SHA256"], "b" * 64)
        self.assertEqual(
            values["KEY_ROTATOR_PROVIDER_POLICY_RECEIPT_FILE"],
            "/run/secrets/provider_policy_receipt.json",
        )
        self.assertEqual(values["KEY_ROTATOR_EGRESS_POLICY_SHA256"], "b" * 64)
        self.assertEqual(values["PG_DATA_VOLUME_NAME"], "aigw-preprod_pg18_data")
        self.assertEqual(
            provider_policy, module.canonical_provider_policy_receipt(policy)
        )
        self.assertIn("seed_policy = prepare_seed_policy(args)", self.script)
        self.assertIn("render_environment(args, seed_policy)", self.script)

    def test_unactivated_or_source_prepare_has_no_seed_policy(self) -> None:
        module = load_preprod_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            missing = root / "missing.json"
            provider_policy = root / "provider-policy.json"
            provider_policy.write_text("old-policy\n", encoding="utf-8")
            with (
                mock.patch.object(module, "SEED_RECEIPT", missing),
                mock.patch.object(
                    module, "PROVIDER_POLICY_RECEIPT", provider_policy
                ),
            ):
                self.assertIsNone(
                    module.prepare_seed_policy(
                        types.SimpleNamespace(image_mode="seed")
                    )
                )
                self.assertEqual(provider_policy.read_text(encoding="utf-8"), "")
                provider_policy.write_text("old-policy\n", encoding="utf-8")
                self.assertIsNone(
                    module.prepare_seed_policy(
                        types.SimpleNamespace(image_mode="source")
                    )
                )
                self.assertEqual(provider_policy.read_text(encoding="utf-8"), "")

    def test_bad_activated_seed_receipt_fails_before_policy_mutation(self) -> None:
        module = load_preprod_module()
        cases = (
            ("malformed", "{", 0o644),
            (
                "wrong-scope",
                json.dumps(
                    {
                        "schema_version": 2,
                        "release_scope": "production",
                        "manifest_sha256": "a" * 64,
                    }
                ),
                0o644,
            ),
            (
                "unsafe-mode",
                json.dumps(
                    {
                        "schema_version": 2,
                        "release_scope": "preprod",
                        "manifest_sha256": "a" * 64,
                    }
                ),
                0o600,
            ),
        )
        for name, content, mode in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                receipt = root / "receipt.json"
                provider_policy = root / "provider-policy.json"
                receipt.write_text(content, encoding="utf-8")
                receipt.chmod(mode)
                provider_policy.write_text("existing-policy\n", encoding="utf-8")
                with (
                    mock.patch.object(module, "SEED_RECEIPT", receipt),
                    mock.patch.object(
                        module, "PROVIDER_POLICY_RECEIPT", provider_policy
                    ),
                    self.assertRaises(SystemExit),
                ):
                    module.prepare_seed_policy(
                        types.SimpleNamespace(image_mode="seed")
                    )
                self.assertEqual(
                    provider_policy.read_text(encoding="utf-8"),
                    "existing-policy\n",
                )

    def test_postgres18_is_the_only_preprod_database_major(self) -> None:
        module = load_preprod_module()
        parser = module.parser()
        parsed = parser.parse_args(["compose-config"])
        module.validate_inputs(parsed)
        self.assertFalse(hasattr(parsed, "postgres_major"))
        self.assertNotIn("--postgres-major", self.script)
        self.assertNotIn("--confirm-postgres16-rehearsal", self.script)
        self.assertNotIn("POSTGRES16_OVERLAY", self.script)
        self.assertIn(
            '"PG_DATA_VOLUME_NAME": f"{args.project}_pg18_data"', self.script
        )

        args = types.SimpleNamespace(project="aigw-preprod", image_mode="seed")
        cleaned = module._clean_room_source_args(args)
        self.assertEqual(cleaned.image_mode, "source")
        self.assertEqual(cleaned.project, "aigw-preprod")
        self.assertFalse(hasattr(cleaned, "postgres_major"))

    def test_clean_room_reconstructs_only_missing_bind_digests(self) -> None:
        module = load_preprod_module()
        digest = "a" * 64
        args = types.SimpleNamespace(subnet_octet=29)
        preserved_name = "AIGW_BIND_DIGEST_TRAEFIK_INT"
        preserved_value = "b" * 64
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / "preprod.env"
            env_file.write_text(
                f"AIGW_PREPROD_CONFIG_DIGEST={digest}\n"
                f"{preserved_name}={preserved_value}\n",
                encoding="utf-8",
            )
            with mock.patch.object(module, "ENV_FILE", env_file):
                overrides = module._clean_room_compose_overrides(args)

            self.assertNotIn(preserved_name, overrides)
            self.assertEqual(
                set(overrides) - {"ALERTMANAGER_OBSERVABILITY_IP"},
                {
                    f"AIGW_BIND_DIGEST_{name}"
                    for name in module.PREPROD_BIND_DIGEST_NAMES
                    if name != "TRAEFIK_INT"
                },
            )
            self.assertEqual(
                overrides["ALERTMANAGER_OBSERVABILITY_IP"], "172.29.15.4"
            )
            self.assertEqual(
                {
                    value
                    for name, value in overrides.items()
                    if name != "ALERTMANAGER_OBSERVABILITY_IP"
                },
                {digest},
            )

            env_file.write_text(
                f"{preserved_name}={preserved_value}\n",
                encoding="utf-8",
            )
            with (
                mock.patch.object(module, "ENV_FILE", env_file),
                self.assertRaisesRegex(SystemExit, "valid compatibility digest"),
            ):
                module._clean_room_compose_overrides(args)

    def test_clean_room_passes_compatibility_digests_without_rewriting_env(self) -> None:
        module = load_preprod_module()
        digest = "c" * 64
        args = types.SimpleNamespace(
            project="aigw-preprod",
            prefix="aigw-preprod",
            subnet_octet=29,
            image_mode="seed",
        )
        inventory = {"containers": {}}
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / "preprod.env"
            original = (
                f"AIGW_PREPROD_CONFIG_DIGEST={digest}\n"
                "PG_DATA_VOLUME_NAME=aigw-preprod_pg18_data\n"
            )
            env_file.write_text(original, encoding="utf-8")
            with (
                mock.patch.object(module, "ENV_FILE", env_file),
                mock.patch.object(
                    module, "rendered_compose_model", return_value={}
                ) as rendered,
                mock.patch.object(
                    module, "verify_rendered_resource_ownership", return_value=set()
                ),
                mock.patch.object(module, "verify_existing_project_boundary"),
                mock.patch.object(
                    module, "_validate_clean_room_generated_state", return_value=0
                ),
                mock.patch.object(module, "_clean_room_list", return_value=[]),
                mock.patch.object(
                    module, "_clean_room_network_inventory", return_value=[]
                ),
            ):
                resources = module.preflight_clean_room_resources(args, inventory)

            expected = {
                f"AIGW_BIND_DIGEST_{name}": digest
                for name in module.PREPROD_BIND_DIGEST_NAMES
            }
            expected["ALERTMANAGER_OBSERVABILITY_IP"] = "172.29.15.4"
            self.assertEqual(
                rendered.call_args.kwargs["environment_overrides"], expected
            )
            self.assertEqual(env_file.read_text(encoding="utf-8"), original)
            self.assertEqual(resources["source_args"].image_mode, "source")

    def test_clean_room_accepts_only_the_rendered_postgres18_volume(self) -> None:
        module = load_preprod_module()
        args = types.SimpleNamespace(
            project="aigw-preprod",
            prefix="aigw-preprod",
            subnet_octet=29,
        )
        expected = "aigw-preprod_pg18_data"
        unexpected = "aigw-preprod_unexpected_data"

        def volume(name: str, *, compose_volume: str = "pg_data") -> dict:
            return {
                "Name": name,
                "Driver": "local",
                "Scope": "local",
                "Labels": {
                    "com.aigw.preprod.project": "aigw-preprod",
                    "com.docker.compose.project": "aigw-preprod",
                    "com.docker.compose.volume": compose_volume,
                },
            }

        documents = {expected: volume(expected), unexpected: volume(unexpected)}
        inventory = {"containers": {}}
        with (
            mock.patch.object(module, "ENV_FILE", mock.Mock(exists=lambda: True)),
            mock.patch.object(module, "_clean_room_source_args", return_value=args),
            mock.patch.object(
                module, "_clean_room_compose_overrides", return_value={}
            ),
            mock.patch.object(module, "rendered_compose_model", return_value={}),
            mock.patch.object(
                module,
                "verify_rendered_resource_ownership",
                return_value={expected},
            ),
            mock.patch.object(module, "verify_existing_project_boundary"),
            mock.patch.object(
                module,
                "_clean_room_list",
                return_value=[expected],
            ),
            mock.patch.object(
                module,
                "_clean_room_inspect_required",
                side_effect=lambda _kind, name: documents[name],
            ),
            mock.patch.object(module, "desired_networks", return_value={}),
            mock.patch.object(module, "_clean_room_network_inventory", return_value=[]),
            mock.patch.object(
                module, "_validate_clean_room_generated_state", return_value=0
            ),
        ):
            resources = module.preflight_clean_room_resources(args, inventory)
        self.assertEqual(resources["volumes"], {expected})

        with (
            mock.patch.object(module, "ENV_FILE", mock.Mock(exists=lambda: True)),
            mock.patch.object(module, "_clean_room_source_args", return_value=args),
            mock.patch.object(
                module, "_clean_room_compose_overrides", return_value={}
            ),
            mock.patch.object(module, "rendered_compose_model", return_value={}),
            mock.patch.object(
                module,
                "verify_rendered_resource_ownership",
                return_value={expected},
            ),
            mock.patch.object(module, "verify_existing_project_boundary"),
            mock.patch.object(
                module,
                "_clean_room_list",
                return_value=[expected, unexpected],
            ),
            mock.patch.object(
                module,
                "_clean_room_inspect_required",
                side_effect=lambda _kind, name: documents[name],
            ),
        ):
            with self.assertRaisesRegex(SystemExit, "outside the exact clean-room"):
                module.preflight_clean_room_resources(args, inventory)
        self.assertNotIn("postgres_rehearsal_volume_names", self.script)
        self.assertNotIn("remove_postgres_rehearsal_volumes", self.script)

    def test_seed_compose_command_has_no_database_major_overlay(self) -> None:
        module = load_preprod_module()
        args = types.SimpleNamespace(
            project="aigw-preprod",
            image_mode="seed",
        )
        with tempfile.TemporaryDirectory() as directory:
            seed_overlay = Path(directory) / "seed.yml"
            seed_overlay.write_text("services: {}\n", encoding="utf-8")
            with (
                mock.patch.object(module, "SEED_OVERLAY", seed_overlay),
                mock.patch.object(
                    module,
                    "local_docker_endpoint",
                    return_value="unix:///tmp/docker.sock",
                ),
            ):
                command = module.compose_command(args, "config")
        self.assertEqual(command[-3:-1], ["--profile", "preprod"])
        self.assertIn(str(seed_overlay), command)
        self.assertFalse(any("postgres16" in argument for argument in command))

    def test_preprod_reconciles_the_openwebui_key_before_acceptance(self) -> None:
        start = self.tasks.index("Start the isolated preprod project")
        vault = self.tasks.index("Initialize or unseal the local test Vault")
        reconcile = self.tasks.index(
            "Reconcile and verify the dedicated Open WebUI LiteLLM key"
        )
        acceptance = self.tasks.index(
            "Run the full local preprod edge and identity acceptance gate"
        )
        self.assertLess(start, reconcile)
        self.assertLess(vault, reconcile)
        self.assertLess(reconcile, acceptance)
        self.assertIn("reconcile-openwebui-key", self.tasks)
        self.assertIn("preprod_openwebui_key.stdout | trim is match(", self.tasks)
        self.assertIn('commands.add_parser("reconcile-openwebui-key")', self.script)
        self.assertIn(
            '"reconcile-openwebui-key": reconcile_openwebui_key,', self.script
        )

    def test_openwebui_key_reconciliation_keeps_secrets_on_stdin(self) -> None:
        module = load_preprod_module()
        args = types.SimpleNamespace(
            prefix="aigw-preprod", project="aigw-preprod", subnet_octet=29
        )
        image = subprocess.CompletedProcess([], 0, "a" * 64 + "\n", "")
        scope = subprocess.CompletedProcess(
            [], 0, "OPENWEBUI_MODELS_SCOPE_PASS models=1\n", ""
        )
        reconcile = subprocess.CompletedProcess(
            [], 0, "OPENWEBUI_SERVICE_KEY_RECONCILED created=true\n", ""
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "reconcile-openwebui-key.py"
            source.write_text("print('fixture')\n", encoding="utf-8")
            secrets_dir = root / "secrets"
            secrets_dir.mkdir()
            with (
                mock.patch.object(module, "OPENWEBUI_RECONCILE_SCRIPT", source),
                mock.patch.object(module, "SECRETS_DIR", secrets_dir),
                mock.patch.object(
                    module,
                    "preprod_env_value",
                    side_effect=lambda name: {
                        "LITELLM_MASTER_KEY": "sk-" + "m" * 32,
                        "WEBUI_LITELLM_KEY": "sk-" + "w" * 32,
                    }[name],
                ),
                mock.patch.object(
                    module,
                    "local_docker_endpoint",
                    return_value="unix:///tmp/docker.sock",
                ),
                mock.patch.object(module, "wait_for_container") as wait,
                mock.patch.object(module, "verify_secret_bearing_portal_network"),
                mock.patch.object(
                    module, "compose", side_effect=[image, scope]
                ) as compose,
                mock.patch.object(module, "run", return_value=reconcile) as runner,
                mock.patch("builtins.print"),
            ):
                module.reconcile_openwebui_key(args)

        command = runner.call_args.args[0]
        secret_input = json.loads(runner.call_args.kwargs["input_text"])
        self.assertNotIn(secret_input["master_key"], command)
        self.assertNotIn(secret_input["candidate_key"], command)
        self.assertTrue(runner.call_args.kwargs["sensitive"])
        self.assertEqual(runner.call_args.kwargs["attempts"], 30)
        self.assertIn("--read-only", command)
        self.assertIn("no-new-privileges:true", command)
        self.assertIn("aigw-preprod-net-portal", command)
        self.assertTrue(
            any(value.endswith(":/reconcile.py:ro,Z") for value in command)
        )
        wait.assert_called_once_with(args, "dev-portal", "healthy", 300)
        self.assertEqual(compose.call_count, 2)

    def test_openwebui_reconciliation_refuses_an_unowned_portal_endpoint(self) -> None:
        module = load_preprod_module()
        args = types.SimpleNamespace(
            prefix="aigw-preprod", project="aigw-preprod", subnet_octet=29
        )
        expected_subnet, expected_internal = module.desired_networks(args)[
            "aigw-preprod-net-portal"
        ]
        network = {
            "Driver": "bridge",
            "Scope": "local",
            "Internal": expected_internal,
            "Labels": {"com.aigw.preprod.project": "aigw-preprod"},
            "IPAM": {
                "Config": [
                    {
                        "Subnet": expected_subnet,
                        "IPRange": module.dynamic_ip_range(expected_subnet),
                    }
                ]
            },
            "Containers": {"a" * 64: {}},
        }
        endpoint = {
            "Config": {
                "Labels": {
                    "com.docker.compose.project": "foreign",
                    "com.aigw.preprod.project": "foreign",
                    "com.docker.compose.service": "litellm",
                }
            },
            "State": {"Running": True, "Health": {"Status": "healthy"}},
        }
        responses = (
            subprocess.CompletedProcess([], 0, json.dumps([network]), ""),
            subprocess.CompletedProcess([], 0, json.dumps([endpoint]), ""),
        )
        with mock.patch.object(module, "docker", side_effect=responses):
            with self.assertRaisesRegex(SystemExit, "unowned endpoint"):
                module.verify_secret_bearing_portal_network(args)

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

    def test_clean_room_playbook_is_confirmed_bounded_and_nonroot(self) -> None:
        playbook = (ROOT / "ansible/preprod-clean-room.yml").read_text()
        tasks = (
            ROOT / "ansible/roles/preprod_stack/tasks/clean_room.yml"
        ).read_text()
        role = (ROOT / "ansible/roles/preprod_stack/tasks/main.yml").read_text()
        defaults = (ROOT / "ansible/roles/preprod_stack/defaults/main.yml").read_text()

        confirmation = "DESTROY_AIGW_PREPROD_RELEASE_IMAGES"
        self.assertIn(confirmation, playbook)
        self.assertIn(confirmation, tasks)
        self.assertIn("preprod_state: clean-room", playbook)
        self.assertIn("preprod_state in ['present', 'absent', 'clean-room']", role)
        self.assertIn("include_tasks: clean_room.yml", role)
        self.assertIn("preprod_manage_hosts: true", defaults)
        self.assertIn("preprod_seed_require_fresh_load: false", defaults)

        purge = tasks.index(
            "- name: Validate, destroy, purge, and prove the exact preprod release boundary"
        )
        engine = tasks.index(
            "- name: Prove clean-room and the Linux root loader use the same Docker engine"
        )
        loopback = tasks.index(
            "- name: Remove only macOS loopback aliases owned by this preprod after clean-room purge"
        )
        hosts = tasks.index(
            "- name: Remove only the exact marker-bounded preprod hosts fragment after clean-room purge"
        )
        report = tasks.index(
            "- name: Report the completed release-image clean-room receipt"
        )
        self.assertLess(engine, purge)
        self.assertLess(purge, loopback)
        self.assertLess(loopback, hosts)
        self.assertLess(hosts, report)
        self.assertIn("become: false", tasks[purge:loopback])
        self.assertIn("become: true", tasks[loopback:hosts])
        self.assertIn("become: true", tasks[hosts:])
        self.assertIn("preprod_clean_room.stdout | trim", tasks[report:])
        self.assertNotIn("compose --rmi", tasks)

        clean_argv = tasks[purge:loopback]
        for option in (
            "clean-room-seed",
            "--archive",
            "--archive-sha256",
            "--manifest",
            "--manifest-sha256",
            "--confirm",
        ):
            self.assertIn(option, clean_argv)
        self.assertIn("PREPROD_CLEAN_ROOM_OK", clean_argv)
        self.assertIn("preprod_clean_room.stdout_lines | length != 1", clean_argv)
        engine_block = tasks[engine:purge]
        self.assertIn("check-root-seed-engine", engine_block)
        self.assertIn("become: false", engine_block)
        self.assertIn("== 'Linux'", engine_block)

    def test_release_grade_seed_load_requires_one_fresh_archive_load(self) -> None:
        defaults = (ROOT / "ansible/roles/preprod_stack/defaults/main.yml").read_text()
        self.assertIn("preprod_seed_require_fresh_load: false", defaults)
        linux_loader = self.tasks.split(
            "- name: Load the exact offline image seed", 1
        )[1].split(
            "- name: Load the exact offline image seed through the Docker Desktop operator",
            1,
        )[0]
        desktop_loader = self.tasks.split(
            "- name: Load the exact offline image seed through the Docker Desktop operator",
            1,
        )[1].split("- name: Bind preprod", 1)[0]
        self.assertIn("preprod_seed_require_fresh_load | bool", linux_loader)
        self.assertIn("'LOADED ' ~ preprod_seed_archive_sha256", linux_loader)
        self.assertIn("preprod_seed_require_fresh_load | bool", desktop_loader)
        self.assertIn(
            "'PREPROD_LOCAL_SEED_LOADED ' ~ preprod_seed_archive_sha256",
            desktop_loader,
        )
        self.assertNotIn("SKIPPED", linux_loader)
        self.assertNotIn("RELOADED ' ~", linux_loader)

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
        self.assertIn("PG_DATA_VOLUME_NAME", self.script)
        self.assertIn("com.aigw.preprod.project", self.script)
        self.assertIn("local Unix-socket Docker context", self.script)

        internal = self.compose.split("  preprod-edge-forwarder:\n", 1)[1].split(
            "\n  preprod-edge-forwarder-adm:\n", 1
        )[0]
        admin = self.compose.split(
            "  preprod-edge-forwarder-adm:\n", 1
        )[1].split("\n  oauth2-proxy:\n", 1)[0]
        self.assertIn("${ETH2_IP:?ETH2_IP must be set}:443:8443", internal)
        self.assertNotIn("ETH1_IP", internal)
        self.assertIn("networks: [net-int-edge]", internal)
        self.assertNotIn("net-adm", internal)
        self.assertIn("preprod-edge-forwarder.yaml:ro,z", internal)
        self.assertIn("${ETH1_IP:?ETH1_IP must be set}:443:9443", admin)
        self.assertNotIn("ETH2_IP", admin)
        self.assertIn("networks: [net-adm]", admin)
        self.assertNotIn("net-int-edge", admin)
        self.assertIn("preprod-edge-forwarder.yaml:ro,z", admin)

        module = load_preprod_module()
        networks = module.desired_networks(
            types.SimpleNamespace(prefix="aigw-preprod", subnet_octet=29)
        )
        self.assertEqual(
            networks["aigw-preprod-net-vendor"],
            ("172.28.7.0/24", True),
        )
        self.assertEqual(
            networks["aigw-preprod-plane-egress"],
            ("172.29.0.0/24", False),
        )

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

    def test_teardown_tolerates_only_a_missing_new_bind_leaf(self) -> None:
        module = load_preprod_module()
        args = types.SimpleNamespace(project="aigw-preprod")
        labels = {
            "com.aigw.preprod.project": args.project,
            "com.aigw.preprod.config-digest": "a" * 64,
        }
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            compose_root = Path(directory).resolve()
            missing = compose_root / "secrets/new-token"
            missing.parent.mkdir()
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
                            },
                            {
                                "type": "bind",
                                "source": str(missing),
                                "target": "/run/secrets/new-token",
                                "read_only": True,
                                "bind": {"selinux": "Z"},
                            },
                        ],
                    }
                },
                "networks": {},
                "volumes": {
                    "vault_data": {
                        "name": "aigw-preprod_vault_data",
                        "labels": labels,
                    }
                },
            }
            with (
                mock.patch.object(module, "COMPOSE_DIR", compose_root),
                mock.patch.object(
                    module, "PREPROD_BIND_SOURCES", ("secrets/new-token",)
                ),
                mock.patch.object(module, "desired_networks", return_value={}),
                mock.patch.object(
                    module,
                    "preprod_env_value",
                    return_value="a" * 64,
                ),
            ):
                with self.assertRaisesRegex(
                    SystemExit, "required preprod bind source is missing"
                ):
                    module.verify_rendered_resource_ownership(args, model)
                names = module.verify_rendered_resource_ownership(
                    args, model, allow_missing_bind_sources=True
                )
            self.assertEqual(names, {"aigw-preprod_vault_data"})

    def test_teardown_tolerates_only_missing_provider_policy_state(self) -> None:
        module = load_preprod_module()
        args = types.SimpleNamespace(
            project="aigw-preprod", image_mode="source"
        )
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
                },
                "key-rotator": {
                    "labels": labels,
                    "environment": {
                        "PROVIDER_POLICY_RECEIPT_FILE": "",
                        "AIGW_EGRESS_POLICY_SHA256": "",
                    },
                },
            },
            "networks": {},
            "volumes": {
                "vault_data": {
                    "name": "aigw-preprod_vault_data",
                    "labels": labels,
                }
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            missing_policy = Path(directory) / "missing-policy.json"
            with (
                mock.patch.object(module, "PROVIDER_POLICY_RECEIPT", missing_policy),
                mock.patch.object(module, "PREPROD_BIND_SOURCES", ()),
                mock.patch.object(module, "desired_networks", return_value={}),
                mock.patch.object(
                    module, "preprod_env_value", return_value="a" * 64
                ),
            ):
                with self.assertRaisesRegex(
                    SystemExit, "source-build provider policy boundary is missing"
                ):
                    module.verify_rendered_resource_ownership(args, model)
                names = module.verify_rendered_resource_ownership(
                    args, model, allow_missing_provider_policy=True
                )
        self.assertEqual(names, {"aigw-preprod_vault_data"})

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

    def test_clean_room_plan_is_canonical_bounded_and_exactly_derived(self) -> None:
        module = load_preprod_module()
        self.assertEqual(
            module._canonical_docker_alias("debian:13-slim"),
            module._canonical_docker_alias("docker.io/library/debian:13-slim"),
        )
        self.assertEqual(
            module._canonical_docker_alias("clean-room-test"),
            "docker.io/library/clean-room-test:latest",
        )
        self.assertEqual(
            module._canonical_docker_alias("docker.io/clean-room-test"),
            "docker.io/library/clean-room-test:latest",
        )
        plan = clean_room_plan(module)
        self.assertEqual(
            module._validate_clean_room_plan(plan, "b" * 64), plan
        )

        malformed_cases = []
        wrong_manifest = json.loads(json.dumps(plan))
        wrong_manifest["manifest_sha256"] = "c" * 64
        malformed_cases.append((wrong_manifest, "different manifest"))
        unsorted = json.loads(json.dumps(plan))
        unsorted["groups"][0]["aliases"].reverse()
        malformed_cases.append((unsorted, "not canonical"))
        wrong_archive_id = json.loads(json.dumps(plan))
        wrong_archive_id["groups"][0]["aliases"][0]["value"] = (
            "ai-gateway/clean-room-test:aigw-seed-" + "c" * 64
        )
        malformed_cases.append((wrong_archive_id, "not exact derivations"))
        missing_archive = json.loads(json.dumps(plan))
        missing_archive["groups"][0]["aliases"].pop(0)
        malformed_cases.append((missing_archive, "not exact derivations"))
        option_alias = json.loads(json.dumps(plan))
        option_alias["groups"][0]["aliases"][1]["value"] = "--force"
        malformed_cases.append((option_alias, "unsafe"))

        for malformed, message in malformed_cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(SystemExit, message):
                    module._validate_clean_room_plan(malformed, "b" * 64)

    def test_clean_room_consumer_accepts_the_loaders_exact_plan_schema(self) -> None:
        module = load_preprod_module()
        loader = load_seed_loader_module()
        custom_id = "sha256:" + "a" * 64
        external_id = "sha256:" + "c" * 64
        document = {
            "external_images": [
                {
                    "image_id": external_id,
                    "reference": "debian:13-slim@sha256:" + "d" * 64,
                }
            ],
            "custom_images": [
                {
                    "archive_reference": (
                        "ai-gateway/clean-room-test:aigw-seed-" + "a" * 64
                    ),
                    "image": "ai-gateway/clean-room-test:1",
                    "image_id": custom_id,
                }
            ],
        }
        plan = loader._purge_plan_aliases(document)
        plan["manifest_sha256"] = "b" * 64
        self.assertEqual(
            module._validate_clean_room_plan(plan, "b" * 64), plan
        )
        custom_group = next(
            group for group in plan["groups"] if group["image_id"] == custom_id
        )
        self.assertEqual(
            [alias["kind"] for alias in custom_group["aliases"]],
            ["custom-archive-reference", "custom-image"],
        )

    def test_clean_room_planner_cli_is_read_only_exact_and_canonical(self) -> None:
        module = load_preprod_module()
        plan = clean_room_plan(module)
        canonical = json.dumps(plan, sort_keys=True, separators=(",", ":")) + "\n"
        args = types.SimpleNamespace(
            archive="/private/release.preprod.docker.tar.zst",
            archive_sha256="c" * 64,
            manifest="/private/release.preprod.manifest.json",
            manifest_sha256="b" * 64,
        )
        completed = subprocess.CompletedProcess([], 0, canonical, "")
        with (
            mock.patch.object(module.os, "geteuid", return_value=501),
            mock.patch.object(
                module,
                "validate_local_docker_context",
                return_value="unix:///private/tmp/docker.sock",
            ),
            mock.patch.object(module, "run", return_value=completed) as runner,
        ):
            self.assertEqual(module.clean_room_purge_plan(args), plan)
        command = runner.call_args.args[0]
        self.assertEqual(command[3], "local-preprod-purge-plan")
        self.assertEqual(command[-1], "unix:///private/tmp/docker.sock")
        self.assertEqual(command[-2], str(ROOT.resolve()))
        for forbidden in ("load", "rm", "rmi", "--force"):
            self.assertNotIn(forbidden, command)

        noncanonical = subprocess.CompletedProcess(
            [], 0, json.dumps(plan, indent=2) + "\n", ""
        )
        with (
            mock.patch.object(module.os, "geteuid", return_value=501),
            mock.patch.object(
                module,
                "validate_local_docker_context",
                return_value="unix:///private/tmp/docker.sock",
            ),
            mock.patch.object(module, "run", return_value=noncanonical),
        ):
            with self.assertRaisesRegex(SystemExit, "unbounded response"):
                module.clean_room_purge_plan(args)

    def test_clean_room_inventory_inspects_all_objects_and_snapshots_non_targets(self) -> None:
        module = load_preprod_module()
        plan = clean_room_plan(module)
        target_id = plan["groups"][0]["image_id"]
        other_id = "sha256:" + "d" * 64
        container_id = "e" * 64
        aliases = {
            alias["value"] for alias in plan["groups"][0]["aliases"]
        }
        target_document = {
            "Id": target_id,
            "RepoTags": sorted(
                "docker.io/" + value
                for value in aliases
                if "@sha256:" not in value
            ),
            "RepoDigests": [
                "docker.io/ai-gateway/clean-room-test@" + target_id
            ],
            "Descriptor": {"digest": target_id},
        }
        other_document = {
            "Id": other_id,
            "RepoTags": ["unrelated/image:1"],
            "RepoDigests": [],
            "Descriptor": {"digest": other_id},
        }
        container_document = {
            "Id": container_id,
            "Name": "/aigw-preprod-test-1",
            "Image": target_id,
            "Config": {
                "Labels": {
                    "com.docker.compose.project": "aigw-preprod",
                    "com.aigw.preprod.project": "aigw-preprod",
                }
            },
        }

        def listed(kind, *_arguments, **_kwargs):
            return [container_id] if kind == "container" else [target_id, other_id]

        def inspected(kind, value):
            if kind == "container":
                return container_document
            return target_document if value == target_id else other_document

        def optional(value, _kind=None):
            if value == other_id:
                return other_document
            return target_document

        with (
            mock.patch.object(module, "_clean_room_list", side_effect=listed),
            mock.patch.object(
                module, "_clean_room_inspect_required", side_effect=inspected
            ) as inspect,
            mock.patch.object(
                module, "_clean_room_inspect_image_optional", side_effect=optional
            ),
        ):
            inventory = module.collect_clean_room_inventory(plan)
        self.assertEqual(inventory["non_target_ids"], {other_id})
        self.assertEqual(inventory["present_target_ids"], {target_id})
        self.assertEqual(len(inventory["present_aliases"]), 2)
        self.assertEqual(len(inventory["generated_aliases"]), 1)
        self.assertEqual(inspect.call_count, 3)

    def test_clean_room_inventory_rejects_foreign_use_alias_and_id_only_trust(self) -> None:
        module = load_preprod_module()
        plan = clean_room_plan(module)
        target_id = plan["groups"][0]["image_id"]
        container_id = "e" * 64
        target_document = {
            "Id": target_id,
            "RepoTags": ["foreign/alias:1"],
            "RepoDigests": [],
            "Descriptor": {"digest": target_id},
        }
        unrelated_container = {
            "Id": container_id,
            "Name": "/unrelated",
            "Image": target_id,
            "Config": {"Labels": {}},
        }

        def listed(kind, *_arguments, **_kwargs):
            return [container_id] if kind == "container" else [target_id]

        def inspected(kind, _value):
            return unrelated_container if kind == "container" else target_document

        with (
            mock.patch.object(module, "_clean_room_list", side_effect=listed),
            mock.patch.object(
                module, "_clean_room_inspect_required", side_effect=inspected
            ),
            mock.patch.object(
                module,
                "_clean_room_inspect_image_optional",
                return_value=target_document,
            ),
        ):
            with self.assertRaisesRegex(SystemExit, "unreviewed Docker alias"):
                module.collect_clean_room_inventory(plan)

        target_document["RepoTags"] = []
        with (
            mock.patch.object(module, "_clean_room_list", side_effect=listed),
            mock.patch.object(
                module, "_clean_room_inspect_required", side_effect=inspected
            ),
            mock.patch.object(
                module, "_clean_room_inspect_image_optional", return_value=None
            ),
        ):
            with self.assertRaisesRegex(SystemExit, "without a reviewed alias binding"):
                module.collect_clean_room_inventory(plan)

        with (
            mock.patch.object(module, "_clean_room_list", side_effect=listed),
            mock.patch.object(
                module, "_clean_room_inspect_required", side_effect=inspected
            ),
            mock.patch.object(
                module,
                "_clean_room_inspect_image_optional",
                return_value=target_document,
            ),
        ):
            with self.assertRaisesRegex(SystemExit, "unrelated running or stopped"):
                module.collect_clean_room_inventory(plan)

    def test_clean_room_image_removal_is_alias_first_no_prune_and_fail_closed(self) -> None:
        module = load_preprod_module()
        plan = clean_room_plan(module)
        target_id = plan["groups"][0]["image_id"]
        document = {"Id": target_id}
        inventory = {
            "present_aliases": [
                (target_id, alias["kind"], alias["value"])
                for alias in plan["groups"][0]["aliases"]
            ],
            "generated_aliases": [
                (
                    target_id,
                    "custom-generated-repository-digest",
                    "ai-gateway/clean-room-test@" + target_id,
                )
            ],
            "present_target_ids": {target_id},
        }
        removals = []
        with (
            mock.patch.object(
                module,
                "_clean_room_inspect_image_optional",
                return_value=document,
            ),
            mock.patch.object(
                module,
                "_remove_clean_room_image_reference",
                side_effect=lambda value, kind: removals.append((value, kind)) or True,
            ),
        ):
            module.remove_clean_room_images(plan, inventory)
        self.assertEqual(
            [value for value, _ in removals[:-1]],
            [alias["value"] for alias in plan["groups"][0]["aliases"]]
            + ["ai-gateway/clean-room-test@" + target_id],
        )
        self.assertEqual(removals[-1], (target_id, None))

        late_foreign_alias = {"Id": target_id, "RepoTags": ["foreign:latest"]}
        with (
            mock.patch.object(
                module,
                "_clean_room_inspect_image_optional",
                side_effect=[document, document, document, late_foreign_alias],
            ),
            mock.patch.object(module, "_remove_clean_room_image_reference") as remove,
        ):
            with self.assertRaisesRegex(SystemExit, "gained an unreviewed alias"):
                module.remove_clean_room_images(plan, inventory)
        self.assertEqual(remove.call_count, 3)

        success = subprocess.CompletedProcess([], 0, "Deleted: " + target_id + "\n", "")
        with mock.patch.object(module, "clean_room_docker", return_value=success) as docker:
            self.assertTrue(
                module._remove_clean_room_image_reference(target_id, None)
            )
        self.assertEqual(
            docker.call_args.args,
            ("image", "rm", "--no-prune", target_id),
        )
        for forbidden in ("--force", "--all", "--prune", "--rmi"):
            self.assertNotIn(forbidden, docker.call_args.args)

        generic = subprocess.CompletedProcess([], 1, "", "daemon unavailable\n")
        with mock.patch.object(module, "clean_room_docker", return_value=generic):
            with self.assertRaisesRegex(SystemExit, "failed while removing"):
                module._remove_clean_room_image_reference(target_id, None)

        exact_missing = subprocess.CompletedProcess(
            [],
            1,
            "",
            "Error response from daemon: No such image: "
            "ai-gateway/missing:latest\n",
        )
        with mock.patch.object(
            module, "clean_room_docker", return_value=exact_missing
        ):
            self.assertFalse(
                module._remove_clean_room_image_reference(
                    "ai-gateway/missing", "custom-image"
                )
            )
        format_newline_missing = subprocess.CompletedProcess(
            [],
            1,
            "\n",
            "Error response from daemon: No such image: "
            "ai-gateway/missing:latest\n",
        )
        with mock.patch.object(
            module, "clean_room_docker", return_value=format_newline_missing
        ):
            self.assertFalse(
                module._remove_clean_room_image_reference(
                    "ai-gateway/missing", "custom-image"
                )
            )
        wrong_missing = subprocess.CompletedProcess(
            [],
            1,
            "",
            "Error response from daemon: No such image: other:latest\n",
        )
        with mock.patch.object(
            module, "clean_room_docker", return_value=wrong_missing
        ):
            with self.assertRaisesRegex(SystemExit, "failed while removing"):
                module._remove_clean_room_image_reference(
                    "ai-gateway/missing", "custom-image"
                )

    def test_clean_room_resource_preflight_refuses_unreconstructable_ownership(self) -> None:
        module = load_preprod_module()
        container_id = "e" * 64
        inventory = {
            "containers": {
                container_id: {
                    "Id": container_id,
                    "Name": "/aigw-preprod-test-1",
                    "Image": "sha256:" + "a" * 64,
                    "Config": {
                        "Labels": {
                            "com.docker.compose.project": "aigw-preprod",
                            "com.aigw.preprod.project": "aigw-preprod",
                        }
                    },
                }
            }
        }
        args = types.SimpleNamespace(
            project="aigw-preprod",
            prefix="aigw-preprod",
            subnet_octet=29,
            image_mode="seed",
        )
        with tempfile.TemporaryDirectory() as directory:
            missing_env = Path(directory) / "preprod.env"
            with mock.patch.object(module, "ENV_FILE", missing_env):
                with self.assertRaisesRegex(SystemExit, "exact clean-room project"):
                    module.preflight_clean_room_resources(args, inventory)

            unsafe_receipt = Path(directory) / "receipt.json"
            target = Path(directory) / "target.json"
            target.write_text("{}", encoding="utf-8")
            unsafe_receipt.symlink_to(target)
            with (
                mock.patch.object(module, "SEED_RECEIPT", unsafe_receipt),
                mock.patch.object(module, "SEED_OVERLAY", Path(directory) / "none"),
                mock.patch.object(module, "VAULT_INIT_FILE", Path(directory) / "vault"),
            ):
                with self.assertRaisesRegex(SystemExit, "unsafe generated"):
                    module._validate_clean_room_generated_state()

    def test_clean_room_audit_fixture_fails_before_resource_destroy(self) -> None:
        module = load_preprod_module()
        plan = clean_room_plan(module)
        inventory = {
            "containers": {},
            "images": {},
            "non_target_ids": set(),
            "generated_aliases": [],
            "present_aliases": [],
            "present_target_ids": set(),
            "target_ids": {plan["groups"][0]["image_id"]},
        }
        args = types.SimpleNamespace(
            confirm=module.CLEAN_ROOM_CONFIRMATION,
            manifest_sha256="b" * 64,
            project="aigw-preprod",
            prefix="aigw-preprod",
            subnet_octet=29,
            image_mode="seed",
        )
        cases = (
            ("unknown-entry", "unknown file"),
            (
                "dangling-directory",
                "unsafe preprod controller audit fixture directory",
            ),
            ("dangling-file", "unsafe preprod controller audit fixture file"),
            (
                "unsafe-directory-mode",
                "unsafe preprod controller audit fixture directory",
            ),
        )

        for case, expected_error in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                audit_directory = root / "controller"
                current = audit_directory / "lifecycle.jsonl"
                rotated = audit_directory / "lifecycle.jsonl.1"
                if case == "dangling-directory":
                    audit_directory.symlink_to(
                        root / "missing-controller", target_is_directory=True
                    )
                else:
                    audit_directory.mkdir(mode=0o755)
                    if case == "unknown-entry":
                        (audit_directory / "unexpected").write_text(
                            "do not remove\n", encoding="utf-8"
                        )
                    elif case == "dangling-file":
                        current.symlink_to(root / "missing-lifecycle")
                    else:
                        audit_directory.chmod(0o700)

                missing = root / "missing"
                with (
                    mock.patch.object(
                        module, "PREPROD_CONTROLLER_AUDIT_DIR", audit_directory
                    ),
                    mock.patch.object(
                        module, "PREPROD_CONTROLLER_AUDIT_FILES", (current, rotated)
                    ),
                    mock.patch.object(module, "SEED_RECEIPT", missing),
                    mock.patch.object(module, "SEED_OVERLAY", missing),
                    mock.patch.object(module, "VAULT_INIT_FILE", missing),
                    mock.patch.object(module, "ENV_FILE", missing),
                    mock.patch.object(
                        module, "clean_room_purge_plan", return_value=plan
                    ),
                    mock.patch.object(
                        module, "collect_clean_room_inventory", return_value=inventory
                    ),
                    mock.patch.object(module, "desired_networks", return_value={}),
                    mock.patch.object(module, "_clean_room_list", return_value=[]),
                    mock.patch.object(
                        module, "_clean_room_network_inventory", return_value=[]
                    ),
                    mock.patch.object(
                        module, "_destroy_project_resources"
                    ) as destroy,
                    self.assertRaisesRegex(SystemExit, expected_error),
                ):
                    module.clean_room_seed(args)
                destroy.assert_not_called()

    def test_clean_room_root_owned_audit_fixture_fails_before_destroy(self) -> None:
        module = load_preprod_module()
        plan = clean_room_plan(module)
        inventory = {
            "containers": {},
            "images": {},
            "non_target_ids": set(),
            "generated_aliases": [],
            "present_aliases": [],
            "present_target_ids": set(),
            "target_ids": {plan["groups"][0]["image_id"]},
        }
        args = types.SimpleNamespace(
            confirm=module.CLEAN_ROOM_CONFIRMATION,
            manifest_sha256="b" * 64,
            project="aigw-preprod",
            prefix="aigw-preprod",
            subnet_octet=29,
            image_mode="seed",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            audit_directory = root / "controller"
            audit_directory.mkdir(mode=0o755)
            current = audit_directory / "lifecycle.jsonl"
            current.write_text("root-owned fixture\n", encoding="utf-8")
            current.chmod(0o644)
            rotated = audit_directory / "lifecycle.jsonl.1"
            missing = root / "missing"
            path_type = type(audit_directory)
            real_lstat = path_type.lstat

            def root_owned_lstat(path):
                metadata = real_lstat(path)
                if path in {audit_directory, current}:
                    values = list(metadata)
                    values[4] = 0
                    values[5] = 0
                    return os.stat_result(values)
                return metadata

            with (
                mock.patch.object(path_type, "lstat", root_owned_lstat),
                mock.patch.object(module.os, "geteuid", return_value=12345),
                mock.patch.object(module.os, "getegid", return_value=12345),
                mock.patch.object(
                    module, "PREPROD_CONTROLLER_AUDIT_DIR", audit_directory
                ),
                mock.patch.object(
                    module, "PREPROD_CONTROLLER_AUDIT_FILES", (current, rotated)
                ),
                mock.patch.object(module, "SEED_RECEIPT", missing),
                mock.patch.object(module, "SEED_OVERLAY", missing),
                mock.patch.object(module, "VAULT_INIT_FILE", missing),
                mock.patch.object(module, "ENV_FILE", missing),
                mock.patch.object(module, "clean_room_purge_plan", return_value=plan),
                mock.patch.object(
                    module, "collect_clean_room_inventory", return_value=inventory
                ),
                mock.patch.object(module, "desired_networks", return_value={}),
                mock.patch.object(module, "_clean_room_list", return_value=[]),
                mock.patch.object(
                    module, "_clean_room_network_inventory", return_value=[]
                ),
                mock.patch.object(module, "_destroy_project_resources") as destroy,
                self.assertRaisesRegex(
                    SystemExit, "unsafe preprod controller audit fixture directory"
                ),
            ):
                module.clean_room_seed(args)
            destroy.assert_not_called()
            self.assertEqual(current.read_text(encoding="utf-8"), "root-owned fixture\n")

    def test_clean_room_network_inventory_binds_full_ids_to_names(self) -> None:
        module = load_preprod_module()
        network_id = "a" * 64
        document = {"Id": network_id, "Name": "aigw-preprod-net-test"}
        with (
            mock.patch.object(module, "_clean_room_list", return_value=[network_id]) as listed,
            mock.patch.object(
                module, "_clean_room_inspect_required", return_value=document
            ) as inspected,
        ):
            self.assertEqual(
                module._clean_room_network_inventory(),
                [(network_id, "aigw-preprod-net-test", document)],
            )
        listed.assert_called_once_with("network", "--no-trunc", "--quiet")
        inspected.assert_called_once_with("network", network_id)

        changed = {"Id": "b" * 64, "Name": "aigw-preprod-net-test"}
        with (
            mock.patch.object(module, "_clean_room_list", return_value=[network_id]),
            mock.patch.object(
                module, "_clean_room_inspect_required", return_value=changed
            ),
            self.assertRaisesRegex(SystemExit, "network inspection changed identity"),
        ):
            module._clean_room_network_inventory()

    def test_clean_room_resource_inventory_uses_bound_network_names(self) -> None:
        module = load_preprod_module()
        args = types.SimpleNamespace(
            project="aigw-preprod",
            prefix="aigw-preprod",
            subnet_octet=29,
            image_mode="seed",
        )
        inventory = {"containers": {}}
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing"
            with (
                mock.patch.object(module, "ENV_FILE", missing),
                mock.patch.object(module, "desired_networks", return_value={}),
                mock.patch.object(
                    module, "_validate_clean_room_generated_state", return_value=0
                ),
                mock.patch.object(
                    module, "_clean_room_network_inventory", return_value=[]
                ) as networks,
                mock.patch.object(module, "_clean_room_list", return_value=[]) as listed,
            ):
                module.preflight_clean_room_resources(args, inventory)
            self.assertEqual(
                listed.call_args_list,
                [
                    mock.call("volume", "--format", "{{.Name}}"),
                ],
            )
            networks.assert_called_once_with()

            with (
                mock.patch.object(module, "SEED_RECEIPT", missing),
                mock.patch.object(module, "SEED_OVERLAY", missing),
                mock.patch.object(module, "VAULT_INIT_FILE", missing),
                mock.patch.object(module, "_clean_room_list", return_value=[]) as listed,
                mock.patch.object(
                    module,
                    "_clean_room_network_inventory",
                    return_value=[
                        (
                            "c" * 64,
                            "aigw-preprod-stale",
                            {"Id": "c" * 64, "Name": "aigw-preprod-stale", "Labels": {}},
                        )
                    ],
                ),
                self.assertRaisesRegex(SystemExit, "preprod network remains"),
            ):
                module.prove_clean_room_resource_absence(args)
            self.assertEqual(
                listed.call_args_list,
                [
                    mock.call("container", "--all", "--no-trunc", "--quiet"),
                    mock.call("volume", "--format", "{{.Name}}"),
                ],
            )

    def test_clean_room_removes_only_the_exact_legacy_vendor_subnet(self) -> None:
        module = load_preprod_module()
        args = types.SimpleNamespace(
            project="aigw-preprod",
            prefix="aigw-preprod",
            subnet_octet=29,
            image_mode="seed",
        )
        container_id = "a" * 64
        inventory = {
            "containers": {
                container_id: {
                    "Name": "/aigw-preprod-litellm-1",
                    "Config": {
                        "Labels": {
                            "com.docker.compose.project": "aigw-preprod",
                            "com.aigw.preprod.project": "aigw-preprod",
                        }
                    },
                }
            }
        }
        network_name = "aigw-preprod-net-vendor"

        def network(subnet: str) -> dict:
            return {
                "Id": "b" * 64,
                "Name": network_name,
                "Labels": {"com.aigw.preprod.project": "aigw-preprod"},
                "Containers": {container_id: {}},
                "Driver": "bridge",
                "Scope": "local",
                "Internal": True,
                "IPAM": {
                    "Config": [
                        {
                            "Subnet": subnet,
                            "IPRange": module.dynamic_ip_range(subnet),
                        }
                    ]
                },
            }

        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / "preprod.env"
            env_file.write_text("test\n", encoding="utf-8")
            with (
                mock.patch.object(module, "ENV_FILE", env_file),
                mock.patch.object(
                    module, "_clean_room_compose_overrides", return_value={}
                ),
                mock.patch.object(module, "rendered_compose_model", return_value={}),
                mock.patch.object(
                    module, "verify_rendered_resource_ownership", return_value=set()
                ),
                mock.patch.object(module, "verify_existing_project_boundary"),
                mock.patch.object(
                    module, "_validate_clean_room_generated_state", return_value=0
                ),
                mock.patch.object(module, "_clean_room_list", return_value=[]),
                mock.patch.object(
                    module,
                    "_clean_room_network_inventory",
                    return_value=[
                        ("b" * 64, network_name, network("172.29.7.0/24"))
                    ],
                ),
            ):
                result = module.preflight_clean_room_resources(args, inventory)
            self.assertEqual(result["networks"], {network_name})

            with (
                mock.patch.object(module, "ENV_FILE", env_file),
                mock.patch.object(
                    module, "_clean_room_compose_overrides", return_value={}
                ),
                mock.patch.object(module, "rendered_compose_model", return_value={}),
                mock.patch.object(
                    module, "verify_rendered_resource_ownership", return_value=set()
                ),
                mock.patch.object(module, "verify_existing_project_boundary"),
                mock.patch.object(
                    module, "_validate_clean_room_generated_state", return_value=0
                ),
                mock.patch.object(module, "_clean_room_list", return_value=[]),
                mock.patch.object(
                    module,
                    "_clean_room_network_inventory",
                    return_value=[
                        ("b" * 64, network_name, network("172.29.8.0/24"))
                    ],
                ),
                self.assertRaisesRegex(SystemExit, "unexpected settings"),
            ):
                module.preflight_clean_room_resources(args, inventory)

    def test_clean_room_orders_all_validation_before_resources_then_images(self) -> None:
        module = load_preprod_module()
        plan = clean_room_plan(module)
        events = []
        inventory = {
            "containers": {},
            "images": {},
            "non_target_ids": {"sha256:" + "d" * 64},
            "generated_aliases": [],
            "present_aliases": [],
            "present_target_ids": set(),
            "target_ids": {plan["groups"][0]["image_id"]},
        }
        resources = {
            "containers": set(),
            "volumes": set(),
            "networks": set(),
            "generated_state_files": 2,
            "source_args": types.SimpleNamespace(image_mode="source"),
        }
        args = types.SimpleNamespace(
            confirm=module.CLEAN_ROOM_CONFIRMATION,
            manifest_sha256="b" * 64,
            project="aigw-preprod",
        )
        with (
            mock.patch.object(
                module, "clean_room_purge_plan", side_effect=lambda _a: events.append("plan") or plan
            ),
            mock.patch.object(
                module, "collect_clean_room_inventory", side_effect=lambda _p: events.append("inventory") or inventory
            ),
            mock.patch.object(
                module, "preflight_clean_room_resources", side_effect=lambda _a, _i: events.append("resource-preflight") or resources
            ),
            mock.patch.object(
                module, "_destroy_project_resources", side_effect=lambda *_a, **_k: events.append("destroy-resources")
            ),
            mock.patch.object(
                module, "prove_clean_room_resource_absence", side_effect=lambda _a: events.append("prove-resources")
            ),
            mock.patch.object(
                module, "prove_clean_room_target_images_unused", side_effect=lambda _ids: events.append("prove-unused")
            ),
            mock.patch.object(
                module, "remove_clean_room_images", side_effect=lambda _p, _i: events.append("remove-images") or {"aliases": 0, "image_ids": 0}
            ),
            mock.patch.object(
                module, "prove_clean_room_image_absence", side_effect=lambda _p, _i: events.append("prove-images")
            ),
            mock.patch("sys.stdout", new_callable=io.StringIO) as stdout,
        ):
            module.clean_room_seed(args)
        self.assertEqual(
            events,
            [
                "plan",
                "inventory",
                "resource-preflight",
                "destroy-resources",
                "prove-resources",
                "prove-unused",
                "remove-images",
                "prove-images",
            ],
        )
        receipt = stdout.getvalue().strip()
        self.assertTrue(receipt.startswith("PREPROD_CLEAN_ROOM_OK {"))
        self.assertLess(len(receipt.encode()), 1100)

        with mock.patch.object(module, "clean_room_purge_plan") as planner:
            args.confirm = "yes"
            with self.assertRaisesRegex(SystemExit, "requires DESTROY"):
                module.clean_room_seed(args)
        planner.assert_not_called()

    def test_clean_room_resource_destroy_suppresses_nonreceipt_output_only(self) -> None:
        module = load_preprod_module()
        args = types.SimpleNamespace(project="aigw-preprod")
        network = "aigw-preprod-edge"

        def docker_result(*arguments, **_kwargs):
            if arguments[:2] == ("network", "ls"):
                return subprocess.CompletedProcess([], 0, network + "\n", "")
            if arguments[:2] == ("network", "inspect"):
                return subprocess.CompletedProcess(
                    [],
                    0,
                    json.dumps(
                        [{"Labels": {"com.aigw.preprod.project": args.project}}]
                    ),
                    "",
                )
            return subprocess.CompletedProcess([], 0, network + "\n", "")

        with tempfile.TemporaryDirectory() as directory:
            missing_env = Path(directory) / "missing.env"
            missing_vault = Path(directory) / "missing-vault.json"
            with (
                mock.patch.object(module, "ENV_FILE", missing_env),
                mock.patch.object(module, "VAULT_INIT_FILE", missing_vault),
                mock.patch.object(module, "desired_networks", return_value={network: None}),
                mock.patch.object(module, "validate_local_docker_context"),
                mock.patch.object(module, "check_context"),
                mock.patch.object(module, "remove_seed_output_files"),
                mock.patch.object(module, "remove_controller_audit_fixture"),
                mock.patch.object(module, "docker", side_effect=docker_result) as docker,
                mock.patch("sys.stdout", new_callable=io.StringIO),
            ):
                module._destroy_project_resources(
                    args, emit_context=False, emit_receipt=False
                )
                self.assertIn(
                    mock.call("network", "rm", network, capture=True),
                    docker.call_args_list,
                )

                docker.reset_mock()
                module._destroy_project_resources(
                    args, emit_context=True, emit_receipt=True
                )
                self.assertIn(
                    mock.call("network", "rm", network, capture=False),
                    docker.call_args_list,
                )

    def test_clean_room_destroy_uses_the_same_compatibility_environment(self) -> None:
        module = load_preprod_module()
        args = types.SimpleNamespace(project="aigw-preprod")
        compatibility = {"AIGW_BIND_DIGEST_ALERTMANAGER": "d" * 64}
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / "preprod.env"
            env_file.write_text("test=value\n", encoding="utf-8")
            missing_vault = Path(directory) / "missing-vault.json"
            with (
                mock.patch.object(module, "ENV_FILE", env_file),
                mock.patch.object(module, "VAULT_INIT_FILE", missing_vault),
                mock.patch.object(module, "validate_local_docker_context"),
                mock.patch.object(
                    module,
                    "_clean_room_compose_overrides",
                    return_value=compatibility,
                ),
                mock.patch.object(
                    module, "rendered_compose_model", return_value={}
                ) as rendered,
                mock.patch.object(
                    module, "verify_rendered_resource_ownership", return_value=set()
                ),
                mock.patch.object(module, "verify_existing_project_boundary"),
                mock.patch.object(module, "compose") as compose,
                mock.patch.object(
                    module,
                    "docker",
                    return_value=subprocess.CompletedProcess([], 0, "", ""),
                ),
                mock.patch.object(module, "desired_networks", return_value={}),
                mock.patch.object(module, "remove_seed_output_files"),
                mock.patch.object(module, "remove_controller_audit_fixture"),
            ):
                module._destroy_project_resources(
                    args, emit_context=False, emit_receipt=False
                )

            rendered.assert_called_once_with(
                args, environment_overrides=compatibility
            )
            self.assertEqual(
                compose.call_args.kwargs["environment_overrides"], compatibility
            )

    def test_post_destroy_foreign_container_stops_before_any_image_removal(self) -> None:
        module = load_preprod_module()
        plan = clean_room_plan(module)
        target_id = plan["groups"][0]["image_id"]
        appeared_id = "f" * 64
        with (
            mock.patch.object(module, "_clean_room_list", return_value=[appeared_id]),
            mock.patch.object(
                module,
                "_clean_room_inspect_required",
                return_value={"Id": appeared_id, "Image": target_id},
            ),
        ):
            with self.assertRaisesRegex(SystemExit, "appeared using"):
                module.prove_clean_room_target_images_unused({target_id})

        inventory = {
            "containers": {},
            "images": {},
            "non_target_ids": set(),
            "generated_aliases": [],
            "present_aliases": [],
            "present_target_ids": set(),
            "target_ids": {target_id},
        }
        resources = {
            "containers": set(),
            "volumes": set(),
            "networks": set(),
            "generated_state_files": 0,
            "source_args": types.SimpleNamespace(image_mode="source"),
        }
        args = types.SimpleNamespace(
            confirm=module.CLEAN_ROOM_CONFIRMATION,
            manifest_sha256="b" * 64,
            project="aigw-preprod",
        )
        with (
            mock.patch.object(module, "clean_room_purge_plan", return_value=plan),
            mock.patch.object(
                module, "collect_clean_room_inventory", return_value=inventory
            ),
            mock.patch.object(
                module, "preflight_clean_room_resources", return_value=resources
            ),
            mock.patch.object(module, "_destroy_project_resources"),
            mock.patch.object(module, "prove_clean_room_resource_absence"),
            mock.patch.object(
                module,
                "prove_clean_room_target_images_unused",
                side_effect=SystemExit(
                    "ERROR: a container appeared using a clean-room target image after destroy"
                ),
            ),
            mock.patch.object(module, "remove_clean_room_images") as remove,
            mock.patch.object(module, "clean_room_docker") as docker,
        ):
            with self.assertRaisesRegex(SystemExit, "container appeared"):
                module.clean_room_seed(args)
        remove.assert_not_called()
        docker.assert_not_called()

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
        self.assertEqual(module.PRODUCTION_VENDOR_SUBNET, "172.28.7.0/24")
        runtime_reference = module.envoy_base_image_reference()
        self.assertRegex(
            runtime_reference,
            r"^dhi\.io/envoy:[A-Za-z0-9_.-]+@sha256:[0-9a-f]{64}$",
        )
        self.assertIn(runtime_reference, (ROOT / "services/egress-proxy/Dockerfile").read_text())

        production_block = self.compose.split("  envoy-egress:\n", 1)[1].split(
            "\n  wif-egress-mock:\n", 1
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

        litellm_block = self.compose.split("  litellm:\n", 1)[1].split(
            "\n  # Build paths", 1
        )[0]
        self.assertIn("preprod-litellm-config.yaml:/app/config.yaml:ro,Z", litellm_block)
        self.assertIn("wif-egress-mock: { condition: service_healthy", litellm_block)
        self.assertNotIn("./litellm/config.yaml:/app/config.yaml", litellm_block)

    def test_preprod_litellm_config_changes_only_reviewed_provider_routes(self) -> None:
        module = load_preprod_module()
        production = (
            "model_list:\n"
            "  - model_name: first\n"
            "    litellm_params:\n"
            "      api_base: http://envoy-egress:8080/anthropic\n"
            "  - model_name: second\n"
            "    litellm_params:\n"
            "      api_base: http://envoy-egress:8080/anthropic\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "litellm").mkdir()
            (root / "litellm/config.yaml").write_text(production, encoding="utf-8")
            secrets = root / "secrets"
            secrets.mkdir()
            with (
                mock.patch.object(module, "COMPOSE_DIR", root),
                mock.patch.object(module, "SECRETS_DIR", secrets),
            ):
                module.render_preprod_litellm_config()
            rendered = (secrets / "preprod-litellm-config.yaml").read_text(
                encoding="utf-8"
            )

        self.assertEqual(
            rendered,
            production.replace(
                "http://envoy-egress:8080/anthropic",
                "http://wif-egress-mock:8080/anthropic",
            ),
        )

        unexpected = production + "      api_base: https://unreviewed.invalid\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "litellm").mkdir()
            (root / "litellm/config.yaml").write_text(unexpected, encoding="utf-8")
            secrets = root / "secrets"
            secrets.mkdir()
            with (
                mock.patch.object(module, "COMPOSE_DIR", root),
                mock.patch.object(module, "SECRETS_DIR", secrets),
                self.assertRaisesRegex(SystemExit, "provider routes changed"),
            ):
                module.render_preprod_litellm_config()

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
                "providers": [
                    {
                        "name": "anthropic",
                        "api_hostname": "api.anthropic.com",
                        "route_prefix": "/anthropic/",
                        "sni": "api.anthropic.com",
                        "exact_sans": ["api.anthropic.com"],
                        "ca_file": "anthropic-ca.pem",
                        "ca_bundle_sha256": "6" * 64,
                        "ca_sha256_fingerprints": ["7" * 64],
                        "provenance_sha256": "8" * 64,
                    }
                ],
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
            provider_policy_path = temporary / "provider_policy_receipt.json"
            with (
                mock.patch.object(module, "SEED_RECEIPT", receipt_path),
                mock.patch.object(module, "SEED_OVERLAY", overlay_path),
                mock.patch.object(
                    module, "PROVIDER_POLICY_RECEIPT", provider_policy_path
                ),
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
            provider_policy = provider_policy_path.read_text(encoding="utf-8")

        self.assertEqual(overlay.count("pull_policy: never"), 8)
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
        self.assertIn("  preprod-edge-forwarder-adm:\n", overlay)
        self.assertIn(f"image: {envoy_base_reference}", overlay)
        self.assertNotIn("envoy_image_id", provider_policy)
        self.assertEqual(
            provider_policy,
            module.canonical_provider_policy_receipt(receipt["egress_policy"]),
        )

        missing_external = {**receipt, "external_images": {}}
        with self.assertRaisesRegex(SystemExit, "no external image for service vault"):
            module.seed_service_images(model, missing_external)

    def test_preprod_observability_cannot_read_host_or_other_project_data(self) -> None:
        self.assertIn(
            "preprod_empty_docker_logs:/var/lib/docker/containers:ro",
            self.compose,
        )
        self.assertIn("Local preprod must never read another local project's Docker logs", self.compose)
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
        self.assertNotIn("prometheus/prometheus.yml", module.PREPROD_BIND_SOURCES)
        self.assertIn(
            "secrets/preprod-prometheus.yml", module.PREPROD_BIND_SOURCES
        )
        for shared_source in (
            "./secrets/preprod-edge-certs:/certs:ro,z",
            "./secrets/preprod-root-ca.pem:/run/preprod/ca.pem:ro,z",
            "./secrets/preprod-samba-bind-password:/run/secrets/samba_ad_bind_password:ro,z",
        ):
            self.assertIn(shared_source, self.compose)
        for private_source in (
            "./secrets/preprod-litellm-config.yaml:/app/config.yaml:ro,Z",
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
                seed = root / "credential-seed"
                seed.write_bytes(b"s" * module.PREPROD_CREDENTIAL_SEED_BYTES)
                seed.chmod(0o600)
                with (
                    mock.patch.object(module, "COMPOSE_DIR", root),
                    mock.patch.object(module, "PREPROD_CREDENTIAL_SEED", seed),
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
            seed = root / "credential-seed"
            seed.write_bytes(b"s" * module.PREPROD_CREDENTIAL_SEED_BYTES)
            seed.chmod(0o600)
            with (
                mock.patch.object(module, "COMPOSE_DIR", root),
                mock.patch.object(module, "PREPROD_CREDENTIAL_SEED", seed),
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

    def test_native_linux_services_can_read_private_litellm_tokens(self) -> None:
        tasks = (
            ROOT
            / "ansible/roles/preprod_stack/tasks/present.yml"
        ).read_text()
        section = tasks.split(
            "- name: Grant native Linux services read-only access to their private tokens",
            1,
        )[1].split("- name: Prove the root loader uses", 1)[0]

        self.assertIn('group: "65532"', section)
        self.assertIn('mode: "0640"', section)
        self.assertIn("follow: false", section)
        self.assertIn("become: true", section)
        self.assertIn("- litellm_otel_token", section)
        self.assertIn("- litellm_usage_token", section)
        self.assertIn("preprod_host_kernel.stdout | trim == 'Linux'", section)
        self.assertIn("no_log: true", section)

    def test_preprod_redis_keeps_its_password_private_on_docker_desktop(self) -> None:
        redis = self.compose.split("  redis:\n", 1)[1].split(
            "\n  alloy:\n", 1
        )[0]
        self.assertIn(
            'user: "${PREPROD_HOST_UID:?PREPROD_HOST_UID must be set}:'
            '${PREPROD_HOST_GID:?PREPROD_HOST_GID must be set}"',
            redis,
        )
        self.assertIn("tmpfs: !override", redis)
        self.assertIn("- /tmp:mode=1777", redis)
        self.assertIn(
            "- /data:uid=${PREPROD_HOST_UID:?PREPROD_HOST_UID must be set},"
            "gid=${PREPROD_HOST_GID:?PREPROD_HOST_GID must be set},mode=0700",
            redis,
        )
        self.assertIn(
            'write_file(SECRETS_DIR / "redis_password", redis_password + "\\n", 0o600)',
            self.script,
        )
        self.assertIn(
            'SECRETS_DIR / "redis_users.acl",\n'
            '        f"user default reset on #{redis_password_hash} ~* &* +@all\\n",\n'
            "        0o600,",
            self.script,
        )
        self.assertIn("user default reset on #", self.script)

    def test_vault_helper_uses_running_container_stdin(self) -> None:
        module = load_preprod_module()
        args = types.SimpleNamespace(project="aigw-preprod")
        response = subprocess.CompletedProcess(
            [], 0, '{"status":501,"body":{"initialized":false}}\n', ""
        )
        with mock.patch.object(module, "compose", return_value=response) as compose:
            status, body = module.vault_call(args, "GET", "/v1/sys/health")

        self.assertEqual(status, 501)
        self.assertEqual(body, {"initialized": False})
        positional = compose.call_args.args
        self.assertEqual(
            positional[:6],
            (args, "exec", "-T", "key-rotator", "/opt/venv/bin/python", "-c"),
        )
        self.assertNotIn("run", positional)
        self.assertEqual(
            json.loads(compose.call_args.kwargs["input_text"]),
            {"method": "GET", "path": "/v1/sys/health"},
        )
        self.assertTrue(compose.call_args.kwargs["sensitive"])

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

    def test_compose_overrides_are_narrow_validated_and_shell_scrubbed(self) -> None:
        module = load_preprod_module()
        hostile = {
            "COMPOSE_FILE": "/tmp/hostile-compose.yml",
            "DOCKER_HOST": "tcp://hostile.example:2375",
            "HOME": "/private/test-home",
            "PATH": "/usr/bin:/bin",
        }
        completed = subprocess.CompletedProcess([], 0, "", "")
        reviewed = {"AIGW_BIND_DIGEST_ALERTMANAGER": "a" * 64}
        with (
            mock.patch.dict(module.os.environ, hostile, clear=True),
            mock.patch.object(module.subprocess, "run", return_value=completed) as runner,
        ):
            module.run(["true"], environment_overrides=reviewed)
        self.assertEqual(
            runner.call_args.kwargs["env"],
            {
                "HOME": "/private/test-home",
                "PATH": "/usr/bin:/bin",
                **reviewed,
            },
        )

        with self.assertRaisesRegex(SystemExit, "unreviewed Compose"):
            module.run(["true"], environment_overrides={"DOCKER_HOST": "hostile"})
        with self.assertRaisesRegex(SystemExit, "invalid Compose"):
            module.run(
                ["true"],
                environment_overrides={"AIGW_BIND_DIGEST_ALERTMANAGER": "bad"},
            )

    def test_sensitive_command_retry_is_bounded_and_stays_redacted(self) -> None:
        module = load_preprod_module()
        failed = subprocess.CompletedProcess([], 1, "", "fixed safe error")
        passed = subprocess.CompletedProcess([], 0, "receipt\n", "")
        with (
            mock.patch.object(
                module.subprocess, "run", side_effect=[failed, passed]
            ) as runner,
            mock.patch.object(module.time, "sleep") as sleep,
        ):
            result = module.run(
                ["true"],
                input_text="secret-input",
                capture=True,
                sensitive=True,
                attempts=2,
            )
        self.assertEqual(result.stdout, "receipt\n")
        self.assertEqual(runner.call_count, 2)
        sleep.assert_called_once_with(2)

        with (
            mock.patch.object(
                module.subprocess, "run", side_effect=[failed, failed]
            ),
            mock.patch.object(module.time, "sleep"),
            self.assertRaisesRegex(SystemExit, "secret-bearing"),
        ):
            module.run(
                ["true"],
                input_text="secret-input",
                capture=True,
                sensitive=True,
                attempts=2,
            )
        for invalid in (False, 0, 31):
            with self.subTest(attempts=invalid), self.assertRaisesRegex(
                SystemExit, "attempts"
            ):
                module.run(["true"], attempts=invalid)

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

        def verify_edge(_args, *, repair_transport=False):
            events.append(("edge", (repair_transport,)))

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
            mock.patch.object(module, "verify_edge_routes", side_effect=verify_edge),
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
        traefik_int_ready = events.index(
            ("wait", ("traefik-int", "healthy", 300))
        )
        traefik_adm_ready = events.index(
            ("wait", ("traefik-adm", "healthy", 300))
        )
        forwarder_ready = events.index(
            ("wait", ("preprod-edge-forwarder", "healthy", 120))
        )
        adm_forwarder_ready = events.index(
            ("wait", ("preprod-edge-forwarder-adm", "healthy", 120))
        )
        litellm_ready = events.index(("wait", ("litellm", "healthy", 600)))
        keycloak_ready = events.index(("wait", ("keycloak", "healthy", 600)))
        edge_verified = events.index(("edge", (True,)))
        self.assertEqual(len(reconciles), 2)
        self.assertLess(stop, postgres_up)
        self.assertLess(postgres_up, postgres_ready)
        self.assertLess(postgres_ready, reconciles[0])
        self.assertLess(reconciles[0], full_up)
        self.assertLess(full_up, traefik_int_ready)
        self.assertLess(full_up, traefik_adm_ready)
        self.assertLess(traefik_int_ready, forwarder_ready)
        self.assertLess(traefik_adm_ready, adm_forwarder_ready)
        self.assertFalse(
            any(
                event[0] == "compose" and event[1] and event[1][0] == "restart"
                for event in events
            )
        )
        self.assertLess(full_up, litellm_ready)
        self.assertLess(litellm_ready, edge_verified)
        self.assertLess(keycloak_ready, edge_verified)
        self.assertLess(forwarder_ready, edge_verified)
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

    def test_internal_identity_mutations_receive_unique_operation_ids(self) -> None:
        module = load_preprod_module()
        response = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout='{"status":204,"body":{}}',
            stderr="",
        )
        with mock.patch.object(module, "compose", return_value=response) as compose:
            fixed_operation_id = "11111111-1111-4111-8111-111111111111"
            module.internal_call(mock.Mock(), "GET", "/identity/groups")
            module.internal_call(
                mock.Mock(),
                "POST",
                "/identity/groups",
                {"name": "preprod-admins", "capabilities": ["aigw-admins"]},
            )
            module.internal_call(
                mock.Mock(),
                "PUT",
                "/identity/groups/group-1/members/user-1",
            )
            module.internal_call(
                mock.Mock(),
                "POST",
                "/identity/groups/group-1/policy/activate",
                {"policy_revision": "a" * 64},
                operation_id=fixed_operation_id,
            )
            module.internal_call(
                mock.Mock(),
                "PUT",
                "/providers/anthropic",
                {"enrollment_confirmation": "ENROLLED"},
            )

        requests = [
            json.loads(call.kwargs["input_text"])
            for call in compose.call_args_list
        ]
        self.assertNotIn("operation_id", requests[0])
        operation_ids = [requests[1]["operation_id"], requests[2]["operation_id"]]
        self.assertEqual(len(set(operation_ids)), 2)
        for operation_id in operation_ids:
            parsed = UUID(operation_id)
            self.assertEqual(parsed.version, 4)
            self.assertEqual(str(parsed), operation_id)
        self.assertEqual(requests[3]["operation_id"], fixed_operation_id)
        self.assertNotIn("operation_id", requests[4])
        self.assertIn(
            'headers["X-AIGW-Operation-ID"] = request["operation_id"]',
            module.INTERNAL_HTTP_HELPER,
        )

    def test_static_preprod_group_policy_is_explicit_and_three_phase(self) -> None:
        module = load_preprod_module()
        models = module.configured_preprod_model_names()
        self.assertEqual(
            models,
            [
                "claude-fable-5",
                "claude-haiku-4-5",
                "claude-opus-4-7",
                "claude-opus-4-8",
                "claude-sonnet-4-5",
                "claude-sonnet-5",
            ],
        )
        desired = {
            "tpm_limit": None,
            "rpm_limit": None,
            "allowed_models": models,
            "default_model": None,
            "model_limits": {},
        }
        revision = "a" * 64
        responses = [
            (
                200,
                {
                    "policy": desired,
                    "policy_revision": revision,
                    "reconciliation_pending": True,
                },
            ),
            (
                200,
                {
                    "active_policy": desired,
                    "policy_revision": revision,
                    "reconciliation_pending": True,
                },
            ),
            (
                200,
                {
                    "active_policy": desired,
                    "policy_revision": revision,
                    "reconciliation_pending": False,
                },
            ),
        ]
        with mock.patch.object(
            module, "internal_call", side_effect=responses
        ) as internal:
            module.ensure_preprod_group_policy(
                mock.Mock(),
                {"id": "group-1", "name": "preprod-users"},
                models,
                created=True,
            )

        self.assertEqual(
            [(call.args[1], call.args[2]) for call in internal.call_args_list],
            [
                ("PUT", "/identity/groups/group-1/policy"),
                ("POST", "/identity/groups/group-1/policy/activate"),
                ("POST", "/identity/groups/group-1/policy/complete"),
            ],
        )
        operation_ids = {
            call.kwargs["operation_id"] for call in internal.call_args_list
        }
        self.assertEqual(len(operation_ids), 1)
        operation_id = operation_ids.pop()
        self.assertEqual(str(UUID(operation_id)), operation_id)

        with mock.patch.object(module, "internal_call") as internal:
            module.ensure_preprod_group_policy(
                mock.Mock(),
                {"id": "group-1", "policy": desired},
                models,
                created=False,
            )
        internal.assert_not_called()

    def test_static_preprod_group_policy_refuses_existing_drift(self) -> None:
        module = load_preprod_module()
        with (
            mock.patch.object(module, "internal_call") as internal,
            self.assertRaisesRegex(SystemExit, "release clean-room test"),
        ):
            module.ensure_preprod_group_policy(
                mock.Mock(),
                {
                    "id": "group-1",
                    "policy": {
                        "tpm_limit": None,
                        "rpm_limit": None,
                        "allowed_models": None,
                        "default_model": None,
                        "model_limits": {},
                    },
                },
                ["claude-sonnet-4-5"],
                created=False,
            )
        internal.assert_not_called()

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
            mock.patch.object(module, "verify_alerting_graph") as alerting_graph,
            mock.patch.object(
                module,
                "internal_call",
                side_effect=[(200, identity), (200, provider)],
            ),
            mock.patch.object(module, "verify_edge_routes") as edge_routes,
            mock.patch.object(module, "write_test_login_summary") as login_summary,
            mock.patch("sys.stdout", new_callable=io.StringIO),
        ):
            module.verify(mock.Mock())
        volume_init.assert_called_once()
        login_summary.assert_called_once()
        alerting_graph.assert_called_once()
        edge_routes.assert_called_once()
        self.assertEqual(
            [call.args[1:] for call in wait.call_args_list],
            [("alpha", "healthy", 120), ("beta", "healthy", 120)],
        )

    def test_edge_route_verifier_is_tls_pinned_bounded_and_fail_closed(self) -> None:
        module = load_preprod_module()
        healthy = subprocess.CompletedProcess([], 0, '"I\'m alive!"', "")
        discovery = subprocess.CompletedProcess(
            [],
            0,
            json.dumps(
                {"issuer": "https://auth.aigw.internal/realms/aigw"},
                separators=(",", ":"),
            ),
            "",
        )
        with (
            mock.patch.object(module, "local_curl", return_value="/usr/bin/curl"),
            mock.patch.object(
                module.subprocess,
                "run",
                side_effect=[healthy, discovery],
            ) as run,
            mock.patch("sys.stdout", new_callable=io.StringIO),
        ):
            module.verify_edge_routes(mock.Mock())
        self.assertEqual(run.call_count, 2)
        commands = [call.args[0] for call in run.call_args_list]
        for command in commands:
            for required in (
                "--disable",
                "--fail-with-body",
                "--http1.1",
                "--limit-rate",
                "--max-filesize",
                "--noproxy",
                "--proto",
                "--cacert",
                "--resolve",
            ):
                self.assertIn(required, command)
            self.assertIn(str(module.PREPROD_ROOT_CA_FILE), command)
            self.assertTrue(command[-1].startswith("https://"))
        self.assertIn(
            "api.aigw.internal:443:127.0.2.1",
            commands[0],
        )
        self.assertIn(
            "auth.aigw.internal:443:127.0.3.1",
            commands[1],
        )

        malformed = subprocess.CompletedProcess([], 0, "not-json", "")
        with (
            mock.patch.object(module, "local_curl", return_value="/usr/bin/curl"),
            mock.patch.object(module.subprocess, "run", return_value=malformed),
        ):
            with self.assertRaisesRegex(SystemExit, "returned invalid JSON"):
                module.edge_json(
                    "api.aigw.internal", "127.0.2.1", "/health/liveliness"
                )
        with self.assertRaisesRegex(SystemExit, "unapproved route"):
            module.edge_json("example.invalid", "127.0.2.1", "/health/liveliness")

        reset = subprocess.CompletedProcess(
            ["/usr/bin/curl"], 35, "", "curl: (35) connection reset\n"
        )
        with (
            mock.patch.object(module, "local_curl", return_value="/usr/bin/curl"),
            mock.patch.object(module.subprocess, "run", return_value=reset),
            mock.patch("sys.stdout", new_callable=io.StringIO) as output,
            mock.patch("sys.stderr", new_callable=io.StringIO),
        ):
            with self.assertRaisesRegex(SystemExit, "curl exit code 35"):
                module.verify_edge_routes(mock.Mock())
        self.assertNotIn("PREPROD_EDGE_ROUTES_VERIFIED", output.getvalue())

        transport_reset = subprocess.CompletedProcess(
            ["/usr/bin/curl"], 56, "", "curl: (56) connection reset\n"
        )
        with (
            mock.patch.object(module, "local_curl", return_value="/usr/bin/curl"),
            mock.patch.object(
                module.subprocess,
                "run",
                side_effect=[healthy, transport_reset, healthy, discovery],
            ) as repaired_run,
            mock.patch.object(module, "compose") as compose,
            mock.patch.object(module, "wait_for_container") as wait,
            mock.patch("sys.stdout", new_callable=io.StringIO) as repaired_output,
        ):
            module.verify_edge_routes(mock.Mock(), repair_transport=True)
        self.assertEqual(repaired_run.call_count, 4)
        compose.assert_called_once_with(
            mock.ANY,
            "up",
            "-d",
            "--no-deps",
            "--force-recreate",
            "preprod-edge-forwarder",
            "preprod-edge-forwarder-adm",
        )
        self.assertEqual(
            [call.args[1:] for call in wait.call_args_list],
            [
                ("preprod-edge-forwarder", "healthy", 120),
                ("preprod-edge-forwarder-adm", "healthy", 120),
            ],
        )
        self.assertIn(
            "PREPROD_EDGE_FORWARDERS_REPAIRED attempt=1",
            repaired_output.getvalue(),
        )
        self.assertIn("PREPROD_EDGE_ROUTES_VERIFIED", repaired_output.getvalue())

        with (
            mock.patch.object(module, "local_curl", return_value="/usr/bin/curl"),
            mock.patch.object(
                module.subprocess,
                "run",
                return_value=transport_reset,
            ) as exhausted_run,
            mock.patch.object(module, "compose") as exhausted_repair,
            mock.patch.object(module, "wait_for_container"),
            mock.patch("sys.stdout", new_callable=io.StringIO),
        ):
            with self.assertRaisesRegex(SystemExit, "after bounded repair"):
                module.verify_edge_routes(mock.Mock(), repair_transport=True)
        self.assertEqual(
            exhausted_run.call_count,
            module.EDGE_FORWARDER_REPAIR_ATTEMPTS + 1,
        )
        self.assertEqual(
            exhausted_repair.call_count,
            module.EDGE_FORWARDER_REPAIR_ATTEMPTS,
        )

        bad_certificate = subprocess.CompletedProcess(
            ["/usr/bin/curl"], 60, "", "certificate verification failed\n"
        )
        with (
            mock.patch.object(module, "local_curl", return_value="/usr/bin/curl"),
            mock.patch.object(
                module.subprocess,
                "run",
                return_value=bad_certificate,
            ),
            mock.patch.object(module, "compose") as forbidden_repair,
            mock.patch("sys.stderr", new_callable=io.StringIO),
        ):
            with self.assertRaisesRegex(
                SystemExit, "edge curl failed with exit code 60"
            ):
                module.verify_edge_routes(mock.Mock(), repair_transport=True)
        forbidden_repair.assert_not_called()

    def test_edge_route_verifier_requires_a_supported_curl(self) -> None:
        module = load_preprod_module()
        with mock.patch.object(module.shutil, "which", return_value=None):
            with self.assertRaisesRegex(SystemExit, "curl 7.76 or newer"):
                module.local_curl()

        old = subprocess.CompletedProcess([], 0, "curl 7.75.0 test\n", "")
        with (
            mock.patch.object(module.shutil, "which", return_value="/usr/bin/curl"),
            mock.patch.object(module, "run", return_value=old),
        ):
            with self.assertRaisesRegex(SystemExit, "curl 7.76 or newer"):
                module.local_curl()

    def test_ansible_runs_full_acceptance_after_internal_verification(self) -> None:
        internal_verify = self.tasks.index(
            "Verify LDAP, OIDC, identity controller, escrow, and WIF state"
        )
        acceptance = self.tasks.index(
            "Run the full local preprod edge and identity acceptance gate"
        )
        cribl_acceptance = self.tasks.index(
            "Prove the full Cribl telemetry mirror and persistent recovery queue"
        )
        report = self.tasks.index("Report the full local preprod acceptance result")
        self.assertLess(internal_verify, acceptance)
        self.assertLess(acceptance, cribl_acceptance)
        self.assertLess(cribl_acceptance, report)
        acceptance_block = self.tasks[acceptance:report]
        self.assertIn("scripts/test-e2e-preprod.py", acceptance_block)
        self.assertIn("scripts/test-preprod-cribl-security.py", acceptance_block)
        self.assertIn("--image-mode", acceptance_block)
        self.assertIn('"{{ preprod_image_mode }}"', acceptance_block)
        self.assertIn("PREPROD_E2E_PASSED", acceptance_block)
        self.assertIn("PREPROD_CRIBL_TELEMETRY_PASSED", acceptance_block)

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
            provider_policy = secrets / "provider_policy_receipt.json"
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
                mock.patch.object(module, "PROVIDER_POLICY_RECEIPT", provider_policy),
                mock.patch.object(module.os, "geteuid", return_value=0),
            ):
                with self.assertRaisesRegex(SystemExit, "recorded non-root operator"):
                    module.activate_seed(None)

            def write_caller_outputs(_args) -> None:
                module.write_file(receipt, "caller activation\n", 0o644)
                module.write_file(overlay, "caller overlay\n", 0o644)
                module.write_file(provider_policy, "caller policy\n", 0o644)

            with (
                mock.patch.object(module, "REPO_ROOT", repo),
                mock.patch.object(module, "ENV_FILE", env_file),
                mock.patch.object(module, "SEED_RECEIPT", receipt),
                mock.patch.object(module, "SEED_OVERLAY", overlay),
                mock.patch.object(module, "PROVIDER_POLICY_RECEIPT", provider_policy),
                mock.patch.object(module, "_activate_seed", side_effect=write_caller_outputs),
                mock.patch.object(module.os, "geteuid", return_value=uid),
                mock.patch.object(module.os, "getegid", return_value=gid),
            ):
                module.activate_seed(None)
                module.remove_seed_output_files()
            self.assertFalse(receipt.exists())
            self.assertFalse(overlay.exists())
            self.assertFalse(provider_policy.exists())
            self.assertEqual(
                module.seed_output_files(),
                (module.SEED_RECEIPT, module.SEED_OVERLAY, module.PROVIDER_POLICY_RECEIPT),
            )

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
            "rand.Reader",
            "now.Before(store.expires)",
            "subtle.ConstantTimeCompare",
            'POST /v1/oauth/token',
            'POST /v1/messages',
            "tls.VersionTLS13",
        ):
            self.assertIn(required, source)
        self.assertNotIn("preprod-only-static-token", source)
        self.assertRegex(dockerfile.splitlines()[0], r"^# syntax=.*@sha256:[0-9a-f]{64}$")
        self.assertIn("RUN --network=none go test ./...", dockerfile)
        self.assertIn("USER 65532:65532", dockerfile)
        self.assertIn(
            "tls_minimum_protocol_version: TLSv1_3", self.script
        )
        self.assertIn(
            "tls_maximum_protocol_version: TLSv1_3", self.script
        )

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
        self.assertIn("preprod-credential-seed-v1", self.script)
        self.assertIn('(\"samba_user_preprod-admin_password\", \"samba-user-admin\")', self.script)
        self.assertNotIn("OnlyForTesting", self.script)
        self.assertNotIn("aigw-preprod-only:", self.script)
        module = load_preprod_module()
        self.assertIn(
            "litellm/aigw_model_limits.py", module.PREPROD_BIND_SOURCES
        )
        self.assertNotIn(
            "secrets/preprod-credential-seed-v1", module.PREPROD_BIND_SOURCES
        )

    def test_private_credential_seed_is_stable_and_local_to_each_checkout(self) -> None:
        module = load_preprod_module()
        args = types.SimpleNamespace(project="aigw-preprod")

        def create_credentials(directory: str) -> tuple[bytes, str, str]:
            secret_dir = Path(directory)
            secret_dir.chmod(0o700)
            seed = secret_dir / "preprod-credential-seed-v1"
            with (
                mock.patch.object(module, "SECRETS_DIR", secret_dir),
                mock.patch.object(module, "PREPROD_CREDENTIAL_SEED", seed),
                mock.patch.object(
                    module, "preprod_docker_state_exists", return_value=False
                ),
            ):
                module.ensure_credential_seed(args)
                first = module.credential_hex("redis")
                second = module.credential_hex("redis")
                password = module.credential_password("samba-user-admin")
            self.assertEqual(stat.S_IMODE(seed.stat().st_mode), 0o600)
            self.assertEqual(first, second)
            return seed.read_bytes(), first, password

        with tempfile.TemporaryDirectory() as first_directory:
            first_seed, first_value, first_password = create_credentials(
                first_directory
            )
        with tempfile.TemporaryDirectory() as second_directory:
            second_seed, second_value, second_password = create_credentials(
                second_directory
            )

        self.assertNotEqual(first_seed, second_seed)
        self.assertNotEqual(first_value, second_value)
        self.assertNotEqual(first_password, second_password)
        self.assertEqual(len(first_seed), module.PREPROD_CREDENTIAL_SEED_BYTES)

        with tempfile.TemporaryDirectory() as directory:
            seed = Path(directory) / "seed"
            seed.write_bytes(first_seed)
            seed.chmod(0o600)
            with mock.patch.object(module, "PREPROD_CREDENTIAL_SEED", seed):
                self.assertNotEqual(
                    module.credential_hex("redis"),
                    module.credential_hex("pg-super"),
                )
                with self.assertRaisesRegex(SystemExit, "length is invalid"):
                    module.credential_hex("redis", 16)

    def test_missing_private_seed_refuses_existing_preprod_state(self) -> None:
        module = load_preprod_module()
        args = types.SimpleNamespace(project="aigw-preprod")
        with tempfile.TemporaryDirectory() as directory:
            secret_dir = Path(directory)
            secret_dir.chmod(0o700)
            seed = secret_dir / "preprod-credential-seed-v1"
            with (
                mock.patch.object(module, "SECRETS_DIR", secret_dir),
                mock.patch.object(module, "PREPROD_CREDENTIAL_SEED", seed),
                mock.patch.object(
                    module, "preprod_docker_state_exists", return_value=True
                ),
            ):
                with self.assertRaisesRegex(
                    SystemExit, "destroy PreProd before rotating credentials"
                ):
                    module.ensure_credential_seed(args)
            self.assertFalse(seed.exists())

    def test_private_seed_boundary_fails_closed(self) -> None:
        module = load_preprod_module()
        with tempfile.TemporaryDirectory() as directory:
            seed = Path(directory) / "seed"
            seed.write_bytes(b"s" * module.PREPROD_CREDENTIAL_SEED_BYTES)
            seed.chmod(0o644)
            with mock.patch.object(module, "PREPROD_CREDENTIAL_SEED", seed):
                with self.assertRaisesRegex(SystemExit, "unsafe boundary"):
                    module.credential_hex("redis")

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            target.write_bytes(b"s" * module.PREPROD_CREDENTIAL_SEED_BYTES)
            target.chmod(0o600)
            seed = Path(directory) / "seed"
            seed.symlink_to(target)
            with mock.patch.object(module, "PREPROD_CREDENTIAL_SEED", seed):
                with self.assertRaisesRegex(SystemExit, "unsafe boundary"):
                    module.credential_hex("redis")

        with tempfile.TemporaryDirectory() as directory:
            seed = Path(directory) / "seed"
            seed.write_bytes(b"s" * module.PREPROD_CREDENTIAL_SEED_BYTES)
            seed.chmod(0o600)
            os.link(seed, Path(directory) / "second-link")
            with mock.patch.object(module, "PREPROD_CREDENTIAL_SEED", seed):
                with self.assertRaisesRegex(SystemExit, "unsafe boundary"):
                    module.credential_hex("redis")

    def test_failed_seed_write_leaves_no_partial_seed_and_can_retry(self) -> None:
        module = load_preprod_module()
        args = types.SimpleNamespace(project="aigw-preprod")
        with tempfile.TemporaryDirectory() as directory:
            secret_dir = Path(directory)
            secret_dir.chmod(0o700)
            seed = secret_dir / "preprod-credential-seed-v1"
            patches = (
                mock.patch.object(module, "SECRETS_DIR", secret_dir),
                mock.patch.object(module, "PREPROD_CREDENTIAL_SEED", seed),
                mock.patch.object(
                    module, "preprod_docker_state_exists", return_value=False
                ),
            )
            with patches[0], patches[1], patches[2]:
                with mock.patch.object(module.os, "write", return_value=0):
                    with self.assertRaisesRegex(SystemExit, "could not create"):
                        module.ensure_credential_seed(args)
                self.assertFalse(seed.exists())
                self.assertEqual(
                    list(secret_dir.glob(".preprod-credential-seed-v1.tmp-*")),
                    [],
                )
                module.ensure_credential_seed(args)
                self.assertEqual(
                    len(seed.read_bytes()), module.PREPROD_CREDENTIAL_SEED_BYTES
                )


class TestLoginSummaryContractTests(unittest.TestCase):
    """The deploy writes one private summary of every local test login."""

    SAMPLE_VALUES = {
        "user_admin": "SAMPLE-USER-ADMIN",
        "user_developer": "SAMPLE-USER-DEVELOPER",
        "user_standard": "SAMPLE-USER-STANDARD",
        "keycloak_admin": "SAMPLE-KEYCLOAK-BREAKGLASS",
        "grafana_admin": "SAMPLE-GRAFANA-BREAKGLASS",
        "litellm_breakglass": "SAMPLE-LITELLM-BREAKGLASS",
        "samba_domain_admin": "SAMPLE-DOMAIN-ADMIN",
        "vault_root_token": "SAMPLE-VAULT-ROOT",
        "vault_unseal_share": "SAMPLE-VAULT-SHARE",
    }

    def test_summary_lists_users_break_glass_and_service_names(self) -> None:
        module = load_preprod_module()
        text = module._test_login_summary_document(dict(self.SAMPLE_VALUES))
        self.assertIn("Local test credentials only.", text)
        self.assertIn("## User-testing logins", text)
        self.assertIn("## Break-glass logins", text)
        self.assertIn("## Service names", text)
        for value in self.SAMPLE_VALUES.values():
            self.assertIn(value, text)
        for name in (
            "chat.aigw.internal",
            "portal.aigw.internal",
            "admin.aigw.internal",
            "api.aigw.internal",
            "auth.aigw.internal",
            "grafana.aigw.internal",
            "prometheus.aigw.internal",
            "litellm-admin.aigw.internal",
            "vault.aigw.internal",
            "samba-ad.aigw.internal:636",
        ):
            self.assertIn(f"`{name}`", text)

    def test_verify_writes_the_private_summary_before_the_marker(self) -> None:
        source = (ROOT / "scripts/preprod.py").read_text(encoding="utf-8")
        self.assertIn(
            'TEST_LOGIN_SUMMARY_FILE = SECRETS_DIR / "preprod-test-logins.md"',
            source,
        )
        verify_body = source.split("def verify(", 1)[1]
        self.assertLess(
            verify_body.index("write_test_login_summary(args)"),
            verify_body.index('print("PREPROD_VERIFIED")'),
        )
        # The summary is written with the same private mode as every other
        # generated credential file, through the shared writer.
        writer_body = source.split("def write_test_login_summary(", 1)[1].split(
            "\ndef ", 1
        )[0]
        self.assertIn("TEST_LOGIN_SUMMARY_FILE", writer_body)
        self.assertIn("0o600", writer_body)


if __name__ == "__main__":
    unittest.main()
