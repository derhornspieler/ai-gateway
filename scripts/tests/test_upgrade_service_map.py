"""Contracts for the unified offline-image update and rollback workflow."""

from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]


def load_tool():
    path = ROOT / "scripts/update-images.py"
    spec = importlib.util.spec_from_file_location("aigw_update_images", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


TOOL = load_tool()


class UpdateImagesContractTest(unittest.TestCase):
    def test_old_single_service_operator_is_retired(self) -> None:
        source = (ROOT / "scripts/upgrade-service.py").read_text()
        self.assertIn("update-images.py", source)
        self.assertNotIn("10.8.10.10", source)
        self.assertNotIn("ansible/inventory/lab.yml", source)
        self.assertNotIn("test-e2e-lab.py", source)
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/upgrade-service.py")],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("scripts/update-images.py", result.stderr)

    def test_prepare_help_documents_required_release_inputs(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/update-images.py"), "prepare", "--help"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("--archive ARCHIVE", result.stdout)
        self.assertIn("--manifest MANIFEST", result.stdout)
        self.assertIn("--platform {linux/amd64,linux/arm64}", result.stdout)
        self.assertIn("--provider NAME", result.stdout)
        self.assertIn("--test-preprod", result.stdout)
        self.assertIn("--ask-become-pass", result.stdout)
        self.assertIn("--become-password-file PATH", result.stdout)

    def test_preprod_become_options_are_mutually_exclusive(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            TOOL.parser().parse_args(
                [
                    "test-preprod",
                    "--archive",
                    "/private/release.docker.tar.zst",
                    "--manifest",
                    "/private/release.manifest.json",
                    "--ask-become-pass",
                    "--become-password-file",
                    "/private/become",
                ]
            )
        self.assertEqual(raised.exception.code, 2)

    def test_become_password_file_is_private_single_link_and_never_opened(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            password = root / "become"
            password.write_text("not-a-real-password\n")
            password.chmod(0o600)

            with mock.patch.object(Path, "open", side_effect=AssertionError("opened")):
                normalized = TOOL.normalize_become_password_file(password)
            self.assertEqual(normalized, password)

            password.chmod(0o640)
            with self.assertRaisesRegex(TOOL.WorkflowError, "mode 0600"):
                TOOL.normalize_become_password_file(password)
            password.chmod(0o600)

            second_link = root / "second-link"
            os.link(password, second_link)
            with self.assertRaisesRegex(TOOL.WorkflowError, "one hard link"):
                TOOL.normalize_become_password_file(password)

    def test_become_password_file_rejects_relative_path_and_symlink(self) -> None:
        with self.assertRaisesRegex(TOOL.WorkflowError, "absolute controller path"):
            TOOL.normalize_become_password_file(Path("become"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            password = root / "become"
            password.write_text("not-a-real-password\n")
            password.chmod(0o600)
            link = root / "become-link"
            link.symlink_to(password)
            with self.assertRaisesRegex(TOOL.WorkflowError, "not a symlink"):
                TOOL.normalize_become_password_file(link)

    def test_ansible_receives_only_the_validated_become_password_path(self) -> None:
        password = Path("/private/operator/become")
        with mock.patch.object(TOOL, "run_checked") as runner:
            TOOL.ansible_command(
                root=ROOT,
                inventory=Path("/inventory.yml"),
                playbook=Path("/playbook.yml"),
                limit=None,
                vault_id=None,
                extra_vars={"safe": True},
                become_password_file=password,
            )
        command = runner.call_args.args[0]
        index = command.index("--become-password-file")
        self.assertEqual(command[index + 1], str(password))
        self.assertNotIn("not-a-real-password", " ".join(command))

    def test_prepare_requires_at_least_one_provider(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            TOOL.parser().parse_args(
                [
                    "prepare",
                    "--archive",
                    "/private/release.docker.tar.zst",
                    "--manifest",
                    "/private/release.manifest.json",
                    "--platform",
                    "linux/amd64",
                ]
            )
        self.assertEqual(raised.exception.code, 2)

    def test_prepare_rejects_become_password_file_without_preprod_test(self) -> None:
        args = TOOL.parser().parse_args(
            [
                "prepare",
                "--archive",
                "/private/release.docker.tar.zst",
                "--manifest",
                "/private/release.manifest.json",
                "--platform",
                "linux/amd64",
                "--provider",
                "anthropic",
                "--become-password-file",
                "/private/become",
            ]
        )
        with self.assertRaisesRegex(TOOL.WorkflowError, "require --test-preprod"):
            TOOL.cmd_prepare(args)

    def test_preprod_sudo_prompt_is_not_limited_to_archive_loading(self) -> None:
        args = TOOL.parser().parse_args(
            [
                "test-preprod",
                "--archive",
                "/private/release.docker.tar.zst",
                "--manifest",
                "/private/release.manifest.json",
                "--ask-become-pass",
            ]
        )
        release = mock.Mock()
        with (
            mock.patch.object(TOOL, "read_release", return_value=release),
            mock.patch.object(TOOL, "test_preprod") as test_preprod,
        ):
            self.assertEqual(TOOL.cmd_test_preprod(args), 0)
        test_preprod.assert_called_once_with(
            release,
            load_archive=False,
            ask_become_pass=True,
            become_password_file=None,
        )

    def test_prepare_passes_sudo_prompt_to_immediate_preprod_test(self) -> None:
        args = TOOL.parser().parse_args(
            [
                "prepare",
                "--archive",
                "/private/release.docker.tar.zst",
                "--manifest",
                "/private/release.manifest.json",
                "--platform",
                "linux/arm64",
                "--provider",
                "anthropic",
                "--test-preprod",
                "--ask-become-pass",
            ]
        )
        release = mock.Mock(
            archive=Path("/private/release.docker.tar.zst"),
            manifest=Path("/private/release.manifest.json"),
            archive_sha256="a" * 64,
            manifest_sha256="b" * 64,
            platform="linux/arm64",
        )
        preprod_release = mock.Mock(
            archive=Path("/private/release.preprod.docker.tar.zst"),
            manifest=Path("/private/release.preprod.manifest.json"),
            archive_sha256="c" * 64,
            manifest_sha256="d" * 64,
            platform="linux/arm64",
        )
        with (
            mock.patch.object(TOOL, "run_checked"),
            mock.patch.object(
                TOOL, "read_release", side_effect=[release, preprod_release]
            ),
            mock.patch.object(TOOL, "validate_release_source_pins"),
            mock.patch.object(TOOL, "test_preprod") as test_preprod,
            mock.patch("sys.stdout", new_callable=io.StringIO),
        ):
            self.assertEqual(TOOL.cmd_prepare(args), 0)
        test_preprod.assert_called_once_with(
            preprod_release,
            load_archive=True,
            ask_become_pass=True,
            become_password_file=None,
        )

    def test_test_preprod_validates_and_passes_become_password_file(self) -> None:
        args = TOOL.parser().parse_args(
            [
                "test-preprod",
                "--archive",
                "/private/release.preprod.docker.tar.zst",
                "--manifest",
                "/private/release.preprod.manifest.json",
                "--load-archive",
                "--become-password-file",
                "/private/become",
            ]
        )
        release = mock.Mock()
        normalized = Path("/private/checked-become")
        with (
            mock.patch.object(TOOL, "read_release", return_value=release),
            mock.patch.object(
                TOOL,
                "normalize_become_password_file",
                return_value=normalized,
            ) as normalize,
            mock.patch.object(TOOL, "test_preprod") as test_preprod,
        ):
            self.assertEqual(TOOL.cmd_test_preprod(args), 0)
        normalize.assert_called_once_with(Path("/private/become"))
        test_preprod.assert_called_once_with(
            release,
            load_archive=True,
            ask_become_pass=False,
            become_password_file=normalized,
        )

    def test_upgrade_help_has_no_target_or_inventory_defaults(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/update-images.py"), "upgrade", "--help"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0)
        for required in (
            "--previous-archive",
            "--previous-manifest",
            "--previous-release-dir",
            "--inventory",
            "--limit",
            "--vault-id",
            "--ssh-target",
            "--ssh-port",
            "--domain",
            "--adm-ip",
            "--internal-ip",
            "--root-ca",
            "--backup-recipient",
            "--rollback-age-identity",
            "--remote-backup-root",
            "--remote-backup-path",
        ):
            self.assertIn(required, result.stdout)
        self.assertNotIn("10.8.10.10", result.stdout)
        self.assertNotIn("inventory/lab", result.stdout)

    def test_prepare_uses_complete_release_and_tag_materialization(self) -> None:
        args = TOOL.parser().parse_args(
            [
                "prepare",
                "--archive",
                "/private/release.docker.tar.zst",
                "--manifest",
                "/private/release.manifest.json",
                "--platform",
                "linux/amd64",
                "--provider",
                "anthropic",
                "--provider",
                "anthropic",
            ]
        )
        release = mock.Mock()
        release.archive = Path("/private/release.docker.tar.zst")
        release.manifest = Path("/private/release.manifest.json")
        release.archive_sha256 = "a" * 64
        release.manifest_sha256 = "b" * 64
        release.platform = "linux/amd64"
        preprod_release = mock.Mock(
            archive=Path("/private/release.preprod.docker.tar.zst"),
            manifest=Path("/private/release.preprod.manifest.json"),
            archive_sha256="c" * 64,
            manifest_sha256="d" * 64,
            platform="linux/amd64",
        )
        with (
            mock.patch.object(TOOL, "run_checked") as runner,
            mock.patch.object(
                TOOL, "read_release", side_effect=[release, preprod_release]
            ),
            mock.patch.object(TOOL, "validate_release_source_pins"),
            mock.patch("sys.stdout", new_callable=io.StringIO),
        ):
            self.assertEqual(TOOL.cmd_prepare(args), 0)
        command = runner.call_args.args[0]
        self.assertIn("--prepare-release", command)
        self.assertIn("--materialize-missing-source-tags", command)
        self.assertIn("--platform", command)
        self.assertIn("--preprod-archive", command)
        self.assertIn("/private/release.preprod.docker.tar.zst", command)
        self.assertIn("--preprod-manifest", command)
        self.assertNotIn("--build-custom=false", command)
        provider_arguments = [
            command[index + 1]
            for index, value in enumerate(command[:-1])
            if value == "--provider"
        ]
        self.assertEqual(provider_arguments, ["anthropic", "anthropic"])

    def test_release_reader_requires_schema_two_and_private_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            archive = root / "release.docker.tar.zst"
            manifest = root / "release.manifest.json"
            archive.write_bytes(b"archive")
            archive.chmod(0o600)
            document = {
                "schema_version": 2,
                "release_scope": "production",
                "platform": "linux/amd64",
                "bundle": archive.name,
                "scope": {
                    "exported_images": 2,
                    "external_images_exported": 1,
                    "custom_ai_gateway_images_exported": 1,
                },
                "verification": {
                    "verified": 2,
                    "missing": 0,
                    "mismatched": 0,
                },
                "images": [
                    {
                        "reference": "registry.example/image:1@sha256:" + "a" * 64,
                        "image_id": "sha256:" + "b" * 64,
                    }
                ],
                "custom_images": [
                    {
                        "image": "ai-gateway/envoy-egress:1",
                        "archive_reference": (
                            "ai-gateway/envoy-egress:aigw-seed-" + "c" * 64
                        ),
                        "image_id": "sha256:" + "c" * 64,
                        "deployment_scope": "production",
                        "target_activation": "active-compose",
                    }
                ],
                "build_inputs": {
                    "schema": 1,
                    "services": {
                        "envoy-egress": {
                            "digest": "d" * 64,
                            "image": "ai-gateway/envoy-egress:1",
                            "image_id": "sha256:" + "c" * 64,
                        }
                    },
                },
                "egress_policy": {
                    "schema_version": 1,
                    "egress_policy_sha256": (
                        "a8a052037365b9d3b80bd06475ee5349"
                        "0d2131561f373fbb4943c9df82e7180d"
                    ),
                    "envoy_config_sha256": "f" * 64,
                    "selected_providers": ["anthropic"],
                    "providers": [
                        {
                            "name": "anthropic",
                            "api_hostname": "api.anthropic.com",
                            "route_prefix": "/anthropic/",
                            "sni": "api.anthropic.com",
                            "exact_sans": ["api.anthropic.com"],
                            "ca_file": "anthropic-ca.pem",
                            "ca_bundle_sha256": "1" * 64,
                            "ca_sha256_fingerprints": ["2" * 64],
                            "provenance_sha256": "3" * 64,
                        }
                    ],
                    "envoy_image_id": "sha256:" + "c" * 64,
                },
            }
            manifest.write_text(json.dumps(document) + "\n")
            manifest.chmod(0o600)
            release = TOOL.read_release(archive, manifest)
            self.assertEqual(release.platform, "linux/amd64")
            document["release_scope"] = "preprod"
            manifest.write_text(json.dumps(document) + "\n")
            with self.assertRaisesRegex(TOOL.WorkflowError, "production-scoped"):
                TOOL.read_release(archive, manifest)
            document["release_scope"] = "production"
            document["schema_version"] = 1
            manifest.write_text(json.dumps(document) + "\n")
            with self.assertRaisesRegex(TOOL.WorkflowError, "schema-v2"):
                TOOL.read_release(archive, manifest)

    def test_release_files_require_a_nonreplaceable_caller_owned_parent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            archive = root / "release.docker.tar.zst"
            archive.write_bytes(b"archive")
            archive.chmod(0o600)
            root.chmod(0o777)
            with self.assertRaisesRegex(TOOL.WorkflowError, "group/other writable"):
                TOOL.require_local_file(
                    archive, ".docker.tar.zst", "release archive"
                )

            root.chmod(0o700)
            real_parent = root / "real"
            real_parent.mkdir()
            linked_parent = root / "linked"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            linked_archive = real_parent / "linked-release.docker.tar.zst"
            linked_archive.write_bytes(b"archive")
            linked_archive.chmod(0o600)
            with self.assertRaisesRegex(TOOL.WorkflowError, "not a symlink"):
                TOOL.require_local_file(
                    linked_parent / linked_archive.name,
                    ".docker.tar.zst",
                    "release archive",
                )

            writable_ancestor = root / "writable-ancestor"
            safe_child = writable_ancestor / "safe-child"
            safe_child.mkdir(parents=True)
            writable_ancestor.chmod(0o777)
            safe_child.chmod(0o700)
            nested_archive = safe_child / "nested-release.docker.tar.zst"
            nested_archive.write_bytes(b"archive")
            nested_archive.chmod(0o600)
            with self.assertRaisesRegex(TOOL.WorkflowError, "group/other writable"):
                TOOL.require_local_file(
                    nested_archive, ".docker.tar.zst", "release archive"
                )

            real_ancestor = root / "real-ancestor"
            real_child = real_ancestor / "safe-child"
            real_child.mkdir(parents=True)
            linked_ancestor = root / "linked-ancestor"
            linked_ancestor.symlink_to(real_ancestor, target_is_directory=True)
            linked_nested_archive = real_child / "deep-release.docker.tar.zst"
            linked_nested_archive.write_bytes(b"archive")
            linked_nested_archive.chmod(0o600)
            linked_path = linked_ancestor / "safe-child" / linked_nested_archive.name
            with self.assertRaisesRegex(TOOL.WorkflowError, "not a symlink"):
                TOOL.require_local_file(
                    linked_path, ".docker.tar.zst", "release archive"
                )

    def test_inventory_and_root_ca_reject_leaf_symlinks_before_resolve(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            inventory = root / "inventory.yml"
            root_ca = root / "root-ca.pem"
            inventory.write_text("all: {}\n", encoding="utf-8")
            root_ca.write_text("test CA\n", encoding="utf-8")
            inventory_link = root / "inventory-link.yml"
            root_ca_link = root / "root-ca-link.pem"
            inventory_link.symlink_to(inventory)
            root_ca_link.symlink_to(root_ca)
            with self.assertRaisesRegex(TOOL.WorkflowError, "not a symlink"):
                TOOL.normalize_inventory(inventory_link)
            with self.assertRaisesRegex(TOOL.WorkflowError, "not a symlink"):
                TOOL.normalize_root_ca(root_ca_link)

    def test_candidate_and_previous_keep_original_bundle_names(self) -> None:
        release = TOOL.Release(
            archive=Path("/private/release.docker.tar.zst"),
            manifest=Path("/private/release.manifest.json"),
            archive_sha256="a" * 64,
            manifest_sha256="b" * 64,
            platform="linux/amd64",
            document={},
        )
        remote = TOOL.remote_paths(release, TOOL.REMOTE_SEED_ROOT, "candidate")
        self.assertTrue(remote.archive.endswith("/release.docker.tar.zst"))
        self.assertTrue(remote.manifest.endswith("/release.manifest.json"))
        self.assertIn("candidate-" + "b" * 16, remote.archive)

    def test_release_provenance_rejects_untracked_runtime_inputs_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for path in (
                root / "ansible/site.yml",
                root / "ansible/deploy-stack-only.yml",
                root / "compose/docker-compose.yml",
                root / "scripts/placeholder.py",
                root / "services/example/Dockerfile",
                root / "ansible.cfg",
            ):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("test\n", encoding="utf-8")
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            subprocess.run(
                [
                    "git", "-C", str(root),
                    "-c", "user.name=AI Gateway Test",
                    "-c", "user.email=test@example.invalid",
                    "commit", "-qm", "test source",
                ],
                check=True,
            )
            (root / "TASKS.md").write_text("local notes\n", encoding="utf-8")
            commit = TOOL.git_release(root, "test source")
            self.assertRegex(commit, r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")

            (root / "services/example/untracked.txt").write_text(
                "affects build context\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(TOOL.WorkflowError, "release-bearing"):
                TOOL.git_release(root, "test source")

    def test_automatic_rollback_restores_state_before_previous_source(self) -> None:
        source = (ROOT / "scripts/update-images.py").read_text()
        restore = source.index('f"{STACK_REMOTE}/scripts/state-restore.sh"')
        previous = source.index("playbook=previous_root / \"ansible/site.yml\"")
        marker = source.index(
            "remove_restore_marker(args.ssh_target, args.ssh_port, backup.sha256)"
        )
        self.assertLess(restore, previous)
        self.assertLess(previous, marker)
        self.assertIn("automatic upgrades refuse PostgreSQL major changes", source)
        self.assertNotIn("skip-backup-check", source)

    def test_unexpected_candidate_exception_still_runs_automatic_rollback(self) -> None:
        args = mock.Mock(
            archive=Path("/candidate.tar.zst"),
            manifest=Path("/candidate.json"),
            previous_archive=Path("/previous.tar.zst"),
            previous_manifest=Path("/previous.json"),
            ssh_target="deployer@gateway.example.internal",
            ssh_port=2222,
            remote_backup_root="/mnt/ai-gateway-backups",
            remote_backup_path="/mnt/ai-gateway-backups/update.age",
            backup_recipient="age1" + "a" * 58,
            limit="gateway01",
        )
        candidate = mock.Mock(platform="linux/amd64", manifest_sha256="a" * 64)
        previous = mock.Mock(platform="linux/amd64", manifest_sha256="b" * 64)
        candidate_remote = mock.Mock()
        previous_remote = mock.Mock()
        backup = TOOL.BackupReceipt(
            path="/mnt/ai-gateway-backups/update.age",
            sha256="c" * 64,
            created_at="2026-07-21T00:00:00Z",
        )
        with (
            mock.patch.object(
                TOOL,
                "validate_upgrade_inputs",
                return_value=(
                    Path("/inventory.yml"),
                    "gateway01@/vault-password",
                    Path("/previous-source"),
                    Path("/rollback.agekey"),
                    "candidate-commit",
                    "previous-commit",
                ),
            ),
            mock.patch.object(TOOL, "read_release", side_effect=[candidate, previous]),
            mock.patch.object(TOOL, "validate_release_source_pins"),
            mock.patch.object(
                TOOL,
                "remote_paths",
                side_effect=[candidate_remote, previous_remote],
            ),
            mock.patch.object(TOOL, "validate_remote_backup_boundary"),
            mock.patch.object(TOOL, "stage_release"),
            mock.patch.object(TOOL, "preload_previous_release"),
            mock.patch.object(TOOL, "manage_remote_recovery_identity") as identity,
            mock.patch.object(TOOL, "take_backup", return_value=backup),
            mock.patch.object(
                TOOL, "deploy_candidate", side_effect=ValueError("parser bug")
            ),
            mock.patch.object(TOOL, "run_external_validation"),
            mock.patch.object(TOOL, "automatic_rollback") as rollback,
        ):
            with self.assertRaisesRegex(
                TOOL.WorkflowError,
                "rolled back: ValueError: parser bug",
            ):
                TOOL.cmd_upgrade(args)
        rollback.assert_called_once()
        self.assertEqual(
            [call.kwargs["state"] for call in identity.call_args_list],
            ["present", "absent"],
        )

    def test_remote_paths_reject_traversal_and_broad_backup_roots(self) -> None:
        for value in ("/", "/var//images/file", "/var/../tmp/file", "/var/./file"):
            with self.assertRaises(TOOL.WorkflowError):
                TOOL.safe_remote_path(value, "test path")
        with self.assertRaisesRegex(TOOL.WorkflowError, "stay below"):
            TOOL.require_strict_descendant(
                "/mnt/other/backup.age", "/mnt/ai-gateway-backups", "backup"
            )
        source = (ROOT / "scripts/update-images.py").read_text()
        self.assertIn("validate_remote_backup_boundary", source)
        self.assertIn("o.parent==r", source)

    def test_direct_ssh_uses_explicit_port_and_noninteractive_sudo(self) -> None:
        with mock.patch.object(TOOL, "run_checked") as runner:
            runner.return_value = subprocess.CompletedProcess([], 0, "", "")
            TOOL.ssh_command(
                "deployer@gateway.example.internal",
                2222,
                ["sudo", "-n", "true"],
                capture=True,
                label="test",
            )
        command = runner.call_args.args[0]
        self.assertIn("-p", command)
        self.assertEqual(command[command.index("-p") + 1], "2222")
        self.assertIn("sudo -n true", command[-1])
        e2e = (ROOT / "scripts/e2e-fresh-vm-check.sh").read_text()
        self.assertIn('--ssh-port)', e2e)
        self.assertIn('-p "$SSH_PORT"', e2e)
        self.assertIn("sudo -n iptables", e2e)

    def test_inventory_topology_must_match_validation_values(self) -> None:
        host = {
            "ansible_user": "deployer",
            "ansible_host": "gateway.example.internal",
            "ansible_port": 2222,
            "aigw_domain": "example.internal",
            "eth1_ip": "192.0.2.20",
            "eth2_ip": "198.51.100.20",
            "aigw_vault_ui_enabled": False,
        }
        completed = subprocess.CompletedProcess([], 0, json.dumps(host), "")
        with mock.patch.object(TOOL, "run_checked", return_value=completed):
            TOOL.require_inventory_ssh_target(
                Path("/inventory.yml"),
                "gateway01",
                "gateway01@/vault-password",
                "deployer@gateway.example.internal",
                2222,
                "example.internal",
                "192.0.2.20",
                "198.51.100.20",
                False,
            )
            with self.assertRaisesRegex(TOOL.WorkflowError, "exactly match inventory"):
                TOOL.require_inventory_ssh_target(
                    Path("/inventory.yml"),
                    "gateway01",
                    "gateway01@/vault-password",
                    "deployer@gateway.example.internal",
                    2222,
                    "wrong.internal",
                    "192.0.2.20",
                    "198.51.100.20",
                    False,
                )

    def test_transferred_preprod_seed_uses_root_stage_and_always_cleanup(self) -> None:
        source = (ROOT / "scripts/update-images.py").read_text()
        self.assertIn('state="present"', source)
        self.assertIn('state="absent"', source)
        playbook = (ROOT / "ansible/stage-preprod-image-seed.yml").read_text()
        self.assertIn("owner: root", playbook)
        self.assertIn('mode: "0600"', playbook)
        self.assertIn("always:", playbook)
        self.assertIn("preprod_seed_stage_removed", playbook)
        inspect_root = playbook.index(
            "Inspect the fixed root staging boundary before cleanup"
        )
        inspect_release = playbook.index(
            "Inspect digest-scoped local preprod staging before cleanup"
        )
        remove_release = playbook.index(
            "Remove only the digest-scoped local preprod staging directory"
        )
        self.assertLess(inspect_root, inspect_release)
        self.assertLess(inspect_release, remove_release)
        cleanup = playbook[inspect_root:remove_release]
        self.assertIn("follow: false", cleanup)
        self.assertIn("stat.uid == 0", cleanup)
        self.assertIn("stat.gid == 0", cleanup)
        self.assertIn("stat.mode == '0700'", cleanup)

        role = (
            ROOT / "ansible/roles/preprod_stack/tasks/present.yml"
        ).read_text()
        activation = role.split(
            "- name: Bind preprod to immutable transfer image references", 1
        )[1].split("- name: Create only namespaced", 1)[0]
        self.assertIn("become: false", activation)
        self.assertIn("preprod_seed_loader_archive", role)
        self.assertIn("preprod_seed_loader_manifest", role)

    def test_remote_stage_rejects_preprod_release_before_ansible_transfer(self) -> None:
        release = mock.Mock(
            document={
                "release_scope": "preprod",
                "custom_images": [
                    {
                        "image": "ai-gateway/samba-ad:preprod",
                        "deployment_scope": "preprod-only",
                        "target_activation": "archive-only",
                    },
                    {
                        "image": "ai-gateway/wif-provider-mock:preprod",
                        "deployment_scope": "preprod-only",
                        "target_activation": "archive-only",
                    },
                ],
                "build_inputs": {
                    "services": {
                        "samba-ad": {"image": "ai-gateway/samba-ad:preprod"},
                        "wif-provider-mock": {
                            "image": "ai-gateway/wif-provider-mock:preprod"
                        },
                    }
                },
            }
        )
        with (
            mock.patch.object(TOOL, "ansible_command") as ansible,
            self.assertRaisesRegex(TOOL.WorkflowError, "production-scoped"),
        ):
            TOOL.stage_release(
                release,
                mock.Mock(),
                inventory=Path("/inventory.yml"),
                limit="gateway01",
                vault_id="gateway01@/vault-password",
            )
        ansible.assert_not_called()

    def test_remote_stage_proves_production_bytes_on_controller_before_copy(self) -> None:
        playbook = (ROOT / "ansible/stage-offline-image-seed.yml").read_text()
        controller_hash = playbook.index(
            "Require private regular controller release files with exact hashes"
        )
        production_gate = playbook.index(
            "Prove production release scope and archive allow-list before transfer"
        )
        transfer = playbook.index(
            "Copy the reviewed archive and manifest to the target"
        )
        self.assertLess(controller_hash, production_gate)
        self.assertLess(production_gate, transfer)
        gate = playbook[production_gate:transfer]
        self.assertIn("validate-production-release", gate)
        self.assertIn("become: false", gate)
        self.assertIn("delegate_to: localhost", gate)
        self.assertIn("VALIDATED_PRODUCTION_RELEASE", gate)

    def test_remote_stage_proves_production_archive_before_ansible_transfer(self) -> None:
        release = mock.Mock(
            document={
                "release_scope": "production",
                "custom_images": [
                    {
                        "image": "ai-gateway/portal:1",
                        "deployment_scope": "production",
                        "target_activation": "active-compose",
                    }
                ],
                "build_inputs": {
                    "services": {
                        "portal": {"image": "ai-gateway/portal:1"},
                    }
                },
            },
            archive=Path("/release/aigw.docker.tar.zst"),
            manifest=Path("/release/aigw.manifest.json"),
            archive_sha256="a" * 64,
            manifest_sha256="b" * 64,
        )
        remote = mock.Mock(archive="/remote/aigw.docker.tar.zst", manifest="/remote/aigw.manifest.json")
        order: list[str] = []
        with (
            mock.patch.object(
                TOOL,
                "validate_release_archive_allowlist",
                side_effect=lambda _release: order.append("allowlist"),
            ),
            mock.patch.object(
                TOOL,
                "ansible_command",
                side_effect=lambda **_kwargs: order.append("transfer"),
            ),
        ):
            TOOL.stage_release(
                release,
                remote,
                inventory=Path("/inventory.yml"),
                limit="gateway01",
                vault_id="gateway01@/vault-password",
            )
        self.assertEqual(order, ["allowlist", "transfer"])

    def test_transferred_seed_loads_as_root_then_activates_original_as_user(self) -> None:
        release = mock.Mock(
            archive=Path("/home/operator/release.docker.tar.zst"),
            manifest=Path("/home/operator/release.manifest.json"),
            archive_sha256="a" * 64,
            manifest_sha256="b" * 64,
        )
        staged_archive = Path(
            "/var/tmp/ai-gateway-preprod-seeds/" + "b" * 16 + "/release.docker.tar.zst"
        )
        staged_manifest = Path(
            "/var/tmp/ai-gateway-preprod-seeds/" + "b" * 16 + "/release.manifest.json"
        )
        stage_calls: list[str] = []

        def stage(
            _release,
            *,
            state: str,
            ask_become_pass: bool,
            become_password_file: Path | None,
        ):
            self.assertTrue(ask_become_pass)
            self.assertIsNone(become_password_file)
            stage_calls.append(state)
            return staged_archive, staged_manifest

        with (
            mock.patch.object(TOOL.sys, "platform", "linux"),
            mock.patch.object(TOOL, "require_release_scope"),
            mock.patch.object(TOOL, "validate_release_source_pins"),
            mock.patch.object(TOOL, "clean_room_preprod_release"),
            mock.patch.object(TOOL, "stage_preprod_release", side_effect=stage),
            mock.patch.object(TOOL, "ansible_command") as ansible,
            mock.patch.object(TOOL, "run_checked"),
            mock.patch("sys.stdout", new_callable=io.StringIO),
        ):
            TOOL.test_preprod(
                release,
                load_archive=True,
                ask_become_pass=True,
                become_password_file=None,
            )

        self.assertEqual(stage_calls, ["present", "absent"])
        values = ansible.call_args.kwargs["extra_vars"]
        self.assertEqual(values["preprod_seed_archive"], str(release.archive))
        self.assertEqual(values["preprod_seed_manifest"], str(release.manifest))
        self.assertEqual(values["preprod_seed_loader_archive"], str(staged_archive))
        self.assertEqual(values["preprod_seed_loader_manifest"], str(staged_manifest))

    def test_docker_desktop_loads_the_original_release_without_a_root_stage(self) -> None:
        release = mock.Mock(
            archive=Path("/private/tmp/release.preprod.docker.tar.zst"),
            manifest=Path("/private/tmp/release.preprod.manifest.json"),
            archive_sha256="a" * 64,
            manifest_sha256="b" * 64,
        )
        with (
            mock.patch.object(TOOL.sys, "platform", "darwin"),
            mock.patch.object(TOOL, "require_release_scope"),
            mock.patch.object(TOOL, "validate_release_source_pins"),
            mock.patch.object(TOOL, "clean_room_preprod_release"),
            mock.patch.object(TOOL, "stage_preprod_release") as stage,
            mock.patch.object(TOOL, "ansible_command") as ansible,
            mock.patch.object(TOOL, "run_checked"),
            mock.patch("sys.stdout", new_callable=io.StringIO),
        ):
            TOOL.test_preprod(
                release,
                load_archive=True,
                ask_become_pass=True,
                become_password_file=None,
            )

        stage.assert_not_called()
        values = ansible.call_args.kwargs["extra_vars"]
        self.assertEqual(values["preprod_seed_loader_archive"], str(release.archive))
        self.assertEqual(values["preprod_seed_loader_manifest"], str(release.manifest))

    def test_release_grade_preprod_cleans_before_staging_then_deploys_once(self) -> None:
        release = mock.Mock(
            archive=Path("/private/release.preprod.docker.tar.zst"),
            manifest=Path("/private/release.preprod.manifest.json"),
            archive_sha256="a" * 64,
            manifest_sha256="b" * 64,
        )
        staged_archive = Path("/var/tmp/staged/release.docker.tar.zst")
        staged_manifest = Path("/var/tmp/staged/release.manifest.json")
        order: list[str] = []

        def stage(_release, *, state: str, **_kwargs):
            order.append(f"stage:{state}")
            return staged_archive, staged_manifest

        def deploy(**kwargs):
            order.append("deploy")
            self.assertEqual(kwargs["playbook"], TOOL.PREPROD_PLAYBOOK)
            self.assertIs(kwargs["extra_vars"]["preprod_seed_require_fresh_load"], True)

        with (
            mock.patch.object(TOOL.sys, "platform", "linux"),
            mock.patch.object(TOOL, "require_release_scope"),
            mock.patch.object(TOOL, "validate_release_source_pins"),
            mock.patch.object(
                TOOL,
                "clean_room_preprod_release",
                side_effect=lambda *_args, **_kwargs: order.append("clean-room"),
            ),
            mock.patch.object(TOOL, "stage_preprod_release", side_effect=stage),
            mock.patch.object(TOOL, "ansible_command", side_effect=deploy),
            mock.patch("sys.stdout", new_callable=io.StringIO),
        ):
            TOOL.test_preprod(
                release,
                load_archive=True,
                ask_become_pass=False,
                become_password_file=Path("/private/become"),
            )

        self.assertEqual(
            order,
            ["clean-room", "stage:present", "deploy", "stage:absent"],
        )

    def test_clean_room_failure_prevents_staging_and_deploy(self) -> None:
        release = mock.Mock()
        with (
            mock.patch.object(TOOL, "require_release_scope"),
            mock.patch.object(TOOL, "validate_release_source_pins"),
            mock.patch.object(
                TOOL,
                "clean_room_preprod_release",
                side_effect=TOOL.WorkflowError("clean-room failed"),
            ),
            mock.patch.object(TOOL, "stage_preprod_release") as stage,
            mock.patch.object(TOOL, "ansible_command") as deploy,
        ):
            with self.assertRaisesRegex(TOOL.WorkflowError, "clean-room failed"):
                TOOL.test_preprod(
                    release,
                    load_archive=True,
                    ask_become_pass=False,
                    become_password_file=None,
                )
        stage.assert_not_called()
        deploy.assert_not_called()

    def test_quick_no_load_preprod_skips_clean_room_and_is_not_release_grade(self) -> None:
        release = mock.Mock(
            archive=Path("/private/release.preprod.docker.tar.zst"),
            manifest=Path("/private/release.preprod.manifest.json"),
            archive_sha256="a" * 64,
            manifest_sha256="b" * 64,
        )
        with (
            mock.patch.object(TOOL, "require_release_scope"),
            mock.patch.object(TOOL, "validate_release_source_pins"),
            mock.patch.object(TOOL, "clean_room_preprod_release") as clean_room,
            mock.patch.object(TOOL, "stage_preprod_release") as stage,
            mock.patch.object(TOOL, "ansible_command") as deploy,
            mock.patch("sys.stdout", new_callable=io.StringIO),
        ):
            TOOL.test_preprod(
                release,
                load_archive=False,
                ask_become_pass=False,
                become_password_file=None,
            )
        clean_room.assert_not_called()
        stage.assert_not_called()
        deploy.assert_called_once()
        self.assertIs(
            deploy.call_args.kwargs["extra_vars"]["preprod_seed_require_fresh_load"],
            False,
        )

    def test_clean_room_playbook_receives_exact_release_and_confirmation(self) -> None:
        release = mock.Mock(
            archive=Path("/private/release.preprod.docker.tar.zst"),
            manifest=Path("/private/release.preprod.manifest.json"),
            archive_sha256="a" * 64,
            manifest_sha256="b" * 64,
        )
        with (
            mock.patch.object(TOOL, "require_release_scope"),
            mock.patch.object(TOOL, "validate_release_archive_allowlist"),
            mock.patch.object(TOOL, "ansible_command") as ansible,
        ):
            TOOL.clean_room_preprod_release(
                release,
                ask_become_pass=False,
                become_password_file=Path("/private/become"),
            )
        values = ansible.call_args.kwargs["extra_vars"]
        self.assertEqual(
            ansible.call_args.kwargs["playbook"],
            TOOL.PREPROD_CLEAN_ROOM_PLAYBOOK,
        )
        self.assertEqual(
            ansible.call_args.kwargs["become_password_file"],
            Path("/private/become"),
        )
        self.assertEqual(values["preprod_seed_archive"], str(release.archive))
        self.assertEqual(values["preprod_seed_archive_sha256"], release.archive_sha256)
        self.assertEqual(values["preprod_seed_manifest"], str(release.manifest))
        self.assertEqual(values["preprod_seed_manifest_sha256"], release.manifest_sha256)
        self.assertEqual(
            values["preprod_clean_room_confirmation"],
            "DESTROY_AIGW_PREPROD_RELEASE_IMAGES",
        )

    def test_preprod_wrapper_uses_the_playbooks_single_acceptance_gate(self) -> None:
        source = (ROOT / "scripts/update-images.py").read_text()
        body = source.split("def test_preprod(", 1)[1].split("def cmd_prepare(", 1)[0]
        self.assertNotIn("test-e2e-preprod.py", body)
        self.assertNotIn("seeded preprod end-to-end test", body)
        self.assertIn("SEEDED_PREPROD_E2E_PASSED", body)

    def test_ask_become_pass_keeps_interactive_stdin(self) -> None:
        with mock.patch("subprocess.run") as runner:
            runner.return_value = subprocess.CompletedProcess([], 0, "", "")
            TOOL.run_checked(["true"], interactive=True, label="interactive test")
        self.assertIsNone(runner.call_args.kwargs["stdin"])

    def test_temporary_age_identity_is_no_log_and_removed_in_always(self) -> None:
        playbook = (ROOT / "ansible/manage-update-recovery-identity.yml").read_text()
        self.assertIn("/run/ai-gateway-image-update/rollback.agekey", playbook)
        self.assertIn("no_log: true", playbook)
        self.assertIn("always:", playbook)
        self.assertIn("update_recovery_identity_removed", playbook)
        inspect = playbook.index("Inspect the volatile recovery directory boundary")
        refuse = playbook.index("Refuse an unsafe existing volatile recovery directory")
        create = playbook.index("Create the root-only volatile recovery directory")
        self.assertLess(inspect, refuse)
        self.assertLess(refuse, create)
        boundary = playbook[inspect:create]
        self.assertIn("follow: false", boundary)
        self.assertIn("stat.uid == 0", boundary)
        self.assertIn("stat.gid == 0", boundary)
        self.assertIn("stat.mode == '0700'", boundary)

        refusal = playbook.index(
            "Refuse to replace a pre-existing temporary recovery identity"
        )
        rescue_remove = playbook.index(
            "Remove only a newly created partial recovery identity"
        )
        rescue = playbook[refusal:rescue_remove + 500]
        self.assertIn("update_recovery_identity_before is defined", rescue)
        self.assertIn(
            "not (update_recovery_identity_before.stat.exists | default(false))",
            rescue,
        )
        self.assertNotIn("Remove any partial temporary recovery identity", playbook)

        cleanup_inspect = playbook.index(
            "Inspect the temporary recovery identity before cleanup"
        )
        cleanup_refuse = playbook.index(
            "Refuse to remove an unexpected recovery identity replacement"
        )
        cleanup_remove = playbook.index(
            "Remove only the fixed temporary recovery identity file"
        )
        self.assertLess(cleanup_inspect, cleanup_refuse)
        self.assertLess(cleanup_refuse, cleanup_remove)
        cleanup_gate = playbook[cleanup_inspect:cleanup_remove]
        for contract in (
            "stat.isreg",
            "stat.islnk",
            "stat.uid == 0",
            "stat.gid == 0",
            "stat.mode == '0600'",
            "stat.nlink",
        ):
            self.assertIn(contract, cleanup_gate)

    def test_stage_playbook_is_hash_and_ownership_gated(self) -> None:
        source = (ROOT / "ansible/stage-offline-image-seed.yml").read_text()
        for contract in (
            "checksum_algorithm: sha256",
            "item.stat.mode == '0600'",
            "item.stat.uid == 0",
            "item.stat.gid == 0",
            "item.stat.checksum == item.item.sha256",
            "follow: false",
        ):
            self.assertIn(contract, source)

    def test_vault_id_requires_private_absolute_password_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            password = root / "vault-password"
            password.write_text("test-only\n")
            password.chmod(0o600)
            value = TOOL.normalize_vault_id(f"gateway@{password}")
            self.assertEqual(value, f"gateway@{password.resolve()}")
            password.chmod(0o644)
            with self.assertRaisesRegex(TOOL.WorkflowError, "group/other"):
                TOOL.normalize_vault_id(f"gateway@{password}")

            unsafe = root / "unsafe"
            private = unsafe / "private"
            private.mkdir(parents=True)
            unsafe.chmod(0o777)
            private.chmod(0o700)
            nested_password = private / "vault-password"
            nested_password.write_text("test-only\n")
            nested_password.chmod(0o600)
            with self.assertRaisesRegex(TOOL.WorkflowError, "group/other writable"):
                TOOL.normalize_vault_id(f"gateway@{nested_password}")

            identity = private / "rollback.agekey"
            identity.write_text("AGE-SECRET-KEY-TEST-ONLY\n")
            identity.chmod(0o600)
            with self.assertRaisesRegex(TOOL.WorkflowError, "group/other writable"):
                TOOL.normalize_age_identity(identity, "age1" + "a" * 58)


if __name__ == "__main__":
    unittest.main()
