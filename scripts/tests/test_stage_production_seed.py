"""Contracts for the first-install production image seed staging helper.

The helper exists so a first install never asks an operator to run ``shasum``
and transcribe two 64-character hashes into ``host_vars``. These tests pin the
parts that would silently break an install if they drifted: the release-pair
discovery, the accepted file permissions, the optional independent-hash gate,
and the exact five inventory keys it rewrites.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]

PRODUCTION_ARCHIVE = "aigw-2026-07-22-linux-amd64.docker.tar.zst"
PRODUCTION_MANIFEST = "aigw-2026-07-22-linux-amd64.manifest.json"
PREPROD_ARCHIVE = "aigw-2026-07-22-linux-amd64.preprod.docker.tar.zst"
PREPROD_MANIFEST = "aigw-2026-07-22-linux-amd64.preprod.manifest.json"

# The generated host_vars block this helper must be able to fill in. Mirrors
# scripts/bootstrap-rocky9-production.py; a drift here breaks a first install.
GENERATED_HOST_VARS = """\
# SECTION 1 — your site settings
eth1_ip: 192.0.2.20

require_encrypted_state: true
offline_image_seed_enabled: false
offline_image_seed_remote_path: ""
offline_image_seed_sha256: ""
offline_image_seed_manifest_remote_path: ""
offline_image_seed_manifest_sha256: ""

# SECTION 2 — generated encrypted application secrets
identity_ldap_enabled: false
"""


def load_tool():
    path = ROOT / "scripts/stage-production-seed.py"
    spec = importlib.util.spec_from_file_location("aigw_stage_production_seed", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


TOOL = load_tool()


class ReleaseDiscoveryTests(unittest.TestCase):
    def test_release_dir_ignores_the_preprod_pair(self) -> None:
        """A release folder holds both pairs; production must pick its own."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for name in (
                PRODUCTION_ARCHIVE,
                PRODUCTION_MANIFEST,
                PREPROD_ARCHIVE,
                PREPROD_MANIFEST,
            ):
                (root / name).write_bytes(b"release-bytes")

            archive = TOOL.sole_match(root, "*.docker.tar.zst", "production archive")
            manifest = TOOL.sole_match(root, "*.manifest.json", "production manifest")

        self.assertEqual(archive.name, PRODUCTION_ARCHIVE)
        self.assertEqual(manifest.name, PRODUCTION_MANIFEST)

    def test_two_releases_in_one_folder_are_refused_by_name(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / PRODUCTION_ARCHIVE).write_bytes(b"one")
            (root / "aigw-2026-07-23-linux-amd64.docker.tar.zst").write_bytes(b"two")

            with self.assertRaises(TOOL.StagingError) as caught:
                TOOL.sole_match(root, "*.docker.tar.zst", "production archive")

        message = str(caught.exception)
        self.assertIn("found 2", message)
        self.assertIn(PRODUCTION_ARCHIVE, message)

    def test_empty_folder_names_the_repair(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(TOOL.StagingError, "--archive and --manifest"):
                TOOL.sole_match(
                    Path(directory).resolve(), "*.docker.tar.zst", "production archive"
                )


class ReleaseFilePermissionTests(unittest.TestCase):
    """A copied release is 0644. Demanding 0600 left operators stuck."""

    def _archive(self, root: Path, mode: int) -> Path:
        path = root / PRODUCTION_ARCHIVE
        path.write_bytes(b"release-bytes")
        path.chmod(mode)
        return path

    def test_normal_copied_permissions_are_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for mode in (0o600, 0o644, 0o640):
                path = self._archive(root, mode)
                self.assertEqual(
                    TOOL.require_release_file(path, ".docker.tar.zst", "release archive"),
                    path,
                )

    def test_group_or_world_writable_is_refused_with_a_fix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for mode in (0o664, 0o666, 0o622):
                path = self._archive(root, mode)
                with self.assertRaises(TOOL.StagingError) as caught:
                    TOOL.require_release_file(path, ".docker.tar.zst", "release archive")
                self.assertIn("chmod go-w", str(caught.exception))

    def test_symlink_and_empty_files_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            real = self._archive(root, 0o644)
            link = root / f"link-{PRODUCTION_ARCHIVE}"
            os.symlink(real, link)
            with self.assertRaisesRegex(TOOL.StagingError, "not a symlink"):
                TOOL.require_release_file(link, ".docker.tar.zst", "release archive")

            empty = root / f"empty-{PRODUCTION_ARCHIVE}"
            empty.write_bytes(b"")
            with self.assertRaisesRegex(TOOL.StagingError, "empty"):
                TOOL.require_release_file(empty, ".docker.tar.zst", "release archive")


class IndependentHashGateTests(unittest.TestCase):
    """Operators holding a separate release record keep the stronger check."""

    ACTUAL = "a" * 64

    def test_no_expectation_is_allowed(self) -> None:
        self.assertIsNone(TOOL.require_expected(self.ACTUAL, None, "release archive"))

    def test_matching_expectation_passes_case_insensitively(self) -> None:
        self.assertIsNone(
            TOOL.require_expected(self.ACTUAL, "  " + "A" * 64 + " ", "release archive")
        )

    def test_mismatch_refuses_and_never_suggests_proceeding(self) -> None:
        with self.assertRaises(TOOL.StagingError) as caught:
            TOOL.require_expected(self.ACTUAL, "b" * 64, "release archive")
        message = str(caught.exception)
        self.assertIn("Do not stage this file", message)

    def test_a_malformed_expectation_is_refused(self) -> None:
        with self.assertRaisesRegex(TOOL.StagingError, "64 lowercase hex"):
            TOOL.require_expected(self.ACTUAL, "not-a-hash", "release archive")


class InventoryRewriteTests(unittest.TestCase):
    ARCHIVE_SHA = "c" * 64
    MANIFEST_SHA = "d" * 64

    def _values(self) -> dict[str, str]:
        remote = f"/var/lib/ai-gateway/image-seeds/candidate-{self.MANIFEST_SHA[:16]}"
        return TOOL.seed_values(
            f"{remote}/{PRODUCTION_ARCHIVE}",
            self.ARCHIVE_SHA,
            f"{remote}/{PRODUCTION_MANIFEST}",
            self.MANIFEST_SHA,
        )

    def test_all_five_loader_keys_move_together(self) -> None:
        """The loader contract is fail-closed on a partial set."""

        self.assertEqual(tuple(self._values()), TOOL.SEED_KEYS)
        self.assertEqual(len(TOOL.SEED_KEYS), 5)

    def test_generated_host_vars_is_filled_in_without_losing_comments(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory).resolve() / "mygateway.yml"
            target.write_text(GENERATED_HOST_VARS, encoding="utf-8")
            target.chmod(0o600)

            TOOL.write_seed_values(target, self._values())
            result = target.read_text(encoding="utf-8")

        self.assertIn("offline_image_seed_enabled: true", result)
        self.assertIn(f'offline_image_seed_sha256: "{self.ARCHIVE_SHA}"', result)
        self.assertIn(f'offline_image_seed_manifest_sha256: "{self.MANIFEST_SHA}"', result)
        self.assertIn(
            f'offline_image_seed_remote_path: "/var/lib/ai-gateway/image-seeds/'
            f'candidate-{self.MANIFEST_SHA[:16]}/{PRODUCTION_ARCHIVE}"',
            result,
        )
        # Everything the operator wrote or the bootstrap explained is preserved.
        self.assertIn("# SECTION 1 — your site settings", result)
        self.assertIn("# SECTION 2 — generated encrypted application secrets", result)
        self.assertIn("eth1_ip: 192.0.2.20", result)
        self.assertIn("require_encrypted_state: true", result)
        self.assertIn("identity_ldap_enabled: false", result)

    def test_rewrite_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory).resolve() / "mygateway.yml"
            target.write_text(GENERATED_HOST_VARS, encoding="utf-8")

            TOOL.write_seed_values(target, self._values())
            once = target.read_text(encoding="utf-8")
            TOOL.write_seed_values(target, self._values())
            twice = target.read_text(encoding="utf-8")

        self.assertEqual(once, twice)

    def test_file_mode_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory).resolve() / "mygateway.yml"
            target.write_text(GENERATED_HOST_VARS, encoding="utf-8")
            target.chmod(0o600)

            TOOL.write_seed_values(target, self._values())

            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_a_missing_key_refuses_instead_of_half_writing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory).resolve() / "mygateway.yml"
            partial = GENERATED_HOST_VARS.replace(
                'offline_image_seed_manifest_sha256: ""\n', ""
            )
            target.write_text(partial, encoding="utf-8")

            with self.assertRaises(TOOL.StagingError) as caught:
                TOOL.write_seed_values(target, self._values())

            self.assertIn("offline_image_seed_manifest_sha256", str(caught.exception))
            self.assertEqual(target.read_text(encoding="utf-8"), partial)
            self.assertEqual(list(target.parent.iterdir()), [target])


class HostVarsLocationTests(unittest.TestCase):
    def test_default_location_follows_the_generated_layout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            inventory = root / "hosts.yml"
            inventory.write_text("all:\n", encoding="utf-8")
            host_vars = root / "host_vars"
            host_vars.mkdir()
            expected = host_vars / "mygateway.yml"
            expected.write_text(GENERATED_HOST_VARS, encoding="utf-8")

            self.assertEqual(
                TOOL.host_vars_path(inventory, "mygateway", None), expected
            )

    def test_a_missing_file_points_at_the_bootstrap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            inventory = Path(directory).resolve() / "hosts.yml"
            inventory.write_text("all:\n", encoding="utf-8")

            with self.assertRaises(TOOL.StagingError) as caught:
                TOOL.host_vars_path(inventory, "mygateway", None)

            self.assertIn("bootstrap-rocky9-production.py", str(caught.exception))


class StagePlaybookInvocationTests(unittest.TestCase):
    def test_the_reviewed_stage_playbook_is_used_with_every_pinned_value(self) -> None:
        """The helper adds no new transfer path; it drives the reviewed play."""

        manifest_sha = "d" * 64
        remote = f"/var/lib/ai-gateway/image-seeds/candidate-{manifest_sha[:16]}"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            inventory = root / "hosts.yml"
            inventory.write_text("all:\n", encoding="utf-8")
            with mock.patch.object(TOOL.subprocess, "run") as runner:
                runner.return_value = mock.Mock(returncode=0)
                TOOL.run_stage_playbook(
                    inventory=inventory,
                    limit="mygateway",
                    vault_id="mygateway@/secure/vault-password",
                    archive=root / PRODUCTION_ARCHIVE,
                    archive_sha="c" * 64,
                    manifest=root / PRODUCTION_MANIFEST,
                    manifest_sha=manifest_sha,
                    remote_directory=remote,
                    remote_archive=f"{remote}/{PRODUCTION_ARCHIVE}",
                    remote_manifest=f"{remote}/{PRODUCTION_MANIFEST}",
                )

        argv = runner.call_args.args[0]
        self.assertEqual(argv[0], "ansible-playbook")
        self.assertIn(str(ROOT / "ansible/stage-offline-image-seed.yml"), argv)
        self.assertIn("--limit", argv)
        self.assertIn("mygateway", argv)
        self.assertIn("--vault-id", argv)
        for key in (
            "image_seed_stage_controller_archive",
            "image_seed_stage_archive_sha256",
            "image_seed_stage_controller_manifest",
            "image_seed_stage_manifest_sha256",
            "image_seed_stage_remote_directory",
            "image_seed_stage_remote_archive",
            "image_seed_stage_remote_manifest",
        ):
            self.assertTrue(
                any(str(item).startswith(f"{key}=") for item in argv),
                f"{key} was not passed to the stage playbook",
            )
        self.assertFalse(runner.call_args.kwargs.get("shell", False))

    def test_a_failed_transfer_never_touches_the_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            inventory = root / "hosts.yml"
            inventory.write_text("all:\n", encoding="utf-8")
            with mock.patch.object(TOOL.subprocess, "run") as runner:
                runner.return_value = mock.Mock(returncode=2)
                with self.assertRaises(TOOL.StagingError) as caught:
                    TOOL.run_stage_playbook(
                        inventory=inventory,
                        limit="mygateway",
                        vault_id="mygateway@/secure/vault-password",
                        archive=root / PRODUCTION_ARCHIVE,
                        archive_sha="c" * 64,
                        manifest=root / PRODUCTION_MANIFEST,
                        manifest_sha="d" * 64,
                        remote_directory="/var/lib/ai-gateway/image-seeds/candidate-dddddddddddddddd",
                        remote_archive="/var/lib/ai-gateway/image-seeds/candidate-dddddddddddddddd/a.docker.tar.zst",
                        remote_manifest="/var/lib/ai-gateway/image-seeds/candidate-dddddddddddddddd/a.manifest.json",
                    )

        self.assertIn("nothing was written to your inventory", str(caught.exception))


class VaultIdCustodyTests(unittest.TestCase):
    def test_a_private_absolute_password_file_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            password = Path(directory).resolve() / "vault-password"
            password.write_text("test-only\n", encoding="utf-8")
            password.chmod(0o600)

            value = f"mygateway@{password}"
            self.assertEqual(TOOL.normalize_vault_id(value), value)

            password.chmod(0o640)
            with self.assertRaisesRegex(TOOL.StagingError, "mode 0600"):
                TOOL.normalize_vault_id(value)

            with self.assertRaisesRegex(TOOL.StagingError, "ALIAS@"):
                TOOL.normalize_vault_id(str(password))

            with self.assertRaisesRegex(TOOL.StagingError, "absolute"):
                TOOL.normalize_vault_id("mygateway@relative/vault-password")


if __name__ == "__main__":
    unittest.main()
