from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).parents[1] / "load-offline-image-seed.py"
SPEC = importlib.util.spec_from_file_location("load_offline_image_seed", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
loader = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(loader)


class OfflineImageSeedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.archive = self.root / "seed.docker.tar.zst"
        self.archive.write_bytes(b"reviewed image seed")
        self.archive.chmod(0o600)
        self.archive_digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()

        self.reference = f"registry.example/base:1@sha256:{'a' * 64}"
        self.image_id = f"sha256:{'b' * 64}"
        self.manifest = self.root / "seed.manifest.json"
        self.manifest.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "platform": "linux/arm64",
                    "bundle": self.archive.name,
                    "scope": {
                        "exported_images": 1,
                        "custom_ai_gateway_images_exported": 0,
                    },
                    "verification": {
                        "verified": 1,
                        "missing": 0,
                        "mismatched": 0,
                    },
                    "images": [
                        {
                            "reference": self.reference,
                            "image_id": self.image_id,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        self.manifest.chmod(0o600)
        self.manifest_digest = hashlib.sha256(self.manifest.read_bytes()).hexdigest()
        self.marker_dir = self.root / "markers"

        self.root_ids = mock.patch.multiple(
            loader, ROOT_UID=os.getuid(), ROOT_GID=os.getgid()
        )
        self.root_ids.start()
        self.addCleanup(self.root_ids.stop)

    def run_with_mocks(self, invalid_side_effect: list[list[str]]) -> tuple[str, mock.Mock]:
        with (
            mock.patch.object(loader, "require_executable", side_effect=["docker", "zstd"]),
            mock.patch.object(loader, "require_docker_ready", return_value="linux/arm64"),
            mock.patch.object(
                loader,
                "invalid_required_images",
                side_effect=invalid_side_effect,
            ),
            mock.patch.object(loader, "load_archive") as load_archive,
        ):
            outcome = loader.run(
                self.archive,
                self.archive_digest,
                self.manifest,
                self.manifest_digest,
                self.marker_dir,
            )
        return outcome, load_archive

    def test_first_load_writes_exact_root_only_marker_then_skips(self) -> None:
        outcome, load_archive = self.run_with_mocks([[], []])
        self.assertEqual(outcome, f"LOADED {self.archive_digest}")
        load_archive.assert_called_once()

        marker = loader.marker_path(
            self.marker_dir, self.archive_digest, self.manifest_digest
        )
        self.assertEqual(
            marker.read_text(encoding="ascii"),
            f"{self.archive_digest} {self.manifest_digest}\n",
        )
        self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.marker_dir.stat().st_mode), 0o700)

        outcome, load_archive = self.run_with_mocks([[]])
        self.assertEqual(outcome, f"SKIPPED {self.archive_digest}")
        load_archive.assert_not_called()

    def test_stale_marker_reloads_when_a_required_image_was_pruned(self) -> None:
        self.run_with_mocks([[], []])
        outcome, load_archive = self.run_with_mocks([[self.reference], []])
        self.assertEqual(outcome, f"RELOADED {self.archive_digest}")
        load_archive.assert_called_once()

    def test_failed_postload_validation_leaves_no_marker(self) -> None:
        self.run_with_mocks([[], []])
        marker = loader.marker_path(
            self.marker_dir, self.archive_digest, self.manifest_digest
        )
        with self.assertRaisesRegex(loader.SeedError, "after load"):
            self.run_with_mocks([[self.reference], [self.reference]])
        self.assertFalse(marker.exists())

    def test_archive_digest_and_permissions_fail_closed(self) -> None:
        self.archive.chmod(0o644)
        with self.assertRaisesRegex(loader.SeedError, "mode must be 0600"):
            loader.validate_archive(self.archive, self.archive_digest)
        self.archive.chmod(0o600)
        with self.assertRaisesRegex(loader.SeedError, "SHA-256"):
            loader.validate_archive(self.archive, "0" * 64)

    def test_manifest_digest_schema_platform_and_custom_images_fail_closed(self) -> None:
        with self.assertRaisesRegex(loader.SeedError, "manifest SHA-256"):
            loader.validate_manifest_file(self.manifest, "0" * 64)

        decoded = loader.validate_manifest_file(self.manifest, self.manifest_digest)
        with self.assertRaisesRegex(loader.SeedError, "does not match"):
            loader.validate_manifest_schema(decoded, self.archive, "linux/amd64")
        decoded["platform"] = "linux/arm64"
        decoded["scope"]["custom_ai_gateway_images_exported"] = 1
        with self.assertRaisesRegex(loader.SeedError, "custom ai-gateway"):
            loader.validate_manifest_schema(decoded, self.archive, "linux/arm64")

    def test_symlink_seed_and_tampered_marker_fail_closed(self) -> None:
        link = self.root / "link.docker.tar.zst"
        link.symlink_to(self.archive)
        with self.assertRaisesRegex(loader.SeedError, "not a symlink"):
            loader.validate_archive(link, self.archive_digest)

        loader.validate_marker_dir(self.marker_dir)
        marker = loader.marker_path(
            self.marker_dir, self.archive_digest, self.manifest_digest
        )
        marker.write_text("tampered\n", encoding="ascii")
        marker.chmod(0o600)
        with self.assertRaisesRegex(loader.SeedError, "content does not match"):
            loader.marker_is_valid(
                marker, self.archive_digest, self.manifest_digest
            )

    def test_image_inspection_requires_exact_id_and_repo_digest(self) -> None:
        valid = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps(
                [
                    {
                        "Id": self.image_id,
                        "RepoDigests": [f"registry.example/base@sha256:{'a' * 64}"],
                    }
                ]
            ).encode(),
        )
        with mock.patch.object(loader.subprocess, "run", return_value=valid) as run:
            self.assertEqual(
                loader.invalid_required_images(
                    "docker",
                    [{"reference": self.reference, "image_id": self.image_id}],
                ),
                [],
            )
            run.assert_called_once_with(
                ["docker", "image", "inspect", "--", self.reference],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
            )

        mismatched = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps(
                [{"Id": f"sha256:{'c' * 64}", "RepoDigests": []}]
            ).encode(),
        )
        with mock.patch.object(loader.subprocess, "run", return_value=mismatched):
            self.assertEqual(
                loader.invalid_required_images(
                    "docker",
                    [{"reference": self.reference, "image_id": self.image_id}],
                ),
                [self.reference],
            )

    def test_manifest_rejects_option_like_reference(self) -> None:
        decoded = loader.validate_manifest_file(self.manifest, self.manifest_digest)
        decoded["images"][0]["reference"] = f"--help:1@sha256:{'a' * 64}"
        with self.assertRaisesRegex(loader.SeedError, "unsafe name or tag"):
            loader.validate_manifest_schema(decoded, self.archive, "linux/arm64")


if __name__ == "__main__":
    unittest.main()
