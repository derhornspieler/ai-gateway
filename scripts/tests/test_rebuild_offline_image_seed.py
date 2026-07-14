from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "rebuild-offline-image-seed.py"
SPEC = importlib.util.spec_from_file_location("rebuild_offline_image_seed", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
builder = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = builder
SPEC.loader.exec_module(builder)


PINNED_DEBIAN = (
    "debian:13-slim@sha256:"
    "28de0877c2189802884ccd20f15ee41c203573bd87bb6b883f5f46362d24c5c2"
)
PINNED_FRONTEND = (
    "docker/dockerfile:1.7@sha256:"
    "a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e"
)


def inspection(image_id: str, digest: str) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout=json.dumps(
            [{"Id": image_id, "RepoDigests": [f"registry.example/team/base@{digest}"]}]
        ),
        stderr="",
    )


class OfflineImageSeedBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.digest = "sha256:" + "a" * 64
        self.image_id = "sha256:" + "b" * 64
        self.reference = f"registry.example/team/base:1.2@{self.digest}"
        self.tag = "registry.example/team/base:1.2"
        self.image = builder.SeedImage(self.reference, self.tag, self.image_id)

    def test_inspection_verifies_pin_but_exports_only_its_tag(self) -> None:
        client = mock.Mock()
        client.run.side_effect = [
            inspection(self.image_id, self.digest),
            inspection(self.image_id, self.digest),
        ]

        images = builder.inspect_images(client, [self.reference])

        self.assertEqual(images, [self.image])
        self.assertEqual(
            client.run.call_args_list,
            [
                mock.call("image", "inspect", "--", self.reference),
                mock.call("image", "inspect", "--", self.tag),
            ],
        )

    def test_inspection_rejects_tag_that_drifted_from_digest_pin(self) -> None:
        client = mock.Mock()
        client.run.side_effect = [
            inspection(self.image_id, self.digest),
            inspection("sha256:" + "c" * 64, self.digest),
        ]

        with self.assertRaisesRegex(builder.SeedBuildError, "does not resolve"):
            builder.inspect_images(client, [self.reference])

    def test_missing_tag_can_only_be_materialized_from_its_verified_pin(self) -> None:
        client = mock.Mock()
        client.run.side_effect = [
            inspection(self.image_id, self.digest),
            subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="missing"),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            inspection(self.image_id, self.digest),
        ]

        images = builder.inspect_images(
            client, [self.reference], materialize_missing_tags=True
        )

        self.assertEqual(images, [self.image])
        self.assertEqual(
            client.run.call_args_list,
            [
                mock.call("image", "inspect", "--", self.reference),
                mock.call("image", "inspect", "--", self.tag),
                mock.call("image", "tag", self.reference, self.tag),
                mock.call("image", "inspect", "--", self.tag),
            ],
        )

    def test_missing_tag_is_not_created_without_explicit_opt_in(self) -> None:
        client = mock.Mock()
        client.run.side_effect = [
            inspection(self.image_id, self.digest),
            subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="missing"),
        ]

        with self.assertRaisesRegex(builder.SeedBuildError, "materialize-missing-source-tags"):
            builder.inspect_images(client, [self.reference])
        self.assertEqual(
            client.run.call_args_list,
            [
                mock.call("image", "inspect", "--", self.reference),
                mock.call("image", "inspect", "--", self.tag),
            ],
        )

    def test_oci_metadata_requires_tag_and_repository_digest_provenance(self) -> None:
        metadata = {
            "manifest.json": [{"RepoTags": [self.tag]}],
            "index.json": {
                "schemaVersion": 2,
                "manifests": [
                    {
                        "digest": self.digest,
                        "annotations": {
                            "io.containerd.image.name": self.tag,
                            "containerd.io/distribution.source.registry.example": "team/base",
                        },
                    }
                ],
            },
        }
        builder._validate_export_metadata(metadata, [self.image])

        metadata["manifest.json"][0]["RepoTags"] = []
        with self.assertRaisesRegex(builder.SeedBuildError, "repository tag"):
            builder._validate_export_metadata(metadata, [self.image])

    def test_oci_metadata_normalizes_docker_hub_references(self) -> None:
        image = builder.SeedImage(
            f"traefik:v3.7.7@{self.digest}",
            "traefik:v3.7.7",
            self.image_id,
        )
        metadata = {
            "manifest.json": [{"RepoTags": [image.save_reference]}],
            "index.json": {
                "schemaVersion": 2,
                "manifests": [
                    {
                        "digest": self.digest,
                        "annotations": {
                            "io.containerd.image.name": "docker.io/library/traefik:v3.7.7",
                            "containerd.io/distribution.source.docker.io": "library/traefik",
                        },
                    }
                ],
            },
        }
        builder._validate_export_metadata(metadata, [image])

    def test_collector_covers_every_current_build_and_runtime_pin(self) -> None:
        project_root = SCRIPT.parents[1]
        references = builder.collect_project_image_references(project_root)

        self.assertEqual(len(references), 25)
        self.assertIn(PINNED_DEBIAN, references)
        self.assertIn(PINNED_FRONTEND, references)
        self.assertIn(
            "dhi.io/golang:1.25.12-alpine-dev@sha256:"
            "4411028e8461d5a111cdbf0aa172db17342557590f7727a4dd4649440bb411c2",
            references,
        )
        self.assertIn(
            "hashicorp/vault:2.0.3@sha256:"
            "a296a888b118615dc01d5f1a6846e6d4a7277946caaed5b447008fff5fe06b54",
            references,
        )
        self.assertIn(
            "ghcr.io/open-webui/open-webui:v0.10.2@sha256:"
            "9fcea9c6e32ab60b0498f3986c6cdf651ddbe61db48d2213a3d28048ddd673d4",
            references,
        )

    def test_only_local_unix_docker_endpoints_are_accepted(self) -> None:
        self.assertEqual(
            builder.validate_local_docker_host("unix:///Users/example/.docker/run/docker.sock"),
            "unix:///Users/example/.docker/run/docker.sock",
        )
        for endpoint in (
            "tcp://127.0.0.1:2375",
            "ssh://gateway.example",
            "unix://localhost/run/docker.sock",
            "unix:///run/docker.sock?remote=1",
        ):
            with self.subTest(endpoint=endpoint):
                with self.assertRaisesRegex(builder.SeedBuildError, "remote TCP and SSH"):
                    builder.validate_local_docker_host(endpoint)

    def test_root_mode_requires_trusted_executables_but_user_mode_does_not(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "docker"
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o755)
            with mock.patch.object(builder, "_trusted_root_path") as trusted:
                self.assertEqual(
                    builder._find_executable(
                        "docker", builder.OutputPolicy(0, 0, True), executable
                    ),
                    str(executable.resolve()),
                )
                trusted.assert_called_once_with(executable.resolve(), executable=True)

            with mock.patch.object(builder, "_trusted_root_path") as trusted:
                self.assertEqual(
                    builder._find_executable(
                        "docker",
                        builder.OutputPolicy(os.geteuid(), os.getegid(), False),
                        executable,
                    ),
                    str(executable.resolve()),
                )
                trusted.assert_not_called()

    def test_unprivileged_output_is_private_and_atomic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "seed.manifest.json"
            policy = builder.OutputPolicy(os.geteuid(), os.getegid(), False)
            builder.replace_private(destination, b"reviewed\n", policy)
            metadata = destination.stat()
            self.assertEqual(destination.read_bytes(), b"reviewed\n")
            self.assertEqual(metadata.st_uid, policy.uid)
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
            self.assertEqual(list(Path(temporary).glob(".*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
