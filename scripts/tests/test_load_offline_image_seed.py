from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).parents[1] / "load-offline-image-seed.py"
STACK_TASKS = SCRIPT.parents[1] / "ansible/roles/docker_stack/tasks/main.yml"
SPEC = importlib.util.spec_from_file_location("load_offline_image_seed", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
loader = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(loader)


def sigstore_artifact_fixture() -> tuple[
    dict[str, object], set[str], dict[str, dict[str, object]], set[str]
]:
    parent_digest = "sha256:" + "1" * 64
    subject_digest = "sha256:" + "2" * 64
    artifact_digest = "sha256:" + "3" * 64
    config_digest = "sha256:" + "4" * 64
    layer_digest = "sha256:" + "5" * 64
    descriptor = {
        "mediaType": loader.OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        "digest": artifact_digest,
        "size": 401,
        "annotations": {"io.containerd.manifest.subject": subject_digest},
    }
    documents = {
        parent_digest: {
            "schemaVersion": 2,
            "manifests": [
                {
                    "mediaType": loader.OCI_IMAGE_MANIFEST_MEDIA_TYPE,
                    "digest": subject_digest,
                    "size": 211,
                    "annotations": {
                        "vnd.docker.reference.type": "attestation-manifest",
                        "vnd.docker.reference.digest": parent_digest,
                    },
                }
            ],
        },
        artifact_digest: {
            "schemaVersion": 2,
            "mediaType": loader.OCI_IMAGE_MANIFEST_MEDIA_TYPE,
            "artifactType": loader.SIGSTORE_BUNDLE_MEDIA_TYPE,
            "subject": {
                "mediaType": loader.OCI_IMAGE_MANIFEST_MEDIA_TYPE,
                "digest": subject_digest,
                "size": 211,
            },
            "config": {
                "mediaType": loader.OCI_EMPTY_MEDIA_TYPE,
                "artifactType": loader.SIGSTORE_BUNDLE_MEDIA_TYPE,
                "digest": config_digest,
                "size": 2,
            },
            "layers": [
                {
                    "mediaType": loader.SIGSTORE_BUNDLE_MEDIA_TYPE,
                    "digest": layer_digest,
                    "size": 307,
                }
            ],
        },
    }
    verified_blobs = {
        parent_digest,
        artifact_digest,
        config_digest,
        layer_digest,
    }
    return descriptor, {parent_digest}, documents, verified_blobs


class OfflineImageSeedTests(unittest.TestCase):
    def setUp(self) -> None:
        # Keep the simulated root tree below a path with no macOS /var
        # compatibility symlink. The production loader rejects every symlink
        # ancestor before root reads or executes anything below it.
        self.temporary = tempfile.TemporaryDirectory(dir=SCRIPT.parents[1])
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
        self.project = self.root / "project"
        (self.project / "services" / "example").mkdir(parents=True)
        (self.project / "docker-compose.yml").write_text(
            f"services:\n  example:\n    image: {self.reference}\n",
            encoding="utf-8",
        )
        (self.project / "services" / "example" / "Dockerfile").write_text(
            "FROM scratch\n",
            encoding="utf-8",
        )

        self.root_ids = mock.patch.multiple(
            loader, ROOT_UID=os.getuid(), ROOT_GID=os.getgid()
        )
        self.root_ids.start()
        self.addCleanup(self.root_ids.stop)

    def schema_v2_manifest(self) -> dict[str, object]:
        production_id = "sha256:" + "c" * 64
        samba_id = "sha256:" + "e" * 64
        wif_id = "sha256:" + "d" * 64
        envoy_id = "sha256:" + "f" * 64
        manifest = {
            "schema_version": 2,
            "release_scope": "preprod",
            "platform": "linux/arm64",
            "bundle": self.archive.name,
            "scope": {
                "exported_images": 5,
                "external_images_exported": 1,
                "custom_ai_gateway_images_exported": 4,
            },
            "verification": {"verified": 5, "missing": 0, "mismatched": 0},
            "images": [{"reference": self.reference, "image_id": self.image_id}],
            "custom_images": [
                {
                    "image": "ai-gateway/portal:1",
                    "archive_reference": (
                        "ai-gateway/portal:aigw-seed-" + production_id[7:]
                    ),
                    "image_id": production_id,
                    "deployment_scope": "production",
                    "target_activation": "active-compose",
                },
                {
                    "image": "ai-gateway/samba-ad:preprod",
                    "archive_reference": (
                        "ai-gateway/samba-ad:aigw-seed-" + samba_id[7:]
                    ),
                    "image_id": samba_id,
                    "deployment_scope": "preprod-only",
                    "target_activation": "archive-only",
                },
                {
                    "image": "ai-gateway/wif-provider-mock:preprod",
                    "archive_reference": (
                        "ai-gateway/wif-provider-mock:aigw-seed-" + wif_id[7:]
                    ),
                    "image_id": wif_id,
                    "deployment_scope": "preprod-only",
                    "target_activation": "archive-only",
                },
                {
                    "image": "ai-gateway/envoy-egress:1",
                    "archive_reference": (
                        "ai-gateway/envoy-egress:aigw-seed-" + envoy_id[7:]
                    ),
                    "image_id": envoy_id,
                    "deployment_scope": "production",
                    "target_activation": "active-compose",
                },
            ],
            "build_inputs": {
                "schema": 1,
                "services": {
                    "portal": {
                        "digest": "1" * 64,
                        "image": "ai-gateway/portal:1",
                        "image_id": production_id,
                    },
                    "samba-ad": {
                        "digest": "3" * 64,
                        "image": "ai-gateway/samba-ad:preprod",
                        "image_id": samba_id,
                    },
                    "wif-provider-mock": {
                        "digest": "2" * 64,
                        "image": "ai-gateway/wif-provider-mock:preprod",
                        "image_id": wif_id,
                    },
                    "envoy-egress": {
                        "digest": "4" * 64,
                        "image": "ai-gateway/envoy-egress:1",
                        "image_id": envoy_id,
                    },
                },
            },
            "egress_policy": {
                "schema_version": 1,
                "egress_policy_sha256": "0" * 64,
                "envoy_config_sha256": "6" * 64,
                "selected_providers": ["anthropic", "synthetic"],
                "providers": [
                    {
                        "name": "anthropic",
                        "api_hostname": "api.anthropic.com",
                        "route_prefix": "/anthropic/",
                        "sni": "api.anthropic.com",
                        "exact_sans": ["api.anthropic.com"],
                        "ca_file": "anthropic-ca.pem",
                        "ca_bundle_sha256": "7" * 64,
                        "ca_sha256_fingerprints": ["8" * 64, "9" * 64],
                        "provenance_sha256": "a" * 64,
                    },
                    {
                        "name": "synthetic",
                        "api_hostname": "api.synthetic.invalid",
                        "route_prefix": "/synthetic/",
                        "sni": "api.synthetic.invalid",
                        "exact_sans": ["api.synthetic.invalid"],
                        "ca_file": "synthetic-ca.pem",
                        "ca_bundle_sha256": "7" * 64,
                        "ca_sha256_fingerprints": ["8" * 64, "9" * 64],
                        "provenance_sha256": "b" * 64,
                    },
                ],
                "envoy_image_id": envoy_id,
            },
        }
        policy = manifest["egress_policy"]
        runtime_policy = {
            "schema_version": policy["schema_version"],
            "selected_providers": policy["selected_providers"],
            "providers": policy["providers"],
            "envoy_config_sha256": policy["envoy_config_sha256"],
        }
        policy["egress_policy_sha256"] = hashlib.sha256(
            (
                json.dumps(runtime_policy, separators=(",", ":")) + "\n"
            ).encode("utf-8")
        ).hexdigest()
        return manifest

    def schema_v2_production_manifest(self) -> dict[str, object]:
        manifest = self.schema_v2_manifest()
        manifest["release_scope"] = "production"
        manifest["custom_images"] = [
            manifest["custom_images"][0],
            manifest["custom_images"][3],
        ]
        manifest["build_inputs"] = {
            "schema": 1,
            "services": {
                "portal": manifest["build_inputs"]["services"]["portal"],
                "envoy-egress": manifest["build_inputs"]["services"]["envoy-egress"],
            },
        }
        manifest["scope"] = {
            "exported_images": 3,
            "external_images_exported": 1,
            "custom_ai_gateway_images_exported": 2,
        }
        manifest["verification"] = {
            "verified": 3,
            "missing": 0,
            "mismatched": 0,
        }
        return manifest

    def write_release_manifest(self, manifest: dict[str, object]) -> None:
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")
        self.manifest.chmod(0o600)
        self.manifest_digest = hashlib.sha256(self.manifest.read_bytes()).hexdigest()

    @staticmethod
    def add_verified_archive_metadata(metadata: dict[str, object]) -> None:
        """Mark every mocked descriptor/config as content-hash verified."""

        verified: set[str] = set()
        for entry in metadata.get("manifest.json", []):
            config = entry.get("Config") if isinstance(entry, dict) else None
            if isinstance(config, str):
                digest = config.removesuffix(".json").removeprefix("blobs/sha256/")
                if len(digest) == 64:
                    verified.add(f"sha256:{digest}")
        index = metadata.get("index.json", {})
        descriptors = index.get("manifests", []) if isinstance(index, dict) else []
        for descriptor in descriptors:
            digest = descriptor.get("digest") if isinstance(descriptor, dict) else None
            if isinstance(digest, str):
                verified.add(digest)
        metadata["_verified_small_blobs"] = verified

    def purge_plan_builder(
        self,
        manifest: dict[str, object],
        *,
        platform: str = "linux/arm64",
        source_references: set[str] | None = None,
        planned_build_inputs: object | None = None,
    ) -> tuple[mock.Mock, mock.Mock, mock.Mock]:
        client = mock.Mock()
        planner = mock.Mock()
        planner.PlanError = RuntimeError
        planner.plan_compose_builds.return_value = {
            "manifest": (
                manifest.get("build_inputs")
                if planned_build_inputs is None
                else planned_build_inputs
            ),
            "services": [],
        }
        builder = mock.Mock()
        builder.SeedBuildError = RuntimeError
        builder.OutputPolicy.side_effect = lambda uid, gid, root: (uid, gid, root)
        builder.resolve_docker_client.return_value = client
        builder.platform.return_value = platform
        if source_references is None:
            source_references = {
                image["reference"]
                for image in manifest.get("images", [])
                if isinstance(image, dict) and isinstance(image.get("reference"), str)
            }
        builder.collect_project_image_reference_scopes.return_value = {
            "production": set(source_references),
            "preprod": set(source_references),
        }
        builder.egress_plan_from_release_receipt.return_value = mock.sentinel.egress
        builder.render_deployable_compose_model.return_value = (
            {"services": {}},
            client,
            [],
        )
        builder._load_build_planner.return_value = planner
        builder._find_executable.return_value = "zstd"
        builder.COMPOSE_PROJECT_NAME = "ai-gateway"
        return builder, client, planner

    def run_with_mocks(
        self, invalid_side_effect: list[list[str]]
    ) -> tuple[str, mock.Mock, mock.Mock]:
        with (
            mock.patch.object(loader, "require_executable", side_effect=["docker", "zstd"]),
            mock.patch.object(loader, "require_docker_ready", return_value="linux/arm64"),
            mock.patch.object(
                loader,
                "invalid_required_images",
                side_effect=invalid_side_effect,
            ),
            mock.patch.object(loader, "load_archive") as load_archive,
            mock.patch.object(
                loader, "validate_archive_image_allowlist"
            ) as validate_allowlist,
        ):
            outcome = loader.run(
                self.archive,
                self.archive_digest,
                self.manifest,
                self.manifest_digest,
                self.marker_dir,
            )
        return outcome, load_archive, validate_allowlist

    def test_external_sigstore_artifact_accepts_exact_verified_shape(self) -> None:
        descriptor, parents, documents, verified_blobs = sigstore_artifact_fixture()

        self.assertTrue(
            loader._approved_external_sigstore_artifact(
                descriptor, parents, documents, verified_blobs
            )
        )

    def test_external_sigstore_artifact_rejects_unapproved_parent_or_subject(self) -> None:
        descriptor, _, documents, verified_blobs = sigstore_artifact_fixture()
        unapproved_parent = {"sha256:" + "9" * 64}
        self.assertFalse(
            loader._approved_external_sigstore_artifact(
                descriptor, unapproved_parent, documents, verified_blobs
            )
        )

        descriptor, parents, documents, verified_blobs = sigstore_artifact_fixture()
        descriptor["annotations"] = {
            "io.containerd.manifest.subject": "sha256:" + "8" * 64
        }
        self.assertFalse(
            loader._approved_external_sigstore_artifact(
                descriptor, parents, documents, verified_blobs
            )
        )

    def test_external_sigstore_artifact_rejects_bad_media_type_or_unverified_blob(self) -> None:
        descriptor, parents, documents, verified_blobs = sigstore_artifact_fixture()
        artifact = documents[descriptor["digest"]]
        artifact["layers"][0]["mediaType"] = "application/octet-stream"
        self.assertFalse(
            loader._approved_external_sigstore_artifact(
                descriptor, parents, documents, verified_blobs
            )
        )

        descriptor, parents, documents, verified_blobs = sigstore_artifact_fixture()
        config_digest = documents[descriptor["digest"]]["config"]["digest"]
        verified_blobs.remove(config_digest)
        self.assertFalse(
            loader._approved_external_sigstore_artifact(
                descriptor, parents, documents, verified_blobs
            )
        )

    def test_local_preprod_loader_selects_the_exact_nonroot_unix_socket(self) -> None:
        socket_path = self.root / "docker.sock"
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(server.close)
        server.bind(str(socket_path))
        original_environment = dict(loader.FIXED_DOCKER_ENV)
        with mock.patch.multiple(
            loader,
            ROOT_UID=0,
            ROOT_GID=0,
            FIXED_PATH="/root-only",
            LOCAL_DOCKER_HOST="unix:///run/docker.sock",
            FIXED_DOCKER_ENV=original_environment,
        ):
            loader.configure_local_controller_docker(f"unix://{socket_path}")
            self.assertEqual(loader.ROOT_UID, os.geteuid())
            self.assertEqual(loader.ROOT_GID, os.getegid())
            self.assertEqual(loader.FIXED_PATH, loader.LOCAL_CONTROLLER_PATH)
            self.assertEqual(loader.LOCAL_DOCKER_HOST, f"unix://{socket_path}")
            self.assertEqual(
                loader.FIXED_DOCKER_ENV["PATH"], loader.LOCAL_CONTROLLER_PATH
            )

        link = self.root / "docker-link.sock"
        link.symlink_to(socket_path)
        with mock.patch.multiple(loader, ROOT_UID=0, ROOT_GID=0):
            with self.assertRaisesRegex(loader.SeedError, "real Unix socket"):
                loader.configure_local_controller_docker(f"unix://{link}")

    def test_local_preprod_load_cli_requires_preprod_scope(self) -> None:
        uid = os.geteuid()
        expected = "LOADED " + self.archive_digest
        with (
            mock.patch.object(loader, "ROOT_UID", 0),
            mock.patch.object(loader.os, "geteuid", return_value=uid),
            mock.patch.object(loader, "configure_local_controller_docker") as configure,
            mock.patch.object(loader, "run", return_value=expected) as load,
            mock.patch("builtins.print") as output,
        ):
            returncode = loader.main(
                [
                    str(SCRIPT),
                    "local-preprod-load",
                    str(self.archive),
                    self.archive_digest,
                    str(self.manifest),
                    self.manifest_digest,
                    str(self.marker_dir),
                    "unix:///private/docker.sock",
                ]
            )

        self.assertEqual(returncode, 0)
        configure.assert_called_once_with("unix:///private/docker.sock")
        load.assert_called_once_with(
            self.archive,
            self.archive_digest,
            self.manifest,
            self.manifest_digest,
            self.marker_dir,
            required_release_scope=loader.RELEASE_SCOPE_PREPROD,
        )
        output.assert_called_once_with(expected)

    def test_local_preprod_purge_plan_cli_uses_exact_release_and_socket(self) -> None:
        outcome = {
            "groups": [],
            "manifest_sha256": self.manifest_digest,
            "record_count": 0,
            "schema_version": 1,
            "unique_image_id_count": 0,
        }
        with (
            mock.patch.object(loader, "ROOT_UID", 0),
            mock.patch.object(loader.os, "geteuid", return_value=501),
            mock.patch.object(loader, "configure_local_controller_docker") as configure,
            mock.patch.object(
                loader, "local_preprod_purge_plan", return_value=outcome
            ) as plan,
            mock.patch("builtins.print") as output,
        ):
            returncode = loader.main(
                [
                    str(SCRIPT),
                    "local-preprod-purge-plan",
                    str(self.archive),
                    self.archive_digest,
                    str(self.manifest),
                    self.manifest_digest,
                    str(self.project),
                    "unix:///private/docker.sock",
                ]
            )

        self.assertEqual(returncode, 0)
        configure.assert_called_once_with("unix:///private/docker.sock")
        plan.assert_called_once_with(
            self.archive,
            self.archive_digest,
            self.manifest,
            self.manifest_digest,
            self.project,
        )
        output.assert_called_once_with(
            json.dumps(outcome, sort_keys=True, separators=(",", ":"))
        )

    def test_local_preprod_purge_plan_groups_only_canonical_reviewed_aliases(self) -> None:
        manifest = self.schema_v2_manifest()
        self.write_release_manifest(manifest)
        # A copied release keeps the normal umask; the whole plan must accept
        # caller-owned, non-writable 0644 files end to end.
        self.archive.chmod(0o644)
        self.manifest.chmod(0o644)
        builder, client, _ = self.purge_plan_builder(manifest)

        with (
            mock.patch.object(loader, "_load_local_builder", return_value=builder),
            mock.patch.object(loader, "validate_archive_document_allowlist") as allowlist,
            mock.patch.object(loader, "_inspect_local_release_image") as inspect,
            mock.patch.object(loader, "load_archive") as load_archive,
        ):
            plan = loader.local_preprod_purge_plan(
                self.archive,
                self.archive_digest,
                self.manifest,
                self.manifest_digest,
                self.project,
            )

        self.assertEqual(plan["manifest_sha256"], self.manifest_digest)
        self.assertEqual(plan["record_count"], 5)
        self.assertEqual(plan["unique_image_id_count"], 5)
        self.assertEqual(
            [group["image_id"] for group in plan["groups"]],
            sorted(group["image_id"] for group in plan["groups"]),
        )
        external_group = next(
            group for group in plan["groups"] if group["image_id"] == self.image_id
        )
        self.assertEqual(
            external_group["aliases"],
            [
                {"kind": "external-reference", "value": self.reference},
                {
                    "kind": "external-repository-digest",
                    "value": "registry.example/base@sha256:" + "a" * 64,
                },
                {
                    "kind": "external-tag",
                    "value": "registry.example/base:1",
                },
            ],
        )
        inspect.assert_not_called()
        load_archive.assert_not_called()
        client.run.assert_not_called()
        allowlist.assert_called_once()

    def test_local_preprod_purge_plan_rejects_schema_scope_and_platform_skew(self) -> None:
        cases = []
        schema_one = json.loads(self.manifest.read_text(encoding="utf-8"))
        cases.append(("schema", schema_one, "linux/arm64", "schema-v2"))
        production = self.schema_v2_production_manifest()
        cases.append(("scope", production, "linux/arm64", "preprod-scoped"))
        preprod = self.schema_v2_manifest()
        cases.append(("platform", preprod, "linux/amd64", "does not match"))

        for name, manifest, platform, error in cases:
            with self.subTest(name=name):
                self.write_release_manifest(manifest)
                builder, _, _ = self.purge_plan_builder(
                    manifest, platform=platform
                )
                with (
                    mock.patch.object(
                        loader, "_load_local_builder", return_value=builder
                    ),
                    mock.patch.object(loader, "validate_archive") as archive_check,
                    mock.patch.object(loader, "validate_archive_document_allowlist"),
                    self.assertRaisesRegex(loader.SeedError, error),
                ):
                    loader.local_preprod_purge_plan(
                        self.archive,
                        self.archive_digest,
                        self.manifest,
                        self.manifest_digest,
                        self.project,
                    )
                if name in {"schema", "scope"}:
                    archive_check.assert_not_called()
                else:
                    archive_check.assert_called_once()

    def test_local_preprod_purge_plan_checks_digests_owner_and_mode(self) -> None:
        manifest = self.schema_v2_manifest()
        self.write_release_manifest(manifest)

        with self.assertRaisesRegex(loader.SeedError, "image seed SHA-256"):
            loader.local_preprod_purge_plan(
                self.archive,
                "0" * 64,
                self.manifest,
                self.manifest_digest,
                self.project,
            )
        with self.assertRaisesRegex(loader.SeedError, "manifest SHA-256"):
            loader.local_preprod_purge_plan(
                self.archive,
                self.archive_digest,
                self.manifest,
                "0" * 64,
                self.project,
            )

        self.archive.chmod(0o664)
        with self.assertRaisesRegex(
            loader.SeedError, "must not be group- or world-writable"
        ):
            loader.local_preprod_purge_plan(
                self.archive,
                self.archive_digest,
                self.manifest,
                self.manifest_digest,
                self.project,
            )
        self.archive.chmod(0o600)

        with (
            mock.patch.object(loader.os, "geteuid", return_value=os.geteuid() + 1),
            self.assertRaisesRegex(loader.SeedError, "owned by the invoking user"),
        ):
            loader.local_preprod_purge_plan(
                self.archive,
                self.archive_digest,
                self.manifest,
                self.manifest_digest,
                self.project,
            )

    def test_local_release_files_accept_safe_copied_permissions(self) -> None:
        # A file copied by the operator keeps the normal umask (0644) and may
        # keep a foreign group. Both are safe: integrity comes from the digest
        # checks, and only writability by other users must stay closed.
        self.archive.chmod(0o644)
        loader._validate_local_release_file(
            self.archive, "release archive", ".docker.tar.zst"
        )
        with mock.patch.object(
            loader.os, "getegid", return_value=os.getegid() + 1
        ):
            loader._validate_local_release_file(
                self.archive, "release archive", ".docker.tar.zst"
            )
        for unsafe_mode in (0o622, 0o646, 0o664, 0o666):
            self.archive.chmod(unsafe_mode)
            with self.assertRaisesRegex(
                loader.SeedError, "must not be group- or world-writable"
            ):
                loader._validate_local_release_file(
                    self.archive, "release archive", ".docker.tar.zst"
                )
        self.archive.chmod(0o600)

    def test_local_preprod_purge_plan_checks_source_build_and_oci_contracts(self) -> None:
        manifest = self.schema_v2_manifest()
        self.write_release_manifest(manifest)

        builder, _, _ = self.purge_plan_builder(
            manifest, source_references=set()
        )
        with (
            mock.patch.object(loader, "_load_local_builder", return_value=builder),
            self.assertRaisesRegex(loader.SeedError, "current source pins"),
        ):
            loader.local_preprod_purge_plan(
                self.archive,
                self.archive_digest,
                self.manifest,
                self.manifest_digest,
                self.project,
            )

        builder, _, _ = self.purge_plan_builder(
            manifest, planned_build_inputs={"schema": 1, "services": {}}
        )
        with (
            mock.patch.object(loader, "_load_local_builder", return_value=builder),
            self.assertRaisesRegex(loader.SeedError, "build inputs"),
        ):
            loader.local_preprod_purge_plan(
                self.archive,
                self.archive_digest,
                self.manifest,
                self.manifest_digest,
                self.project,
            )

        builder, _, _ = self.purge_plan_builder(manifest)
        with (
            mock.patch.object(loader, "_load_local_builder", return_value=builder),
            mock.patch.object(
                loader,
                "validate_archive_document_allowlist",
                side_effect=loader.SeedError("unapproved OCI descriptor"),
            ),
            self.assertRaisesRegex(loader.SeedError, "unapproved OCI descriptor"),
        ):
            loader.local_preprod_purge_plan(
                self.archive,
                self.archive_digest,
                self.manifest,
                self.manifest_digest,
                self.project,
            )

    def test_local_preprod_purge_plan_rejects_malformed_or_unreviewed_alias_data(self) -> None:
        cases = []
        bad_id = self.schema_v2_manifest()
        bad_id["images"][0]["image_id"] = "sha256:not-an-id"
        cases.append(("image ID", bad_id, "invalid image ID"))
        bad_reference = self.schema_v2_manifest()
        bad_reference["images"][0]["reference"] = "https://registry.example/base:1"
        cases.append(("reference", bad_reference, "not digest-pinned"))
        arbitrary_alias = self.schema_v2_manifest()
        arbitrary_alias["images"][0]["alias"] = "attacker.example/image:latest"
        cases.append(("alias", arbitrary_alias, "exact object"))
        unexpected = self.schema_v2_manifest()
        unexpected["unreviewed"] = True
        cases.append(("root field", unexpected, "unexpected or missing fields"))

        for name, manifest, error in cases:
            with self.subTest(name=name):
                self.write_release_manifest(manifest)
                builder, _, _ = self.purge_plan_builder(manifest)
                with (
                    mock.patch.object(
                        loader, "_load_local_builder", return_value=builder
                    ),
                    mock.patch.object(loader, "validate_archive_document_allowlist"),
                    self.assertRaisesRegex(loader.SeedError, error),
                ):
                    loader.local_preprod_purge_plan(
                        self.archive,
                        self.archive_digest,
                        self.manifest,
                        self.manifest_digest,
                        self.project,
                    )

    def test_local_preprod_purge_plan_rejects_one_alias_owned_by_two_ids(self) -> None:
        manifest = self.schema_v2_manifest()
        portal = manifest["custom_images"][0]
        samba = manifest["custom_images"][1]
        portal["image"] = samba["archive_reference"]
        portal["archive_reference"] = (
            "ai-gateway/samba-ad:aigw-seed-" + portal["image_id"][7:]
        )
        manifest["build_inputs"]["services"]["portal"]["image"] = portal["image"]
        self.write_release_manifest(manifest)
        builder, _, _ = self.purge_plan_builder(manifest)

        with (
            mock.patch.object(loader, "_load_local_builder", return_value=builder),
            mock.patch.object(loader, "validate_archive_document_allowlist"),
            self.assertRaisesRegex(loader.SeedError, "alias to multiple IDs"),
        ):
            loader.local_preprod_purge_plan(
                self.archive,
                self.archive_digest,
                self.manifest,
                self.manifest_digest,
                self.project,
            )

    def test_purge_plan_rejects_docker_equivalent_alias_collisions(self) -> None:
        first_id = "sha256:" + "1" * 64
        second_id = "sha256:" + "2" * 64
        digest = "sha256:" + "3" * 64
        self.assertEqual(
            loader._canonical_local_image_alias("docker.io/debian:stable"),
            loader._canonical_local_image_alias(
                "docker.io/library/debian:stable"
            ),
        )
        self.assertNotEqual(
            loader._canonical_local_image_alias(
                "registry-1.docker.io/library/debian:stable"
            ),
            loader._canonical_local_image_alias(
                "docker.io/library/debian:stable"
            ),
        )
        with self.assertRaisesRegex(loader.SeedError, "alias to multiple IDs"):
            loader._purge_plan_aliases(
                {
                    "external_images": [
                        {
                            "reference": f"debian:stable@{digest}",
                            "image_id": first_id,
                        },
                        {
                            "reference": (
                                f"docker.io/library/debian:stable@{digest}"
                            ),
                            "image_id": second_id,
                        },
                    ],
                    "custom_images": [],
                }
            )

        with self.assertRaisesRegex(loader.SeedError, "alias to multiple IDs"):
            loader._purge_plan_aliases(
                {
                    "external_images": [],
                    "custom_images": [
                        {
                            "archive_reference": (
                                "ai-gateway/tool:aigw-seed-" + "1" * 64
                            ),
                            "image": "ai-gateway/tool",
                            "image_id": first_id,
                        },
                        {
                            "archive_reference": (
                                "docker.io/ai-gateway/tool:aigw-seed-" + "2" * 64
                            ),
                            "image": "docker.io/ai-gateway/tool:latest",
                            "image_id": second_id,
                        },
                    ],
                }
            )

    def test_production_loader_cli_requires_production_scope(self) -> None:
        expected = "LOADED " + self.archive_digest
        fake_environment = {"UNTRUSTED": "removed"}
        with (
            mock.patch.object(loader.os, "environ", fake_environment),
            mock.patch.object(loader.os, "geteuid", return_value=loader.ROOT_UID),
            mock.patch.object(loader, "run", return_value=expected) as load,
            mock.patch("builtins.print") as output,
        ):
            returncode = loader.main(
                [
                    str(SCRIPT),
                    str(self.archive),
                    self.archive_digest,
                    str(self.manifest),
                    self.manifest_digest,
                    str(self.marker_dir),
                ]
            )

        self.assertEqual(returncode, 0)
        self.assertEqual(fake_environment, {"PATH": loader.FIXED_PATH})
        load.assert_called_once_with(
            self.archive,
            self.archive_digest,
            self.manifest,
            self.manifest_digest,
            self.marker_dir,
            required_release_scope=loader.RELEASE_SCOPE_PRODUCTION,
        )
        output.assert_called_once_with(expected)

    def test_root_preprod_loader_cli_requires_preprod_scope(self) -> None:
        expected = "LOADED " + self.archive_digest
        fake_environment = {"UNTRUSTED": "removed"}
        with (
            mock.patch.object(loader.os, "environ", fake_environment),
            mock.patch.object(loader.os, "geteuid", return_value=loader.ROOT_UID),
            mock.patch.object(loader, "run", return_value=expected) as load,
            mock.patch("builtins.print") as output,
        ):
            returncode = loader.main(
                [
                    str(SCRIPT),
                    "root-preprod-load",
                    str(self.archive),
                    self.archive_digest,
                    str(self.manifest),
                    self.manifest_digest,
                    str(self.marker_dir),
                ]
            )

        self.assertEqual(returncode, 0)
        self.assertEqual(fake_environment, {"PATH": loader.FIXED_PATH})
        load.assert_called_once_with(
            self.archive,
            self.archive_digest,
            self.manifest,
            self.manifest_digest,
            self.marker_dir,
            required_release_scope=loader.RELEASE_SCOPE_PREPROD,
        )
        output.assert_called_once_with(expected)

    def test_scope_gate_runs_before_archive_load(self) -> None:
        with (
            mock.patch.object(loader, "require_executable", side_effect=["docker", "zstd"]),
            mock.patch.object(loader, "require_docker_ready", return_value="linux/arm64"),
            mock.patch.object(loader, "validate_archive_document_allowlist"),
            mock.patch.object(loader, "load_archive") as load_archive,
            self.assertRaisesRegex(loader.SeedError, "release scope must be 'preprod'"),
        ):
            loader.run(
                self.archive,
                self.archive_digest,
                self.manifest,
                self.manifest_digest,
                self.marker_dir,
                required_release_scope=loader.RELEASE_SCOPE_PREPROD,
            )
        load_archive.assert_not_called()

    def test_production_scope_gate_rejects_preprod_before_load_or_marker(self) -> None:
        self.manifest.write_text(
            json.dumps(self.schema_v2_manifest()), encoding="utf-8"
        )
        self.manifest_digest = hashlib.sha256(self.manifest.read_bytes()).hexdigest()
        with (
            mock.patch.object(loader, "require_executable", return_value="docker"),
            mock.patch.object(loader, "require_docker_ready", return_value="linux/arm64"),
            mock.patch.object(loader, "validate_archive") as validate_archive,
            mock.patch.object(loader, "load_archive") as load_archive,
            mock.patch.object(loader, "write_marker") as write_marker,
            self.assertRaisesRegex(loader.SeedError, "release scope must be 'production'"),
        ):
            loader.run(
                self.archive,
                self.archive_digest,
                self.manifest,
                self.manifest_digest,
                self.marker_dir,
                required_release_scope=loader.RELEASE_SCOPE_PRODUCTION,
            )

        validate_archive.assert_not_called()
        load_archive.assert_not_called()
        write_marker.assert_not_called()
        self.assertEqual(list(self.marker_dir.glob("*.loaded")), [])

    def test_read_only_production_release_gate_rejects_preprod_before_archive_work(self) -> None:
        self.manifest.write_text(
            json.dumps(self.schema_v2_manifest()), encoding="utf-8"
        )
        self.manifest_digest = hashlib.sha256(self.manifest.read_bytes()).hexdigest()
        with (
            mock.patch.object(loader, "validate_archive") as validate_archive,
            mock.patch.object(loader, "require_executable") as executable,
            mock.patch.object(loader, "validate_archive_document_allowlist") as allowlist,
            self.assertRaisesRegex(loader.SeedError, "production-scoped schema-v2"),
        ):
            loader.validate_production_release(
                self.archive,
                self.archive_digest,
                self.manifest,
                self.manifest_digest,
            )

        validate_archive.assert_not_called()
        executable.assert_not_called()
        allowlist.assert_not_called()

    def test_local_preprod_load_refuses_to_move_an_existing_daemon_tag(self) -> None:
        self.manifest.write_text(
            json.dumps(self.schema_v2_manifest()), encoding="utf-8"
        )
        self.manifest_digest = hashlib.sha256(self.manifest.read_bytes()).hexdigest()
        with (
            mock.patch.object(loader, "require_executable", side_effect=["docker", "zstd"]),
            mock.patch.object(loader, "require_docker_ready", return_value="linux/arm64"),
            mock.patch.object(loader, "validate_archive_document_allowlist"),
            mock.patch.object(loader, "invalid_document_images", return_value=[]),
            mock.patch.object(
                loader,
                "existing_seed_tag_conflicts",
                return_value=["registry.example/base:1"],
            ),
            mock.patch.object(loader, "load_archive") as load_archive,
            self.assertRaisesRegex(loader.SeedError, "would overwrite existing Docker image tags"),
        ):
            loader.run(
                self.archive,
                self.archive_digest,
                self.manifest,
                self.manifest_digest,
                self.marker_dir,
                required_release_scope=loader.RELEASE_SCOPE_PREPROD,
            )
        load_archive.assert_not_called()

    def test_first_load_writes_exact_root_only_marker_then_skips(self) -> None:
        outcome, load_archive, validate_allowlist = self.run_with_mocks([[], []])
        self.assertEqual(outcome, f"LOADED {self.archive_digest}")
        load_archive.assert_called_once()
        validate_allowlist.assert_called_once_with(
            self.archive,
            "zstd",
            [{"reference": self.reference, "image_id": self.image_id}],
        )

        marker = loader.marker_path(
            self.marker_dir, self.archive_digest, self.manifest_digest
        )
        self.assertEqual(
            marker.read_text(encoding="ascii"),
            f"{self.archive_digest} {self.manifest_digest}\n",
        )
        self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.marker_dir.stat().st_mode), 0o700)

        outcome, load_archive, validate_allowlist = self.run_with_mocks([[]])
        self.assertEqual(outcome, f"SKIPPED {self.archive_digest}")
        load_archive.assert_not_called()
        # A marker cannot bypass proof that the staged archive itself has the
        # reviewed allow-list before a destructive reset consumes it.
        validate_allowlist.assert_called_once()

    def test_stale_marker_reloads_when_a_required_image_was_pruned(self) -> None:
        self.run_with_mocks([[], []])
        outcome, load_archive, _ = self.run_with_mocks([[self.reference], []])
        self.assertEqual(outcome, f"RELOADED {self.archive_digest}")
        load_archive.assert_called_once()

    def test_schema_v2_load_checks_external_and_custom_images_before_marker(self) -> None:
        self.manifest.write_text(
            json.dumps(self.schema_v2_manifest()), encoding="utf-8"
        )
        self.manifest_digest = hashlib.sha256(self.manifest.read_bytes()).hexdigest()
        with (
            mock.patch.object(loader, "require_executable", side_effect=["docker", "zstd"]),
            mock.patch.object(loader, "require_docker_ready", return_value="linux/arm64"),
            mock.patch.object(
                loader, "invalid_document_images", side_effect=[[], []]
            ) as inspect,
            mock.patch.object(loader, "load_archive") as load_archive,
            mock.patch.object(loader, "validate_archive_document_allowlist") as allowlist,
            mock.patch.object(loader, "validate_archive_image_allowlist") as legacy_allowlist,
        ):
            outcome = loader.run(
                self.archive,
                self.archive_digest,
                self.manifest,
                self.manifest_digest,
                self.marker_dir,
            )

        self.assertEqual(outcome, f"LOADED {self.archive_digest}")
        self.assertEqual(inspect.call_count, 2)
        load_archive.assert_called_once_with(self.archive, "zstd", "docker")
        allowlist.assert_called_once()
        legacy_allowlist.assert_not_called()

    def test_failed_postload_validation_leaves_no_marker(self) -> None:
        self.run_with_mocks([[], []])
        marker = loader.marker_path(
            self.marker_dir, self.archive_digest, self.manifest_digest
        )
        with self.assertRaisesRegex(loader.SeedError, "after load"):
            self.run_with_mocks([[self.reference], [self.reference]])
        self.assertFalse(marker.exists())

    def test_archive_digest_and_permissions_fail_closed(self) -> None:
        self.archive.chmod(0o664)
        with self.assertRaisesRegex(
            loader.SeedError, "must not be group- or world-writable"
        ):
            loader.validate_archive(self.archive, self.archive_digest)
        self.archive.chmod(0o644)
        loader.validate_archive(self.archive, self.archive_digest)
        self.archive.chmod(0o600)
        with self.assertRaisesRegex(loader.SeedError, "SHA-256"):
            loader.validate_archive(self.archive, "0" * 64)

    def test_root_loader_rejects_writable_or_symlinked_parent_lineage(self) -> None:
        unsafe = self.root / "unsafe"
        unsafe.mkdir(mode=0o777)
        unsafe.chmod(0o777)
        unsafe_archive = unsafe / "unsafe.docker.tar.zst"
        unsafe_archive.write_bytes(self.archive.read_bytes())
        unsafe_archive.chmod(0o600)
        with self.assertRaisesRegex(loader.SeedError, "writable without sticky"):
            loader.validate_archive(unsafe_archive, self.archive_digest)

        safe = self.root / "safe"
        safe.mkdir(mode=0o700)
        linked = self.root / "linked"
        linked.symlink_to(safe, target_is_directory=True)
        linked_archive = linked / "linked.docker.tar.zst"
        linked_archive.write_bytes(self.archive.read_bytes())
        linked_archive.chmod(0o600)
        with self.assertRaisesRegex(loader.SeedError, "real directory"):
            loader.validate_archive(linked_archive, self.archive_digest)

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
                [
                    "docker", "--host", loader.LOCAL_DOCKER_HOST,
                    "image", "inspect", "--", self.reference,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
                env=loader.FIXED_DOCKER_ENV,
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

    def test_image_inspection_accepts_loaded_oci_index_for_exact_platform(self) -> None:
        child_id = "sha256:" + "c" * 64
        parent = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps(
                [
                    {
                        "Id": self.image_id,
                        "RepoDigests": [
                            f"registry.example/base@sha256:{'a' * 64}"
                        ],
                        "Os": "",
                        "Architecture": "",
                        "Descriptor": {
                            "mediaType": "application/vnd.oci.image.index.v1+json",
                            "digest": self.image_id,
                        },
                    }
                ]
            ).encode(),
        )
        child = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps(
                [
                    {
                        "Id": child_id,
                        "Os": "",
                        "Architecture": "",
                        "Descriptor": {
                            "mediaType": loader.OCI_IMAGE_MANIFEST_MEDIA_TYPE,
                            "digest": child_id,
                            "platform": {
                                "os": "linux",
                                "architecture": "arm64",
                                "variant": "v8",
                            },
                        },
                    }
                ]
            ).encode(),
        )
        with mock.patch.object(
            loader.subprocess, "run", side_effect=[parent, child]
        ) as run:
            self.assertEqual(
                loader.invalid_required_images(
                    "docker",
                    [{"reference": self.reference, "image_id": self.image_id}],
                    "linux/arm64",
                ),
                [],
            )
        self.assertEqual(
            run.call_args_list[1].args[0],
            [
                "docker",
                "--host",
                loader.LOCAL_DOCKER_HOST,
                "image",
                "inspect",
                "--platform",
                "linux/arm64",
                "--",
                self.reference,
            ],
        )

    def test_image_inspection_rejects_index_without_requested_platform(self) -> None:
        parent_record = {
            "Id": self.image_id,
            "RepoDigests": [f"registry.example/base@sha256:{'a' * 64}"],
            "Os": "",
            "Architecture": "",
            "Descriptor": {
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "digest": self.image_id,
            },
        }
        parent = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps([parent_record]).encode()
        )
        missing_platform = subprocess.CompletedProcess(
            args=[], returncode=1, stdout=b"", stderr=b"not found"
        )
        with mock.patch.object(
            loader.subprocess, "run", side_effect=[parent, missing_platform]
        ):
            self.assertEqual(
                loader.invalid_required_images(
                    "docker",
                    [{"reference": self.reference, "image_id": self.image_id}],
                    "linux/arm64",
                ),
                [self.reference],
            )

    def test_local_release_receipt_platform_gate_accepts_loaded_oci_index(self) -> None:
        child_id = "sha256:" + "c" * 64
        parent = {
            "Id": self.image_id,
            "RepoDigests": [f"registry.example/base@sha256:{'a' * 64}"],
            "Os": "",
            "Architecture": "",
            "Descriptor": {
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "digest": self.image_id,
            },
        }
        child = {
            "Id": child_id,
            "Os": "",
            "Architecture": "",
            "Descriptor": {
                "mediaType": loader.OCI_IMAGE_MANIFEST_MEDIA_TYPE,
                "digest": child_id,
                "platform": {"os": "linux", "architecture": "arm64"},
            },
        }
        client = mock.Mock()
        client.run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps([child]), stderr=""
        )

        self.assertTrue(
            loader._local_release_image_has_platform(
                client, self.reference, parent, "linux/arm64"
            )
        )
        client.run.assert_called_once_with(
            "image",
            "inspect",
            "--platform",
            "linux/arm64",
            "--",
            self.reference,
        )

    def test_loaded_envoy_policy_is_verified_by_labels_without_execution(self) -> None:
        document = loader.validate_manifest_document(
            self.schema_v2_manifest(), self.archive, "linux/arm64"
        )
        policy = document["egress_policy"]
        custom_images = document["custom_images"]
        envoy = next(
            image
            for image in custom_images
            if image["image"] == "ai-gateway/envoy-egress:1"
        )
        record = {
            "Id": envoy["image_id"],
            "Config": {
                "Labels": {
                    loader.EGRESS_LABEL_SCHEMA: "1",
                    loader.EGRESS_LABEL_PROVIDERS: "anthropic,synthetic",
                    loader.EGRESS_LABEL_SHA256: policy["egress_policy_sha256"],
                    loader.EGRESS_LABEL_SOURCE_DATE_EPOCH: "0",
                }
            },
        }
        inspected = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps([record]).encode(), stderr=b""
        )
        with mock.patch.object(loader.subprocess, "run", return_value=inspected) as run:
            self.assertEqual(
                loader.invalid_egress_policy_image(
                    "docker", custom_images, policy
                ),
                [],
            )
        run.assert_called_once_with(
            [
                "docker",
                "--host",
                loader.LOCAL_DOCKER_HOST,
                "image",
                "inspect",
                "--",
                envoy["archive_reference"],
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            env=loader.FIXED_DOCKER_ENV,
        )

        for label, value in (
            (loader.EGRESS_LABEL_SCHEMA, "2"),
            (loader.EGRESS_LABEL_PROVIDERS, "synthetic,anthropic"),
            (loader.EGRESS_LABEL_SHA256, "0" * 64),
            (loader.EGRESS_LABEL_SOURCE_DATE_EPOCH, "1"),
        ):
            with self.subTest(label=label):
                bad_record = json.loads(json.dumps(record))
                bad_record["Config"]["Labels"][label] = value
                bad = subprocess.CompletedProcess(
                    args=[],
                    returncode=0,
                    stdout=json.dumps([bad_record]).encode(),
                    stderr=b"",
                )
                with mock.patch.object(loader.subprocess, "run", return_value=bad):
                    self.assertEqual(
                        loader.invalid_egress_policy_image(
                            "docker", custom_images, policy
                        ),
                        [envoy["archive_reference"]],
                    )

        bad_id = json.loads(json.dumps(record))
        bad_id["Id"] = "sha256:" + "0" * 64
        inspected = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps([bad_id]).encode(), stderr=b""
        )
        with mock.patch.object(loader.subprocess, "run", return_value=inspected):
            self.assertEqual(
                loader.invalid_egress_policy_image(
                    "docker", custom_images, policy
                ),
                [envoy["archive_reference"]],
            )

    def test_loaded_egress_policy_receipt_checks_archive_and_all_loaded_images(self) -> None:
        manifest = self.schema_v2_manifest()
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")
        self.manifest.chmod(0o600)
        self.manifest_digest = hashlib.sha256(self.manifest.read_bytes()).hexdigest()
        expected_policy = manifest["egress_policy"]
        with (
            mock.patch.object(
                loader, "require_executable", side_effect=["docker", "zstd"]
            ) as executable,
            mock.patch.object(
                loader, "require_docker_ready", return_value="linux/arm64"
            ),
            mock.patch.object(
                loader, "validate_archive_document_allowlist"
            ) as allowlist,
            mock.patch.object(
                loader, "invalid_document_images", return_value=[]
            ) as loaded_images,
        ):
            receipt = loader.loaded_egress_policy_receipt(
                self.archive, self.manifest, self.manifest_digest
            )

        self.assertEqual(receipt, expected_policy)
        self.assertEqual(
            executable.call_args_list,
            [mock.call("docker"), mock.call("zstd")],
        )
        allowlist.assert_called_once()
        loaded_images.assert_called_once()

        with (
            mock.patch.object(
                loader, "require_executable", side_effect=["docker", "zstd"]
            ),
            mock.patch.object(
                loader, "require_docker_ready", return_value="linux/arm64"
            ),
            mock.patch.object(loader, "validate_archive_document_allowlist"),
            mock.patch.object(
                loader,
                "invalid_document_images",
                return_value=["ai-gateway/envoy-egress:aigw-seed-bad"],
            ),
            self.assertRaisesRegex(loader.SeedError, "policy labels are mismatched"),
        ):
            loader.loaded_egress_policy_receipt(
                self.archive, self.manifest, self.manifest_digest
            )

    def test_loaded_egress_policy_receipt_cli_outputs_only_canonical_policy(self) -> None:
        policy = self.schema_v2_manifest()["egress_policy"]
        expected = json.dumps(policy, sort_keys=True, separators=(",", ":"))
        fake_environment = {"UNTRUSTED": "removed"}
        with (
            mock.patch.object(loader.os, "environ", fake_environment),
            mock.patch.object(loader.os, "geteuid", return_value=loader.ROOT_UID),
            mock.patch.object(
                loader, "loaded_egress_policy_receipt", return_value=policy
            ) as loaded,
            mock.patch("builtins.print") as output,
        ):
            returncode = loader.main(
                [
                    str(SCRIPT),
                    "loaded-egress-policy-receipt",
                    str(self.archive),
                    str(self.manifest),
                    self.manifest_digest,
                ]
            )

        self.assertEqual(returncode, 0)
        self.assertEqual(fake_environment, {"PATH": loader.FIXED_PATH})
        loaded.assert_called_once_with(self.archive, self.manifest, self.manifest_digest)
        output.assert_called_once_with(expected)

    def test_manifest_rejects_option_like_reference(self) -> None:
        decoded = loader.validate_manifest_file(self.manifest, self.manifest_digest)
        decoded["images"][0]["reference"] = f"--help:1@sha256:{'a' * 64}"
        with self.assertRaisesRegex(loader.SeedError, "unsafe name or tag"):
            loader.validate_manifest_schema(decoded, self.archive, "linux/arm64")

    def test_schema_v2_binds_production_and_preprod_only_custom_images(self) -> None:
        document = loader.validate_manifest_document(
            self.schema_v2_manifest(), self.archive, "linux/arm64"
        )

        self.assertEqual(document["schema_version"], 2)
        custom_images = document["custom_images"]
        self.assertEqual(len(custom_images), 4)
        wif = next(
            image for image in custom_images if image["deployment_scope"] == "preprod-only"
        )
        self.assertEqual(wif["target_activation"], "archive-only")

        invalid = self.schema_v2_manifest()
        invalid["custom_images"][1]["target_activation"] = "active-compose"
        with self.assertRaisesRegex(loader.SeedError, "scope and activation"):
            loader.validate_manifest_document(invalid, self.archive, "linux/arm64")

    def test_schema_v2_release_scope_is_required_and_production_excludes_extras(self) -> None:
        production = loader.validate_manifest_document(
            self.schema_v2_production_manifest(), self.archive, "linux/arm64"
        )
        self.assertEqual(production["release_scope"], "production")
        self.assertEqual(
            [image["image"] for image in production["custom_images"]],
            ["ai-gateway/portal:1", "ai-gateway/envoy-egress:1"],
        )
        self.assertEqual(
            set(production["build_inputs"]["services"]),
            {"portal", "envoy-egress"},
        )

        missing_scope = self.schema_v2_production_manifest()
        missing_scope.pop("release_scope")
        with self.assertRaisesRegex(loader.SeedError, "release_scope"):
            loader.validate_manifest_document(missing_scope, self.archive, "linux/arm64")

        mixed = self.schema_v2_manifest()
        mixed["release_scope"] = "production"
        with self.assertRaisesRegex(loader.SeedError, "preproduction-only"):
            loader.validate_manifest_document(mixed, self.archive, "linux/arm64")

    def test_schema_v2_requires_exact_egress_policy_and_binds_envoy_id(self) -> None:
        for manifest in (
            self.schema_v2_manifest(),
            self.schema_v2_production_manifest(),
        ):
            with self.subTest(scope=manifest["release_scope"]):
                document = loader.validate_manifest_document(
                    manifest, self.archive, "linux/arm64"
                )
                policy = document["egress_policy"]
                self.assertEqual(policy["selected_providers"], ["anthropic", "synthetic"])
                self.assertEqual(policy["envoy_image_id"], "sha256:" + "f" * 64)
                receipt = loader.format_release_receipt(
                    self.archive, self.manifest, self.manifest_digest, document
                )
                self.assertEqual(receipt["egress_policy"], policy)

        missing = self.schema_v2_manifest()
        missing.pop("egress_policy")
        with self.assertRaisesRegex(loader.SeedError, "egress policy.*exact object"):
            loader.validate_manifest_document(missing, self.archive, "linux/arm64")

        extra = self.schema_v2_manifest()
        extra["egress_policy"]["unreviewed"] = "forbidden"
        with self.assertRaisesRegex(loader.SeedError, "egress policy.*exact object"):
            loader.validate_manifest_document(extra, self.archive, "linux/arm64")

        mismatch = self.schema_v2_manifest()
        mismatch["egress_policy"]["envoy_image_id"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(loader.SeedError, "does not match the custom image"):
            loader.validate_manifest_document(mismatch, self.archive, "linux/arm64")

        tampered = self.schema_v2_manifest()
        provider = tampered["egress_policy"]["providers"][0]
        provider["api_hostname"] = "api2.anthropic.com"
        provider["sni"] = "api2.anthropic.com"
        provider["exact_sans"] = ["api2.anthropic.com"]
        with self.assertRaisesRegex(loader.SeedError, "SHA-256.*canonical receipt"):
            loader.validate_manifest_document(tampered, self.archive, "linux/arm64")

    def test_schema_v2_egress_policy_rejects_bad_schema_hashes_and_selection(self) -> None:
        bad_values = (
            ("schema", "schema_version", True, "schema_version"),
            ("policy hash", "egress_policy_sha256", "A" * 64, "hashes"),
            ("config hash", "envoy_config_sha256", "short", "hashes"),
        )
        for label, field, value, error in bad_values:
            with self.subTest(label=label):
                manifest = self.schema_v2_manifest()
                manifest["egress_policy"][field] = value
                with self.assertRaisesRegex(loader.SeedError, error):
                    loader.validate_manifest_document(
                        manifest, self.archive, "linux/arm64"
                    )

        for selected in ([], ["synthetic", "anthropic"], ["anthropic", "anthropic"]):
            with self.subTest(selected=selected):
                manifest = self.schema_v2_manifest()
                manifest["egress_policy"]["selected_providers"] = selected
                with self.assertRaisesRegex(loader.SeedError, "nonempty, sorted, and unique"):
                    loader.validate_manifest_document(
                        manifest, self.archive, "linux/arm64"
                    )

        wrong_order = self.schema_v2_manifest()
        wrong_order["egress_policy"]["providers"].reverse()
        with self.assertRaisesRegex(loader.SeedError, "canonical selected-provider order"):
            loader.validate_manifest_document(wrong_order, self.archive, "linux/arm64")

    def test_schema_v2_egress_provider_fields_fail_closed(self) -> None:
        field_cases = (
            ("unsafe name", "name", "Open_AI", "canonical selected-provider order"),
            ("IP hostname", "api_hostname", "127.0.0.1", "hostname, route, or SNI"),
            ("uppercase hostname", "api_hostname", "API.ANTHROPIC.COM", "hostname, route, or SNI"),
            ("bad route", "route_prefix", "/anthropic", "hostname, route, or SNI"),
            ("CA path", "ca_file", "../anthropic-ca.pem", "CA filename"),
            ("bundle hash", "ca_bundle_sha256", "z" * 64, "reviewed hash"),
            ("provenance hash", "provenance_sha256", "0", "reviewed hash"),
        )
        for label, field, value, error in field_cases:
            with self.subTest(label=label):
                manifest = self.schema_v2_manifest()
                manifest["egress_policy"]["providers"][0][field] = value
                with self.assertRaisesRegex(loader.SeedError, error):
                    loader.validate_manifest_document(
                        manifest, self.archive, "linux/arm64"
                    )

        extra = self.schema_v2_manifest()
        extra["egress_policy"]["providers"][0]["ca_path"] = "/tmp/unreviewed.pem"
        with self.assertRaisesRegex(loader.SeedError, "provider record 0.*exact object"):
            loader.validate_manifest_document(extra, self.archive, "linux/arm64")

        bad_sans = (
            (["z.example.com", "api.anthropic.com"], "sorted, and unique"),
            (["bad_host.example.com"], "sorted, and unique"),
            (["other.example.com"], "SNI is absent"),
        )
        for sans, error in bad_sans:
            with self.subTest(sans=sans):
                manifest = self.schema_v2_manifest()
                manifest["egress_policy"]["providers"][0]["exact_sans"] = sans
                with self.assertRaisesRegex(loader.SeedError, error):
                    loader.validate_manifest_document(
                        manifest, self.archive, "linux/arm64"
                    )

        for fingerprints in ([], ["8" * 64, "8" * 64], ["X" * 64]):
            with self.subTest(fingerprints=fingerprints):
                manifest = self.schema_v2_manifest()
                manifest["egress_policy"]["providers"][0][
                    "ca_sha256_fingerprints"
                ] = fingerprints
                with self.assertRaisesRegex(loader.SeedError, "CA fingerprints"):
                    loader.validate_manifest_document(
                        manifest, self.archive, "linux/arm64"
                    )

    def test_schema_v2_egress_provider_uniqueness_and_routes_are_enforced(self) -> None:
        duplicate_hostname = self.schema_v2_manifest()
        duplicate_hostname["egress_policy"]["providers"][1]["api_hostname"] = (
            "api.anthropic.com"
        )
        with self.assertRaisesRegex(loader.SeedError, "must be unique"):
            loader.validate_manifest_document(
                duplicate_hostname, self.archive, "linux/arm64"
            )

        overlapping_route = self.schema_v2_manifest()
        overlapping_route["egress_policy"]["providers"][1]["route_prefix"] = (
            "/anthropic/models/"
        )
        with self.assertRaisesRegex(loader.SeedError, "routes.*overlap"):
            loader.validate_manifest_document(
                overlapping_route, self.archive, "linux/arm64"
            )

    def test_schema_v1_keeps_its_original_manifest_and_receipt_shape(self) -> None:
        manifest = loader.validate_manifest_file(self.manifest, self.manifest_digest)
        document = loader.validate_manifest_document(
            manifest, self.archive, "linux/arm64"
        )
        self.assertIsNone(document["egress_policy"])
        receipt = loader.format_release_receipt(
            self.archive, self.manifest, self.manifest_digest, document
        )
        self.assertNotIn("egress_policy", receipt)

    def test_archive_reader_hashes_oci_and_legacy_config_metadata(self) -> None:
        legacy_content = b'{"architecture":"arm64","kind":"legacy"}'
        oci_content = b'{"architecture":"arm64","kind":"oci"}'
        legacy_digest = hashlib.sha256(legacy_content).hexdigest()
        oci_digest = hashlib.sha256(oci_content).hexdigest()
        large_layer = b"x" * (loader.MAX_ARCHIVE_METADATA_BYTES + 1)
        large_layer_digest = hashlib.sha256(large_layer).hexdigest()

        def process_for(entries: list[tuple[str, bytes]]) -> mock.Mock:
            archive_stream = io.BytesIO()
            with tarfile.open(fileobj=archive_stream, mode="w") as archive:
                for name, content in entries:
                    info = tarfile.TarInfo(name)
                    info.size = len(content)
                    archive.addfile(info, io.BytesIO(content))
            process = mock.Mock()
            process.stdout = io.BytesIO(archive_stream.getvalue())
            process.stderr = io.BytesIO(b"")
            process.wait.return_value = 0
            return process

        entries = [
            ("manifest.json", b"[]"),
            ("index.json", b'{"schemaVersion":2,"manifests":[]}'),
            (legacy_digest + ".json", legacy_content),
            ("blobs/sha256/" + oci_digest, oci_content),
            ("blobs/sha256/" + large_layer_digest, large_layer),
        ]
        with (
            mock.patch.object(
                loader.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0, b"", b""),
            ),
            mock.patch.object(
                loader.subprocess, "Popen", return_value=process_for(entries)
            ),
        ):
            metadata = loader._read_archive_metadata(self.archive, "zstd")
        self.assertEqual(
            metadata["_verified_small_blobs"],
            {f"sha256:{legacy_digest}", f"sha256:{oci_digest}"},
        )
        self.assertNotIn(
            f"sha256:{large_layer_digest}", metadata["_verified_small_blobs"]
        )

        duplicate_entries = [*entries, (legacy_digest + ".json", legacy_content)]
        with (
            mock.patch.object(
                loader.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0, b"", b""),
            ),
            mock.patch.object(
                loader.subprocess,
                "Popen",
                return_value=process_for(duplicate_entries),
            ),
            self.assertRaisesRegex(loader.SeedError, "duplicate image metadata"),
        ):
            loader._read_archive_metadata(self.archive, "zstd")

    def test_production_archive_allowlist_rejects_preprod_descriptor_and_tag(self) -> None:
        document = loader.validate_manifest_document(
            self.schema_v2_production_manifest(), self.archive, "linux/arm64"
        )
        production_images = document["custom_images"]
        external_tag = self.reference.rsplit("@sha256:", 1)[0]
        metadata = {
            "manifest.json": [
                {
                    "Config": self.image_id[7:] + ".json",
                    "RepoTags": [external_tag],
                },
                *[
                    {
                        "Config": image["image_id"][7:] + ".json",
                        "RepoTags": [image["archive_reference"]],
                    }
                    for image in production_images
                ],
            ],
            "index.json": {
                "schemaVersion": 2,
                "manifests": [
                    {
                        "digest": "sha256:" + "a" * 64,
                        "annotations": {
                            "io.containerd.image.name": external_tag,
                            "containerd.io/distribution.source.registry.example": "base",
                        },
                    },
                    *[
                        {
                            "digest": image["image_id"],
                            "annotations": {
                                "io.containerd.image.name": (
                                    "docker.io/" + image["archive_reference"]
                                )
                            },
                        }
                        for image in production_images
                    ],
                ],
            },
        }
        self.add_verified_archive_metadata(metadata)
        with mock.patch.object(loader, "_read_archive_metadata", return_value=metadata):
            loader.validate_archive_document_allowlist(self.archive, "zstd", document)

        metadata["manifest.json"].append(
            {"RepoTags": ["ai-gateway/wif-provider-mock:aigw-seed-" + "d" * 64]}
        )
        metadata["index.json"]["manifests"].append(
            {
                "digest": "sha256:" + "d" * 64,
                "annotations": {
                    "io.containerd.image.name": (
                        "docker.io/ai-gateway/wif-provider-mock:aigw-seed-" + "d" * 64
                    )
                },
            }
        )
        self.add_verified_archive_metadata(metadata)
        with mock.patch.object(loader, "_read_archive_metadata", return_value=metadata):
            with self.assertRaisesRegex(loader.SeedError, "unapproved"):
                loader.validate_archive_document_allowlist(
                    self.archive, "zstd", document
                )

    def test_archive_oci_metadata_must_exactly_match_manifest_allowlist(self) -> None:
        tag = "registry.example/base:1"
        metadata = {
            "manifest.json": [{"RepoTags": [tag]}],
            "index.json": {
                "schemaVersion": 2,
                "manifests": [
                    {
                        "digest": f"sha256:{'a' * 64}",
                        "annotations": {
                            "io.containerd.image.name": tag,
                            "containerd.io/distribution.source.registry.example": "base",
                        },
                    }
                ],
            },
        }
        required = [{"reference": self.reference, "image_id": self.image_id}]
        with mock.patch.object(loader, "_read_archive_metadata", return_value=metadata):
            loader.validate_archive_image_allowlist(self.archive, "zstd", required)

        metadata["manifest.json"][0]["RepoTags"].append("registry.example/extra:1")
        with mock.patch.object(loader, "_read_archive_metadata", return_value=metadata):
            with self.assertRaisesRegex(loader.SeedError, "unapproved"):
                loader.validate_archive_image_allowlist(self.archive, "zstd", required)

    def test_schema_v2_archive_allowlist_checks_custom_config_image_ids(self) -> None:
        document = loader.validate_manifest_document(
            self.schema_v2_manifest(), self.archive, "linux/arm64"
        )
        custom_by_image = {
            image["image"]: image for image in document["custom_images"]
        }
        production = custom_by_image["ai-gateway/portal:1"]
        samba = custom_by_image["ai-gateway/samba-ad:preprod"]
        wif = custom_by_image["ai-gateway/wif-provider-mock:preprod"]
        envoy = custom_by_image["ai-gateway/envoy-egress:1"]
        tag = self.reference.rsplit("@sha256:", 1)[0]
        metadata = {
            "manifest.json": [
                {
                    "Config": self.image_id[7:] + ".json",
                    "RepoTags": [tag],
                },
                {
                    "Config": production["image_id"][7:] + ".json",
                    "RepoTags": [production["archive_reference"]],
                },
                {
                    "Config": samba["image_id"][7:] + ".json",
                    "RepoTags": [samba["archive_reference"]],
                },
                {
                    "Config": wif["image_id"][7:] + ".json",
                    "RepoTags": [wif["archive_reference"]],
                },
                {
                    "Config": envoy["image_id"][7:] + ".json",
                    "RepoTags": [envoy["archive_reference"]],
                },
            ],
            "index.json": {
                "schemaVersion": 2,
                "manifests": [
                    {
                        "digest": "sha256:" + "a" * 64,
                        "annotations": {
                            "io.containerd.image.name": tag,
                            "containerd.io/distribution.source.registry.example": "base",
                        },
                    },
                    {
                        "digest": "sha256:" + "e" * 64,
                        "annotations": {
                            "io.containerd.image.name": (
                                "docker.io/" + production["archive_reference"]
                            )
                        },
                    },
                    {
                        "digest": "sha256:" + "9" * 64,
                        "annotations": {
                            "io.containerd.image.name": (
                                "docker.io/" + samba["archive_reference"]
                            )
                        },
                    },
                    {
                        "digest": "sha256:" + "f" * 64,
                        "annotations": {
                            "io.containerd.image.name": (
                                "docker.io/" + wif["archive_reference"]
                            )
                        },
                    },
                    {
                        "digest": envoy["image_id"],
                        "annotations": {
                            "io.containerd.image.name": (
                                "docker.io/" + envoy["archive_reference"]
                            )
                        },
                    },
                ],
            },
        }
        self.add_verified_archive_metadata(metadata)
        with mock.patch.object(loader, "_read_archive_metadata", return_value=metadata):
            loader.validate_archive_document_allowlist(self.archive, "zstd", document)

        # The containerd image store binds an image ID through the unique OCI
        # index descriptor instead of the platform config digest.
        metadata["manifest.json"][3]["Config"] = (
            "blobs/sha256/" + "8" * 64
        )
        metadata["index.json"]["manifests"][3]["digest"] = wif["image_id"]
        self.add_verified_archive_metadata(metadata)
        with mock.patch.object(loader, "_read_archive_metadata", return_value=metadata):
            loader.validate_archive_document_allowlist(
                self.archive, "zstd", document
            )

        metadata["index.json"]["manifests"][3]["digest"] = "sha256:" + "f" * 64
        self.add_verified_archive_metadata(metadata)
        with mock.patch.object(loader, "_read_archive_metadata", return_value=metadata):
            with self.assertRaisesRegex(loader.SeedError, "immutable image ID"):
                loader.validate_archive_document_allowlist(
                    self.archive, "zstd", document
                )

    def test_schema_v2_archive_allowlist_binds_external_image_id(self) -> None:
        document = loader.validate_manifest_document(
            self.schema_v2_manifest(), self.archive, "linux/arm64"
        )
        tag = self.reference.rsplit("@sha256:", 1)[0]
        metadata = {
            "manifest.json": [
                {
                    "Config": self.image_id[7:] + ".json",
                    "RepoTags": [tag],
                },
                *[
                    {
                        "Config": image["image_id"][7:] + ".json",
                        "RepoTags": [image["archive_reference"]],
                    }
                    for image in document["custom_images"]
                ],
            ],
            "index.json": {
                "schemaVersion": 2,
                "manifests": [
                    {
                        "digest": "sha256:" + "a" * 64,
                        "annotations": {
                            "io.containerd.image.name": tag,
                            "containerd.io/distribution.source.registry.example": "base",
                        },
                    },
                    *[
                        {
                            "digest": image["image_id"],
                            "annotations": {
                                "io.containerd.image.name": (
                                    "docker.io/" + image["archive_reference"]
                                )
                            },
                        }
                        for image in document["custom_images"]
                    ],
                ],
            },
        }
        self.add_verified_archive_metadata(metadata)

        with mock.patch.object(loader, "_read_archive_metadata", return_value=metadata):
            loader.validate_archive_document_allowlist(self.archive, "zstd", document)

        metadata["_verified_small_blobs"] = set()
        with mock.patch.object(loader, "_read_archive_metadata", return_value=metadata):
            with self.assertRaisesRegex(loader.SeedError, "missing or unverified"):
                loader.validate_archive_document_allowlist(
                    self.archive, "zstd", document
                )
        self.add_verified_archive_metadata(metadata)

        document["external_images"][0]["image_id"] = (
            document["custom_images"][0]["image_id"]
        )
        with mock.patch.object(loader, "_read_archive_metadata", return_value=metadata):
            with self.assertRaisesRegex(loader.SeedError, "external image.*immutable"):
                loader.validate_archive_document_allowlist(
                    self.archive, "zstd", document
                )

    def test_schema_v2_reconciliation_requires_exact_active_build_inputs(self) -> None:
        document = loader.validate_manifest_document(
            self.schema_v2_manifest(), self.archive, "linux/arm64"
        )
        old_id = "sha256:" + "e" * 64
        plan = {
            "manifest": {
                "schema": 1,
                "services": {
                    "portal": {
                        "digest": "1" * 64,
                        "image": "ai-gateway/portal:1",
                        "image_id": old_id,
                    }
                },
            },
            "services": [],
        }
        with mock.patch.object(
            loader, "_current_seed_document", return_value=("docker", document)
        ):
            reconciled = loader.reconcile_build_plan(
                self.archive,
                self.manifest,
                self.manifest_digest,
                self.project,
                plan,
            )
        self.assertEqual(reconciled["schema_version"], 2)
        self.assertEqual(reconciled["plan"]["services"], ["portal"])

        plan["manifest"]["services"]["portal"]["digest"] = "9" * 64
        with (
            mock.patch.object(
                loader, "_current_seed_document", return_value=("docker", document)
            ),
            self.assertRaisesRegex(loader.SeedError, "build inputs"),
        ):
            loader.reconcile_build_plan(
                self.archive,
                self.manifest,
                self.manifest_digest,
                self.project,
                plan,
            )

    def test_release_receipt_maps_canonical_tags_to_loaded_transfer_ids(self) -> None:
        document = loader.validate_manifest_document(
            self.schema_v2_manifest(), self.archive, "linux/arm64"
        )
        builder = mock.Mock()
        with (
            mock.patch.object(
                loader, "_current_seed_document", return_value=("docker", document)
            ),
            mock.patch.object(
                loader, "_load_local_builder", return_value=builder
            ) as load_builder,
            mock.patch.object(loader, "_verify_release_build_inputs") as build_proof,
        ):
            receipt = loader.release_receipt(
                self.archive,
                self.manifest,
                self.manifest_digest,
                self.project,
            )
        load_builder.assert_called_once_with(self.project, privileged=True)
        build_proof.assert_called_once()

        wif = receipt["custom_images"]["ai-gateway/wif-provider-mock:preprod"]
        self.assertEqual(wif["image_id"], "sha256:" + "d" * 64)
        self.assertEqual(
            wif["archive_reference"],
            "ai-gateway/wif-provider-mock:aigw-seed-" + "d" * 64,
        )
        self.assertEqual(wif["target_activation"], "archive-only")
        samba = receipt["custom_images"]["ai-gateway/samba-ad:preprod"]
        self.assertEqual(samba["image_id"], "sha256:" + "e" * 64)
        self.assertEqual(samba["deployment_scope"], "preprod-only")

    def test_root_release_receipt_rejects_changed_custom_build_inputs(self) -> None:
        document = loader.validate_manifest_document(
            self.schema_v2_manifest(), self.archive, "linux/arm64"
        )

        class FakeBuildError(RuntimeError):
            pass

        class FakePlanError(RuntimeError):
            pass

        planner = mock.Mock()
        planner.PlanError = FakePlanError
        planner.plan_compose_builds.return_value = {
            "manifest": {
                "schema": 1,
                "services": {
                    "portal": {
                        "digest": "9" * 64,
                        "image": "ai-gateway/portal:1",
                        "image_id": "sha256:" + "c" * 64,
                    }
                },
            },
            "services": [],
        }
        builder = mock.Mock()
        builder.SeedBuildError = FakeBuildError
        builder.DockerClient.return_value = mock.Mock()
        builder.render_deployable_compose_model.return_value = (
            {"services": {}},
            mock.Mock(),
            [],
        )
        builder._load_build_planner.return_value = planner
        builder.COMPOSE_PROJECT_NAME = "ai-gateway"
        with (
            mock.patch.object(
                loader, "_current_seed_document", return_value=("docker", document)
            ),
            mock.patch.object(loader, "_load_local_builder", return_value=builder),
            self.assertRaisesRegex(loader.SeedError, "build inputs do not match"),
        ):
            loader.release_receipt(
                self.archive,
                self.manifest,
                self.manifest_digest,
                self.project,
            )
        builder._load_build_planner.assert_called_once_with(
            self.project, privileged=True
        )

    def test_privileged_builder_requires_a_canonical_project_root(self) -> None:
        scripts = self.project / "scripts"
        scripts.mkdir()
        scripts.joinpath("rebuild-offline-image-seed.py").write_text(
            "VALUE = 1\n", encoding="utf-8"
        )
        noncanonical = self.project / "services" / ".."

        with self.assertRaisesRegex(loader.SeedError, "canonical"):
            loader._load_local_builder(noncanonical, privileged=True)

    def test_privileged_builder_rejects_unsafe_internal_ancestors(self) -> None:
        scripts = self.project / "scripts"
        scripts.mkdir()
        scripts.joinpath("rebuild-offline-image-seed.py").write_text(
            "VALUE = 1\n", encoding="utf-8"
        )
        scripts.chmod(0o775)
        with self.assertRaisesRegex(loader.SeedError, "group- or world-writable"):
            loader._load_local_builder(self.project, privileged=True)

        scripts.chmod(0o755)
        scripts.rename(self.project / "real-scripts")
        scripts.symlink_to(self.project / "real-scripts", target_is_directory=True)
        with self.assertRaisesRegex(loader.SeedError, "real directories"):
            loader._load_local_builder(self.project, privileged=True)

    def test_privileged_builder_requires_root_root_nonwritable_file(self) -> None:
        scripts = self.project / "scripts"
        scripts.mkdir()
        builder = scripts / "rebuild-offline-image-seed.py"
        builder.write_text("VALUE = 1\n", encoding="utf-8")
        builder.chmod(0o664)
        with self.assertRaisesRegex(loader.SeedError, "group- or world-writable"):
            loader._load_local_builder(self.project, privileged=True)

        builder.chmod(0o644)
        with (
            mock.patch.object(loader, "ROOT_GID", os.getgid() + 1),
            self.assertRaisesRegex(loader.SeedError, "root:root"),
        ):
            loader._load_local_builder(self.project, privileged=True)

    def test_nonroot_builder_keeps_local_user_owned_behavior(self) -> None:
        scripts = self.project / "scripts"
        scripts.mkdir(mode=0o777)
        scripts.chmod(0o777)
        builder = scripts / "rebuild-offline-image-seed.py"
        builder.write_text("VALUE = 42\n", encoding="utf-8")
        builder.chmod(0o666)

        module = loader._load_local_builder(self.project)

        self.assertEqual(module.VALUE, 42)

    def test_local_receipt_proves_loaded_archive_tags_source_and_build_input_parity(self) -> None:
        manifest = self.schema_v2_manifest()
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")
        self.manifest.chmod(0o600)
        self.manifest_digest = hashlib.sha256(self.manifest.read_bytes()).hexdigest()
        document = loader.validate_manifest_document(
            manifest, self.archive, "linux/arm64"
        )
        by_reference = {
            image["reference"].rsplit("@sha256:", 1)[0]: {
                "Id": image["image_id"],
                # Docker does not restore RepoDigests from a saved archive.
                "RepoDigests": [],
                "Os": "linux",
                "Architecture": "arm64",
            }
            for image in document["external_images"]
        }
        by_reference.update(
            {
                image["archive_reference"]: {
                    "Id": image["image_id"],
                    "RepoDigests": [],
                    "Os": "linux",
                    "Architecture": "arm64",
                }
                for image in document["custom_images"]
            }
        )
        envoy_reference = next(
            image["archive_reference"]
            for image in document["custom_images"]
            if image["image"] == "ai-gateway/envoy-egress:1"
        )
        by_reference[envoy_reference]["Config"] = {
            "Labels": {
                loader.EGRESS_LABEL_SCHEMA: "1",
                loader.EGRESS_LABEL_PROVIDERS: "anthropic,synthetic",
                loader.EGRESS_LABEL_SHA256: document["egress_policy"][
                    "egress_policy_sha256"
                ],
                loader.EGRESS_LABEL_SOURCE_DATE_EPOCH: "0",
            }
        }
        client = mock.Mock()

        def inspect(*arguments):
            reference = arguments[-1]
            return subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=json.dumps([by_reference[reference]]),
                stderr="",
            )

        client.run.side_effect = inspect
        planner = mock.Mock()
        planner.plan_compose_builds.return_value = {
            "manifest": document["build_inputs"],
            "services": [],
        }
        builder = mock.Mock()
        builder.OutputPolicy.side_effect = lambda uid, gid, root: (uid, gid, root)
        builder._initial_docker_config.return_value = Path.home() / ".docker"
        builder.resolve_docker_client.return_value = client
        builder.platform.return_value = "linux/arm64"
        builder.collect_project_image_reference_scopes.return_value = {
            "production": {self.reference},
            "preprod": {self.reference},
        }
        builder.render_deployable_compose_model.return_value = (
            {"services": {}},
            client,
            [],
        )
        builder._load_build_planner.return_value = planner
        builder._find_executable.return_value = "zstd"
        builder.COMPOSE_PROJECT_NAME = "ai-gateway"

        with (
            mock.patch.object(loader, "_load_local_builder", return_value=builder),
            mock.patch.object(loader, "validate_archive_document_allowlist") as allowlist,
        ):
            receipt = loader.local_release_receipt(
                self.archive,
                self.manifest,
                self.manifest_digest,
                self.project,
            )

        self.assertIn("ai-gateway/samba-ad:preprod", receipt["custom_images"])
        self.assertIn("ai-gateway/wif-provider-mock:preprod", receipt["custom_images"])
        inspected = [call.args[-1] for call in client.run.call_args_list]
        self.assertIn("registry.example/base:1", inspected)
        self.assertNotIn(self.reference, inspected)
        builder.add_preprod_build_services.assert_called_once()
        builder._load_build_planner.assert_called_once_with(
            self.project, privileged=False
        )
        allowlist.assert_called_once_with(self.archive, "zstd", document)

    def test_schema_v2_activation_uses_transfer_id_and_skips_remote_build(self) -> None:
        document = loader.validate_manifest_document(
            self.schema_v2_manifest(), self.archive, "linux/arm64"
        )
        old_id = "sha256:" + "e" * 64
        plan = {
            "manifest": {
                "schema": 1,
                "services": {
                    "portal": {
                        "digest": "1" * 64,
                        "image": "ai-gateway/portal:1",
                        "image_id": old_id,
                    }
                },
            },
            "services": ["portal"],
        }
        reconciled = {"schema_version": 2, "plan": plan}
        production = next(
            image
            for image in document["custom_images"]
            if image["image"] == "ai-gateway/portal:1"
        )
        with (
            mock.patch.object(loader, "reconcile_build_plan", return_value=reconciled),
            mock.patch.object(
                loader, "_current_seed_document", return_value=("docker", document)
            ),
            mock.patch.object(
                loader,
                "_inspect_local_image_id",
                side_effect=[old_id, production["image_id"]],
            ),
            mock.patch.object(loader, "_tag_local_image") as tag,
        ):
            activated = loader.activate_custom_images(
                self.archive,
                self.manifest,
                self.manifest_digest,
                self.project,
                plan,
            )

        tag.assert_called_once_with(
            "docker", production["archive_reference"], production["image"]
        )
        self.assertEqual(activated["plan"]["services"], [])
        self.assertEqual(
            activated["plan"]["manifest"]["services"]["portal"]["image_id"],
            production["image_id"],
        )

    def test_current_source_manifest_parity_and_local_presence_are_required(self) -> None:
        with (
            mock.patch.object(loader, "require_executable", return_value="docker"),
            mock.patch.object(loader, "require_docker_ready", return_value="linux/arm64"),
            mock.patch.object(loader, "invalid_required_images", return_value=[]) as inspect,
        ):
            outcome = loader.verify_current(
                self.archive,
                self.manifest,
                self.manifest_digest,
                self.project,
            )
        self.assertEqual(outcome, f"VERIFIED {self.manifest_digest}")
        inspect.assert_called_once_with(
            "docker",
            [{"reference": self.reference, "image_id": self.image_id}],
            "linux/arm64",
        )

        stale = f"registry.example/stale:1@sha256:{'c' * 64}"
        (self.project / "services" / "example" / "Dockerfile").write_text(
            f"FROM {stale}\n",
            encoding="utf-8",
        )
        with (
            mock.patch.object(loader, "require_executable", return_value="docker"),
            mock.patch.object(loader, "require_docker_ready", return_value="linux/arm64"),
            self.assertRaisesRegex(loader.SeedError, "current source pins"),
        ):
            loader.verify_current(
                self.archive,
                self.manifest,
                self.manifest_digest,
                self.project,
            )

    def test_current_source_verification_rejects_missing_local_image(self) -> None:
        with (
            mock.patch.object(loader, "require_executable", return_value="docker"),
            mock.patch.object(loader, "require_docker_ready", return_value="linux/arm64"),
            mock.patch.object(
                loader, "invalid_required_images", return_value=[self.reference]
            ),
            self.assertRaisesRegex(loader.SeedError, "absent or mismatched"),
        ):
            loader.verify_current(
                self.archive,
                self.manifest,
                self.manifest_digest,
                self.project,
            )

    def test_current_source_collector_rejects_symlinked_dockerfiles(self) -> None:
        dockerfile = self.project / "services" / "example" / "Dockerfile"
        outside = self.root / "outside.Dockerfile"
        outside.write_text(f"FROM {self.reference}\n", encoding="utf-8")
        dockerfile.unlink()
        dockerfile.symlink_to(outside)
        with self.assertRaisesRegex(loader.SeedError, "escapes|non-symlink"):
            loader.collect_current_image_references(self.project)

    def test_current_source_collector_includes_known_compose_overlays(self) -> None:
        platform_reference = (
            "registry.example/platform:1@sha256:" + "c" * 64
        )
        preprod_reference = (
            "registry.example/preprod:1@sha256:" + "d" * 64
        )
        self.project.joinpath("docker-compose.platform-dns.yml").write_text(
            f"services:\n  platform:\n    image: {platform_reference}\n"
        )
        self.project.joinpath("docker-compose.preprod.yml").write_text(
            f"services:\n  preprod:\n    image: {preprod_reference}\n"
        )
        samba = self.project / "services" / "samba-ad-preprod"
        samba.mkdir()
        samba.joinpath("Dockerfile").write_text(f"FROM {preprod_reference}\n")
        wif = self.project / "services" / "wif-provider-mock"
        wif.mkdir()
        wif.joinpath("Dockerfile").write_text(f"FROM {self.reference}\n")

        self.assertEqual(
            loader.collect_current_image_references(self.project),
            {self.reference, platform_reference, preprod_reference},
        )
        scopes = loader.collect_current_image_reference_scopes(self.project)
        self.assertEqual(
            scopes["production"], {self.reference, platform_reference}
        )
        self.assertEqual(
            scopes["preprod"],
            {self.reference, platform_reference, preprod_reference},
        )

    def test_ansible_proves_current_seed_before_build_with_pull_disabled(self) -> None:
        source = STACK_TASKS.read_text(encoding="utf-8")
        verify_position = source.index(
            "- name: Prove offline seed parity and local pins before any custom build"
        )
        build_position = source.index(
            "- name: Build only missing or build-input-changed custom images"
        )
        reconcile_position = source.index(
            "- name: Match custom-image plan to the reviewed offline release"
        )
        preserve_position = source.index(
            "- name: Preserve exact running images for planned build rollback"
        )
        activate_position = source.index(
            "- name: Activate tested custom images after rollback preservation"
        )
        self.assertLess(verify_position, build_position)
        self.assertLess(reconcile_position, preserve_position)
        self.assertLess(preserve_position, activate_position)
        self.assertLess(activate_position, build_position)
        build = source[build_position : source.index(
            "- name: Inventory the pinned CoreDNS runtime plugins", build_position
        )]
        self.assertIn("['build', '--pull=false']", build)


if __name__ == "__main__":
    unittest.main()
