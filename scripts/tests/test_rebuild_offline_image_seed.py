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
    "debian:13.6-slim@sha256:"
    "020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd"
)
PINNED_FRONTEND = (
    "docker/dockerfile:1.25.0@sha256:"
    "0adf442eae370b6087e08edc7c50b552d80ddf261576f4ebd6421006b2461f12"
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


def custom_inspection(image_id: str) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout=json.dumps(
            [{"Id": image_id, "Os": "linux", "Architecture": "arm64"}]
        ),
        stderr="",
    )


def egress_plan() -> builder.EgressPolicyPlan:
    receipt = {
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
    }
    return builder.EgressPolicyPlan(receipt, "anthropic", "4" * 64)


def sigstore_artifact_fixture() -> tuple[
    dict[str, object], set[str], dict[str, dict[str, object]], set[str]
]:
    parent_digest = "sha256:" + "1" * 64
    subject_digest = "sha256:" + "2" * 64
    artifact_digest = "sha256:" + "3" * 64
    config_digest = "sha256:" + "4" * 64
    layer_digest = "sha256:" + "5" * 64
    descriptor = {
        "mediaType": builder.OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        "digest": artifact_digest,
        "size": 401,
        "annotations": {"io.containerd.manifest.subject": subject_digest},
    }
    documents = {
        parent_digest: {
            "schemaVersion": 2,
            "manifests": [
                {
                    "mediaType": builder.OCI_IMAGE_MANIFEST_MEDIA_TYPE,
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
            "mediaType": builder.OCI_IMAGE_MANIFEST_MEDIA_TYPE,
            "artifactType": builder.SIGSTORE_BUNDLE_MEDIA_TYPE,
            "subject": {
                "mediaType": builder.OCI_IMAGE_MANIFEST_MEDIA_TYPE,
                "digest": subject_digest,
                "size": 211,
            },
            "config": {
                "mediaType": builder.OCI_EMPTY_MEDIA_TYPE,
                "artifactType": builder.SIGSTORE_BUNDLE_MEDIA_TYPE,
                "digest": config_digest,
                "size": 2,
            },
            "layers": [
                {
                    "mediaType": builder.SIGSTORE_BUNDLE_MEDIA_TYPE,
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


class OfflineImageSeedBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.digest = "sha256:" + "a" * 64
        self.image_id = "sha256:" + "b" * 64
        self.reference = f"registry.example/team/base:1.2@{self.digest}"
        self.tag = "registry.example/team/base:1.2"
        self.image = builder.SeedImage(self.reference, self.tag, self.image_id)

    def test_egress_planner_receives_repeated_names_and_returns_canonical_order(self) -> None:
        plan = egress_plan()
        client = mock.Mock()
        client.run.side_effect = [
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=json.dumps(plan.receipt, separators=(",", ":")) + "\n",
                stderr="",
            ),
        ]

        actual = builder.plan_egress_policy(
            client,
            SCRIPT.parents[1],
            "linux/arm64",
            ["anthropic", "anthropic"],
        )

        self.assertEqual(actual, plan)
        planner_run = client.run.call_args_list[1].args
        self.assertEqual(
            planner_run[-6:],
            (
                builder.ENVOY_POLICY_PLANNER_IMAGE,
                "plan",
                "--provider",
                "anthropic",
                "--provider",
                "anthropic",
            ),
        )

    def test_egress_planner_rejects_unknown_provider(self) -> None:
        client = mock.Mock()
        client.run.side_effect = [
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(
                args=[], returncode=1, stdout="", stderr='unknown provider "example.com"'
            ),
        ]
        with self.assertRaisesRegex(builder.SeedBuildError, "selection was rejected"):
            builder.plan_egress_policy(
                client,
                SCRIPT.parents[1],
                "linux/amd64",
                ["example.com"],
            )

    def test_egress_receipt_rejects_empty_or_duplicate_selection(self) -> None:
        for selected in ([], ["anthropic", "anthropic"]):
            receipt = dict(egress_plan().receipt)
            receipt["selected_providers"] = selected
            with self.assertRaisesRegex(builder.SeedBuildError, "canonical provider"):
                builder._validate_egress_receipt(receipt)

    def test_immutable_envoy_build_loads_and_checks_the_single_export(self) -> None:
        plan = egress_plan()
        image_id = "sha256:" + "9" * 64
        client = mock.Mock()

        def run(*arguments):
            if arguments[:2] == ("buildx", "build"):
                output = arguments[arguments.index("--output") + 1]
                destination = Path(output.split("dest=", 1)[1].split(",", 1)[0])
                destination.write_bytes(b"exact deterministic export")
                return subprocess.CompletedProcess(arguments, 0, "", "")
            if arguments[:2] == ("image", "load"):
                return subprocess.CompletedProcess(arguments, 0, "loaded", "")
            if arguments[:2] == ("image", "inspect"):
                record = {
                    "Id": image_id,
                    "Os": "linux",
                    "Architecture": "arm64",
                    "Config": {
                        "Labels": {
                            "com.aigw.egress-policy.schema": "1",
                            "com.aigw.egress-policy.providers": "anthropic",
                            "com.aigw.egress-policy.sha256": plan.policy_sha256,
                            "com.aigw.source-date-epoch": "0",
                        }
                    },
                }
                return subprocess.CompletedProcess(
                    arguments, 0, json.dumps([record]), ""
                )
            return subprocess.CompletedProcess(
                arguments,
                0,
                json.dumps(plan.receipt, separators=(",", ":")) + "\n",
                "",
            )

        client.run.side_effect = run
        actual = builder.build_immutable_envoy_image(
            client, SCRIPT.parents[1], "linux/arm64", plan
        )

        self.assertEqual(actual, image_id)
        build = client.run.call_args_list[0].args
        self.assertIn("--no-cache", build)
        self.assertIn("--network=none", build)
        self.assertIn("--provenance=false", build)
        self.assertIn("--sbom=false", build)
        output = build[build.index("--output") + 1]
        self.assertTrue(output.endswith(",rewrite-timestamp=true"))
        self.assertEqual(
            sum(call.args[:2] == ("image", "load") for call in client.run.call_args_list),
            1,
        )

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

    def test_pull_uses_the_requested_platform_for_every_exact_pin(self) -> None:
        client = mock.Mock()
        client.run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )

        builder.pull_images(client, [self.reference], "linux/amd64")

        client.run.assert_called_once_with(
            "image", "pull", "--platform", "linux/amd64", self.reference
        )

    def test_pull_reports_the_registry_login_needed_for_auth_failure(self) -> None:
        client = mock.Mock()
        client.run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="unauthorized: authentication required"
        )

        with self.assertRaisesRegex(
            builder.SeedBuildError, r"docker login registry\.example"
        ):
            builder.pull_images(client, [self.reference], "linux/arm64")

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

    def test_stale_tag_can_only_be_repaired_from_its_verified_pin(self) -> None:
        stale_digest = "sha256:" + "d" * 64
        client = mock.Mock()
        client.run.side_effect = [
            inspection(self.image_id, self.digest),
            inspection("sha256:" + "c" * 64, stale_digest),
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

    def test_oci_metadata_rejects_untagged_attestation_descriptor(self) -> None:
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
                    },
                    {
                        "digest": "sha256:" + "e" * 64,
                        "annotations": {
                            "io.containerd.manifest.subject": self.image_id,
                        },
                    },
                ],
            },
        }

        with self.assertRaisesRegex(
            builder.SeedBuildError, "unapproved untagged descriptor"
        ):
            builder._validate_export_metadata(metadata, [self.image])

    def test_external_sigstore_artifact_accepts_exact_verified_shape(self) -> None:
        descriptor, parents, documents, verified_blobs = sigstore_artifact_fixture()

        self.assertTrue(
            builder._approved_external_sigstore_artifact(
                descriptor, parents, documents, verified_blobs
            )
        )

    def test_external_sigstore_artifact_rejects_unapproved_parent_or_subject(self) -> None:
        descriptor, _, documents, verified_blobs = sigstore_artifact_fixture()
        unapproved_parent = {"sha256:" + "9" * 64}
        self.assertFalse(
            builder._approved_external_sigstore_artifact(
                descriptor, unapproved_parent, documents, verified_blobs
            )
        )

        descriptor, parents, documents, verified_blobs = sigstore_artifact_fixture()
        descriptor["annotations"] = {
            "io.containerd.manifest.subject": "sha256:" + "8" * 64
        }
        self.assertFalse(
            builder._approved_external_sigstore_artifact(
                descriptor, parents, documents, verified_blobs
            )
        )

    def test_external_sigstore_artifact_rejects_bad_media_type_or_unverified_blob(self) -> None:
        descriptor, parents, documents, verified_blobs = sigstore_artifact_fixture()
        artifact = documents[descriptor["digest"]]
        artifact["layers"][0]["mediaType"] = "application/octet-stream"
        self.assertFalse(
            builder._approved_external_sigstore_artifact(
                descriptor, parents, documents, verified_blobs
            )
        )

        descriptor, parents, documents, verified_blobs = sigstore_artifact_fixture()
        config_digest = documents[descriptor["digest"]]["config"]["digest"]
        verified_blobs.remove(config_digest)
        self.assertFalse(
            builder._approved_external_sigstore_artifact(
                descriptor, parents, documents, verified_blobs
            )
        )

    def test_oci_metadata_binds_a_custom_transfer_tag_to_its_image_id(self) -> None:
        custom = builder.CustomSeedImage(
            "ai-gateway/example:1",
            f"ai-gateway/example:aigw-seed-{self.image_id.removeprefix('sha256:')}",
            self.image_id,
        )
        metadata = {
            "manifest.json": [
                {"RepoTags": [self.tag]},
                {
                    "Config": f"{self.image_id.removeprefix('sha256:')}.json",
                    "RepoTags": [custom.archive_reference],
                },
            ],
            "index.json": {
                "schemaVersion": 2,
                "manifests": [
                    {
                        "digest": self.digest,
                        "annotations": {
                            "io.containerd.image.name": self.tag,
                            "containerd.io/distribution.source.registry.example": "team/base",
                        },
                    },
                    {
                        "digest": "sha256:" + "c" * 64,
                        "annotations": {
                            "io.containerd.image.name": (
                                "docker.io/" + custom.archive_reference
                            ),
                        },
                    },
                ],
            },
        }

        builder._validate_export_metadata(metadata, [self.image], [custom])
        # Docker's classic store reports the config digest as image ID. The
        # containerd store reports the top-level OCI index digest instead.
        metadata["manifest.json"][1]["Config"] = (
            "blobs/sha256/" + "d" * 64
        )
        metadata["index.json"]["manifests"][1]["digest"] = custom.image_id
        builder._validate_export_metadata(metadata, [self.image], [custom])

        metadata["index.json"]["manifests"][1]["digest"] = "sha256:" + "c" * 64
        with self.assertRaisesRegex(builder.SeedBuildError, "immutable image ID"):
            builder._validate_export_metadata(metadata, [self.image], [custom])

    def test_production_oci_metadata_has_no_samba_only_base_tag_descriptor_or_config(self) -> None:
        samba_id = "sha256:" + "d" * 64
        samba = builder.SeedImage(
            PINNED_DEBIAN,
            PINNED_DEBIAN.rsplit("@sha256:", 1)[0],
            samba_id,
        )
        production = {
            "manifest.json": [
                {
                    "Config": self.image_id[7:] + ".json",
                    "RepoTags": [self.tag],
                }
            ],
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
        preprod = json.loads(json.dumps(production))
        preprod["manifest.json"].append(
            {"Config": samba_id[7:] + ".json", "RepoTags": [samba.save_reference]}
        )
        preprod["index.json"]["manifests"].append(
            {
                "digest": "sha256:" + PINNED_DEBIAN.rsplit("@sha256:", 1)[1],
                "annotations": {
                            "io.containerd.image.name": "docker.io/library/debian:13.6-slim",
                    "containerd.io/distribution.source.docker.io": "library/debian",
                },
            }
        )

        builder._validate_export_metadata(production, [self.image])
        builder._validate_export_metadata(preprod, [self.image, samba])
        production_bytes = json.dumps(production, sort_keys=True)
        preprod_bytes = json.dumps(preprod, sort_keys=True)
        for value in (
            samba.save_reference,
            PINNED_DEBIAN.rsplit("@sha256:", 1)[1],
            samba_id[7:] + ".json",
        ):
            self.assertNotIn(value, production_bytes)
            self.assertIn(value, preprod_bytes)

    def test_custom_build_includes_preprod_samba_wif_and_provenance(self) -> None:
        production_id = "sha256:" + "c" * 64
        envoy_id = "sha256:" + "f" * 64
        samba_id = "sha256:" + "e" * 64
        wif_id = "sha256:" + "d" * 64
        model = {
            "services": {
                builder.ENVOY_SERVICE: {
                    "build": {
                        "context": str(
                            SCRIPT.parents[1] / "services/egress-proxy"
                        )
                    },
                    "image": builder.ENVOY_IMAGE,
                },
                "portal": {
                    "build": {"context": str(SCRIPT.parents[1] / "services/dev-portal")},
                    "image": "ai-gateway/portal:1",
                }
            }
        }
        compose_client = mock.Mock()
        compose_client.run.side_effect = [
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            custom_inspection(envoy_id),
            custom_inspection(production_id),
            custom_inspection(samba_id),
            custom_inspection(wif_id),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            custom_inspection(envoy_id),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            custom_inspection(production_id),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            custom_inspection(samba_id),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            custom_inspection(wif_id),
        ]

        def plan(rendered, **kwargs):
            self.assertIn("wif-provider-mock", rendered["services"])
            inspect_image = kwargs["image_inspector"]
            return {
                "manifest": {
                    "schema": 1,
                    "services": {
                        builder.ENVOY_SERVICE: {
                            "digest": "9" * 64,
                            "image": builder.ENVOY_IMAGE,
                            "image_id": inspect_image(builder.ENVOY_IMAGE),
                        },
                        "portal": {
                            "digest": "1" * 64,
                            "image": "ai-gateway/portal:1",
                            "image_id": inspect_image("ai-gateway/portal:1"),
                        },
                        "samba-ad": {
                            "digest": "3" * 64,
                            "image": builder.PREPROD_SAMBA_IMAGE,
                            "image_id": inspect_image(builder.PREPROD_SAMBA_IMAGE),
                        },
                        "wif-provider-mock": {
                            "digest": "2" * 64,
                            "image": builder.PREPROD_WIF_IMAGE,
                            "image_id": inspect_image(builder.PREPROD_WIF_IMAGE),
                        },
                    },
                }
            }

        planner = mock.Mock()
        planner.plan_compose_builds.side_effect = plan
        with (
            mock.patch.object(
                builder,
                "render_deployable_compose_model",
                return_value=(model, compose_client, [Path("compose.yml")]),
            ),
            mock.patch.object(
                builder, "_load_build_planner", return_value=planner
            ) as load_planner,
            mock.patch.object(
                builder, "build_immutable_envoy_image", return_value=envoy_id
            ) as build_envoy,
        ):
            custom_images, manifest = builder.build_custom_images(
                mock.Mock(),
                SCRIPT.parents[1],
                "linux/arm64",
                egress_plan(),
                privileged=False,
            )
        load_planner.assert_called_once_with(
            SCRIPT.parents[1], privileged=False
        )
        build_envoy.assert_called_once()

        by_image = {image.image: image for image in custom_images}
        self.assertEqual(by_image[builder.PREPROD_SAMBA_IMAGE].image_id, samba_id)
        self.assertEqual(
            by_image[builder.PREPROD_SAMBA_IMAGE].deployment_scope,
            "preprod-only",
        )
        self.assertEqual(
            by_image[builder.PREPROD_SAMBA_IMAGE].target_activation,
            "archive-only",
        )
        self.assertEqual(by_image[builder.PREPROD_WIF_IMAGE].image_id, wif_id)
        self.assertEqual(
            by_image[builder.PREPROD_WIF_IMAGE].deployment_scope,
            "preprod-only",
        )
        self.assertEqual(
            by_image[builder.PREPROD_WIF_IMAGE].target_activation,
            "archive-only",
        )
        self.assertIn("samba-ad", manifest["services"])
        self.assertIn("wif-provider-mock", manifest["services"])
        self.assertEqual(manifest["services"][builder.ENVOY_SERVICE]["image_id"], envoy_id)
        ordinary_builds = [
            call.args
            for call in compose_client.run.call_args_list
            if "build" in call.args and "portal" in call.args
        ]
        self.assertEqual(len(ordinary_builds), 1)
        self.assertIn("--pull=false", ordinary_builds[0])
        self.assertIn("--no-cache", ordinary_builds[0])
        self.assertIn("--provenance=false", ordinary_builds[0])
        self.assertIn("--sbom=false", ordinary_builds[0])
        self.assertIn(
            mock.call(
                "build",
                "--pull=false",
                "--no-cache",
                "--provenance=false",
                "--sbom=false",
                "--platform",
                "linux/arm64",
                "--network",
                "none",
                "--tag",
                builder.PREPROD_WIF_IMAGE,
                "--file",
                str(SCRIPT.parents[1] / "services/wif-provider-mock/Dockerfile"),
                str(SCRIPT.parents[1] / "services/wif-provider-mock"),
            ),
            compose_client.run.call_args_list,
        )

    def test_one_build_result_splits_production_from_full_preprod_release(self) -> None:
        production_id = "sha256:" + "1" * 64
        envoy_id = "sha256:" + "9" * 64
        samba_id = "sha256:" + "2" * 64
        wif_id = "sha256:" + "3" * 64
        custom = [
            builder.CustomSeedImage(
                builder.ENVOY_IMAGE,
                "ai-gateway/envoy-egress:aigw-seed-" + envoy_id[7:],
                envoy_id,
            ),
            builder.CustomSeedImage(
                "ai-gateway/portal:1",
                "ai-gateway/portal:aigw-seed-" + production_id[7:],
                production_id,
            ),
            builder.CustomSeedImage(
                builder.PREPROD_SAMBA_IMAGE,
                "ai-gateway/samba-ad:aigw-seed-" + samba_id[7:],
                samba_id,
                deployment_scope="preprod-only",
                target_activation="archive-only",
            ),
            builder.CustomSeedImage(
                builder.PREPROD_WIF_IMAGE,
                "ai-gateway/wif-provider-mock:aigw-seed-" + wif_id[7:],
                wif_id,
                deployment_scope="preprod-only",
                target_activation="archive-only",
            ),
        ]
        inputs = {
            "schema": 1,
            "services": {
                builder.ENVOY_SERVICE: {
                    "digest": "9" * 64,
                    "image": builder.ENVOY_IMAGE,
                    "image_id": envoy_id,
                },
                "portal": {
                    "digest": "4" * 64,
                    "image": "ai-gateway/portal:1",
                    "image_id": production_id,
                },
                "samba-ad": {
                    "digest": "5" * 64,
                    "image": builder.PREPROD_SAMBA_IMAGE,
                    "image_id": samba_id,
                },
                "wif-provider-mock": {
                    "digest": "6" * 64,
                    "image": builder.PREPROD_WIF_IMAGE,
                    "image_id": wif_id,
                },
            },
        }

        production, production_inputs = builder.scoped_custom_release(
            custom, inputs, builder.RELEASE_SCOPE_PRODUCTION
        )
        preprod, preprod_inputs = builder.scoped_custom_release(
            custom, inputs, builder.RELEASE_SCOPE_PREPROD
        )

        self.assertEqual(
            [image.image for image in production],
            [builder.ENVOY_IMAGE, "ai-gateway/portal:1"],
        )
        self.assertEqual(
            set(production_inputs["services"]), {builder.ENVOY_SERVICE, "portal"}
        )
        self.assertEqual(preprod, custom)
        self.assertEqual(
            set(preprod_inputs["services"]),
            {builder.ENVOY_SERVICE, "portal", "samba-ad", "wif-provider-mock"},
        )

        production_manifest = builder.build_manifest(
            Path("/release/aigw.docker.tar.zst"),
            "linux/amd64",
            [self.image],
            production,
            production_inputs,
            builder.RELEASE_SCOPE_PRODUCTION,
            builder.egress_policy_release_receipt(egress_plan(), custom),
        )
        preprod_manifest = builder.build_manifest(
            Path("/release/aigw.preprod.docker.tar.zst"),
            "linux/amd64",
            [self.image],
            preprod,
            preprod_inputs,
            builder.RELEASE_SCOPE_PREPROD,
            builder.egress_policy_release_receipt(egress_plan(), custom),
        )
        self.assertEqual(production_manifest["release_scope"], "production")
        self.assertEqual(preprod_manifest["release_scope"], "preprod")
        self.assertEqual(
            production_manifest["egress_policy"]["envoy_image_id"], envoy_id
        )
        encoded_production = json.dumps(production_manifest)
        self.assertNotIn("ai-gateway/samba-ad", encoded_production)
        self.assertNotIn("ai-gateway/wif-provider-mock", encoded_production)

    def test_preprod_output_paths_are_deterministic_or_explicit_as_a_pair(self) -> None:
        archive = Path("/release/aigw.docker.tar.zst")
        manifest = Path("/release/aigw.manifest.json")
        self.assertEqual(
            builder.preprod_output_paths(archive, manifest),
            (
                Path("/release/aigw.preprod.docker.tar.zst"),
                Path("/release/aigw.preprod.manifest.json"),
            ),
        )
        explicit = (
            Path("/release/full.docker.tar.zst"),
            Path("/release/full.manifest.json"),
        )
        self.assertEqual(
            builder.preprod_output_paths(archive, manifest, *explicit), explicit
        )
        with self.assertRaisesRegex(builder.SeedBuildError, "supplied together"):
            builder.preprod_output_paths(archive, manifest, explicit[0], None)

    def test_schema_two_builder_requires_a_provider_selection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch("sys.stderr", new_callable=mock.MagicMock) as stderr:
                result = builder.main(
                    [
                        "--build-custom",
                        "--platform",
                        "linux/arm64",
                        "--allow-unprivileged-controller",
                        str(root / "release.docker.tar.zst"),
                        str(root / "release.manifest.json"),
                    ]
                )
        self.assertEqual(result, 1)
        self.assertIn("at least one --provider", str(stderr.write.call_args_list))

    def test_prepare_release_builds_once_and_exports_two_scoped_archives(self) -> None:
        production_id = "sha256:" + "1" * 64
        envoy_id = "sha256:" + "9" * 64
        samba_id = "sha256:" + "2" * 64
        wif_id = "sha256:" + "3" * 64
        custom = [
            builder.CustomSeedImage(
                builder.ENVOY_IMAGE,
                "ai-gateway/envoy-egress:aigw-seed-" + envoy_id[7:],
                envoy_id,
            ),
            builder.CustomSeedImage(
                "ai-gateway/portal:1",
                "ai-gateway/portal:aigw-seed-" + production_id[7:],
                production_id,
            ),
            builder.CustomSeedImage(
                builder.PREPROD_SAMBA_IMAGE,
                "ai-gateway/samba-ad:aigw-seed-" + samba_id[7:],
                samba_id,
                "preprod-only",
                "archive-only",
            ),
            builder.CustomSeedImage(
                builder.PREPROD_WIF_IMAGE,
                "ai-gateway/wif-provider-mock:aigw-seed-" + wif_id[7:],
                wif_id,
                "preprod-only",
                "archive-only",
            ),
        ]
        inputs = {
            "schema": 1,
            "services": {
                builder.ENVOY_SERVICE: {
                    "digest": "9" * 64,
                    "image": builder.ENVOY_IMAGE,
                    "image_id": envoy_id,
                },
                "portal": {
                    "digest": "4" * 64,
                    "image": "ai-gateway/portal:1",
                    "image_id": production_id,
                },
                "samba-ad": {
                    "digest": "5" * 64,
                    "image": builder.PREPROD_SAMBA_IMAGE,
                    "image_id": samba_id,
                },
                "wif-provider-mock": {
                    "digest": "6" * 64,
                    "image": builder.PREPROD_WIF_IMAGE,
                    "image_id": wif_id,
                },
            },
        }
        samba_base = builder.SeedImage(
            PINNED_DEBIAN,
            PINNED_DEBIAN.rsplit("@sha256:", 1)[0],
            "sha256:" + "7" * 64,
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "aigw.docker.tar.zst"
            manifest = root / "aigw.manifest.json"

            def save(path, scoped_external, scoped_custom, *_args):
                path.write_bytes(
                    "\n".join(
                        [
                            *(image.reference for image in scoped_external),
                            *(image.image for image in scoped_custom),
                        ]
                    ).encode()
                )
                path.chmod(0o600)

            with (
                mock.patch.object(
                    builder,
                    "collect_project_image_reference_scopes",
                    return_value={
                        "production": {self.reference},
                        "preprod": {self.reference, PINNED_DEBIAN},
                    },
                ),
                mock.patch.object(builder, "resolve_docker_client", return_value=mock.Mock()),
                mock.patch.object(builder, "platform", return_value="linux/arm64"),
                mock.patch.object(builder, "pull_images"),
                mock.patch.object(
                    builder, "inspect_images", return_value=[self.image, samba_base]
                ),
                mock.patch.object(
                    builder, "plan_egress_policy", return_value=egress_plan()
                ) as plan_policy,
                mock.patch.object(
                    builder, "build_custom_images", return_value=(custom, inputs)
                ) as build,
                mock.patch.object(builder, "_find_executable", return_value="zstd"),
                mock.patch.object(builder, "_stream_save", side_effect=save) as stream,
                mock.patch("sys.stdout", new_callable=mock.MagicMock),
            ):
                result = builder.main(
                    [
                        "--prepare-release",
                        "--platform",
                        "linux/arm64",
                        "--provider",
                        "anthropic",
                        "--allow-unprivileged-controller",
                        "--project-root",
                        str(SCRIPT.parents[1]),
                        str(archive),
                        str(manifest),
                    ]
                )

            self.assertEqual(result, 0)
            build.assert_called_once()
            plan_policy.assert_called_once()
            self.assertEqual(stream.call_count, 2)
            production_external = stream.call_args_list[0].args[1]
            preprod_external = stream.call_args_list[1].args[1]
            production_custom = stream.call_args_list[0].args[2]
            preprod_custom = stream.call_args_list[1].args[2]
            self.assertEqual(
                [image.reference for image in production_external], [self.reference]
            )
            self.assertEqual(
                {image.reference for image in preprod_external},
                {self.reference, PINNED_DEBIAN},
            )
            self.assertEqual(
                [image.image for image in production_custom],
                [builder.ENVOY_IMAGE, "ai-gateway/portal:1"],
            )
            self.assertEqual([image.image for image in preprod_custom], [
                builder.ENVOY_IMAGE,
                "ai-gateway/portal:1",
                builder.PREPROD_SAMBA_IMAGE,
                builder.PREPROD_WIF_IMAGE,
            ])
            production_manifest = json.loads(manifest.read_text())
            preprod_manifest = json.loads(
                (root / "aigw.preprod.manifest.json").read_text()
            )
            self.assertEqual(production_manifest["release_scope"], "production")
            self.assertEqual(preprod_manifest["release_scope"], "preprod")
            self.assertNotIn(PINNED_DEBIAN, archive.read_text())
            self.assertIn(
                PINNED_DEBIAN,
                (root / "aigw.preprod.docker.tar.zst").read_text(),
            )

    def test_privileged_planner_rejects_writable_file(self) -> None:
        with tempfile.TemporaryDirectory(dir=SCRIPT.parents[1]) as temporary:
            project = Path(temporary)
            scripts = project / "scripts"
            scripts.mkdir()
            planner = scripts / "plan-compose-builds.py"
            planner.write_text("VALUE = 1\n", encoding="utf-8")
            planner.chmod(0o664)

            with (
                mock.patch.multiple(
                    builder,
                    ROOT_UID=os.getuid(),
                    ROOT_GID=os.getgid(),
                ),
                self.assertRaisesRegex(
                    builder.SeedBuildError, "group- or world-writable"
                ),
            ):
                builder._load_build_planner(project, privileged=True)

            planner.chmod(0o644)
            scripts.chmod(0o775)
            with (
                mock.patch.multiple(
                    builder,
                    ROOT_UID=os.getuid(),
                    ROOT_GID=os.getgid(),
                ),
                self.assertRaisesRegex(
                    builder.SeedBuildError, "group- or world-writable"
                ),
            ):
                builder._load_build_planner(project, privileged=True)

    def test_privileged_planner_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory(dir=SCRIPT.parents[1]) as temporary:
            project = Path(temporary)
            scripts = project / "scripts"
            scripts.mkdir()
            target = scripts / "reviewed-planner.py"
            target.write_text("VALUE = 1\n", encoding="utf-8")
            (scripts / "plan-compose-builds.py").symlink_to(target)

            with (
                mock.patch.multiple(
                    builder,
                    ROOT_UID=os.getuid(),
                    ROOT_GID=os.getgid(),
                ),
                self.assertRaisesRegex(builder.SeedBuildError, "symlinks"),
            ):
                builder._load_build_planner(project, privileged=True)

            (scripts / "plan-compose-builds.py").unlink()
            scripts.rename(project / "reviewed-scripts")
            scripts.symlink_to(project / "reviewed-scripts", target_is_directory=True)
            with (
                mock.patch.multiple(
                    builder,
                    ROOT_UID=os.getuid(),
                    ROOT_GID=os.getgid(),
                ),
                self.assertRaisesRegex(builder.SeedBuildError, "real directories"),
            ):
                builder._load_build_planner(project, privileged=True)

    def test_privileged_planner_requires_root_root_owner(self) -> None:
        with tempfile.TemporaryDirectory(dir=SCRIPT.parents[1]) as temporary:
            project = Path(temporary)
            scripts = project / "scripts"
            scripts.mkdir()
            planner = scripts / "plan-compose-builds.py"
            planner.write_text("VALUE = 1\n", encoding="utf-8")

            with (
                mock.patch.multiple(
                    builder,
                    ROOT_UID=os.getuid(),
                    ROOT_GID=os.getgid() + 1,
                ),
                self.assertRaisesRegex(builder.SeedBuildError, "root:root"),
            ):
                builder._load_build_planner(project, privileged=True)

    def test_nonroot_planner_keeps_local_user_owned_behavior(self) -> None:
        with tempfile.TemporaryDirectory(dir=SCRIPT.parents[1]) as temporary:
            project = Path(temporary)
            scripts = project / "scripts"
            scripts.mkdir()
            planner = scripts / "plan-compose-builds.py"
            planner.write_text("VALUE = 42\n", encoding="utf-8")
            planner.chmod(0o666)

            module = builder._load_build_planner(project, privileged=False)

            self.assertEqual(module.VALUE, 42)

    def test_collector_covers_every_current_build_and_runtime_pin(self) -> None:
        project_root = SCRIPT.parents[1]
        scopes = builder.collect_project_image_reference_scopes(project_root)
        references = scopes["preprod"]

        self.assertEqual(len(references), 24)
        self.assertIn(PINNED_DEBIAN, references)
        self.assertIn(PINNED_FRONTEND, references)
        self.assertIn(
            "dhi.io/golang:1.26.5-alpine-dev@sha256:"
            "711ea0b8f09f549c50f2f550dc26859d3e6441ca11d5640caecf69c29a862f0c",
            references,
        )
        self.assertNotIn(PINNED_DEBIAN, scopes["production"])
        self.assertIn(PINNED_DEBIAN, scopes["preprod"])
        self.assertIn(
            "dhi.io/golang:1.26.5-alpine-dev@sha256:"
            "711ea0b8f09f549c50f2f550dc26859d3e6441ca11d5640caecf69c29a862f0c",
            scopes["production"],
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

    def test_collector_includes_platform_and_preprod_compose_pins(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            compose = project / "compose"
            service = project / "services" / "example"
            compose.mkdir()
            service.mkdir(parents=True)
            compose.joinpath("docker-compose.yml").write_text(
                f"services:\n  base:\n    image: {self.reference}\n"
            )
            platform_reference = (
                "registry.example/platform:1@sha256:" + "c" * 64
            )
            compose.joinpath("docker-compose.platform-dns.yml").write_text(
                f"services:\n  platform:\n    image: {platform_reference}\n"
            )
            preprod_reference = (
                "registry.example/preprod:1@sha256:" + "d" * 64
            )
            compose.joinpath("docker-compose.preprod.yml").write_text(
                f"services:\n  preprod:\n    image: {preprod_reference}\n"
            )
            service.joinpath("Dockerfile").write_text("FROM scratch\n")

            self.assertEqual(
                builder.collect_project_image_references(project),
                {self.reference, platform_reference, preprod_reference},
            )
            scopes = builder.collect_project_image_reference_scopes(project)
            self.assertEqual(
                scopes["production"], {self.reference, platform_reference}
            )
            self.assertEqual(
                scopes["preprod"],
                {self.reference, platform_reference, preprod_reference},
            )

    def test_release_build_does_not_depend_on_the_retired_lab_overlay(self) -> None:
        compose_files = builder._compose_files(SCRIPT.parents[1])
        self.assertNotIn("docker-compose.lab.yml", {path.name for path in compose_files})
        command = builder._compose_command(SCRIPT.parents[1], compose_files)
        self.assertNotIn("lab-ad", command)

    def test_only_local_unix_docker_endpoints_are_accepted(self) -> None:
        self.assertEqual(
            builder.validate_local_docker_host("unix:///private/tmp/docker.sock"),
            "unix:///private/tmp/docker.sock",
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

    def test_local_controller_home_supports_docker_desktop_credentials_only(self) -> None:
        policy = builder.OutputPolicy(os.geteuid(), os.getegid(), False)
        environment = builder._docker_environment(Path.home() / ".docker", policy)

        self.assertEqual(environment["HOME"], str(Path.home().resolve()))
        self.assertEqual(environment["DOCKER_CONFIG"], str(Path.home() / ".docker"))
        self.assertNotIn("DOCKER_HOST", environment)
        self.assertNotIn("DOCKER_CONTEXT", environment)

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
