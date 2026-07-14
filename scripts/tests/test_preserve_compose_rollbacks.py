from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "preserve-compose-rollbacks.py"
SPEC = importlib.util.spec_from_file_location("preserve_compose_rollbacks", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
preserver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preserver)


OLD_IMAGE = "sha256:" + "a" * 64
OTHER_IMAGE = "sha256:" + "b" * 64
NEW_IMAGE = "sha256:" + "1" * 64
CONTAINER_ID = "c" * 64
OTHER_CONTAINER_ID = "d" * 64


class FakeDocker:
    def __init__(
        self,
        image: str,
        *,
        service: str = "key-rotator",
        image_id: str = OLD_IMAGE,
        container_id: str = CONTAINER_ID,
    ) -> None:
        self.image = image
        self.service = service
        self.images: dict[str, str] = {image: image_id, image_id: image_id}
        self.container_lists: list[list[str]] = [[container_id], [container_id]]
        self.container = self._container(container_id, image_id)
        self.ready_calls = 0
        self.tag_calls: list[tuple[str, str]] = []
        self.break_tag_verification = False
        self.image_inspect_sequences: dict[str, list[str | None]] = {}
        self.dependency_gate_proven = False
        self.dependency_gate_calls: list[tuple[str, str]] = []

    def _container(self, identifier: str, image_id: str) -> dict[str, object]:
        return {
            "Id": identifier,
            "Image": image_id,
            "Config": {
                "Image": self.image,
                "Labels": {
                    "com.docker.compose.project": "ai-gateway",
                    "com.docker.compose.service": self.service,
                    "com.docker.compose.oneoff": "False",
                    "com.docker.compose.container-number": "1",
                },
            },
            "State": {
                "Running": True,
                "Status": "running",
                "Restarting": False,
                "Dead": False,
                "Health": {"Status": "healthy"},
            },
            "RestartCount": 0,
        }

    def ensure_ready(self) -> None:
        self.ready_calls += 1

    def list_service_containers(self, project: str, service: str) -> list[str]:
        assert project == "ai-gateway"
        assert service == self.service
        if len(self.container_lists) > 1:
            return self.container_lists.pop(0)
        return list(self.container_lists[0])

    def inspect_container(self, identifier: str) -> dict[str, object]:
        if identifier != self.container["Id"]:
            raise preserver.PreserveError("unknown fake container")
        return dict(self.container)

    def inspect_image(self, reference: str, *, allow_missing: bool = False) -> str | None:
        sequence = self.image_inspect_sequences.get(reference)
        if sequence:
            result = sequence.pop(0)
            if result is None and not allow_missing:
                raise preserver.PreserveError(f"missing fake image: {reference}")
            return result
        if reference in self.images:
            return self.images[reference]
        if allow_missing:
            return None
        raise preserver.PreserveError(f"missing fake image: {reference}")

    def tag_image(self, source_image_id: str, target_reference: str) -> None:
        self.tag_calls.append((source_image_id, target_reference))
        self.images[target_reference] = (
            OTHER_IMAGE if self.break_tag_verification else source_image_id
        )

    def prove_key_rotator_dependency_gate(
        self,
        project: str,
        identifier: str,
        container: dict[str, object],
    ) -> bool:
        assert project == "ai-gateway"
        assert identifier == self.container["Id"]
        assert container["Id"] == identifier
        self.dependency_gate_calls.append((project, identifier))
        return self.dependency_gate_proven


class ComposeRollbackPreservationTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.stack = Path(temporary.name) / "stack"
        self.state = self.stack / ".state"
        self.state.mkdir(parents=True)
        self.stack.chmod(0o750)
        self.state.chmod(0o700)
        self.image = "ai-gateway-key-rotator"
        self.rollback = preserver.rollback_reference(
            self.image, "ai-gateway", "key-rotator", OLD_IMAGE
        )
        self.plan: dict[str, object] = {
            "services": ["key-rotator"],
            "manifest": {
                "schema": 1,
                "services": {
                    "key-rotator": {
                        "digest": "e" * 64,
                        "image": self.image,
                        "image_id": OLD_IMAGE,
                    }
                },
            },
        }
        self.root_ids = mock.patch.multiple(
            preserver, ROOT_UID=os.getuid(), ROOT_GID=os.getgid()
        )
        self.root_ids.start()
        self.addCleanup(self.root_ids.stop)

    def preserve(self, docker: FakeDocker) -> dict[str, object]:
        return preserver.preserve_rollbacks(
            self.plan,
            stack=self.stack,
            project="ai-gateway",
            docker=docker,
        )

    def write_manifest(self, services: dict[str, object]) -> Path:
        path = self.state / preserver.MANIFEST_NAME
        path.write_text(
            json.dumps(
                {
                    "schema": preserver.ROLLBACK_SCHEMA,
                    "project": "ai-gateway",
                    "services": services,
                }
            )
        )
        path.chmod(0o600)
        return path

    def write_completed_build_receipt(self, payload: str | None = None) -> Path:
        """Create the root-only marker written after a successful image build."""
        if payload is None:
            payload = json.dumps(self.plan["manifest"])
        path = self.state / preserver.BUILD_INPUTS_NAME
        path.write_text(payload)
        path.chmod(0o600)
        return path

    def test_running_immutable_image_is_tagged_and_manifested_atomically(self) -> None:
        docker = FakeDocker(self.image)
        result = self.preserve(docker)

        self.assertEqual(docker.ready_calls, 1)
        self.assertEqual(docker.tag_calls, [(OLD_IMAGE, self.rollback)])
        record = result["services"]["key-rotator"]  # type: ignore[index]
        self.assertEqual(record["status"], "preserved")
        self.assertEqual(record["container_id"], CONTAINER_ID)
        self.assertEqual(record["source_image_id"], OLD_IMAGE)
        self.assertEqual(record["rollback_image"], self.rollback)
        self.assertEqual(result["updated_services"], ["key-rotator"])

        manifest = self.state / preserver.MANIFEST_NAME
        persisted = dict(result)
        persisted.pop("updated_services")
        self.assertEqual(json.loads(manifest.read_text()), persisted)
        metadata = manifest.stat()
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
        self.assertEqual(metadata.st_nlink, 1)
        self.assertEqual((metadata.st_uid, metadata.st_gid), (os.getuid(), os.getgid()))

    def test_first_build_is_explicit_only_when_all_image_state_is_absent(self) -> None:
        self.plan["manifest"]["services"]["key-rotator"]["image_id"] = None  # type: ignore[index]
        docker = FakeDocker(self.image)
        docker.images.clear()
        docker.container_lists = [[], []]

        result = self.preserve(docker)
        record = result["services"]["key-rotator"]  # type: ignore[index]
        self.assertEqual(record["status"], "first-build")
        self.assertIsNone(record["container_id"])
        self.assertIsNone(record["source_image_id"])
        self.assertIsNone(record["rollback_image"])
        self.assertEqual(docker.tag_calls, [])

        (self.state / preserver.MANIFEST_NAME).unlink()
        docker = FakeDocker(self.image)
        docker.container_lists = [[], []]
        with self.assertRaisesRegex(preserver.PreserveError, "build plan"):
            self.preserve(docker)

    def test_clean_first_build_allows_exact_preseeded_planned_image(self) -> None:
        # The clean Rocky reset seeds reviewed custom images so the first
        # Compose build can run offline.  Before a successful-build receipt
        # exists, that exact planned image is not evidence of an older runtime
        # generation and must be represented as an explicit first build.
        docker = FakeDocker(self.image)
        docker.container_lists = [[], []]

        result = self.preserve(docker)

        record = result["services"]["key-rotator"]  # type: ignore[index]
        self.assertEqual(record["status"], "first-build")
        self.assertEqual(record["planned_image_id"], OLD_IMAGE)
        self.assertIsNone(record["container_id"])
        self.assertIsNone(record["source_image_id"])
        self.assertIsNone(record["rollback_image"])
        self.assertEqual(docker.tag_calls, [])

    def test_completed_build_receipt_disallows_preseeded_image_without_container(self) -> None:
        # Once Ansible has durably recorded a successful custom-image build,
        # a missing service container must never be mistaken for first deploy.
        self.write_completed_build_receipt()
        docker = FakeDocker(self.image)
        docker.container_lists = [[], []]

        with self.assertRaisesRegex(
            preserver.PreserveError, "no authoritative container"
        ):
            self.preserve(docker)
        self.assertEqual(docker.tag_calls, [])

    def test_new_service_can_start_after_valid_receipt_omits_it(self) -> None:
        # A later-added service has no historical runtime merely because other
        # services are present in a completed deployment receipt. An empty
        # rollback inventory is normal after first-build proofs are retired.
        self.write_manifest({})
        self.write_completed_build_receipt(
            json.dumps(
                {
                    "schema": 1,
                    "services": {
                        "portal": {
                            "digest": "f" * 64,
                            "image": "ai-gateway-portal",
                            "image_id": OTHER_IMAGE,
                        }
                    },
                }
            )
        )
        docker = FakeDocker(self.image)
        docker.container_lists = [[], []]

        result = self.preserve(docker)

        self.assertEqual(
            result["services"]["key-rotator"]["status"],  # type: ignore[index]
            "first-build",
        )

    def test_existing_rollback_manifest_without_receipt_is_not_clean_deploy(self) -> None:
        # A deleted build receipt must not reclassify a historical stack as a
        # clean deployment. Normal completed first builds retain an empty
        # rollback inventory after their retry proofs are retired.
        self.write_manifest({})
        docker = FakeDocker(self.image)
        docker.container_lists = [[], []]

        with self.assertRaisesRegex(
            preserver.PreserveError, "no authoritative container"
        ):
            self.preserve(docker)
        self.assertEqual(docker.tag_calls, [])

    def test_malformed_completed_build_receipt_fails_before_docker(self) -> None:
        self.write_completed_build_receipt("{}")
        docker = FakeDocker(self.image)
        docker.container_lists = [[], []]

        with self.assertRaisesRegex(
            preserver.PreserveError, "build-input receipt envelope"
        ):
            self.preserve(docker)
        self.assertEqual(docker.ready_calls, 0)
        self.assertEqual(docker.tag_calls, [])

    def test_unsafe_completed_build_receipt_fails_closed(self) -> None:
        receipt = self.state / preserver.BUILD_INPUTS_NAME
        outside = self.stack / "untrusted-build-inputs.json"
        outside.write_text("{}")

        receipt.symlink_to(outside)
        docker = FakeDocker(self.image)
        docker.container_lists = [[], []]
        with self.assertRaisesRegex(preserver.PreserveError, "build-input receipt"):
            self.preserve(docker)
        self.assertEqual(docker.tag_calls, [])

        receipt.unlink()
        self.write_completed_build_receipt()
        receipt.chmod(0o644)
        docker = FakeDocker(self.image)
        docker.container_lists = [[], []]
        with self.assertRaisesRegex(preserver.PreserveError, "build-input receipt"):
            self.preserve(docker)
        self.assertEqual(docker.tag_calls, [])

    def test_interrupted_first_build_with_committed_proof_is_retryable(self) -> None:
        self.plan["manifest"]["services"]["key-rotator"]["image_id"] = None  # type: ignore[index]
        first = FakeDocker(self.image)
        first.images.clear()
        first.container_lists = [[], []]
        self.preserve(first)

        # Model a successful/partial image build before Ansible persisted the
        # build-input marker or created the service container.
        self.plan["manifest"]["services"]["key-rotator"]["digest"] = "f" * 64  # type: ignore[index]
        self.plan["manifest"]["services"]["key-rotator"]["image_id"] = OLD_IMAGE  # type: ignore[index]
        retry = FakeDocker(self.image)
        retry.container_lists = [[], []]

        result = self.preserve(retry)

        record = result["services"]["key-rotator"]  # type: ignore[index]
        self.assertEqual(record["status"], "first-build")
        self.assertEqual(record["planned_image_id"], OLD_IMAGE)
        self.assertIsNone(record["rollback_image"])
        self.assertEqual(retry.tag_calls, [])

    def test_successful_build_marker_retires_first_build_retry_proof(self) -> None:
        self.plan["manifest"]["services"]["key-rotator"]["image_id"] = None  # type: ignore[index]
        first = FakeDocker(self.image)
        first.images.clear()
        first.container_lists = [[], []]
        self.preserve(first)

        successful = json.loads(json.dumps(self.plan["manifest"]))
        successful["services"]["key-rotator"]["image_id"] = OLD_IMAGE
        result = preserver.retire_first_build_records(
            successful,
            stack=self.stack,
            project="ai-gateway",
        )

        self.assertEqual(result["retired_services"], ["key-rotator"])
        self.assertEqual(result["services"], {})
        persisted = json.loads((self.state / preserver.MANIFEST_NAME).read_text())
        self.assertEqual(persisted["services"], {})

        # The real successful-build receipt is what closes the clean deploy
        # window even after its first-build rollback proof has been retired.
        self.write_completed_build_receipt(json.dumps(successful))

        # The stale initial-deployment proof can no longer authorize a future
        # no-container build merely because an image tag exists.
        self.plan["manifest"]["services"]["key-rotator"]["digest"] = "f" * 64  # type: ignore[index]
        self.plan["manifest"]["services"]["key-rotator"]["image_id"] = OLD_IMAGE  # type: ignore[index]
        missing = FakeDocker(self.image)
        missing.container_lists = [[], []]
        with self.assertRaisesRegex(preserver.PreserveError, "no authoritative container"):
            self.preserve(missing)

    def test_multiple_or_stopped_containers_fail_before_tagging(self) -> None:
        docker = FakeDocker(self.image)
        docker.container_lists = [[CONTAINER_ID, OTHER_CONTAINER_ID]]
        with self.assertRaisesRegex(preserver.PreserveError, "multiple containers"):
            self.preserve(docker)
        self.assertEqual(docker.tag_calls, [])

        docker = FakeDocker(self.image)
        docker.container["State"]["Running"] = False  # type: ignore[index]
        docker.container["State"]["Status"] = "exited"  # type: ignore[index]
        with self.assertRaisesRegex(preserver.PreserveError, "not stably running"):
            self.preserve(docker)
        self.assertEqual(docker.tag_calls, [])

    def test_restarted_or_unhealthy_source_is_never_made_the_rollback(self) -> None:
        docker = FakeDocker(self.image)
        docker.container["RestartCount"] = 1
        with self.assertRaisesRegex(preserver.PreserveError, "has restarted"):
            self.preserve(docker)
        self.assertEqual(docker.tag_calls, [])

        docker = FakeDocker(self.image)
        docker.container["State"]["Health"]["Status"] = "starting"  # type: ignore[index]
        with self.assertRaisesRegex(preserver.PreserveError, "not healthy"):
            self.preserve(docker)
        self.assertEqual(docker.tag_calls, [])

        docker = FakeDocker(self.image)
        del docker.container["State"]["Health"]  # type: ignore[index]
        with self.assertRaisesRegex(preserver.PreserveError, "not healthy"):
            self.preserve(docker)
        self.assertEqual(docker.tag_calls, [])

    def test_exact_sealed_vault_dependency_gate_can_preserve_rotator(self) -> None:
        docker = FakeDocker(self.image)
        docker.container["State"]["Health"]["Status"] = "unhealthy"  # type: ignore[index]
        docker.dependency_gate_proven = True

        result = self.preserve(docker)

        self.assertEqual(
            result["services"]["key-rotator"]["status"],  # type: ignore[index]
            "preserved",
        )
        self.assertEqual(
            docker.dependency_gate_calls,
            [
                ("ai-gateway", CONTAINER_ID),
                ("ai-gateway", CONTAINER_ID),
            ],
        )

    def test_unproven_unhealthy_rotator_is_never_preserved(self) -> None:
        docker = FakeDocker(self.image)
        docker.container["State"]["Health"]["Status"] = "unhealthy"  # type: ignore[index]

        with self.assertRaisesRegex(preserver.PreserveError, "not healthy"):
            self.preserve(docker)

        self.assertEqual(
            docker.dependency_gate_calls,
            [("ai-gateway", CONTAINER_ID)],
        )
        self.assertEqual(docker.tag_calls, [])

    def test_moved_tag_or_mismatched_container_reference_fails_closed(self) -> None:
        docker = FakeDocker(self.image)
        docker.images[self.image] = OTHER_IMAGE
        with self.assertRaisesRegex(preserver.PreserveError, "build plan"):
            self.preserve(docker)
        self.assertEqual(docker.tag_calls, [])

        docker = FakeDocker(self.image)
        docker.container["Config"]["Image"] = "ai-gateway-key-rotator:other"  # type: ignore[index]
        with self.assertRaisesRegex(preserver.PreserveError, "reference drifted"):
            self.preserve(docker)

    def test_interrupted_build_with_preserved_running_source_is_retryable(self) -> None:
        self.preserve(FakeDocker(self.image))

        # The desired tag moved, but Compose has not deployed it and the exact
        # running generation is still named by the committed rollback record.
        self.plan["manifest"]["services"]["key-rotator"]["digest"] = "f" * 64  # type: ignore[index]
        self.plan["manifest"]["services"]["key-rotator"]["image_id"] = OTHER_IMAGE  # type: ignore[index]
        retry = FakeDocker(self.image)
        retry.images[self.image] = OTHER_IMAGE
        retry.images[self.rollback] = OLD_IMAGE

        result = self.preserve(retry)

        record = result["services"]["key-rotator"]  # type: ignore[index]
        self.assertEqual(record["source_image_id"], OLD_IMAGE)
        self.assertEqual(record["planned_image_id"], OTHER_IMAGE)
        self.assertEqual(record["rollback_image"], self.rollback)
        self.assertEqual(retry.tag_calls, [])

    def test_content_addressed_tag_survives_interrupted_manifest_commit(self) -> None:
        old_result = self.preserve(FakeDocker(self.image))
        old_record = old_result["services"]["key-rotator"]  # type: ignore[index]

        # Model a later deployed generation being prepared for another build.
        self.plan["manifest"]["services"]["key-rotator"]["digest"] = "f" * 64  # type: ignore[index]
        self.plan["manifest"]["services"]["key-rotator"]["image_id"] = NEW_IMAGE  # type: ignore[index]
        docker = FakeDocker(self.image, image_id=NEW_IMAGE)
        docker.images[self.rollback] = OLD_IMAGE
        new_rollback = preserver.rollback_reference(
            self.image, "ai-gateway", "key-rotator", NEW_IMAGE
        )
        self.assertNotEqual(new_rollback, self.rollback)

        with mock.patch.object(
            preserver,
            "_atomic_manifest_write",
            side_effect=preserver.PreserveError("synthetic commit interruption"),
        ):
            with self.assertRaisesRegex(preserver.PreserveError, "commit interruption"):
                self.preserve(docker)

        # The prior committed generation was never renamed or overwritten.
        persisted = json.loads((self.state / preserver.MANIFEST_NAME).read_text())
        self.assertEqual(persisted["services"]["key-rotator"], old_record)
        self.assertEqual(docker.images[self.rollback], OLD_IMAGE)
        self.assertEqual(docker.images[new_rollback], NEW_IMAGE)

        # Retrying reuses the exact extra content tag and atomically advances the
        # manifest without another Docker tag mutation.
        tag_calls = list(docker.tag_calls)
        result = self.preserve(docker)
        self.assertEqual(docker.tag_calls, tag_calls)
        self.assertEqual(
            result["services"]["key-rotator"]["rollback_image"],  # type: ignore[index]
            new_rollback,
        )

    def test_partial_multi_service_tag_failure_is_retryable(self) -> None:
        services = {
            "alpha": {
                "image": "ai-gateway-alpha",
                "old": OLD_IMAGE,
                "new": NEW_IMAGE,
                "container": CONTAINER_ID,
            },
            "beta": {
                "image": "ai-gateway-beta",
                "old": OTHER_IMAGE,
                "new": "sha256:" + "2" * 64,
                "container": OTHER_CONTAINER_ID,
            },
        }
        old_records: dict[str, object] = {}
        for service, values in services.items():
            old_records[service] = {
                "service": service,
                "build_input_digest": "e" * 64,
                "desired_image": values["image"],
                "planned_image_id": values["old"],
                "rollback_image": preserver.rollback_reference(
                    values["image"], "ai-gateway", service, values["old"]
                ),
                "status": "preserved",
                "container_id": values["container"],
                "source_image_id": values["old"],
            }
        self.write_manifest(old_records)
        plan = {
            "services": sorted(services),
            "manifest": {
                "schema": 1,
                "services": {
                    service: {
                        "digest": "f" * 64,
                        "image": values["image"],
                        "image_id": values["new"],
                    }
                    for service, values in services.items()
                },
            },
        }

        class MultiDocker:
            def __init__(self) -> None:
                self.fail_target = preserver.rollback_reference(
                    services["beta"]["image"],
                    "ai-gateway",
                    "beta",
                    services["beta"]["new"],
                )
                self.images: dict[str, str] = {}
                self.tag_calls: list[tuple[str, str]] = []
                for service, values in services.items():
                    self.images[values["image"]] = values["new"]
                    self.images[values["new"]] = values["new"]
                    old_ref = old_records[service]["rollback_image"]  # type: ignore[index]
                    self.images[old_ref] = values["old"]

            def ensure_ready(self) -> None:
                pass

            def list_service_containers(self, project: str, service: str) -> list[str]:
                self.assert_project(project)
                return [services[service]["container"]]

            @staticmethod
            def assert_project(project: str) -> None:
                if project != "ai-gateway":
                    raise AssertionError(project)

            def inspect_container(self, identifier: str) -> dict[str, object]:
                service = next(
                    name
                    for name, values in services.items()
                    if values["container"] == identifier
                )
                values = services[service]
                return {
                    "Id": identifier,
                    "Image": values["new"],
                    "Config": {
                        "Image": values["image"],
                        "Labels": {
                            "com.docker.compose.project": "ai-gateway",
                            "com.docker.compose.service": service,
                            "com.docker.compose.oneoff": "False",
                            "com.docker.compose.container-number": "1",
                        },
                    },
                    "State": {
                        "Running": True,
                        "Status": "running",
                        "Restarting": False,
                        "Dead": False,
                        "Health": {"Status": "healthy"},
                    },
                    "RestartCount": 0,
                }

            def inspect_image(
                self, reference: str, *, allow_missing: bool = False
            ) -> str | None:
                if reference in self.images:
                    return self.images[reference]
                if allow_missing:
                    return None
                raise preserver.PreserveError(f"missing fake image: {reference}")

            def tag_image(self, source_image_id: str, target_reference: str) -> None:
                self.tag_calls.append((source_image_id, target_reference))
                if target_reference == self.fail_target:
                    raise preserver.PreserveError("synthetic second-service tag failure")
                self.images[target_reference] = source_image_id

        docker = MultiDocker()
        with self.assertRaisesRegex(preserver.PreserveError, "second-service"):
            preserver.preserve_rollbacks(
                plan, stack=self.stack, project="ai-gateway", docker=docker
            )

        # The committed manifest and both old generation tags are unchanged;
        # only alpha's new immutable tag exists as a harmless extra generation.
        persisted = json.loads((self.state / preserver.MANIFEST_NAME).read_text())
        self.assertEqual(persisted["services"], old_records)
        for service, values in services.items():
            self.assertEqual(
                docker.images[old_records[service]["rollback_image"]],  # type: ignore[index]
                values["old"],
            )

        docker.fail_target = ""
        calls_before_retry = list(docker.tag_calls)
        result = preserver.preserve_rollbacks(
            plan, stack=self.stack, project="ai-gateway", docker=docker
        )
        self.assertEqual(
            docker.tag_calls.count(calls_before_retry[0]),
            1,
            "the already-created alpha content tag must be reused",
        )
        self.assertEqual(set(result["updated_services"]), set(services))

    def test_tag_verification_and_container_race_fail_closed(self) -> None:
        docker = FakeDocker(self.image)
        docker.break_tag_verification = True
        with self.assertRaisesRegex(preserver.PreserveError, "tag verification"):
            self.preserve(docker)
        self.assertFalse((self.state / preserver.MANIFEST_NAME).exists())

        docker = FakeDocker(self.image)
        docker.container_lists = [[CONTAINER_ID], [OTHER_CONTAINER_ID]]
        with self.assertRaisesRegex(preserver.PreserveError, "changed during preservation"):
            self.preserve(docker)
        self.assertFalse((self.state / preserver.MANIFEST_NAME).exists())

        docker = FakeDocker(self.image)
        docker.image_inspect_sequences[self.image] = [OLD_IMAGE, OTHER_IMAGE]
        with self.assertRaisesRegex(preserver.PreserveError, "tag changed"):
            self.preserve(docker)
        self.assertFalse((self.state / preserver.MANIFEST_NAME).exists())

    def test_existing_service_generations_are_validated_and_merged(self) -> None:
        other_service = "portal"
        other_image = "ai-gateway-portal"
        other_rollback = preserver.rollback_reference(
            other_image, "ai-gateway", other_service, OTHER_IMAGE
        )
        other_record = {
            "service": other_service,
            "build_input_digest": "f" * 64,
            "desired_image": other_image,
            "planned_image_id": OTHER_IMAGE,
            "rollback_image": other_rollback,
            "status": "preserved",
            "container_id": OTHER_CONTAINER_ID,
            "source_image_id": OTHER_IMAGE,
        }
        self.write_manifest({other_service: other_record})
        docker = FakeDocker(self.image)
        docker.images[other_rollback] = OTHER_IMAGE

        result = self.preserve(docker)

        self.assertEqual(set(result["services"]), {"key-rotator", other_service})  # type: ignore[arg-type]
        self.assertEqual(result["services"][other_service], other_record)  # type: ignore[index]
        persisted = dict(result)
        persisted.pop("updated_services")
        self.assertEqual(
            json.loads((self.state / preserver.MANIFEST_NAME).read_text()), persisted
        )

        malformed = dict(other_record)
        malformed["rollback_image"] = "ai-gateway-portal:attacker"
        self.write_manifest({other_service: malformed})
        docker = FakeDocker(self.image)
        with self.assertRaisesRegex(preserver.PreserveError, "reference is invalid"):
            self.preserve(docker)
        self.assertEqual(docker.ready_calls, 0)
        self.assertEqual(docker.tag_calls, [])

    def test_sequential_single_service_builds_keep_both_generations(self) -> None:
        first = self.preserve(FakeDocker(self.image))
        self.assertEqual(first["updated_services"], ["key-rotator"])

        portal_image = "ai-gateway-portal"
        portal_rollback = preserver.rollback_reference(
            portal_image, "ai-gateway", "portal", OTHER_IMAGE
        )
        self.plan = {
            "services": ["portal"],
            "manifest": {
                "schema": 1,
                "services": {
                    "portal": {
                        "digest": "f" * 64,
                        "image": portal_image,
                        "image_id": OTHER_IMAGE,
                    }
                },
            },
        }
        docker = FakeDocker(
            portal_image,
            service="portal",
            image_id=OTHER_IMAGE,
            container_id=OTHER_CONTAINER_ID,
        )
        docker.images[self.rollback] = OLD_IMAGE

        second = self.preserve(docker)

        self.assertEqual(second["updated_services"], ["portal"])
        self.assertEqual(set(second["services"]), {"key-rotator", "portal"})  # type: ignore[arg-type]
        self.assertEqual(
            second["services"]["key-rotator"],  # type: ignore[index]
            first["services"]["key-rotator"],  # type: ignore[index]
        )
        self.assertEqual(
            second["services"]["portal"]["rollback_image"],  # type: ignore[index]
            portal_rollback,
        )
        persisted = dict(second)
        persisted.pop("updated_services")
        self.assertEqual(
            json.loads((self.state / preserver.MANIFEST_NAME).read_text()), persisted
        )

    def test_unsafe_plan_and_manifest_destination_fail_closed(self) -> None:
        self.plan["manifest"]["services"]["key-rotator"]["image"] = "--help"  # type: ignore[index]
        with self.assertRaisesRegex(preserver.PreserveError, "unsafe"):
            self.preserve(FakeDocker(self.image))

        self.plan["manifest"]["services"]["key-rotator"]["image"] = self.image  # type: ignore[index]
        manifest = self.state / preserver.MANIFEST_NAME
        target = self.stack / "outside"
        target.write_text("do not overwrite")
        manifest.symlink_to(target)
        with self.assertRaisesRegex(preserver.PreserveError, "single-link regular"):
            docker = FakeDocker(self.image)
            self.preserve(docker)
        self.assertEqual(target.read_text(), "do not overwrite")
        self.assertEqual(docker.ready_calls, 0)
        self.assertEqual(docker.tag_calls, [])

        manifest.unlink()
        self.stack.chmod(0o755)
        with self.assertRaisesRegex(preserver.PreserveError, "mode must be 0750"):
            docker = FakeDocker(self.image)
            self.preserve(docker)
        self.assertEqual(docker.ready_calls, 0)
        self.assertEqual(docker.tag_calls, [])

    def test_build_plan_service_count_is_bounded(self) -> None:
        services = [f"service-{index:03d}" for index in range(257)]
        plan = {
            "services": services,
            "manifest": {
                "schema": 1,
                "services": {
                    service: {
                        "digest": "e" * 64,
                        "image": f"ai-gateway-{service}",
                        "image_id": OLD_IMAGE,
                    }
                    for service in services
                },
            },
        }
        with self.assertRaisesRegex(preserver.PreserveError, "256-service"):
            preserver.validate_plan(plan, "ai-gateway")

    def test_docker_client_uses_fixed_exec_argv_and_rejects_ambiguous_json(self) -> None:
        responses = [
            subprocess.CompletedProcess(
                args=[], returncode=0, stdout=(CONTAINER_ID + "\n").encode(), stderr=b""
            ),
            subprocess.CompletedProcess(
                args=[], returncode=0, stdout=b"[]", stderr=b""
            ),
        ]
        runner = mock.Mock(side_effect=responses)
        client = preserver.DockerClient("/usr/bin/docker", runner=runner)
        self.assertEqual(
            client.list_service_containers("ai-gateway", "key-rotator"),
            [CONTAINER_ID],
        )
        self.assertEqual(
            runner.call_args_list[0].args[0],
            [
                "/usr/bin/docker",
                "--host",
                "unix:///run/docker.sock",
                "ps",
                "-a",
                "--no-trunc",
                "--filter",
                "label=com.docker.compose.project=ai-gateway",
                "--filter",
                "label=com.docker.compose.service=key-rotator",
                "--format",
                "{{.ID}}",
            ],
        )
        self.assertEqual(
            runner.call_args_list[0].kwargs["env"],
            {
                "DOCKER_HOST": "unix:///run/docker.sock",
                "HOME": "/",
                "LC_ALL": "C",
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            },
        )
        with self.assertRaisesRegex(preserver.PreserveError, "ambiguous"):
            client.inspect_image(self.image)

    def test_docker_client_proves_exact_rotator_sealed_vault_gate(self) -> None:
        rotator = FakeDocker(self.image).container
        rotator["Config"]["Healthcheck"] = {  # type: ignore[index]
            "Test": preserver.KEY_ROTATOR_READINESS_HEALTHCHECK
        }
        vault = {
            "Id": OTHER_CONTAINER_ID,
            "Config": {
                "Labels": {
                    "com.docker.compose.project": "ai-gateway",
                    "com.docker.compose.service": "vault",
                    "com.docker.compose.oneoff": "False",
                    "com.docker.compose.container-number": "1",
                }
            },
            "State": {
                "Running": True,
                "Status": "running",
                "Restarting": False,
                "Dead": False,
            },
        }
        responses = [
            subprocess.CompletedProcess(args=[], returncode=0, stdout=b"", stderr=b""),
            subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=(OTHER_CONTAINER_ID + "\n").encode(),
                stderr=b"",
            ),
            subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=json.dumps([vault]).encode(),
                stderr=b"",
            ),
            subprocess.CompletedProcess(
                args=[],
                returncode=2,
                stdout=b'{"initialized":true,"sealed":true}',
                stderr=b"",
            ),
        ]
        runner = mock.Mock(side_effect=responses)
        client = preserver.DockerClient("/usr/bin/docker", runner=runner)

        self.assertTrue(
            client.prove_key_rotator_dependency_gate(
                "ai-gateway", CONTAINER_ID, rotator
            )
        )
        self.assertEqual(
            runner.call_args_list[0].args[0],
            [
                "/usr/bin/docker",
                "--host",
                "unix:///run/docker.sock",
                "container",
                "exec",
                CONTAINER_ID,
                "python3",
                "-c",
                preserver.KEY_ROTATOR_DEPENDENCY_PROBE,
            ],
        )
        self.assertEqual(
            runner.call_args_list[-1].args[0],
            [
                "/usr/bin/docker",
                "--host",
                "unix:///run/docker.sock",
                "container",
                "exec",
                OTHER_CONTAINER_ID,
                "vault",
                "status",
                "-address=http://127.0.0.1:8200",
                "-format=json",
            ],
        )

    def test_docker_client_rejects_unsealed_dependency_gate(self) -> None:
        rotator = FakeDocker(self.image).container
        rotator["Config"]["Healthcheck"] = {  # type: ignore[index]
            "Test": preserver.KEY_ROTATOR_READINESS_HEALTHCHECK
        }
        vault = {
            "Id": OTHER_CONTAINER_ID,
            "Config": {
                "Labels": {
                    "com.docker.compose.project": "ai-gateway",
                    "com.docker.compose.service": "vault",
                    "com.docker.compose.oneoff": "False",
                    "com.docker.compose.container-number": "1",
                }
            },
            "State": {
                "Running": True,
                "Status": "running",
                "Restarting": False,
                "Dead": False,
            },
        }
        responses = [
            subprocess.CompletedProcess(args=[], returncode=0, stdout=b"", stderr=b""),
            subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=(OTHER_CONTAINER_ID + "\n").encode(),
                stderr=b"",
            ),
            subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=json.dumps([vault]).encode(),
                stderr=b"",
            ),
            subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=b'{"initialized":true,"sealed":false}',
                stderr=b"",
            ),
        ]
        client = preserver.DockerClient(
            "/usr/bin/docker", runner=mock.Mock(side_effect=responses)
        )

        self.assertFalse(
            client.prove_key_rotator_dependency_gate(
                "ai-gateway", CONTAINER_ID, rotator
            )
        )


if __name__ == "__main__":
    unittest.main()
