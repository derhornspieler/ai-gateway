"""Contracts for the target-side controller lifecycle audit boundary."""

from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
WRITER_PATH = ROOT / "scripts/controller-lifecycle-audit.py"
PLAYBOOK_PATH = ROOT / "ansible/record-controller-lifecycle.yml"
ROLE_PATH = ROOT / "ansible/roles/docker_stack/tasks/main.yml"
PREPROD_PATH = ROOT / "scripts/preprod.py"
PREPROD_CRIBL_PATH = ROOT / "scripts/test-preprod-cribl-security.py"


def load_writer():
    spec = importlib.util.spec_from_file_location(
        "aigw_controller_lifecycle_audit", WRITER_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


WRITER = load_writer()


def load_preprod():
    spec = importlib.util.spec_from_file_location(
        "aigw_controller_audit_preprod", PREPROD_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_preprod_cribl():
    spec = importlib.util.spec_from_file_location(
        "aigw_controller_audit_preprod_cribl", PREPROD_CRIBL_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ControllerLifecycleAuditTest(unittest.TestCase):
    def valid_arguments(self, action: str = "upgrade", outcome: str = "started") -> list[str]:
        return [
            action,
            outcome,
            "123e4567-e89b-42d3-a456-426614174000",
            "a" * 64,
            "b" * 40,
            "sha256:" + "c" * 64,
            "d" * 64,
        ]

    def test_valid_record_has_one_exact_schema(self) -> None:
        record = WRITER.validate_record(self.valid_arguments())
        self.assertEqual(
            set(record),
            {
                "schema_version",
                "event",
                "timestamp",
                "action",
                "outcome",
                "operation_id",
                "release_manifest_sha256",
                "release_commit",
                "envoy_image_id",
                "egress_policy_sha256",
            },
        )
        self.assertEqual(record["schema_version"], 1)
        self.assertEqual(record["event"], "aigw.controller.lifecycle")
        self.assertRegex(
            str(record["timestamp"]),
            r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$",
        )

    def test_fixed_action_and_outcome_catalog(self) -> None:
        for action in ("upgrade", "rollback"):
            for outcome in ("started", "success", "failed"):
                with self.subTest(action=action, outcome=outcome):
                    record = WRITER.validate_record(
                        self.valid_arguments(action, outcome)
                    )
                    self.assertEqual((record["action"], record["outcome"]), (action, outcome))
        for action, outcome in (
            ("deploy", "success"),
            ("restore", "success"),
            ("upgrade", "warning"),
            ("anything", "anything"),
        ):
            with self.subTest(action=action, outcome=outcome):
                with self.assertRaises(WRITER.AuditError):
                    WRITER.validate_record(self.valid_arguments(action, outcome))

    def test_rejects_extra_fields_and_noncanonical_identifiers(self) -> None:
        cases = []
        cases.append(self.valid_arguments() + ["arbitrary=value"])
        invalid_uuid = self.valid_arguments()
        invalid_uuid[2] = invalid_uuid[2].upper()
        cases.append(invalid_uuid)
        wrong_version = self.valid_arguments()
        wrong_version[2] = "123e4567-e89b-12d3-a456-426614174000"
        cases.append(wrong_version)
        uppercase_digest = self.valid_arguments()
        uppercase_digest[3] = "A" * 64
        cases.append(uppercase_digest)
        bad_image = self.valid_arguments()
        bad_image[5] = "repo/image:latest"
        cases.append(bad_image)
        for arguments in cases:
            with self.subTest(arguments=arguments):
                with self.assertRaises(WRITER.AuditError):
                    WRITER.validate_record(arguments)

    def test_cli_prints_only_a_fixed_receipt(self) -> None:
        with (
            mock.patch.object(WRITER, "append_record") as append,
            mock.patch("sys.stdout", new_callable=io.StringIO) as stdout,
        ):
            self.assertEqual(WRITER.main(self.valid_arguments()), 0)
        append.assert_called_once()
        self.assertEqual(stdout.getvalue(), "CONTROLLER_LIFECYCLE_AUDIT_RECORDED\n")
        self.assertNotIn("123e4567", stdout.getvalue())

    def test_real_append_and_rotation_keep_valid_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            audit_directory = root / "audit"
            audit_directory.mkdir(mode=0o750)
            lock_file = root / "writer.lock"
            record = WRITER.validate_record(self.valid_arguments())
            encoded = (
                json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode("ascii")
            with (
                mock.patch.object(WRITER, "AUDIT_DIRECTORY", audit_directory),
                mock.patch.object(WRITER, "LOCK_FILE", lock_file),
                mock.patch.object(WRITER, "ROOT_UID", os.geteuid()),
                mock.patch.object(WRITER, "ROOT_GID", os.getegid()),
                mock.patch.object(WRITER, "ALLOY_GID", os.getegid()),
                mock.patch.object(WRITER, "MAX_FILE_BYTES", len(encoded) + 1),
            ):
                WRITER.append_record(record)
                WRITER.append_record(record)

            current = audit_directory / WRITER.AUDIT_FILE_NAME
            rotated = audit_directory / WRITER.ROTATED_FILE_NAME
            self.assertEqual(json.loads(current.read_text()), record)
            self.assertEqual(json.loads(rotated.read_text()), record)
            self.assertEqual(current.stat().st_mode & 0o777, 0o640)
            self.assertEqual(rotated.stat().st_mode & 0o777, 0o640)

    def test_lifecycle_evidence_persists_across_a_source_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            audit_directory = root / "audit"
            audit_directory.mkdir(mode=0o750)
            lock_file = root / "writer.lock"
            with (
                mock.patch.object(WRITER, "AUDIT_DIRECTORY", audit_directory),
                mock.patch.object(WRITER, "LOCK_FILE", lock_file),
                mock.patch.object(WRITER, "ROOT_UID", os.geteuid()),
                mock.patch.object(WRITER, "ROOT_GID", os.getegid()),
                mock.patch.object(WRITER, "ALLOY_GID", os.getegid()),
            ):
                for action, outcome in (
                    ("upgrade", "started"),
                    ("upgrade", "failed"),
                    ("rollback", "started"),
                ):
                    WRITER.append_record(
                        WRITER.validate_record(
                            self.valid_arguments(action, outcome)
                        )
                    )

                # This is the file effect of the previous source's normal
                # idempotent directory converge: ownership/mode may be
                # asserted again, but evidence is not removed or truncated.
                audit_directory.mkdir(mode=0o750, exist_ok=True)
                audit_directory.chmod(0o750)

                WRITER.append_record(
                    WRITER.validate_record(
                        self.valid_arguments("rollback", "success")
                    )
                )

            records = [
                json.loads(line)
                for line in (audit_directory / WRITER.AUDIT_FILE_NAME)
                .read_text(encoding="ascii")
                .splitlines()
            ]
            self.assertEqual(
                [(record["action"], record["outcome"]) for record in records],
                [
                    ("upgrade", "started"),
                    ("upgrade", "failed"),
                    ("rollback", "started"),
                    ("rollback", "success"),
                ],
            )
            self.assertEqual(len({record["operation_id"] for record in records}), 1)

    def test_real_append_refuses_a_symlinked_active_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            audit_directory = root / "audit"
            audit_directory.mkdir(mode=0o750)
            target = root / "outside.jsonl"
            target.write_text("unchanged\n", encoding="utf-8")
            (audit_directory / WRITER.AUDIT_FILE_NAME).symlink_to(target)
            with (
                mock.patch.object(WRITER, "AUDIT_DIRECTORY", audit_directory),
                mock.patch.object(WRITER, "LOCK_FILE", root / "writer.lock"),
                mock.patch.object(WRITER, "ROOT_UID", os.geteuid()),
                mock.patch.object(WRITER, "ROOT_GID", os.getegid()),
                mock.patch.object(WRITER, "ALLOY_GID", os.getegid()),
                self.assertRaises(WRITER.AuditError),
            ):
                WRITER.append_record(WRITER.validate_record(self.valid_arguments()))
            self.assertEqual(target.read_text(encoding="utf-8"), "unchanged\n")

    def test_append_refuses_unsafe_rotated_files_before_changing_active(self) -> None:
        active_bytes = b"preserve active\n"
        rotated_bytes = b"preserve rotated\n"
        for unsafe_kind in ("symlink", "hardlink", "mode", "size"):
            with (
                self.subTest(unsafe_kind=unsafe_kind),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                audit_directory = root / "audit"
                audit_directory.mkdir(mode=0o750)
                current = audit_directory / WRITER.AUDIT_FILE_NAME
                current.write_bytes(active_bytes)
                current.chmod(0o640)
                rotated = audit_directory / WRITER.ROTATED_FILE_NAME
                outside = root / "outside.jsonl"

                if unsafe_kind == "symlink":
                    outside.write_bytes(rotated_bytes)
                    outside.chmod(0o640)
                    rotated.symlink_to(outside)
                elif unsafe_kind == "hardlink":
                    outside.write_bytes(rotated_bytes)
                    outside.chmod(0o640)
                    os.link(outside, rotated)
                elif unsafe_kind == "mode":
                    rotated.write_bytes(rotated_bytes)
                    rotated.chmod(0o644)
                else:
                    rotated.write_bytes(b"x" * 4097)
                    rotated.chmod(0o640)

                with (
                    mock.patch.object(WRITER, "AUDIT_DIRECTORY", audit_directory),
                    mock.patch.object(WRITER, "LOCK_FILE", root / "writer.lock"),
                    mock.patch.object(WRITER, "ROOT_UID", os.geteuid()),
                    mock.patch.object(WRITER, "ROOT_GID", os.getegid()),
                    mock.patch.object(WRITER, "ALLOY_GID", os.getegid()),
                    mock.patch.object(WRITER, "MAX_FILE_BYTES", 4096),
                    self.assertRaises(WRITER.AuditError),
                ):
                    WRITER.append_record(
                        WRITER.validate_record(self.valid_arguments())
                    )

                self.assertEqual(current.read_bytes(), active_bytes)
                if outside.exists():
                    self.assertEqual(outside.read_bytes(), rotated_bytes)

    def test_append_refuses_wrong_rotated_owner_before_changing_active(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            audit_directory = root / "audit"
            audit_directory.mkdir(mode=0o750)
            current = audit_directory / WRITER.AUDIT_FILE_NAME
            active_bytes = b"preserve active\n"
            current.write_bytes(active_bytes)
            current.chmod(0o640)
            rotated = audit_directory / WRITER.ROTATED_FILE_NAME
            rotated.write_bytes(b"preserve rotated\n")
            rotated.chmod(0o640)
            real_stat_optional = WRITER._stat_optional

            def stat_with_wrong_rotated_owner(
                directory_fd: int, name: str
            ) -> os.stat_result | None:
                metadata = real_stat_optional(directory_fd, name)
                if metadata is None or name != WRITER.ROTATED_FILE_NAME:
                    return metadata
                fields = list(metadata)
                fields[4] = os.geteuid() + 1
                return os.stat_result(fields)

            with (
                mock.patch.object(WRITER, "AUDIT_DIRECTORY", audit_directory),
                mock.patch.object(WRITER, "LOCK_FILE", root / "writer.lock"),
                mock.patch.object(WRITER, "ROOT_UID", os.geteuid()),
                mock.patch.object(WRITER, "ROOT_GID", os.getegid()),
                mock.patch.object(WRITER, "ALLOY_GID", os.getegid()),
                mock.patch.object(
                    WRITER,
                    "_stat_optional",
                    side_effect=stat_with_wrong_rotated_owner,
                ),
                self.assertRaises(WRITER.AuditError),
            ):
                WRITER.append_record(WRITER.validate_record(self.valid_arguments()))

            self.assertEqual(current.read_bytes(), active_bytes)

    def test_writer_is_root_only_symlink_safe_and_size_bounded(self) -> None:
        source = WRITER_PATH.read_text(encoding="utf-8")
        for contract in (
            'AUDIT_DIRECTORY = Path("/var/log/ai-gateway-controller")',
            'AUDIT_FILE_NAME = "lifecycle.jsonl"',
            'ROTATED_FILE_NAME = "lifecycle.jsonl.1"',
            "MAX_FILE_BYTES = 8 * 1024 * 1024",
            "os.geteuid() != ROOT_UID",
            "os.O_APPEND",
            "os.O_NOFOLLOW",
            "os.O_CLOEXEC",
            "fcntl.LOCK_EX",
            "metadata.st_nlink != 1",
            "metadata.st_size > MAX_FILE_BYTES",
            "os.fsync(audit_fd)",
            "os.fsync(directory_fd)",
        ):
            self.assertIn(contract, source)
        self.assertNotIn("shell=True", source)
        self.assertNotIn("input(", source)

    def test_ansible_owns_only_the_fixed_file_boundary(self) -> None:
        playbook = PLAYBOOK_PATH.read_text(encoding="utf-8")
        for contract in (
            "/var/log/ai-gateway-controller/lifecycle.jsonl",
            "/usr/local/sbin/aigw-controller-lifecycle-audit",
            "owner: root",
            'group: "473"',
            'mode: "0750"',
            "item.stat.mode == '0640'",
            "item.stat.nlink",
            "controller_lifecycle_operation_id is match(",
            "controller_lifecycle_manifest_sha256 is match('^[0-9a-f]{64}$')",
            "controller_lifecycle_envoy_image_id is match('^sha256:[0-9a-f]{64}$')",
            "item.item != controller_lifecycle_audit_file or",
        ):
            self.assertIn(contract, playbook)
        self.assertNotIn("stdin:", playbook)
        self.assertNotIn("ansible.builtin.shell", playbook)
        self.assertNotRegex(playbook, re.compile(r"controller_lifecycle_(?:message|detail|fields)"))

    def test_writer_is_in_the_flat_operational_script_manifest(self) -> None:
        role = ROLE_PATH.read_text(encoding="utf-8")
        manifest = role.split("aigw_operational_scripts:", 1)[1].split("  block:", 1)[0]
        self.assertEqual(manifest.count("controller-lifecycle-audit.py"), 1)

    def test_production_creates_the_alloy_source_before_compose(self) -> None:
        role = ROLE_PATH.read_text(encoding="utf-8")
        inspect = role.index("Inspect the controller lifecycle audit source directory")
        refuse = role.index("Refuse an unsafe controller lifecycle audit source directory")
        create = role.index(
            "Create the controller lifecycle audit source directory before Compose"
        )
        inventory = role.index(
            "Inventory the fixed controller lifecycle audit source boundary"
        )
        inspect_files = role.index(
            "Inspect the fixed controller lifecycle audit source files"
        )
        refuse_files = role.index(
            "Refuse unsafe controller lifecycle audit source files"
        )
        deploy = role.index("Deploy stack without implicitly rebuilding custom images")
        self.assertLess(inspect, refuse)
        self.assertLess(refuse, create)
        self.assertLess(create, inventory)
        self.assertLess(inventory, inspect_files)
        self.assertLess(inspect_files, refuse_files)
        self.assertLess(refuse_files, deploy)
        self.assertLess(create, deploy)
        boundary = role[
            inspect : role.index(
                "- name: Validate the PostgreSQL 18 physical-volume contract",
                create,
            )
        ]
        self.assertIn("Persistent, host-owned audit infrastructure", role)
        for contract in (
            "path: /var/log/ai-gateway-controller",
            "follow: false",
            "stat.islnk",
            "stat.uid == 0",
            "stat.gid == 473",
            "stat.mode == '0750'",
            "owner: root",
            'group: "473"',
            'mode: "0750"',
        ):
            self.assertIn(contract, boundary)
        self.assertNotIn("state: absent", boundary)

    def test_production_refuses_unsafe_audit_files_before_compose(self) -> None:
        role = ROLE_PATH.read_text(encoding="utf-8")
        begin = role.index(
            "Inventory the fixed controller lifecycle audit source boundary"
        )
        deploy = role.index("Deploy stack without implicitly rebuilding custom images")
        boundary = role[begin:deploy]
        for contract in (
            "file_type: any",
            "follow: false",
            "Refuse unknown controller lifecycle audit source entries",
            "difference([",
            "/var/log/ai-gateway-controller/lifecycle.jsonl",
            "/var/log/ai-gateway-controller/lifecycle.jsonl.1",
            "Refuse unsafe controller lifecycle audit source files",
            "item.stat.isreg",
            "item.stat.islnk",
            "item.stat.uid == 0",
            "item.stat.gid == 473",
            "item.stat.mode == '0640'",
            "item.stat.nlink",
            "item.stat.size",
            "<= 8388608",
        ):
            self.assertIn(contract, boundary)
        self.assertIn(
            "Existing controller lifecycle audit source file is unsafe.", boundary
        )

    def test_alloy_mounts_the_exact_controller_source_read_only(self) -> None:
        production = (ROOT / "compose/docker-compose.yml").read_text(encoding="utf-8")
        preprod = (ROOT / "compose/docker-compose.preprod.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "- /var/log/ai-gateway-controller:/var/log/aigw/controller:ro",
            production,
        )
        self.assertIn(
            "- ./secrets/preprod-controller-lifecycle:/var/log/aigw/controller:ro,Z",
            preprod,
        )
        self.assertNotIn(
            "/var/log/ai-gateway-controller:/var/log/aigw/controller:rw",
            production,
        )
        self.assertNotIn(
            "./secrets/preprod-controller-lifecycle:/var/log/aigw/controller:rw",
            preprod,
        )
        self.assertIn(
            "security_opt: [no-new-privileges:true, label=disable]",
            production.split("  alloy:", 1)[1].split("  prometheus:", 1)[0],
        )

    def test_preprod_fixture_is_declared_generated_state_and_destroyed(self) -> None:
        source = PREPROD_PATH.read_text(encoding="utf-8")
        self.assertIn('"secrets/preprod-controller-lifecycle",', source)
        self.assertIn(
            '(PREPROD_CONTROLLER_AUDIT_FILES[0], 0o644),', source
        )
        self.assertIn(
            '(PREPROD_CONTROLLER_AUDIT_FILES[1], 0o644),', source
        )
        self.assertIn("prepare_controller_audit_fixture()", source)
        self.assertIn("remove_controller_audit_fixture()", source)
        self.assertIn("PREPROD_CONTROLLER_AUDIT_DIR.lstat()", source)
        self.assertIn(
            'fail("generated preprod controller audit state remains after removal")',
            source,
        )
        destroy = source.split("def _destroy_project_resources(", 1)[1].split(
            "\ndef destroy(", 1
        )[0]
        self.assertLess(destroy.index('"down",'), destroy.index(
            "remove_controller_audit_fixture()"
        ))

    def test_preprod_fixture_repeated_prepare_preserves_both_inodes(self) -> None:
        preprod = load_preprod()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            audit_directory = root / "controller"
            current = audit_directory / "lifecycle.jsonl"
            rotated = audit_directory / "lifecycle.jsonl.1"
            with (
                mock.patch.object(
                    preprod, "PREPROD_CONTROLLER_AUDIT_DIR", audit_directory
                ),
                mock.patch.object(
                    preprod, "PREPROD_CONTROLLER_AUDIT_FILES", (current, rotated)
                ),
                mock.patch.object(preprod, "SEED_RECEIPT", root / "missing-receipt"),
                mock.patch.object(preprod, "SEED_OVERLAY", root / "missing-overlay"),
                mock.patch.object(
                    preprod,
                    "PROVIDER_POLICY_RECEIPT",
                    root / "missing-provider-policy",
                ),
                mock.patch.object(
                    preprod,
                    "POSTGRES18_REHEARSAL_RECEIPT",
                    root / "missing-postgres-rehearsal",
                ),
                mock.patch.object(preprod, "VAULT_INIT_FILE", root / "missing-vault"),
            ):
                preprod.prepare_controller_audit_fixture()
                identities = {
                    path: (path.stat().st_dev, path.stat().st_ino)
                    for path in (current, rotated)
                }
                for path in (current, rotated):
                    self.assertEqual(path.read_bytes(), b"")
                    self.assertEqual(path.stat().st_mode & 0o777, 0o644)
                current.write_text("stale current\n", encoding="utf-8")
                rotated.write_text("stale rotated\n", encoding="utf-8")

                preprod.prepare_controller_audit_fixture()
                for path in (current, rotated):
                    self.assertEqual(path.read_bytes(), b"")
                    self.assertEqual(
                        (path.stat().st_dev, path.stat().st_ino), identities[path]
                    )
                self.assertEqual(preprod._validate_clean_room_generated_state(), 2)

                preprod.remove_controller_audit_fixture()
                self.assertFalse(audit_directory.exists())

    def test_preprod_acceptance_writes_both_files_in_place(self) -> None:
        preprod = load_preprod()
        receipt = load_preprod_cribl()
        with tempfile.TemporaryDirectory() as temporary:
            audit_directory = Path(temporary) / "controller"
            current = audit_directory / "lifecycle.jsonl"
            rotated = audit_directory / "lifecycle.jsonl.1"
            with (
                mock.patch.object(
                    preprod, "PREPROD_CONTROLLER_AUDIT_DIR", audit_directory
                ),
                mock.patch.object(
                    preprod, "PREPROD_CONTROLLER_AUDIT_FILES", (current, rotated)
                ),
                mock.patch.object(receipt, "CONTROLLER_AUDIT_DIR", audit_directory),
                mock.patch.object(receipt, "CONTROLLER_AUDIT_CURRENT", current),
                mock.patch.object(receipt, "CONTROLLER_AUDIT_ROTATED", rotated),
            ):
                preprod.prepare_controller_audit_fixture()
                identities = {
                    path: (path.stat().st_dev, path.stat().st_ino)
                    for path in (current, rotated)
                }
                receipt.write_controller_lifecycle_fixtures("0123456789abcdef")

                for path in (current, rotated):
                    self.assertGreater(path.stat().st_size, 0)
                    self.assertEqual(
                        (path.stat().st_dev, path.stat().st_ino), identities[path]
                    )

                receipt.empty_controller_lifecycle_fixtures()
                for path in (current, rotated):
                    self.assertEqual(path.read_bytes(), b"")
                    self.assertEqual(
                        (path.stat().st_dev, path.stat().st_ino), identities[path]
                    )

    def test_preprod_fixture_refuses_a_symlinked_rotation(self) -> None:
        preprod = load_preprod()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            audit_directory = root / "controller"
            audit_directory.mkdir(mode=0o755)
            current = audit_directory / "lifecycle.jsonl"
            rotated = audit_directory / "lifecycle.jsonl.1"
            current.write_text("preserve current\n", encoding="utf-8")
            current.chmod(0o644)
            outside = root / "outside"
            outside.write_text("unchanged\n", encoding="utf-8")
            rotated.symlink_to(outside)
            with (
                mock.patch.object(
                    preprod, "PREPROD_CONTROLLER_AUDIT_DIR", audit_directory
                ),
                mock.patch.object(
                    preprod, "PREPROD_CONTROLLER_AUDIT_FILES", (current, rotated)
                ),
                self.assertRaisesRegex(SystemExit, "controller audit fixture file"),
            ):
                preprod.prepare_controller_audit_fixture()
            self.assertEqual(current.read_text(encoding="utf-8"), "preserve current\n")
            self.assertEqual(outside.read_text(encoding="utf-8"), "unchanged\n")

    def test_preprod_fixture_refuses_unknown_entry_before_reset(self) -> None:
        preprod = load_preprod()
        with tempfile.TemporaryDirectory() as temporary:
            audit_directory = Path(temporary) / "controller"
            audit_directory.mkdir(mode=0o755)
            current = audit_directory / "lifecycle.jsonl"
            rotated = audit_directory / "lifecycle.jsonl.1"
            current.write_text("preserve current\n", encoding="utf-8")
            current.chmod(0o644)
            unknown = audit_directory / "do-not-remove"
            unknown.write_text("preserve unknown\n", encoding="utf-8")
            with (
                mock.patch.object(
                    preprod, "PREPROD_CONTROLLER_AUDIT_DIR", audit_directory
                ),
                mock.patch.object(
                    preprod, "PREPROD_CONTROLLER_AUDIT_FILES", (current, rotated)
                ),
                self.assertRaisesRegex(SystemExit, "contains an unknown file"),
            ):
                preprod.prepare_controller_audit_fixture()
            self.assertEqual(current.read_text(encoding="utf-8"), "preserve current\n")
            self.assertEqual(unknown.read_text(encoding="utf-8"), "preserve unknown\n")

    def test_upgrade_and_rollback_events_follow_honest_boundaries(self) -> None:
        source = (ROOT / "scripts/update-images.py").read_text(encoding="utf-8")
        body = source.split("def cmd_upgrade(", 1)[1].split(
            "def add_release_arguments(", 1
        )[0]
        upgrade_start = body.index(
            'action="upgrade",\n            outcome="started"'
        )
        candidate_deploy = body.index("deploy_candidate(")
        external_validation = body.index("run_external_validation(args)")
        candidate_identity_cleanup = body.index(
            'state="absent"', external_validation
        )
        upgrade_success = body.index(
            'action="upgrade",\n                outcome="success"'
        )
        upgrade_failure = body.index(
            'action="upgrade",\n                    outcome="failed"'
        )
        rollback_start = body.index(
            'action="rollback",\n                    outcome="started"'
        )
        rollback = body.index("automatic_rollback(")
        rollback_identity_cleanup = body.index(
            'state="absent"', rollback
        )
        rollback_success = body.index(
            'action="rollback",\n                    outcome="success"'
        )
        self.assertLess(upgrade_start, candidate_deploy)
        self.assertLess(candidate_deploy, external_validation)
        self.assertLess(external_validation, candidate_identity_cleanup)
        self.assertLess(candidate_identity_cleanup, upgrade_success)
        self.assertLess(external_validation, upgrade_success)
        self.assertLess(upgrade_failure, upgrade_success)
        self.assertLess(upgrade_failure, rollback_start)
        self.assertLess(rollback_start, rollback)
        self.assertLess(rollback, rollback_identity_cleanup)
        self.assertLess(rollback_identity_cleanup, rollback_success)
        self.assertLess(rollback, rollback_success)


if __name__ == "__main__":
    unittest.main()
