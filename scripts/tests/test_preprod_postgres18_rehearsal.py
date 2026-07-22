"""Contracts for the fixed exact-seed PostgreSQL 16 to 18 rehearsal."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]


def load_rehearsal():
    path = ROOT / "scripts/preprod-postgres18-rehearsal.py"
    spec = importlib.util.spec_from_file_location("aigw_preprod_postgres18", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


REHEARSAL = load_rehearsal()


class PreprodPostgres18RehearsalTests(unittest.TestCase):
    def test_images_project_volumes_and_paths_are_fixed(self) -> None:
        self.assertEqual(REHEARSAL.PROJECT, "aigw-preprod")
        self.assertEqual(REHEARSAL.DOMAIN, "aigw.internal")
        self.assertEqual(REHEARSAL.SOURCE_VOLUME, "aigw-preprod_pg16_data")
        self.assertEqual(REHEARSAL.TARGET_VOLUME, "aigw-preprod_pg18_data")
        self.assertIn("dhi.io/postgres:16.14@sha256:", REHEARSAL.POSTGRES16_IMAGE)
        self.assertIn("dhi.io/postgres:18.4@sha256:", REHEARSAL.POSTGRES18_IMAGE)
        source = (ROOT / "scripts/preprod-postgres18-rehearsal.py").read_text()
        self.assertNotIn("argparse", source)
        self.assertNotIn("--host", source.split("def main()", 1)[1])
        self.assertEqual(source.count('"--archive",'), 2)

    def test_fixture_profile_is_deterministic_and_bounded(self) -> None:
        self.assertEqual(set(REHEARSAL.FIXTURE_PROFILE), {"keycloak", "litellm", "rotator"})
        for database, profile in REHEARSAL.FIXTURE_PROFILE.items():
            with self.subTest(database=database):
                self.assertGreaterEqual(profile["rows"], 500_000)
                self.assertGreaterEqual(
                    profile["minimum_bytes"], 128 * 1024 * 1024
                )
                first = REHEARSAL.fixture_sql(database, profile["rows"])
                second = REHEARSAL.fixture_sql(database, profile["rows"])
                self.assertEqual(first, second)
                self.assertIn("sha256", first)
                self.assertIn("generate_series", first)
                self.assertIn(f"SET ROLE {database};", first)
                self.assertIn("RESET ROLE;", first)

    def test_logical_migration_preserves_owners_and_grants(self) -> None:
        source = (ROOT / "scripts/preprod-postgres18-rehearsal.py").read_text()
        logical = source.split("def logical_dumps", 1)[1].split(
            "def volume_document", 1
        )[0]
        restore = source.split("def restore_logical_dumps", 1)[1].split(
            "def stable_runtime_fingerprint", 1
        )[0]
        for section in (logical, restore):
            self.assertNotIn("--no-owner", section)
            self.assertNotIn("--no-privileges", section)
        self.assertIn("verify_service_role_access(endpoint)", restore)

    def test_service_role_access_proves_read_and_write_without_committing(self) -> None:
        result = types.SimpleNamespace(stdout=b"", stderr=b"", returncode=0)
        with mock.patch.object(
            REHEARSAL, "postgres_exec", return_value=result
        ) as postgres_exec:
            REHEARSAL.verify_service_role_access("unix:///tmp/docker.sock")
        self.assertEqual(postgres_exec.call_count, 3)
        for database, call in zip(
            REHEARSAL.FIXTURE_PROFILE, postgres_exec.call_args_list
        ):
            arguments = call.args
            self.assertEqual(arguments[0], "unix:///tmp/docker.sock")
            sql = arguments[-1]
            self.assertIn(f"SET LOCAL ROLE {database};", sql)
            self.assertIn("UPDATE public.aigw_preprod_migration_fixture", sql)
            self.assertIn("ROLLBACK;", sql)

    def test_seed_receipt_requires_both_exact_postgres_images(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "receipt.json"
            receipt.write_text(
                json.dumps(
                    {
                        "schema_version": 2,
                        "release_scope": "preprod",
                        "manifest_sha256": "a" * 64,
                        "external_images": {
                            REHEARSAL.POSTGRES18_IMAGE: "sha256:"
                            + REHEARSAL.POSTGRES18_IMAGE.rsplit("@sha256:", 1)[1]
                        },
                    }
                )
            )
            receipt.chmod(0o644)
            with mock.patch.object(REHEARSAL, "SEED_RECEIPT", receipt):
                with self.assertRaisesRegex(REHEARSAL.RehearsalError, "exact seeded image"):
                    REHEARSAL.read_seed_receipt()

    def test_post_write_downgrade_uses_real_preprod_guard_without_mutation(self) -> None:
        image_id = "sha256:" + REHEARSAL.POSTGRES18_IMAGE.rsplit("@sha256:", 1)[1]
        seed = {
            "manifest_sha256": "a" * 64,
            "external_images": {REHEARSAL.POSTGRES18_IMAGE: image_id},
        }
        fixtures = {"keycloak": {"content_sha256": "b" * 64}}
        verified = {"keycloak": {"content_sha256": "b" * 64}}
        refusal = REHEARSAL.RehearsalError(
            "real command failed: ERROR: PostgreSQL 16 downgrade refused after "
            "PostgreSQL 18 writes opened"
        )

        with (
            mock.patch.object(REHEARSAL, "atomic_receipt") as receipt,
            mock.patch.object(
                REHEARSAL,
                "stable_runtime_fingerprint",
                side_effect=["c" * 64, "c" * 64],
            ),
            mock.patch.object(
                REHEARSAL,
                "verify_fixtures",
                side_effect=[verified, verified],
            ),
            mock.patch.object(REHEARSAL, "run", side_effect=refusal) as runner,
        ):
            result = REHEARSAL.prove_downgrade_refusal(
                "unix:///tmp/docker.sock", fixtures, seed
            )

        self.assertTrue(result["refused"])
        self.assertTrue(result["fixtures_unchanged"])
        command = runner.call_args.args[0]
        self.assertEqual(command, REHEARSAL.preprod_command("16", "compose-config"))
        self.assertIn("--confirm-postgres16-rehearsal", command)
        phase = receipt.call_args.args[0]
        self.assertEqual(phase["status"], "running")
        self.assertEqual(phase["phase"], "writes_opened")
        self.assertEqual(phase["target_image_id"], image_id)

    def test_postgres_exec_never_invents_compose_exec_flags(self) -> None:
        container = {"Id": "a" * 64}
        result = types.SimpleNamespace(stdout=b"", stderr=b"", returncode=0)
        with (
            mock.patch.object(REHEARSAL, "postgres_container", return_value=container),
            mock.patch.object(REHEARSAL, "docker", return_value=result) as docker,
        ):
            REHEARSAL.postgres_exec("unix:///tmp/docker.sock", "psql")
            arguments = docker.call_args.args
            self.assertEqual(arguments[1:4], ("exec", "a" * 64, "psql"))
            self.assertNotIn("-T", arguments)

    def test_writer_stop_keeps_only_the_owned_postgres_container(self) -> None:
        postgres_id = "a" * 64
        writer_id = "b" * 64
        listed = types.SimpleNamespace(
            stdout=f"{postgres_id}\n{writer_id}\n".encode(), stderr=b"", returncode=0
        )
        inspected = types.SimpleNamespace(
            stdout=json.dumps(
                [
                    {
                        "Id": postgres_id,
                        "Config": {
                            "Labels": {
                                "com.docker.compose.project": "aigw-preprod",
                                "com.aigw.preprod.project": "aigw-preprod",
                                "com.docker.compose.service": "postgres",
                            }
                        },
                    },
                    {
                        "Id": writer_id,
                        "Config": {
                            "Labels": {
                                "com.docker.compose.project": "aigw-preprod",
                                "com.aigw.preprod.project": "aigw-preprod",
                                "com.docker.compose.service": "litellm",
                            }
                        },
                    },
                ]
            ).encode(),
            stderr=b"",
            returncode=0,
        )
        stopped = types.SimpleNamespace(stdout=b"", stderr=b"", returncode=0)
        with (
            mock.patch.object(
                REHEARSAL, "docker", side_effect=[listed, inspected, stopped]
            ) as docker,
            mock.patch.object(REHEARSAL, "psql") as psql,
        ):
            REHEARSAL.stop_application_writers("unix:///tmp/docker.sock")
        self.assertEqual(
            docker.call_args_list[-1].args,
            ("unix:///tmp/docker.sock", "stop", "--timeout", "60", writer_id),
        )
        psql.assert_called_once_with(
            "unix:///tmp/docker.sock", "postgres", "CHECKPOINT;"
        )

    def test_full_acceptance_passes_the_guard_for_postgres16(self) -> None:
        commands: list[list[str]] = []

        def record(command, **_kwargs):
            commands.append(command)
            return types.SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

        with (
            mock.patch.object(REHEARSAL, "preprod"),
            mock.patch.object(REHEARSAL, "run", side_effect=record),
        ):
            REHEARSAL.full_acceptance("16")
        self.assertEqual(len(commands), 2)
        for command in commands:
            self.assertIn("--postgres-major", command)
            self.assertIn("16", command)
            self.assertIn("--confirm-postgres16-rehearsal", command)

    def test_machine_receipt_is_canonical_and_mode_0644(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "receipt.json"
            with (
                mock.patch.object(REHEARSAL, "SECRETS_DIR", root),
                mock.patch.object(REHEARSAL, "RECEIPT_FILE", destination),
            ):
                REHEARSAL.atomic_receipt({"status": "passed", "format": "test"})
            self.assertEqual(
                destination.read_text(), '{"format":"test","status":"passed"}\n'
            )
            self.assertEqual(destination.stat().st_mode & 0o777, 0o644)

    def test_ansible_playbook_has_one_exact_seed_gate(self) -> None:
        playbook = (
            ROOT / "ansible/preprod-postgres18-rehearsal.yml"
        ).read_text(encoding="utf-8")
        for required in (
            "Require the fixed schema-v2 PostgreSQL rehearsal inputs",
            "preprod_seed_require_fresh_load | bool",
            "preprod-postgres18-rehearsal.py",
            "POSTGRES18_PREPROD_REHEARSAL_PASSED",
            "SEEDED_PREPROD_POSTGRES18_REHEARSAL_PASSED",
        ):
            self.assertIn(required, playbook)
        self.assertNotIn("rocky", playbook.lower())
        self.assertNotIn("parallels", playbook.lower())
        harness = (ROOT / "scripts/preprod-postgres18-rehearsal.py").read_text()
        self.assertIn("docker-compose.preprod-postgres16.yml", harness)


if __name__ == "__main__":
    unittest.main()
