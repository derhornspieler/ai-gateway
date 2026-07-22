"""Contract tests for the isolated PostgreSQL 16 to 18 migration."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/postgres-major-migrate.py"
spec = importlib.util.spec_from_file_location("postgres_major_migrate", SCRIPT)
assert spec and spec.loader
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)

SOURCE_ID = "a" * 64
WRITER_ID = "b" * 64
STOPPED_ID = "c" * 64
UNKNOWN_ID = "d" * 64
SOURCE_IMAGE = "dhi.io/postgres:16.10@sha256:" + "1" * 64
SOURCE_IMAGE_ID = "sha256:" + "2" * 64


def project_container(container_id: str, service: str, *, running: bool) -> dict[str, object]:
    container: dict[str, object] = {
        "Id": container_id,
        "Image": SOURCE_IMAGE_ID if service == "postgres" else "sha256:" + "3" * 64,
        "Config": {
            "Image": SOURCE_IMAGE if service == "postgres" else "example.invalid/app:1@sha256:" + "4" * 64,
            "Labels": {
                "com.docker.compose.project": "ai-gateway",
                "com.docker.compose.service": service,
            },
        },
        "State": {
            "Running": running,
            "StartedAt": f"started-{container_id[0]}",
            "FinishedAt": f"finished-{container_id[0]}",
        },
        "RestartCount": 0,
        "Mounts": [],
    }
    if service == "postgres":
        container["Mounts"] = [
            {
                "Type": "volume",
                "Name": "ai-gateway_pg_data",
                "Destination": migration.SOURCE_DATA_PATH,
            }
        ]
    return container


def migration_receipt(phase: str = "migrated") -> dict[str, object]:
    return {
        "format": migration.RECEIPT_FORMAT,
        "migration_id": "12345678-1234-1234-1234-123456789abc",
        "phase": phase,
        "project": "ai-gateway",
        "source_volume": "ai-gateway_pg_data",
        "target_volume": "ai-gateway_pg18_data",
        "source_quiesce_format": migration.BACKUP_QUIESCE_FORMAT,
        "source_project_container_ids": [SOURCE_ID, WRITER_ID, STOPPED_ID],
        "source_running_container_ids": [SOURCE_ID, WRITER_ID],
        "source_writer_container_ids": [WRITER_ID],
        "source_stopped_container_states": {
            WRITER_ID: {
                "started_at": "started-b",
                "finished_at": "finished-b",
                "restart_count": 0,
            },
            STOPPED_ID: {
                "started_at": "started-c",
                "finished_at": "finished-c",
                "restart_count": 0,
            },
        },
        "source_container_id": SOURCE_ID,
        "source_image": SOURCE_IMAGE,
        "source_image_id": SOURCE_IMAGE_ID,
        "source_data_path": migration.SOURCE_DATA_PATH,
    }


def volume(name: str) -> dict[str, object]:
    labels = {
        "com.docker.compose.project": "ai-gateway",
        "com.docker.compose.volume": "pg_data",
    }
    if name == "ai-gateway_pg18_data":
        labels.update(
            {
                "com.aigw.postgres.major": migration.TARGET_MAJOR,
                "com.aigw.postgres.migration-id": "12345678-1234-1234-1234-123456789abc",
            }
        )
    return {"Name": name, "Labels": labels}


class PostgresMigrationUnitTests(unittest.TestCase):
    def test_exact_postgres_18_image_contract_is_pinned(self) -> None:
        self.assertEqual(
            migration.POSTGRES_IMAGE,
            "dhi.io/postgres:18.4@sha256:"
            "a807e832c1fc9ded731956abcb53dc98ed003fd82e27275eaef8dcf52fb90236",
        )
        self.assertEqual(migration.POSTGRES_DATA_PATH, "/var/lib/postgresql/18/data")
        self.assertEqual(migration.SOURCE_MAJOR, "16")
        self.assertEqual(migration.TARGET_MAJOR, "18")

    def test_globals_inventory_is_parsed_but_never_executed(self) -> None:
        text = "\n".join(
            [
                "ALTER ROLE postgres WITH SUPERUSER;",
                "CREATE ROLE litellm;",
                "ALTER ROLE litellm WITH LOGIN;",
                "CREATE ROLE keycloak;",
                "ALTER ROLE keycloak WITH LOGIN;",
                "CREATE ROLE rotator;",
                "ALTER ROLE rotator WITH LOGIN;",
                "CREATE ROLE grafana_ro;",
                "ALTER ROLE grafana_ro WITH LOGIN;",
            ]
        )
        self.assertEqual(migration.parse_globals_roles(text), migration.EXPECTED_ROLES)

    def test_globals_reject_unknown_role_membership_and_tablespace(self) -> None:
        base = "\n".join(
            [
                "ALTER ROLE postgres WITH SUPERUSER;",
                "CREATE ROLE litellm;",
                "CREATE ROLE keycloak;",
                "CREATE ROLE rotator;",
                "CREATE ROLE grafana_ro;",
            ]
        )
        with self.assertRaisesRegex(migration.MigrationError, "inventory"):
            migration.parse_globals_roles(base + "\nCREATE ROLE surprise;")
        with self.assertRaisesRegex(migration.MigrationError, "memberships"):
            migration.parse_globals_roles(base + "\nGRANT litellm TO keycloak;")
        with self.assertRaisesRegex(migration.MigrationError, "tablespace"):
            migration.parse_globals_roles(base + "\nCREATE TABLESPACE outside LOCATION '/tmp';")

    def test_env_reader_selects_only_exact_postgres_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / ".env"
            path.write_text(
                "PG_SUPER_PASSWORD=a\n"
                "PG_LITELLM_PASSWORD=b\n"
                "PG_KEYCLOAK_PASSWORD=c\n"
                "PG_ROTATOR_PASSWORD=d\n"
                "PG_GRAFANA_RO_PASSWORD=e\n"
                "UNRELATED_SECRET=do-not-copy\n",
                encoding="utf-8",
            )
            path.chmod(0o600)
            # parse_env's production ownership check is tested by exact source
            # contracts below; a local developer does not own files as uid 0.
            original_lstat = Path.lstat

            class Metadata:
                st_mode = 0o100600
                st_nlink = 1
                st_uid = 0
                st_gid = 0

            try:
                Path.lstat = lambda _self: Metadata()  # type: ignore[method-assign]
                values = migration.parse_env(path)
            finally:
                Path.lstat = original_lstat  # type: ignore[method-assign]
            self.assertEqual(set(values), set(migration.SECRET_KEYS))
            self.assertNotIn("UNRELATED_SECRET", values)

    def test_cli_requires_bounded_backup_age_and_fresh_volume(self) -> None:
        common = [
            "plan",
            "--receipt",
            "/tmp/receipt",
            "--project",
            "ai-gateway",
            "--target-volume",
            "ai-gateway_pg18_data",
            "--input",
            "/tmp/backup.age",
            "--identity",
            "/tmp/key",
            "--sha256",
            "0" * 64,
            "--source-volume",
            "ai-gateway_pg_data",
            "--deployment-profile",
            "generic-rocky9",
        ]
        parsed = migration.parse_args(common)
        self.assertEqual(parsed.max_backup_age_minutes, 30)
        with self.assertRaises(SystemExit):
            migration.parse_args(common + ["--max-backup-age-minutes", "61"])

    def test_host_architecture_maps_to_the_exact_image_platform(self) -> None:
        with mock.patch.object(migration, "docker") as docker:
            docker.return_value.stdout = b"aarch64\n"
            self.assertEqual(migration.host_platform(), "linux/arm64")
            docker.return_value.stdout = b"x86_64\n"
            self.assertEqual(migration.host_platform(), "linux/amd64")
            docker.return_value.stdout = b"riscv64\n"
            with self.assertRaisesRegex(migration.MigrationError, "unsupported"):
                migration.host_platform()

    def test_final_checkpoint_uses_psql_error_stop(self) -> None:
        with mock.patch.object(migration, "docker") as docker:
            migration.force_checkpoint("a" * 64)
        docker.assert_called_once_with(
            "exec",
            "a" * 64,
            "psql",
            "--username",
            "postgres",
            "--dbname",
            "postgres",
            "--set",
            "ON_ERROR_STOP=1",
            "--command",
            "CHECKPOINT;",
        )

    def test_legacy_or_malformed_backup_barrier_is_rejected(self) -> None:
        migration.require_backup_write_barrier(
            {"postgres_write_barrier": migration.BACKUP_WRITE_BARRIER}
        )
        for manifest in ({}, {"postgres_write_barrier": "older-contract"}):
            with self.subTest(manifest=manifest):
                with self.assertRaisesRegex(migration.MigrationError, "checkpoint barrier"):
                    migration.require_backup_write_barrier(manifest)

    def test_backup_quiesce_contract_records_exact_source_and_container_graph(self) -> None:
        receipt = migration_receipt()
        contract = migration.quiesce_contract_from_receipt(receipt)
        self.assertEqual(
            contract["project_container_ids"], [SOURCE_ID, WRITER_ID, STOPPED_ID]
        )
        self.assertEqual(contract["prior_running_container_ids"], [SOURCE_ID, WRITER_ID])
        self.assertEqual(contract["writer_container_ids"], [WRITER_ID])
        self.assertEqual(
            set(contract["stopped_container_states"]), {WRITER_ID, STOPPED_ID}
        )
        self.assertEqual(contract["source"]["image_id"], SOURCE_IMAGE_ID)

    def test_quiesce_requires_only_the_recorded_postgres_source_running(self) -> None:
        receipt = migration_receipt()
        contract = migration.quiesce_contract_from_receipt(receipt)
        containers = [
            project_container(SOURCE_ID, "postgres", running=True),
            project_container(WRITER_ID, "litellm", running=False),
            project_container(STOPPED_ID, "volume-init", running=False),
        ]
        migration.verify_quiesced_source(
            containers, containers[0], contract, project="ai-gateway"
        )
        containers[1]["State"] = {"Running": True}
        with self.assertRaisesRegex(migration.MigrationError, "restarted"):
            migration.verify_quiesced_source(
                containers, containers[0], contract, project="ai-gateway"
            )

    def test_rollback_restarts_only_the_receipted_container_inventory(self) -> None:
        receipt = migration_receipt()
        args = migration.parse_args(
            [
                "rollback",
                "--receipt",
                "/tmp/receipt",
                "--project",
                "ai-gateway",
                "--target-volume",
                "ai-gateway_pg18_data",
                "--confirm",
                "ROLLBACK_POSTGRES_18_TO_16",
            ]
        )

        before = [
            project_container(SOURCE_ID, "postgres", running=True),
            project_container(WRITER_ID, "litellm", running=True),
            project_container(STOPPED_ID, "volume-init", running=False),
        ]
        stopped = [
            project_container(SOURCE_ID, "postgres", running=False),
            project_container(WRITER_ID, "litellm", running=False),
            project_container(STOPPED_ID, "volume-init", running=False),
        ]
        restored = [
            project_container(SOURCE_ID, "postgres", running=True),
            project_container(WRITER_ID, "litellm", running=True),
            project_container(STOPPED_ID, "volume-init", running=False),
        ]

        def fake_docker(*arguments: str, **_kwargs: object):
            result = mock.Mock(returncode=0, stdout=b"", stderr=b"")
            if arguments[:2] == ("ps", "-aq"):
                result.stdout = b""
            return result

        def fake_volume_info(name: str):
            return volume(name)

        with (
            mock.patch.object(migration, "read_receipt", return_value=receipt),
            mock.patch.object(migration, "volume_info", side_effect=fake_volume_info),
            mock.patch.object(
                migration, "project_containers", side_effect=[before, stopped, restored]
            ),
            mock.patch.object(migration, "docker", side_effect=fake_docker) as docker,
            mock.patch.object(migration, "atomic_json"),
            mock.patch("builtins.print"),
        ):
            migration.command_rollback(args)
        docker.assert_any_call("stop", "--time", "60", SOURCE_ID, WRITER_ID)
        docker.assert_any_call("volume", "rm", "ai-gateway_pg18_data")
        docker.assert_any_call("start", SOURCE_ID, WRITER_ID)

    def test_rollback_refuses_unknown_project_container_before_mutation(self) -> None:
        receipt = migration_receipt()
        args = migration.parse_args(
            [
                "rollback",
                "--receipt",
                "/tmp/receipt",
                "--project",
                "ai-gateway",
                "--target-volume",
                "ai-gateway_pg18_data",
                "--confirm",
                "ROLLBACK_POSTGRES_18_TO_16",
            ]
        )
        containers = [
            project_container(SOURCE_ID, "postgres", running=False),
            project_container(WRITER_ID, "litellm", running=False),
            project_container(STOPPED_ID, "volume-init", running=False),
            project_container(UNKNOWN_ID, "surprise", running=False),
        ]
        with (
            mock.patch.object(migration, "read_receipt", return_value=receipt),
            mock.patch.object(migration, "volume_info", side_effect=lambda name: volume(name)),
            mock.patch.object(migration, "project_containers", return_value=containers),
            mock.patch.object(migration, "docker") as docker,
            mock.patch.object(migration, "atomic_json") as atomic_json,
        ):
            with self.assertRaisesRegex(migration.MigrationError, "containers changed"):
                migration.command_rollback(args)
        docker.assert_not_called()
        atomic_json.assert_not_called()

    def test_rollback_after_writes_opened_or_validated_has_zero_docker_mutations(self) -> None:
        args = migration.parse_args(
            [
                "rollback",
                "--receipt",
                "/tmp/receipt",
                "--project",
                "ai-gateway",
                "--target-volume",
                "ai-gateway_pg18_data",
                "--confirm",
                "ROLLBACK_POSTGRES_18_TO_16",
            ]
        )
        for phase in ("writes_opened", "validated"):
            with self.subTest(phase=phase):
                with (
                    mock.patch.object(
                        migration, "read_receipt", return_value=migration_receipt(phase)
                    ),
                    mock.patch.object(migration, "volume_info") as volume_info,
                    mock.patch.object(
                        migration, "project_containers"
                    ) as project_containers,
                    mock.patch.object(migration, "docker") as docker,
                    mock.patch.object(migration, "atomic_json") as atomic_json,
                ):
                    with self.assertRaisesRegex(migration.MigrationError, "writes reopened"):
                        migration.command_rollback(args)
                volume_info.assert_not_called()
                project_containers.assert_not_called()
                docker.assert_not_called()
                atomic_json.assert_not_called()

    def test_completed_rollback_is_idempotent_without_docker_mutation(self) -> None:
        receipt = migration_receipt("rolled_back")
        args = migration.parse_args(
            [
                "rollback",
                "--receipt",
                "/tmp/receipt",
                "--project",
                "ai-gateway",
                "--target-volume",
                "ai-gateway_pg18_data",
                "--confirm",
                "ROLLBACK_POSTGRES_18_TO_16",
            ]
        )
        containers = [
            project_container(SOURCE_ID, "postgres", running=True),
            project_container(WRITER_ID, "litellm", running=True),
            project_container(STOPPED_ID, "volume-init", running=False),
        ]
        with (
            mock.patch.object(migration, "read_receipt", return_value=receipt),
            mock.patch.object(
                migration,
                "volume_info",
                side_effect=lambda name: volume(name) if name.endswith("pg_data") else None,
            ),
            mock.patch.object(migration, "project_containers", return_value=containers),
            mock.patch.object(migration, "docker") as docker,
            mock.patch.object(migration, "atomic_json") as atomic_json,
            mock.patch("builtins.print"),
        ):
            migration.command_rollback(args)
        docker.assert_not_called()
        atomic_json.assert_not_called()

    def test_interrupted_rollback_resumes_after_target_removal_and_partial_start(self) -> None:
        receipt = migration_receipt("rollback_in_progress")
        receipt["rollback_target_existed"] = True
        args = migration.parse_args(
            [
                "rollback",
                "--receipt",
                "/tmp/receipt",
                "--project",
                "ai-gateway",
                "--target-volume",
                "ai-gateway_pg18_data",
                "--confirm",
                "ROLLBACK_POSTGRES_18_TO_16",
            ]
        )
        partial = [
            project_container(SOURCE_ID, "postgres", running=True),
            project_container(WRITER_ID, "litellm", running=False),
            project_container(STOPPED_ID, "volume-init", running=False),
        ]
        stopped = [
            project_container(SOURCE_ID, "postgres", running=False),
            project_container(WRITER_ID, "litellm", running=False),
            project_container(STOPPED_ID, "volume-init", running=False),
        ]
        restored = [
            project_container(SOURCE_ID, "postgres", running=True),
            project_container(WRITER_ID, "litellm", running=True),
            project_container(STOPPED_ID, "volume-init", running=False),
        ]

        def fake_docker(*arguments: str, **_kwargs: object):
            result = mock.Mock(returncode=0, stdout=b"", stderr=b"")
            if arguments[:2] == ("ps", "-aq"):
                result.stdout = b""
            return result

        with (
            mock.patch.object(migration, "read_receipt", return_value=receipt),
            mock.patch.object(
                migration,
                "volume_info",
                side_effect=lambda name: volume(name) if name.endswith("pg_data") else None,
            ),
            mock.patch.object(
                migration,
                "project_containers",
                side_effect=[partial, stopped, restored],
            ),
            mock.patch.object(migration, "docker", side_effect=fake_docker) as docker,
            mock.patch.object(migration, "atomic_json") as atomic_json,
            mock.patch("builtins.print"),
        ):
            migration.command_rollback(args)
        docker.assert_any_call("stop", "--time", "60", SOURCE_ID)
        docker.assert_any_call("start", SOURCE_ID, WRITER_ID)
        self.assertNotIn(
            mock.call("volume", "rm", "ai-gateway_pg18_data"), docker.mock_calls
        )
        atomic_json.assert_called_once()


class PostgresMigrationRepositoryContracts(unittest.TestCase):
    def test_compose_uses_postgres_18_and_explicit_new_volume(self) -> None:
        compose = (ROOT / "compose/docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn(migration.POSTGRES_IMAGE, compose)
        self.assertIn("- pg_data:/var/lib/postgresql/18/data", compose)
        self.assertIn(
            "name: ${PG_DATA_VOLUME_NAME:?PG_DATA_VOLUME_NAME must be set}", compose
        )
        self.assertNotIn("pg_data:/var/lib/postgresql/16/data", compose)

    def test_migration_uses_logical_restore_and_fail_closed_cutover(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('"--single-transaction"', source)
        self.assertIn('"--exit-on-error"', source)
        self.assertNotIn("psql -f globals.sql", source)
        self.assertNotIn("pg_upgrade", source)
        self.assertIn("rollback refused after writes reopened", source)
        self.assertIn("fix forward", source)
        self.assertIn("PostgreSQL changed after the backup", source)

    def test_quiesced_writers_are_proved_before_the_final_checkpoint(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        migrate = source.split("def command_migrate", 1)[1].split(
            "def check_volume_receipt", 1
        )[0]
        self.assertNotIn('docker("stop", "--time", "60", *writer_ids)', migrate)
        quiesce_proof = migrate.index("verify_quiesced_source(")
        forced_checkpoint = migrate.index("force_checkpoint(postgres_id)", quiesce_proof)
        final_checkpoint = migrate.index(
            'postgres_id, "SELECT next_xid FROM pg_control_checkpoint();"',
            forced_checkpoint,
        )
        final_quiesce_proof = migrate.index(
            "verify_quiesced_source(", final_checkpoint
        )
        postgres_stop = migrate.index(
            'docker("stop", "--time", "60", postgres_id)', final_checkpoint
        )
        restore = migrate.index('"pg_restore",', postgres_stop)
        self.assertLess(quiesce_proof, forced_checkpoint)
        self.assertLess(forced_checkpoint, final_checkpoint)
        self.assertLess(final_checkpoint, final_quiesce_proof)
        self.assertLess(final_checkpoint, postgres_stop)
        self.assertLess(postgres_stop, restore)
        self.assertIn('"source_writer_container_ids": quiesce["writer_container_ids"]', source)

    def test_target_database_contract_runs_before_and_after_restore(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        migrate = source.split("def command_migrate", 1)[1].split(
            "def check_volume_receipt", 1
        )[0]
        ready = migrate.index("wait_for_postgres(container)")
        init_before = migrate.index("reconcile_database_contract(container)", ready)
        restore = migrate.index('"pg_restore",', init_before)
        init_after = migrate.index("reconcile_database_contract(container)", restore)
        validate = migrate.index("metrics = validate_database(container)", init_after)
        self.assertLess(ready, init_before)
        self.assertLess(init_before, restore)
        self.assertLess(restore, init_after)
        self.assertLess(init_after, validate)
        self.assertEqual(migrate.count("reconcile_database_contract(container)"), 2)

    def test_ansible_runs_separate_plan_migrate_validate_workflow(self) -> None:
        playbook = (ROOT / "ansible/migrate-postgres18.yml").read_text(encoding="utf-8")
        for command in ("plan", "migrate", "rollback", "validate"):
            self.assertIn(f"- {command}\n", playbook)
        self.assertIn("- import_playbook: deploy-stack-only.yml", playbook)
        self.assertIn("postgres_migration_stage", playbook)
        self.assertIn("MIGRATE_POSTGRES_16_TO_18", playbook)
        bounded = playbook.split(
            "- name: Plan and run the bounded PostgreSQL 18 migration", 1
        )[1].split("- import_playbook: deploy-stack-only.yml", 1)[0]
        self.assertLess(bounded.index("- plan"), bounded.index("always:"))
        self.assertLess(bounded.index("- migrate"), bounded.index("always:"))
        self.assertIn("Remove the temporary PostgreSQL migration age identity", bounded)

    def test_ordinary_image_update_refuses_postgres_major_change(self) -> None:
        updater = (ROOT / "scripts/update-images.py").read_text(encoding="utf-8")
        self.assertIn("if postgres_major(ROOT) != postgres_major(previous_root):", updater)
        self.assertIn("automatic upgrades refuse PostgreSQL major changes", updater)

    def test_backup_records_checkpoint_and_restore_uses_explicit_volume(self) -> None:
        backup = (ROOT / "scripts/state-backup.sh").read_text(encoding="utf-8")
        restore = (ROOT / "scripts/state-restore.sh").read_text(encoding="utf-8")
        self.assertIn("SELECT next_xid FROM pg_control_checkpoint()", backup)
        self.assertIn('"postgres_next_xid":', backup)
        self.assertIn('"postgres_write_barrier":', backup)
        self.assertIn(migration.BACKUP_WRITE_BARRIER, backup)
        self.assertIn("--major-migration-quiesce", backup)
        self.assertIn("QUIESCE_POSTGRES_16_FOR_MAJOR_MIGRATION", backup)
        self.assertIn(migration.BACKUP_QUIESCE_FORMAT, backup)
        self.assertIn('"project_container_ids": project_ids', backup)
        self.assertIn('"prior_running_container_ids": prior_running_ids', backup)
        self.assertIn('"writer_container_ids": writer_ids', backup)
        self.assertIn('"stopped_container_states": stopped_states', backup)
        self.assertIn('"source": source', backup)
        self.assertIn('"${docker_cmd[@]}" start "$postgres_cid"', backup)
        self.assertIn('elif ((${#running_containers[@]})); then', backup)
        dumps_end = backup.index("done\n# Flush the post-dump transaction state")
        final_checkpoint = backup.index("-c CHECKPOINT", dumps_end)
        checkpoint_read = backup.index("SELECT next_xid FROM pg_control_checkpoint()")
        self.assertLess(dumps_end, final_checkpoint)
        self.assertLess(final_checkpoint, checkpoint_read)
        self.assertIn("PG_DATA_VOLUME_NAME=", restore)
        self.assertIn('volume_name="$restored_pg_volume"', restore)


if __name__ == "__main__":
    unittest.main()
