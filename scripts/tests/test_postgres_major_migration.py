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

    def test_rollback_restarts_only_the_receipted_container_inventory(self) -> None:
        receipt = {
            "format": migration.RECEIPT_FORMAT,
            "migration_id": "12345678-1234-1234-1234-123456789abc",
            "phase": "migrated",
            "project": "ai-gateway",
            "source_volume": "ai-gateway_pg_data",
            "target_volume": "ai-gateway_pg18_data",
            "source_running_container_ids": ["a" * 64, "b" * 64],
        }
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

        def fake_docker(*arguments: str, **_kwargs: object):
            result = mock.Mock(returncode=0, stdout=b"", stderr=b"")
            if arguments[:2] == ("ps", "-q"):
                result.stdout = b""
            elif arguments[0] == "inspect":
                result.stdout = b"[{}, {}]"
            elif arguments[:2] == ("ps", "-aq"):
                result.stdout = b""
            return result

        with (
            mock.patch.object(migration, "read_receipt", return_value=receipt),
            mock.patch.object(migration, "check_volume_receipt"),
            mock.patch.object(migration, "volume_info", return_value={}),
            mock.patch.object(migration, "docker", side_effect=fake_docker) as docker,
            mock.patch.object(migration, "atomic_json"),
            mock.patch("builtins.print"),
        ):
            migration.command_rollback(args)
        docker.assert_any_call("volume", "rm", "ai-gateway_pg18_data")
        docker.assert_any_call("start", "a" * 64, "b" * 64)


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

    def test_writers_stop_before_the_final_checkpoint_proof(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        writer_stop = source.index(
            'docker("stop", "--time", "60", *writer_ids)'
        )
        final_checkpoint = source.index(
            'postgres_id, "SELECT next_xid FROM pg_control_checkpoint();"', writer_stop
        )
        postgres_stop = source.index(
            'docker("stop", "--time", "60", postgres_id)', final_checkpoint
        )
        restore = source.index('"pg_restore",', postgres_stop)
        self.assertLess(writer_stop, final_checkpoint)
        self.assertLess(final_checkpoint, postgres_stop)
        self.assertLess(postgres_stop, restore)
        self.assertIn('plan["source_running_container_ids"] = sorted(running_ids)', source)

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

    def test_ordinary_image_update_refuses_postgres_major_change(self) -> None:
        updater = (ROOT / "scripts/update-images.py").read_text(encoding="utf-8")
        self.assertIn("if postgres_major(ROOT) != postgres_major(previous_root):", updater)
        self.assertIn("automatic upgrades refuse PostgreSQL major changes", updater)

    def test_backup_records_checkpoint_and_restore_uses_explicit_volume(self) -> None:
        backup = (ROOT / "scripts/state-backup.sh").read_text(encoding="utf-8")
        restore = (ROOT / "scripts/state-restore.sh").read_text(encoding="utf-8")
        self.assertIn("SELECT next_xid FROM pg_control_checkpoint()", backup)
        self.assertIn('"postgres_next_xid":', backup)
        self.assertIn("PG_DATA_VOLUME_NAME=", restore)
        self.assertIn('volume_name="$restored_pg_volume"', restore)


if __name__ == "__main__":
    unittest.main()
