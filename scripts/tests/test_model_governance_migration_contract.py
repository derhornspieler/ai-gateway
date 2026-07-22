from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class ModelGovernanceMigrationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.migration = (
            ROOT / "compose/postgres/init/02-governance.sql"
        ).read_text()
        cls.reconcile = (
            ROOT / "compose/postgres/init/01-init-databases.sh"
        ).read_text()
        cls.db_source = (
            ROOT / "services/key-rotator/app/db.py"
        ).read_text()
        cls.schema_source = (
            ROOT / "services/key-rotator/app/governance_schema.py"
        ).read_text()
        cls.store_source = (
            ROOT / "services/key-rotator/app/governance_store.py"
        ).read_text()
        cls.stack = (
            ROOT / "ansible/roles/docker_stack/tasks/main.yml"
        ).read_text()

    def test_cluster_admin_runs_the_migration_on_boot_and_reconcile(self) -> None:
        self.assertIn(
            "--file /docker-entrypoint-initdb.d/02-governance.sql",
            self.reconcile,
        )
        self.assertIn(
            'governance_schema_receipt="$(',
            self.reconcile,
        )
        self.assertIn(
            '[[ "$governance_schema_receipt" != "AIGW_GOVERNANCE_SCHEMA_V1" ]]',
            self.reconcile,
        )
        self.assertIn("--quiet --tuples-only --no-align", self.reconcile)
        self.assertIn("SELECT count(*) = 14", self.migration)
        self.assertIn("postgres/init/02-governance.sql", self.stack)
        self.assertIn("postgres_init_mount.results[2].stat.mode == '0644'", self.stack)
        reconcile_task = self.stack.split(
            "- name: Reconcile PostgreSQL roles, passwords, databases, and CONNECT ACLs",
            1,
        )[1].split("- name:", 1)[0]
        self.assertIn("01-init-databases.sh", reconcile_task)
        self.assertIn("no_log: true", reconcile_task)
        self.assertLess(
            self.stack.index(
                "- name: Reconcile PostgreSQL roles, passwords, databases, and CONNECT ACLs"
            ),
            self.stack.index(
                "- name: Deploy stack without implicitly rebuilding custom images"
            ),
        )

    def test_non_login_owner_and_role_boundary_are_explicit(self) -> None:
        for required in (
            "CREATE ROLE aigw_governance_owner NOLOGIN",
            "ALTER ROLE aigw_governance_owner WITH NOLOGIN NOSUPERUSER",
            "ALTER SCHEMA aigw_governance OWNER TO aigw_governance_owner",
            "OWNER TO aigw_governance_owner",
            "REVOKE ALL ON SCHEMA aigw_governance FROM PUBLIC, rotator",
            "GRANT USAGE ON SCHEMA aigw_governance TO rotator",
        ):
            self.assertIn(required, self.migration)
        self.assertNotIn("GRANT aigw_governance_owner TO rotator", self.migration)
        self.assertIn("pg_auth_members", self.migration)

    def test_application_can_only_read_and_append_evidence(self) -> None:
        self.assertIn("GRANT SELECT, INSERT ON TABLE", self.migration)
        self.assertIn("GRANT SELECT ON TABLE aigw_governance.schema_version", self.migration)
        self.assertNotRegex(
            self.migration,
            r"GRANT[^;]*(?:UPDATE|DELETE|TRUNCATE)[^;]*TO rotator",
        )
        for mutation in ("UPDATE OR DELETE", "TRUNCATE"):
            self.assertIn(mutation, self.migration)
        self.assertIn(
            "trigger.tgenabled",
            self.schema_source.replace("installed_", ""),
        )
        self.assertIn(
            "GOVERNANCE_TRIGGER_COUNT = len(GOVERNANCE_TABLES) * 2",
            self.schema_source,
        )
        self.assertEqual(
            self.schema_source.count(
                "object.relname IN ({_sql_strings(GOVERNANCE_TABLES)})"
            ),
            2,
        )

    def test_schema_version_and_provider_policy_binding_fail_closed(self) -> None:
        self.assertIn("CHECK (version = 1)", self.migration)
        self.assertIn("ARRAY[1]", self.migration)
        self.assertGreaterEqual(self.migration.count("egress_policy_sha256"), 12)
        self.assertIn("schema is missing or has unsafe ownership", self.db_source)
        init_schema = self.db_source.split(
            "async def _init_schema", 1
        )[1].split("async def ", 1)[0]
        self.assertIn("GOVERNANCE_SCHEMA_RECEIPT_SQL", init_schema)
        self.assertNotIn("CREATE_GOVERNED_MODELS_SQL", init_schema)
        self.assertNotIn("CREATE_GOVERNANCE_APPEND_ONLY", init_schema)

    def test_model_api_base_accepts_only_the_two_internal_egress_services(self) -> None:
        self.assertIn(
            "^http://(envoy-egress|wif-egress-mock):8080/[a-z0-9-]+$",
            self.migration,
        )
        api_base_check = self.migration.split(
            "api_base varchar(512) NOT NULL", 1
        )[1].split("litellm_credential_name", 1)[0]
        for unsafe in ("https://", "0.0.0.0", "localhost", "127.0.0.1"):
            self.assertNotIn(unsafe, api_base_check)

    def test_runtime_queries_name_the_protected_schema(self) -> None:
        runtime = self.store_source
        table_names = (
            "governed_model_versions",
            "governed_model_events",
            "governed_price_versions",
            "price_backdate_previews",
            "price_backdate_confirmations",
            "governance_audit",
        )
        for table in table_names:
            self.assertNotRegex(
                runtime,
                rf"(?:FROM|INTO)\s+{table}\b",
                f"unqualified SQL table {table}",
            )

    def test_runtime_receipt_and_migration_name_the_same_tables(self) -> None:
        table_names = (
            "schema_version",
            "governed_model_versions",
            "governed_model_events",
            "governed_price_versions",
            "price_backdate_previews",
            "price_backdate_confirmations",
            "governance_audit",
        )
        self.assertEqual(
            self.migration.count("CREATE TABLE IF NOT EXISTS"),
            len(table_names),
        )
        for table in table_names:
            self.assertIn(f'    "{table}"', self.schema_source)
            self.assertIn(
                f"CREATE TABLE IF NOT EXISTS aigw_governance.{table}",
                self.migration,
            )


if __name__ == "__main__":
    unittest.main()
