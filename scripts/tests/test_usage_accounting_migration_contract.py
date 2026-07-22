from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class UsageAccountingMigrationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.migration = (
            ROOT / "compose/postgres/init/03-usage-accounting.sql"
        ).read_text()
        cls.reconcile = (
            ROOT / "compose/postgres/init/01-init-databases.sh"
        ).read_text()
        cls.stack = (
            ROOT / "ansible/roles/docker_stack/tasks/main.yml"
        ).read_text()
        cls.schema_source = (
            ROOT / "services/key-rotator/app/usage_schema.py"
        ).read_text()
        cls.store_source = (
            ROOT / "services/key-rotator/app/usage_store.py"
        ).read_text()
        cls.governance_store_source = (
            ROOT / "services/key-rotator/app/governance_store.py"
        ).read_text()
        cls.db_source = (ROOT / "services/key-rotator/app/db.py").read_text()
        cls.main_source = (ROOT / "services/key-rotator/app/main.py").read_text()
        cls.backup = (ROOT / "scripts/state-backup.sh").read_text()
        cls.restore = (ROOT / "scripts/restore_archive.py").read_text()

    def test_governance_then_usage_runs_on_boot_and_reconcile(self) -> None:
        governance = (
            "--file /docker-entrypoint-initdb.d/02-governance.sql"
        )
        usage = (
            "--file /docker-entrypoint-initdb.d/03-usage-accounting.sql"
        )
        self.assertIn(governance, self.reconcile)
        self.assertIn(usage, self.reconcile)
        self.assertLess(self.reconcile.index(governance), self.reconcile.index(usage))
        self.assertIn('usage_schema_receipt="$(', self.reconcile)
        self.assertIn(
            '[[ "$usage_schema_receipt" != "AIGW_USAGE_ACCOUNTING_SCHEMA_V1" ]]',
            self.reconcile,
        )
        self.assertLess(
            self.reconcile.index("AIGW_GOVERNANCE_SCHEMA_V1"),
            self.reconcile.index("AIGW_USAGE_ACCOUNTING_SCHEMA_V1"),
        )
        self.assertIn("02-governance.sql must run before usage accounting", self.migration)

    def test_ansible_syncs_both_read_only_sql_files(self) -> None:
        self.assertIn("postgres/init/02-governance.sql", self.stack)
        self.assertIn("postgres/init/03-usage-accounting.sql", self.stack)
        self.assertIn(
            "postgres_init_mount.results[2].stat.mode == '0644'",
            self.stack,
        )
        self.assertIn(
            "postgres_init_mount.results[3].stat.mode == '0644'",
            self.stack,
        )

    def test_expected_tables_and_reporting_views_are_exact(self) -> None:
        tables = (
            "usage_schema_version",
            "usage_events",
            "usage_reprice_previews",
            "usage_reprice_preview_rows",
            "usage_cost_adjustments",
        )
        views = ("usage_component_reporting", "usage_reporting")
        self.assertEqual(
            self.migration.count("CREATE TABLE IF NOT EXISTS"), len(tables)
        )
        for table in tables:
            self.assertIn(f'    "{table}"', self.schema_source)
            self.assertIn(
                f"CREATE TABLE IF NOT EXISTS aigw_governance.{table}",
                self.migration,
            )
        for view in views:
            self.assertIn(f'    "{view}"', self.schema_source)
            self.assertIn(
                f"CREATE OR REPLACE VIEW aigw_governance.{view}",
                self.migration,
            )
        self.assertEqual(self.migration.count("WITH (security_barrier = true)"), 2)

    def test_usage_is_prompt_free_and_records_audit_join_fields(self) -> None:
        usage_table = self.migration.split(
            "CREATE TABLE IF NOT EXISTS aigw_governance.usage_events", 1
        )[1].split(");", 1)[0]
        for required in (
            "request_id varchar(256) NOT NULL",
            "provider_response_id varchar(256)",
            "trace_id varchar(256)",
            "requested_model varchar(128)",
            "actual_model varchar(128)",
            "stable_user_id varchar(256)",
            "project_id varchar(64)",
            "egress_policy_sha256 varchar(64)",
        ):
            self.assertIn(required, usage_table)
        self.assertNotRegex(
            usage_table.lower(),
            r"\b(prompt|messages|request_headers|response_body|api_key)\s+",
        )

    def test_five_usage_classes_keep_cost_and_price_provenance(self) -> None:
        for name in (
            "normal_input",
            "cache_creation_5m",
            "cache_creation_1h",
            "cache_read",
            "output",
        ):
            self.assertIn(f"{name}_tokens bigint", self.migration)
            self.assertIn(f"{name}_configured_cost_usd numeric", self.migration)
            self.assertIn(f"{name}_price_version_id varchar", self.migration)
        self.assertIn("configured_cost_status IN ('complete', 'unknown')", self.migration)
        self.assertIn("usage_completeness IN (", self.migration)
        self.assertIn("egress_policy_sha256,", self.store_source)

    def test_database_rechecks_the_exact_effective_price(self) -> None:
        for required in (
            "CREATE OR REPLACE FUNCTION "
            "aigw_governance.validate_usage_event_price()",
            "SECURITY DEFINER",
            "price.provider_name = NEW.provider_name",
            "price.gateway_model_name = NEW.requested_model",
            "price.egress_policy_sha256 = NEW.egress_policy_sha256",
            "model.egress_policy_sha256 = NEW.egress_policy_sha256",
            "price.effective_at <= NEW.occurred_at",
            "ORDER BY price.effective_at DESC, price.version_id DESC",
            "component.price_version_id IS DISTINCT FROM expected_version_id",
            "component.configured_cost IS DISTINCT FROM expected_cost",
            "aigw_validate_usage_event_price",
        ):
            self.assertIn(required, self.migration)
        self.assertIn("aigw_validate_usage_event_price", self.schema_source)

    def test_evidence_is_append_only_and_rotator_has_no_mutation_right(self) -> None:
        self.assertIn("USAGE_TRIGGER_COUNT = len(USAGE_TABLES) * 2", self.schema_source)
        self.assertIn("UPDATE OR DELETE", self.migration)
        self.assertIn("BEFORE TRUNCATE", self.migration)
        self.assertIn("usage_adjustments_one_successor_idx", self.migration)
        self.assertIn("NULLS NOT DISTINCT", self.migration)
        self.assertIn("GRANT SELECT, INSERT ON TABLE", self.migration)
        self.assertNotRegex(
            self.migration,
            r"GRANT[^;]*(?:UPDATE|DELETE|TRUNCATE)[^;]*TO rotator",
        )
        self.assertNotIn("GRANT aigw_governance_owner TO rotator", self.migration)

    def test_adjustments_are_bound_to_the_exact_preview_and_confirmation(self) -> None:
        for required in (
            "price_preview_class_version_key",
            "UNIQUE (preview_id, usage_class, candidate_version_id)",
            "price_confirmation_preview_version_key",
            "UNIQUE (confirmation_operation_id, preview_id, version_id)",
            "usage_preview_event_class_version_key",
            "usage_adjustment_confirmation_binding_fk",
            "usage_preview_candidate_binding_fk",
            "usage_adjustment_preview_binding_fk",
            "confirmation_operation_id,\n                preview_id,\n                new_price_version_id",
            "preview_id,\n                usage_event_id,\n                usage_class,\n                new_price_version_id",
        ):
            self.assertIn(required, self.migration)

    def test_backdate_adjustment_history_is_bounded(self) -> None:
        for required in (
            "MAX_BACKDATE_ADJUSTMENT_ROWS = 10_000",
            "(event_ids, MAX_BACKDATE_ADJUSTMENT_ROWS + 1)",
            "len(adjustment_rows) > MAX_BACKDATE_ADJUSTMENT_ROWS",
            "backdate reads more than 10000 cost adjustments",
        ):
            self.assertIn(required, self.governance_store_source)

    def test_grafana_reads_views_but_not_evidence_tables(self) -> None:
        self.assertIn(
            "aigw_governance.usage_component_reporting,\n"
            "    aigw_governance.usage_reporting\n"
            "TO rotator, grafana_ro;",
            self.migration,
        )
        evidence_grant = self.migration.split(
            "GRANT SELECT, INSERT ON TABLE", 1
        )[1].split(";", 1)[0]
        self.assertNotIn("grafana_ro", evidence_grant)
        self.assertIn("GRANT USAGE ON SCHEMA aigw_governance TO grafana_ro", self.migration)

    def test_migration_is_additive_and_backup_keeps_all_evidence(self) -> None:
        for destructive in ("DROP TABLE", "DROP SCHEMA", "DELETE FROM"):
            self.assertNotIn(destructive, self.migration.upper())
        self.assertIn("-d \"$database\" --format=custom", self.backup)
        self.assertIn('for database in litellm keycloak rotator; do', self.backup)
        self.assertIn('"postgres/rotator.dump"', self.restore)

    def test_receipt_checks_version_ownership_triggers_and_rights(self) -> None:
        for required in (
            "ARRAY[1]",
            "aigw_governance_owner",
            "object.relkind = 'r'",
            "object.relkind = 'v'",
            "security_barrier=true",
            "installed_trigger.tgenabled = 'O'",
            "UPDATE, DELETE, TRUNCATE",
        ):
            self.assertIn(required, self.schema_source)
        self.assertNotIn("SELECT *", self.schema_source)
        init_schema = self.db_source.split("async def _init_schema", 1)[1].split(
            "async def ", 1
        )[0]
        self.assertIn("USAGE_SCHEMA_RECEIPT_SQL", init_schema)
        self.assertIn(
            "usage accounting schema is missing or has unsafe ownership",
            init_schema,
        )

    def test_usage_route_has_one_separate_auth_exception(self) -> None:
        self.assertIn("app.include_router(usage_router)", self.main_source)
        self.assertIn(
            'request.method == "POST" and request.url.path == "/usage/events"',
            self.main_source,
        )
        self.assertEqual(self.main_source.count('request.url.path == "/usage/events"'), 1)
        self.assertIn('state["usage_token"] = read_usage_token()', self.main_source)
        self.assertIn('state["usage_store"] = PostgresUsageStore(', self.main_source)


if __name__ == "__main__":
    unittest.main()
