"""Expected shape of the administrator-owned governance schema.

The PostgreSQL migration is the only place that creates these objects.  The
application uses this small receipt query to prove that the migration ran and
that the rotator still has append-only access.
"""

from __future__ import annotations


GOVERNANCE_TABLES = (
    "schema_version",
    "governed_model_versions",
    "governed_model_events",
    "governed_price_versions",
    "price_backdate_previews",
    "price_backdate_confirmations",
    "governance_audit",
)
GOVERNANCE_INSERT_TABLES = GOVERNANCE_TABLES[1:]
GOVERNANCE_TRIGGER_COUNT = len(GOVERNANCE_TABLES) * 2


def _sql_strings(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{value}'" for value in values)


GOVERNANCE_SCHEMA_RECEIPT_SQL = f"""
SELECT
    (SELECT array_agg(version ORDER BY version)
       FROM aigw_governance.schema_version) = ARRAY[1]
    AND NOT pg_has_role(current_user, 'aigw_governance_owner', 'MEMBER')
    AND (
        SELECT count(*) = {len(GOVERNANCE_TABLES)}
        FROM pg_class object
        JOIN pg_namespace namespace ON namespace.oid = object.relnamespace
        JOIN pg_roles owner ON owner.oid = object.relowner
        WHERE namespace.nspname = 'aigw_governance'
          AND object.relkind = 'r'
          AND object.relname IN ({_sql_strings(GOVERNANCE_TABLES)})
          AND owner.rolname = 'aigw_governance_owner'
    )
    AND (
        SELECT count(*) = {GOVERNANCE_TRIGGER_COUNT}
        FROM pg_trigger installed_trigger
        JOIN pg_class object ON object.oid = installed_trigger.tgrelid
        JOIN pg_namespace namespace ON namespace.oid = object.relnamespace
        WHERE namespace.nspname = 'aigw_governance'
          AND object.relname IN ({_sql_strings(GOVERNANCE_TABLES)})
          AND installed_trigger.tgname LIKE 'aigw_append_only_%'
          AND installed_trigger.tgenabled = 'O'
          AND NOT installed_trigger.tgisinternal
    )
    AND (
        SELECT bool_and(
            has_table_privilege(
                current_user,
                format('aigw_governance.%I', table_name),
                'SELECT'
            )
            AND has_table_privilege(
                current_user,
                format('aigw_governance.%I', table_name),
                'INSERT'
            )
            AND NOT has_table_privilege(
                current_user,
                format('aigw_governance.%I', table_name),
                'UPDATE, DELETE, TRUNCATE'
            )
        )
        FROM unnest(ARRAY[{_sql_strings(GOVERNANCE_INSERT_TABLES)}])
            AS table_name
    ) AS valid;
"""
