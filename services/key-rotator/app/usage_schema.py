"""Expected shape of the administrator-owned usage accounting schema.

The PostgreSQL migration creates these objects. The application runs the
receipt query at startup so a missing trigger or unsafe grant stops usage
accounting before it can accept evidence.
"""

from __future__ import annotations


USAGE_TABLES = (
    "usage_schema_version",
    "usage_events",
    "usage_reprice_previews",
    "usage_reprice_preview_rows",
    "usage_cost_adjustments",
)
USAGE_INSERT_TABLES = USAGE_TABLES[1:]
USAGE_VIEWS = (
    "usage_component_reporting",
    "usage_reporting",
)
USAGE_TRIGGER_COUNT = len(USAGE_TABLES) * 2


def _sql_strings(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{value}'" for value in values)


USAGE_SCHEMA_RECEIPT_SQL = f"""
SELECT
    (SELECT array_agg(version ORDER BY version)
       FROM aigw_governance.usage_schema_version) = ARRAY[1]
    AND NOT pg_has_role(current_user, 'aigw_governance_owner', 'MEMBER')
    AND (
        SELECT count(*) = {len(USAGE_TABLES)}
        FROM pg_class object
        JOIN pg_namespace namespace ON namespace.oid = object.relnamespace
        JOIN pg_roles owner ON owner.oid = object.relowner
        WHERE namespace.nspname = 'aigw_governance'
          AND object.relkind = 'r'
          AND object.relname IN ({_sql_strings(USAGE_TABLES)})
          AND owner.rolname = 'aigw_governance_owner'
    )
    AND (
        SELECT count(*) = {len(USAGE_VIEWS)}
        FROM pg_class object
        JOIN pg_namespace namespace ON namespace.oid = object.relnamespace
        JOIN pg_roles owner ON owner.oid = object.relowner
        WHERE namespace.nspname = 'aigw_governance'
          AND object.relkind = 'v'
          AND object.relname IN ({_sql_strings(USAGE_VIEWS)})
          AND owner.rolname = 'aigw_governance_owner'
          AND 'security_barrier=true' = ANY(object.reloptions)
    )
    AND (
        SELECT count(*) = {USAGE_TRIGGER_COUNT}
        FROM pg_trigger installed_trigger
        JOIN pg_class object ON object.oid = installed_trigger.tgrelid
        JOIN pg_namespace namespace ON namespace.oid = object.relnamespace
        WHERE namespace.nspname = 'aigw_governance'
          AND object.relname IN ({_sql_strings(USAGE_TABLES)})
          AND installed_trigger.tgname LIKE 'aigw_append_only_%'
          AND installed_trigger.tgenabled = 'O'
          AND NOT installed_trigger.tgisinternal
    )
    AND EXISTS (
        SELECT 1
        FROM pg_trigger installed_trigger
        WHERE installed_trigger.tgrelid =
                'aigw_governance.usage_events'::regclass
          AND installed_trigger.tgname = 'aigw_validate_usage_event_price'
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
        FROM unnest(ARRAY[{_sql_strings(USAGE_INSERT_TABLES)}])
            AS table_name
    )
    AND (
        SELECT bool_and(
            has_table_privilege(
                current_user,
                format('aigw_governance.%I', view_name),
                'SELECT'
            )
            AND NOT has_table_privilege(
                current_user,
                format('aigw_governance.%I', view_name),
                'INSERT, UPDATE, DELETE, TRUNCATE'
            )
        )
        FROM unnest(ARRAY[{_sql_strings(USAGE_VIEWS)}]) AS view_name
    ) AS valid;
"""
