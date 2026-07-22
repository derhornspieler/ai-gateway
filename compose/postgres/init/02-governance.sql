\set ON_ERROR_STOP on

-- Model and price evidence has a separate non-login owner. The key-rotator
-- login can read and append records, but it cannot change the schema, disable
-- its triggers, or delete history. PostgreSQL runs this file as the cluster
-- administrator during first boot and every Ansible reconciliation.
SELECT 'CREATE ROLE aigw_governance_owner NOLOGIN'
WHERE NOT EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname = 'aigw_governance_owner'
) \gexec
ALTER ROLE aigw_governance_owner WITH NOLOGIN NOSUPERUSER NOCREATEDB
    NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
ALTER ROLE aigw_governance_owner RESET ALL;

-- Neither role may SET ROLE across the application/migration boundary.
SELECT format('REVOKE %I FROM %I', granted.rolname, member.rolname)
FROM pg_auth_members membership
JOIN pg_roles granted ON granted.oid = membership.roleid
JOIN pg_roles member ON member.oid = membership.member
WHERE granted.rolname IN ('aigw_governance_owner', 'rotator')
   OR member.rolname IN ('aigw_governance_owner', 'rotator')
ORDER BY granted.rolname, member.rolname \gexec

\connect rotator
BEGIN;

CREATE SCHEMA IF NOT EXISTS aigw_governance
    AUTHORIZATION aigw_governance_owner;
ALTER SCHEMA aigw_governance OWNER TO aigw_governance_owner;

-- Move the short-lived pre-release tables, if they exist. A conflicting pair
-- is refused instead of guessing which copy contains the real evidence.
DO $migration$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'governed_model_versions',
        'governed_model_events',
        'governed_price_versions',
        'price_backdate_previews',
        'price_backdate_confirmations',
        'governance_audit'
    ]
    LOOP
        IF to_regclass('public.' || table_name) IS NOT NULL
           AND to_regclass('aigw_governance.' || table_name) IS NOT NULL THEN
            RAISE EXCEPTION 'conflicting governance table: %', table_name;
        ELSIF to_regclass('public.' || table_name) IS NOT NULL THEN
            EXECUTE format(
                'ALTER TABLE public.%I SET SCHEMA aigw_governance',
                table_name
            );
        END IF;
    END LOOP;
END;
$migration$;

-- The pre-release application-owned tables may already have row guards. The
-- migration administrator removes those guards only inside this transaction,
-- fills the new immutable policy column, and installs owner-controlled row
-- and TRUNCATE guards below before commit.
DO $legacy_triggers$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'governed_model_versions',
        'governed_model_events',
        'governed_price_versions',
        'price_backdate_previews',
        'price_backdate_confirmations',
        'governance_audit'
    ]
    LOOP
        IF to_regclass('aigw_governance.' || table_name) IS NOT NULL THEN
            EXECUTE format(
                'DROP TRIGGER IF EXISTS %I ON aigw_governance.%I',
                'aigw_append_only_' || table_name,
                table_name
            );
            EXECUTE format(
                'DROP TRIGGER IF EXISTS %I ON aigw_governance.%I',
                'aigw_append_only_truncate_' || table_name,
                table_name
            );
        END IF;
    END LOOP;
END;
$legacy_triggers$;

SET LOCAL ROLE aigw_governance_owner;

CREATE TABLE IF NOT EXISTS aigw_governance.schema_version (
    version integer PRIMARY KEY CHECK (version = 1),
    installed_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS aigw_governance.governed_model_versions (
    operation_id uuid PRIMARY KEY,
    gateway_model_name varchar(128) NOT NULL,
    provider_name varchar(63) NOT NULL,
    provider_model_id varchar(128) NOT NULL,
    initial_visible_in_discovery boolean NOT NULL,
    egress_policy_sha256 varchar(64) NOT NULL
        CHECK (egress_policy_sha256 ~ '^[0-9a-f]{64}$'),
    litellm_model varchar(256) NOT NULL,
    api_base varchar(512) NOT NULL
        CHECK (
            api_base ~
            '^http://(envoy-egress|wif-egress-mock):8080/[a-z0-9-]+$'
        ),
    litellm_credential_name varchar(128) NOT NULL,
    cache_control_injection_points jsonb NOT NULL,
    source_reference varchar(256) NOT NULL,
    review_note varchar(500) NOT NULL,
    actor varchar(128) NOT NULL,
    document_sha256 varchar(64) NOT NULL
        CHECK (document_sha256 ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (gateway_model_name, egress_policy_sha256),
    UNIQUE (provider_name, provider_model_id, egress_policy_sha256)
);

CREATE TABLE IF NOT EXISTS aigw_governance.governed_model_events (
    event_sequence bigserial PRIMARY KEY,
    operation_id uuid NOT NULL UNIQUE,
    model_operation_id uuid NOT NULL REFERENCES
        aigw_governance.governed_model_versions(operation_id),
    action varchar(16) NOT NULL CHECK (
        action IN ('activate', 'show', 'hide', 'retire')
    ),
    actor varchar(128) NOT NULL,
    document_sha256 varchar(64) NOT NULL
        CHECK (document_sha256 ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS aigw_governance.governed_price_versions (
    version_id varchar(128) PRIMARY KEY,
    operation_id uuid NOT NULL UNIQUE,
    model_operation_id uuid NOT NULL REFERENCES
        aigw_governance.governed_model_versions(operation_id),
    egress_policy_sha256 varchar(64) NOT NULL
        CHECK (egress_policy_sha256 ~ '^[0-9a-f]{64}$'),
    gateway_model_name varchar(128) NOT NULL,
    provider_name varchar(63) NOT NULL,
    usage_class varchar(32) NOT NULL CHECK (usage_class IN (
        'normal_input',
        'cache_creation_5m',
        'cache_creation_1h',
        'cache_read',
        'output'
    )),
    token_unit bigint NOT NULL CHECK (token_unit BETWEEN 1 AND 1000000000),
    amount numeric(30, 12) NOT NULL CHECK (amount BETWEEN 0 AND 1000000),
    currency varchar(3) NOT NULL CHECK (currency = 'USD'),
    explicit_free boolean NOT NULL CHECK (
        (amount = 0 AND explicit_free)
        OR (amount > 0 AND NOT explicit_free)
    ),
    effective_at timestamptz NOT NULL,
    source_reference varchar(256) NOT NULL,
    review_note varchar(500) NOT NULL,
    actor varchar(128) NOT NULL,
    document_sha256 varchar(64) NOT NULL
        CHECK (document_sha256 ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (model_operation_id, usage_class, effective_at)
);

CREATE TABLE IF NOT EXISTS aigw_governance.price_backdate_previews (
    preview_id uuid PRIMARY KEY,
    model_operation_id uuid NOT NULL REFERENCES
        aigw_governance.governed_model_versions(operation_id),
    egress_policy_sha256 varchar(64) NOT NULL
        CHECK (egress_policy_sha256 ~ '^[0-9a-f]{64}$'),
    candidate_version_id varchar(128) NOT NULL,
    gateway_model_name varchar(128) NOT NULL,
    provider_name varchar(63) NOT NULL,
    usage_class varchar(32) NOT NULL CHECK (usage_class IN (
        'normal_input',
        'cache_creation_5m',
        'cache_creation_1h',
        'cache_read',
        'output'
    )),
    token_unit bigint NOT NULL CHECK (token_unit BETWEEN 1 AND 1000000000),
    amount numeric(30, 12) NOT NULL CHECK (amount BETWEEN 0 AND 1000000),
    currency varchar(3) NOT NULL CHECK (currency = 'USD'),
    explicit_free boolean NOT NULL CHECK (
        (amount = 0 AND explicit_free)
        OR (amount > 0 AND NOT explicit_free)
    ),
    effective_at timestamptz NOT NULL,
    source_reference varchar(256) NOT NULL,
    review_note varchar(500) NOT NULL,
    actor varchar(128) NOT NULL,
    baseline_price_policy_sha256 varchar(64) NOT NULL
        CHECK (baseline_price_policy_sha256 ~ '^[0-9a-f]{64}$'),
    candidate_sha256 varchar(64) NOT NULL
        CHECK (candidate_sha256 ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS aigw_governance.price_backdate_confirmations (
    confirmation_operation_id uuid PRIMARY KEY,
    preview_id uuid NOT NULL UNIQUE REFERENCES
        aigw_governance.price_backdate_previews(preview_id),
    version_id varchar(128) NOT NULL UNIQUE REFERENCES
        aigw_governance.governed_price_versions(version_id),
    candidate_sha256 varchar(64) NOT NULL
        CHECK (candidate_sha256 ~ '^[0-9a-f]{64}$'),
    actor varchar(128) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS aigw_governance.governance_audit (
    id bigserial PRIMARY KEY,
    operation_id uuid NOT NULL UNIQUE,
    actor varchar(128) NOT NULL,
    action varchar(64) NOT NULL,
    resource_type varchar(64) NOT NULL,
    resource_id varchar(128) NOT NULL,
    document_sha256 varchar(64) NOT NULL
        CHECK (document_sha256 ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL DEFAULT now()
);

RESET ROLE;

-- Upgrade the short-lived pre-release tables before their mutation guards are
-- installed again. The immutable model row supplies the policy digest.
DO $model_draft_column$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'aigw_governance'
          AND table_name = 'governed_model_versions'
          AND column_name = 'visible_in_discovery'
    ) AND NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'aigw_governance'
          AND table_name = 'governed_model_versions'
          AND column_name = 'initial_visible_in_discovery'
    ) THEN
        ALTER TABLE aigw_governance.governed_model_versions
            RENAME COLUMN visible_in_discovery
            TO initial_visible_in_discovery;
    END IF;
END;
$model_draft_column$;

ALTER TABLE aigw_governance.governed_price_versions
    ADD COLUMN IF NOT EXISTS egress_policy_sha256 varchar(64);
ALTER TABLE aigw_governance.price_backdate_previews
    ADD COLUMN IF NOT EXISTS egress_policy_sha256 varchar(64);
UPDATE aigw_governance.governed_price_versions price
SET egress_policy_sha256 = model.egress_policy_sha256
FROM aigw_governance.governed_model_versions model
WHERE price.model_operation_id = model.operation_id
  AND price.egress_policy_sha256 IS NULL;
UPDATE aigw_governance.price_backdate_previews preview
SET egress_policy_sha256 = model.egress_policy_sha256
FROM aigw_governance.governed_model_versions model
WHERE preview.model_operation_id = model.operation_id
  AND preview.egress_policy_sha256 IS NULL;
ALTER TABLE aigw_governance.governed_price_versions
    ALTER COLUMN egress_policy_sha256 SET NOT NULL;
ALTER TABLE aigw_governance.price_backdate_previews
    ALTER COLUMN egress_policy_sha256 SET NOT NULL;
DO $policy_checks$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'governed_price_versions_egress_policy_sha256_check'
          AND conrelid =
              'aigw_governance.governed_price_versions'::regclass
    ) THEN
        ALTER TABLE aigw_governance.governed_price_versions
            ADD CONSTRAINT governed_price_versions_egress_policy_sha256_check
            CHECK (egress_policy_sha256 ~ '^[0-9a-f]{64}$');
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'price_backdate_previews_egress_policy_sha256_check'
          AND conrelid =
              'aigw_governance.price_backdate_previews'::regclass
    ) THEN
        ALTER TABLE aigw_governance.price_backdate_previews
            ADD CONSTRAINT price_backdate_previews_egress_policy_sha256_check
            CHECK (egress_policy_sha256 ~ '^[0-9a-f]{64}$');
    END IF;
END;
$policy_checks$;

-- The migration login, not the application login, owns every evidence object.
ALTER TABLE aigw_governance.schema_version OWNER TO aigw_governance_owner;
ALTER TABLE aigw_governance.governed_model_versions
    OWNER TO aigw_governance_owner;
ALTER TABLE aigw_governance.governed_model_events
    OWNER TO aigw_governance_owner;
ALTER TABLE aigw_governance.governed_price_versions
    OWNER TO aigw_governance_owner;
ALTER TABLE aigw_governance.price_backdate_previews
    OWNER TO aigw_governance_owner;
ALTER TABLE aigw_governance.price_backdate_confirmations
    OWNER TO aigw_governance_owner;
ALTER TABLE aigw_governance.governance_audit OWNER TO aigw_governance_owner;
ALTER SEQUENCE aigw_governance.governance_audit_id_seq
    OWNER TO aigw_governance_owner;
ALTER SEQUENCE aigw_governance.governed_model_events_event_sequence_seq
    OWNER TO aigw_governance_owner;

SET LOCAL ROLE aigw_governance_owner;

CREATE OR REPLACE FUNCTION aigw_governance.reject_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    RAISE EXCEPTION 'governance records are append-only';
    RETURN OLD;
END;
$function$;

DO $triggers$
DECLARE
    table_name text;
    trigger_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'schema_version',
        'governed_model_versions',
        'governed_model_events',
        'governed_price_versions',
        'price_backdate_previews',
        'price_backdate_confirmations',
        'governance_audit'
    ]
    LOOP
        trigger_name := 'aigw_append_only_' || table_name;
        IF NOT EXISTS (
            SELECT 1 FROM pg_trigger
            WHERE tgname = trigger_name
              AND tgrelid = format('aigw_governance.%I', table_name)::regclass
              AND NOT tgisinternal
        ) THEN
            EXECUTE format(
                'CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON '
                'aigw_governance.%I FOR EACH ROW EXECUTE FUNCTION '
                'aigw_governance.reject_mutation()',
                trigger_name,
                table_name
            );
        END IF;

        trigger_name := 'aigw_append_only_truncate_' || table_name;
        IF NOT EXISTS (
            SELECT 1 FROM pg_trigger
            WHERE tgname = trigger_name
              AND tgrelid = format('aigw_governance.%I', table_name)::regclass
              AND NOT tgisinternal
        ) THEN
            EXECUTE format(
                'CREATE TRIGGER %I BEFORE TRUNCATE ON '
                'aigw_governance.%I FOR EACH STATEMENT EXECUTE FUNCTION '
                'aigw_governance.reject_mutation()',
                trigger_name,
                table_name
            );
        END IF;
    END LOOP;
END;
$triggers$;

INSERT INTO aigw_governance.schema_version (version)
VALUES (1)
ON CONFLICT (version) DO NOTHING;

RESET ROLE;

REVOKE ALL ON SCHEMA aigw_governance FROM PUBLIC, rotator;
GRANT USAGE ON SCHEMA aigw_governance TO rotator;
REVOKE ALL ON ALL TABLES IN SCHEMA aigw_governance FROM PUBLIC, rotator;
GRANT SELECT, INSERT ON TABLE
    aigw_governance.governed_model_versions,
    aigw_governance.governed_model_events,
    aigw_governance.governed_price_versions,
    aigw_governance.price_backdate_previews,
    aigw_governance.price_backdate_confirmations,
    aigw_governance.governance_audit
TO rotator;
GRANT SELECT ON TABLE aigw_governance.schema_version TO rotator;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA aigw_governance FROM PUBLIC, rotator;
GRANT USAGE ON SEQUENCE aigw_governance.governance_audit_id_seq TO rotator;
GRANT USAGE ON SEQUENCE
    aigw_governance.governed_model_events_event_sequence_seq TO rotator;
REVOKE ALL ON FUNCTION aigw_governance.reject_mutation() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aigw_governance.reject_mutation() TO rotator;

COMMIT;

-- A concise receipt for the reconcile caller. Do not print table contents.
SELECT 'AIGW_GOVERNANCE_SCHEMA_V1' AS governance_schema_receipt
WHERE (SELECT array_agg(version ORDER BY version)
       FROM aigw_governance.schema_version) = ARRAY[1]
  AND (
      SELECT count(*) = 14
      FROM pg_trigger installed_trigger
      JOIN pg_class object ON object.oid = installed_trigger.tgrelid
      JOIN pg_namespace namespace ON namespace.oid = object.relnamespace
      WHERE namespace.nspname = 'aigw_governance'
        AND object.relname IN (
            'schema_version',
            'governed_model_versions',
            'governed_model_events',
            'governed_price_versions',
            'price_backdate_previews',
            'price_backdate_confirmations',
            'governance_audit'
        )
        AND installed_trigger.tgname LIKE 'aigw_append_only_%'
        AND installed_trigger.tgenabled = 'O'
        AND NOT installed_trigger.tgisinternal
  )
  AND (
      SELECT count(*) = 0
      FROM pg_auth_members membership
      JOIN pg_roles granted ON granted.oid = membership.roleid
      JOIN pg_roles member ON member.oid = membership.member
      WHERE granted.rolname IN ('aigw_governance_owner', 'rotator')
         OR member.rolname IN ('aigw_governance_owner', 'rotator')
  );
