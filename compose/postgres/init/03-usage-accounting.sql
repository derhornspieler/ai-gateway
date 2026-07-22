\set ON_ERROR_STOP on

-- Usage accounting is an additive migration after 02-governance.sql. The
-- catalog owns model and price versions. This file owns prompt-free usage,
-- backdate impact evidence, immutable cost adjustments, and report views.
\connect rotator
BEGIN;

DO $required_foundation$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'price_preview_class_version_key'
          AND conrelid =
              'aigw_governance.price_backdate_previews'::regclass
    ) THEN
        ALTER TABLE aigw_governance.price_backdate_previews
            ADD CONSTRAINT price_preview_class_version_key
            UNIQUE (preview_id, usage_class, candidate_version_id);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_roles
        WHERE rolname = 'aigw_governance_owner' AND NOT rolcanlogin
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_namespace
        WHERE nspname = 'aigw_governance'
          AND nspowner = 'aigw_governance_owner'::regrole
    ) OR to_regclass(
        'aigw_governance.governed_price_versions'
    ) IS NULL THEN
        RAISE EXCEPTION '02-governance.sql must run before usage accounting';
    END IF;
END;
$required_foundation$;

SET LOCAL ROLE aigw_governance_owner;

CREATE TABLE IF NOT EXISTS aigw_governance.usage_schema_version (
    version integer PRIMARY KEY CHECK (version = 1),
    installed_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS aigw_governance.usage_events (
    event_id varchar(64) PRIMARY KEY
        CHECK (event_id ~ '^[0-9a-f]{64}$'),
    document_sha256 varchar(64) NOT NULL
        CHECK (document_sha256 ~ '^[0-9a-f]{64}$'),
    request_id varchar(256) NOT NULL
        CHECK (request_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:@/+\-]{0,255}$'),
    request_id_source varchar(32) NOT NULL CHECK (request_id_source IN (
        'litellm_call_id', 'trace_id', 'provider_response_id'
    )),
    provider_response_id varchar(256)
        CHECK (
            provider_response_id IS NULL OR
            provider_response_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:@/+\-]{0,255}$'
        ),
    trace_id varchar(256)
        CHECK (
            trace_id IS NULL OR
            trace_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:@/+\-]{0,255}$'
        ),
    provider_name varchar(63) NOT NULL
        CHECK (provider_name ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'),
    requested_model varchar(128)
        CHECK (
            requested_model IS NULL OR
            requested_model ~ '^[A-Za-z0-9][A-Za-z0-9_./:\-]{0,127}$'
        ),
    actual_model varchar(128)
        CHECK (
            actual_model IS NULL OR
            actual_model ~ '^[A-Za-z0-9][A-Za-z0-9_./:\-]{0,127}$'
        ),
    stable_user_id varchar(256)
        CHECK (
            stable_user_id IS NULL OR
            stable_user_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:@/+\-]{0,255}$'
        ),
    project_id varchar(64)
        CHECK (
            project_id IS NULL OR
            project_id ~ '^[a-z0-9][a-z0-9_.\-]{0,63}$'
        ),
    status varchar(16) NOT NULL CHECK (status IN ('success', 'failure')),
    stream boolean,
    retry_count smallint CHECK (retry_count BETWEEN 0 AND 100),
    occurred_at timestamptz NOT NULL,
    egress_policy_sha256 varchar(64)
        CHECK (
            egress_policy_sha256 IS NULL OR
            egress_policy_sha256 ~ '^[0-9a-f]{64}$'
        ),
    normal_input_tokens bigint CHECK (normal_input_tokens >= 0),
    cache_creation_5m_tokens bigint CHECK (cache_creation_5m_tokens >= 0),
    cache_creation_1h_tokens bigint CHECK (cache_creation_1h_tokens >= 0),
    cache_read_tokens bigint CHECK (cache_read_tokens >= 0),
    output_tokens bigint CHECK (output_tokens >= 0),
    usage_completeness varchar(16) NOT NULL CHECK (usage_completeness IN (
        'complete', 'partial', 'unknown', 'not_applicable'
    )),
    litellm_cost_usd numeric(60, 18)
        CHECK (litellm_cost_usd BETWEEN 0 AND 1000000000),
    provider_cost_usd numeric(60, 18)
        CHECK (provider_cost_usd BETWEEN 0 AND 1000000000),
    normal_input_configured_cost_usd numeric(80, 50)
        CHECK (normal_input_configured_cost_usd >= 0),
    cache_creation_5m_configured_cost_usd numeric(80, 50)
        CHECK (cache_creation_5m_configured_cost_usd >= 0),
    cache_creation_1h_configured_cost_usd numeric(80, 50)
        CHECK (cache_creation_1h_configured_cost_usd >= 0),
    cache_read_configured_cost_usd numeric(80, 50)
        CHECK (cache_read_configured_cost_usd >= 0),
    output_configured_cost_usd numeric(80, 50)
        CHECK (output_configured_cost_usd >= 0),
    normal_input_price_version_id varchar(128) REFERENCES
        aigw_governance.governed_price_versions(version_id),
    cache_creation_5m_price_version_id varchar(128) REFERENCES
        aigw_governance.governed_price_versions(version_id),
    cache_creation_1h_price_version_id varchar(128) REFERENCES
        aigw_governance.governed_price_versions(version_id),
    cache_read_price_version_id varchar(128) REFERENCES
        aigw_governance.governed_price_versions(version_id),
    output_price_version_id varchar(128) REFERENCES
        aigw_governance.governed_price_versions(version_id),
    configured_total_cost_usd numeric(80, 50)
        CHECK (configured_total_cost_usd >= 0),
    configured_cost_status varchar(16) NOT NULL
        CHECK (configured_cost_status IN ('complete', 'unknown')),
    source_version varchar(32) NOT NULL
        CHECK (source_version = 'litellm-1.93.0'),
    received_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT usage_status_shape CHECK (
        (
            status = 'failure'
            AND usage_completeness = 'not_applicable'
            AND normal_input_tokens IS NULL
            AND cache_creation_5m_tokens IS NULL
            AND cache_creation_1h_tokens IS NULL
            AND cache_read_tokens IS NULL
            AND output_tokens IS NULL
            AND litellm_cost_usd IS NULL
            AND provider_cost_usd IS NULL
        ) OR (
            status = 'success'
            AND usage_completeness <> 'not_applicable'
        )
    ),
    CONSTRAINT usage_completeness_shape CHECK (
        (
            usage_completeness = 'complete'
            AND normal_input_tokens IS NOT NULL
            AND cache_creation_5m_tokens IS NOT NULL
            AND cache_creation_1h_tokens IS NOT NULL
            AND cache_read_tokens IS NOT NULL
            AND output_tokens IS NOT NULL
        ) OR (
            usage_completeness = 'partial'
            AND num_nonnulls(
                normal_input_tokens,
                cache_creation_5m_tokens,
                cache_creation_1h_tokens,
                cache_read_tokens,
                output_tokens
            ) BETWEEN 1 AND 4
        ) OR (
            usage_completeness IN ('unknown', 'not_applicable')
            AND num_nonnulls(
                normal_input_tokens,
                cache_creation_5m_tokens,
                cache_creation_1h_tokens,
                cache_read_tokens,
                output_tokens
            ) = 0
        )
    ),
    CONSTRAINT incomplete_usage_has_no_configured_cost CHECK (
        usage_completeness = 'complete' OR (
            normal_input_configured_cost_usd IS NULL
            AND cache_creation_5m_configured_cost_usd IS NULL
            AND cache_creation_1h_configured_cost_usd IS NULL
            AND cache_read_configured_cost_usd IS NULL
            AND output_configured_cost_usd IS NULL
            AND normal_input_price_version_id IS NULL
            AND cache_creation_5m_price_version_id IS NULL
            AND cache_creation_1h_price_version_id IS NULL
            AND cache_read_price_version_id IS NULL
            AND output_price_version_id IS NULL
            AND configured_total_cost_usd IS NULL
            AND configured_cost_status = 'unknown'
        )
    ),
    CONSTRAINT configured_cost_has_policy CHECK (
        egress_policy_sha256 IS NOT NULL OR num_nonnulls(
            normal_input_configured_cost_usd,
            cache_creation_5m_configured_cost_usd,
            cache_creation_1h_configured_cost_usd,
            cache_read_configured_cost_usd,
            output_configured_cost_usd,
            normal_input_price_version_id,
            cache_creation_5m_price_version_id,
            cache_creation_1h_price_version_id,
            cache_read_price_version_id,
            output_price_version_id,
            configured_total_cost_usd
        ) = 0
    ),
    CONSTRAINT normal_input_cost_pair CHECK (
        usage_completeness <> 'complete' OR
        (normal_input_tokens = 0
         AND normal_input_configured_cost_usd = 0
         AND normal_input_price_version_id IS NULL) OR
        (normal_input_tokens > 0 AND (
            (normal_input_configured_cost_usd IS NULL
             AND normal_input_price_version_id IS NULL) OR
            (normal_input_configured_cost_usd IS NOT NULL
             AND normal_input_price_version_id IS NOT NULL)
        ))
    ),
    CONSTRAINT cache_creation_5m_cost_pair CHECK (
        usage_completeness <> 'complete' OR
        (cache_creation_5m_tokens = 0
         AND cache_creation_5m_configured_cost_usd = 0
         AND cache_creation_5m_price_version_id IS NULL) OR
        (cache_creation_5m_tokens > 0 AND (
            (cache_creation_5m_configured_cost_usd IS NULL
             AND cache_creation_5m_price_version_id IS NULL) OR
            (cache_creation_5m_configured_cost_usd IS NOT NULL
             AND cache_creation_5m_price_version_id IS NOT NULL)
        ))
    ),
    CONSTRAINT cache_creation_1h_cost_pair CHECK (
        usage_completeness <> 'complete' OR
        (cache_creation_1h_tokens = 0
         AND cache_creation_1h_configured_cost_usd = 0
         AND cache_creation_1h_price_version_id IS NULL) OR
        (cache_creation_1h_tokens > 0 AND (
            (cache_creation_1h_configured_cost_usd IS NULL
             AND cache_creation_1h_price_version_id IS NULL) OR
            (cache_creation_1h_configured_cost_usd IS NOT NULL
             AND cache_creation_1h_price_version_id IS NOT NULL)
        ))
    ),
    CONSTRAINT cache_read_cost_pair CHECK (
        usage_completeness <> 'complete' OR
        (cache_read_tokens = 0
         AND cache_read_configured_cost_usd = 0
         AND cache_read_price_version_id IS NULL) OR
        (cache_read_tokens > 0 AND (
            (cache_read_configured_cost_usd IS NULL
             AND cache_read_price_version_id IS NULL) OR
            (cache_read_configured_cost_usd IS NOT NULL
             AND cache_read_price_version_id IS NOT NULL)
        ))
    ),
    CONSTRAINT output_cost_pair CHECK (
        usage_completeness <> 'complete' OR
        (output_tokens = 0
         AND output_configured_cost_usd = 0
         AND output_price_version_id IS NULL) OR
        (output_tokens > 0 AND (
            (output_configured_cost_usd IS NULL
             AND output_price_version_id IS NULL) OR
            (output_configured_cost_usd IS NOT NULL
             AND output_price_version_id IS NOT NULL)
        ))
    ),
    CONSTRAINT configured_total_shape CHECK (
        (
            configured_cost_status = 'complete'
            AND num_nonnulls(
                normal_input_configured_cost_usd,
                cache_creation_5m_configured_cost_usd,
                cache_creation_1h_configured_cost_usd,
                cache_read_configured_cost_usd,
                output_configured_cost_usd
            ) = 5
            AND configured_total_cost_usd =
                normal_input_configured_cost_usd +
                cache_creation_5m_configured_cost_usd +
                cache_creation_1h_configured_cost_usd +
                cache_read_configured_cost_usd +
                output_configured_cost_usd
        ) OR (
            configured_cost_status = 'unknown'
            AND num_nonnulls(
                normal_input_configured_cost_usd,
                cache_creation_5m_configured_cost_usd,
                cache_creation_1h_configured_cost_usd,
                cache_read_configured_cost_usd,
                output_configured_cost_usd
            ) < 5
            AND configured_total_cost_usd IS NULL
        )
    )
);

CREATE OR REPLACE FUNCTION aigw_governance.validate_usage_event_price()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    component record;
    expected_version_id varchar(128);
    expected_cost numeric;
BEGIN
    FOR component IN
        SELECT * FROM (VALUES
            ('normal_input', NEW.normal_input_tokens,
             NEW.normal_input_configured_cost_usd,
             NEW.normal_input_price_version_id),
            ('cache_creation_5m', NEW.cache_creation_5m_tokens,
             NEW.cache_creation_5m_configured_cost_usd,
             NEW.cache_creation_5m_price_version_id),
            ('cache_creation_1h', NEW.cache_creation_1h_tokens,
             NEW.cache_creation_1h_configured_cost_usd,
             NEW.cache_creation_1h_price_version_id),
            ('cache_read', NEW.cache_read_tokens,
             NEW.cache_read_configured_cost_usd,
             NEW.cache_read_price_version_id),
            ('output', NEW.output_tokens,
             NEW.output_configured_cost_usd,
             NEW.output_price_version_id)
        ) AS value(usage_class, token_count, configured_cost, price_version_id)
    LOOP
        IF component.token_count IS NULL OR component.token_count = 0 THEN
            CONTINUE;
        END IF;

        expected_version_id := NULL;
        expected_cost := NULL;
        IF NEW.egress_policy_sha256 IS NOT NULL
           AND NEW.requested_model IS NOT NULL THEN
            SELECT
                price.version_id,
                component.token_count::numeric * price.amount /
                    price.token_unit::numeric
            INTO expected_version_id, expected_cost
            FROM aigw_governance.governed_price_versions AS price
            JOIN aigw_governance.governed_model_versions AS model
              ON model.operation_id = price.model_operation_id
            WHERE price.provider_name = NEW.provider_name
              AND price.gateway_model_name = NEW.requested_model
              AND price.egress_policy_sha256 = NEW.egress_policy_sha256
              AND model.egress_policy_sha256 = NEW.egress_policy_sha256
              AND price.usage_class = component.usage_class
              AND price.effective_at <= NEW.occurred_at
            ORDER BY price.effective_at DESC, price.version_id DESC
            LIMIT 1;
        END IF;

        IF component.price_version_id IS DISTINCT FROM expected_version_id
           OR component.configured_cost IS DISTINCT FROM expected_cost THEN
            RAISE EXCEPTION
                'usage cost does not match the effective governed price';
        END IF;
    END LOOP;
    RETURN NEW;
END;
$function$;

DO $price_validation_trigger$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'aigw_validate_usage_event_price'
          AND tgrelid = 'aigw_governance.usage_events'::regclass
          AND NOT tgisinternal
    ) THEN
        CREATE TRIGGER aigw_validate_usage_event_price
        BEFORE INSERT ON aigw_governance.usage_events
        FOR EACH ROW EXECUTE FUNCTION
            aigw_governance.validate_usage_event_price();
    END IF;
END;
$price_validation_trigger$;

CREATE INDEX IF NOT EXISTS usage_events_occurred_at_idx
    ON aigw_governance.usage_events (occurred_at DESC, event_id);
CREATE INDEX IF NOT EXISTS usage_events_model_idx
    ON aigw_governance.usage_events (requested_model, occurred_at DESC);
CREATE INDEX IF NOT EXISTS usage_events_project_idx
    ON aigw_governance.usage_events (project_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS usage_events_user_idx
    ON aigw_governance.usage_events (stable_user_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS usage_events_request_idx
    ON aigw_governance.usage_events (request_id);

CREATE TABLE IF NOT EXISTS aigw_governance.usage_reprice_previews (
    preview_id uuid PRIMARY KEY REFERENCES
        aigw_governance.price_backdate_previews(preview_id),
    baseline_adjustments_sha256 varchar(64) NOT NULL
        CHECK (baseline_adjustments_sha256 ~ '^[0-9a-f]{64}$'),
    preview_sha256 varchar(64) NOT NULL
        CHECK (preview_sha256 ~ '^[0-9a-f]{64}$'),
    effective_to timestamptz,
    affected_count integer NOT NULL CHECK (affected_count BETWEEN 0 AND 10000),
    old_total_usd numeric(80, 50),
    new_total_usd numeric(80, 50),
    delta_usd numeric(80, 50),
    old_unknown_count integer NOT NULL
        CHECK (old_unknown_count BETWEEN 0 AND affected_count),
    new_unknown_count integer NOT NULL
        CHECK (new_unknown_count BETWEEN 0 AND affected_count),
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT reprice_preview_old_total_shape CHECK (
        (old_unknown_count = 0 AND old_total_usd IS NOT NULL) OR
        (old_unknown_count > 0 AND old_total_usd IS NULL)
    ),
    CONSTRAINT reprice_preview_new_total_shape CHECK (
        (new_unknown_count = 0 AND new_total_usd IS NOT NULL) OR
        (new_unknown_count > 0 AND new_total_usd IS NULL)
    ),
    CONSTRAINT reprice_preview_delta_shape CHECK (
        (old_total_usd IS NOT NULL AND new_total_usd IS NOT NULL
         AND delta_usd = new_total_usd - old_total_usd) OR
        ((old_total_usd IS NULL OR new_total_usd IS NULL)
         AND delta_usd IS NULL)
    )
);

CREATE TABLE IF NOT EXISTS aigw_governance.usage_reprice_preview_rows (
    preview_id uuid NOT NULL REFERENCES
        aigw_governance.usage_reprice_previews(preview_id),
    usage_event_id varchar(64) NOT NULL REFERENCES
        aigw_governance.usage_events(event_id),
    usage_class varchar(32) NOT NULL CHECK (usage_class IN (
        'normal_input',
        'cache_creation_5m',
        'cache_creation_1h',
        'cache_read',
        'output'
    )),
    units bigint NOT NULL CHECK (units > 0),
    supersedes_adjustment_id varchar(64),
    previous_price_version_id varchar(128) REFERENCES
        aigw_governance.governed_price_versions(version_id),
    new_price_version_id varchar(128) NOT NULL,
    previous_component_cost_usd numeric(80, 50)
        CHECK (previous_component_cost_usd >= 0),
    new_component_cost_usd numeric(80, 50) NOT NULL
        CHECK (new_component_cost_usd >= 0),
    component_delta_usd numeric(80, 50),
    previous_total_cost_usd numeric(80, 50)
        CHECK (previous_total_cost_usd >= 0),
    new_total_cost_usd numeric(80, 50)
        CHECK (new_total_cost_usd >= 0),
    row_sha256 varchar(64) NOT NULL
        CHECK (row_sha256 ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (preview_id, usage_event_id),
    CONSTRAINT preview_component_delta_shape CHECK (
        (previous_component_cost_usd IS NOT NULL
         AND component_delta_usd =
             new_component_cost_usd - previous_component_cost_usd) OR
        (previous_component_cost_usd IS NULL AND component_delta_usd IS NULL)
    )
);

CREATE TABLE IF NOT EXISTS aigw_governance.usage_cost_adjustments (
    adjustment_id varchar(64) PRIMARY KEY
        CHECK (adjustment_id ~ '^[0-9a-f]{64}$'),
    preview_id uuid NOT NULL,
    confirmation_operation_id uuid NOT NULL REFERENCES
        aigw_governance.price_backdate_confirmations(
            confirmation_operation_id
        ),
    usage_event_id varchar(64) NOT NULL,
    usage_class varchar(32) NOT NULL CHECK (usage_class IN (
        'normal_input',
        'cache_creation_5m',
        'cache_creation_1h',
        'cache_read',
        'output'
    )),
    units bigint NOT NULL CHECK (units > 0),
    supersedes_adjustment_id varchar(64) REFERENCES
        aigw_governance.usage_cost_adjustments(adjustment_id),
    previous_price_version_id varchar(128) REFERENCES
        aigw_governance.governed_price_versions(version_id),
    new_price_version_id varchar(128) NOT NULL REFERENCES
        aigw_governance.governed_price_versions(version_id),
    previous_cost_usd numeric(80, 50)
        CHECK (previous_cost_usd >= 0),
    new_cost_usd numeric(80, 50) NOT NULL CHECK (new_cost_usd >= 0),
    delta_usd numeric(80, 50),
    new_price_sha256 varchar(64) NOT NULL
        CHECK (new_price_sha256 ~ '^[0-9a-f]{64}$'),
    actor varchar(128) NOT NULL
        CHECK (actor ~ '^[A-Za-z0-9][A-Za-z0-9_.:@\-]{0,127}$'),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (confirmation_operation_id, usage_event_id, usage_class),
    FOREIGN KEY (preview_id, usage_event_id) REFERENCES
        aigw_governance.usage_reprice_preview_rows(
            preview_id, usage_event_id
        ),
    CONSTRAINT adjustment_delta_shape CHECK (
        (previous_cost_usd IS NOT NULL
         AND delta_usd = new_cost_usd - previous_cost_usd) OR
        (previous_cost_usd IS NULL AND delta_usd IS NULL)
    )
);

-- Bind every adjustment to one exact confirmation and one exact preview row.
-- The wider unique keys are intentionally redundant with the primary keys:
-- PostgreSQL needs them as reviewed targets for the composite foreign keys.
DO $backdate_evidence_bindings$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'price_confirmation_preview_version_key'
          AND conrelid =
              'aigw_governance.price_backdate_confirmations'::regclass
    ) THEN
        ALTER TABLE aigw_governance.price_backdate_confirmations
            ADD CONSTRAINT price_confirmation_preview_version_key
            UNIQUE (confirmation_operation_id, preview_id, version_id);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'usage_preview_event_class_version_key'
          AND conrelid =
              'aigw_governance.usage_reprice_preview_rows'::regclass
    ) THEN
        ALTER TABLE aigw_governance.usage_reprice_preview_rows
            ADD CONSTRAINT usage_preview_event_class_version_key
            UNIQUE (
                preview_id,
                usage_event_id,
                usage_class,
                new_price_version_id
            );
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'usage_adjustment_confirmation_binding_fk'
          AND conrelid =
              'aigw_governance.usage_cost_adjustments'::regclass
    ) THEN
        ALTER TABLE aigw_governance.usage_cost_adjustments
            ADD CONSTRAINT usage_adjustment_confirmation_binding_fk
            FOREIGN KEY (
                confirmation_operation_id,
                preview_id,
                new_price_version_id
            ) REFERENCES aigw_governance.price_backdate_confirmations (
                confirmation_operation_id,
                preview_id,
                version_id
            );
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'usage_preview_candidate_binding_fk'
          AND conrelid =
              'aigw_governance.usage_reprice_preview_rows'::regclass
    ) THEN
        ALTER TABLE aigw_governance.usage_reprice_preview_rows
            ADD CONSTRAINT usage_preview_candidate_binding_fk
            FOREIGN KEY (
                preview_id,
                usage_class,
                new_price_version_id
            ) REFERENCES aigw_governance.price_backdate_previews (
                preview_id,
                usage_class,
                candidate_version_id
            );
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'usage_adjustment_preview_binding_fk'
          AND conrelid =
              'aigw_governance.usage_cost_adjustments'::regclass
    ) THEN
        ALTER TABLE aigw_governance.usage_cost_adjustments
            ADD CONSTRAINT usage_adjustment_preview_binding_fk
            FOREIGN KEY (
                preview_id,
                usage_event_id,
                usage_class,
                new_price_version_id
            ) REFERENCES aigw_governance.usage_reprice_preview_rows (
                preview_id,
                usage_event_id,
                usage_class,
                new_price_version_id
            );
    END IF;
END;
$backdate_evidence_bindings$;

DO $preview_adjustment_fk$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'usage_preview_superseded_adjustment_fk'
          AND conrelid =
              'aigw_governance.usage_reprice_preview_rows'::regclass
    ) THEN
        ALTER TABLE aigw_governance.usage_reprice_preview_rows
            ADD CONSTRAINT usage_preview_superseded_adjustment_fk
            FOREIGN KEY (supersedes_adjustment_id) REFERENCES
                aigw_governance.usage_cost_adjustments(adjustment_id);
    END IF;
END;
$preview_adjustment_fk$;

CREATE INDEX IF NOT EXISTS usage_adjustments_event_idx
    ON aigw_governance.usage_cost_adjustments (
        usage_event_id, usage_class, created_at DESC, adjustment_id DESC
    );
CREATE UNIQUE INDEX IF NOT EXISTS usage_adjustments_one_successor_idx
    ON aigw_governance.usage_cost_adjustments (
        usage_event_id, usage_class, supersedes_adjustment_id
    ) NULLS NOT DISTINCT;

INSERT INTO aigw_governance.usage_schema_version (version)
VALUES (1)
ON CONFLICT (version) DO NOTHING;

CREATE OR REPLACE VIEW aigw_governance.usage_component_reporting
WITH (security_barrier = true)
AS
SELECT
    usage.event_id,
    usage.request_id,
    usage.provider_name,
    usage.requested_model,
    usage.actual_model,
    usage.stable_user_id,
    usage.project_id,
    usage.status,
    usage.stream,
    usage.retry_count,
    usage.occurred_at,
    usage.usage_completeness,
    usage.litellm_cost_usd,
    usage.provider_cost_usd,
    component.usage_class,
    component.token_count,
    component.booked_cost_usd,
    component.booked_price_version_id,
    CASE
        WHEN adjustment.adjustment_id IS NULL
        THEN component.booked_cost_usd
        ELSE adjustment.new_cost_usd
    END AS current_cost_usd,
    CASE
        WHEN adjustment.adjustment_id IS NULL
        THEN component.booked_price_version_id
        ELSE adjustment.new_price_version_id
    END AS current_price_version_id,
    adjustment.adjustment_id AS current_adjustment_id
FROM aigw_governance.usage_events AS usage
CROSS JOIN LATERAL (
    VALUES
        ('normal_input', usage.normal_input_tokens,
         usage.normal_input_configured_cost_usd,
         usage.normal_input_price_version_id),
        ('cache_creation_5m', usage.cache_creation_5m_tokens,
         usage.cache_creation_5m_configured_cost_usd,
         usage.cache_creation_5m_price_version_id),
        ('cache_creation_1h', usage.cache_creation_1h_tokens,
         usage.cache_creation_1h_configured_cost_usd,
         usage.cache_creation_1h_price_version_id),
        ('cache_read', usage.cache_read_tokens,
         usage.cache_read_configured_cost_usd,
         usage.cache_read_price_version_id),
        ('output', usage.output_tokens,
         usage.output_configured_cost_usd,
         usage.output_price_version_id)
) AS component(
    usage_class, token_count, booked_cost_usd, booked_price_version_id
)
LEFT JOIN LATERAL (
    SELECT
        candidate.adjustment_id,
        candidate.new_cost_usd,
        candidate.new_price_version_id
    FROM aigw_governance.usage_cost_adjustments AS candidate
    WHERE candidate.usage_event_id = usage.event_id
      AND candidate.usage_class = component.usage_class
      AND NOT EXISTS (
          SELECT 1
          FROM aigw_governance.usage_cost_adjustments AS successor
          WHERE successor.supersedes_adjustment_id = candidate.adjustment_id
      )
    ORDER BY candidate.created_at DESC, candidate.adjustment_id DESC
    LIMIT 1
) AS adjustment ON true;

CREATE OR REPLACE VIEW aigw_governance.usage_reporting
WITH (security_barrier = true)
AS
SELECT
    usage.event_id,
    usage.request_id,
    usage.request_id_source,
    usage.provider_response_id,
    usage.trace_id,
    usage.provider_name,
    usage.requested_model,
    usage.actual_model,
    usage.stable_user_id,
    usage.project_id,
    usage.status,
    usage.stream,
    usage.retry_count,
    usage.occurred_at,
    usage.normal_input_tokens,
    usage.cache_creation_5m_tokens,
    usage.cache_creation_1h_tokens,
    usage.cache_read_tokens,
    usage.output_tokens,
    usage.usage_completeness,
    usage.litellm_cost_usd,
    usage.provider_cost_usd,
    usage.configured_total_cost_usd AS booked_configured_total_cost_usd,
    CASE
        WHEN count(component.current_cost_usd) = 5
        THEN sum(component.current_cost_usd)
        ELSE NULL
    END AS current_configured_total_cost_usd,
    CASE
        WHEN count(component.current_cost_usd) = 5 THEN 'complete'
        ELSE 'unknown'
    END AS current_configured_cost_status,
    (
        SELECT count(*)
        FROM aigw_governance.usage_cost_adjustments AS adjustment
        WHERE adjustment.usage_event_id = usage.event_id
    ) AS adjustment_count,
    usage.received_at
FROM aigw_governance.usage_events AS usage
JOIN aigw_governance.usage_component_reporting AS component
  ON component.event_id = usage.event_id
GROUP BY usage.event_id;

ALTER TABLE aigw_governance.usage_schema_version
    OWNER TO aigw_governance_owner;
ALTER TABLE aigw_governance.usage_events OWNER TO aigw_governance_owner;
ALTER TABLE aigw_governance.usage_reprice_previews
    OWNER TO aigw_governance_owner;
ALTER TABLE aigw_governance.usage_reprice_preview_rows
    OWNER TO aigw_governance_owner;
ALTER TABLE aigw_governance.usage_cost_adjustments
    OWNER TO aigw_governance_owner;
ALTER VIEW aigw_governance.usage_component_reporting
    OWNER TO aigw_governance_owner;
ALTER VIEW aigw_governance.usage_reporting
    OWNER TO aigw_governance_owner;

DO $append_only_triggers$
DECLARE
    table_name text;
    trigger_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'usage_schema_version',
        'usage_events',
        'usage_reprice_previews',
        'usage_reprice_preview_rows',
        'usage_cost_adjustments'
    ]
    LOOP
        trigger_name := 'aigw_append_only_' || table_name;
        IF NOT EXISTS (
            SELECT 1 FROM pg_trigger
            WHERE tgname = trigger_name
              AND tgrelid =
                  format('aigw_governance.%I', table_name)::regclass
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
              AND tgrelid =
                  format('aigw_governance.%I', table_name)::regclass
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
$append_only_triggers$;

RESET ROLE;

REVOKE ALL ON TABLE
    aigw_governance.usage_schema_version,
    aigw_governance.usage_events,
    aigw_governance.usage_reprice_previews,
    aigw_governance.usage_reprice_preview_rows,
    aigw_governance.usage_cost_adjustments
FROM PUBLIC, rotator, grafana_ro;
GRANT SELECT, INSERT ON TABLE
    aigw_governance.usage_events,
    aigw_governance.usage_reprice_previews,
    aigw_governance.usage_reprice_preview_rows,
    aigw_governance.usage_cost_adjustments
TO rotator;
GRANT SELECT ON TABLE aigw_governance.usage_schema_version TO rotator;

REVOKE ALL ON TABLE
    aigw_governance.usage_component_reporting,
    aigw_governance.usage_reporting
FROM PUBLIC, rotator, grafana_ro;
GRANT SELECT ON TABLE
    aigw_governance.usage_component_reporting,
    aigw_governance.usage_reporting
TO rotator, grafana_ro;
GRANT USAGE ON SCHEMA aigw_governance TO grafana_ro;
REVOKE ALL ON FUNCTION
    aigw_governance.validate_usage_event_price()
FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
    aigw_governance.validate_usage_event_price()
TO rotator;

COMMIT;

-- One content-free receipt for the reconcile caller.
SELECT 'AIGW_USAGE_ACCOUNTING_SCHEMA_V1' AS usage_schema_receipt
WHERE (SELECT array_agg(version ORDER BY version)
       FROM aigw_governance.usage_schema_version) = ARRAY[1]
  AND (
      SELECT count(*) = 10
      FROM pg_trigger installed_trigger
      JOIN pg_class object ON object.oid = installed_trigger.tgrelid
      JOIN pg_namespace namespace ON namespace.oid = object.relnamespace
      WHERE namespace.nspname = 'aigw_governance'
        AND object.relname IN (
            'usage_schema_version',
            'usage_events',
            'usage_reprice_previews',
            'usage_reprice_preview_rows',
            'usage_cost_adjustments'
        )
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
  );
