#!/bin/bash
# Creates per-service databases + least-privilege users. Runs once on first
# boot of the postgres volume. Passwords arrive via container env (compose .env).
#
# Passwords are passed as psql variables and expanded with :'var', which
# performs proper SQL literal quoting — never interpolate them into the SQL
# text from the shell. The heredoc delimiter is quoted so the shell leaves
# the SQL untouched. On an already-running cluster, each desired password is
# tested through the SCRAM host-auth path and is rewritten only on mismatch;
# this avoids generating a new salted verifier on every unchanged converge.
set -euo pipefail

# docker-entrypoint.sh supplies this default only inside its initialization
# process. The Ansible existing-volume reconciliation executes the script
# later via docker exec, where an unset POSTGRES_USER must still mean postgres.
POSTGRES_USER="${POSTGRES_USER:-postgres}"

password_matches() {
    local role="$1" password="$2" database="$3"
    local result
    result="$(PGPASSWORD="$password" PGCONNECT_TIMEOUT=2 psql \
        --host 127.0.0.1 --username "$role" --dbname "$database" \
        --no-password --tuples-only --no-align --command 'SELECT 1' \
        2>/dev/null)" || return 1
    [[ "$result" == 1 ]]
}

role_security_matches() {
    local role="$1" result
    result="$(psql --username "$POSTGRES_USER" --dbname postgres \
        --tuples-only --no-align --command \
        "SELECT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND
                NOT rolcreaterole AND NOT rolinherit AND NOT rolreplication AND
                NOT rolbypassrls AND rolconnlimit = -1 AND rolconfig IS NULL AND
                (rolvaliduntil IS NULL OR rolvaliduntil = 'infinity'::timestamptz)
           FROM pg_roles WHERE rolname = '$role';")"
    [[ "$result" == t ]]
}

database_owner_matches() {
    local database="$1" owner="$2" result
    result="$(psql --username "$POSTGRES_USER" --dbname postgres \
        --tuples-only --no-align --command \
        "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = '$database';")"
    [[ "$result" == "$owner" ]]
}

# The docker-entrypoint initialization server listens only on its Unix socket;
# a normal runtime server accepts TCP here. First initialization must create
# all verifiers, while a runtime reconciliation can authenticate before ALTER.
runtime_reconcile=false
if pg_isready --host 127.0.0.1 --username "$POSTGRES_USER" \
        --dbname postgres >/dev/null 2>&1; then
    runtime_reconcile=true
fi

state_changed=false
set_postgres_password=true
set_litellm_password=true
set_keycloak_password=true
set_rotator_password=true
set_grafana_ro_password=true
fix_litellm_role=true
fix_keycloak_role=true
fix_rotator_role=true
fix_grafana_ro_role=true
fix_litellm_owner=true
fix_keycloak_owner=true
fix_rotator_owner=true
fix_connect_acl=true
fix_grafana_ro_grants=true

if [[ "$runtime_reconcile" == true ]]; then
    if password_matches postgres "$POSTGRES_PASSWORD" postgres; then
        set_postgres_password=false
    else
        state_changed=true
    fi
    if password_matches litellm "$PG_LITELLM_PASSWORD" litellm; then
        set_litellm_password=false
    else
        state_changed=true
    fi
    if password_matches keycloak "$PG_KEYCLOAK_PASSWORD" keycloak; then
        set_keycloak_password=false
    else
        state_changed=true
    fi
    if password_matches rotator "$PG_ROTATOR_PASSWORD" rotator; then
        set_rotator_password=false
    else
        state_changed=true
    fi
    if password_matches grafana_ro "$PG_GRAFANA_RO_PASSWORD" litellm; then
        set_grafana_ro_password=false
    else
        state_changed=true
    fi

    if role_security_matches litellm; then
        fix_litellm_role=false
    else
        state_changed=true
    fi
    if role_security_matches keycloak; then
        fix_keycloak_role=false
    else
        state_changed=true
    fi
    if role_security_matches rotator; then
        fix_rotator_role=false
    else
        state_changed=true
    fi
    if role_security_matches grafana_ro; then
        fix_grafana_ro_role=false
    else
        state_changed=true
    fi

    if database_owner_matches litellm litellm; then
        fix_litellm_owner=false
    else
        state_changed=true
    fi
    if database_owner_matches keycloak keycloak; then
        fix_keycloak_owner=false
    else
        state_changed=true
    fi
    if database_owner_matches rotator rotator; then
        fix_rotator_owner=false
    else
        state_changed=true
    fi

    membership_count="$(psql --username "$POSTGRES_USER" --dbname postgres \
        --tuples-only --no-align --command "
          SELECT count(*) FROM pg_auth_members membership
          JOIN pg_roles granted_role ON granted_role.oid = membership.roleid
          JOIN pg_roles member_role ON member_role.oid = membership.member
          WHERE granted_role.rolname IN ('litellm','keycloak','rotator','grafana_ro')
             OR member_role.rolname IN ('litellm','keycloak','rotator','grafana_ro');")"
    [[ "$membership_count" == 0 ]] || state_changed=true

    structure_ok="$(psql --username "$POSTGRES_USER" --dbname postgres \
        --tuples-only --no-align --command \
        "SELECT (SELECT count(*) FROM pg_roles WHERE rolname IN ('litellm','keycloak','rotator','grafana_ro')) = 4 AND
                (SELECT count(*) FROM pg_database WHERE datname IN ('litellm','keycloak','rotator')) = 3 AND
                (SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = 'litellm') = 'litellm' AND
                (SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = 'keycloak') = 'keycloak' AND
                (SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = 'rotator') = 'rotator';")"
    acl_ok=false
    if [[ "$structure_ok" == t ]]; then
        actual_matrix="$(psql --username "$POSTGRES_USER" --dbname postgres \
            --tuples-only --no-align --command "
              SELECT role_name || '|' || db_name || '|' ||
                     CASE WHEN has_database_privilege(role_name, db_name, 'CONNECT')
                          THEN 'true' ELSE 'false' END
                FROM unnest(ARRAY['grafana_ro','keycloak','litellm','rotator']) AS role_name
               CROSS JOIN unnest(ARRAY['keycloak','litellm','rotator','postgres']) AS db_name
               ORDER BY role_name, db_name;
              SELECT 'postgres|postgres|' ||
                     CASE WHEN has_database_privilege('postgres', 'postgres', 'CONNECT')
                          THEN 'true' ELSE 'false' END;")"
        expected_matrix="$(printf '%s\n' \
            'grafana_ro|keycloak|false' 'grafana_ro|litellm|true' \
            'grafana_ro|postgres|false' 'grafana_ro|rotator|false' \
            'keycloak|keycloak|true' 'keycloak|litellm|false' \
            'keycloak|postgres|false' 'keycloak|rotator|false' \
            'litellm|keycloak|false' 'litellm|litellm|true' \
            'litellm|postgres|false' 'litellm|rotator|false' \
            'rotator|keycloak|false' \
            'rotator|litellm|false' 'rotator|postgres|false' \
            'rotator|rotator|true' 'postgres|postgres|true')"
        if [[ "$actual_matrix" == "$expected_matrix" ]]; then
            acl_ok=true
            fix_connect_acl=false
        fi
    fi
    [[ "$acl_ok" == true ]] || state_changed=true

    # Reporting grants exist only after LiteLLM's own migrations created the
    # reviewed tables; until then the desired state is "no grants" and the
    # section below correctly performs no writes. Owner decision: Grafana's
    # read-only spend datasource reads exactly these four tables.
    grafana_grants_ok="$(psql --username "$POSTGRES_USER" --dbname litellm \
        --tuples-only --no-align --command "
          SELECT count(*) = 0 FROM unnest(ARRAY[
                   'LiteLLM_SpendLogs','LiteLLM_VerificationToken',
                   'LiteLLM_UserTable','LiteLLM_DailyUserSpend'
                 ]) AS tab
           WHERE to_regclass(format('public.%I', tab)) IS NOT NULL
             AND NOT has_table_privilege('grafana_ro', format('public.%I', tab), 'SELECT');")" \
        || grafana_grants_ok=f
    if [[ "$grafana_grants_ok" == t ]]; then
        fix_grafana_ro_grants=false
    else
        state_changed=true
    fi
else
    state_changed=true
fi

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" \
     -v postgres_pw="$POSTGRES_PASSWORD" \
     -v litellm_pw="$PG_LITELLM_PASSWORD" \
     -v keycloak_pw="$PG_KEYCLOAK_PASSWORD" \
     -v rotator_pw="$PG_ROTATOR_PASSWORD" \
     -v grafana_ro_pw="$PG_GRAFANA_RO_PASSWORD" \
     -v set_postgres_password="$set_postgres_password" \
     -v set_litellm_password="$set_litellm_password" \
     -v set_keycloak_password="$set_keycloak_password" \
     -v set_rotator_password="$set_rotator_password" \
     -v set_grafana_ro_password="$set_grafana_ro_password" \
     -v fix_litellm_role="$fix_litellm_role" \
     -v fix_keycloak_role="$fix_keycloak_role" \
     -v fix_rotator_role="$fix_rotator_role" \
     -v fix_grafana_ro_role="$fix_grafana_ro_role" \
     -v fix_litellm_owner="$fix_litellm_owner" \
     -v fix_keycloak_owner="$fix_keycloak_owner" \
     -v fix_rotator_owner="$fix_rotator_owner" \
     -v fix_connect_acl="$fix_connect_acl" \
     -v fix_grafana_ro_grants="$fix_grafana_ro_grants" <<-'EOSQL'
    -- The official image consumes POSTGRES_PASSWORD only while PGDATA is
    -- empty.  Ansible deliberately re-runs this idempotent script over the
    -- local Unix socket on every converge so changing the encrypted overlay
    -- also changes the already-initialized database roles.
    \if :set_postgres_password
    ALTER USER postgres WITH PASSWORD :'postgres_pw';
    \endif

    SELECT 'CREATE USER litellm'
        WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'litellm') \gexec
    \if :fix_litellm_role
    ALTER ROLE litellm WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
        NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1 VALID UNTIL 'infinity';
    ALTER ROLE litellm RESET ALL;
    \endif
    \if :set_litellm_password
    ALTER USER litellm WITH PASSWORD :'litellm_pw';
    \endif
    SELECT 'CREATE DATABASE litellm OWNER litellm'
        WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'litellm') \gexec
    \if :fix_litellm_owner
    ALTER DATABASE litellm OWNER TO litellm;
    \endif

    SELECT 'CREATE USER keycloak'
        WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'keycloak') \gexec
    \if :fix_keycloak_role
    ALTER ROLE keycloak WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
        NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1 VALID UNTIL 'infinity';
    ALTER ROLE keycloak RESET ALL;
    \endif
    \if :set_keycloak_password
    ALTER USER keycloak WITH PASSWORD :'keycloak_pw';
    \endif
    SELECT 'CREATE DATABASE keycloak OWNER keycloak'
        WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'keycloak') \gexec
    \if :fix_keycloak_owner
    ALTER DATABASE keycloak OWNER TO keycloak;
    \endif

    SELECT 'CREATE USER rotator'
        WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rotator') \gexec
    \if :fix_rotator_role
    ALTER ROLE rotator WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
        NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1 VALID UNTIL 'infinity';
    ALTER ROLE rotator RESET ALL;
    \endif
    \if :set_rotator_password
    ALTER USER rotator WITH PASSWORD :'rotator_pw';
    \endif
    SELECT 'CREATE DATABASE rotator OWNER rotator'
        WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'rotator') \gexec
    \if :fix_rotator_owner
    ALTER DATABASE rotator OWNER TO rotator;
    \endif

    -- Read-only reporting identity for Grafana's provisioned LiteLLM spend
    -- datasource (owner-approved admin observability). It owns no database:
    -- it may CONNECT only to litellm and SELECT only the reviewed tables
    -- granted below after LiteLLM's own migrations create them.
    SELECT 'CREATE USER grafana_ro'
        WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'grafana_ro') \gexec
    \if :fix_grafana_ro_role
    ALTER ROLE grafana_ro WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
        NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1 VALID UNTIL 'infinity';
    ALTER ROLE grafana_ro RESET ALL;
    \endif
    \if :set_grafana_ro_password
    ALTER USER grafana_ro WITH PASSWORD :'grafana_ro_pw';
    \endif

    -- Service roles are terminal identities, never privilege/group carriers.
    -- Revoke memberships in both directions so neither a service role nor an
    -- unexpected member can SET ROLE across this boundary.
    SELECT format('REVOKE %I FROM %I', granted_role.rolname, member_role.rolname)
      FROM pg_auth_members membership
      JOIN pg_roles granted_role ON granted_role.oid = membership.roleid
      JOIN pg_roles member_role ON member_role.oid = membership.member
     WHERE granted_role.rolname IN ('litellm','keycloak','rotator','grafana_ro')
        OR member_role.rolname IN ('litellm','keycloak','rotator','grafana_ro')
     ORDER BY granted_role.rolname, member_role.rolname \gexec

    -- PostgreSQL grants CONNECT to PUBLIC by default. Reconcile the matrix
    -- only on drift so an unchanged converge performs no catalog writes.
    \if :fix_connect_acl
    REVOKE CONNECT ON DATABASE litellm FROM PUBLIC;
    REVOKE CONNECT ON DATABASE keycloak FROM PUBLIC;
    REVOKE CONNECT ON DATABASE rotator FROM PUBLIC;
    REVOKE CONNECT ON DATABASE postgres FROM PUBLIC;
    GRANT CONNECT ON DATABASE litellm TO litellm;
    GRANT CONNECT ON DATABASE litellm TO grafana_ro;
    GRANT CONNECT ON DATABASE keycloak TO keycloak;
    GRANT CONNECT ON DATABASE rotator TO rotator;
    GRANT CONNECT ON DATABASE postgres TO postgres;
    \endif

    -- Least-privilege reporting grants: SELECT on exactly the reviewed spend,
    -- token, user, and daily-aggregate tables — never a schema-wide or
    -- default-privilege grant (the daily aggregate carries the prompt-cache
    -- read/creation token split that the cache-utilization panels surface).
    -- LiteLLM's migrations create these tables on its first start, so
    -- a first converge legitimately grants nothing here and the second pass
    -- (or any later converge) converges the grants. Prompt bodies are not
    -- reachable: store_prompts_in_spend_logs is pinned false, so spend rows
    -- are metadata-only.
    \if :fix_grafana_ro_grants
    \connect litellm
    SELECT format('GRANT SELECT ON TABLE public.%I TO grafana_ro', tab)
      FROM unnest(ARRAY[
             'LiteLLM_SpendLogs','LiteLLM_VerificationToken',
             'LiteLLM_UserTable','LiteLLM_DailyUserSpend'
           ]) AS tab
     WHERE to_regclass(format('public.%I', tab)) IS NOT NULL
     ORDER BY tab \gexec
    \connect postgres
    \endif
EOSQL

if [[ "$state_changed" == true ]]; then
    echo AIGW_POSTGRES_CHANGED
else
    echo AIGW_POSTGRES_OK
fi
