# postgres

## What it does

postgres is the one PostgreSQL 18 instance for the whole stack. It holds three
separate application databases — `litellm`, `keycloak`, and `rotator` — each
owned by its own least-privilege role, plus a fourth read-only role for
Grafana's spend dashboards. Nothing shares a database across services.

## Who talks to it

- `litellm` (network `net-db-litellm`) connects to the `litellm` database as
  the `litellm` role.
- `keycloak` (network `net-db-keycloak`) connects to the `keycloak` database
  as the `keycloak` role (`KC_DB_URL: jdbc:postgresql://postgres:5432/keycloak`).
- `key-rotator` (network `net-db-rotator`) connects to the `rotator` database
  as the `rotator` role — this is where the append-only model, price,
  lifecycle, and usage-evidence rows live.
- `grafana` (network `net-db-grafana`) connects as the read-only `grafana_ro`
  role, granted `CONNECT` only on the `litellm` and `rotator` databases (never
  `keycloak`), from `compose/postgres/init/01-init-databases.sh`.
- `volume-init` must finish first: it chowns `/state/postgres` to `70:70` (the
  image's non-root postgres uid/gid) before postgres's own
  `service_completed_successfully` dependency lets it start.

## The load-bearing config

The image pin and volume, from `compose/docker-compose.yml`:

```yaml
image: dhi.io/postgres:18.4@sha256:a807e832c1fc9ded731956abcb53dc98ed003fd82e27275eaef8dcf52fb90236
volumes:
  - pg_data:/var/lib/postgresql/18/data
```

The exact `18.4` tag, the `/18/data` path, and the named `pg_data` volume ("The
fixed physical name keeps PostgreSQL 18 state explicit and makes a same-major
backup or restore easy to verify") commit this release to PostgreSQL 18 only.
`scripts/update-images.py` reads that same major version out of this line and
refuses to build an upgrade plan when a previous release's major differs —
there is no automatic path across a PostgreSQL major version in this release.

## How you know it is healthy

The compose healthcheck runs `pg_isready --username postgres --dbname
postgres` every 5s (24 retries, 20s start period) — it proves a real
authenticated connection works, not just that the process exists. No
Prometheus scrape target is wired up for postgres (`compose/alloy/config.alloy`
has none), so beyond that Docker health state, the only other signal is its
own container logs: Alloy tails them generically and labels them
`service="postgres"` in Loki.

## Learn more

See [Project status — What is implemented](../project-status.md#what-is-implemented).
