# key-rotator

## What it does

key-rotator is the gateway's automation and identity controller. It rotates
provider credentials (Anthropic WIF/JWT exchange), issues and retires LiteLLM
virtual keys, reconciles model and price policy, and — after Vault and LDAPS
are ready — configures Keycloak's identity controller, managed groups, and
break-glass admin account (see `docs/identity-operations.md`).

## Who talks to it

- `dev-portal` calls it for self-service key issuance and project-membership
  reads, using a least-privilege `PORTAL_IDENTITY_TOKEN`
  (`ROTATOR_URL: http://key-rotator:8080` in `compose/docker-compose.yml`).
- `admin-portal` calls it with the broader `ROTATOR_INTERNAL_TOKEN` for
  admin-only key, project, and price operations.
- It in turn reaches Vault (`VAULT_ADDR: http://vault:8200`, over
  `net-vault`), Keycloak (`KEYCLOAK_URL: http://keycloak:8080`, over
  `net-admin-app`/`net-portal`), LiteLLM and Envoy egress (`LITELLM_URL`,
  `EGRESS_BASE`, over `net-vendor`), and its own `postgres` database
  (`DATABASE_URL`, over `net-db-rotator`).
- It exports telemetry to Alloy over `net-telemetry`.

## The load-bearing config

Its `depends_on` block in `compose/docker-compose.yml`:

```yaml
depends_on:
  postgres: { condition: service_healthy }
  # First converge intentionally starts the rotator before Vault is
  # initialized. Strict /readyz remains 503 until the approved bootstrap
  # or unseal ceremony; deployment verification enforces that separately.
  vault: { condition: service_started }
  envoy-egress: { condition: service_healthy }
```

Compose only waits for Vault's process to start, not for Vault to be
unsealed. Requiring health here would deadlock the very first converge,
because a freshly installed Vault is sealed and uninitialized until an
operator completes the Vault ceremony — that is expected, not a failure.

## How you know it is healthy

The compose healthcheck hits `/healthz` (liveness only — it tolerates a
sealed Vault). The real readiness signal is `/readyz`: Ansible polls it up to
12 times, 5 seconds apart, and requires HTTP 200 rather than 503 once Vault
is expected to be initialized
(`ansible/roles/docker_stack/tasks/main.yml`, "Probe strict key-rotator
dependency readiness after stack start").

## Learn more

See [Identity operations — What Ansible does](../identity-operations.md#what-ansible-does).
