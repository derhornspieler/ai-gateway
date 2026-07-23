# keycloak

## What it does

Keycloak is the gateway's single sign-on and identity provider. Every human
login — browser chat, the developer portal, and the admin portal — and every
first-party OIDC client check runs through it. It federates users from the
customer's LDAPS directory instead of storing its own user database, and it
issues the tokens every other service trusts for role checks (for example,
`aigw-admins`).

## Who talks to it

- `open-webui` sends browsers here to sign in
  (`OPENID_PROVIDER_URL: "https://auth.${DOMAIN}/realms/aigw/.well-known/openid-configuration"`
  in `compose/docker-compose.yml`), over `net-chat`, and will not start until
  Keycloak reports healthy.
- `dev-portal` and `admin-portal` do the same OIDC login
  (`OIDC_INTERNAL_ISSUER: "http://keycloak:8080/realms/aigw"`), over
  `net-portal` / `net-admin-app`, also gated on Keycloak being healthy.
- `key-rotator` is Keycloak's identity controller: it creates the
  `aigw-identity-controller` service client, the `keycloak-admins` group, and
  the `break-glass-admin` user, reachable over `net-admin-app` and
  `net-portal` (see `docs/keycloak-realm-architecture.md`).
- `oauth2-proxy-vault` (only when the optional `vault-ui` profile is on)
  exchanges tokens with it for the Vault UI's admin-group gate.
- `postgres` is its database, over the dedicated `net-db-keycloak` network
  (`KC_DB_URL: jdbc:postgresql://postgres:5432/keycloak`).
- Alloy scrapes its `/metrics` over `net-metrics`.

## The load-bearing config

Keycloak's startup command in `compose/docker-compose.yml` includes:

```yaml
command:
  - start
  - --import-realm
```

This only ever imports on a **fresh** database. As
`docs/identity-operations.md` states plainly: "Keycloak reads realm imports
only when its database is empty." Editing a realm JSON template under
`keycloak/realms/` does nothing to a realm Keycloak has already created —
changes there only take effect against a brand-new, empty database.

## How you know it is healthy

The compose healthcheck does an HTTP GET to `http://127.0.0.1:9000/health/ready`
and requires the response to contain `"UP"`. The real signals are the generic
`AIGatewayScrapeTargetDown` alert (`up == 0`, `compose/prometheus/rules.yml`),
which covers Alloy's `job="keycloak"` scrape of `keycloak:9000/metrics`, and a
spike in `LOGIN_ERROR` / `CLIENT_LOGIN_ERROR` events reaching the reviewed
security log pipeline in `compose/alloy/config.alloy`.

## Learn more

See [Identity operations — Migrating an existing realm to `aigw-chat`](../identity-operations.md#migrating-an-existing-realm-to-aigw-chat).
