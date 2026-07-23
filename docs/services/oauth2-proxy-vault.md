# oauth2-proxy-vault

## What it does

This is the login gate in front of the optional Vault UI. It only exists
when an operator turns the Vault browser surface on (the `vault-ui` Compose
profile). A Keycloak login (OIDC — an industry-standard "prove who you are"
handshake) carrying the `aigw-admins` role must succeed here first; Vault
itself then runs its own separate OIDC check against a narrower
`vault-admins` policy, so reaching Vault's UI needs two independent role
checks, not one.

## Who talks to it

- traefik-adm's `vault.<domain>` router sends every request here first
  (`service: oauth2-proxy-vault` in `compose/traefik/dynamic-adm.yml`), and
  that router only exists in the rendered config when `VAULT_UI_ENABLED` is
  true.
- It trusts only traefik-adm's fixed address on `net-admin-app`
  (`OAUTH2_PROXY_TRUSTED_PROXY_IPS: ${TRAEFIK_ADM_ADMIN_IP}/32`).
- After login, it forwards to `vault-ui-proxy:8080`
  (`OAUTH2_PROXY_UPSTREAMS`) — a separate proxy that serves the reviewed
  static UI assets and forwards only Vault's `/v1` API, since the DHI Vault
  binary itself ships with no UI. It starts only after `vault-ui-proxy`
  reports healthy (`depends_on: vault-ui-proxy: condition: service_healthy`).
- It redeems the login code and fetches signing keys directly from
  `keycloak:8080` over `net-admin-app`; the interactive login page is the
  public `https://auth.<domain>/realms/aigw/...` URL, reached through
  traefik-adm.

## The load-bearing config

The role gate and the profile that makes this service optional, from
`compose/docker-compose.yml`:

```yaml
    profiles: [vault-ui]
      ...
      OAUTH2_PROXY_UPSTREAMS: http://vault-ui-proxy:8080
      OAUTH2_PROXY_ALLOWED_GROUPS: "aigw-admins"
      OAUTH2_PROXY_OIDC_GROUPS_CLAIM: "roles"
```

`profiles: [vault-ui]` means this container does not exist at all in a
default deploy — `scripts/aigw-compose.sh` only starts it when the profile is
enabled. When it does run, the `roles` claim's exact `aigw-admins` value is
required before a request ever reaches `vault-ui-proxy`.

## How you know it is healthy

The compose healthcheck calls `GET /ready` through the `aigw-health-probe`
helper binary. There is no Prometheus scrape target for this service; Alloy
tails its container output generically and labels it
`service_name="oauth2-proxy-vault"` in Loki, and the configured
`OAUTH2_PROXY_AUTH_LOGGING_FORMAT` line records each login decision's
`status` field without leaking the one-time OAuth code or token.

## Learn more

See [Keycloak realms and admin access — Login gates](../keycloak-realm-architecture.md#login-gates).
