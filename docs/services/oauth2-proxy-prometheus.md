# oauth2-proxy-prometheus

## What it does

This is the login gate in front of the Prometheus UI. Prometheus has no login
of its own, so this proxy is the whole authentication boundary: a Keycloak
login (OIDC — an industry-standard "prove who you are" handshake) carrying
the `aigw-admins` role must succeed here before any Prometheus page or API
call is reachable.

## Who talks to it

- traefik-adm's `prometheus.<domain>` router sends every request here first
  (`service: oauth2-proxy-prometheus` in `compose/traefik/dynamic-adm.yml`),
  trusting only traefik-adm's fixed address on `net-admin-app`
  (`OAUTH2_PROXY_TRUSTED_PROXY_IPS: ${TRAEFIK_ADM_ADMIN_IP}/32`).
- After login, it forwards to Prometheus's fixed address on the private
  `net-observability` network
  (`OAUTH2_PROXY_UPSTREAMS: http://${PROMETHEUS_OBSERVABILITY_IP}:9090`) —
  Prometheus listens only on that address, never a DNS name, so it starts
  only after Prometheus reports healthy (`depends_on: prometheus: condition:
  service_healthy`).
- It redeems the login code and fetches signing keys directly from
  `keycloak:8080` over `net-admin-app`; the interactive login page is the
  public `https://auth.<domain>/realms/aigw/...` URL, reached through
  traefik-adm.

## The load-bearing config

The role gate and the fixed-address upstream, from
`compose/docker-compose.yml`:

```yaml
      OAUTH2_PROXY_UPSTREAMS: http://${PROMETHEUS_OBSERVABILITY_IP:?PROMETHEUS_OBSERVABILITY_IP must be set}:9090
      OAUTH2_PROXY_ALLOWED_GROUPS: "aigw-admins"
      OAUTH2_PROXY_OIDC_GROUPS_CLAIM: "roles"
```

Prometheus has no per-user identity concept, so unlike the Grafana variant
this proxy does not forward identity headers downstream — the `aigw-admins`
role check is the entire access decision, and it happens before the request
ever reaches Prometheus's address.

## How you know it is healthy

The compose healthcheck calls `GET /ready` through the `aigw-health-probe`
helper binary. There is no Prometheus scrape target for this service (it
fronts Prometheus, it is not scraped by it); Alloy tails its container output
generically and labels it `service_name="oauth2-proxy-prometheus"` in Loki,
and the configured `OAUTH2_PROXY_AUTH_LOGGING_FORMAT` line records each login
decision's `status` field without leaking the one-time OAuth code or token.

## Learn more

See [Keycloak realms and admin access — Login gates](../keycloak-realm-architecture.md#login-gates).
