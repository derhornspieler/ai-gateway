# oauth2-proxy-grafana

## What it does

This is the login gate in front of Grafana. Grafana has no login form of its
own here — it trusts whichever username this proxy hands it in a header. So
this proxy is the entire authentication boundary for the dashboards: a
Keycloak login (OIDC — an industry-standard "prove who you are" handshake)
carrying the `aigw-admins` role must succeed here before Grafana ever sees a
request.

## Who talks to it

- traefik-adm's `grafana.<domain>` router sends every request here first
  (`service: oauth2-proxy-grafana` in `compose/traefik/dynamic-adm.yml`),
  trusting only its fixed address on `net-admin-app`
  (`OAUTH2_PROXY_TRUSTED_PROXY_IPS: ${TRAEFIK_ADM_GRAFANA_IP}/32`).
- After login, it forwards to `grafana:3000` (`OAUTH2_PROXY_UPSTREAMS`) on a
  fixed address on `net-grafana` that Grafana in turn trusts as its one
  identity source (`GF_AUTH_PROXY_WHITELIST` in `compose/docker-compose.yml`).
- It redeems the login code and fetches signing keys directly from
  `keycloak:8080` over `net-admin-app`; the interactive login page is the
  public `https://auth.<domain>/realms/aigw/...` URL, reached through
  traefik-adm.

## The load-bearing config

The role gate and the header pass-through, from `compose/docker-compose.yml`:

```yaml
      OAUTH2_PROXY_PASS_USER_HEADERS: "true"
      OAUTH2_PROXY_ALLOWED_GROUPS: "aigw-admins"
      OAUTH2_PROXY_OIDC_GROUPS_CLAIM: "roles"
```

`PASS_USER_HEADERS` is `"true"` only on this variant: Grafana's own
`GF_AUTH_PROXY_HEADERS` reads the resulting `X-Forwarded-Preferred-Username`
and email headers to know who logged in. That header is only ever set after
the `roles` claim's exact `aigw-admins` value has already passed.

## How you know it is healthy

The compose healthcheck calls `GET /ready` through the `aigw-health-probe`
helper binary. There is no Prometheus scrape target for this service; Alloy
tails its container output generically and labels it
`service_name="oauth2-proxy-grafana"` in Loki, and the configured
`OAUTH2_PROXY_AUTH_LOGGING_FORMAT` line records each login decision's
`status` field without leaking the one-time OAuth code or token.

## Learn more

See [Keycloak realms and admin access — Login gates](../keycloak-realm-architecture.md#login-gates).
