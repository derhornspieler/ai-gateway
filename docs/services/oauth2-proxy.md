# oauth2-proxy

## What it does

This is the login gate in front of LiteLLM's native Admin UI. LiteLLM's own
built-in single sign-on is an enterprise-only feature, so this separate proxy
stands in front of it instead: every request must first complete a Keycloak
login (OIDC — an industry-standard "prove who you are" handshake) and carry
the `aigw-admins` role before it is ever forwarded to LiteLLM.

## Who talks to it

- traefik-adm's `litellm-admin.<domain>` and `litellm-admin-root` routers
  send every request here first (`service: oauth2-proxy` in
  `compose/traefik/dynamic-adm.yml`); the docs/openapi and model-mutation
  routes are denied by Traefik before they even reach this gate.
- It only trusts forwarded-proto/host headers from traefik-adm's one fixed
  address (`OAUTH2_PROXY_TRUSTED_PROXY_IPS: ${TRAEFIK_ADM_ADMIN_IP}/32`).
- After login, it forwards the request to `litellm` on `http://litellm:4000`
  (`OAUTH2_PROXY_UPSTREAMS`), over a fixed address on `net-admin-app` that
  LiteLLM in turn trusts as a proxy hop (`FORWARDED_ALLOW_IPS`).
- It redeems the login code and fetches signing keys directly from
  `keycloak:8080` over the private network; the interactive login page itself
  is the public `https://auth.<domain>/realms/aigw/...` URL, reached through
  traefik-adm like any other browser request.

## The load-bearing config

The role gate and the exact-hop trust, from `compose/docker-compose.yml`:

```yaml
      OAUTH2_PROXY_TRUSTED_PROXY_IPS: ${TRAEFIK_ADM_ADMIN_IP:?TRAEFIK_ADM_ADMIN_IP must be set}/32
      OAUTH2_PROXY_ALLOWED_GROUPS: "aigw-admins"
      OAUTH2_PROXY_OIDC_GROUPS_CLAIM: "roles"
```

Only a Keycloak login carrying the `roles` claim's exact `aigw-admins` value
is let through; the trusted-proxy line means only traefik-adm's one fixed
address can hand this proxy a forwarded scheme/host at all, so a compromised
peer container cannot forge one.

## How you know it is healthy

The compose healthcheck calls `GET /ready` (oauth2-proxy's readiness
contract, not just a TCP check) through the `aigw-health-probe` helper binary.
There is no Prometheus scrape target for this service, so day-to-day
visibility comes from its own logs: Alloy tails its container output
generically and labels it `service_name="oauth2-proxy"` in Loki, and the
configured `OAUTH2_PROXY_AUTH_LOGGING_FORMAT` line records each login
decision's `status` field without leaking the one-time OAuth code or token.

## Learn more

See [Keycloak realms and admin access — Login gates](../keycloak-realm-architecture.md#login-gates).
