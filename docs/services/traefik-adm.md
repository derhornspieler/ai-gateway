# traefik-adm

## What it does

traefik-adm is the one HTTPS front door for administrators, reachable only
from the approved VPN range on the ADM network interface. It is a reverse
proxy — a single listener that reads the hostname a browser asked for and
hands the request to the right admin tool, or rejects it. Every admin tool
behind it (except the Keycloak login pages) sits behind its own dedicated
OAuth2 Proxy gate, so reaching a hostname here is never the same as being
authenticated to use it.

## Who talks to it

- VPN-connected admins connect straight to it on `${ETH1_IP}:443` — its only
  host port (`compose/docker-compose.yml`).
- Its routing table (`compose/traefik/dynamic-adm.yml`) sends
  `litellm-admin.<domain>` and `grafana.<domain>` and `prometheus.<domain>`
  each to its own `oauth2-proxy*` gate; `admin.<domain>` straight to
  `admin-portal` (which does its own live role check); `chat.<domain>` to
  `open-webui` as a second, VPN-only path; and `auth.<domain>` to `keycloak`
  for the full admin console (the internal edge only allows narrow login
  paths there). `vault.<domain>` routes to `oauth2-proxy-vault` only when
  `VAULT_UI_ENABLED` is true — this file is a Go template, and Traefik
  renders the `{{ if eq (env "VAULT_UI_ENABLED") "true" }}` block (and every
  `{{ env "DOMAIN" }}` placeholder) before parsing the resulting YAML, so a
  disabled Vault UI removes the router entirely instead of just hiding it.
- It reaches `keycloak` at a fixed, network-scoped `keycloak-adm` DNS alias on
  `net-admin-app`, and carries a fixed address there (`TRAEFIK_ADM_ADMIN_IP`)
  that downstream services trust as the one real proxy hop.
- Alloy scrapes its metrics on `net-metrics`
  (`{ "__address__" = "traefik-adm:9100", "job" = "traefik" }`).

## The load-bearing config

The exact-NIC-IP port binding, from `compose/docker-compose.yml`:

```yaml
    ports:
      - "${ETH1_IP:?ETH1_IP must be set}:443:443"
```

This binds only to the configured ADM-interface address — never `0.0.0.0` —
so the admin edge cannot be reached from the internal or egress interfaces
even if the host firewall were misconfigured. Traefik is the only service
allowed a `ports:` entry in the stack.

## How you know it is healthy

The compose healthcheck runs `traefik healthcheck` against the private
`/ping` handler, reporting unhealthy during graceful shutdown. The real
operator signals are `up{job="traefik"}` in Prometheus and the
`aigw-service-safety` rule group in `compose/prometheus/rules.yml`:
`AIGatewayServiceLatencyHigh`/`Critical`, `AIGatewayServiceErrorRateHigh`/
`Critical`, and `AIGatewayCertificateExpiresSoon`/`Critical`, distinguishing
traefik-adm from traefik-int by the `instance` label.

## Learn more

See [Production network security — Host connections and firewall zones](../network-security.md#1-host-connections-and-firewall-zones).
