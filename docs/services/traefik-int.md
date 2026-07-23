# traefik-int

## What it does

traefik-int is the one HTTPS front door for internal (LAN) users. It is a
reverse proxy — a single listener that reads the hostname and path a browser
asked for and hands the request to the right backend container, or rejects
it. Its routing table is a reviewed file, not automatic Docker-label
discovery, so only an explicit allow-list of hostnames and paths is ever
reachable; everything else falls through to a deny rule that returns 403
before it reaches an application.

## Who talks to it

- Internal users connect straight to it on `${ETH2_IP}:443` — the only host
  port this service publishes (`compose/docker-compose.yml`).
- It forwards to four backends, each on its own hostname
  (`compose/traefik/dynamic-int.yml`): `litellm` for an exact allow-list of
  inference paths on `api.<domain>` (never the admin API or UI); `dev-portal`
  for model discovery on `api.<domain>` and the portal itself on
  `portal.<domain>`; `keycloak` for only the login/logout paths users need on
  `auth.<domain>` (never the admin console); and `open-webui` on
  `chat.<domain>`.
- Alloy scrapes its Traefik metrics on the private `net-metrics` network
  (`{ "__address__" = "traefik-int:9100", "job" = "traefik" }` in
  `compose/alloy/config.alloy`) — metrics live on a separate, non-published
  entry point from the public `websecure` one.
- It also attaches to `net-int-edge`, a plain bridge with no application
  peers that exists only so Docker can NAT the published port.

## The load-bearing config

The exact-NIC-IP port binding, from `compose/docker-compose.yml`:

```yaml
    ports:
      - "${ETH2_IP:?ETH2_IP must be set}:443:443"
```

This binds only to the configured internal-interface address — never
`0.0.0.0` — so the container cannot accidentally listen on the ADM or egress
interfaces too. Traefik is the only service in the stack allowed a `ports:`
entry at all.

## How you know it is healthy

The compose healthcheck runs `traefik healthcheck` against Traefik's own
`/ping` handler on the private metrics entry point, and reports unhealthy
during graceful shutdown so a load balancer can drain it first. The real
operator signals are `up{job="traefik"}` in Prometheus and the
`aigw-service-safety` rule group in `compose/prometheus/rules.yml`:
`AIGatewayServiceLatencyHigh`/`Critical`, `AIGatewayServiceErrorRateHigh`/
`Critical`, and the `AIGatewayCertificateExpiresSoon`/`Critical` pair, all
distinguishing traefik-int from traefik-adm by the `instance` label.

## Learn more

See [Production network security — Host connections and firewall zones](../network-security.md#1-host-connections-and-firewall-zones).
