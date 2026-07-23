# envoy-egress

## What it does

Envoy egress is the only service in the gateway allowed to open a connection
to the public internet. LiteLLM and key-rotator never talk to a provider
directly — they send plain HTTP to Envoy on a private network, and Envoy is
the one that starts a real TLS connection out to the provider, using a
reviewed CA bundle it was built with. It has no catch-all route: only the
providers selected at release time are compiled into its image.

## Who talks to it

- LiteLLM sends every model request here (`api_base: http://envoy-egress:8080/anthropic`
  in `compose/litellm/config.yaml`), over the private `net-vendor` bridge.
- key-rotator also reaches it over `net-vendor` (`EGRESS_BASE: http://envoy-egress:8080`
  in `compose/docker-compose.yml`) for provider token exchange.
- Envoy is the only workload attached to `net-egress`, at a fixed address
  (`ENVOY_EGRESS_IP`) that the host firewall's `DOCKER-USER` allow-list is
  built around — nothing else on that bridge is permitted to reach the
  internet.
- Alloy scrapes Envoy's own stats on the private `net-metrics` bridge
  (`envoy-egress:9902/stats/prometheus` in `compose/alloy/config.alloy`).

## The load-bearing config

Envoy's TLS validation replaces the system trust store with one reviewed CA
file and one exact provider hostname, checked on every connection — Envoy
drops the request if either check fails, with no fallback to system trust.
See [How the CA pin is enforced, checked, and watched](../security-model.md#how-the-ca-pin-is-enforced-checked-and-watched)
for the exact config and the two separate checks that prove the pin itself
hasn't drifted from what was reviewed.

## How you know it is healthy

The compose healthcheck runs `aigw-envoy-entrypoint health` in-container,
which asks Envoy's own loopback-only admin port for its ready state and
requires the literal text `LIVE` (`services/egress-proxy/entrypoint.go`).
That only proves the process is up — for real dropped-traffic detection,
watch `AIGatewayEgressTLSVerifyFailures` (real certificate chain failures) and
`AIGatewayEgressScrapeAbsent` (metrics path itself is down), both driven by
the `envoy_cluster_ssl_fail_verify_error` metric in
`compose/prometheus/rules.yml`.

## Learn more

See [Observability operations — Egress trust alerts](../observability-operations.md#egress-trust-alerts).
