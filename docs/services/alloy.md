# alloy

## What it does

Alloy (Grafana Alloy) is the AI Gateway's telemetry collector — the one
program that gathers logs, metrics, and traces from the rest of the stack and
decides where they go. It receives OTLP (the OpenTelemetry wire format) from
internal services, scrapes Prometheus-style metrics from the rest of the
stack, writes a sanitized copy of everything to the local Loki and Prometheus
stores, and mirrors that same admitted stream out to the customer's Cribl SOC
endpoint.

## Who talks to it

Alloy is the one outbound telemetry choke point: everything admitted flows
through it before any of it can leave the gateway.

- LiteLLM sends AI-request trace spans to Alloy's authenticated port 4319
  (`http://alloy:4319/v1/traces`, from `compose/litellm/aigw_otel_callback.py`),
  proven by a bearer token read from a file.
- key-rotator sends ordinary OTLP telemetry to Alloy's open port 4318. The
  two portals do not speak OTLP at all — they write structured JSON security
  events to stdout, and Alloy's Docker log pipeline picks those up like any
  other container log.
- Alloy scrapes Traefik, Envoy egress, Keycloak, Grafana, Prometheus,
  Alertmanager, Loki, node-exporter, and itself (`prometheus.scrape
  "gateway"` in `compose/alloy/config.alloy`) — Prometheus never scrapes
  anything itself.
- Alloy pushes admitted metrics into Prometheus over remote-write, and
  admitted logs into Loki.
- Prometheus sends only its own generated alert state back to Alloy over a
  private mutual-TLS listener, so that state can be mirrored to Cribl too.
- Alloy tails Docker's own JSON log files read-only, and two root-owned log
  trees (Vault audit, controller upgrade/rollback records), also read-only.

## The load-bearing config

The only path out to the customer, from `compose/alloy/config.alloy`
(uncommitted working-tree state):

```hcl
otelcol.exporter.otlp "cribl" {
  client {
    endpoint = sys.env("CRIBL_OTLP_ENDPOINT")
    tls {
      insecure = true
    }
  }
  ...
}
```

This is the single exporter that can send data to Cribl. Its queue is
byte-bounded at 2 GiB and retries for up to 24 hours before giving up. The
`insecure = true` line is a development-only default aimed at the bundled
`cribl-mock` stand-in; a production converge replaces this whole marked block
with a verified TLS configuration instead.

## How you know it is healthy

The compose healthcheck does an HTTP GET to `/-/ready` and requires the
response to contain the text `Alloy is ready.`. That only proves Alloy
started — it does not prove delivery is working. For that, watch the real
alerts in `compose/prometheus/rules.yml`: `AIGatewayAlloyExporterSendFailures`,
`AIGatewayAlloyExporterEnqueueFailures`, and
`AIGatewayAlloyExporterQueueSaturation` for the Cribl path, plus
`AIGatewayLokiWriteDrops` and `AIGatewayPrometheusRemoteWriteFailures` for the
two local stores.

## Learn more

See [Observability operations — Cribl delivery alerts](../observability-operations.md#cribl-delivery-alerts).
