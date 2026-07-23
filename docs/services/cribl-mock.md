# cribl-mock

## What it does

cribl-mock is a stand-in for the customer's real Cribl Stream worker: a bare
OpenTelemetry Collector that accepts OTLP logs, metrics, and traces and prints
every record it receives (the `debug` exporter, `verbosity: detailed`). It
exists so the whole SOC export leg — Alloy's redaction, allow-lists, and
delivery retries — is testable without a live customer endpoint. It ships
inside the same `compose/docker-compose.yml` as every other service, not only
in local preprod; a comment on the service records the swap: point
`CRIBL_OTLP_ENDPOINT` at the real Cribl worker, then delete this service.

## Who talks to it

- Alloy is its only client, on the private `net-internal` network, from its
  own fixed source address — the same Alloy export leg documented in
  [`docs/services/alloy.md`](alloy.md).
- Nothing else can reach it: it has no other network membership and publishes
  no host port.

## The load-bearing config

Its OTLP receiver, from `compose/cribl-mock/config.yaml`:

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318
```

This receiver has no `tls:` block, so the default service in
`compose/docker-compose.yml` accepts plaintext OTLP only — matching Alloy's
own `insecure = true` exporter setting for it. A second file,
`config.preprod-tls.yaml`, layers TLS onto this same receiver, but only in
local preprod's `compose/docker-compose.preprod.yml`; the production compose
file never loads it.

## How you know it is healthy

The compose healthcheck does an HTTP GET to its own loopback-only
`health_check` extension at `http://127.0.0.1:13133/` (10s interval, 12
retries, 10s start period) — that only proves the collector process started,
not that Alloy is actually delivering to it. For delivery, watch Alloy's own
export alerts in `compose/prometheus/rules.yml` instead:
`AIGatewayAlloyExporterSendFailures`, `AIGatewayAlloyExporterEnqueueFailures`,
and `AIGatewayAlloyExporterQueueSaturation` all fire on the same Cribl
exporter that targets this service (or the real Cribl worker in production).

## Learn more

See [Cribl SOC handoff — Production configuration](../cribl-soc-handoff.md#production-configuration).
