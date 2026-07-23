# loki

## What it does

Loki is the gateway's local log store. It keeps admitted service logs and the
sanitized per-request AI audit stream on local disk (filesystem storage, not
a remote object store), for 7 days by default.

## Who talks to it

- Alloy is Loki's only writer: it pushes every admitted log line to
  `http://loki:3100/loki/api/v1/push` (`loki.write "local"` in
  `compose/alloy/config.alloy`), including the dedicated
  `service_name="aigw-requests"` stream built from LiteLLM's request traces.
- Grafana reads Loki over `net-observability` through the provisioned,
  read-only `Loki` datasource (uid `loki`) — Loki has no browser UI of its
  own, so Grafana is how an operator actually queries logs.
- Alloy also scrapes Loki's own metrics
  (`{ "__address__" = "loki:3100", "job" = "loki" }`).
- Loki has no host port and only one network. In `compose/docker-compose.yml`
  its entry is simply `networks: [net-observability]`.

## The load-bearing config

From `compose/loki/config.yml`:

```yaml
limits_config:
  retention_period: 168h   # 7d for ordinary local troubleshooting logs
  retention_stream:
    - selector: '{job="controller-lifecycle"}'
      priority: 10
      period: 24h
```

168 hours (7 days) is the default keep-time for ordinary logs. The
`controller-lifecycle` stream — Ansible's upgrade and rollback audit records
— is deliberately kept for only 24 hours here locally, because its durable
copy lives in the target's root-owned audit files and, after redaction, in
Cribl. The `compactor:` block's `retention_enabled: true` is what actually
deletes data past these limits; `limits_config` alone only marks it eligible.

## How you know it is healthy

The compose healthcheck does an HTTP GET to `/ready`, which checks Loki's own
internal service manager and ingester state, not just that the process
exists. The real signal is `up{job="loki"}` from Alloy's scrape, plus the
`AIGatewayLokiWriteDrops` and `AIGatewayLokiWriteRetriesHigh` alerts in
`compose/prometheus/rules.yml` — both measured from Alloy's writer, since
Loki raises no alerts of its own.

## Learn more

See [Observability operations — Retention and limits](../observability-operations.md#retention-and-limits).
