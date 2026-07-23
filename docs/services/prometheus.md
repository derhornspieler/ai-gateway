# prometheus

## What it does

Prometheus is the gateway's local metrics database and its only alert
evaluator. It does not scrape anything itself — its own `scrape_configs` list
is empty on purpose. Alloy owns the entire scrape graph and pushes metrics in
over remote-write instead. Prometheus keeps local data for up to 30 days (or
a configured size cap, whichever limit is hit first) and continuously checks
every rule in `compose/prometheus/rules.yml`.

## Who talks to it

- Alloy is the only writer: it pushes every admitted metric to Prometheus's
  remote-write receiver (`--web.enable-remote-write-receiver` in
  `compose/docker-compose.yml`).
- Alloy also scrapes Prometheus's own metrics endpoint over the private
  observability network — Prometheus never reaches out to Alloy itself.
- Prometheus sends its evaluated alerts to Alertmanager
  (`alertmanagers: - targets: [alertmanager:9093]` in
  `compose/prometheus/prometheus.yml`), and will not start until Alertmanager
  reports healthy (`depends_on: alertmanager: condition: service_healthy`).
- Prometheus pushes only its own generated `ALERTS` / `ALERTS_FOR_STATE`
  series back out to Alloy, over a dedicated mutual-TLS connection — nothing
  else it stores ever leaves this way, so the export path cannot loop back
  into local storage.
- Grafana reads Prometheus through a read-only, non-editable proxy datasource
  (`compose/grafana/provisioning/datasources/datasources.yml`).

## The load-bearing config

The watchdog rule group header, from `compose/prometheus/rules.yml`
(uncommitted working-tree state):

```yaml
groups:
  - name: aigw-observability-pipeline
    rules:
      - alert: AIGatewayWatchdog
        expr: vector(1)
        for: 0m
```

`vector(1)` is always true, so this alert is designed to never actually stop
firing. If it does stop, something broke somewhere between Prometheus's rule
evaluation, Alertmanager's delivery, and Grafana's alert display — it is the
trip-wire for the whole alert pipeline, not a check on any one service.

## How you know it is healthy

The compose healthcheck does an HTTP GET to `/-/ready` over the private
observability network. The real signal an operator should trust is the
`AIGatewayWatchdog` alert staying in the firing state and `up{job="prometheus"}`
staying at 1 in Grafana — a red watchdog panel means one part of the
Prometheus-to-Alertmanager-to-Grafana path is missing.

## Learn more

See [Observability operations — Alert path watchdog](../observability-operations.md#alert-path-watchdog).
