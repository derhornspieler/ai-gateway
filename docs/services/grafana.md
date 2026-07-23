# grafana

## What it does

Grafana is the operator-facing dashboard and alert-viewing UI for the
gateway. It reads from Prometheus, Loki, and Alertmanager, plus two
read-only PostgreSQL views (LiteLLM spend and the rotator's usage ledger),
but it evaluates no alert rules of its own — Prometheus stays the only rule
evaluator.

## Who talks to it

- oauth2-proxy is the only trusted browser login path: `GF_AUTH_PROXY_ENABLED:
  "true"`, and Grafana trusts its identity header only from oauth2-proxy's
  fixed private address (`GF_AUTH_PROXY_WHITELIST`). There is no second login
  form (`GF_AUTH_DISABLE_LOGIN_FORM: "true"`).
- Traefik on the ADM edge is the only reverse proxy that can reach it, over
  the `net-grafana` network (`networks: [net-grafana, net-observability,
  net-db-grafana]` in `compose/docker-compose.yml`).
- Grafana reads Prometheus, Loki, and Alertmanager over `net-observability`,
  and reads PostgreSQL over the private `net-db-grafana` bridge with a
  dedicated read-only role, `grafana_ro`.
- Alloy scrapes Grafana's own metrics
  (`{ "__address__" = "grafana:3000", "job" = "grafana" }`).
- Grafana waits for Prometheus and Alertmanager to report healthy, and for
  Loki to have started, before it starts itself (`depends_on:`).

## The load-bearing config

The provisioned Alertmanager datasource, from
`compose/grafana/provisioning/datasources/datasources.yml` (uncommitted
working-tree change touched the dashboards in this same directory):

```yaml
  - name: Alertmanager
    type: alertmanager
    uid: alertmanager
    access: proxy
    url: http://alertmanager:9093
    editable: false
    jsonData:
      implementation: prometheus
      handleGrafanaManagedAlerts: false
```

`handleGrafanaManagedAlerts: false` keeps Prometheus as the only alert
evaluator — Grafana only displays alert state here, it never runs a second,
competing set of rules. `editable: false` means an operator cannot quietly
repoint this datasource from inside the Grafana UI; changing it needs a
reviewed Ansible converge instead.

## How you know it is healthy

The compose healthcheck does an HTTP GET to `/api/health`. The real signal is
`up{job="grafana"}` from Alloy's scrape, plus the provisioned **AI Gateway
Alerts and Capacity** dashboard actually rendering data — an empty or
error panel there usually means a broken datasource connection, not a
Grafana crash.

## Learn more

See [Observability operations — Local dashboards and data sources](../observability-operations.md#local-dashboards-and-data-sources).
