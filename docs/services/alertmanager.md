# alertmanager

## What it does

Alertmanager receives Prometheus's evaluated alerts and manages only their
lifecycle: grouping related alerts together, deduplicating repeats,
inhibiting a lower-severity alert while its paired critical alert is also
firing, and tracking resolved state. This release deliberately sends nothing
outside the gateway — no email, chat, webhook, or Cribl receiver is wired up.

## Who talks to it

- Prometheus is Alertmanager's only alert source
  (`alertmanagers: - targets: [alertmanager:9093]` in
  `compose/prometheus/prometheus.yml`).
- Alloy scrapes Alertmanager's own metrics
  (`{ "__address__" = "alertmanager:9093", "job" = "alertmanager" }` in
  `compose/alloy/config.alloy`), which is how Prometheus later learns whether
  notification delivery is failing.
- Grafana reads Alertmanager through a read-only proxy datasource so an
  operator can see active and silenced alerts in the Alerting UI, while
  Grafana's own alert engine stays off
  (`GF_UNIFIED_ALERTING_ENABLED: "false"`).
- It has no host port, no Traefik route, and no public hostname. In
  `compose/docker-compose.yml`, Alertmanager's only `networks:` entry is
  `net-observability`, and it carries no `ports:` key at all.

## The load-bearing config

From `compose/docker-compose.yml`, the command line that keeps the API
private:

```yaml
    # One local instance: disable the otherwise separate gossip listener.
    - --cluster.listen-address=
    # The API is reachable only by private observability-network peers. It
    # has no host port, Traefik route, FQDN, or external receiver.
    - --web.listen-address=${ALERTMANAGER_OBSERVABILITY_IP:?ALERTMANAGER_OBSERVABILITY_IP must be set}:9093
```

And its only configured receiver, from `compose/alertmanager/alertmanager.yml`:

```yaml
receivers:
  - name: aigw-local-dashboard
```

No `slack_configs`, `webhook_configs`, or similar block exists under that
receiver — alerts are grouped and tracked locally, and the operator-facing
view is Grafana's dashboard, matching the "no host port" fact above.

## How you know it is healthy

The compose healthcheck does an HTTP GET to `/-/ready`. The real signal is
whether Prometheus can actually reach and deliver to it: watch
`prometheus_notifications_alertmanagers_discovered` (the
`AIGatewayAlertmanagerUnavailable` alert) and
`prometheus_notifications_errors_total` / `prometheus_notifications_dropped_total`
(the `AIGatewayAlertmanagerDeliveryFailures` alert), both defined in
`compose/prometheus/rules.yml`.

## Learn more

See [Observability operations — Alert path watchdog](../observability-operations.md#alert-path-watchdog).
