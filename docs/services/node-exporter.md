# node-exporter

## What it does

node-exporter reads the Rocky Linux host's own CPU, memory, disk, and
filesystem counters (from `/proc` and `/sys`) and exposes them as
Prometheus-style metrics. It is the only service in the stack that reports on
host health rather than gateway or application health.

## Who talks to it

- Alloy is its only real client: it scrapes `node-exporter:9100` over the
  private `net-metrics` network (`prometheus.scrape "gateway"` in
  `compose/alloy/config.alloy`) — node-exporter has no other network, no host
  port, and never talks to Prometheus, Loki, or Cribl directly.
- Nearly every alert in the `aigw-state-capacity` rule group in
  `compose/prometheus/rules.yml` — CPU, load, memory, swap, OOM kills,
  filesystem space and inodes, disk latency, and file descriptors — reads
  node-exporter's metrics through Prometheus, once Alloy has forwarded them
  there.

## The load-bearing config

Its host mount and collector flags, from `compose/docker-compose.yml`:

```yaml
    command:
      - --path.rootfs=/host
      - --path.procfs=/host/proc
      - --path.sysfs=/host/sys
      - --collector.filesystem.mount-points-exclude=^/(dev|proc|sys|run|var/lib/docker/(containers|overlay2)/.+)($|/)
    volumes:
      - /:/host:ro,rslave
```

The whole host root filesystem is bind-mounted read-only (`:ro`) so
node-exporter reports the real host's disk, CPU, and memory state instead of
its own container's limited view; `rslave` keeps that view current as the
host mounts more filesystems later. The exclude pattern keeps Docker's own
per-container overlay mounts from flooding filesystem metrics with thousands
of near-duplicate series.

## How you know it is healthy

The compose healthcheck does an HTTP GET to its own `:9100/metrics` and
requires the string `node_exporter_build_info` in the response — proving the
HTTP collector path works, not just that a process or socket exists. The real
signal is `up{job="node-exporter"}` in Prometheus (fed by Alloy), plus the
host-capacity alerts such as `AIGatewayHostCPUHigh`,
`AIGatewayHostMemoryLow`, and `AIGatewayFilesystemSpaceLow` in
`compose/prometheus/rules.yml`, all of which read its metrics.

## Learn more

See [Observability operations — Host capacity alerts](../observability-operations.md#host-capacity-alerts).
