# volume-init

## What it does

volume-init is a one-shot container, not a running service. It starts before
every stateful service, fixes the Unix owner and permission mode on nine named
data volumes, and exits. Every long-running service that owns one of those
volumes waits for it to finish successfully before its own container is even
created.

## Who talks to it

Nothing "talks" to volume-init — it takes no network (`network_mode: none`)
and exits — but nine services gate their own startup on it with
`depends_on: { volume-init: { condition: service_completed_successfully } }`
in `compose/docker-compose.yml`: `postgres`, `open-webui`, `keycloak`,
`vault`, `alloy`, `prometheus`, `alertmanager`, `loki`, and `grafana`. Each
one's chown target below matches the volume it later mounts.

## The load-bearing config

It deliberately does not inherit the shared `x-hardening` anchor, from
`compose/docker-compose.yml`:

```yaml
restart: "no"
# The one-shot intentionally does not inherit x-hardening because its
# restart/capability contract differs. Keep the same bounded/log-routing
# metadata as long-running services so Alloy assigns an exact service.
cap_add: [CHOWN, FOWNER, FSETID]
```

`x-hardening` sets `restart: unless-stopped` and `cap_drop: [ALL]` for every
long-running service. volume-init needs the opposite restart policy (it must
exit once, not restart forever) and needs `CHOWN`, `FOWNER`, and `FSETID`
back to change ownership on volumes it doesn't already own — so it copies only
the shared logging labels from that anchor and sets its own security options
by hand.

## How you know it is healthy

volume-init has no compose healthcheck — a one-shot container's success is
its exit code. Docker Compose's `service_completed_successfully` condition
is that signal: every dependent service listed above refuses to start if
volume-init exits non-zero. Its `pids_limit: 32` also bounds it far below the
512 default, since it runs one shell script and nothing else. Its logs
(`service="volume-init"` in Loki, via Alloy's generic Docker log tail) show
the exact `chown`/`chmod` lines it ran.

## Learn more

See [Container security — Volumes and config mounts](../docker-security.md#volumes-and-config-mounts).
