# Scaling and High Availability Posture

The implemented `rocky9-production` profile (deprecated alias
`generic-rocky9`) runs one Docker Compose project on one Rocky Linux 9 VM.
This deployment is **not highly available**. High availability on Docker
Compose is not supported. The host, Docker daemon, kernel, storage, firewalls,
network interfaces, and power all share one failure domain. Compose bridges
and service-name DNS do not span hosts. Adding replicas on the same VM does
not change that. The recovery and reboot exercises in
[operations.md](operations.md) restore this single stack; they do not confer
HA. Current posture is tracked in
[project-status.md](project-status.md).

## Capacity on this deployment: scale the VM vertically

The supported way to add capacity to the Compose deployment is vertical:
increase the VM's CPU, memory, and disk, then raise the reviewed per-service
resource limits. Per-service knobs — LiteLLM workers/connection pools first
among them — are bounded in [litellm-scaling.md](litellm-scaling.md).

Ad hoc Compose `--scale` is not supported. Several services carry
single-replica invariants: key-rotator's managed-group topology lock and the
portals' key-lifecycle serialization are process-local, LiteLLM's worker/pool
accounting assumes the reviewed container count, and Grafana, Loki,
Prometheus, Vault, and Postgres all use local single-writer state. Keep one
replica and one worker per service unless a change is explicitly reviewed.

## High availability and horizontal scaling: Kubernetes

True HA and horizontal scaling require a separate Kubernetes design. Another
Compose overlay on this VM is not enough. The Kubernetes design must include:

- independent nodes in separate failure domains;
- external HA PostgreSQL and Redis;
- Vault Integrated Storage with TLS and a production unseal ceremony;
- object storage for Loki;
- customer-owned AD/LDAP and DNS;
- readiness, drain, migration, and disruption rules for each service; and
- the current isolation model, including exact egress identity, no Docker
  socket discovery, and separate network planes.

Component-level blockers noted above (process-local locks in key-rotator and
the portals) must be replaced with database-backed or leader-elected
coordination before any of those services runs more than one replica.

Sizing, node counts, storage services, RTO/RPO targets, and load-balancer
ownership are customer infrastructure decisions; they are inputs to the
Kubernetes design, not choices this repository can make. A Kubernetes profile
would be specified, reviewed, and accepted on its own evidence — distinct from
the single-stack drills in [test-runbook.md](test-runbook.md).

## Planning exercise (future): Blue/Green upgrades across two VMs

**Status: planning exercise only.** Nothing below is implemented, scheduled,
or supported today; it is recorded so the option surfaces when upgrade
downtime becomes a real constraint (owner request, 2026-07-16).

The idea: two identical single-stack VMs ("blue" and "green") behind a small
third VM running a TLS-passthrough L4 proxy (HAProxy or similar) that owns the
published edge IPs. Upgrades converge the idle color, prove it with the
acceptance runbook, then cut traffic over; the previous color remains a warm
rollback until the next cycle. This buys zero-interruption *planned* upgrades
without re-platforming, and is not HA — the proxy VM and each stack VM remain
single failure domains.

What makes this a design exercise rather than a procedure is state. Each data
store has one local writer today. This includes Postgres, Vault, Open WebUI,
Grafana, Loki, and Prometheus. Process-local locks in key-rotator and the
portals also prevent replicas.

A future cutover design needs:

- a state map that says what each image update keeps or destroys;
- a choice to replicate, restore during a write freeze, or accept loss for
  each data store;
- a Vault unseal step during cutover; and
- a session plan, such as requiring users to sign in again.

The existing [upgrade durability audit](research/upgrade-durability-audit-20260716.md)
defines the restore and freeze order. Both stack VMs would need the full
egress, ADM, and internal topology. The proxy VM would need its own small,
reviewed edge policy.

If the state-map work concludes that most stores must be externalized to make
cutover safe, that is the signal to spend the effort on the Kubernetes design
above instead — externalized state is most of that migration's cost anyway.
