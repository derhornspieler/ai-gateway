# Scaling and High Availability Posture

The implemented `rocky9-production` (deprecated alias `generic-rocky9`) and
`rocky9-lab` profiles run one Docker Compose project on one Rocky Linux 9 VM.
This deployment is **not highly
available**, and building HA on Docker Compose is **not recommended or
supported**: the host, Docker daemon, kernel, storage, firewalls, physical
interfaces, and power are one failure domain, and host-local Compose bridges
and service-name DNS do not span hosts. Adding container replicas on the same
VM does not change that. The recovery and reboot exercises in
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
accounting assumes the reviewed container count, and Grafana, Loki, Tempo,
Prometheus, Vault, and Postgres all use local single-writer state. Keep one
replica and one worker per service unless a change is explicitly reviewed.

## High availability and horizontal scaling: Kubernetes

True HA and horizontal scaling require re-platforming to Kubernetes — a
separate architecture, not another Compose overlay on this VM. That design
must supply, at minimum: multiple independent nodes across failure domains;
external HA PostgreSQL and Redis; Vault on Integrated Storage with TLS and a
production unseal ceremony; object storage for Loki/Tempo; the customer's own
AD/LDAP and DNS; per-service readiness, drain, migration, and disruption
policy; and preservation of this stack's isolation model (exact egress
identity, no Docker-socket/broad discovery, per-plane network segmentation).
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

What makes this a design exercise rather than a procedure is state. This
stack is deliberately stateful in one place per concern, and none of it spans
hosts today: Postgres (Keycloak realm + LiteLLM), Vault (file backend,
manual unseal), Open WebUI's app database, Grafana/Loki/Tempo/Prometheus
local storage, and the key-rotator/portal process-local locks that already
forbid replicas. A cutover therefore needs, at minimum: a per-service state
map of what an image bump preserves versus destroys (recorded in the
[upgrade durability audit](research/upgrade-durability-audit-20260716.md),
whose §3 derives the restore/freeze tiers and cutover ordering directly);
a decision per store between replicate-to-green, restore-into-green
during a write freeze, or accept-loss; a Vault unseal step inside the cutover
window; and an identity plan for sessions (users re-authenticate after
cutover — acceptable — versus session replication — not pursued). The
three-NIC firewall ABI also multiplies: both stack VMs need the full
egress/ADM/internal topology, and the proxy VM needs its own reviewed,
minimal edge posture.

If the state-map work concludes that most stores must be externalized to make
cutover safe, that is the signal to spend the effort on the Kubernetes design
above instead — externalized state is most of that migration's cost anyway.
