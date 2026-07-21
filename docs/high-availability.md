# Scaling and availability

Production runs one Docker Compose stack on one Rocky Linux 9 VM. The profile
name is `rocky9-production`. `generic-rocky9` is an older alias.

This design is **not highly available**. The VM, Docker, storage, firewall,
network cards, and power are one failure point. Docker Compose networks do not
cross hosts. More copies of a container on the same VM do not fix this limit.

The reboot and recovery steps in [production operations](operations.md) bring
this one stack back. They do not provide high availability. See the
[project status](project-status.md) for the current release limits.

## Add capacity to the current VM

Give the VM more CPU, memory, or disk when it needs more capacity. Then review
and raise the matching service limits. Start with LiteLLM worker and database
pool limits in the [LiteLLM scaling guide](litellm-scaling.md).

Do not use `docker compose --scale`. Several services must have one process:

- key-rotator and the portals use in-process locks;
- LiteLLM limits assume the reviewed worker count; and
- Grafana, Loki, Prometheus, Vault, and PostgreSQL use local state.

Keep one container and one worker for each service unless a reviewed design
changes these rules.

## True high availability needs a new platform

True high availability needs a separate Kubernetes design. A second Compose
file on the same VM is not enough.

That design must include:

- nodes in separate failure zones;
- highly available PostgreSQL and Redis services;
- Vault storage, TLS, and a production unseal plan;
- object storage for Loki;
- customer AD or LDAP and DNS;
- safe startup, drain, update, and disruption rules; and
- the current network and egress security boundaries.

The in-process locks in key-rotator and the portals must move to a shared
database or leader-election system before those services can have replicas.

The customer must set capacity, node count, storage, recovery targets, and
load-balancer ownership. A Kubernetes release would need its own design,
review, tests, and acceptance evidence. The current
[test runbook](test-runbook.md) covers only the single-VM design.

## Future idea: blue and green VMs

**This is an idea, not a supported procedure.**

A future design could use two single-stack VMs called blue and green. A small
third VM could pass TLS traffic to the active stack. An update would deploy to
the idle stack, test it, and then move traffic. The old stack could stay ready
for rollback.

This may reduce planned update downtime. It is still not full high
availability. The proxy and each stack VM remain single failure points.

State is the hard part. PostgreSQL, Vault, Open WebUI, Grafana, Loki, and
Prometheus each have one local writer today. A safe future design must decide,
for each store, whether to:

- copy changes between hosts;
- stop writes and restore a backup; or
- accept data loss.

It also needs a Vault unseal step and a user-session plan. Both stack VMs need
the full egress, ADM, and internal network layout. The proxy needs a small,
reviewed edge policy.

Use the current [image update workflow](image-update-workflow.md) and
[production operations guide](operations.md) for supported backup, update,
validation, and rollback steps. If most state must move to shared services,
build the Kubernetes design instead. Shared state is most of that work.
