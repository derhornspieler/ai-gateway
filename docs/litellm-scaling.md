# LiteLLM Capacity and Scaling Design

This document separates tuning that is possible in the current single-VM
deployment from a future multi-replica design. It is not an HA claim. One
Rocky Linux host, one Docker daemon, one edge pair, one database, one cache,
and one physical network path still share failure domains even if more
LiteLLM processes are started.

The upstream production guidance referenced here is version-sensitive. It was
reviewed on 2026-07-12; recheck the
[LiteLLM production guide](https://docs.litellm.ai/docs/proxy/prod) and
[health-check contract](https://docs.litellm.ai/docs/proxy/health) when the
pinned image changes.

## Current executable topology

The implemented Compose service is one LiteLLM container using the default one
Uvicorn worker. Its reviewed limits are 2 CPUs, 4 GiB memory, and 1024 PIDs.
It has a 600-second provider request timeout, two retries, one shared
PostgreSQL database, and one shared Redis service. The Redis service is a
bounded, password-protected, non-persistent cache/router store; PostgreSQL is
the durable virtual-key, credential, budget, and spend store.

Traefik, oauth2-proxy, Open WebUI, dev-portal, and key-rotator all target the
single `litellm:4000` service name. The container healthcheck currently probes
`/health/liveliness`; the public inference allow-list also exposes
`/health/readiness`, but no implemented load balancer uses readiness to remove
an instance from rotation. Compose's default termination grace is also shorter
than the longest permitted 600-second inference request. Planned container
replacement is therefore not proven hitless for long or streaming requests.

Do not use `docker compose up --scale litellm=N` as an operational shortcut.
Docker DNS answers, client DNS caching, concurrent schema migration, database
connection multiplication, background work, readiness, and connection drain
have not been made deterministic in that topology. The portal's separate
single-worker restriction is unrelated and remains mandatory: scaling
LiteLLM does not authorize scaling `dev-portal` or its process-local API-key
creation lock.

## Safe vertical tuning

Treat every change as a measured capacity experiment, not as a generic CPU
formula.

1. Establish a repeatable baseline with one worker and the pinned image.
   Measure CPU throttling, RSS, PIDs, file descriptors, event-loop latency,
   PostgreSQL connections/query latency, Redis latency, Envoy latency, and
   Alloy drops as well as request latency and throughput.
2. Increase CPU, memory, and PID limits together in small reviewed increments.
   Preserve host headroom for PostgreSQL, Redis, Envoy, Vault, and the
   prompt-bearing telemetry pipeline. A larger LiteLLM limit that induces host
   reclaim or OOM pressure is a regression.
3. Keep one worker until evidence shows process saturation rather than provider
   latency, database contention, telemetry cost, or egress limits. LiteLLM's
   documented default is one Uvicorn worker.
4. If multiple workers in one container are tested, set `--num_workers`
   explicitly. Review whether Gunicorn supervision and bounded, jittered
   worker recycling are needed; never add those flags without testing them
   against the exact pinned image. Database capacity must include every worker:

   ```text
   total LiteLLM DB connections =
     per-worker pool limit × workers per container × containers
   ```

   Reserve separate PostgreSQL capacity for Keycloak, key-rotator, backup,
   migrations, and operator recovery. A pooler is a separate reviewed service,
   not a substitute for connection accounting.
5. Keep debug logging disabled and use bounded structured telemetry. Benchmark
   with the required prompt capture enabled; a result obtained by disabling
   mandatory audit/trace work is not representative.
6. Do not shorten the 600-second request timeout merely to make restart tests
   pass. If the workload permits a lower bound, change the API contract first,
   then align client, load-balancer, proxy, and termination timeouts.

## Required multi-replica architecture

A future throughput-oriented design should use one worker per LiteLLM
container and explicit replica identities. It must not grant any proxy access
to `/var/run/docker.sock` or depend on Docker-label discovery.

The bounded design is:

1. Ansible renders named replica services or an orchestrator renders stable
   replica endpoints. Every replica receives the same reviewed image, model
   config, master/salt keys, security settings, and resource limits.
2. Replicas share one reviewed PostgreSQL service and one reviewed Redis
   service. They attach to a dedicated LiteLLM backend bridge plus the existing
   vendor, database, cache, and telemetry planes; they do not join user/admin
   frontend planes directly.
3. A dedicated internal `litellm-lb` joins the backend bridge and only the
   specific frontend planes needed by Traefik, oauth2-proxy, Open WebUI,
   dev-portal, and key-rotator. All five consumers target that stable load
   balancer name instead of an individual replica.
4. The load balancer uses a reviewed static file containing the exact replica
   URLs, active `/health/readiness` checks, bounded passive-failure handling,
   and explicit timeouts. The intended primitives are documented by
   [Traefik's file-configured HTTP service load balancer](https://doc.traefik.io/traefik/reference/routing-configuration/http/load-balancing/service/).
   Configuration comes from Ansible/inventory, not the Docker API. External
   inference paths remain restricted by the existing Traefik allow-list, and
   the LiteLLM Admin UI remains behind oauth2-proxy.
5. A deployment first runs the exact schema migration once as a separate
   controlled job. Only after it succeeds do application replicas with
   automatic schema updates disabled start or roll. Multiple replicas must
   never race migrations.
6. A rolling update adds and proves a ready replacement before draining an old
   replica. Draining removes the old replica from new selection, waits longer
   than the maximum approved in-flight request/stream duration, and only then
   sends the final stop signal. At least two ready replicas are required during
   that sequence.

This design improves LiteLLM process capacity but does not make this single-VM
stack highly available. Host, Docker, load-balancer, PostgreSQL, Redis, Envoy,
and physical-network failure remain shared. Real HA requires at least separate
failure domains plus replicated/managed state and an external load-balancing
control plane.

### Shared-state requirements

- All replicas must use the same stable `LITELLM_SALT_KEY`; changing it can
  make stored credentials unreadable.
- PostgreSQL sizing must cover aggregate worker pools and migrations. Backup,
  restore, ACL reconciliation, and upgrade gates remain single coordinated
  operations.
- Redis must be shared by every replica for coordinated router/cache state. If
  global rate-limit or other correctness controls are moved into Redis, the
  present tmpfs/single-instance posture is insufficient; define persistence,
  replication, outage semantics, and fail-open/fail-closed behavior first.
- Credential creation/rotation must become visible on every replica within a
  measured bound. Test cache invalidation and do not assume a successful write
  through one instance proves immediate use by all others.
- Do not enable `allow_requests_on_db_unavailable` by default. Upstream notes
  that it changes readiness and authorization behavior; this deployment must
  define which key, budget, and audit guarantees may fail before considering
  that availability tradeoff.

## Benchmark and failure acceptance

Record the exact image digest, host size, worker/replica count, pool settings,
model/provider, payload distribution, prompt-capture setting, concurrency,
duration, and client location. Use synthetic prompts unless production data is
explicitly approved. Include both streaming and non-streaming requests and
enough duration to expose memory growth and connection exhaustion.

Use the version-reviewed
[official LiteLLM benchmark method](https://docs.litellm.ai/docs/benchmarks) as
one reproducible input, not as a promised result. Run two distinct phases:

1. A `network_mock: true` microbenchmark with retries and callbacks disabled,
   following the upstream benchmark configuration, measures LiteLLM's hot-path
   proxy overhead without provider/network variance. Because it bypasses Envoy
   and required prompt telemetry, it cannot by itself approve this gateway.
2. A representative end-to-end run restores the reviewed retries, Envoy path,
   PostgreSQL/Redis behavior, virtual-key enforcement, OTel callback, and full
   prompt capture. This is the release-capacity measurement.

In both phases, capture the `x-litellm-overhead-duration-ms` response header
and report its p50/p95/p99 distribution beside total request latency. Reject a
harness that silently omits the header or mixes proxy-overhead samples with
provider latency. Do not copy upstream RPS/latency results into this project's
capacity claim; hardware, image, callbacks, database, and traffic differ.

At minimum collect:

- successful requests/second, error/timeout rate, time to first token, and
  end-to-end p50/p95/p99 latency;
- per-replica CPU, throttling, RSS, PIDs, restarts, open connections, and
  request distribution;
- PostgreSQL active/queued connections, lock/query latency, transaction errors,
  and storage/WAL growth;
- Redis latency, memory, evictions, connection count, and restart impact;
- Envoy upstream latency/errors and Alloy queue/refusal/drop counters; and
- provider rate-limit responses separately from gateway-generated failures.

The candidate passes only when it also proves these security and failure
properties:

1. virtual-key ownership, project limits, budgets, and management-path denial
   remain correct under concurrency;
2. every replica can reach vendors only through Envoy and cannot reach the host
   or external network directly;
3. traffic is sent only to ready replicas; a killed/unready replica is removed
   within the declared bound and produces no authentication bypass;
4. a planned drain completes in-flight ordinary and streaming requests while
   new requests move to healthy replicas;
5. one controlled schema migration succeeds with application replicas barred
   from racing it;
6. provider credential rotation and virtual-key deactivation take effect on
   every replica within the accepted bound;
7. PostgreSQL and Redis outage behavior matches the documented security policy;
   and
8. an unchanged full converge preserves the intended replica set and does not
   recreate healthy stateful services.

Set workload-specific service-level thresholds before running the test. “More
RPS” alone is not acceptance if tail latency, dropped streams, database
headroom, authorization consistency, or observability deteriorates.
