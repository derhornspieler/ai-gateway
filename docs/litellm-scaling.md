# LiteLLM Capacity and Scaling Design

This document separates the tuning that is possible in the current single-VM
deployment from a future multi-replica design. It is not a high-availability
claim; that boundary is drawn in [high-availability.md](high-availability.md),
and the surrounding trust model lives in [solution-map.md](solution-map.md).
One Rocky Linux host, one Docker daemon, one edge pair, one database server,
one cache, and one physical network path remain shared failure domains no
matter how many LiteLLM processes are started.

The upstream production guidance referenced here is version-sensitive. It was
reviewed on 2026-07-12; recheck the
[LiteLLM production guide](https://docs.litellm.ai/docs/proxy/prod) and the
[health-check contract](https://docs.litellm.ai/docs/proxy/health) whenever the
pinned image changes.

## Current executable topology

The implemented Compose service is a single LiteLLM container running the image
`ghcr.io/berriai/litellm:v1.93.0`, pinned by digest. LiteLLM is one of the
stack's three reviewed non-DHI application exceptions rather than a
locally-built DHI derivative. It uses the default single Uvicorn worker within
reviewed limits of 2 CPUs, 4 GiB memory, and 1024 PIDs, with a 600-second
provider request timeout and two retries.

Its state lives in two services that are already part of the stack. A dedicated
`litellm` logical database on the shared PostgreSQL server, reached over
`net-db-litellm`, is the durable virtual-key, credential, budget, and spend
store. A single password-protected, non-persistent Redis instance on
`net-cache` is the bounded cache and router-coordination store. LiteLLM reaches
vendors only through `envoy-egress` on `net-vendor`, and emits prompt-bearing
OTel spans to Alloy on `net-telemetry`.

Traffic reaches LiteLLM on two separate edges. On the internal leg
`traefik-int` publishes the `api.$DOMAIN` host but routes only an explicit
allow-list of the inference surface — `/v1` and `/v1/…`, `/chat/completions`,
`/completions`, `/embeddings`, `/models`, `/health/liveliness`, and
`/health/readiness` — to `litellm:4000`. Every other path on that host falls
through to a catch-all `api-deny` router whose `deny-all` middleware returns 403
before it can reach the proxy, so the management API and Admin UI are never
exposed there. The LiteLLM Admin UI is reached only on the ADM leg:
`admin.$DOMAIN` on `traefik-adm` passes through `oauth2-proxy` (Keycloak OIDC,
`aigw-admins` role) to `litellm:4000` over `net-admin-app`.

Six consumers target the single `litellm:4000` service name: the `traefik-int`
api router, the `oauth2-proxy` Admin-UI gate, Open WebUI, the dev-portal, the
admin-portal, and key-rotator. To serve them LiteLLM joins `net-chat`,
`net-portal`, `net-admin-app`, `net-vendor`, `net-db-litellm`, `net-cache`, and
`net-telemetry`.

The container healthcheck probes `/health/liveliness`. The api-host allow-list
additionally exposes `/health/readiness`, but no implemented load balancer uses
readiness to remove an instance from rotation. Compose's default termination
grace is also shorter than the longest permitted 600-second inference request,
so planned container replacement is not proven hitless for long or streaming
requests.

Do not use `docker compose up --scale litellm=N` as an operational shortcut.
Docker DNS answers, client DNS caching, concurrent schema migration, database
connection multiplication, background work, readiness, and connection drain
have not been made deterministic in that topology. The portals' separate
single-worker restriction is unrelated and remains mandatory: scaling LiteLLM
does not authorize scaling `dev-portal`/`admin-portal` or their process-local
API-key creation lock.

## Safe vertical tuning

Treat every change as a measured capacity experiment, not a generic CPU
formula.

1. Establish a repeatable baseline with one worker and the pinned image.
   Measure CPU throttling, RSS, PIDs, file descriptors, event-loop latency,
   PostgreSQL connections and query latency, Redis latency, Envoy latency, and
   Alloy drops alongside request latency and throughput.
2. Increase CPU, memory, and PID limits together in small reviewed increments.
   Preserve host headroom for PostgreSQL, Redis, Envoy, Vault, and the
   prompt-bearing telemetry pipeline. A larger LiteLLM limit that induces host
   reclaim or OOM pressure is a regression.
3. Keep one worker until evidence shows process saturation rather than provider
   latency, database contention, telemetry cost, or egress limits. LiteLLM's
   documented default is one Uvicorn worker, and the command in Compose sets no
   `--num_workers`.
4. If multiple workers in one container are tested, set `--num_workers`
   explicitly and review whether Gunicorn supervision and bounded, jittered
   worker recycling are needed; never add those flags without testing them
   against the exact pinned image. Database capacity must account for every
   worker:

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

## Required multi-replica architecture (design, not implemented)

Nothing in this section exists today. It is a bounded design for a future
high-throughput profile. The current stack already has one PostgreSQL server
with the `litellm` database and one Redis instance. Future work would add
stable replica identities, a load balancer that does not use the Docker
socket, a controlled migration step, and safe connection draining. No proxy
may access `/var/run/docker.sock` or depend on Docker-label discovery.

1. Ansible renders named replica services, or an orchestrator renders stable
   replica endpoints. Every replica receives the same reviewed image, model
   config, master and salt keys, security settings, and resource limits.
2. Replicas share the one reviewed PostgreSQL service and the one reviewed
   Redis service. They attach to a dedicated LiteLLM backend bridge plus the
   existing vendor, database, cache, and telemetry planes; they do not join the
   user or admin frontend planes directly.
3. A dedicated internal `litellm-lb` joins the backend bridge and only the
   specific frontend planes needed by the six consumers — the `traefik-int` api
   router, `oauth2-proxy`, Open WebUI, dev-portal, admin-portal, and
   key-rotator. All six target that stable load-balancer name instead of an
   individual replica. Because per-request authorization, budget, and spend
   state live in PostgreSQL and router/cache coordination lives in Redis, the
   replicas are stateless at the HTTP layer: the load balancer needs
   readiness-aware round-robin across ready replicas, not sticky sessions.
4. The load balancer uses a reviewed static file containing the exact replica
   URLs, active `/health/readiness` checks, bounded passive-failure handling,
   and explicit timeouts. The intended primitives are documented by
   [Traefik's file-configured HTTP load balancer](https://doc.traefik.io/traefik/reference/routing-configuration/http/load-balancing/service/).
   Configuration comes from Ansible and inventory, not the Docker API. External
   inference paths stay restricted by the existing `traefik-int` allow-list, and
   the Admin UI stays behind `oauth2-proxy` on the ADM leg.
5. A deployment first runs the exact schema migration once as a separate
   controlled job. Only after it succeeds do application replicas start or roll
   with automatic schema updates disabled. Multiple replicas must never race
   migrations.
6. A rolling update adds and proves a ready replacement before draining an old
   replica. Draining removes the old replica from new selection, waits longer
   than the maximum approved in-flight request or stream duration, and only then
   sends the final stop signal. At least two ready replicas are required
   throughout that sequence.

This design improves LiteLLM process capacity but does not make the single-VM
stack highly available. Host, Docker, load-balancer, PostgreSQL, Redis, Envoy,
and physical-network failure remain shared. Real HA requires separate failure
domains plus replicated or managed state and an external load-balancing control
plane; see [high-availability.md](high-availability.md).

### Shared-state requirements

All replicas must use the same stable `LITELLM_SALT_KEY`, because changing it
can make stored credentials unreadable, and the same `LITELLM_MASTER_KEY`.
PostgreSQL sizing must cover all worker pools and migrations. Backup, restore,
ACL repair, and the upgrade gates in [operations.md](operations.md) remain one
coordinated operation. Every replica must share Redis for router and cache
state. Before Redis owns global rate limits or other required controls, define
its persistence, replication, outage behavior, and fail-open or fail-closed
rules. The current single tmpfs instance is not enough for that role.

Credential creation and rotation must become visible on every replica within a
measured bound — test cache invalidation rather than assuming that a successful
write through one instance proves immediate use by all others. Do not enable
`allow_requests_on_db_unavailable` by default: upstream notes that it changes
readiness and authorization behavior, and this deployment must first define
which key, budget, and audit guarantees may fail before accepting that
availability tradeoff.

## Benchmark and failure acceptance

Record the exact image digest, host size, worker/replica count, pool settings,
model and provider, payload distribution, prompt-capture setting, concurrency,
duration, and client location. Use synthetic prompts unless production data is
explicitly approved. Include both streaming and non-streaming requests and
enough duration to expose memory growth and connection exhaustion. The full
acceptance runbook lives in [test-runbook.md](test-runbook.md).

Use the version-reviewed
[official LiteLLM benchmark method](https://docs.litellm.ai/docs/benchmarks) as
one reproducible input, not as a promised result. Run two distinct phases. A
`network_mock: true` microbenchmark with retries and callbacks disabled,
following the upstream configuration, measures LiteLLM's hot-path proxy
overhead without provider or network variance; because it bypasses Envoy and
the required prompt telemetry it cannot by itself approve this gateway. A
representative end-to-end run then restores the reviewed retries, Envoy path,
PostgreSQL and Redis behavior, virtual-key enforcement, OTel callback, and full
prompt capture — this is the release-capacity measurement.

In both phases capture the `x-litellm-overhead-duration-ms` response header and
report its p50/p95/p99 distribution beside total request latency. Reject a
harness that silently omits the header or mixes proxy-overhead samples with
provider latency. Do not copy upstream RPS or latency results into this
project's capacity claim; hardware, image, callbacks, database, and traffic all
differ. At minimum collect:

- successful requests per second, error and timeout rate, time to first token,
  and end-to-end p50/p95/p99 latency;
- per-replica CPU, throttling, RSS, PIDs, restarts, open connections, and
  request distribution;
- PostgreSQL active and queued connections, lock and query latency, transaction
  errors, and storage/WAL growth;
- Redis latency, memory, evictions, connection count, and restart impact;
- Envoy upstream latency and errors, and Alloy queue, refusal, and drop
  counters; and
- provider rate-limit responses, kept separate from gateway-generated failures.

The candidate passes only when it also proves these security and failure
properties:

1. virtual-key ownership, project limits, budgets, and management-path denial
   remain correct under concurrency;
2. every replica can reach vendors only through Envoy and cannot reach the host
   or external network directly;
3. traffic is sent only to ready replicas, and a killed or unready replica is
   removed within the declared bound with no authentication bypass;
4. a planned drain completes in-flight ordinary and streaming requests while new
   requests move to healthy replicas;
5. one controlled schema migration succeeds with application replicas barred
   from racing it;
6. provider credential rotation and virtual-key deactivation take effect on
   every replica within the accepted bound;
7. PostgreSQL and Redis outage behavior matches the documented security policy;
   and
8. an unchanged full converge preserves the intended replica set and does not
   recreate healthy stateful services.

Set workload-specific service-level thresholds before running the test. "More
RPS" alone is not acceptance if tail latency, dropped streams, database
headroom, authorization consistency, or observability deteriorate.
