# LiteLLM capacity and scaling

This page explains what can scale today and what needs a new design. The
current deployment is one VM. More LiteLLM processes on that VM would not make
the system highly available. See [availability limits](high-availability.md).

The upstream guidance was last reviewed on 2026-07-12. Recheck the
[LiteLLM production guide](https://docs.litellm.ai/docs/proxy/prod),
[health checks](https://docs.litellm.ai/docs/proxy/health), and pinned image
before changing this design.

## Current design

The stack runs one LiteLLM container with one Uvicorn worker. The image is
`ghcr.io/berriai/litellm:v1.93.0`, pinned by digest.

Current limits are:

| Setting | Value |
| --- | --- |
| CPU | 2 CPUs |
| Memory | 4 GiB |
| PIDs | 1024 |
| Provider timeout | 600 seconds |
| Provider retries | 2 |

LiteLLM uses:

- PostgreSQL for keys, credentials, budgets, and spend data;
- Redis for private cache and router state;
- Envoy as its only provider path; and
- Alloy for prompt-bearing telemetry.

The public API is `api.<domain>` on the internal edge. Traefik allows only the
approved inference, model, liveness, and readiness paths. Other paths return
HTTP 403 before they reach LiteLLM.

The Admin UI is `litellm-admin.<domain>` on the ADM edge. OAuth2 Proxy checks
the Keycloak `aigw-admins` role before it sends traffic to LiteLLM.

Six consumers use the one `litellm:4000` service:

- the internal API edge;
- the LiteLLM Admin gate;
- Open WebUI;
- the developer portal;
- the admin portal; and
- key-rotator.

The container health check calls `/health/liveliness`. The edge also exposes
`/health/readiness`, but there is no replica load balancer that removes an
unready instance. The normal Compose stop window is also shorter than the
longest 600-second request. A restart is not proven to be hitless for long or
streaming calls.

## Do not use Compose scaling

Do not run this shortcut:

```bash
docker compose up --scale litellm=2
```

The current design does not control:

- Docker DNS and client caching;
- database migration races;
- database connections per worker;
- background jobs;
- readiness-based traffic removal; or
- connection drain during a restart.

The developer and admin portal single-worker rule is separate. Scaling
LiteLLM does not allow more portal workers. Their key-creation locks are local
to one process.

## Safe changes today

The supported path is measured vertical tuning on the same VM.

1. Record a one-worker baseline.
2. Raise CPU, memory, and PID limits in small steps.
3. Keep enough host room for PostgreSQL, Redis, Envoy, Vault, and telemetry.
4. Keep one worker unless tests show that the Python process is the real limit.
5. Run the full security and telemetry workload during every benchmark.
6. Keep the 600-second timeout unless the API contract changes first.

Measure at least:

- CPU use and throttling;
- memory, PIDs, and file descriptors;
- request count, errors, and latency;
- PostgreSQL connections and query time;
- Redis delay and evictions;
- Envoy provider delay and errors; and
- Alloy queue, refusal, and drop counters.

A larger LiteLLM limit is a failure if it causes host memory pressure, slow
databases, lost telemetry, or container restarts.

If you test more workers in one container, set the worker count on purpose.
Do not rely on an image default. Count database connections with this formula:

```text
total LiteLLM database connections =
  pool limit per worker x workers per container x containers
```

Leave separate PostgreSQL room for Keycloak, key-rotator, Grafana reads,
backup, migration, and recovery. A connection pooler would be a new reviewed
service. It is not a way to skip connection planning.

## Future multi-replica design

This section is a design only. It is not implemented.

A safe multi-replica profile needs:

1. Named replicas with stable addresses.
2. The same image, model config, keys, limits, and security rules on every
   replica.
3. One static, socket-free load balancer in front of the replicas.
4. Active `/health/readiness` checks.
5. One controlled database migration job.
6. A drain step before an old replica stops.

The load balancer must use an Ansible-made static file. It must not read the
Docker socket or discover containers from labels.

The six current consumers would call the stable load balancer name. The load
balancer would send requests only to ready replicas. Sticky sessions should
not be needed because authorization, budgets, and spend live in PostgreSQL and
cache coordination lives in Redis.

Replicas would share only the networks they need:

- one new private LiteLLM backend network;
- the provider network to Envoy;
- the LiteLLM database network;
- the cache network; and
- the telemetry network.

Replicas would not join user or admin edge networks. The load balancer would
join the exact edge networks needed by the six consumers.

### Database migration and drain

Run the schema migration once, before application replicas start. Disable
automatic migration in the replicas. Two replicas must never race a schema
change.

A rolling update must follow this order:

```text
start replacement
  -> wait for readiness
  -> add it to traffic
  -> remove old replica from new traffic
  -> wait for in-flight calls and streams
  -> stop old replica
```

At least two ready replicas must stay available during the roll. The drain
window must be longer than the approved longest request or stream.

### Shared state

All replicas must use the same `LITELLM_SALT_KEY` and `LITELLM_MASTER_KEY`.
Changing the salt can make saved credentials unreadable.

All replicas must share PostgreSQL and Redis. Test how fast a new credential,
key deactivation, budget change, or rotation reaches every replica. Do not
assume one successful write updates all caches at once.

The current Redis service is one non-persistent instance. Before it becomes a
required global rate-limit control, define persistence, replication, outage
behavior, and fail-open or fail-closed rules.

Do not enable `allow_requests_on_db_unavailable` without a separate security
decision. It changes readiness and authorization behavior.

## Benchmark plan

Record the exact test inputs:

- image digest and host size;
- worker and replica count;
- database pool settings;
- model and provider;
- request sizes and concurrency;
- prompt-capture setting;
- streaming and non-streaming mix;
- test length; and
- client location.

Use synthetic prompts unless production data is approved.

Run two phases:

1. A `network_mock: true` test measures LiteLLM code overhead. It does not
   prove Envoy, provider, database, key, or telemetry behavior.
2. A full gateway test restores retries, Envoy, PostgreSQL, Redis, virtual
   keys, Alloy, and prompt capture. This is the release-capacity test.

Use the version-matched
[official benchmark method](https://docs.litellm.ai/docs/benchmarks) as an
input, not as a promised result.

Record the `x-litellm-overhead-duration-ms` header. Report its p50, p95, and
p99 values apart from total provider latency. Also report throughput, errors,
timeouts, time to first token, resource use, database delay, Redis delay,
Envoy errors, Alloy loss, and provider rate limits.

## Acceptance rules

A candidate passes only when all of these remain true:

1. Key ownership, project limits, budgets, and admin-path denial work under
   load.
2. Every replica reaches providers only through Envoy.
3. An unready or dead replica leaves traffic within the stated time.
4. A planned drain finishes in-flight normal and streaming requests.
5. Only one schema migration runs.
6. Credential rotation and key deactivation reach every replica in time.
7. PostgreSQL and Redis failures match the written security policy.
8. A second unchanged Ansible converge keeps healthy services in place.

Set pass and fail limits before the test. More requests per second is not a
pass if tail latency, database room, authorization, or telemetry gets worse.

Even this future design would still share one VM, Docker daemon, load balancer,
PostgreSQL, Redis, Envoy, and network path. Real high availability needs more
than one failure domain.
