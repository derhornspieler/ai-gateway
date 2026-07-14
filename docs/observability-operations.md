# Observability and Sensitive-Telemetry Operations

## Telemetry sanitization and scrape scope (enforced in configuration)

Alloy is the sanitization chokepoint: it promotes only server-authenticated
identity into safe span attributes (`aigw.user.id`, `aigw.api_key.id`,
`aigw.project.id`, strictly validated), then strips secret- and
identity-bearing keys from every OTLP signal before batching or export —
authorization and API-key material, raw request headers, cookies,
client/server addresses and ports, query strings, and e-mail addresses.
Telemetry that cannot be sanitized is dropped rather than exported.

Prometheus scrapes only reviewed metrics/observability-plane endpoints (the
two Traefik edges, Envoy's read-only stats facade, Keycloak management,
Alloy, Grafana, Tempo, Loki, node-exporter, and itself); Vault, Postgres,
Redis, and LiteLLM are deliberately not scraped because exposing their
metrics would weaken an authentication boundary. Alert rules live in
Prometheus (`compose/prometheus/rules.yml`), not Grafana.

Grafana is fully provisioned and immutable in the UI: three reviewed
dashboards (overview, live logs, request audit) in the "AI Gateway" folder,
exactly three datasources (Prometheus, Loki, Tempo) with trace/log
cross-linking, no plugin downloads, and no alerting configured in Grafana
itself.

This is the operational contract for the local Grafana stack and the optional
Cribl export. It is explicit because AI prompt capture changes the
data-classification, capacity, and recovery requirements of an otherwise ordinary
telemetry pipeline. It complements the operator guide in
[operations.md](operations.md) and the architecture in
[solution-map.md](solution-map.md).

## Collection and routing

Grafana Alloy is the single collector and router. It accepts OTLP only on its
fixed `net-telemetry` address and fans each signal out to a local store and,
optionally, to Cribl: traces go to Tempo over `net-traces`, logs go to Loki over
`net-observability`, and metrics go to Prometheus over `net-observability`.
Prometheus additionally scrapes isolated service endpoints and, on the separate
`net-metrics` bridge, the node-exporter host metrics; Alloy also derives bounded
`spanmetrics` from AI spans. Grafana reads the provisioned Prometheus, Loki, and
Tempo datasources on `net-observability` and is reached only through
`net-grafana`. Alloy's one `net-internal` leg is the fixed source identity for an
explicitly enabled Cribl export, and the in-stack `cribl-mock` OpenTelemetry
Collector lives on `net-internal` as the development export target.

| Data | Source and path | Local destination | External copy |
|---|---|---|---|
| AI request/response content | LiteLLM emits OTLP spans with `OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=SPAN_ONLY`; Alloy accepts OTLP only on its fixed `net-telemetry` address | Tempo | Cribl OTLP |
| Other application OTLP | LiteLLM and instrumented custom services to Alloy | traces: Tempo; logs: Loki; metrics: Prometheus | original OTLP signals to Cribl |
| Container stdout/stderr | bounded Docker `json-file` files to a read-only Alloy file tail (no Docker socket) | Loki | Cribl OTLP logs, except Alloy and the mock sink to prevent feedback |
| Vault audit | Vault HMAC-protected audit file to a dedicated read-only Alloy mount | Loki | Cribl OTLP logs |
| Service/host metrics | Prometheus scrapes isolated service endpoints and node-exporter; Alloy derives bounded `spanmetrics` from AI spans | Prometheus | Cribl receives source OTLP, not node-exporter or locally derived spanmetrics series |

## Sensitive prompt content

Full prompts and completions are deliberately retained as trace attributes in
Tempo and, when enabled, in Cribl. They are never written as Loki log records and
never become metric labels. Do not add a debug exporter or log span bodies to
stdout: either would create an uncontrolled second prompt store. This is the core
data-classification rule of the deployment, so the Grafana, Prometheus, Loki,
Tempo, and Alloy APIs must not be published directly, and the ADM Grafana vhost is
the only supported query path for prompt-bearing data.

Before trace batching, Alloy promotes validated server-authenticated LiteLLM
metadata on `litellm_request` spans into five canonical correlation attributes:
`aigw.user.id`, `aigw.api_key.id`, `aigw.api_key.alias`, `aigw.project.id`, and
`aigw.request.id`. The key ID copies `user_api_key_hash` and must be exactly 64
lowercase hexadecimal characters; the project is extracted from LiteLLM's
stringified key-auth metadata only when it matches the portal's
`^[a-z0-9][a-z0-9_.-]{0,63}$` contract; and `aigw.request.id` copies the stable
`litellm.call_id`, since Alloy never manufactures `gen_ai.request.id`. Raw
authorization and token values and any client-supplied `llm.user` are never
promoted. Missing or malformed optional fields leave a trace intact and
uncorrelated because the transform runs with `error_mode = ignore`; intrinsic
timestamps, trace and span IDs, and the captured prompt/completion content are
not rewritten. These five fields stay trace attributes and are excluded from
metric dimensions to prevent user-controlled cardinality growth.

LiteLLM spend rows are a separate cost and accounting index, not the prompt audit
store. `general_settings.store_prompts_in_spend_logs` is pinned to `false`, so
`messages`, `response`, and `proxy_server_request` remain empty objects while
prompt content stays in the controlled Tempo/Cribl trace path. Because the
portal's project is namespaced key metadata rather than a native LiteLLM project,
a correct spend correlation joins `LiteLLM_SpendLogs.api_key` (the SHA-256 key
identifier) to `LiteLLM_VerificationToken.token` and reads
`metadata.aigw_project_id`; zero rows in `LiteLLM_ProjectTable` is expected and
must not be reported as missing project attribution. Never enable spend-log
prompt storage to make that join self-contained, since it creates a second
sensitive-content store with a different retention and access boundary.

Open WebUI is an explicit attribution exception. Its one shared scoped key is
owned by `svc-open-webui`, so its spans prove the originating service and project
but not the human browser user, and an upstream or client `llm.user` value is
untrusted and not promoted to `aigw.user.id`. Do not present Open WebUI traces as
per-person audit evidence until a server-side, identity-bound propagation design
has been implemented and adversarially tested; portal-issued direct API keys
continue to provide per-human owner attribution. See
[operations.md](operations.md) for how that shared key is reconciled each
converge.

The container-log pipeline heuristically redacts credential-shaped fields and
`sk-*` values as defense in depth, not as a substitute for applications never
logging secrets, and user-controlled key aliases are excluded from Prometheus
labels to prevent cardinality exhaustion.

## Access-log path suppression

Both Traefik edges emit JSON access records with request headers, query
parameters, `RequestPath`, and the path-bearing `RequestLine` disabled. This
prevents OIDC authorization codes and logout `id_token_hint` JWTs from being
copied out of Docker logs into Loki and Cribl. Method, vhost, router and service,
status, byte counts, timing, and TLS fields remain available. The deliberate
tradeoff is that an access record cannot identify the requested path, so use
application audit events or a short reviewed packet capture for path-specific
diagnosis and never temporarily re-enable path logging on live authentication
traffic. The portal likewise disables Uvicorn's redundant request access log
because it includes the full OIDC callback URI, while its explicit structured
audit events stay enabled.

## Docker-log ACL boundary

Alloy's uid 473 receives traversal only (`--x`) on the configured Docker data
root, `r-x` plus the reviewed default traversal entry on its `containers` root,
`r-x` only on immediate Docker container directories, and `r--` on `*-json.log*`.
The authoritative host reconciler places an explicit `u:473:---` deny on every
other regular sibling, including `config.v2.json`, `hostconfig.json`, and
`resolv.conf.hash`, so world-readable Docker files cannot bypass the named-user
boundary; the only non-log exceptions are the running Alloy container's own
non-secret `hosts`, `hostname`, and `resolv.conf`, which stay `r--` so its process
can resolve peers. Current source verifies without mutating the Docker-root
traversal entry, repairs the `containers` root before walking bounded children,
fails if enumeration fails, removes inherited default entries from container
directories, and limits the systemd unit's write boundary to the containers
subtree. It runs during converge, again after Compose, and every 15 seconds for
rotation. Do not use a recursive `setfacl -x u:473` migration, which also deletes
the intended log ACLs and creates a collection gap, and do not grant broad
Docker-root read or write to compensate for a missing parent entry.

On a pristine target the deployed render validator has no controller-side Ansible
tree to inspect this boundary, so the role installs the exact non-secret ACL
helper and its hardened oneshot unit before invoking
`scripts/validate-compose.sh`, without enabling the 15-second timer or running the
helper until the later Docker-directory ACL setup completes. The replacement VM's
first controlled reboot proved the then-live timer did not restore the recreated
`containers`-root ACL and a later Ansible converge did; the parent-first
reconciler above has passed focused source tests but has not completed the
controlled live deploy and Docker-restart proof, so log continuity across that
restart is PENDING even though the durable-state comparison passed. See
[operations.md](operations.md) for the boot-time ACL check.

## The gated query path

Every local backend has no application authentication and no published host port,
reachable only on segmented Docker bridges. The ADM vhosts are therefore the
supported query paths, and each is double-gated on the ADM interface: Traefik
accepts it only on that interface, an oauth2-proxy instance requires the Keycloak
`aigw-admins` role, and the backend then applies its own contract.
`oauth2-proxy-grafana` fronts Grafana, which additionally requires its local
administrator login with anonymous access and sign-up disabled, and
`oauth2-proxy-prometheus` fronts the Prometheus UI. This layered login is
deliberate defense in depth for prompt-bearing data.

## Retention, limits, and outage behavior

| Store/buffer | Enforced bound |
|---|---|
| Docker stdout/stderr | 5 files x 20 MiB per container (about 100 MiB per service instance) |
| Loki | 30 days; compactor deletion enabled with a 2-hour delete delay |
| Tempo | 30 days; 8 MiB maximum attribute, 16 MiB maximum trace, 10 MiB/s steady and 16 MiB burst ingestion |
| Prometheus | 15 days and 5 GB by default; the first limit reached wins |
| Alloy process | 384 MiB memory limiter plus 64 MiB spike allowance inside a 512 MiB container limit |
| Alloy to Tempo | 32 MiB in-memory queue; retries for at most 1 minute |
| Alloy to Cribl | 64 MiB in-memory queue; retries for at most 5 minutes |

Both OTLP exporter queues are byte-bounded with `block_on_overflow=false`, so
after the retry window or once a queue fills, that destination loses new telemetry
rather than exhausting the VM. The local and Cribl branches are separate, so a
short Cribl outage does not directly stop a healthy local store; sustained
collector pressure can still make the shared OTLP receiver reject work, and SDK
retry behavior then determines upstream loss. Alloy file positions and the
Prometheus remote-write WAL persist in `alloy_data`, but the OTLP exporter queues
do not survive an Alloy restart. Alert on exporter send failures, queue capacity,
receiver refusals, and host disk usage.

Cribl retention is a customer-side policy and is not controlled here. A real Cribl
target must use `host:port` with no URL scheme, `cribl_otlp_insecure: false`, the
issuing CA file, the expected TLS server name, TLS 1.2 or newer, and certificate
verification, and the host firewall permits only the fixed Alloy internal address
to the explicitly enabled Cribl destination CIDR (prefer `/32`) and port. The
current exporter attaches no bearer token or client certificate, so use a
network-restricted TLS listener or extend the deployment with the customer's
required Cribl authentication before cutover. Plaintext is allowed only for the
in-stack `cribl-mock` target. Ansible renders these as mutually exclusive Alloy
client blocks: the mock gets only `tls { insecure = true }`, while a real target
gets `insecure = false`, a CA file, server name, verification enabled, and minimum
TLS 1.2. Do not retain TLS-only fields in the plaintext block, because Alloy
1.17.1 would then attempt a TLS handshake against the mock.

Prometheus evaluates three host-filesystem rules from node-exporter: below 15%
free for 10 minutes, below 5% free for 5 minutes, and predicted exhaustion within
24 hours. They are visible through Prometheus and Grafana, but the stack deploys
no Alertmanager or notification receiver, so treat rule evaluation without
delivery as an incomplete paging control.

## Capacity planning

The 40 GB lab disk is suitable only for low-volume testing and is not a production
sizing recommendation when full prompts are retained for 30 days. Measure
representative traffic, then size the encrypted Docker data volume as roughly:

```text
(daily Tempo bytes + daily Loki bytes) × 30 days × 2 headroom
+ Prometheus, Postgres, Vault, images, and up to ~100 MiB × container instances
```

Prompt and tool payload size dominates Tempo growth. Record daily growth with
`docker system df -v` and `du` against Docker's volume root for at least a week,
then tune the warning and critical thresholds to the measured recovery time; the
committed rules alert at 85% and 95% used plus predicted exhaustion within 24
hours. Generic and customer Ansible require both the Docker data root and the
stack directory to have a `crypto_LUKS` ancestor but do not create or unlock that
storage. A full filesystem is a gateway availability failure, not merely an
observability failure.

## Backup and recovery of telemetry volumes

Telemetry state lives in the named volumes `tempo_data`, `loki_data`,
`prom_data`, `grafana_data`, `alloy_data`, and `vault_audit`. They are single-node
local stores with no replication. `scripts/state-backup.sh` quiesces the complete
writer set and includes these volumes in one age-encrypted artifact alongside
Postgres logical dumps, the exact project volumes, Vault, and rendered
configuration, refusing same-filesystem output outside the exact disposable lab
override. Keep the customer's Cribl archive policy independent and prove the
artifact with `state-restore.sh` on an isolated target, because copying live files
is not a consistent backup. The Vault audit file also has the separate 15-minute
rotation described in [operations.md](operations.md); it bounds that one source
but does not replace an evidence archive, a timer-failure alert, or the backup
procedure.

After a destructive restore exits zero, require zero running project containers
and the exact root-only authenticated restore marker, keep ingress in maintenance
and run the full designated current-source Ansible converge first to replace
captured configuration and repair bind ownership while restored Vault stays
sealed, then unseal with the separately held old share, run the complete runtime
wait, and verify that new logs, traces, and metrics arrive before reopening
access. `vault-bootstrap.sh` is forbidden while the marker exists. Losing
`alloy_data` can cause file-tail duplicates or gaps around rotated Docker logs;
losing the Tempo, Loki, or Prometheus volumes loses local history but should not
block inference. `docker compose down` preserves named volumes, while
`docker compose down -v` irreversibly deletes the local telemetry stores, Vault
data and audit records, and application databases, so use it only for an
explicitly disposable lab.

## Verification

Run `scripts/validate-compose.sh` after every Compose or environment change. Do
not accept Grafana's native `/api/health` alone: the verify role queries the
authenticated API from an isolated `net-grafana` probe, requires exactly the
provisioned Prometheus, Loki, and Tempo datasource graph, and requires `OK` from
every datasource health endpoint, which detects an unreadable provisioning bind
tree that container health cannot see. That probe is bounded to 12 attempts with a
five-second delay, the password is exact stdin with no Ansible-added newline, all
task output is `no_log`, and the probe container uses no Docker logging.

After an authentication-flow test, scan both current Traefik Docker logs and
Loki/Cribl for OAuth `code`, `id_token_hint`, and three-segment JWT shapes; any
match is a release blocker. On a disposable lab that previously logged those
values, stop Alloy and Loki, remove and recreate `loki_data` and `alloy_data`,
clear the development Cribl sink state, and recreate the edges before collecting
fresh evidence, while production deletion must follow the customer evidence and
incident process. In Grafana Explore, use Tempo to locate a test trace and confirm
the expected prompt attribute plus the five canonical `aigw.*` fields, checking
that the API-key ID equals the source lowercase hash, the request ID equals
`litellm.call_id`, and the project matches the portal project; then send missing,
malformed, uppercase-hash, overlength or injection-like project, and non-LiteLLM
spans and confirm they keep their original trace, timestamps, and content, gain no
invalid canonical attributes, and cause zero transform or export drops. Use Loki
for container and Vault audit logs and Prometheus for Envoy TLS, spanmetrics,
node-exporter, and the `aigw-state-capacity` rule group.

For an Open WebUI request, require service and project correlation to
`svc-open-webui` and `open-webui`, record per-human attribution as not
implemented, and prove that a supplied `llm.user` value cannot become a canonical
trusted user attribute. Confirm that a user without `aigw-admins` is rejected
before Grafana and that an admin still receives the Grafana local login. For a
real Cribl cutover, send a non-sensitive canary through each signal, verify
certificate and SNI validation and the narrow firewall counter, then test an
endpoint outage long enough to observe bounded queue and drop alerts.

### Evidence status

The synthetic span-correlation batch is the authoritative collector-correlation
proof. Its protected evidence log records one non-sensitive four-span fake batch
through Alloy: the valid LiteLLM-shaped span received all five exact canonical
fields while the missing, invalid, and non-LiteLLM spans received none; Tempo and
the lab Cribl sink each received four of four; spanmetrics reported four; source
IDs, timestamps, tags, and the harmless prompt were preserved; drops were zero;
queues were empty; and runtime and security state did not drift. The sanitized
read-only lane separately proved existing Tempo, Loki, Prometheus, Alloy, and lab
Cribl flow with zero reviewed credential, JWT, or OAuth patterns, healthy Grafana
datasources, and no collector failures in the observed window.

That closes collector correlation, not inference correlation. The real canary
received LiteLLM HTTP 401 before Envoy because Anthropic WIF and provider
configuration are not supplied, so real Anthropic exchange, inference, and derived
telemetry are NOT EXECUTED; do not reinterpret the synthetic batch, existing
infrastructure traces, or an HTTP 401 as a provider or LiteLLM pass. The later
replacement-host reboot retained the observability volumes and passed the durable
comparison after one stdin-only Vault unseal, but it also removed the parent
Docker-log ACL until Ansible reapplied it, so it is not a passing log-tail restart
test. The remediated ACL timer must still prove the exact parent/child boundary
and zero unexpected collector loss across the final controlled Docker-daemon
restart, and that same pending source converge must enable Docker SELinux
integration, confine the ordinary graph under MCS labels, retain Alloy as one of
only two bounded disabled-label readers, and prove its bind and ACL access with no
converge-window AVC. These remain source assertions until the gate receipts record
them on the replacement VM; the register is [lab-dr-rehearsal.md](archive/lab-dr-rehearsal.md)
and the living status is [project-status.md](project-status.md).
