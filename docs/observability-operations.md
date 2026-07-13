# Observability and Sensitive-Telemetry Operations

This is the operational contract for the local Grafana stack and the optional
Cribl export. It is intentionally explicit because AI prompt capture changes
the data-classification, capacity, and recovery requirements of an otherwise
ordinary telemetry pipeline.

## Data paths and boundaries

| Data | Source and path | Local destination | External copy |
|---|---|---|---|
| AI request/response content | LiteLLM emits OpenTelemetry spans with `OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=SPAN_ONLY`; Alloy accepts OTLP only on its fixed `net-telemetry` address | **Tempo** | Cribl OTLP |
| Other application OTLP | LiteLLM and instrumented custom services → Alloy | traces: Tempo; logs: Loki; metrics: Prometheus | original OTLP signals → Cribl |
| Container stdout/stderr | bounded Docker `json-file` files → Alloy read-only file tail (no Docker socket) | **Loki** | Cribl OTLP logs, except Alloy and the mock sink to prevent feedback |
| Vault audit | Vault HMAC-protected audit file → dedicated read-only Alloy mount | Loki | Cribl OTLP logs |
| Service/host metrics | Prometheus scrapes isolated service endpoints and node-exporter; Alloy derives bounded `spanmetrics` from AI spans | **Prometheus** | Cribl receives source OTLP, not node-exporter or locally derived spanmetrics series |

Full prompts and completions are deliberately retained as **trace attributes in
Tempo and Cribl**, not as Loki log records. Do not add a debug exporter or log
span bodies to stdout: that would create an uncontrolled second prompt store.
Before trace batching, Alloy promotes validated server-authenticated LiteLLM
metadata on `litellm_request` spans into `aigw.user.id`, `aigw.api_key.id`,
`aigw.api_key.alias`, `aigw.project.id`, and `aigw.request.id`. The project is
extracted from LiteLLM's stringified key-auth metadata only when it matches the
portal's `^[a-z0-9][a-z0-9_.-]{0,63}$` contract; the key ID must be exactly 64
lowercase hexadecimal characters. `aigw.request.id` copies the stable
`litellm.call_id`; Alloy does not manufacture `gen_ai.request.id`. Raw
authorization/token values and client-supplied `llm.user` are never promoted.
Missing or malformed optional fields leave a trace intact and uncorrelated;
intrinsic UTC timestamps, trace/span IDs, and `gen_ai.input.messages` are not
rewritten. These fields remain trace attributes and are excluded from metric
dimensions to prevent user-controlled cardinality growth.

LiteLLM spend rows are a separate cost/accounting index, not the prompt audit
store. `general_settings.store_prompts_in_spend_logs` is pinned to `false`, so
`messages`, `response`, and `proxy_server_request` remain empty objects while
prompt/completion content stays in the controlled Tempo/Cribl trace path. The
portal's project is namespaced key metadata, not a native LiteLLM project: a
correct spend correlation joins `LiteLLM_SpendLogs.api_key` (the SHA-256 key
identifier) to `LiteLLM_VerificationToken.token` and reads
`metadata.aigw_project_id`. Zero rows in `LiteLLM_ProjectTable` is therefore
expected and must not be reported as missing project attribution. Never enable
spend-log prompt storage merely to make this join self-contained; that creates
a second sensitive-content store with a different retention/access boundary.

Open WebUI is an explicit attribution exception. Its one shared scoped key is
owned by `svc-open-webui`, so its spans can prove the originating service and
project but not the human browser user. An upstream/client `llm.user` value is
untrusted and is not promoted to `aigw.user.id`. Do not present Open WebUI
traces as per-person audit evidence until a server-side, identity-bound
propagation design has been implemented and adversarially tested. Portal-
issued direct API keys continue to provide per-human owner attribution.

The container-log pipeline heuristically redacts credential-shaped fields and
`sk-*` values, but this is defense in depth, not a substitute for applications
never logging secrets. User-controlled key aliases are excluded from
Prometheus labels to prevent cardinality exhaustion.

Alloy's uid 473 receives traversal only (`--x`) on the configured Docker data
root, `r-x` plus the reviewed default traversal entry on its `containers`
root, `r-x` only on immediate Docker container directories, and `r--` on
`*-json.log*`. The authoritative host reconciler places an explicit
`u:473:---` deny on every other regular sibling, including `config.v2.json`,
`hostconfig.json`, and `resolv.conf.hash`; this prevents world-readable Docker
files from bypassing the named-user boundary. The only non-log exceptions are
the running Alloy container's own non-secret `hosts`, `hostname`, and
`resolv.conf`, which remain `r--` so its uid 473 process can resolve required
peers.

Current source verifies without mutating the Docker-root traversal entry,
repairs the `containers` root before walking bounded children, fails if Docker
enumeration fails, removes inherited default entries from container
directories, and limits the systemd unit's write boundary to the containers
subtree. It runs immediately during converge, again after Compose, and every
15 seconds for rotation. Do not use a recursive `setfacl -x u:473` migration:
it also deletes the intended log ACLs and creates a telemetry collection gap.
Do not grant broad Docker-root read/write to compensate for a missing parent
entry.

On a pristine target, the deployed render validator has no controller-side
Ansible tree from which to inspect this boundary. The role therefore installs
the exact non-secret ACL helper and its hardened oneshot unit before invoking
`scripts/validate-compose.sh`; it does **not** enable the 15-second timer or run
the helper until the later Docker-directory ACL setup is complete. The local
validator asserts this task ordering as a regression gate and, in deployed
layout, inspects the exact helper/unit bytes that will execute. Moving
validation before artifact installation makes a pristine deployment fail on a
missing helper; moving activation before directory preparation risks an
incorrect or incomplete ACL application.

The replacement VM's first controlled reboot proved the then-live timer did
not restore the recreated `containers`-root ACL; a later Ansible converge did.
The parent-first reconciler described above has passed focused source tests but
has not yet completed the controlled live deploy and Docker-restart proof. Log
continuity after that restart is PENDING even though the earlier durable-state
comparison passed.

Both Traefik edges emit JSON access records with request headers, query
parameters, `RequestPath`, and the path-bearing `RequestLine` disabled. This
prevents OIDC authorization codes and logout `id_token_hint` JWTs from being
copied from Docker logs into Loki and Cribl. Method, vhost, router/service,
status, byte counts, timing, and TLS fields remain available. The deliberate
tradeoff is that an access record cannot identify the requested path; use
application audit events or a short, reviewed packet capture for path-specific
diagnosis, and never temporarily re-enable path logging on live authentication
traffic. The portal also disables Uvicorn's redundant request access log,
because it includes the full OIDC callback URI; explicit structured portal
audit events remain enabled.

All local backends have no application authentication and no published host
ports. They are reachable only on segmented Docker bridges. The ADM Grafana
vhost is therefore the supported query path:

1. Traefik accepts it only on the ADM interface.
2. `oauth2-proxy-grafana` requires the Keycloak `aigw-admins` role.
3. Grafana then requires its local administrator login; anonymous access and
   sign-up are disabled.

This double login is deliberate defense in depth for prompt-bearing data. The
Grafana, Prometheus, Loki, Tempo, and Alloy APIs must not be published directly.

## Retention, limits, and outage behavior

| Store/buffer | Enforced bound |
|---|---|
| Docker stdout/stderr | 5 files × 20 MiB per container (about 100 MiB maximum per service instance) |
| Loki | 30 days; compactor deletion enabled with a 2-hour delete delay |
| Tempo | 30 days; 8 MiB maximum attribute, 16 MiB maximum trace, 10 MiB/s steady and 16 MiB burst ingestion limits |
| Prometheus | 15 days and 5 GB by default; the first limit reached wins |
| Alloy process | 384 MiB memory limiter plus 64 MiB spike allowance inside a 512 MiB container limit |
| Alloy → Tempo | 32 MiB in-memory queue; retries for at most 1 minute |
| Alloy → Cribl | 64 MiB in-memory queue; retries for at most 5 minutes |

The two OTLP exporter queues are intentionally byte-bounded and
`block_on_overflow=false`. After the retry window or when a queue fills, that
destination loses new telemetry instead of exhausting the VM. The local and
Cribl branches are separate, so a short Cribl outage does not directly stop a
healthy local store; sustained collector pressure can still make the shared
OTLP receiver reject work, and SDK retry behavior then determines upstream
loss. Alloy file positions and the Prometheus remote-write WAL persist in
`alloy_data`; OTLP exporter queues do **not** survive an Alloy restart. Alert on
exporter send failures, queue capacity, receiver refusals, and host disk usage.

Cribl retention is a customer-side policy and is not controlled here. A real
Cribl target must use `host:port` (no URL scheme),
`cribl_otlp_insecure: false`, the issuing CA file, the expected TLS server name,
TLS 1.2 or newer, and certificate verification. The host firewall permits only
the fixed Alloy internal address to the explicitly enabled Cribl destination
CIDR (prefer `/32`) and port. The current exporter does not attach a bearer
token or client certificate; use a network-restricted TLS listener, or extend
the deployment with the customer's required Cribl authentication before
cutover. Plaintext is allowed only for the in-stack `cribl-mock` target.
Ansible renders these as mutually exclusive Alloy client blocks: the mock gets
only `tls { insecure = true }`, while a real target gets `insecure = false`, a
CA file, server name, verification enabled, and minimum TLS 1.2. Do not retain
TLS-only fields in the plaintext block; Alloy 1.17.1 otherwise attempts a TLS
handshake against the mock.

Prometheus evaluates three host-filesystem rules from node-exporter: below 15%
free for 10 minutes, below 5% for 5 minutes, and predicted exhaustion within
24 hours. They are visible through Prometheus/Grafana, but the stack does not
deploy Alertmanager or any notification receiver. Treat rule evaluation
without delivery as an incomplete paging control.

## Capacity planning

The 40 GB lab disk is suitable only for low-volume testing. It is not a
production sizing recommendation when full prompts are retained for 30 days.
Measure representative traffic, then size the encrypted Docker data volume as:

```text
(daily Tempo bytes + daily Loki bytes) × 30 days × 2 headroom
+ Prometheus, Postgres, Vault, images, and up to ~100 MiB × container instances
```

Prompt/tool payload size dominates Tempo growth. Record daily growth with
`docker system df -v` and `du` against Docker's volume root for at least a week,
then tune warning/critical thresholds to the measured recovery time. The
committed rules alert at 85% and 95% used, plus predicted exhaustion within 24
hours. Generic/customer Ansible requires both the Docker data root and stack
directory to have a `crypto_LUKS` ancestor; it does not create or unlock that
storage. A full filesystem is a gateway availability failure, not merely an
observability failure.

## Backup and recovery

State lives in the named volumes `tempo_data`, `loki_data`, `prom_data`,
`grafana_data`, `alloy_data`, and `vault_audit`. They are single-node local
stores with no replication. `scripts/state-backup.sh` quiesces the complete
writer set and includes these volumes in one age-encrypted artifact along with
Postgres logical dumps, exact project volumes, Vault, and rendered
configuration. It refuses same-filesystem output outside an exact disposable
lab override. Keep the customer's Cribl archive policy independent and prove
the artifact with `state-restore.sh` on an isolated target; copying live files
is not a consistent backup.

The Vault audit file has a separate 15-minute systemd rotation check. It
rotates at 100 MiB and retains 14 compressed files by default after asking
Vault to reopen its active file. This bounds that one source but does not
replace an evidence archive, timer-failure alert, or the backup procedure.

After the destructive restore exits zero, require zero running project
containers and the exact root-only authenticated restore marker. Keep ingress
in maintenance and run the full designated current-source Ansible converge
first; this replaces captured configuration and repairs exact bind ownership
while restored Vault remains sealed. Only then unseal with the separately held
old share, run the complete runtime wait, and verify new logs, traces, and
metrics arrive before reopening access. `vault-bootstrap.sh` is forbidden
while the marker exists. Losing `alloy_data`
can cause file-tail duplicates or gaps around rotated Docker logs. Losing
Tempo/Loki/Prometheus volumes loses local history but should not block inference.

`docker compose down` preserves named volumes. `docker compose down -v`
irreversibly deletes the local telemetry stores, Vault data/audit records, and
application databases; use it only for an explicitly disposable lab.

## Verification

- Run `scripts/validate-compose.sh` after every Compose or environment change.
- Do not accept Grafana's native `/api/health` alone. The full Ansible verify
  role must query the authenticated API from an isolated `net-grafana` probe,
  find exactly the provisioned Prometheus/Loki/Tempo datasource graph, and
  receive `OK` from every datasource health endpoint. This detects an
  unreadable provisioning bind tree that container health cannot see. The
  probe is bounded to 12 attempts with a five-second delay; the password is
  exact stdin with no Ansible-added newline, all task output is `no_log`, and
  the isolated probe container uses no Docker logging.
- After an authentication-flow test, scan both current Traefik Docker logs and
  Loki/Cribl for OAuth `code`, `id_token_hint`, and three-segment JWT shapes.
  Any match is a release blocker. On a disposable lab that previously logged
  those values, stop Alloy and Loki, remove and recreate `loki_data` and
  `alloy_data` (file positions/WAL), clear the development Cribl sink state,
  and then recreate the edges before collecting fresh evidence. Production
  deletion must follow the customer evidence-retention and incident process.
- In Grafana Explore, use **Tempo** to locate a test trace and confirm the
  expected prompt attribute plus the five canonical `aigw.*` correlation
  fields. Confirm the API-key ID equals the source lowercase hash, request ID
  equals `litellm.call_id`, and project matches the portal project. Also send
  missing, malformed, uppercase-hash, overlength/injection-like project, and
  non-LiteLLM spans: they must retain their original trace/timestamps/content,
  gain no invalid canonical attributes, and cause zero transform/export drops.
  Use **Loki** for container and Vault audit logs;
  use **Prometheus** for Envoy TLS, spanmetrics, node-exporter, and the
  `aigw-state-capacity` rule group.
- For an Open WebUI request, require service/project correlation to
  `svc-open-webui` / `open-webui`. Record per-human attribution as **not
  implemented**, and prove a supplied `llm.user` value cannot become a
  canonical trusted user attribute.
- Confirm a user without `aigw-admins` is rejected before Grafana and an admin
  still receives the Grafana local login.
- For a real Cribl cutover, send a non-sensitive canary through each signal,
  verify certificate/SNI validation and the narrow firewall counter, then test
  an endpoint outage long enough to observe bounded queue/drop alerts.

### Current replacement-VM evidence status

The sanitized 2026-07-13 read-only lane proved existing Tempo, Loki,
Prometheus, Alloy, and lab Cribl flow; zero reviewed credential/JWT/OAuth
patterns; healthy Grafana datasources; no collector failures/drops in the
observed window; and 22/22 healthy services with zero restarts. The subsequent
portal lifecycle lane also found zero exact key-plaintext matches in Docker,
Loki, and the lab Cribl sink.

The separate protected evidence
`g6-synthetic-correlation-20260713T084705Z.log` records one non-sensitive
four-span fake batch through Alloy. The valid LiteLLM-shaped span received all
five exact canonical fields; the missing, invalid, and non-LiteLLM spans
received none. Tempo and the lab Cribl sink each received 4/4, spanmetrics
reported four, source IDs/timestamps/tags/harmless prompt were preserved,
drops were zero, queues were empty, and runtime/security state did not drift.
The evidence is mode `0600`, immutable, and has SHA-256
`939132ab7fd5337d6eb24db92554b0364d642baac28e4a00b6993cc2c2e7b3a3`.

That closes collector correlation, not inference correlation. The real canary
received LiteLLM HTTP 401 before Envoy because Anthropic WIF/provider
configuration is not supplied; its Envoy delta and canonical
`litellm_request`/Tempo matches were zero. Real Anthropic exchange, inference,
and derived telemetry are **NOT EXECUTED**. Do not reinterpret the synthetic
batch, existing infrastructure traces, or HTTP 401 as a provider/LiteLLM pass.

The later replacement-host reboot retained observability volumes and passed
the durable semantic comparison after one stdin-only Vault unseal. It also
removed the parent Docker-log ACL until Ansible reapplied it, so it is not a
passing log-tail restart test. The remediated ACL timer must still prove the
exact parent/child boundary and zero unexpected collector loss across the final
controlled Docker-daemon restart. That same pending source converge must enable
Docker SELinux integration, confine the ordinary graph under MCS labels, retain
Alloy as one of only two bounded disabled-label readers, and prove its bind/
ACL access without any converge-window AVC. These are source assertions until
the G7 receipts record them on the replacement VM.
