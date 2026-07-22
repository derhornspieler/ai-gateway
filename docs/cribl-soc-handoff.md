# Cribl telemetry handoff

This page is the handoff between the AI Gateway team and the Cribl team.
Grafana Alloy is the only service that sends telemetry out of the gateway.
It sends every log, metric, and trace that passes the gateway's collection and
secret-removal rules.

Alloy also keeps the local paths working:

- logs go to Loki;
- metrics go to Prometheus; and
- traces go to Cribl because this release has no local trace database.

Cribl is not allowed to bypass Alloy. Services, Prometheus, and Alertmanager
must not connect to Cribl on their own.

Prometheus does send its generated alert state back to Alloy. That is not a
Cribl connection. It is a private mTLS hop on `net-observability`. Alloy is
still the only process that sends data out of the gateway.

Related pages:

- [Observability operations](observability-operations.md)
- [Security model](security-model.md#local-operations-data-and-the-soc-feed)
- [Network security](network-security.md)
- [Container security](docker-security.md)
- [Production deployment](deploy-runbook.md)

## Connection contract

| Item | Required value |
|---|---|
| Sender | Grafana Alloy in the AI Gateway stack |
| Protocol | Native OTLP over gRPC and TLS |
| Destination | `<cribl-worker-ip>:4317` |
| TLS server name | `<cribl-worker-fqdn>` |
| TLS trust | Dedicated, reviewed Cribl CA bundle |
| Minimum TLS version | TLS 1.2 |
| Gateway source address on Docker | Alloy at `172.28.2.2` |
| Source seen by Cribl | Gateway internal-leg host IP |
| Firewall path | One approved Cribl `/32` and one TCP port |
| Cribl retention | Exactly 24 hours |
| Gateway outage buffer | Persistent 2 GiB cap and 24-hour retry window |

Use a literal destination IP. Alloy has no external DNS permission. The TLS
server name is still required and must match a SAN in the Cribl certificate.

The current exporter uses server-authenticated TLS. It does not send a bearer
token or client certificate. If the Cribl team requires either control, stop
the cutover and add it as a tested release change. Never turn off certificate
checks to make the connection work.

## What Alloy sends

Alloy sends three OTLP signal types through one reviewed exporter. Each signal
has its own batch processor before the shared persistent queue.

### Logs

Alloy sends ordinary Docker service logs after credential-shaped values are
removed. The same safe log also goes to local Loki.

Some security sources need a stricter copy:

| Source | Export rule |
|---|---|
| Keycloak authentication events | Rebuild a short record from the reviewed event, realm, client, and user IDs |
| Gateway `AIGW_SECURITY_EVENT` records | Keep only the fields approved for that event class |
| Envoy TLS failures | Keep the selected provider and a fixed failure reason |
| Vault audit file | Keep the raw record local; export only operation, path class, outcome, and HMAC-protected status |
| Upgrade and rollback file | Accept only the exact controller lifecycle schema |

The raw versions of these records do not enter the general log mirror. This
prevents a new or nested field from slipping past the reviewed projection.

The normalized security classes include:

- AI request audit;
- Keycloak login, logout, token, identity-provider, lockout, and impersonation
  success or failure;
- portal authorization and identity changes;
- admin model-catalog and price-version changes;
- LiteLLM per-model limit reservations, denials, and fail-closed results;
- provider rotation and egress trust;
- Vault state and bounded Vault audit metadata; and
- controller upgrade and rollback results.

Model-governance records contain the admin subject, model, approved provider
or usage class, operation ID, and reviewed policy digests. A price record also
contains the committed configured amount, token unit, effective time, source
reference, and SHA-256 hash of the review note. It is built from the saved
backend row. The raw review note, provider invoice, and contract text are not
logged or exported. Per-model limit records contain only the model, project,
fixed control name, result, and bounded reason. The allowed reasons are
`capacity_reserved`, `request_cap_exceeded`,
`minute_quota_exceeded`, `policy_invalid`, and `redis_unavailable`. The
records never contain a prompt, API key, request ID, session ID, header,
requested text, token value, or exception text.

### Metrics

Alloy owns the complete scrape list. Prometheus does not scrape services
directly. Alloy scrapes these ten approved targets:

- both Traefik edges;
- Envoy's read-only Prometheus stats path;
- Keycloak's management metrics path;
- Alloy;
- Grafana;
- Prometheus;
- Alertmanager;
- Loki; and
- node-exporter.

Alloy converts each scrape to OTLP. It sends the same admitted metric points to
local Prometheus and Cribl. It also mirrors safe OTLP metrics sent by internal
applications and the request metrics derived from LiteLLM spans.

Prometheus keeps metrics for up to 30 days or the configured size cap,
whichever limit is reached first. The default cap is 5 GB. Cribl keeps its
copy for 24 hours.

Prometheus creates two metric families for alert lifecycle state: `ALERTS` and
`ALERTS_FOR_STATE`. A separate remote-write queue sends only those two names to
Alloy port `12346`. The hop uses a dedicated client certificate, server
certificate, and target-local CA. The server name is `alloy-alert-state`, and
both sides require TLS 1.3. Prometheus keeps an exact approved alert-name list
and a short label list. Alloy checks the same lists again, adds the deployment
and `alert-state` labels, and sends the result only to the normal Cribl metric
batch. Alloy never writes this branch to Prometheus. This prevents a loop.

Alertmanager sends nothing to Cribl. It continues to group, inhibit,
deduplicate, and resolve alerts locally.

### Traces

Alloy sends sanitized OTLP traces to Cribl. This includes LiteLLM request
traces that pass the authenticated receiver and any ordinary internal trace
that passes the open receiver's source rules.

LiteLLM uses Alloy's private OTLP/HTTP port `4319`. It reads a 64-character
bearer token from a read-only file. Alloy checks that token and adds the source
marker. The ordinary OTLP receiver on ports `4317` and `4318` removes a forged
marker and rejects a trace that claims to be LiteLLM.

Alloy also turns the exact `litellm_request` span into a local request-audit
log. A malformed or unattributed LiteLLM span cannot become that normalized
log. Its sanitized source trace may still be part of the general trace mirror.

There is no local Tempo service in this release. Cribl is the trace
destination. Adding a local trace store requires a separate reviewed change.

## Secret and privacy boundary

"Send everything" means every item Alloy admits after the safety gates. It
does not mean collect or export credentials.

Alloy removes or replaces:

- API keys, authorization values, passwords, and client secrets;
- session values, cookies, access tokens, and refresh tokens;
- JWTs, Vault tokens, unseal or recovery material, and client assertions;
- private-key PEM blocks;
- raw headers, query strings, and network peer fields; and
- nested bodies that cannot be proven safe.

The deployment environment is server-owned. A sender cannot label preprod data
as production. The common security producer, schema, and event-class fields
are also removed from general input and rebuilt only by the reviewed security
projection.

Prompt and completion content is approved high-sensitivity data. Alloy keeps
it only in sanitized LiteLLM telemetry. Credential-shaped values inside those
strings are replaced. Treat the remaining content as sensitive.

A transform error drops the affected external item. It must not send an unsafe
fallback. The local inference request must continue even when telemetry is
dropped or Cribl is unavailable.

## Retention

| Store or buffer | Bound |
|---|---|
| Docker JSON logs | 5 files of 20 MiB per container |
| Local Loki | 7 days |
| Local Prometheus | Up to 30 days or the configured size cap; first limit wins |
| Local traces | No local trace store |
| Alloy to Cribl queue | Persistent 2 GiB cap and 24-hour retry window |
| Cribl destination | Exactly 24 hours, owned by the Cribl team |

The Alloy queue is not an archive. The exporter has no hard per-record queue
TTL. A record can wait behind other data before its retry timer starts. The
byte cap can also cause an earlier drop. Cribl must enforce its own 24-hour
retention even if a delayed batch arrives later.

## Queue, retry, and backpressure

Alloy uses separate log, metric, and trace batches. All three feed one
file-backed, fsync-enabled exporter queue under `alloy_data`.

The queue rules are:

- retry with backoff for up to 24 hours;
- use no more than 2 GiB for serialized queued data;
- survive an Alloy restart;
- use `block_on_overflow=false`; and
- keep local Loki, Prometheus, Grafana, and inference working during an outage.

The non-blocking rule protects the application. If the queue fills, new
telemetry can be lost. Prometheus alerts on send failures, enqueue failures,
and queue use above 80 percent. The alerts stay on the Grafana dashboard. No
Alertmanager or service connects directly to Cribl.

Delivery is at least once. Cribl should deduplicate repeated stable event IDs
where an event class provides one.

## Cribl source setup

The Cribl team owns these steps:

1. Create one source named `aigw-otlp`.
2. Select native OTLP over gRPC.
3. Listen on the approved worker IP and TCP port `4317`.
4. Install a certificate whose SAN matches the agreed server name.
5. Trust only the gateway internal-leg host IP.
6. Enable logs, metrics, and traces on the source.
7. Route the three signals to their approved Cribl datasets.
8. Apply exactly 24-hour retention to every destination.
9. Keep high-sensitivity AI content under the approved SOC access policy.
10. Confirm whether retention uses ingest time or source event time.

Do not add a second gateway source for Prometheus, a service, or Alertmanager.
All outbound telemetry must keep the Alloy TLS and redaction boundary.

## Production configuration

Set these production inventory values:

```yaml
cribl_external_export_enabled: true
cribl_otlp_insecure: false
cribl_otlp_endpoint: "10.20.30.40:4317"
cribl_otlp_server_name: "cribl-worker.example.internal"
cribl_otlp_ca_file: "/etc/ssl/certs/aigw-cribl-ca.pem"
cribl_otlp_ca_pem_file: "/private/controller/path/cribl-ca.pem"
```

Ansible validates the CA file, renders verified TLS, and allows only the exact
Alloy-to-Cribl network tuple. Plaintext is allowed only for the local
`cribl-mock` test sink.

## Verification

Run the local contract checks after any telemetry change:

```bash
bash scripts/validate-compose.sh
python3 -I -m unittest discover -v -s scripts/tests -p 'test_*cribl*.py'
python3 -I -m unittest discover -v -s scripts/tests -p 'test_*telemetry*.py'
python3 -I -m unittest discover -v -s scripts/tests -p 'test_*prometheus*.py'
```

The exact offline-seed preprod deployment runs:

```bash
python3 -I scripts/test-preprod-cribl-security.py --image-mode seed
```

A green live receipt must prove:

- verified TLS and server-name checks;
- one admitted log, metric, and trace at the mock;
- one live test alert firing and resolving through Prometheus, Alertmanager,
  the Grafana dashboard query, and the filtered Alloy path;
- one ordinary Docker log at the mock;
- normalized Keycloak, portal, Vault, egress, and controller events;
- credential strings are absent or replaced;
- a forged LiteLLM source is rejected;
- all three signal queues grow during an outage;
- the queues survive an Alloy restart and drain after recovery; and
- local Loki, Prometheus, and Grafana stay healthy.

The local mock does not prove the customer firewall, customer PKI, Cribl
routes, or 24-hour destination retention. Record those checks during the
approved production connection window.

## Outage test

1. Confirm all three Cribl queue sizes are zero.
2. Stop the test receiver or block its exact endpoint.
3. Send a fixture that creates a log, metric, and trace.
4. Confirm all three queue signals become non-zero.
5. Restart Alloy while the receiver is still unavailable.
6. Confirm queued data remains and inference still works.
7. Restore the receiver.
8. Confirm all three signals arrive and the queue drains.
9. Check Grafana for send, enqueue, or saturation alerts.

Never wait 24 hours in the normal test suite. Use the bounded queue and retry
path to prove the behavior.

## Ownership and troubleshooting

| Area | Owner |
|---|---|
| Collection, redaction, batching, and queue | AI Gateway team |
| Cribl listener, routes, datasets, searches, and 24-hour retention | Cribl/SOC team |
| Server certificate, CA review, renewal, and SAN | PKI team |
| `/32` route and TCP 4317 on both sides | Network team |
| Prompt-content access and data classification | Security/data owner |

Troubleshoot in this order:

1. Check Alloy readiness and exporter counters in Grafana.
2. Check each signal's queue size and failure counters.
3. Check the gateway firewall counters.
4. Check TCP reachability to the one approved IP and port.
5. Check certificate time, chain, SAN, and configured server name.
6. Check the Cribl source, route, and destination.
7. Compare a missing record with the committed source and redaction rules.

Do not widen the firewall, disable TLS checks, or bypass Alloy to make a test
pass. Change the reviewed contract, tests, and release together.
