# Cribl SOC logging handoff

This page is the handoff between the AI Gateway team and the Cribl/SOC team.
It defines the only records that may leave the gateway through Cribl.

The Cribl feed is a small security-event feed. It is not a copy of the local
observability stack. Metrics, raw traces, and ordinary service logs must stay
local.

Alloy sends only reviewed fields. For structured service events, it reads the
approved scalar values and builds a new record. It never forwards the source
JSON. Unknown fields, nested objects, and raw JSON stay on the gateway.

> **Release gate:** Do not enable a real Cribl endpoint until automated tests
> prove this allow-list. A healthy TLS connection does not prove the data scope.

> **Queue-age limit:** Alloy has a 24-hour retry window but no hard per-record
> queue TTL. If the data owner requires proof that no queued record can exceed
> 24 hours before delivery, production cutover remains blocked until the
> exporter can enforce and test that rule.

Related pages:

- [Observability operations](observability-operations.md)
- [Security model](security-model.md#local-operations-data-and-the-soc-feed)
- [Network security](network-security.md)
- [Container security](docker-security.md)
- [Architecture diagrams](architecture-diagrams.md#9-telemetry-and-soc-log-flow)
- [Production deployment](deploy-runbook.md)

## One-page connection contract

| Item | Required value |
|---|---|
| Sender | Grafana Alloy in the AI Gateway stack |
| Wire protocol | Native OTLP over gRPC and TLS |
| Destination | `<cribl-worker-ip>:4317` |
| TLS server name | `<cribl-worker-fqdn>` |
| TLS trust | Dedicated reviewed Cribl CA bundle |
| Minimum TLS version | TLS 1.2 |
| Client certificate | Not supported by the current gateway exporter |
| Bearer token | Not supported by the current gateway exporter |
| Gateway source on the Docker bridge | Alloy at `172.28.2.2` |
| Source seen on the physical network | The gateway internal-leg host IP |
| Host path | Internal NIC only, to one approved Cribl `/32` and TCP port |
| Cribl retention | 24 hours |
| Gateway outage buffer | Persistent 2 GiB cap; 24-hour retry window after dequeue; no hard per-record age limit |

The endpoint uses a literal IP because Alloy has no permission to query an
external DNS resolver. The separate server name must match a SAN in the Cribl
server certificate.

The current gateway supports server-authenticated TLS. It does not send a
client certificate or bearer token. If the Cribl team requires mTLS or a token,
stop the cutover. Add and test that feature first.

That rule describes the external Alloy-to-Cribl link. LiteLLM uses a separate
internal bearer token when it sends audit traces to Alloy. The internal token
is never sent to Cribl.

## Exact outbound scope

Every outbound record must be an OTLP **log** record in one of the classes
below. Alloy must drop everything else before the Cribl exporter.

### 1. AI request audit

Class: `aigw.security.event_class=ai_request_audit`

Alloy converts the exact LiteLLM `litellm_request` span into one structured log
record. The original span must not leave the gateway. The record may contain:

- request time, duration, outcome, and request ID;
- stable user, key, and project identifiers;
- the readable attribution name, which is not an authorization input;
- requested and returned model names;
- token counts, cost, finish reason, and streaming status; and
- prompt and completion content.

Prompt and completion content is high-sensitivity data. It is allowed only in
this dataset. It must not appear in runtime logs, metrics, or another SOC event
class. For the four reviewed string prompt and completion attributes, Alloy
redacts six narrow value shapes:

- named credentials, including session material, Vault recovery material, and
  client assertions;
- Bearer and Basic authorization values;
- `sk-` and `sk-ant-` vendor keys;
- three-part JWT values;
- Vault `hvs.`, `hvb.`, and `hvr.` tokens; and
- complete or cut-off private-key PEM blocks.

A non-string or nested prompt value is removed before spanlogs can copy it into
Loki or Cribl. The filter is not recursive and does not use a broad
high-entropy guess. Treat all prompt content as sensitive even after these
patterns run.

The stable user, key, and project values come from reviewed server-owned
sources. For a portal or direct API key, the authenticated key supplies the
subject. For Open WebUI, the signed assertion subject supplies the stable
per-user ID. A separate reviewed callback selects the readable name. AI
request export fails closed unless the bounded user ID, readable name, name
source, key hash, project ID, and request ID are all present.

#### How the readable name is selected

The callback accepts only these name sources:

| `aigw.user.name_source` | Required proof | Readable value |
|---|---|---|
| `portal_key_metadata` | A portal-owned key with exact `created_via=dev-portal` metadata and no service-key marker | Bounded portal username |
| `open_webui_signed_oidc` | The exact Open WebUI service key and a valid, short-lived HS256 assertion signed by Open WebUI | Signed username or e-mail; `@` is allowed |
| `key_subject` | A bounded subject on the authenticated key | Key subject |

The Open WebUI key check uses its exact owner, alias, and service metadata. Its
alias identifies that one reviewed service key; an alias is never copied into
the readable-name field. The signed assertion must use the reviewed issuer,
required claims, and a lifetime of no more than five minutes. Its subject is
the stable human audit ID. Its signed username or e-mail is the readable name.
The shared LiteLLM key remains service authorization evidence only.

A request body, plain forwarded identity header, caller end-user field, and
arbitrary key alias can never supply the readable name. Alloy copies the
server-selected name and source, then removes the raw server fields, assertion,
headers, end-user fields, alias, and LiteLLM authentication metadata. An
unresolved or malformed name is dropped.

`aigw.user.name` is attribution, not authorization. Key and OIDC checks decide
access before this record is created. Open WebUI still uses one shared service
key in the LiteLLM spend ledger, even though its signed assertion adds a
per-browser-user name to this request-audit record.

#### How Alloy proves the LiteLLM source

LiteLLM does not use Alloy's ordinary OTLP receiver for audit traces. Its
reviewed callback reads one 64-character token from a read-only secret file and
sends traces to Alloy's internal OTLP/HTTP port 4319 with a bearer header. The
token is not stored in Compose environment data, command arguments, LiteLLM
settings, or logs.

Alloy checks the token before it adds
`aigw.security.source_authenticated=litellm_bearer_v1`. The AI request filter
requires that server-owned marker. The ordinary OTLP receiver on ports 4317
and 4318 deletes any caller-supplied marker and rejects a trace that claims
`service.name=litellm`. A peer cannot turn its own field into source proof.

Port 4319 uses HTTP only on the private telemetry network and is not published
on the host. This internal bearer check proves which workload sent the trace.
It is not a replacement for TLS on the external Cribl link.

Production Ansible creates the token once as a fixed-shape, read-only file. A
state restore may leave that safe file owned by `root:root`. Current source
validates the file and token first, then restores the exact reader group and
mode. Commit `c5c1e50` added the authenticated receiver. Commit `33c79e5`
completed the restore repair.

### 2. Authentication and authorization events

Classes: `keycloak_event`, `aigw.portal.audit`, and `aigw.identity.audit`

This class includes structured security events, not all Keycloak or portal
logs. The current implementation exports the Keycloak events listed below,
reviewed portal actions, authorization denials, identity changes, managed
identity checks, and the break-glass lifecycle.

For Keycloak, accept records only from the `org.keycloak.events` category. The
exact `EventType` success/error pairs are:

- `LOGIN`, `LOGOUT`, `CODE_TO_TOKEN`, `CLIENT_LOGIN`, and `REFRESH_TOKEN`;
- `IDENTITY_PROVIDER_LOGIN`, `IDENTITY_PROVIDER_FIRST_LOGIN`, and
  `IDENTITY_PROVIDER_POST_LOGIN`;
- `USER_DISABLED_BY_TEMPORARY_LOCKOUT` and
  `USER_DISABLED_BY_PERMANENT_LOCKOUT`; and
- `IMPERSONATE`.

Each name also includes its matching `_ERROR` name. No other Keycloak event is
allowed. Keycloak admin events, profile changes, registration events, and
ordinary server logs stay local.

Keycloak 26 writes these event lines with quoted values. The parser accepts the
exact quoted form and does not turn off Keycloak's log sanitization. A local
source-mode preprod run has received natural `LOGIN`, `LOGIN_ERROR`, and
`LOGOUT` events from the real Keycloak container. The final exact-seed receipt
is still pending.

### 3. Provider and Envoy trust events

Event: `aigw.egress.trust`

Allowed records are:

- Envoy startup-gate success or failure;
- provider-policy acceptance or rejection;
- CA fingerprint, expiration, SAN, or SNI validation failure; and
- upstream TLS handshake failure tied to a selected provider.

A successful startup record is Anthropic-only in the current release. It must
carry the immutable policy digest, `anthropic` provider name,
`api.anthropic.com` SNI, the exact `api.anthropic.com` SAN, and both reviewed CA
SHA-256 fingerprints. A startup failure carries only a reviewed failure reason.
An upstream TLS failure carries only the selected provider and the fixed
`tls_transport_failure` reason. Raw TLS errors and arbitrary hostnames stay
local.

The startup event does not contain the final Envoy image ID. An image cannot
safely embed its own final content ID. Release evidence gets the expected ID
from the verified schema-v2 manifest and compares it with the running
container's image ID from live Docker inspection. The policy digest joins that
image evidence to the startup event. Do not claim the image ID was
self-embedded in the event.

### 4. Key, Vault, directory, and security-gate events

The current implementation exports:

- provider-rotation start, attempt, terminal result, and recovery events;
- Vault state changes: `sealed`, `unsealed`, `uninitialized`, or `unavailable`;
- bounded metadata derived from selected Vault audit records; and
- identity deployment, bootstrap cleanup, break-glass, LDAP drift, and managed
  identity drift events.

One provider rotation uses one canonical UUIDv4 `rotation_id`. `start` has no
attempt number. `attempt`, terminal `rotate`, and `recovery` use an integer
attempt from 1 through 999. A recovery record means a later rotation succeeded
after a known failure. It does not mean the old credential was restored, and
there is no provider rollback action.

The raw Vault audit record always stays local. The outbound copy contains only
record type, approved operation, a short path class, outcome, and the fact that
the source value was HMAC-protected. It never contains a Vault token, request
body, response body, full path, or raw JSON.

Managed identity has two separate event pairs:

- `managed_identity_change_planned` and `managed_identity_change_applied` mean
  the reviewed desired policy changed; and
- `managed_identity_drift_detected` and `managed_identity_recovery` mean live
  security state moved away from the last verified policy.

The controller writes one pending record to Vault before the first live
mutation. One canonical UUIDv4 follows retries and the terminal event. The
pending record is cleared only after live verification, durable state
verification, and the terminal audit event pass. A malformed pending record or
a changed desired-policy digest stops before another live mutation.

LDAP provider rename also stops before mutation. The only automatic legacy
case is an old blank provider name whose stored provider ID matches the same
live desired-name provider. Any other name or ID change needs a reviewed
migration.

### 5. Controller upgrade and rollback events

Class: `controller_lifecycle`

Event: `aigw.controller.lifecycle`

Allowed actions are `upgrade` and `rollback`. Allowed outcomes are `started`,
`success`, and `failed`. One UUIDv4 ties the upgrade and any rollback together.
Each record also contains the release manifest hash, source commit, Envoy image
ID, and egress-policy digest. The target creates the UTC timestamp.

Production does not export Ansible stdout. Ansible calls a fixed root-only
writer on the target. The writer appends only to:

```text
/var/log/ai-gateway-controller/lifecycle.jsonl
/var/log/ai-gateway-controller/lifecycle.jsonl.1
```

The directory is `root:473` mode `0750`. Both files are `root:473` mode `0640`,
single-link regular files, with an 8 MiB limit each. Symlinks, extra file
shapes, bad ownership, bad modes, and oversized files fail closed. Ansible
validates the directory before Compose. Alloy reads it through a read-only
bind. A source rollback preserves this target audit evidence.

Local preprod uses an operator-owned generated fixture at
`compose/secrets/preprod-controller-lifecycle`. It exercises the exact Alloy
file-source parser. It is not a production ownership example. Final clean-room
teardown must remove this generated fixture before it removes release images.

### Current structured marker allow-list

Gateway services prefix a reviewed JSON record with `AIGW_SECURITY_EVENT`.
Alloy accepts only these exact pairs:

| `event` | Allowed `action` values |
|---|---|
| `aigw.portal.audit` | `key.generate`, `key.deactivate`, `egress.trust.verify`, `rotation.settings.update`, `rotation.trigger`, `provider.anthropic.configure`, `provider.anthropic.disable`, `provider.anthropic.delete`, `identity.group.create`, `identity.group.delete`, `identity.member.add`, `identity.member.remove`, `identity.group.policy`, `authorization.role.denied`, `authorization.step_up.required`, `admin.key.block`, `admin.key.unblock`, `admin.key.limits` |
| `aigw.identity.audit` | `bootstrap`, `bootstrap_cleanup`, `break_glass_activate`, `break_glass_disable`, `break_glass_use`, `deployment_converge`, `group_policy_update`, `group_create`, `group_delete`, `group_member_add`, `group_member_remove`, `ldap_check`, `ldap_drift_detected`, `ldap_recovery`, `managed_identity_change_planned`, `managed_identity_change_applied`, `managed_identity_drift_detected`, `managed_identity_recovery` |
| `aigw.provider.rotation` | `start`, `attempt`, `rotate`, `recovery` |
| `aigw.vault.state` | `state_observed` |
| `aigw.egress.trust` | `startup_gate` |

The full checked outcome vocabulary is `intent`, `success`, `failure`,
`failed`, `indeterminate`, `mismatch`, `denied-active-key`,
`denied-membership`, and `denied-ownership`. Each action uses only its reviewed
subset. Identity deployment events use `success` or `failed`. Rotation events
use `success` or `failure`, with the action and status checked together. A
service/event mismatch, unknown action, mismatched outcome, or unknown target
is dropped.

### Fixed-field projection

The marker body is input only. Alloy never uses it as the outbound body. Alloy
checks the emitter, event, action, outcome, and each approved scalar field. It
then builds a new line from this fixed list:

- `subject`, `project`, `group`, `target_subject`, `changed`, `change_kind`,
  `operation_id`, `error_type`, and `ldap_provider`;
- `purpose`, `vendor`, `rotation_id`, `attempt`, `rotation_status`, and `state`;
  and
- `policy_sha256`, `providers`, `sni`, `exact_sans`,
  `ca_sha256_fingerprints`, and `reason`.

Each field has a short format or exact value rule. Required fields depend on
the event. `group` and `target_subject` allow only letters, numbers, dot,
underscore, and hyphen, with a maximum of 128 characters. Group create/delete
requires `group`. Member add/remove requires both `group` and `target_subject`.
A successful member removal also requires its bounded `project`. An unknown
source field or nested source value is ignored and never copied. A missing or
malformed required approved field drops the outbound copy. The original local
log remains available in Loki. There is no raw-JSON fallback.

Keycloak, Envoy TLS, and Vault audit classifiers use the same rule: parse a
known source, keep only approved scalar values, and build a new line. The AI
request path selects an explicit span-field list and never exports the source
span.

## Signals that must never reach Cribl

The exporter must have no metrics input and no traces input. It must also
reject ordinary logs from:

- LiteLLM runtime, Traefik, Open WebUI, and oauth2-proxy;
- ordinary portal and key-rotator logs outside their reviewed event marker;
- Keycloak outside the reviewed security-event allow-list;
- Envoy outside the reviewed trust-event allow-list;
- Vault raw audit output;
- source `AIGW_SECURITY_EVENT` JSON, unknown fields, and nested values;
- Postgres, Redis, Grafana, Prometheus, Loki, Alloy, and node-exporter; and
- the local `cribl-mock` receiver.

Alerts are not SOC log records. Alertmanager payloads, exporter-health alerts,
and resolved-alert notices must never enter Cribl.

Debug exporters are forbidden in production. A Cribl-side route must repeat
the same class/event allow-list as a second check. The gateway-side Alloy
filter is still the main security boundary.

## Field and redaction contract

Every record must contain:

| Field | Rule |
|---|---|
| `aigw.security.schema_version` | Integer `1` on every outbound OTLP log |
| `aigw.security.event_class` | `ai_request_audit`, `keycloak_event`, `egress_tls`, `vault_audit`, `security_event`, or `controller_lifecycle` |
| `event` | Reviewed structured-event name, not free text; not used for the request or Keycloak class |
| `outcome` | Exact reviewed value when the class has an outcome |
| `aigw.security.producer` | Server-selected producer from the table below |
| `service.name` | Must exactly match `aigw.security.producer` |
| OTLP log time | Real UTC source timestamp; not zero, over 24 hours old, or over one minute in the future |
| `deployment.environment` | Exact `preprod` or `production` value |

Add only the fields needed for that event class. Missing required fields must
drop the outbound copy and raise a local counter. Do not forward an unparsed
line as a fallback.

Alloy selects the producer from the reviewed event class:

| Event class or structured source | Producer and `service.name` |
|---|---|
| AI request audit | `litellm` |
| Keycloak event | `keycloak` |
| Envoy TLS event | `envoy-egress` |
| Vault audit event | `vault` |
| Structured security event | Exact source service: `dev-portal`, `admin-portal`, `key-rotator`, or `envoy-egress` |
| Controller lifecycle file source | `controller` |

One fail-closed Alloy path removes caller versions of the common fields and
adds the server-owned schema, environment, producer, and service immediately
before the only Cribl batch. A producer may also carry `schema_version=1` in
its JSON body, but the OTLP attribute above is the machine contract. The time
gate runs before queue entry. Time spent waiting in the queue is governed by
the separate queue rules.

Alloy must remove these values before the allow-list check:

- authorization headers, API keys, access tokens, refresh tokens, and cookies;
- passwords, LDAP bind credentials, client secrets, and Vault tokens;
- Vault unseal shares, private keys, and recovery material;
- raw JWTs, signed Open WebUI assertions, HTTP headers, query strings,
  redirect URIs, and OIDC codes;
- caller end-user values, key aliases, and raw LiteLLM authentication metadata;
- e-mail addresses and network peer addresses, except the reviewed signed
  Open WebUI username or e-mail selected as `aigw.user.name`; and
- nested maps that cannot be proven safe.

Use stable opaque IDs when possible. `aigw.user.name` is readable attribution,
not proof of authorization. Certificate fingerprints and policy digests are
safe integrity metadata. The Envoy image ID stays in the verified release and
live-inspection evidence; it is not added to the startup event.

The AI request dataset is the one exception for approved prompt and completion
content. The redactor covers the six narrow value shapes listed above and
removes non-string or nested prompt values because it cannot prove them safe.
It cannot recognize every secret a person could place in plain text. Treat the
remaining content as sensitive.

## Remaining deployment and data gaps

The in-stack contract is implemented. These items still need an external trust
boundary:

1. The customer Cribl address, certificate, route, and exact 24-hour retention
   setting must be tested at the real endpoint.
2. Alloy has no hard per-record queue age. If policy requires that bound, keep
   production export blocked until the sender or Cribl route can enforce it.

Track these remaining items in [TASKS.md](../TASKS.md).

## What stays local

Alloy keeps the local routes separate from the Cribl route:

| Data | Local path | Retention or behavior |
|---|---|---|
| Service and security logs | Alloy to Loki | 7 days |
| AI request audit | Alloy to Loki as `service_name="aigw-requests"` | 7 days |
| Service and host metrics | Prometheus | 30 days and 5 GB; the first limit reached wins |
| Dashboards | Grafana reads Loki, Prometheus, and LiteLLM spend data | Grafana is not a retention store |
| Alerts | Prometheus evaluates rules today; local Alertmanager and the Grafana lifecycle view remain backlog work | No external notification receiver in the approved design |
| Raw traces | No local trace store | Never sent to Cribl |

Prometheus currently has a 5 GB byte cap. A `30d` time setting alone is not
proof that 30 days will fit. Record actual disk growth and leave headroom for
compaction and incident spikes. Change the reviewed Compose release if the cap
is too small.

Current local rules cover sustained exporter send failure, enqueue loss, and
queue use above 80 percent. They also protect the local Loki, Prometheus, and
filesystem paths. A reliable per-record queue-age signal does not exist.
Local Alertmanager grouping and the Grafana firing/resolved lifecycle view
remain backlog work. The approved design has no e-mail, Slack, Teams, webhook,
or Cribl alert receiver.

## Cribl source setup

The Cribl team owns these steps. Cribl's current source page calls this an
[OpenTelemetry source](https://docs.cribl.io/stream/sources-otel/).

1. Create one source named `aigw-soc-otlp`.
2. Select OTLP over gRPC.
3. Listen on TCP `4317` on the approved worker address.
4. Install a server certificate whose SAN contains
   `<cribl-worker-fqdn>`.
5. Install the complete server chain. Send the issuing CA bundle to the gateway
   PKI owner through the approved channel.
6. Restrict the listener to the gateway internal-leg host IP.
7. Route only the reviewed class and structured-event pairs on this page.
8. Drop and alert on a metric, trace, unknown dataset, or malformed record.
9. Send accepted records to a destination with exactly 24 hours of retention.
10. Confirm whether retention is measured from Cribl ingest time or the source
    event time. If policy is based on event age, add and test a Cribl-side drop
    for records that already exceed that age.
11. Give the gateway team the worker IP, port, server name, CA fingerprint,
    route name, destination name, and retention proof.

Do not use the in-stack `cribl-mock` settings for production. The mock uses a
generated local TLS certificate and is disposable. Do not reuse its test CA,
certificate, key, or endpoint in production.

## Gateway inventory

Set these values in the generated production inventory:

```yaml
cribl_external_export_enabled: true
cribl_otlp_endpoint: "<cribl-worker-ip>:4317"
cribl_otlp_insecure: false
cribl_otlp_server_name: "<cribl-worker-fqdn>"
cribl_otlp_ca_file: "/etc/ssl/certs/aigw-cribl-ca.pem"
cribl_otlp_ca_pem_file: "/secure/controller/path/cribl-ca.pem"
cribl_otlp_allowed_cidr: "<cribl-worker-ip>/32"
cribl_otlp_allowed_port: 4317
```

The CA file is controller-local input. Ansible validates it and installs the
dedicated bundle. Do not reuse the edge CA or an LDAP CA.

## Firewall path

The approved packet path is:

```text
Alloy 172.28.2.2
  -> net-internal bridge
  -> gateway internal NIC
  -> one Cribl worker /32, TCP 4317
```

`DOCKER-USER` and the independent `aigw_guard` nftables table both enforce the
container source, destination, port, and physical interface. No whole subnet is
allowed. The Cribl side should allow the gateway internal-leg host IP only.

## Queue, retry, and backpressure

The Cribl exporter uses a persistent file-backed queue in `alloy_data`. The
queue survives an Alloy restart. Delivery is at least once, so the SOC must be
able to handle a duplicate record ID.

The buffer is not an archive. Its byte use and retry work are bounded:

- retry with backoff during a temporary outage;
- retry a failed batch for no more than 24 hours after it is dequeued;
- stop retrying and count a drop when that batch reaches the retry limit;
- cap bytes so an outage cannot fill the gateway disk; and
- keep `block_on_overflow=false` so Cribl cannot stop inference.

Alloy does not provide a per-record queue TTL. A record waiting behind other
work can therefore be older than 24 hours before its batch is dequeued. The 2
GiB cap may also drop records before 24 hours during a high-volume outage. Do
not describe this as a hard 24-hour queue-age control. Cribl's separate
destination retention must still be exactly 24 hours.

When the queue fills, the gateway drops the new outbound copy. The local Loki
and Prometheus routes must keep working. Local metrics and alerts must record
the loss and recovery. No alert payload is sent to Cribl.

Grafana Alloy documents that a file storage handler makes an exporter queue
persistent. It also documents that retry duration and queue size are separate
limits. See the official
[Alloy OTLP exporter](https://grafana.com/docs/alloy/latest/reference/components/otelcol/otelcol.exporter.otlp/)
and [file storage](https://grafana.com/docs/alloy/latest/reference/components/otelcol/otelcol.storage.file/)
pages.

## Receipt validation

Run the automated check first against `cribl-mock` in local seeded preprod:

```bash
python3 -I scripts/test-preprod-cribl-security.py --image-mode seed
```

Know what this test proves:

- Most Docker-log records for portal, identity, provider rotation, Vault state,
  Envoy startup, and Envoy TLS failure are synthetic fixtures. They prove the
  Alloy classifiers, fixed-field projection, allow-list, and deny rules. They
  do not prove that every live producer emitted every event.
- A source-mode preprod receipt uses real Keycloak container logs for one
  successful login, one failed login, and one logout. It proves the natural
  quoted Keycloak 26 event form. Repeat it through the exact release seed
  before release approval.
- The controller fixture enters through the exact read-only file source and
  fixed parser. It is operator-owned generated preprod state, not a copy of the
  root-owned production boundary. Clean-room teardown must remove it before
  release images.
- The fixtures cover bounded portal and identity targets, the complete rotation
  lifecycle, mismatched outcomes, an unknown field, and a nested secret. The
  test proves that malformed or unapproved values did not reach the mock.
- The AI request test uses Alloy's bearer-authenticated LiteLLM receiver,
  filter, batch, and queue. Its input is a test span, but it follows the natural
  OTLP path. The test also proves that the ordinary receiver cannot forge the
  source marker and that port 4319 rejects a missing or wrong token. This
  receipt covers the portal and key-subject sources, caller spoof attempts, and
  an unresolved name. Callback tests cover the signed Open WebUI subject as the
  stable user ID, its signed username or e-mail as the readable name, and the
  shared key as service authorization evidence only.
- Every accepted fixture must arrive with schema version 1, the exact
  environment, a matching producer and service, and its real UTC event time.
  Zero, stale, and future times are negative tests.
- The Vault audit check reads the real Vault audit file path. It does not place
  a fake Vault record in the Docker-log fixture.

Producer unit and contract tests cover the current emitters. The final
current-candidate receipt is still pending the exact seeded run. Add a natural
producer receipt test for every new event family.

Repeat these checks against the real Cribl source during an approved production
window:

1. Send one real approved AI request with a unique request ID.
2. Perform one successful Keycloak login, one failed login, and one logout.
3. Capture one authorization denial and one portal identity change. Check the
   bounded actor, group, and target subject.
4. Capture identity drift detection and recovery, each stage of one provider
   rotation, and one Vault state change. Correlate the rotation with its UUID.
5. Capture one controller upgrade lifecycle. If a rollback test is approved,
   prove the same operation UUID joins upgrade failure and rollback result.
6. Capture one safe Envoy startup record and, in a bounded test, one TLS
   failure record.
7. Correlate the startup policy digest with the Envoy image ID in the verified
   manifest and the live Docker inspection result.
8. Confirm that Cribl received each allowed record once or with a documented
   at-least-once duplicate.
9. Confirm every common field, readable name source, target, and fixed event
   field. Search for rejected unknown, nested, raw, spoofed, and secret values
   and prove they are absent.
10. Generate an OTLP metric, a raw span, and an ordinary service log. Prove that
   Cribl received none of them.
11. Confirm Loki and Prometheus still received their local data.
12. Save the source configuration, route configuration, 24-hour retention
    proof, search results, source commit, manifest, and live image inspection
    with the release evidence.

A source health check or non-zero record count is not enough. The evidence must
show allowed records and prove the denied records are absent.

## Failure and restore test

1. Record the current queue size and exporter counters.
2. Block the Cribl destination or stop the test receiver.
3. Generate unique allowed events for at least two retry intervals.
4. Confirm the queue grows and the local stores stay healthy.
5. Restart Alloy and confirm the persistent queue remains.
6. Restore the receiver.
7. Confirm queued records arrive and exporter metrics return to healthy. After
   the Alertmanager backlog is implemented, also confirm the alert resolves.
8. Confirm there is no metric, raw trace, or unapproved log in the recovered
   batch.
9. Test the byte cap and a shortened exporter retry window in a bounded test
   profile. Confirm a local alert and exact drop count. Record that this does
   not prove a hard per-record age limit.

Never wait 24 hours in the normal test suite. Use a test-only short limit that
exercises the same code path.

## Ownership and troubleshooting

| Area | Owner |
|---|---|
| Event producers, Alloy filters, schema, redaction, queue | AI Gateway team |
| Listener, Cribl route, destination, 24-hour retention, SOC searches | Cribl/SOC team |
| Server certificate, CA review, renewal, SAN | PKI team |
| `/32` routes and both sides of TCP 4317 | Network team |
| Event classification and prompt-content approval | Security/data owner |
| Keycloak event meaning and allow-list | Identity team |

Troubleshoot in this order:

1. Check Alloy readiness and exporter counters locally.
2. Check queue growth and drops.
3. Check both gateway firewall counters.
4. Check TCP reachability to the one approved IP and port.
5. Check certificate time, chain, SAN, and configured server name.
6. Check the Cribl source, route, and destination.
7. Compare the rejected record with the committed field contract.

Do not weaken TLS, widen the firewall, or bypass the dataset filter to make a
test pass. Change the reviewed contract, tests, and release together.
