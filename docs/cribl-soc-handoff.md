# Cribl SOC logging handoff

This page is the handoff between the AI Gateway team and the Cribl/SOC team.
It defines the only records that may leave the gateway through Cribl.

The Cribl feed is a small security-event feed. It is not a copy of the local
observability stack. Metrics, raw traces, and ordinary service logs must stay
local.

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
class.

### 2. Authentication and authorization events

Classes: `keycloak_event`, `aigw.portal.audit`, and `aigw.identity.audit`

This class includes structured security events, not all Keycloak or portal
logs. Allowed actions are:

- authentication success and failure;
- logout and token-exchange success or failure;
- account lockout;
- an authorization denial;
- a privileged identity change; and
- a break-glass account action.

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

### 3. Provider and Envoy trust events

Event: `aigw.egress.trust`

Allowed records are:

- Envoy startup-gate success or failure;
- provider-policy acceptance or rejection;
- CA fingerprint, expiration, SAN, or SNI validation failure; and
- upstream TLS handshake failure tied to a selected provider.

A startup record must carry the immutable policy digest, selected provider
names, reviewed CA SHA-256 fingerprints, and final Envoy image ID. It must not
carry certificate private material or an arbitrary upstream hostname.

Today the structured marker path admits only the `startup_gate` action shown
below. The other trust failures remain design requirements until a reviewed
emitter and receipt test exist. Do not claim that they reach Cribl yet.

### 4. Key, Vault, directory, and security-gate events

The reviewed contract also requires these structured security events:

Allowed records are:

- provider-key rotation start, success, failure, or rollback;
- Vault seal, unseal, and selected audit outcomes;
- break-glass activation, use, disable, or cleanup;
- LDAP or managed-identity drift and reconcile failure;
- an identity security-gate failure.

This is not permission to ship the raw Vault audit file or all key-rotator
logs. Each record needs a reviewed structured event name and field allow-list.
Some events in this section do not have a structured producer yet. Keep that
release gate open until source and receipt tests prove each one. Controller-side
Ansible output is not collected by Alloy today. Do not claim that a
controller-only gate reached Cribl unless a separate reviewed sender exists.

### Current structured marker allow-list

Gateway services prefix a reviewed JSON record with `AIGW_SECURITY_EVENT`.
Alloy accepts only these exact pairs:

| `event` | Allowed `action` values |
|---|---|
| `aigw.portal.audit` | `key.generate`, `key.deactivate`, `egress.trust.verify`, `rotation.settings.update`, `rotation.trigger`, `provider.anthropic.configure`, `provider.anthropic.disable`, `provider.anthropic.delete`, `identity.member.remove`, `identity.group.policy`, `admin.key.block`, `admin.key.unblock`, `admin.key.limits` |
| `aigw.identity.audit` | `bootstrap`, `deployment_converge`, `group_policy_update`, `group_create`, `group_delete`, `group_member_add`, `group_member_remove` |
| `aigw.egress.trust` | `startup_gate` |

Allowed outcomes are `success`, `failure`, `failed`, `mismatch`,
`denied-active-key`, and `denied-membership`. A service/event mismatch, an
unknown action, or an unknown outcome is dropped.

## Signals that must never reach Cribl

The exporter must have no metrics input and no traces input. It must also
reject ordinary logs from:

- LiteLLM runtime, Traefik, Open WebUI, and oauth2-proxy;
- ordinary portal and key-rotator logs outside their reviewed event marker;
- Keycloak outside the reviewed security-event allow-list;
- Envoy outside the reviewed trust-event allow-list;
- Vault raw audit output;
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
| event class | `ai_request_audit`, `keycloak_event`, or one reviewed `event` value |
| `event` | Reviewed structured-event name, not free text; not used for the request or Keycloak class |
| `outcome` | Exact reviewed value when the class has an outcome |
| `service.name` | Reviewed producer name |
| event time | UTC source timestamp |
| `deployment.environment` | `preprod` or the production inventory name |

Add only the fields needed for that event class. Missing required fields must
drop the outbound copy and raise a local counter. Do not forward an unparsed
line as a fallback.

One fail-closed Alloy transform adds the common schema attribute immediately
before the only Cribl batch. A producer may also carry `schema_version=1` in
its JSON body, but the OTLP attribute above is the machine contract.

Alloy must remove these values before the allow-list check:

- authorization headers, API keys, access tokens, refresh tokens, and cookies;
- passwords, LDAP bind credentials, client secrets, and Vault tokens;
- Vault unseal shares, private keys, and recovery material;
- raw HTTP headers, query strings, redirect URIs, and OIDC codes;
- e-mail addresses and network peer addresses; and
- nested maps that cannot be proven safe.

Use stable opaque IDs when possible. `aigw.user.name` is readable attribution,
not proof of authorization. Certificate fingerprints, image IDs, and policy
digests are integrity metadata and are safe to export.

The AI request dataset is the one exception for approved prompt and completion
content. Credential redaction still applies inside those fields.

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

Do not use the in-stack `cribl-mock` settings for production. The mock is
plaintext and disposable.

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

Run this test first against `cribl-mock` in local seeded preprod. Repeat the
wire, TLS, firewall, and receipt checks against the real Cribl source during an
approved production window.

1. Send one mock AI request with a unique request ID.
2. Perform one successful Keycloak login, one failed login, and one logout.
3. Trigger one safe Envoy policy-gate event.
4. Trigger one approved security-control canary.
5. Confirm that Cribl received each allowed record once or with a documented
   at-least-once duplicate.
6. Confirm the required fields and redactions.
7. Generate a portal log, a Vault audit line, an OTLP metric, and a raw span.
8. Prove that Cribl received none of those denied signals.
9. Confirm Loki and Prometheus still received their local data.
10. Save the source configuration, route configuration, 24-hour retention
    proof, search results, source commit, and image manifest with the release
    evidence.

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
