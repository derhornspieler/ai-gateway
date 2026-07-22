# Security model

AI Gateway follows one main rule: traffic should cross only the boundaries it
needs. Each boundary has its own check. One failed layer does not turn off the
others.

Use these pages for exact details:

- [Solution map](solution-map.md).
- [Technical diagrams](architecture-diagrams.md).
- [Network rules](network-security.md).
- [Container security](docker-security.md).
- [Rocky Linux host security](os-security.md).
- [Provider onboarding](provider-onboarding.md).
- [Cribl SOC handoff](cribl-soc-handoff.md).
- [Model lifecycle SOP](sop/model-lifecycle.md).
- [Usage and cost accounting](usage-and-cost-accounting.md).

## What the system protects

The protected data includes:

- Prompts and model replies.
- User identity, projects, and gateway keys.
- Provider credentials and signing keys.
- Database, Vault, and audit state.
- Model policy, price history, and prompt-free usage records.
- Rules that limit provider network access.

Production runs on one customer-owned Rocky Linux 9 VM. It is a hardened
single-host design, not a high-availability design.

Local preprod runs on a local Docker engine. It tests application behavior. It
does not prove production firewall, SELinux, disk encryption, or the real
Cribl destination settings.

## Main trust boundaries

| Boundary | Allowed traffic | Main checks |
| --- | --- | --- |
| Internal user to gateway | HTTPS chat and approved API routes | Exact host, Traefik path list, OIDC role or gateway key |
| Admin to gateway | SSH and HTTPS admin tools | VPN range, ADM path, admin role, and fresh login for writes |
| One service plane to another | Reviewed service calls only | Small Docker networks and two packet filters |
| Gateway to provider | Selected requests through Envoy only | Fixed Envoy IP, exact route, SNI, SAN, and CA bundle |
| Gateway to Cribl | Every log, metric, and trace admitted by Alloy | Alloy filter, redaction, one address and port, verified TLS |
| LiteLLM to Alloy | AI request audit spans only | Private port 4319, file-backed bearer token, and Alloy-owned source marker |
| LiteLLM to usage ledger | Prompt-free result event only | Separate private token, one route, strict event shape, and idempotent ID |
| Admin to model and price policy | Reviewed catalog and price changes only | Admin role, CSRF, recent login, provider receipt, and append-only records |
| Open WebUI to LiteLLM | Chat with a trusted audit name | Exact workload-key markers and one short-lived signed user assertion |
| Controller to VM | Ansible work and protected input | Key-only SSH, ADM source rule, pipelining, and secrets on stdin |
| Target lifecycle files to Alloy | Upgrade and rollback audit only | Root-owned two-file boundary, fixed writer, read-only mount, and common Cribl gate |

## Layers of defense

1. The egress connection has no listener. ADM and internal accept only the
   approved sources and ports.
2. `DOCKER-USER` and `aigw_guard` deny unsafe container traffic.
3. Each service joins only the Docker networks it needs.
4. Keycloak roles protect browser apps. Gateway keys carry project and model
   limits.
5. Vault stores provider and signing secrets. File secrets have narrow owners
   and modes.
6. Containers run with small users, capabilities, filesystems, and resource
   limits.
7. SELinux separates normal containers and private mounts.
8. Image digests and the schema-v2 seed tie code, provider policy, and Envoy
   image ID into one release.

See the [layered security diagram](architecture-diagrams.md#8-security-design--layered-enforcement).

Open WebUI is a chat-only service in this design. Its `aigw2` image has a
read-only root filesystem, no remote Chroma client path, and no local embedding
or retrieval work. Unused local ML and document-conversion packages are
removed. Required state stays in its named data volume, and temporary files
stay in a bounded `tmpfs`. See
[container security](docker-security.md#open-webui-chat-only-image) for the
exact image and vulnerability-review rules.

Ansible also reconciles the exact Open WebUI workload key. Open WebUI signs a
short-lived assertion for the logged-in directory user. LiteLLM checks the
signature and the full service-key marker set before it sends a model request.
The signed subject becomes the stable per-user audit ID. The signed username or
e-mail becomes the readable audit name and may contain `@`. The shared key
proves service authorization only. A missing, duplicate, malformed, changed,
or expired assertion stops the request. Plain caller headers are not trusted
audit identity.

## Developer keys are shown once

The developer portal shows a new gateway key only in the response that creates
it. The server does not store the plaintext key for later display. The browser
also removes the whole key panel as soon as the user changes the portal tab,
submits a form, follows a link, or leaves the page. Normal link navigation
replaces the secret-bearing history entry. A restored browser-history page
checks both its history marker and its navigation type before it can show the
panel. Using Back or Forward must never show the key again.

The response uses `Cache-Control: no-store`. Plaintext values are cleared
before the page can enter the browser's back-forward cache. These browser
controls reduce accidental redisplay; they do not replace the operator rule to
copy the key once, store it in an approved secret store, and revoke it when it
is no longer needed.

## Model and price policy is append-only

The admin portal accepts a model provider only from the loaded Envoy policy
receipt. It never accepts a provider hostname, route, CA file, or credential.
Model and price writes need the admin role, CSRF protection, and a recent
Keycloak login.

The rotator database keeps immutable model, lifecycle, price, and prompt-free
usage records. A separate no-login role owns the schema. key-rotator can append
checked evidence, but it cannot update, delete, truncate, or disable the row
guards. It fails readiness if the managed LiteLLM model copy has an unexpected
or changed row.

A project may set two output controls for each allowed model: a maximum for
one request and a quota for one fixed UTC minute. The pre-call gate checks the
request cap and reserves minute capacity with one atomic Redis operation before
provider dispatch. A Redis error denies the controlled request with HTTP 503;
there is no process-local fallback. If Redis restarts during a minute, the gate
denies controlled calls until the next minute. The reservation uses the full
requested maximum and is not refunded during that minute. This release does
not claim rolling windows, monthly quotas, per-user limits, or money budgets.

The LiteLLM usage callback has a separate private token for one route. Its
event has no prompt, reply, API key, or request header. Exact replays return the
saved result; a changed replay is a conflict. Grafana reads only reviewed
views through a read-only login. The current source supports backdated prices
through a stored preview, immutable row digest, fresh admin confirmation, and
append-only adjustments. Production activation still waits for the exact-seed
PreProd and rollback gates.

## Provider egress is selected at release time

LiteLLM and key-rotator cannot call a provider directly. They call Envoy over
the private vendor network. Envoy starts TLS to the provider.

The release operator selects names from a committed provider catalog.
Anthropic is the only approved provider in this release. The CLI accepts no
arbitrary hostname or CA path.

Each catalog record pins:

- Provider name and API hostname.
- Route prefix.
- SNI and exact SAN names.
- Reviewed CA bundle.
- CA certificate fingerprints.
- Review and provenance evidence.

The final Envoy image contains only the selected routes and CA files. It has no
catch-all provider route and no system trust fallback. Ansible deploys this
image. It never downloads provider CA files during deploy.

Changing the provider set or CA evidence creates a new policy digest and image
ID. The offline manifest records both. The Envoy startup gate checks the same
evidence before it serves traffic.

These diagrams show the release flow:

- [Provider selection and build](architecture-diagrams.md#11-provider-selection-and-immutable-envoy-build).
- [Runtime provider request](architecture-diagrams.md#12-runtime-request-path-for-selected-providers).
- [CA review and rotation](architecture-diagrams.md#13-ca-capture-review-rotation-and-approval).
- [Seed deploy and rollback](architecture-diagrams.md#14-offline-seed-validation-deployment-and-rollback).

## The CA stores are not interchangeable

The project uses separate CA stores for separate jobs.

| Trust job | Where it lives | How it changes |
| --- | --- | --- |
| Provider TLS | Inside the selected Envoy image | Catalog review, new build, and new offline release |
| Cribl TLS | Dedicated public CA file for Alloy | Production inventory and Ansible converge |
| Directory LDAPS | Dedicated public CA file for Keycloak | Directory inventory and Ansible converge |
| Gateway HTTPS | Customer chain and private key on the host | Customer PKI ceremony |
| Local preprod | Local test Root CA | New preprod preparation |

Do not reuse one bundle for another job. A Cribl, LDAPS, or edge CA file is not
provider trust.

## Local PreProd credentials

PreProd keeps fixed test usernames, but its passwords are private. The first
Ansible preparation creates a random 256-bit seed at
`compose/secrets/preprod-credential-seed-v1`. The file is ignored by Git and
uses mode `0600`.

The PreProd helper uses HMAC-SHA-256 and a different label for each password,
token, and client secret. The same seed makes the same values after a local
destroy and redeploy. A different controller seed makes different values.
Production never reads this seed.

If the seed is missing while the PreProd project still has containers or
volumes, preparation fails. Destroy the local project before rotating the
seed. See [Private test users](preprod.md#private-test-users).

## What CA evidence proves

These terms answer different questions:

- **Integrity:** Does the certificate still have the reviewed bytes? A SHA-256
  fingerprint helps answer this.
- **Provenance:** Where did the certificate come from, and who checked it? A
  review record answers this. A hash alone does not.
- **CA country:** What country appears in the CA subject?
- **Endpoint location:** Where did one server IP appear to be at one time?
- **Data residency:** Where does the provider process or store customer data?
  This needs policy, contract, and audit proof.

A matching hash, `C=US`, or one IP lookup does not prove United States data
residency. Follow the [CA maintenance SOP](sop/provider-ca-maintenance.md).

## Local operations data and the SOC feed

Local operations and the SOC feed have different purposes.

| Signal | Local gateway | Cribl SOC |
| --- | --- | --- |
| Admitted service logs | Loki, 7 days | Yes, after redaction |
| AI request audit | Loki, 7 days | Yes, as a sanitized log and trace |
| Keycloak auth and access events | Loki | Yes, with a fixed field projection |
| Provider trust and policy failures | Loki | Yes, with a fixed field projection |
| Controller upgrade and rollback | Target audit files, then Loki | Yes, with a fixed field projection |
| Admitted metrics | Prometheus, up to 30 days or the configured size cap | Yes |
| Alert state | Prometheus, Alertmanager, and Grafana | Yes, through the private filtered Alloy feedback path |
| Admitted traces | No local trace store | Yes |
| Raw Vault audit file | Loki | No; only a fixed safe projection is exported |

Alloy is the only export gate. It sends every log, metric, and trace that passes
the collection and secret-removal rules. Security-sensitive logs also pass a
fixed field projection so a new field cannot leak by accident. A common gate
adds the server-owned schema, environment, producer, matching service name,
and time check before queue entry. The firewall permits only one Cribl address
and port. TLS checks the server name and CA. All controls must pass.

Prometheus is the only alert evaluator. It returns only `ALERTS` and
`ALERTS_FOR_STATE` to Alloy over dedicated mutual TLS. The client and server
use a target-local CA that signs no other identity. Exact metric-name,
alert-name, and label allow-lists run before Cribl export. This branch never
returns to local Prometheus, so it cannot form a telemetry loop. If a generated
alert has no target, Prometheus adds fixed `job` and `instance` labels only for
this export. It does not replace labels from a real target. Alertmanager does
not connect to Cribl.

The local disk queue is capped at 2 GiB. A failed batch retries for up to 24
hours after dequeue. Alloy does not give each waiting record a hard 24-hour
age limit. The Cribl destination must enforce its own exact 24-hour retention.

See the [Cribl queue and back-pressure rules](cribl-soc-handoff.md#queue-retry-and-backpressure).

## Important limits

- One VM failure stops the gateway.
- Local preprod cannot prove production host rules.
- The customer supplies and unlocks LUKS storage. Ansible warns if it is
  missing; it does not create it.
- Vault seals after a restart until the approved unseal path succeeds.
- Provider CA drift has no early automatic monitor. A provider chain change
  may break TLS until a reviewed release is ready.
- Prompt and reply logs are high-sensitivity data. Access, retention, and disk
  space are security controls.
- LiteLLM's internal telemetry token proves the source of an AI audit span. It
  stays in a read-only file and never enters the external Cribl record.
- Cribl uses server-authenticated TLS today. Required mTLS or bearer auth needs
  a reviewed change.
- Prometheus evaluates local alert rules. Private Alertmanager groups and
  inhibits alerts and records resolved state. Grafana is the operator-facing
  alert UI; Alertmanager has no public port or FQDN.

## Short glossary

- **CA:** A system or organization that signs TLS certificates.
- **Immutable:** Replaced with a new complete artifact instead of edited while
  running.
- **OIDC:** The browser login protocol used with Keycloak.
- **SNI:** The server name Envoy sends at the start of TLS.
- **SAN:** A DNS name a server certificate may cover.
- **OTLP:** The OpenTelemetry format used for logs, metrics, and traces.
- **TTL:** A hard age limit after which data must be removed or rejected.
- **mTLS:** TLS where both the client and server show a certificate.

See [project status](project-status.md) and the
[engineering backlog](backlog.md) for current open work.
