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

## What the system protects

The protected data includes:

- Prompts and model replies.
- User identity, projects, and gateway keys.
- Provider credentials and signing keys.
- Database, Vault, and audit state.
- Rules that limit provider network access.

Production runs on one customer-owned Rocky Linux 9 VM. It is a hardened
single-host design, not a high-availability design.

Local preprod runs on a local Docker engine. It tests application behavior. It
does not prove production firewall, SELinux, disk encryption, or Cribl rules.

## Main trust boundaries

| Boundary | Allowed traffic | Main checks |
| --- | --- | --- |
| Internal user to gateway | HTTPS chat and approved API routes | Exact host, Traefik path list, OIDC role or gateway key |
| Admin to gateway | SSH and HTTPS admin tools | VPN range, ADM path, admin role, and fresh login for writes |
| One service plane to another | Reviewed service calls only | Small Docker networks and two packet filters |
| Gateway to provider | Selected requests through Envoy only | Fixed Envoy IP, exact route, SNI, SAN, and CA bundle |
| Gateway to Cribl | Approved SOC log records only | Alloy filter, redaction, one address and port, verified TLS |
| Controller to VM | Ansible work and protected input | Key-only SSH, ADM source rule, pipelining, and secrets on stdin |

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
| Normal service logs | Loki, 7 days | No |
| AI request audit | Loki, 7 days | Yes, after filter and redaction |
| Keycloak auth and access events | Loki | Yes, reviewed fields only |
| Provider trust and policy failures | Loki | Yes, reviewed fields only |
| Metrics | Prometheus, up to 30 days and 5 GB | Never |
| Alert state | Prometheus and Grafana | Never |
| Raw traces | No local trace store | Never |
| Raw Vault audit file | Loki | Never |

Alloy is the export gate. Its data filter permits only reviewed security event
classes. The firewall permits only one Cribl address and port. TLS checks the
server name and CA. All three controls must pass.

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
- Cribl uses server-authenticated TLS today. Required mTLS or bearer auth needs
  a reviewed change.
- Prometheus evaluates local alert rules. Alertmanager grouping, inhibition,
  and resolved-alert handling remain backlog work.

## Short glossary

- **CA:** A system or organization that signs TLS certificates.
- **Immutable:** Replaced with a new complete artifact instead of edited while
  running.
- **OIDC:** The browser login protocol used with Keycloak.
- **SNI:** The server name Envoy sends at the start of TLS.
- **SAN:** A DNS name a server certificate may cover.
- **OTLP:** The OpenTelemetry format used for logs and metrics.
- **TTL:** A hard age limit after which data must be removed or rejected.
- **mTLS:** TLS where both the client and server show a certificate.

See [project status](project-status.md) and the
[engineering backlog](backlog.md) for current open work.
