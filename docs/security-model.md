# Security model

AI Gateway is built on one simple rule: a request should cross only the
boundaries it needs. Each boundary has its own check. A failure in one layer
does not turn off the other layers.

This page is the plain-language security overview. Use these pages for exact
implementation details:

- [Architecture and trust boundaries](solution-map.md)
- [Architecture diagrams](architecture-diagrams.md)
- [Network enforcement](network-security.md)
- [Container security](docker-security.md)
- [Rocky Linux host security](os-security.md)
- [Provider onboarding](provider-onboarding.md)
- [Cribl SOC logging handoff](cribl-soc-handoff.md)

## What the system protects

The main protected data is:

- AI prompts and model replies;
- user identity, project membership, and gateway keys;
- provider credentials and workload-signing keys;
- database, Vault, and audit state; and
- the rules that decide which provider endpoints the gateway may reach.

The current production design runs on one customer-owned Rocky Linux 9 VM.
It is a hardened single-host design, not a high-availability design. Local
preprod runs on a local Docker engine and tests the application flow. It does
not prove Rocky Linux firewall, SELinux, storage-encryption, or production
Cribl behavior.

## Main trust boundaries

| Boundary | What may cross it | Main checks |
|---|---|---|
| Internal users to gateway | HTTPS chat and approved API routes | exact host address, Traefik route allow-list, gateway key or OIDC role |
| Administrators to gateway | SSH and HTTPS admin tools | VPN source range, ADM interface, Keycloak `aigw-admins` role, fresh login for sensitive changes |
| One container plane to another | only the service calls in the reviewed design | separate Docker bridges, fixed memberships, `DOCKER-USER`, and an independent nftables guard |
| Gateway to an AI provider | selected provider requests through Envoy only | fixed Envoy address, reviewed route, exact SNI and SAN, provider-only CA bundle |
| Gateway to Cribl | reviewed security log records only | Alloy allow-list and redaction, one destination IP and port, verified TLS |
| Controller to target VM | Ansible modules and protected input | key-only SSH, source-scoped ADM access, Ansible pipelining, secrets on stdin |

## Layers of defense

1. **Host entry rules.** The egress interface has no listener. The ADM and
   internal interfaces accept only their approved source ranges and ports.
2. **Container packet rules.** Two separate packet filters deny cross-plane,
   container-to-host, and unapproved outbound traffic.
3. **Small network memberships.** A service joins only the Docker networks it
   needs. Fixed addresses used by firewall rules are reserved from automatic
   address assignment.
4. **Identity checks.** Keycloak roles protect browser applications. Gateway
   keys carry project and model limits. Admin changes require stronger checks.
5. **Secret handling.** Durable provider credentials and signing keys live in
   Vault. File-backed secrets use narrow owners and modes. Secrets are not put
   in command arguments.
6. **Container hardening.** Services run without root where possible, drop
   capabilities, use read-only filesystems, and have CPU, memory, PID, and log
   limits.
7. **Host confinement.** SELinux separates containers and their private bind
   mounts. A deployment fails if a new SELinux denial appears.
8. **Release integrity.** Images use immutable digests. The offline manifest
   binds the selected provider policy to the exact Envoy image ID.

See [the layered-enforcement diagram](architecture-diagrams.md#8-security-design--layered-enforcement).

## Provider egress is selected at release time

LiteLLM and key-rotator cannot call an AI provider directly. They send plain
HTTP on the private `net-vendor` bridge to Envoy. Envoy starts TLS to the
provider.

The release operator selects provider names such as `anthropic`. A
network-disabled planner resolves each name through a committed catalog. The
catalog pins the hostname, route prefix, SNI, exact SAN names, CA bundle,
certificate fingerprints, and review record.

The final Envoy image contains only the selected routes and provider CA files.
There is no default route and no system-trust fallback. Ansible deploys that
image; it does not download provider CA files or mount a new provider CA into
the running container.

These provider diagrams show the complete flow:

- [selection and immutable build](architecture-diagrams.md#11-provider-selection-and-immutable-envoy-build);
- [runtime request path](architecture-diagrams.md#12-runtime-request-path-for-selected-providers);
- [CA capture and approval](architecture-diagrams.md#13-ca-capture-review-rotation-and-approval); and
- [seed validation and rollback](architecture-diagrams.md#14-offline-seed-validation-deployment-and-rollback).

## The CA stores are not interchangeable

The project uses several certificate authorities (CAs). Their update paths are
different.

| Trust use | Where trust lives | How it changes |
|---|---|---|
| AI provider TLS | baked into the selected immutable Envoy image | reviewed catalog and provenance change, then a new offline release |
| Cribl server TLS | dedicated public CA file installed for Alloy | production inventory and Ansible converge |
| External directory LDAPS | dedicated public CA file mounted into Keycloak | directory inventory and Ansible converge |
| Gateway edge HTTPS | customer certificate chain and private key on the host | separate PKI ceremony |
| Local preprod | locally generated test Root CA | namespaced preprod preparation only |

Do not reuse one CA bundle for another purpose. In particular, a runtime file
used for Cribl, LDAP, or edge TLS is not the provider trust store.

## What CA evidence proves

These facts sound similar, but they answer different questions:

- **Certificate integrity:** Does this certificate have the reviewed bytes?
  A SHA-256 fingerprint can answer this.
- **Trust provenance:** Where did the certificate come from, and how was it
  checked? A review record answers this. A hash alone does not.
- **CA organization country:** What country is written in the CA subject? This
  describes the CA's organization record.
- **Endpoint geography:** Where did one server IP appear to be for one
  connection? A CDN can change that location.
- **Data residency:** Where does the provider process or store customer data?
  This needs provider policy, contract, and audit evidence.

A matching hash, `C=US`, or one IP lookup does not prove United States data
residency. Follow the [provider CA maintenance procedure](sop/provider-ca-maintenance.md)
for capture, independent review, rotation, and rollback.

## Local operations data and the SOC feed

The local observability path and the Cribl path serve different jobs.

| Signal | Local gateway | Cribl SOC |
|---|---|---|
| Service logs | Loki, 7 days | no, unless an exact security marker is approved |
| AI request audit | Loki, 7 days | yes, after redaction and classification |
| Metrics | Prometheus, up to 30 days and 5 GB | never |
| Alert rule state | Prometheus; local alert lifecycle work is still planned | never |
| Raw traces | no trace store | never |
| Raw Vault audit file | Loki | never |

Alloy is the export gate. It accepts only reviewed event classes, removes
unapproved fields, and sends OTLP logs to one Cribl IP and port over verified
TLS. The firewall limits the network path. The Alloy filter limits the data.
Both are required.

The disk queue is capped at 2 GiB, and a failed export batch is retried for at
most 24 hours after that batch is dequeued. Alloy does not provide a hard
per-record queue TTL. Records waiting behind other work can therefore be older
than 24 hours. Cribl's separate destination retention must still be exactly 24
hours. See the [Cribl handoff](cribl-soc-handoff.md#queue-retry-and-backpressure)
for the release limitation and outage test.

## Important limits

- One VM failure stops the gateway. Backups do not provide high availability.
- Local preprod cannot prove production host controls.
- LUKS storage is supplied by the customer. Ansible checks it and warns when
  sensitive paths are not on LUKS; it does not create or unlock the volume.
- Vault seals after restart until the approved unseal path succeeds.
- Provider CA drift has no automatic pre-failure monitor. A changed provider
  chain can cause Envoy TLS failures until a reviewed release is built.
- Prompts and completions are intentionally sensitive audit data. Retention,
  access, and disk capacity are security controls.
- Cribl currently uses server-authenticated TLS. A required client certificate
  or bearer token needs a reviewed implementation before cutover.
- Alertmanager grouping, inhibition, and resolved-alert display are planned;
  Prometheus evaluates the current local rules today.

## Short glossary

- **CA (certificate authority):** an organization or system that signs TLS
  certificates.
- **Immutable:** replaced as a complete new artifact instead of edited while
  it is running.
- **OIDC (OpenID Connect):** the browser sign-in protocol used with Keycloak.
- **SNI (Server Name Indication):** the server name Envoy sends when it starts
  a TLS connection.
- **SAN (Subject Alternative Name):** a DNS name the server certificate is
  valid for.
- **OTLP:** the OpenTelemetry wire format Alloy uses for logs and metrics.
- **TTL (time to live):** a hard age limit after which a record must be removed
  or rejected.
- **mTLS (mutual TLS):** TLS where both the client and server show a
  certificate.

Current release blockers and deferred work are listed in
[project status](project-status.md) and [the engineering backlog](backlog.md).
