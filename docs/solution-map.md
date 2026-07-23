# AI Gateway solution map

This page explains what runs, where traffic goes, and where trust changes.
It describes the current code in `compose/`, `ansible/`, and `services/`.
It is not a production approval. See [project status](project-status.md) for
open release gates.

Start with these pages when you need more detail:

- [Technical diagrams](architecture-diagrams.md)
- [Security model](security-model.md)
- [Production network rules](network-security.md)
- [Production deploy runbook](deploy-runbook.md)
- [Local preprod](preprod.md)
- [Image update workflow](image-update-workflow.md)
- [Test runbook](test-runbook.md)
- [Model lifecycle SOP](sop/model-lifecycle.md)
- [Usage and cost accounting](usage-and-cost-accounting.md)

## Two deployment types

Production runs one Docker Compose project on an existing Rocky Linux 9 VM.
The customer supplies the VM, three network connections, addresses, gateways,
DNS, and upstream routes. Ansible checks those facts before it changes the
host. It does not create a VM or change customer-owned addresses.

The three production connections have separate jobs:

| Connection | Inbound use | Outbound use |
| --- | --- | --- |
| Egress | No listener | Envoy DNS and provider TCP 443 only |
| ADM | SSH and HTTPS from the approved VPN range | Admin replies |
| Internal | HTTPS from the approved user range | User replies, LDAPS, and optional Cribl export |

Local preprod runs on one local Docker engine. It always uses `aigw.internal`.
It adds a test Root CA, Samba AD over LDAPS, fixed test users, a WIF mock, and
a provider mock. It models egress, ADM, and internal paths with Docker
networks. It does not claim to test Rocky Linux firewall, SELinux, or routing
rules.

## How Ansible deploys production

`ansible/site.yml` is the full production converge. It runs host setup first,
then the application stack:

```text
host_preflight
  -> firewall_preflight
  -> time_sync
  -> selinux_baseline
  -> network_routing
  -> firewalld_zones
  -> os_baseline
  -> docker_networks
  -> docker_stack
  -> verify
  -> host_finalize
```

The order is a security control. Firewall rules must be active before Docker
starts containers. Verification must pass before Ansible marks the host as
ready.

Use these playbooks:

- `ansible/site.yml` runs the full converge.
- `ansible/os-prep.yml` prepares the host but starts no containers.
- `ansible/deploy-stack-only.yml` updates a prepared host. It refuses an
  unknown or stale host.
- `ansible/preprod.yml` manages only the local preprod project.

Production inventory comes from `scripts/bootstrap-rocky9-production.py`.
Keycloak URLs, callback URLs, logout URLs, and trusted origins all come from
the domain in that inventory. There is no user-run portal initialization
step. Ansible sets up Keycloak, LDAPS, clients, roles, and lasting admin
controls when the required inputs are present.

## Running services

The base Compose file defines one short-lived setup job and 24 long-running
services. Two of those services, `vault-ui-proxy` and
`oauth2-proxy-vault`, run only when the `vault-ui` profile is enabled. Optional
platform DNS adds one more service. Local preprod adds four test-only services
and runs 26 long-running containers in its normal profile.

| Service | Job |
| --- | --- |
| `volume-init` | Sets the owner and mode of state volumes, then exits |
| `traefik-int` | Internal HTTPS edge |
| `traefik-adm` | ADM HTTPS edge |
| `oauth2-proxy` | Admin role gate for LiteLLM Admin |
| `oauth2-proxy-grafana` | Admin role gate for Grafana |
| `oauth2-proxy-prometheus` | Admin role gate for Prometheus |
| `oauth2-proxy-vault` | Optional admin role gate for the Vault UI |
| `litellm` | AI API, virtual keys, limits, provider routing, and prompt-free usage callback |
| `open-webui` | Browser chat |
| `keycloak` | Login, roles, OIDC clients, and LDAPS federation |
| `dev-portal` | User key creation and tool examples |
| `admin-portal` | User, project, provider, model, and price controls |
| `vault-ui-proxy` | Optional fixed Vault UI and `/v1` proxy |
| `envoy-egress` | The only provider internet path |
| `key-rotator` | Provider secrets, WIF, identity, model, price, and usage control |
| `vault` | Provider secrets, PKI, key material, and audit data |
| `postgres` | Separate LiteLLM, Keycloak, and rotator databases |
| `redis` | Private, non-persistent LiteLLM cache |
| `alloy` | The only log, metric, and trace collection and Cribl export path |
| `prometheus` | Local metrics and alert rule checks |
| `alertmanager` | Private alert grouping, inhibition, and resolved lifecycle |
| `node-exporter` | Host capacity metrics |
| `loki` | Local operational, audit, and request logs |
| `grafana` | Local dashboards and alert views |
| `cribl-mock` | Local TLS receipt test for admitted logs, metrics, and traces |
| `platform-dns` | Optional split, non-recursive DNS for the domain |

Preprod adds these test-only services:

- `preprod-edge-forwarder` publishes the internal test plane.
- `preprod-edge-forwarder-adm` publishes the admin test plane. Separate
  publishers avoid a Docker Desktop bug that can misroute two loopback ports
  from one container. If Docker Desktop leaves a stale port forward, the test
  may recreate only these two publishers twice. It then tests both TLS routes
  again. Certificate, HTTP, or response errors still stop the deployment.
- `samba-ad` provides the local LDAPS directory.
- `wif-egress-mock` stands in for the provider token path.
- `wif-provider-mock` stands in for the provider control plane.

Every long-running service has a health check. Ansible also tests real routes,
TLS names, login rules, callbacks, database access, and service behavior. A
green container health check alone is not release proof.

## User and admin traffic

Only Traefik publishes application ports in production. It binds to the exact
ADM or internal host address. Nothing binds to the egress address or
`0.0.0.0`.

Internal users can reach:

- `api.<domain>` for approved AI API paths;
- `chat.<domain>` for Open WebUI;
- `portal.<domain>` for user key management; and
- the limited `aigw` realm paths on `auth.<domain>`.

VPN admins can reach:

- `admin.<domain>`;
- `litellm-admin.<domain>`;
- `grafana.<domain>`;
- `prometheus.<domain>`;
- full Keycloak admin paths on `auth.<domain>`; and
- `vault.<domain>` when the optional Vault UI is enabled.

The domain is an Ansible input. The same value builds every Keycloak redirect,
origin, issuer, and logout URL.

## Identity and access

The `aigw` Keycloak realm uses these roles:

| Role | Access |
| --- | --- |
| `aigw-chat` | Open WebUI |
| `aigw-developers` | Developer portal and personal API keys |
| `aigw-admins` | Developer access plus all ADM tools |
| `aigw-users` | Old compatibility role; it no longer gates chat |

Open WebUI API keys are disabled. The developer portal creates LiteLLM virtual
keys for approved users and projects. A new key is shown once. Later pages
show `YOUR_KEY`, not the secret.

Ansible creates or repairs one Open WebUI workload key on every deploy. The
key can list models and send chat requests, but it cannot use LiteLLM
management routes. The key proves which service made the request. Open WebUI
also signs a short-lived assertion with the logged-in directory identity.
LiteLLM rejects an Open WebUI request before provider dispatch when that
assertion is missing, changed, expired, or does not match the exact workload
key. The signed subject becomes the stable per-user audit ID. The signed
username or e-mail becomes the readable name and may contain `@`. This is a
reviewed audit exception, not an authorization rule. Portal-issued keys remain
the trusted per-person API identity for tools.

The admin portal has no manual setup button. Each admin page checks the live
Keycloak role. A write also needs CSRF protection and a fresh Keycloak login.
Ansible keeps one Vault-backed break-glass admin and removes temporary setup
admins only after the lasting controls pass.

When production LDAPS is enabled, Keycloak trusts only the supplied CA bundle
and checks the directory hostname. The bind password is a root-owned file. It
is never a command argument, Compose environment value, or log field.

The identity controller stores a policy digest and any pending repair in
Vault. A planned inventory change emits planned/applied events. Unexpected
live drift emits security-drift/recovery events. One UUID follows a retry until
the terminal event is written and the pending record is cleared. A managed
LDAP provider rename needs a reviewed migration. The only automatic legacy
case is a blank saved name whose saved provider ID matches the same live
provider.

## Docker network boundaries

Ansible creates 20 active bridges in the `172.28.0.0/24` through
`172.28.20.0/24` range. `172.28.16.0/24` is retired and stays reserved. The
base stack uses 18 bridges. The optional DNS overlay uses one more. The last
bridge, `net-identity`, is
used by the local Samba test path. Production LDAPS uses Keycloak's exact
address on `net-internal` and a host firewall rule to the customer directory.

Each bridge has a fixed short name. Fixed IP addresses are part of the
firewall contract. Fifteen bridges are Docker `internal` networks and have no
normal NAT path.

The main groups are:

| Group | Purpose |
| --- | --- |
| Egress, ADM, internal | Host-facing traffic planes |
| Chat, portal, admin, Grafana | User and admin application paths |
| Vendor and Vault | Provider and secret paths |
| Four database networks | One network for each database client |
| Cache | LiteLLM to Redis only |
| Telemetry, metrics, observability | Local logs, metrics, and dashboards |
| Identity | Local Samba test path; production LDAPS uses the internal plane |
| Platform DNS and internal edge | Port publishing with no app peers |

Services on different bridges cannot talk unless they also share a reviewed
bridge. See [production network rules](network-security.md) for the exact
subnets and packet rules.

## Host packet rules

Three layers protect traffic:

1. firewalld protects services on the host.
2. `DOCKER-USER` protects Docker forwarding.
3. `aigw_guard` is a separate nftables guard that stays active during a
   firewalld reload.

The two container filters allow only exact paths. Examples include the Envoy
IP to provider TCP 443, the Keycloak IP to one LDAPS server, and the Alloy IP
to one optional Cribl address and port. Other bridge-to-host, cross-bridge,
and bridge-to-physical traffic is denied.

Source-based route tables send ADM and internal replies back through the same
connection. Ansible sets only the saved NetworkManager firewall zone. It does
not rewrite customer addresses or routes.

## Provider egress and immutable trust

LiteLLM and key-rotator call Envoy over plain HTTP on the private vendor
network. Envoy starts TLS to the selected provider. Anthropic is the only
approved provider in this release.

The release operator selects providers with repeated `--provider` options.
Names must exist in the reviewed catalog. The CLI accepts no arbitrary host or
CA file.

The offline build does these jobs:

1. Check and sort provider names.
2. Generate exact routes, SNI, SAN, and CA rules.
3. Build Envoy with networking disabled.
4. Put only selected provider files in the image.
5. Record providers, CA fingerprints, policy digest, and image ID in the
   schema-v2 seed manifest.

The Envoy startup gate fails on a missing, extra, changed, expired, or broken
CA file. It also fails on policy, SNI, SAN, or config drift. Ansible never
downloads CA trust during deploy.

A certificate hash proves that the reviewed bytes did not change. It does not
prove where the certificate came from. A CA country field does not prove an
endpoint location or data residency. See [provider onboarding](provider-onboarding.md)
and the [CA maintenance SOP](sop/provider-ca-maintenance.md).

Provider secrets live in Vault. Anthropic WIF uses `private_key_jwt`; it has no
shared-secret fallback. Adding another provider needs a reviewed driver,
catalog entry, CA evidence, offline build, and full seed test.

## Data and secrets

PostgreSQL 18 holds separate LiteLLM, Keycloak, and rotator databases. Each
application login can connect only to its database. The rotator database has
append-only model, price, and prompt-free usage records. A separate no-login
role owns that schema, so the application cannot edit or delete old evidence.

The saved model policy is the source of truth. key-rotator checks and repairs
the LiteLLM runtime copy, and it fails readiness on unmanaged or changed model
rows. Public discovery shows only active, visible models allowed for the
caller. An assigned hidden model remains callable only by its exact name.

A project may set a maximum output size per request and a fixed UTC-minute
output quota for each allowed model. LiteLLM checks the request cap and makes
one atomic Redis reservation before provider dispatch. Redis errors deny the
controlled request; the gateway does not fall back to a local counter. These
two controls do not claim rolling windows, monthly limits, per-user limits, or
money budgets.

Grafana's `grafana_ro` login can read only approved reporting views and narrow
LiteLLM spend columns. It cannot read prompt fields. The usage callback sends
no prompt, reply, key, or request header. Missing usage or price data stays
unknown instead of becoming zero. See the [model lifecycle SOP](sop/model-lifecycle.md)
and [usage and cost accounting](usage-and-cost-accounting.md).

Redis is a password-protected, non-persistent cache. The server reads a hash
verifier file. Clients read a separate password file. Docker metadata does not
contain the password.

Vault stores provider secrets, PKI data, and identity keys. It seals after a
restart. A later Ansible converge can unseal it with the encrypted
controller-held key. See [the reboot SOP](sop/vault-unseal-after-reboot.md).

Production checks whether Docker state and `/opt/ai-gateway` sit on encrypted
storage. The repository does not create or unlock LUKS. Backups and off-host
custody remain operator work.

Bind-mounted config has a keyed digest in each service label. A config change
therefore recreates the right service. Volume setup uses a separate versioned
one-shot check.

## Logs, metrics, and SOC export

Alloy collects local service logs and metrics. It does not mount the Docker
socket. Narrow file ACLs let it read only Docker JSON logs.

Prometheus keeps metrics for up to 30 days or until its configured size cap is
reached, whichever comes first. The default cap is 5 GB. Grafana shows
dashboards and local alert state. Alerts cover early warning and hard failure
conditions. Private Alertmanager groups, deduplicates, inhibits, and records
resolved alert state. It has no host port or FQDN.

Loki keeps local operational and request logs. The request stream may include
prompt and response content, so it is high-sensitivity data.

The Cribl path sends every log, metric, and trace admitted by Alloy over
verified OTLP/gRPC TLS. Ordinary logs are redacted. Security-sensitive logs,
such as request audit, login, provider trust, identity, Vault, and controller
lifecycle events, are rebuilt from fixed approved fields. Alloy applies one
common schema, environment, producer, service-name, and time gate. Prometheus
returns only its generated `ALERTS` and `ALERTS_FOR_STATE` series to a private,
mutual-TLS Alloy listener. That branch goes only to Cribl and never back to
Prometheus. Alertmanager does not send a second notification stream. The local
queue has back-pressure controls and a 24-hour retry window, but it does not
enforce a hard per-record 24-hour age limit. The Cribl destination must enforce
its own 24-hour retention.

See [observability operations](observability-operations.md) and the
[Cribl handoff](cribl-soc-handoff.md).

## Image and release rules

Every source image uses a tag and immutable digest. Custom Dockerfiles use
pinned bases and network-disabled build steps. DHI is preferred when its image
is current, compatible, and at least as secure as the reviewed choice.

An image exception is not permission to use `latest`, skip a scan, or change a
registry without review. The current pins live in Compose and the service
Dockerfiles. The generated seed manifest records the exact release image IDs.

The update path is:

```text
review source pins
  -> prepare schema-v2 seed
  -> destroy owned preprod resources and old release images
  -> load the seed
  -> deploy with Ansible
  -> run full local checks
  -> exact-manifest teardown and absence proof
  -> transfer the same production seed
  -> guarded remote upgrade, validation, and rollback
```

Never rebuild on the production host. Remote upgrade and rollback treat the
Envoy image and provider policy as one release unit.

## Limits that still matter

- This is one VM, not a highly available system.
- LiteLLM and both portal apps use reviewed single-worker limits.
- The current source has no final browser or exact-seed receipt. See
  [project status](project-status.md#current-source-candidate).
- Production LDAPS, TLS, Vault custody, Anthropic enrollment, Cribl, backup,
  and change-window steps need customer operators.
- Fresh production and preprod installs use PostgreSQL 18. The release flow
  supports same-major PostgreSQL 18 image updates and refuses a major change.
- The protected GitHub environment has approved DHI credentials. The current
  commit still needs every exact image build and blocking security check.
- The current exact-seed test, protected container scan, and live alert-path
  acceptance are tracked in [TASKS.md](../TASKS.md).

Do not call the release production-approved until the dated gates in
[project status](project-status.md) pass and the release owner accepts the
remaining risks.

## Main design choices

| Choice | Reason |
| --- | --- |
| Ansible for deployment | The VM already exists; the work is host setup and application converge. |
| Traefik at two edges | It supports exact file-based routes without a Docker socket. |
| Envoy for provider egress | Envoy starts TLS and can enforce CA, SNI, SAN, and route rules. |
| Catalog-selected CA bundles | Provider trust changes only through a reviewed release. |
| Separate Docker networks | A service gets only the paths it needs. |
| Four OAuth2 Proxy gates | Each admin tool gets a separate OIDC cookie and role gate. |
| Vault CE | The design needs KV, PKI, audit, and local secret custody. |
| Alloy as the telemetry choke point | Local logs and metrics keep working while every admitted log, metric, and trace is mirrored safely to Cribl. |

Older lab, Caddy, flat-network, CONNECT-proxy, OpenBao, and manual-init designs
are retired. Archived pages are history, not current instructions.
