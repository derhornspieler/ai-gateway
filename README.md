# AI Gateway

AI Gateway is a security-focused, self-hosted AI access platform for an
existing Rocky Linux 9 VM. It provides OpenAI- and Anthropic-compatible API
front doors, browser chat, per-user gateway keys, Keycloak OIDC, pinned vendor
egress, Vault-backed provider credentials, and local plus Cribl telemetry.

The supported host has three customer-owned, already-addressed interfaces:

- **egress**: the only default route; no gateway listener is published here;
- **ADM**: SSH and administrative HTTPS, restricted to the VPN source CIDR;
- **internal**: user HTTPS and an optional exact Cribl export, restricted to
  the internal source CIDR.

Ansible configures the host and containers. It does **not** create the VM or a
NetworkManager profile, readdress an interface, or change customer-owned
routes, gateways, DNS, or static IP addressing. It owns one bounded property
on each supplied active physical profile: `connection.zone`, addressed by its
live UUID, so a firewalld reload cannot move that interface back to the default
zone. It neither cycles nor reactivates the connection. The committed
Parallels inventory is an explicit lab profile, not a production default.

## Current status

The repository contains an implemented 20-service long-running base Compose
stack plus a one-shot DHI volume initializer. Ansible pre-creates 20 segmented
Docker bridges; the base stack uses 19 of them. The Parallels lab overlay adds
two long-running services: Samba AD on the isolated identity bridge and an
authoritative, non-recursive DNS service on a dedicated no-peer bridge. Samba
publishes no AD port; lab DNS publishes TCP/UDP 53 only on the exact ADM and
internal host addresses, never the egress address. An earlier stack revision
was converged on the three-NIC Parallels Rocky 9 lab and exposed real
firewalld/NetworkManager bugs; those fixes are retained. The current
security-audit workspace has passed
local Compose, Ansible syntax/configuration, runtime-start, service-unit,
ARM64 Samba/Keycloak, and disposable age-encrypted backup/restore tests. On
2026-07-12 its latest full three-NIC lab converge passed with `ok=178`,
`changed=10`, and `failed=0`: all 22 long-running services were healthy and
`volume-init` remained exited zero. Live checks proved the effective key-only
SSH/no-forwarding policy and fresh sudo path, the complete PostgreSQL
privilege matrix, the stable Open WebUI signing secret, and the exact scoped
Open WebUI workload key including model/route scope, management denial,
hash-only database storage, and absence from project logs. A forced Open WebUI
recreate returned healthy, and the live admin, developer, ordinary-user, and
removed-user identity flows passed. The signing-secret digest remained exact
after the recreate; the portal's standard and concurrent one-time-key
lifecycle tests passed without retaining plaintext; and a fresh encrypted
backup passed receipt/hash/age and the complete non-destructive hostile-archive
parser. A final unchanged converge also passed with the exact 23-container
snapshot unchanged: 22 services healthy, zero restarts/OOM events,
`volume-init` still exited zero with unchanged timestamps, Vault healthy and
unsealed, and zero dangling volumes. These results do not waive the separate
production and acceptance-runbook residuals documented below.

That accepted snapshot belonged to the predecessor lab VM. In the active
2026-07-13 destructive recovery rehearsal, its encrypted state and recovery
inputs were verified off-VM, the predecessor was deliberately deleted, and a
genuinely new vanilla Rocky 9.8 VM passed the G2 topology/access gate. Its
fifth full converge then passed G3 with exact saved/runtime/permanent zones,
an empty `public` zone, one default route, five policy rules, intact maintenance
and forwarding guards, exact listeners, unchanged container IDs/restarts, and
pre-restore Vault correctly uninitialized and sealed. Restore, old-share
unseal, and the complete healthy runtime have since passed G4 and G5 using the
corrected offline sequence. G6 durable persistence, identity/OIDC/LDAPS,
portal key lifecycle, infrastructure/observability, secret-scan, and negative
network lanes passed. A non-sensitive four-span synthetic batch then proved
the exact positive/negative Alloy correlation rules, Tempo and lab Cribl 4/4
delivery, spanmetrics, and zero drops without state drift, closing G6. Real
Anthropic WIF exchange, end-to-end LiteLLM inference, and its derived telemetry
remain explicitly NOT EXECUTED because the customer-supplied external
configuration is absent. G7, marker removal, and access reopening remain
PENDING in the [rehearsal register](docs/lab-dr-rehearsal.md).

The replacement VM also passed one controlled host reboot and durable-state
comparison: the boot firewall guard loaded before Docker, the exact project
container/image/volume/network inventory survived, `volume-init` did not
rerun, Vault returned sealed as designed and accepted exactly one stdin-only
lab unseal, all 22 long-running services returned healthy with zero restart
counts, and the durable semantic comparison matched. That reboot uncovered a
real key-rotator defect: zero-interval startup `DateTrigger` jobs were consumed
while Vault was sealed and recorded two failures instead of retrying after
unseal. The scheduler fix is source-tested and deployed. It defers a sealed or
temporarily unavailable Vault without writing rotation history, recreates an
explicit driver-requested retry, and leaves generic failures terminal. Its
final sealed-start-to-unseal retry proof is still PENDING.

The same exercise found that a Docker restart removed Alloy uid 473's access
ACL from `/var/lib/docker/containers`; the then-live timer repaired children
but not that parent. A least-privilege parent/child ACL reconciliation change
and a schema-2, content-addressed pre-build rollback-retention helper have
passed source tests, but have not yet completed the controlled live deploy and
Docker-daemon plus long-running-service restart gates. The exact predecessor
key-rotator image that had been
garbage-collected after its mutable build tag moved has since been recovered
from the neutral OCI artifact and loaded under the immutable rollback reference
derived by the current helper. The artifact, load receipt, and final
pre-deployment baseline are restricted, immutable, and secret-scan clean. This
closes the image-recovery prerequisite only; it does not close G7 or prove the
new source live. The successful VM restore and reboot do not make the current
source accepted, highly available, or ready for access reopening.

The fourth replacement-host converge exposed NetworkManager re-importing blank
saved zone properties into firewalld's default `public` zone after reload. The
bounded fix persists only `connection.zone`; the fifth converge proved that
correction. The rehearsal register remains authoritative for later gates.

The Samba AD lab image, isolated identity network, Docker-secret mounts,
Keycloak federation, and portal-backed identity controller are wired into the
explicit Parallels profile. Samba is lab-only and is never a customer
directory. A generic customer LDAP provider remains a separately reviewed
customer integration rather than an automatic Ansible action.

Docker Hardened Images (DHI) are used directly or as the final stage for every
catalog-supported component that passed the project's compatibility and
security review. Traefik is a reviewed DHI derivative: the shellless, non-root
`dhi.io/traefik:3.7.6` runtime carries only the immutable upstream 3.7.7
Traefik binary needed to fix `GHSA-cxjq-mrr5-89rv`. Three non-DHI application
exceptions remain: upstream LiteLLM 1.91.3, upstream Open WebUI 0.10.2, and the
lab-only Debian Samba build. Every source remains exact tag-and-digest pinned;
the rationale and re-evaluation rules are in the current architecture
document.

The current source also makes SELinux a fail-closed deployment contract. The
full playbook checks that Rocky's `targeted` policy is already enabled and
enforcing before it mutates the host; it does not convert a permissive or
disabled host. It then installs the container policy/tooling, enables Docker's
SELinux integration, requires per-container MCS labels for every ordinary
service, and permits `label=disable` only for the bounded Alloy Docker-log and
node-exporter host-root readers. Exact `z`/`Z` bind contexts, Docker runtime
types, live seccomp/capability state, and zero AVCs in the converge window are
release assertions.

Atomic Ansible file replacement can otherwise leave a running bind mount on
the old inode. A stable root-only HMAC key now derives a framed, bounded digest
for each service's reviewed bind sources; the digest is part of that service's
Compose metadata, so only affected consumers are recreated. Authenticated
restore retires the local key as a new bind epoch, forcing restored consumers
to be recreated without putting a reusable secret verifier in Compose or
logs. These SELinux and bind-recreation controls remain source-validated, not
live G7 evidence, until the final controlled converge succeeds.

The dev-portal production image installs the complete transitive Python
graph from a generated exact-version, SHA-256-hashed lock using pip
`--require-hashes`; render validation proves every direct pin is present in the
lock and prevents fallback to the direct-only requirements file. A new
controller-only safe-inventory canonicalizer provides reproducible future
non-secret markers but is intentionally not deployed and cannot retroactively
repair the old marker's missing canonicalizer or certificate-fingerprint
fields. The SELinux/MCS, bind-recreation, rollback-retention, Vault-readiness,
and ACL source changes described above require the pending final
converge/runtime proof before G7 can close.

The admin portal does not create its own first administrator. A generic
deployment requires one pre-existing `aigw` realm user mapped to
`aigw-admins` through a controlled Keycloak/customer-IdP procedure. Only the
Parallels lab seeds disposable `testadmin`, which must be removed after the
Samba `lab-admin` handoff is proved.

Vault bootstrap is also deliberately a **lab/test bootstrap** today: it uses a
1-of-1 unseal scheme, a local file backend, an internally generated test root,
and an internal plaintext listener isolated on `net-vault`. Production rollout
requires the controls called out in the deployment and operations guides.

## Documentation

Read these in order for a deployment:

1. [Current architecture and trust boundaries](docs/solution-map.md)
2. [Generic Rocky 9 and Parallels deployment](docs/deploy-guide.md)
3. [Offline external-image seed](docs/offline-image-seed.md)
4. [Identity, Samba AD lab, and group administration](docs/identity-operations.md)
5. [Anthropic WIF and `private_key_jwt`](docs/anthropic-wif-bootstrap.md)
6. [Operations, recovery, upgrades, and troubleshooting](docs/operations.md)
7. [Parallels destructive rebuild and restore rehearsal](docs/lab-dr-rehearsal.md)
8. [Sensitive telemetry and retention](docs/observability-operations.md)
9. [LiteLLM capacity and scaling design](docs/litellm-scaling.md)
10. [High availability and rolling-update matrix](docs/high-availability.md)
11. [Acceptance test runbook](docs/test-runbook.md)

The original [architecture skeleton](architecture-skeleton.md) is retained as
historical input only. It is not an operational reference.

## Deployment entry points

For a real customer host, supply the actual interface names, addresses,
gateways, source CIDRs, and resolver through an environment-specific inventory,
`--extra-vars`, or the documented `AIGW_*` controller environment variables:

```bash
ansible-galaxy collection install -r ansible/requirements.yml
ansible-playbook -i ansible/inventory/hosts.yml ansible/site.yml \
  -e @/secure/customer-topology.yml --ask-vault-pass
```

For the explicit Parallels lab only:

```bash
ansible-playbook -i ansible/inventory/lab.yml ansible/site.yml \
  --ask-vault-pass
```

Both commands intentionally fail before mutating the host if the supplied
topology disagrees with live interface/default-route facts. See the
[deployment guide](docs/deploy-guide.md) before running either command.

Safe local validation that starts no containers and needs no secret overlay:

```bash
scripts/validate-compose.sh
```

## Repository layout

```text
ansible/
  site.yml                 full host + network + stack converge
  deploy-stack-only.yml    app-only rollout; refuses a stale firewall/network ABI
  inventory/               generic entry point and explicit Parallels lab profile
  roles/                   baseline, PBR, firewall, Docker networks/stack, verify
compose/
  docker-compose.yml       implemented stack; images are tag-and-digest pinned
  traefik/                 separate internal and ADM routing
  keycloak/ litellm/ postgres/
  alloy/ prometheus/ loki/ tempo/ grafana/ cribl-mock/
services/
  egress-proxy/            Envoy TLS-originating, narrowed-CA vendor egress
  key-rotator/             rotation engine and Keycloak identity controller
  dev-portal/              OIDC key self-service and admin workflows
  samba-ad-lab/            disposable AD/LDAPS lab image for the lab profile
scripts/
  aigw-compose.sh           profile-aware deployed Compose wrapper
  validate-compose.sh      render-only Compose validation
  vault-bootstrap.sh       lab/test Vault bootstrap; run on the target VM
  state-backup.sh          quiesced, age-encrypted state backup
  state-restore.sh         authenticated offline restore; leaves graph stopped
  pre-upgrade-check.sh     recent-backup gate for stateful image changes
  preserve-compose-rollbacks.py
                           exact healthy running-image retention before a planned build
docs/                      current operator and architecture documentation
```

## Primary security boundaries

- Only Traefik publishes container ports, bound to the exact ADM/internal host
  addresses; no container port is bound to the egress address or `0.0.0.0`.
- Envoy at fixed `172.28.0.2` is the only workload allowed external DNS and
  TCP/443. Vendor TLS uses exact SANs and narrowed per-vendor CA bundles.
- Atomic `DOCKER-USER` rules and an independent native nftables guard deny
  cross-plane, container-to-host, and unapproved bridge egress.
- User/API, administrative, database, cache, Vault, telemetry, and trace planes
  use separate Docker bridges. Services join only the planes they need.
- SSH is public-key-only: root/password/interactive login and TCP, socket,
  agent, X11, and tunnel forwarding are denied. Ansible proves a fresh key-only
  login and non-interactive sudo after reloading the validated policy.
- Keycloak realm roles gate chat, developer-key, and admin capabilities.
  Grafana and the LiteLLM admin UI are additionally fronted by separate
  oauth2-proxy instances in reverse-proxy mode. Open-source Traefik provides
  TLS and routing here; it does not replace the Keycloak OIDC session layer.
- Full prompts/completions are sensitive Tempo trace attributes and may also be
  exported to Cribl. They are not intended to be ordinary Loki log records.
- Validated LiteLLM trace metadata is promoted to timestamped canonical user,
  key-hash/key-alias, project, and request attributes. Direct portal keys
  therefore retain human ownership without logging bearer plaintext; the
  spend row joins its hashed key to namespaced project metadata rather than a
  native LiteLLM project row. Open WebUI deliberately uses one inference-only
  service key, so its current audit attribution is `svc-open-webui`, not the
  individual browser user.
- Redis server command/environment metadata contains no credential: the server
  reads a SHA-256 verifier ACL file and the client probe alone receives the
  separate password file. The previously exposed test value was rotated and
  is intentionally absent from documentation.
- Authenticated restore exits with zero running project containers and an
  exact root-only marker. Current-source full converge must run under that
  marker before old-share unseal and the complete runtime wait;
  `vault-bootstrap.sh` is forbidden on the recovery path.
- Recovery acceptance does not make this profile highly available. It remains
  one Compose project on one Rocky VM, and the LiteLLM Admin/Grafana login
  architecture remains two independent oauth2-proxy services behind
  open-source Traefik.

This is still a customer prototype, not a turnkey production appliance. Review
the documented residual risks, rehearse stateful upgrades and restore, and run
the complete acceptance suite before production use.
