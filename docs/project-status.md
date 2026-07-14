# AI Gateway — Project Status

_As of 2026-07-14._

This is the living implementation-status record for AI Gateway. For the
authoritative, gate-by-gate destructive-recovery evidence, see the
[lab rebuild and restore rehearsal register](archive/lab-dr-rehearsal.md). For
architecture and trust boundaries, see the [solution map](solution-map.md).

## Maturity

AI Gateway is a **customer prototype under active hardening**, not a turnkey
production appliance. It is **not highly available**: one Docker Compose project
on one Rocky Linux 9 VM. Recovery and reboot acceptance do not confer high
availability, and passing source tests does not make the current source
accepted, highly available, or ready for access reopening.

## What is implemented

The hardened control-plane drop (July 2026) added: a generated per-customer
inventory flow (`scripts/bootstrap-generic-rocky9.py` plus the controller-only
`ansible/preflight-generic-rocky9.yml` gate), three new converge roles
(`firewall_preflight`, `time_sync`, `host_finalize`), split internal/egress
DNS resolver planes replacing the shared container resolver, four per-gate
OAuth cookie secrets, an optional extracted-asset Vault browser UI
(`vault-ui-proxy`), continuous portal-key reconciliation, a pre-Vault
identity baseline bridge, an Anthropic WIF enrollment control plane,
provisioned immutable Grafana dashboards with Alloy-side telemetry
sanitization, and a snapshot-gated legacy lab reset playbook.


The repository contains an implemented base Compose stack of 25 services — one
`volume-init` one-shot DHI volume initializer plus 23 long-running services —
using 18 of the 20 segmented Docker bridges that Ansible pre-creates. The
lab overlay adds two long-running services: Samba AD on the isolated
identity bridge and an authoritative, non-recursive CoreDNS service on a
dedicated bridge. Samba publishes no AD port; lab DNS publishes TCP/UDP 53 only
on the exact ADM and internal host addresses, never egress. Samba is lab-only
and is never a customer directory; a generic customer LDAP provider remains a
separately reviewed integration rather than an automatic Ansible action.

Docker Hardened Images (DHI) are used directly or as the final build stage for
every catalog-supported component that passed compatibility and security review;
shellless DHI runtimes embed a static health-probe binary. Three non-DHI
application exceptions remain — upstream LiteLLM 1.91.3, upstream Open WebUI
0.10.2, and the lab-only Debian Samba build. Traefik is a reviewed DHI
derivative that carries the upstream 3.7.7 security binary on the non-root DHI
runtime. Every source is exact tag-and-digest pinned; the rationale and
re-evaluation rules are in the [solution map](solution-map.md).

The current source also enforces the SELinux fail-closed contract, bind-source
HMAC recreation digests, per-service rollback retention, and least-privilege
Alloy ACL reconciliation described in [operations](operations.md).

## Verification completed

The current security-audit workspace has passed local Compose render, Ansible
syntax/configuration, runtime-start, service-unit, ARM64 Samba/Keycloak, and
disposable age-encrypted backup/restore tests.

The most recent full three-NIC lab converge passed clean
(`failed=0`), with all long-running services healthy and `volume-init` exited
zero. Live checks proved the key-only, no-forwarding SSH policy and fresh sudo
path, the full PostgreSQL privilege matrix, the stable Open WebUI signing
secret, and the exact scoped Open WebUI workload key — model/route scope,
management denial, hash-only database storage, and absence from project logs. A
forced Open WebUI recreate returned healthy; the admin, developer,
ordinary-user, and removed-user identity flows passed; the portal one-time-key
lifecycle (standard and concurrent) retained no plaintext; and a fresh encrypted
backup passed receipt, hash, age, and the complete non-destructive
hostile-archive parser.

In the active destructive-recovery rehearsal, the predecessor lab VM was
verified off-box and deliberately deleted, and a genuinely new vanilla Rocky 9.8
VM passed gates G2 through G6: topology and access; the host boundary before any
state (empty `public` zone, one default route, the exact policy rules, and Vault
correctly uninitialized and sealed pre-restore); offline restore and old-share
unseal; durable persistence, identity/OIDC/LDAPS, portal key lifecycle,
infrastructure/observability, secret-scan, and negative network lanes; and a
synthetic four-span Alloy/Tempo/Cribl telemetry correlation batch with zero
drops. A controlled host reboot also passed: the boot firewall guard loaded
before Docker, the exact container/image/volume/network inventory survived,
`volume-init` did not re-run, and Vault returned sealed by design and accepted
exactly one stdin-only lab unseal.

See the [rehearsal register](archive/lab-dr-rehearsal.md) for exact per-gate figures.

## Open items before production and access reopening

The following are explicitly **not yet closed**:

- **G7 and access reopening — PENDING.** Marker removal and access reopening
  remain pending in the rehearsal register. The SELinux/MCS, bind-recreation,
  rollback-retention, Vault-readiness, and ACL changes in the current source are
  source-validated only and still require the final controlled converge and
  runtime proof.
- **Real Anthropic inference — NOT EXECUTED.** Real Anthropic WIF exchange,
  end-to-end LiteLLM inference, and its derived telemetry cannot run until the
  customer supplies the external configuration; see
  [Anthropic WIF bootstrap](anthropic-wif-bootstrap.md).
- **Key-rotator sealed-start retry — proof PENDING.** A reboot exposed a defect
  where zero-interval startup jobs were consumed while Vault was sealed. The
  scheduler fix (defer while sealed or unavailable, retry after unseal, leave
  generic failures terminal) is source-tested and deployed, but its
  sealed-start-to-unseal retry proof is still pending.
- **Alloy ACL and rollback-retention live gates — PENDING.** The parent/child
  ACL reconciliation and the content-addressed rollback-retention helper pass
  source tests but have not completed the controlled live deploy and the
  Docker-daemon plus long-running-service restart gates. The garbage-collected
  predecessor key-rotator image has been recovered under an immutable rollback
  reference; this closes only the image-recovery prerequisite.
- **Vault production hardening.** The lab/test bootstrap (1-of-1 unseal, file
  backend, internal test root, plaintext listener on `net-vault`) must be
  replaced with the controls in the [deployment](deploy-guide.md) and
  [operations](operations.md) guides.
- **First administrator provisioning.** A generic deployment requires one
  pre-existing `aigw` realm user mapped to `aigw-admins` through a controlled
  Keycloak or customer-IdP procedure. Only the lab seeds disposable
  `testadmin`, which must be removed after the Samba `lab-admin` handoff is
  proved.
- **High availability.** There is no HA today, and HA is not pursued on
  Docker Compose: the VM scales vertically, and horizontal scaling/HA would be
  a separate Kubernetes design. See the
  [scaling and HA posture](high-availability.md).

These residuals are not waived by any local or recovery test. Rehearse stateful
upgrades and restore, and run the full [acceptance test runbook](test-runbook.md)
before production use.
