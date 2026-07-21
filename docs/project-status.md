# AI Gateway project status

_Updated 2026-07-21._

AI Gateway is a customer prototype under active hardening. It runs on one
Docker host and is not highly available. A passing local test does not approve
a production release.

For design details, read the [solution map](solution-map.md). For release
steps, use the [acceptance runbook](test-runbook.md). Old Rocky lab and recovery
records are kept only as historical evidence in
[docs/archive](archive/lab-dr-rehearsal.md). They are not deployment
instructions.

## Supported deployment paths

There are two separate paths:

| Environment | Purpose | Entry point |
| --- | --- | --- |
| Local preprod | Test the full stack on one local Docker engine | [Local preprod](preprod.md) |
| Production | Deploy to an existing three-NIC Rocky Linux 9 VM | [Production runbook](deploy-runbook.md) |

Local preprod uses the fixed domain `aigw.internal`. It creates its own test
root CA, Samba AD over LDAPS, WIF provider mock, static users, and labeled
Docker networks and volumes. It is localhost-only and does not run the Rocky
host-hardening roles.

Production uses the domain, IP addresses, directory, certificates, and secret
custody values from a generated inventory. Ansible validates the live host
before it changes anything.

## Implemented in the current source

- `scripts/bootstrap-rocky9-production.py` has a guided terminal setup and a
  complete non-interactive example. Its older `generic-rocky9` names remain
  compatibility aliases.
- `ansible/preprod.yml` creates and verifies local preprod. The matching
  destroy playbook removes only resources with the exact `aigw-preprod`
  namespace and ownership labels.
- Preprod models egress, ADM, and internal planes with separate Docker
  networks. Public test traffic binds only to `127.0.2.1` and `127.0.3.1`.
- Keycloak URLs, redirect URIs, web origins, logout URLs, and WIF issuer URLs
  come from the selected deployment domain. Existing realms are reconciled;
  changing a realm JSON file alone is not treated as an update.
- When LDAPS is enabled, Ansible mounts the bind password from its protected
  file and automatically configures and verifies federation, durable identity
  control, OIDC clients, the break-glass account, and temporary-admin cleanup.
  The admin portal has no user-run initialization step.
- `scripts/update-images.py` joins the image release steps: fetch exact pins,
  build custom images, create an offline seed, test that seed in local
  preprod, stage it for a remote host, deploy with Ansible, validate, and roll
  back on failure.
- Offline seed mode verifies image IDs, removes Compose build sections, and
  sets `pull_policy: never` before startup. The source-tag materialization
  workaround is still available as
  `--materialize-missing-source-tags`.
- Production keeps its host firewall, routing, SELinux, encrypted-state,
  backup, Vault, and segmented-network checks. Local preprod does not weaken
  those production checks.

## Verified so far

The current workspace has source and contract coverage for Compose rendering,
production and preprod Ansible syntax, identity policy, portal and key-rotator
behavior, offline seed planning and loading, update rollback rules, the Go
services, and shell scripts.

Local safety checks have also proved that preprod network creation and removal
leave unrelated Docker projects alone. The Samba image tests prove that its
test passwords do not appear in process arguments and that the lockout policy
survives a restart.

These checks are useful, but they are not the final release proof described in
the [acceptance runbook](test-runbook.md).

## Open release gates

- **Seeded preprod:** the exact ARM64 schema-v2 release seed has been built.
  Load its preprod archive into a clean local Docker engine and start preprod
  from those exact image IDs. Run the full browser/OIDC, LDAPS, WIF, portal,
  chat, admin-gate, validation, and local rollback checks. Do not create a
  Rocky or Parallels test VM for this gate.
- **Production upgrade:** promote only the production-scoped release after the
  seeded local test passes. During the approved production maintenance window,
  make a fresh backup, deploy through Ansible, validate the real host, and keep
  the previous source, images, and state ready for rollback. Do not force a
  failure on the production host merely to create test evidence.
- **Production ceremonies:** customer TLS, external LDAPS, Vault
  initialization and custody, Anthropic enrollment, backups, and final access
  approval remain operator-owned work.
- **Cribl SOC feed:** the source now has a log-only Alloy queue, a reviewed
  Keycloak event list, request-audit conversion, and bounded structured-event
  classifiers. The release still needs a seeded-preprod receipt test for every
  approved class and proof that denied metrics, traces, alerts, malformed
  records, and ordinary logs do not arrive. Any required event without a
  structured producer remains open. See the
  [logging-team handoff](cribl-soc-handoff.md).
- **Security and version review:** the full source/container Trivy audit,
  production-sized PostgreSQL 18 migration rehearsal, and complete
  DHI/upstream version review are tracked in the
  [repository task list](../TASKS.md).
  PostgreSQL 18.4 is stable and operator-selected. Exact DHI 17.10 and 18.4
  both passed the bounded application and restore comparison; seeded preprod
  and production-sized evidence are still required.
- **High availability:** there is no HA in the Docker Compose design. See the
  [HA posture](high-availability.md).
- **Repository history:** the active tree blocks prohibited customer and
  personal identifiers. Removing old commit metadata or changing repository
  ownership needs a separate owner-approved history plan.

Do not reopen production access until every required section in the
[acceptance runbook](test-runbook.md) has dated evidence and an owner has
accepted every remaining risk.
