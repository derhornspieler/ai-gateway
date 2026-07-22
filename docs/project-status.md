# AI Gateway project status

_Updated 2026-07-21._

AI Gateway is a customer prototype. It runs on one Docker host and is not
highly available. Local tests reduce release risk, but they do not approve a
production change.

Start with the [solution map](solution-map.md) for design details. Use the
[test runbook](test-runbook.md) for release checks. Old Rocky lab records are
in [the archive](archive/lab-dr-rehearsal.md). They are not current deploy
instructions.

## Supported paths

| Environment | Purpose | Guide |
| --- | --- | --- |
| Local preprod | Test the whole stack on local Docker | [Local preprod](preprod.md) |
| Production | Deploy to an existing three-NIC Rocky Linux 9 VM | [Production deploy](deploy-runbook.md) |

Local preprod always uses `aigw.internal`. It creates a test Root CA, Samba AD
over LDAPS, WIF and provider mocks, and fixed test users. It models the three
host-facing network planes and keeps service networks separate. It does not
run production host-hardening roles.

Production gets its domain, addresses, directory settings, certificates, and
secret values from a generated Ansible inventory. Ansible checks the live host
before it changes anything.

## What is implemented

- `scripts/bootstrap-rocky9-production.py` supports guided setup. Its
  non-interactive mode documents all required options.
- `ansible/preprod.yml` creates and checks local preprod. The destroy and
  clean-room playbooks remove only resources owned by `aigw-preprod`.
- Keycloak URLs and callbacks come from the Ansible domain. Ansible sets up
  LDAPS, OIDC clients, lasting identity control, and temporary-admin cleanup.
  The admin portal has no user-run initialization step.
- `scripts/update-images.py` pulls exact pins, builds custom images, creates
  schema-v2 offline seeds, tests the preprod seed, and provides the guarded
  remote upgrade and rollback flow.
- Operators select Envoy providers from a reviewed catalog. The image contains
  only the chosen routes and CA files. Anthropic is the only approved provider
  in this release.
- LiteLLM sends audit traces to Alloy's separate OTLP/HTTP receiver on port
  4319. A private bearer token proves the source before Alloy stamps its own
  trust marker. The ordinary receiver cannot claim to be LiteLLM.
- Seed mode uses exact image IDs. It disables pulls and source builds.
- Open WebUI uses the chat-only `0.10.2-aigw2` derivative. Its root filesystem
  is read-only. Unused local ML and document-conversion packages are removed,
  remote Chroma settings are removed, and embedding and retrieval are bypassed.
- Production keeps its firewall, routing, SELinux, encrypted-state, backup,
  Vault, and network checks. Preprod does not weaken those production rules.

## Current source candidate

The current worktree is newer than every saved offline-seed receipt. It is not
release-approved yet. The final commit, four release-file hashes, policy
digest, Envoy image ID, exact container image IDs, browser result, GitHub scan,
and teardown receipt are all pending.

The current source adds these release controls:

- The Open WebUI assertion carries a stable per-user subject. Its signed
  username or e-mail may become the reviewed readable audit name. The shared
  LiteLLM key remains service authorization evidence only.
- Managed identity changes use a durable UUID and pending Vault record. Planned
  inventory changes use planned/applied events. Unexpected live changes use
  security-drift/recovery events. LDAP provider rename fails closed unless a
  legacy blank-name record points to the same live provider ID.
- Alloy applies one common record gate before the Cribl queue. It also reads
  protected target-side upgrade and rollback records. Prompt fields use the
  reviewed redaction patterns before export.
- A source-mode preprod receipt has seen natural quoted Keycloak `LOGIN`,
  `LOGIN_ERROR`, and `LOGOUT` events. This is useful implementation evidence,
  but it is not evidence for the final offline seed.

The release owner must now build a new Anthropic-only schema-v2 pair from one
exact local commit. The matching preprod pair must pass a fresh archive load,
one Ansible seed-mode deploy, the full automated and browser checks, and a
final exact-manifest clean-room teardown. Push that same commit after the local
gate passes. Local seeded preprod is the only release rehearsal. Do not create
a Rocky or Parallels test VM.

The final teardown must prove that all owned containers, images, volumes,
networks, generated files, hosts entries, and loopback aliases are absent. It
must also prove that unrelated image IDs are unchanged. The ordinary destroy
play is useful for development, but it is not the final release receipt.

Old `r7` through `r14` results remain dated history in [TASKS.md](../TASKS.md).
They show that earlier code passed earlier tests. They do not approve this
source candidate and must not supply its hashes or browser result.

## Gates that remain open

- **Current-candidate acceptance:** build and test a new exact seed from the
  final pushed commit. The current candidate has no final seed, browser, or
  teardown receipt yet.
- **Credential-gated security audit:** credential-independent GitHub jobs are
  green. The DHI image jobs stop at their required credential gate because the
  `release-container-security` environment has no DHI secrets. Add approved
  credentials and rerun the exact release. Review the source and every image,
  raw Trivy JSON, blocking VEX-aware Scout result, SBOM, provenance record,
  waiver, and remaining risk before release.
- **Production ceremonies:** customer TLS, external LDAPS, Vault key custody,
  Anthropic enrollment, production backups, the real Cribl endpoint, and final
  access approval need customer operators. This is operator-owned work.
- **Cribl acceptance:** repeat the local receipt through the exact current
  seed. The Cribl team must still apply and prove its 24-hour destination
  retention. If a hard 24-hour age limit is required on the local queue, that
  control is still a release gate. See the [Cribl handoff](cribl-soc-handoff.md).
- **PostgreSQL migration size:** PostgreSQL 18.4 is stable and passed the full
  seeded preprod stack in earlier tests. The production-sized PostgreSQL
  16-to-18 rehearsal and forced rollback cases remain in
  [TASKS.md](../TASKS.md). Run them in local seeded preprod, not on another VM.
- **High availability:** the Compose design has no HA. See
  [scaling and availability](high-availability.md).
- **Repository history:** the active tree has no prohibited customer or
  personal identifiers. A history rewrite or repository-owner change needs a
  separate owner-approved plan.

Do not call this production-approved until the open release gates have dated
evidence and the release owner accepts every remaining risk.
