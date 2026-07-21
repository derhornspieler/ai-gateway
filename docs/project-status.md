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
- Seed mode uses exact image IDs. It disables pulls and source builds.
- Production keeps its firewall, routing, SELinux, encrypted-state, backup,
  Vault, and network checks. Preprod does not weaken those production rules.

## Final local release evidence

The ARM64 `r10` release test ran on 2026-07-21. It built both schema-v2 seeds,
destroyed the old owned test stack, removed all old release images, loaded the
new preprod archive, and deployed once with Ansible in seed mode.

The clean-room receipt removed 26 containers, 19 networks, 11 volumes, and 43
release image IDs. It preserved 129 unrelated image IDs.

The final markers were:

```text
PREPROD_CLEAN_ROOM_OK
PREPROD_E2E_PASSED
SEEDED_PREPROD_E2E_PASSED
```

All 25 long-running containers were healthy. The checks covered the Root CA,
Samba AD and LDAPS, all three test users, automatic Keycloak setup, OIDC roles
and callbacks, Vault init and unseal, WIF, mock inference, the immutable
production Envoy startup gate, and the curated Cribl TLS queue and recovery
path.

The production seed has 40 images. The preprod seed has 43 images. Production
does not contain the preprod-only Samba AD or WIF mock images.

| Artifact | SHA-256 |
| --- | --- |
| Production archive | `958ee15a3609a9bdee13d7144b941cbb4379136b1d674103f5ae887bf04cd453` |
| Production manifest | `0960fab4f0133cf4be610c8e552a554eb3d795d5114bb108201243deb90c3da7` |
| Preprod archive | `73e244dc6fc6fd347f7b8711a8710b586f554c603bcb1c4e0a3ca5938f0ad7e8` |
| Preprod manifest | `80173e1a67fcb0997fd90572a1f1e8087d22ecd9a2438038f33f1191d93d7d02` |

The selected provider is `anthropic`. The Envoy policy digest is
`8c553d83bc98edeee4e1157368b8620ec6234e557b59a8195be6390677cdada6`.
The Envoy image ID is
`sha256:4fc925d12af6f8a693c363a5249ff7b71851c2276a3fcab7b3f6379fc2f66b35`.
Two clean builds produced that same Envoy image ID.

Local code checks also passed: 762 infrastructure contracts, 147 portal tests,
323 key-rotator tests, all four Go race and vet suites, Compose rendering,
identity policy, documentation links, YAML lint, ShellCheck, Ruff, and Bandit.

## Gates that remain open

- **Real browser:** no in-app browser backend was attached. The HTTP and OIDC
  acceptance checks passed, but a person still must test login, callbacks,
  cookies, roles, and logout in a real browser.
- **GitHub container scans:** ordinary GitHub checks are green. The DHI image
  build and Trivy jobs stop at their required credential gate because the
  `release-container-security` GitHub environment has no DHI secrets. Do not
  weaken that gate. Add approved credentials, rerun it, and review every
  result before release.
- **Production upgrade:** no approved remote VM or maintenance window was in
  scope. Do not create a Rocky or Parallels test VM. Run the guarded remote
  upgrade only on the approved target after the local and CI gates pass.
- **Production ceremonies:** customer TLS, external LDAPS, Vault key custody,
  Anthropic enrollment, production backups, the real Cribl endpoint, and final
  access approval need customer operators. This is operator-owned work.
- **Cribl retention:** the seeded receipt and outage recovery passed. The Cribl
  team must still apply and prove its 24-hour destination retention. If a hard
  24-hour age limit is required on the local queue, that control is still a
  release gate. See the [Cribl handoff](cribl-soc-handoff.md).
- **PostgreSQL migration size:** PostgreSQL 18.4 is stable and passed the full
  seeded preprod stack. The production-sized PostgreSQL 16-to-18 rehearsal and
  forced rollback cases remain in [TASKS.md](../TASKS.md).
- **High availability:** the Compose design has no HA. See
  [scaling and availability](high-availability.md).
- **Repository history:** the active tree has no prohibited customer or
  personal identifiers. A history rewrite or repository-owner change needs a
  separate owner-approved plan.

Do not call this production-approved until the open release gates have dated
evidence and the release owner accepts every remaining risk.
