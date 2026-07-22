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

## Current release candidate: r14

Release candidate `r14` was built from pushed commit
`c5c1e503053c76e35f8bb93d242a9ac630d1b98e`. Its production scope has 23
external and 17 custom image references, for 40 total. Its preprod scope has 24
external and 19 custom image references, for 43 total.

There are two preprod-only custom services: `samba-ad:preprod` and
`wif-provider-mock:preprod`. The Debian 13.6-slim base used by those builds is
the third extra preprod image reference. None of these three references is in
the production seed. Anthropic is the only selected provider.

The exact `r14` preprod archive passed the clean-room Ansible test. The initial
pre-deploy purge receipt removed 26 containers, 19 networks, 11 volumes, 62
image aliases, and all 43 target image IDs. It preserved 185 unrelated image
IDs. The archive then loaded fresh. Seed mode skipped pulls and source builds.

The seeded test passed Redis first start, Vault, automatic Keycloak and LDAPS
identity setup, all three users, WIF, OIDC roles and logout, edge inference,
and Cribl queue outage and recovery. The Cribl test also proved that LiteLLM
used the authenticated receiver and that a missing token, wrong token, or
forged source marker could not create an AI audit record. The run ended with:

```text
PREPROD_CLEAN_ROOM_OK
PREPROD_E2E_PASSED
SEEDED_PREPROD_E2E_PASSED
```

After the tests, the final bounded clean-room teardown returned
`PREPROD_CLEAN_ROOM_OK` for project `aigw-preprod`, cleanup-receipt schema 1,
and manifest
`1ab6902ace9c1b25a3e8a3a1d1a81e014dbf60d0045d8e67a4b8604b7b58ceab`.
It removed 26 containers, 19 networks, 11 volumes, 43 image aliases, 43 image
IDs, and three generated state files. It preserved 185 unrelated image IDs.
Ansible also removed the owned macOS loopback aliases and marker-bounded hosts
fragment.

| `r14` artifact | SHA-256 |
| --- | --- |
| Production archive | `b04cce16df11c366a098b3a9d801bc57a96051e0766caba182cd342493285298` |
| Production manifest | `9b2efbd2f6768bd98f969b3f4312cf8d0cff9b1761d5d59dd7ebd44a6869c92f` |
| Preprod archive | `482618f21eb5e09c3f41e9c9c55deada7e317edf4c4fada0f96dd7e93ff2a691` |
| Preprod manifest | `1ab6902ace9c1b25a3e8a3a1d1a81e014dbf60d0045d8e67a4b8604b7b58ceab` |

The exact r14 manifest selects only `anthropic`, with route `/anthropic/` and
hostname, SNI, and SAN `api.anthropic.com`. Its Envoy policy digest is
`8c553d83bc98edeee4e1157368b8620ec6234e557b59a8195be6390677cdada6`.
Its Envoy image ID is
`sha256:04f3d74c450509bdf288ec64fdbee584e616522f503428a3699442a48b8cc08f`.
The two reviewed CA SHA-256 fingerprints are
`1dfc1605fbad358d8bc844f76d15203fac9ca5c1a79fd4857ffaf2864fbebf96`
and
`349dfa4058c5e263123b398ae795573c4e1313c83fe68f93556cd5e8031b3c7d`.

The visual browser replay has not run for `r14` because no browser session
exists. Do not use the accepted `r10` browser result as proof for `r14`.

The Open WebUI derivative in `r14` is `0.10.2-aigw2`. Its committed local
OpenVEX review covers the one raw Scout finding, `CVE-2026-45829`, and expires
on 2026-10-19. That review is unsigned and Git-reviewed; it is separate from
Docker-signed DHI VEX. The protected GitHub release scan for the exact `r14`
images is still blocked on its required DHI credentials, so this candidate is
not release-approved.

The r14 image pair was built at `c5c1e50`. Current deployment source also
includes pushed follow-up `33c79e5`. That follow-up does not change the image
set. It validates a restored LiteLLM telemetry token before Ansible repairs its
reader group and mode.

## Final local release evidence

The last fully accepted local release is `r10`.

The ARM64 `r10` release test ran on 2026-07-21. It built both schema-v2 seeds,
destroyed the old owned test stack, removed all old release images, loaded the
new preprod archive, and deployed once with Ansible in seed mode.

The clean-room receipt removed 26 containers, 19 networks, 11 volumes, and 43
release image IDs. It preserved 129 unrelated image IDs.

After the documentation overhaul, the same `r10` preprod seed was tested again
from a full clean room. The repeat removed the same owned resources and release
images, preserved the same 129 unrelated image IDs, loaded the archive again,
and performed one Ansible seed-mode deploy with pulls and source builds
disabled. All 25 long-running containers were healthy at the end.

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

The `r10` production seed has 40 image references. Its preprod seed has 43.
Production does not contain the preprod-only Samba AD or WIF mock images, or
their extra Debian base reference.

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

For `r10`, local code checks also passed: 762 infrastructure contracts, 147
portal tests, 323 key-rotator tests, all four Go race and vet suites, Compose
rendering, identity policy, documentation links, YAML lint, ShellCheck, Ruff,
and Bandit.

System Chrome also passed the real-browser acceptance check. It followed the
domain-derived redirects for the developer portal, admin portal, Open WebUI,
Grafana, and Keycloak. Allowed roles reached their pages, denied roles saw a
403 page, logout cleared the application and Keycloak sessions, and Back plus
Refresh did not reopen the protected developer page. The browser reported TLS
1.3, `*.aigw.internal`, and the AI Gateway preprod test Root CA. The separate
certificate tests proved the Root CA chain and names.

## Gates that remain open

- **r14 browser acceptance:** the exact `r14` seed passed clean-room loading,
  Ansible deployment, integration, end-to-end, and authenticated Cribl checks.
  Repeat the real-browser test for `r14` when a browser session is available.
  Until then, `r10` remains the last release with full local and visual browser
  acceptance.
- **Credential-gated security audit:** credential-independent GitHub jobs are
  green. The DHI image jobs stop at their required credential gate because the
  `release-container-security` environment has no DHI secrets. Add approved
  credentials and rerun the exact release. Review the source and every image,
  raw Trivy JSON, blocking VEX-aware Scout result, SBOM, provenance record,
  waiver, and remaining risk before release.
- **Production ceremonies:** customer TLS, external LDAPS, Vault key custody,
  Anthropic enrollment, production backups, the real Cribl endpoint, and final
  access approval need customer operators. This is operator-owned work.
- **Cribl retention:** the seeded receipt and outage recovery passed. The Cribl
  team must still apply and prove its 24-hour destination retention. If a hard
  24-hour age limit is required on the local queue, that control is still a
  release gate. Trusted readable attribution and broader reviewed string-secret
  patterns also remain open. See the
  [Cribl handoff](cribl-soc-handoff.md).
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
