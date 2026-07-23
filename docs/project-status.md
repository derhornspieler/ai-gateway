# AI Gateway project status

_Updated 2026-07-22._

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
- Fresh production and preprod deployments use PostgreSQL 18. Same-major image
  updates, encrypted backups, and same-major restores are supported. The image
  updater refuses PostgreSQL major changes.
- Operators select Envoy providers from a reviewed catalog. The image contains
  only the chosen routes and CA files. Anthropic is the only approved provider
  in this release.
- LiteLLM sends audit traces to Alloy's separate OTLP/HTTP receiver on port
  4319. A private bearer token proves the source before Alloy stamps its own
  trust marker. The ordinary receiver cannot claim to be LiteLLM.
- The current source has an append-only, prompt-free usage ledger, five token
  price classes, immutable future and backdated prices, read-only Grafana usage
  views, and bounded accounting-gap audit events. Existing PostgreSQL volumes
  run the governance and usage schema updates in order and must return both
  schema receipts before consumers start. This source still needs the current
  exact-seed acceptance run described below.
- Seed mode uses exact image IDs. It disables pulls and source builds.
- Open WebUI uses the chat-only `0.10.2-aigw2` derivative. Its root filesystem
  is read-only. Unused local ML and document-conversion packages are removed,
  remote Chroma settings are removed, and embedding and retrieval are bypassed.
- Production keeps its firewall, routing, SELinux, encrypted-state, backup,
  Vault, and network checks. Preprod does not weaken those production rules.

## Current exact-seed evidence

Runtime commit `ada03be` produced a new Anthropic-only schema-v2 release for
`linux/arm64` on 2026-07-22. The production seed has 43 images. The PreProd
seed has 46 images. Both use PostgreSQL 18.4 only. Neither seed contains a
PostgreSQL 16 or migration-rehearsal image.

Ansible loaded the exact PreProd archive and deployed `aigw.internal` with
pulls and source builds disabled. The full automated acceptance suite passed
three times. Vault restart, sealed-state detection, Ansible unseal, and a
PostgreSQL 18 same-major physical backup and restore also passed.

The production archive SHA-256 is
`84a76e0ac3c25e7fabf2d9fce598d1d1714211ca1b671f0263d2d8a48c146d05`.
Its manifest SHA-256 is
`cef1162e3f457e7e184a83880d05dbb7d96a60893ef6001fac1e267e7eba93f2`.
The PreProd archive SHA-256 is
`800fabcc3b2c64af4a820f01fc8ae9bbd95cef99b494bc156653c12456e1674a`.
Its manifest SHA-256 is
`5f63a881a9fa75048bc1b64d9cd3b9b42455fdabd764d637097b73ddb31a7be5`.

No browser controller was available for this run. Browserless redirect,
callback, cookie, role, logout, LDAP, Keycloak, and portal tests passed. They
do not replace the manual one-time-key Back and Forward check. The final exact
clean room removed all 29 owned containers, 12 volumes, 19 networks, 46 image
IDs, 46 aliases, and six generated state files. It preserved two unrelated
image IDs. The push and GitHub Actions results are not recorded as complete
until those steps finish.

The [dated version review](image-version-review.md) found that every selected
image and direct library is current for its reviewed source. The reusable
local Root CA, leaf keys, private credential seed, and rendered inputs remain
after cleanup by design. The seed keeps PreProd identities stable on one
controller without publishing the passwords. These files are not running
deployment state.

## Gates that remain open

- **Current-candidate release closeout:** push the tested source and
  documentation, then make the required GitHub Actions checks green.
- **Current-candidate browser check:** when a browser controller is available,
  test redirects, login, roles, cookies, logout, and the one-time-key Back and
  Forward rule against a newly loaded exact seed. Then revoke the test key.
- **Credential-gated security audit:** the protected DHI credentials were added
  on 2026-07-22 and authentication now passes. Earlier runs exposed release
  workflow defects. Push the tested fixes, run every exact image job for the
  current commit, and review the raw scan data, blocking policy result, SBOM,
  provenance record, waivers, and remaining risk before release. The current
  DHI Alertmanager `0.33.1` image has an open gRPC HIGH finding on both
  architectures. DHI has no fixed digest or signed VEX yet. Keep the scan
  blocking and follow the [durable recheck task](../TASKS.md#recheck-and-clear-the-dhi-alertmanager-security-finding).
- **Production ceremonies:** customer TLS, external LDAPS, Vault key custody,
  Anthropic enrollment, production backups, the real Cribl endpoint, and final
  access approval need customer operators. This is operator-owned work.
- **Cribl acceptance:** the last accepted seed passed the local TLS, schema,
  redaction, backpressure, outage, and recovery receipt. Repeat that receipt
  with the current seed. The Cribl team must still apply and prove its 24-hour
  destination retention. If a hard 24-hour age limit is required on the local
  queue, that control is still a release gate. See the
  [Cribl handoff](cribl-soc-handoff.md).
- **High availability:** the Compose design has no HA. See
  [scaling and availability](high-availability.md).
- **Repository history:** the active tree has no prohibited customer or
  personal identifiers. A history rewrite or repository-owner change needs a
  separate owner-approved plan.

Do not call this production-approved until the open release gates have dated
evidence and the release owner accepts every remaining risk.
