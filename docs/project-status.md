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
- Operators select Envoy providers from a reviewed catalog. The image contains
  only the chosen routes and CA files. Anthropic is the only approved provider
  in this release.
- LiteLLM sends audit traces to Alloy's separate OTLP/HTTP receiver on port
  4319. A private bearer token proves the source before Alloy stamps its own
  trust marker. The ordinary receiver cannot claim to be LiteLLM.
- The current source has an append-only, prompt-free usage ledger, five token
  price classes, immutable future and backdated prices, read-only Grafana usage
  views, and bounded accounting-gap audit events. Existing PostgreSQL volumes
  run the governance and usage migrations in order and must return both schema
  receipts before consumers start. This source still needs the current
  exact-seed acceptance run described below.
- Seed mode uses exact image IDs. It disables pulls and source builds.
- Open WebUI uses the chat-only `0.10.2-aigw2` derivative. Its root filesystem
  is read-only. Unused local ML and document-conversion packages are removed,
  remote Chroma settings are removed, and embedding and retrieval are bypassed.
- Production keeps its firewall, routing, SELinux, encrypted-state, backup,
  Vault, and network checks. Preprod does not weaken those production rules.

## Last accepted exact-seed evidence

The release built from commit `77c50d3` is the last candidate that passed the
full exact-seed test. This is historical evidence. Later source changes affect
runtime images and configuration, so this seed is not the current release.

The Anthropic-only ARM64 production release had 23 external and 17 custom
images. The matching PreProd release had 25 external and 19 custom images. The
PreProd pair adds Samba AD, the WIF provider mock, their build base, and the
archive-only PostgreSQL 16.14 migration source. Exact file hashes, the Envoy
image ID, and the provider-policy hash are in
[TASKS.md](../TASKS.md#complete-current-candidate-release-acceptance).

That historical seed passed these local release checks:

1. Ansible proved a clean boundary and freshly loaded all 44 PreProd images.
2. The full PostgreSQL 16.14 stack passed application and Cribl checks.
3. Each application database received more than 128 MiB of fixed test data.
4. A forced pre-cutover failure restarted the unchanged PostgreSQL 16 source
   and passed the full checks again.
5. Logical restore to PostgreSQL 18.4 kept the Keycloak, LiteLLM, and rotator
   table owners and grants. Each restricted service role could read and write.
6. PostgreSQL 18 passed the full checks. A real downgrade request then failed
   closed without changing data after writes opened.
7. A PostgreSQL 18 physical backup and restore passed the full checks again.
8. A second fresh seed load started the ordinary PostgreSQL 18 graph and
   passed the application, identity, WIF, and Cribl checks.
9. Final exact-manifest cleanup removed every owned container, seed image,
   volume, network, hosts entry, and loopback alias. It preserved all unrelated
   image IDs.

The browser controller available during that run could not start a browser.
The browserless redirect, callback, cookie, role, logout, LDAP, Keycloak, and
portal tests passed. They did not replace a visual browser pass for that seed.

## Current source candidate

The current source includes new private PreProd credential handling, refreshed
same-tag image digests, a private Alertmanager and Grafana alert dashboard, and
model governance, usage, pricing, and limit work. These changes affect runtime
images or configuration. They need a new Anthropic-only schema-v2 seed and a
fresh Ansible PreProd run.

The browser controller is now available. Run the browser checklist against the
new exact-seed deployment. It must also prove that a one-time developer key
does not return after the user leaves the page and uses Back or Forward.

Source-level checks are being rerun while the feature work settles. Record the
final test counts and exact seed hashes only after the same commit passes every
required gate.

The [dated version review](image-version-review.md) found that every selected
image and direct library is current for its reviewed source. The reusable
local Root CA, leaf keys, private credential seed, and rendered inputs remain
after cleanup by design. The seed keeps PreProd identities stable on one
controller without publishing the passwords. These files are not running
deployment state.

## Gates that remain open

- **Current-candidate exact-seed check:** build a fresh ARM64 production and
  PreProd pair, remove only owned PreProd resources and manifest-listed images,
  load the exact PreProd archive, deploy it once through Ansible, and pass the
  full automated checks. Use local Docker only. Do not create a Rocky or
  Parallels rehearsal VM.
- **Current-candidate browser check:** while that exact seed is running, use
  the available browser controller to test redirects, login, roles, cookies,
  logout, and the one-time-key Back and Forward rule. Then revoke the test key.
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
