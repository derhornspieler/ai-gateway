# Engineering backlog

This page is the public engineering backlog. It contains product work only.

The PostgreSQL 18 release test and the image/dependency version review are
complete. See the [dated version review](image-version-review.md).

## Finish the plain-language documentation review

The active guides now separate local preprod from production. The automated
documentation gate checks:

- local links and heading bookmarks;
- code fences;
- local image links;
- Mermaid syntax and node labels; and
- navigation between related pages.

The diagrams and main design guides were checked against the deployed code.
The release test uses the offline seed in local Docker preprod. It does not use
a Rocky or Parallels test VM.

One human plain-language review remains:

1. Ask a new operator to follow local preprod with no verbal help.
2. Ask a production operator to review the production commands.
3. Fix any sentence, command, or diagram they cannot follow the first time.
4. Define any security word they do not know.
5. Save the notes and final link report with release evidence.

## Finish alert dashboard acceptance

The source includes a private Alertmanager, Prometheus alert rules, and the
Grafana **AI Gateway Alerts and Capacity** dashboard. Prometheus is the only
rule evaluator. Grafana is the operator UI. Alertmanager has no host port or
FQDN, and it sends no direct notification to Cribl.

Keep this work open until the current exact seed proves the live watchdog,
active and resolved alerts, fault recovery, and dashboard data. Local Docker
cannot prove Rocky host network, container restart, Vault seal, or backup
signals. Do not report those gaps as passed and do not add a privileged Docker
socket collector to make the test green. See
[observability operations](observability-operations.md#local-alerts).

## Run a full security audit

Review the full code and release, including:

- login, roles, secrets, networks, files, commands, backup, upgrade, and
  rollback;
- Ansible, Compose, Python, Go, shell, and GitHub Actions;
- every exact upstream and custom image in the release;
- SBOM and provenance data; and
- every open finding or waiver.

Use the GitHub container-security workflow for the release scan. It must build
the custom images, resolve exact image IDs, and run Trivy on source and images.
Do not replace it with an unrecorded local scan.

The protected GitHub environment now has approved DHI secrets. Keep the login
gate fail closed. Run the workflow to completion, then fix each finding or add
a short waiver with an owner, reason, and end date.

Publish a dated report. Include commands, tool versions, image IDs, findings,
fixes, waivers, and remaining risk.

## Recheck current upstream container findings

The [dated scan report](container-security-report-2026-07-22.md) records the
current findings, one per image and advisory, with fixed versions where they
exist. The release scan stays red when an upstream image contains an unpatched high
or critical finding. Do not hide these findings and do not add a broad local
waiver. Keep the newest reviewed image pin until its publisher releases a
fixed tag, a rebuilt digest, or a signed VEX statement that applies to the
exact image.

After a fix is available:

1. Update the exact tag and digest.
2. Build a new schema-v2 offline seed.
3. Load that exact seed into local PreProd.
4. Run the full Ansible, application, identity, telemetry, and rollback tests.
5. Require the GitHub image scan to pass for the new image ID.

## Finish the release-file custody and permission review

A release archive or manifest copied to another machine used to be rejected
unless its mode was exactly `0600` and its group matched the operator's
group. An operator hit this in the field: a normal copied file (mode `0644`)
could not be loaded into local Docker. The local checks now accept any
caller-owned file that no other user can write, because content integrity
comes from the SHA-256 checks, not from read permissions.

Remaining work:

1. Map every custody check across the image update, seed rebuild, seed
   loader, PreProd staging, and remote upgrade code. Decide which checks
   protect the release while it is built and which still apply after a
   transfer.
2. Review the parent-directory lineage rules for safe shared locations.
   Keep rejecting directories another user can write.
3. Support safe root-owned and Ansible-staged files on the controller.
4. Keep every fail-closed rule for symlinks, hard links, replacement during
   verification, wrong SHA-256, and manifest mismatches.
5. Make every rejection name the path, the failed rule, and a safe repair
   command.
6. Add macOS and Linux contract tests for the safe and unsafe cases.
7. Update the seed and image-update guides to explain ownership, write
   permission, custody, and integrity in plain language.

## Explore Admin Portal access to Grafana dashboards

A future convenience feature, not part of the current release. Compare a
normal link to the existing admin-only Grafana origin against embedded
panels. Prefer the link unless embedding has a clear operator benefit. Any
iframe work first needs a review of CSP, clickjacking, cross-origin cookies,
OIDC redirects, logout, role checks, and the ADM-only network boundary. Never
copy a Grafana token or session cookie into the portal. An ADR, browser
tests, and rollback steps come before implementation.

## Finish model controls, pricing, and routing

The current model-control work has a durable
[implementation plan](model-governance-plan.md). It covers:

- hidden models tied to the immutable provider release;
- per-model usage and hard limits;
- admin-managed, effective-dated, and backdated token prices;
- model, project, user, cache, and cost dashboards;
- audited Alloy-to-Cribl events over OTLP/gRPC and TLS; and
- a disabled local-only automatic-routing prototype.

The [automatic routing ADR](automatic-model-routing-adr.md) compares the safe
choices and keeps the proposed router disabled until its release tests pass.

The governed catalog, lifecycle, filtered discovery, project assignment gate,
two per-model output controls, prompt-free usage ledger, five-part configured
cost, backdate adjustment flow, and usage dashboard are complete in source.
They have unit, contract, portal, application-schema, and PostgreSQL 18
coverage plus seed-only PreProd acceptance harnesses. They are not
release-accepted until the new exact seed, browser, Grafana, Cribl, backup,
restore, and rollback gates pass. Automatic routing remains design-only and
disabled.
