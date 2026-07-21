# Engineering backlog

[TASKS.md](../TASKS.md) is the durable source of truth for task status. This
page gives extra context for a few deferred engineering items. If the two files
disagree, update `TASKS.md` first and then repair this page.

## Finish the plain-language documentation review

The active guides now separate local preprod from production. CI checks active
links, heading bookmarks, code fences, local images, and Mermaid node labels.
The release rehearsal uses the offline seed in local Docker preprod. It does
not require a Rocky or Parallels test VM.

The remaining work is a human review:

- Ask a new operator to follow the local preprod path without verbal help.
- Ask a production operator to review the production path and commands.
- Replace any sentence or diagram they cannot understand on the first read.
- Keep uncommon security terms, but define them in plain language.
- Save the link-check result and review notes with the release evidence.

## Run a full security audit

- Review authentication, authorization, secret handling, network boundaries,
  file permissions, command execution, backups, upgrades, and rollback code.
- Review Ansible, Compose, Python, Go, shell, and CI workflows by hand and with
  the appropriate static-analysis tools.
- Use the main/manual GitHub container-security workflow to build every custom
  image and resolve the exact image IDs used by the committed release scan.
- Review its Trivy result for every exact upstream and custom image in the
  committed release, plus the repository scan. Do not substitute an unrecorded
  local scan.
- Review each finding. Fix it or record a time-limited waiver with an owner and
  reason.
- Verify SBOM and provenance data for DHI images and custom builds.
- Publish a dated report with commands, tool versions, image IDs, findings, and
  remaining risk.

## Rehearse the PostgreSQL 18 migration with production-sized data

The source now pins PostgreSQL `18.4`. The image, data path, explicit physical
volume name, backup checkpoint, logical restore tool, Ansible migration
playbook, fail-closed cutover, and operator SOP are implemented. The normal
image updater still refuses a PostgreSQL major change.

PostgreSQL 18.4 is a stable release. A bounded ARM64 check on 2026-07-21 ran
the same application, logical-restore, and physical-restore checks against the
exact DHI PostgreSQL 17.10 and 18.4 images. Both passed. The operator selected
18.4. This does not close the seeded preprod or production-sized rehearsal
gates below.

The remaining work needs real deployment evidence:

- build the exact image into the offline seed;
- start a clean local preprod stack on PostgreSQL 18;
- create production-sized PostgreSQL 16 test data;
- run the complete encrypted backup and logical migration;
- test LiteLLM, Keycloak, Grafana, and key-rotator after cutover;
- force a restore failure and prove the pre-cutover PostgreSQL 16 rollback;
- force a post-cutover failure and prove downgrade is refused; and
- test a same-major PostgreSQL 18 physical backup restore on a clean host.

There is no recorded technical reason why the first project commit used
PostgreSQL 16. The likely reason was a conservative first choice, but that is
an inference. Read the
[PostgreSQL 18 migration SOP](sop/postgresql-18-migration.md) before running
this rehearsal.

## Review every container image version

- Inventory every DHI and non-DHI image, including build-stage images.
- Record the upstream release, support status, current fix release, digest,
  platform, and reason for the selected major.
- Prefer a current supported release. Keep an older major only when a tested
  compatibility or migration reason is written down.
- Pull and build by digest, scan the exact result, run it in local preprod, and
  test rollback before changing production.
- Repeat the review on a schedule and when an upstream security advisory lands.

DHI tags are versioned and images can be pinned by digest. A newer tag must
still pass this repository's compatibility and rollback tests before it is
promoted. See the [DHI digest guidance](https://docs.docker.com/dhi/core-concepts/digests/).
