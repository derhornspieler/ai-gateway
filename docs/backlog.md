# Engineering backlog

[TASKS.md](../TASKS.md) is the source of truth for task status. This page adds
short notes for the largest open jobs. If the files differ, fix `TASKS.md`
first.

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

One human plain language review remains. It is tracked in
[TASKS.md](../TASKS.md#run-a-new-operator-documentation-usability-review):

1. Ask a new operator to follow local preprod with no verbal help.
2. Ask a production operator to review the production commands.
3. Fix any sentence, command, or diagram they cannot follow the first time.
4. Define any security word they do not know.
5. Save the notes and final link report with release evidence.

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

The workflow currently stops at its required DHI login gate because the
protected GitHub environment has no approved DHI secrets. Do not weaken that
gate. Add approved secrets, rerun the workflow, then fix each finding or add a
short waiver with an owner, reason, and end date.

Publish a dated report. Include commands, tool versions, image IDs, findings,
fixes, waivers, and remaining risk.

## Rehearse the PostgreSQL 18 migration with production-sized data

The source pins stable PostgreSQL `18.4`. The migration playbook and
[operator SOP](sop/postgresql-18-migration.md) are implemented.

Earlier ARM64 seed tests started a clean PostgreSQL 18.4 preprod stack.
LiteLLM, Keycloak, key-rotator, and Grafana passed. Smaller tests also proved
PostgreSQL 16 logical restore and PostgreSQL 18 same-major physical restore.
Those dated results do not approve the current source candidate.

The remaining job needs production-sized test data:

1. Build the current Anthropic-only schema-v2 seed.
2. Start the test from a clean local Docker preprod boundary.
3. Create a large, realistic PostgreSQL 16 test backup.
4. Run the full encrypted backup and logical 16-to-18 migration locally.
5. Test every database client after cutover.
6. Force a failure before cutover and prove the pre-cutover PostgreSQL 16 rollback.
7. Force a post-cutover failure and prove downgrade is refused.
8. Restore a PostgreSQL 18 physical backup in local preprod.
9. Run the exact-manifest clean-room teardown and save its absence proof.

Do not create a separate test host or VM. Do not run forced-failure tests on
production. This item is tracked in [TASKS.md](../TASKS.md).

Git history gives no technical reason for the first PostgreSQL 16 choice. It
may have been a careful first choice, but that is only an inference.

## Review every container image version

This item is tracked in
[TASKS.md](../TASKS.md#review-every-container-image-and-language-dependency-version).

For each DHI and non-DHI image, including build images, record:

- current pin and digest;
- newest supported stable release;
- support state and security fixes;
- CPU platform;
- DHI availability; and
- the reason for its selected major version.

Prefer the newest tested stable release. Keep an older release only when a
written compatibility or migration reason exists.

A 2026-07-21 review found newer upstream releases for a few services that were
not yet present in DHI. The current release keeps the newest compatible DHI
pin rather than changing registries without review. Traefik uses the current
patched upstream binary on the reviewed DHI runtime.

For each promoted pin, build by digest, create the schema-v2 seed, destroy the
owned preprod stack and old release images, load the seed, deploy with Ansible,
run the full local test, and prove rollback. Scan the exact release in GitHub
Actions before production approval.

Repeat this review on a schedule and after an upstream security notice. See the
[image update workflow](image-update-workflow.md) and
[DHI digest guide](https://docs.docker.com/dhi/core-concepts/digests/).
