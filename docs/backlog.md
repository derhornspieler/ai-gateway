# Engineering backlog

[TASKS.md](../TASKS.md) is the source of truth for task status. This page adds
short notes for the largest open jobs. If the files differ, fix `TASKS.md`
first.

The production-size PostgreSQL 18 rehearsal and the image/dependency version
review are complete. See the [dated version review](image-version-review.md)
and the Done section in [TASKS.md](../TASKS.md#done).

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

## Plan model controls, pricing, and routing

The future model-control work now has a durable
[implementation plan](model-governance-plan.md). It covers:

- hidden models tied to the immutable provider release;
- per-model usage and hard limits;
- admin-managed, effective-dated, and backdated token prices;
- model, project, user, cache, and cost dashboards;
- audited Alloy-to-Cribl events over OTLP/gRPC and TLS; and
- a disabled local-only automatic-routing prototype.

This plan is not a finished feature. Follow its phased tests, migrations, and
rollback gates after the current release work is complete.
