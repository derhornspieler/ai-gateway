# Image update workflow

Use `scripts/update-images.py` to build, test, deploy, validate, and roll back
image releases. The tool has no saved host, inventory, password, domain, or
provider defaults.

Each release build creates two file pairs:

- a **production** archive and manifest with production images only; and
- a **preprod** archive and manifest with the same production images plus the
  Samba AD and WIF mock images.

The two projections come from one build. Production files never contain the
preprod-only image bytes.

Provider design and CA review are covered in [Provider onboarding](provider-onboarding.md)
and the [Provider CA maintenance SOP](sop/provider-ca-maintenance.md).

## 1. Build the offline release

Create a private directory. Select at least one reviewed provider and build for
the target Docker architecture:

```bash
install -d -m 0700 /srv/ai-gateway-releases/candidate
python3 -I scripts/update-images.py prepare \
  --provider anthropic \
  --platform linux/amd64 \
  --archive /srv/ai-gateway-releases/candidate/aigw-candidate.docker.tar.zst \
  --manifest /srv/ai-gateway-releases/candidate/aigw-candidate.manifest.json
```

Use `linux/arm64` for an ARM64 target. Anthropic is the only approved provider
today. Repeat `--provider` only when a future reviewed catalog contains more
than one needed provider. Names must exist in the committed catalog. The
command has no hostname or CA-file option.

With the names above, the default outputs are:

```text
aigw-candidate.docker.tar.zst
aigw-candidate.manifest.json
aigw-candidate.preprod.docker.tar.zst
aigw-candidate.preprod.manifest.json
```

Use `--preprod-archive` and `--preprod-manifest` together if those sibling
names do not fit your release layout.

The command does all of this:

1. Pulls every exact reviewed tag-and-digest pin.
2. Restores a missing ordinary Docker tag only after checking its digest. The
   update tool automatically enables the narrow
   `--materialize-missing-source-tags` behavior needed by some Docker engines.
3. Validates provider names through the network-disabled catalog planner.
4. Builds a reproducible Envoy image with networking disabled and only the
   selected routes and CA bundles.
5. Builds all other production custom images and the two preprod-only images.
6. Writes separate production and preprod schema-v2 releases with mode `0600`.
7. Checks manifest pins, custom build-input hashes, provider evidence, policy
   digest, image labels, and immutable image IDs against this source.

The manifest's `egress_policy` object records the canonical selected provider
list, provider hostnames and TLS rules, CA fingerprints, provenance hashes,
generated config digest, policy digest, and final Envoy image ID. A different
provider selection changes the policy and image identity.

### Wait for the GitHub container-security gate

Push the reviewed commit to `main`. The **Repository and release container
security** workflow does not allow manual dispatch, so branch-selected workflow
code cannot request DHI release secrets. The workflow reads the committed
`.github/release-container-security.json` selection. It scans every exact
external image and every unique custom image in the full production plus
preprod release set.

The gate requires both DHI secrets. Missing credentials are a failure, not a
skip. Every image must produce a `HIGH`/`CRITICAL` Trivy report, CycloneDX SBOM,
and provenance record. Repository waivers belong in `.trivyignore.yaml`.
Image vulnerability waivers belong in `.github/trivyignore-images.yaml` and
must name an exact versioned package PURL. Every waiver must name an owner,
explain the reason, and expire within one year. Save the workflow URL and the
resolved inventory artifact with the release evidence.

Put the DHI secrets only in a GitHub Environment named
`release-container-security`. Restrict that environment to the protected
`main` branch. Remove repository-level and organization-level copies available
to this repository. A workflow condition is not a secret boundary because
branch code can change the condition. An environment branch rule is the
enforcement point.

This hosted gate rebuilds from the commit. It does not have the offline archive
made on the operator workstation, and its provenance record is not a signed
SLSA statement. Trivy also uses the vulnerability database available when the
job runs. For those reasons, the gate does not replace the exact seeded
preprod test in the next section. Do not run a separate local Trivy scan and
call it the final release result.

## 2. Test the exact preprod seed

When local Docker has the same architecture, add `--test-preprod` to the
`prepare` command:

```bash
python3 -I scripts/update-images.py prepare \
  --provider anthropic \
  --platform linux/amd64 \
  --archive /srv/ai-gateway-releases/candidate/aigw-candidate.docker.tar.zst \
  --manifest /srv/ai-gateway-releases/candidate/aigw-candidate.manifest.json \
  --test-preprod
```

On macOS, also add `--ask-become-pass`. Ansible needs permission to add the
owned `127.0.2.1` and `127.0.3.1` loopback aliases that Docker Desktop lacks.
Linux does not run that privileged alias task.

This fast path activates the generated `.preprod` release from the exact images
that `prepare` just built. It verifies the release receipt but does not unpack
the archive a second time. It does not test the smaller production archive.
Ansible starts the seed image IDs with `pull_policy: never` and no build
sections. The end-to-end test checks Samba LDAPS, automatic Keycloak setup,
static users and roles, WIF token exchange, LiteLLM, Envoy, and the mocked
provider response.

To load and test a copied preprod pair on macOS or Linux, use the preprod
filenames:

```bash
python3 -I scripts/update-images.py test-preprod \
  --archive /srv/ai-gateway-releases/candidate/aigw-candidate.preprod.docker.tar.zst \
  --manifest /srv/ai-gateway-releases/candidate/aigw-candidate.preprod.manifest.json \
  --load-archive
```

On macOS, append `--ask-become-pass`. If the exact images are already loaded
and you need only a development check, omit `--load-archive`.

On Linux, the tool copies caller-owned `0600` files into a digest-scoped,
root-owned staging directory. The root-only loader checks and loads those
copies. An Ansible `always` cleanup proves the staging directory was removed
even when a test fails. On macOS, the Docker Desktop user verifies and loads
the caller-owned private files directly.

Keep the release only if local preprod passes. The detailed checks are in the
[test runbook](test-runbook.md#2-build-and-test-the-offline-release).

`--test-preprod` is the fast development path. Final release evidence must use
the test runbook's clean sequence: build the seed, destroy only namespaced
preprod, load the `.preprod` archive, and let Ansible start with no pull or
build. A green hosted-CI job does not replace that test. A registry-dependent
job that did not complete is not a pass.

## 3. Keep the previous release ready

Automatic rollback needs the actual previous state, source, images, and Envoy
provider policy. Keep:

- the previous production schema-v2 archive and manifest;
- a clean checkout or Git worktree at the previous reviewed commit;
- a new backup path on an independent mounted filesystem; and
- the matching age identity on the controller with mode `0600`.

Example worktree:

```bash
git worktree add /srv/ai-gateway-releases/previous-source release-2026-07-01
```

The candidate and previous checkouts must have no tracked edits. The tool
recalculates external pins and all custom build-input hashes against each
checkout. It also proves that the previous production seed matches the running
images before it takes a backup.

## 4. Upgrade the remote host

Transfer the production pair and independently recorded hashes to the
controller. Do not pass the `.preprod` pair to `upgrade`.

This example is complete. Replace every example value:

```bash
python3 -I scripts/update-images.py upgrade \
  --archive /srv/ai-gateway-releases/candidate/aigw-candidate.docker.tar.zst \
  --manifest /srv/ai-gateway-releases/candidate/aigw-candidate.manifest.json \
  --previous-archive /srv/ai-gateway-releases/previous/aigw-previous.docker.tar.zst \
  --previous-manifest /srv/ai-gateway-releases/previous/aigw-previous.manifest.json \
  --previous-release-dir /srv/ai-gateway-releases/previous-source \
  --inventory /srv/ai-gateway-controller/inventory/hosts.yml \
  --limit gateway01 \
  --vault-id gateway01@/srv/ai-gateway-controller/custody/gateway01.vault-password \
  --ssh-target deployer@gateway01.example.internal \
  --ssh-port 22 \
  --domain example.internal \
  --adm-ip 192.0.2.20 \
  --internal-ip 198.51.100.20 \
  --root-ca /srv/ai-gateway-controller/pki/root-ca.pem \
  --backup-recipient age1example0000000000000000000000000000000000000000000000000000 \
  --rollback-age-identity /srv/ai-gateway-controller/custody/backup-age-identity.txt \
  --remote-backup-root /mnt/ai-gateway-backups \
  --remote-backup-path /mnt/ai-gateway-backups/gateway01-before-image-update.tar.gz.age
```

The provider list is already sealed into the candidate manifest and Envoy
image. `upgrade` does not accept a new provider selection.

The `--ssh-target` and `--ssh-port` values must exactly match `ansible_user`,
`ansible_host`, and `ansible_port` for `--limit`. Direct SSH uses batch mode,
disables forwarding, uses the explicit port, and runs `sudo -n`. Configure a
reviewed noninteractive sudo rule before maintenance.

The backup root must be a dedicated directory. Do not use `/`, `/var`, `/tmp`,
or another broad system root. `state-backup.sh` refuses a destination on the
same block filesystem as the stack. The backup path must be new.

## What happens on the host

1. Ansible stages the previous and candidate production seeds below the
   private `/var/lib/ai-gateway/image-seeds` directory.
2. The loader proves each archive allow-list, release scope, source contract,
   image ID, and Envoy image-policy label binding.
3. The tool proves the previous seed matches the running release.
4. Ansible copies the controller-held age identity to fixed root-only storage
   under `/run` for this workflow only.
5. `state-backup.sh` stops writers, creates an authenticated encrypted backup,
   restarts the original containers, and writes a fresh receipt.
6. `ansible/deploy-stack-only.yml` activates the tested candidate images and
   runs the verify role. The Envoy image and selected-provider policy move as
   one release unit.
7. `scripts/e2e-fresh-vm-check.sh` checks TLS, network planes, Keycloak redirect
   URLs, and the live egress firewall on the actual production host. Its legacy
   filename is kept for compatibility; it does not create or require a test VM.
   Use `--validation-program` to add a reviewed site-specific executable gate.
8. A Python `finally` path invokes the cleanup play and proves the temporary
   age identity is gone.

## Automatic rollback

Any deployment or validation failure starts rollback. The tool:

1. authenticates and restores the encrypted pre-upgrade state archive;
2. runs the full `ansible/site.yml` from the previous clean source checkout;
3. loads the previous production seed instead of rebuilding or pulling;
4. restores the previous Envoy image and its matching provider policy;
5. reruns the same external acceptance gate; and
6. removes the exact restore marker only after validation passes.

If restore, previous-source converge, validation, or temporary-key cleanup
fails, the command exits with `AUTOMATIC ROLLBACK FAILED`. Keep ingress closed
and keep the backup. The workflow never falls back to changing image tags
alone.

An external CA cutover can make an old release unable to reach a provider.
Plan CA rotations with an overlap window by following the
[CA maintenance SOP](sop/provider-ca-maintenance.md#rotation-with-an-overlap-window).

PostgreSQL major changes are refused before staging. Use the separate
[PostgreSQL 18 logical migration SOP](sop/postgresql-18-migration.md). It keeps
the PostgreSQL 16 volume unchanged and closes rollback before PostgreSQL 18
accepts normal application writes.

The workflow does not rewrite source image pins. Change tag-and-digest pins
through normal code review first. `prepare` fetches exactly those reviewed
pins.
