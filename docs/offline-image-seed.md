# Offline image releases

An offline image release is a private pair of files:

- a compressed Docker archive ending in `.docker.tar.zst`; and
- a JSON manifest ending in `.manifest.json`.

A schema-v2 build publishes two release pairs:

- `release_scope: production` contains external and custom production images;
- `release_scope: preprod` contains the same production images plus the Samba
  AD and WIF mock images.

Production archives do not contain preprod-only image bytes. Local preprod
uses the preprod pair. A remote production deployment uses the production
pair. Both projections come from the same reviewed build.

The older schema-v1 format is still accepted for external images only. A v1
target builds custom images locally with `--pull=false`. Use schema v2 for new
releases.

For the normal prepare, local test, remote upgrade, validation, and rollback
cycle, follow the [image update workflow](image-update-workflow.md). This page
documents the lower-level seed and manifest contract.

## Prepare both release pairs

Run from the repository root. Use the architecture of the remote Docker host:

```bash
install -d -m 0700 "$PWD/private/offline-images"
python3 -I scripts/rebuild-offline-image-seed.py \
  --prepare-release \
  --provider anthropic \
  --platform linux/amd64 \
  --materialize-missing-source-tags \
  --allow-unprivileged-controller \
  "$PWD/private/offline-images/aigw-release-linux-amd64.docker.tar.zst" \
  "$PWD/private/offline-images/aigw-release-linux-amd64.manifest.json"
```

Use `linux/arm64` for an ARM64 target. Anthropic is the only approved provider
today. At least one provider is required. Names must exist in the
[reviewed provider catalog](provider-onboarding.md#catalog-files). The command
does not accept arbitrary provider hostnames or CA paths.

The production output names above also create these default preprod siblings:

```text
aigw-release-linux-amd64.preprod.docker.tar.zst
aigw-release-linux-amd64.preprod.manifest.json
```

Use `--preprod-archive` and `--preprod-manifest` together to set different
absolute paths.

All four output paths must be distinct and absolute. Each file is published
atomically with mode `0600`. Use a new name or directory for each release. If
a stopped build leaves files from two releases, their hashes and bundle names
will not match, so validation fails before Docker loads an image.

The higher-level `update-images.py prepare` command is preferred. It enables
the same `--materialize-missing-source-tags` flag automatically. This narrow
flag handles Docker engines that pull a digest without restoring its ordinary
tag. The builder creates the tag only after it checks the immutable digest.

## What the builder does

`--prepare-release` performs these steps:

1. Collect every literal external `tag@sha256` pin from reviewed Compose and
   Dockerfile source.
2. Pull each exact pin for the requested platform.
3. Verify each digest before restoring any missing ordinary source tag.
4. Render the production and preprod Compose models.
5. Run the reviewed Envoy provider planner with networking disabled.
6. Build the Envoy image with networking disabled, reproducible timestamps,
   and only the selected provider policy and CA files.
7. Build the other custom images with `--pull=false`.
8. Calculate the source and build-definition digest for every custom service.
9. Give each custom image a transfer tag derived from its immutable image ID.
10. Export the production and preprod image sets separately.
11. Verify each archive allow-list before publishing any output.

The Docker daemon must be local. UNIX sockets are accepted. TCP and SSH Docker
endpoints are refused. If a private registry rejects a pull, authenticate the
same local Docker client and retry:

```bash
docker login dhi.io
```

Registry credentials stay with the local Docker client. They are not written
to an archive or manifest.

## Release scopes

The two schema-v2 projections have different custom-image sets:

| Scope | Contents | Allowed use |
|---|---|---|
| `production` | Reviewed external images and production custom images only | Transfer to and activate on the Rocky Linux production host |
| `preprod` | All production images plus `ai-gateway/samba-ad:preprod` and `ai-gateway/wif-provider-mock:preprod` | Load into local Ansible preprod and run end-to-end tests |

The loader rejects preprod-only images in a production manifest. It also
rejects a preprod manifest that lacks either preprod-only image.

## Schema-v2 manifest guarantees

Every schema-v2 manifest records:

- exact `release_scope` and target platform;
- archive bundle name and image counts;
- every external `tag@sha256` reference and immutable image ID;
- every custom image, transfer tag, immutable image ID, deployment scope, and
  activation rule;
- exact build-input digest for every included custom service; and
- one immutable `egress_policy` receipt.

The `egress_policy` object records:

- schema version;
- generated egress-policy SHA-256;
- generated Envoy config SHA-256;
- selected provider names in sorted, unique order;
- provider hostnames, route prefixes, SNI, and exact SAN requirements;
- selected CA filenames, complete bundle hashes, ordered certificate
  fingerprints, and provenance hashes; and
- final Envoy image ID.

The archive allow-list must exactly match the manifest. Extra tags, missing
tags, duplicate tags, unapproved OCI descriptors, and custom tags whose image
config does not match the recorded image ID are rejected before Docker loads
the archive.

Do not put passwords, registry tokens, private keys, or customer data in an
archive or manifest.

## Envoy image and policy binding

The loader recalculates the canonical policy digest from the manifest. It then
finds the one production Envoy custom image and requires its ID to equal
`egress_policy.envoy_image_id`.

After loading, it inspects these image labels:

```text
com.aigw.egress-policy.schema
com.aigw.egress-policy.providers
com.aigw.egress-policy.sha256
```

The labels must match the manifest's schema, canonical provider list, and
policy digest. A manifest cannot pair one provider policy with another Envoy
image. Deployment and rollback therefore treat the image and policy as one
release unit.

The final image contains only selected provider routes and CA files. At
startup, its compiled gate checks policy and config digests, certificate
fingerprints and dates, exact SAN and SNI rules, and missing or unexpected CA
files. It does not download trust material or use the system CA store as a
fallback.

## Stage the production pair on a remote host

Set these five inventory values. Paths are on the remote Docker host:

```yaml
offline_image_seed_enabled: true
offline_image_seed_remote_path: /var/tmp/aigw-release-linux-amd64.docker.tar.zst
offline_image_seed_sha256: <archive-sha256>
offline_image_seed_manifest_remote_path: /var/tmp/aigw-release-linux-amd64.manifest.json
offline_image_seed_manifest_sha256: <manifest-sha256>
```

Use the production pair, not the `.preprod` pair. Transfer both files to
temporary names. Independently verify their SHA-256 values, then install them
at the inventory paths as regular, non-symlink files owned by `root:root` with
mode `0600`.

Example controller hash command:

```bash
shasum -a 256 \
  "$PWD/private/offline-images/aigw-release-linux-amd64.docker.tar.zst" \
  "$PWD/private/offline-images/aigw-release-linux-amd64.manifest.json"
```

## What Ansible and the loader do

The `docker_stack` role installs and runs
`scripts/load-offline-image-seed.py`. The loader:

1. validates the complete opt-in contract;
2. checks trusted path ancestry, root ownership, mode `0600`, size limits,
   hashes, platform, release scope, and manifest schema;
3. validates custom build inputs and the complete Envoy policy receipt;
4. reads bounded OCI metadata and proves the archive allow-list before load;
5. streams the archive through `zstd` to the local Docker daemon;
6. checks every external RepoDigest and image ID;
7. checks every custom transfer-tag image ID and Envoy policy label; and
8. writes a root-owned release receipt only after all checks pass.

Before a custom Compose tag changes, Ansible compares active source and
build-input digests with the manifest. A mismatch stops deployment. It saves
the exact running image IDs under rollback tags before it activates the tested
custom image IDs. Schema-v2 images are never rebuilt on the target.

The normal Compose deployment and verify role run after activation. A failed
load, parity check, preservation, activation, readiness check, or external
validation stops the converge.

## Validate a loaded preprod release

Local preprod can request a machine-readable receipt after loading the preprod
pair:

```bash
python3 -I scripts/load-offline-image-seed.py local-release-receipt \
  "$PWD/private/offline-images/aigw-release-linux-amd64.preprod.docker.tar.zst" \
  "$PWD/private/offline-images/aigw-release-linux-amd64.preprod.manifest.json" \
  <preprod-manifest-sha256> \
  "$PWD"
```

Run this as the desktop Docker user, not root. It accepts only a local
`unix://` Docker endpoint and caller-owned mode-`0600` files. It recalculates
source pins and build-input digests before issuing the receipt.

Each key under `custom_images` is a canonical image name. Its
`archive_reference` is the content-addressed tag used with `pull_policy:
never`. Its `image_id` is the exact ID checked immediately before startup. The
receipt also includes the validated egress policy.

The root-only `release-receipt` command is used on deployed Linux hosts.

## Recovery and retention

The checksum marker lives in `offline_image_seed_marker_dir`, which defaults to
`<docker_data_root>/.aigw-image-seeds`. If a seeded image is pruned, the next
converge detects it, removes the stale marker, and reloads the still-staged
archive.

Keep both release pairs, their independent hashes, and the previous known-good
production release until the candidate is accepted or retired. Do not reuse a
release after source pins, custom build inputs, provider selection, or CA
evidence change. Build and test a new release.

Run the focused contract tests from the repository root:

```bash
python3 -I -m unittest discover -v -s scripts/tests \
  -p 'test_rebuild_offline_image_seed.py'
python3 -I -m unittest discover -v -s scripts/tests \
  -p 'test_load_offline_image_seed.py'
```
