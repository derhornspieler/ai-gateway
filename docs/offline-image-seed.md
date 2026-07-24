# Offline image releases

An offline release has two private files:

- a Docker archive named `*.docker.tar.zst`; and
- a JSON manifest named `*.manifest.json`.

Schema v2 makes two file pairs from one build:

| Scope | Contents | Use |
| --- | --- | --- |
| `production` | All production image references | A production VM |
| `preprod` | Production plus test services and their build base | Local preprod |

The production archive has no preprod-only image bytes. Do not send the
preprod pair to a production host.

At this source revision, production has 24 external and 19 custom references,
for 43 total. Preprod has 25 external and 21 custom references, for 46 total.
The production count now includes the Alertmanager base and custom image and
the reviewed LiteLLM security derivative.
Samba AD and the WIF provider mock are the two preprod-only custom services.
Their Debian 13.6-slim base is also preprod-only. None of these three extra
references enters the production archive. Both scopes contain the same exact
PostgreSQL 18 runtime image; neither scope contains an older PostgreSQL major.

Schema v1 is still accepted for old external-only seeds. Use schema v2 for all
new releases.

## Build both release pairs

Most operators should follow the
[build offline seed SOP](sop/build-offline-seed.md), which wraps this in a
numbered checklist. Run the updater from the repository root:

```bash
python3 -I scripts/update-images.py prepare \
  --provider anthropic \
  --platform linux/amd64 \
  --archive /absolute/private/path/aigw-2026-07-22-linux-amd64.docker.tar.zst \
  --manifest /absolute/private/path/aigw-2026-07-22-linux-amd64.manifest.json
```

Use `linux/arm64` for an ARM64 target. Anthropic is the only approved provider
today. A provider name must exist in the reviewed catalog. The tool has no
option for a custom hostname or CA path.

The command creates these four files:

```text
aigw-2026-07-22-linux-amd64.docker.tar.zst
aigw-2026-07-22-linux-amd64.manifest.json
aigw-2026-07-22-linux-amd64.preprod.docker.tar.zst
aigw-2026-07-22-linux-amd64.preprod.manifest.json
```

All paths must be absolute and different. The tool writes each file with mode
`0600`. Use a new dated name for each release.

The manifest is generated proof. Do not edit it. Keep it with the archive,
hashes, source commit, and test record.

Follow the [image update workflow](image-update-workflow.md) for the full
build, test, upgrade, and rollback process.

## Lower-level builder

This command is for release-tool maintenance. Normal operators should use
`update-images.py`.

```bash
install -d -m 0700 "$PWD/private/offline-images/2026-07-22-linux-amd64"
python3 -I scripts/rebuild-offline-image-seed.py \
  --prepare-release \
  --provider anthropic \
  --platform linux/amd64 \
  --materialize-missing-source-tags \
  --allow-unprivileged-controller \
  "$PWD/private/offline-images/2026-07-22-linux-amd64/aigw-2026-07-22-linux-amd64.docker.tar.zst" \
  "$PWD/private/offline-images/2026-07-22-linux-amd64/aigw-2026-07-22-linux-amd64.manifest.json"
```

`update-images.py prepare` adds
`--materialize-missing-source-tags` for you. Some Docker engines pull a digest
but do not restore its normal tag. This flag adds the tag only after the tool
checks the digest.

The Docker engine must be local. Unix sockets are allowed. TCP and SSH Docker
endpoints are refused.

If `dhi.io` refuses a pull, log in with the same local Docker client:

```bash
docker login dhi.io
```

Registry credentials do not enter the archive or manifest.

## What the builder does

The builder:

1. Finds each exact tag and digest pin in reviewed source.
2. Pulls each pin for the target platform.
3. Checks each digest.
4. Restores a missing source tag when needed.
5. Renders the production and preprod Compose models.
6. Checks the selected provider through the catalog.
7. Builds Envoy with no build network.
8. Adds only the selected routes and CA files to Envoy.
9. Builds the other custom images without pulling new base tags.
10. Records each custom build-input hash and image ID.
11. Exports the production and preprod image sets on their own.
12. Checks each archive list before it publishes files.

If any step fails, no release is accepted.

## What schema v2 records

The manifest records:

- the release scope and target platform;
- the archive name and image counts;
- each external tag, digest, and image ID;
- each custom transfer tag and image ID;
- each custom image's production or preprod scope;
- each custom build-input hash; and
- one Envoy egress-policy receipt.

The egress receipt records:

- selected providers in sorted order;
- provider hostnames, route prefixes, SNI, and exact SAN rules;
- CA filenames, bundle hashes, certificate fingerprints, and source hashes;
- generated config and policy hashes; and
- the final Envoy image ID.

The archive list must match the manifest. Extra, missing, or duplicate image
entries fail before Docker loads the archive.

Never put passwords, tokens, private keys, or customer data in either file.

## Envoy image and policy binding

The loader rebuilds the policy hash from the manifest. It finds the production
Envoy image. That image ID must match `egress_policy.envoy_image_id`.

It also checks these image labels:

```text
com.aigw.egress-policy.schema
com.aigw.egress-policy.providers
com.aigw.egress-policy.sha256
```

The labels must match the manifest. This stops one provider policy from being
paired with a different Envoy image. Upgrade and rollback move the image and
policy as one release unit.

At startup, the Envoy gate checks the policy, config, CA file list,
fingerprints, dates, SNI, and SAN rules. It fails closed for missing, extra,
bad, or expired CA data. It does not download trust data during deployment.

## Stage a production pair

One command copies the release to the VM and fills in the inventory. Give
`--release-dir` the **folder** holding the release files, not a file inside
it:

```bash
python3 -I scripts/stage-production-seed.py \
  --release-dir /absolute/private/path/2026-07-22-linux-amd64 \
  --inventory ansible/inventory/generated/mygateway/hosts.yml \
  --limit mygateway \
  --vault-id mygateway@/secure/path/mygateway.vault-password
```

It picks the production pair (never the `.preprod` one), reads both SHA-256
values from the files, copies them to a private root-owned directory on the
VM, checks the bytes again there, and then writes these five values into
`host_vars/mygateway.yml` for you:

```yaml
offline_image_seed_enabled: true
offline_image_seed_remote_path: "/var/lib/ai-gateway/image-seeds/candidate-<16-hex>/aigw-2026-07-22-linux-amd64.docker.tar.zst"
offline_image_seed_sha256: "<archive-sha256>"
offline_image_seed_manifest_remote_path: "/var/lib/ai-gateway/image-seeds/candidate-<16-hex>/aigw-2026-07-22-linux-amd64.manifest.json"
offline_image_seed_manifest_sha256: "<manifest-sha256>"
```

You never type a hash. The release is still pinned by exact SHA-256 at every
hop: the file on the controller, the copy on the VM, and every image the
loader unpacks.

Add `--print-only` to see the five values without writing them. Add
`--expect-manifest-sha256 <hash>` when you hold the release hash from a
separate record — the copy then refuses to start unless the file matches.

Your release files must be owned by you and not writable by any other user.
Normal copied permissions (`0644`) are fine. The staged copy on the VM is
created as `root:root` mode `0600`.

For a later image update, use `scripts/update-images.py upgrade` instead. It
does all of this and adds the backup, rollback, and validation steps.

## What Ansible checks

Ansible runs `scripts/load-offline-image-seed.py`. The loader checks:

1. all five inventory values;
2. safe paths, owner, mode, file size, and hashes;
3. platform, scope, and schema;
4. source pins and custom build-input hashes;
5. the Envoy policy receipt;
6. the archive image list;
7. external image digests and IDs; and
8. custom image IDs and Envoy labels.

The loader writes a root-owned receipt only after every check passes. Schema-v2
custom images are not rebuilt on the production host.

Before activation, Ansible saves the exact running custom image IDs under
rollback tags. It then starts the normal stack and runs the verify role. A bad
load, check, activation, health test, or outside validation stops the run.

## Check a loaded preprod release

The normal path is:

```bash
python3 -I scripts/update-images.py test-preprod \
  --archive /absolute/private/path/aigw-2026-07-22-linux-amd64.preprod.docker.tar.zst \
  --manifest /absolute/private/path/aigw-2026-07-22-linux-amd64.preprod.manifest.json \
  --load-archive \
  --become-password-file "$HOME/.ssh/become"
```

Use `--ask-become-pass` instead when you want an interactive sudo prompt.

This is a clean-room load. The updater first runs
`ansible/preprod-clean-room.yml`. That play checks the preprod manifest,
proves Docker is local, and checks the Linux root loader socket before any
change. It then destroys and proves removal of only owned preprod resources,
removes only the image aliases and IDs listed in the manifest, proves those
images are absent, then removes the bounded hosts block and owned loopback
aliases. If cleanup fails, staging and deploy do not start.

After the absence proof, rootful Linux gets a private staging copy. Docker
Desktop uses the caller-owned files. The loader must return exactly
`LOADED <archive-sha256>`. `SKIPPED` or `RELOADED` fails this release path.
The updater then runs `ansible/preprod.yml` once for seed activation, deploy,
and acceptance. Seed mode has no pull or build sections. The play installs the
bounded preprod hosts block for browser tests.

After all release tests, tear the stack down against the same exact pair with
`scripts/preprod-down.sh --seed <the release folder>`. That final receipt
must prove every owned resource and every manifest-listed image is absent. It
must also prove that unrelated image IDs are unchanged. Ordinary cleanup does
not provide this release proof. See
[final release teardown](preprod.md#finish-with-exact-manifest-teardown).

The become password file, when used, must be an absolute, caller-owned,
mode-`0600` regular file with one hard link and no symbolic link. The updater
does not read or copy it. It passes only its path to Ansible.

Running `test-preprod` without `--load-archive` is a quick check of images that
are already present. It skips the clean-room and load steps. Do not use it as
release evidence.

The lower-level receipt command is for troubleshooting. It is the one command
here that takes a hash as an argument, so let the shell supply it:

```bash
REL=/absolute/private/path/aigw-2026-07-22-linux-amd64
python3 -I scripts/load-offline-image-seed.py local-release-receipt \
  "$REL.preprod.docker.tar.zst" \
  "$REL.preprod.manifest.json" \
  "$(shasum -a 256 "$REL.preprod.manifest.json" | cut -d' ' -f1)" \
  "$(pwd)"
```

Run that command as the local Docker user, not root. It accepts only a local
Unix Docker socket and caller-owned files that no other user can write. A
copied file with normal read permissions (mode `0644`) is fine.

## Recovery and retention

Keep both release pairs and the last known-good production release. Keep their
hashes, source commits, provider choices, and CA evidence.

If a seeded image is pruned, the next converge sees the missing image and
reloads the staged archive. Do not reuse a release after a source pin, build
input, provider choice, or CA record changes. Build a new release.

Clean-room preprod is local-only. Never run its purge flow on a production
host. Production uses the staged production pair, an encrypted backup,
validation, and automatic rollback from the
[image update workflow](image-update-workflow.md#4-upgrade-the-remote-host).

Run the seed contract tests from the repository root:

```bash
python3 -I -m unittest discover -v -s scripts/tests \
  -p 'test_rebuild_offline_image_seed.py'
python3 -I -m unittest discover -v -s scripts/tests \
  -p 'test_load_offline_image_seed.py'
```

## Related pages

- [Image update workflow](image-update-workflow.md)
- [Local preprod](preprod.md)
- [Acceptance test runbook](test-runbook.md)
