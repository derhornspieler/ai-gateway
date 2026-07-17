# Offline external-image seed

The deployment can optionally load a pre-staged, secret-free Docker archive
before any Compose validation or build needs an external image. This is a
bootstrap aid for a host that cannot authenticate to one or more image
registries — the committed lab is exactly that case, since the clean
VM has no DHI registry credential. It is not a substitute for normal image
provenance review, and it never exports or accepts locally built
`ai-gateway/*` outputs. For where this fits in a lab converge see the lab-deployment
section of the [deployment guide](deploy-guide.md); for image provenance overall
see [solution-map.md](solution-map.md).

## What the seed carries

The archive holds every literal digest-pinned external image in the reviewed
Compose and Dockerfile sources — exactly the set
`scripts/rebuild-offline-image-seed.py` collects: the directly run DHI pins
(`busybox`, `postgres`), the DHI base images that each locally built
`ai-gateway/dhi-*:<ver>-probe` derivative is built FROM (oauth2-proxy,
keycloak, vault, redis, alloy, prometheus, node-exporter, loki, grafana, and
the OpenTelemetry Collector, plus both the DHI Traefik runtime base and the
upstream Traefik binary source that the patched Traefik image combines), the
two non-DHI upstream bases for the application exceptions LiteLLM and Open
WebUI, the upstream `hashicorp/vault` release image that the `vault-ui-proxy`
build parses for its embedded UI assets, the pinned BuildKit Dockerfile
frontend, and the public Debian base for the lab-only Samba build.

By assertion it carries no `ai-gateway/*` image: the `-probe` derivatives, the
two Traefik edges, and the portals are always built on the VM from the seeded
bases. A generic/customer inventory must make its own reviewed decision about
which of these external images to pre-stage and must never copy the lab paths
or hashes by habit.

## Enabling the feature

Generic/customer defaults are disabled and pathless. Enabling it requires the
opt-in flag plus four environment-specific inventory values, and partial
configuration fails closed:

```yaml
offline_image_seed_enabled: true
offline_image_seed_remote_path: /var/tmp/<reviewed>.docker.tar.zst
offline_image_seed_sha256: <64-lowercase-hex-archive-digest>
offline_image_seed_manifest_remote_path: /var/tmp/<reviewed>.manifest.json
offline_image_seed_manifest_sha256: <64-lowercase-hex-manifest-digest>
```

These are target-host paths, not controller paths. Pre-stage both files as
regular, non-symlink files owned by `root:root` with mode `0600`. Transfer to a
non-final temporary name, verify the independently obtained hashes, and use
`install -o root -g root -m 0600` or an equivalent atomic promotion into the
inventory paths. Do not put credentials, registry tokens, or customer secrets in
either artifact.

## Fail-closed load sequence

The `docker_stack` role runs `scripts/load-offline-image-seed.py` as
`/usr/local/sbin/aigw-load-offline-image-seed`, which performs the following:

1. Require the complete explicit opt-in contract; partial configuration fails.
2. Prove Docker is started after the host firewall roles, then use the `zstd`
   package installed by the OS baseline. The loader normalizes and pins the
   target platform to the running daemon's own architecture.
3. Verify manifest ownership, mode, the 1 MiB size bound, exact SHA-256,
   schema, target platform, archive name, image count, and the
   zero-custom-image assertion.
4. Require every manifest image to have an exact `tag@sha256` reference and an
   immutable 71-character expected image ID, with no duplicate references.
5. Trust an existing root-owned checksum marker only when all required
   references still resolve to the expected RepoDigest and image ID.
6. Otherwise verify the archive ownership, mode, exact SHA-256, and zstd
   integrity; stream it through `zstd --decompress` into `docker image load`;
   then repeat every per-image check.
7. Atomically write a root-owned `0600` marker only after post-load validation
   succeeds. The marker directory is root-owned `0700` under Docker's data root
   (`offline_image_seed_marker_dir`, default `<docker_data_root>/.aigw-image-seeds`),
   so resetting Docker state also removes the skip decision.

The marker filename combines both digests, and its body is the exact
`<archive> <manifest>` digest pair; a marker whose ownership, mode, or content
does not match is rejected rather than trusted.

## Recovery and retention

If `docker system prune -a` removes any seeded image, a later converge detects
the missing reference even when a marker exists, deletes the stale marker, and
reloads the still-pre-staged archive (reported as `RELOADED`). A failed reload
or post-load mismatch leaves no marker and stops before Compose. Keep the two
staged artifacts until the host has durable registry access or the deployment is
retired. Because the loader clears its environment and runs on a fixed system
`PATH`, an ambient controller environment cannot influence it; see
[operations.md](operations.md) for the surrounding recovery procedures.

## Current lab rehearsal artifact

The current lab seed was rebuilt on 2026-07-17 (batched DHI bumps: Keycloak 26.7.0, Prometheus 3.13.1, node-exporter 1.12.1, CoreDNS 1.14.6, Traefik patch v3.7.8)
with `scripts/rebuild-offline-image-seed.py` running as root on the lab VM's
own root Docker daemon (linux/arm64, containerd image store), matching the
hashes committed in `inventory/host_vars/lab-aigw01.yml` and staged
root-owned mode `0600` at the pinned `/var/tmp` paths:

| Artifact | Size | SHA-256 |
|---|---:|---|
| `aigw-external-images-linux-arm64-20260717-notempo.docker.tar.zst` | 3,310,325,144 bytes | `1e485c3c8cb3eb0ecfb8d2358d71ef44d0919e490d204cf2d8d0f6aa4be73410` |
| `aigw-external-images-linux-arm64-20260717-notempo.manifest.json` | 4,999 bytes | `ebafa86ae961a698620af77e126b6fd0a76e4f49889c9e156211186a1b2bf7cd` |

Both files are also retained mode `0600` beneath
`/Users/jamesrudisill/.aigw-lab-dr/20260717-notempo-seed`. The archive passed
zstd integrity and OCI-metadata validation during export. Its manifest records
24 exact Linux/ARM64 external `tag@sha256` references and immutable image IDs
— the complete digest-pinned source set of the checkout it was built from
after the Tempo removal (traces now flow to Cribl only), including the
upstream `hashicorp/vault` Vault UI source added for the
optional Vault UI feature — and asserts that no locally built `ai-gateway/*`
image is present. Every recorded RepoDigest and image ID was verified against
the daemon before export. The frozen legacy map in
`ansible/reset-rocky9-lab.yml` (`aigw_lab_reset_legacy_seed_image_tags`)
still describes the 25-image 2026-07-17 "batch" seed (including
`dhi.io/tempo`) because the legacy reset compares against the snapshot-era
staging, not the current seed.

The superseded 2026-07-17 "batch" seed
(`aigw-external-images-linux-arm64-20260717-batch.docker.tar.zst`,
`e5f25660d8d766044492a5c562622f5a44e4339147a31b0fb287ce717122e483`, 25 images,
pre-Tempo-removal pins) remains retained beneath
`/Users/jamesrudisill/.aigw-lab-dr/20260717-batch-seed`, the 2026-07-16 seed
(`aigw-external-images-linux-arm64-20260716-vaultui.docker.tar.zst`,
`00b9e596cda233eb8660e6ae63850169441814b6c0a679cad56db8f059854869`, 25 images,
pre-batch pins) remains retained beneath
`/Users/jamesrudisill/.aigw-lab-dr/20260716-vaultui-seed`, the 2026-07-15 seed
(`aigw-external-images-linux-arm64-20260715-vaultui.docker.tar.zst`,
`4cd1d451a4654d1f183127cafc8e9dbfe7a04ade891e2a42928401586e160470`, 25 images,
LiteLLM `v1.91.3`) beneath
`/Users/jamesrudisill/.aigw-lab-dr/20260715-vaultui-seed`, and the earlier
2026-07-13 seed
(`aigw-external-images-linux-arm64-20260713.docker.tar.zst`,
`e418ac9299351254412028b3a1481eccaf8791a4847e931d724a4882de2defde`, 22 images,
no `hashicorp/vault` UI source) beneath
`/Users/jamesrudisill/.aigw-lab-dr/20260713-pre-rebuild` for the recorded G3
rehearsal history; neither matches the inventory pins any longer and neither
may be re-staged.

To validate this feature locally without contacting a VM or loading images:

```bash
python3 -m unittest scripts.tests.test_load_offline_image_seed
ansible-playbook -i ansible/inventory/lab.yml ansible/site.yml \
  --syntax-check --ask-vault-pass
```

## Building a seed

`scripts/rebuild-offline-image-seed.py` is the build-side counterpart to the
on-target loader: run it on a controller or build host with a local Docker
daemon (remote TCP/SSH daemons are refused). It never pulls — it exports
already-present, digest-pin-verified images into a root-owned OCI archive
plus manifest (`<name>.docker.tar.zst` + `<name>.manifest.json`), which are
then staged on the target and consumed exactly once at converge time by
`scripts/load-offline-image-seed.py` under the `offline_image_seed_*`
inventory variables.
