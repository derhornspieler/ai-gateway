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

The archive holds only the external images the converge would otherwise pull:
the directly run DHI pins (`busybox`, `postgres`, `tempo`), the DHI base images
that each locally built `ai-gateway/dhi-*:<ver>-probe` derivative is built FROM
(oauth2-proxy, keycloak, vault, redis, alloy, prometheus, node-exporter, loki,
grafana, and the OpenTelemetry Collector, plus both the DHI Traefik runtime base
and the upstream Traefik binary source that the patched Traefik image combines),
and the two non-DHI upstream bases for the application exceptions LiteLLM and
Open WebUI.

By assertion it carries no `ai-gateway/*` image: the `-probe` derivatives, the
two Traefik edges, and the portals are always built on the VM from the seeded
bases. The public, digest-pinned Debian base for the lab-only Samba build is
also intentionally excluded — it needs no registry credential and is pulled from
Docker Hub during the build. A generic/customer inventory must make its own
reviewed decision about which of these external images to pre-stage and must
never copy the lab paths or hashes by habit.

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

The 2026-07-13 rebuild uses this manifest-backed, secret-free seed from the
recovery workstation, matching the hashes committed in
`inventory/host_vars/lab-aigw01.yml`:

| Artifact | Size | SHA-256 |
|---|---:|---|
| `aigw-external-images-linux-arm64-20260713.docker.tar.zst` | 3,304,886,294 bytes | `e418ac9299351254412028b3a1481eccaf8791a4847e931d724a4882de2defde` |
| `aigw-external-images-linux-arm64-20260713.manifest.json` | 7,206 bytes | `ebde9dd8a2f8053666414e665be03acbfcf3b841af94d9e7b26e3da9ed6b5515` |

Both files are retained mode `0600` beneath
`/Users/jamesrudisill/.aigw-lab-dr/20260713-pre-rebuild`. The archive passed
zstd integrity verification. Its manifest records 22 exact Linux/ARM64 external
`tag@sha256` references and immutable image IDs, including both the DHI Traefik
runtime and the patched upstream binary source, and asserts that no locally
built `ai-gateway/*` image is present. Every recorded RepoDigest and image ID
was verified before export. These checks establish a reviewed bootstrap input.
The replacement VM's G3 converge subsequently passed the live load/post-load
exact-reference verification using this seed. That proves the external-image
bootstrap lane only; it does not prove the later final-source G7 converge,
custom-image rollback, runtime, or unchanged-converge gates.

To validate this feature locally without contacting a VM or loading images:

```bash
python3 -m unittest scripts.tests.test_load_offline_image_seed
ansible-playbook -i ansible/inventory/lab.yml ansible/site.yml \
  --syntax-check --ask-vault-pass
```
