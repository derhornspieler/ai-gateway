# Offline external-image seed

The deployment can optionally load a pre-staged, secret-free Docker archive
before any Compose validation or build needs an external image. This is a
bootstrap aid for a host that cannot authenticate to one or more image
registries. It is not a substitute for normal image provenance review, and it
never exports or accepts locally built `ai-gateway/*` outputs.

Generic/customer defaults are disabled and pathless. Enabling the feature
requires four environment-specific inventory values:

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
inventory paths. Do not put credentials, registry tokens, or customer secrets
in either artifact.

The `docker_stack` role performs the following fail-closed sequence:

1. Require the complete explicit opt-in contract; partial configuration fails.
2. Prove Docker is started after the host firewall roles and use the `zstd`
   package installed by the OS baseline.
3. Verify manifest ownership, mode, size bound, exact SHA-256, schema, target
   platform, archive name, image count, and the zero-custom-image assertion.
4. Require every manifest image to have an exact `tag@sha256` reference and
   immutable expected image ID.
5. Trust an existing root-owned checksum marker only when all required
   references still resolve to the expected RepoDigest and image ID.
6. Otherwise verify the archive ownership, mode, exact SHA-256, and zstd
   integrity; stream it to `docker image load`; then repeat every image check.
7. Atomically write a root-owned `0600` marker only after post-load validation
   succeeds. The marker directory is root-owned `0700` under Docker's data
   root, so resetting Docker state also removes the skip decision.

If `docker system prune -a` removes any seeded image, a later converge detects
the missing reference even if a marker exists. It deletes the stale marker and
reloads the still-pre-staged archive. A failed reload or post-load mismatch
leaves no marker and stops before Compose. Keep the two staged artifacts until
the host has durable registry access or the deployment is retired.

The committed Parallels lab inventory opts into the reviewed arm64 archive
because the clean lab VM has no DHI registry credential. The Samba image's
digest-pinned Debian base is intentionally not in that seed: it is public and
is pulled from Docker Hub during the build. A generic/customer inventory must
make its own reviewed decision and must never copy the lab paths or hashes by
habit.

### Current Parallels rehearsal artifact

The 2026-07-13 rebuild uses this manifest-backed, secret-free seed from the
recovery workstation:

| Artifact | Size | SHA-256 |
|---|---:|---|
| `aigw-external-images-linux-arm64-20260713.docker.tar.zst` | 3,304,886,294 bytes | `e418ac9299351254412028b3a1481eccaf8791a4847e931d724a4882de2defde` |
| `aigw-external-images-linux-arm64-20260713.manifest.json` | 7,206 bytes | `ebde9dd8a2f8053666414e665be03acbfcf3b841af94d9e7b26e3da9ed6b5515` |

Both files are retained mode `0600` beneath
`/Users/jamesrudisill/.aigw-lab-dr/20260713-pre-rebuild`. The archive passed
zstd integrity verification. Its manifest records 22 exact Linux/ARM64
external `tag@sha256` references and immutable image IDs, including both the
DHI Traefik runtime and patched upstream binary source, and asserts that no
locally built `ai-gateway/*` image is present. Every recorded RepoDigest and
image ID was verified before export. These checks establish a reviewed
bootstrap input. The replacement VM's G3 converge subsequently passed the live
load/post-load exact-reference verification using this seed. That proves the
external-image bootstrap lane only; it does not prove the later final-source
G7 converge, custom-image rollback, runtime, or unchanged-converge gates.

To validate this feature locally without contacting a VM or loading images:

```bash
python3 -m unittest scripts.tests.test_load_offline_image_seed
ansible-playbook -i ansible/inventory/lab.yml ansible/site.yml \
  --syntax-check --ask-vault-pass
```
