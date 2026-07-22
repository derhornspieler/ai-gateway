# Image update workflow

Use `scripts/update-images.py` for image releases. It can build, test, deploy,
check, and roll back a release. It has no saved host, password, domain,
inventory, or provider default.

One build makes two file pairs:

- **production:** production images only; and
- **preprod:** the same images plus Samba AD and WIF test images.

Never send the preprod pair to production.

At this source revision, production has 23 external and 17 custom image
references, for 40 total. Preprod has 25 external and 19 custom references,
for 44 total. Two custom services are preprod-only: Samba AD and the WIF
provider mock. Their Debian 13.6-slim build base is also preprod-only. The
fourth extra reference is the archive-only PostgreSQL 16 source used to test
the PostgreSQL 18 migration. Compose never starts that source image during an
ordinary PreProd deploy.

## The normal engineer flow

Use this order for each image change:

1. Read the upstream release and upgrade notes.
2. Pick the newest stable version that all linked services support.
3. Change the reviewed tag and digest in the Dockerfile, Compose file, or
   other pinned source file.
4. Update app settings or libraries if the new image needs them.
5. Run static checks and commit the source change.
6. Run `prepare` to build both release pairs.
7. Run the clean-room seeded preprod test. The updater destroys only owned
   preprod state, purges the manifest image set, loads the archive, and runs
   Ansible acceptance.
8. Run the browser checks while the exact seed is still running.
9. Run the final exact-manifest clean-room teardown. Save the absence and
   unrelated-image preservation receipt.
10. Push the commit to `main`. Wait for the GitHub image scan.
11. Transfer only the production pair for an approved upgrade.

Do not edit a generated manifest. Git holds the reviewed source pins. The
builder makes the manifest as release proof. Keep the archive, manifest,
hashes, source commit, and test record together in private release storage.

Provider review is covered in [Provider onboarding](provider-onboarding.md).
CA work is covered in the
[Provider CA SOP](sop/provider-ca-maintenance.md).

## 1. Build the offline release

Make a new private directory. Put the date and platform in its name:

```bash
install -d -m 0700 /srv/ai-gateway-releases/2026-07-21-linux-amd64
python3 -I scripts/update-images.py prepare \
  --provider anthropic \
  --platform linux/amd64 \
  --archive /srv/ai-gateway-releases/2026-07-21-linux-amd64/aigw-2026-07-21-linux-amd64.docker.tar.zst \
  --manifest /srv/ai-gateway-releases/2026-07-21-linux-amd64/aigw-2026-07-21-linux-amd64.manifest.json
```

Use `linux/arm64` for an ARM64 host. Anthropic is the only approved provider
today. The provider name must exist in the committed catalog. The CLI does not
accept a custom provider host or CA file.

The command writes:

```text
aigw-2026-07-21-linux-amd64.docker.tar.zst
aigw-2026-07-21-linux-amd64.manifest.json
aigw-2026-07-21-linux-amd64.preprod.docker.tar.zst
aigw-2026-07-21-linux-amd64.preprod.manifest.json
```

Use `--preprod-archive` and `--preprod-manifest` together when you need other
preprod paths.

`prepare` does this work:

1. Pulls each reviewed tag and digest pin.
2. Checks the digest before it restores a missing normal tag.
3. Checks the provider through the committed catalog.
4. Builds Envoy with no build network.
5. Adds only the selected provider route and CA data to Envoy.
6. Builds the other production custom images.
7. Builds the two preprod-only custom services. Their Debian 13.6-slim base is
   also included only in the preprod release.
8. Writes both schema-v2 pairs with mode `0600`.
9. Checks image IDs, source hashes, labels, provider data, and policy hashes.

The manifest records the provider list, hostnames, TLS rules, CA fingerprints,
policy hash, and final Envoy image ID. A different provider choice makes a
different policy and image.

### CI gate after local acceptance

Do not push yet. First pass the clean-room preprod test in Section 2. After
that pass, push the reviewed commit to `main`. The **Repository and release
container security** job scans the full production and preprod image union.

The GitHub Environment `release-container-security` must hold:

```text
DHI_USERNAME
DHI_PASSWORD
```

Limit that environment to protected `main`. Missing secrets fail the job. The
job also fails for a pull, build, scan, SBOM, provenance, or upload error.

Trivy saves the raw `HIGH` and `CRITICAL` JSON without VEX filtering. Docker
Scout 1.23.1 is the blocking VEX-aware gate. For an exact DHI base, CI fetches
the matching Docker VEX statement, verifies it with the committed Docker
public key, and selects it only for that final image. A missing statement gives
no DHI VEX suppression.

Docker's current DHI VEX statements have no public transparency-log entries.
CI uses `--verify --skip-tlog`, so the pinned-key signature is checked but
public-log inclusion is not. The receipt records that limit. Open WebUI is not
a DHI image; its one local OpenVEX statement is unsigned, Git-reviewed, tied to
the exact `0.10.2-aigw2` inputs, and expires on 2026-10-19.

Keep waivers owned, dated, and tied to an exact package version. Do not treat a
local scan or VEX review as proof that the protected GitHub job passed.

Hosted CI rebuilds from the commit. It does not receive the local archive.
For that reason, CI does not replace the seeded preprod test.

### Review software inside each image

An image update also reviews the software inside the image. For the Python
services, use Python 3.14.6, validate the direct pins, rebuild the hash-locked
dependency graph for Python 3.14, and run the clean temporary-environment steps
in the [test runbook](test-runbook.md#python-services). CI currently pins
ansible-core 2.21.2 and yamllint 1.38.0.

Regenerate each Python lock from its service directory with the reviewed tool:

```bash
uvx --from uv==0.11.31 uv pip compile requirements.txt \
  --python-version 3.14 --python-platform linux --generate-hashes \
  --output-file requirements.lock
```

Keep the tool version in the command. A floating lock generator can change the
file even when the application requirements did not change.

The newest upstream application tag is not always present in DHI. These are
the current reviewed holds:

| Component | Reviewed choice | Why |
| --- | --- | --- |
| Traefik | Upstream 3.7.8 binary on DHI 3.7.6 | DHI 3.7.7 and 3.7.8 were not available |
| Alloy | DHI 1.17.1 | DHI 1.17.2 and upstream 1.18.0 were not available in DHI |
| Grafana | DHI 13.1.0 | Upstream 13.1.1 was not available in DHI |
| OpenTelemetry Collector | DHI 0.156.0-contrib | Upstream 0.157.0 was not available in DHI |

Recheck these facts for every release. Record a new reason if a component
stays below a compatible stable version. If a new image changes its startup,
filesystem, user, health, or configuration contract, update the source and
tests before building a seed.

## 2. Test the exact preprod seed

To build both pairs and run the release-grade preprod test in one command, add
`--test-preprod` to `prepare`:

```bash
python3 -I scripts/update-images.py prepare \
  --provider anthropic \
  --platform linux/amd64 \
  --archive /srv/ai-gateway-releases/2026-07-21-linux-amd64/aigw-2026-07-21-linux-amd64.docker.tar.zst \
  --manifest /srv/ai-gateway-releases/2026-07-21-linux-amd64/aigw-2026-07-21-linux-amd64.manifest.json \
  --test-preprod \
  --become-password-file "$HOME/.ssh/become"
```

This path uses the generated `.preprod` pair. It runs clean-room cleanup, then
loads the archive bytes and runs Ansible acceptance. Use
`--ask-become-pass` instead of `--become-password-file` for an interactive
sudo prompt. Do not use both.

You can run the same release-grade test later from a copied preprod pair:

```bash
python3 -I scripts/update-images.py test-preprod \
  --archive /srv/ai-gateway-releases/2026-07-21-linux-amd64/aigw-2026-07-21-linux-amd64.preprod.docker.tar.zst \
  --manifest /srv/ai-gateway-releases/2026-07-21-linux-amd64/aigw-2026-07-21-linux-amd64.preprod.manifest.json \
  --load-archive \
  --become-password-file "$HOME/.ssh/become"
```

The password file must be an absolute, caller-owned, mode-`0600` regular file
with one hard link. It cannot be a symbolic link. The updater never reads or
copies it. It passes only the checked path to Ansible.

Both commands use this exact order:

1. Check the preprod manifest and archive allow-list.
2. Run `ansible/preprod-clean-room.yml` with the exact release paths and
   hashes.
3. Prove Docker is local. On Linux, prove the root loader and operator use the
   same Docker socket.
4. Destroy only owned preprod resources and generated seed state. Prove those
   resources are gone.
5. Purge only the manifest-listed image aliases and IDs after checking that no
   foreign container uses them.
6. Prove those images are absent and unrelated images were preserved.
7. Remove the bounded preprod hosts block and only owned loopback aliases.
8. Stage a private root copy on rootful Linux. Docker Desktop uses the
   caller-owned files.
9. Load the archive. Require exactly `LOADED`; reject `SKIPPED` and `RELOADED`.
10. Run `ansible/preprod.yml` once for deploy and acceptance. Seed mode has no
   pull or build sections. The play installs the bounded preprod hosts block.
11. Remove any private root staging copy.

A clean-room failure stops before staging and deploy. A load, deploy,
acceptance, or staging-cleanup failure fails the test.

The test covers Samba LDAPS, the local Root CA, Vault, automatic Keycloak
setup, domain-based redirects, static users, roles, WIF, LiteLLM, the exact
production Envoy startup gate, and inference through the preprod-only TLS
Envoy and provider mock. It also proves that only the bearer-authenticated
LiteLLM receiver can create an AI request audit record.

Keep the release only when the clean test passes. Follow the exact order in
the [acceptance test runbook](test-runbook.md#2-build-and-test-the-offline-release).

After the browser and other release checks, run the clean-room play again with
the same preprod pair and hashes. The final receipt must prove all owned
resources and manifest-listed images are absent, while unrelated image IDs are
unchanged. The ordinary destroy play is only a development cleanup. Use the
[exact command](preprod.md#finish-with-exact-manifest-teardown).

For a quick local check of images that are already loaded, run `test-preprod`
without `--load-archive`. That skips clean-room cleanup and archive loading.
It is **not** release evidence.

## 3. Keep the previous release ready

Rollback needs more than an old image tag. Keep:

- the previous production archive and manifest;
- a clean checkout at the previous reviewed commit;
- a new backup path on a separate file system; and
- the matching age identity on the controller with mode `0600`.

Example:

```bash
git worktree add /srv/ai-gateway-releases/previous-source release-2026-07-01
```

The current and previous checkouts must have no tracked edits. The updater
checks both source trees. It also proves the previous seed matches the running
release before it takes a backup.

## 4. Upgrade the remote host

Copy the production pair and its hashes to the controller. Do not use the
`.preprod` pair.

The local clean-room command is never used on production. Production upgrade
uses the separate backup, staged production seed, validation, and automatic
rollback flow below. It does not purge the running host's image set before the
backup and rollback gates are ready.

Replace every sample value below:

```bash
python3 -I scripts/update-images.py upgrade \
  --archive /srv/ai-gateway-releases/2026-07-21-linux-amd64/aigw-2026-07-21-linux-amd64.docker.tar.zst \
  --manifest /srv/ai-gateway-releases/2026-07-21-linux-amd64/aigw-2026-07-21-linux-amd64.manifest.json \
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

The provider choice is already sealed in the manifest and Envoy image. The
upgrade command cannot change it.

The SSH target and port must match the limited Ansible host. Direct SSH uses
batch mode and `sudo -n`. Set up approved non-interactive sudo before the
maintenance window.

The backup root must be a dedicated directory on a separate file system. Do
not use `/`, `/var`, or `/tmp`. The backup output path must be new.

## What happens on the host

The updater:

1. Stages the old and new production seeds in a private root path.
2. Checks both seeds and their Envoy policy links.
3. Proves the old seed matches the running release.
4. Copies the age identity to a fixed private path under `/run`.
5. Stops writers and makes a checked encrypted backup.
6. Appends `upgrade/started` to the protected target lifecycle source.
7. Runs `ansible/deploy-stack-only.yml` with the new seed.
8. Runs the normal verify role and the outside acceptance check.
9. Runs an optional site test set by `--validation-program`.
10. Removes the temp age identity in a final cleanup step.
11. Appends `upgrade/success`. If this final audit append fails, the validated
    candidate stays running and the command fails so an operator can repair
    the audit path.

Envoy and its provider policy always move as one release unit.

Each lifecycle record has one shared UUIDv4, release manifest hash, source
commit, Envoy image ID, and egress-policy digest. The target creates the UTC
time. Production keeps only `lifecycle.jsonl` and `lifecycle.jsonl.1` in the
root-owned `/var/log/ai-gateway-controller` boundary. Each file is at most
8 MiB. Ansible validates that boundary before Compose. Alloy reads it through
a read-only bind and applies the same common-record gate used by every Cribl
record. A source rollback preserves these audit files.

## Automatic rollback

A deploy or validation failure starts rollback. The updater:

1. Appends `upgrade/failed` and `rollback/started` with the same operation UUID.
2. Checks and restores the encrypted backup.
3. Runs the full `ansible/site.yml` from the old clean checkout.
4. Loads the old production seed.
5. Restores the old Envoy image and provider policy.
6. Runs the same acceptance check.
7. Removes the restore marker only after a pass.
8. Appends `rollback/success`, or `rollback/failed` if recovery does not pass.

If restore, old-source deploy, validation, or cleanup fails, the command ends
with `AUTOMATIC ROLLBACK FAILED`. Keep ingress closed. Keep the backup. Do not
fall back to changing tags by hand.

An old release may stop working after a provider CA cutover. Plan CA rotation
with an overlap window. See the
[Provider CA SOP](sop/provider-ca-maintenance.md#rotation-with-an-overlap-window).

The normal remote image workflow refuses a PostgreSQL major change. First run
the fixed [local PostgreSQL 16 to 18 rehearsal](preprod.md#rehearse-the-postgresql-move)
from the exact preprod seed. Production still uses the separate
[PostgreSQL 18 migration SOP](sop/postgresql-18-migration.md).

## Related pages

- [Dated image and dependency version review](image-version-review.md)
- [Local preprod](preprod.md)
- [Acceptance test runbook](test-runbook.md)
- [Offline seed details](offline-image-seed.md)
- [Production operations](operations.md)
