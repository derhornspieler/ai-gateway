# Local preprod

Local preprod runs the full AI Gateway on the local Docker engine. Ansible owns
the deploy. You do not need a test VM or a second host.

Preprod is for release tests. It is not production. It uses:

- the fixed domain `aigw.internal`;
- the fixed Compose project `aigw-preprod`;
- three host-facing planes plus separate service networks;
- a local test Root CA;
- Samba AD over LDAPS;
- fixed test usernames with private local passwords; and
- local WIF and provider mocks.

Ansible refuses a remote inventory or remote Docker context. It does not run
the Rocky Linux host roles. It does not change a production project.

## Pick a test path

| Need | Path |
| --- | --- |
| Quick source check | [Start from source](#start-from-source) |
| Final release test | [Test an offline seed](#test-an-offline-seed) |
| PostgreSQL 16 to 18 test | [Rehearse the PostgreSQL move](#rehearse-the-postgresql-move) |
| Manual browser test | [Local names](#local-names), then the [browser checks](test-runbook.md#4-run-the-real-browser-check) |
| Final release teardown | [Finish with exact-manifest teardown](#finish-with-exact-manifest-teardown) |
| Quick development cleanup | [Remove a development stack](#remove-a-development-stack) |

The final release test must load the new preprod archive. A source-mode run is
useful, but it is not final release proof.

## Network model

Three host-facing networks model the production planes:

| Plane | Docker network | Host listener |
| --- | --- | --- |
| Egress | `aigw-preprod-plane-egress` | none |
| ADM | `aigw-preprod-plane-adm` | `127.0.3.1:443` |
| Internal | `aigw-preprod-plane-internal` | `127.0.2.1:443` |

The service networks still stay separate. Each preprod container, volume, and
network has an ownership label. Start and destroy stop if a resource uses a
preprod name without the right label.

Most preprod service networks use the separate `172.29.0.0/16` test range.
`aigw-preprod-net-vendor` uses `172.28.7.0/24`, which is the production vendor
CIDR. This is required because the exact production Envoy image allows requests
only from that reviewed CIDR. The network name and ownership label remain local
to preprod. Docker refuses the run if that CIDR is already in use.

The exact production Envoy image still starts from the offline seed. Its baked
provider policy, CA files, and startup checks are not changed or mounted over.
Preprod cannot use its fake WIF token with the real Anthropic service. A
generated copy of the production LiteLLM model list therefore sends test
inference through a separate preprod-only Envoy and TLS provider mock. The
renderer fails if it sees an unknown provider route. This tests WIF and
inference without sending a fake token to the Internet or weakening production
CA pinning.

Docker Desktop cannot publish the same port from two containers, even when
the host IPs differ. One preprod-only Envoy forwarder owns both loopback binds.
It sends raw TLS to the correct internal or ADM Traefik container. Production
does not use this forwarder.

Preprod does not mount the workstation root or read other projects' Docker
logs. It still checks local Loki, Prometheus, Grafana, and the Cribl mock. It
does not prove production firewall rules, customer PKI, or Cribl retention.

## Requirements

- macOS or Linux
- a local Unix-socket Docker context
- Docker Compose 5.3.1, the version used by the current release checks
- Ansible Core
- OpenSSL
- curl 7.76 or newer
- enough memory and disk for the full stack
- access to the pinned DHI images, or a checked offline seed

On macOS, Docker Desktop needs these two `/24` aliases on `lo0`:

- Internal: `127.0.2.1` in `127.0.2.0/24`
- ADM: `127.0.3.1` in `127.0.3.0/24`

Ansible uses sudo only to add missing macOS aliases and to manage the bounded
hosts block. Docker still runs as the current user. Linux skips the alias task
but still updates the hosts block.

You may use `--ask-become-pass`. You may also use a private password file:

```bash
chmod 600 "$HOME/.ssh/become"
```

Keep that file outside this repository. Never commit it. When
`scripts/update-images.py` uses it, the file must:

- have an absolute path;
- be a regular file, not a symbolic link;
- have only one hard link;
- be owned by the current user; and
- have mode `0600`.

The updater does not read, copy, or print the password. It passes only the
validated path to `ansible-playbook`.

## Start from source

From the repository root, use one sudo method. With the private password file
described above:

```bash
ansible-playbook -i ansible/inventory/preprod.yml ansible/preprod.yml \
  --become-password-file "$HOME/.ssh/become"
```

For an interactive prompt:

```bash
ansible-playbook -i ansible/inventory/preprod.yml ansible/preprod.yml \
  --ask-become-pass
```

The play creates test certificates, builds custom images, starts the stack,
sets up the test Vault, configures Keycloak from LDAPS, creates the test users,
sets up WIF, and runs the full checks. The user does not initialize Keycloak
through the admin portal.

To refresh every exact base image pin before a source build:

```bash
ansible-playbook -i ansible/inventory/preprod.yml ansible/preprod.yml \
  -e preprod_pull_images=true \
  --become-password-file "$HOME/.ssh/become"
```

This does not use `latest`. It pulls the reviewed tag and digest pins.

## Local names

The play installs or updates this exact marker-bounded block in `/etc/hosts`:

```text
# BEGIN AIGW PREPROD MANAGED
127.0.2.1 api.aigw.internal portal.aigw.internal
127.0.3.1 auth.aigw.internal chat.aigw.internal admin.aigw.internal litellm-admin.aigw.internal grafana.aigw.internal prometheus.aigw.internal vault.aigw.internal
# END AIGW PREPROD MANAGED
```

Use loopback IPs in `/etc/hosts`, not Docker bridge IPs. Docker Desktop does not
route bridge IPs from the host.

Ansible refuses an unowned or malformed block. Destroy and clean-room runs
remove only the text between these two markers. They do not rewrite other
hosts entries.

Ansible records only the macOS aliases it created. Destroy removes only those
owned aliases. An address that existed before preprod is never claimed.

The test Root CA is `compose/secrets/preprod-root-ca.pem`. Ansible does not add
it to the operating system trust store. Add it only to a test browser profile,
then remove it when browser testing is done.

## Private test users

The usernames are the same on every PreProd install. The passwords are not in
Git. Ansible creates them from a private seed in
`compose/secrets/preprod-credential-seed-v1`.

| Username | Private password file | Access |
| --- | --- | --- |
| `preprod-admin` | `compose/secrets/samba_user_preprod-admin_password` | admin and chat |
| `preprod-developer` | `compose/secrets/samba_user_preprod-developer_password` | developer portal and chat |
| `preprod-user` | `compose/secrets/samba_user_preprod-user_password` | chat |

To view a password for a browser test, open only its local file. For example:

```bash
less compose/secrets/samba_user_preprod-admin_password
```

Press `q` to close `less`. Do not paste the password into Git, chat, a ticket,
or a command argument.

The seed and generated files use mode `0600`. Git ignores the whole
`compose/secrets/` directory. The same checkout keeps the same passwords after
destroy and redeploy. A different checkout gets different passwords.

To rotate all local PreProd passwords:

1. Run the [development destroy](#remove-a-development-stack). This removes
   the PreProd containers and volumes.
2. Delete only `compose/secrets/preprod-credential-seed-v1`.
3. Run the Ansible deployment again. It creates a new seed and replaces every
   generated password.

Preparation stops if the seed is missing while PreProd containers or volumes
still exist. This prevents a silent password change from breaking a running
stack. The test Root CA is not rotated with the passwords.

An earlier release put disposable PreProd passwords and a predictable password
recipe in Git. Treat every old PreProd password as permanently compromised and
never reuse it. An exact history audit found no match for the current sudo,
DHI, Docker Hub, or generated private-key values. Rewriting shared Git history
is a separate, disruptive operation and requires explicit owner approval.

Samba serves LDAPS at `samba-ad.aigw.internal:636`. The test Root CA signs its
certificate, the edge certificate, and the WIF mock certificate.

## Run the end-to-end check

The Ansible play runs this check after stack health and identity checks. A pass
prints:

```text
PREPROD_E2E_PASSED
```

To rerun only the check:

```bash
python3 -I scripts/test-e2e-preprod.py
```

The check uses a safe local name map. It does not need `/etc/hosts`. It proves:

- every required service is ready;
- `volume-init` exited once with success;
- Vault is initialized and unsealed;
- Keycloak uses `https://auth.aigw.internal/realms/aigw`;
- all three users log in through LDAPS;
- portal, chat, and admin role rules work;
- Keycloak callbacks and logout work;
- Ansible reconciles the exact Open WebUI workload key;
- a valid signed chat identity reaches LiteLLM, while missing or bad chat
  assertions stop before the mock provider;
- WIF checks the live Keycloak JWT;
- LiteLLM reaches the mock provider through the preprod-only TLS Envoy;
- the exact production Envoy passes its immutable policy and CA startup gate; and
- the mock response is `pong`.

The [acceptance test runbook](test-runbook.md) lists every release gate.

## Test an offline seed

Seed mode uses the exact image IDs in the manifest. It removes Compose build
sections and sets `pull_policy: never`. It refuses a production-only manifest
because that release does not include the Samba AD and WIF test images or
their extra Debian build base.

For a final release test, load the copied preprod pair. Use one sudo option if
your workstation needs it:

```bash
python3 -I scripts/update-images.py test-preprod \
  --archive /absolute/private/path/aigw-YYYY-MM-DD.preprod.docker.tar.zst \
  --manifest /absolute/private/path/aigw-YYYY-MM-DD.preprod.manifest.json \
  --load-archive \
  --become-password-file "$HOME/.ssh/become"
```

Use `--ask-become-pass` instead of `--become-password-file` when you want an
interactive prompt. Do not use both.

The release-grade path runs these fail-closed steps in order:

1. Check the schema-v2 preprod manifest and archive allow-list.
2. Run `ansible/preprod-clean-room.yml` with the exact file paths and hashes.
3. Prove Docker is local. On Linux, prove the root loader and operator use the
   same Docker socket.
4. Destroy only owned `aigw-preprod` containers, volumes, networks, and
   generated seed state. Prove those resources are gone.
5. Remove only the image aliases and image IDs listed by the checked manifest.
   Stop if another container uses one of those images.
6. Prove the listed images are absent and unrelated images are unchanged.
7. Remove only owned loopback aliases and the bounded hosts block.
8. Stage private loader copies on rootful Linux. Docker Desktop uses the
   caller-owned files directly.
9. Load the archive. The loader must return exactly `LOADED` for this archive.
   `SKIPPED` and `RELOADED` fail the release test.
10. Run `ansible/preprod.yml` once. It deploys in seed mode and runs the full
   acceptance gate.

If the clean-room play fails, the updater does not stage files or deploy. If a
root staging copy was made, the updater removes it after the run, even when
the deploy fails.

If the exact images are already loaded, omit `--load-archive` for a quick
development check. That path skips clean-room cleanup and is **not** release
evidence.

On rootful Linux, the updater makes private root-owned staging copies for the
loader. It proves the operator and root use the same Docker socket. Rootless or
remote Docker fails before any image changes.

On macOS, Docker Desktop loads the caller-owned files. The files must be
private and owned by the caller.

Expected final markers are:

```text
PREPROD_CLEAN_ROOM_OK ...
PREPROD_E2E_PASSED
SEEDED_PREPROD_E2E_PASSED
```

Follow the clean build, destroy, load, deploy, and browser order in the
[acceptance test runbook](test-runbook.md#required-rehearsal-order).

## Rehearse the PostgreSQL move

Use this test only with the preprod archive. It does not connect to a VM or a
production host. It always starts with a clean-room load of the exact archive.

```bash
python3 -I scripts/update-images.py test-postgres18-preprod \
  --archive /absolute/private/path/aigw-YYYY-MM-DD.preprod.docker.tar.zst \
  --manifest /absolute/private/path/aigw-YYYY-MM-DD.preprod.manifest.json \
  --become-password-file "$HOME/.ssh/become"
```

You may use `--ask-become-pass` instead. There is no quick or no-load form of
this command.

This is a local behavior test. It proves the data move, application checks,
failure recovery, and rollback rules with the exact seeded images. It does not
literally run the Linux/root `scripts/state-backup.sh`,
`scripts/postgres-major-migrate.py`, or the `generic_rocky9` plays in
`ansible/migrate-postgres18.yml`.

Those production tools keep their unit, source, and Ansible contract coverage.
They run on the existing production Linux host during its approved maintenance
window. We accept this boundary because this project does not create a separate
rehearsal VM. A green local receipt does not claim that the Linux-only commands
ran.

The command checks this full path:

1. Validate the schema-v2 manifest and both exact PostgreSQL image IDs.
2. Remove the old local release and load the archive again.
3. Run the whole application on PostgreSQL 16.
4. Create 512,000 fixed test rows in each of the LiteLLM, Keycloak, and rotator
   databases. Require at least 128 MiB per database, or 384 MiB total. Record a
   row count, byte size, and content SHA-256 for each.
5. Force a failure before cutover. Remove the unused PostgreSQL 18 volume,
   restart PostgreSQL 16, and prove every test row is unchanged.
6. Make logical dumps and restore them into the exact PostgreSQL 18 image.
7. Run the full Ansible PreProd checks on PostgreSQL 18.
8. Open writes, try a downgrade, and prove the refusal changed no container,
   volume, or test row.
9. Make a physical PostgreSQL 18 backup, restore it to a clean volume, and run
   all checks again.

A pass prints:

```text
POSTGRES18_PREPROD_REHEARSAL_PASSED ...
SEEDED_PREPROD_POSTGRES18_REHEARSAL_PASSED
```

The machine-readable receipt is
`compose/secrets/preprod-postgres18-rehearsal-receipt.json`. It has no
passwords. Save it with the release evidence before teardown. The exact
clean-room teardown removes this generated receipt with the other PreProd
state.

This local test does not replace the production change plan. Production uses
the separate [PostgreSQL 18 migration SOP](sop/postgresql-18-migration.md).

## Finish with exact-manifest teardown

After the release tests pass or fail, run the clean-room play again with the
exact tested preprod pair. Replace the paths and hashes with values from that
release:

```bash
ansible-playbook -i ansible/inventory/preprod.yml \
  ansible/preprod-clean-room.yml \
  -e preprod_seed_archive=/absolute/private/path/aigw-YYYY-MM-DD.preprod.docker.tar.zst \
  -e preprod_seed_archive_sha256=REPLACE_WITH_ARCHIVE_SHA256 \
  -e preprod_seed_manifest=/absolute/private/path/aigw-YYYY-MM-DD.preprod.manifest.json \
  -e preprod_seed_manifest_sha256=REPLACE_WITH_MANIFEST_SHA256 \
  -e preprod_clean_room_confirmation=DESTROY_AIGW_PREPROD_RELEASE_IMAGES \
  --become-password-file "$HOME/.ssh/become"
```

Use `--ask-become-pass` instead when needed. This is the final release
teardown. It validates the manifest boundary and proves that all owned
containers, image aliases, image IDs, volumes, networks, generated state,
hosts entries, and loopback aliases are absent. It also proves that unrelated
image IDs were preserved. Save the one-line `PREPROD_CLEAN_ROOM_OK` receipt.

Do not use `docker system prune` or a broad image delete. Do not accept the
release if this exact-manifest teardown fails.

## Remove a development stack

```bash
ansible-playbook -i ansible/inventory/preprod.yml \
  ansible/preprod-destroy.yml \
  -e preprod_destroy_confirmation=DESTROY_AIGW_PREPROD
```

Add the same sudo option used during start.

Destroy removes only owned `aigw-preprod` containers, volumes, networks,
aliases, hosts entries, and the test Vault recovery record. It keeps the local
test Root CA and leaf files, so a new run does not force a new browser trust
step. It does not purge or prove absence of the exact manifest image set. Use
it only for ordinary development cleanup, not a final release receipt.

Preprod Samba lives only in `services/samba-ad-preprod`. No retired lab
Compose file or profile is used.
