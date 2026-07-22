# Acceptance test runbook

Use this runbook before you publish a production image release. The main test
runs in local Docker preprod. It loads the exact preprod offline archive.

You do not need a test VM. This runbook does not change production.

Do not save passwords, tokens, keys, prompts, Vault output, cookies, or
registry credentials in test evidence.

## What each test layer proves

One green layer is not a complete release test.

| Layer | Proof |
| --- | --- |
| Unit | Small functions handle good and bad input |
| Contract | CLI, manifest, Compose, Ansible, links, and diagrams agree |
| Integration | Real images, archives, image IDs, and provider policy work together |
| End to end | The exact seed passes LDAPS, Vault, WIF, OIDC, roles, and inference |
| Browser | Redirects, cookies, access rules, and logout work in a browser |
| Release | Every required layer passed for the same files and source commit |

GitHub CI runs static, unit, contract, and container scan jobs. It does not get
the archive built on the operator's system. It does not run local preprod or a
real browser.

If a step did not run, write `NOT RUN` or `BLOCKED`. Do not call it a pass.

## Required rehearsal order

Run these steps in order:

1. Pass static, unit, contract, lint, and security checks.
2. Build new production and preprod schema-v2 pairs.
3. Let the clean-room play destroy only owned `aigw-preprod` state.
4. Purge the manifest-listed image aliases and IDs, then prove their absence.
5. Load the new preprod archive and require an exact fresh `LOADED` receipt.
6. Let Ansible start seed mode once, with no pull or build.
7. Pass service, LDAPS, Root CA, Vault, WIF, OIDC, role, logout, and inference
   checks.
8. Restart Vault. Prove it seals, then let Ansible unseal it and pass the same
   exact-seed checks again.
9. Pass the real-browser checks.
10. Run the exact-manifest clean-room teardown. Prove every owned resource and
   release image is absent and unrelated image IDs are unchanged.
11. Push the exact tested commit to `main`.
12. Wait for every required GitHub job, including the release container scan.
13. Save the final non-secret release record.

The automated test uses real TLS, Samba AD, Keycloak, and web sessions. It does
not launch a browser. The browser step is separate.

## 1. Run static release checks

Run these commands from the repository root:

```bash
bash scripts/validate-compose.sh
python3 -I -m unittest discover -v -s scripts/tests -p 'test_*.py'
python3 -I scripts/validate-identity-policy.py
python3 -I .github/scripts/validate-docs.py
bash .github/scripts/run-shellcheck.sh error
yamllint -c .yamllint.yml \
  .github .trivyignore.yaml .yamllint.yml ansible compose services
```

Every command must exit with status `0`. The Compose check only renders the
model. It does not start containers.

### Python services

Use Python 3.14.6, which is the exact version used by GitHub CI. Build a clean,
temporary environment for each service. This avoids passing a test because an
old package happens to be installed on the workstation.

Run this block from the repository root. It installs both the direct
application requirements and the development tools. It then applies the
hash-locked production graph before it runs the checks.

```bash
set -euo pipefail
python_test_root="$(mktemp -d "${TMPDIR:-/tmp}/aigw-python-tests.XXXXXX")"
trap 'rm -rf -- "$python_test_root"' EXIT

for service in dev-portal key-rotator; do
  service_dir="$PWD/services/$service"
  test_env="$python_test_root/$service"

  uv venv --python 3.14.6 "$test_env"
  uv pip install --python "$test_env/bin/python" \
    -r "$service_dir/requirements.txt" \
    -r "$service_dir/requirements-dev.txt"
  uv pip install --python "$test_env/bin/python" --require-hashes \
    -r "$service_dir/requirements.lock"
  uv pip check --python "$test_env/bin/python"

  (
    cd "$service_dir"
    PYTHONPATH=. "$test_env/bin/python" -m pytest -q
    "$test_env/bin/ruff" check app tests
    "$test_env/bin/bandit" -q -r app \
      --severity-level medium --confidence-level medium
    "$test_env/bin/pip-audit" --disable-pip -r requirements.lock
  )
done
```

The `trap` removes only the new temporary directory when the shell exits. Do
not run bare `pytest` from the repository root. If Python 3.14.6 is not
available to `uv`, stop and install that version; do not substitute another
Python version for release evidence.

### Go services

```bash
for module in dhi-health-probe egress-proxy vault-ui-proxy wif-provider-mock; do
  (cd "services/$module" && go test -race ./... && go vet ./...)
done
```

Provider tests must cover repeated values, sort order, duplicates, unknown
names, and an empty provider list. They must reject custom hosts and CA paths.
They must prove repeat builds match. They must also prove that a changed
provider set changes the policy and image. CA, date, SNI, SAN, or fingerprint
errors must fail closed.

### Ansible syntax

```bash
ansible-playbook -i ansible/inventory/preprod.yml \
  ansible/preprod.yml --syntax-check
ansible-playbook -i ansible/inventory/preprod.yml \
  ansible/preprod-destroy.yml --syntax-check
ansible-playbook -i ansible/inventory/preprod.yml \
  ansible/preprod-clean-room.yml --syntax-check
```

### GitHub release container scan

This gate runs after the clean-room and browser tests pass. A push to `main`
starts the full release scan. It scans each exact external image and each
unique custom image for the production and preprod union. It also writes an
SBOM and a provenance record for each image.

The job needs these two secrets in the GitHub Environment named
`release-container-security`:

```text
DHI_USERNAME
DHI_PASSWORD
```

Limit that environment to protected `main`. Missing secrets are a failure, not
a skip. A pull, build, scan, SBOM, provenance, or upload error also fails the
job.

For release images, Trivy saves the raw `HIGH` and `CRITICAL` JSON without VEX
filtering. Docker Scout 1.23.1 is the blocking, VEX-aware check. Repository
waivers live in `.trivyignore.yaml`. Image waivers live in
`.github/trivyignore-images.yaml`. Each waiver needs an owner, reason, exact
package version, and end date.

For an exact DHI base, CI fetches Docker's VEX statement for that tag and
digest. It verifies the statement with the committed Docker public key and
uses it only for the matching final image. Docker's current statements have no
public transparency-log entry, so CI uses `--verify --skip-tlog`: the key
signature is checked, but public-log inclusion is not. The evidence record
must state that limit. If an exact base has no VEX statement, it gets no DHI
VEX suppression.

Open WebUI is not a DHI image. Its exact `0.10.2-aigw2` derivative has one
committed OpenVEX review for `CVE-2026-45829`. The review is unsigned,
Git-reviewed, tied to exact build inputs, and expires on 2026-10-19. A reviewed
local comparison found one raw Scout finding and zero findings after that VEX
statement was applied. This is local evidence only. It does not mean the
credential-protected GitHub release scan passed.

Do not replace this job with an unrecorded local scan. The GitHub runner rebuilds
from the commit. It does not inspect the local archive, so the seeded test below
is still required.

## 2. Build and test the offline release

This is the required release rehearsal. It proves that the exact archive can
start with no pull or source build.

### Before the build

Check these facts:

- Docker uses a local Unix socket.
- Docker is logged in to `dhi.io`.
- The provider is in the committed catalog.
- Local Docker can run the target platform.
- The private output path has enough free space.
- No unrelated resource uses an `aigw-preprod` name.

Use `linux/arm64` for an ARM64 target. Use a new dated path for every build.

### Step 1 — Build both pairs

```bash
install -d -m 0700 /absolute/private/path/2026-07-21-linux-amd64
python3 -I scripts/update-images.py prepare \
  --provider anthropic \
  --platform linux/amd64 \
  --archive /absolute/private/path/2026-07-21-linux-amd64/aigw-2026-07-21-linux-amd64.docker.tar.zst \
  --manifest /absolute/private/path/2026-07-21-linux-amd64/aigw-2026-07-21-linux-amd64.manifest.json
```

The command writes:

```text
aigw-2026-07-21-linux-amd64.docker.tar.zst
aigw-2026-07-21-linux-amd64.manifest.json
aigw-2026-07-21-linux-amd64.preprod.docker.tar.zst
aigw-2026-07-21-linux-amd64.preprod.manifest.json
```

At this source revision, production has 23 external and 17 custom image
references, for 40 total. Preprod has 25 external and 19 custom image
references, for 44 total. The two preprod-only custom services are Samba AD
and the WIF provider mock. Their Debian 13.6-slim base and the archive-only
PostgreSQL 16 migration source are the two extra external references. None of
these four PreProd-only references belongs in the production archive.

Record all four SHA-256 values:

```bash
# macOS
shasum -a 256 /absolute/private/path/2026-07-21-linux-amd64/aigw-2026-07-21-linux-amd64*

# Linux
sha256sum /absolute/private/path/2026-07-21-linux-amd64/aigw-2026-07-21-linux-amd64*
```

Run the command for your operating system.

### Step 2 — Clean, load, and test the exact preprod pair

```bash
python3 -I scripts/update-images.py test-preprod \
  --archive /absolute/private/path/2026-07-21-linux-amd64/aigw-2026-07-21-linux-amd64.preprod.docker.tar.zst \
  --manifest /absolute/private/path/2026-07-21-linux-amd64/aigw-2026-07-21-linux-amd64.preprod.manifest.json \
  --load-archive \
  --become-password-file "$HOME/.ssh/become"
```

Use `--ask-become-pass` instead if you want an interactive prompt. Do not use
both options. The password file must be absolute, owned by the current user,
mode `0600`, a regular file, not a symbolic link, and have one hard link. The
updater passes only its path to Ansible. It does not read or copy it.

The updater runs these steps in order:

1. Check the schema-v2 preprod manifest and archive allow-list.
2. Run `ansible/preprod-clean-room.yml` with the exact paths and hashes.
3. Prove Docker is local. On Linux, prove the root loader and operator use the
   same Docker socket.
4. Destroy only owned preprod containers, volumes, networks, and generated
   seed state. Prove those resources are gone.
5. Remove only the image aliases and IDs listed by the manifest. Stop if a
   foreign container uses one.
6. Prove the listed images are absent and unrelated images are unchanged.
7. Remove only owned loopback aliases and the bounded hosts block.
8. Stage private root-owned copies on rootful Linux. Docker Desktop uses the
   caller-owned files.
9. Load the archive. Require exactly `LOADED <archive-sha256>`. Reject
   `SKIPPED` and `RELOADED`.
10. Run `ansible/preprod.yml` once. It deploys with `pull_policy: never`, no
   build sections, the bounded hosts block, and the full acceptance gate.
11. Remove any private root staging copy.

If the clean-room play fails, staging and deploy do not start. Do not use
`docker system prune`, a broad Compose project, or a broad image delete.

A pass includes these markers:

```text
PREPROD_CLEAN_ROOM_OK ...
PREPROD_E2E_PASSED
SEEDED_PREPROD_E2E_PASSED
```

You may add `--test-preprod` to the Step 1 `prepare` command instead. That
uses the same clean-room, archive-load, and Ansible acceptance path for the
newly built preprod pair.

Running `test-preprod` without `--load-archive` skips clean-room cleanup and
archive loading. It is only a quick development check. It is not release
evidence.

The run must prove:

- all image IDs and the manifest scope match;
- the Envoy labels match the provider policy;
- each required service is ready;
- the Root CA signs edge, LDAPS, and WIF test certificates;
- Vault is ready;
- Ansible set up Keycloak without a portal init step;
- all three test users pass their allow and deny rules;
- OIDC callbacks and logout work;
- Ansible reconciled the exact Open WebUI workload key;
- valid signed chat identity reached LiteLLM, while missing, bad, expired, or
  duplicate assertions stopped before the mock provider;
- WIF checks a real Keycloak JWT;
- LiteLLM gets `pong` through the preprod-only TLS Envoy;
- LiteLLM audit spans enter Alloy only through the bearer-authenticated
  receiver, while a missing token, wrong token, or forged source marker fails;
- the exact production Envoy passes its immutable policy and CA startup gate; and
- the approved SOC test logs reach the Cribl mock without secret fields.

See [Local preprod](preprod.md) for the users and network model.

### Step 3 — Rehearse PostgreSQL 16 to 18

Run this step for a release that adds or changes the PostgreSQL major-version
move. It uses local Docker only. It does not create a Rocky or Parallels VM.

This step proves application, data, failure-recovery, and rollback behavior. It
does not literally run the Linux/root `scripts/state-backup.sh`,
`scripts/postgres-major-migrate.py`, or the `generic_rocky9` plays in
`ansible/migrate-postgres18.yml`. Those production paths have unit, source, and
Ansible contract coverage here. They run on the existing production Linux host
during the approved maintenance window. This is the accepted no-rehearsal-VM
boundary, not proof that the Linux-only commands ran.

```bash
python3 -I scripts/update-images.py test-postgres18-preprod \
  --archive /absolute/private/path/2026-07-21-linux-amd64/aigw-2026-07-21-linux-amd64.preprod.docker.tar.zst \
  --manifest /absolute/private/path/2026-07-21-linux-amd64/aigw-2026-07-21-linux-amd64.preprod.manifest.json \
  --become-password-file "$HOME/.ssh/become"
```

This command always does another exact clean-room load. It must prove the
PostgreSQL 16 application graph, fixed fixtures of at least 384 MiB, fixture
hashes, pre-cutover rollback, and logical restore to the exact PostgreSQL 18
image. It must also prove post-write downgrade refusal with no mutation, then
complete a same-major physical backup and restore. It runs the full PreProd
acceptance gate again after the restore.

Save these two markers and the JSON receipt named in
[Local preprod](preprod.md#rehearse-the-postgresql-move):

```text
POSTGRES18_PREPROD_REHEARSAL_PASSED ...
SEEDED_PREPROD_POSTGRES18_REHEARSAL_PASSED
```

## 3. Prove Vault restart recovery

Keep the exact seeded preprod deployment running. This test proves the normal
Vault restart and Ansible recovery path. It does not create or reboot a VM.

Restart only the preprod Vault container:

```bash
docker restart --time 30 aigw-preprod-vault-1
```

Check Vault from inside that container:

```bash
docker exec -e VAULT_ADDR=http://127.0.0.1:8200 \
  aigw-preprod-vault-1 vault status -format=json
```

Exit code `2` is expected while Vault is sealed. The JSON must say
`"initialized": true` and `"sealed": true`. The health probe must fail with
HTTP 503:

```bash
docker exec aigw-preprod-vault-1 \
  /usr/local/bin/aigw-health-probe http \
  --url 'http://127.0.0.1:8200/v1/sys/health?standbyok=true'
```

Rerun the exact preprod pair without `--load-archive`. The archive was already
loaded. This second run asks Ansible to unseal Vault and recheck the whole
deployment:

```bash
python3 -I scripts/update-images.py test-preprod \
  --archive /absolute/private/path/aigw-YYYY-MM-DD.preprod.docker.tar.zst \
  --manifest /absolute/private/path/aigw-YYYY-MM-DD.preprod.manifest.json \
  --become-password-file "$HOME/.ssh/become"
```

Use `--ask-become-pass` instead when needed. A pass prints
`PREPROD_E2E_PASSED` and `SEEDED_PREPROD_E2E_PASSED` again. Check Vault one
more time with the same `vault status` command. It must now exit `0` and say
`"initialized": true` and `"sealed": false`. The same health probe must also
exit `0`.

Never put the Vault share on the command line, in an environment variable, or
in the test record. Ansible reads the encrypted controller value and sends the
share on standard input.

## 4. Run the real-browser check

Keep seeded preprod running. Use a new browser profile with no old cookies.
The Ansible deploy already installed the marker-bounded preprod block in
`/etc/hosts`. Do not add unbounded or Docker bridge addresses by hand.

Import `compose/secrets/preprod-root-ca.pem` into that test profile only. Use
the accounts in [Local preprod](preprod.md#static-test-users).

Pass only if:

- each `aigw.internal` certificate is trusted;
- each redirect stays on the right app and `auth.aigw.internal`;
- the admin reaches admin and chat pages;
- the developer reaches the developer portal and chat, but not admin pages;
- the user reaches chat, but not portal or admin pages;
- every cookie is `Secure` and limited to the right host and path;
- application session and Keycloak identity cookies are `HttpOnly`;
- logout clears the app and Keycloak sessions; and
- Back, then Refresh, does not reopen a protected page.

Keycloak's `KEYCLOAK_SESSION` and `KC_AUTH_SESSION_HASH` status cookies are
intentionally readable by its session-check JavaScript. They do not carry a
plain user ID or token. Do not force `HttpOnly` onto those two cookies; doing
so breaks the supported login flow. Keycloak documents the hashed session
format in its
[26.1 release note](https://www.keycloak.org/2025/01/keycloak-2610-released).

Remove the Root CA from the browser profile. The exact-manifest teardown in the
next section removes the preprod hosts block. Do not save cookie values in the
test record.

## 5. Clean up and handle a failure

After a release pass or failure, run the clean-room play with the exact tested
preprod paths and hashes:

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

Use `--ask-become-pass` instead when needed. This final step must prove that
all owned containers, image aliases, image IDs, volumes, networks, generated
state, hosts entries, and loopback aliases are absent. It must also prove that
unrelated image IDs are unchanged. A pass prints one bounded receipt:

```text
PREPROD_CLEAN_ROOM_OK {...}
```

`ansible/preprod-destroy.yml` is still available for quick development
cleanup. It preserves the test CA and does not prove absence of the exact
manifest image set. Do not use its `PREPROD_DESTROYED_CA_PRESERVED` marker as
release evidence.

If a required check fails:

1. Mark the release `FAIL` or `BLOCKED`.
2. Do not transfer the production pair.
3. Save only safe output, hashes, image IDs, and the failed check name.
4. Fix the source.
5. Build new files with new names.
6. Repeat the full clean rehearsal.

Do not edit a manifest. Do not weaken an ownership check.

## 6. Understand the production boundary

Local preprod does not prove production NICs, routes, SELinux, disk encryption,
customer PKI, firewall rules, or the customer directory. Production Ansible
checks those facts on the real host.

For a first install, use the [production runbook](deploy-runbook.md). For an
image update, use the
[remote upgrade workflow](image-update-workflow.md#4-upgrade-the-remote-host).

Do not create a rehearsal VM. Do not force a test failure on production. The
upgrade state machine has contract tests. Real validation runs only in the
approved maintenance window.

PostgreSQL major changes use the
[PostgreSQL 18 migration SOP](sop/postgresql-18-migration.md).

## 7. Record the result

Record:

- source commit and test date;
- target platform and provider list;
- all four filenames and SHA-256 values;
- both release scopes;
- policy hash and Envoy image ID;
- Docker version and operator;
- each command and result marker;
- the final exact-manifest teardown receipt and unrelated-image preservation
  count;
- each required GitHub job and final state; and
- browser results without cookies.

Accept the release only when every required step passed for the same source
and files. If access, disk, registry login, or another input is missing, mark
the release `BLOCKED`. A browser result from an older release does not approve
a newer release. Keep old results only as dated historical evidence.
