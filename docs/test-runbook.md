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
8. Pass the real-browser checks.
9. Destroy preprod and save the non-secret local test record.
10. Push the exact tested commit to `main`.
11. Wait for every required GitHub job, including the release container scan.
12. Save the final non-secret release record.

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

Use each service's pinned development tools. Run inside each service folder:

```bash
cd services/dev-portal
PYTHONPATH=. pytest -q
ruff check app tests
bandit -q -r app --severity-level medium --confidence-level medium

cd ../key-rotator
PYTHONPATH=. pytest -q
ruff check app tests
bandit -q -r app --severity-level medium --confidence-level medium
cd ../..
```

Do not run bare `pytest` from the repository root.

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

The scan blocks `HIGH` and `CRITICAL` findings unless a reviewed waiver covers
the exact issue. Repository waivers live in `.trivyignore.yaml`. Image waivers
live in `.github/trivyignore-images.yaml`. Each waiver needs an owner, reason,
exact package version, and end date.

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

The production archive has no Samba AD or WIF mock image. The preprod archive
has the production images plus those two test images.

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
- WIF checks a real Keycloak JWT;
- LiteLLM gets `pong` through the preprod-only TLS Envoy;
- the exact production Envoy passes its immutable policy and CA startup gate; and
- the approved SOC test logs reach the Cribl mock without secret fields.

See [Local preprod](preprod.md) for the users and network model.

## 3. Run the real-browser check

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

Remove the Root CA from the browser profile. The bounded destroy command in
the next section removes the preprod hosts block. Do not save cookie values in
the test record.

## 4. Clean up and handle a failure

After a pass or failure, run the bounded destroy play:

```bash
ansible-playbook -i ansible/inventory/preprod.yml \
  ansible/preprod-destroy.yml \
  -e preprod_destroy_confirmation=DESTROY_AIGW_PREPROD \
  --become-password-file "$HOME/.ssh/become"
```

Use `--ask-become-pass` instead when needed. The destroy play removes only
owned preprod resources, owned aliases, and the bounded hosts block. It
preserves the test Root CA. A pass prints:

```text
PREPROD_DESTROYED_CA_PRESERVED
```

If a required check fails:

1. Mark the release `FAIL` or `BLOCKED`.
2. Do not transfer the production pair.
3. Save only safe output, hashes, image IDs, and the failed check name.
4. Fix the source.
5. Build new files with new names.
6. Repeat the full clean rehearsal.

Do not edit a manifest. Do not weaken an ownership check.

## 5. Understand the production boundary

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

## 6. Record the result

Record:

- source commit and test date;
- target platform and provider list;
- all four filenames and SHA-256 values;
- both release scopes;
- policy hash and Envoy image ID;
- Docker version and operator;
- each command and result marker;
- each required GitHub job and final state; and
- browser results without cookies.

Accept the release only when every required step passed for the same source
and files. If access, disk, registry login, or another input is missing, mark
the release `BLOCKED`.
