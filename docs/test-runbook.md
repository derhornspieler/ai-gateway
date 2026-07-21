# Acceptance test runbook

Use this runbook before publishing a production image release. The required
release rehearsal runs in local Docker preprod from the exact offline seed.

You do not need a Parallels VM, a Rocky test VM, or a second lab host. This
runbook does not create or change a production host.

Local preprod proves the application, identity, TLS, provider-policy, and seed
contracts. It cannot prove a customer's physical NICs, SELinux state, disk
encryption, routes, firewall, customer PKI, or customer directory. Ansible
checks those facts on the real production host during the production preflight
and converge. See the [production deployment runbook](deploy-runbook.md).

Never put passwords, tokens, private keys, prompt text, Vault output, cookie
values, or registry credentials in test evidence.

## What each test layer proves

One green layer is not a complete release test.

| Layer | What it proves | Where it runs |
|---|---|---|
| Unit | Small functions handle provider catalogs, CA files, policy generation, startup checks, and service logic. | CI and the developer workstation |
| Contract | CLI arguments, manifests, image labels, loader rules, Compose, Ansible, links, and diagrams agree. | CI and the developer workstation |
| Integration | Real image builds, Docker archives, image IDs, and the generated Envoy policy work together. | Local Docker or an approved self-hosted runner |
| End to end | The exact preprod seed starts with no pull or build and passes LDAP, CA, Vault, WIF, OIDC, role, and inference flows. | Clean local Docker preprod |
| Real browser | A browser follows redirects, stores safe cookies, enforces roles, and completes logout. | A dedicated local browser profile |
| Release acceptance | Every required layer passed for the exact archive and manifest that will be published. | Evidence from the checks above |

GitHub-hosted CI runs static, unit, contract, and final container-security
checks. The full image scan runs after a push to `main`. It requires DHI
credentials and fails when they are missing. Hosted CI does not
receive the local offline archive. It also does not run seeded preprod or a
real browser.

If a required stage did not run, mark it `NOT RUN` or `BLOCKED`. Do not call it
`PASS` because another stage was green.

## Required rehearsal order

Run these steps in order:

1. Run static, unit, contract, lint, and security checks.
2. Build new production and preprod schema-v2 release pairs.
3. Destroy only the namespaced `aigw-preprod` environment and old seed
   activation files.
4. Load the new preprod archive through the offline-seed loader.
5. Let Ansible start seed mode with `pull_policy: never` and no build sections.
6. Pass service, LDAPS, Root CA, Vault, WIF, Keycloak/OIDC, role, logout, and
   mocked-inference checks.
7. Complete the real-browser login, redirect, cookie, allow, deny, and logout
   checks.
8. Destroy namespaced preprod and record the release evidence.

The automated checks use real TLS, Samba AD, Keycloak, and HTTP session flows.
They do not launch a browser engine. The browser step is separate.

## Contents

1. [Run static release checks](#1-run-static-release-checks)
2. [Build and test the offline release](#2-build-and-test-the-offline-release)
3. [Run the real-browser check](#3-run-the-real-browser-check)
4. [Handle a failure and clean up](#4-handle-a-failure-and-clean-up)
5. [Understand the production boundary](#5-understand-the-production-boundary)
6. [Record the result](#6-record-the-result)

## 1. Run static release checks

Run commands from the repository root unless a command changes directory.

### Repository checks

```bash
bash scripts/validate-compose.sh
python3 -I -m unittest discover -v -s scripts/tests -p 'test_*.py'
python3 -I scripts/validate-identity-policy.py
python3 -I .github/scripts/validate-docs.py
bash .github/scripts/run-shellcheck.sh error
yamllint -c .yamllint.yml \
  .github .trivyignore.yaml .yamllint.yml ansible compose services
```

Pass only if every command exits zero. `validate-compose.sh` renders Compose.
It does not start containers.

### Python services

Install each service's pinned development tools in a clean virtual
environment. Run these commands inside each service directory:

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

The provider tests must prove all of these:

- repeated `--provider` values are sorted and deduplicated;
- empty, malformed, and unknown selections fail;
- a caller cannot pass an arbitrary hostname or CA path;
- equal selections produce equal policy and config bytes;
- different selections change policy and image identity;
- only selected routes and CA files enter the image; and
- changed fingerprints, dates, SNI, SANs, or CA files fail closed.

### GitHub release container scan

`.github/workflows/trivy.yml` is the final container scan. A pull request runs
the smaller repository and configuration scan. A push to `main` also performs
the full release scan. Manual dispatch is disabled so branch-selected workflow
code cannot request the DHI release secrets. Do not replace this gate with an
unrecorded local Trivy run.

The committed selection is in
`.github/release-container-security.json`. It currently selects
`linux/amd64` and Anthropic. The workflow uses the offline-seed builder to find
the full preprod union: every exact external image used by production or
preprod, and every unique final custom image. It then:

1. pulls each external image by its tag and digest;
2. rebuilds each custom release image from the commit;
3. fails for any `HIGH` or `CRITICAL` finding, including an unfixed finding;
4. applies only reviewed, owned, unexpired waivers: repository waivers in
   `.trivyignore.yaml` and version-scoped image PURLs in
   `.github/trivyignore-images.yaml`; and
5. uploads a Trivy JSON report, CycloneDX SBOM, and provenance record for each
   image. It also uploads the resolved image inventory and Envoy policy
   receipt.

A repository administrator must create the GitHub Environment named
`release-container-security`. Allow deployments from the protected `main`
branch only. Store `DHI_USERNAME` and `DHI_PASSWORD` in that environment, and
remove copies from repository-level or organization-level secrets available to
this repository. This is the real branch security boundary. A check inside a
workflow file cannot protect a repository secret from changed branch code.

The workflow fails when either DHI secret is missing. A failed pull, build,
scan, SBOM, provenance step, or artifact upload also fails the gate. The
workflow limits parallel jobs so it does not flood the private registry.

Read the evidence with these limits in mind:

- The runner rebuilds candidates from the Git commit. It does not receive or
  inspect the operator's local offline archive.
- The provenance JSON is useful GitHub Actions audit metadata. It is not a
  signed SLSA statement.
- Trivy uses the vulnerability database available at run time. A later scan
  can find a new issue in unchanged bytes.
- The committed CI selection proves only its listed platform and providers.
  The exact operator-selected offline release must still pass seeded preprod
  below.

The separate Go workflow keeps the network-disabled, repeat-build Envoy check.
It compares deterministic archives and checks the live policy receipt. The
complete release scan above is the authoritative container-security gate.

### Local Ansible syntax

```bash
ansible-playbook -i ansible/inventory/preprod.yml \
  ansible/preprod.yml --syntax-check
ansible-playbook -i ansible/inventory/preprod.yml \
  ansible/preprod-destroy.yml --syntax-check
```

Production syntax and preflight checks run with the real production inventory
when an operator deploys. They are not a reason to create a test VM.

## 2. Build and test the offline release

This is the required release rehearsal. It proves the exact offline images can
start without a pull or source build.

### Prerequisites

- Docker uses the local Unix socket.
- Docker is logged in to `dhi.io` with an entitled account.
- Every selected provider is in the committed provider catalog.
- Local Docker can run the target platform.
- The private output directory has enough free space.
- No unrelated Docker resource uses the `aigw-preprod` names.

Use `linux/arm64` instead of `linux/amd64` when ARM64 is the release target.

### Step 1: Build both release pairs

```bash
install -d -m 0700 /absolute/private/path/candidate
python3 -I scripts/update-images.py prepare \
  --provider anthropic \
  --platform linux/amd64 \
  --archive /absolute/private/path/candidate/aigw-candidate.docker.tar.zst \
  --manifest /absolute/private/path/candidate/aigw-candidate.manifest.json
```

The command writes four private files:

```text
aigw-candidate.docker.tar.zst
aigw-candidate.manifest.json
aigw-candidate.preprod.docker.tar.zst
aigw-candidate.preprod.manifest.json
```

The production pair contains no Samba AD or WIF mock bytes. The preprod pair
contains the production images plus those two test images. The command also
uses the reviewed missing-source-tag workaround after it checks each digest.

Record all four SHA-256 values:

```bash
# macOS
shasum -a 256 /absolute/private/path/candidate/aigw-candidate*

# Linux
sha256sum /absolute/private/path/candidate/aigw-candidate*
```

Run the command for your operating system, not both.

### Step 2: Destroy only old preprod

```bash
ansible-playbook -i ansible/inventory/preprod.yml \
  ansible/preprod-destroy.yml \
  -e preprod_destroy_confirmation=DESTROY_AIGW_PREPROD
```

On macOS, append `--ask-become-pass`.

The destroy play removes only the named preprod containers, volumes, networks,
and generated seed activation files. It removes only loopback aliases it owns.
It keeps the disposable preprod Root CA so the same browser trust can be used
across clean test runs.

Expected success marker:

```text
PREPROD_DESTROYED_CA_PRESERVED
```

Do not use `docker system prune`, a broad Compose project, or a broad delete.

### Step 3: Load and test the exact preprod seed

```bash
python3 -I scripts/update-images.py test-preprod \
  --archive /absolute/private/path/candidate/aigw-candidate.preprod.docker.tar.zst \
  --manifest /absolute/private/path/candidate/aigw-candidate.preprod.manifest.json \
  --load-archive
```

On macOS, append `--ask-become-pass`. Ansible creates only the missing owned
`127.0.2.1` and `127.0.3.1` aliases needed by Docker Desktop.

The updater stages private copies, loads the archive, checks the source and
manifest, and asks Ansible to start seed mode. Seed mode refuses every pull and
build command. It checks every image ID before startup.

Expected final markers:

```text
PREPROD_E2E_PASSED
SEEDED_PREPROD_E2E_PASSED
```

Pass only if the run proves all of these:

- every external and custom image ID matches the release receipt;
- the manifest scope is `preprod`;
- the Envoy image labels match the selected provider policy;
- no unselected provider route or CA file enters the Envoy image;
- every long-running service is healthy;
- `volume-init` exited successfully once;
- the Root CA signs the edge, Samba LDAPS, and WIF mock certificates;
- every certificate hostname and chain check passes;
- Vault is initialized, unsealed, and ready with disposable custody;
- identity setup completed without a portal initialization step;
- all three static users authenticate through Samba AD over LDAPS;
- Keycloak advertises `https://auth.aigw.internal/realms/aigw`;
- OIDC callback, role allow, role deny, and logout checks pass;
- WIF exchanges a real Keycloak JWT at the TLS mock;
- LiteLLM returns `pong` from the mocked provider path;
- `cribl-mock` receives every approved SOC event class as OTLP logs;
- `cribl-mock` receives no raw span, metric, alert, malformed event, Vault raw
  audit record, or ordinary service log;
- the SOC copy contains no credential, cookie, OIDC code, e-mail address, or
  network peer address; and
- unrelated Docker containers, volumes, and networks did not change.

The detailed preprod design and public test credentials are in
[Local Docker preprod](preprod.md). The exact event and receipt contract is in
[Cribl SOC logging handoff](cribl-soc-handoff.md).

`prepare --test-preprod` is a useful development shortcut. It is not the final
clean-start rehearsal unless you ran the namespaced destroy step first.

## 3. Run the real-browser check

Keep the seeded preprod environment running. Use a new browser profile with no
AI Gateway cookies.

Install only the marker-bounded preprod hosts block:

```bash
sudo python3 -I scripts/preprod.py install-hosts
```

Import `compose/secrets/preprod-root-ca.pem` into that test browser profile.
Do not add this CA to a normal user or production trust store.

Use the static accounts in [Local Docker preprod](preprod.md#static-test-users).
Record the result without recording cookie values.

Pass only if:

- every browser certificate is trusted for its `aigw.internal` name;
- redirects stay on the expected relying party and
  `auth.aigw.internal` issuer;
- `preprod-admin` reaches admin, chat, and the allowed admin UIs;
- `preprod-developer` reaches the developer portal and chat but is denied
  admin paths;
- `preprod-user` reaches chat but is denied portal and admin paths;
- session cookies are `Secure`, `HttpOnly`, and limited to the expected host
  and path;
- logout returns to the expected app and clears its session;
- Back followed by Refresh cannot reopen a protected page; and
- no callback loop, wrong-domain redirect, mixed content, or TLS warning
  appears.

Remove the test CA from the browser profile. Then remove only the managed hosts
block:

```bash
sudo python3 -I scripts/preprod.py remove-hosts
```

## 4. Handle a failure and clean up

If any required check fails:

1. Mark the release `FAIL` or `BLOCKED`.
2. Do not transfer or deploy the production archive.
3. Save only non-secret output, manifest hashes, image IDs, and the failing
   check name.
4. Fix the source, then build a new release with new filenames.
5. Repeat the full clean rehearsal. Do not hand-edit a manifest.

Remove preprod with the bounded destroy play:

```bash
ansible-playbook -i ansible/inventory/preprod.yml \
  ansible/preprod-destroy.yml \
  -e preprod_destroy_confirmation=DESTROY_AIGW_PREPROD
```

On macOS, append `--ask-become-pass`.

If cleanup refuses an ownership or boundary check, stop. Inspect the named
resource. Do not weaken the check or delete unrelated Docker resources.

## 5. Understand the production boundary

A locally accepted release produces a production-scoped archive that is ready
for controlled transfer. Local acceptance does not deploy it.

For a first production deployment, follow the
[production deployment runbook](deploy-runbook.md). It checks the real Rocky
Linux host, three customer-owned NICs, routes, firewall, SELinux, encrypted
storage, customer PKI, customer directory, Vault custody, and live services.

For a later image update, follow the
[image update workflow](image-update-workflow.md#4-upgrade-the-remote-host).
That command verifies the previous and candidate production seeds, takes an
encrypted backup, deploys through Ansible, validates the result, and rolls back
state, images, and the Envoy provider policy if a real validation fails.

Do not create a Rocky or Parallels rehearsal VM for this release gate. Do not
force an artificial failure on a production host. The upgrade and rollback
state machine is covered by contract tests; production validation runs during
the real approved maintenance.

PostgreSQL major changes do not use the normal image rollback. Follow the
[PostgreSQL 18 migration SOP](sop/postgresql-18-migration.md).

## 6. Record the result

Record:

- source commit;
- target platform;
- selected providers;
- all four release filenames and SHA-256 values;
- both manifest `release_scope` values;
- production and preprod manifest hashes;
- egress-policy digest and Envoy image ID;
- test date, workstation, Docker version, and operator;
- each command's result and expected marker;
- required CI job names and final status;
- browser checks, with no cookie values; and
- an owner and issue for every `FAIL`, `BLOCKED`, or `NOT RUN` result.

Accept the release only when:

- all static, unit, contract, lint, and security checks pass;
- every required CI job is complete, not skipped;
- the two scoped release pairs and hashes are recorded;
- a clean local preprod loaded the exact new preprod archive;
- Ansible seed mode used no pull or source build;
- automated LDAPS, CA, Vault, WIF, OIDC, role, logout, and inference checks
  passed;
- the real-browser checks passed; and
- bounded cleanup passed.

If credentials, disk space, browser access, or another required input is
missing, mark the release `BLOCKED`. Do not rename a missing test as a pass.
