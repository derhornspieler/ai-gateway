# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## What this is

AI Gateway is a security-focused, self-hosted AI access platform. Production
runs one hardened Docker Compose stack on an existing customer-owned Rocky
Linux 9 VM with egress, ADM, and internal interfaces. The stack includes
LiteLLM, Open WebUI, Keycloak, Vault, key-rotator, Envoy egress, and local
telemetry. Local preprod runs the same application on one local Docker engine.
See `docs/project-status.md` for open items.

There is **no top-level build entry point** — no Makefile, no root pytest config, no root go.mod. The authoritative commands live in `.github/workflows/*.yml` and `docs/test-runbook.md`.

## Commands

### The minimum local verification loop

Editing anything under `ansible/`, `compose/`, `scripts/`, or `.github/workflows/` very likely breaks exact-string contract assertions. Always run:

```bash
bash scripts/validate-compose.sh                                  # render-only Compose + contract gate; starts no containers; needs a local Docker daemon
python3 -I -m unittest discover -v -s scripts/tests -p 'test_*.py' # infrastructure contract suite; stdlib unittest, NOT pytest
python3 -I scripts/validate-identity-policy.py                    # identity policy parity (only needed for keycloak/realm changes)
```

All three run from the repository root. Some script tests call
`ansible-vault` and `ansible-playbook`, so both must be on `PATH`. Only
`validate-compose.sh` needs the local Docker daemon. Release acceptance uses
the local offline-seed preprod path in `docs/test-runbook.md`; it does not need
a Rocky or Parallels test VM.

### Infrastructure tests (scripts/tests — stdlib unittest)

```bash
python3 -m unittest -v scripts/tests/test_<name>.py                       # single file (repo root only)
python3 -m unittest -v scripts.tests.test_<name>.<TestClass>.<test_method> # single test method
```

### Python services (services/dev-portal, services/key-rotator — pytest)

Run from **inside the service directory** — never bare `pytest` from the repo root (key-rotator tests fail that way):

```bash
cd services/<service>
PYTHONPATH=. pytest -q                            # whole suite
PYTHONPATH=. pytest -q tests/test_<file>.py::<test_name>  # single test
ruff check app tests                              # lint
bandit -q -r app --severity-level medium --confidence-level medium  # security gate (CI variant; the runbook's --severity-level high is a looser release-flow supplement)
```

Toolchain is pinned in each service's `requirements-dev.txt` (ruff 0.15.22, pytest 9.1.1, bandit 1.9.4); install with `pip install -r requirements-dev.txt` or use the clean-venv flow in `docs/test-runbook.md` §1. CI pins Python 3.14.6.

### Go modules (services/{dhi-health-probe,egress-proxy,vault-ui-proxy,wif-provider-mock} — stdlib-only, no go.sum)

```bash
cd services/<module> && go test -race ./... && go vet ./...   # Go 1.26.x; four independent modules
```

Dockerfiles also run tests during `docker build` with `RUN --network=none`, so Go tests must never need network.

### YAML / Ansible lint

```bash
yamllint -c .yamllint.yml .github .trivyignore.yaml .yamllint.yml ansible compose services
ansible-playbook -i ansible/inventory/preprod.yml ansible/preprod.yml --syntax-check
ansible-playbook -i ansible/inventory/generated/<alias>/hosts.yml \
  ansible/site.yml --syntax-check --limit <alias> \
  --vault-id <vault-id>@<vault-password-file>
```

CI reproduces with `ansible-core==2.21.2` + `yamllint==1.38.0` (minimum ansible-core is 2.16) and `ansible-galaxy collection install -r ansible/requirements.yml`. There is **no ansible-lint**.

### Shell lint

```bash
bash .github/scripts/run-shellcheck.sh error   # blocking bar in CI; currently clean
bash .github/scripts/run-shellcheck.sh info    # advisory; 16 known pre-existing findings
```

ShellCheck (pinned by tag+digest, run in Docker) replaced the old `bash -n` gate. `run-shellcheck.sh` holds the **single** target list, and `scripts/tests/test_ci_health_checks.py` fails if a tracked shell file is neither listed there nor explicitly excluded — so a new root-run script cannot quietly escape the linter. `ansible/**/templates/*.j2` are excluded and unlintable: ShellCheck cannot parse Jinja.

### Deploy (controller → target VM)

```bash
ansible-galaxy collection install -r ansible/requirements.yml
scripts/bootstrap-rocky9-production.py --inventory-alias <alias> --vault-id <alias> --vault-password-file <file>
# edit ansible/inventory/generated/<alias>/host_vars/<alias>.yml, then:
ansible-playbook -i ansible/inventory/generated/<alias>/hosts.yml ansible/preflight-rocky9-production.yml --limit <alias> --vault-id <alias>@<file>
ansible-playbook -i ansible/inventory/generated/<alias>/hosts.yml ansible/site.yml --limit <alias> --vault-id <alias>@<file>
```

Local preprod is a separate localhost-only flow. It does not run the Rocky host
roles:

```bash
ansible-playbook -i ansible/inventory/preprod.yml ansible/preprod.yml
python3 -I scripts/test-e2e-preprod.py
```

See `docs/preprod.md` for seed mode, local names, and safe removal.

**Run converges from the repo root with pipelining ON — it is a confidentiality control.** The automatic Vault-unseal task and the LDAP bind task pass their decrypted secret on the command module's `stdin` under `no_log`. `no_log` only suppresses Ansible's own logging; with pipelining **off** Ansible still base64-embeds that stdin in the AnsiballZ module payload it writes to `~/.ansible/tmp` on the **target**. Pipelining streams the module over the SSH session so the secret never lands on remote disk. Ansible only auto-loads `./ansible.cfg` from the current directory, so the committed **repo-root `ansible.cfg`** (a mirror of `ansible/ansible.cfg`, both set `pipelining = True` in `[defaults]`) is what makes `ansible-playbook … ansible/site.yml` from the repo root safe. Verify before a converge: `ansible-config dump | grep PIPELINING` must show `= True`, never `(default) = False`. Invoking from another directory requires `ANSIBLE_PIPELINING=True` (or `ANSIBLE_CONFIG=$PWD/ansible/ansible.cfg`). The two `ansible.cfg` files are pinned in sync by `scripts/tests/test_vault_ansible_unseal_contract.py`.

**Three playbooks, one converge.** `ansible/site.yml` is a pure composition — `import_playbook: os-prep.yml` then `import_playbook: deploy-stack-only.yml` — and all three accept the same inventory/vault arguments:

- `ansible/site.yml` — the full converge (host prep + stack). First deploys and whenever unsure.
- `ansible/os-prep.yml` — host preparation only: the read-only input/topology validation plus roles `host_preflight`→`docker_networks`. Starts no containers; on a first converge it leaves the pending dedicated-host marker as the host-prep-done signal.
- `ansible/deploy-stack-only.yml` — stack only (`docker_stack`, `verify`, `host_finalize`): app/config updates on a prepared host, or the second half of a first deploy after `os-prep.yml`. It refuses a host without the exact completed-or-pending dedicated-host marker or with a stale live firewall/network ABI — if it refuses, run the full `site.yml`; never bypass its assertions.

The converge is **deliberately two-pass**: the first `site.yml` run leaves Vault uninitialized (expected, not a failure); then the reviewed production Vault init ceremony runs and `scripts/store-vault-unseal-key.py` stores the share on the controller; then the identical `site.yml` command runs again for strict readiness.

### CI-only gates (no local invocation — don't chase these locally)

Trivy fs scan (HIGH/CRITICAL, waivers only via `.trivyignore.yaml` with `expired_at` + justification), actionlint + zizmor + **mandatory full-commit-SHA pinning of every workflow `uses:`** (a bare `@v4` fails CI), dependency-review, gitleaks over full git history (a secret committed then removed still fails). Final DHI image builds skip on PRs without `dhi.io` credentials — a green PR does not prove images build.

**`runtime-skew.yml` is advisory.** `validate-compose.sh` checks the rendered
model. The workflow also starts containers and checks runtime behavior against
the pinned Compose version and the newest upstream release. It warns before a
future pin update breaks tmpfs options or live-project `exec`. Scheduled runs
can file an issue, but normal runs do not block a merge. Use `strict: true` from
the Actions page when the result must gate a planned version update. Runtime
checks require `noexec,nosuid,nodev,uid,gid,mode` and must not contain `ro`;
they do not depend on a literal `rw` token.

`repo-hygiene.yml`: ShellCheck (blocking at `error`, advisory at `info`), JSON duplicate-key/BOM rejection, and an advisory contract-test drift guard that flags a PR touching `ansible/`, `compose/`, `scripts/`, or `.github/workflows/` with no matching contract-test or validator change. The drift guard is a reviewer prompt and never blocks. `scorecard.yml`: OpenSSF Scorecard, scheduled, advisory, results to the Security tab only (`publish_results: false` — this prototype's posture is not public telemetry).

## Architecture

**Two-machine model.** A controller workstation (macOS/Linux, ansible-core) runs everything against the target VM over SSH. Ansible configures an existing host only — it never provisions VMs, NICs, addresses, routes, or DNS, and `site.yml` refuses to run if declared topology disagrees with live facts (no override switches; fix inventory or the host).

**Ansible converge.** `ansible/site.yml` runs `os-prep.yml` and then
`deploy-stack-only.yml`. Its role order is:

`host_preflight → firewall_preflight → time_sync → selinux_baseline → network_routing → firewalld_zones → os_baseline → docker_networks → docker_stack → verify → host_finalize`

Routing and both firewall layers must be live before any container starts.
Security handlers run inside their role; do not move them to the end. Host
preparation writes `/etc/ai-gateway/dedicated-docker-host-v1.pending`.
`host_finalize` replaces it with the completed marker only after verification.
`deploy-stack-only.yml` refuses a host without an exact pending or completed
marker. The canonical profile is `rocky9-production`; `generic-rocky9` is a
deprecated alias. Local preprod is a separate localhost workflow.

**`ansible/generic-rocky9-contract.json`** is shared by the production
bootstrap, controller preflight, and host-variables template. Adding a secret
or topology key means updating every consumer. `vault_unseal_key` cannot exist
until `vault operator init` and belongs in its dedicated encrypted overlay.

**Compose stack** (`compose/docker-compose.yml`, project `ai-gateway`, deployed to `/opt/ai-gateway`) defines 24 services — one-shot `volume-init` plus 23 long-running, of which `vault-ui-proxy`/`oauth2-proxy-vault` are gated behind the `vault-ui` profile (22 run by default, including the one-shot). Ansible may add the optional `platform-dns` overlay. **Never run `docker compose up` by hand** on a deployed host; use `scripts/aigw-compose.sh`, which derives files and profiles from `.env`. Local preprod uses `compose/docker-compose.preprod.yml` and `scripts/preprod.py`. Two shared anchors: `x-hardening` (cap_drop ALL, no-new-privileges, bounded logging) merges into every long-running service; `volume-init` deliberately does not inherit it.

**Networks are a firewall ABI.** All 20 bridges (172.28.0.0/24 … 172.28.20.0/24; 172.28.16.0/24 is retired/reserved) are pre-created by Ansible as `external: true` (base stack attaches 18); bridge names, subnets, and fixed `ipv4_address` values (e.g. Envoy at 172.28.0.2) feed DOCKER-USER allowlists, trusted-proxy lists, and `site.yml`'s embedded topology check. Changing one requires updating `ansible/group_vars/all.yml`, the compose file, and the firewall expectations together. Only Traefik publishes ports, bound to exact NIC IPs (`${ETH1_IP}`/`${ETH2_IP}`), never 0.0.0.0.

**Egress.** Anthropic is the only approved provider today. LiteLLM and key-rotator speak plain HTTP to `http://envoy-egress:8080/anthropic/...`; Envoy is the only workload allowed external DNS/443 and originates TLS with the reviewed Anthropic CA bundle. Its compiled Go entrypoint is a trust boundary (validates CA bundles, refuses config overrides) — never override `entrypoint:` in compose. A new provider requires a reviewed catalog and release change.

**Bind-source digest mechanism.** Every bind-mounting service carries a `com.aigw.contract.bind-source-digest` label (HMAC-SHA256 over config content, computed by `scripts/compute-bind-source-digests.py` from `compose/bind-source-digest-inputs.json`, keyed by host-local `.state/bind-digest.key`). Changing any bind-mounted config (traefik, litellm, keycloak realms, grafana provisioning, …) therefore requires an Ansible re-converge — a manual `compose up` fails closed (`${AIGW_BIND_DIGEST_*:?}`). Adding/removing a bind mount means updating **five places in sync**: the service's volumes + digest label in `docker-compose.yml`, `bind-source-digest-inputs.json`, `ansible/roles/docker_stack/templates/env.j2`, the digest sets in `validate-compose.sh`, and the SELinux bind-source list in the docker_stack role.

**services/ layout.** Four Go modules use only the standard library:
`dhi-health-probe`, `egress-proxy`, `vault-ui-proxy`, and the preprod-only
`wif-provider-mock`. The two Python services are `dev-portal`, whose image also
serves the admin portal, and `key-rotator`, which also controls identity.
Packaging directories include `traefik`, `platform-dns`, and
`samba-ad-preprod`. All images use a tag and digest. Never use `latest` or a
blind `docker compose pull`.

**Vault lifecycle.** Vault initialization is a reviewed production operator ceremony and is **forbidden on the restore path**. Vault seals on every restart; `scripts/vault-unseal.sh` takes the share on stdin only. Later converges auto-unseal from the encrypted controller-held `vault_unseal_key` (stored via `store-vault-unseal-key.py` in a dedicated inline-encrypted overlay — never in `group_vars/all.yml`, which a contract test enforces).

## Conventions that will bite you

- **Exact-string contract tests pin the reviewed text.** `scripts/tests/*.py` and `validate-compose.sh` assert exact task names, ordering, mount flags, healthcheck arrays, Dockerfile lines, and workflow text across `ansible/`, `compose/`, `scripts/`, and `.github/workflows/`. Most edits there require a matching test/validator update — this is by design, not test brittleness. Python `assert` statements are the release gates; don't refactor them into logging.
- **Operational script manifest:** a new script in `scripts/` that ships to the VM must be added to the manifest in `ansible/roles/docker_stack/tasks/main.yml` (26 entries) AND the expected list in `validate-compose.sh`.
- **Secrets travel on stdin only** — never argv, env vars, or logs. `vault-unseal.sh` and `store-vault-unseal-key.py` refuse a TTY; Ansible uses `no_log` with `stdin:`. Follow the `read -rsp` + pipe idiom. Never print, diff, or commit decrypted vault overlay values.
- **unittest vs pytest split:** `scripts/tests` is stdlib unittest run from the repo root; service tests are pytest run from inside the service dir. Runtime acceptance harnesses are hyphenated on purpose; do not add them to unit-test discovery.
- **SELinux relabel suffixes are load-bearing:** shared bind mounts (`./certs`, `ca.pem`) use `:ro,z`; private mounts use `:ro,Z`. Switching z→Z lets the last-created container steal the label from its peers. Short bind syntax (not the long mount form) is required.
- **Don't "fix" intentional non-strict dependencies:** `key-rotator` uses `depends_on vault: service_started` (not healthy) and admin-portal similarly, because a fresh/sealed Vault keeps `/readyz` at 503 until the unseal ceremony — requiring health would deadlock the first converge.
- **Single-worker constraint:** dev-portal runs uvicorn with exactly `--workers 1` and key-rotator keeps one replica — key-issuance dedupe and last-admin protection are process-local locks. Never scale these ad hoc.
- **Python deps:** `requirements.txt` pins must be exact `==` and present in `requirements.lock`, regenerated with `uv pip compile requirements.txt --python-version 3.14 --python-platform linux --generate-hashes --output-file requirements.lock` (the header line is asserted). `requirements-dev.txt` must never enter production images.
- **Keycloak realm JSON imports only into an empty database** — editing realm templates does nothing to an existing realm.
