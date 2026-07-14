# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

AI Gateway is a security-focused, self-hosted AI access platform: one hardened Docker Compose stack (LiteLLM OpenAI/Anthropic-compatible API, Open WebUI chat, Keycloak OIDC, Vault-backed provider credentials, key-rotator, pinned Envoy egress, Grafana/Prometheus/Loki/Tempo telemetry) deployed by Ansible onto an existing customer-owned Rocky Linux 9 VM with three NICs (egress / ADM / internal). It is a customer prototype under active hardening — see `docs/project-status.md` for open items.

There is **no top-level build entry point** — no Makefile, no root pytest config, no root go.mod. The authoritative commands live in `.github/workflows/*.yml` and `docs/test-runbook.md`.

## Commands

### The minimum local verification loop

Editing anything under `ansible/`, `compose/`, `scripts/`, or `.github/workflows/` very likely breaks exact-string contract assertions. Always run:

```bash
bash scripts/validate-compose.sh                                  # render-only Compose + contract gate; starts no containers; needs a local Docker daemon
python3 -I -m unittest discover -v -s scripts/tests -p 'test_*.py' # infrastructure contract suite (~315 tests, ~1 min); stdlib unittest, NOT pytest
python3 -I scripts/validate-identity-policy.py                    # identity policy parity (only needed for keycloak/realm changes)
```

All three run from the repo root. The scripts suite requires `ansible-vault`/`ansible-playbook` on PATH (some tests execute them).

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

Toolchain is pinned in each service's `requirements-dev.txt` (ruff 0.15.21, pytest 9.1.1, bandit 1.9.4); install with `pip install -r requirements-dev.txt` or use the clean-venv flow in `docs/test-runbook.md` §1. CI pins Python 3.12.13.

### Go modules (services/{dhi-health-probe,egress-proxy,vault-ui-proxy} — stdlib-only, no go.sum)

```bash
cd services/<module> && go test -race ./... && go vet ./...   # Go 1.25.x; three independent modules
```

Dockerfiles also run tests during `docker build` with `RUN --network=none`, so Go tests must never need network.

### YAML / Ansible lint

```bash
yamllint -c .yamllint.yml .github .trivyignore.yaml .yamllint.yml ansible compose services
ansible-playbook -i ansible/inventory/lab.yml ansible/site.yml --syntax-check --ask-vault-pass
```

CI reproduces with `ansible-core==2.21.1` + `yamllint==1.38.0` (minimum ansible-core is 2.16) and `ansible-galaxy collection install -r ansible/requirements.yml`. There is **no ansible-lint**.

### Shell lint

```bash
bash .github/scripts/run-shellcheck.sh error   # blocking bar in CI; currently clean
bash .github/scripts/run-shellcheck.sh info    # advisory; 16 known pre-existing findings
```

ShellCheck (pinned by tag+digest, run in Docker) replaced the old `bash -n` gate. `run-shellcheck.sh` holds the **single** target list, and `scripts/tests/test_ci_health_checks.py` fails if a tracked shell file is neither listed there nor explicitly excluded — so a new root-run script cannot quietly escape the linter. `ansible/**/templates/*.j2` are excluded and unlintable: ShellCheck cannot parse Jinja.

### Deploy (controller → target VM)

```bash
ansible-galaxy collection install -r ansible/requirements.yml
scripts/bootstrap-generic-rocky9.py --inventory-alias <alias> --vault-id <alias> --vault-password-file <file>
# edit ansible/inventory/generated/<alias>/host_vars/<alias>.yml, then:
ansible-playbook -i ansible/inventory/generated/<alias>/hosts.yml ansible/preflight-generic-rocky9.yml --limit <alias> --vault-id <alias>@<file>
ansible-playbook -i ansible/inventory/generated/<alias>/hosts.yml ansible/site.yml --limit <alias> --vault-id <alias>@<file>
```

Lab profile instead: `ansible-playbook -i ansible/inventory/lab.yml ansible/site.yml --ask-vault-pass` (lab uses `--ask-vault-pass`; generated inventories use `--vault-id`). App-only updates after a successful full converge: `ansible/deploy-stack-only.yml` — if it refuses (stale firewall/network ABI), run the full `site.yml`; never bypass its assertions.

The converge is **deliberately two-pass**: the first `site.yml` run leaves Vault uninitialized (expected, not a failure); then the Vault init ceremony runs (lab: `sudo scripts/vault-bootstrap.sh` on the VM from `/opt/ai-gateway`; production: operator ceremony + `scripts/store-vault-unseal-key.py` on the controller); then the identical `site.yml` command runs again for strict readiness.

### CI-only gates (no local invocation — don't chase these locally)

Trivy fs scan (HIGH/CRITICAL, waivers only via `.trivyignore.yaml` with `expired_at` + justification), actionlint + zizmor + **mandatory full-commit-SHA pinning of every workflow `uses:`** (a bare `@v4` fails CI), dependency-review, gitleaks over full git history (a secret committed then removed still fails). Final DHI image builds skip on PRs without `dhi.io` credentials — a green PR does not prove images build.

**`runtime-skew.yml` is advisory and expected to be loud.** `validate-compose.sh` only proves the rendered *model*; this workflow starts real containers and asserts the *runtime* contracts the verify role checks on a live host (tmpfs option tokens, live-project `exec` under the joined profile set) against both the runner's Compose and the newest upstream release — the one a converge actually installs, since `os_baseline` pins no `docker-compose-plugin` version. It never blocks a merge (upstream must not red-wall unrelated PRs); it annotates, writes a job summary, and files an issue on scheduled runs. Run it with `strict: true` from the Actions tab to gate on it deliberately. This canary independently rediscovered both Compose-v5 skew bugs that broke live converges (`COMPOSE_PROFILES` emptied on live-project `exec`; the implicit `rw` tmpfs token no longer materialised) — both are fixed as of `58267fa`, so it should now report clean. Assertions state the security property and tolerate the format: require `noexec,nosuid,nodev,uid,gid,mode` and the *absence* of `ro`, never a literal `rw`.

`repo-hygiene.yml`: ShellCheck (blocking at `error`, advisory at `info`), JSON duplicate-key/BOM rejection, and an advisory contract-test drift guard that flags a PR touching `ansible/`, `compose/`, `scripts/`, or `.github/workflows/` with no matching contract-test or validator change. The drift guard is a reviewer prompt and never blocks. `scorecard.yml`: OpenSSF Scorecard, scheduled, advisory, results to the Security tab only (`publish_results: false` — this prototype's posture is not public telemetry).

## Architecture

**Two-machine model.** A controller workstation (macOS/Linux, ansible-core) runs everything against the target VM over SSH. Ansible configures an existing host only — it never provisions VMs, NICs, addresses, routes, or DNS, and `site.yml` refuses to run if declared topology disagrees with live facts (no override switches; fix inventory or the host).

**Ansible converge** (`ansible/site.yml`) runs 11 roles in a security-load-bearing order: `host_preflight → firewall_preflight → time_sync → selinux_baseline → network_routing → firewalld_zones → os_baseline → docker_networks → docker_stack → verify → host_finalize`. Routing and firewall (DOCKER-USER + independent nftables `aigw_guard`) must be live before any container starts; security handlers are flushed in-role — never move them to end-of-play. `host_finalize` promotes the `/etc/ai-gateway/dedicated-docker-host-v1` marker that gates `deploy-stack-only.yml`. Two profiles exist: `generic-rocky9` (customer, fail-closed, requires LUKS-encrypted state) and `rocky9-lab` (committed lab inventory; the only place lab-only exceptions like Samba AD or unencrypted state are legal).

**`ansible/generic-rocky9-contract.json`** is the shared contract between `scripts/bootstrap-generic-rocky9.py` (generates the encrypted inventory), `ansible/preflight-generic-rocky9.yml` (controller-only validation, emits an `AIGW_GENERIC_PREFLIGHT` JSON receipt), and the host_vars template. Adding a secret or topology key means touching all consumers. `vault_unseal_key` is the sole operator-supplied secret — it cannot exist until `vault operator init`.

**Compose stack** (`compose/docker-compose.yml`, project `ai-gateway`, deployed to `/opt/ai-gateway`) defines 25 services — one-shot `volume-init` plus 24 long-running, of which `vault-ui-proxy`/`oauth2-proxy-vault` are gated behind the `vault-ui` profile (23 run by default). The lab overlay adds `samba-ad` + `lab-dns`. Ansible assembles the file/profile list — **never run `docker compose up` by hand**; on a deployed host use `scripts/aigw-compose.sh`, which derives files and profiles from `.env`. Two shared anchors: `x-hardening` (cap_drop ALL, no-new-privileges, bounded logging) merges into every long-running service; `volume-init` deliberately does not inherit it.

**Networks are a firewall ABI.** All 20 bridges (172.28.0.0/24 … 172.28.19.0/24) are pre-created by Ansible as `external: true` (base stack attaches 18); bridge names, subnets, and fixed `ipv4_address` values (e.g. Envoy at 172.28.0.2) feed DOCKER-USER allowlists, trusted-proxy lists, and `site.yml`'s embedded topology check. Changing one requires updating `ansible/group_vars/all.yml`, the compose file, and the firewall expectations together. Only Traefik publishes ports, bound to exact NIC IPs (`${ETH1_IP}`/`${ETH2_IP}`), never 0.0.0.0.

**Egress.** LiteLLM and key-rotator speak plain HTTP to `http://envoy-egress:8080/anthropic/...` or `/openai/...`; Envoy is the only workload allowed external DNS/443 and originates TLS with narrowed per-vendor CA bundles. Its compiled Go entrypoint is a trust boundary (validates CA bundles, refuses config overrides) — never override `entrypoint:` in compose.

**Bind-source digest mechanism.** Every bind-mounting service carries a `com.aigw.contract.bind-source-digest` label (HMAC-SHA256 over config content, computed by `scripts/compute-bind-source-digests.py` from `compose/bind-source-digest-inputs.json`, keyed by host-local `.state/bind-digest.key`). Changing any bind-mounted config (traefik, litellm, keycloak realms, grafana provisioning, …) therefore requires an Ansible re-converge — a manual `compose up` fails closed (`${AIGW_BIND_DIGEST_*:?}`). Adding/removing a bind mount means updating **five places in sync**: the service's volumes + digest label in `docker-compose.yml`, `bind-source-digest-inputs.json`, `ansible/roles/docker_stack/templates/env.j2`, the digest sets in `validate-compose.sh`, and the SELinux bind-source list in the docker_stack role.

**services/ layout.** Three stdlib-only Go modules (`dhi-health-probe` health binary layered onto ~15 images, `egress-proxy` Envoy entrypoint gate, `vault-ui-proxy`); two FastAPI/Python services (`dev-portal` — one image serving both dev-portal and admin-portal ASGI apps; `key-rotator` — rotation engine + Keycloak identity controller, all routes gated by `X-Internal-Auth`); three packaging-only image dirs (`traefik`, `lab-dns`, `samba-ad-lab`). All images are tag-AND-digest pinned — never `latest`, never blind `docker compose pull`.

**Vault lifecycle.** `vault-bootstrap.sh` is lab/test-only (refuses unless `DEPLOYMENT_PROFILE=rocky9-lab`), one-time, and **forbidden on the restore path**; it hard-fails on an initialized Vault. Vault seals on every restart; `scripts/vault-unseal.sh` takes the share on stdin only. Later converges auto-unseal from the encrypted controller-held `vault_unseal_key` (stored via `store-vault-unseal-key.py` in a dedicated inline-encrypted overlay — never in `group_vars/all.yml`, which a contract test enforces).

## Conventions that will bite you

- **Exact-string contract tests pin the reviewed text.** `scripts/tests/*.py` and `validate-compose.sh` assert exact task names, ordering, mount flags, healthcheck arrays, Dockerfile lines, and workflow text across `ansible/`, `compose/`, `scripts/`, and `.github/workflows/`. Most edits there require a matching test/validator update — this is by design, not test brittleness. Python `assert` statements are the release gates; don't refactor them into logging.
- **Operational script manifest:** a new script in `scripts/` that ships to the VM must be added to the manifest in `ansible/roles/docker_stack/tasks/main.yml` (24 entries) AND the expected list in `validate-compose.sh`.
- **Secrets travel on stdin only** — never argv, env vars, or logs. `vault-unseal.sh` and `store-vault-unseal-key.py` refuse a TTY; Ansible uses `no_log` with `stdin:`. Follow the `read -rsp` + pipe idiom. Never print, diff, or commit decrypted vault overlay values.
- **unittest vs pytest split:** `scripts/tests` is stdlib unittest run from the repo root; service tests are pytest run from inside the service dir. The live-lab harnesses (`scripts/test-portal-*.py`, `test-oidc-callbacks.py`, `verify-live-lab-identity.py`) are hyphenated on purpose — they hit a real deployed lab; don't run them casually or add them to discovery.
- **SELinux relabel suffixes are load-bearing:** shared bind mounts (`./certs`, `ca.pem`) use `:ro,z`; private mounts use `:ro,Z`. Switching z→Z lets the last-created container steal the label from its peers. Short bind syntax (not the long mount form) is required.
- **Don't "fix" intentional non-strict dependencies:** `key-rotator` uses `depends_on vault: service_started` (not healthy) and admin-portal similarly, because a fresh/sealed Vault keeps `/readyz` at 503 until the unseal ceremony — requiring health would deadlock the first converge.
- **Single-worker constraint:** dev-portal runs uvicorn with exactly `--workers 1` and key-rotator keeps one replica — key-issuance dedupe and last-admin protection are process-local locks. Never scale these ad hoc.
- **Python deps:** `requirements.txt` pins must be exact `==` and present in `requirements.lock`, regenerated with `uv pip compile requirements.txt --python-version 3.12 --python-platform linux --generate-hashes --output-file requirements.lock` (the header line is asserted). `requirements-dev.txt` must never enter production images.
- **Keycloak realm JSON imports only into an empty database** — editing realm templates does nothing to an existing realm.
