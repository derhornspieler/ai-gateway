# Acceptance runbook — destroy and redeploy from a clean VM, then validate end-to-end

This is a **push-button acceptance runbook**: it takes a clean Rocky 9 VM to a fully
converged, verified AI Gateway and then proves the deployment end-to-end. It works for
**both** the Parallels lab (`aigw01`) and **production**, with the substitutions called out
in [Production differences](#production-differences).

It is authored to be executed top-to-bottom by an operator (or an orchestrator). Every
command has been checked against the actual playbooks and scripts in this repo — nothing
here is invented. Read [CLAUDE.md](../CLAUDE.md) once first; the invariants it lists
(repo-root converges, pipelining as a confidentiality control, secrets on stdin only,
two-pass converge) are load-bearing here.

> **Edge-TLS mode used by this runbook.** The lab path below exercises
> **`customer-intermediate`** end to end (operator supplies an intermediate CA
> certificate **+ private key** + chain; Vault imports it and issues every leaf). This is
> the same mode a customer uses, so the lab rehearses the real ceremony. The committed lab
> host_vars (`ansible/inventory/host_vars/lab-aigw01.yml`) ships `vault-intermediate`
> instead (Vault mints the key, customer CA signs a CSR); if you use that mode, replace
> the Phase 3 `import-intermediate` call with the `csr` → `install-signed` pair
> (see [Alternative edge modes](#alternative-edge-modes)). Everything else is identical.

---

## What you get / topology reference

**Two machines.** A *controller* (macOS/Linux with `ansible-core`) drives everything over
SSH; Ansible only *configures* an existing VM — it never provisions the VM, its NICs,
addresses, routes, or DNS. The *target VM* is a Rocky 9 host with three NICs and a
LUKS-backed disk.

**Three planes / NICs** (lab values shown; production differs):

| Plane | NIC (lab) | IP var | Lab IP | Purpose |
|---|---|---|---|---|
| egress | `enp0s5` | `eth0_ip` | `10.211.55.3` | Internet-facing; only Envoy egresses |
| ADM | `enp0s7` | `eth1_ip` | `10.8.10.10` | admin/operator edge (`traefik-adm`), VPN-restricted |
| internal | `enp0s8` | `eth2_ip` | `10.20.0.10` | user edge (`traefik-int`) |

**FQDN → plane map** (source of truth: `compose/traefik/dynamic-adm.yml` +
`compose/traefik/dynamic-int.yml`). HTTPS terminates **only** at the two Traefik edges,
each bound to one NIC IP, publishing only `:443`. All names use the same wildcard
`*.<domain>` (+ apex) leaf.

| FQDN (`<label>.<domain>`) | Plane / edge | Backend | Notes |
|---|---|---|---|
| `chat.` | **both** (ADM + internal) | open-webui | dual-homed (owner decision): VPN admins via ADM, LAN users via internal; one OIDC client, gated by `aigw-chat` |
| `admin.` | ADM | admin-portal | |
| `litellm-admin.` | ADM | oauth2-proxy → litellm | native LiteLLM admin UI |
| `grafana.` | ADM | oauth2-proxy-grafana | |
| `prometheus.` | ADM | oauth2-proxy-prometheus | |
| `vault.` | ADM | oauth2-proxy-vault | only when `aigw_vault_ui_enabled: true` |
| `auth.` | **both** | keycloak | ADM = full admin console; internal = OIDC browser subset only |
| `api.` | internal (`traefik-int`) | litellm | inference paths allow-listed; everything else 403 |
| `portal.` | internal | dev-portal | user self-service portal |

Admin FQDNs must **404 on the internal edge**; user FQDNs must **404 on the ADM edge**.
`auth.` answers on both (different path scopes).

**OIDC clients** (realm `aigw`, `compose/keycloak/realms/aigw-realm.json`):

| client_id | redirect_uri (`<domain>` = your deployment domain) |
|---|---|
| `open-webui` | `https://chat.<domain>/oauth/oidc/callback` |
| `dev-portal` | `https://portal.<domain>/auth/callback` |
| `admin-portal` | `https://admin.<domain>/auth/callback` |
| `admin-ui` | `https://litellm-admin.<domain>/oauth2/callback` (also grafana/prometheus/vault) |

**Egress.** Envoy is pinned at `172.28.0.2` (`net-egress`, `172.28.0.0/24`) and is the
**only** workload permitted external DNS/443, enforced independently by DOCKER-USER and the
native nft `aigw_guard`.

**Expected running containers after a full converge:**

- **Lab** (this runbook: `customer-intermediate`, with `platform_authoritative_dns`,
  `samba_lab`, and `vault_ui` enabled) → **26 long-running containers healthy** (22 base
  + `lab-dns` + `samba-ad` + `oauth2-proxy-vault` + `vault-ui-proxy`) plus the one-shot
  `volume-init` that exits 0.
- **Production default** (no vault-ui, no platform-DNS, no Samba) → **22 long-running**.

The `verify` role proves the exact set healthy and prints `selinux-runtime-contract=ok …`;
the play recap must end `failed=0`.

---

## Prerequisites (controller)

```bash
# From the repo root ALWAYS (loads ./ansible.cfg → pipelining = confidentiality control).
cd /path/to/ai-gateway

# Ansible collections.
ansible-galaxy collection install -r ansible/requirements.yml

# Pipelining MUST be on, or refuse to converge (secrets ride module stdin under no_log).
ansible-config dump | grep PIPELINING     # must show '= True', never '(default) = False'
```

You also need a private, `0600` Ansible-Vault password file and a Vault-ID label for the
custody helper (`scripts/store-vault-unseal-key.py` requires both even when the converge
uses `--ask-vault-pass`). For the lab, its content must equal the password protecting the
lab overlay `ansible/inventory/group_vars/gateway/vault.yml`:

```bash
umask 077
printf '%s' 'THE-LAB-VAULT-PASSWORD' > ~/.aigw-lab-vault-pass   # 0600, never committed
export AIGW_VAULT_ID=lab
export AIGW_VAULT_PASSWORD_FILE=~/.aigw-lab-vault-pass
```

---

## Phase 0 — clean VM

### Lab (Parallels `aigw01`)

Revert to a clean **pre-AIGW** snapshot. That snapshot must be Rocky 9 with the three NICs
(`enp0s5`/`enp0s7`/`enp0s8` = egress/ADM/internal) on a **LUKS-backed** disk and **no
AIGW configuration** (no `/etc/ai-gateway`, no Docker stack, vanilla firewalld/SELinux).

```bash
# On the controller / Parallels host:
prlctl snapshot-list aigw01                       # find the clean pre-AIGW snapshot id
prlctl snapshot-switch aigw01 --id <CLEAN_SNAPSHOT_ID>
prlctl start aigw01                               # if not auto-started
```

Sanity-check the reverted host (expect a bare Rocky 9, three NICs, LUKS, no AIGW marker):

```bash
ssh ansible@10.8.10.10 'ls /etc/ai-gateway 2>/dev/null; \
  ip -brief -4 addr show; \
  lsblk -o NAME,FSTYPE,MOUNTPOINT | grep -i crypto; \
  docker ps 2>/dev/null || echo "no docker / no containers (expected)"'
```

You should see **no** `/etc/ai-gateway/dedicated-docker-host-v1*` marker and **no** running
containers.

### Production

The engineer provisions a **fresh Rocky 9 VM** with three NICs (egress/ADM/internal), a
**LUKS-encrypted** system/data disk (LUKS is a build-time concern the converge does **not**
manage — it only warns), a management SSH key on the ADM interface, and provides the **ADM
IP** (and the other two NIC IPs/gateways). Confirm the same prerequisites as above:
vanilla host, three NICs owning their configured IPs, exactly one default route via the
egress NIC, chrony synced, and no foreign Docker containers/networks.

---

## Phase 0b — stage the intermediate CA (customer-intermediate only, controller, one-time)

`customer-intermediate` needs the operator's **intermediate CA certificate + PRIVATE KEY +
complete chain** staged into the gitignored `ansible/inventory/local-pki/`. Use the shipped
safe template:

```bash
# Point these at YOUR intermediate CA outputs (the ROOT key is never referenced/copied):
export AIGW_LOCAL_PKI_INT_CERT=/path/to/intermediate-ca.pem
export AIGW_LOCAL_PKI_INT_KEY=/path/to/intermediate-ca-key.pem     # 0600
export AIGW_LOCAL_PKI_CHAIN=/path/to/ca-chain.pem                  # intermediate + root
bash ansible/inventory/examples/rocky9-lab.stage-customer-intermediate.sh.example
# -> stages ansible/inventory/local-pki/{intermediate.pem,intermediate.key,ca-chain.pem}
```

Set the lab host_vars to `customer-intermediate` (copy from
`ansible/inventory/examples/rocky9-lab.customer-intermediate.host-vars.yml.example`,
which already points at `ansible/inventory/local-pki/…`). The **domain must fall inside the
intermediate/root name-constraint subtree** (e.g. Aegis root permits `aegisgroup.ch`, so
`aigw.aegisgroup.ch` verifies; a domain outside it fails the import fail-closed).

Keep `ca-chain.pem` handy — it is the **root-CA path** the Phase 5 check script verifies
against.

---

## Phase 1 — host prep (`os-prep.yml`)

Runs the eight host-prep roles in the security-pinned order
`host_preflight → firewall_preflight → time_sync → selinux_baseline → network_routing →
firewalld_zones → os_baseline → docker_networks`. It validates every topology input
read-only first, brings routing + firewalld (incl. the DOCKER-USER egress lockdown) live
**before** any container can exist, and **stops at the Docker bridges** — it starts **no
containers**.

```bash
# Lab:
ansible-playbook -i ansible/inventory/lab.yml ansible/os-prep.yml --ask-vault-pass

# Production (generated inventory):
ansible-playbook -i ansible/inventory/generated/<alias>/hosts.yml ansible/os-prep.yml \
  --limit <alias> --vault-id <alias>@<file>
```

**Confirm it stopped before containers** (pending marker present, nothing running):

```bash
ssh ansible@10.8.10.10 'sudo cat /etc/ai-gateway/dedicated-docker-host-v1.pending; \
  echo "--- markers ---"; ls -l /etc/ai-gateway/dedicated-docker-host-v1* 2>/dev/null; \
  echo "--- containers ---"; sudo docker ps -q | wc -l'
```

Expect the **`.pending`** ownership marker present, **no** promoted
`dedicated-docker-host-v1` marker yet, and **0** running containers. The recap ends
`failed=0`.

---

## Phase 2 — bring up the stack, pass 1 (`deploy-stack-only.yml`)

Deploys the container stack onto the prepared host. It re-derives the live
firewall/network ABI and refuses to run on an unprepared host. On this first stack deploy
Vault comes up **deliberately uninitialized/sealed** — this is **expected, not a failure**.
In `customer-intermediate` mode this pass also **stages** the intermediate material onto the
VM at `secrets/aigw-intermediate-import.{pem,key}` + `…-chain.pem` (0600 root, `no_log`).

```bash
# Lab (stack-only on the host os-prep just prepared):
ansible-playbook -i ansible/inventory/lab.yml ansible/deploy-stack-only.yml --ask-vault-pass

# Production:
ansible-playbook -i ansible/inventory/generated/<alias>/hosts.yml \
  ansible/deploy-stack-only.yml --limit <alias> --vault-id <alias>@<file>
```

> **Equivalent one-shot:** `ansible/site.yml` = `os-prep.yml` + `deploy-stack-only.yml`.
> The canonical first-init flow (and the shipped
> `ansible/inventory/examples/*.first-init.sh.example` scripts) run the full `site.yml`
> twice rather than the two half-playbooks; either is correct. Use `site.yml` "whenever
> unsure."

**Confirm Vault is up-but-sealed (expected) and staging happened:**

```bash
ssh ansible@10.8.10.10 'cd /opt/ai-gateway; \
  sudo docker ps --format "{{.Names}} {{.Status}}" | sort; \
  echo "--- vault (expect initialized=false sealed=true) ---"; \
  sudo docker exec ai-gateway-vault-1 sh -c \
    "wget -qO- http://127.0.0.1:8200/v1/sys/health?standbyok=true || true" 2>/dev/null; \
  echo "--- staged intermediate (customer-intermediate) ---"; \
  sudo ls -l secrets/aigw-intermediate-import.pem secrets/aigw-intermediate-import.key \
    secrets/aigw-intermediate-import-chain.pem'
```

The recap ends `failed=0` (the `verify` role tolerates a fresh uninitialized/sealed Vault
and the `key-rotator`/`admin-portal` `service_started` dependencies on this first pass).

---

## Phase 3 — Vault init + PKI ceremony (on the VM)

Two sub-steps, both **on the target VM from `/opt/ai-gateway`**. Every secret rides
**stdin only** — never argv, env, or a log.

### 3a. Vault init + unseal-share custody

`vault-bootstrap.sh` is the **lab/test-only** one-time init (it refuses unless
`DEPLOYMENT_PROFILE=rocky9-lab`; 1-of-1 share — production uses 5/3). With
`customer-intermediate` selected it **defers the edge** (no test root, no edge cert; the
customer CA owns the edge) and still does init, unseal, audit, kv, and the rotator token.
Run it with `--emit-unseal-key` and pipe the accepted share straight into the controller
custody helper — the share is emitted **only** after Vault accepts it and the full runtime
gate passes:

```bash
# From the controller repo root:
ssh -T ansible@10.8.10.10 'sudo -- /opt/ai-gateway/scripts/vault-bootstrap.sh --emit-unseal-key' \
  | python3 scripts/store-vault-unseal-key.py \
      --vault-file ansible/inventory/group_vars/gateway/vault-unseal.yml \
      --vault-id "$AIGW_VAULT_ID" \
      --vault-password-file "$AIGW_VAULT_PASSWORD_FILE"
```

This writes the single inline-encrypted `vault_unseal_key` into a dedicated overlay
(never into `group_vars/all.yml`), decrypts it back in memory to verify custody, and
prints a success line. The root token and unseal share remain in the root-owned `0600`
`secrets/vault-init.json` on the VM as the recovery copy until the second converge succeeds.

### 3b. Import the customer intermediate (edge now chains to the customer root)

The intermediate private key is validated fail-closed (`edge-tls.py validate-intermediate`:
non-self-signed CA that can sign, key matches the cert, exactly one private key, chain
anchors on a self-signed root, domain inside the name-constraint subtree), imported into
`pki_int` **over stdin**, promoted to the default issuer, and then **shredded** from disk.
The **Vault token arrives on stdin only** (paste the root token you custodied from
`secrets/vault-init.json`):

```bash
ssh ansible@10.8.10.10
sudo -s
cd /opt/ai-gateway
read -rsp 'Vault token: ' TOK; printf '\n'
printf '%s\n' "$TOK" | scripts/vault-pki-intermediate.sh import-intermediate \
    --intermediate     secrets/aigw-intermediate-import.pem \
    --intermediate-key secrets/aigw-intermediate-import.key \
    --chain            secrets/aigw-intermediate-import-chain.pem
unset TOK
exit; exit
```

On success it prints `edge now serves a certificate chaining to the customer root CA
(customer-intermediate)` and confirms the staged intermediate key was shredded (it now
lives only inside Vault). It also recreates `traefik-int`/`traefik-adm`/`open-webui` and
runs the strict runtime wait.

> **Production substitutions:** replace 3a with the reviewed **operator Vault init
> ceremony** (5/3 shares to separate custodians — **not** `vault-bootstrap.sh`), then a
> hidden controller read piped to `store-vault-unseal-key.py` (see
> `ansible/inventory/examples/production-rocky9.first-init.sh.example`). For 3b the engineer
> supplies the intermediate cert/key/chain (staged in Phase 0b); the same
> `import-intermediate` call runs on the host.

---

## Phase 4 — converge, pass 2 (`site.yml`)

Run the **identical** full converge again. Now Vault is initialized; Ansible **auto-unseals**
from the encrypted controller `vault_unseal_key`, requires strict readiness of Vault and
`key-rotator`, re-digests the freshly installed customer-CA edge bytes, and the `verify`
role runs all post-converge assertions — including
`edge-tls.py validate-installed --reject-self-signed`, which now **rejects** any placeholder
and requires a real, in-window, CA-issued leaf.

```bash
# Lab:
ansible-playbook -i ansible/inventory/lab.yml ansible/site.yml --ask-vault-pass

# Production:
ansible-playbook -i ansible/inventory/generated/<alias>/hosts.yml ansible/site.yml \
  --limit <alias> --vault-id <alias>@<file>
```

**Green means:**

- Play recap ends `failed=0`.
- The `verify` role's runtime task prints `selinux-runtime-contract=ok confined=<N> …`.
- All expected containers healthy — **26/26 long-running for the lab** profile above (22
  for production default); `volume-init` shows `Exited (0)`.

Quick host-side confirmation:

```bash
ssh ansible@10.8.10.10 'sudo docker ps --format "{{.Names}} {{.Status}}" | sort; \
  echo "--- vault (expect initialized=true sealed=false) ---"; \
  sudo docker exec ai-gateway-vault-1 sh -c \
    "wget -qO- http://127.0.0.1:8200/v1/sys/health?standbyok=true" 2>/dev/null'
```

---

## Phase 5 — end-to-end validation (`scripts/e2e-fresh-vm-check.sh`)

`scripts/e2e-fresh-vm-check.sh` is a **read-only** post-deploy verifier (curl + openssl; it
starts nothing, changes nothing, prints no secrets, and exits non-zero on any failed
check). Run it from a vantage that can reach **both** published edges on `443` — in the
Parallels lab that is the controller (it sits on both the ADM `10.8.10.0/24` and internal
`10.20.0.0/24` host-only networks); in production, a jump host with routes to both planes
(or run it twice, once per plane vantage).

```bash
scripts/e2e-fresh-vm-check.sh \
  --domain aigw.aegisgroup.ch \
  --adm-ip 10.8.10.10 \
  --internal-ip 10.20.0.10 \
  --root-ca ansible/inventory/local-pki/ca-chain.pem \
  --vault-ui \
  --ssh ansible@10.8.10.10        # optional: enables the read-only no-egress proof (E)
# add --system-trust once the customer root is installed in the controller OS trust store
```

### What the script proves headlessly

| Check | Proves | How |
|---|---|---|
| **A** | Every FQDN's leaf chains to the **customer root** with **hostname verification** (the green lock) | `openssl s_client -verify_hostname … -CAfile <root>` **and** `curl --cacert <root>` → `ssl_verify_result=0`; with `--system-trust` also verifies against the OS trust store |
| **B** | Each **admin** FQDN answers on the **ADM** edge and **404s** on the internal edge | `curl --resolve <fqdn>:443:<ADM_IP>` vs `…:<INTERNAL_IP>` |
| **C** | Each **user** FQDN answers on the **internal** edge (and 404s on ADM); `auth.` answers on both | `curl --resolve` per plane |
| **D** | Keycloak **authorization endpoint returns 200** (login page) for **each** OIDC client's `redirect_uri` (SSO wired) | `curl -G --data-urlencode client_id/redirect_uri/response_type/scope` against `auth.<domain>/realms/aigw/protocol/openid-connect/auth` on the internal edge |
| **E** *(needs `--ssh`)* | Envoy `172.28.0.2` is the **only** vendor egress path and every bridge is default-drop → internal containers **cannot reach the Internet** | reads live `iptables -S DOCKER-USER` + `nft list table inet aigw_guard` over SSH (read-only) — the same evidence the `verify` role asserts |

### What still needs a human

| Step | Why it is not headless |
|---|---|
| **Real OIDC login** (type credentials, land on an authenticated chat/portal/admin page) | Requires a **browser click** (Chrome + the extension, which may be unavailable). The script proves the authorization page *renders* (Check D); completing the code exchange and landing authenticated is a manual Chrome step. |
| **Browser "green lock" screenshot** | The script proves the chain verifies headlessly (Check A); a visual padlock confirmation is a manual Chrome step. |
| **F — Samba/directory LDAPS `testLDAPConnection`** | Keycloak's `POST /admin/realms/aigw/testLDAPConnection` (invoked once as `testConnection`, once as `testAuthentication`; expect **HTTP 204** each) needs a realm-**admin bearer token** the read-only script must not custody. Run it by hand against `ldaps://samba-ad.<domain>:636` (lab) / the customer directory (prod) with a token obtained via the admin console on the ADM edge. The converge already proves the firewall pins exactly one `tcp/636` allowance from Keycloak's `/32` to the directory. |

A `RESULT: PASS` line with `failed=0` is the acceptance gate for the headless checks.

---

## Rollback

This runbook is destroy-and-redeploy, so rollback is simply **revert the snapshot again**:

```bash
# Lab:
prlctl snapshot-switch aigw01 --id <CLEAN_SNAPSHOT_ID>
```

On the **controller**, discard the run-specific custody overlay so a re-run starts clean
(the helper refuses to overwrite an existing `vault_unseal_key`):

```bash
rm -f ansible/inventory/group_vars/gateway/vault-unseal.yml   # lab custody overlay
```

For **production** there is no snapshot: rebuild the VM from the clean image (Phase 0),
and rotate/revoke any Vault init material that was generated. Never reuse `vault-bootstrap.sh`
on a Vault that is already initialized — it hard-fails by design; use the held unseal shares.

---

## Production differences

| Concern | Lab (`aigw01`) | Production (engineer provides) |
|---|---|---|
| Clean VM | `prlctl snapshot-switch aigw01 --id <clean>` | Fresh Rocky 9 VM, three NICs, **LUKS at build time**, ADM IP + all NIC IPs/gateways |
| Profile | `deployment_profile: rocky9-lab` | `rocky9-production` (canonical) |
| Inventory | committed `ansible/inventory/lab.yml` + `host_vars/lab-aigw01.yml` | generated by `scripts/bootstrap-rocky9-production.py`; converge with `--vault-id <alias>@<file>` (not `--ask-vault-pass`) |
| Domain / DNS | `aigw.aegisgroup.ch`; `platform_authoritative_dns_enabled: true` (in-stack CoreDNS) | real `<INTERNAL_DNS_ZONE>`; `platform_authoritative_dns_enabled: false` — engineer creates the **DNS records** (`admin/…` → ADM IP, `api/portal/auth/chat` → internal IP; `chat` and `auth` also exist in the ADM view → ADM IP) in the corporate zone |
| Stack secrets | lab overlay `inventory/group_vars/gateway/vault.yml` | `group_vars/production_rocky9/vault.yml` — **all** secrets from `production-rocky9.vault.yml.example` as inline `!vault` values |
| Vault init | `vault-bootstrap.sh` (1-of-1, lab-only) | **reviewed operator init ceremony** (5/3 shares to separate custodians); then `store-vault-unseal-key.py` |
| Edge TLS material | intermediate CA **cert+key+chain** staged from a local PKI | engineer supplies the intermediate CA **cert + private key + complete chain** (`customer-intermediate`), **or** a signed CSR (`vault-intermediate`), **or** the full leaf+key+chain (`customer-supplied`) |
| `vault_unseal_key` | inline-encrypted in `gateway/vault-unseal.yml` | inline-encrypted in `production_rocky9/vault-unseal.yml` (operator init output; never generated) |
| Access exceptions | `aigw_ssh_password_authentication: true`, `samba_lab`, `aigw_seed_test_users`, `vault_ui` on | all **off**; identity via `identity_ldap_enabled` LDAPS to the customer directory |
| Containers healthy | 26 long-running | 22 long-running (default flags) |
| Encrypted state | `require_encrypted_state: false` (disposable) | `require_encrypted_state: true` — converge **warns** (does not fail) if state is not on a LUKS ancestor; encrypt at build |

---

## Alternative edge modes

If the lab uses the committed **`vault-intermediate`** host_vars instead of
`customer-intermediate`, replace Phase 3b with the CSR ceremony (Vault mints the
intermediate key internally; the customer CA signs the CSR offline; nothing but the CSR
leaves the host):

```bash
# on the VM, /opt/ai-gateway, token on stdin:
printf '%s\n' "$TOK" | sudo scripts/vault-pki-intermediate.sh csr        # -> secrets/aigw-intermediate.csr
#   customer CA signs it offline (scripts/sign-vault-intermediate.sh on the CA host)
printf '%s\n' "$TOK" | sudo scripts/vault-pki-intermediate.sh install-signed \
    --signed-intermediate /tmp/intermediate.pem --chain /tmp/chain.pem
```

`customer-supplied` mode instead ships a ready leaf+key+chain via Ansible with no on-host
PKI ceremony. All modes converge and validate identically from Phase 4 onward.

---

## One-glance command sequence (lab, customer-intermediate)

```bash
cd /path/to/ai-gateway
ansible-galaxy collection install -r ansible/requirements.yml
ansible-config dump | grep PIPELINING                                   # = True

# Phase 0: prlctl snapshot-switch aigw01 --id <clean>   (+ verify bare host)
# Phase 0b (stage intermediate on controller):
bash ansible/inventory/examples/rocky9-lab.stage-customer-intermediate.sh.example

ansible-playbook -i ansible/inventory/lab.yml ansible/os-prep.yml --ask-vault-pass          # Phase 1
ansible-playbook -i ansible/inventory/lab.yml ansible/deploy-stack-only.yml --ask-vault-pass # Phase 2

ssh -T ansible@10.8.10.10 'sudo -- /opt/ai-gateway/scripts/vault-bootstrap.sh --emit-unseal-key' \
  | python3 scripts/store-vault-unseal-key.py \
      --vault-file ansible/inventory/group_vars/gateway/vault-unseal.yml \
      --vault-id "$AIGW_VAULT_ID" --vault-password-file "$AIGW_VAULT_PASSWORD_FILE"      # Phase 3a
# Phase 3b: on the VM, import-intermediate (token on stdin) — see Phase 3

ansible-playbook -i ansible/inventory/lab.yml ansible/site.yml --ask-vault-pass          # Phase 4

scripts/e2e-fresh-vm-check.sh --domain aigw.aegisgroup.ch \
  --adm-ip 10.8.10.10 --internal-ip 10.20.0.10 \
  --root-ca ansible/inventory/local-pki/ca-chain.pem --vault-ui --ssh ansible@10.8.10.10 # Phase 5
```
