# AI Gateway — Deployment Runbook

This runbook walks you through deploying AI Gateway from nothing to a working
system, step by step. It is written so that an engineer with basic IT
experience — comfortable with a terminal, SSH, and editing a text file — can
complete the deployment without prior knowledge of this project. Every step
tells you what to type, what you should see, and what to do if you don't see
it. Deeper explanations live in the [deployment guide](deploy-guide.md); you
do not need them to finish this runbook.

**Time required:** roughly 2–4 hours, most of it waiting for the automated
converge.

**The two computers involved:**

| Name | What it is | What you do on it |
|---|---|---|
| **Controller** | Your workstation or a jump host (Linux or macOS) | Run the setup scripts and Ansible commands |
| **Target VM** | The Rocky Linux 9 virtual machine that will run AI Gateway | Mostly nothing — Ansible configures it for you. You log in once, near the end |

> **What is Ansible?** An automation tool that connects to the target VM over
> SSH and configures it exactly as this repository specifies. You run it from
> the controller; it does the work on the VM. If any safety check fails, it
> stops *before* changing anything — a failed run early on is normal and safe.

---

## Secrets and vault prerequisites (read before you start)

**Time to read:** about 5 minutes. Nothing here to run yet — this is the
complete, up-front list of every secret this deployment needs, so nothing
surprises you halfway through.

The important message first: **almost every secret is generated for you.** The
one command in [Part 3](#part-3--generate-your-deployment-folder-5-minutes)
creates all 27 stack secrets — database passwords, signing keys, OIDC client
secrets, and the rest — randomly, and writes them **already encrypted** into
your inventory. You never invent, type, or paste any of them. Only a short,
known list is yours to supply, and it is all laid out below.

> **A "secret" here means a value stored inside the encrypted inventory (the
> vault overlay).** An *inline-encrypted overlay* is a small file where each
> secret is individually encrypted with your vault passphrase, so it is safe to
> keep in the inventory. See the [Glossary](#glossary).

### At a glance

| Secret | What it is | How it is provided | When |
|---|---|---|---|
| **27 stack secrets** (databases, LiteLLM, Redis, Keycloak, OIDC, sessions, tokens, Grafana) | The credentials the running services use to talk to each other | **Auto-generated** and inline-encrypted by `scripts/bootstrap-rocky9-production.py` | Part 3 — automatic, no operator input |
| `vault_unseal_key` | The key that unlocks the secrets safe (Vault) after every restart | **You supply it** from the Vault init ceremony, stored with `scripts/store-vault-unseal-key.py` | Part 7 — *after* the first converge (it cannot exist earlier) |
| `identity_ldap_bind_password` *(only if you connect a customer directory)* | The read-only bind-account password for your AD/LDAPS server | **You supply it**, stored with `scripts/store-identity-ldap-bind-password.py` | Before the converge, only when `identity_ldap_enabled: true` |
| **Edge TLS material** *(depends on `aigw_edge_tls_mode`)* | Your real certificate / intermediate CA, its private key, and chain | **You supply it as controller-local file *paths*** — never inventory secrets | Before the converge |
| **Anthropic WIF record** *(at go-live)* | Non-secret Anthropic identifiers written into Vault | **You supply it** into Vault after the human Anthropic Console ceremony | Part 8 — after the stack is up |

### 1. Auto-generated — you supply none of these (Part 3)

`scripts/bootstrap-rocky9-production.py` generates **27** random secrets and
writes them, already encrypted, into
`group_vars/production_rocky9/vault.yml` inside your generated inventory. You
never see them, type them, or store them in plain text. Grouped by purpose:

| Purpose | Keys | Count |
|---|---|---|
| PostgreSQL role passwords | `pg_super_password`, `pg_litellm_password`, `pg_keycloak_password`, `pg_rotator_password`, `pg_grafana_ro_password` | 5 |
| LiteLLM keys | `litellm_master_key`, `litellm_salt_key`, `litellm_ui_breakglass_password`, `webui_litellm_key` | 4 |
| Redis | `redis_password` | 1 |
| Keycloak admin/bootstrap | `kc_admin_password`, `kc_bootstrap_admin_client_secret` | 2 |
| OIDC client secrets | `webui_oidc_client_secret`, `portal_oidc_client_secret`, `admin_portal_oidc_client_secret`, `oauth2_proxy_client_secret`, `vault_oidc_client_secret` | 5 |
| oauth2-proxy cookie secrets | `oauth2_proxy_litellm_cookie_secret`, `oauth2_proxy_grafana_cookie_secret`, `oauth2_proxy_prometheus_cookie_secret`, `oauth2_proxy_vault_cookie_secret` | 4 |
| Session / app-signing secrets | `webui_secret_key`, `portal_session_secret`, `admin_portal_session_secret` | 3 |
| Internal service tokens | `rotator_internal_token`, `portal_identity_token` | 2 |
| Grafana break-glass password | `grafana_admin_password` | 1 |

The complete, authoritative list is `required_secret_keys` in
`ansible/generic-rocky9-contract.json`. **Nothing in this table is an operator
input.** If you ever need to *change* one later, edit the overlay in place (see
the "You need to change a secret later" row under
[Troubleshooting](#troubleshooting-quick-reference)) — you still never generate
it by hand on the first deploy.

> **Not a stack secret, but yours to keep:** the master **vault password** you
> create in [Part 2](#part-2--prepare-the-controller-10-minutes)
> (`~/.aigw-vault-pass`) is the passphrase that encrypts all 27 of the above. It
> is never written into the inventory — you custody it yourself, in a password
> manager. Lose it and the encrypted secrets cannot be read or changed.

### 2. Operator-supplied — the short list you must provide

Everything below is something the bootstrap does **not** generate.

#### 2a. `vault_unseal_key` — always required (done in Part 7)

This is the **only unconditional operator secret**. It comes from the one-time
`vault operator init` ceremony, so it **cannot exist until after your first
converge** — the automation deliberately lets the first `site.yml` run finish
with Vault still uninitialized (that "waits only for core services" notice at
the end of [Part 6](#part-6--run-the-converge-3090-minutes) is expected, not an
error). You then initialize Vault and store its unseal key with the stdin-only
helper into a **dedicated sibling overlay** — never `group_vars/all.yml`, which
a contract test forbids.

- **Helper:** `scripts/store-vault-unseal-key.py` — reads the key from stdin
  only, refuses a terminal, and will not overwrite an existing key.
- **Where it goes:** `group_vars/production_rocky9/vault-unseal.yml` in your
  generated inventory.
- **Exact commands:** [Part 7, Step 7b](#part-7--initialize-the-secrets-vault-and-hand-its-key-to-the-controller-15-minutes)
  — do not run them now; you reach them after Part 6.

#### 2b. `identity_ldap_bind_password` — only when you connect a customer directory

Skip this entirely unless you set `identity_ldap_enabled: true` to federate an
**external customer Active Directory over LDAPS** (encrypted LDAP — see the
[Glossary](#glossary)). It is the password for the read-only directory **bind
account** — the service account Keycloak uses to look users up. It is never
generated, and never placed in `.env`, on a command line, or in logs; it reaches
the stack only as a root-owned file bind-mounted into the key-rotator service.

Store it with the stdin-only helper **before** the converge:

```bash
read -rsp 'Directory bind-account password: ' AIGW_LDAP_BIND; printf '\n'
printf '%s\n' "$AIGW_LDAP_BIND" | python3 scripts/store-identity-ldap-bind-password.py \
  --vault-file ansible/inventory/generated/mygateway/group_vars/production_rocky9/identity-ldap.yml \
  --vault-id mygateway \
  --vault-password-file ~/.aigw-vault-pass
unset AIGW_LDAP_BIND
```

**You should see** `Stored and verified inline-encrypted identity_ldap_bind_password`.

Enabling LDAP also means filling in these **non-secret** keys in your
`host_vars` file (plain topology/identity settings, not encrypted secrets):

| Key | What to put there |
|---|---|
| `identity_ldap_enabled` | `true` to turn the feature on — this changes the firewall ABI, so it requires a full `site.yml` run |
| `identity_ldap_url` | Your directory endpoint — **must** begin `ldaps://` (plain `ldap://` is rejected) |
| `identity_ldap_provider_name` | A display name for the directory |
| `identity_ldap_vendor` | The directory vendor (e.g. Active Directory) |
| `identity_ldap_directory_ip` | The directory server's IP (reached over the internal leg) |
| `identity_ldap_bind_dn` | The bind account's distinguished name |
| `identity_ldap_users_dn` | The base DN under which user accounts live |
| `identity_ldap_ca_bundle_src` | Controller-local path to the CA bundle that signs the LDAPS certificate |
| `identity_ldap_username_attribute`, `identity_ldap_rdn_attribute`, `identity_ldap_uuid_attribute`, `identity_ldap_user_object_classes`, `identity_ldap_user_filter` | The directory's user-schema mapping |

Keep `identity_ldap_enabled: false` until every one of these is filled in.

#### 2c. Edge TLS material — file paths, not inventory secrets

Your gateway needs a real TLS certificate for its web addresses. Which files you
supply depends on `aigw_edge_tls_mode`, which you set in `host_vars`. **In every
mode the certificate and private key are given as controller-local *file
paths* — they are never inventory secrets and never go into an inline-encrypted
overlay** (a private key least of all):

| `aigw_edge_tls_mode` | What you supply | Keys (file paths in `host_vars`) |
|---|---|---|
| `customer-supplied` | Your ready `*.<domain>` leaf certificate, its private key, and the full chain | `aigw_edge_tls_leaf_cert_file`, `aigw_edge_tls_private_key_file`, `aigw_edge_tls_chain_file` |
| `customer-intermediate` | An intermediate CA certificate, its private key, and the full chain (Vault then issues every leaf) | `aigw_edge_tls_intermediate_cert_file`, `aigw_edge_tls_intermediate_key_file`, `aigw_edge_tls_intermediate_chain_file` |
| `vault-intermediate` | *No files up front* — Vault emits a CSR that your CA signs offline | (none in the inventory; an on-host ceremony) |

The full mode table, when to use each, and the exact on-host ceremonies are in
[operations — production edge TLS](operations.md#production-edge-tls). Point the
file paths at a protected location outside the repository; the preflight fails
closed if the set is incomplete or the private-key file is group-readable or a
symlink.

> **These must be absolute paths (starting with `/`), not relative ones.**
> Ansible resolves a relative path against the invoking playbook's own
> directory (`ansible/`), never the repository root or your shell's working
> directory — so a relative value silently mis-resolves to a nonexistent
> location. The preflight now fails closed with a clear "must be an absolute
> path" error if you give it one, rather than a confusing "not found." This
> applies to `identity_ldap_ca_bundle_src` too (§2b).

#### 2d. Anthropic WIF record — operator-completed at go-live (Part 8)

This one is easy to miss because these values are **identifiers, not
passwords** — but you still write them by hand, after the stack is up.
Following the human Anthropic organization-admin Console (or Admin API)
ceremony, you write one record directly into Vault at
`kv/ai-gateway/anthropic-wif` holding the returned **non-secret** identifiers:
`federation_issuer_id` (`fdis_…`), `federation_rule_id` (`fdrl_…`),
`service_account_id` (`svac_…`), `organization_id`, `workspace_id`
(`wrkspc_…`), and the approved `federation_jwks_sha256`. No bearer token is
stored.

- **Do it in:** [Part 8, step 4](#part-8--first-administrator-and-sign-off-15-minutes),
  following the [Anthropic WIF setup SOP](sop/anthropic-wif-jwt-setup.md) and its
  reference [anthropic-wif-bootstrap.md](anthropic-wif-bootstrap.md).
- **Helper:** the Anthropic Console side can now be driven from the controller
  with `scripts/anthropic-wif-enroll.py`. It needs a short-lived `org:admin`
  OAuth bearer piped on stdin, which it holds only in memory and never stores.

#### Lab profile only

The disposable `rocky9-lab` profile additionally seeds five throwaway Samba
directory passwords (`samba_*`). **These do not apply to a production
deployment** — the customer profile has no Samba directory.

---

## Part 1 — Check the target VM (10 minutes)

Someone (you, or your virtualization/cloud team) must provide a VM that meets
this checklist **before** you start. For each row, run the exact command shown
**from the controller** (it opens its own one-off SSH connection per command —
you do not need to stay logged into the VM) and compare.

| # | Requirement | How to check (run from the controller) | You should see |
|---|---|---|---|
| 1 | Rocky Linux 9 | `ssh <user>@<vm> 'cat /etc/rocky-release'` | `Rocky Linux release 9.x` |
| 2 | Three network interfaces, each already configured with its own IP address: one for internet egress, one for administrators (ADM), one for internal users | `ssh <user>@<vm> 'ip -br -4 address'` | Three interfaces, each with an IPv4 address |
| 3 | Exactly one default route, on the egress interface | `ssh <user>@<vm> 'ip -4 route show table main'` | One line starting `default via …` naming the egress interface |
| 4 | SELinux enforcing | `ssh <user>@<vm> getenforce` | `Enforcing` |
| 5 | Encrypted disk under Docker and the install directory (**strongly recommended**, see note) | `ssh <user>@<vm> "lsblk -o NAME,FSTYPE \| grep crypto_LUKS"` | At least one `crypto_LUKS` entry backing the root/data volume |
| 6 | Clock synchronized | `ssh <user>@<vm> "chronyc tracking \| head -2"` | A reference server and a small offset (under 5 seconds) |
| 7 | A login account with sudo that accepts your SSH key | `ssh <user>@<vm> sudo -n true` | No password prompt, no error |
| 8 | Enough resources | — | At least 4 vCPU / 24 GiB RAM / 100 GB disk for a pilot; the services alone reserve ~20 GiB of memory |

If any row fails, stop and fix it first — the automation checks all of these
and will refuse to proceed, **except the encrypted-disk check (row 5)**. LUKS
(full-disk encryption) is a build-time disk task the converge does not manage:
if the disk is not encrypted the converge prints a loud
`AIGW_ENCRYPTED_STATE_WARNING` and a `WARNING: … NOT on LUKS-encrypted storage`
line and then continues. Provision the encrypted disk when the VM is built and
keep the passphrase yourself; do not treat the warning as permission to skip
encryption for real customer data.

Write down these values now; you will need them in Part 3:

- The **names** of the three interfaces (e.g. `ens160`, `ens192`, `ens224`)
  and which role each plays (egress / ADM / internal)
- Each interface's **IP address** and **gateway**
- The **network range (CIDR)** administrators connect from (e.g. `10.8.10.0/24`)
- The **network range (CIDR)** internal users connect from
- One to three **internal DNS server** addresses (your corporate resolvers)
- One to three **internet DNS server** addresses (what the gateway may use to
  look up AI vendor APIs — must be different servers from the internal list)
- The **base domain** the services will live under (e.g. `aigw.example.com` —
  the system creates hostnames like `chat.aigw.example.com` under it)

## Part 2 — Prepare the controller (10 minutes)

On your workstation:

```bash
# 1. Confirm Ansible 2.16 or newer is installed
ansible --version | head -1

# 2. Get the repository and its pinned dependencies
git clone <repository-url> ai-gateway
cd ai-gateway
ansible-galaxy collection install -r ansible/requirements.yml
```

Create a **vault password file** — a single strong passphrase that encrypts
all the secrets this deployment will generate. Do not reuse an existing
password:

```bash
umask 077
openssl rand -base64 30 > ~/.aigw-vault-pass
```

Keep this file safe (and back the passphrase up in your password manager):
without it, the deployment's secrets cannot be read or changed later.

## Part 3 — Generate your deployment folder (5 minutes)

One command creates a dedicated inventory for this customer/host, with every
secret generated randomly and stored only in encrypted form:

```bash
scripts/bootstrap-rocky9-production.py \
  --inventory-alias mygateway \
  --vault-id mygateway \
  --vault-password-file ~/.aigw-vault-pass
```

(The older `scripts/bootstrap-generic-rocky9.py` still works as a DEPRECATED
compatibility alias and prints a one-line notice pointing at this canonical
command.)

Pick your own short name instead of `mygateway` (letters, digits, dots,
dashes). **You should see** it create three files under
`ansible/inventory/generated/mygateway/` and print the exact next command to
run. It never prints or stores a secret in plain text.

Now open the one file you must fill in:

```bash
nano ansible/inventory/generated/mygateway/host_vars/mygateway.yml
```

Every blank value maps to something you wrote down in Part 1. The essentials:

| Field | What to put there |
|---|---|
| `ansible_host` | The VM's management IP (usually the ADM address) |
| `ansible_user` | The sudo account from Part 1, row 7 |
| `aigw_domain` | Your base domain, lowercase (e.g. `aigw.example.com`) |
| `nic_egress` / `nic_adm` / `nic_internal` | The three interface **names** |
| `eth0_ip` / `eth0_gateway` | Egress interface IP and gateway |
| `eth1_ip` / `eth1_gateway` | ADM interface IP and gateway |
| `eth2_ip` / `eth2_gateway` | Internal interface IP and gateway |
| `vpn_client_cidr` | The administrators' network range |
| `internal_cidr` | The internal users' network range |
| `internal_dns_servers` / `egress_dns_servers` / `platform_authoritative_dns_enabled` | Three fields, one DNS mode — see below |

**DNS: pick exactly one mode.** `internal_dns_servers`, `egress_dns_servers`, and
`platform_authoritative_dns_enabled` are three separate YAML fields that work
together as a single choice; the value of one determines what the others
should hold.

**Mode A — use your existing corporate DNS** (the usual choice for a real
deployment):

```yaml
internal_dns_servers: ["<resolver reachable through ADM/internal>", "<optional second>"]
egress_dns_servers: ["<a distinct Internet resolver reachable only through egress>"]
platform_authoritative_dns_enabled: false
```

**Mode B — let the gateway answer only for its own `aigw_domain`** (no
recursion, no corporate resolver needed — useful for a pilot or test where
you don't have one):

```yaml
internal_dns_servers: ["{{ eth1_ip }}", "{{ eth2_ip }}"]
egress_dns_servers: ["<a distinct Internet resolver reachable only through egress>"]
platform_authoritative_dns_enabled: true
```

In Mode B, ADM clients use `eth1_ip` and internal clients use `eth2_ip` as
their resolver; this authoritative service returns `NXDOMAIN` for every other
zone, so it must not replace a client's general recursive resolver. In
**both** modes, `egress_dns_servers` must be a distinct resolver from
`internal_dns_servers` — it is reachable only through the egress interface
and is the sole DNS that Envoy (and only Envoy) uses to reach AI vendor APIs.

Leave everything you don't understand at its default — the defaults are the
safe, fail-closed choices. (The `eth0/1/2` names are just labels; your real
interfaces can be called anything.)

## Part 4 — Pass the preflight gate (2 minutes)

This checks your folder for mistakes **without touching the VM at all**:

```bash
ansible-playbook -i ansible/inventory/generated/mygateway/hosts.yml \
  ansible/preflight-rocky9-production.yml --limit mygateway \
  --vault-id mygateway@~/.aigw-vault-pass
```

**You should see** a line containing `AIGW_GENERIC_PREFLIGHT=` with
`"status": "ok"`. If the status is `invalid`, the same line lists exactly
which fields are missing or malformed — fix them in the `host_vars` file and
run it again. Repeat until it says `ok`.

Then confirm the controller can actually reach the VM:

```bash
ansible -i ansible/inventory/generated/mygateway/hosts.yml mygateway -m ping
```

**You should see** `"ping": "pong"`. If not, check `ansible_host`,
`ansible_user`, and your SSH key.

## Part 5 — Register the DNS names (coordinate with your DNS admin)

Before the converge, your DNS must point these names at the gateway. All of
them are hostnames under your base domain:

| Hostname | Points to | Who uses it |
|---|---|---|
| `portal.<domain>`, `api.<domain>`, `auth.<domain>` | the **internal** interface IP | users and developers |
| `chat.<domain>`, `admin.<domain>`, `litellm-admin.<domain>`, `grafana.<domain>`, `prometheus.<domain>`, `vault.<domain>` | the **ADM** interface IP | chat and administration (ADM leg) |

The complete name inventory, per-audience resolution expectations, and the
internal-vs-internet DNS design are in the
[FQDN inventory](fqdn-inventory.md).

## Part 6 — Run the converge (30–90 minutes)

This is the main event. Keep your current terminal open until it finishes —
the automation hardens SSH partway through and proves it can still log in
before continuing, but don't close your safety line early.

```bash
ansible-playbook -i ansible/inventory/generated/mygateway/hosts.yml \
  ansible/site.yml --limit mygateway \
  --vault-id mygateway@~/.aigw-vault-pass
```

What happens, in order: safety checks on the host → clock verification →
SELinux verification → network policy routing → firewall zones and packet
rules → OS packages, Docker, and SSH hardening → 20 isolated container
networks → configuration rendering, image builds, and container start →
verification of everything it just did.

### The three playbooks — which one do I run?

`site.yml` is actually two playbooks run back-to-back, and you can run each
half on its own. All three take the same `-i`, `--limit`, and `--vault-id`
arguments shown above:

| Playbook | What it does | When you run it |
|---|---|---|
| `ansible/site.yml` | Everything: prepares the host, then deploys and verifies the stack | **First deploy** (this Part and Step 7c), and any time you are unsure — it is always safe |
| `ansible/os-prep.yml` | Host preparation only: all safety checks, clock, SELinux, routing, firewall, OS packages, Docker, and the 20 container networks. **Starts no containers.** | When the host/OS team prepares the VM ahead of time, or after changing host-level inventory (NICs, firewall, DNS resolvers) without wanting to touch the running stack yet |
| `ansible/deploy-stack-only.yml` | Stack only: deploys the containers, verifies everything, and records the host as a completed dedicated gateway host | App/config updates on a host that already converged, or the stack half of a first deploy after `os-prep.yml` ran |

```bash
# Host preparation only (no containers started):
ansible-playbook -i ansible/inventory/generated/mygateway/hosts.yml \
  ansible/os-prep.yml --limit mygateway \
  --vault-id mygateway@~/.aigw-vault-pass

# Stack deploy/redeploy on a prepared host:
ansible-playbook -i ansible/inventory/generated/mygateway/hosts.yml \
  ansible/deploy-stack-only.yml --limit mygateway \
  --vault-id mygateway@~/.aigw-vault-pass
```

Two rules keep this safe, and the playbooks enforce both for you:

- `deploy-stack-only.yml` **refuses to run on a host that was never
  prepared** — it requires the ownership marker that only `os-prep.yml` (or
  `site.yml`) writes, and it re-checks the live firewall and container
  networks before touching anything. If it refuses, run `site.yml`; never
  work around its assertions.
- Running `os-prep.yml` then `deploy-stack-only.yml` ends in exactly the
  same state as one `site.yml` run, so you can hand the two halves to two
  different people (host team, then app team) without losing anything.

**Two outcomes are normal:**

- It stops early with a clear assertion message. Nothing was changed; read
  the message, fix the input, and run it again.
- It completes but prints an explicit notice that **Vault is not initialized
  yet** and that it only waited for the core services. **This is expected on
  the first run** — Vault (the secrets safe) starts empty and sealed on
  purpose. Continue to Part 7.

## Part 7 — Initialize the secrets vault and hand its key to the controller (15 minutes)

Vault (the built-in secrets safe) starts empty and sealed. You now do three
things in order: (7a) initialize Vault once on the VM, (7b) give the
controller an encrypted copy of Vault's unlock key, and (7c) run the converge
again so the automation can unlock Vault and finish.

**Step 7a — Initialize Vault on the VM.** Log in to the VM (first time you
actually need to) and run the bootstrap:

```bash
ssh <ansible_user>@<vm>
cd /opt/ai-gateway
sudo AIGW_ALLOW_INSECURE_VAULT_BOOTSTRAP=I_UNDERSTAND_THIS_IS_LAB_ONLY \
  scripts/vault-bootstrap.sh
```

> **Important:** this is the built-in **lab/test** Vault ceremony — one
> unseal key, no TLS on the internal listener. The acknowledgement variable is
> required because this pilot uses the customer `rocky9-production` profile, and
> the script refuses to run on that profile without it. It is acceptable for a
> pilot; a production deployment replaces this whole step with the customer's
> reviewed Vault ceremony (see [operations](operations.md)), driven by the
> [`production-rocky9.first-init.sh.example`](../ansible/inventory/examples/production-rocky9.first-init.sh.example)
> sequence.

The script initializes Vault, sets up the credential-rotation policies, and
then waits (up to 10 minutes) for the entire service graph to become
healthy. It prints one **unseal key** (a 44-character string ending in `=`)
and one **root token**. **Securely store both** — a password manager or paper,
never a shared drive. Anyone with them controls the gateway's secrets.

**Step 7b — Give the controller an encrypted copy of the unseal key.** Back on
the controller, store the unseal key in a dedicated encrypted file so the
automation can unlock Vault on every later run. The command reads the key from
your keyboard (it is never typed on the command line or saved in plain text)
and writes only its encrypted form:

```bash
read -rsp 'Vault unseal key from Step 7a: ' AIGW_UNSEAL_SHARE; printf '\n'
printf '%s\n' "$AIGW_UNSEAL_SHARE" | python3 scripts/store-vault-unseal-key.py \
  --vault-file ansible/inventory/generated/mygateway/group_vars/production_rocky9/vault-unseal.yml \
  --vault-id mygateway \
  --vault-password-file ~/.aigw-vault-pass
unset AIGW_UNSEAL_SHARE
```

**You should see** `Stored and verified inline-encrypted vault_unseal_key`.
The helper accepts exactly one valid share, never prints it, and refuses to
overwrite an existing one.

**Step 7c — Run the converge one more time.** Back on the controller, run the
exact command from Part 6 again. Because Vault is now initialized, the
automation **automatically unlocks it** using the encrypted key you just
stored, then waits for and verifies the complete system.

```bash
ansible-playbook -i ansible/inventory/generated/mygateway/hosts.yml \
  ansible/site.yml --limit mygateway \
  --vault-id mygateway@~/.aigw-vault-pass
```

> If you skip Step 7b, this run **stops on purpose** with a message that an
> initialized Vault needs `vault_unseal_key` from the controller — it refuses
> to finish a half-unlocked system. Do Step 7b, then rerun.

The whole 7a → 7b → 7c sequence is also captured, ready to copy, in
[`rocky9-lab.first-init.sh.example`](../ansible/inventory/examples/rocky9-lab.first-init.sh.example)
(disposable lab, which pipes the share straight from the bootstrap without
printing it) and
[`production-rocky9.first-init.sh.example`](../ansible/inventory/examples/production-rocky9.first-init.sh.example)
(reviewed production ceremony).

## Part 8 — First administrator and sign-off (15 minutes)

1. Connect your directory and create the first administrator following
   [identity operations](identity-operations.md) — the short version: a
   Keycloak/directory procedure grants one named person the `aigw-admins`
   role, and that person then presses **Initialize identity control** in the
   admin portal at `https://admin.<domain>`.
2. From an administrator machine (on the ADM network), open
   `https://admin.<domain>` and `https://grafana.<domain>` — both should
   redirect you to a login page and let the administrator in. In Grafana, the
   "AI Gateway" folder should already hold every provisioned dashboard (see
   [observability operations](observability-operations.md) for the current
   list — eight at the time of writing); the newer dashboards link back to
   AI Gateway Overview as their hub.
3. From a machine on the ADM network, open `https://chat.<domain>` — you
   should reach the chat login. From a user machine (on the internal
   network), open `https://portal.<domain>` — you should reach the
   developer portal login.
4. Enroll the AI vendor credential (Anthropic) following the step-by-step
   [Anthropic WIF setup SOP](sop/anthropic-wif-jwt-setup.md). The deep
   reference behind that SOP is
   [anthropic-wif-bootstrap.md](anthropic-wif-bootstrap.md).
5. Before opening access to real users, run the applicable sections of the
   [acceptance test runbook](test-runbook.md).

## Troubleshooting quick reference

| Symptom | Likely cause | What to do |
|---|---|---|
| Preflight says `"status": "invalid"` | A blank or malformed field in `host_vars` | The receipt lists the exact keys; fix and rerun — nothing was touched |
| `ping` fails in Part 4 | SSH target/user/key wrong | Verify `ssh <user>@<vm>` works by hand first |
| Converge stops at a topology assertion | The values you entered disagree with the VM's live interfaces/routes | Re-run the Part 1 checks; correct `host_vars` |
| Converge stops at SELinux / clock / encryption | VM doesn't meet Part 1 rows 4–6 | Fix the VM (this may need the VM team), rerun |
| First converge "waits only for core services" and mentions Vault | Not an error | Expected — do Part 7 |
| A service is unhealthy after Part 7 | Vault sealed (e.g. after a reboot) | Re-run the Part 6 converge — it auto-unlocks Vault from the controller's stored key. For an immediate fix on the VM, pipe the stored unseal key into `sudo scripts/vault-unseal.sh` (see [operations](operations.md)) |
| Step 7c stops: "initialized Vault requires vault_unseal_key" | You skipped Step 7b, so the controller has no stored unlock key | Do Step 7b (store the key), then rerun Step 7c |
| You need to change a secret later | — | `ansible-vault edit ansible/inventory/generated/<alias>/group_vars/production_rocky9/vault.yml --vault-id <alias>@<password-file>`, then rerun the converge |

## Glossary

- **Converge** — one full run of the Ansible automation that brings the VM to
  the exact desired state. Safe to rerun; an unchanged system stays unchanged.
- **Vault** — the built-in secrets safe holding provider credentials and
  signing keys. Starts sealed (locked) until initialized/unsealed.
- **Unseal key** — the key that unlocks Vault after every restart. Stored
  offline by a human, and also kept as an encrypted copy on the controller
  (Step 7b) so a later converge can unlock Vault automatically. Never held in
  plain text and never on the VM.
- **ADM / internal / egress** — the three network legs: administrators-only,
  internal users, and outbound internet (AI vendors), respectively. Nothing
  listens on the egress leg.
- **Inventory** — the folder generated in Part 3 holding this deployment's
  connection details, topology, and encrypted secrets.
- **Inline-encrypted overlay** — a small inventory file in which each secret is
  encrypted individually with your vault passphrase (rather than the whole file
  at once). The operator-supplied secrets live in dedicated overlays like
  `vault-unseal.yml`, kept separate from the auto-generated `vault.yml`.
- **Preflight** — a check that reads and validates but changes nothing.
- **Leaf certificate** — the actual server certificate a browser sees, as
  opposed to the intermediate CA that signs it or the offline root above that.
- **LDAPS** — LDAP over TLS: the encrypted way the gateway talks to a customer
  directory (Active Directory). Plain, unencrypted `ldap://` is rejected.
- **WIF (Workload Identity Federation)** — the keyless way the gateway
  authenticates to Anthropic: it presents short-lived signed assertions instead
  of a stored API key. Its Anthropic-side identifiers are set up once by a human
  organization administrator (Part 8).
