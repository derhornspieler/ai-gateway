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

## Part 1 — Check the target VM (10 minutes)

Someone (you, or your virtualization/cloud team) must provide a VM that meets
this checklist **before** you start. For each row, run the check command on
the VM and compare.

| # | Requirement | How to check (run on the VM) | You should see |
|---|---|---|---|
| 1 | Rocky Linux 9 | `cat /etc/rocky-release` | `Rocky Linux release 9.x` |
| 2 | Three network interfaces, each already configured with its own IP address: one for internet egress, one for administrators (ADM), one for internal users | `ip -br -4 address` | Three interfaces, each with an IPv4 address |
| 3 | Exactly one default route, on the egress interface | `ip -4 route show table main` | One line starting `default via …` naming the egress interface |
| 4 | SELinux enforcing | `getenforce` | `Enforcing` |
| 5 | Encrypted disk under Docker and the install directory | `lsblk -o NAME,FSTYPE \| grep crypto_LUKS` | At least one `crypto_LUKS` entry backing the root/data volume |
| 6 | Clock synchronized | `chronyc tracking \| head -2` | A reference server and a small offset (under 5 seconds) |
| 7 | A login account with sudo that accepts your SSH key | `ssh <user>@<vm> sudo -n true` from the controller | No password prompt, no error |
| 8 | Enough resources | — | At least 4 vCPU / 24 GiB RAM / 100 GB disk for a pilot; the services alone reserve ~20 GiB of memory |

If any row fails, stop and fix it first — the automation checks all of these
and will refuse to proceed.

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
| `internal_dns_servers` | Your corporate resolver list (1–3 addresses) |
| `egress_dns_servers` | The internet resolver list (1–3 addresses, no overlap with the line above) |

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
| `chat.<domain>`, `admin.<domain>`, `admin-portal.<domain>`, `litellm-admin.<domain>`, `grafana.<domain>`, `prometheus.<domain>`, `vault.<domain>` | the **ADM** interface IP | chat and administration (ADM leg) |

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
   "AI Gateway" folder should already hold six provisioned dashboards
   (AI Gateway Overview, Live Logs, Request Audit, plus the new Rocky 9 Host,
   Grafana LGTM Stack, and Edge/Egress/Identity Services); the newer dashboards
   link back to AI Gateway Overview as their hub.
3. From a machine on the ADM network, open `https://chat.<domain>` — you
   should reach the chat login. From a user machine (on the internal
   network), open `https://portal.<domain>` — you should reach the
   developer portal login.
4. Enroll the AI vendor credential (Anthropic) following
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
- **Preflight** — a check that reads and validates but changes nothing.
