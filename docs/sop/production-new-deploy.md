# Install AI Gateway on a new production VM

Use this SOP for the first install on an existing Rocky Linux 9 VM. It is
the operator checklist for the
[deployment runbook](../deploy-runbook.md); read that runbook once before
your first install. The converge is **deliberately two passes** with the
one-time Vault ceremony between them.

## Before you start

You need:

- an existing Rocky Linux 9 VM with its egress, ADM, and internal
  interfaces already created — Ansible configures the host; it never
  creates VMs, NICs, addresses, routes, or DNS;
- a controller (macOS or Linux) with `ansible-core` 2.16 or newer;
- SSH access from the controller to the VM;
- a private Ansible Vault password file;
- the customer TLS material for your selected edge mode;
- a decision on how the VM gets images — either log the VM's **root**
  Docker daemon in to `dhi.io`, or stage a production offline seed
  (a normal user's Docker login does not log in the root daemon).

## 1. Prepare the controller

```bash
git clone <repository-url> ai-gateway
cd ai-gateway
ansible-galaxy collection install -r ansible/requirements.yml
```

Run everything that follows from the repository root. Then check
pipelining — it is a confidentiality control, not a preference:

```bash
ansible-config dump | grep PIPELINING
```

The output must show `= True`. Stop if it shows the default `False`.

## 2. Generate the inventory and secrets

The easy path is the guided setup. Run the bootstrap with no options and
answer its questions:

```bash
scripts/bootstrap-rocky9-production.py
```

It never shows a secret on screen. The direct form does the same thing
with explicit options:

```bash
scripts/bootstrap-rocky9-production.py \
  --inventory-alias mygateway \
  --vault-id mygateway \
  --vault-password-file /secure/path/mygateway.vault-password
```

Both forms create these files under
`ansible/inventory/generated/mygateway/`:

| File | What it is | Do you edit it? |
| --- | --- | --- |
| `hosts.yml` | The inventory Ansible reads | No |
| `host_vars/mygateway.yml` | Your site settings | **Yes — this is the one file you fill in** |
| `group_vars/production_rocky9/vault.yml` | All stack passwords, generated randomly and stored encrypted | Only with `ansible-vault edit`, and normally never |
| `group_vars/production_rocky9/vault-unseal.yml` | The encrypted Vault unseal key | Never by hand — step 5 creates it |

Open `host_vars/mygateway.yml`. The file explains itself in plain words at
the top. Fill in SECTION 1 (your VM's addresses, interfaces, DNS, and
domain), pick one HTTPS mode in SECTION 5, and — for the offline image
path — set the five `offline_image_seed_*` values from
[stage a production pair](../offline-image-seed.md#stage-a-production-pair).
Skip SECTION 3 and SECTION 4 for now; the file tells you when they apply.

Never paste a decrypted password into `host_vars`. The generated secrets
stay encrypted and the deploy reads them for you.

## 3. Preflight the VM

```bash
ansible-playbook \
  -i ansible/inventory/generated/mygateway/hosts.yml \
  ansible/preflight-rocky9-production.yml \
  --limit mygateway \
  --vault-id mygateway@/secure/path/mygateway.vault-password
```

Fix every reported problem before the converge.

## 4. First converge pass

```bash
ansible-playbook \
  -i ansible/inventory/generated/mygateway/hosts.yml \
  ansible/site.yml \
  --limit mygateway \
  --vault-id mygateway@/secure/path/mygateway.vault-password
```

This pass ends with Vault **uninitialized**. That is expected, not a
failure.

## 5. One-time Vault ceremony

Run the reviewed production Vault initialization ceremony from the
[deployment runbook](../deploy-runbook.md). Then store the unseal share on
the controller with the stdin-only helper:

```bash
read -rsp 'Vault unseal key: ' AIGW_UNSEAL_SHARE; printf '\n'
printf '%s\n' "$AIGW_UNSEAL_SHARE" | \
  python3 -I scripts/store-vault-unseal-key.py \
    --vault-file ansible/inventory/generated/mygateway/group_vars/production_rocky9/vault-unseal.yml \
    --vault-id mygateway \
    --vault-password-file /secure/path/mygateway.vault-password
unset AIGW_UNSEAL_SHARE
```

Never put the share in a command option, an environment value, or a log.
Never initialize Vault again after this day; see
[unseal Vault after a reboot](vault-unseal-after-reboot.md) for every later
restart.

## 6. Second converge pass

Run the exact same `site.yml` command from step 4 again. This pass
auto-unseals Vault from the encrypted controller-held share and must end
with strict readiness: exit status `0` and every required service healthy.

## What success looks like

- Both passes exit `0`; the second one reports full readiness.
- The dedicated-host marker on the VM is the completed marker.
- The verify role passes; only Traefik publishes ports, bound to the exact
  NIC addresses.

## If something fails

- A topology disagreement stops `site.yml` before any change. Fix the host
  or the declared inventory, never the check.
- Later config changes on a prepared host can use
  `ansible/deploy-stack-only.yml`; if it refuses the host, run the full
  `ansible/site.yml` again. Never bypass its assertions.
- Image updates after this install follow the
  [production image upgrade SOP](production-image-upgrade.md).
