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

## 2. Bootstrap the inventory

```bash
scripts/bootstrap-rocky9-production.py \
  --inventory-alias mygateway \
  --vault-id mygateway \
  --vault-password-file /secure/path/mygateway.vault-password
```

This generates the encrypted inventory and stack secrets under
`ansible/inventory/generated/mygateway/`. Then edit
`ansible/inventory/generated/mygateway/host_vars/mygateway.yml` and fill in
your site values: addresses, domain, edge-TLS mode, and — for the offline
image path — the five `offline_image_seed_*` values from
[stage a production pair](../offline-image-seed.md#stage-a-production-pair).

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
