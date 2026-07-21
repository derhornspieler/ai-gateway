# Unseal Vault after a production VM reboot

Use this SOP after a reboot for patches or maintenance. Vault starts sealed
after every reboot. The normal Ansible play unlocks it with the encrypted
unseal key on the controller.

Do not initialize Vault again. Initialization is a one-time install step.
Running it again would replace the keys used to read the current data.

## Before you start

You need:

- the AI Gateway repository on the Ansible controller;
- SSH access to the production VM;
- the inventory alias;
- the private Ansible Vault password file; and
- the encrypted `vault-unseal.yml` file made during the first install.

Run every command from the repository root.

## Run the playbook

First check Ansible pipelining:

```bash
ansible-config dump | grep PIPELINING
```

The output must show `= True`. Stop if it shows the default value as `False`.

Run the stack-only play. Replace the sample alias and password-file path:

```bash
ansible-playbook \
  -i ansible/inventory/generated/mygateway/hosts.yml \
  ansible/deploy-stack-only.yml \
  --limit mygateway \
  --vault-id mygateway@/secure/path/mygateway.vault-password
```

Ansible decrypts the unseal key on the controller. It sends the key to the VM
through standard input. It does not place the key in a command option, an
environment value, or a log. The play then checks Vault and the full stack.

## What success looks like

The command exits with status `0`. Vault is initialized, unsealed, and ready.
All required services pass their health checks.

If the play reports an old host marker, firewall, or network setup, run the
full play with the same inventory and Vault password file:

```bash
ansible-playbook \
  -i ansible/inventory/generated/mygateway/hosts.yml \
  ansible/site.yml \
  --limit mygateway \
  --vault-id mygateway@/secure/path/mygateway.vault-password
```

Do not skip or weaken a failed check. Fix the named problem and run the play
again.

## Emergency manual method

Use this only when the controller is down and an approved custodian has an
unseal share. Run it on the production VM:

```bash
cd /opt/ai-gateway
read -rsp 'Vault unseal share: ' AIGW_UNSEAL_SHARE; printf '\n'
printf '%s\n' "$AIGW_UNSEAL_SHARE" | sudo scripts/vault-unseal.sh
unset AIGW_UNSEAL_SHARE
```

Run the command once for each required share. Never paste a share into a
command option, ticket, chat, or shell history.

After the manual unlock, run the normal Ansible play as soon as the controller
is back. This checks the rest of the stack.

## Related pages

- [Production deployment](../deploy-runbook.md)
- [Production operations](../operations.md)
