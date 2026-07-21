# Unseal Vault after a production VM reboot

Use this procedure after the VM reboots for security patches or maintenance.
Vault always starts sealed. The normal Ansible deployment can unlock it with
the encrypted unseal key already stored on the controller.

## Before you start

You need:

- the repository on the Ansible controller;
- SSH access to the production VM;
- the generated inventory alias;
- the Ansible Vault password file; and
- the encrypted `vault-unseal.yml` file created during the first deployment.

Do not initialize Vault again. Initialization is a one-time deployment
ceremony, not a reboot or restore step. Reinitializing it would replace the
keys needed to read the existing data.

## Run the playbook

Start in the repository root. First confirm that Ansible pipelining is enabled:

```bash
ansible-config dump | grep PIPELINING
```

The output must end with `= True`. Then run the stack playbook. Replace
`mygateway` and the password-file path with your deployment values:

```bash
ansible-playbook \
  -i ansible/inventory/generated/mygateway/hosts.yml \
  ansible/deploy-stack-only.yml \
  --limit mygateway \
  --vault-id mygateway@/secure/path/mygateway.vault-password
```

The playbook reads the encrypted unseal key on the controller, sends it to the
VM over standard input, unlocks Vault, and runs the normal service checks. The
key is not placed in a command argument, environment variable, or log.

## What success looks like

The playbook exits with status `0`. Its Vault readiness and final verification
tasks pass. No service remains unhealthy.

If the stack-only playbook says the host marker, firewall, or network setup is
stale, run the full playbook with the same inventory and Vault options:

```bash
ansible-playbook \
  -i ansible/inventory/generated/mygateway/hosts.yml \
  ansible/site.yml \
  --limit mygateway \
  --vault-id mygateway@/secure/path/mygateway.vault-password
```

Do not bypass a failed check. Fix the reported problem and run the playbook
again.

## Emergency manual method

Use this only when the controller is unavailable and an approved custodian has
an unseal share. Run it on the VM:

```bash
cd /opt/ai-gateway
read -rsp 'Vault unseal share: ' AIGW_UNSEAL_SHARE; printf '\n'
printf '%s\n' "$AIGW_UNSEAL_SHARE" | sudo scripts/vault-unseal.sh
unset AIGW_UNSEAL_SHARE
```

Never paste the share into a command argument, ticket, chat, or shell history.
