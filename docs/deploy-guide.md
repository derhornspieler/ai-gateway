# Choose a deployment path

AI Gateway has two deployment paths. Pick one before you run a command.

| Goal | Where it runs | Start here |
| --- | --- | --- |
| Test a release | Local Docker on macOS or Linux | [Local preprod](preprod.md) |
| Install production | An existing Rocky Linux 9 VM | [Production runbook](deploy-runbook.md) |
| Update production images | Local Docker, then the production VM | [Image update workflow](image-update-workflow.md) |
| Unlock Vault after a reboot | The Ansible controller and production VM | [Vault unseal SOP](sop/vault-unseal-after-reboot.md) |

Local preprod and production are separate. Preprod uses `aigw.internal`, test
users, a test Root CA, Samba AD, and a WIF mock. Production uses the domain,
directory, certificates, and network values in its Ansible inventory.

You do not need a test VM. Release testing runs in local Docker preprod.

## Production

Production uses a two-pass Ansible run on a customer-owned Rocky Linux 9 VM.
The first pass prepares the host and starts the core stack. An operator then
initializes Vault once. The second pass unlocks Vault, configures Keycloak from
LDAPS, and checks the full system.

Start by creating the inventory:

```bash
python3 -I scripts/bootstrap-rocky9-production.py \
  --inventory-alias <alias> \
  --vault-id <vault-id> \
  --vault-password-file </absolute/private/password-file>
```

The three options are required for a non-interactive run. Run the script with
no options in a terminal if you want guided prompts.

Follow the [production runbook](deploy-runbook.md) for the full command list.
It covers the host check, DNS, TLS, Vault, LDAPS, Keycloak, and sign-off.

## Local preprod

Start source mode with Ansible. Sudo is used only for the bounded hosts block
and, on macOS, two loopback aliases:

```bash
ansible-playbook -i ansible/inventory/preprod.yml ansible/preprod.yml \
  --ask-become-pass
```

You may use a private password file outside this repository instead of the
prompt:

```bash
ansible-playbook -i ansible/inventory/preprod.yml ansible/preprod.yml \
  --become-password-file </absolute/private/become-password-file>
```

The normal release gate loads the exact preprod offline seed before Ansible
starts the stack. See [Local preprod](preprod.md#test-an-offline-seed).

## Image updates and offline transfer

Do not edit a generated manifest. Change reviewed image pins in the Compose
files or Dockerfiles. Commit the change. Then run `scripts/update-images.py`.
It builds both seed pairs, tests the preprod pair, and can deploy the production
pair with validation and rollback.

Follow the [image update workflow](image-update-workflow.md).

## Next pages

- [Acceptance test runbook](test-runbook.md)
- [Production operations](operations.md)
- [Offline seed details](offline-image-seed.md)
