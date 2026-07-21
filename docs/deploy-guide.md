# Deployment Guide

Production deployment is a two-pass, fail-closed Ansible converge onto a
customer-owned Rocky Linux 9 VM. Local acceptance is a separate Docker Desktop
preprod workflow; it is never selected by a production inventory.

## Production

1. Generate an inventory and encrypted secret overlay:

   ```bash
   python3 scripts/bootstrap-rocky9-production.py \
     --inventory-alias <alias> \
     --vault-id <vault-id> \
     --vault-password-file </absolute/private/password-file>
   ```

2. Complete the generated host variables, then run the controller-only
   preflight and full converge from the repository root. The committed
   `ansible.cfg` keeps connection pipelining enabled so decrypted stdin does
   not land in remote Ansible temporary files.

3. Perform the reviewed production Vault initialization ceremony, store its
   unseal share with `scripts/store-vault-unseal-key.py`, and run the identical
   converge again. The second run requires complete runtime readiness.

The exact commands, expected receipts, topology requirements, TLS modes, and
operator sign-off are in [deploy-runbook.md](deploy-runbook.md).

## Local preprod

Use [preprod.md](preprod.md) and `scripts/update-images.py test-preprod`.
Preprod binds only to loopback, creates its own three Docker networks, issues a
local root CA, and uses static preprod-only identities. It does not modify
`/etc/hosts` without explicit operator approval.

## Image updates and offline transfer

Use [image-update-workflow.md](image-update-workflow.md). The unified updater
builds the complete offline seed, validates it in local preprod, stages it on
the controller/target with root-only ownership, deploys through Ansible, runs
post-upgrade validation, and rolls back on failure.
