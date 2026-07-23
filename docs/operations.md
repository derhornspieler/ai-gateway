# Production operations

Use Ansible for production changes. Use the deployed
`scripts/aigw-compose.sh` wrapper for read-only checks and logs. Do not build a
Compose command by hand.

| Need | Use |
| --- | --- |
| Full host and stack check | `ansible/site.yml` |
| App-only deploy on a prepared host | `ansible/deploy-stack-only.yml` |
| Vault unlock after reboot | [Vault unseal SOP](sop/vault-unseal-after-reboot.md) |
| Image update | [Image update workflow](image-update-workflow.md) |
| Upgrade production images | [Production image upgrade SOP](sop/production-image-upgrade.md) |
| Test a release in local preprod | [Preprod test deploy SOP](sop/preprod-test-deploy.md) |
| First production install | [Production new-deploy SOP](sop/production-new-deploy.md) |
| Add, hide, or retire a model | [Model lifecycle SOP](sop/model-lifecycle.md) |
| Alerts, dashboards, and telemetry | [Observability operations](observability-operations.md) |
| New production install | [Deployment runbook](deploy-runbook.md) |
| Local release test | [Local preprod](preprod.md) |

## Routine checks

Before any Ansible run, start at the repository root and check pipelining:

```bash
ansible-config dump | grep PIPELINING
```

It must show `True`. Pipelining keeps decrypted standard input out of remote
Ansible temp files.

Use a full `site.yml` run when host, firewall, route, or Docker network state
may have changed. Use `deploy-stack-only.yml` only when the host has the exact
pending or completed gateway marker. The stack-only play stops if the host is
not ready.

On the production VM, check container state with:

```bash
cd /opt/ai-gateway
sudo scripts/aigw-compose.sh ps
```

Each required long-running service must be running and healthy. The
`volume-init` one-shot must show a successful exit.

Open Grafana's **AI Gateway Alerts and Capacity** dashboard. The watchdog must
be firing, no unexplained critical alert may be active, and recently resolved
alerts must match known work. Alertmanager stays private and has no FQDN. Use
the [alert response runbooks](observability-operations.md#alert-response-runbooks)
for the next check.

Vault seals after a VM restart. Follow the
[Vault unseal SOP](sop/vault-unseal-after-reboot.md). A normal Ansible run
uses the encrypted controller copy of the share and then checks the stack.

## Production edge TLS

TLS ends at the internal and ADM Traefik edges. Envoy opens a separate checked
TLS link to the selected AI provider. Alloy uses its own CA bundle when the
optional Cribl feed is on.

The edge certificate must cover both `*.<domain>` and `<domain>`. Pick one mode
in the generated host variables:

| Mode | What you provide |
| --- | --- |
| `customer-supplied` | A leaf certificate, private key, and full chain |
| `customer-intermediate` | An intermediate certificate, private key, and full chain |
| `vault-intermediate` | Vault makes the intermediate key and a CSR; your CA signs the CSR |

Keep the customer root private key off the gateway and out of this repository.
Keep controller-side private keys outside the repository with mode `0600`.
Ansible checks paths, ownership, certificates, keys, chains, names, dates, and
key use before install.

For `customer-intermediate`, run this once after Vault initialization on the
production VM:

```bash
cd /opt/ai-gateway
read -rsp 'Vault root token: ' AIGW_VAULT_TOKEN; printf '\n'
printf '%s\n' "$AIGW_VAULT_TOKEN" | sudo scripts/vault-pki-intermediate.sh \
  import-intermediate \
  --intermediate secrets/aigw-intermediate-import.pem \
  --intermediate-key secrets/aigw-intermediate-import.key \
  --chain secrets/aigw-intermediate-import-chain.pem
unset AIGW_VAULT_TOKEN
```

For `vault-intermediate`, use this three-step flow:

1. Ask Vault to make its key and CSR on the production VM:

   ```bash
   cd /opt/ai-gateway
   read -rsp 'Vault root token: ' AIGW_VAULT_TOKEN; printf '\n'
   printf '%s\n' "$AIGW_VAULT_TOKEN" | \
     sudo scripts/vault-pki-intermediate.sh csr
   unset AIGW_VAULT_TOKEN
   ```

2. Move only the CSR to the approved CA workstation. Sign it there:

   ```bash
   scripts/sign-vault-intermediate.sh \
     --csr /path/to/aigw-intermediate.csr \
     --root-cert /path/to/root-ca.pem \
     --root-key /path/to/root-ca-key.pem \
     --out-dir /private/output/directory
   ```

3. Copy `intermediate.pem` and `chain.pem` to protected temp paths on the VM.
   Install them:

   ```bash
   cd /opt/ai-gateway
   read -rsp 'Vault root token: ' AIGW_VAULT_TOKEN; printf '\n'
   printf '%s\n' "$AIGW_VAULT_TOKEN" | \
     sudo scripts/vault-pki-intermediate.sh install-signed \
       --signed-intermediate /protected/path/intermediate.pem \
       --chain /protected/path/chain.pem
   unset AIGW_VAULT_TOKEN
   ```

Run the full production converge after either ceremony. Test both edge IPs
with the real hostname and customer Root CA. A test that works only when
certificate checks are off does not pass.

For the optional Cribl TLS setup, follow the
[Cribl telemetry-team handoff](cribl-soc-handoff.md).

## Backup and restore

`scripts/state-backup.sh` stops writers and makes an age-encrypted backup on a
separate file system. `scripts/state-restore.sh` checks and restores an approved
backup. Restore leaves the project stopped under a root-only marker.

After restore, run a full current-source converge. Then unlock Vault and check
all services before you open ingress. Never initialize a new Vault over
restored state.

## Updates

Use `scripts/update-images.py` and the
[image update workflow](image-update-workflow.md). The workflow requires a new
backup for stateful changes. It deploys through Ansible. It checks the result
and restores the old state, source, images, and Envoy policy if validation
fails.

## Local preprod

Local preprod is not a production host. It uses the fixed `aigw-preprod`
project, `aigw.internal`, and loopback listeners. Operate it through Ansible or
the image updater. See [Local preprod](preprod.md).
