# Operations

Production operations use the deployed `scripts/aigw-compose.sh` wrapper and
Ansible entry points; do not assemble Compose files or profiles by hand.

## Routine checks

- Run `ansible/site.yml` for a full converge whenever host/firewall state is in
  doubt. Use `deploy-stack-only.yml` only on a host carrying the exact pending
  or completed dedicated-host marker.
- Verify Ansible pipelining before a converge with
  `ansible-config dump | grep PIPELINING`; it must report `True`.
- Use `scripts/aigw-compose.sh ps` for container state. Every expected
  long-running service must be running and healthy; the `volume-init` one-shot
  must remain successfully exited.
- Vault seals after restart. A normal converge submits the encrypted
  controller-held share through stdin and then proves strict dependency
  readiness. Follow [sop/vault-unseal-after-reboot.md](sop/vault-unseal-after-reboot.md).

## Production edge TLS

HTTPS ends at the two Traefik edges. Most container-to-container traffic is
plain HTTP on segmented Docker networks; the platform does not claim internal
mTLS. Envoy starts separate verified TLS connections to AI vendors. Alloy uses
a separate CA bundle for the optional Cribl SOC log endpoint. Follow the
[Cribl logging-team handoff](cribl-soc-handoff.md) before enabling it.

One certificate covers `*.<domain>` and `<domain>`. The validator requires both
names. Choose one production mode in the generated host variables:

| Mode | What the operator supplies |
| --- | --- |
| `customer-supplied` | A ready leaf certificate, its private key, and full chain |
| `customer-intermediate` | An intermediate certificate, its private key, and full chain; Vault imports it and issues the leaf |
| `vault-intermediate` | No private key file; Vault creates the intermediate key and emits a CSR for the customer CA to sign |

The customer root private key must never enter the repository or gateway VM.
Keep all controller-side private-key files outside the repository with mode
`0600`. Ansible validates the certificate, key, chain, SANs, dates, usages,
links, and file permissions before promotion.

For `customer-intermediate`, run this after Vault initialization from
`/opt/ai-gateway` on the target:

```bash
read -rsp 'Vault root token: ' AIGW_VAULT_TOKEN; printf '\n'
printf '%s\n' "$AIGW_VAULT_TOKEN" | sudo scripts/vault-pki-intermediate.sh \
  import-intermediate \
  --intermediate secrets/aigw-intermediate-import.pem \
  --intermediate-key secrets/aigw-intermediate-import.key \
  --chain secrets/aigw-intermediate-import-chain.pem
unset AIGW_VAULT_TOKEN
```

For `vault-intermediate`:

1. On the target, ask Vault to create its internal intermediate key and CSR:

   ```bash
   cd /opt/ai-gateway
   read -rsp 'Vault root token: ' AIGW_VAULT_TOKEN; printf '\n'
   printf '%s\n' "$AIGW_VAULT_TOKEN" | sudo scripts/vault-pki-intermediate.sh csr
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

3. Copy `intermediate.pem` and `chain.pem` to protected temporary paths on the
   target. Import them with the token on stdin:

   ```bash
   cd /opt/ai-gateway
   read -rsp 'Vault root token: ' AIGW_VAULT_TOKEN; printf '\n'
   printf '%s\n' "$AIGW_VAULT_TOKEN" | sudo scripts/vault-pki-intermediate.sh \
     install-signed \
     --signed-intermediate /protected/path/intermediate.pem \
     --chain /protected/path/chain.pem
   unset AIGW_VAULT_TOKEN
   ```

After either intermediate ceremony, run the normal full production converge
again. Verify both published edges with the customer root and the real
hostname. A connection that succeeds only with certificate checking disabled
does not pass.

## Backup and restore

`scripts/state-backup.sh` creates a quiesced age-encrypted backup on an
independent filesystem. `scripts/state-restore.sh` authenticates and stages the
archive, restores the exact approved volume/configuration inventory, and leaves
the project stopped beneath a root-only recovery marker. Run a full
current-source converge before unsealing and reopening ingress. Never perform a
replacement Vault initialization on restored state.

## Updates

Use `scripts/update-images.py` and
[image-update-workflow.md](image-update-workflow.md). The workflow requires a
fresh backup for stateful changes, deploys through Ansible, validates the full
service graph, and restores both state and source during rollback.

## Local preprod

Local preprod is operated only through `scripts/preprod.py` or the unified
updater. It uses a distinct Compose project and loopback bindings. Destroying it
must not target unrelated Docker projects; see [preprod.md](preprod.md).
