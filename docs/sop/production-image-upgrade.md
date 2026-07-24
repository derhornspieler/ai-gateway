# Upgrade production images with an offline release

Use this SOP to move an existing production VM to a new tested release. One
controller command stages the new seed on the VM over SSH, verifies it,
takes an encrypted backup, deploys, validates, and rolls back by itself if
validation fails. You never copy images by hand, you never type a SHA-256,
and you never run `docker compose` on the VM.

The full background is the [image update workflow](../image-update-workflow.md).
This SOP is the operator checklist for step 4 of that workflow.

## Before you start

You need:

- this repository on the controller, with commands run from its root;
- the new production release pair, already proven by the
  [preprod test deploy SOP](preprod-test-deploy.md) and the GitHub
  container security scan on the exact commit;
- the currently deployed (previous) release pair and its source checkout —
  they are the rollback anchor;
- the generated inventory alias and its private Ansible Vault password file;
- SSH access to the VM for the deploy user, with **non-interactive sudo**
  (`sudo -n`) approved before the maintenance window — the upgrade never
  prompts mid-run;
- the customer root CA file, the `age` backup recipient, and the matching
  private age identity file (mode `0600`);
- a dedicated backup directory on its own file system on the VM — never
  `/`, `/var`, or `/tmp`.

The release platform must match the VM. An `arm64` seed cannot deploy to an
x86 VM. Your release files must be owned by you and not writable by any
other user; normal copied permissions are fine.

## Check pipelining first

```bash
ansible-config dump | grep PIPELINING
```

The output must show `= True`. Stop if it shows the default `False`.

## Run the upgrade

Replace every sample value:

```bash
python3 -I scripts/update-images.py upgrade \
  --archive /srv/ai-gateway-releases/2026-07-22-linux-amd64/aigw-2026-07-22-linux-amd64.docker.tar.zst \
  --manifest /srv/ai-gateway-releases/2026-07-22-linux-amd64/aigw-2026-07-22-linux-amd64.manifest.json \
  --previous-archive /srv/ai-gateway-releases/previous/aigw-previous.docker.tar.zst \
  --previous-manifest /srv/ai-gateway-releases/previous/aigw-previous.manifest.json \
  --previous-release-dir /srv/ai-gateway-releases/previous-source \
  --inventory ansible/inventory/generated/mygateway/hosts.yml \
  --limit mygateway \
  --vault-id mygateway@/secure/path/mygateway.vault-password \
  --ssh-target deployer@gateway01.example.internal \
  --ssh-port 22 \
  --domain example.internal \
  --adm-ip 192.0.2.20 \
  --internal-ip 198.51.100.20 \
  --root-ca /secure/path/root-ca.pem \
  --backup-recipient age1example0000000000000000000000000000000000000000000000000000 \
  --rollback-age-identity /secure/path/backup-age-identity.txt \
  --remote-backup-root /mnt/ai-gateway-backups \
  --remote-backup-path /mnt/ai-gateway-backups/gateway01-before-image-update.tar.gz.age
```

Use the production pair, never the `.preprod` pair. The provider choice is
sealed inside the manifest and Envoy image; this command cannot change it.

## What success looks like

The command exits with status `0` after it has:

1. staged both seeds in a private root path on the VM;
2. proven the previous seed matches the running release;
3. taken and checked the encrypted backup;
4. deployed the new release through Ansible;
5. passed the built-in acceptance gate.

## If validation fails

The updater restores the old state, source, images, and Envoy policy by
itself. Do not "fix forward" on the VM by hand. Read the failure, fix the
cause in source, build a new release, and start this SOP again from the
preprod test.

Details: [image update workflow](../image-update-workflow.md) and
[offline image releases](../offline-image-seed.md).
