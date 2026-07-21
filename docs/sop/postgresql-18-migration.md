# Move PostgreSQL 16 to PostgreSQL 18

Use this SOP only for an existing AI Gateway that still has a PostgreSQL 16
volume. A clean deployment starts on PostgreSQL 18 and does not need this SOP.

Do not use `scripts/update-images.py` for this change. It refuses PostgreSQL
major changes on purpose.

## What this migration protects

PostgreSQL 16 and 18 cannot share a data directory. This workflow creates a
new PostgreSQL 18 volume named `ai-gateway_pg18_data`. It restores three
logical database dumps into that volume:

- `litellm.dump`
- `keycloak.dump`
- `rotator.dump`

The old `ai-gateway_pg_data` volume is not changed. The workflow reads
`globals.sql` only to check the role list. It does not run that SQL file.
Passwords, roles, databases, ownership, and access rules come from the current
encrypted Ansible inventory and the reviewed database init script.

PostgreSQL 18.4 is a stable release, not a preview. The operator selected it
after a bounded comparison with PostgreSQL 17.10. Both exact DHI images passed
the same checks: database setup, LiteLLM migrations and readiness, Keycloak
startup, key-rotator database work, Grafana read-only access, PostgreSQL 16
logical restore, and same-major physical restore. PostgreSQL 18 also has a
longer support window and enables data checksums by default on a new cluster.

Those checks do not replace the full seeded preprod rehearsal. That release
gate remains open. The repository has no recorded technical reason for
starting on PostgreSQL 16. A conservative first choice is possible, but that
is an inference, not a recorded decision.

## Before you start

You need:

- the production inventory alias;
- its Ansible Vault ID and password file;
- SSH and `sudo` access to the Docker host;
- an age recipient whose private identity is held on separate recovery
  storage; and
- an independent backup mount on the Docker host.

Keep a maintenance window open. Do not allow users back in until the final
validation passes.

The examples below use these values:

```text
Inventory alias: gateway01
Vault ID: gateway01
Vault password file: /secure/gateway01.vault-pass
Backup: /mnt/aigw-backups/gateway01-pg16-final.tar.gz.age
Temporary age identity: /run/ai-gateway-postgres18/backup.agekey
```

Replace them with your real paths. Do not put the age identity in the Git
checkout or the backup directory.

## 1. Stage the new backup and migration tools

Run this from the repository root on the Ansible controller:

```bash
ansible-playbook \
  -i ansible/inventory/generated/gateway01/hosts.yml \
  ansible/migrate-postgres18.yml \
  --limit gateway01 \
  --vault-id gateway01@/secure/gateway01.vault-pass \
  --tags postgres_migration_stage
```

This step copies three reviewed scripts. It does not stop a container or
change a database.

## 2. Take the final PostgreSQL 16 backup

On the Docker host, run:

```bash
sudo /opt/ai-gateway/scripts/state-backup.sh \
  --recipient age1REPLACE_WITH_THE_REAL_AGE_RECIPIENT \
  --output /mnt/aigw-backups/gateway01-pg16-final.tar.gz.age
```

The backup stops writers, creates custom-format logical dumps, records the
PostgreSQL checkpoint ID, encrypts the result, and restarts the same
containers. It also seals Vault because Vault was restarted. Perform the
normal Vault unseal procedure if you need the live system before cutover.

Copy the SHA-256 shown by the command into the next step. The migration accepts
backups that are no more than 30 minutes old. It also compares the saved
PostgreSQL checkpoint ID with the live server. If any database write happened
after the backup, the migration stops and asks for a new backup.

## 3. Place the temporary age identity on the Docker host

Create the fixed private directory:

```bash
ssh gateway01 'sudo install -d -o root -g root -m 0700 /run/ai-gateway-postgres18'
```

Copy the identity by your approved secure transfer method, then set:

```bash
ssh gateway01 \
  'sudo chown root:root /run/ai-gateway-postgres18/backup.agekey && \
   sudo chmod 0600 /run/ai-gateway-postgres18/backup.agekey'
```

The playbook deletes this temporary identity after the logical restore,
whether the restore passes or rolls back.

## 4. Run migration, deploy, and validation

Run this from the repository root:

```bash
ansible-playbook \
  -i ansible/inventory/generated/gateway01/hosts.yml \
  ansible/migrate-postgres18.yml \
  --limit gateway01 \
  --vault-id gateway01@/secure/gateway01.vault-pass \
  --extra-vars postgres_migration_backup_path=/mnt/aigw-backups/gateway01-pg16-final.tar.gz.age \
  --extra-vars postgres_migration_age_identity_path=/run/ai-gateway-postgres18/backup.agekey \
  --extra-vars postgres_migration_backup_sha256=REPLACE_WITH_64_LOWERCASE_HEX_CHARACTERS \
  --extra-vars postgres_migration_confirm=MIGRATE_POSTGRES_16_TO_18
```

The playbook performs these steps:

1. Check the backup hash, age envelope, manifest, PostgreSQL version, and
   checkpoint ID.
2. Check the exact PostgreSQL 18.4 image metadata.
3. Stop the exact running AI Gateway containers.
4. Create `ai-gateway_pg18_data` as a fresh volume.
5. Start a network-disabled temporary PostgreSQL 18 container.
6. Run the reviewed database setup script to create the roles and databases.
7. Restore each dump with `pg_restore --single-transaction --exit-on-error`.
8. Run the setup script again, then check database owners, role flags,
   memberships, and access. The second run repairs any restored access drift.
9. Remove the temporary container and age identity.
10. Run the normal stack-only Ansible deploy and full verify role.
11. Check the live image ID, volume mount, PostgreSQL version, database
    objects, and security matrix.

The receipt is stored at:

```text
/opt/ai-gateway/.state/postgres-major-migration-v1.json
```

It is root-owned mode `0600`.

## Rollback boundary

There are two clear states.

Before PostgreSQL 18 starts in the normal stack, rollback is allowed. If the
logical restore or its first validation fails, Ansible removes the failed new
volume and restarts the exact PostgreSQL 16 container graph. The old volume was
never changed.

Before the normal deploy starts PostgreSQL 18, Ansible changes the receipt to
`writes_opened`. This closes the rollback window. PostgreSQL does not support
writing on version 18 and then mounting that data in version 16.

After `writes_opened`, never start PostgreSQL 16. Keep ingress closed, keep the
backup, fix the PostgreSQL 18 problem, and run the same playbook or normal
converge again. This is a fail-closed, fix-forward state.

## 5. Check the result

After the playbook succeeds, confirm the receipt phase:

```bash
ssh gateway01 \
  'sudo python3 -c '\''import json; print(json.load(open("/opt/ai-gateway/.state/postgres-major-migration-v1.json"))["phase"])'\'''
```

The output must be:

```text
validated
```

Then run the normal external acceptance test from the controller. Unseal Vault
if the deploy restarted it. Do not delete the PostgreSQL 16 volume during this
change window. Retire it only after the owner accepts the backup, restore test,
database checks, and application acceptance evidence.

## Common refusals

`PostgreSQL changed after the backup` means at least one transaction advanced
the source checkpoint. Take a new backup and retry.

`target PostgreSQL 18 volume already exists` means an earlier attempt left
state behind or the selected volume name is not fresh. Inspect the migration
receipt before doing anything. Do not delete a volume by name alone.

`rollback refused after writes reopened` means the safe downgrade window is
closed. Keep PostgreSQL 18 and fix forward.
