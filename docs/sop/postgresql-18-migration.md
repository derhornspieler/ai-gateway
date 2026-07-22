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

The exact-seed local Docker PreProd rehearsal also passed. It used more than
128 MiB of fixed PostgreSQL 16 data in each application database. It tested
rollback, service access, PostgreSQL 18 restore, downgrade refusal, physical
restore, and exact-manifest cleanup. Do not create a Rocky or Parallels test
VM, and do not force a failure on the production host. See the completed test
evidence in [TASKS.md](../../TASKS.md#done).

The repository has no recorded technical reason for starting on PostgreSQL
16. A conservative first choice is possible, but that is an inference, not a
recorded decision.

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
  --output /mnt/aigw-backups/gateway01-pg16-final.tar.gz.age \
  --major-migration-quiesce \
  --confirm QUIESCE_POSTGRES_16_FOR_MAJOR_MIGRATION
```

This confirmation is required only for a major migration. An ordinary state
backup still restarts the exact containers that were running before it began.

Major-migration mode stops every application container and leaves it stopped.
It creates the logical dumps, forces a PostgreSQL checkpoint, and records the
checkpoint ID. It also records the full project container list, the exact
containers that were running, and the PostgreSQL 16 container, image, and
volume IDs. It records the stopped-state generation of every other container,
so a brief restart is also detected. The encrypted backup protects this
record. At the end, the script starts only that exact PostgreSQL 16 container.

Do not unseal Vault, start a portal, or run the normal stack deploy now. Those
actions would reopen database writers. Continue directly to the migration.

Copy the SHA-256 shown by the command into the next step. The migration accepts
backups that are no more than 30 minutes old. During both plan and migration,
it proves that the full container list is unchanged, the recorded PostgreSQL
16 source is the only running project container, and every application writer
is still stopped. It then forces another checkpoint and compares the live ID
with the saved ID. If the source changed, the migration asks for a new backup.

The migration rejects backups made by an older script that did not record the
post-dump checkpoint barrier. Stage the current scripts and take a new backup.
Do not reuse an older PostgreSQL 16 backup for this migration.

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

The playbook deletes this temporary identity after planning and restoring. It
also deletes the identity when planning fails before the restore starts.

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

1. Check the backup hash, age envelope, manifest, PostgreSQL version,
   post-dump checkpoint barrier, checkpoint ID, and exact source identity.
2. Prove that only the recorded PostgreSQL 16 source is running.
3. Check the exact PostgreSQL 18.4 image metadata.
4. Stop PostgreSQL 16. The application writers were already stopped by the
   major-migration backup and must stay stopped.
5. Create `ai-gateway_pg18_data` as a fresh volume.
6. Start a network-disabled temporary PostgreSQL 18 container.
7. Run the reviewed database setup script to create the roles and databases.
8. Restore each dump with `pg_restore --single-transaction --exit-on-error`.
9. Run the setup script again, then check database owners, role flags,
   memberships, and access. The second run repairs any restored access drift.
10. Remove the temporary container and age identity.
11. Run the normal stack-only Ansible deploy and full verify role.
12. Check the live image ID, volume mount, PostgreSQL version, database
    objects, and security matrix.

The receipt is stored at:

```text
/opt/ai-gateway/.state/postgres-major-migration-v1.json
```

It is root-owned mode `0600`.

## Rollback boundary

There are two clear states.

Before PostgreSQL 18 starts in the normal stack, rollback is allowed. If the
logical restore fails, rollback first checks the full recorded container list
and source identity. It refuses an unknown or missing project container. It
safely stops any recorded containers that are still running, removes only the
PostgreSQL 18 volume with matching migration labels, and restarts the exact
graph that was running before the backup. The old volume was never changed.
Repeating rollback is safe after a partial stop or a completed rollback.

If the read-only plan refuses an input, it does not change Docker. PostgreSQL
16 remains the only running project container, and the playbook deletes the
temporary age identity. Fix the input, copy the identity back, and retry while
the maintenance window stays closed. Take a new major-migration backup if the
source or container inventory changed.

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

`major migration requires the exact PostgreSQL 16 source to be the only
running project container` means an application container was started after
the backup. Stop and investigate it. Take a new major-migration backup; do not
bypass the check.

`project containers changed after the major-migration backup` means a
container was added, removed, or replaced. Take a new major-migration backup
from the reviewed stack.

`backup lacks the forced post-dump PostgreSQL checkpoint barrier` means the
backup came from an older script or its manifest changed. Stage the current
scripts, take a new backup, and retry. Do not bypass this check.

`target PostgreSQL 18 volume already exists` means an earlier attempt left
state behind or the selected volume name is not fresh. Inspect the migration
receipt before doing anything. Do not delete a volume by name alone.

`rollback refused after writes reopened` means the safe downgrade window is
closed. Keep PostgreSQL 18 and fix forward.
