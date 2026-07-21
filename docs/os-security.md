# Rocky Linux 9 host security

This page explains the host rules applied by the production Ansible playbook.
Local preprod does not change or prove these rules.

Read [network security](network-security.md) for firewall and route details.
Read [container security](docker-security.md) for Docker rules.

## Required host state

Production supports Rocky Linux 9 only. Ansible checks the host before it
changes it.

The host must:

- run SELinux with the `targeted` policy in enforcing mode;
- allow key-only SSH through ADM from the approved VPN range;
- use reviewed Docker, Compose, containerd, `age`, and Python SDK versions;
- keep project files and secrets at exact owners and modes; and
- report any new SELinux denial as a failed deployment.

The customer should put sensitive state on LUKS-encrypted storage. Ansible
checks this, but it warns and continues when LUKS is missing. The repository
does not create or unlock disks.

## SELinux

The required state is:

```text
Policy: targeted
Mode:   Enforcing
```

If `aigw_manage_selinux` is false, the host must already have this state. If
Ansible manages SELinux, a change that needs a reboot is blocked unless the
operator sets `aigw_allow_selinux_reboot: true` for an approved window.

Ansible also refuses that reboot while Docker is active or enabled. This keeps
containers from starting before host packet rules are ready.

Changing a live Docker host from permissive to enforcing may expose old label
errors. It needs the separate approval
`aigw_allow_active_selinux_enforcement: true`.

Ansible installs the Rocky SELinux and container policy tools. It then sets
persistent labels:

- Docker state uses `container_var_lib_t`.
- Reviewed read-only bind files use `container_ro_file_t`.
- Normal containers run as `container_t` with their own MCS label.

Alloy and node-exporter are the only two approved `label=disable` cases. They
read host trees that must not be relabeled. Their mounts, users, capabilities,
networks, and ports remain limited and checked.

Each bind mount must be read-only and use the right shared `z` or private `Z`
flag. A private bind must match its container's MCS label.

Ansible records the time before it starts host work. At the end, it checks
`AVC` and `USER_AVC` audit events for that window. Any new denial fails the
deploy.

## SSH

Ansible writes this drop-in:

```text
/etc/ssh/sshd_config.d/00-ai-gateway-hardening.conf
```

The main rules are:

| Area | Rule |
| --- | --- |
| Login | Public key only; no password, keyboard, host, GSSAPI, or empty-password login |
| Privilege | No root login, user environment, or user RC file |
| Forwarding | No TCP, Unix socket, agent, X11, tunnel, or gateway forwarding |
| Limits | 3 auth tries, 30-second grace, 4 sessions, `MaxStartups 10:30:30` |

SSH listens only on the managed ADM path and port. firewalld limits it to
`vpn_client_cidr`.

Ansible avoids lockout in this order:

1. Prove a new key-only login before the change.
2. Check the new file and full sshd config with `sshd -t`.
3. Reload sshd; do not restart it.
4. Read back all effective rules with `sshd -T -C`.
5. Prove another key-only login and non-interactive `sudo -n`.

## Time

OIDC, TLS, signed packages, and short-lived WIF tokens need correct time.
`aigw_require_time_sync` is on by default. The allowed clock offset defaults
to five seconds.

## Encrypted state and backups

The customer creates and unlocks LUKS storage when the VM is built. AI Gateway
never receives the LUKS passphrase.

With `require_encrypted_state: true`, Ansible checks the storage below:

- Docker's data root; and
- `/opt/ai-gateway`.

It follows each path to its block device and looks for a `crypto_LUKS`
ancestor. A missing LUKS layer prints `AIGW_ENCRYPTED_STATE_WARNING` and a
plain warning, then continues. Both host prep and stack-only deploy run this
check.

State backups use `age` X25519 encryption to an operator-owned recipient. A
stateful image upgrade is blocked unless a verified backup receipt is less
than 24 hours old when `require_preupgrade_backup` is true.

## Package pins

Ansible uses signed Rocky, EPEL, and Docker repositories. It installs exact
versions instead of silently taking the newest package.

Current host pins are:

| Package | Version |
| --- | --- |
| `docker-ce` | `29.6.1-1.el9` |
| `docker-ce-cli` | `29.6.1-1.el9` |
| `containerd.io` | `2.2.6-1.el9` |
| `docker-compose-plugin` | `5.3.1-1.el9` |
| `age` | `1.3.1-1.el9` |
| Python Docker SDK | `7.2.0` |

The values live in `ansible/group_vars/all.yml`. A reviewed inventory may
override them. If a repository no longer has the exact version, the deploy
stops. If a host already has a newer Docker version, Ansible will not silently
downgrade it.

There is no automatic package update service and no `dnf versionlock`. A pin
change is a reviewed release step with backup and test gates. See
[operations](operations.md).

## Audit and maintenance jobs

The host runs these controls:

- `auditd` records the SELinux events used by the zero-denial gate.
- `aigw-vault-audit-rotate.timer` checks every 15 minutes. It rotates the
  Vault audit file after 100 MiB and keeps a limited archive set.
- `aigw-docker-log-acl.timer` checks every 15 seconds. It gives Alloy UID 473
  read access only to this project's Docker JSON log files.

The log ACL job runs in a locked systemd sandbox. It gets only the file rights
needed to repair those ACLs. It does not give Alloy broad Docker state access.

## File owners and modes

Ansible sets and verifies these main rules:

| Path or type | Owner and mode |
| --- | --- |
| Runtime `.env` | `root:root 0600` |
| Secrets directory | `root:root 0700` |
| Redis verifier/client sources | `root:65532 0440` |
| External LDAPS bind password | `root:65532 0440` |
| Private files read by UID 65532 | group `65532`, usually `0640` or `0440` |
| Public certificates | `0644` |
| Normal non-secret config | `root:root`, directories `0755`, files `0644` |
| Root-only markers and keys | `0600` |

Verification rejects unsafe symlinks and files with extra hard links.

The Redis server reads only a SHA-256 password verifier. Its command and
environment do not contain the password. Clients use a separate mounted file.

## Dedicated-host marker

The production VM is a dedicated Docker host for this stack.

Host prep writes:

```text
/etc/ai-gateway/dedicated-docker-host-v1.pending
```

After the stack passes verification, Ansible promotes it to:

```text
/etc/ai-gateway/dedicated-docker-host-v1
```

`deploy-stack-only.yml` accepts the exact pending or completed marker. It
refuses an unknown host.

The read-only preflight also refuses:

- a controller outside the future ADM SSH rule;
- unsafe path owners, modes, symlinks, or ancestry;
- foreign containers or Docker networks;
- active Swarm mode;
- unknown Docker sockets, plugins, systemd overrides, or daemon flags;
- rootless Docker or another container runtime;
- drifted Docker config on a marked host; and
- existing Docker, firewall, or SSH state without the exact adoption approval.

Adoption flags are narrow and one-time. Firewall adoption can only resume a
validated pending converge. Verification must still pass before the final
marker is written.
