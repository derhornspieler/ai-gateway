# Operating System Security Baseline (Rocky Linux 9)

This document describes the host-level hardening AI Gateway's Ansible
playbooks require and apply on the target Rocky Linux 9 VM: SELinux policy
and verification, SSH hardening, encrypted state storage, package hygiene,
auditing, and filesystem permission contracts. Network enforcement is covered
separately in [network security](network-security.md); the container platform
in [Docker security](docker-security.md).

## Posture summary

The playbook validates before it mutates, and it fails closed: every contract
below is asserted by a read-only preflight or the post-converge `verify`
role, and a violated contract stops the run rather than being silently
repaired. Only Rocky Linux 9 is supported; any other distribution or major
version is refused.

## 1. SELinux

**Required state.** The `targeted` policy, `Enforcing`, on Rocky 9. These
values are hard-pinned; the play asserts them and refuses substitutes. With
management disabled (`aigw_manage_selinux: false`) the play still requires
the host to already be enforcing.

**Controlled transitions only.** If reaching enforcing requires a reboot
(disabled policy, wrong loaded policy, or `selinux=0` on the kernel command
line), the play refuses unless the operator explicitly sets
`aigw_allow_selinux_reboot: true`, and it will not reboot at all while the
Docker unit is enabled or active — the host must never boot into an unguarded
container start. Switching a *live* Docker host from permissive to enforcing
additionally requires `aigw_allow_active_selinux_enforcement: true`, because
that transition can surface latent labeling defects immediately.

**Installed tooling.** `selinux-policy-targeted`, `container-selinux`,
`policycoreutils(-python-utils)`, `libselinux-utils`, `python3-libselinux`,
and `grubby` for kernel-parameter management.

**Persistent file contexts.** Docker's data root carries
`container_var_lib_t`; every reviewed read-only bind source (certificates,
Traefik/LiteLLM/Keycloak/Vault/telemetry configuration, and the secrets
files) is persisted as `container_ro_file_t`. Relabeling runs only when no
project container exists yet, so a live container's private MCS category is
never erased, and `restorecon` is never applied to Docker's runtime tree.

**Per-container confinement.** Every ordinary service must run as
`container_t` with its own MCS category pair on both process and mount
label, verified against `/proc/<pid>/attr/current`. Exactly two bounded
exceptions run with `label=disable` (the log collector and the host-metrics
exporter — see [Docker security](docker-security.md)); anything else
unlabeled fails verification. Each bind mount must be read-only with exactly
one relabel flag, and private (`Z`) binds must show the exact MCS category of
their owning container.

**Zero-AVC gate.** The play records a timestamp before host mutation and,
after converge, requires `ausearch -m AVC,USER_AVC` to return no matches for
the window. Any denial — even a tolerated one — fails the deployment.

## 2. SSH hardening

The baseline installs `/etc/ssh/sshd_config.d/00-ai-gateway-hardening.conf`,
enforcing key-only authentication and disabling every forwarding channel:

| Category | Directives |
|---|---|
| Authentication | `AuthenticationMethods publickey`, `PubkeyAuthentication yes`, `PasswordAuthentication no`, `KbdInteractiveAuthentication no`, `ChallengeResponseAuthentication no`, `PermitEmptyPasswords no`, `HostbasedAuthentication no`, `GSSAPIAuthentication no`, `IgnoreRhosts yes` |
| Privilege | `PermitRootLogin no`, `PermitUserEnvironment no`, `PermitUserRC no` |
| Forwarding | `DisableForwarding yes`, `AllowTcpForwarding no`, `AllowStreamLocalForwarding no`, `AllowAgentForwarding no`, `X11Forwarding no`, `PermitTunnel no`, `GatewayPorts no` |
| Rate limits | `MaxAuthTries 3`, `LoginGraceTime 30`, `MaxSessions 4`, `MaxStartups 10:30:30` |

**Lockout-safe application.** Before touching sshd, the controller proves a
fresh, strictly key-only connection. The candidate file is validated in
isolation (`sshd -t -f`), the complete daemon configuration is validated
(`sshd -t`), sshd is *reloaded* rather than restarted, the effective policy
is evaluated for the real automation user and connection path (`sshd -T -C`)
with all 23 directives asserted, and a second independent key-only login with
non-interactive `sudo -n` is proved before the play proceeds. SSH is
reachable only on the ADM interface from `vpn_client_cidr`, on the exact
managed port.

## 3. Encrypted state storage

With `require_encrypted_state: true` (the default), both Docker's data root
and `/opt/ai-gateway` must resolve through a block device whose ancestry
includes a `crypto_LUKS` volume, verified via `findmnt`/`lsblk` before any
mutation. Only the disposable lab inventory opts out. State backups are
encrypted with `age` (X25519) to an operator-supplied recipient; stateful
image upgrades are refused unless a hash-verified backup receipt younger
than 24 hours exists (`require_preupgrade_backup: true`).

## 4. Package hygiene

The baseline installs from Docker's GPG-checked official repository and
Rocky's signed EPEL: Docker CE + Compose plugin, `containerd.io`,
`container-selinux`, `audit`, `openssl`, `bind-utils`, `acl`, `zstd`, and
supporting Python tooling. Two dependencies are exact-pinned by policy — the
`age-1.3.1-1.el9` package and the `docker==7.2.0` Python SDK — so a
privileged converge can never resolve an unbounded future version. No
automatic-update service is configured; updates are an operator action
executed through the reviewed converge and its backup gates.

## 5. Auditing and scheduled maintenance

- **auditd** backs the zero-AVC deployment gate (§1).
- **`aigw-vault-audit-rotate.timer`** (15-minute cadence) rotates Vault's
  file audit device once it exceeds 100 MiB, using a locked, networkless,
  capability-dropped helper container; Vault is signaled to reopen its audit
  file before compression, and a bounded number of archives is retained.
- **`aigw-docker-log-acl.timer`** (15-second cadence) maintains
  least-privilege POSIX ACLs so the log collector (uid 473) can read only
  the current project's container JSON logs — named-deny entries cover every
  other runtime file. The reconciler runs in an aggressively sandboxed
  systemd unit (read-only socket bind, three DAC capabilities, private
  devices/network, `ProtectSystem=strict`).

## 6. Filesystem permission contracts

Deployment applies deterministic ownership and modes rather than trusting
checkout state, and `verify` proves them (rejecting symlinks and multi-link
files):

- Rendered runtime environment `/opt/ai-gateway/.env`: `root:root 0600`.
- Secrets directory: `root:root 0700`; Redis authentication sources
  `root:65532 0440` (the server receives only a SHA-256 verifier — no
  plaintext in its command line or environment); lab Samba secrets
  `root:root 0400` (bind password `root:65532 0440`).
- Files a non-root (uid 65532) container must read are group-owned 65532
  with `0640`/`0440` and `0750` directories (Keycloak realms, Traefik key);
  public certificates remain world-readable `0644`.
- Reviewed non-secret configuration is `root:root 0755/0644`, with exactly
  one executable exception (the PostgreSQL initializer).
- Root-only state markers (dedicated-host marker, rollback manifest, restore
  marker, bind-digest key) are `0600`, single-link, exact-content files.

## 7. Dedicated-host contract and preflight refusals

The VM is a dedicated Docker host for this stack, recorded by a marker at
`/etc/ai-gateway/dedicated-docker-host-v1` that is promoted only after a
fully verified converge. The read-only preflight refuses, among other
conditions: a controller connection that does not already traverse the
future ADM firewall rule; conflicting Docker daemon flags or environment
indirection in systemd drop-ins; unsafe (symlinked, group-writable,
non-root) path ancestry for the stack, data root, or configuration;
foreign containers or networks on a live daemon; active Swarm mode; a
drifted `daemon.json` on a marked host; and adoption of any pre-existing
Docker or firewall state without its explicit one-time acknowledgement flag.
