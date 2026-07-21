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

**Controlled transitions only.** A reboot may be needed when SELinux is
disabled, the wrong policy is loaded, or the kernel uses `selinux=0`. The play
refuses that reboot unless the operator sets
`aigw_allow_selinux_reboot: true`. It also refuses to reboot while Docker is
enabled or active. This prevents containers from starting before their host
guards. Switching a *live* Docker host from permissive to enforcing
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

The hardened production profile keeps password authentication and every SSH
forwarding mode disabled. Local preprod does not manage the workstation's SSH
server.

**Lockout-safe application.** Before changing sshd, the controller proves a
fresh key-only connection. It checks the candidate file with `sshd -t -f` and
the full configuration with `sshd -t`. It reloads sshd instead of restarting
it. Next, `sshd -T -C` checks all 23 rules for the real user and connection
path. A second key-only login must then pass with non-interactive `sudo -n`
before the play continues. SSH is
reachable only on the ADM interface from `vpn_client_cidr`, on the exact
managed port.

## 2.5 Time synchronization

The `time_sync` role requires a synchronized clock before SELinux or Docker can
install signed packages or build images. `aigw_require_time_sync` is on by
default. `aigw_time_sync_max_offset_seconds` defaults to five seconds. OIDC,
TLS, and short-lived JWTs all need trustworthy time.

## 3. Encrypted state storage

LUKS (Linux Unified Key Setup — full-disk encryption) is a **build-time,
disk-provisioning** concern that the converge deliberately does not manage: it
never creates the encrypted volume, never unlocks it, and never holds the
passphrase. The operator provisions the encrypted disk when the VM is built and
**custodies the passphrase themselves** (offline, or in their own vault); the
gateway never sees it.

With `require_encrypted_state: true` (the default), a read-only preflight
resolves both Docker's data root and `/opt/ai-gateway` to their backing block
device and checks (via `findmnt`/`lsblk`) that the ancestry includes a
`crypto_LUKS` volume. When a path is not on LUKS, the check **warns and
continues** rather than failing closed: it emits
`AIGW_ENCRYPTED_STATE_WARNING: …` and then a plain-language `WARNING: sensitive
AI Gateway state is NOT on LUKS-encrypted storage …` line, and the converge
proceeds. Both the host-prep phase (`os-prep.yml`) and the stack phase
(`deploy-stack-only.yml`) run this same warn-only check. Local preprod is a
separate workstation workflow and does not run Rocky host checks. State backups
are encrypted with `age` (X25519) to an operator-supplied recipient; stateful image
upgrades are refused unless a hash-verified backup receipt younger than 24 hours
exists (`require_preupgrade_backup: true`).

## 4. Package hygiene

The baseline uses Docker's GPG-checked repository and Rocky's signed EPEL. It
installs Docker CE, the Compose plugin, `containerd.io`, `container-selinux`,
`audit`, `openssl`, `bind-utils`, `acl`, `zstd`, and supporting Python tools.

The live Docker packages use the exact versions proven by the test suite:

- `docker-ce` and `docker-ce-cli` `29.6.1-1.el9`;
- `containerd.io` `2.2.6-1.el9`; and
- `docker-compose-plugin` `5.3.1-1.el9`.

The values live in `ansible/group_vars/all.yml` and may be overridden in
`host_vars`. An unpinned `docker-ce-stable` install twice
adopted a Compose-v5 release that broke a live converge, so the pin is a
stability control. `state: present` makes the converge stop if the mirror no
longer has the exact version. It never installs the newest version silently.
`allow_downgrade: false` also stops a host that has already moved to a newer
version; Ansible will not downgrade Docker under a running stack.

Two further dependencies are exact-pinned
the same way — the `age-1.3.1-1.el9` package and the `docker==7.2.0` Python
SDK — so a privileged converge can never resolve an unbounded future version.
There is no `dnf versionlock`. The converge checks every pin on each run and is
the approved change path for the dedicated host. The repository also pins the
`age` package, Docker SDK, and every container image. No automatic-update
service is configured; a version bump is
an operator action executed through the reviewed converge and its backup
gates — see the deliberate-upgrade path in `docs/operations.md`.

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
  plaintext in its command line or environment); external-LDAPS bind password
  `root:65532 0440`.
- Files a non-root (uid 65532) container must read are group-owned 65532
  with `0640`/`0440` and `0750` directories (Keycloak realms, Traefik key);
  public certificates remain world-readable `0644`.
- Reviewed non-secret configuration is `root:root 0755/0644`, with exactly
  one executable exception (the PostgreSQL initializer).
- Root-only state markers (dedicated-host marker, rollback manifest, restore
  marker, bind-digest key) are `0600`, single-link, exact-content files.

## 7. Dedicated-host contract and preflight refusals

The VM is a dedicated Docker host for this stack. A verified host carries
`/etc/ai-gateway/dedicated-docker-host-v1`. During host preparation,
`os_baseline` first writes the matching `.pending` marker. This tells
`deploy-stack-only.yml` that host preparation passed. `host_finalize` replaces
it with the completed marker only after `verify` passes.

The read-only preflight refuses:

- a controller connection outside the future ADM firewall rule;
- conflicting Docker daemon flags or indirect systemd environment files;
- symlinked, group-writable, or non-root path ancestry;
- foreign containers or networks on a live daemon;
- active Swarm mode;
- a changed `daemon.json` on a marked host;
- a non-standard or non-root Docker CLI;
- extra daemon sockets, unreviewed systemd overrides, Docker plugins, rootless
  Docker, or a second container runtime; and
- adoption of existing Docker, firewall, or AIGW sshd state without the exact
  acknowledgement flag.

Those flags are `aigw_adopt_dedicated_docker_host`,
`aigw_adopt_firewalld_state`, and `aigw_adopt_ssh_state`. The firewall flag can
only resume a validated pending converge. A `firewall_preflight` role audits
existing firewall state, and `host_finalize` promotes the dedicated-host
marker only after a fully verified converge.
