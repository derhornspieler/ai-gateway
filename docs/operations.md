# Operations, Recovery, Upgrades, and Troubleshooting

This is the operator guide for the implemented single-VM stack. It distinguishes
commands that verify current state from controls that are still production
blockers.

## Compose command context

Base/customer deployment:

```bash
cd /opt/ai-gateway
docker compose ps
```

Parallels Samba lab:

```bash
cd /opt/ai-gateway
docker compose -f docker-compose.yml -f docker-compose.lab.yml \
  --profile lab-ad ps
```

Use the same file/profile arguments for every lab `up`, `stop`, `logs`, `run`,
and `down` command. Ansible selects them automatically from
`deployment_profile`; direct Compose does not. Deployed operator scripts use
`scripts/aigw-compose.sh`, which reads `DEPLOYMENT_PROFILE` from the rendered
`.env` and selects the base or merged lab project consistently. Use that
wrapper for inspection and service-specific operations so Samba cannot be
omitted from a quiesce/restore.

Start or reconcile the full long-running graph with:

```bash
cd /opt/ai-gateway
sudo scripts/aigw-runtime-up.sh -d --wait --wait-timeout 300
```

The runtime helper derives the service list from the effective deployment
profile, requires exactly one `volume-init` service, excludes it, and invokes
Compose with `--no-deps --no-build`. Do not use a broad raw
`docker compose up`: dependency traversal can rerun the initializer during an
ordinary lifecycle operation. Any manual service-specific `up` must also use
`--no-deps` and must not enable implicit builds.

## State-volume initialization contract

`volume-init` owns only these volume-root metadata contracts:

| Volume | UID:GID | Mode |
|---|---:|---:|
| `pg_data` | `70:70` | `0700` |
| `vault_data` | `1000:1000` | `0700` |
| `vault_audit` | `1000:473` | `2750` |
| `alloy_data` | `473:473` | `0700` |
| `prom_data` | `65532:65532` | `0700` |
| `loki_data` | `65532:65532` | `0700` |
| `tempo_data` | `65532:65532` | `0700` |
| `grafana_data` | `65532:65532` | `0700` |

Ansible hashes the initializer's effective Compose definition and reruns it
only when its container is absent, its previous exit was nonzero, the hash
changed, or one of those eight root metadata contracts drifted. It verifies
the exact owner/group/mode after the run. The networkless, read-only one-shot
drops every capability and adds back only `CHOWN`, `FOWNER`, and `FSETID`;
`FSETID` preserves the required SGID bit on `vault_audit` after its group is
changed. Do not grant broader capabilities, add unreviewed volumes, or perform
recursive ownership changes manually.

## SELinux and bind-mounted configuration

The full playbook **checks**, rather than changes, the host SELinux mode. It
requires the Rocky `targeted` policy to be enabled and `Enforcing` before any
host mutation. A permissive or disabled host is a failed prerequisite; change
that state through the customer's operating-system baseline and reboot/review
process, then rerun Ansible. Once the prerequisite passes, Ansible installs
`container-selinux` and policy tooling, enables Docker's SELinux integration,
and requires Docker to report `name=selinux`.

Every ordinary long-running container must run as `container_t` with its own
MCS process/mount level. Every reviewed bind uses exactly one read-only `z` or
`Z` relabel contract, and the verifier compares the host source to the
container's effective mount level. The only `label=disable` exceptions are
Alloy, which reads Docker's runtime-owned JSON logs through the separately
bounded uid-473 ACL, and node-exporter, which has a read-only host-root mount;
both remain non-root, capability-dropped, unpublished, and network-bounded.
Never apply `z`/`Z` or `restorecon` to `/var/lib/docker`.

Ansible persists `container_ro_file_t` only for the exact reviewed bind-source
paths. It applies those base types only when no Docker container exists; a
repeat `restorecon` after Docker has assigned a private `Z` range would erase
the MCS category while leaving an unchanged container on the old category.
Post-converge verification therefore reads, but does not relabel, every source
and Docker runtime root and fails on any AVC/USER_AVC recorded during the
controlled converge window.

Linux bind mounts retain the inode selected at container creation. Because
Ansible normally replaces a file atomically, a path-stable Compose model can
otherwise leave a running service reading stale bytes. The repository's exact
`bind-source-digest-inputs.json` allow-list maps each consumer to its mounted
sources. A stable 32-byte key stored as the single-link root-only
`.state/bind-digest.key` is accepted by the digest helper only on stdin; the
helper HMACs framed path, type, owner, group, mode, size, and content under
strict object/byte limits and rejects links, special files, nested/duplicate
inputs, and files that race while being read. Only the resulting per-service
digest enters Compose metadata, causing selective recreation when a source
inode or its security-relevant metadata changes.

`.state` is deliberately excluded from state backups. Authenticated restore
removes the local bind-digest key as a new restore epoch before it writes the
restore marker. The next current-source converge creates a fresh key and
therefore recreates every bind consumer, even if restored bytes happen to
match, while leaving `volume-init` under its separate one-shot contract. Never
copy a bind-digest key between hosts or put it in an evidence bundle.

## Normal boot and reboot

1. Unlock and mount the encrypted state filesystems before Docker starts. The
   repository does not provision/unlock LUKS, but both the full and stack-only
   customer playbooks fail unless the configured Docker data root and stack
   directory resolve through a block device with a `crypto_LUKS` ancestor.
   The disposable Parallels profile is the only committed opt-out.
2. Confirm the packet-policy units and Docker are active:

```bash
systemctl is-active firewalld \
  aigw-host-input-rules.service \
  docker-user-rules.service \
  docker-user-rules-watch.service \
  docker.service
systemctl is-active aigw-vault-audit-rotate.timer \
  aigw-docker-log-acl.timer
```

3. Confirm the policy exists before trusting restarted containers:

```bash
nft list table inet aigw_guard
iptables -S DOCKER-USER
```

4. Vault starts sealed. Retrieve an unseal share from approved offline custody
   and pipe it on stdin—never include it in command arguments or shell history:

```bash
cd /opt/ai-gateway
read -rsp 'Vault unseal share: ' AIGW_UNSEAL_SHARE; printf '\n'
printf '%s\n' "$AIGW_UNSEAL_SHARE" | sudo scripts/vault-unseal.sh
unset AIGW_UNSEAL_SHARE
```

The helper uses a one-shot, non-root, read-only DHI Python container attached
only to `net-vault`; it disables proxies, redirects, capabilities, and Docker
logging. The share exists only on stdin. Repeat once per custodian share until
the threshold is reached. The current lab script creates one share with a
threshold of one; production requires a separately implemented custody model.

5. After Vault is unsealed, wait for `key-rotator` and inspect project status
   and recent errors. The patched scheduler must defer startup rotations while
   Vault is sealed without writing failed history, then retry after unseal.
   Do not use a manual container restart to make a sealed-start acceptance test
   pass; that masks the behavior being tested.

```bash
docker compose ps
docker compose logs --since=15m vault key-rotator keycloak litellm envoy-egress
```

6. Verify the Docker-log ACL boundary after every Docker restart:

```bash
sudo getfacl -cp /var/lib/docker /var/lib/docker/containers
sudo systemctl --no-pager --full status aigw-docker-log-acl.timer
```

The configured Docker root grants Alloy uid 473 traversal only (`--x`), not
read or write. The `containers` root grants the reviewed `r-x` access and
default traversal entry needed to discover log paths. Immediate container
directories and `*-json.log*` files then receive only the documented ACLs;
ordinary sibling metadata remains explicitly unreadable. Never repair this by
granting uid 473 broad recursive read access to the Docker data root.

`docker compose ps` proves process state only when no healthcheck exists. Every
long-running base and lab service now has an explicit exec-form health
contract; `volume-init` is the sole intentional exited-zero one-shot. Do not
replace these probes with PID checks or shell assumptions:

| Service(s) | Exact in-container contract |
|---|---|
| `traefik-int`, `traefik-adm` | native `traefik healthcheck` against private `/ping`; returns unready during graceful termination |
| `oauth2-proxy`, `oauth2-proxy-grafana` | loopback `/ready`, including configured session-store readiness |
| `litellm` | loopback `/health/liveliness`; startup is gated on healthy Postgres, Redis, and Envoy |
| `open-webui` | loopback `/health`, including application initialization and basic local-database access |
| `keycloak` | management-port `/health/ready` must contain `"UP"` |
| `dev-portal` | loopback `/healthz` application liveness only; OIDC, LiteLLM, and rotator remain separate functional tests |
| `envoy-egress` | compiled probe requires loopback Envoy admin `/ready` HTTP 200 containing `LIVE`, with redirects and proxies disabled |
| `key-rotator` | loopback `/readyz` requires a writable database check and authenticated, unsealed Vault access |
| `vault` | loopback `/v1/sys/health?standbyok=true`; the current active file-backed node is healthy only when initialized and unsealed |
| `postgres` | `pg_isready` for the local `postgres` database; this proves server acceptance, not password authentication or the cross-database ACL matrix |
| `redis` | authenticated native `AUTH` + `PING`; the static probe reads the root-rendered, container-private password file and never receives the credential through argv or `Config.Env` |
| `alloy` | fixed observability-address `/-/ready` must contain `Alloy is ready.`; component/export failures remain alert signals rather than restart triggers |
| `prometheus` | fixed observability-address `/-/ready` |
| `node-exporter` | loopback `/metrics` scrape must contain `node_exporter_build_info` |
| `loki` | loopback `/ready`, including service-manager/ingester readiness |
| `tempo` | DHI's native `/opt/tempo/tempo --health` readiness client |
| `grafana` | loopback `/api/health` |
| `cribl-mock` | loopback-only OpenTelemetry Collector `health_check` extension on port 13133; signal delivery is tested separately |
| `lab-dns` | loopback CoreDNS `/health` must return exactly `OK`; authoritative answers, NXDOMAIN behavior, and egress denial are separate probes |
| `samba-ad` | database/config presence, Samba control/domain response, exact lockout policy, and hostname-verified LDAPS |

Shellless DHI images that lack a client contain only the repository's static,
non-root `aigw-health-probe`; their original user, entrypoint, command,
read-only rootfs, capability, and no-new-privileges contracts are unchanged.
Green Docker health therefore does not replace the HTTP/OIDC, database-ACL,
DNS, identity, inference, egress, or telemetry tests in the acceptance runbook.

The reduced first-converge wait is allowed only when public Vault status says
that Vault is uninitialized or sealed. If the strict probe fails while Vault
is both initialized and unsealed, Ansible fails closed; it must not classify
that state as bootstrap and allow unhealthy Vault/key-rotator services through
verification. Diagnose the listener, storage, or probe contract instead of
reinitializing Vault or broadening the exception.

Two native probes have important blind spots. Traefik's private `/ping` can be
healthy while a non-root process cannot read its dynamic TLS/router files, and
Grafana's `/api/health` can be healthy while its provisioning tree was not
loaded. The full Ansible verify role therefore performs trusted TLS with exact
SNI and requires `portal.<domain>/healthz` = 200, internal
`api.<domain>/ui` = 403, and ADM `admin.<domain>/` = 403. While destructive
recovery maintenance intentionally denies host-origin traffic to the physical
published addresses, this probe connects directly to each reviewed Traefik
service-plane attachment with CA validation and exact SNI. Listener, DNAT, and
firewall checks separately prove physical publication. It also queries
Grafana's authenticated API from an isolated `net-grafana` probe and requires
the exact Prometheus, Loki, and Tempo datasource graph with each datasource
reporting `OK`. The Grafana probe retries at most 12 times with a five-second
delay for bounded startup convergence; Ansible streams the password on exact
stdin with `stdin_add_newline: false`, keeps the result under `no_log`, and
disables container logging. These functional proofs are release gates, not
replacement Docker healthchecks.

The deployment does not preserve controller-checkout modes. Reviewed
non-secret configuration directories are deterministically `root:root 0755`
and ordinary files `root:root 0644`, with executable mode granted only to the
explicit PostgreSQL initializer and service scripts. Private bind trees are
narrower: Keycloak realm imports are `root:65532 0750/0640`, and Traefik's
certificate directory/private key are `root:65532 0750/0640`. Ansible verifies
these exact contracts so a root-owned restore cannot leave a healthy-looking
but functionally unreadable non-root service.

During the 2026-07-13 rehearsal, inspection found the Redis credential in
Docker `Config.Cmd`. It was treated as exposed and rotated in the encrypted
overlay; no credential value belongs in documentation or evidence. The
corrected server command and environment contain no credential. Redis reads a
SHA-256 verifier from a read-only ACL file, while only the authenticated client
probe receives the separate password file. Both host sources are regular,
single-link `root:65532 0440` files beneath the root-only `secrets/` directory,
and render validation rejects any reintroduction into command or environment
metadata.

`WEBUI_SECRET_KEY` is a required, stable encrypted-overlay value. Before and
after an Open WebUI replacement, compare only a cryptographic digest of the
container's configured value; never print the value itself. A changed digest
is a release blocker because it invalidates sessions and breaks shared signing
state. Normal Ansible converges must preserve the digest.

### 2026-07-13 reboot-validation status

The clean replacement VM passed one full reboot, old-share unseal, 22-service
health recovery, exact container/image/volume/network retention, initializer
non-rerun, and durable semantic comparison. The reboot also proved that the
then-deployed ACL timer did not restore the recreated
`/var/lib/docker/containers` parent ACL and that the then-deployed
key-rotator consumed two sealed-Vault startup jobs as failures.

The scheduler remediation has been deployed and passed its available-Vault
path. The least-privilege ACL, SELinux/MCS, bind-recreation, Vault-readiness,
and pre-build rollback-retention remediations are source-tested but not yet
live. The exact predecessor key-rotator image is now loaded under its immutable
rollback reference. A controlled source converge and Docker restart proving
the new runtime labels and parent ACL repair, followed by an explicit restart
of only the long-running service set proving the sealed-to-unsealed retry path,
remains PENDING; `live-restore` means the daemon restart alone cannot provide
the sealed-Vault evidence. The successful durable-state reboot or image
recovery must not be cited as that proof.

## SSH access and recovery

The baseline is key-only. Password, keyboard-interactive, host-based, GSSAPI,
empty-password, and root logins are denied. `DisableForwarding yes` is backed
by explicit TCP, Unix-domain socket, agent, X11, tunnel, gateway-port, user-RC,
and user-environment denials. Rocky's system crypto policy remains authoritative
for algorithms; do not paste an unmaintained cipher list into the drop-in.

Verify syntax and the effective automation-user policy without relying on the
text of one file:

```bash
sudo /usr/sbin/sshd -t
read -r ssh_client ssh_client_port ssh_local ssh_port \
  <<<"${SSH_CONNECTION:?not an SSH session}"
sudo /usr/sbin/sshd -T -C \
  "user=$USER,host=$ssh_client,addr=$ssh_client,laddr=$ssh_local,lport=$ssh_port" | egrep \
  '^(authenticationmethods|passwordauthentication|kbdinteractiveauthentication|permitrootlogin|disableforwarding|allowstreamlocalforwarding) '
```

Expected values are `publickey`, `no`, `no`, `no`, `yes`, and `no`,
respectively. Supplying the complete active connection tuple matters because a
later `Match Address`/`Match LocalAddress` block can override a safe-looking
global result. Ansible performs the same complete-tuple evaluation, opens a
fresh controller connection with password methods disabled, and proves
`sudo -n true` after every reload.

If a first converge fails its postflight, keep the original session open and
use the VM/provider console. Validate the current file before changing
anything. Only for lockout recovery, move
`/etc/ssh/sshd_config.d/00-ai-gateway-hardening.conf` out of the include
directory, run `/usr/sbin/sshd -t`, reload `sshd`, repair the authorized key or
controller OpenSSH configuration, and immediately rerun the full playbook.
Never restart sshd with an invalid configuration or leave password login as
the recovery state.

## Routine health checks

### Host routing and listeners

```bash
ip -4 route show table main default
ip -4 rule show priority 10101
ip -4 route show table 101
ip -4 rule show priority 10102
ip -4 route show table 102
firewall-cmd --get-active-zones
firewall-cmd --zone=aigw-adm --list-rich-rules
firewall-cmd --zone=aigw-internal --list-rich-rules
firewall-cmd --zone=aigw-egress --get-target
firewall-cmd --zone=aigw-adm --get-target
firewall-cmd --zone=aigw-internal --get-target
ss -H -tlnp
```

For each configured physical interface, also compare its saved, runtime, and
permanent ownership without changing the connection:

```bash
for interface in <EGRESS_INTERFACE> <ADM_INTERFACE> <INTERNAL_INTERFACE>; do
  uuid="$(nmcli --get-values GENERAL.CON-UUID device show "$interface")"
  printf '%s saved=%s runtime=%s\n' \
    "$interface" \
    "$(nmcli --get-values connection.zone connection show uuid "$uuid")" \
    "$(firewall-cmd --get-zone-of-interface "$interface")"
done
firewall-cmd --permanent --zone=aigw-egress --list-interfaces
firewall-cmd --permanent --zone=aigw-adm --list-interfaces
firewall-cmd --permanent --zone=aigw-internal --list-interfaces
```

Expected invariants:

- one main default route on the configured egress NIC;
- ADM/internal `/32` source rules and per-leg defaults in tables 101/102;
- each active physical profile has the expected saved `connection.zone`, the
  runtime zone matches it, and the corresponding permanent project zone lists
  exactly that one interface;
- `aigw-egress` has canonical target `DROP`; `aigw-adm` and `aigw-internal`
  have canonical target `REJECT`;
- no legacy zone-wide open ports;
- only SSH may bind a wildcard host address;
- Traefik binds exactly the ADM/internal addresses on 443;
- in the Parallels lab only, authoritative DNS binds TCP/UDP 53 on those same
  exact ADM/internal addresses and nowhere else;
- nothing binds the egress address.

### Firewall persistence and reload test

The native nftables guard survives a firewalld reload. The watcher must then
reassert `DOCKER-USER`. During a maintenance window:

```bash
firewall-cmd --reload
systemctl is-active aigw-host-input-rules.service \
  docker-user-rules.service docker-user-rules-watch.service
nft list table inet aigw_guard
iptables -S DOCKER-USER
```

After reload, repeat the saved/runtime/permanent comparison above. A physical
leg in `public`, even with key-only SSH and the independent Docker forward
guards intact, is a failed host-input boundary.

Verify the exact fixed Envoy source, DNS `/32`, vendor TCP/443 allow, optional
exact Alloy-to-Cribl rule, reply-direction state rule, cross-plane drops, and
final bridge-origin default drop are still present. Do not settle for checking
only that the chains/tables exist.

If they are absent, fail closed and restore them:

```bash
systemctl restart aigw-host-input-rules.service
systemctl restart docker-user-rules.service
systemctl restart docker-user-rules-watch.service
```

Then rerun the full `ansible/site.yml`. Do not start/recreate application
containers while the policy is absent.

### Container boundary packet test

This non-destructive probe verifies Docker service discovery still works while
container-to-host and direct internet connections fail. Run from the deployed
base directory; the lab overlay is not needed because `dev-portal` is a base
service.

```bash
PORTAL_GATEWAY="$(docker network inspect net-portal \
  --format '{{ (index .IPAM.Config 0).Gateway }}')"
docker compose exec -T -e PORTAL_GATEWAY="$PORTAL_GATEWAY" dev-portal \
  python3 - <<'PY'
import os
import socket

socket.getaddrinfo("keycloak", 8080)
for host, port in ((os.environ["PORTAL_GATEWAY"], 22), ("1.1.1.1", 443)):
    try:
        connection = socket.create_connection((host, port), timeout=2)
    except OSError:
        print(f"blocked as expected: {host}:{port}")
    else:
        connection.close()
        raise SystemExit(f"UNEXPECTED CONNECTIVITY: {host}:{port}")
print("internal service discovery succeeded")
PY
```

The Ansible verify role also sends an informational vendor canary through
Envoy. A vendor HTTP 401 proves DNS, routing, Envoy path matching, and upstream
TLS worked without requiring a valid inference key. A connection error means
inspect resolver routing, firewall counters, narrowed CA bundles, and the
egress physical leg.

For packet-level evidence during an inference request, capture on each real
interface:

```bash
tcpdump -ni <EGRESS_INTERFACE> '(udp port 53 or tcp port 53 or tcp port 443)'
tcpdump -ni <ADM_INTERFACE> 'tcp port 443'
tcpdump -ni <INTERNAL_INTERFACE> 'tcp port 443'
```

Expect vendor/DNS traffic only on egress, administrator traffic only on ADM,
and user HTTPS/approved Cribl only on internal. Capture files can contain
sensitive addressing and timing metadata; protect and delete them under the
customer evidence policy.

### Application checks

- `https://auth.<domain>/realms/aigw/.well-known/openid-configuration` works
  from an internal client; the Keycloak admin console is denied there.
- `https://api.<domain>/health/liveliness` and `/health/readiness` are allowed;
  a management path such as `/key/list` is denied at Traefik.
- An `aigw-users` user can reach chat; a user without an allowed role cannot.
- An `aigw-developers` user can list/mint/revoke only keys owned by that OIDC
  subject.
- The LiteLLM Admin UI and Grafana first require `aigw-admins`; Grafana then
  requires its local login.
- The portal admin page shows rotation/identity status but does not display
  internal tokens or private keys.

Use [the acceptance runbook](test-runbook.md) for the complete expected
results.

## Vault operations

`scripts/vault-bootstrap.sh` is explicitly a lab/test initializer. It:

- initializes file-backed Vault with 1-of-1 unseal;
- enables a file audit device;
- creates a test root/intermediate and a 90-day wildcard edge certificate;
- installs the exact rotator/identity Vault policy and a 32-day periodic token;
- optionally seeds static provider keys; and
- writes only the rotator token into `.env` before recreating consumers.

Vault CLI defaults must not decide the transport for the isolated plaintext
listener. The public initialization/seal-state probe invokes
`vault status -address=http://127.0.0.1:8200 -format=json` explicitly; this
avoids a false HTTPS attempt while retaining the expected status exit codes.

It is not production-safe merely because the listener is isolated. Production
needs a customer-rooted intermediate, TLS on the Vault listener, multiple
custodians or an approved auto-unseal design, token-renewal monitoring,
notification routing for disk alerts, and an executable backup/restore drill.

Vault audit writes to `vault_audit`. A systemd timer checks every 15 minutes;
`scripts/rotate-vault-audit.sh` uses a locked, networkless, read-only helper,
rotates at 100 MiB by default, signals Vault to reopen the file, compresses it,
and keeps 14 rotations. The Ansible verify role requires the timer to be
active. These bounds are configurable through the script environment but the
installed unit currently uses the defaults. Monitor timer failures and ensure
customer evidence retention does not require a longer independent archive.
Rotation uses the same exact digest-pinned DHI BusyBox image as `volume-init`,
under Vault's audit-volume UID/GID, rather than assuming an application image
contains a shell. It deliberately defers when Vault is unavailable, so monitor
the actual audit volume size as well as timer state.

Never pass root tokens, unseal shares, provider keys, Samba passwords, or
private keys as command-line values. Never copy Vault private-key records into
the portal or ticketing system.

## State inventory and backup requirements

| State | Location | Recovery importance |
|---|---|---|
| LiteLLM, Keycloak, rotator DBs | `pg_data` | critical; logical consistency required |
| Open WebUI data | `openwebui_data` | user/chat/application state |
| Vault file backend | `vault_data` | critical encrypted secret state |
| Vault audit | `vault_audit` | security evidence; separate retention policy |
| Alloy positions/WAL | `alloy_data` | prevents log duplicates/gaps; telemetry only |
| Prometheus | `prom_data` | local metrics history |
| Loki | `loki_data` | local operational/audit history |
| Tempo | `tempo_data` | sensitive full-prompt trace history |
| Grafana | `grafana_data` | local users/preferences; data sources are provisioned |
| Redis | tmpfs | disposable cache; no restore expected |
| Samba lab | `samba_ad_config`, `samba_ad_state`, `samba_ad_public` | lab identity/password/LDAPS state; restore together |
| rendered secrets/certs | `/opt/ai-gateway/.env`, `certs/`, `secrets/` | highly sensitive; encrypt and control separately |

### Create an encrypted backup

`scripts/state-backup.sh` requires root plus the pinned `age`/`age-inspect`
tools. It refuses an output on the stack's backing filesystem, an existing or
symlink output, an unverifiable/in-progress credential rotation, and any
co-located `secrets/vault-init.json`. It stops writers, takes PostgreSQL
globals and custom-format logical dumps, stops Postgres, archives every present
allow-listed named volume with the exact digest-pinned DHI BusyBox `tar` and
numeric ownership, and archives the reviewed
rendered stack/config/secrets. It then age-encrypts and validates the artifact,
atomically installs it, writes `.state/last-backup.json`, and restores exactly
the concrete containers that were running before quiesce. Restart uses those
captured container IDs directly; it must not ask Compose to traverse
dependencies, because that would rerun the successful exited `volume-init`
one-shot.

`openwebui_data/cache` is the one intentional volume exclusion. It contains
regenerable downloaded embedding-model objects whose upstream layout uses
symlinks; the hostile-archive restore gate rejects every link before mutation.
The durable Open WebUI database and application data remain in the backup, and
basic authenticated chat remains available after restore. Open WebUI has no
approved external egress in this deployment, so embedding/RAG assets are not
automatically downloaded again: restore operations must use a reviewed offline
model reseed, or a future explicitly approved import/egress path, before those
features are returned to service.

Generate and custody the age identity separately. Retain only its public
X25519 recipient on the gateway. Write to already-mounted independent,
encrypted, or off-host storage:

```bash
cd /opt/ai-gateway
sudo ./scripts/state-backup.sh \
  --recipient age1... \
  --output /independent-backup/aigw-$(date -u +%Y%m%dT%H%M%SZ).tar.gz.age
```

The script prints the encrypted artifact's SHA-256. Store that hash and the
age identity through an authenticated path independent of the backup and the
VM. The exact lab-only override
`AIGW_ALLOW_SAME_DEVICE_BACKUP=I_UNDERSTAND_THIS_IS_NOT_DR` permits mechanical
testing on one disposable disk; it is not a production backup.

Vault restarts sealed after the quiesced backup. Perform the normal manual
unseal and a full Compose wait before declaring the gateway ready. Use the
merged Compose files/profile in the lab.

### Restore an authenticated backup

Restore is destructive. Build an isolated target with the firewall/network
boundary first, copy in the encrypted artifact and mode-`0600` age identity,
and obtain the expected SHA-256 from the independent receipt. Then run:

```bash
cd /opt/ai-gateway
sudo ./scripts/state-restore.sh \
  --input /recovery/aigw-STATE.tar.gz.age \
  --identity /secure-recovery/age-identity.txt \
  --sha256 <authenticated-64-character-sha256> \
  --confirm RESTORE_AI_GATEWAY_STATE
```

The restore authenticates the encrypted artifact checksum before decryption,
then validates the exact outer inventory, manifest/checksum bijection, every
nested archive path/type, and all profile volume names before stopping a
service. Sparse maps are rejected even when represented as regular tar
members. The hostile-input ceilings are 100,000 stack-configuration members,
2,000,000 members and 1 TiB of declared data per volume, 2 TiB declared across
all volumes, and a mandatory 256 MiB free reserve. The declared total must fit
the live Docker data filesystem after all restore staging; this conservative
check does not count bytes that a later wipe might free. Volume wiping runs
networkless/read-only with only `DAC_OVERRIDE` and `FOWNER`; numeric-owner
extraction adds only `CHOWN`. Both helpers drop every other capability and use
`no-new-privileges`. The script then replaces only manifest-listed project
volumes and installs the safely staged configuration while the project remains
offline. On success it requires zero running project containers, writes
`.state/restore-required-unseal` as an exact `root:root 0600` regular file
containing only the authenticated backup SHA-256, removes any target-local
`.state/bind-digest.key` as a new bind epoch, and exits zero without starting
the captured graph. The next converge must recreate the key and every bind
consumer; the key is deployment state, not backed-up application state.
Complete these steps in order:

1. keep both ingress legs in maintenance and run the full `ansible/site.yml`
   converge from the designated current source while the marker remains;
2. confirm that converge retained the authenticated marker and recognized an
   initialized, sealed restored Vault rather than replacement state;
3. unseal Vault using the separately held old shares;
4. run `scripts/aigw-runtime-up.sh -d --wait --wait-timeout 300`;
5. verify database ACLs, identity fingerprints, Samba LDAPS where applicable,
   provider canaries, and telemetry, then complete the acceptance runbook; and
6. remove `.state/restore-required-unseal` only after all proof succeeds.

While the marker exists, Ansible requires Vault's restored public state to be
initialized and prohibits replacement initialization. Do not run
`scripts/vault-bootstrap.sh`; that lab initializer is valid only for an
uninitialized fresh deployment with no restore marker.

Do not describe an untested artifact as recoverable. The scripts are tooling,
not evidence; production approval requires a successful isolated restore. The
Vault init response/unseal material remains deliberately outside this backup.
The repository audit completed a disposable encrypted backup/restore smoke
test, including PostgreSQL and Open WebUI state rollback plus the required
post-restore unseal marker. That proves mechanics, not the customer's storage,
key custody, capacity, or recovery-time objective.

The first destructive replacement-VM restore attempt exited 1 and is not G4 or
G5 evidence. That earlier workflow started the captured graph before current
Ansible reconciled bind ownership; Keycloak could not read its restored,
root-owned realm bind tree. Ingress remained in maintenance, the restore
marker was retained, and no later gate was accepted. The corrected offline
restore must be repeated from the immutable authenticated artifact; an
operator may not continue, patch around, or bootstrap over that failed target.

The corrected repeat subsequently passed: restore exited 0 with zero running
project containers and the exact marker; the designated current-source sealed
converge exited 0; the separately held old share unsealed Vault; and a bounded
runtime-only retry completed with 22/22 services healthy and zero restarts.
The authoritative receipts, G6 pass with explicit external NOT EXECUTED lanes,
and still-pending G7 disposition are listed in the
[lab rebuild and restore rehearsal](lab-dr-rehearsal.md).

The source path of the final 2026-07-13 lab artifact was
`/var/backups/ai-gateway-lab/aigw-20260713T035736Z-post-audit-fixed.tar.gz.age`.
Before the predecessor VM was deliberately deleted, its mode-`0600` recovery
copy was verified at
`/Users/jamesrudisill/.aigw-lab-dr/20260713-pre-rebuild/aigw-20260713T035736Z-post-audit-fixed.tar.gz.age`.
It has SHA-256
`ebf2bf27d7bd0dd524d1d6305ce13a1e14db7187c27833ae7434ece718bf1d94`.
Its receipt/hash/age validation, independent decryption/listing, complete
non-destructive hostile-archive parser, and exact-container restart passed;
`volume-init` did not rerun. The rejected intermediate was removed. This is G0
VM-loss recovery-input evidence on the same physical Mac. That artifact record
alone does not prove the later completed restore, Mac-host loss, site loss, or
any G4-through-G7 result; the gate register and protected execution receipts
provide the later gate evidence.

`docker compose down` preserves named volumes. `docker compose down -v`
destroys all project databases, Vault, identity, and telemetry state. In the
lab, use the merged files/profile or Samba volumes can be missed.

## Recovery order

For the destructive vanilla-VM Parallels exercise, follow the dedicated
[lab rebuild and restore rehearsal](lab-dr-rehearsal.md). G4 and G5 have passed
on the replacement VM; configured G6 lanes have also passed, with real
Anthropic/WIF inference explicitly NOT EXECUTED. G7 remains controlled by that
register. One replacement-host reboot also passed durable-state comparison and
healthy recovery after one stdin-only lab unseal, but exposed the sealed-job
and Docker-parent-ACL defects described above. Do not clear the marker based on
that reboot; the remediated Docker-daemon lane, separate long-running-service
sealed-Vault lane, and final unchanged converge remain open.

1. Recover the host/VM and unlock both encrypted state filesystems.
2. Restore the reviewed source and encrypted variable overlay, then run the
   full Ansible converge so PBR, firewalld, nftables, `DOCKER-USER`, bridge
   names/subnets, pinned helper images, and listeners exist before state is
   admitted.
3. Run `state-restore.sh` with the authenticated artifact/hash and separately
   held age identity. Require exit 0, zero running project containers, and the
   exact root-only authenticated marker. Do not open user/ADM access yet.
4. With ingress still in maintenance and the marker present, rerun the full
   `ansible/site.yml` from the designated, content-addressed current source.
   This replaces captured configuration, repairs exact bind ownership/modes,
   and starts only the current graph; restored Vault remains sealed.
5. Stream the separately held old share to `scripts/vault-unseal.sh`, then run
   `scripts/aigw-runtime-up.sh -d --wait --wait-timeout 300` for the complete
   merged project. Never run `vault-bootstrap.sh` on this path.
6. Recover the temporary
   Keycloak service client only if the Vault/controller proof fails; see
   [identity operations](identity-operations.md).
7. Verify packet policy, identity fingerprints, database access, prompt/log
   storage, and a vendor canary.
8. Run the entire acceptance suite and the final G7 change/restart/unchanged-
   converge sequence. Clear the restore marker only after G7 passes and before
   reopening user or ADM access.

If preflight reports a Docker subnet/live-route collision, choose new inventory
subnets and update every fixed-IP/trust/firewall assertion as one reviewed
change. Never force-create a colliding bridge.

## Pre-build rollback retention

Current source places `scripts/preserve-compose-rollbacks.py` after the shared
build planner and before any planned custom-image build. For every planned
service with an existing container, it must prove exactly one Compose instance
is running, healthy, and at restart count zero; that the desired local tag and
the container's immutable image ID agree; and that the local Docker socket is
the one being inspected. It then creates an immutable rollback reference from
the project/service namespace plus the full source image digest, rechecks the
container and both references for races, and atomically writes schema 2 of
`.state/compose-build-rollbacks.json` as a single-link `root:root 0600` file.
Previously recorded services and their rollback references are revalidated; a
new generation never moves a reference named by the committed manifest. A
genuinely container-free first build is explicitly recorded as having no
predecessor, and that temporary proof is retired after the successful build-
input marker is durable.

The shared build planner hashes a domain-separated version-2 stream. Every
build definition, path, type, mode, and file/symlink payload carries explicit
length framing, and regular files are checked for identity/metadata races
while streaming. The old unframed digest is accepted only as a one-converge
comparison for a pre-existing manifest; current source always persists the
framed digest. This prevents a file payload from absorbing the next inventory
record and suppressing a required rebuild without breaking SHA-256.

Any malformed manifest, multiple container, missing health contract,
unhealthy/restarted source, mismatched desired image, moved rollback tag,
failed Docker enumeration, or inspect/tag race stops the build. Do not delete
the manifest, move its tags, or manually bless a replacement image to bypass a
failure. The manifest is non-secret evidence, not a substitute for the
encrypted state backup or a schema-compatible rollback test.

This control has passed focused source tests but has not yet completed its live
deployment gate. The predecessor key-rotator OCI image with digest prefix
`e97456` was garbage-collected before this control existed; it has now been
recovered from the neutral OCI artifact and loaded under the immutable
schema-2 rollback reference whose source digest matches exactly. The protected
load receipt and final pre-deployment baseline are immutable and secret-scan
clean. G7 remains on hold until the final controlled source converge,
Docker-daemon restart, separate long-running-service sealed-Vault restart,
runtime proof, and unchanged converge pass.

## Upgrade procedure

Images are tag-and-digest pinned; an upgrade changes both deliberately. Do not
use `latest` or a blind `docker compose pull`.

1. Read upstream security/migration notes for every stateful component.
2. Scan and record the exact candidate digests and custom dependency locks.
   For dev-portal, regenerate and review the complete transitive
   `requirements.lock`; production builds use `--require-hashes`, and
   validation requires every direct exact pin to appear in that hashed lock.
   Never substitute the direct-only `requirements.txt` in the image build.
3. Produce and restore-test the encrypted pre-upgrade backup. Generic/customer
   Ansible defaults `require_preupgrade_backup: true`: when a stateful direct
   image reference changes, or the shared build planner detects changed source,
   build definition, missing tag, or local image ID for an existing stateful
   custom image, `scripts/pre-upgrade-check.sh` requires an available artifact
   whose receipt/hash still match and is no more than 24 hours old. This includes
   Alloy's durable positions and the lab Samba state as well as application data.
   The disposable Parallels profile disables this gate only so candidate
   upgrades can be tested; do not copy that exception to customer inventory.
4. Review the shared build plan. For every planned custom build with an
   existing service, require successful pre-build rollback retention and the
   private manifest described above before the build begins. Retain both the
   exact rollback tag and backup receipt through acceptance. Do not treat image
   retention as database-schema rollback.
5. Validate without starting containers:

```bash
scripts/validate-compose.sh
ansible-playbook -i ansible/inventory/lab.yml ansible/site.yml \
  --syntax-check --ask-vault-pass
```

6. Rebuild and run unit/config/runtime tests, then converge the Parallels lab.
7. Test schema migrations and rollback for Postgres, Keycloak, LiteLLM,
   Open WebUI, Vault, Loki, and Tempo. A binary rollback is not sufficient when
   an on-disk schema has migrated.
8. Use `deploy-stack-only.yml` only after its live firewall/network preflight
   passes. Otherwise run the full converge.
9. Repeat packet, identity, provider, and telemetry acceptance checks.

LiteLLM worker or replica changes are architecture changes, not ordinary
resource edits. Follow [LiteLLM capacity and scaling](litellm-scaling.md),
including aggregate PostgreSQL connection accounting, shared Redis behavior,
single-run migrations, readiness-based routing, drain time for long streams,
and benchmark/failure acceptance. Do not use an ad hoc Compose `--scale`
command as a production rollout.

Ansible now reconciles PostgreSQL roles, passwords, databases, and `CONNECT`
ACLs on every deployment by rerunning the idempotent initialization script over
the trusted local Unix socket before Compose reconciles consumers. The script
tests the desired password through the normal SCRAM TCP path and rewrites its
salted verifier only on mismatch. No password is placed in task output or
command arguments. Each service role is reconciled to `LOGIN`, non-superuser,
`NOCREATEDB`, `NOCREATEROLE`, `NOINHERIT`, `NOREPLICATION`, `NOBYPASSRLS`,
connection limit `-1`, no role-local settings, and no finite expiry. Each
database has its matching service-role owner, and memberships in either
direction involving any service role are removed. `PUBLIC` has no `CONNECT`
on any of the four databases, and the service-role matrix is exact:

| Login role | `litellm` DB | `keycloak` DB | `rotator` DB | `postgres` DB |
|---|---:|---:|---:|---:|
| `litellm` | allow | deny | deny | deny |
| `keycloak` | deny | allow | deny | deny |
| `rotator` | deny | deny | allow | deny |

The `postgres` superuser retains maintenance access. The play checks all 12
service-role/database decisions, the three owners, three role contracts, zero
memberships, and maintenance access on every converge. An unchanged run emits
`AIGW_POSTGRES_OK` internally and performs no password/ACL catalog rewrite;
the Ansible task reports changed only for `AIGW_POSTGRES_CHANGED`. Treat a
password change as complete only after the play finishes and all three
consumers are healthy; rehearse rollback with the encrypted prior overlay
before production use.

The Open WebUI integration uses one shared LiteLLM workload key, not the proxy
master and not a human portal key. Each converge resolves both its exact alias
and the SHA-256 of the encrypted-overlay candidate; only a unique 0/0 create or
1/1 same-token update is accepted. The key is owned by `svc-open-webui`, tagged
as service `open-webui` / project `open-webui`, limited to the three approved
model aliases and the model-list/chat-completions routes, and denied all
management endpoints. Consequently its trace attribution identifies the
shared Open WebUI service, not the individual browser user. Direct API keys
issued through the portal retain per-user attribution; trusted end-user
propagation through Open WebUI requires a separate reviewed design.

## Troubleshooting

### Full preflight refuses the topology

Use `ip -br -4 address`, `ip -4 route show table main`, and `ip -4 route get`
to compare live facts with the selected inventory. For table-name collisions,
inspect `/etc/iproute2/rt_tables` when it exists; on a vanilla Rocky 9 host,
inspect `/usr/share/iproute2/rt_tables` instead. The first mutating routing
role seeds a missing `/etc` override from that vendor file. Correct the
inventory or customer-owned network configuration out of band; the playbook
intentionally will not repair or guess NIC addressing.

### Stack-only deployment refuses to run

Its live firewall/network ABI is stale or missing. Run full `site.yml`. Do not
skip assertions or manually attach services to broader networks.

### OIDC callback or issuer errors

Check split DNS, the browser-visible `https://auth.<domain>` issuer, the exact
redirect URI, internal CA trust, and Keycloak's proxy-trusted addresses. Realm
imports do not update an existing database; reconcile changed callbacks and
secrets in Keycloak explicitly.

### Vendor calls fail

Check Envoy startup-gate output, narrowed CA expiry/issuer changes, exact SAN,
resolver reachability, fixed `172.28.0.2` attachment, firewall counters, and
the physical egress route. Never “fix” an outage by using the system CA bundle,
adding a default route to another service, or permitting the whole bridge.

### Memory or disk pressure

Full prompt traces can consume storage quickly. Redis is bounded at 384 MiB
with `allkeys-lru` below its 512 MiB container limit; Loki WAL replay is capped
at 512 MiB and flushes on clean shutdown; Vault audit rotates as described
above. Node-exporter feeds 15%, 5%, and predicted-24-hour filesystem rules, but
no Alertmanager/notification route is deployed. Monitor those rules directly
and see [observability operations](observability-operations.md) for capacity
math.

### Firewall reload caused an outage

Confirm the watcher is active, inspect both nftables and `DOCKER-USER`, restart
the three policy units, then run the full converge. The independent native
forward hook should preserve denial during the reload; an outage can still
occur if approved rules were not reasserted.

## Residual security boundary

The packet policy constrains managed project bridges, not arbitrary root-owned
host processes. Docker image pulls and other host-namespace traffic are outside
`DOCKER-USER`. Envoy necessarily retains a DNS channel to one approved
resolver. Unmanaged bridges whose names are outside the project inventory are
outside the native container-input scope. Root on the VM, Docker daemon access,
Compose file/entrypoint changes, and the encrypted secret overlay remain
high-trust administrative boundaries.
