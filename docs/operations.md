# Operations, Recovery, Upgrades, and Troubleshooting

This is the operator guide for the implemented single-VM stack. It is a customer
prototype, not a turnkey production appliance: one Docker Compose project on one
Rocky Linux 9 VM, not highly available, with Vault running in its lab/test
bootstrap today. Recovery acceptance does not confer high availability. The guide
distinguishes commands that verify current state from controls that remain
production blockers, and it cross-links the architecture in
[solution-map.md](solution-map.md), the install flow in
[deploy-guide.md](deploy-guide.md), the scaling and HA
posture in [high-availability.md](high-availability.md), and the living status in
[project-status.md](project-status.md).

The base project defines 25 services: one `volume-init` one-shot plus 24
long-running services, two of which (`vault-ui-proxy`, `oauth2-proxy-vault`)
run only when the optional Vault UI profile is enabled. The lab overlay adds `samba-ad` and `lab-dns`, for 25
long-running services. Wherever a service count matters below it refers to that
current topology; historical rehearsal receipts that recorded a smaller set are
held in [lab-dr-rehearsal.md](archive/lab-dr-rehearsal.md).

## Contents

**Boot, runtime, and health**

- [Compose command context](#compose-command-context)
- [State-volume initialization contract](#state-volume-initialization-contract)
- [SELinux and bind-mounted configuration](#selinux-and-bind-mounted-configuration)
- [Normal boot and reboot](#normal-boot-and-reboot)
  - [Health contracts](#health-contracts)
  - [Reboot and remediation status](#reboot-and-remediation-status)
- [Routine health checks](#routine-health-checks)
  - [Host routing and listeners](#host-routing-and-listeners)
  - [Firewall persistence and reload test](#firewall-persistence-and-reload-test)
  - [Container boundary packet test](#container-boundary-packet-test)
  - [Application checks](#application-checks)

**SSH**

- [SSH access and recovery](#ssh-access-and-recovery)

**PKI ceremonies**

- [Production edge TLS](#production-edge-tls)
  - [Where TLS actually is (and is not)](#where-tls-actually-is-and-is-not)
  - [Choosing a mode](#choosing-a-mode)
  - [Mode 2 ceremony (`vault-intermediate`)](#mode-2-ceremony-vault-intermediate)
  - [Mode 3 ceremony (`customer-intermediate`)](#mode-3-ceremony-customer-intermediate)
  - [Mode 1 (`customer-supplied`)](#mode-1-customer-supplied)
  - [What is validated before anything goes live](#what-is-validated-before-anything-goes-live)

**Vault**

- [Vault operations](#vault-operations)

**Backup and restore**

- [State inventory and backup](#state-inventory-and-backup)
  - [Create an encrypted backup](#create-an-encrypted-backup)
  - [Restore an authenticated backup](#restore-an-authenticated-backup)
- [Recovery order](#recovery-order)

**Upgrade**

- [Pre-build rollback retention](#pre-build-rollback-retention)
- [Upgrade procedure](#upgrade-procedure)
  - [Docker Engine and Compose plugin version bumps](#docker-engine-and-compose-plugin-version-bumps)
  - [PostgreSQL role and ACL reconciliation](#postgresql-role-and-acl-reconciliation)
  - [Open WebUI service key](#open-webui-service-key)

**Troubleshooting and reference**

- [Troubleshooting](#troubleshooting)
- [Residual security boundary](#residual-security-boundary)
- [Legacy lab reset](#legacy-lab-reset)

## Compose command context

Deployed operator scripts never call Compose directly. `scripts/aigw-compose.sh`
is the one authoritative, profile-aware selector: it reads `DEPLOYMENT_PROFILE`
from the rendered `.env`, always passes the base `docker-compose.yml`, and adds
`-f docker-compose.lab.yml --profile lab-ad` only when the profile is
`rocky9-lab`. Using that wrapper for every inspection, quiesce, and
restore guarantees the lab's Samba and DNS services cannot be silently omitted.
For a plain base deployment it resolves to an ordinary `docker compose` call:

```bash
cd /opt/ai-gateway
scripts/aigw-compose.sh ps
```

Start or reconcile the full long-running graph with the runtime helper, which
wraps the selector:

```bash
cd /opt/ai-gateway
sudo scripts/aigw-runtime-up.sh -d --wait --wait-timeout 300
```

`aigw-runtime-up.sh` derives the effective service list from the selector,
requires exactly one `volume-init` service, excludes it, and invokes
`up --no-deps --no-build` against only the runtime services. Do not substitute a
broad raw `docker compose up`: dependency traversal can rerun the versioned
`volume-init` one-shot during an ordinary lifecycle operation. Any manual
service-specific `up` must also pass `--no-deps` and must not enable implicit
builds. The helper accepts only `-d`/`--detach`, `--wait`, and a positive
`--wait-timeout`; anything else is rejected.

## State-volume initialization contract

`volume-init` (pinned `dhi.io/busybox:1.38.0-alpine`) owns only the volume-root
metadata contracts below and nothing else.

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

Ansible hashes the initializer's effective Compose definition and reruns it only
when its container is absent, its previous exit was nonzero, the hash changed, or
one of those eight root metadata contracts drifted; it then verifies the exact
owner, group, and mode after the run. The networkless, read-only one-shot drops
every capability and adds back only `CHOWN`, `FOWNER`, and `FSETID`, where
`FSETID` preserves the required SGID bit on `vault_audit` after its group is
changed. Do not grant broader capabilities, add unreviewed volumes, or perform
recursive ownership changes by hand.

## SELinux and bind-mounted configuration

The full playbook checks, rather than changes, the host SELinux mode. It requires
the Rocky `targeted` policy to be enabled and `Enforcing` before any host
mutation, so a permissive or disabled host is a failed prerequisite: change that
state through the customer's operating-system baseline and reboot, then rerun
Ansible. Once the prerequisite passes, Ansible installs `container-selinux` and
policy tooling, enables Docker's SELinux integration, and requires Docker to
report `name=selinux`. Every ordinary long-running container then runs as
`container_t` with its own MCS process and mount level, and every reviewed bind
uses exactly one read-only `z` or `Z` relabel contract that the verifier compares
against the container's effective mount level.

The only `label=disable` exceptions are Alloy, which reads Docker's
runtime-owned JSON logs through a separately bounded uid-473 ACL, and
node-exporter, which has a read-only host-root mount; both remain non-root,
capability-dropped, unpublished, and network-bounded. Never apply `z`/`Z` or
`restorecon` to `/var/lib/docker`. Ansible persists `container_ro_file_t` only
for the exact reviewed bind-source paths and applies those base types only when
no Docker container exists, because a repeat `restorecon` after Docker has
assigned a private `Z` range would erase the MCS category while leaving an
unchanged container on the old one. Post-converge verification therefore reads,
but does not relabel, every source and Docker runtime root, and it fails on any
AVC or USER_AVC recorded during the controlled converge window.

### Why this works (reference)

Linux bind mounts retain the inode selected at container creation, so a
path-stable Compose model that atomically replaces a file can otherwise leave a
running service reading stale bytes. The repository's exact
`bind-source-digest-inputs.json` allow-list maps each consumer to its mounted
sources. A stable 32-byte key stored as the single-link, root-only
`.state/bind-digest.key` is accepted by the digest helper only on stdin; the
helper HMACs framed path, type, owner, group, mode, size, and content under
strict object and byte limits, rejecting links, special files, nested or
duplicate inputs, and files that race while being read. Only the resulting
per-service digest, published as the `AIGW_BIND_DIGEST_*` Compose values, enters
service metadata, so a source inode or a security-relevant metadata change
recreates only the affected consumers.

`.state` is deliberately excluded from state backups. Authenticated restore
removes the local bind-digest key as a new restore epoch before it writes the
restore marker, so the next current-source converge creates a fresh key and
recreates every bind consumer even if the restored bytes happen to match, while
`volume-init` stays under its separate one-shot contract. Never copy a
bind-digest key between hosts or place it in an evidence bundle.

## Normal boot and reboot

Unlock and mount the encrypted state filesystems before Docker starts. The
repository does not provision or unlock LUKS, but both the full and stack-only
customer playbooks fail unless the configured Docker data root and stack
directory resolve through a block device with a `crypto_LUKS` ancestor; the
disposable lab profile is the only committed opt-out.

The host-input firewall guard is ordered `Before=docker.service` and wanted by
`docker.service`, so the packet policy loads before Docker can publish any port;
`docker-user-rules.service` then applies `DOCKER-USER` before Docker forwards
traffic. Confirm the policy units and Docker after a reboot:

```bash
systemctl is-active firewalld \
  aigw-host-input-rules.service \
  docker-user-rules.service \
  docker-user-rules-watch.service \
  docker.service
systemctl is-active aigw-vault-audit-rotate.timer \
  aigw-docker-log-acl.timer
nft list table inet aigw_guard
iptables -S DOCKER-USER
```

**What success looks like:** every listed unit and timer reports `active`, and
both the `aigw_guard` nftables table and the `DOCKER-USER` chain print their
rules rather than an empty or missing result.

Vault starts sealed by design after every restart. Two supported paths unlock
it. From the controller, rerunning the full `site.yml` converge auto-unseals an
initialized Vault from the encrypted `vault_unseal_key` (streamed to the
stdin-only helper under `no_log`) and then requires full readiness; this is the
normal path once first-init custody is complete. For an immediate fix on the VM
itself, retrieve an unseal share from approved offline custody and pipe it on
stdin; never place it in command arguments or shell history:

```bash
cd /opt/ai-gateway
read -rsp 'Vault unseal share: ' AIGW_UNSEAL_SHARE; printf '\n'
printf '%s\n' "$AIGW_UNSEAL_SHARE" | sudo scripts/vault-unseal.sh
unset AIGW_UNSEAL_SHARE
```

`scripts/vault-unseal.sh` submits one share through a one-shot, non-root,
read-only DHI Python container attached only to `net-vault`; it disables proxies
and redirects, drops all capabilities, uses `no-new-privileges`, sets
`--log-driver none`, and PUTs `/v1/sys/unseal` with the share read only from
stdin. It prints fixed non-secret status text and never echoes the share. Repeat
once per custodian share until the threshold is reached. The current lab
bootstrap creates one share with a threshold of one; production requires a
separately implemented custody model.

**What success looks like:** the script prints only its fixed non-secret status
text, and once the threshold is reached the `vault` healthcheck reports healthy
(initialized and unsealed).

After Vault is unsealed, wait for `key-rotator` and inspect status and recent
errors. The patched scheduler must defer startup rotations while Vault is sealed
without writing failed history, then retry after unseal. This behavior was
proven live on 2026-07-16 under a genuine VM reboot: the sealed window showed
30 s one-shot deferrals (never consumed) and non-terminal reconcile failures
with ALERTs, and after the converge auto-unseal the credential re-minted within
one 15 s reconcile tick with end-to-end inference passing. For any future
re-proof, note that Docker `live-restore` means a daemon restart alone cannot
seal Vault — only a reboot or an explicit restart of the long-running service
set demonstrates it. Do not use a manual container restart to make a
sealed-start acceptance test pass; that masks the behavior under test.

```bash
scripts/aigw-compose.sh ps
scripts/aigw-compose.sh logs --since=15m vault key-rotator keycloak litellm envoy-egress
```

**What success looks like:** `key-rotator` reports healthy and its recent logs
show no failed startup-rotation entries from the sealed-Vault window — the
scheduler deferred those rotations rather than recording them as failures.

Verify the Docker-log ACL boundary after every Docker restart, since a recreated
`/var/lib/docker/containers` parent can lose its ACL until the reconciler runs:

```bash
sudo getfacl -cp /var/lib/docker /var/lib/docker/containers
sudo systemctl --no-pager --full status aigw-docker-log-acl.timer
```

**What success looks like:** `getfacl` shows uid 473 with traversal-only
(`--x`) on the Docker data root and the reviewed `r-x` on the `containers`
root, and `aigw-docker-log-acl.timer` reports `active`.

The configured Docker root grants Alloy uid 473 traversal only (`--x`); the
`containers` root grants the reviewed `r-x` plus the default traversal entry
needed to discover log paths; immediate container directories and `*-json.log*`
files then receive only the documented ACLs, while ordinary sibling metadata
stays explicitly unreadable. Never repair this by granting uid 473 broad
recursive read on the Docker data root. See
[observability operations](observability-operations.md) for the exact ACL matrix.

### Health contracts

`docker compose ps` proves process state only when no healthcheck exists. Every
long-running base and lab service now has an explicit exec-form health contract;
`volume-init` is the sole intentional exited-zero one-shot. Do not replace these
probes with PID checks or shell assumptions.

| Service(s) | Exact in-container contract |
|---|---|
| `traefik-int`, `traefik-adm` | native `traefik healthcheck` against private `/ping`; returns unready during graceful termination |
| `oauth2-proxy`, `oauth2-proxy-grafana`, `oauth2-proxy-prometheus`, `oauth2-proxy-vault` | loopback `/ready`, including configured session-store readiness |
| `litellm` | loopback `/health/liveliness`; startup is gated on healthy Postgres, Redis, and Envoy |
| `open-webui` | loopback `/health`, including application initialization and basic local-database access |
| `keycloak` | management-port `/health/ready` must contain `"UP"` |
| `dev-portal`, `admin-portal` | loopback `/healthz` application liveness only; OIDC, LiteLLM, and rotator remain separate functional tests |
| `envoy-egress` | compiled probe requires loopback Envoy admin `/ready` HTTP 200 containing `LIVE`, with redirects and proxies disabled |
| `key-rotator` | loopback `/readyz` requires a writable database check and authenticated, unsealed Vault access |
| `vault` | loopback `/v1/sys/health?standbyok=true`; the active file-backed node is healthy only when initialized and unsealed |
| `postgres` | `pg_isready` for the local `postgres` database; this proves server acceptance, not password authentication or the cross-database ACL matrix |
| `redis` | authenticated native `AUTH` + `PING`; the static probe reads the root-rendered, container-private password file and never receives the credential through argv or `Config.Env` |
| `alloy` | fixed observability-address `/-/ready` must contain `Alloy is ready.`; component/export failures remain alert signals rather than restart triggers |
| `prometheus` | fixed observability-address `/-/ready` |
| `node-exporter` | loopback `/metrics` scrape must contain `node_exporter_build_info` |
| `loki` | loopback `/ready`, including service-manager and ingester readiness |
| `tempo` | DHI's native `/opt/tempo/tempo --health` readiness client |
| `grafana` | loopback `/api/health` |
| `cribl-mock` | loopback OpenTelemetry Collector `health_check` extension on port 13133; signal delivery is tested separately |
| `lab-dns` | loopback CoreDNS `/health` must return exactly `OK`; authoritative answers, NXDOMAIN behavior, and egress denial are separate probes |
| `samba-ad` | database/config presence, Samba control and domain response, exact lockout policy, and hostname-verified LDAPS |

Shellless DHI images that lack a client contain only the repository's static,
non-root `aigw-health-probe`; their original user, entrypoint, command, read-only
rootfs, capability, and no-new-privileges contracts are unchanged. Green Docker
health therefore does not replace the HTTP, OIDC, database-ACL, DNS, identity,
inference, egress, or telemetry tests in the [acceptance
runbook](test-runbook.md).

The reduced first-converge wait is now allowed only when Vault's public status
says it is genuinely **uninitialized**. An initialized Vault is auto-unsealed
from the controller `vault_unseal_key` and must then pass the strict probe: if
it stays sealed or unready (wrong share, a seal contract other than `t=1`/`n=1`,
or a missing key), Ansible fails closed rather than treating that state as
bootstrap; diagnose the listener, storage, or probe contract instead of
reinitializing Vault or broadening the exception. Two native probes have
important blind spots: Traefik's private `/ping` can be healthy while a non-root
process cannot read its dynamic TLS and router files, and Grafana's `/api/health`
can be healthy while its provisioning tree was not loaded. The verify role
therefore performs trusted TLS with exact SNI, requiring
`portal.<domain>/healthz` = 200, internal `api.<domain>/ui` = 403, ADM
`admin.<domain>/` = 303 (OIDC redirect), and
`litellm-admin.<domain>/openapi.json` = 403, and it queries Grafana's authenticated API from an
isolated `net-grafana` probe that must find the exact Prometheus, Loki, and Tempo
datasource graph with each datasource reporting `OK`. That probe retries at most
12 times with a five-second delay; Ansible streams the password on exact stdin
with `stdin_add_newline: false`, keeps the result under `no_log`, and disables
container logging. These functional proofs are release gates, not replacement
Docker healthchecks.

The deployment does not preserve controller-checkout modes. Reviewed non-secret
configuration directories are deterministically `root:root 0755` and ordinary
files `root:root 0644`, with executable mode granted only to the explicit
PostgreSQL initializer and service scripts. Private bind trees are narrower:
Keycloak realm imports and Traefik's certificate directory and private key are
`root:65532 0750/0640`. Ansible verifies these exact contracts so a root-owned
restore cannot leave a healthy-looking but functionally unreadable non-root
service.

Redis reads a SHA-256 verifier from a read-only ACL file, while only the
authenticated client probe receives the separate password file. Both host
sources are regular, single-link `root:65532 0440` files beneath the root-only
`secrets/` directory, and render validation rejects any reintroduction of the
credential into command or environment metadata. `WEBUI_SECRET_KEY` is a
required, stable encrypted-overlay value; before and after an Open WebUI
replacement compare only a cryptographic digest of the configured value and never
print it, because a changed digest invalidates sessions and breaks shared signing
state and is a release blocker.

### Reboot and remediation status

A clean replacement VM has passed one full reboot with old-share unseal, healthy
recovery of the long-running graph, exact container/image/volume/network
retention, `volume-init` non-rerun, and durable semantic comparison. That reboot
also exposed two defects since fixed in source: the then-deployed ACL timer did
not restore the recreated `containers`-root ACL, and the then-deployed
key-rotator consumed two sealed-Vault startup jobs as failures. The scheduler
remediation is deployed and passed its available-Vault path. The least-privilege
ACL, SELinux/MCS confinement, bind recreation, Vault-readiness, and pre-build
rollback-retention remediations are source-tested but not yet proven live. A
controlled source converge and Docker restart proving the new runtime labels and
parent-ACL repair, followed by an explicit restart of only the long-running
service set proving the sealed-to-unsealed retry path, remains PENDING; the
successful durable-state reboot must not be cited as that proof. The gate
register is [lab-dr-rehearsal.md](archive/lab-dr-rehearsal.md).

## SSH access and recovery

The baseline is public-key only. Password, keyboard-interactive, host-based,
GSSAPI, empty-password, and root logins are denied, and `DisableForwarding yes`
is backed by explicit TCP, Unix-domain socket, agent, X11, tunnel, gateway-port,
user-RC, and user-environment denials. Rocky's system crypto policy stays
authoritative for algorithms, so do not paste an unmaintained cipher list into
the drop-in. Verify syntax and the effective automation-user policy without
trusting the text of one file:

```bash
sudo /usr/sbin/sshd -t
read -r ssh_client ssh_client_port ssh_local ssh_port \
  <<<"${SSH_CONNECTION:?not an SSH session}"
sudo /usr/sbin/sshd -T -C \
  "user=$USER,host=$ssh_client,addr=$ssh_client,laddr=$ssh_local,lport=$ssh_port" | egrep \
  '^(authenticationmethods|passwordauthentication|kbdinteractiveauthentication|permitrootlogin|disableforwarding|allowstreamlocalforwarding) '
```

Expected values are `publickey`, `no`, `no`, `no`, `yes`, and `no`. Supplying the
complete active connection tuple matters because a later `Match Address` or
`Match LocalAddress` block can override a safe-looking global result; Ansible
performs the same complete-tuple evaluation, opens a fresh controller connection
with password methods disabled, and proves `sudo -n true` after every reload.

If a first converge fails its postflight, keep the original session open and use
the VM or provider console. Only for lockout recovery, move
`/etc/ssh/sshd_config.d/00-ai-gateway-hardening.conf` out of the include
directory, run `/usr/sbin/sshd -t`, reload `sshd`, repair the authorized key or
controller OpenSSH configuration, and immediately rerun the full playbook. Never
restart sshd with an invalid configuration or leave password login as the
recovery state.

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

For each configured physical interface, compare its saved, runtime, and permanent
ownership without changing the connection:

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

The expected invariants are one main default route on the egress NIC; ADM and
internal `/32` source rules with per-leg defaults in tables 101 and 102; each
active physical profile carrying its expected saved `connection.zone` with the
runtime zone matching and the corresponding permanent project zone listing
exactly that one interface; `aigw-egress` at canonical target `DROP` and
`aigw-adm`/`aigw-internal` at `REJECT`; no legacy zone-wide open ports; only SSH
binding a wildcard host address; Traefik binding exactly the ADM and internal
addresses on 443; in the lab only, authoritative DNS binding TCP and
UDP 53 on those same exact addresses and nowhere else; and nothing binding the
egress address.

### Firewall persistence and reload test

The native nftables guard survives a firewalld reload, after which the watcher
must reassert `DOCKER-USER`. During a maintenance window:

```bash
firewall-cmd --reload
systemctl is-active aigw-host-input-rules.service \
  docker-user-rules.service docker-user-rules-watch.service
nft list table inet aigw_guard
iptables -S DOCKER-USER
```

**What success looks like:** the three policy units report `active` after
`firewall-cmd --reload`, and both `nft list table inet aigw_guard` and
`iptables -S DOCKER-USER` still print their rules.

- Repeat the saved/runtime/permanent comparison afterward: a physical leg in `public`, even with key-only SSH and intact Docker forward guards, is a failed host-input boundary.
- Verify the exact fixed Envoy source, DNS `/32`, vendor TCP/443 allow, optional exact Alloy-to-Cribl rule, reply-direction state rule, cross-plane drops, and final bridge-origin default drop are all still present; do not settle for confirming that the chains and tables merely exist.
- If rules are absent, fail closed, restart the three policy units, then rerun the full `ansible/site.yml`.

Do not start or recreate application containers while the policy is absent.

```bash
systemctl restart aigw-host-input-rules.service
systemctl restart docker-user-rules.service
systemctl restart docker-user-rules-watch.service
```

### Container boundary packet test

This non-destructive probe verifies that Docker service discovery still works
while container-to-host and direct internet connections fail. Run it from the
deployed base directory; the lab overlay is not needed because `dev-portal` is a
base service.

```bash
PORTAL_GATEWAY="$(docker network inspect net-portal \
  --format '{{ (index .IPAM.Config 0).Gateway }}')"
scripts/aigw-compose.sh exec -T -e PORTAL_GATEWAY="$PORTAL_GATEWAY" dev-portal \
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

**What success looks like:** the probe prints `blocked as expected:` for both
the gateway and internet targets and finishes with
`internal service discovery succeeded`; any `UNEXPECTED CONNECTIVITY` line is a
failed boundary.

The verify role also sends an informational vendor canary through Envoy: a vendor
HTTP 401 proves DNS, routing, Envoy path matching, and upstream TLS worked
without a valid inference key, while a connection error points at resolver
routing, firewall counters, the narrowed CA bundles, or the egress leg. For
packet-level evidence during an inference request, capture on each real
interface:

```bash
tcpdump -ni <EGRESS_INTERFACE> '(udp port 53 or tcp port 53 or tcp port 443)'
tcpdump -ni <ADM_INTERFACE> 'tcp port 443'
tcpdump -ni <INTERNAL_INTERFACE> 'tcp port 443'
```

Expect vendor and DNS traffic only on egress, administrator traffic only on ADM,
and user HTTPS and approved Cribl only on internal. Capture files can contain
sensitive addressing and timing metadata; protect and delete them under the
customer evidence policy.

### Application checks

An internal client should reach
`https://auth.<domain>/realms/aigw/.well-known/openid-configuration` while the
Keycloak admin console stays denied there;
`https://api.<domain>/health/liveliness` and `/health/readiness` are allowed
while a management path such as `/key/list` is denied at Traefik. An `aigw-chat`
member can reach chat and an unauthorized user cannot; an `aigw-developers`
member can list, mint, and revoke only keys owned by that OIDC subject. The
LiteLLM Admin UI, Grafana, and the Prometheus UI first require `aigw-admins`
through their respective oauth2-proxy instances on the ADM leg, and Grafana then
requires its own local login. The portal admin page shows rotation and identity
status but never displays internal tokens or private keys. See the [acceptance
runbook](test-runbook.md) for the complete expected results.

## Production edge TLS

### Where TLS actually is (and is not)

HTTPS terminates at the **two Traefik edges only** (`traefik-int` on the internal
NIC, `traefik-adm` on the ADM NIC). Both read a single certificate store,
`/opt/ai-gateway/certs/{int.crt,int.key}`. Behind them, container-to-container
application traffic is **plain HTTP on segmented, internal-only Docker bridges** —
that is a deliberate design choice, not an oversight, and the bridges plus
DOCKER-USER/nftables rules are what constrain that traffic. **This platform does
not do service-to-service mTLS. Do not claim that it does.**

The only other TLS originators are:

* **Envoy** — originates vendor TLS outbound with narrowed per-vendor CA bundles.
* **Alloy → Cribl** — OTLP/TLS using a **dedicated** CA bundle at
  `certs/cribl-ca.pem` (`cribl_otlp_ca_pem_file`). This is deliberately *not* the
  edge CA: the authority that signs this gateway's edge certificate has no
  business vouching for the customer's telemetry endpoint, and trusting it there
  would silently widen the set of certificates Alloy accepts.

Because every published vhost is a one-level subdomain of `aigw_domain`, one
certificate with `SAN = DNS:*.<domain>, DNS:<domain>` covers both edges. The
validator **requires** both the wildcard and the apex.

### Choosing a mode

`aigw_edge_tls_mode` is fail-closed — `site.yml` refuses to run without exactly
one valid selection.

| mode | who | how the edge key is produced |
|---|---|---|
| `customer-supplied` | production | You hand over an existing leaf certificate + its private key + the complete chain as controller-local files. Use when you already hold a wildcard certificate issued for `*.<domain>`. |
| `vault-intermediate` | production **and** the lab | Vault generates the intermediate key **internally** and it never leaves Vault; a CSR goes out, your CA signs it **offline**, the signed cert + chain are imported back. Vault then issues the edge leaf. Use when you want an intermediate under your root but do **not** want the gateway to hold intermediate key material. |
| `customer-intermediate` | production **and** the lab | You hand over an intermediate CA certificate **and its private key** plus the full chain. Vault imports that intermediate, promotes it to the default issuer, and issues every leaf from it. Use when your CA can issue a constrained intermediate + key and you accept the gateway holding a live signing key. |
| `lab` | `rocky9-lab` only | `vault-bootstrap.sh` mints a self-signed **TEST** root. No browser or customer trusts it. Fallback for a disposable lab with no real CA. |

*Glossary: **leaf** — the actual server certificate a browser sees; **intermediate CA** — a signing certificate that sits between your root and the leaf; **root** — the top of the trust chain, whose private key you keep offline; **chain** — the ordered set of certificates from the intermediate up to the root.*

**The customer's root/issuing private key is never requested, transported, or
stored by this platform.** In `vault-intermediate` the only thing that crosses
the boundary is a CSR going out and a signed certificate coming back. The
ceremony script that touches the root key (`scripts/sign-vault-intermediate.sh`)
is deliberately **not** deployed to the gateway — a contract test asserts it is
absent from the operational-script manifest.

### Mode 2 ceremony (`vault-intermediate`)

Run after the Vault init ceremony, from `/opt/ai-gateway` on the VM:

```bash
# 1. Vault generates the intermediate key internally and emits a CSR.
read -rsp 'Vault token: ' TOK; printf '\n'
printf '%s\n' "$TOK" | sudo scripts/vault-pki-intermediate.sh csr
#    -> /opt/ai-gateway/secrets/aigw-intermediate.csr

# 2. On the CA workstation (the ONLY machine holding the root key):
scripts/sign-vault-intermediate.sh \
    --csr       ./aigw-intermediate.csr \
    --root-cert /path/to/root-ca.pem \
    --root-key  /path/to/root-ca-key.pem \
    --out-dir   ./signed
#    -> signed/intermediate.pem, signed/chain.pem  (intermediate + root)
#    The root key is read in place and never copied.

# 3. Import the signed certificate + chain and issue the edge leaf.
printf '%s\n' "$TOK" | sudo scripts/vault-pki-intermediate.sh install-signed \
    --signed-intermediate /tmp/intermediate.pem --chain /tmp/chain.pem
unset TOK
```

The intermediate is signed with exactly
`basicConstraints=critical,CA:true,pathlen:0` and
`keyUsage=critical,digitalSignature,cRLSign,keyCertSign`. `install-signed`
validates everything *before* touching the live certificate store, then
force-recreates the edge consumers. Then run the second `site.yml` converge.

**What success looks like:** `install-signed` reports validation of the signed
material before it touches the live certificate store, the edge consumers are
force-recreated with the newly issued leaf, and the second `site.yml` converge
completes.

Leaf renewal later:

```bash
sudo scripts/vault-pki-intermediate.sh renew-leaf
```

### Mode 3 ceremony (`customer-intermediate`)

Here you hand the gateway an **intermediate CA certificate, its private key, and
the full `intermediate + root` chain**, plus `aigw_domain`. Vault imports the
intermediate, promotes it to the default issuer, pins the `aigw` issuing role to
it, then issues every edge leaf (`*.<domain>`/`<domain>`, and the lab Samba LDAPS
certificate) from it. **The customer root private key is still never supplied,
transported, or stored** — only an intermediate that your root constrains.

**Where the material comes from — two paths, one mode.** The mode is identical
for lab and production; only the source of the three files differs.

* **Production:** the deploying engineer sets four inventory values —
  `aigw_edge_tls_mode: customer-intermediate`, `aigw_domain`, and the three
  controller-local PEM paths `aigw_edge_tls_intermediate_cert_file` /
  `aigw_edge_tls_intermediate_key_file` /
  `aigw_edge_tls_intermediate_chain_file`. The key file must be `0600` and a
  regular, non-symlink, single-link file. The controller preflight **fails
  closed** — before any host is touched — if the set is incomplete or the key is
  group-readable or a symlink. Start from
  [`production-rocky9.host-vars.yml.example`](../ansible/inventory/examples/production-rocky9.host-vars.yml.example).
* **Lab:** stage a local intermediate once (for example from the `aegisgroup.ch`
  PKI), then converge normally. The template
  [`rocky9-lab.customer-intermediate.host-vars.yml.example`](../ansible/inventory/examples/rocky9-lab.customer-intermediate.host-vars.yml.example)
  points the three paths at the **gitignored** `ansible/inventory/local-pki/`
  directory, and
  [`rocky9-lab.stage-customer-intermediate.sh.example`](../ansible/inventory/examples/rocky9-lab.stage-customer-intermediate.sh.example)
  copies your intermediate cert + key + chain into it (run once, from the repo
  root):

  ```bash
  AIGW_LOCAL_PKI_INT_CERT=/path/to/intermediate.pem \
  AIGW_LOCAL_PKI_INT_KEY=/path/to/intermediate.key \
  AIGW_LOCAL_PKI_CHAIN=/path/to/ca-chain.pem \
    bash ansible/inventory/examples/rocky9-lab.stage-customer-intermediate.sh.example
  ```

  This writes `ansible/inventory/local-pki/{intermediate.pem,intermediate.key,ca-chain.pem}`
  (key `0600`) — material that never enters git.

**The ordered ceremony** (the same two-pass converge as every mode, plus one
import step on the VM):

1. **Converge, pass 1** (`site.yml`). Ansible stages the three files into
   `/opt/ai-gateway/secrets/` on the VM over the `no_log` SSH pipe
   (`aigw-intermediate-import.pem`, `aigw-intermediate-import.key` at `0600 root`,
   `aigw-intermediate-import-chain.pem`), installs the self-signed **placeholder**
   so Traefik can start, and leaves Vault uninitialized. This is expected, not a
   failure.
2. **Initialize Vault.** Lab: `sudo scripts/vault-bootstrap.sh`, which in this
   mode enables `pki_int` and **defers** the edge — no test root. Production: the
   reviewed operator ceremony plus `scripts/store-vault-unseal-key.py` on the
   controller.
3. **Converge, pass 2** (`site.yml`). The placeholder is still served; the
   production reject-self-signed gate stays dormant because no ceremony marker
   exists yet.
4. **Import ceremony**, on the VM from `/opt/ai-gateway`, with the Vault token on
   stdin only:

   ```bash
   read -rsp 'Vault token: ' TOK; printf '\n'
   printf '%s\n' "$TOK" | sudo scripts/vault-pki-intermediate.sh import-intermediate \
       --intermediate      secrets/aigw-intermediate-import.pem \
       --intermediate-key  secrets/aigw-intermediate-import.key \
       --chain             secrets/aigw-intermediate-import-chain.pem
   unset TOK
   ```

   This validates the material fail-closed (`edge-tls.py validate-intermediate`),
   imports the intermediate over stdin (`pki_int/issuers/import/bundle`), promotes
   it and *proves* it is the mount's default issuer, pins the `aigw` role, issues
   and installs the edge leaf, writes the `.state/edge-tls-issued` marker, and
   finally **shreds the staged private key** — after which the intermediate key
   lives only inside Vault (encrypted at rest).

Leaf renewal later:

```bash
sudo scripts/vault-pki-intermediate.sh renew-leaf
```

Re-running the import ceremony requires **another converge first** to re-stage the
files, because the ceremony shreds them on success and the staging step is skipped
once the marker exists.

> **Name constraints are load-bearing here.** Before touching Vault, the ceremony
> signs a throwaway test leaf with your supplied intermediate and runs the exact
> `openssl verify` the real leaves get — for both `portal.<domain>` and
> `samba-ad.<domain>`. If `aigw_domain` is **outside** the permitted DNS subtree
> your root/intermediate constrains (for example an `aegisgroup.ch`-constrained
> intermediate with `aigw_domain=foo.example.com`), OpenSSL reports
> `permitted subtree violation` and the ceremony **fails closed** before any
> import. The domain has to fall inside the CA's permitted subtree — move the
> domain, not the check.

> **`customer-intermediate` is a higher-trust posture than `vault-intermediate`.**
> In `vault-intermediate` the intermediate private key is generated inside Vault
> and never leaves it. In `customer-intermediate` you deliberately hand the
> gateway a live intermediate signing key: it transits the `no_log` Ansible pipe,
> sits at `secrets/aigw-intermediate-import.key` (`0600 root`) between the staging
> converge and the import ceremony, is imported into Vault over stdin, and is then
> shredded from disk. Anyone who can read Vault's storage/seal or gain root on the
> gateway before the shred can recover an issuing key for your `aigw_domain`
> subtree. Choose it only when you accept that; otherwise prefer
> `vault-intermediate`, where the key never leaves Vault.

### Mode 1 (`customer-supplied`)

Set the three controller-local paths (the key must be `0600`, and the chain file
must contain the **complete** chain **including the self-signed root**). Ansible
stages them with `no_log`, validates, and installs atomically on every converge.
Renewal is: replace the files, rerun `site.yml`.

### What is validated before anything goes live

`scripts/edge-tls.py` runs every check **before** the first byte of `certs/` is
touched; a failure leaves the previous certificates exactly as they were:

* inputs are absolute, regular, non-symlink, single-hard-link files; the key is `0600`
* the private key matches the leaf (public-key comparison)
* SAN carries **both** `*.<domain>` and `<domain>`; EKU includes `serverAuth`; the leaf is not a CA
* every chain member is a CA, a **self-signed root is present**, and the chain verifies with `-purpose sslserver`
* the certificate verifies for a real vhost (`-verify_hostname portal.<domain>`)
* leaf, intermediates, **and root** all outlive `aigw_edge_tls_min_days_remaining` (default 30)
* a certificate input containing `PRIVATE KEY` is a hard refusal

On production profiles the converge and `verify` additionally run
`validate-installed --reject-self-signed`, which rejects the bootstrap
placeholder. That matters because the SNI probe validates the leaf against
`certs/ca.pem`, and a self-signed placeholder trivially satisfies that — it *is*
its own CA bundle.

> **Name constraints.** If the customer root carries `nameConstraints` (permitted
> DNS subtrees), the gateway domain must fall inside a permitted subtree or
> OpenSSL reports `permitted subtree violation` and the chain is refused. The
> validator surfaces OpenSSL's message verbatim. This is a property of the CA,
> not a bug — the domain has to move, not the check.

## Vault operations

> **Plain-language note — "1-of-1" and "Shamir share".** Vault's unseal secret
> can be split into several *Shamir* shares, each held by a different custodian,
> with a threshold number of them required to unlock. "1-of-1" means a single
> share with a threshold of one: one unseal key — the key that unlocks Vault
> after every restart. The production custody requirements for moving beyond a
> single share are stated later in this section.

`scripts/vault-bootstrap.sh` is explicitly a lab/test initializer, run on the VM.
It initializes file-backed Vault with 1-of-1 unseal, enables a file audit device,
installs the exact rotator/identity Vault policy and a 32-day periodic token,
optionally seeds static provider keys, and writes only the rotator token into
`.env` before recreating consumers. Its listener and seal-readiness probe uses
the static `aigw-health-probe http` binary against
`http://127.0.0.1:8200/v1/sys/health?standbyok=true` (accepting 200/501/503),
and its containerized `vault` CLI wrapper pins `VAULT_ADDR=http://127.0.0.1:8200`
so the isolated plaintext listener does not trigger a false HTTPS attempt. (The
explicit `vault status -address=... -format=json` seal-state probe belongs to
the Ansible converge, not this script.)

**Edge PKI depends on `aigw_edge_tls_mode`.** When the mode is
`vault-intermediate` (what the committed lab uses) or `customer-intermediate`,
`vault-bootstrap.sh` deliberately creates **no** root mount, **no** test root,
and **no** edge certificate — the customer CA owns the edge, and
`vault-pki-intermediate.sh` performs the ceremony (`csr` + `install-signed` for
`vault-intermediate`, `import-intermediate` for `customer-intermediate`). Only the
explicit `lab` fallback mints the self-signed test root plus a 90-day wildcard
certificate.

This is not production-safe merely because the listener is isolated: production
still needs TLS on the Vault listener, multiple custodians or an approved
auto-unseal design, token-renewal monitoring, disk-alert notification, and an
executable backup/restore drill. (The customer-rooted intermediate that used to
be listed here is now implemented — see **Production edge TLS** above.)

`vault-bootstrap.sh` is forbidden on the restore path. It is valid only for an
uninitialized fresh deployment with no restore marker; running it against a
restored, initialized Vault is a data-loss error.

Later converges auto-unseal an already-initialized Vault. This is Ansible
replaying the existing 1-of-1 Shamir share held on the controller as the
encrypted `vault_unseal_key` — custodied once with
`scripts/store-vault-unseal-key.py` into a dedicated `vault-unseal.yml` overlay,
streamed to the same stdin-only `vault-unseal.sh` under `no_log`, and never
rendered into `.env` or the target. It is *not* a Vault-native seal such as a
cloud-KMS or transit auto-unseal; the seal mechanism itself is unchanged, and
the converge simply refuses to complete an initialized-but-sealed Vault. The
production hardening above (listener TLS and either multiple custodians or a
reviewed KMS auto-unseal) is still required before this single-share replay is
treated as sufficient.

Vault audit rotation:

- Vault audit writes to `vault_audit`, and `aigw-vault-audit-rotate.timer` checks every 15 minutes.
- `scripts/rotate-vault-audit.sh` runs a locked, networkless, read-only helper under Vault's audit-volume UID/GID, rotates at 100 MiB by default, HUPs Vault to reopen the file, compresses the old inode, and keeps 14 rotations; the verify role requires the timer active.
- Those bounds are configurable through `VAULT_AUDIT_MAX_BYTES` and `VAULT_AUDIT_KEEP_FILES`, but the installed unit uses the defaults.
- Rotation uses the same digest-pinned DHI BusyBox image as `volume-init` rather than assuming an application image has a shell, and it deliberately defers when Vault is unavailable, so monitor the actual audit-volume size as well as timer state.

Never pass root tokens, unseal shares, provider keys, Samba passwords, or private keys as command-line values, and never copy Vault private-key records into the portal or a ticketing system.

## State inventory and backup

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
| Redis | none (in-memory) | disposable cache; no restore expected |
| Samba lab | `samba_ad_config`, `samba_ad_state`, `samba_ad_public` | lab identity/password/LDAPS state; restore together |
| rendered secrets/certs | `/opt/ai-gateway/.env`, `certs/`, `secrets/` | highly sensitive; encrypt and control separately |

### Create an encrypted backup

Generate and custody the age identity separately, retain only its public X25519
recipient on the gateway, and write to already-mounted independent, encrypted, or
off-host storage:

```bash
cd /opt/ai-gateway
sudo ./scripts/state-backup.sh \
  --recipient age1... \
  --output /independent-backup/aigw-$(date -u +%Y%m%dT%H%M%SZ).tar.gz.age
```

**What success looks like:** the run exits zero, age-encrypts and validates the
artifact, prints its SHA-256, writes `.state/last-backup.json`, and restarts
exactly the containers that were running before the quiesce.

The script prints the encrypted artifact's SHA-256; store that hash and the age
identity through an authenticated path independent of the backup and the VM. The
exact lab-only override
`AIGW_ALLOW_SAME_DEVICE_BACKUP=I_UNDERSTAND_THIS_IS_NOT_DR` permits mechanical
testing on one disposable disk and is not a production backup. Vault restarts
sealed after the quiesced backup, so perform the normal manual unseal and a full
Compose wait before declaring the gateway ready, using the merged files and
profile in the lab.

#### Why this works (reference)

`scripts/state-backup.sh` requires root plus the pinned `age`/`age-inspect`
tools. It refuses output on the stack's backing filesystem, an existing or
symlink output, an unverifiable or in-progress credential rotation, and any
co-located `secrets/vault-init.json`. It records the exact containers running
before quiesce, stops every writer, takes PostgreSQL globals and custom-format
logical dumps of the `litellm`, `keycloak`, and `rotator` databases, stops
Postgres, archives every present allow-listed named volume with the digest-pinned
DHI BusyBox `tar` under numeric ownership, and archives the reviewed rendered
stack, configuration, and secrets. It then age-encrypts and validates the
artifact, atomically installs it, writes `.state/last-backup.json`, and restarts
exactly the captured container IDs directly rather than asking Compose to
traverse dependencies, because that would rerun the successful exited
`volume-init` one-shot.

`openwebui_data/cache` is the one intentional volume exclusion: it holds
regenerable downloaded embedding-model objects whose upstream layout uses
symlinks, which the hostile-archive restore gate rejects before any mutation. The
durable Open WebUI database and application data remain in the backup, so
authenticated chat works after restore, but because Open WebUI has no approved
external egress here, embedding and RAG assets are not re-downloaded
automatically: restore requires a reviewed offline model reseed or a future
approved import path before those features return to service.

### Restore an authenticated backup

Restore is destructive. Build an isolated target with the firewall and network
boundary first, copy in the encrypted artifact and a mode-`0600` age identity,
and obtain the expected SHA-256 from the independent receipt. Then run:

```bash
cd /opt/ai-gateway
sudo ./scripts/state-restore.sh \
  --input /recovery/aigw-STATE.tar.gz.age \
  --identity /secure-recovery/age-identity.txt \
  --sha256 <authenticated-64-character-sha256> \
  --confirm RESTORE_AI_GATEWAY_STATE
```

**What success looks like:** the script authenticates the encrypted artifact
checksum before decryption, replaces only manifest-listed project volumes while
the project stays offline, writes the `.state/restore-required-unseal` marker, and
exits zero without starting the captured graph.

Complete the restore in order: keep both ingress legs in maintenance and run the
full `ansible/site.yml` converge from the designated current source while the
marker remains; confirm the converge retained the marker and recognized an
initialized, sealed restored Vault rather than replacement state; unseal Vault
with the separately held old shares; run `scripts/aigw-runtime-up.sh -d --wait
--wait-timeout 300`; verify database ACLs, identity fingerprints, Samba LDAPS
where applicable, provider canaries, and telemetry, then complete the acceptance
runbook; and remove `.state/restore-required-unseal` only after all proof
succeeds. While the marker exists, Ansible requires Vault's restored public state
to be initialized and prohibits replacement initialization, and
`scripts/vault-bootstrap.sh` must not be run.

Do not describe an untested artifact as recoverable. The scripts are tooling, not
evidence; production approval requires a successful isolated restore, and the
Vault init response and unseal material remain deliberately outside this backup.
The repository has completed a disposable encrypted backup/restore smoke test,
including PostgreSQL and Open WebUI rollback and the required post-restore unseal
marker; that proves mechanics, not the customer's storage, key custody, capacity,
or recovery-time objective. The first destructive replacement-VM restore attempt
exited 1 because it started the captured graph before current Ansible reconciled
bind ownership and Keycloak could not read its root-owned realm bind tree; the
corrected offline restore was repeated from the immutable authenticated artifact,
and an operator may never continue, patch around, or bootstrap over a failed
target. The corrected repeat and the full gate evidence, including the
still-pending G7 disposition, are recorded in
[lab-dr-rehearsal.md](archive/lab-dr-rehearsal.md).

`docker compose down` preserves named volumes. `docker compose down -v` destroys
all project databases, Vault, identity, and telemetry state; in the lab use the
merged files and profile through `aigw-compose.sh` or Samba volumes can be missed.

#### Why this works (reference)

The script authenticates the encrypted artifact checksum before decryption, then
`restore_archive.py` validates the exact outer inventory, the manifest/checksum
bijection, every nested archive path and type, and all profile volume names
before a single service is stopped. Sparse maps are rejected even when
represented as regular tar members. The hostile-input ceilings are 100,000
stack-configuration members, 2,000,000 members and 1 TiB declared per volume,
2 TiB declared across all volumes, and a mandatory 256 MiB free reserve, and the
declared total must fit the live Docker data filesystem after staging. Volume
wiping runs networkless and read-only with only `DAC_OVERRIDE` and `FOWNER`;
numeric-owner extraction adds only `CHOWN`; both helpers drop every other
capability and use `no-new-privileges`. The script replaces only manifest-listed
project volumes, installs the safely staged configuration while the project stays
offline, requires zero running project containers, writes
`.state/restore-required-unseal` as an exact `root:root 0600` file containing only
the authenticated backup SHA-256, removes any target-local `.state/bind-digest.key`
as a new bind epoch, and exits zero without starting the captured graph.

## Recovery order

For the destructive vanilla-VM lab exercise, follow the dedicated
[lab rebuild and restore rehearsal](archive/lab-dr-rehearsal.md), which holds the gate
register and the protected execution receipts. The summarized order is:

1. Recover the host or VM and unlock both encrypted state filesystems.
2. Restore the reviewed source and encrypted variable overlay, then run the full
   Ansible converge so PBR, firewalld, nftables, `DOCKER-USER`, bridge
   names/subnets, pinned helper images, and listeners exist before state is
   admitted.
3. Run `state-restore.sh` with the authenticated artifact, hash, and separately
   held age identity. Require exit 0, zero running project containers, and the
   exact root-only marker; do not open user or ADM access yet.
4. With ingress still in maintenance and the marker present, rerun the full
   `ansible/site.yml` from the designated content-addressed current source. This
   replaces captured configuration, repairs exact bind ownership and modes, and
   starts only the current graph while restored Vault stays sealed.
5. Stream the separately held old share to `scripts/vault-unseal.sh`, then run
   `scripts/aigw-runtime-up.sh -d --wait --wait-timeout 300`. Never run
   `vault-bootstrap.sh` on this path.
6. Recover the temporary Keycloak service client only if the Vault/controller
   proof fails; see [identity operations](identity-operations.md).
7. Verify packet policy, identity fingerprints, database access, prompt and log
   storage, and a vendor canary, then run the entire acceptance suite. Clear the
   restore marker only after the final gate passes and before reopening access.

Interaction with automatic unseal: current source makes the full converge in
steps 4–5 auto-unseal an initialized Vault from the controller-held
`vault_unseal_key`, and the verify role refuses to finish with an initialized
Vault sealed. Where the controller holds the matching 1-of-1 share, that
converge performs the unseal and the explicit step-5 `vault-unseal.sh` becomes
the fallback for a controller that does not hold it. This restore-path
interaction is source-tested but not yet proven live; the authoritative
sequence and its gates remain the [lab rebuild and restore
rehearsal](archive/lab-dr-rehearsal.md).

If preflight reports a Docker subnet or live-route collision, choose new
inventory subnets and update every fixed-IP, trust, and firewall assertion as one
reviewed change. Never force-create a colliding bridge.

## Pre-build rollback retention

- Current source runs `scripts/preserve-compose-rollbacks.py` after the shared build planner and before any planned custom-image build.
- For every planned service with an existing container it proves exactly one Compose instance is running, healthy, and at restart count zero; that the desired local tag and the container's immutable image ID agree; and that the local Docker socket is the one inspected.
- It then creates an immutable rollback reference from the project/service namespace plus the full source image digest, rechecks the container and both references for races, and atomically writes schema 2 of `.state/compose-build-rollbacks.json` as a single-link `root:root 0600` file.
- Previously recorded services are revalidated, a new generation never moves a reference named by the committed manifest, and a genuinely container-free first build is explicitly recorded as having no predecessor.

- The shared build planner, `scripts/plan-compose-builds.py`, hashes a domain-separated version-2 stream in which every build definition, path, type, mode, and file or symlink payload carries explicit length framing and every regular file is checked for identity and metadata races while streaming.
- The old unframed digest is accepted only as a one-converge comparison for a pre-existing manifest; current source always persists the framed digest, which prevents a file payload from absorbing the next inventory record and suppressing a required rebuild without breaking SHA-256.
- Any malformed manifest, multiple container, missing health contract, unhealthy or restarted source, mismatched desired image, moved rollback tag, failed Docker enumeration, or inspect/tag race stops the build.

Do not delete the manifest, move its tags, or manually bless a replacement
image to bypass a failure; the manifest is non-secret evidence, not a substitute
for the encrypted state backup or a schema-compatible rollback test. This control
has passed focused source tests but has not completed its live deployment gate.

## Upgrade procedure

Images are tag-and-digest pinned, and an upgrade changes both deliberately. Do
not use `latest` or a blind `docker compose pull`. Read upstream security and
migration notes for every stateful component, then scan and record the exact
candidate digests and custom dependency locks. For the portal image, regenerate
and review the complete transitive `requirements.lock`; production builds use
`--require-hashes`, validation requires every direct exact pin to appear in that
hashed lock, and the direct-only `requirements.txt` must never be substituted
into the image build.

Produce and restore-test the encrypted pre-upgrade backup. Generic and customer
Ansible default `require_preupgrade_backup: true`, so when a stateful direct image
reference changes, or the shared build planner detects changed source, a changed
build definition, a missing tag, or a differing local image ID for an existing
stateful custom image, `scripts/pre-upgrade-check.sh` requires an available
artifact whose receipt and hash still match and that is no more than 24 hours old.
The gated stateful set is Postgres, Keycloak, LiteLLM, Open WebUI, Vault, Alloy,
Prometheus, Loki, Tempo, Grafana, and lab Samba, so Alloy's durable positions and
the lab Samba state are covered as well as application data. The check also
refuses to run while `.state/restore-required-unseal` exists. The disposable
lab profile disables this gate only so candidate upgrades can be tested; do
not copy that exception to customer inventory.

Review the shared build plan and, for every planned custom build with an existing
service, require successful pre-build rollback retention before the build begins,
retaining both the exact rollback tag and the backup receipt through acceptance.
Do not treat image retention as database-schema rollback. Then validate without
starting containers, rebuild and run the unit, config, and runtime tests,
converge the lab, and test schema migrations and rollback for Postgres,
Keycloak, LiteLLM, Open WebUI, Vault, Loki, and Tempo, because a binary rollback
is insufficient once an on-disk schema has migrated.

```bash
scripts/validate-compose.sh
ansible-playbook -i ansible/inventory/lab.yml ansible/site.yml \
  --syntax-check --ask-vault-pass
```

### Docker Engine and Compose plugin version bumps

The Docker Engine, CLI, `containerd.io`, and Compose plugin are installed at
the exact NEVRA pinned in `ansible/group_vars/all.yml`
(`aigw_docker_ce_version`, `aigw_docker_ce_cli_version`,
`aigw_containerd_version`, `aigw_docker_compose_plugin_version`). They are
pinned because an unpinned `docker-ce-stable` install twice adopted a
Compose-v5 release that broke a live converge. Bumping them is a small,
sequenced procedure — never an ad-hoc `dnf upgrade docker-ce` on a host, and
never a blind `docker compose` self-update:

1. Read the upstream Docker Engine and Compose release notes for the candidate
   versions, then bump the four pins in `ansible/group_vars/all.yml` (or in the
   target's `host_vars` for a single host) to the candidate NEVRA.
2. Run the `runtime-skew.yml` canary from the Actions tab with `strict: true`
   and `compose_version` set to the candidate Compose tag. It starts real
   containers and asserts the same runtime contracts the `verify` role checks,
   so it proves the candidate Compose before any host changes. Left on its
   default schedule the canary already exercises the newest upstream release —
   with the pin in place that upstream leg is the early warning that a *future*
   bump is safe, not the version a converge silently installs.
3. Converge the lab with the two-pass `site.yml` flow and let `verify` pass on
   the live stack.
4. Only then bump the pins for customer/production inventory and converge,
   behind the usual pre-upgrade backup gate.

The converge fails closed if the mirror no longer offers the pinned NEVRA, and
`allow_downgrade: false` makes it refuse to roll a drifted-newer host back
under a running stack — downgrading Docker is a deliberate, separately
sequenced operation, not something a converge does on its own.

Use `deploy-stack-only.yml` only after its dedicated-host-marker and live
firewall/network preflights pass; otherwise run the full converge (host-level
inventory changes alone can use `os-prep.yml`, which converges the host up to
the Docker bridges without touching the running stack). Repeat the packet,
identity, provider,
and telemetry acceptance checks afterward. LiteLLM worker or replica changes are
architecture changes, not ordinary resource edits: follow [LiteLLM capacity and
scaling](litellm-scaling.md) for aggregate PostgreSQL connection accounting,
shared Redis behavior, single-run migrations, readiness-based routing, drain time
for long streams, and benchmark and failure acceptance, and never use an ad hoc
Compose `--scale` command as a production rollout.

### PostgreSQL role and ACL reconciliation

Ansible reconciles PostgreSQL roles, passwords, databases, and `CONNECT` ACLs on
every deployment by rerunning the idempotent initialization script over the
trusted local Unix socket before Compose reconciles consumers. The script tests
the desired password through the normal SCRAM TCP path and rewrites its salted
verifier only on mismatch, with no password in task output or command arguments.
Each service role is reconciled to `LOGIN`, non-superuser, `NOCREATEDB`,
`NOCREATEROLE`, `NOINHERIT`, `NOREPLICATION`, `NOBYPASSRLS`, connection limit
`-1`, no role-local settings, and no finite expiry; each database has its matching
service-role owner; memberships in either direction involving any service role are
removed; and `PUBLIC` has no `CONNECT` on any of the four databases.

| Login role | `litellm` DB | `keycloak` DB | `rotator` DB | `postgres` DB |
|---|---:|---:|---:|---:|
| `litellm` | allow | deny | deny | deny |
| `keycloak` | deny | allow | deny | deny |
| `rotator` | deny | deny | allow | deny |

The `postgres` superuser retains maintenance access. The play checks all twelve
service-role/database decisions, the three owners, three role contracts, zero
memberships, and maintenance access on every converge; an unchanged run emits
`AIGW_POSTGRES_OK` internally and rewrites no catalog, while the task reports
changed only for `AIGW_POSTGRES_CHANGED`. Treat a password change as complete only
after the play finishes and all three consumers are healthy, and rehearse rollback
with the encrypted prior overlay before production use.

### Open WebUI service key

The Open WebUI integration uses one shared LiteLLM workload key, not the proxy
master and not a human portal key. Each converge resolves both its exact alias and
the SHA-256 of the encrypted-overlay candidate and accepts only a unique 0/0
create or a 1/1 same-token update. The key is owned by `svc-open-webui`, tagged as
service and project `open-webui`, limited to the three approved model aliases and
the model-list and chat-completions routes, and denied all management endpoints.
Its trace attribution therefore identifies the shared Open WebUI service, not the
individual browser user; direct API keys issued through the portal keep per-user
attribution, and trusted end-user propagation through Open WebUI requires a
separate reviewed design. See
[observability operations](observability-operations.md) for the correlation
detail.

## Troubleshooting

When full preflight refuses the topology, use `ip -br -4 address`, `ip -4 route
show table main`, and `ip -4 route get` to compare live facts with the selected
inventory. For table-name collisions, inspect `/etc/iproute2/rt_tables` when it
exists and `/usr/share/iproute2/rt_tables` on a vanilla Rocky 9 host; the first
mutating routing role seeds a missing `/etc` override from that vendor file.
Correct the inventory or customer-owned network configuration out of band, since
the playbook intentionally will not repair or guess NIC addressing. When the
stack-only deployment refuses to run, its live firewall/network ABI is stale or
missing: run the full `site.yml` rather than skipping assertions or attaching
services to broader networks by hand.

For OIDC callback or issuer errors, check split DNS, the browser-visible
`https://auth.<domain>` issuer, the exact redirect URI, internal CA trust, and
Keycloak's proxy-trusted addresses; realm imports do not update an existing
database, so reconcile changed callbacks and secrets in Keycloak explicitly. A
`400 "Invalid parameter: redirect_uri"` on every login after an `aigw_domain`
change is this exact case: while the identity bootstrap window is open a
converge realigns the managed clients' callbacks automatically, and after the
ceremony it requires re-running the bootstrap ceremony — see
[identity operations](identity-operations.md#domain-migration-on-an-existing-realm).
When
vendor calls fail, check Envoy's startup-gate output, narrowed CA expiry or issuer
changes, exact SAN, resolver reachability, the fixed `172.28.0.2` attachment,
firewall counters, and the physical egress route; never "fix" an outage by using
the system CA bundle, adding a default route to another service, or permitting the
whole bridge.

For memory or disk pressure, remember that full prompt traces consume storage
quickly. Redis is bounded at 384 MiB with `allkeys-lru` below its 512 MiB
container limit, Loki WAL replay is capped at 512 MiB and flushes on clean
shutdown, and Vault audit rotates as described above. Node-exporter feeds the
15%, 5%, and predicted-24-hour filesystem rules, but no Alertmanager or
notification route is deployed, so monitor those rules directly; see
[observability operations](observability-operations.md) for the capacity math.
If a firewall reload caused an outage, confirm the watcher is active, inspect both
nftables and `DOCKER-USER`, restart the three policy units, then run the full
converge: the independent native forward hook should preserve denial during the
reload, but an outage can still occur if approved rules were not reasserted.

## Residual security boundary

- The packet policy constrains managed project bridges, not arbitrary root-owned host processes.
- Docker image pulls and other host-namespace traffic are outside `DOCKER-USER`; Envoy necessarily retains a DNS channel to one approved resolver; and unmanaged bridges whose names are outside the project inventory are outside the native container-input scope.
- Root on the VM, Docker daemon access, Compose file and entrypoint changes, and the encrypted secret overlay remain high-trust administrative boundaries.

## Legacy lab reset

`ansible/reset-rocky9-lab.yml` is a destructive, snapshot-gated teardown for
the unmarked legacy lab VM only. It refuses to run without a verified
hypervisor snapshot, exact VM identity and NIC binding, the profile
`rocky9-lab`, and two literal acknowledgement tokens
(`DESTROY_AIGW01_LAB_STATE` and `REMOVE_AIGW01_LEGACY_HOST_ARTIFACTS`); it
removes only preflight-enumerated AIGW objects, never runs a broad prune,
and hands the NICs to a fail-closed `drop` zone. It never targets a generic
or customer inventory.

