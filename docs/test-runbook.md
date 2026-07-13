# Acceptance Test Runbook

This runbook is the release gate for a complete Rocky Linux 9 deployment. A
single-NIC shortcut is not supported: routing, firewalld, Docker forwarding,
and listener placement are part of the product and require the real three-leg
topology. Use customer-supplied interfaces and addresses, or the exact
lab profile in [the deployment guide](deploy-guide.md).

Run destructive and fault-injection cases only on the disposable lab. Record
the source revision, image digests, inventory profile, timestamps, and pass or
fail evidence without copying passwords, tokens, prompt bodies, private keys,
Vault responses, or session cookies into the evidence bundle.

See the [solution map](solution-map.md) for the architecture and trust
boundaries this runbook exercises, and [project status](project-status.md) for
the current implementation posture and the residuals that remain pending.

## 1. Static release checks

From the repository checkout on the control machine:

```bash
scripts/validate-compose.sh
python3 -I scripts/validate-identity-policy.py
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v \
  scripts/tests/test_restore_archive.py \
  scripts/tests/test_load_offline_image_seed.py \
  scripts/tests/test_plan_compose_builds.py \
  scripts/tests/test_pre_upgrade_check.py \
  scripts/tests/test_preserve_compose_rollbacks.py \
  scripts/tests/test_compute_bind_source_digests.py \
  scripts/tests/test_selinux_contract.py \
  scripts/tests/test_acl_reconciler_source.py \
  scripts/tests/test_safe_inventory_marker.py \
  scripts/tests/test_validate_identity_policy.py

python3.12 -m venv /tmp/aigw-dev-portal-test
/tmp/aigw-dev-portal-test/bin/python -m pip install --require-hashes \
  -r services/dev-portal/requirements.lock
/tmp/aigw-dev-portal-test/bin/python -m pip install \
  -r services/dev-portal/requirements-dev.txt
(cd services/dev-portal && PYTHONDONTWRITEBYTECODE=1 \
  /tmp/aigw-dev-portal-test/bin/python -m pytest -q -p no:cacheprovider)
/tmp/aigw-dev-portal-test/bin/ruff check \
  services/dev-portal/app services/dev-portal/tests
/tmp/aigw-dev-portal-test/bin/bandit --quiet --severity-level high \
  --recursive services/dev-portal/app
/tmp/aigw-dev-portal-test/bin/pip-audit \
  --path /tmp/aigw-dev-portal-test/lib/python3.12/site-packages

python3.12 -m venv /tmp/aigw-key-rotator-test
/tmp/aigw-key-rotator-test/bin/python -m pip install --require-hashes \
  -r services/key-rotator/requirements.lock
/tmp/aigw-key-rotator-test/bin/python -m pip install \
  -r services/key-rotator/requirements-dev.txt
(cd services/key-rotator && PYTHONDONTWRITEBYTECODE=1 \
  /tmp/aigw-key-rotator-test/bin/python -m pytest -q -p no:cacheprovider)
/tmp/aigw-key-rotator-test/bin/ruff check \
  services/key-rotator/app services/key-rotator/tests
/tmp/aigw-key-rotator-test/bin/bandit --quiet --severity-level high \
  --recursive services/key-rotator/app
/tmp/aigw-key-rotator-test/bin/pip-audit \
  --path /tmp/aigw-key-rotator-test/lib/python3.12/site-packages

bash -n scripts/*.sh services/samba-ad-lab/samba-ad-entrypoint \
  services/samba-ad-lab/samba-ad-healthcheck

docker build -t aigw-samba-ad:test services/samba-ad-lab
sh services/samba-ad-lab/tests/test-secret-argv.sh aigw-samba-ad:test
sh services/samba-ad-lab/tests/test-lockout-policy.sh aigw-samba-ad:test
```

`validate-compose.sh` is render-only and must not start containers. The two
exact-pinned `requirements-dev.txt` files are release tooling only; do not add
them to either production image. Run the checks in clean virtual environments
or the project CI image, not by installing packages into the target host.
Bandit's high-severity gate is complemented by manual review of lower-severity
results so deliberate retry jitter and empty one-use archive passwords do not
create false release failures. For dev-portal, validation must also prove that
`requirements.lock` contains
the complete transitive graph with exact versions and SHA-256 hashes, includes
every direct pin from `requirements.txt`, and that the production Dockerfile
installs only the lock with pip `--require-hashes`.

The safe-inventory tests must prove deterministic canonical JSON/receipt,
bounded input, sensitive-field rejection, exact durable comparison, and only
explicit volatile-scalar or append-only-prefix exceptions. The tool is
controller-only and must remain absent from the deployed script allow-list.

The build-planner tests must prove the version-2, domain-separated, length-
framed record stream distinguishes formerly colliding inventories, checks file
identity/metadata races, persists only the framed digest, and permits only the
bounded one-converge legacy comparison. The rollback-retention tests must prove
local-socket-only Docker inspection, exactly one healthy/running/zero-restart
source container, desired-tag and immutable-ID agreement, immutable project/
service/full-source-digest references, preservation/revalidation of retained
service records, private schema-2 atomic manifest writes, post-tag race checks,
interruption-safe first-build proof retirement, and fail-closed ambiguous,
unhealthy, and malformed cases.

The bind-digest tests must prove stdin-only key use, domain/path/payload
framing, deterministic per-service output, exact metadata sensitivity, bounded
object/byte input, and fail-closed links, hardlinks, special files,
duplicates/nesting, escapes, and read races. The SELinux source tests must
prove preflight occurs before mutation, Docker integration is enabled and
validated, every ordinary service carries the recreation generation and
read-only `z`/`Z` contract, only Alloy/node-exporter disable labels, exact
fcontext/restorecon ordering, MCS/runtime-type verification, and the zero-AVC
gate. The ACL source tests must prove canonical inventory paths, traversal-only
Docker-root verification, parent-before-child containers ACL repair, checked
Docker enumeration, bounded walks, and a systemd write boundary limited to the
containers subtree.

Also run the playbook syntax check with access to the encrypted inventory:

```bash
ansible-playbook -i ansible/inventory/lab.yml ansible/site.yml \
  --syntax-check --ask-vault-pass
```

Reject the release if any check needs a placeholder credential, a disabled
assertion, or an edited generic default to pass.

## 2. Topology and clean converge

On the target, capture the pre-converge facts:

```bash
ip -br -4 address
ip -4 route show table main
ip -4 rule show
lsblk -f
findmnt /var/lib/docker /opt/ai-gateway
getenforce
sestatus
```

Require `Enforcing` and the loaded `targeted` policy before running Ansible.
Prove a permissive/disabled fixture is rejected before any baseline role can
install packages, write Docker configuration, or change host networking. The
playbook is not an SELinux-mode conversion mechanism.

For the lab, prove all of these exact facts before deployment:

| Leg | Interface | Address | Gateway |
|---|---|---|---|
| egress | `enp0s5` | `10.211.55.3` | `10.211.55.1` |
| ADM | `enp0s7` | `10.8.10.10` | `10.8.10.2` |
| internal | `enp0s8` | `10.20.0.10` | `10.20.0.2` |

Run the full converge, not the stack-only playbook:

```bash
ansible-playbook -i ansible/inventory/lab.yml ansible/site.yml \
  --ask-vault-pass
```

For a customer deployment, substitute the generic inventory and protected
topology file documented in `deploy-guide.md`. The play must complete its
post-converge assertions. Confirm NetworkManager connection profiles and the
three static addresses did not change.

The lab profile is the only supported exception to encrypted-state
enforcement. A generic/customer converge must fail before starting Docker if
the configured Docker and stack state paths do not resolve through the
reviewed encrypted block-device boundary.

### SSH hardening acceptance

Keep the console and original SSH session available for the first converge.
Confirm Ansible's preflight and postflight both opened independent key-only
connections, and that the postflight proved non-interactive sudo. Then run:

```bash
sudo /usr/sbin/sshd -t
read -r ssh_client ssh_client_port ssh_local ssh_port \
  <<<"${SSH_CONNECTION:?not an SSH session}"
sudo /usr/sbin/sshd -T -C \
  "user=$USER,host=$ssh_client,addr=$ssh_client,laddr=$ssh_local,lport=$ssh_port" | egrep \
  '^(authenticationmethods|pubkeyauthentication|passwordauthentication|kbdinteractiveauthentication|permitemptypasswords|hostbasedauthentication|gssapiauthentication|permitrootlogin|x11forwarding|disableforwarding|allowtcpforwarding|allowstreamlocalforwarding|allowagentforwarding|permittunnel|gatewayports|permituserenvironment|permituserrc|maxauthtries|logingracetime|maxsessions|maxstartups) '
```

Require public-key authentication, root/password/interactive/empty-password/
host-based/GSSAPI denial, all listed forwarding controls denied (with
`disableforwarding yes`), `MaxAuthTries 3`, `LoginGraceTime 30`, `MaxSessions
4`, and `MaxStartups 10:30:30`. The complete connection tuple is mandatory so
the check evaluates any `Match Address` or `Match LocalAddress` clauses. From
another terminal prove a fresh key login
and `sudo -n true` succeed. Also prove password-only authentication fails and
`ssh -N -L 18080:127.0.0.1:22 ...` cannot create a forwarding channel. Do not
test lockout recovery by breaking the only lab access path; use the documented
console recovery procedure during a disposable recovery drill.

## 3. Host routing, firewall, and listeners

Run as an administrator on the target:

```bash
ip -4 route show table main default
ip -4 rule show priority 10101
ip -4 route show table 101
ip -4 rule show priority 10102
ip -4 route show table 102

firewall-cmd --get-active-zones
firewall-cmd --zone=aigw-egress --list-all
firewall-cmd --zone=aigw-adm --list-rich-rules
firewall-cmd --zone=aigw-internal --list-rich-rules
firewall-cmd --zone=aigw-egress --get-target
firewall-cmd --zone=aigw-adm --get-target
firewall-cmd --zone=aigw-internal --get-target

for interface in <EGRESS_INTERFACE> <ADM_INTERFACE> <INTERNAL_INTERFACE>; do
  uuid="$(nmcli --get-values GENERAL.CON-UUID device show "$interface")"
  printf '%s|%s|%s\n' \
    "$interface" \
    "$(nmcli --get-values connection.zone connection show uuid "$uuid")" \
    "$(firewall-cmd --get-zone-of-interface "$interface")"
done
firewall-cmd --permanent --zone=aigw-egress --list-interfaces
firewall-cmd --permanent --zone=aigw-adm --list-interfaces
firewall-cmd --permanent --zone=aigw-internal --list-interfaces

nft list table inet aigw_guard
iptables -S DOCKER-USER
systemctl is-active aigw-host-input-rules.service \
  docker-user-rules.service docker-user-rules-watch.service docker.service
ss -H -tlnp
```

Pass criteria:

- the main table has exactly one default through the egress leg;
- priority 10101 selects table 101 for the ADM `/32`, and 10102 selects table
  102 for the internal `/32`; both tables contain their connected routes and
  per-leg default;
- no firewalld zone exposes a zone-wide port; only the VPN CIDR can reach ADM
  TCP/22 and TCP/443, and only the internal CIDR can reach internal TCP/443.
  The lab profile additionally permits TCP/UDP 53 from those same scoped
  source CIDRs to the corresponding exact host addresses;
- each physical interface resolves to one valid, distinct active
  NetworkManager UUID; its saved `connection.zone` and runtime firewalld zone
  equal the expected project zone; and that permanent project zone contains
  exactly that interface. `aigw-egress` reports target `DROP`, while
  `aigw-adm` and `aigw-internal` report canonical target `REJECT`;
- the native nftables table and `DOCKER-USER` both require DNAT state, the
  exact original ADM/internal host address and port, and a managed bridge for
  physical ingress; both also contain fixed-source Envoy DNS/443 allows,
  optional exact Alloy-to-Cribl allow, reply-direction state, cross-plane
  denies, container-to-host denies, and a final bridge-origin physical-egress
  drop;
- only SSH may use a wildcard listener; Traefik binds exact ADM/internal
  addresses on TCP/443. Lab DNS binds TCP/UDP 53 on those two exact addresses;
  nothing listens on the egress address.

During a maintenance window, prove policy survives firewalld reload:

```bash
firewall-cmd --reload
systemctl is-active aigw-host-input-rules.service \
  docker-user-rules.service docker-user-rules-watch.service
nft list table inet aigw_guard
iptables -S DOCKER-USER
```

Repeat the saved/runtime/permanent zone comparison after reload. Compare the
substantive forward rules, not merely the existence of the table/chain. Any
physical interface reappearing in `public` fails acceptance even if key-only
SSH and the independent Docker forward guards reduced exposure.

## 4. Docker segmentation and negative packet tests

The base stack has 23 long-running services plus one successful one-shot
`volume-init`, and uses 18 of the 20 pre-created networks. The lab overlay adds
two long-running services — Samba AD on `net-identity` and authoritative DNS on
`net-lab-dns` — bringing every one of the 20 bridges into use and the total to
25 long-running services plus `volume-init`. On the lab always use the merged
command:

```bash
cd /opt/ai-gateway
docker compose -f docker-compose.yml -f docker-compose.lab.yml \
  --profile lab-ad config --services
docker compose -f docker-compose.yml -f docker-compose.lab.yml \
  --profile lab-ad ps
docker network ls --filter label=com.docker.compose.project=ai-gateway
```

Inspect all 20 networks and confirm the exact subnet, the `.128/25` container
`IPRange` half, the stable `br-*` name, `EnableIPv6=false`, and the `Internal`
flag match Ansible. `net-egress`, `net-adm`, `net-internal`, `net-int-edge`, and
`net-lab-dns` are non-internal. The last
two must have exactly one service peer and no permitted container egress;
they exist only to preserve exact-IP host publication under Docker 29.
`samba-ad` must have no published port and only one attachment,
`net-identity`. `lab-dns` must publish TCP/UDP 53 only on the exact ADM and
internal addresses, have no forwarding plugin, and return `NXDOMAIN` for a
name outside `aigw.internal`.

Prove service discovery still works while direct internet and host access are
blocked:

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

Pass only if both unapproved connections fail. The full Ansible converge also
runs an informational request through Envoy; an upstream 401 proves the
approved DNS, route, TLS, and proxy path. It does not prove inference
credentials.

## 5. Vault and application readiness

Use the lab bootstrap only on the disposable lab profile, as described
in `deploy-guide.md`. Unseal Vault without putting the share in an argument or
shell history, then wait for health checks:

```bash
cd /opt/ai-gateway
read -rsp 'Vault unseal share: ' VAULT_UNSEAL_SHARE; printf '\n'
printf '%s\n' "$VAULT_UNSEAL_SHARE" | sudo scripts/vault-unseal.sh
unset VAULT_UNSEAL_SHARE

docker compose ps
docker compose logs --since=15m \
  vault postgres redis keycloak key-rotator litellm envoy-egress alloy
```

Use the merged Compose arguments in the lab. Pass criteria are healthy/ready
state for all 25 long-running lab services, no restart loop, no
placeholder-secret failure, Vault unsealed, database migrations complete, and
no outbound TLS/pin error. `volume-init` must remain exited zero; it is the sole
non-running exception. A container merely being `Up` is not sufficient. Compare
the rendered probes with the complete service-by-service health inventory in
[operations](operations.md); green Docker health still does not prove the
separate database ACL, DNS, OIDC, inference, or telemetry contracts below.

Exercise the reduced bootstrap wait in isolation. An uninitialized or sealed
Vault may select only the documented bootstrap-independent core. A fixture in
which public Vault status is both initialized and unsealed while the strict
readiness probe fails must stop the converge before final verification; it
must not be accepted merely because `vault status` itself returned parseable
JSON. A restore marker with uninitialized Vault must also stop and must never
run replacement bootstrap.

Require the full Ansible functional probes as well. Connecting to the exact
Traefik service-plane addresses with trusted TLS and exact SNI, the reviewed
edge contract is: 200 for internal `portal.<domain>/healthz` and
`auth.<domain>/realms/aigw/.well-known/openid-configuration`; 403 for internal
`api.<domain>/ui`; 200 for ADM `admin-portal.<domain>/healthz`; and a 302 OIDC
redirect for ADM `admin.<domain>/`, `grafana.<domain>/`, `prometheus.<domain>/`,
`vault.<domain>/`, and `auth.<domain>/admin/`, as each oauth2-proxy or the
Keycloak admin route bounces an unauthenticated request to Keycloak. During
recovery maintenance, connect to the exact Traefik service-plane addresses
rather than the deliberately denied physical host addresses; verify physical
listeners, DNAT, and firewall policy separately. These checks detect unreadable
Traefik dynamic route/TLS files that native `/ping` misses. An isolated,
network-scoped probe container reads Grafana's provisioned datasource table
read-only from a `--volumes-from grafana:ro` mount — proving exactly Prometheus,
Loki, and Tempo with the reviewed UIDs, types, and URLs — and confirms all three
backends answer their native readiness endpoints (`/-/ready`, `/ready`,
`/ready`). It runs inside the bounded 12 attempts with five-second delay, with
the probe container's logging disabled and no secret in its arguments or output;
Grafana's own login form and basic auth are disabled, so no admin password is
presented. Reading `/api/health` alone does not prove the provisioning graph
loaded.

Inspect the rendered Redis service metadata without copying it into evidence.
Its server `Config.Cmd` and `Config.Env` must contain no credential, and the
command must name only the read-only ACL verifier file. The separate plaintext
password file is for the authenticated client health probe only. Both host
files must remain regular, single-link `root:65532 0440` files beneath the
root-only secret directory. Any plaintext in Docker metadata is an exposure
requiring value rotation, not a documentation exception.

For the mandatory idempotency run, capture before and after snapshots of all 26
container IDs, image IDs, start/finish timestamps, status, health, exit code,
and restart count, including the exited initializer. Separately record the
initializer's definition-hash label, timestamps, and exit code; every deployed
configuration/build-input hash; policy-routing state; all eight volume-root
owner/group/mode contracts; and Vault's container ID, restart count, health,
and seal state.

| Volume | Expected UID:GID | Expected mode |
|---|---:|---:|
| `pg_data` | `70:70` | `0700` |
| `vault_data` | `1000:1000` | `0700` |
| `vault_audit` | `1000:473` | `2750` |
| `alloy_data` | `473:473` | `0700` |
| `prom_data` | `65532:65532` | `0700` |
| `loki_data` | `65532:65532` | `0700` |
| `tempo_data` | `65532:65532` | `0700` |
| `grafana_data` | `65532:65532` | `0700` |

Compare those semantic leaves, not the total number of Ansible tasks reporting
`changed`: some policy reassertion and evidence tasks intentionally report a
change on every converge. Passing requires zero changed modeled leaves, no
custom-image builds, the initializer still exited zero with the same hash and
timestamps, every long-running container ID/start time/restart count unchanged,
and Vault healthy and unsealed. The root-only
`.state/compose-build-inputs.json` file is build-cache metadata, not secret or
backup state; do not delete it between the two runs.

Also require Docker to report `name=selinux`; every ordinary long-running
service to have matching `container_t` process and `container_file_t` MCS
mount labels; Alloy and node-exporter alone to remain bounded `spc_t`
exceptions; every read-only bind source to match its exact shared/private
contract; and both Docker runtime roots to remain `container_var_lib_t`.
Require zero AVC/USER_AVC events after the preflight timestamp. Compare the
single-link root-only bind-digest key by metadata only, never by value, and
require every consumer's computed digest to equal its Compose label.

On a disposable source fixture, atomically replace one mounted non-secret
configuration file with semantically harmless changed bytes. Pass only when
its declared consumer is recreated, unrelated services retain their IDs/start
times, and the consumer sees the new inode/bytes. On an isolated restore
fixture, require `state-restore.sh` to remove the target-local bind-digest key;
the next current-source converge must create a new key and recreate every bind
consumer without rerunning `volume-init`.

On a disposable clone only, deliberately drift one managed volume root's owner
or mode and reconverge. Pass when only the initializer reruns, the exact
contract is repaired, and unrelated long-running services are not recreated.
Do not conduct this destructive drift test against retained customer state.

For the final reboot/restart gate, keep maintenance ingress and any recovery
marker in place. Capture the exact 26-container/image/configuration/volume/
network inventory, key-rotator history prefix, durable semantic markers, host
guards, and Docker ACLs. Run two distinct controlled events; do not conflate
their evidence.

First restart the Docker daemon exactly once without recreating the Compose
project. Because `live-restore` is enabled, this event is expected to leave the
running containers alive and **does not** create a sealed-Vault startup. Pass
this daemon-restart lane only when:

- the native/firewalld/`DOCKER-USER` boundaries remain active and the same 26
  container IDs, images, configurations, volumes, and networks remain;
- Docker still reports SELinux active; every ordinary service retains its
  exact process/mount MCS pair, only Alloy/node-exporter retain the reviewed
  disabled-label exception, every bind context still matches, Docker runtime
  roots retain their policy type, and no new AVC/USER_AVC appears;
- `volume-init` does not rerun and no container records an unexpected restart
  count or OOM event; and
- within the timer bound, uid 473 has traversal only on the configured Docker
  root, exact `r-x` plus the reviewed default entry on its `containers` root,
  exact directory/log ACLs below it, and explicit denial on ordinary sibling
  metadata; a forced Docker enumeration failure must fail the reconciler;

Then derive the exact profile-aware service list, require it to contain the 25
long-running services and exactly one separate `volume-init`, and explicitly
restart only those 25 services. Do not use dependency traversal or a broad
`docker compose restart` with no service list. This second event keeps the
container identities/configurations/images/volumes/networks but intentionally
changes the long-running processes' start times. Pass the sealed-start lane
only when:

- `volume-init` remains exited zero with its original timestamps;
- Vault returns initialized and sealed, and key-rotator appends no rotation
  history while its startup jobs are deferred;
- exactly one lab share is streamed only on stdin, Vault returns healthy, and
  the scheduler's bounded retry produces exactly the expected two static
  outcomes (`skipped` when no seed keys exist), with no failed row and no key
  material in evidence; and
- all 25 long-running services return healthy, restart counts remain zero, and
  the complete durable/identity/packet/telemetry comparison still matches.

Do not substitute a key-rotator restart for the sealed-to-unsealed scheduler
proof. The 2026-07-13 replacement VM passed the durability portion of this
exercise, but its then-live scheduler wrote two failures and its then-live ACL
timer missed the containers-root ACL. The scheduler patch is deployed; the ACL
patch plus the SELinux/MCS, bind-recreation, Vault-readiness, and rollback
source candidate have passed static gates, but the combined remediated source
converge, daemon-restart, and long-running-service sealed-start proof remains
PENDING.

Confirm only the expected named volumes exist and that Redis has no named
persistent volume. Do not query or print Vault secret data as acceptance
evidence.

Record the full converge's sorted PostgreSQL security output: all 12
service-role/database decisions must match the exact allow/deny table in
[operations](operations.md), `postgres|postgres|true` must prove maintenance
access, each database owner must match its service role, all three exact role
attribute rows must be true, and `membership|0` must show that no membership
exists in either direction involving a service role. This query uses
`has_database_privilege` and reveals no password. On an unchanged second
converge, also compare the four stored verifier hashes through a root-only
digest or equality test rather than printing them; they must remain unchanged.
A green `pg_isready` probe is not ACL or SCRAM evidence. Any extra
service-role `CONNECT`, privilege-bearing attribute, membership, wrong owner,
or unnecessary verifier rewrite fails acceptance.

## 6. TLS, routing, and negative HTTP tests

From clients on the correct physical source networks, trust the issued test or
customer CA rather than using `-k`. Set environment-specific values:

```bash
export AIGW_DOMAIN=aigw.example.internal
export AIGW_CA=/path/to/aigw-trusted-ca.pem
export AIGW_INTERNAL_IP=10.20.0.10
export AIGW_ADM_IP=10.8.10.10
```

From an internal client:

```bash
curl --fail --silent --show-error --cacert "$AIGW_CA" \
  --resolve "auth.$AIGW_DOMAIN:443:$AIGW_INTERNAL_IP" \
  "https://auth.$AIGW_DOMAIN/realms/aigw/.well-known/openid-configuration" \
  >/dev/null

test "$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --cacert "$AIGW_CA" --resolve "auth.$AIGW_DOMAIN:443:$AIGW_INTERNAL_IP" \
  "https://auth.$AIGW_DOMAIN/admin/")" = 403

test "$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --cacert "$AIGW_CA" --resolve "api.$AIGW_DOMAIN:443:$AIGW_INTERNAL_IP" \
  "https://api.$AIGW_DOMAIN/key/list")" = 403
```

Also prove the internal source cannot connect to the ADM address, and an
unapproved source cannot connect to either published address. From the VPN/ADM
source, prove `admin`, `admin-portal`, `grafana`, `prometheus`, `vault`, and the
Keycloak admin console (`auth.<domain>/admin/`) are reachable with valid TLS.
Inspect the served chain and SANs:

```bash
openssl s_client -connect "$AIGW_INTERNAL_IP:443" \
  -servername "portal.$AIGW_DOMAIN" -CAfile "$AIGW_CA" </dev/null
```

Reject wildcard host bindings, unexpected certificates, hostname mismatch,
TLS verification bypass, or a Keycloak master/admin route on the internal
edge.

## 7. OIDC and authorization matrix

Use separate browser profiles and retrieve disposable lab passwords only from
the encrypted overlay. Never place them in this runbook, screenshots, or
command history.

| Test identity | Expected result |
|---|---|
| no session | redirected to Keycloak or rejected; no protected content |
| user without AI Gateway role | denied chat, developer, and admin functions |
| `aigw-users` only | chat allowed; key and admin functions denied |
| `aigw-developers` | own key list/mint/revoke and snippets allowed; admin denied |
| `aigw-admins` | developer functions plus portal admin; ADM gates allowed |

For each login, confirm the browser-visible issuer is exactly
`https://auth.<domain>/realms/aigw`, callback hosts stay on the expected
physical edge, and logout/new login removes old role effects. Specifically
prove that removing an admin/developer role invalidates or revalidates the
portal session before another privileged action; a stale cookie must not retain
authorization until its nominal session expiry.

Test each admin UI separately after Keycloak logout. Four oauth2-proxy
instances — for the LiteLLM Admin UI, Grafana, Prometheus, and Vault — sit on
the ADM leg and share the single `admin-ui` Keycloak client; all four
refresh/revalidate their cookies every five minutes and expire them after eight
hours. Privileged access must be rejected no later than the first refresh after
revocation; separately prove an inactive cookie cannot exceed the eight-hour
maximum. Every portal admin page read and mutation must deny the live-revoked
administrator immediately.

Each admin UI must first pass its own oauth2-proxy `aigw-admins` gate. Grafana
then consumes the proxied identity through its auth-proxy allow-list — its login
form and basic auth are disabled — so it presents no second login. The portal
admin surface is the dedicated `admin-portal` ASGI application on the ADM leg
(`admin-portal.<domain>` via traefik-adm on `net-admin-app`); the internal
user/developer portal never registers an admin surface. The `/admin` read
revalidates live admin authority on every request, and mutations add CSRF plus a
fresh step-up reauthentication bounded to roughly five minutes.

## 8. Samba AD and identity-controller lab acceptance

This section applies only to the lab overlay.

1. Confirm `samba-ad` is healthy, read-only, non-privileged, has only the
   reviewed capabilities, publishes no port, and joins only `net-identity`.
2. Sign into `admin-portal.<domain>/admin` as disposable `testadmin`, select
   **Reauthenticate with Keycloak**, then submit `INITIALIZE`.
3. Confirm status shows the durable controller and WIF broker ready, the lab
   LDAP provider ready, certificate fingerprints, and no
   `bootstrap_cleanup_required`. Private keys, bootstrap tokens, PKCS#12 data,
   and LDAP credentials must never appear.
4. Confirm only the three seeded Samba users are imported from the dedicated
   AI Gateway user OU; `svc-keycloak-ldap` must not appear.
5. Create capability groups below `/aigw-managed`, assign imported users, and
   prove fresh login changes the emitted roles and access matrix.
6. Prove an out-of-tree group, unknown capability, non-federated user,
   non-empty group deletion, and removal of the final managed administrator
   are rejected.
7. Adversarially race deletion of an empty recovery-admin group, addition of a
   recovery administrator to it, and removal of the existing last
   administrator. Pass only if the process-local topology lock serializes all
   three operations and at least one conflicting mutation fails without
   leaving zero managed administrators. This is single-worker evidence, not a
   multi-replica guarantee.
8. Create a second durable directory administrator for the lab, synchronize
   users, assign both durable administrators, and prove both can log in using
   Samba-owned passwords.
9. Remove disposable `testadmin` through the controlled Keycloak ADM process,
   sign out its sessions, and prove it can no longer authenticate. Do not leave
   seeded Keycloak-local identities in a customer deployment.

Run Samba consistency and LDAPS checks without exposing passwords:

```bash
docker compose -f docker-compose.yml -f docker-compose.lab.yml \
  --profile lab-ad exec -T samba-ad samba-tool dbcheck --cross-ncs
docker compose -f docker-compose.yml -f docker-compose.lab.yml \
  --profile lab-ad exec -T samba-ad \
  openssl s_client -connect samba-ad:636 -servername samba-ad \
  -CAfile /var/lib/samba-public/ca.pem </dev/null
```

Follow [identity operations](identity-operations.md) for user creation, manual
full sync, bind-password rotation, and recovery. Do not test partial-volume
reset or bootstrap recovery on retained state.

## 9. Developer key isolation and model path

First verify the non-human Open WebUI integration. Through the protected
LiteLLM management path, confirm exactly one active key matches both alias
`aigw-open-webui-service` and the encrypted-overlay candidate's SHA-256,
without printing the plaintext. Require owner `svc-open-webui`, service/project
`open-webui`, exact models `claude-sonnet`, `claude-haiku`, and `gpt`, exact
routes `/v1/models` and `/v1/chat/completions`, empty management permissions,
and a direct management request with that workload key to return 403. Its
model-list request must succeed after reconciliation.

Compare only digests of the encrypted-overlay `webui_secret_key` and the
deployed Open WebUI `WEBUI_SECRET_KEY`. Recreate Open WebUI and run an
unchanged converge; pass only if the digest stays identical and existing
application-signed session state remains valid. Never include either secret
or the workload key in test output.

Generate one browser-chat trace. It must identify the shared service owner
`svc-open-webui` and project `open-webui`; do not expect or claim trusted
per-human attribution. Prove a client/upstream `llm.user` value does not become
the canonical `aigw.user.id`. Record trusted per-human Open WebUI attribution
as **NOT IMPLEMENTED**. The per-human tests below apply to direct portal-issued
API keys, not the shared chat workload key.

As two different developer identities, mint one LiteLLM virtual key each for
the same allow-listed project. Prove each account can list and deactivate only
its own key. Attempting to submit another user's token/hash, another project,
or a fabricated owner must fail closed.

For each identity, capture the plaintext key only from the immediate successful
creation response. Navigate away, reload the inventory and snippets pages, use
browser back/forward cache navigation, and inspect the session cookie. The
plaintext must not reappear in HTML, snippets, cookies, server-side session
state, Docker logs, Loki, or Cribl; later snippets must contain `YOUR_KEY`.
With the first key still active, a second creation for the same owner/project
must be rejected. Explicitly deactivate the concrete current key, create a
replacement, and prove it is distinct. An expired or already blocked key must
not count as active. Perform the concurrent-create regression and pass only if
at most one key remains active. Keep the deployed portal at one container and
one Uvicorn worker until its process-local creation lock is replaced by a
distributed/database lock.

Read one disposable test key interactively and call an enabled model. Do not
use the LiteLLM master key:

```bash
read -rsp 'Disposable LiteLLM virtual key: ' AIGW_TEST_KEY; printf '\n'
curl --fail --silent --show-error --cacert "$AIGW_CA" \
  --resolve "api.$AIGW_DOMAIN:443:$AIGW_INTERNAL_IP" \
  "https://api.$AIGW_DOMAIN/v1/chat/completions" \
  -H "Authorization: Bearer $AIGW_TEST_KEY" \
  -H 'Content-Type: application/json' \
  --data '{"model":"claude-haiku","messages":[{"role":"user","content":"acceptance canary"}],"max_tokens":16}' \
  >/dev/null
unset AIGW_TEST_KEY
```

Pass only if the request traverses LiteLLM and Envoy, the provider sees the
expected workspace/credential, and no other workload makes direct vendor
connections. If no paid provider credential is approved for the lab, classify
an upstream 401 as a network-only pass only when request counters independently
prove LiteLLM and Envoy traversal. A 401 generated by LiteLLM before any Envoy
delta is NOT EXECUTED for the egress/provider lane—never relabel either case as
a successful model test.

## 10. Observability and sensitive-data handling

Generate a uniquely tagged, synthetic prompt. In Grafana Explore, prove:

- the trace appears in Tempo with the expected service/model and prompt-bearing
  span attributes;
- operational service logs appear in Loki and do not duplicate the full
  prompt or expose credentials;
- both Traefik edges retain method/status/vhost/timing metadata but omit
  `RequestPath`, `RequestLine`, headers, and query parameters; after a complete
  login/logout flow, Docker, Loki, and Cribl contain zero OAuth `code`,
  `id_token_hint`, or three-segment JWT shapes;
- span-derived request, error, and latency metrics appear in Prometheus;
- valid `litellm_request` spans contain exact `aigw.user.id`,
  `aigw.api_key.id`, `aigw.api_key.alias`, `aigw.project.id`, and
  `aigw.request.id` correlation attributes while preserving the original UTC
  timestamps, trace ID, and `gen_ai.input.messages`; missing, malformed,
  uppercase-hash, overlength/injection-like project, and non-LiteLLM canaries
  gain no invalid canonical attributes and produce no transform/export drops;
- for a portal-issued direct key, the spend row's hashed `api_key` joins the
  verification-token row that contains the authenticated owner and
  `metadata.aigw_project_id`; zero native LiteLLM project rows is expected.
  Require prompt/request/response objects in the spend row to remain empty and
  use the timestamped Tempo span as the prompt audit record. Never print or
  search for the plaintext bearer key as evidence;
- classify the shared Open WebUI key as service/project attribution only; do
  not claim its browser traffic is per-human until a trusted server-side
  identity propagation design has passed this matrix;
- the Cribl mock or approved external receiver records delivery without a
  collector feedback loop;
- a user without `aigw-admins` cannot cross the Grafana edge gate.

Then stop the Cribl receiver briefly on the disposable lab, generate bounded
telemetry, and restore it. Alloy must remain within its memory limit, retry
within its configured window, expose the failure, and recover without
recursive log amplification. Delete or expire the synthetic prompt under the
test retention policy. See [observability operations](observability-operations.md).

## 11. LiteLLM capacity and scaling acceptance

The current release baseline is one LiteLLM container with the default one
Uvicorn worker. Record its concurrency, streaming/non-streaming latency,
throughput, CPU/memory/PID headroom, PostgreSQL connections, Redis behavior,
Envoy errors, and Alloy drops before changing limits or process count.

If no scaling change is proposed, confirm the single-instance topology and
mark the multi-replica tests NOT APPLICABLE, not PASS. If workers or replicas
are changed, run the complete acceptance matrix in
[LiteLLM capacity and scaling](litellm-scaling.md). In particular, reject:

- unreviewed `docker compose --scale` service-name round robin;
- Docker-socket or label-based backend discovery;
- aggregate database pools that exceed the reserved connection budget;
- concurrent application-driven schema migrations;
- a load balancer that selects liveness-only or draining replicas;
- a stop/drain grace shorter than an approved in-flight stream; or
- a test that disables required prompt capture or authorization controls to
  improve throughput.

Pass a changed topology only after readiness removal, planned drain, replica
failure, credential/key propagation, shared-state outage, network isolation,
and an unchanged second converge all meet their declared bounds.

Any future HA design is a separate Kubernetes architecture accepted on its
own evidence; see the [scaling and HA posture](high-availability.md). Multiple
containers on the same Rocky host do not constitute host redundancy.

## 12. Stateful recovery and upgrade gate

Execute `scripts/state-backup.sh` to independent/off-host storage and perform a
destructive `scripts/state-restore.sh` drill on an isolated target, following
[operations](operations.md). For the vanilla lab VM-loss exercise, use
the explicit pending gates in the
[lab rebuild and restore rehearsal](archive/lab-dr-rehearsal.md). Test both a changed
stateful direct-image reference and a Dockerfile/context-only change beneath a
stateful custom build while its image tag remains unchanged. Prove
`scripts/pre-upgrade-check.sh` rejects a missing, stale, unavailable, or
hash-mismatched artifact, accepts the fresh matching receipt, gates Alloy and
lab Samba when their existing state-bearing containers would rebuild, and does
not demand a receipt on a container-free first deployment. A release cannot
pass merely because named volumes exist or a filesystem copy completed.

The recovery sequence is mandatory: `state-restore.sh` must exit zero with
zero running project containers, remove the target-local
`.state/bind-digest.key` as a restore epoch, and leave a `root:root 0600`
regular single-link marker containing only the authenticated artifact SHA-256.
Keep maintenance
ingress and the marker in place; run the full designated current-source Ansible
converge to replace captured configuration and repair exact bind modes; then
stream the separately held old share to `vault-unseal.sh`; then run
`aigw-runtime-up.sh -d --wait --wait-timeout 300`. The marker-aware converge
must recognize initialized, sealed restored Vault state and reject replacement
initialization. `vault-bootstrap.sh` is prohibited on this path. Only a
successful persistence/security comparison plus the final change/restart/
unchanged-converge gate permits marker removal and access reopening.

The 2026-07-13 first replacement-VM restore attempt exited 1 after the older
workflow started the captured graph with an unreadable root-owned Keycloak
realm bind tree. It is failed/non-evidence; the corrected offline procedure
was subsequently repeated in full and passed G4. The current-source sealed
converge, old-share unseal, and healthy runtime passed G5. The protected
receipts are indexed in the
[lab rebuild and restore rehearsal](archive/lab-dr-rehearsal.md), which controls the
final gate dispositions. The configured G6 lanes, including the
collector-only synthetic correlation batch, have now passed; real
Anthropic/WIF exchange/inference remains NOT EXECUTED. One host reboot passed
the durable-state comparison but exposed sealed-start rotation and Docker
parent-ACL defects. The scheduler fix is deployed; rollback-retention, ACL,
SELinux/MCS, bind-recreation, and Vault-readiness changes are source-tested but
not yet live. Exact predecessor key-rotator image recovery has passed under the
immutable schema-2 reference, but the remaining G7 live gates remain on
release hold.

At minimum prove:

- outer/nested extra paths, traversal, links, devices, sparse metadata,
  duplicate paths, and wrong profile volume sets are rejected while the live
  stack is still running; also prove the exact hostile-input ceilings:
  100,000 stack members, 2,000,000 members and 1 TiB declared per volume,
  2 TiB declared in total, and a 256 MiB DockerRootDir free reserve;
- the wipe helper has only `DAC_OVERRIDE`/`FOWNER`; the numeric-owner extraction
  helper adds only `CHOWN`; both are networkless, read-only,
  `no-new-privileges`, and drop every other capability;
- PostgreSQL logical backup restores all three databases, exact owners,
  service-role attributes, zero-membership boundary, and `CONNECT` ACLs;
- Vault file state, identity keys/state, and Keycloak state restore to matching
  controller/broker fingerprints when the pre-destroy marker retained those
  fields. A missing historical fingerprint is an evidence gap, not permission
  to invent a value or call current internal consistency a pre/post match;
- restored non-secret configuration has deterministic modes rather than
  controller-checkout modes: ordinary directories/files are `0755`/`0644`,
  explicit executables alone are executable, and the Keycloak and Traefik
  private bind trees retain their reviewed narrower ownership/modes;
- lab Samba's three volumes restore as one consistent set;
- Tempo/Loki/Prometheus retention state is either restored or explicitly
  accepted as disposable by policy;
- any Keycloak session-table count difference is classified from authenticated
  rows and realm policy. In the 2026-07-13 evidence, the 9+9 rows all had
  `offline_flag=0` and aged beyond the exact 1,800-second idle timeout; they are
  deterministic expired online sessions, not offline-session or durable-state
  loss;
- every historical digest is reproducible from its retained canonicalizer. If
  the pre-marker omitted that algorithm/provenance, record an evidence gap and
  use a documented supplemental canonicalizer plus authenticated dump hashes;
  never guess, pad, or silently replace the historical value;
- synthetic collector correlation proves the five canonical `aigw.*` fields,
  content/timestamp preservation, and zero transform/export drops before G6
  closes;
- before every planned custom build with an existing service, a healthy,
  running, zero-restart source image is retained under the immutable project/
  service/full-source-digest reference and recorded in the exact private
  schema-2 manifest. Reject moved references, ambiguous containers, missing
  health, Docker-context changes, and inspect/tag races. Also prove a
  container-free first build does not invent a predecessor and that its
  temporary proof is retired after a successful build marker;
- binary rollback testing uses the exact retained OCI identity. A rebuild that
  merely produces equivalent application files is not exact image recovery,
  and image rollback alone cannot undo an incompatible state/schema migration;
- a Docker restart restores the exact uid 473 Docker-root/containers-root/
  child/log ACL boundary within the timer limit without granting broad read or
  write on the Docker root, and a failed Docker enumeration makes the
  reconciler fail rather than silently pass;
- an explicit profile-aware restart of only the long-running services writes
  no startup rotation-history row while Vault is sealed; after stdin-only
  unseal, each deferred static job reaches the expected terminal outcome
  exactly once without a failed row or manual key-rotator-only restart;
- real Anthropic WIF exchange, Envoy traversal, LiteLLM inference, and derived
  telemetry are recorded as **NOT EXECUTED** when the external customer
  configuration is absent. An HTTP 401 with zero Envoy delta is not a pass;
- the restored system completes this entire runbook on an isolated target;
- a PostgreSQL password change follows the implemented local-socket
  reconciliation, changes only the intended SCRAM verifier, and passes the
  complete role/owner/membership/ACL verification followed by consumer health
  and encrypted-overlay rollback rehearsal, rather than only changing Compose
  environment values.

Mark this section **BLOCKED** if independent storage, separate age-key/hash
custody, a successful isolated restore, or a fresh pre-upgrade artifact is not
available. Tooling without a completed drill is not production evidence.

## 13. Final disposition

Record each section as PASS, FAIL, BLOCKED, or NOT APPLICABLE, with an owner
and ticket for every non-pass. Mandatory production sections cannot be waived
by calling the deployment a prototype. At minimum, production approval
requires:

- a clean full three-NIC converge and a second idempotent converge;
- firewall reload survival and negative packet tests;
- TLS, OIDC, role/session revocation, identity, and per-user key isolation;
- real inference through pinned egress and WIF/static-credential behavior as
  explicitly approved;
- prompt/log/metric delivery and capacity evidence;
- encrypted state plus a successful isolated backup/restore drill; and
- documented acceptance of every residual in `solution-map.md`.
