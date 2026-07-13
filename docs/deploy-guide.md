# Deployment Guide

This guide covers two distinct targets: a generic customer Rocky Linux 9 host
with three existing, statically addressed interfaces, and the committed
Parallels Rocky 9 lab profile used for local acceptance, including the
disposable Samba AD overlay. For the trust-boundary architecture read
[solution-map.md](solution-map.md); for recovery, upgrades, and troubleshooting
read [operations.md](operations.md); for the current release posture read
[project-status.md](project-status.md).

Ansible configures an existing host. It does not provision a VM, create a NIC
or NetworkManager profile, or change an address, route, gateway, DNS value, or
interface binding. It does persist the expected firewalld zone in the single
bounded `connection.zone` property of each supplied active profile, by exact
UUID and without cycling or reactivating the connection.

One converge brings up a single Compose project. The base stack is 24 services:
one `volume-init` one-shot plus 23 long-running services, spread across 18 of
the 20 pre-created Docker bridges, fronted by two Traefik instances, gated by
four oauth2-proxy OIDC reverse proxies, and served through two portals. The
Parallels lab overlay adds a Samba AD directory and an authoritative lab DNS
service, taking the graph to 25 long-running services plus `volume-init` and
using all 20 bridges.

## Production-readiness warning

The current stack is a security-focused prototype. It now enforces encrypted
backing for generic/customer state, reconciles existing PostgreSQL role
passwords, bounds Redis and Loki memory behavior, rotates the Vault audit file,
and has explicit in-container health checks on every long-running base/lab
service. Do not admit production data until the following remaining controls
are implemented and rehearsed:

- operator-provisioned/unlocked LUKS backing for both configured sensitive
  paths; Ansible verifies it but does not create or unlock it;
- a successful age-encrypted backup to independent/off-host storage and an
  isolated customer restore rehearsal using the provided scripts; the local
  replacement-VM lab has passed corrected offline restore, unseal/runtime, one
  controlled reboot, and durable-state comparison, but code presence and
  same-Mac evidence do not prove customer custody, Mac-host/site loss, or the
  customer's RTO/RPO;
- production Vault bootstrap/unseal/PKI/TLS instead of the lab 1-of-1 script;
- alert delivery/dashboards and customer capacity sizing; local filesystem
  alert rules exist but no Alertmanager/notification route is deployed;
- a fully rehearsed stateful upgrade/rollback procedure. Every long-running
  service has an explicit health contract, but health alone is not a rollback
  rehearsal or availability architecture. Traefik routing and Grafana
  datasource provisioning additionally require the functional probes described
  in the operations and acceptance runbooks.

The reboot exposed a sealed-Vault scheduler defect and a Docker parent-ACL
recovery gap. The scheduler remediation is deployed. The pre-build
rollback-retention, SELinux/MCS, bind-recreation, Vault-readiness, and
least-privilege ACL changes are source-tested but not yet live. The exact
predecessor key-rotator OCI image has been recovered and loaded under its
current content-addressed rollback reference, but the final controlled source
converge, Docker-daemon restart, separate long-running-service sealed-Vault
restart, and unchanged converge remain PENDING. This is a release hold, not a
waiver earned by the successful durable-state comparison or image recovery.

The [operations guide](operations.md) treats these as blockers, not completed
features, and [project-status.md](project-status.md) tracks the open gates. The
current Compose profiles are not HA; a future multi-host profile requires the
external infrastructure choices and service-specific design in the
[HA and rolling-update matrix](high-availability.md).

## Prerequisites

### Control node

The controller needs `ansible-core` 2.16 or newer, SSH key access to a
sudo-capable target account, and host-key verification left enabled — the
repository does not disable it. If the inventory uses a non-default
`ansible_port` or `ansible_ssh_private_key_file`, make that value available to
the controller's OpenSSH client. Bastion/ProxyJump sites must configure the
jump in `~/.ssh/config`; the key-only lockout probe deliberately does not
shell-split `ansible_ssh_common_args`. Install the pinned collections first:

```bash
ansible-galaxy collection install -r ansible/requirements.yml
```

That file pins `community.docker` 5.2.1, `community.general` 13.1.0, and
`ansible.posix` 2.2.0.

### Target VM

The target is Rocky Linux 9 with Python 3, and SELinux must already be enabled
with Rocky's `targeted` policy in `Enforcing` mode. The full playbook checks
this before any host mutation and fails closed when it is permissive or
disabled; it does not change the host enforcement mode. The host must present
three distinct, active IPv4 interfaces whose addressing and gateways are
already correct, exactly one main-table default route through the egress
interface, a real non-loopback DNS resolver reachable over one supplied
physical leg, working time synchronization (OIDC, TLS, and short-lived JWTs
depend on it), and outbound access for package/image retrieval and vendor API
traffic.

Provide enough capacity for the configured service limits. The base Compose
limits total roughly 19.6 GiB before the lab overlay adds a 2 GiB Samba limit
and a 64 MiB DNS limit. A 4-vCPU, 12-GiB, 40-GB VM is a low-volume lab only;
start production sizing from measured workload and prompt-retention growth,
normally with substantially more memory and encrypted storage.

For a generic/customer profile, `/var/lib/docker` (or the configured
`docker_data_root`) and `/opt/ai-gateway` must both resolve through a block
device with a `crypto_LUKS` ancestor before Ansible runs. The explicit
disposable Parallels inventory is the only committed opt-out.

The baseline role installs Docker CE, the Compose plugin, firewalld/nftables
dependencies, OpenSSL, `container-selinux`, SELinux policy tooling, the audit
client, the pinned Python Docker SDK, and signed EPEL's pinned
`age-1.3.1-1.el9` backup-encryption package. It validates Docker's daemon
configuration with `dockerd --validate`, explicitly enables Docker SELinux
integration, and does not start Docker until the host packet policy is live.

The same role installs `/etc/ssh/sshd_config.d/00-ai-gateway-hardening.conf`.
Before changing sshd it opens an independent controller connection with
password and keyboard-interactive authentication disabled, validates the
candidate and complete daemon configuration, reloads rather than restarts sshd,
evaluates the effective policy for the actual automation user, then opens a
second key-only connection and proves `sudo -n` still works. The result is
public-key-only SSH, no root login, and no TCP, Unix-socket, agent, X11,
tunnel, or user-controlled forwarding. Keep the first deployment's console and
existing SSH session available until the postflight passes.

## Inputs

Keep environment topology in a customer inventory/host-vars file or a separate
`--extra-vars` file. Keep credentials only in an Ansible-Vault/SOPS-encrypted
overlay. Do not turn the generic defaults or the Parallels profile into a
customer template.

### Connection and topology

The operator supplies topology through Ansible inventory variables, each of
which also accepts a controller `AIGW_*` environment fallback:

| Ansible variable | Controller environment equivalent | Meaning |
|---|---|---|
| inventory `ansible_host` | `AIGW_ANSIBLE_HOST` | SSH target |
| inventory `ansible_user` | `AIGW_ANSIBLE_USER` | sudo-capable SSH account (defaults to `ansible`) |
| `deployment_profile` | `AIGW_DEPLOYMENT_PROFILE` | descriptive profile; generic default is `generic-rocky9` |
| `nic_egress` | `AIGW_NIC_EGRESS` | interface owning the only default route |
| `nic_adm` | `AIGW_NIC_ADM` | administrator/VPN interface |
| `nic_internal` | `AIGW_NIC_INTERNAL` | internal-user interface |
| `eth0_ip`, `eth0_gateway` | `AIGW_EGRESS_IP`, `AIGW_EGRESS_GATEWAY` | existing egress address and next hop |
| `eth1_ip`, `eth1_gateway` | `AIGW_ADM_IP`, `AIGW_ADM_GATEWAY` | existing ADM address and next hop |
| `eth2_ip`, `eth2_gateway` | `AIGW_INTERNAL_IP`, `AIGW_INTERNAL_GATEWAY` | existing internal address and next hop |
| `vpn_client_cidr` | `AIGW_VPN_CLIENT_CIDR` | only source range allowed to ADM TCP/22 and TCP/443 |
| `internal_cidr` | `AIGW_INTERNAL_CIDR` | only source range allowed to internal TCP/443 |
| `container_dns_server` | `AIGW_CONTAINER_DNS_SERVER` | explicit real resolver; loopback/link-local/multicast rejected |

Despite their historical `eth0_*` names, the address variables are semantic;
the actual interfaces may be named `enp*`, `ens*`, or otherwise. The full
preflight validates names, live addresses, gateways, one default route, source
CIDRs, route-table IDs/names, resolver reachability, Docker subnet overlap, and
fixed workload IP placement before the first mutating role.

NetworkManager is authoritative for an active interface's firewalld zone on
Rocky 9. A permanent firewalld interface binding alone is insufficient: after
reload, a profile whose saved `connection.zone` is blank can re-advertise its
interface into the default zone. The firewalld role resolves the one active
UUID for each supplied physical interface, requires all three UUIDs to be valid
and distinct, reads the saved zone, and changes only a drifted
`connection.zone`. It never invokes `nmcli connection up`, `nmcli device
reapply`, or any addressing operation. The dispatcher reasserts only runtime
firewalld ownership after relevant link events; it does not modify the saved
profile. Verification requires the same exact interface/zone mapping in the
saved profile, firewalld runtime, and permanent firewalld configuration.

Rocky 9 normally ships the pristine table-name registry at
`/usr/share/iproute2/rt_tables`; a genuinely vanilla host may have no
`/etc/iproute2/rt_tables`. That absence is not topology drift. Preflight reads
an existing `/etc` file only when it is a regular non-symlink, otherwise it uses
the regular vendor file. During the mutating routing role, Ansible copies the
vendor registry to the missing `/etc` path without overwriting an existing
administrator file, then adds only the managed table 101/102 block.

`manage_networking=false` and `manage_firewalld=false` skip their roles but do
not turn a single-NIC host into a supported topology. Use the full three-NIC
lab or customer layout for meaningful validation.

### Rendered Compose environment

Ansible renders these inventory values into `/opt/ai-gateway/.env`.
`compose/.env.example` is the annotated template and the authoritative contract
for direct Compose use; the exact keys are what the containers read. Secret
values in the example are intentionally blank so Compose's `${VAR:?}` guards
fail closed until each is populated.

`DEPLOYMENT_PROFILE` selects the profile (`generic-rocky9` by default,
`parallels-rocky9-lab` for the lab; `aigw-compose.sh` and `vault-bootstrap.sh`
key off this exact value). `DOMAIN` is the base domain every router host is
built from. `ETH1_IP` is the ADM leg that `traefik-adm` binds `:443` on, and
`ETH2_IP` is the internal leg that `traefik-int` binds `:443` on — nothing
binds the egress IP or `0.0.0.0`. `CONTAINER_DNS_SERVER` is the approved
non-loopback resolver.

A set of fixed workload IPs pin the few containers that other components
address directly: `ENVOY_EGRESS_IP` (the sole external-DNS/TCP-443 workload at
`172.28.0.2`), `ALLOY_INTERNAL_IP`, `ALLOY_TELEMETRY_IP`,
`ALLOY_OBSERVABILITY_IP`, `PROMETHEUS_OBSERVABILITY_IP`, `TEMPO_INGEST_IP`,
`TRAEFIK_INT_CHAT_IP`, `TRAEFIK_INT_PORTAL_IP`, `TRAEFIK_ADM_ADMIN_IP`,
`TRAEFIK_ADM_GRAFANA_IP`, and the lab-only `LAB_DNS_IP`. These must stay inside
their bridge subnets and off the reserved gateway address; the preflight
rejects a value that is out of range or collides with a reserved address.

Ansible also writes one keyed `AIGW_BIND_DIGEST_*` content marker per service
whose read-only bind sources must be intact before it starts:
`AIGW_BIND_DIGEST_TRAEFIK_INT`, `_TRAEFIK_ADM`, `_LITELLM`, `_OPEN_WEBUI`,
`_KEYCLOAK`, `_VAULT`, `_POSTGRES`, `_REDIS`, `_ALLOY`, `_PROMETHEUS`, `_LOKI`,
`_TEMPO`, `_GRAFANA`, `_CRIBL_MOCK`, and the lab-only `_LAB_DNS`, `_SAMBA_AD`,
`_KEY_ROTATOR_LAB`. They are blank in the example so a direct Compose start
stays fail-closed until Ansible has computed the digests; a changed digest
recreates only the affected consumer.

### Sensitive state backing

| Variable | Default | Contract |
|---|---|---|
| `docker_data_root` | `/var/lib/docker` | must match Docker's live `DockerRootDir` after converge |
| `encrypted_state_paths` | Docker data root and `/opt/ai-gateway` | each path is resolved to its backing block-device ancestry |
| `require_encrypted_state` | `true` | refuses full and stack-only customer deployment unless every path has a `crypto_LUKS` ancestor |
| `require_preupgrade_backup` | `true` | refuses changed stateful direct-image references or custom build-input/image-ID drift without an available, hash-matching backup receipt no older than 24 hours |

Only `ansible/inventory/host_vars/lab-aigw01.yml` disables encrypted-state and
pre-upgrade-backup enforcement. Do not copy those opt-outs into a customer
inventory. If the customer uses different mount points, update the complete path
list; do not merely change Docker's root and leave rendered secrets,
certificates, or backup staging under unencrypted `/opt`.

### Cribl export

The default is the in-stack plaintext `cribl-mock:4317`. A customer endpoint
requires all of these in a reviewed inventory overlay:

```yaml
cribl_external_export_enabled: true
cribl_otlp_endpoint: "192.0.2.40:4317"       # literal IP:port
cribl_otlp_allowed_cidr: "192.0.2.40/32"    # exact same IP
cribl_otlp_allowed_port: 4317
cribl_otlp_insecure: false
cribl_otlp_server_name: "cribl-worker.internal.example"
cribl_otlp_ca_file: "/etc/ssl/certs/aigw-ca.pem"
```

The endpoint must route over `nic_internal`. Alloy receives no external DNS
exception, so a hostname in `cribl_otlp_endpoint` is rejected by the network
contract; TLS SNI/name validation remains the DNS name supplied separately. The
mounted CA bundle must include the Cribl issuing CA as well as any internal CA
consumers require; the lab Vault bootstrap currently overwrites that file, so
external-Cribl CA lifecycle needs an explicit production integration. The
current exporter sends no bearer token or client certificate; extend and
validate the exporter before cutover if the customer requires application-layer
Cribl authentication.

### Encrypted secret overlay

The ordinary stack requires all of the following. The role validates lengths,
rejects obvious placeholders, and generally permits only `[A-Za-z0-9_-]` so
Compose interpolation and database URLs remain unambiguous.

| Variable | Purpose / constraint |
|---|---|
| `pg_super_password` | Postgres superuser; 24+ characters |
| `pg_litellm_password`, `pg_keycloak_password`, `pg_rotator_password` | isolated DB users; each 24+ |
| `kc_admin_password` | temporary Keycloak bootstrap user; 24+ |
| `kc_bootstrap_admin_client_secret` | one-time Keycloak bootstrap service client; 32+ |
| `litellm_master_key` | LiteLLM administrative key; 32+, normally `sk-...` |
| `litellm_salt_key` | LiteLLM credential encryption; 32+ |
| `redis_password` | Redis authentication; 32+ |
| `webui_litellm_key` | dedicated scoped LiteLLM virtual key, never the master key |
| `webui_secret_key` | stable 32+ character Open WebUI application/session signing secret; never regenerate during converge or replacement |
| `webui_oidc_client_secret`, `portal_oidc_client_secret`, `admin_portal_oidc_client_secret`, `oauth2_proxy_client_secret` | OIDC clients; each 32+ and alphanumeric-safe |
| `oauth2_proxy_cookie_secret` | stable, exactly 32 alphanumeric bytes |
| `portal_session_secret`, `admin_portal_session_secret` | sign the two portals' role-bearing sessions; each 32+ and mutually distinct |
| `rotator_internal_token` | admin portal → rotator internal API; 32+ |
| `portal_identity_token` | dev portal → rotator identity API; 32+, distinct from `rotator_internal_token` |
| `grafana_admin_password` | Grafana local break-glass second factor behind its proxy; 24+ |

The two portals run one image but authenticate independently, so the dev-portal
and admin-portal OIDC-client, session, and rotator-token secrets are separate
values. The lab profile additionally requires five 16+ character secrets:

- `samba_ad_admin_password`
- `samba_ad_bind_password`
- `samba_user_lab_admin_password`
- `samba_user_lab_developer_password`
- `samba_user_lab_user_password`

Edit the encrypted overlay without producing a plaintext working copy:

```bash
ansible-vault edit ansible/inventory/group_vars/gateway/vault.yml
```

Do not print, diff, or commit decrypted values. The role renders
`/opt/ai-gateway/.env` mode `0600`. It also renders Redis authentication sources
beneath the root-only `/opt/ai-gateway/secrets` directory as `root:65532` mode
`0440`: Redis receives only an SHA-256 ACL verifier, while its authenticated
health probe reads the separate password file. Neither value is placed in the
Redis server's command or environment metadata. The lab profile adds the
root-owned Samba Docker-secret sources in the same directory. These files must
never enter source control or ordinary backups unencrypted.

The Redis value used before this file-based design was found in Docker
`Config.Cmd`, treated as exposed, and rotated in the encrypted overlay. Do not
record that value in a ticket, log, or evidence bundle. Render validation now
asserts that the server command/environment remain secretless and that both
authentication sources are regular, single-link files with the exact private
ownership above.

Ansible also assigns deterministic deployment modes rather than preserving
controller-checkout modes. Reviewed non-secret directories/files are
`root:root 0755/0644`; only explicit scripts and the PostgreSQL initializer are
executable. Keycloak's realm directory/files are `root:65532 0750/0640`, the
Traefik certificate directory/private key are `root:65532 0750/0640`, and public
certificates remain `root:root 0644`. The verify role asserts these contracts.
This is required for non-root DHI containers and for safe recovery from an
archive installed as root.

On an authenticated recovery, `state-restore.sh` exits with zero running project
containers and a `root:root 0600` marker containing the authenticated artifact
SHA-256. Keep maintenance ingress and that marker in place while the full
designated current-source Ansible play replaces captured configuration and
repairs bind ownership. Only then supply the old separately held Vault share and
run the complete runtime wait. Marker-aware Ansible requires an initialized
restored Vault and rejects replacement initialization; `vault-bootstrap.sh` is
valid only for a fresh uninitialized deployment with no restore marker.

### DNS and certificates

Use split DNS where necessary. The internal leg publishes `auth`, `chat`, `api`,
and `portal`, which resolve to the internal host address. The ADM leg publishes
`admin`, `admin-portal`, `grafana`, `prometheus`, `vault`, and `auth`, which
resolve to the ADM host address. There is no separate `keycloak` hostname:
`auth.DOMAIN` is dual-homed. Resolved to the internal address it serves the
`aigw` realm, and the internal router scopes it to `/realms/aigw` and
`/resources` so the master realm and admin paths are denied. Resolved to the ADM
address it is the Keycloak administration console; the ADM router permits
`/admin/`. Point administrators at `auth` on the ADM address, not the internal
one.

Four oauth2-proxy reverse proxies sit on the ADM leg behind `traefik-adm`, each
enforcing the `aigw-admins` group before its UI: `admin` (LiteLLM Admin UI),
`grafana`, `prometheus`, and `vault`. Grafana runs in auth-proxy mode behind
`oauth2-proxy-grafana` with its login form disabled, trusting the proxied
identity and keeping `grafana_admin_password` only as a local break-glass second
factor. Keycloak (via ADM `auth`) and Vault still require their own
administrator/token login after the edge gate. The separate `admin-portal` is
the only ADM UI that uses application-native OIDC directly rather than an
oauth2-proxy gate.

The same wildcard certificate covers both Traefik instances. Ansible creates a
seven-day self-signed placeholder only so the first stack can start. The lab
Vault script replaces it with a test-root-issued certificate. Production must
provide a customer-rooted chain and a renewal procedure before access is opened.
Traefik currently consumes certificate files; Vault ACME is a design option, not
implemented configuration.

The Parallels overlay supplies this split view through an authoritative,
non-recursive `aigw.internal` CoreDNS service. It publishes TCP and UDP 53 on
the exact ADM and internal lab addresses, not on the egress address, and has no
forwarder. Its dedicated ordinary bridge has no peers; it exists because Docker
29 does not publish host ports for a container attached only to an
`internal: true` bridge. `DOCKER-USER` and the independent nftables guard deny
DNS-container egress. Generic/customer deployment does not start this lab DNS
service and must supply equivalent records through customer DNS.

Before building Envoy, independently validate the committed narrowed CA bundles
from trusted network vantage points. A vendor issuing-CA change requires a
reviewed bundle update and Envoy rebuild; see
`services/egress-proxy/README.md`.

## Generic Rocky 9 deployment

First verify the customer-owned topology without changing it:

```bash
ip -br -4 address
ip -4 route show table main
ip -4 route get <ADM_GATEWAY> oif <ADM_INTERFACE>
ip -4 route get <INTERNAL_GATEWAY> oif <INTERNAL_INTERFACE>
```

Supply topology through a protected file such as
`/secure/customer-topology.yml`, set the SSH target, and confirm reachability:

```bash
export AIGW_ANSIBLE_HOST=<VM_MANAGEMENT_ADDRESS>
export AIGW_ANSIBLE_USER=<SUDO_ACCOUNT>
ansible -i ansible/inventory/hosts.yml gateway -m ping
```

Then run the full ordered converge. The vault password unlocks the encrypted
secret overlay; the extra-vars file carries the non-secret topology:

```bash
ansible-playbook -i ansible/inventory/hosts.yml ansible/site.yml \
  -e @/secure/customer-topology.yml --ask-vault-pass
```

The role order in `site.yml` is deliberate:

1. preflight requires Rocky `targeted` SELinux to be enabled and enforcing,
   then validates topology, collision constraints, and encrypted backing for
   every configured sensitive state path;
2. policy routing installs additive tables/rules and persistence;
3. firewalld persists only the active profiles' `connection.zone` values, then
   native nftables and atomic `DOCKER-USER` protection go live;
4. Docker is installed/configured and then started behind that policy;
5. all 20 segmented bridges are created and pinned to stable bridge names (the
   base stack uses 18 of them; `net-identity` and `net-lab-dns` are lab-only);
   two bridges are no-peer port-publication bridges whose container egress
   remains denied;
6. stack configuration is rendered; exact read-only bind-source file-context
   rules and per-service keyed bind digests are reconciled; PostgreSQL starts
   locally; four desired passwords, three exact least-privilege service-role
   contracts, three database owners, zero service-role memberships, and the
   complete `CONNECT` matrix are reconciled without secret task output; and
   changed stateful images pass the recent-backup gate;
7. the versioned state-volume initializer runs only when absent, previously
   failed, definition-changed, or when one of the eight exact owner/group/mode
   contracts has drifted, and its result is verified;
8. each custom image's effective build definition and allow-listed context are
   compared with the root-only `.state/compose-build-inputs.json` manifest; the
   planner's domain-separated, length-framed stream prevents structural record
   collisions, and the pre-upgrade gate uses this same planner so source-only
   drift beneath a stable tag cannot bypass backup enforcement. The exact
   running predecessor is retained under an immutable content-addressed
   reference before a planned build; only missing or changed images are built,
   after which Compose starts with implicit builds disabled. The dev-portal
   build additionally installs its complete transitive, exact-pinned,
   SHA-256-hashed `requirements.lock` with pip `--require-hashes`; validation
   proves the direct pins are a subset and forbids production installation from
   direct-only `requirements.txt`. The controller-only
   `scripts/safe-inventory-marker.py` is validated locally but intentionally
   excluded from the VM operational-script allow-list; and
9. audit-rotation, routing, firewall, listener, network, storage-root, SELinux
   MCS/bind/runtime-type, zero-AVC, and lab Samba assertions run.

The first converge intentionally cannot report the whole graph ready because
Vault is uninitialized/sealed and key-rotator's `/readyz` requires both a
database query and authenticated unsealed Vault access. It waits only for the
bootstrap-independent core and prints the explicit Vault gate. A subsequent
converge with ready Vault waits for the complete graph; the lab
`vault-bootstrap.sh` also ends with a full profile-aware Compose wait. An
initialized and unsealed Vault is never eligible for that bootstrap exception:
if its strict readiness probe fails, the converge stops instead of allowing
Vault or key-rotator health failures through the reduced wait.

The initialization/seal-state command fixes the isolated listener transport
explicitly with `vault status -address=http://127.0.0.1:8200 -format=json`;
never rely on the Vault CLI's default HTTPS address for this intentionally
plaintext internal lab listener.

For an unchanged second converge, record the initializer's definition hash and
start/finish timestamps plus every long-running container ID and restart count.
All must remain unchanged. The initializer reruns only for a definition change
or managed-volume metadata drift; ordinary lifecycle starts exclude it. In
particular, preserve the Vault container ID and verify that it remains healthy
and unsealed. A real change to Vault's own probe build context, base-image build
argument, or service definition intentionally recreates Vault; plan the normal
unseal procedure for that change. An application-only build-input change does
not rebuild the Vault image.

Generic deployment does not automatically configure a customer LDAP server.
Configure real AD/LDAP through a separately reviewed Keycloak overlay or
administrator procedure before using the portal group workflow. The Samba
overlay is intentionally unavailable in the generic profile. The portal also
does not self-bootstrap its first administrator: before identity-controller
initialization, a controlled Keycloak/customer-IdP procedure must establish at
least one pre-existing `aigw` realm user whose token carries `aigw-admins`.
Document that temporary grant and remove it only after two durable customer
administrator identities have been proved. See
[identity operations](identity-operations.md) for the full procedure.

## Explicit Parallels lab deployment

The only committed lab topology is:

| Purpose | Interface | Address / gateway |
|---|---|---|
| egress | `enp0s5` | `10.211.55.3` / `10.211.55.1` |
| ADM | `enp0s7` | `10.8.10.10` / `10.8.10.2` |
| internal | `enp0s8` | `10.20.0.10` / `10.20.0.2` |

The lab resolver is `10.211.55.1`; approved sources are `10.8.10.0/24` and
`10.20.0.0/24`. `site.yml` has an additional assertion that the named
`parallels-rocky9-lab` profile matches those exact facts, and `lab.yml` sets the
SSH target to `10.8.10.10` directly.

The committed lab inventory also enables the reviewed secret-free external image
seed because the clean VM has no DHI registry credential. Before the first
converge, pre-stage the archive and its manifest at the exact remote paths
declared in `inventory/host_vars/lab-aigw01.yml`, as regular non-symlink
`root:root` files with mode `0600`. The role verifies both SHA-256 values,
platform/schema, and all 22 immutable image IDs before proceeding. See
[offline external-image seeding](offline-image-seed.md) for the transfer
contract, prune recovery, marker behavior, and generic opt-in rules.

Deploy it with no generic topology overrides:

```bash
ansible-playbook -i ansible/inventory/lab.yml ansible/site.yml \
  --ask-vault-pass
```

This automatically selects `docker-compose.lab.yml`, enables profile `lab-ad`,
starts Samba on isolated `net-identity`, mounts its passwords as Docker secret
files, and makes Keycloak wait for hostname-verified LDAPS health. It also seeds
one Keycloak-local test administrator from encrypted inventory
(`aigw_seed_test_users`, off by default and on only in the lab) so an operator
can enter the portal before LDAP federation exists. Samba seeds `lab-admin`,
`lab-developer`, and `lab-user`; their passwords remain in the encrypted overlay
and the directory itself.

For manual Compose commands on the lab, always include the overlay/profile:

```bash
cd /opt/ai-gateway
docker compose -f docker-compose.yml -f docker-compose.lab.yml \
  --profile lab-ad ps
```

The deployed `scripts/aigw-compose.sh` selects exactly this file/profile set
from `DEPLOYMENT_PROFILE`; prefer it in operator scripts. Using only the base
file for `down` or recovery leaves the Samba service and its state outside the
intended operation.

## First bootstrap after Compose starts

Run the lab/test Vault bootstrap from `/opt/ai-gateway`. Prompt for any optional
vendor seed keys so they do not enter shell history:

```bash
cd /opt/ai-gateway
read -rsp 'Anthropic seed key (optional): ' ANTHROPIC_API_KEY; printf '\n'
read -rsp 'OpenAI seed key (optional): ' OPENAI_API_KEY; printf '\n'
export ANTHROPIC_API_KEY OPENAI_API_KEY
sudo --preserve-env=ANTHROPIC_API_KEY,OPENAI_API_KEY ./scripts/vault-bootstrap.sh
unset ANTHROPIC_API_KEY OPENAI_API_KEY
```

This is a lab/test bootstrap: a single 1-of-1 unseal share, a local file
backend, an internally generated test root, and a plaintext listener isolated on
`net-vault`. The script refuses to run unless `DEPLOYMENT_PROFILE` is
`parallels-rocky9-lab`, or `AIGW_ALLOW_INSECURE_VAULT_BOOTSTRAP` is set to the
exact acknowledgement string for an explicitly disposable non-Parallels test VM.
It is not the customer Vault initialization path and is forbidden on the restore
path. Immediately move its generated unseal key/root token into approved offline
custody and remove the plaintext `secrets/vault-init.json` as the script
instructs; `state-backup.sh` refuses to run while that file is co-located with
Vault state. After every reboot Vault is sealed again — reuse the stdin-only
`scripts/vault-unseal.sh` helper, which never places the share in argv,
environment, container config, or logs.

Next, establish the first administrator. Sign in to Keycloak over the ADM
address (`auth.DOMAIN` resolved to the ADM leg) using the server bootstrap
administrator. For a generic deployment, use the approved customer IdP or
controlled Keycloak process to establish the required pre-existing `aigw` realm
user with `aigw-admins`; the portal cannot create its own first administrator.
Only the Parallels lab seeds a disposable Keycloak-local `testadmin`. Then
follow [identity operations](identity-operations.md) to initialize the
Vault-backed controller, configure lab Samba LDAPS federation where applicable,
create authorization groups, hand off to durable administrators, and remove the
disposable lab user with `scripts/remove-lab-local-keycloak-users.py`.

Set `WEBUI_LITELLM_KEY` in the encrypted overlay to a dedicated high-entropy
`sk-*` workload key that is distinct from `LITELLM_MASTER_KEY`. After LiteLLM is
ready, Ansible idempotently creates or updates that exact custom virtual key as
alias `aigw-open-webui-service`, owner `svc-open-webui`, and project
`open-webui`. It permits only `/v1/models` and `/v1/chat/completions` for the
exact three configured model aliases. Alias or hash collisions fail closed;
reconciliation updates by stored hash and never emits the plaintext key. Do not
mint this key manually and never substitute `LITELLM_MASTER_KEY`. Also set one
high-entropy `webui_secret_key` and retain it for the lifetime of the
installation; Ansible supplies it as `WEBUI_SECRET_KEY`, and changing it during a
converge or container replacement invalidates active Open WebUI sessions and
prevents replicas from sharing application-signed state.

If static vendor keys were seeded after the rotator's run-once startup jobs, use
the portal admin page to trigger `static-anthropic` and/or `static-openai`.
Confirm success in rotation history before testing models. On a sealed boot, the
patched scheduler must defer these jobs without a failed history row and retry
after unseal; do not restart the container to manufacture that result. Configure
Anthropic WIF or OpenAI automated rotation only after their external
identifiers/admin material are present and the static fallback is understood; see
[Anthropic WIF](anthropic-wif-bootstrap.md).

Realm JSON is imported only into an empty Keycloak database. Editing a realm
template later does not update an existing realm automatically. Domain, callback,
client-secret, or mapper changes require a deliberate Keycloak Admin API/UI
update or a destructive empty-database reimport.

When bootstrap is complete, run the acceptance checks in
[test-runbook.md](test-runbook.md) before treating the deployment as usable.

## Stack-only rollout

After a successful full converge, application/config updates can use the
app-only playbook:

```bash
ansible-playbook -i <inventory> ansible/deploy-stack-only.yml \
  --ask-vault-pass
```

It runs only `docker_stack` and `verify`, and refuses to proceed unless the live
`DOCKER-USER` identity pin, native container-to-host guard, Docker SELinux state
on the reviewed data root, and every external Docker network match the declared
firewall/network ABI in `group_vars`. If it refuses, run the full `site.yml`; do
not bypass the check or recreate networks manually. For a planned custom build
with an existing service, current source also requires successful retention of
the exact healthy running image under an immutable
project/service/source-digest rollback reference and a private schema-2 atomic
manifest before building. Build-input digests use a domain-separated,
length-framed stream so file contents cannot absorb the following inventory
record. A one-converge legacy-digest comparison can migrate the old manifest
without an unnecessary build, but only the framed digest is persisted. These
controls are not substitutes for the encrypted state backup or schema rollback
test and, at this documentation checkpoint, have not yet completed the live G7
deployment gate.
