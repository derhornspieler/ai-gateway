# AI Gateway — Ansible Deployment Runbook

This runbook is the condensed, execution-order procedure for deploying AI
Gateway onto a customer-provided Rocky Linux 9 VM with the repository's
Ansible playbooks. It tells the deploying engineer exactly what to prepare,
what values to supply, and in what order to run each step. The
[deployment guide](deploy-guide.md) remains the authoritative reference for
the rationale, edge cases, and full validation behavior behind each step;
section references below point into it.

**Audience:** an infrastructure engineer with SSH and sudo access to the
target VM and permission to manage the customer's DNS and certificate
issuance.

**Scope:** the `generic-rocky9` profile (one Docker Compose project on one
VM). The `rocky9-lab` profile differs only where noted.

## 1. Before you begin

Confirm every item below before running any playbook. The preflight fails
closed on each of these, but confirming them first avoids a failed first run.

| # | Requirement | Detail |
|---|---|---|
| 1 | Control node | `ansible-core` 2.16+, SSH key access to a sudo-capable account on the VM, host-key verification enabled |
| 2 | Target OS | Rocky Linux 9 with Python 3 |
| 3 | SELinux | Rocky `targeted` policy already **Enforcing** — the playbook verifies this and will not convert a permissive or disabled host |
| 4 | Interfaces | Three distinct, active, already-addressed IPv4 interfaces (egress, ADM, internal); exactly one main-table default route, through the egress interface |
| 5 | DNS resolver | A real, non-loopback resolver reachable over a supplied physical leg |
| 6 | Time sync | Working NTP/chrony (OIDC, TLS, and short-lived JWTs depend on it) |
| 7 | Encrypted storage | `/var/lib/docker` (or the configured `docker_data_root`) and `/opt/ai-gateway` must resolve through a `crypto_LUKS` block-device ancestor |
| 8 | Capacity | Base service limits total ≈ 19.6 GiB memory. A 4-vCPU / 12-GiB / 40-GB VM is a low-volume lab baseline only; size production from measured workload (see the [scaling posture](high-availability.md)) |
| 9 | Outbound access | Package/image retrieval and vendor API traffic (or a completed [offline image seed](offline-image-seed.md)) |

Install the pinned collections once on the control node:

```bash
ansible-galaxy collection install -r ansible/requirements.yml
```

## 2. Values the engineer must supply

### 2.1 Connection and network topology (non-secret)

Provide these in an environment-specific inventory or `--extra-vars` file
(for example `/secure/customer-topology.yml`). Every variable also accepts
the listed `AIGW_*` environment variable on the control node. None have
usable defaults except where shown; the playbook rejects empty values before
mutating the host.

| Ansible variable | Environment equivalent | Value to supply |
|---|---|---|
| `ansible_host` | `AIGW_ANSIBLE_HOST` | SSH management address of the VM |
| `ansible_user` | `AIGW_ANSIBLE_USER` | sudo-capable SSH account (default `ansible`) |
| `deployment_profile` | `AIGW_DEPLOYMENT_PROFILE` | `generic-rocky9` (default) or `rocky9-lab` |
| `nic_egress` | `AIGW_NIC_EGRESS` | interface name owning the only default route |
| `nic_adm` | `AIGW_NIC_ADM` | administrator/VPN interface name |
| `nic_internal` | `AIGW_NIC_INTERNAL` | internal-user interface name |
| `eth0_ip` / `eth0_gateway` | `AIGW_EGRESS_IP` / `AIGW_EGRESS_GATEWAY` | existing egress address and next hop |
| `eth1_ip` / `eth1_gateway` | `AIGW_ADM_IP` / `AIGW_ADM_GATEWAY` | existing ADM address and next hop |
| `eth2_ip` / `eth2_gateway` | `AIGW_INTERNAL_IP` / `AIGW_INTERNAL_GATEWAY` | existing internal address and next hop |
| `vpn_client_cidr` | `AIGW_VPN_CLIENT_CIDR` | only source range permitted to ADM TCP/22 and TCP/443 |
| `internal_cidr` | `AIGW_INTERNAL_CIDR` | only source range permitted to internal TCP/443 |
| `container_dns_server` | `AIGW_CONTAINER_DNS_SERVER` | real resolver address; loopback, link-local, and multicast values are rejected |

The `eth0_/eth1_/eth2_` names are semantic labels; actual interfaces may be
named `enp*`, `ens*`, or otherwise. Ansible validates the supplied names,
live addresses, gateways, default route, and source CIDRs against the running
host and stops before the first mutating role on any mismatch
(deploy-guide §“Connection and topology”).

### 2.2 Domain and DNS

Supply the base `DOMAIN` for the stack. The customer DNS must resolve the
service hosts (`portal`, `auth`, `admin`, `admin-portal`, `grafana`,
`prometheus`, `vault`, and the chat/API hosts) to the correct leg — the
verify role checks them (deploy-guide §“DNS and certificates”).

### 2.3 Secrets (encrypted overlay)

All credentials live only in the Ansible-Vault-encrypted overlay
`ansible/inventory/group_vars/gateway/vault.yml`. Edit it in place — never
create a plaintext working copy:

```bash
ansible-vault edit ansible/inventory/group_vars/gateway/vault.yml
```

Prepare values that meet these enforced constraints (characters are generally
restricted to `[A-Za-z0-9_-]`; the role rejects short values and obvious
placeholders):

| Secret | Constraint |
|---|---|
| `pg_super_password` | 24+ characters |
| `pg_litellm_password`, `pg_keycloak_password`, `pg_rotator_password` | 24+ each |
| `kc_admin_password` | 24+ (temporary bootstrap user) |
| `kc_bootstrap_admin_client_secret` | 32+ (one-time bootstrap client) |
| `litellm_master_key` | 32+, normally `sk-...` |
| `litellm_salt_key` | 32+ |
| `redis_password` | 32+ |
| `webui_litellm_key` | scoped LiteLLM virtual key — never the master key |
| `webui_secret_key` | 32+, stable for the life of the deployment |
| `webui_oidc_client_secret`, `portal_oidc_client_secret`, `admin_portal_oidc_client_secret`, `oauth2_proxy_client_secret` | 32+ each |
| `oauth2_proxy_cookie_secret` | exactly 32 alphanumeric bytes |
| `portal_session_secret`, `admin_portal_session_secret` | 32+ each, mutually distinct |
| `rotator_internal_token`, `portal_identity_token` | 32+ each, mutually distinct |
| `grafana_admin_password` | 24+ |

The `rocky9-lab` profile additionally requires the five 16+ character Samba
lab secrets (`samba_ad_admin_password`, `samba_ad_bind_password`, and the
three `samba_user_lab_*` passwords).

### 2.4 Optional overrides

Review these only when the customer environment requires them
(deploy-guide §“Inputs”): `docker_data_root`, `encrypted_state_paths`,
`require_encrypted_state`, `require_preupgrade_backup`,
`aigw_management_ssh_port`, and the external Cribl export block
(`cribl_external_export_enabled` and its endpoint/TLS variables).

## 3. Deployment procedure

Run each step in order; do not skip a verification step.

1. **Verify the customer topology read-only** on the VM before any playbook:

   ```bash
   ip -br -4 address
   ip -4 route show table main
   ip -4 route get <ADM_GATEWAY> oif <ADM_INTERFACE>
   ip -4 route get <INTERNAL_GATEWAY> oif <INTERNAL_INTERFACE>
   ```

2. **Confirm controller connectivity:**

   ```bash
   export AIGW_ANSIBLE_HOST=<VM_MANAGEMENT_ADDRESS>
   export AIGW_ANSIBLE_USER=<SUDO_ACCOUNT>
   ansible -i ansible/inventory/hosts.yml gateway -m ping
   ```

3. **Run the full converge.** The vault password unlocks the secret overlay;
   the extra-vars file carries the non-secret topology:

   ```bash
   ansible-playbook -i ansible/inventory/hosts.yml ansible/site.yml \
     -e @/secure/customer-topology.yml --ask-vault-pass
   ```

   Keep the existing console/SSH session open until the run completes: the
   playbook hardens sshd (key-only, no forwarding) and proves a fresh key-only
   login before proceeding. Roles run in a fixed order — `host_preflight`,
   `selinux_baseline`, `network_routing`, `firewalld_zones`, `os_baseline`,
   `docker_networks`, `docker_stack`, `verify` — and the run stops at the
   first failed contract.

4. **Expect the Vault gate on the first converge.** Vault starts
   uninitialized and sealed, so the first run deliberately waits only for the
   bootstrap-independent services and prints the explicit Vault gate; this is
   normal, not a failure.

5. **Initialize Vault.** On the lab profile, run `scripts/vault-bootstrap.sh`
   on the VM. For a customer deployment, the lab bootstrap is not
   production-safe; perform the reviewed production Vault ceremony instead
   (see [operations](operations.md) and the
   [project status](project-status.md) open items).

6. **Re-run the converge** (or the runtime helper) once Vault is initialized
   and unsealed; this run waits for the complete service graph.

7. **Bootstrap identity.** Establish the first `aigw-admins` administrator
   through the controlled Keycloak/customer-IdP procedure, then run the admin
   portal's identity-controller initialization
   ([identity operations](identity-operations.md)).

8. **Accept.** Execute the applicable sections of the
   [acceptance test runbook](test-runbook.md) before opening user access.

## 4. Re-running and application-only rollouts

The full `site.yml` converge is idempotent and safe to re-run. For
application-only changes on an already-converged host, use
`ansible/deploy-stack-only.yml`, which refuses to run against a stale
firewall or network configuration (deploy-guide §“Stack-only rollout”).
Render-only validation that starts no containers:

```bash
scripts/validate-compose.sh
```
