# Production deployment runbook

Use this runbook to install AI Gateway on an existing Rocky Linux 9 VM.

This is the production path. Local release tests use Docker preprod instead.
See [Local preprod](preprod.md).

Two systems take part:

| System | Purpose |
| --- | --- |
| Controller | A Linux or macOS system that runs Ansible |
| Target VM | The Rocky Linux 9 VM that runs AI Gateway |

Ansible configures the target VM. It does not create the VM, NICs, IPs, routes,
or customer DNS records.

## Secrets and Vault prerequisites

The inventory bootstrap makes the stack secrets. This includes database,
Keycloak, OIDC, session, Redis, LiteLLM, and Grafana values. Do not make these
values by hand.

You provide only the items that belong to your site:

| Item | When it is needed |
| --- | --- |
| Ansible Vault password file | Always; it protects the generated inventory secrets |
| Vault unseal key | After the one-time Vault initialization |
| LDAPS bind password | When `identity_ldap_enabled: true` |
| Edge certificate or intermediate CA files | Based on the selected TLS mode |
| Anthropic WIF identifiers | At go-live, after the provider setup ceremony |
| Cribl worker details and CA | Only when the optional SOC log feed is on |

Rules for every secret:

- Keep it out of Git.
- Keep it out of command options and logs.
- Use an absolute private file path when a command asks for a password file.
- Use the stdin-only helper when this runbook says to pipe a value.
- Never initialize Vault a second time.

The bootstrap writes generated stack secrets to an encrypted inventory file.
The Vault unseal key and LDAPS bind password use their own encrypted files.

## Part 1 — Check the target VM

The VM team must provide this host before Ansible runs:

| Need | Check from the controller |
| --- | --- |
| Rocky Linux 9 | `ssh <user>@<vm> 'cat /etc/rocky-release'` |
| Three active IPv4 NICs | `ssh <user>@<vm> 'ip -br -4 address'` |
| One default route on egress | `ssh <user>@<vm> 'ip -4 route show table main'` |
| SELinux enforcing | `ssh <user>@<vm> getenforce` |
| Clock in sync | `ssh <user>@<vm> 'chronyc tracking'` |
| SSH key login and non-interactive sudo | `ssh <user>@<vm> sudo -n true` |
| Enough pilot capacity | At least 4 vCPU, 24 GiB RAM, and 100 GB disk |
| LUKS-backed state disk | `ssh <user>@<vm> 'lsblk -o NAME,FSTYPE'` |

The host needs three separate network roles:

- **egress** has the only default route;
- **ADM** serves SSH and admin HTTPS; and
- **internal** serves the API and user portal.

Write down:

- each NIC name, IP, and gateway;
- the ADM VPN source CIDR;
- the internal user source CIDR;
- internal DNS servers;
- separate egress DNS servers; and
- the base domain for the gateway.

The converge warns if the state paths are not on LUKS storage. It cannot add
disk encryption. Fix the disk before real customer data is stored.

### Choose how the VM gets images

Pick one path before the converge:

1. Log the target VM's root Docker daemon in to `dhi.io`; or
2. Stage a production offline seed and set the five
   `offline_image_seed_*` inventory values.

A Docker login for the normal SSH user does not log in the root daemon. For
the offline path, follow [Offline image releases](offline-image-seed.md).

## Part 2 — Prepare the controller

Install Ansible Core 2.16 or newer. Then get this repository and its required
Ansible collections:

```bash
git clone <repository-url> ai-gateway
cd ai-gateway
ansible-galaxy collection install -r ansible/requirements.yml
```

Create one private password file for this inventory:

```bash
umask 077
install -d -m 0700 "$HOME/.config/ai-gateway"
openssl rand -base64 30 > "$HOME/.config/ai-gateway/mygateway.vault-password"
chmod 600 "$HOME/.config/ai-gateway/mygateway.vault-password"
```

Back up the password in the approved password manager. Do not put the file in
this repository.

## Part 3 — Generate your deployment folder

For a non-interactive run, all three options below are required:

```bash
python3 -I scripts/bootstrap-rocky9-production.py \
  --inventory-alias mygateway \
  --vault-id mygateway \
  --vault-password-file "$HOME/.config/ai-gateway/mygateway.vault-password"
```

Replace `mygateway` with a short name for this install. The script makes:

```text
ansible/inventory/generated/mygateway/hosts.yml
ansible/inventory/generated/mygateway/host_vars/mygateway.yml
ansible/inventory/generated/mygateway/group_vars/production_rocky9/vault.yml
```

Run the script with no options in a terminal if you want guided prompts.

Open the host variables:

```bash
nano ansible/inventory/generated/mygateway/host_vars/mygateway.yml
```

Fill in the values from Part 1:

| Field | Value |
| --- | --- |
| `ansible_host` | Target VM SSH address |
| `ansible_user` | SSH user with `sudo -n` access |
| `aigw_domain` | Lowercase base domain, such as `aigw.example.internal` |
| `nic_egress`, `nic_adm`, `nic_internal` | Live NIC names |
| `eth0_ip`, `eth0_gateway` | Egress values |
| `eth1_ip`, `eth1_gateway` | ADM values |
| `eth2_ip`, `eth2_gateway` | Internal values |
| `vpn_client_cidr` | Allowed ADM client range |
| `internal_cidr` | Allowed internal client range |
| `internal_dns_servers` | Customer internal resolvers |
| `egress_dns_servers` | Separate resolvers reached through egress |

The `eth0`, `eth1`, and `eth2` labels show roles. Your live NIC names may be
different.

### Pick a DNS mode

Most sites use customer DNS:

```yaml
internal_dns_servers: ["<internal-resolver>"]
egress_dns_servers: ["<separate-egress-resolver>"]
platform_authoritative_dns_enabled: false
```

A pilot may let the gateway answer only for `aigw_domain`:

```yaml
internal_dns_servers: ["{{ eth1_ip }}", "{{ eth2_ip }}"]
egress_dns_servers: ["<separate-egress-resolver>"]
platform_authoritative_dns_enabled: true
```

The built-in DNS service is not a general resolver. It returns `NXDOMAIN` for
other zones.

### Pick an edge TLS mode

Set one `aigw_edge_tls_mode`:

| Mode | Input |
| --- | --- |
| `customer-supplied` | Absolute paths to the leaf certificate, key, and chain |
| `customer-intermediate` | Absolute paths to the intermediate certificate, key, and chain |
| `vault-intermediate` | No key file at this step; Vault makes a key and CSR later |

Private key files must be regular single-link files with mode `0600`. See
[Production edge TLS](operations.md#production-edge-tls).

### Add production LDAPS

To connect a customer directory, set `identity_ldap_enabled: true`. Fill in all
`identity_ldap_*` fields. The URL must use `ldaps://`. The CA bundle path must
be absolute.

Store the bind password in its own encrypted file:

```bash
read -rsp 'Directory bind password: ' AIGW_LDAP_BIND; printf '\n'
printf '%s\n' "$AIGW_LDAP_BIND" | \
  python3 -I scripts/store-identity-ldap-bind-password.py \
    --vault-file ansible/inventory/generated/mygateway/group_vars/production_rocky9/identity-ldap.yml \
    --vault-id mygateway \
    --vault-password-file "$HOME/.config/ai-gateway/mygateway.vault-password"
unset AIGW_LDAP_BIND
```

Ansible later uses this password to configure Keycloak. There is no user-run
identity initialization page.

## Part 4 — Pass the preflight gate

First check Ansible pipelining from the repository root:

```bash
ansible-config dump | grep PIPELINING
```

It must show `True`.

Run the controller-only preflight. Use an absolute password-file path after
the `@` sign:

```bash
ansible-playbook \
  -i ansible/inventory/generated/mygateway/hosts.yml \
  ansible/preflight-rocky9-production.yml \
  --limit mygateway \
  --vault-id mygateway@/absolute/private/mygateway.vault-password
```

A pass prints an `AIGW_GENERIC_PREFLIGHT` receipt with status `ok`. If it says
`invalid`, fix the listed field and run it again.

Check SSH:

```bash
ansible -i ansible/inventory/generated/mygateway/hosts.yml \
  mygateway -m ping
```

The result must include `"ping": "pong"`.

## Part 5 — Register the DNS names

Create these records before the full converge:

| Names | Target |
| --- | --- |
| `portal.<domain>`, `api.<domain>`, `auth.<domain>` | Internal IP |
| `chat.<domain>`, `admin.<domain>`, `litellm-admin.<domain>`, `grafana.<domain>`, `prometheus.<domain>`, `vault.<domain>` | ADM IP |

See the [FQDN inventory](fqdn-inventory.md) for the full split-DNS rules.

## Part 6 — Run the first converge

Run the full play from the repository root:

```bash
ansible-playbook \
  -i ansible/inventory/generated/mygateway/hosts.yml \
  ansible/site.yml \
  --limit mygateway \
  --vault-id mygateway@/absolute/private/mygateway.vault-password
```

The play checks the host, sets network and firewall rules, installs Docker,
creates the container networks, deploys the core stack, and runs checks.

On a new install, Vault is still empty. A first-run notice that only core
services are ready is expected. Continue to Part 7.

### Which production playbook should I use?

| Playbook | Use |
| --- | --- |
| `ansible/site.yml` | First install, host changes, or any time you are unsure |
| `ansible/os-prep.yml` | Host setup only; it starts no containers |
| `ansible/deploy-stack-only.yml` | App deploy on a host that already passed host setup |

The stack-only play checks the host marker, firewall, and networks. If it
refuses, run `site.yml`. Do not bypass the check.

## Part 7 — Initialize Vault and finish the install

Vault initialization happens once. A reboot needs only an unseal, not a new
initialization.

### Step 7a — Initialize Vault once

Follow the approved production Vault ceremony. Do not run the local test
bootstrap script on production. The controller handoff example is
[`production-rocky9.first-init.sh.example`](../ansible/inventory/examples/production-rocky9.first-init.sh.example).

Protect all recovery shares and the first root token. Do not place them in Git,
logs, tickets, or chat.

Before you store or revoke the first root token, enable the reviewed file audit
device on the target VM. Run this from `/opt/ai-gateway`:

```bash
sudo -v
read -rsp 'First Vault root token: ' AIGW_FIRST_ROOT_TOKEN; printf '\n'
printf '%s\n' "$AIGW_FIRST_ROOT_TOKEN" | sudo scripts/vault-enable-audit.sh
unset AIGW_FIRST_ROOT_TOKEN
```

The helper accepts the token only on stdin. It enables JSON audit records at
`/vault/logs/audit.log`, keeps raw values HMAC-protected, sets mode `0640`, and
reads the live Vault configuration back. The second Ansible converge refuses
an initialized Vault when this file is missing, empty, unreadable by Alloy, or
not JSON-shaped.

### Step 7b — Store one encrypted unseal key on the controller

Use the stdin-only helper:

```bash
read -rsp 'Vault unseal key: ' AIGW_UNSEAL_SHARE; printf '\n'
printf '%s\n' "$AIGW_UNSEAL_SHARE" | \
  python3 -I scripts/store-vault-unseal-key.py \
    --vault-file ansible/inventory/generated/mygateway/group_vars/production_rocky9/vault-unseal.yml \
    --vault-id mygateway \
    --vault-password-file "$HOME/.config/ai-gateway/mygateway.vault-password"
unset AIGW_UNSEAL_SHARE
```

The helper writes only an encrypted value. It does not replace an existing
one.

### Step 7c — Finish the edge CA ceremony when needed

Skip this step for `customer-supplied` TLS.

For `customer-intermediate`, import the staged intermediate into Vault. For
`vault-intermediate`, ask Vault for a CSR, sign it on the approved CA system,
then install the signed result. Follow
[Production edge TLS](operations.md#production-edge-tls).

Test the live edge with the customer Root CA. A connection that works only
with certificate checks off does not pass.

### Step 7d — Run the full converge again

Run the same command from Part 6:

```bash
ansible-playbook \
  -i ansible/inventory/generated/mygateway/hosts.yml \
  ansible/site.yml \
  --limit mygateway \
  --vault-id mygateway@/absolute/private/mygateway.vault-password
```

Ansible now unlocks Vault with the encrypted controller copy. When LDAPS is
enabled, Ansible also:

1. proves the directory TLS chain, hostname, and bind;
2. configures Keycloak federation;
3. builds all managed redirect, origin, and logout URLs from `aigw_domain`;
4. removes short-term bootstrap access; and
5. verifies the final identity state.

The admin portal does not ask the user to initialize identity.

## Part 8 — First administrator and sign-off

1. Assign one approved directory user to the `aigw-admins` group. This grants
   access; it does not initialize the platform.
2. On the ADM network, open `https://admin.<domain>` and
   `https://grafana.<domain>`. Both must redirect to Keycloak and return after
   login.
3. Open `https://chat.<domain>` on ADM and `https://portal.<domain>` on the
   internal network.
4. Test logout from each app. It must end the Keycloak session and return to
   the same deployed domain.
5. Enroll Anthropic WIF with the
   [WIF setup SOP](sop/anthropic-wif-jwt-setup.md).
6. Run the needed parts of the [acceptance test runbook](test-runbook.md).

Save only non-secret test evidence.

## Troubleshooting quick reference

| Problem | What to do |
| --- | --- |
| Bootstrap says required options are missing | Pass `--inventory-alias`, `--vault-id`, and `--vault-password-file`, or run with no options for prompts |
| Preflight status is `invalid` | Fix the exact listed host variable and rerun |
| Ansible ping fails | Check `ansible_host`, `ansible_user`, SSH keys, and `sudo -n` |
| Topology check fails | Make inventory match the live NICs, IPs, and default route |
| Registry returns `401` | Log the root Docker daemon in to `dhi.io`, or use the production offline seed |
| First run says Vault is not initialized | This is expected; complete Part 7 |
| Run says Vault is sealed | Follow the [Vault unseal SOP](sop/vault-unseal-after-reboot.md) |
| Run rejects a test edge certificate | Finish the selected CA ceremony and rerun |
| Keycloak rejects a redirect URL | Check `aigw_domain`, DNS, and certificates, then rerun the full converge; do not hand-edit a second domain into Keycloak |

## Glossary

- **Controller:** the system that runs Ansible.
- **Converge:** an Ansible run that makes the target match the inventory.
- **Inventory:** the files that hold host settings and encrypted secrets.
- **Preflight:** a read-only input check.
- **Vault:** the service that holds provider and signing secrets.
- **Unseal key:** a key that unlocks Vault after a restart.
- **LDAPS:** LDAP protected by TLS.
- **WIF:** short-lived provider login without a stored vendor API key.

## Next pages

- [Identity operations](identity-operations.md)
- [Production operations](operations.md)
- [Image update workflow](image-update-workflow.md)
- [Vault unseal after reboot](sop/vault-unseal-after-reboot.md)
