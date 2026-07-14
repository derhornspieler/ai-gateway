#!/usr/bin/env python3
"""Create a separate, deployable production Rocky 9 Ansible inventory.

The helper deliberately never reads an existing vault and never writes a
plaintext secret file.  It creates a new inventory layout, with the host-vars
file named exactly for the requested inventory alias, and encrypts each
required stack secret directly from process memory with ``ansible-vault``.
The HashiCorp Vault unseal share is never randomly generated here because it
does not exist until ``vault operator init`` completes.

This is the shared implementation for both the canonical ``rocky9-production``
profile (Ansible group ``production_rocky9``) and the DEPRECATED compatibility
``generic-rocky9`` profile (group ``generic_rocky9``); neither is a lab
profile. The canonical entry point is ``scripts/bootstrap-rocky9-production.py``;
invoking this file directly keeps the legacy layout byte-identical but prints a
one-line deprecation notice on stderr. Both entry points run this exact module
— the profile only selects the Ansible group name and the generated
inventory/host-vars layout, never a separate code path.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, NoReturn


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "ansible" / "generic-rocky9-contract.json"
ALIAS_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,62}\Z")
VAULT_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
SAFE_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
ALNUM_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


class BootstrapError(RuntimeError):
    """A requested layout or Vault operation is not safe to perform."""


def fail(message: str) -> NoReturn:
    raise BootstrapError(message)


def parse_arguments(
    argv: list[str] | None = None, *, default_profile: str = "generic-rocky9"
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Create a new production Rocky 9 inventory and encrypted Ansible Vault "
            "without a plaintext secret file."
        )
    )
    parser.add_argument(
        "--deployment-profile",
        choices=sorted(PROFILES),
        default=default_profile,
        help=(
            "deployment profile to generate: 'rocky9-production' (canonical) or "
            "'generic-rocky9' (deprecated compatibility alias). Default: %(default)s"
        ),
    )
    parser.add_argument(
        "--inventory-dir",
        type=Path,
        help=(
            "new directory that will contain hosts.yml, host_vars/, and group_vars/ "
            "(default: ansible/inventory/generated/<inventory-alias>)"
        ),
    )
    parser.add_argument(
        "--inventory-alias",
        required=True,
        help="host alias used in hosts.yml and host_vars/<alias>.yml",
    )
    parser.add_argument(
        "--vault-id",
        required=True,
        help="explicit Ansible Vault ID label (for example customer-prod)",
    )
    parser.add_argument(
        "--vault-password-file",
        required=True,
        type=Path,
        help="regular local file that supplies the explicit Vault ID password",
    )
    parser.add_argument(
        "--ansible-vault",
        default="ansible-vault",
        help="ansible-vault executable (default: ansible-vault from PATH)",
    )
    return parser.parse_args(argv)


def load_contract() -> dict[str, Any]:
    try:
        contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot load generic Rocky 9 contract: {exc}")
    if (
        not isinstance(contract, dict)
        or contract.get("schema") != "aigw.generic-rocky9/v1"
        or contract.get("profile") != "generic-rocky9"
        or not isinstance(contract.get("required_secret_keys"), list)
        or contract.get("operator_supplied_secret_keys")
        != [
            {
                "name": "vault_unseal_key",
                "source": "hashicorp-vault-operator-init",
                "generated_by_inventory_bootstrap": False,
            }
        ]
    ):
        fail("generic Rocky 9 contract has an invalid schema")
    return contract


def validate_inputs(args: argparse.Namespace) -> tuple[Path, Path]:
    if ALIAS_RE.fullmatch(args.inventory_alias) is None:
        fail("inventory alias must match [A-Za-z][A-Za-z0-9_.-]{0,62}")
    if VAULT_ID_RE.fullmatch(args.vault_id) is None:
        fail("vault ID must match [A-Za-z0-9][A-Za-z0-9_.-]{0,63}")

    password_file = args.vault_password_file.expanduser()
    try:
        metadata = password_file.lstat()
    except OSError as exc:
        fail(f"cannot inspect vault password file: {exc}")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        fail("vault password file must be a non-symlink regular file")
    if metadata.st_uid != os.geteuid():
        fail("vault password file must be owned by the current user")
    if metadata.st_nlink != 1:
        fail("vault password file must have exactly one hard link")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        fail("vault password file must not grant group or world access")
    if not os.access(password_file, os.R_OK):
        fail("vault password file is not readable")

    destination = (
        args.inventory_dir.expanduser()
        if args.inventory_dir is not None
        else ROOT / "ansible" / "inventory" / "generated" / args.inventory_alias
    )
    if destination.exists() or destination.is_symlink():
        fail(f"refusing to overwrite existing inventory directory: {destination}")
    if destination.name in {"", ".", ".."}:
        fail("inventory directory must name a new child directory")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.parent.is_symlink() or not destination.parent.is_dir():
        fail("inventory directory parent must be a real directory")
    return destination, password_file


def write_text(path: Path, content: str, mode: int) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        mode,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as destination:
            destination.write(content)
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def inventory_document(alias: str) -> str:
    return f"""---
# Generated production Rocky 9 inventory. Keep this separate from the
# committed lab inventory. The generic_rocky9 group name is retained as a
# backwards-compatible automation selector. Host-specific non-secret values
# live in host_vars/{alias}.yml.
all:
  children:
    # Empty selector group: the generic host below is deliberately not a
    # gateway member, so a lab-only Vault cannot be inherited.
    gateway:
      hosts: {{}}
    # Compatibility selector used by existing playbooks. New automation may
    # target production_rocky9; generic_rocky9 deliberately includes it.
    generic_rocky9:
      children:
        production_rocky9:
    production_rocky9:
      hosts:
        {alias}:
"""


def host_vars_document(alias: str) -> str:
    return f"""---
# Generated production Rocky 9 host contract. Fill every empty value before
# the non-mutating preflight; the encrypted Vault is intentionally elsewhere.
# deployment_profile=generic-rocky9 is the backwards-compatible production
# runtime identifier and must not be changed to the lab-only rocky9-lab value.
aigw_generic_inventory_alias: {alias}
deployment_profile: generic-rocky9

# Controller connection and public names.
ansible_host: ""
ansible_user: ansible
ansible_become: true
aigw_domain: ""
aigw_management_ssh_port: 22

# Existing three-plane Rocky 9 topology.
nic_egress: ""
nic_adm: ""
nic_internal: ""
eth0_ip: ""
eth0_gateway: ""
eth1_ip: ""
eth1_gateway: ""
eth2_ip: ""
eth2_gateway: ""
vpn_client_cidr: ""
internal_cidr: ""

# Keep corporate/internal and Internet egress resolver planes distinct.
#
# Mode A -- use existing corporate DNS:
#   internal_dns_servers: ["<resolver reachable through ADM/internal>"]
#   platform_authoritative_dns_enabled: false
#
# Mode B -- let this gateway answer only its own aigw_domain (no recursion):
#   internal_dns_servers: ["{{{{ eth1_ip }}}}", "{{{{ eth2_ip }}}}"]
#   platform_authoritative_dns_enabled: true
# Configure a conditional/split resolver for aigw_domain: ADM clients use
# eth1_ip and internal clients use eth2_ip. This authoritative service returns
# NXDOMAIN for every other zone, so it must not replace a client's general
# recursive resolver. In both modes, egress_dns_servers must contain a distinct
# recursive Internet resolver routed only through nic_egress; only Envoy gets
# it. Backends on isolated Docker networks keep service discovery but have no
# upstream DNS; the routable ADM/internal edge services use the internal list.
internal_dns_servers: []
egress_dns_servers: []
platform_authoritative_dns_enabled: false

# Optional ADM-only Vault browser surface. The internal Vault API remains
# deployed for platform consumers when this stays false.
aigw_vault_ui_enabled: false

# Production edge TLS. HTTPS terminates at the two Traefik edges; container-to-
# container traffic stays plain HTTP on segmented internal bridges. Choose
# exactly one mode -- the converge refuses to start without one.
#
#   vault-intermediate -- Vault GENERATES the intermediate private key
#                         INTERNALLY and emits a CSR. Your CA signs that CSR
#                         OFFLINE and you import the signed certificate plus the
#                         complete chain. Leave the three *_file paths empty.
#                         Your CA's root/issuing PRIVATE KEY is never requested,
#                         never copied here, and never placed on the gateway.
#                         After the Vault init ceremony:
#                             sudo scripts/vault-pki-intermediate.sh csr
#                             scripts/sign-vault-intermediate.sh   (on your CA host)
#                             sudo scripts/vault-pki-intermediate.sh install-signed ...
#
#   customer-supplied  -- you already hold an edge certificate for this domain.
#                         Set the three paths below to controller-local PEM
#                         files. The key must be mode 0600 and owned by you. The
#                         chain file must contain the COMPLETE chain including
#                         the self-signed root. Ansible validates the material
#                         (key/leaf match, wildcard+apex SAN, serverAuth EKU,
#                         chain to root, expiry window) before installing it.
aigw_edge_tls_mode: ""
aigw_edge_tls_leaf_cert_file: ""
aigw_edge_tls_private_key_file: ""
aigw_edge_tls_chain_file: ""
aigw_edge_tls_min_days_remaining: 30

# Telemetry export CA. Required only when exporting to a real Cribl endpoint.
# This is deliberately a SEPARATE trust anchor from the edge CA above.
cribl_otlp_ca_pem_file: ""

# Source-policy routes are enabled for the ADM and internal interfaces.
manage_networking: true
pbr_tables: []
# Populate exactly two entries after filling the interfaces/addresses above:
#   - {{ name: adm, id: 101, priority: 10101, dev: "{{{{ nic_adm }}}}",
#       gw: "{{{{ eth1_gateway }}}}", src: "{{{{ eth1_ip }}}}" }}
#   - {{ name: internal, id: 102, priority: 10102, dev: "{{{{ nic_internal }}}}",
#       gw: "{{{{ eth2_gateway }}}}", src: "{{{{ eth2_ip }}}}" }}

# Generic/customer profiles stay outside all lab-only exceptions.
require_encrypted_state: true
require_preupgrade_backup: true
aigw_ssh_password_authentication: false
aigw_adm_socks_enabled: false
aigw_adm_socks_users: []
aigw_adm_socks_groups: []
aigw_adm_socks_source_cidrs: []
aigw_adm_socks_group_test_users: {{}}
aigw_adm_socks_trusted_operator_ack: ""
samba_lab_enabled: false
aigw_seed_test_users: false
retain_bootstrap_admin_user: false
aigw_prebootstrap_oidc_scope_reconciliation: false
aigw_prebootstrap_oidc_scope_reconciliation_ack: ""
aigw_lab_reset_handoff_drop_interfaces: []
offline_image_seed_enabled: false
offline_image_seed_remote_path: ""
offline_image_seed_sha256: ""
offline_image_seed_manifest_remote_path: ""
offline_image_seed_manifest_sha256: ""

# ── Optional external Active Directory / LDAPS federation ───────────────
# Enable only after completing EVERY value below and storing the directory
# bind credential with scripts/store-identity-ldap-bind-password.py (stdin
# only) into group_vars/generic_rocky9/identity-ldap.yml. The URL must be
# ldaps:// on port 636; plaintext ldap:// is refused at every layer.
# identity_ldap_directory_ip is the exact IPv4 address of the directory; it
# pins both Keycloak's name resolution and the single tcp/636 firewall
# allowance, so toggling identity_ldap_enabled changes the firewall ABI and
# requires a full site.yml converge (not deploy-stack-only.yml).
identity_ldap_enabled: false
identity_ldap_provider_name: ""
identity_ldap_url: ""
identity_ldap_users_dn: ""
identity_ldap_bind_dn: ""
identity_ldap_ca_bundle_src: ""
identity_ldap_directory_ip: ""
identity_ldap_vendor: ad
identity_ldap_username_attribute: sAMAccountName
identity_ldap_rdn_attribute: cn
identity_ldap_uuid_attribute: objectGUID
identity_ldap_user_object_classes: "person, organizationalPerson, user"
identity_ldap_user_filter: ""
"""


def production_inventory_document(alias: str) -> str:
    return f"""---
# Generated rocky9-production inventory (canonical profile). Keep this separate
# from the committed lab inventory. Its host-specific non-secret values live in
# host_vars/{alias}.yml.
all:
  children:
    # Empty selector group: the production host below is deliberately not a
    # gateway member, so a lab-only Vault cannot be inherited.
    gateway:
      hosts: {{}}
    # 'generic_rocky9' is the DEPRECATED compatibility parent group. The
    # canonical 'production_rocky9' child carries this host, so both the legacy
    # and canonical play host patterns (and the preflight) select it while the
    # generated Vault overlay lives under group_vars/production_rocky9/.
    generic_rocky9:
      children:
        production_rocky9:
    production_rocky9:
      hosts:
        {alias}:
"""


def production_host_vars_document(alias: str) -> str:
    return f"""---
# Generated rocky9-production host contract (canonical profile). Fill every
# empty value in SECTION 1 before the non-mutating preflight; the encrypted
# Vault is intentionally in group_vars/production_rocky9/vault.yml beside this
# file. SECTIONS 3 and 5 are inputs added later in the deployment lifecycle;
# leave them exactly as-is until the referenced step. SECTION 4 is an optional
# feature that ships disabled and fails closed until every value is supplied.
aigw_generic_inventory_alias: {alias}
deployment_profile: rocky9-production

# ── SECTION 1 — non-secret host / interface / routing / DNS inputs ───────
# Controller connection and public names.
ansible_host: ""
ansible_user: ansible
ansible_become: true
aigw_domain: ""
aigw_management_ssh_port: 22

# Existing three-plane Rocky 9 topology.
nic_egress: ""
nic_adm: ""
nic_internal: ""
eth0_ip: ""
eth0_gateway: ""
eth1_ip: ""
eth1_gateway: ""
eth2_ip: ""
eth2_gateway: ""
vpn_client_cidr: ""
internal_cidr: ""

# Keep corporate/internal and Internet egress resolver planes distinct.
#
# Mode A -- use existing corporate DNS:
#   internal_dns_servers: ["<resolver reachable through ADM/internal>"]
#   platform_authoritative_dns_enabled: false
#
# Mode B -- let this gateway answer only its own aigw_domain (no recursion):
#   internal_dns_servers: ["{{{{ eth1_ip }}}}", "{{{{ eth2_ip }}}}"]
#   platform_authoritative_dns_enabled: true
# Configure a conditional/split resolver for aigw_domain: ADM clients use
# eth1_ip and internal clients use eth2_ip. This authoritative service returns
# NXDOMAIN for every other zone, so it must not replace a client's general
# recursive resolver. In both modes, egress_dns_servers must contain a distinct
# recursive Internet resolver routed only through nic_egress; only Envoy gets
# it. Backends on isolated Docker networks keep service discovery but have no
# upstream DNS; the routable ADM/internal edge services use the internal list.
internal_dns_servers: []
egress_dns_servers: []
platform_authoritative_dns_enabled: false

# Optional ADM-only Vault browser surface. The internal Vault API remains
# deployed for platform consumers when this stays false.
aigw_vault_ui_enabled: false

# Source-policy routes are enabled for the ADM and internal interfaces.
manage_networking: true
pbr_tables: []
# Populate exactly two entries after filling the interfaces/addresses above:
#   - {{ name: adm, id: 101, priority: 10101, dev: "{{{{ nic_adm }}}}",
#       gw: "{{{{ eth1_gateway }}}}", src: "{{{{ eth1_ip }}}}" }}
#   - {{ name: internal, id: 102, priority: 10102, dev: "{{{{ nic_internal }}}}",
#       gw: "{{{{ eth2_gateway }}}}", src: "{{{{ eth2_ip }}}}" }}

# Production profiles stay outside all lab-only exceptions.
require_encrypted_state: true
require_preupgrade_backup: true
aigw_ssh_password_authentication: false
aigw_adm_socks_enabled: false
aigw_adm_socks_users: []
aigw_adm_socks_groups: []
aigw_adm_socks_source_cidrs: []
aigw_adm_socks_group_test_users: {{}}
aigw_adm_socks_trusted_operator_ack: ""
samba_lab_enabled: false
aigw_seed_test_users: false
retain_bootstrap_admin_user: false
aigw_prebootstrap_oidc_scope_reconciliation: false
aigw_prebootstrap_oidc_scope_reconciliation_ack: ""
aigw_lab_reset_handoff_drop_interfaces: []
offline_image_seed_enabled: false
offline_image_seed_remote_path: ""
offline_image_seed_sha256: ""
offline_image_seed_manifest_remote_path: ""
offline_image_seed_manifest_sha256: ""

# ── SECTION 2 — generated encrypted application secrets ──────────────────
# Every stack credential was generated with high entropy and written ONLY in
# ciphertext to the sibling overlay group_vars/production_rocky9/vault.yml under
# your explicit --vault-id. No plaintext secret is ever written to this file.
# Edit that overlay in place with `ansible-vault edit`; never paste a decrypted
# value into this host_vars file.

# ── SECTION 3 — operator-supplied vault_unseal_key (post-initialization) ─
# vault_unseal_key is the SOLE operator-supplied secret and is NEVER randomly
# generated by this tool: it cannot exist until `vault operator init` runs on
# the target during the two-pass converge. After the reviewed production init
# ceremony returns its 1-of-1 Shamir share, pipe it (stdin only, never argv or
# environment) into scripts/store-vault-unseal-key.py, which writes exactly one
# inline-encrypted value to the dedicated sibling overlay
# group_vars/production_rocky9/vault-unseal.yml — never to group_vars/all.yml,
# never in plaintext, never into this file. Until that overlay exists, later
# converges leave an initialized Vault sealed by design; once present, every
# converge auto-unseals from the encrypted controller custody. See
# ansible/inventory/examples/production-rocky9.first-init.sh.example for the
# exact runnable sequence.

# ── SECTION 4 — external AD / LDAPS inputs (optional, ships disabled) ────
# Binds this gateway's Keycloak to the CUSTOMER's existing Active Directory (or
# another LDAPS directory) as a READ-ONLY user federation provider. Leave
# identity_ldap_enabled false to keep local Keycloak users only; nothing below
# is read while it is false.
#
# To enable, complete EVERY value below and store the directory bind credential
# with scripts/store-identity-ldap-bind-password.py (stdin only, never argv or
# the environment) into the sibling overlay
# group_vars/production_rocky9/identity-ldap.yml. The credential is never
# written to this file, never generated by this tool, and never reaches the
# stack as a Compose environment variable.
#
# identity_ldap_url must be ldaps:// on an FQDN, port 636 or omitted; plaintext
# ldap:// is refused by the preflight, site.yml, the converge, and the
# key-rotator itself. identity_ldap_ca_bundle_src is a controller-local PEM
# holding ONLY the certificate chain that signed the directory's LDAPS
# certificate; it becomes Keycloak's sole trust anchor and Keycloak verifies the
# directory's hostname against it. identity_ldap_directory_ip is the exact IPv4
# address of that directory: it pins Keycloak's name resolution and the single
# tcp/636 firewall allowance, so toggling identity_ldap_enabled changes the
# firewall ABI and needs a full site.yml converge (not deploy-stack-only.yml).
identity_ldap_enabled: false
identity_ldap_provider_name: ""
identity_ldap_url: ""
identity_ldap_users_dn: ""
identity_ldap_bind_dn: ""
identity_ldap_ca_bundle_src: ""
identity_ldap_directory_ip: ""
identity_ldap_vendor: ad
identity_ldap_username_attribute: sAMAccountName
identity_ldap_rdn_attribute: cn
identity_ldap_uuid_attribute: objectGUID
identity_ldap_user_object_classes: "person, organizationalPerson, user"
identity_ldap_user_filter: ""

# ── SECTION 5 — PKI inputs (placeholder) ─────────────────────────────────
# Reserved for the production TLS / PKI workstream (customer-supplied leaf chain
# or a CA-signed Vault intermediate). Its variables are defined by a parallel
# change; do not invent keys here yet. Leave this section empty until that
# contract lands.
"""


# Both entry points run this single module. A profile only selects the Ansible
# group name, the generated inventory/host-vars layout, and the canonical
# preflight entry-point name printed at the end — never a separate code path.
PROFILES: dict[str, dict[str, Any]] = {
    "generic-rocky9": {
        "group": "generic_rocky9",
        "legacy": True,
        "inventory_document": inventory_document,
        "host_vars_document": host_vars_document,
        "preflight": "ansible/preflight-generic-rocky9.yml",
    },
    "rocky9-production": {
        "group": "production_rocky9",
        "legacy": False,
        "inventory_document": production_inventory_document,
        "host_vars_document": production_host_vars_document,
        "preflight": "ansible/preflight-rocky9-production.yml",
    },
}


def random_secret(entry: dict[str, Any], seen: set[str]) -> str:
    exact_length = entry.get("exact_length")
    minimum_length = entry.get("min_length")
    if exact_length is not None:
        if not isinstance(exact_length, int) or exact_length < 16:
            fail(f"invalid exact length for {entry.get('name')!r}")
        length = exact_length
    elif isinstance(minimum_length, int) and minimum_length >= 16:
        length = max(minimum_length, 48)
    else:
        fail(f"invalid minimum length for {entry.get('name')!r}")

    alphabet_name = entry.get("alphabet")
    if alphabet_name == "safe":
        alphabet = SAFE_ALPHABET
    elif alphabet_name == "alnum":
        alphabet = ALNUM_ALPHABET
    else:
        fail(f"invalid alphabet for {entry.get('name')!r}")

    while True:
        value = "".join(secrets.choice(alphabet) for _ in range(length))
        if value not in seen:
            seen.add(value)
            return value


def encrypted_value(
    *, executable: str, vault_id: str, password_file: Path, name: str, value: str
) -> str:
    command = [
        executable,
        "encrypt_string",
        "--vault-id",
        f"{vault_id}@{password_file}",
        "--stdin-name",
        name,
    ]
    try:
        result = subprocess.run(
            command,
            input=value.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        fail(f"cannot execute ansible-vault: {exc}")
    if result.returncode != 0:
        fail(f"ansible-vault could not encrypt {name}; check --vault-id and password file")
    try:
        rendered = result.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        fail(f"ansible-vault returned non-text output for {name}")
    if not rendered.startswith(f"{name}: !vault |\n") or "$ANSIBLE_VAULT;" not in rendered:
        fail(f"ansible-vault returned an unexpected encrypted value for {name}")
    return rendered


def vault_document(args: argparse.Namespace, password_file: Path, contract: dict[str, Any]) -> str:
    rendered = (
        "# Generated by bootstrap-generic-rocky9.py. Every value below is "
        "encrypted with the explicit Vault ID.\n"
        "# Keep non-secret topology in host_vars; do not put plaintext values here.\n"
    )
    seen: set[str] = set()
    names: set[str] = set()
    for entry in contract["required_secret_keys"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            fail("generic Rocky 9 contract contains an invalid secret key")
        name = entry["name"]
        if name in names:
            fail(f"generic Rocky 9 contract repeats secret key {name}")
        names.add(name)
        value = random_secret(entry, seen)
        rendered += encrypted_value(
            executable=args.ansible_vault,
            vault_id=args.vault_id,
            password_file=password_file,
            name=name,
            value=value,
        )
    return rendered


def create_layout(args: argparse.Namespace) -> tuple[Path, Path, Path]:
    contract = load_contract()
    profile = PROFILES[args.deployment_profile]
    group = profile["group"]
    build_inventory = profile["inventory_document"]
    build_host_vars = profile["host_vars_document"]
    destination, password_file = validate_inputs(args)
    stage = Path(tempfile.mkdtemp(prefix=f".{destination.name}.", dir=destination.parent))
    os.chmod(stage, 0o700)
    try:
        host_vars = stage / "host_vars"
        vault_dir = stage / "group_vars" / group
        host_vars.mkdir(mode=0o700)
        vault_dir.mkdir(parents=True, mode=0o700)
        inventory_path = stage / "hosts.yml"
        host_path = host_vars / f"{args.inventory_alias}.yml"
        vault_path = vault_dir / "vault.yml"
        write_text(inventory_path, build_inventory(args.inventory_alias), 0o600)
        write_text(host_path, build_host_vars(args.inventory_alias), 0o600)
        write_text(vault_path, vault_document(args, password_file, contract), 0o600)
        if destination.exists() or destination.is_symlink():
            fail(f"refusing to overwrite existing inventory directory: {destination}")
        stage.rename(destination)
        return (
            destination / "hosts.yml",
            destination / "host_vars" / f"{args.inventory_alias}.yml",
            destination / "group_vars" / group / "vault.yml",
        )
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def main(argv: list[str] | None = None, *, default_profile: str = "generic-rocky9") -> int:
    try:
        args = parse_arguments(argv, default_profile=default_profile)
        profile = PROFILES[args.deployment_profile]
        if profile["legacy"]:
            print(
                "DEPRECATION: 'generic-rocky9' is a compatibility alias; new "
                "deployments should use scripts/bootstrap-rocky9-production.py "
                "(profile rocky9-production, Ansible group production_rocky9).",
                file=sys.stderr,
            )
        inventory_path, host_path, vault_path = create_layout(args)
    except BootstrapError as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 2

    vault_reference = f"{args.vault_id}@{args.vault_password_file.expanduser()}"
    if profile["legacy"]:
        # Byte-identical legacy stdout; only stderr carries the deprecation.
        print(f"Created production Rocky 9 inventory: {inventory_path}")
    else:
        print(f"Created {args.deployment_profile} inventory: {inventory_path}")
    print(f"Fill non-secret topology in: {host_path}")
    print(f"Created encrypted Vault only: {vault_path}")
    custody_path = vault_path.with_name("vault-unseal.yml")
    preflight_command = (
        "ansible-playbook"
        f" -i {inventory_path} {profile['preflight']}"
        f" --limit {args.inventory_alias} --vault-id {vault_reference}"
    )
    deploy_command = (
        "ansible-playbook"
        f" -i {inventory_path} ansible/site.yml"
        f" --limit {args.inventory_alias} --vault-id {vault_reference}"
    )
    print("vault_unseal_key was NOT generated; HashiCorp Vault creates it at first init.")
    print("\nTWO-PHASE DEPLOYMENT BOUNDARY (the first converge is not completion):")
    print("1. Fill host-vars, then run the non-mutating contract gate:")
    print(f"  {preflight_command}")
    print("   External AD/LDAPS federation is optional and off by default. To enable it,")
    print("   complete every identity_ldap_* host-var and store the directory bind")
    print("   credential without echo (stdin only, never argv or the environment):")
    print(
        "  python3 scripts/store-identity-ldap-bind-password.py"
        f" --vault-file {vault_path.with_name('identity-ldap.yml')}"
        f" --vault-id {args.vault_id}"
        f" --vault-password-file {args.vault_password_file.expanduser()}"
    )
    print("2. Run the first converge. A fresh Vault remains uninitialized by design:")
    print(f"  {deploy_command}")
    print("3. Complete the reviewed production Vault init/unseal ceremony. The bundled")
    print("   vault-bootstrap.sh is lab-only and is intentionally NOT invoked here.")
    print("   On the controller, enter its generated 1-of-1 share without echo:")
    print("  read -rsp 'Vault unseal share: ' AIGW_UNSEAL_SHARE; printf '\\n'")
    print(
        "  printf '%s\\n' \"$AIGW_UNSEAL_SHARE\" | "
        "python3 scripts/store-vault-unseal-key.py"
        f" --vault-file {custody_path}"
        f" --vault-id {args.vault_id}"
        f" --vault-password-file {args.vault_password_file.expanduser()}"
    )
    print("  unset AIGW_UNSEAL_SHARE")
    print("4. Run the ordinary converge again. It must finish strict readiness with")
    print("   the controller-owned vault_unseal_key available for future auto-unseal:")
    print(f"  {deploy_command}")
    print("5. Only after step 4 succeeds, separately custody or revoke the bootstrap")
    print("   root token, then securely delete remote secrets/vault-init.json.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
