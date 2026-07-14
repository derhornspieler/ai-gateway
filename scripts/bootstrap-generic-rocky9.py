#!/usr/bin/env python3
"""Create a separate, deployable generic Rocky 9 Ansible inventory.

The helper deliberately never reads an existing vault and never writes a
plaintext secret file.  It creates a new inventory layout, with the host-vars
file named exactly for the requested inventory alias, and encrypts each
required stack secret directly from process memory with ``ansible-vault``.
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


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Create a new generic Rocky 9 inventory and encrypted Ansible Vault "
            "without a plaintext secret file."
        )
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
    return parser.parse_args()


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
# Generated generic Rocky 9 inventory. Keep this separate from the committed
# lab inventory. Its host-specific non-secret values live in host_vars/{alias}.yml.
all:
  children:
    # Empty selector group: the generic host below is deliberately not a
    # gateway member, so a lab-only Vault cannot be inherited.
    gateway:
      hosts: {{}}
    generic_rocky9:
      hosts:
        {alias}:
"""


def host_vars_document(alias: str) -> str:
    return f"""---
# Generated generic Rocky 9 host contract. Fill every empty value before the
# non-mutating preflight; the encrypted Vault is intentionally elsewhere.
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
"""


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
    destination, password_file = validate_inputs(args)
    stage = Path(tempfile.mkdtemp(prefix=f".{destination.name}.", dir=destination.parent))
    os.chmod(stage, 0o700)
    try:
        host_vars = stage / "host_vars"
        vault_dir = stage / "group_vars" / "generic_rocky9"
        host_vars.mkdir(mode=0o700)
        vault_dir.mkdir(parents=True, mode=0o700)
        inventory_path = stage / "hosts.yml"
        host_path = host_vars / f"{args.inventory_alias}.yml"
        vault_path = vault_dir / "vault.yml"
        write_text(inventory_path, inventory_document(args.inventory_alias), 0o600)
        write_text(host_path, host_vars_document(args.inventory_alias), 0o600)
        write_text(vault_path, vault_document(args, password_file, contract), 0o600)
        if destination.exists() or destination.is_symlink():
            fail(f"refusing to overwrite existing inventory directory: {destination}")
        stage.rename(destination)
        return (
            destination / "hosts.yml",
            destination / "host_vars" / f"{args.inventory_alias}.yml",
            destination / "group_vars" / "generic_rocky9" / "vault.yml",
        )
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def main() -> int:
    try:
        args = parse_arguments()
        inventory_path, host_path, vault_path = create_layout(args)
    except BootstrapError as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 2

    vault_reference = f"{args.vault_id}@{args.vault_password_file.expanduser()}"
    print(f"Created generic Rocky 9 inventory: {inventory_path}")
    print(f"Fill non-secret topology in: {host_path}")
    print(f"Created encrypted Vault only: {vault_path}")
    print("Then run the non-mutating contract gate:")
    print(
        "  ansible-playbook"
        f" -i {inventory_path} ansible/preflight-generic-rocky9.yml"
        f" --limit {args.inventory_alias} --vault-id {vault_reference}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
