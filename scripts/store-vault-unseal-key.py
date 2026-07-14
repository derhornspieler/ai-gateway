#!/usr/bin/env python3
"""Store one stdin-supplied Vault unseal share as an inline Ansible Vault value.

This helper is intentionally narrow: it writes only ``vault_unseal_key``,
requires the operator to name the destination and Vault identity explicitly,
and never accepts the unseal share in argv or the environment.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from typing import NoReturn


VARIABLE_NAME = "vault_unseal_key"
VAULT_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
UNSEAL_KEY_RE = re.compile(rb"[A-Za-z0-9+/]{43}=\Z")
VARIABLE_RE = re.compile(r"(?m)^\s*vault_unseal_key\s*:")
MAX_INPUT_BYTES = 4096


class CustodyError(RuntimeError):
    """The requested custody operation is unsafe or ambiguous."""


def fail(message: str) -> NoReturn:
    raise CustodyError(message)


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Read one HashiCorp Vault unseal share from stdin and atomically "
            "store it as the inline-encrypted Ansible variable vault_unseal_key."
        )
    )
    parser.add_argument(
        "--vault-file",
        required=True,
        type=Path,
        help="explicit value-level Ansible Vault overlay to create or extend",
    )
    parser.add_argument(
        "--vault-id",
        required=True,
        help="explicit Ansible Vault ID label used by this inventory",
    )
    parser.add_argument(
        "--vault-password-file",
        required=True,
        type=Path,
        help="private local file supplying the Ansible Vault ID password",
    )
    parser.add_argument(
        "--ansible-vault",
        default="ansible-vault",
        help="ansible-vault executable (default: ansible-vault from PATH)",
    )
    return parser.parse_args()


def inspect_private_file(path: Path, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        fail(f"cannot inspect {label}: {exc}")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        fail(f"{label} must be a non-symlink regular file")
    if metadata.st_uid != os.geteuid():
        fail(f"{label} must be owned by the current user")
    if metadata.st_nlink != 1:
        fail(f"{label} must have exactly one hard link")
    return metadata


def validate_inputs(args: argparse.Namespace) -> tuple[Path, Path, bytes]:
    if VAULT_ID_RE.fullmatch(args.vault_id) is None:
        fail("vault ID must match [A-Za-z0-9][A-Za-z0-9_.-]{0,63}")

    password_file = Path(os.path.abspath(args.vault_password_file.expanduser()))
    password_metadata = inspect_private_file(password_file, "vault password file")
    if stat.S_IMODE(password_metadata.st_mode) & 0o077:
        fail("vault password file must not grant group or world access")
    if not os.access(password_file, os.R_OK):
        fail("vault password file is not readable")

    destination = Path(os.path.abspath(args.vault_file.expanduser()))
    parent = destination.parent
    try:
        parent_metadata = parent.lstat()
    except OSError as exc:
        fail(f"cannot inspect vault overlay parent: {exc}")
    if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(parent_metadata.st_mode):
        fail("vault overlay parent must be an existing non-symlink directory")
    if parent_metadata.st_uid != os.geteuid():
        fail("vault overlay parent must be owned by the current user")
    if stat.S_IMODE(parent_metadata.st_mode) & 0o022:
        fail("vault overlay parent must not be group- or world-writable")
    if destination.exists() or destination.is_symlink():
        overlay_metadata = inspect_private_file(destination, "vault overlay")
        if stat.S_IMODE(overlay_metadata.st_mode) & 0o022:
            fail("vault overlay must not be group- or world-writable")

    if sys.stdin.isatty():
        fail("pipe exactly one unseal share on stdin; interactive input is disabled")
    raw = bytearray(sys.stdin.buffer.read(MAX_INPUT_BYTES + 1))
    if len(raw) > MAX_INPUT_BYTES:
        for index in range(len(raw)):
            raw[index] = 0
        fail("unseal input exceeds the bounded maximum")
    if raw.endswith(b"\r\n"):
        del raw[-2:]
    elif raw.endswith(b"\n"):
        raw.pop()
    if UNSEAL_KEY_RE.fullmatch(raw) is None:
        for index in range(len(raw)):
            raw[index] = 0
        fail("stdin did not contain exactly one syntactically valid unseal share")
    value = bytes(raw)
    for index in range(len(raw)):
        raw[index] = 0
    return destination, password_file, value


def read_existing(destination: Path) -> tuple[str, bool]:
    if not destination.exists():
        return (
            (
                "---\n"
                "# Operator-custodied HashiCorp Vault material. Values in this file "
                "must remain inline-encrypted.\n"
            ),
            False,
        )
    try:
        existing = destination.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        fail(f"cannot read vault overlay: {exc}")
    if existing.lstrip().startswith("$ANSIBLE_VAULT;"):
        fail(
            "vault overlay is whole-file encrypted; choose a dedicated sibling "
            "overlay so the helper never decrypts plaintext to disk"
        )
    if VARIABLE_RE.search(existing):
        fail(
            "vault_unseal_key already exists; refusing replacement or an ambiguous duplicate"
        )
    return existing, True


def encrypt_value(args: argparse.Namespace, password_file: Path, value: bytes) -> str:
    command = [
        args.ansible_vault,
        "encrypt_string",
        "--vault-id",
        f"{args.vault_id}@{password_file}",
        "--stdin-name",
        VARIABLE_NAME,
    ]
    try:
        result = subprocess.run(
            command,
            input=value,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        fail(f"cannot execute ansible-vault: {exc}")
    if result.returncode != 0:
        fail(
            "ansible-vault could not encrypt vault_unseal_key; check the explicit "
            "Vault ID and password file"
        )
    try:
        rendered = result.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        fail("ansible-vault returned non-text output")
    if (
        not rendered.startswith(f"{VARIABLE_NAME}: !vault |\n")
        or "$ANSIBLE_VAULT;" not in rendered
    ):
        fail("ansible-vault returned an unexpected encrypted value")
    return rendered


def verify_encrypted_value(
    args: argparse.Namespace, password_file: Path, rendered: str, expected: bytes
) -> None:
    """Decrypt the emitted ciphertext in memory and compare without printing it."""
    lines = rendered.splitlines()
    if len(lines) < 3 or lines[0] != f"{VARIABLE_NAME}: !vault |":
        fail("cannot isolate the inline-encrypted value for custody verification")
    ciphertext = "\n".join(line.lstrip() for line in lines[1:]) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(prefix=".aigw-vault-verify.")
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="ascii") as output:
            output.write(ciphertext)
            output.flush()
            os.fsync(output.fileno())
        try:
            result = subprocess.run(
                [
                    args.ansible_vault,
                    "view",
                    "--vault-id",
                    f"{args.vault_id}@{password_file}",
                    str(temporary),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        except OSError as exc:
            fail(f"cannot execute ansible-vault verification: {exc}")
        decrypted = result.stdout
        if decrypted.endswith(b"\r\n"):
            decrypted = decrypted[:-2]
        elif decrypted.endswith(b"\n"):
            decrypted = decrypted[:-1]
        if result.returncode != 0 or decrypted != expected:
            fail("encrypted custody verification failed; remote cleanup is not permitted")
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def atomic_write(
    destination: Path, content: str, expected_existing: str, expected_exists: bool
) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        # Recheck immediately before the sole commit operation. This helper
        # never overwrites a concurrently-created custody file.
        current_exists = destination.exists() or destination.is_symlink()
        if current_exists != expected_exists:
            fail("vault overlay changed during encryption; refusing concurrent replacement")
        if current_exists:
            current = destination.read_text(encoding="utf-8")
            if current != expected_existing:
                fail("vault overlay changed during encryption; refusing concurrent replacement")
        os.replace(temporary, destination)
        directory_fd = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def main() -> int:
    try:
        args = arguments()
        destination, password_file, value = validate_inputs(args)
        existing, existed = read_existing(destination)
        encrypted = encrypt_value(args, password_file, value)
        verify_encrypted_value(args, password_file, encrypted, value)
        separator = "" if not existing or existing.endswith("\n") else "\n"
        atomic_write(
            destination,
            existing + separator + encrypted,
            expected_existing=existing,
            expected_exists=existed,
        )
        # Verify the exact ciphertext now durably present at the destination,
        # not merely ansible-vault's pre-write output.
        committed = destination.read_text(encoding="utf-8")
        if not committed.endswith(encrypted):
            fail("committed custody overlay did not contain the expected encrypted value")
        verify_encrypted_value(args, password_file, encrypted, value)
        del value
    except CustodyError as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 2
    print(f"Stored and verified inline-encrypted vault_unseal_key in: {destination}")
    print(
        "Encrypted controller custody is verified. Complete the ordinary "
        "post-bootstrap Ansible converge before remote init-material cleanup."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
