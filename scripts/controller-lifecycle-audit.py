#!/usr/bin/env python3
"""Append one strictly bounded controller lifecycle record on the target."""

from __future__ import annotations

import datetime as dt
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid


AUDIT_DIRECTORY = Path("/var/log/ai-gateway-controller")
AUDIT_FILE_NAME = "lifecycle.jsonl"
ROTATED_FILE_NAME = "lifecycle.jsonl.1"
LOCK_FILE = Path("/run/lock/aigw-controller-lifecycle-audit.lock")
ROOT_UID = 0
ROOT_GID = 0
ALLOY_GID = 473
MAX_FILE_BYTES = 8 * 1024 * 1024

ACTION_OUTCOMES = {
    "upgrade": frozenset({"started", "success", "failed"}),
    "rollback": frozenset({"started", "success", "failed"}),
}
HEX64 = re.compile(r"[0-9a-f]{64}")
COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")


class AuditError(RuntimeError):
    """The target audit boundary is unsafe or an input is malformed."""


def canonical_operation_id(value: str) -> str:
    """Return a canonical lowercase RFC 4122 UUIDv4 or fail closed."""

    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError, TypeError) as exc:
        raise AuditError("operation_id must be a canonical UUIDv4") from exc
    if parsed.version != 4 or parsed.variant != uuid.RFC_4122 or str(parsed) != value:
        raise AuditError("operation_id must be a canonical UUIDv4")
    return value


def validate_record(arguments: list[str]) -> dict[str, object]:
    """Build the only JSON shape this tool is allowed to write."""

    if len(arguments) != 7:
        raise AuditError(
            "expected ACTION OUTCOME OPERATION_ID MANIFEST_SHA256 COMMIT "
            "ENVOY_IMAGE_ID EGRESS_POLICY_SHA256"
        )
    action, outcome, operation_id, manifest, commit, image_id, policy = arguments
    if action not in ACTION_OUTCOMES or outcome not in ACTION_OUTCOMES[action]:
        raise AuditError("action/outcome is not in the reviewed lifecycle catalog")
    if HEX64.fullmatch(manifest) is None:
        raise AuditError("release manifest digest must be lowercase SHA-256")
    if COMMIT.fullmatch(commit) is None:
        raise AuditError("release commit must be a lowercase Git object ID")
    if IMAGE_ID.fullmatch(image_id) is None:
        raise AuditError("Envoy image ID must be a lowercase SHA-256 image ID")
    if HEX64.fullmatch(policy) is None:
        raise AuditError("egress policy digest must be lowercase SHA-256")

    timestamp = dt.datetime.now(dt.timezone.utc).isoformat(
        timespec="milliseconds"
    ).replace("+00:00", "Z")
    return {
        "schema_version": 1,
        "event": "aigw.controller.lifecycle",
        "timestamp": timestamp,
        "action": action,
        "outcome": outcome,
        "operation_id": canonical_operation_id(operation_id),
        "release_manifest_sha256": manifest,
        "release_commit": commit,
        "envoy_image_id": image_id,
        "egress_policy_sha256": policy,
    }


def _require_directory() -> int:
    try:
        metadata = AUDIT_DIRECTORY.lstat()
    except OSError as exc:
        raise AuditError("audit directory is unavailable") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != ROOT_UID
        or metadata.st_gid != ALLOY_GID
        or stat.S_IMODE(metadata.st_mode) != 0o750
    ):
        raise AuditError("audit directory must be root:473 mode 0750 without a link")
    try:
        return os.open(
            AUDIT_DIRECTORY,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except OSError as exc:
        raise AuditError("audit directory changed during inspection") from exc


def _require_file(metadata: os.stat_result, label: str) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != ROOT_UID
        or metadata.st_gid != ALLOY_GID
        or stat.S_IMODE(metadata.st_mode) != 0o640
        or metadata.st_nlink != 1
        or metadata.st_size > MAX_FILE_BYTES
    ):
        raise AuditError(
            f"{label} must be root:473 mode 0640, single-link, and at most 8 MiB"
        )


def _stat_optional(directory_fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise AuditError(f"cannot inspect {name}") from exc


def _open_lock() -> int:
    try:
        descriptor = os.open(
            LOCK_FILE,
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
    except OSError as exc:
        raise AuditError("cannot open the lifecycle audit lock") from exc
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != ROOT_UID
        or metadata.st_gid != ROOT_GID
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        os.close(descriptor)
        raise AuditError("lifecycle audit lock has an unsafe owner or mode")
    return descriptor


def _require_existing_audit_files(directory_fd: int) -> None:
    """Validate both optional files before this writer mutates either one."""

    for name in (AUDIT_FILE_NAME, ROTATED_FILE_NAME):
        metadata = _stat_optional(directory_fd, name)
        if metadata is not None:
            _require_file(metadata, name)


def _rotate_if_needed(directory_fd: int, line_size: int) -> bool:
    """Rotate when needed and report whether the active file still exists."""

    current = _stat_optional(directory_fd, AUDIT_FILE_NAME)
    if current is None:
        return False
    _require_file(current, AUDIT_FILE_NAME)
    if current.st_size + line_size <= MAX_FILE_BYTES:
        return True

    prior = _stat_optional(directory_fd, ROTATED_FILE_NAME)
    if prior is not None:
        _require_file(prior, ROTATED_FILE_NAME)
        os.unlink(ROTATED_FILE_NAME, dir_fd=directory_fd)
    os.rename(
        AUDIT_FILE_NAME,
        ROTATED_FILE_NAME,
        src_dir_fd=directory_fd,
        dst_dir_fd=directory_fd,
    )
    os.fsync(directory_fd)
    return False


def append_record(record: dict[str, object]) -> None:
    """Append one record with a fixed 8 MiB/two-file rotation boundary."""

    if os.geteuid() != ROOT_UID:
        raise AuditError("controller lifecycle audit writer must run as root")
    line = (
        json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")
    if len(line) > 1024:
        raise AuditError("lifecycle audit record exceeds its fixed size bound")

    directory_fd = _require_directory()
    lock_fd = _open_lock()
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        _require_existing_audit_files(directory_fd)
        active_exists = _rotate_if_needed(directory_fd, len(line))
        flags = os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC
        if not active_exists:
            flags |= os.O_CREAT | os.O_EXCL
        try:
            audit_fd = os.open(AUDIT_FILE_NAME, flags, 0o640, dir_fd=directory_fd)
        except OSError as exc:
            raise AuditError("cannot open the lifecycle audit file") from exc
        try:
            if not active_exists:
                os.fchown(audit_fd, ROOT_UID, ALLOY_GID)
                os.fchmod(audit_fd, 0o640)
            _require_file(os.fstat(audit_fd), AUDIT_FILE_NAME)
            written = os.write(audit_fd, line)
            if written != len(line):
                raise AuditError("lifecycle audit append was incomplete")
            os.fsync(audit_fd)
        finally:
            os.close(audit_fd)
        os.fsync(directory_fd)
    finally:
        os.close(lock_fd)
        os.close(directory_fd)


def main(argv: list[str] | None = None) -> int:
    try:
        append_record(validate_record(list(sys.argv[1:] if argv is None else argv)))
    except (AuditError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print("CONTROLLER_LIFECYCLE_AUDIT_RECORDED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
