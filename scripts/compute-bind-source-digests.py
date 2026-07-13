#!/usr/bin/env python3
"""Compute bounded keyed digests for reviewed Compose bind-source trees.

The HMAC key is accepted only on stdin. The manifest is non-secret JSON whose
keys are Compose service names and whose values are canonical paths relative to
the supplied stack root. No path may escape that root or traverse a symlink.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
from typing import Iterator


MAX_KEY_BYTES = 4096
MAX_MANIFEST_BYTES = 32_768
MAX_SERVICES = 64
MAX_SOURCES_PER_SERVICE = 64
MAX_OBJECTS_PER_SERVICE = 4096
MAX_BYTES_PER_SERVICE = 64 * 1024 * 1024
SERVICE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class DigestError(ValueError):
    """The requested digest inventory is outside the reviewed boundary."""


def _frame(digest: hmac.HMAC, kind: bytes, relative: str, payload: bytes) -> None:
    encoded = relative.encode("utf-8")
    digest.update(kind)
    digest.update(len(encoded).to_bytes(4, "big"))
    digest.update(encoded)
    digest.update(len(payload).to_bytes(8, "big"))
    digest.update(payload)


def _canonical_relative(value: object) -> Path:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise DigestError("bind-source path must be a bounded non-empty string")
    candidate = Path(value)
    if (
        candidate.is_absolute()
        or candidate.as_posix() != value
        or len(candidate.parts) > 16
    ):
        raise DigestError(f"bind-source path is not canonical: {value!r}")
    if any(part in {"", ".", ".."} or not SEGMENT.fullmatch(part) for part in candidate.parts):
        raise DigestError(f"bind-source path is not canonical: {value!r}")
    return candidate


def _inventory(root: Path, relative: Path) -> Iterator[tuple[bytes, str, Path, os.stat_result]]:
    source = root.joinpath(relative)
    boundary = root
    for component in relative.parts:
        boundary = boundary / component
        try:
            boundary_stat = boundary.lstat()
        except FileNotFoundError as exc:
            raise DigestError(f"bind source is missing: {relative.as_posix()}") from exc
        if stat.S_ISLNK(boundary_stat.st_mode):
            raise DigestError(f"symlink component in bind source: {relative.as_posix()}")
    try:
        source_stat = source.lstat()
    except FileNotFoundError as exc:
        raise DigestError(f"bind source is missing: {relative.as_posix()}") from exc
    if stat.S_ISLNK(source_stat.st_mode):
        raise DigestError(f"bind source is a symlink: {relative.as_posix()}")
    if stat.S_ISREG(source_stat.st_mode):
        yield b"F", relative.as_posix(), source, source_stat
        return
    if not stat.S_ISDIR(source_stat.st_mode):
        raise DigestError(f"bind source is not a regular file/directory: {relative.as_posix()}")

    yield b"D", relative.as_posix(), source, source_stat
    pending = [(source, relative)]
    while pending:
        directory, directory_relative = pending.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as exc:
            raise DigestError(f"cannot enumerate bind source: {directory_relative}") from exc
        child_directories = []
        for entry in entries:
            if not SEGMENT.fullmatch(entry.name):
                raise DigestError(f"noncanonical name below bind source: {directory_relative / entry.name}")
            child_relative = directory_relative / entry.name
            try:
                entry_stat = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise DigestError(f"cannot stat bind source: {child_relative}") from exc
            if stat.S_ISLNK(entry_stat.st_mode):
                raise DigestError(f"symlink below bind source: {child_relative}")
            if stat.S_ISREG(entry_stat.st_mode):
                yield b"F", child_relative.as_posix(), Path(entry.path), entry_stat
            elif stat.S_ISDIR(entry_stat.st_mode):
                yield b"D", child_relative.as_posix(), Path(entry.path), entry_stat
                child_directories.append((Path(entry.path), child_relative))
            else:
                raise DigestError(f"special object below bind source: {child_relative}")
        pending.extend(reversed(child_directories))


def _hash_file(
    path: Path,
    expected: os.stat_result,
    digest: hmac.HMAC,
    remaining_bytes: int,
) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise DigestError(f"cannot open bind source without following links: {path}") from exc
    total = 0
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise DigestError(f"bind source changed type while hashing: {path}")
        if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
            raise DigestError(f"bind source changed identity while hashing: {path}")
        if opened.st_nlink != 1:
            raise DigestError(f"hard-linked bind source is forbidden: {path}")
        stable_fields = (
            "st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid",
            "st_size", "st_mtime_ns", "st_ctime_ns",
        )
        if any(getattr(expected, field) != getattr(opened, field) for field in stable_fields):
            raise DigestError(f"bind source changed before hashing: {path}")
        # Enforce the resource ceiling before the first read. Checking only
        # after streaming a single oversized file would reject the inventory
        # eventually but would not actually bound attacker-controlled I/O.
        if opened.st_size > remaining_bytes:
            raise DigestError("bind-source byte cap exceeded")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            digest.update(chunk)
        final = os.fstat(descriptor)
        if any(getattr(opened, field) != getattr(final, field) for field in stable_fields):
            raise DigestError(f"bind source changed while hashing: {path}")
        if total != opened.st_size:
            raise DigestError(f"bind source size changed while hashing: {path}")
    finally:
        os.close(descriptor)
    return total


def compute_digests(root: Path, manifest: object, key: bytes) -> dict[str, str]:
    if len(key) < 32 or len(key) > MAX_KEY_BYTES:
        raise DigestError("HMAC key must contain 32..4096 bytes")
    if not isinstance(manifest, dict) or not 1 <= len(manifest) <= MAX_SERVICES:
        raise DigestError("digest manifest must be a bounded non-empty object")
    if root.is_symlink() or not root.is_dir() or not root.is_absolute():
        raise DigestError("stack root must be an absolute non-symlink directory")
    resolved_root = root.resolve(strict=True)

    output: dict[str, str] = {}
    for service in sorted(manifest):
        sources = manifest[service]
        if not isinstance(service, str) or not SERVICE.fullmatch(service):
            raise DigestError(f"invalid Compose service name: {service!r}")
        if not isinstance(sources, list) or not 1 <= len(sources) <= MAX_SOURCES_PER_SERVICE:
            raise DigestError(f"invalid bind-source list for {service}")
        relative_sources = [_canonical_relative(source) for source in sources]
        if len({source.as_posix() for source in relative_sources}) != len(relative_sources):
            raise DigestError(f"duplicate bind source for {service}")
        for index, source in enumerate(relative_sources):
            if any(
                source in other.parents or other in source.parents
                for other in relative_sources[index + 1 :]
            ):
                raise DigestError(f"nested bind sources for {service}")

        digest = hmac.new(
            key,
            b"aigw-bind-source-digest/v1\x00" + service.encode("ascii") + b"\x00",
            hashlib.sha256,
        )
        object_count = 0
        byte_count = 0
        for relative in sorted(relative_sources, key=lambda item: item.as_posix()):
            source = resolved_root.joinpath(relative)
            try:
                source.relative_to(resolved_root)
            except ValueError as exc:
                raise DigestError(f"bind source escapes stack root: {relative}") from exc
            for kind, inventory_path, path, path_stat in _inventory(resolved_root, relative):
                object_count += 1
                if object_count > MAX_OBJECTS_PER_SERVICE:
                    raise DigestError(f"bind-source object cap exceeded for {service}")
                metadata = struct.pack(
                    ">IIIQ",
                    stat.S_IFMT(path_stat.st_mode) | stat.S_IMODE(path_stat.st_mode),
                    path_stat.st_uid,
                    path_stat.st_gid,
                    path_stat.st_size if kind == b"F" else 0,
                )
                _frame(digest, kind, inventory_path, metadata)
                if kind == b"F":
                    byte_count += _hash_file(
                        path,
                        path_stat,
                        digest,
                        MAX_BYTES_PER_SERVICE - byte_count,
                    )
        output[service] = digest.hexdigest()
    return output


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: compute-bind-source-digests.py STACK_ROOT MANIFEST_JSON", file=sys.stderr)
        return 2
    encoded_manifest = argv[2].encode("utf-8")
    if len(encoded_manifest) > MAX_MANIFEST_BYTES:
        print("bind-digest error: manifest exceeds the byte cap", file=sys.stderr)
        return 2
    key = sys.stdin.buffer.read(MAX_KEY_BYTES + 1)
    try:
        manifest = json.loads(encoded_manifest)
        output = compute_digests(Path(argv[1]), manifest, key)
    except (DigestError, json.JSONDecodeError, UnicodeError) as exc:
        print(f"bind-digest error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
