#!/usr/bin/env python3
"""Validate and stage an AI Gateway state backup without mutating live state.

The encrypted envelope is authenticated out-of-band by ``state-restore.sh``.
This module treats its decrypted tar payload as hostile nonetheless: every
member and manifest relationship is proven before the shell script stops a
container, wipes a volume, or replaces deployed configuration.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
from typing import Iterable


BASE_VOLUMES = frozenset(
    {
        "pg_data",
        "openwebui_data",
        "vault_data",
        "vault_audit",
        "alloy_data",
        "prom_data",
        "alertmanager_data",
        "loki_data",
        "grafana_data",
    }
)
POSTGRES_FILES = frozenset(
    {
        "postgres/globals.sql",
        "postgres/litellm.dump",
        "postgres/keycloak.dump",
        "postgres/rotator.dump",
    }
)
STACK_REQUIRED_ROOTS = frozenset(
    {
        "docker-compose.yml",
        "docker-compose.dns.yml",
        "docker-compose.platform-dns.yml",
        ".env",
        "alertmanager",
        "alloy",
        "cribl-mock",
        "grafana",
        "keycloak",
        "litellm",
        "loki",
        "postgres",
        "prometheus",
        "traefik",
        "services",
        "scripts",
        "certs",
    }
)
# "tempo" is tolerated (never required) so a pre-Tempo-removal archive's
# configuration tree still passes the top-level root scan; its volume
# manifest (tempo_data) still fails the exact-volume contract by design.
STACK_OPTIONAL_ROOTS = frozenset(
    {"bind-source-digest-inputs.json", "secrets", "tempo"}
)
SAFE_SERVICE_RE = re.compile(r"[a-z0-9][a-z0-9-]*\Z")
SAFE_PROJECT_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}\Z")
SAFE_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
MAX_STACK_MEMBERS = 100_000
MAX_VOLUME_MEMBERS = 2_000_000
# These are format safety ceilings, not capacity promises. A larger supported
# deployment requires an explicit format revision and restore rehearsal rather
# than accepting attacker-controlled multi-petabyte tar size declarations.
MAX_VOLUME_DECLARED_BYTES = 1024 * 1024 * 1024 * 1024
MAX_TOTAL_VOLUME_DECLARED_BYTES = 2 * MAX_VOLUME_DECLARED_BYTES
MIN_FREE_RESERVE_BYTES = 256 * 1024 * 1024


class ArchiveError(RuntimeError):
    """The decrypted backup violates the reviewed restore format."""


def expected_volumes(profile: str) -> frozenset[str]:
    return BASE_VOLUMES


def _normalized_name(raw: str) -> str:
    if not isinstance(raw, str) or not raw or "\\" in raw or "\x00" in raw:
        raise ArchiveError(f"unsafe archive path: {raw!r}")
    path = PurePosixPath(raw)
    if path.is_absolute() or ".." in path.parts:
        raise ArchiveError(f"unsafe archive path: {raw!r}")
    parts = [part for part in path.parts if part not in {"", "."}]
    return "/".join(parts)


def _scan_members(
    archive: tarfile.TarFile,
    *,
    label: str,
    allowed_files: frozenset[str] | None = None,
    allowed_directories: frozenset[str] | None = None,
    allowed_roots: frozenset[str] | None = None,
    require_dot_root: bool = False,
    max_members: int | None = None,
    max_file_sizes: dict[str, int] | None = None,
    max_declared_bytes: int | None = None,
) -> list[tuple[tarfile.TarInfo, str]]:
    scanned: list[tuple[tarfile.TarInfo, str]] = []
    seen: set[str] = set()
    files: set[str] = set()
    directories: set[str] = set()
    declared_bytes = 0

    for count, member in enumerate(archive, start=1):
        if max_members is not None and count > max_members:
            raise ArchiveError(f"{label} exceeds the {max_members}-member safety cap")
        normalized = _normalized_name(member.name)
        if normalized in seen:
            raise ArchiveError(f"{label} contains duplicate path {normalized!r}")
        seen.add(normalized)

        pax_headers = getattr(member, "pax_headers", {}) or {}
        sparse_metadata = getattr(member, "sparse", None)
        if sparse_metadata is not None or any(
            key.startswith("GNU.sparse.")
            or key in {"GNU.sparse", "SCHILY.realsize"}
            or (key == "SCHILY.filetype" and value == "sparse")
            for key, value in pax_headers.items()
        ):
            # GNU/PAX sparse members can be reported as ordinary REGTYPE by
            # tarfile. Reject their metadata explicitly before trusting size.
            raise ArchiveError(f"{label} contains sparse member {member.name!r}")

        # Explicitly reject symlinks, hard links, sparse/special files, devices,
        # FIFOs, and unknown extension types. Only ordinary files/directories
        # can ever reach a restore staging directory or volume extractor.
        if member.type == tarfile.DIRTYPE:
            directories.add(normalized)
        elif member.type in {tarfile.REGTYPE, tarfile.AREGTYPE}:
            if not normalized:
                raise ArchiveError(f"{label} contains a file at archive root")
            if member.size < 0:
                raise ArchiveError(f"{label} contains a negative-size member")
            declared_bytes += member.size
            if (
                max_declared_bytes is not None
                and declared_bytes > max_declared_bytes
            ):
                raise ArchiveError(
                    f"{label} exceeds the {max_declared_bytes}-byte "
                    "declared-data safety cap"
                )
            if max_file_sizes and normalized in max_file_sizes:
                limit = max_file_sizes[normalized]
                if member.size > limit:
                    raise ArchiveError(
                        f"{label} member {normalized!r} exceeds {limit} bytes"
                    )
            files.add(normalized)
        else:
            raise ArchiveError(
                f"{label} contains non-regular member {member.name!r}"
            )
        if member.mode & ~0o7777:
            raise ArchiveError(f"{label} contains an invalid mode for {member.name!r}")
        scanned.append((member, normalized))

    if require_dot_root and "" not in directories:
        raise ArchiveError(f"{label} does not contain the exact '.' volume root")
    if allowed_files is not None and files != set(allowed_files):
        missing = sorted(set(allowed_files) - files)
        extra = sorted(files - set(allowed_files))
        raise ArchiveError(
            f"{label} file inventory mismatch; missing={missing}, extra={extra}"
        )
    if allowed_directories is not None and directories != set(allowed_directories):
        missing = sorted(set(allowed_directories) - directories)
        extra = sorted(directories - set(allowed_directories))
        raise ArchiveError(
            f"{label} directory inventory mismatch; missing={missing}, extra={extra}"
        )
    if allowed_roots is not None:
        roots = {
            name.split("/", 1)[0]
            for name in files | {name for name in directories if name}
        }
        extra_roots = roots - set(allowed_roots)
        if extra_roots:
            raise ArchiveError(
                f"{label} contains unexpected top-level roots {sorted(extra_roots)}"
            )

    file_paths = files
    for name in files | {name for name in directories if name}:
        parts = name.split("/")
        for index in range(1, len(parts)):
            ancestor = "/".join(parts[:index])
            if ancestor in file_paths:
                raise ArchiveError(
                    f"{label} places {name!r} beneath regular file {ancestor!r}"
                )
    return scanned


def _extract_regular(
    archive: tarfile.TarFile,
    scanned: Iterable[tuple[tarfile.TarInfo, str]],
    destination: Path,
    *,
    preserve_modes: bool,
) -> None:
    destination = destination.resolve()
    declared_bytes = sum(
        member.size
        for member, _ in scanned
        if member.type in {tarfile.REGTYPE, tarfile.AREGTYPE}
    )
    free_bytes = shutil.disk_usage(destination.parent).free
    if declared_bytes > max(0, free_bytes - MIN_FREE_RESERVE_BYTES):
        raise ArchiveError(
            "archive declared size exceeds available restore staging space "
            f"after the {MIN_FREE_RESERVE_BYTES}-byte reserve"
        )
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    directory_modes: list[tuple[Path, int]] = []
    for member, normalized in scanned:
        target = destination.joinpath(*normalized.split("/")) if normalized else destination
        if member.type == tarfile.DIRTYPE:
            target.mkdir(mode=0o700, parents=True, exist_ok=True)
            directory_modes.append((target, member.mode & 0o777))
            continue

        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        source = archive.extractfile(member)
        if source is None:
            raise ArchiveError(f"archive member {member.name!r} is unreadable")
        with source, target.open("xb") as output:
            shutil.copyfileobj(source, output, length=1024 * 1024)
        target.chmod((member.mode & 0o777) if preserve_modes else 0o600)

    for directory, mode in sorted(
        directory_modes, key=lambda item: len(item[0].parts), reverse=True
    ):
        directory.chmod(mode if preserve_modes else 0o700)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_manifest(
    root: Path, *, project: str, profile: str, expected_files: frozenset[str]
) -> dict[str, object]:
    try:
        manifest = json.loads((root / "manifest.json").read_text())
    except (OSError, UnicodeError, ValueError) as exc:
        raise ArchiveError("backup manifest is missing or invalid JSON") from exc
    if not isinstance(manifest, dict) or manifest.get("format") != "aigw-state-backup-v1":
        raise ArchiveError("unsupported backup format")
    if manifest.get("project") != project:
        raise ArchiveError("backup Compose project mismatch")
    if manifest.get("deployment_profile", "") != profile:
        raise ArchiveError("backup deployment profile/Compose overlay mismatch")

    volumes = manifest.get("volumes")
    wanted_volumes = expected_volumes(profile)
    if (
        not isinstance(volumes, list)
        or not all(isinstance(value, str) for value in volumes)
        or len(volumes) != len(set(volumes))
        or set(volumes) != set(wanted_volumes)
    ):
        raise ArchiveError(
            "backup volume inventory does not exactly match the deployment profile"
        )

    checksums = manifest.get("sha256")
    checksum_files = expected_files - {"manifest.json"}
    if not isinstance(checksums, dict) or set(checksums) != set(checksum_files):
        raise ArchiveError("backup manifest checksum inventory is not exact")
    for relative in sorted(checksum_files):
        expected = checksums.get(relative)
        if not isinstance(expected, str) or SAFE_SHA256_RE.fullmatch(expected) is None:
            raise ArchiveError(f"backup checksum is invalid for {relative}")
        path = root / relative
        if not path.is_file() or path.is_symlink() or _file_sha256(path) != expected:
            raise ArchiveError(f"backup member checksum mismatch: {relative}")

    running = manifest.get("running_services")
    if (
        not isinstance(running, list)
        or not all(
            isinstance(service, str) and SAFE_SERVICE_RE.fullmatch(service)
            for service in running
        )
        or len(running) != len(set(running))
    ):
        raise ArchiveError("backup running-service inventory is invalid")
    return manifest


def prepare_restore(
    archive_path: Path,
    extracted_root: Path,
    config_root: Path,
    *,
    project: str,
    profile: str,
    volume_target: Path | None = None,
) -> None:
    volumes = expected_volumes(profile)
    outer_files = frozenset(
        {
            "manifest.json",
            "running-services.txt",
            "stack-config.tar.gz",
            *POSTGRES_FILES,
            *(f"volumes/{volume}.tar.gz" for volume in volumes),
        }
    )
    with tarfile.open(archive_path, "r:gz") as outer:
        scanned = _scan_members(
            outer,
            label="decrypted outer archive",
            allowed_files=outer_files,
            allowed_directories=frozenset({"", "postgres", "volumes"}),
            max_members=len(outer_files) + 3,
            max_file_sizes={
                "manifest.json": 1024 * 1024,
                "running-services.txt": 1024 * 1024,
                "stack-config.tar.gz": 1024 * 1024 * 1024,
                "postgres/globals.sql": 64 * 1024 * 1024,
            },
        )
        _extract_regular(outer, scanned, extracted_root, preserve_modes=False)

    _load_manifest(
        extracted_root,
        project=project,
        profile=profile,
        expected_files=outer_files,
    )

    total_volume_bytes = 0
    for volume in sorted(volumes):
        with tarfile.open(extracted_root / "volumes" / f"{volume}.tar.gz", "r:gz") as tf:
            scanned = _scan_members(
                tf,
                label=f"volume archive {volume}",
                require_dot_root=True,
                max_members=MAX_VOLUME_MEMBERS,
                max_declared_bytes=MAX_VOLUME_DECLARED_BYTES,
            )
            total_volume_bytes += sum(
                member.size
                for member, _ in scanned
                if member.type in {tarfile.REGTYPE, tarfile.AREGTYPE}
            )
            if total_volume_bytes > MAX_TOTAL_VOLUME_DECLARED_BYTES:
                raise ArchiveError(
                    "volume archives exceed the total declared-data safety cap"
                )

    allowed_roots = STACK_REQUIRED_ROOTS | STACK_OPTIONAL_ROOTS
    with tarfile.open(extracted_root / "stack-config.tar.gz", "r:gz") as config:
        scanned = _scan_members(
            config,
            label="stack configuration archive",
            allowed_roots=allowed_roots,
            max_members=MAX_STACK_MEMBERS,
        )
        present_roots = {
            name.split("/", 1)[0]
            for _, name in scanned
            if name
        }
        required_roots = set(STACK_REQUIRED_ROOTS)
        if not required_roots.issubset(present_roots):
            raise ArchiveError(
                "stack configuration archive lacks required top-level roots: "
                f"{sorted(required_roots - present_roots)}"
            )
        _extract_regular(config, scanned, config_root, preserve_modes=True)

    if volume_target is not None:
        if not volume_target.is_dir() or volume_target.is_symlink():
            raise ArchiveError("volume restore target must be a real directory")
        free_bytes = shutil.disk_usage(volume_target).free
        if free_bytes < MIN_FREE_RESERVE_BYTES:
            raise ArchiveError(
                "volume restore target lacks the required free-space reserve"
            )
        usable_bytes = free_bytes - MIN_FREE_RESERVE_BYTES
        if total_volume_bytes > usable_bytes:
            raise ArchiveError(
                "volume archives declare more data than the live restore "
                "target can hold while preserving the free-space reserve"
            )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--extracted-root", required=True, type=Path)
    parser.add_argument("--config-root", required=True, type=Path)
    parser.add_argument("--project", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--volume-target", required=True, type=Path)
    args = parser.parse_args()
    if SAFE_PROJECT_RE.fullmatch(args.project) is None:
        raise SystemExit("unsafe Compose project name")
    for destination in (args.extracted_root, args.config_root):
        if destination.exists() or destination.is_symlink():
            raise SystemExit(f"restore destination must not exist: {destination}")
    try:
        prepare_restore(
            args.archive,
            args.extracted_root,
            args.config_root,
            project=args.project,
            profile=args.profile,
            volume_target=args.volume_target,
        )
    except (ArchiveError, OSError, tarfile.TarError) as exc:
        raise SystemExit(f"restore archive rejected: {exc}") from exc


if __name__ == "__main__":
    main()
