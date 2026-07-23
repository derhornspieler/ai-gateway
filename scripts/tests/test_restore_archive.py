from __future__ import annotations

from io import BytesIO
import hashlib
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from restore_archive import (  # noqa: E402
    ArchiveError,
    MIN_FREE_RESERVE_BYTES,
    POSTGRES_FILES,
    STACK_REQUIRED_ROOTS,
    expected_volumes,
    prepare_restore,
)


def _tar_bytes(
    entries: list[tuple[str, bytes | None, bytes]],
    *,
    sparse_names: frozenset[str] = frozenset(),
) -> bytes:
    """Build a gzip tar: (name, content-or-None-for-dir, type)."""
    output = BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, content, member_type in entries:
            member = tarfile.TarInfo(name)
            member.type = member_type
            member.mode = 0o700 if member_type == tarfile.DIRTYPE else 0o600
            if name in sparse_names:
                # PAX sparse metadata can accompany an ordinary REGTYPE.
                member.pax_headers = {"SCHILY.filetype": "sparse"}
            if content is not None:
                member.size = len(content)
                archive.addfile(member, BytesIO(content))
            else:
                archive.addfile(member)
    return output.getvalue()


def _volume_tar(*, unsafe_link: bool = False, unsafe_sparse: bool = False) -> bytes:
    entries = [
        (".", None, tarfile.DIRTYPE),
        ("./data", None, tarfile.DIRTYPE),
        ("./data/value", b"state", tarfile.REGTYPE),
    ]
    if unsafe_link:
        entries.append(("./escape", None, tarfile.SYMTYPE))
    return _tar_bytes(
        entries,
        sparse_names=frozenset({"./data/value"}) if unsafe_sparse else frozenset(),
    )


def _stack_config_tar(*, unsafe_link: bool = False) -> bytes:
    entries: list[tuple[str, bytes | None, bytes]] = []
    for root in sorted(STACK_REQUIRED_ROOTS):
        if root in {
            "docker-compose.yml",
            "docker-compose.dns.yml",
            "docker-compose.platform-dns.yml",
            "bind-source-digest-inputs.json",
            ".env",
        }:
            entries.append((root, f"{root}\n".encode(), tarfile.REGTYPE))
        else:
            entries.append((root, None, tarfile.DIRTYPE))
            entries.append((f"{root}/placeholder", b"config", tarfile.REGTYPE))
    if unsafe_link:
        entries.append(("scripts/escape", None, tarfile.SYMTYPE))
    return _tar_bytes(entries)


def _outer_backup(
    *,
    extra_outer: bool = False,
    missing_manifest_volume: bool = False,
    unsafe_volume: str | None = None,
    sparse_volume: str | None = None,
    unsafe_stack_link: bool = False,
) -> bytes:
    profile = "generic-rocky9"
    volumes = sorted(expected_volumes(profile))
    files: dict[str, bytes] = {
        "running-services.txt": b"postgres\n",
        "stack-config.tar.gz": _stack_config_tar(unsafe_link=unsafe_stack_link),
    }
    for relative in POSTGRES_FILES:
        files[relative] = f"backup:{relative}\n".encode()
    for volume in volumes:
        files[f"volumes/{volume}.tar.gz"] = _volume_tar(
            unsafe_link=volume == unsafe_volume,
            unsafe_sparse=volume == sparse_volume,
        )
    if extra_outer:
        files["unexpected.txt"] = b"not allowed"

    manifest_volumes = volumes[:-1] if missing_manifest_volume else volumes
    manifest = {
        "format": "aigw-state-backup-v1",
        "backup_id": "00000000-0000-0000-0000-000000000000",
        "created_at": "2026-01-01T00:00:00+00:00",
        "project": "ai-gateway",
        "deployment_profile": profile,
        "postgres_version": "18.4",
        "volumes": manifest_volumes,
        "running_services": ["postgres"],
        "images": ["example.invalid/image@sha256:" + "a" * 64],
        "sha256": {
            name: hashlib.sha256(content).hexdigest()
            for name, content in files.items()
        },
    }
    files["manifest.json"] = json.dumps(manifest).encode()

    entries: list[tuple[str, bytes | None, bytes]] = [
        (".", None, tarfile.DIRTYPE),
        ("./postgres", None, tarfile.DIRTYPE),
        ("./volumes", None, tarfile.DIRTYPE),
    ]
    entries.extend(
        (f"./{name}", content, tarfile.REGTYPE)
        for name, content in sorted(files.items())
    )
    return _tar_bytes(entries)


class RestoreArchiveTests(unittest.TestCase):
    def prepare(self, payload: bytes) -> tuple[Path, Path]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        archive = root / "outer.tar.gz"
        archive.write_bytes(payload)
        extracted = root / "extracted"
        config = root / "config"
        volume_target = root / "docker"
        volume_target.mkdir()
        prepare_restore(
            archive,
            extracted,
            config,
            project="ai-gateway",
            profile="generic-rocky9",
            volume_target=volume_target,
        )
        return extracted, config

    def test_valid_profile_is_fully_staged(self) -> None:
        extracted, config = self.prepare(_outer_backup())
        self.assertTrue((extracted / "manifest.json").is_file())
        self.assertTrue((config / "docker-compose.yml").is_file())
        self.assertTrue((config / "docker-compose.dns.yml").is_file())
        self.assertTrue((config / "docker-compose.platform-dns.yml").is_file())
        self.assertTrue((config / "scripts" / "placeholder").is_file())

    def test_extra_outer_member_is_rejected(self) -> None:
        with self.assertRaisesRegex(ArchiveError, "safety cap|inventory mismatch"):
            self.prepare(_outer_backup(extra_outer=True))

    def test_manifest_volume_set_must_be_exact(self) -> None:
        with self.assertRaisesRegex(ArchiveError, "volume inventory"):
            self.prepare(_outer_backup(missing_manifest_volume=True))

    def test_link_inside_volume_is_rejected_before_restore(self) -> None:
        volume = sorted(expected_volumes("generic-rocky9"))[0]
        with self.assertRaisesRegex(ArchiveError, "non-regular member"):
            self.prepare(_outer_backup(unsafe_volume=volume))

    def test_regtype_with_sparse_metadata_is_rejected(self) -> None:
        volume = sorted(expected_volumes("generic-rocky9"))[0]
        with self.assertRaisesRegex(ArchiveError, "sparse member"):
            self.prepare(_outer_backup(sparse_volume=volume))

    def test_per_volume_declared_byte_ceiling_is_enforced(self) -> None:
        with mock.patch("restore_archive.MAX_VOLUME_DECLARED_BYTES", 4):
            with self.assertRaisesRegex(ArchiveError, "declared-data safety cap"):
                self.prepare(_outer_backup())

    def test_total_volume_declared_byte_ceiling_is_enforced(self) -> None:
        with mock.patch("restore_archive.MAX_TOTAL_VOLUME_DECLARED_BYTES", 9):
            with self.assertRaisesRegex(ArchiveError, "total declared-data"):
                self.prepare(_outer_backup())

    def test_link_inside_stack_config_is_rejected(self) -> None:
        with self.assertRaisesRegex(ArchiveError, "non-regular member"):
            self.prepare(_outer_backup(unsafe_stack_link=True))

    def test_declared_outer_size_must_leave_staging_reserve(self) -> None:
        with mock.patch("restore_archive.shutil.disk_usage") as disk_usage:
            disk_usage.return_value.free = 1
            with self.assertRaisesRegex(ArchiveError, "available restore staging"):
                self.prepare(_outer_backup())

    def test_volume_target_must_preserve_free_space_reserve(self) -> None:
        ample = mock.Mock(free=1024 * 1024 * 1024)
        no_reserve = mock.Mock(free=MIN_FREE_RESERVE_BYTES - 1)
        with mock.patch(
            "restore_archive.shutil.disk_usage",
            side_effect=[ample, ample, no_reserve],
        ):
            with self.assertRaisesRegex(ArchiveError, "free-space reserve"):
                self.prepare(_outer_backup())


if __name__ == "__main__":
    unittest.main()
