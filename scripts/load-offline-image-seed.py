#!/usr/bin/env python3
"""Verify and load one pre-staged Docker image seed exactly once.

The caller supplies an absolute archive path, its reviewed SHA-256, and a
root-only marker directory.  No archive bytes are accepted until ownership,
mode, compression integrity, and digest all match.  A marker is written only
after both sides of the zstd -> docker image load pipeline succeed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT_UID = 0
ROOT_GID = 0
SEED_MODE = 0o600
MARKER_DIR_MODE = 0o700
MARKER_MODE = 0o600
FIXED_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
LOCAL_DOCKER_HOST = "unix:///run/docker.sock"
REPOSITORY_COMPONENT = re.compile(r"^[a-z0-9]+(?:[._-]+[a-z0-9]+)*$")
TAG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")


class SeedError(RuntimeError):
    """A fail-closed seed validation or load error."""


def _mode(value: os.stat_result) -> int:
    return stat.S_IMODE(value.st_mode)


def validate_arguments(
    archive: Path,
    archive_digest: str,
    manifest: Path,
    manifest_digest: str,
    marker_dir: Path,
) -> None:
    if not archive.is_absolute():
        raise SeedError("archive path must be absolute")
    if not str(archive).endswith(".docker.tar.zst"):
        raise SeedError("archive path must end in .docker.tar.zst")
    if not manifest.is_absolute():
        raise SeedError("manifest path must be absolute")
    if not str(manifest).endswith(".manifest.json"):
        raise SeedError("manifest path must end in .manifest.json")
    if not marker_dir.is_absolute():
        raise SeedError("marker directory must be absolute")
    for label, digest in (
        ("archive", archive_digest),
        ("manifest", manifest_digest),
    ):
        if len(digest) != 64 or any(
            character not in "0123456789abcdef" for character in digest
        ):
            raise SeedError(
                f"expected {label} SHA-256 must be exactly 64 lowercase "
                "hexadecimal characters"
            )


def validate_marker_dir(marker_dir: Path) -> None:
    try:
        metadata = marker_dir.lstat()
    except FileNotFoundError:
        try:
            marker_dir.mkdir(mode=MARKER_DIR_MODE)
            os.chown(marker_dir, ROOT_UID, ROOT_GID)
            os.chmod(marker_dir, MARKER_DIR_MODE)
        except OSError as exc:
            raise SeedError(f"cannot create marker directory: {exc}") from exc
        metadata = marker_dir.lstat()

    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise SeedError("marker directory must be a real directory, not a symlink")
    if (metadata.st_uid, metadata.st_gid) != (ROOT_UID, ROOT_GID):
        raise SeedError("marker directory must be owned by root:root")
    if _mode(metadata) != MARKER_DIR_MODE:
        raise SeedError("marker directory mode must be 0700")


def marker_path(marker_dir: Path, archive_digest: str, manifest_digest: str) -> Path:
    return marker_dir / f"{archive_digest}-{manifest_digest}.loaded"


def marker_is_valid(marker: Path, archive_digest: str, manifest_digest: str) -> bool:
    try:
        metadata = marker.lstat()
    except FileNotFoundError:
        return False

    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise SeedError("existing checksum marker must be a regular file, not a symlink")
    if (metadata.st_uid, metadata.st_gid) != (ROOT_UID, ROOT_GID):
        raise SeedError("existing checksum marker must be owned by root:root")
    if _mode(metadata) != MARKER_MODE:
        raise SeedError("existing checksum marker mode must be 0600")
    try:
        content = marker.read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise SeedError(f"cannot read existing checksum marker: {exc}") from exc
    if content != f"{archive_digest} {manifest_digest}\n":
        raise SeedError("existing checksum marker content does not match its expected digest")
    return True


def validate_regular_file(path: Path, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise SeedError(f"pre-staged {label} is missing: {path}") from exc

    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise SeedError(f"{label} must be a regular file, not a symlink")
    if (metadata.st_uid, metadata.st_gid) != (ROOT_UID, ROOT_GID):
        raise SeedError(f"{label} must be owned by root:root")
    if _mode(metadata) != SEED_MODE:
        raise SeedError(f"{label} mode must be 0600")
    if metadata.st_size <= 0:
        raise SeedError(f"{label} must not be empty")
    return metadata


def sha256_file(path: Path, label: str) -> str:
    actual = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                actual.update(block)
    except OSError as exc:
        raise SeedError(f"cannot read {label}: {exc}") from exc
    return actual.hexdigest()


def validate_archive(archive: Path, expected_digest: str) -> None:
    validate_regular_file(archive, "image seed")
    if sha256_file(archive, "image seed") != expected_digest:
        raise SeedError("image seed SHA-256 does not match the reviewed inventory value")


def validate_manifest_file(manifest: Path, expected_digest: str) -> dict[str, object]:
    metadata = validate_regular_file(manifest, "image seed manifest")
    if metadata.st_size > 1024 * 1024:
        raise SeedError("image seed manifest exceeds the 1 MiB safety bound")
    if sha256_file(manifest, "image seed manifest") != expected_digest:
        raise SeedError(
            "image seed manifest SHA-256 does not match the reviewed inventory value"
        )

    try:
        decoded = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SeedError(f"cannot decode image seed manifest: {exc}") from exc
    if not isinstance(decoded, dict):
        raise SeedError("image seed manifest root must be an object")
    return decoded


def require_executable(name: str) -> str:
    executable = shutil.which(name, path=FIXED_PATH)
    if not executable:
        raise SeedError(f"required executable is unavailable in the fixed system PATH: {name}")
    return executable


def require_docker_ready(docker: str) -> str:
    check = subprocess.run(
        [docker, "--host", LOCAL_DOCKER_HOST, "info", "--format", "{{.Architecture}}"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check.returncode != 0:
        raise SeedError("Docker daemon is not ready")
    architecture = check.stdout.decode("ascii", errors="replace").strip()
    normalized = {
        "aarch64": "arm64",
        "x86_64": "amd64",
    }.get(architecture, architecture)
    if not normalized or any(
        character not in "abcdefghijklmnopqrstuvwxyz0123456789_-"
        for character in normalized
    ):
        raise SeedError("Docker returned an invalid architecture")
    return f"linux/{normalized}"


def validate_manifest_schema(
    manifest: dict[str, object], archive: Path, platform: str
) -> list[dict[str, str]]:
    if manifest.get("schema_version") != 1:
        raise SeedError("image seed manifest schema_version must be 1")
    if manifest.get("platform") != platform:
        raise SeedError(
            f"image seed platform {manifest.get('platform')!r} does not match {platform}"
        )
    if manifest.get("bundle") != archive.name:
        raise SeedError("image seed manifest bundle name does not match the archive")

    scope = manifest.get("scope")
    verification = manifest.get("verification")
    raw_images = manifest.get("images")
    if (
        not isinstance(scope, dict)
        or not isinstance(verification, dict)
        or not isinstance(raw_images, list)
        or not raw_images
    ):
        raise SeedError(
            "image seed manifest must contain non-empty scope/verification/images data"
        )
    if scope.get("exported_images") != len(raw_images):
        raise SeedError("image seed manifest image count disagrees with its scope")
    if scope.get("custom_ai_gateway_images_exported") != 0:
        raise SeedError("image seed manifest must not contain custom ai-gateway outputs")
    if (
        verification.get("verified") != len(raw_images)
        or verification.get("missing") != 0
        or verification.get("mismatched") != 0
    ):
        raise SeedError("image seed manifest verification summary is not clean")

    images: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, raw_image in enumerate(raw_images):
        if not isinstance(raw_image, dict):
            raise SeedError(f"image seed manifest image {index} must be an object")
        reference = raw_image.get("reference")
        image_id = raw_image.get("image_id")
        if not isinstance(reference, str) or not isinstance(image_id, str):
            raise SeedError(f"image seed manifest image {index} has invalid fields")
        if reference.startswith("ai-gateway/"):
            raise SeedError("image seed must not contain custom ai-gateway outputs")
        if reference.count("@sha256:") != 1:
            raise SeedError(f"image seed reference is not digest-pinned: {reference}")
        name_and_tag, pinned_digest = reference.rsplit("@sha256:", 1)
        final_component = name_and_tag.rsplit("/", 1)[-1]
        if ":" not in final_component:
            raise SeedError(f"image seed reference is not tag-and-digest pinned: {reference}")
        repository, tag = name_and_tag.rsplit(":", 1)
        repository_components = repository.split("/")
        if (
            not repository_components
            or any(not REPOSITORY_COMPONENT.fullmatch(part) for part in repository_components)
            or not TAG.fullmatch(tag)
        ):
            raise SeedError(f"image seed reference has an unsafe name or tag: {reference}")
        if len(pinned_digest) != 64 or any(
            character not in "0123456789abcdef" for character in pinned_digest
        ):
            raise SeedError(f"image seed reference has an invalid digest: {reference}")
        if len(image_id) != 71 or not image_id.startswith("sha256:") or any(
            character not in "0123456789abcdef" for character in image_id[7:]
        ):
            raise SeedError(f"image seed manifest has an invalid image ID: {reference}")
        if reference in seen:
            raise SeedError(f"image seed manifest contains a duplicate reference: {reference}")
        seen.add(reference)
        images.append({"reference": reference, "image_id": image_id})
    return images


def invalid_required_images(docker: str, images: list[dict[str, str]]) -> list[str]:
    invalid: list[str] = []
    for image in images:
        reference = image["reference"]
        inspection = subprocess.run(
            [docker, "--host", LOCAL_DOCKER_HOST, "image", "inspect", "--", reference],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if inspection.returncode != 0:
            invalid.append(reference)
            continue
        try:
            records = json.loads(inspection.stdout)
            record = records[0]
            repo_digests = record.get("RepoDigests") or []
        except (IndexError, KeyError, TypeError, json.JSONDecodeError):
            invalid.append(reference)
            continue
        pinned_digest = reference.rsplit("@sha256:", 1)[1]
        if record.get("Id") != image["image_id"] or not any(
            isinstance(repo_digest, str)
            and repo_digest.endswith(f"@sha256:{pinned_digest}")
            for repo_digest in repo_digests
        ):
            invalid.append(reference)
    return invalid


def load_archive(archive: Path, zstd: str, docker: str) -> None:
    integrity = subprocess.run(
        [zstd, "--quiet", "--test", "--", str(archive)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        check=False,
    )
    if integrity.returncode != 0:
        detail = integrity.stderr.decode("utf-8", errors="replace")[-4096:].strip()
        raise SeedError(f"zstd integrity test failed: {detail or 'no diagnostic'}")

    decompressor = subprocess.Popen(
        [zstd, "--decompress", "--stdout", "--quiet", "--", str(archive)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if decompressor.stdout is None or decompressor.stderr is None:
        decompressor.kill()
        raise SeedError("cannot establish the zstd output pipe")

    try:
        loader = subprocess.Popen(
            [docker, "--host", LOCAL_DOCKER_HOST, "image", "load"],
            stdin=decompressor.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError:
        decompressor.kill()
        decompressor.wait()
        raise
    finally:
        decompressor.stdout.close()

    loader_stdout, loader_stderr = loader.communicate()
    decompressor_stderr = decompressor.stderr.read()
    decompressor_returncode = decompressor.wait()

    if decompressor_returncode != 0 or loader.returncode != 0:
        details = b"\n".join((decompressor_stderr, loader_stdout, loader_stderr))
        detail = details.decode("utf-8", errors="replace")[-4096:].strip()
        raise SeedError(
            "offline image seed load failed before its checksum marker was written: "
            f"{detail or 'no diagnostic'}"
        )


def write_marker(marker: Path, archive_digest: str, manifest_digest: str) -> None:
    descriptor = -1
    temporary_name = ""
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{archive_digest}.", suffix=".tmp", dir=marker.parent
        )
        os.fchmod(descriptor, MARKER_MODE)
        os.fchown(descriptor, ROOT_UID, ROOT_GID)
        with os.fdopen(descriptor, "w", encoding="ascii", closefd=True) as destination:
            descriptor = -1
            destination.write(f"{archive_digest} {manifest_digest}\n")
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary_name, marker)
        temporary_name = ""
        os.chown(marker, ROOT_UID, ROOT_GID)
        os.chmod(marker, MARKER_MODE)
        directory_descriptor = os.open(marker.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as exc:
        raise SeedError(f"cannot persist checksum marker: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_name:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def run(
    archive: Path,
    archive_digest: str,
    manifest_path: Path,
    manifest_digest: str,
    marker_dir: Path,
) -> str:
    validate_arguments(
        archive, archive_digest, manifest_path, manifest_digest, marker_dir
    )
    docker = require_executable("docker")
    platform = require_docker_ready(docker)
    validate_marker_dir(marker_dir)
    manifest = validate_manifest_file(manifest_path, manifest_digest)
    required_images = validate_manifest_schema(manifest, archive, platform)

    marker = marker_path(marker_dir, archive_digest, manifest_digest)
    existing_marker = marker_is_valid(marker, archive_digest, manifest_digest)
    invalid_images = invalid_required_images(docker, required_images)
    if existing_marker and not invalid_images:
        return f"SKIPPED {archive_digest}"
    if existing_marker:
        try:
            marker.unlink()
        except OSError as exc:
            raise SeedError(f"cannot invalidate stale checksum marker: {exc}") from exc

    validate_archive(archive, archive_digest)
    zstd = require_executable("zstd")
    load_archive(archive, zstd, docker)
    invalid_images = invalid_required_images(docker, required_images)
    if invalid_images:
        preview = ", ".join(invalid_images[:5])
        suffix = " ..." if len(invalid_images) > 5 else ""
        raise SeedError(
            "required seeded images are missing or mismatched after load: "
            f"{preview}{suffix}"
        )
    write_marker(marker, archive_digest, manifest_digest)
    if not marker_is_valid(marker, archive_digest, manifest_digest):
        raise SeedError("checksum marker postcondition failed")
    outcome = "RELOADED" if existing_marker else "LOADED"
    return f"{outcome} {archive_digest}"


def main(argv: list[str]) -> int:
    if len(argv) != 6:
        print(
            "usage: load-offline-image-seed.py ARCHIVE.docker.tar.zst "
            "ARCHIVE_SHA256 MANIFEST.manifest.json MANIFEST_SHA256 "
            "MARKER_DIRECTORY",
            file=sys.stderr,
        )
        return 2
    if os.geteuid() != ROOT_UID:
        print("ERROR: offline image seed loader must run as root", file=sys.stderr)
        return 1

    os.environ.clear()
    os.environ["PATH"] = FIXED_PATH
    try:
        outcome = run(
            Path(argv[1]), argv[2], Path(argv[3]), argv[4], Path(argv[5])
        )
    except (OSError, SeedError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(outcome)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
