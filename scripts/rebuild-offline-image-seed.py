#!/usr/bin/env python3
"""Build a verified Docker image seed for an air-gapped Linux host.

The builder deliberately exports *tag* references after first verifying their
``tag@sha256:...`` source references.  Docker's OCI archive exporter omits
``RepoTags`` when it is given a digest-qualified reference; an archive made
that way cannot restore the tag or repository digest on a clean daemon.  A
tag export retains both in OCI metadata, while the manifest continues to bind
the saved tag to the originally reviewed digest.

This utility never pulls.  It only uses a local Unix-domain Docker endpoint,
then atomically publishes root-owned, mode-0600 output files.  It is designed
to work with a Linux Docker daemon reached through either Linux Docker Engine
or Docker Desktop on macOS; remote TCP and SSH Docker contexts are rejected.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Iterable
from urllib.parse import urlsplit


ROOT_UID = 0
ROOT_GID = 0
PRIVATE_FILE_MODE = 0o600
MAX_ARCHIVE_METADATA_BYTES = 1024 * 1024
MAX_ARCHIVE_MEMBERS = 100_000
ROOT_SYSTEM_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
CONTROLLER_SYSTEM_PATH = "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
FIXED_ENV = {
    "HOME": "/",
    "LC_ALL": "C",
    "PATH": ROOT_SYSTEM_PATH,
}
REFERENCE_RE = re.compile(
    r"^(?!ai-gateway/)(?:[a-z0-9]+(?:[._-]+[a-z0-9]+)*/)*"
    r"[a-z0-9]+(?:[._-]+[a-z0-9]+)*:"
    r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}@sha256:[0-9a-f]{64}$"
)
CONTEXT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
PIN_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9._/-])"
    r"((?!ai-gateway/)(?:[a-z0-9]+(?:[._-]+[a-z0-9]+)*/)*"
    r"[a-z0-9]+(?:[._-]+[a-z0-9]+)*:"
    r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}@sha256:[0-9a-f]{64})"
    r"(?![A-Za-z0-9._/-])"
)


class SeedBuildError(RuntimeError):
    """The local image inventory cannot safely form a seed."""


@dataclass(frozen=True)
class SeedImage:
    """One digest-pinned source image and the tag which must be saved."""

    reference: str
    save_reference: str
    image_id: str


@dataclass(frozen=True)
class OutputPolicy:
    """The only principal allowed to own generated seed files."""

    uid: int
    gid: int
    root_controller: bool


@dataclass(frozen=True)
class DockerClient:
    """A selected local Docker CLI and an explicitly local endpoint."""

    executable: str
    endpoint_options: tuple[str, ...]
    environment: dict[str, str]

    def command(self, *arguments: str) -> list[str]:
        return [self.executable, *self.endpoint_options, *arguments]

    def run(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            self.command(*arguments),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            check=False,
            env=self.environment,
        )


def output_policy(allow_unprivileged_controller: bool) -> OutputPolicy:
    """Keep target-grade root output by default; allow a narrow Mac workflow."""

    if os.geteuid() == ROOT_UID:
        return OutputPolicy(ROOT_UID, ROOT_GID, True)
    if not allow_unprivileged_controller:
        raise SeedBuildError(
            "offline image seed builder must run as root; use "
            "--allow-unprivileged-controller only for a local controller archive"
        )
    return OutputPolicy(os.geteuid(), os.getegid(), False)


def _mode(metadata: os.stat_result) -> int:
    return stat.S_IMODE(metadata.st_mode)


def _directory_is_safe(
    metadata: os.stat_result,
    *,
    expected_uid: int,
    expected_gid: int | None,
    allow_sticky_write: bool,
) -> bool:
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        return False
    if metadata.st_uid != expected_uid:
        return False
    if expected_gid is not None and metadata.st_gid != expected_gid:
        return False
    # A root-owned sticky directory (for example /var/tmp) is safe for
    # root-owned temporary/output entries: unprivileged users cannot replace
    # or unlink them.  A non-sticky writable directory is not safe.
    return not (_mode(metadata) & 0o022) or (
        allow_sticky_write and bool(metadata.st_mode & stat.S_ISVTX)
    )


def _validate_directory_lineage(directory: Path, policy: OutputPolicy) -> None:
    """Reject writable/untrusted path components before creating root files."""

    cursor = directory
    first = True
    while True:
        try:
            metadata = cursor.lstat()
        except OSError as exc:
            raise SeedBuildError(f"cannot inspect output directory {cursor}: {exc}") from exc
        if first:
            safe = _directory_is_safe(
                metadata,
                expected_uid=policy.uid,
                # A local controller can inherit a trusted directory's group
                # (for example macOS /tmp).  Privacy comes from ownership and
                # lack of group/other write, not a particular numeric GID.
                expected_gid=policy.gid if policy.root_controller else None,
                allow_sticky_write=policy.root_controller,
            )
        elif policy.root_controller:
            safe = _directory_is_safe(
                metadata,
                expected_uid=ROOT_UID,
                expected_gid=None,
                allow_sticky_write=True,
            )
        else:
            # A local controller may live beneath a root-owned sticky path
            # such as /tmp, or beneath its own non-writable private tree.  Do
            # not let another UID or a non-sticky writable ancestor race a
            # rootless atomic replacement.
            safe = (
                _directory_is_safe(
                    metadata,
                    expected_uid=ROOT_UID,
                    expected_gid=None,
                    allow_sticky_write=True,
                )
                or _directory_is_safe(
                    metadata,
                    expected_uid=policy.uid,
                    expected_gid=None,
                    allow_sticky_write=False,
                )
            )
        if not safe:
            raise SeedBuildError(
                "output directory has an unsafe owner, mode, or ancestor"
            )
        if cursor == cursor.parent:
            return
        cursor = cursor.parent
        first = False


def require_safe_output(path: Path, suffix: str, policy: OutputPolicy) -> Path:
    """Return a canonical, trusted output path with the requested suffix."""

    if not path.is_absolute() or not str(path).endswith(suffix) or path.name in {"", ".", ".."}:
        raise SeedBuildError(f"output path must be absolute and end in {suffix}")
    try:
        parent = path.parent.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise SeedBuildError("output directory is missing or cannot be resolved") from exc
    _validate_directory_lineage(parent, policy)
    # Use the canonical parent, not the caller's possibly symlinked spelling,
    # for every subsequent creation and replacement operation.
    return parent / path.name


def _trusted_root_path(path: Path, *, executable: bool = False) -> None:
    """Do not execute or connect through user-controlled objects as root."""

    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.lstat()
    except (OSError, RuntimeError) as exc:
        raise SeedBuildError(f"cannot resolve trusted root path: {path}") from exc
    if metadata.st_uid != ROOT_UID or metadata.st_gid != ROOT_GID:
        raise SeedBuildError(f"root controller requires a root:root path: {resolved}")
    if _mode(metadata) & 0o022:
        raise SeedBuildError(f"root controller refuses a writable path: {resolved}")
    if executable and (not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK)):
        raise SeedBuildError(f"root controller requires an executable regular file: {resolved}")

    cursor = resolved.parent
    while True:
        try:
            parent_metadata = cursor.lstat()
        except OSError as exc:
            raise SeedBuildError(f"cannot inspect root executable ancestor: {cursor}") from exc
        if (
            stat.S_ISLNK(parent_metadata.st_mode)
            or not stat.S_ISDIR(parent_metadata.st_mode)
            or parent_metadata.st_uid != ROOT_UID
            or (_mode(parent_metadata) & 0o022)
        ):
            raise SeedBuildError(
                f"root controller requires non-writable root-owned ancestors: {cursor}"
            )
        if cursor == cursor.parent:
            return
        cursor = cursor.parent


def _find_executable(
    name: str, policy: OutputPolicy, explicit: Path | None = None
) -> str:
    if explicit is not None:
        candidate = explicit
        if not candidate.is_absolute():
            raise SeedBuildError(f"{name} executable path must be absolute")
        resolved = candidate.resolve(strict=True)
        if not resolved.is_file() or not os.access(resolved, os.X_OK):
            raise SeedBuildError(f"{name} executable is not executable: {candidate}")
        if policy.root_controller:
            _trusted_root_path(resolved, executable=True)
        return str(resolved)

    search_path = ROOT_SYSTEM_PATH if policy.root_controller else CONTROLLER_SYSTEM_PATH
    discovered = shutil.which(name, path=search_path)
    if not discovered:
        raise SeedBuildError(f"required executable is unavailable: {name}")
    try:
        resolved = Path(discovered).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise SeedBuildError(f"cannot resolve {name} executable") from exc
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise SeedBuildError(f"{name} executable is not executable: {resolved}")
    if policy.root_controller:
        _trusted_root_path(resolved, executable=True)
    return str(resolved)


def _validated_config_directory(path: Path | None, policy: OutputPolicy) -> Path | None:
    if path is None:
        return None
    if not path.is_absolute():
        raise SeedBuildError("Docker config directory must be absolute")
    try:
        metadata = path.stat()
    except OSError as exc:
        raise SeedBuildError(f"cannot inspect Docker config directory: {exc}") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise SeedBuildError("Docker config path is not a directory")
    resolved = path.resolve(strict=True)
    if policy.root_controller:
        _trusted_root_path(resolved)
    return resolved


def _docker_environment(config_directory: Path | None, policy: OutputPolicy) -> dict[str, str]:
    environment = dict(FIXED_ENV)
    if not policy.root_controller:
        environment["PATH"] = CONTROLLER_SYSTEM_PATH
    if config_directory is not None:
        environment["DOCKER_CONFIG"] = str(config_directory)
    return environment


def validate_local_docker_host(host: str) -> str:
    """Accept only a local absolute Unix socket, never a remote Docker API."""

    parsed = urlsplit(host)
    if (
        parsed.scheme != "unix"
        or parsed.netloc
        or not parsed.path.startswith("/")
        or parsed.query
        or parsed.fragment
    ):
        raise SeedBuildError(
            "Docker endpoint must be an absolute local unix:// socket; "
            "remote TCP and SSH Docker contexts are prohibited"
        )
    return f"unix://{parsed.path}"


def _require_trusted_root_docker_socket(host: str) -> str:
    """A root controller must not issue privileged requests to a user socket."""

    local_host = validate_local_docker_host(host)
    socket_path = Path(urlsplit(local_host).path)
    try:
        resolved = socket_path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise SeedBuildError(f"cannot inspect local Docker socket: {socket_path}") from exc
    if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != ROOT_UID:
        raise SeedBuildError("root controller requires a root-owned local Docker socket")
    if _mode(metadata) & 0o002:
        raise SeedBuildError("root controller refuses a world-writable Docker socket")
    cursor = resolved.parent
    while True:
        parent_metadata = cursor.lstat()
        if (
            stat.S_ISLNK(parent_metadata.st_mode)
            or not stat.S_ISDIR(parent_metadata.st_mode)
            or parent_metadata.st_uid != ROOT_UID
            or (_mode(parent_metadata) & 0o022)
        ):
            raise SeedBuildError("root controller requires trusted Docker socket ancestors")
        if cursor == cursor.parent:
            break
        cursor = cursor.parent
    # Keep the exact context spelling for Docker CLI compatibility on macOS
    # (/var commonly resolves to /private/var), while the canonical target was
    # used above for the trust decision.
    return local_host


def _context_name_from_cli(
    docker: str, environment: dict[str, str], config_directory: Path | None
) -> str:
    command = [docker]
    if config_directory is not None:
        command.extend(("--config", str(config_directory)))
    command.extend(("context", "show"))
    result = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        check=False,
        env=environment,
    )
    name = result.stdout.strip()
    if result.returncode or CONTEXT_RE.fullmatch(name) is None:
        raise SeedBuildError("cannot determine the selected Docker context")
    return name


def _context_host_from_cli(
    docker: str,
    environment: dict[str, str],
    config_directory: Path | None,
    context: str,
) -> str:
    command = [docker]
    if config_directory is not None:
        command.extend(("--config", str(config_directory)))
    command.extend(
        ("context", "inspect", context, "--format", "{{.Endpoints.docker.Host}}")
    )
    result = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        check=False,
        env=environment,
    )
    if result.returncode:
        raise SeedBuildError(f"cannot inspect Docker context {context!r}")
    return validate_local_docker_host(result.stdout.strip())


def resolve_docker_client(
    *,
    policy: OutputPolicy,
    docker_path: Path | None,
    docker_config: Path | None,
    docker_context: str | None,
    docker_host: str | None,
) -> DockerClient:
    """Resolve one local Docker context without inheriting remote endpoints."""

    docker = _find_executable("docker", policy, docker_path)
    config_directory = _validated_config_directory(docker_config, policy)
    environment = _docker_environment(config_directory, policy)

    if docker_context is not None and CONTEXT_RE.fullmatch(docker_context) is None:
        raise SeedBuildError("Docker context name is unsafe")
    if docker_host is not None and docker_context is not None:
        raise SeedBuildError("specify either a Docker host or a Docker context, not both")

    if docker_host is not None:
        local_host = validate_local_docker_host(docker_host)
        if policy.root_controller:
            local_host = _require_trusted_root_docker_socket(local_host)
        return DockerClient(
            docker,
            ("--host", local_host),
            environment,
        )

    context = docker_context or _context_name_from_cli(docker, environment, config_directory)
    # Inspect before executing a Docker operation so a selected tcp:// or
    # ssh:// context cannot turn a local maintenance action into a remote one.
    local_host = _context_host_from_cli(docker, environment, config_directory, context)
    if policy.root_controller:
        _require_trusted_root_docker_socket(local_host)
    options: list[str] = []
    if config_directory is not None:
        options.extend(("--config", str(config_directory)))
    options.extend(("--context", context))
    return DockerClient(docker, tuple(options), environment)


def _parse_inspection(
    reference: str, result: subprocess.CompletedProcess[str], *, required: bool = True
) -> dict[str, object] | None:
    if result.returncode:
        if not required:
            return None
        raise SeedBuildError(f"required pinned image is absent: {reference}")
    try:
        records = json.loads(result.stdout)
        record = records[0]
    except (IndexError, TypeError, json.JSONDecodeError) as exc:
        raise SeedBuildError(f"Docker returned invalid inspection data: {reference}") from exc
    if not isinstance(record, dict):
        raise SeedBuildError(f"Docker returned invalid inspection data: {reference}")
    return record


def _verified_image_id(record: dict[str, object], reference: str) -> str:
    image_id = record.get("Id")
    digests = record.get("RepoDigests") or []
    digest = reference.rsplit("@sha256:", 1)[1]
    if (
        not isinstance(image_id, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None
        or not isinstance(digests, list)
        or not any(
            isinstance(value, str) and value.endswith(f"@sha256:{digest}")
            for value in digests
        )
    ):
        raise SeedBuildError(f"required pinned image digest is not locally verified: {reference}")
    return image_id


def inspect_images(
    client: DockerClient, references: list[str], *, materialize_missing_tags: bool = False
) -> list[SeedImage]:
    """Verify source pins and the tag that Docker must serialise on load."""

    images: list[SeedImage] = []
    for reference in references:
        pinned_record = _parse_inspection(
            reference, client.run("image", "inspect", "--", reference)
        )
        assert pinned_record is not None
        image_id = _verified_image_id(pinned_record, reference)
        save_reference = reference.rsplit("@sha256:", 1)[0]
        tag_record = _parse_inspection(
            save_reference,
            client.run("image", "inspect", "--", save_reference),
            required=False,
        )
        if tag_record is None:
            if not materialize_missing_tags:
                raise SeedBuildError(
                    "verified pinned image has no source tag alias; rerun with "
                    "--materialize-missing-source-tags to create only its reviewed tag: "
                    f"{reference}"
                )
            tag_result = client.run("image", "tag", reference, save_reference)
            if tag_result.returncode:
                raise SeedBuildError(
                    "cannot create the reviewed source tag alias for pinned image: "
                    f"{reference}"
                )
            tag_record = _parse_inspection(
                save_reference, client.run("image", "inspect", "--", save_reference)
            )
            assert tag_record is not None
        if _verified_image_id(tag_record, reference) != image_id:
            raise SeedBuildError(
                "tag reference does not resolve to the reviewed digest-pinned image: "
                f"{reference}"
            )
        images.append(SeedImage(reference, save_reference, image_id))
    return images


def collect_project_image_references(project_root: Path) -> set[str]:
    """Collect every literal external pin needed by Compose and Dockerfiles.

    The collector deliberately avoids YAML/Dockerfile evaluation.  It accepts
    only literal digest pins in the small, reviewed source set, including the
    pinned Dockerfile frontend and lab-only Samba base image.  Variable-backed
    ``FROM`` values are represented by the Compose build arguments and are
    therefore covered by the Compose scan.
    """

    try:
        root = project_root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise SeedBuildError("project root is missing or cannot be resolved") from exc
    if not root.is_dir():
        raise SeedBuildError("project root is not a directory")

    compose_source = root / "compose" / "docker-compose.yml"
    services_root = root / "services"
    source_paths = [compose_source]
    if services_root.is_dir():
        source_paths.extend(sorted(services_root.glob("**/Dockerfile*")))
    if not compose_source.is_file() or len(source_paths) == 1:
        raise SeedBuildError("project root does not contain the reviewed Compose and Dockerfile sources")

    references: set[str] = set()
    for source_path in source_paths:
        try:
            resolved = source_path.resolve(strict=True)
            resolved.relative_to(root)
            metadata = resolved.lstat()
        except (OSError, RuntimeError, ValueError) as exc:
            raise SeedBuildError("project image source escapes the supplied project root") from exc
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise SeedBuildError(f"project image source is not a regular file: {source_path}")
        if metadata.st_size > MAX_ARCHIVE_METADATA_BYTES:
            raise SeedBuildError(f"project image source exceeds the safety bound: {source_path}")
        try:
            content = resolved.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise SeedBuildError(f"cannot read project image source: {source_path}") from exc
        for match in PIN_TOKEN_RE.finditer(content):
            reference = match.group(1)
            if REFERENCE_RE.fullmatch(reference) is None:
                raise SeedBuildError(f"project image source contains an unsafe pin: {source_path}")
            references.add(reference)
    if not references:
        raise SeedBuildError("project image source contains no digest-pinned external images")
    return references


def _repository_root_from_script() -> Path | None:
    """Use source coverage automatically when this utility runs from this repo."""

    candidate = Path(__file__).resolve().parents[1]
    if (candidate / "compose" / "docker-compose.yml").is_file() and (candidate / "services").is_dir():
        return candidate
    return None


def platform(client: DockerClient) -> str:
    result = client.run("info", "--format", "{{.OSType}}/{{.Architecture}}")
    if result.returncode:
        raise SeedBuildError("local Docker daemon is unavailable")
    reported = result.stdout.strip()
    operating_system, separator, architecture = reported.partition("/")
    architecture = {"aarch64": "arm64", "x86_64": "amd64"}.get(architecture, architecture)
    if separator != "/" or operating_system != "linux" or architecture not in {"arm64", "amd64"}:
        raise SeedBuildError("local Docker daemon must be a supported Linux amd64 or arm64 daemon")
    return f"linux/{architecture}"


def _open_private_temp(
    directory: Path, destination_name: str, policy: OutputPolicy
) -> tuple[int, Path]:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination_name}.", suffix=".tmp", dir=directory
    )
    temporary = Path(temporary_name)
    try:
        if policy.root_controller:
            os.fchown(descriptor, policy.uid, policy.gid)
        else:
            metadata = os.fstat(descriptor)
            if metadata.st_uid != policy.uid:
                raise SeedBuildError("controller temporary output has an unexpected owner")
        os.fchmod(descriptor, PRIVATE_FILE_MODE)
    except (OSError, SeedBuildError):
        os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise
    return descriptor, temporary


def _fsync_directory(directory: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(directory, flags)
    try:
        try:
            os.fsync(descriptor)
        except OSError as exc:
            # APFS/HFS and some overlay filesystems do not implement directory
            # fsync.  The file is still atomically published; do not mask real
            # permission or I/O errors.
            if exc.errno not in {errno.EINVAL, errno.ENOTSUP}:
                raise
    finally:
        os.close(descriptor)


def _publish_private_temp(temporary: Path, destination: Path) -> None:
    os.replace(temporary, destination)
    _fsync_directory(destination.parent)


def replace_private(path: Path, content: bytes, policy: OutputPolicy) -> None:
    descriptor = -1
    temporary: Path | None = None
    try:
        descriptor, temporary = _open_private_temp(path.parent, path.name, policy)
        with os.fdopen(descriptor, "wb", closefd=True) as target:
            descriptor = -1
            target.write(content)
            target.flush()
            os.fsync(target.fileno())
        _publish_private_temp(temporary, path)
        temporary = None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_export_metadata(archive: Path, zstd: str) -> dict[str, object]:
    """Read only the OCI metadata members from a compressed Docker export."""

    integrity = subprocess.run(
        [zstd, "--quiet", "--test", "--", str(archive)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        check=False,
        env=FIXED_ENV,
    )
    if integrity.returncode:
        detail = integrity.stderr.decode("utf-8", errors="replace")[-2048:].strip()
        raise SeedBuildError(f"image seed compression integrity check failed: {detail or 'no diagnostic'}")

    decompressor = subprocess.Popen(
        [zstd, "--decompress", "--stdout", "--quiet", "--", str(archive)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=FIXED_ENV,
    )
    if decompressor.stdout is None or decompressor.stderr is None:
        decompressor.kill()
        raise SeedBuildError("could not create image seed metadata stream")

    found: dict[str, object] = {}
    try:
        with tarfile.open(fileobj=decompressor.stdout, mode="r|") as source:
            for count, member in enumerate(source, start=1):
                if count > MAX_ARCHIVE_MEMBERS:
                    raise SeedBuildError("image seed archive contains too many members")
                if member.name not in {"manifest.json", "index.json"}:
                    continue
                if (
                    not member.isfile()
                    or member.size < 1
                    or member.size > MAX_ARCHIVE_METADATA_BYTES
                    or member.name in found
                ):
                    raise SeedBuildError("image seed archive has unsafe OCI metadata")
                member_file = source.extractfile(member)
                if member_file is None:
                    raise SeedBuildError("cannot read image seed OCI metadata")
                try:
                    found[member.name] = json.loads(member_file.read().decode("utf-8"))
                except (UnicodeError, json.JSONDecodeError) as exc:
                    raise SeedBuildError("image seed OCI metadata is not valid JSON") from exc
    except (OSError, tarfile.TarError) as exc:
        raise SeedBuildError(f"cannot read image seed archive metadata: {exc}") from exc
    finally:
        decompressor.stdout.close()

    stderr = decompressor.stderr.read()
    returncode = decompressor.wait()
    if returncode:
        detail = stderr.decode("utf-8", errors="replace")[-2048:].strip()
        raise SeedBuildError(f"cannot decompress image seed metadata: {detail or 'no diagnostic'}")
    return found


def _normalised_oci_name(save_reference: str) -> tuple[str, str, str]:
    repository, tag = save_reference.rsplit(":", 1)
    components = repository.split("/")
    if len(components) == 1 or not (
        "." in components[0] or ":" in components[0] or components[0] == "localhost"
    ):
        registry = "docker.io"
        image_path = "/".join(components)
        if len(components) == 1:
            image_path = f"library/{image_path}"
    else:
        registry = components[0]
        image_path = "/".join(components[1:])
    return registry, image_path, f"{registry}/{image_path}:{tag}"


def _validate_export_metadata(metadata: dict[str, object], images: Iterable[SeedImage]) -> None:
    """Prove the archive carries the OCI tag/digest metadata Docker load needs."""

    manifest = metadata.get("manifest.json")
    index = metadata.get("index.json")
    if not isinstance(manifest, list) or not isinstance(index, dict):
        raise SeedBuildError("image seed must be an OCI archive with manifest.json and index.json")

    expected = list(images)
    expected_tags = {image.save_reference for image in expected}
    exported_tags: set[str] = set()
    for entry in manifest:
        if not isinstance(entry, dict):
            raise SeedBuildError("image seed manifest contains an invalid entry")
        tags = entry.get("RepoTags")
        if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
            raise SeedBuildError("image seed archive omitted a required repository tag")
        exported_tags.update(tags)
    if exported_tags != expected_tags:
        raise SeedBuildError(
            "image seed archive repository tags do not exactly match the reviewed image set"
        )

    descriptors = index.get("manifests")
    if index.get("schemaVersion") != 2 or not isinstance(descriptors, list):
        raise SeedBuildError("image seed OCI index is invalid")
    for image in expected:
        registry, image_path, canonical_name = _normalised_oci_name(image.save_reference)
        expected_digest = f"sha256:{image.reference.rsplit('@sha256:', 1)[1]}"
        source_key = f"containerd.io/distribution.source.{registry}"
        matching = [
            descriptor
            for descriptor in descriptors
            if isinstance(descriptor, dict)
            and descriptor.get("digest") == expected_digest
            and isinstance(descriptor.get("annotations"), dict)
            and descriptor["annotations"].get("io.containerd.image.name") == canonical_name
            and descriptor["annotations"].get(source_key) == image_path
        ]
        if len(matching) != 1:
            raise SeedBuildError(
                "image seed OCI metadata cannot restore the reviewed repository digest: "
                f"{image.reference}"
            )


def _stream_save(
    archive: Path,
    images: list[SeedImage],
    client: DockerClient,
    zstd: str,
    policy: OutputPolicy,
) -> None:
    descriptor = -1
    temporary: Path | None = None
    saver: subprocess.Popen[bytes] | None = None
    compressor: subprocess.Popen[bytes] | None = None
    try:
        descriptor, temporary = _open_private_temp(archive.parent, archive.name, policy)
        with os.fdopen(descriptor, "wb", closefd=True) as target:
            descriptor = -1
            saver = subprocess.Popen(
                client.command("image", "save", *(image.save_reference for image in images)),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=client.environment,
            )
            if saver.stdout is None or saver.stderr is None:
                raise SeedBuildError("could not create Docker image-save stream")
            compressor = subprocess.Popen(
                [zstd, "--compress", "--quiet", "--threads=0", "--stdout"],
                stdin=saver.stdout,
                stdout=target,
                stderr=subprocess.PIPE,
                env=FIXED_ENV,
            )
            saver.stdout.close()
            _, compressor_stderr = compressor.communicate()
            saver_stderr = saver.stderr.read()
            saver_returncode = saver.wait()
            if saver_returncode or compressor.returncode:
                detail = (saver_stderr + b"\n" + compressor_stderr).decode(
                    "utf-8", errors="replace"
                )[-2048:].strip()
                raise SeedBuildError(f"Docker image seed export failed: {detail or 'no diagnostic'}")
            target.flush()
            os.fsync(target.fileno())

        # A save of tag@digest has no RepoTags. Verify that we deliberately
        # emitted tag references and that the OCI index will recreate their
        # RepoDigests on a clean daemon before publishing this archive.
        _validate_export_metadata(_read_export_metadata(temporary, zstd), images)
        _publish_private_temp(temporary, archive)
        temporary = None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if saver is not None and saver.poll() is None:
            saver.kill()
            saver.wait()
        if compressor is not None and compressor.poll() is None:
            compressor.kill()
            compressor.wait()
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def _initial_docker_config(explicit: Path | None, policy: OutputPolicy) -> Path | None:
    if explicit is not None:
        return explicit
    configured = os.environ.get("DOCKER_CONFIG")
    if configured:
        return Path(configured)
    if not policy.root_controller:
        # Docker Desktop's selected context normally lives in the invoking
        # user's ~/.docker.  Pass that directory explicitly rather than
        # trusting HOME/DOCKER_* endpoint variables in subprocesses.
        home = os.environ.get("HOME")
        if home and Path(home).is_absolute():
            candidate = Path(home) / ".docker"
            if candidate.is_dir():
                return candidate
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--image", action="append", default=[])
    parser.add_argument(
        "--materialize-missing-source-tags",
        action="store_true",
        help=(
            "create a missing ordinary source tag only from its already "
            "verified tag@digest image; never pulls or accepts another tag"
        ),
    )
    parser.add_argument(
        "--allow-unprivileged-controller",
        action="store_true",
        help=(
            "allow a local controller to create caller-owned 0600 files only "
            "inside a private non-writable directory; the target transfer must own them root:root"
        ),
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        help=(
            "collect all literal digest-pinned Compose/Dockerfile sources; "
            "defaults to this checkout when the utility runs from it"
        ),
    )
    parser.add_argument(
        "--docker",
        type=Path,
        help="absolute path to a Docker CLI (normally discovered automatically)",
    )
    parser.add_argument(
        "--docker-config",
        type=Path,
        help="absolute Docker config directory used to select a local context",
    )
    endpoint = parser.add_mutually_exclusive_group()
    endpoint.add_argument(
        "--docker-context",
        help="explicit Docker context name; it must resolve to a local unix:// socket",
    )
    endpoint.add_argument(
        "--docker-host",
        help="explicit local unix:// Docker socket; TCP and SSH endpoints are refused",
    )
    args = parser.parse_args(argv)
    try:
        policy = output_policy(args.allow_unprivileged_controller)
        archive = require_safe_output(args.archive, ".docker.tar.zst", policy)
        manifest_path = require_safe_output(args.manifest, ".manifest.json", policy)
        if archive.parent != manifest_path.parent:
            raise SeedBuildError("archive and manifest must use the same directory")
        if len(set(args.image)) != len(args.image) or any(
            REFERENCE_RE.fullmatch(value) is None for value in args.image
        ):
            raise SeedBuildError("seed images must be nonempty, unique, digest-pinned external references")

        project_root = args.project_root or _repository_root_from_script()
        source_references = (
            collect_project_image_references(project_root) if project_root is not None else set()
        )
        references = sorted(set(args.image) | source_references)
        if not references:
            raise SeedBuildError(
                "provide at least one --image or run from a project checkout with digest-pinned sources"
            )

        docker_host = args.docker_host if args.docker_host is not None else os.environ.get("DOCKER_HOST")
        docker_context = (
            args.docker_context
            if args.docker_context is not None
            else (None if docker_host is not None else os.environ.get("DOCKER_CONTEXT"))
        )
        client = resolve_docker_client(
            policy=policy,
            docker_path=args.docker,
            docker_config=_initial_docker_config(args.docker_config, policy),
            docker_context=docker_context,
            docker_host=docker_host,
        )
        image_platform = platform(client)
        images = inspect_images(
            client,
            references,
            materialize_missing_tags=args.materialize_missing_source_tags,
        )
        zstd = _find_executable("zstd", policy)
        _stream_save(archive, images, client, zstd, policy)
        manifest = {
            "schema_version": 1,
            "platform": image_platform,
            "bundle": archive.name,
            "scope": {
                "exported_images": len(images),
                "custom_ai_gateway_images_exported": 0,
            },
            "verification": {"verified": len(images), "missing": 0, "mismatched": 0},
            "images": [
                {"reference": image.reference, "image_id": image.image_id}
                for image in images
            ],
        }
        replace_private(
            manifest_path,
            (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode(),
            policy,
        )
        print(
            json.dumps(
                {
                    "archive_sha256": sha256(archive),
                    "manifest_sha256": sha256(manifest_path),
                    "images": len(images),
                    "platform": image_platform,
                },
                sort_keys=True,
            )
        )
    except (OSError, SeedBuildError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
