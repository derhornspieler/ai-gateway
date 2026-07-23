#!/usr/bin/env python3
"""Build a verified Docker image release for an offline Linux host.

The builder deliberately exports *tag* references after first verifying their
``tag@sha256:...`` source references.  Docker's OCI archive exporter omits
``RepoTags`` when it is given a digest-qualified reference; an archive made
that way cannot restore the tag or repository digest on a clean daemon.  A
tag export retains both in OCI metadata, while the manifest continues to bind
the saved tag to the originally reviewed digest.

Release preparation pulls only the collected digest pins, builds custom images
with pull disabled, and exports both sets. The legacy mode exports images that
already exist locally. Both modes use only a local Unix-domain Docker endpoint
and atomically publish mode-0600 output files. Remote TCP and SSH Docker
contexts are rejected.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
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
MAX_CAPTURED_OCI_DOCUMENTS = 512
OCI_BLOB_PATH_RE = re.compile(r"^blobs/sha256/([0-9a-f]{64})$")
OCI_IMAGE_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
OCI_EMPTY_MEDIA_TYPE = "application/vnd.oci.empty.v1+json"
SIGSTORE_BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
ROOT_SYSTEM_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
CONTROLLER_SYSTEM_PATH = "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
SUPPORTED_PLATFORMS = ("linux/amd64", "linux/arm64")
COMPOSE_PROJECT_NAME = "ai-gateway"
PREPROD_SAMBA_IMAGE = "ai-gateway/samba-ad:preprod"
PREPROD_WIF_IMAGE = "ai-gateway/wif-provider-mock:preprod"
PREPROD_ONLY_SERVICES = {"samba-ad", "wif-provider-mock"}
ENVOY_SERVICE = "envoy-egress"
ENVOY_IMAGE = "ai-gateway/envoy-egress:1"
ENVOY_POLICY_PLANNER_IMAGE = "ai-gateway/egress-policy-planner:release"
ENVOY_POLICY_SCHEMA = 1
SOURCE_DATE_EPOCH = "0"
RELEASE_SCOPE_PRODUCTION = "production"
RELEASE_SCOPE_PREPROD = "preprod"
RELEASE_SCOPES = {RELEASE_SCOPE_PRODUCTION, RELEASE_SCOPE_PREPROD}
MANIFEST_SCHEMA_V1 = 1
MANIFEST_SCHEMA_V2 = 2
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
MUTABLE_IMAGE_RE = re.compile(
    r"^(?:[a-z0-9]+(?:[._-]+[a-z0-9]+)*/)*"
    r"[a-z0-9]+(?:[._-]+[a-z0-9]+)*"
    r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?$"
)
SERVICE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
PROVIDER_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
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
class CustomSeedImage:
    """One locally built image carried under a non-moving transfer tag."""

    image: str
    archive_reference: str
    image_id: str
    deployment_scope: str = "production"
    target_activation: str = "active-compose"


@dataclass(frozen=True)
class EgressPolicyPlan:
    """Canonical provider selection returned by the reviewed Go planner."""

    receipt: dict[str, object]
    providers_csv: str
    policy_sha256: str


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
        try:
            account_home = Path(pwd.getpwuid(policy.uid).pw_dir).resolve(strict=True)
            home_metadata = account_home.stat()
        except (KeyError, OSError, RuntimeError) as exc:
            raise SeedBuildError("cannot resolve the local controller home directory") from exc
        if not account_home.is_dir() or home_metadata.st_uid != policy.uid:
            raise SeedBuildError("local controller home directory has an unsafe owner")
        # Docker Desktop's credential helper uses HOME for its local log and
        # keychain paths. Endpoint selection is still pinned by explicit CLI
        # options and validated as a local Unix socket before any Docker work.
        environment["HOME"] = str(account_home)
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


def _verified_platform(record: dict[str, object], reference: str, expected: str) -> None:
    operating_system, architecture = expected.split("/", 1)
    actual_os = record.get("Os")
    actual_arch = record.get("Architecture")
    actual_arch = {"aarch64": "arm64", "x86_64": "amd64"}.get(
        actual_arch, actual_arch
    )
    if actual_os != operating_system or actual_arch != architecture:
        raise SeedBuildError(
            f"image platform does not match requested {expected}: {reference}"
        )


def pull_images(client: DockerClient, references: list[str], requested_platform: str) -> None:
    """Fetch only reviewed tag@digest pins for one explicit target platform."""

    if requested_platform not in SUPPORTED_PLATFORMS:
        raise SeedBuildError("requested image platform must be linux/amd64 or linux/arm64")
    for reference in references:
        result = client.run("image", "pull", "--platform", requested_platform, reference)
        if result.returncode == 0:
            continue
        diagnostic = result.stderr.lower()
        if any(
            marker in diagnostic
            for marker in (
                "unauthorized",
                "authentication required",
                "pull access denied",
                "requested access to the resource is denied",
                "denied: denied",
            )
        ):
            registry = reference.split("/", 1)[0] if "/" in reference else "docker.io"
            raise SeedBuildError(
                f"registry authentication failed for {registry}; authenticate the "
                f"selected local Docker client (for example: docker login {registry})"
            )
        detail = result.stderr.strip().splitlines()
        tail = detail[-1][:512] if detail else "no diagnostic"
        raise SeedBuildError(f"cannot pull reviewed image {reference}: {tail}")


def inspect_images(
    client: DockerClient,
    references: list[str],
    *,
    materialize_missing_tags: bool = False,
    expected_platform: str | None = None,
) -> list[SeedImage]:
    """Verify source pins and the tag that Docker must serialise on load."""

    images: list[SeedImage] = []
    for reference in references:
        pinned_record = _parse_inspection(
            reference, client.run("image", "inspect", "--", reference)
        )
        assert pinned_record is not None
        image_id = _verified_image_id(pinned_record, reference)
        if expected_platform is not None:
            _verified_platform(pinned_record, reference, expected_platform)
        save_reference = reference.rsplit("@sha256:", 1)[0]
        tag_record = _parse_inspection(
            save_reference,
            client.run("image", "inspect", "--", save_reference),
            required=False,
        )
        tag_image_id: str | None = None
        if tag_record is not None:
            try:
                tag_image_id = _verified_image_id(tag_record, reference)
            except SeedBuildError:
                # Docker Desktop can leave the ordinary tag on a different
                # platform after a digest-pinned pull. The exact pin above is
                # already verified, so the explicit materialization option may
                # repair this narrow local alias safely.
                tag_image_id = None

        if tag_image_id != image_id:
            if not materialize_missing_tags:
                if tag_record is None:
                    raise SeedBuildError(
                        "verified pinned image has no source tag alias; rerun with "
                        "--materialize-missing-source-tags to create only its reviewed tag: "
                        f"{reference}"
                    )
                raise SeedBuildError(
                    "tag reference does not resolve to the reviewed digest-pinned image: "
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
            tag_image_id = _verified_image_id(tag_record, reference)
        if tag_image_id != image_id:
            raise SeedBuildError(
                "tag reference does not resolve to the reviewed digest-pinned image: "
                f"{reference}"
            )
        if expected_platform is not None:
            _verified_platform(tag_record, reference, expected_platform)
        images.append(SeedImage(reference, save_reference, image_id))
    return images


def collect_project_image_reference_scopes(
    project_root: Path,
) -> dict[str, set[str]]:
    """Collect production pins and the full preprod union separately.

    The production set excludes the preprod overlay and both preprod-only
    build contexts. A pin used by any production source remains production,
    even when a preprod-only Dockerfile also uses it. The preprod set is the
    full union. Collection is textual and accepts only reviewed literal pins.
    """

    try:
        root = project_root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise SeedBuildError("project root is missing or cannot be resolved") from exc
    if not root.is_dir():
        raise SeedBuildError("project root is not a directory")

    compose_root = root / "compose"
    compose_source = compose_root / "docker-compose.yml"
    services_root = root / "services"
    production_paths = [
        compose_source,
        *(path for path in (
            compose_root / "docker-compose.platform-dns.yml",
        ) if path.is_file()),
    ]
    preprod_only_paths = [compose_root / "docker-compose.preprod.yml"]
    if services_root.is_dir():
        for path in sorted(services_root.glob("**/Dockerfile*")):
            relative = path.relative_to(services_root)
            if relative.parts[0] in {"samba-ad-preprod", "wif-provider-mock"}:
                preprod_only_paths.append(path)
            else:
                production_paths.append(path)
    source_paths = [*production_paths, *preprod_only_paths]
    if not compose_source.is_file() or len(production_paths) == 1:
        raise SeedBuildError("project root does not contain the reviewed Compose and Dockerfile sources")

    references_by_path: dict[Path, set[str]] = {}
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
        references: set[str] = set()
        for match in PIN_TOKEN_RE.finditer(content):
            reference = match.group(1)
            if REFERENCE_RE.fullmatch(reference) is None:
                raise SeedBuildError(f"project image source contains an unsafe pin: {source_path}")
            references.add(reference)
        references_by_path[source_path] = references
    production = set().union(
        *(references_by_path[path] for path in production_paths)
    )
    preprod = production | set().union(
        *(references_by_path[path] for path in preprod_only_paths)
    )
    if not production or not preprod:
        raise SeedBuildError("project image source contains no digest-pinned external images")
    return {
        RELEASE_SCOPE_PRODUCTION: production,
        RELEASE_SCOPE_PREPROD: preprod,
    }


def collect_project_image_references(project_root: Path) -> set[str]:
    """Return the full preprod union for legacy callers and one-pass pulls."""

    return collect_project_image_reference_scopes(project_root)[
        RELEASE_SCOPE_PREPROD
    ]


def scoped_external_images(
    images: list[SeedImage], references: set[str]
) -> list[SeedImage]:
    """Select already inspected images for one release without another pull."""

    selected = [image for image in images if image.reference in references]
    if {image.reference for image in selected} != references:
        raise SeedBuildError("inspected external images do not cover the release scope")
    return selected


def _repository_root_from_script() -> Path | None:
    """Use source coverage automatically when this utility runs from this repo."""

    candidate = Path(__file__).resolve().parents[1]
    if (candidate / "compose" / "docker-compose.yml").is_file() and (candidate / "services").is_dir():
        return candidate
    return None


def platform(client: DockerClient, requested: str | None = None) -> str:
    result = client.run("info", "--format", "{{.OSType}}/{{.Architecture}}")
    if result.returncode:
        raise SeedBuildError("local Docker daemon is unavailable")
    reported = result.stdout.strip()
    operating_system, separator, architecture = reported.partition("/")
    architecture = {"aarch64": "arm64", "x86_64": "amd64"}.get(architecture, architecture)
    if separator != "/" or operating_system != "linux" or architecture not in {"arm64", "amd64"}:
        raise SeedBuildError("local Docker daemon must be a supported Linux amd64 or arm64 daemon")
    daemon_platform = f"linux/{architecture}"
    if requested is None:
        return daemon_platform
    if requested not in SUPPORTED_PLATFORMS:
        raise SeedBuildError("requested image platform must be linux/amd64 or linux/arm64")
    return requested


def _compose_files(project_root: Path) -> list[Path]:
    compose_root = project_root / "compose"
    paths = [
        compose_root / "docker-compose.yml",
        compose_root / "docker-compose.platform-dns.yml",
    ]
    if any(not path.is_file() for path in paths):
        raise SeedBuildError("project root lacks the reviewed deployable Compose files")
    return paths


def _compose_environment(
    base: dict[str, str],
    compose_files: list[Path],
    requested_platform: str,
    egress_plan: EgressPolicyPlan,
) -> dict[str, str]:
    """Return non-secret interpolation values used only for build-model rendering."""

    variables: set[str] = set()
    token = re.compile(r"\$\{([A-Z][A-Z0-9_]*)")
    for path in compose_files:
        variables.update(token.findall(path.read_text(encoding="utf-8")))

    environment = dict(base)
    environment.update(
        {
            name: "AigwOfflineSeedValidation0123456789"
            for name in variables
        }
    )
    environment.update(
        {
            "COMPOSE_PROFILES": "vault-ui",
            "DOCKER_DEFAULT_PLATFORM": requested_platform,
            "VAULT_UI_ENABLED": "true",
            "DOMAIN": "offline-seed.invalid",
            "DOCKER_DATA_ROOT": "/var/lib/docker",
            "ETH1_IP": "10.8.10.10",
            "ETH2_IP": "10.20.0.10",
            "TRAEFIK_INT_CHAT_IP": "172.28.3.2",
            "TRAEFIK_INT_PORTAL_IP": "172.28.4.2",
            "TRAEFIK_ADM_ADMIN_IP": "172.28.5.2",
            "OAUTH2_PROXY_LITELLM_IP": "172.28.5.3",
            "TRAEFIK_ADM_GRAFANA_IP": "172.28.6.2",
            "OAUTH2_PROXY_GRAFANA_IP": "172.28.6.3",
            "ENVOY_EGRESS_IP": "172.28.0.2",
            "ALLOY_INTERNAL_IP": "172.28.2.2",
            "ALLOY_TELEMETRY_IP": "172.28.13.2",
            "ALLOY_OBSERVABILITY_IP": "172.28.15.2",
            "PROMETHEUS_OBSERVABILITY_IP": "172.28.15.3",
            "PLATFORM_DNS_IP": "172.28.18.2",
            "PLATFORM_DNS_ADM_CIDR": "10.8.10.0/24",
            "KEYCLOAK_INTERNAL_IP": "172.28.2.3",
            "IDENTITY_LDAP_DIRECTORY_IP": "10.20.5.10",
            "PORTAL_KEY_DEFAULT_MAX_BUDGET": "none",
            "PORTAL_KEY_DEFAULT_TPM_LIMIT": "none",
            "PORTAL_KEY_DEFAULT_RPM_LIMIT": "none",
            "PORTAL_KEY_DEFAULT_DURATION": "none",
            "PORTAL_KEY_PROJECT_LIMITS": "{}",
            "PROMETHEUS_RETENTION_SIZE": "1GB",
            "CRIBL_OTLP_ENDPOINT": "cribl-mock:4317",
            "CRIBL_OTLP_INSECURE": "true",
            "CRIBL_OTLP_CA_FILE": "/etc/ssl/certs/aigw-ca.pem",
            "CRIBL_OTLP_SERVER_NAME": "cribl-mock",
            "AIGW_EGRESS_SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH,
            "AIGW_EGRESS_PROVIDERS": egress_plan.providers_csv,
            "AIGW_EGRESS_POLICY_SHA256": egress_plan.policy_sha256,
        }
    )
    for name in variables:
        if name.startswith("AIGW_BIND_DIGEST_"):
            environment[name] = hashlib.sha256(name.encode("ascii")).hexdigest()
    return environment


def _compose_command(project_root: Path, compose_files: list[Path]) -> list[str]:
    arguments = ["compose", "--project-directory", str(project_root)]
    for path in compose_files:
        arguments.extend(("--file", str(path)))
    arguments.extend(("--profile", "vault-ui"))
    return arguments


def render_deployable_compose_model(
    client: DockerClient,
    project_root: Path,
    requested_platform: str,
    egress_plan: EgressPolicyPlan,
) -> tuple[dict[str, object], DockerClient, list[Path]]:
    compose_files = _compose_files(project_root)
    environment = _compose_environment(
        client.environment, compose_files, requested_platform, egress_plan
    )
    compose_client = DockerClient(
        client.executable, client.endpoint_options, environment
    )
    result = compose_client.run(
        *_compose_command(project_root, compose_files),
        "config",
        "--format",
        "json",
    )
    if result.returncode:
        detail = result.stderr.strip().splitlines()
        tail = detail[-1][:1024] if detail else "no diagnostic"
        raise SeedBuildError(f"cannot render deployable Compose build model: {tail}")
    try:
        model = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise SeedBuildError("Docker Compose returned an invalid build model") from exc
    if not isinstance(model, dict) or not isinstance(model.get("services"), dict):
        raise SeedBuildError("Docker Compose build model has no services object")
    return model, compose_client, compose_files


def _validate_egress_receipt(receipt: object) -> dict[str, object]:
    """Validate planner output without reimplementing provider selection."""

    required = {
        "schema_version",
        "egress_policy_sha256",
        "envoy_config_sha256",
        "selected_providers",
        "providers",
    }
    if not isinstance(receipt, dict) or set(receipt) != required:
        raise SeedBuildError("egress policy planner returned an invalid receipt shape")
    if receipt.get("schema_version") != ENVOY_POLICY_SCHEMA:
        raise SeedBuildError("egress policy planner returned an unsupported schema")
    for name in ("egress_policy_sha256", "envoy_config_sha256"):
        value = receipt.get(name)
        if not isinstance(value, str) or HEX64_RE.fullmatch(value) is None:
            raise SeedBuildError(f"egress policy planner returned an invalid {name}")

    selected = receipt.get("selected_providers")
    providers = receipt.get("providers")
    if (
        not isinstance(selected, list)
        or not selected
        or any(
            not isinstance(name, str) or PROVIDER_RE.fullmatch(name) is None
            for name in selected
        )
        or selected != sorted(set(selected))
        or not isinstance(providers, list)
        or len(providers) != len(selected)
    ):
        raise SeedBuildError(
            "egress policy planner did not return a canonical provider selection"
        )

    provider_fields = {
        "name",
        "api_hostname",
        "route_prefix",
        "sni",
        "exact_sans",
        "ca_file",
        "ca_bundle_sha256",
        "ca_sha256_fingerprints",
        "provenance_sha256",
    }
    for index, provider in enumerate(providers):
        if not isinstance(provider, dict) or set(provider) != provider_fields:
            raise SeedBuildError("egress policy planner returned an invalid provider record")
        name = provider.get("name")
        hostname = provider.get("api_hostname")
        route = provider.get("route_prefix")
        sni = provider.get("sni")
        sans = provider.get("exact_sans")
        fingerprints = provider.get("ca_sha256_fingerprints")
        if (
            name != selected[index]
            or not isinstance(hostname, str)
            or HOSTNAME_RE.fullmatch(hostname) is None
            or not isinstance(route, str)
            or not route.startswith("/")
            or not route.endswith("/")
            or not isinstance(sni, str)
            or HOSTNAME_RE.fullmatch(sni) is None
            or not isinstance(sans, list)
            or not sans
            or any(
                not isinstance(value, str) or HOSTNAME_RE.fullmatch(value) is None
                for value in sans
            )
            or sans != sorted(set(sans))
            or provider.get("ca_file") != f"{name}-ca.pem"
            or not isinstance(fingerprints, list)
            or not fingerprints
            or any(
                not isinstance(value, str) or HEX64_RE.fullmatch(value) is None
                for value in fingerprints
            )
            or fingerprints != sorted(set(fingerprints))
        ):
            raise SeedBuildError("egress policy planner returned malformed provider metadata")
        for digest_name in ("ca_bundle_sha256", "provenance_sha256"):
            value = provider.get(digest_name)
            if not isinstance(value, str) or HEX64_RE.fullmatch(value) is None:
                raise SeedBuildError(
                    f"egress policy planner returned an invalid {digest_name}"
                )
    return receipt


def egress_plan_from_release_receipt(receipt: object) -> EgressPolicyPlan:
    """Recover Compose build arguments from one validated release receipt."""

    if not isinstance(receipt, dict) or set(receipt) != {
        "schema_version",
        "egress_policy_sha256",
        "envoy_config_sha256",
        "selected_providers",
        "providers",
        "envoy_image_id",
    }:
        raise SeedBuildError("release egress policy receipt has an invalid shape")
    image_id = receipt.get("envoy_image_id")
    if not isinstance(image_id, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None:
        raise SeedBuildError("release egress policy receipt has an invalid Envoy image ID")
    planner_receipt = dict(receipt)
    del planner_receipt["envoy_image_id"]
    validated = _validate_egress_receipt(planner_receipt)
    selected = validated["selected_providers"]
    policy_sha256 = validated["egress_policy_sha256"]
    assert isinstance(selected, list)
    assert isinstance(policy_sha256, str)
    return EgressPolicyPlan(validated, ",".join(selected), policy_sha256)


def plan_egress_policy(
    client: DockerClient,
    project_root: Path,
    requested_platform: str,
    requested_providers: list[str],
) -> EgressPolicyPlan:
    """Ask the reviewed, network-isolated Go planner for canonical policy."""

    context = project_root / "services" / "egress-proxy"
    dockerfile = context / "Dockerfile"
    if not dockerfile.is_file():
        raise SeedBuildError("reviewed Envoy egress build context is missing")
    build = client.run(
        "build",
        "--pull=false",
        "--network",
        "none",
        "--platform",
        requested_platform,
        "--target",
        "policy-planner",
        "--build-arg",
        f"SOURCE_DATE_EPOCH={SOURCE_DATE_EPOCH}",
        "--tag",
        ENVOY_POLICY_PLANNER_IMAGE,
        "--file",
        str(dockerfile),
        str(context),
    )
    if build.returncode:
        detail = build.stderr.strip().splitlines()
        tail = detail[-1][:2048] if detail else "no diagnostic"
        raise SeedBuildError(f"egress policy planner build failed: {tail}")

    arguments: list[str] = []
    for provider in requested_providers:
        arguments.extend(("--provider", provider))
    planned = client.run(
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=4m,mode=1777",
        "--user",
        "65532:65532",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        ENVOY_POLICY_PLANNER_IMAGE,
        "plan",
        *arguments,
    )
    if planned.returncode:
        detail = planned.stderr.strip().splitlines()
        tail = detail[-1][:2048] if detail else "no diagnostic"
        raise SeedBuildError(f"egress provider selection was rejected: {tail}")
    try:
        receipt = _validate_egress_receipt(json.loads(planned.stdout))
    except json.JSONDecodeError as exc:
        raise SeedBuildError("egress policy planner returned invalid JSON") from exc
    selected = receipt["selected_providers"]
    assert isinstance(selected, list)
    policy_sha256 = receipt["egress_policy_sha256"]
    assert isinstance(policy_sha256, str)
    return EgressPolicyPlan(
        receipt=receipt,
        providers_csv=",".join(selected),
        policy_sha256=policy_sha256,
    )


def build_immutable_envoy_image(
    client: DockerClient,
    project_root: Path,
    requested_platform: str,
    egress_plan: EgressPolicyPlan,
) -> str:
    """Build once, load that exact deterministic export, and verify its receipt."""

    context = project_root / "services" / "egress-proxy"
    with tempfile.TemporaryDirectory(prefix="aigw-envoy-release-") as temporary:
        export = Path(temporary) / "envoy.docker.tar"
        build = client.run(
            "buildx",
            "build",
            "--no-cache",
            "--pull=false",
            "--network=none",
            "--platform",
            requested_platform,
            "--provenance=false",
            "--sbom=false",
            "--build-arg",
            f"SOURCE_DATE_EPOCH={SOURCE_DATE_EPOCH}",
            "--build-arg",
            f"AIGW_EGRESS_PROVIDERS={egress_plan.providers_csv}",
            "--build-arg",
            f"AIGW_EGRESS_POLICY_SHA256={egress_plan.policy_sha256}",
            "--tag",
            ENVOY_IMAGE,
            "--output",
            f"type=docker,dest={export},rewrite-timestamp=true",
            str(context),
        )
        if build.returncode:
            detail = build.stderr.strip().splitlines()
            tail = detail[-1][:2048] if detail else "no diagnostic"
            raise SeedBuildError(f"immutable Envoy image build failed: {tail}")
        if not export.is_file() or export.stat().st_size < 1:
            raise SeedBuildError("immutable Envoy build produced no Docker archive")
        loaded = client.run("image", "load", "--input", str(export))
        if loaded.returncode:
            raise SeedBuildError("cannot load the exact immutable Envoy build artifact")

    inspection = _parse_inspection(
        ENVOY_IMAGE, client.run("image", "inspect", "--", ENVOY_IMAGE)
    )
    assert inspection is not None
    _verified_platform(inspection, ENVOY_IMAGE, requested_platform)
    image_id = inspection.get("Id")
    config = inspection.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    expected_labels = {
        "com.aigw.egress-policy.schema": str(ENVOY_POLICY_SCHEMA),
        "com.aigw.egress-policy.providers": egress_plan.providers_csv,
        "com.aigw.egress-policy.sha256": egress_plan.policy_sha256,
        "com.aigw.source-date-epoch": SOURCE_DATE_EPOCH,
    }
    if (
        not isinstance(image_id, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None
        or not isinstance(labels, dict)
        or any(labels.get(name) != value for name, value in expected_labels.items())
    ):
        raise SeedBuildError("immutable Envoy image labels or image ID are invalid")

    runtime = client.run(
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--user",
        "65532:65532",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        ENVOY_IMAGE,
        "receipt",
    )
    if runtime.returncode:
        raise SeedBuildError("immutable Envoy startup gate rejected its built policy")
    try:
        runtime_receipt = _validate_egress_receipt(json.loads(runtime.stdout))
    except json.JSONDecodeError as exc:
        raise SeedBuildError("immutable Envoy image returned invalid policy JSON") from exc
    if runtime_receipt != egress_plan.receipt:
        raise SeedBuildError("immutable Envoy image policy differs from the reviewed plan")
    return image_id


def _privileged_planner_path(project_root: Path) -> Path:
    """Return the planner only when root can trust its complete project path."""

    if not project_root.is_absolute():
        raise SeedBuildError("planner project root must be canonical and absolute")
    try:
        canonical_root = project_root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise SeedBuildError("planner project root is missing or cannot be resolved") from exc
    if project_root != canonical_root:
        raise SeedBuildError("planner project root must be canonical and contain no symlinks")

    cursor = canonical_root.parent
    while True:
        try:
            metadata = cursor.lstat()
        except OSError as exc:
            raise SeedBuildError("cannot inspect planner project root ancestor") from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid not in {0, ROOT_UID}
            or (
                _mode(metadata) & 0o022
                and not metadata.st_mode & stat.S_ISVTX
            )
        ):
            raise SeedBuildError("planner project root has an untrusted ancestor")
        if cursor == cursor.parent:
            break
        cursor = cursor.parent

    scripts_directory = canonical_root / "scripts"
    for directory in (canonical_root, scripts_directory):
        try:
            metadata = directory.lstat()
        except OSError as exc:
            raise SeedBuildError("planner ancestor is missing") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise SeedBuildError("planner ancestors must be real directories")
        if metadata.st_uid != ROOT_UID:
            raise SeedBuildError("planner ancestors must be root-owned")
        if _mode(metadata) & 0o022:
            raise SeedBuildError(
                "planner ancestors must not be group- or world-writable"
            )

    planner_path = scripts_directory / "plan-compose-builds.py"
    try:
        resolved_path = planner_path.resolve(strict=True)
        resolved_path.relative_to(canonical_root)
        metadata = planner_path.lstat()
    except (OSError, RuntimeError, ValueError) as exc:
        raise SeedBuildError(
            "planner must stay inside the canonical project root"
        ) from exc
    if resolved_path != planner_path:
        raise SeedBuildError("planner must be canonical and contain no symlinks")
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise SeedBuildError("planner must be a regular non-symlink file")
    if (metadata.st_uid, metadata.st_gid) != (ROOT_UID, ROOT_GID):
        raise SeedBuildError("planner must be owned by root:root")
    if _mode(metadata) & 0o022:
        raise SeedBuildError("planner must not be group- or world-writable")
    return planner_path


def _load_build_planner(project_root: Path, *, privileged: bool):
    planner_path = (
        _privileged_planner_path(project_root)
        if privileged
        else project_root / "scripts" / "plan-compose-builds.py"
    )
    spec = importlib.util.spec_from_file_location("_aigw_offline_seed_planner", planner_path)
    if spec is None or spec.loader is None:
        raise SeedBuildError("cannot load the reviewed Compose build planner")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _inspect_custom_image(
    client: DockerClient, image: str, requested_platform: str
) -> str:
    if MUTABLE_IMAGE_RE.fullmatch(image) is None or image.startswith("-") or "@" in image:
        raise SeedBuildError(f"Compose produced an unsafe custom image name: {image!r}")
    record = _parse_inspection(image, client.run("image", "inspect", "--", image))
    assert record is not None
    image_id = record.get("Id")
    if not isinstance(image_id, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None:
        raise SeedBuildError(f"Docker returned an invalid custom image ID: {image}")
    _verified_platform(record, image, requested_platform)
    return image_id


def _custom_archive_reference(image: str, image_id: str) -> str:
    repository = image.rsplit(":", 1)[0] if ":" in image.rsplit("/", 1)[-1] else image
    return f"{repository}:aigw-seed-{image_id.removeprefix('sha256:')}"


def add_preprod_build_services(
    model: dict[str, object], project_root: Path
) -> list[tuple[str, Path, str, str]]:
    services = model.get("services")
    if not isinstance(services, dict):
        raise SeedBuildError("Compose build model has no services object")
    preprod_builds = [
        (
            "samba-ad",
            project_root / "services" / "samba-ad-preprod",
            PREPROD_SAMBA_IMAGE,
            "host",
        ),
        (
            "wif-provider-mock",
            project_root / "services" / "wif-provider-mock",
            PREPROD_WIF_IMAGE,
            "none",
        ),
    ]
    for service, context, image, network in preprod_builds:
        dockerfile = context / "Dockerfile"
        if not context.is_dir() or not dockerfile.is_file():
            raise SeedBuildError(f"preproduction build context is missing: {service}")
        if service in services:
            raise SeedBuildError(
                f"production Compose model unexpectedly defines preproduction service={service}"
            )
        services[service] = {
            "build": {
                "context": str(context.resolve()),
                "network": network,
            },
            "image": image,
        }
    return preprod_builds


def build_custom_images(
    client: DockerClient,
    project_root: Path,
    requested_platform: str,
    egress_plan: EgressPolicyPlan,
    *,
    privileged: bool,
) -> tuple[list[CustomSeedImage], dict[str, object]]:
    """Build every base/profile/preprod image and bind it to planner inputs."""

    model, compose_client, compose_files = render_deployable_compose_model(
        client, project_root, requested_platform, egress_plan
    )
    services = model["services"]
    assert isinstance(services, dict)
    production_build_services = sorted(
        name
        for name, service in services.items()
        if isinstance(name, str) and isinstance(service, dict) and service.get("build")
    )
    if not production_build_services or any(
        SERVICE_RE.fullmatch(name) is None for name in production_build_services
    ):
        raise SeedBuildError("deployable Compose model has no safe custom build services")

    envoy_service = services.get(ENVOY_SERVICE)
    if (
        ENVOY_SERVICE not in production_build_services
        or not isinstance(envoy_service, dict)
        or envoy_service.get("image") != ENVOY_IMAGE
    ):
        raise SeedBuildError("deployable Compose model lacks the immutable Envoy image")
    envoy_image_id = build_immutable_envoy_image(
        compose_client, project_root, requested_platform, egress_plan
    )
    ordinary_build_services = [
        name for name in production_build_services if name != ENVOY_SERVICE
    ]

    if ordinary_build_services:
        build = compose_client.run(
            *_compose_command(project_root, compose_files),
            "build",
            "--pull=false",
            "--no-cache",
            "--provenance=false",
            "--sbom=false",
            *ordinary_build_services,
        )
        if build.returncode:
            detail = build.stderr.strip().splitlines()
            tail = detail[-1][:2048] if detail else "no diagnostic"
            raise SeedBuildError(f"custom Compose image build failed: {tail}")

    preprod_builds = add_preprod_build_services(model, project_root)
    for service, context, image, network in preprod_builds:
        dockerfile = context / "Dockerfile"
        result = compose_client.run(
            "build",
            "--pull=false",
            "--no-cache",
            "--provenance=false",
            "--sbom=false",
            "--platform",
            requested_platform,
            "--network",
            network,
            "--tag",
            image,
            "--file",
            str(dockerfile),
            str(context),
        )
        if result.returncode:
            detail = result.stderr.strip().splitlines()
            tail = detail[-1][:2048] if detail else "no diagnostic"
            raise SeedBuildError(
                f"preproduction custom image build failed for {service}: {tail}"
            )
    build_services = sorted([*production_build_services, *PREPROD_ONLY_SERVICES])

    planner = _load_build_planner(project_root, privileged=privileged)

    def inspect(image: str) -> str | None:
        return _inspect_custom_image(compose_client, image, requested_platform)

    with tempfile.TemporaryDirectory(prefix="aigw-seed-plan-") as temporary:
        plan = planner.plan_compose_builds(
            model,
            stack=project_root,
            state_path=Path(temporary) / "absent.json",
            project=COMPOSE_PROJECT_NAME,
            image_inspector=inspect,
        )
    manifest = plan.get("manifest")
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema") != 1
        or not isinstance(manifest.get("services"), dict)
        or set(manifest["services"]) != set(build_services)
    ):
        raise SeedBuildError("Compose build planner returned an incomplete manifest")
    envoy_record = manifest["services"].get(ENVOY_SERVICE)
    if not isinstance(envoy_record, dict) or envoy_record.get("image_id") != envoy_image_id:
        raise SeedBuildError("build planner did not bind the exact immutable Envoy image")

    custom_by_image: dict[str, CustomSeedImage] = {}
    for service, record in sorted(manifest["services"].items()):
        if not isinstance(record, dict):
            raise SeedBuildError(f"invalid build-input record for service {service}")
        image = record.get("image")
        image_id = record.get("image_id")
        digest = record.get("digest")
        if (
            not isinstance(image, str)
            or MUTABLE_IMAGE_RE.fullmatch(image) is None
            or not isinstance(image_id, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None
            or not isinstance(digest, str)
            or HEX64_RE.fullmatch(digest) is None
        ):
            raise SeedBuildError(f"invalid build-input record for service {service}")
        existing = custom_by_image.get(image)
        if existing is not None and existing.image_id != image_id:
            raise SeedBuildError(f"shared custom image tag resolved ambiguously: {image}")
        archive_reference = _custom_archive_reference(image, image_id)
        tag = compose_client.run("image", "tag", image_id, archive_reference)
        if tag.returncode:
            raise SeedBuildError(f"cannot create custom image transfer tag: {image}")
        if _inspect_custom_image(compose_client, archive_reference, requested_platform) != image_id:
            raise SeedBuildError(f"custom image transfer tag verification failed: {image}")
        if service in PREPROD_ONLY_SERVICES:
            custom_image = CustomSeedImage(
                image,
                archive_reference,
                image_id,
                deployment_scope="preprod-only",
                target_activation="archive-only",
            )
        else:
            custom_image = CustomSeedImage(image, archive_reference, image_id)
        if existing is not None and (
            existing.deployment_scope != custom_image.deployment_scope
            or existing.target_activation != custom_image.target_activation
        ):
            raise SeedBuildError(f"shared custom image has conflicting scope: {image}")
        custom_by_image[image] = custom_image
    return [custom_by_image[name] for name in sorted(custom_by_image)], manifest


def scoped_custom_release(
    custom_images: list[CustomSeedImage],
    build_inputs: dict[str, object],
    release_scope: str,
) -> tuple[list[CustomSeedImage], dict[str, object]]:
    """Select one release without rebuilding or weakening its build proof."""

    if release_scope not in RELEASE_SCOPES:
        raise SeedBuildError(f"unsupported release scope: {release_scope!r}")
    services = build_inputs.get("services")
    if build_inputs.get("schema") != 1 or not isinstance(services, dict):
        raise SeedBuildError("custom build-input manifest is invalid")

    if release_scope == RELEASE_SCOPE_PRODUCTION:
        selected = [
            image
            for image in custom_images
            if image.deployment_scope == RELEASE_SCOPE_PRODUCTION
        ]
    else:
        selected = list(custom_images)
    selected_names = {image.image for image in selected}
    scoped_services = {
        service: record
        for service, record in sorted(services.items())
        if isinstance(record, dict) and record.get("image") in selected_names
    }
    if not selected or {record.get("image") for record in scoped_services.values()} != selected_names:
        raise SeedBuildError(
            f"{release_scope} release custom images and build inputs disagree"
        )

    preprod_images = {
        image.image for image in custom_images if image.deployment_scope == "preprod-only"
    }
    if preprod_images != {PREPROD_SAMBA_IMAGE, PREPROD_WIF_IMAGE}:
        raise SeedBuildError("preproduction release must contain exactly Samba AD and WIF mock extras")
    if release_scope == RELEASE_SCOPE_PRODUCTION and (
        any(image.deployment_scope != "production" for image in selected)
        or PREPROD_ONLY_SERVICES.intersection(scoped_services)
        or preprod_images.intersection(selected_names)
    ):
        raise SeedBuildError("production release contains preproduction-only image data")

    return selected, {"schema": 1, "services": scoped_services}


def preprod_output_paths(
    archive: Path,
    manifest: Path,
    explicit_archive: Path | None = None,
    explicit_manifest: Path | None = None,
) -> tuple[Path, Path]:
    """Return explicit or deterministic sibling paths for the full preprod seed."""

    if (explicit_archive is None) != (explicit_manifest is None):
        raise SeedBuildError(
            "--preprod-archive and --preprod-manifest must be supplied together"
        )
    if explicit_archive is not None and explicit_manifest is not None:
        return explicit_archive, explicit_manifest
    archive_suffix = ".docker.tar.zst"
    manifest_suffix = ".manifest.json"
    if not archive.name.endswith(archive_suffix) or not manifest.name.endswith(
        manifest_suffix
    ):
        raise SeedBuildError("release output paths use an invalid suffix")
    return (
        archive.with_name(archive.name[: -len(archive_suffix)] + ".preprod" + archive_suffix),
        manifest.with_name(
            manifest.name[: -len(manifest_suffix)] + ".preprod" + manifest_suffix
        ),
    )


def egress_policy_release_receipt(
    egress_plan: EgressPolicyPlan,
    custom_images: list[CustomSeedImage],
) -> dict[str, object]:
    """Bind the reviewed policy receipt to the one final Envoy image ID."""

    matches = [image for image in custom_images if image.image == ENVOY_IMAGE]
    if len(matches) != 1 or matches[0].deployment_scope != RELEASE_SCOPE_PRODUCTION:
        raise SeedBuildError("release does not contain exactly one production Envoy image")
    receipt = dict(egress_plan.receipt)
    receipt["envoy_image_id"] = matches[0].image_id
    return receipt


def build_manifest(
    archive: Path,
    platform_name: str,
    images: list[SeedImage],
    custom_images: list[CustomSeedImage],
    build_inputs: dict[str, object],
    release_scope: str,
    egress_policy: dict[str, object],
) -> dict[str, object]:
    """Create the exact schema-v2 manifest for one immutable release scope."""

    total = len(images) + len(custom_images)
    return {
        "schema_version": MANIFEST_SCHEMA_V2,
        "release_scope": release_scope,
        "platform": platform_name,
        "bundle": archive.name,
        "scope": {
            "exported_images": total,
            "external_images_exported": len(images),
            "custom_ai_gateway_images_exported": len(custom_images),
        },
        "verification": {"verified": total, "missing": 0, "mismatched": 0},
        "images": [
            {"reference": image.reference, "image_id": image.image_id}
            for image in images
        ],
        "custom_images": [
            {
                "image": image.image,
                "archive_reference": image.archive_reference,
                "image_id": image.image_id,
                "deployment_scope": image.deployment_scope,
                "target_activation": image.target_activation,
            }
            for image in custom_images
        ],
        "build_inputs": build_inputs,
        "egress_policy": egress_policy,
    }


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
    oci_documents: dict[str, dict[str, object]] = {}
    verified_small_blobs: set[str] = set()
    stream_error: SeedBuildError | None = None
    try:
        with tarfile.open(fileobj=decompressor.stdout, mode="r|") as source:
            for count, member in enumerate(source, start=1):
                if count > MAX_ARCHIVE_MEMBERS:
                    raise SeedBuildError("image seed archive contains too many members")
                if member.name in {"manifest.json", "index.json"}:
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
                    continue

                blob_match = OCI_BLOB_PATH_RE.fullmatch(member.name)
                if (
                    blob_match is None
                    or not member.isfile()
                    or member.size < 1
                    or member.size > MAX_ARCHIVE_METADATA_BYTES
                ):
                    continue
                member_file = source.extractfile(member)
                if member_file is None:
                    raise SeedBuildError("cannot read image seed OCI blob metadata")
                content = member_file.read()
                digest = f"sha256:{blob_match.group(1)}"
                if hashlib.sha256(content).hexdigest() != blob_match.group(1):
                    raise SeedBuildError("image seed OCI blob digest does not match its path")
                verified_small_blobs.add(digest)
                try:
                    document = json.loads(content.decode("utf-8"))
                except (UnicodeError, json.JSONDecodeError):
                    continue
                if not isinstance(document, dict) or not (
                    isinstance(document.get("manifests"), list)
                    or document.get("artifactType") == SIGSTORE_BUNDLE_MEDIA_TYPE
                ):
                    continue
                if (
                    digest in oci_documents
                    or len(oci_documents) >= MAX_CAPTURED_OCI_DOCUMENTS
                ):
                    raise SeedBuildError("image seed has too many or duplicate OCI documents")
                oci_documents[digest] = document
    except SeedBuildError as exc:
        stream_error = exc
    except (OSError, tarfile.TarError) as exc:
        stream_error = SeedBuildError(f"cannot read image seed archive metadata: {exc}")
    finally:
        decompressor.stdout.close()

    stderr = decompressor.stderr.read()
    returncode = decompressor.wait()
    if stream_error is not None:
        raise stream_error
    if returncode:
        detail = stderr.decode("utf-8", errors="replace")[-2048:].strip()
        raise SeedBuildError(f"cannot decompress image seed metadata: {detail or 'no diagnostic'}")
    found["_oci_documents"] = oci_documents
    found["_verified_small_blobs"] = verified_small_blobs
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


def _config_matches_image_id(config: object, image_id: str) -> bool:
    if not isinstance(config, str):
        return False
    digest = image_id.removeprefix("sha256:")
    return config in {f"{digest}.json", f"blobs/sha256/{digest}"}


def _approved_external_sigstore_artifact(
    descriptor: object,
    expected_external_digests: set[str],
    oci_documents: dict[str, dict[str, object]],
    verified_small_blobs: set[str],
) -> bool:
    """Admit only a signature bundle bound to a pinned external OCI index."""

    if not isinstance(descriptor, dict):
        return False
    descriptor_digest = descriptor.get("digest")
    descriptor_size = descriptor.get("size")
    annotations = descriptor.get("annotations")
    if (
        descriptor.get("mediaType") != OCI_IMAGE_MANIFEST_MEDIA_TYPE
        or not isinstance(descriptor_digest, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", descriptor_digest) is None
        or not isinstance(descriptor_size, int)
        or descriptor_size < 1
        or not isinstance(annotations, dict)
        or set(annotations) != {"io.containerd.manifest.subject"}
    ):
        return False
    subject = annotations.get("io.containerd.manifest.subject")
    if (
        not isinstance(subject, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", subject) is None
    ):
        return False

    subject_is_approved = False
    for parent_digest in expected_external_digests:
        parent = oci_documents.get(parent_digest)
        manifests = parent.get("manifests") if isinstance(parent, dict) else None
        if not isinstance(manifests, list):
            continue
        for candidate in manifests:
            candidate_annotations = (
                candidate.get("annotations") if isinstance(candidate, dict) else None
            )
            if (
                isinstance(candidate, dict)
                and candidate.get("digest") == subject
                and isinstance(candidate_annotations, dict)
                and candidate_annotations.get("vnd.docker.reference.type")
                == "attestation-manifest"
                and isinstance(
                    candidate_annotations.get("vnd.docker.reference.digest"), str
                )
                and re.fullmatch(
                    r"sha256:[0-9a-f]{64}",
                    candidate_annotations["vnd.docker.reference.digest"],
                )
            ):
                subject_is_approved = True
                break
        if subject_is_approved:
            break
    if not subject_is_approved:
        return False

    artifact = oci_documents.get(descriptor_digest)
    if not isinstance(artifact, dict):
        return False
    artifact_subject = artifact.get("subject")
    config = artifact.get("config")
    layers = artifact.get("layers")
    if (
        artifact.get("schemaVersion") != 2
        or artifact.get("mediaType") != OCI_IMAGE_MANIFEST_MEDIA_TYPE
        or artifact.get("artifactType") != SIGSTORE_BUNDLE_MEDIA_TYPE
        or not isinstance(artifact_subject, dict)
        or artifact_subject.get("mediaType") != OCI_IMAGE_MANIFEST_MEDIA_TYPE
        or artifact_subject.get("digest") != subject
        or not isinstance(artifact_subject.get("size"), int)
        or artifact_subject["size"] < 1
        or not isinstance(config, dict)
        or config.get("mediaType") != OCI_EMPTY_MEDIA_TYPE
        or config.get("artifactType") != SIGSTORE_BUNDLE_MEDIA_TYPE
        or not isinstance(config.get("digest"), str)
        or config["digest"] not in verified_small_blobs
        or not isinstance(config.get("size"), int)
        or config["size"] < 1
        or not isinstance(layers, list)
        or len(layers) != 1
        or not isinstance(layers[0], dict)
        or layers[0].get("mediaType") != SIGSTORE_BUNDLE_MEDIA_TYPE
        or not isinstance(layers[0].get("digest"), str)
        or layers[0]["digest"] not in verified_small_blobs
        or not isinstance(layers[0].get("size"), int)
        or layers[0]["size"] < 1
    ):
        return False
    return descriptor_digest in verified_small_blobs


def _validate_export_metadata(
    metadata: dict[str, object],
    images: Iterable[SeedImage],
    custom_images: Iterable[CustomSeedImage] = (),
) -> None:
    """Prove the archive carries the OCI tag/digest metadata Docker load needs."""

    manifest = metadata.get("manifest.json")
    index = metadata.get("index.json")
    if not isinstance(manifest, list) or not isinstance(index, dict):
        raise SeedBuildError("image seed must be an OCI archive with manifest.json and index.json")

    expected = list(images)
    expected_custom = list(custom_images)
    expected_tags = {image.save_reference for image in expected} | {
        image.archive_reference for image in expected_custom
    }
    exported_tags: set[str] = set()
    custom_config_matches: dict[str, bool] = {}
    for entry in manifest:
        if not isinstance(entry, dict):
            raise SeedBuildError("image seed manifest contains an invalid entry")
        tags = entry.get("RepoTags")
        if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
            raise SeedBuildError("image seed archive omitted a required repository tag")
        exported_tags.update(tags)
        for image in expected_custom:
            if image.archive_reference in tags:
                custom_config_matches[image.archive_reference] = (
                    _config_matches_image_id(entry.get("Config"), image.image_id)
                )
    if exported_tags != expected_tags:
        raise SeedBuildError(
            "image seed archive repository tags do not exactly match the reviewed image set"
        )
    if set(custom_config_matches) != {
        image.archive_reference for image in expected_custom
    }:
        raise SeedBuildError("image seed archive omitted a custom image ID binding")

    descriptors = index.get("manifests")
    if index.get("schemaVersion") != 2 or not isinstance(descriptors, list):
        raise SeedBuildError("image seed OCI index is invalid")
    expected_descriptor_names = {
        _normalised_oci_name(image.save_reference)[2] for image in expected
    } | {
        _normalised_oci_name(image.archive_reference)[2]
        for image in expected_custom
    }
    expected_external_digests = {
        f"sha256:{image.reference.rsplit('@sha256:', 1)[1]}" for image in expected
    }
    raw_oci_documents = metadata.get("_oci_documents", {})
    raw_verified_small_blobs = metadata.get("_verified_small_blobs", set())
    if not isinstance(raw_oci_documents, dict) or not isinstance(
        raw_verified_small_blobs, set
    ):
        raise SeedBuildError("image seed OCI support metadata is invalid")
    oci_documents = {
        digest: document
        for digest, document in raw_oci_documents.items()
        if isinstance(digest, str) and isinstance(document, dict)
    }
    if len(oci_documents) != len(raw_oci_documents) or any(
        not isinstance(digest, str) for digest in raw_verified_small_blobs
    ):
        raise SeedBuildError("image seed OCI support metadata is invalid")
    verified_small_blobs = set(raw_verified_small_blobs)
    actual_descriptor_names: list[str] = []
    approved_artifact_digests: set[str] = set()
    for descriptor in descriptors:
        annotations = descriptor.get("annotations") if isinstance(descriptor, dict) else None
        canonical_name = (
            annotations.get("io.containerd.image.name")
            if isinstance(annotations, dict)
            else None
        )
        if isinstance(canonical_name, str):
            actual_descriptor_names.append(canonical_name)
            continue
        if _approved_external_sigstore_artifact(
            descriptor,
            expected_external_digests,
            oci_documents,
            verified_small_blobs,
        ):
            artifact_digest = descriptor.get("digest")
            assert isinstance(artifact_digest, str)
            if artifact_digest in approved_artifact_digests:
                raise SeedBuildError("image seed contains a duplicate signature artifact")
            approved_artifact_digests.add(artifact_digest)
            continue
        else:
            raise SeedBuildError(
                "image seed OCI index contains an unapproved untagged descriptor"
            )
    if (
        len(actual_descriptor_names) != len(expected_descriptor_names)
        or set(actual_descriptor_names) != expected_descriptor_names
    ):
        raise SeedBuildError(
            "image seed OCI descriptors do not exactly match the reviewed image set"
        )
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
    for image in expected_custom:
        _, _, canonical_name = _normalised_oci_name(image.archive_reference)
        matching = [
            descriptor
            for descriptor in descriptors
            if isinstance(descriptor, dict)
            and isinstance(descriptor.get("annotations"), dict)
            and descriptor["annotations"].get("io.containerd.image.name")
            == canonical_name
        ]
        if len(matching) != 1:
            raise SeedBuildError(
                "image seed OCI metadata cannot restore custom transfer tag: "
                f"{image.archive_reference}"
            )
        descriptor_digest = matching[0].get("digest")
        if (
            not isinstance(descriptor_digest, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", descriptor_digest) is None
        ):
            raise SeedBuildError(
                "custom image OCI descriptor lacks digest provenance: "
                f"{image.archive_reference}"
            )
        if (
            descriptor_digest != image.image_id
            and not custom_config_matches[image.archive_reference]
        ):
            raise SeedBuildError(
                "custom image archive tag does not bind its immutable image ID: "
                f"{image.image}"
            )


def _stream_save(
    archive: Path,
    images: list[SeedImage],
    custom_images: list[CustomSeedImage],
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
                client.command(
                    "image",
                    "save",
                    *(image.save_reference for image in images),
                    *(image.archive_reference for image in custom_images),
                ),
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
        _validate_export_metadata(
            _read_export_metadata(temporary, zstd), images, custom_images
        )
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
    parser = argparse.ArgumentParser(
        description=(
            "Pull, build, verify, and export a platform-bound offline image release. "
            "Without --prepare-release/--pull/--build-custom it retains the legacy "
            "schema-v1 export-existing behavior."
        )
    )
    parser.add_argument(
        "archive", type=Path, help="absolute output path ending in .docker.tar.zst"
    )
    parser.add_argument(
        "manifest", type=Path, help="absolute output path ending in .manifest.json"
    )
    parser.add_argument(
        "--preprod-archive",
        type=Path,
        help=(
            "optional full preprod archive path; defaults to the production "
            "archive name with .preprod before .docker.tar.zst"
        ),
    )
    parser.add_argument(
        "--preprod-manifest",
        type=Path,
        help=(
            "optional full preprod manifest path; defaults to the production "
            "manifest name with .preprod before .manifest.json"
        ),
    )
    parser.add_argument("--image", action="append", default=[])
    parser.add_argument(
        "--provider",
        action="append",
        default=[],
        metavar="NAME",
        help=(
            "reviewed Envoy egress provider; repeat to select more than one "
            "(required for schema-v2 release preparation)"
        ),
    )
    parser.add_argument(
        "--platform",
        choices=SUPPORTED_PLATFORMS,
        help="exact target platform required for pull/build release preparation",
    )
    parser.add_argument(
        "--pull",
        action="store_true",
        help="pull every exact external tag@digest pin for --platform",
    )
    parser.add_argument(
        "--build-custom",
        action="store_true",
        help="build every deployable custom Compose image with --pull=false",
    )
    parser.add_argument(
        "--prepare-release",
        action="store_true",
        help="controller workflow shortcut: --pull plus --build-custom (schema v2)",
    )
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
        source_reference_scopes = (
            collect_project_image_reference_scopes(project_root)
            if project_root is not None
            else {
                RELEASE_SCOPE_PRODUCTION: set(),
                RELEASE_SCOPE_PREPROD: set(),
            }
        )
        source_references = source_reference_scopes[RELEASE_SCOPE_PREPROD]
        references = sorted(set(args.image) | source_references)
        if not references:
            raise SeedBuildError(
                "provide at least one --image or run from a project checkout with digest-pinned sources"
            )
        pull_requested = args.pull or args.prepare_release
        build_requested = args.build_custom or args.prepare_release
        if build_requested and not args.provider:
            raise SeedBuildError(
                "schema-v2 release preparation requires at least one --provider"
            )
        if not build_requested and args.provider:
            raise SeedBuildError("--provider requires --build-custom or --prepare-release")
        if not build_requested and (
            args.preprod_archive is not None or args.preprod_manifest is not None
        ):
            raise SeedBuildError(
                "preprod release outputs require --build-custom or --prepare-release"
            )
        if (pull_requested or build_requested) and args.platform is None:
            raise SeedBuildError(
                "--platform linux/amd64 or --platform linux/arm64 is required for pull/build"
            )
        if build_requested and project_root is None:
            raise SeedBuildError("--build-custom requires a reviewed project checkout")
        if build_requested and set(references) != source_references:
            raise SeedBuildError(
                "schema-v2 release must contain exactly the project external pins; "
                "additional --image references are prohibited"
            )

        preprod_archive: Path | None = None
        preprod_manifest_path: Path | None = None
        if build_requested:
            preprod_archive_raw, preprod_manifest_raw = preprod_output_paths(
                archive,
                manifest_path,
                args.preprod_archive,
                args.preprod_manifest,
            )
            preprod_archive = require_safe_output(
                preprod_archive_raw, ".docker.tar.zst", policy
            )
            preprod_manifest_path = require_safe_output(
                preprod_manifest_raw, ".manifest.json", policy
            )
            if (
                preprod_archive.parent != archive.parent
                or preprod_manifest_path.parent != archive.parent
            ):
                raise SeedBuildError(
                    "production and preprod release outputs must use the same directory"
                )
            if len({archive, manifest_path, preprod_archive, preprod_manifest_path}) != 4:
                raise SeedBuildError("production and preprod release outputs must be distinct")

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
        image_platform = platform(client, args.platform)
        if pull_requested:
            pull_images(client, references, image_platform)
        images = inspect_images(
            client,
            references,
            materialize_missing_tags=(
                args.materialize_missing_source_tags or pull_requested
            ),
            expected_platform=image_platform if args.platform is not None else None,
        )
        custom_images: list[CustomSeedImage] = []
        build_inputs: dict[str, object] | None = None
        egress_plan: EgressPolicyPlan | None = None
        if build_requested:
            assert project_root is not None
            egress_plan = plan_egress_policy(
                client,
                project_root,
                image_platform,
                args.provider,
            )
            custom_images, build_inputs = build_custom_images(
                client,
                project_root,
                image_platform,
                egress_plan,
                privileged=policy.root_controller,
            )
        zstd = _find_executable("zstd", policy)
        manifest: dict[str, object]
        if build_requested:
            assert build_inputs is not None
            assert egress_plan is not None
            assert preprod_archive is not None
            assert preprod_manifest_path is not None
            production_images, production_inputs = scoped_custom_release(
                custom_images, build_inputs, RELEASE_SCOPE_PRODUCTION
            )
            preprod_images, preprod_inputs = scoped_custom_release(
                custom_images, build_inputs, RELEASE_SCOPE_PREPROD
            )
            production_external = scoped_external_images(
                images, source_reference_scopes[RELEASE_SCOPE_PRODUCTION]
            )
            preprod_external = scoped_external_images(
                images, source_reference_scopes[RELEASE_SCOPE_PREPROD]
            )
            egress_policy = egress_policy_release_receipt(
                egress_plan, custom_images
            )
            _stream_save(
                archive,
                production_external,
                production_images,
                client,
                zstd,
                policy,
            )
            manifest = build_manifest(
                archive,
                image_platform,
                production_external,
                production_images,
                production_inputs,
                RELEASE_SCOPE_PRODUCTION,
                egress_policy,
            )
            replace_private(
                manifest_path,
                (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode(),
                policy,
            )

            # Reuse the exact images from the one build pass. The second save
            # adds only the two preprod-only outputs; it never pulls or builds.
            _stream_save(
                preprod_archive,
                preprod_external,
                preprod_images,
                client,
                zstd,
                policy,
            )
            preprod_manifest = build_manifest(
                preprod_archive,
                image_platform,
                preprod_external,
                preprod_images,
                preprod_inputs,
                RELEASE_SCOPE_PREPROD,
                egress_policy,
            )
            replace_private(
                preprod_manifest_path,
                (
                    json.dumps(preprod_manifest, sort_keys=True, separators=(",", ":"))
                    + "\n"
                ).encode(),
                policy,
            )
        else:
            # Preserve the exact historical schema-v1 shape.
            _stream_save(archive, images, [], client, zstd, policy)
            manifest = {
                "schema_version": MANIFEST_SCHEMA_V1,
                "platform": image_platform,
                "bundle": archive.name,
                "scope": {
                    "exported_images": len(images),
                    "custom_ai_gateway_images_exported": 0,
                },
                "verification": {
                    "verified": len(images),
                    "missing": 0,
                    "mismatched": 0,
                },
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
        result: dict[str, object] = {
            "archive_sha256": sha256(archive),
            "manifest_sha256": sha256(manifest_path),
            "images": manifest["scope"]["exported_images"],  # type: ignore[index]
            "external_images": manifest["scope"]["external_images_exported"] if build_requested else len(images),  # type: ignore[index]
            "custom_images": manifest["scope"]["custom_ai_gateway_images_exported"],  # type: ignore[index]
            "platform": image_platform,
            "schema_version": manifest["schema_version"],
        }
        if build_requested:
            assert preprod_archive is not None
            assert preprod_manifest_path is not None
            result.update(
                {
                    "release_scope": RELEASE_SCOPE_PRODUCTION,
                    "preprod_archive": str(preprod_archive),
                    "preprod_archive_sha256": sha256(preprod_archive),
                    "preprod_manifest": str(preprod_manifest_path),
                    "preprod_manifest_sha256": sha256(preprod_manifest_path),
                    "selected_providers": egress_plan.receipt["selected_providers"],
                    "egress_policy_sha256": egress_plan.policy_sha256,
                }
            )
        print(
            json.dumps(result, sort_keys=True)
        )
    except (OSError, SeedBuildError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
