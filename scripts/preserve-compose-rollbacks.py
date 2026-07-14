#!/usr/bin/env python3
"""Preserve the exact running image for every planned Compose build.

The build planner deliberately follows a mutable local image tag.  Replacing
that tag can make the prior image immediately uninspectable when Docker uses
the containerd image store and Compose removes the old container.  This helper
runs after planning and before building.  It resolves the one supported
single-host replica from the container itself, pins that immutable image under
a project/service/content-addressed rollback tag, verifies the tag, and
atomically records one active generation per service in a root-only,
non-secret rollback manifest.  A failed multi-service operation can leave only
additional immutable tags; it can never move a tag named by the prior manifest.

No shell is used. A first build is represented explicitly. A clean initial
deployment may begin from an exact plan-matching preseeded image, but only
before a completed build-input receipt exists and without a prior rollback
manifest. Once a service is recorded in that receipt, a missing authoritative
container remains fail-closed. An unchanged converge never calls this helper.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
# subprocess is restricted to the fixed exec-form Docker CLI wrapper below.
import subprocess  # nosec B404
import sys
import tempfile
from typing import Any, Callable


ROOT_UID = 0
ROOT_GID = 0
STATE_DIR_MODE = 0o700
MANIFEST_MODE = 0o600
MAX_PLAN_BYTES = 4 * 1024 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_SERVICES = 256
FIXED_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
LOCAL_DOCKER_HOST = "unix:///run/docker.sock"
FIXED_DOCKER_ENV = {
    "DOCKER_HOST": LOCAL_DOCKER_HOST,
    "HOME": "/",
    "LC_ALL": "C",
    "PATH": FIXED_PATH,
}
MANIFEST_NAME = "compose-build-rollbacks.json"
BUILD_INPUTS_NAME = "compose-build-inputs.json"
ROLLBACK_SCHEMA = 2
BUILD_INPUTS_SCHEMA = 1
KEY_ROTATOR_SERVICE = "key-rotator"
VAULT_SERVICE = "vault"
KEY_ROTATOR_READINESS_HEALTHCHECK = [
    "CMD",
    "python3",
    "-c",
    (
        "import urllib.request; "
        "urllib.request.urlopen('http://127.0.0.1:8080/readyz', timeout=3).read()"
    ),
]
KEY_ROTATOR_DEPENDENCY_PROBE = (
    "import json,urllib.error,urllib.request;"
    "h=urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=3);"
    "d=json.loads(h.read(4097));"
    "assert h.status==200 and d.get('ok') is True;"
    "\ntry: urllib.request.urlopen('http://127.0.0.1:8080/readyz',timeout=3)\n"
    "except urllib.error.HTTPError as e: assert e.code==503\n"
    "else: raise AssertionError('key-rotator unexpectedly ready')"
)

PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
SERVICE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
PATH_COMPONENT_RE = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
REGISTRY_RE = re.compile(
    r"^(?:localhost|[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?)(?::[0-9]{1,5})?$"
)


class PreserveError(RuntimeError):
    """A fail-closed rollback-preservation error."""


RunCommand = Callable[..., subprocess.CompletedProcess[bytes]]


def _mode(metadata: os.stat_result) -> int:
    return stat.S_IMODE(metadata.st_mode)


def _validated_repository(image: str) -> str:
    """Return a conservative Docker repository without its optional tag."""
    if not image or len(image) > 384 or image.startswith("-") or "@" in image:
        raise PreserveError(f"unsafe mutable build image reference: {image!r}")

    final_component = image.rsplit("/", 1)[-1]
    if ":" in final_component:
        repository, tag = image.rsplit(":", 1)
        if not TAG_RE.fullmatch(tag):
            raise PreserveError(f"unsafe mutable build image tag: {image!r}")
    else:
        repository = image

    components = repository.split("/")
    if not components or any(not component for component in components):
        raise PreserveError(f"unsafe mutable build repository: {image!r}")
    first_is_registry = len(components) > 1 and (
        components[0] == "localhost"
        or "." in components[0]
        or ":" in components[0]
    )
    path_components = components
    if first_is_registry:
        registry = components[0]
        if not REGISTRY_RE.fullmatch(registry):
            raise PreserveError(f"unsafe build image registry: {image!r}")
        if ":" in registry:
            port = int(registry.rsplit(":", 1)[1])
            if port < 1 or port > 65535:
                raise PreserveError(f"unsafe build image registry port: {image!r}")
        path_components = components[1:]

    if not path_components or any(
        PATH_COMPONENT_RE.fullmatch(component) is None
        for component in path_components
    ):
        raise PreserveError(f"unsafe mutable build repository: {image!r}")
    return repository


def rollback_reference(
    image: str, project: str, service: str, source_image_id: str
) -> str:
    if PROJECT_RE.fullmatch(project) is None:
        raise PreserveError(f"unsafe Compose project name: {project!r}")
    if SERVICE_RE.fullmatch(service) is None:
        raise PreserveError(f"unsafe Compose service name: {service!r}")
    if IMAGE_ID_RE.fullmatch(source_image_id) is None:
        raise PreserveError(f"unsafe immutable source image ID: {source_image_id!r}")
    repository = _validated_repository(image)
    # Include the full source digest so a new generation never moves a tag named
    # by the currently committed manifest. The 96-bit namespace token scopes a
    # shared repository to the exact project/service while keeping the Docker
    # tag far below its 128-byte limit.
    namespace_token = hashlib.sha256(
        project.encode("ascii") + b"\0" + service.encode("ascii")
    ).hexdigest()[:24]
    source_digest = source_image_id.removeprefix("sha256:")
    rollback = f"{repository}:aigw-rollback-{namespace_token}-{source_digest}"
    if rollback == image:
        raise PreserveError("desired image already uses its reserved rollback tag")
    return rollback


def validate_plan(raw: object, project: str) -> list[dict[str, str | None]]:
    if PROJECT_RE.fullmatch(project) is None:
        raise PreserveError("unsafe Compose project name")
    if not isinstance(raw, dict) or set(raw) != {"manifest", "services"}:
        raise PreserveError("build plan root must be an object")
    services = raw.get("services")
    manifest = raw.get("manifest")
    if not isinstance(services, list) or not services:
        raise PreserveError("rollback preservation requires a non-empty build plan")
    if len(services) > MAX_SERVICES:
        raise PreserveError("build plan exceeds the 256-service bound")
    if any(
        not isinstance(service, str) or SERVICE_RE.fullmatch(service) is None
        for service in services
    ):
        raise PreserveError("build plan contains an unsafe Compose service name")
    if services != sorted(services) or len(set(services)) != len(services):
        raise PreserveError("planned services must be unique and sorted")
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"schema", "services"}
        or manifest.get("schema") != 1
        or not isinstance(manifest.get("services"), dict)
        or len(manifest["services"]) > MAX_SERVICES
    ):
        raise PreserveError("build plan manifest is invalid")

    records: list[dict[str, str | None]] = []
    for service in services:
        raw_record = manifest["services"].get(service)
        if not isinstance(raw_record, dict) or set(raw_record) != {
            "digest",
            "image",
            "image_id",
        }:
            raise PreserveError(f"planned service has no manifest record: {service}")
        digest = raw_record.get("digest")
        image = raw_record.get("image")
        image_id = raw_record.get("image_id")
        if not isinstance(digest, str) or DIGEST_RE.fullmatch(digest) is None:
            raise PreserveError(f"invalid build-input digest for service={service}")
        if not isinstance(image, str):
            raise PreserveError(f"invalid image reference for service={service}")
        _validated_repository(image)
        if image_id is not None and (
            not isinstance(image_id, str) or IMAGE_ID_RE.fullmatch(image_id) is None
        ):
            raise PreserveError(f"invalid planned image ID for service={service}")
        records.append(
            {
                "service": service,
                "build_input_digest": digest,
                "desired_image": image,
                "planned_image_id": image_id,
            }
        )
    return records


class DockerClient:
    """Small fixed-argv Docker client used by the preservation boundary."""

    def __init__(self, executable: str, runner: RunCommand = subprocess.run) -> None:
        self.executable = executable
        self._runner = runner

    def _run(self, arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
        # The executable is fixed and every variable argument is validated.
        return self._runner(  # nosec B603
            [self.executable, "--host", LOCAL_DOCKER_HOST, *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=FIXED_DOCKER_ENV,
        )

    @staticmethod
    def _decoded_json(
        result: subprocess.CompletedProcess[bytes], label: str
    ) -> list[dict[str, Any]]:
        if result.returncode != 0:
            raise PreserveError(f"Docker failed to inspect {label}")
        try:
            decoded = json.loads(result.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PreserveError(f"Docker returned invalid JSON for {label}") from exc
        if (
            not isinstance(decoded, list)
            or len(decoded) != 1
            or not isinstance(decoded[0], dict)
        ):
            raise PreserveError(f"Docker returned an ambiguous inspection for {label}")
        return decoded

    def ensure_ready(self) -> None:
        result = self._run(["info", "--format", "{{.ServerVersion}}"])
        if result.returncode != 0 or not result.stdout.strip():
            raise PreserveError("Docker daemon is not ready")

    def list_service_containers(self, project: str, service: str) -> list[str]:
        result = self._run(
            [
                "ps",
                "-a",
                "--no-trunc",
                "--filter",
                f"label=com.docker.compose.project={project}",
                "--filter",
                f"label=com.docker.compose.service={service}",
                "--format",
                "{{.ID}}",
            ]
        )
        if result.returncode != 0:
            raise PreserveError(f"Docker failed to list service={service} containers")
        try:
            identifiers = result.stdout.decode("ascii").splitlines()
        except UnicodeDecodeError as exc:
            raise PreserveError("Docker returned a non-ASCII container ID") from exc
        identifiers = [identifier.strip() for identifier in identifiers if identifier.strip()]
        if len(set(identifiers)) != len(identifiers) or any(
            re.fullmatch(r"[0-9a-f]{64}", identifier) is None
            for identifier in identifiers
        ):
            raise PreserveError(f"Docker returned invalid service={service} container IDs")
        return identifiers

    def inspect_container(self, identifier: str) -> dict[str, Any]:
        result = self._run(["container", "inspect", "--", identifier])
        return self._decoded_json(result, f"container={identifier}")[0]

    def inspect_image(self, reference: str, *, allow_missing: bool = False) -> str | None:
        result = self._run(["image", "inspect", "--", reference])
        if result.returncode != 0 and allow_missing:
            error = result.stderr.decode("utf-8", errors="replace").lower()
            if "no such image" in error or "no such object" in error or "not found" in error:
                return None
        decoded = self._decoded_json(result, f"image={reference}")
        image_id = decoded[0].get("Id")
        if not isinstance(image_id, str) or IMAGE_ID_RE.fullmatch(image_id) is None:
            raise PreserveError(f"Docker returned an invalid image ID for {reference}")
        return image_id

    def tag_image(self, source_image_id: str, target_reference: str) -> None:
        result = self._run(["image", "tag", source_image_id, target_reference])
        if result.returncode != 0:
            raise PreserveError(f"Docker failed to create rollback tag {target_reference}")

    def prove_key_rotator_dependency_gate(
        self,
        project: str,
        identifier: str,
        container: dict[str, Any],
    ) -> bool:
        """Prove the sole accepted unhealthy source is blocked by sealed Vault.

        Older deployments used strict ``/readyz`` as Docker health for the
        rotator, so an intentionally sealed Vault made a sound running image
        impossible to preserve before an upgrade.  This migration exception
        accepts only that exact historical probe, proves rotator liveness and
        expected unready status from inside the container, then independently
        proves the one Compose-owned Vault is either fresh or sealed.  No
        caller-controlled command, service, URL, or status is accepted.
        """

        config = container.get("Config")
        healthcheck = config.get("Healthcheck") if isinstance(config, dict) else None
        if (
            not isinstance(healthcheck, dict)
            or healthcheck.get("Test") != KEY_ROTATOR_READINESS_HEALTHCHECK
        ):
            return False
        rotator_probe = self._run(
            [
                "container",
                "exec",
                identifier,
                "python3",
                "-c",
                KEY_ROTATOR_DEPENDENCY_PROBE,
            ]
        )
        if rotator_probe.returncode != 0 or rotator_probe.stdout.strip():
            return False

        vault_identifiers = self.list_service_containers(project, VAULT_SERVICE)
        if len(vault_identifiers) != 1:
            return False
        vault_id = vault_identifiers[0]
        vault = self.inspect_container(vault_id)
        vault_config = vault.get("Config")
        vault_labels = (
            vault_config.get("Labels") if isinstance(vault_config, dict) else None
        )
        vault_state = vault.get("State")
        if (
            vault.get("Id") != vault_id
            or not isinstance(vault_labels, dict)
            or vault_labels.get("com.docker.compose.project") != project
            or vault_labels.get("com.docker.compose.service") != VAULT_SERVICE
            or vault_labels.get("com.docker.compose.oneoff") != "False"
            or vault_labels.get("com.docker.compose.container-number") != "1"
            or not isinstance(vault_state, dict)
            or vault_state.get("Running") is not True
            or vault_state.get("Status") != "running"
            or vault_state.get("Restarting") is True
            or vault_state.get("Dead") is True
        ):
            return False
        status = self._run(
            [
                "container",
                "exec",
                vault_id,
                "vault",
                "status",
                "-address=http://127.0.0.1:8200",
                "-format=json",
            ]
        )
        if status.returncode not in (0, 2) or len(status.stdout) > 64 * 1024:
            return False
        try:
            document = json.loads(status.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False
        if not isinstance(document, dict):
            return False
        initialized = document.get("initialized")
        sealed = document.get("sealed")
        return (
            isinstance(initialized, bool)
            and isinstance(sealed, bool)
            and (not initialized or sealed)
        )


def _validate_state_directory(stack: Path) -> Path:
    if not stack.is_absolute():
        raise PreserveError("stack path must be absolute")
    try:
        stack_metadata = stack.lstat()
    except FileNotFoundError as exc:
        raise PreserveError("stack path is missing") from exc
    if not stat.S_ISDIR(stack_metadata.st_mode) or stat.S_ISLNK(stack_metadata.st_mode):
        raise PreserveError("stack path must be a real directory")
    if (stack_metadata.st_uid, stack_metadata.st_gid) != (ROOT_UID, ROOT_GID):
        raise PreserveError("stack path must be owned by root:root")
    if _mode(stack_metadata) != 0o750:
        raise PreserveError("stack path mode must be 0750")

    state_dir = stack / ".state"
    try:
        metadata = state_dir.lstat()
    except FileNotFoundError as exc:
        raise PreserveError("private deployment-state directory is missing") from exc
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise PreserveError("deployment-state path must be a real directory")
    if (metadata.st_uid, metadata.st_gid) != (ROOT_UID, ROOT_GID):
        raise PreserveError("deployment-state directory must be owned by root:root")
    if _mode(metadata) != STATE_DIR_MODE:
        raise PreserveError("deployment-state directory mode must be 0700")
    return state_dir


def _validate_existing_manifest(path: Path) -> os.stat_result | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        raise PreserveError("existing rollback manifest must be a single-link regular file")
    if (metadata.st_uid, metadata.st_gid) != (ROOT_UID, ROOT_GID):
        raise PreserveError("existing rollback manifest must be owned by root:root")
    if _mode(metadata) != MANIFEST_MODE:
        raise PreserveError("existing rollback manifest mode must be 0600")
    if metadata.st_size > MAX_MANIFEST_BYTES:
        raise PreserveError("existing rollback manifest exceeds the 4 MiB bound")
    return metadata


def _validate_existing_build_inputs(path: Path) -> os.stat_result | None:
    """Validate the successful-build receipt inode before it is trusted."""
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        raise PreserveError(
            "existing build-input receipt must be a single-link regular file"
        )
    if (metadata.st_uid, metadata.st_gid) != (ROOT_UID, ROOT_GID):
        raise PreserveError("existing build-input receipt must be owned by root:root")
    if _mode(metadata) != MANIFEST_MODE:
        raise PreserveError("existing build-input receipt mode must be 0600")
    if metadata.st_size > MAX_MANIFEST_BYTES:
        raise PreserveError("existing build-input receipt exceeds the 4 MiB bound")
    return metadata


def _validated_manifest_record(
    service: str, raw_record: object, project: str
) -> dict[str, object]:
    if SERVICE_RE.fullmatch(service) is None or not isinstance(raw_record, dict):
        raise PreserveError("existing rollback manifest contains an invalid service")
    required_keys = {
        "build_input_digest",
        "container_id",
        "desired_image",
        "planned_image_id",
        "rollback_image",
        "service",
        "source_image_id",
        "status",
    }
    if set(raw_record) != required_keys or raw_record.get("service") != service:
        raise PreserveError(f"existing rollback record shape is invalid: service={service}")

    digest = raw_record.get("build_input_digest")
    desired_image = raw_record.get("desired_image")
    planned_image_id = raw_record.get("planned_image_id")
    rollback_image = raw_record.get("rollback_image")
    container_id = raw_record.get("container_id")
    source_image_id = raw_record.get("source_image_id")
    status_value = raw_record.get("status")
    if not isinstance(digest, str) or DIGEST_RE.fullmatch(digest) is None:
        raise PreserveError(f"existing rollback digest is invalid: service={service}")
    if not isinstance(desired_image, str):
        raise PreserveError(f"existing desired image is invalid: service={service}")
    _validated_repository(desired_image)
    if planned_image_id is not None and (
        not isinstance(planned_image_id, str)
        or IMAGE_ID_RE.fullmatch(planned_image_id) is None
    ):
        raise PreserveError(f"existing planned image ID is invalid: service={service}")

    if status_value == "preserved":
        if (
            planned_image_id is None
            or not isinstance(source_image_id, str)
            or IMAGE_ID_RE.fullmatch(source_image_id) is None
            or not isinstance(container_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
        ):
            raise PreserveError(
                f"existing preserved rollback record is invalid: service={service}"
            )
        expected_rollback = rollback_reference(
            desired_image, project, service, source_image_id
        )
        if rollback_image != expected_rollback:
            raise PreserveError(
                f"existing rollback reference is invalid: service={service}"
            )
    elif status_value == "first-build":
        if any(value is not None for value in (rollback_image, container_id, source_image_id)):
            raise PreserveError(
                f"existing first-build rollback record is invalid: service={service}"
            )
    else:
        raise PreserveError(f"existing rollback status is invalid: service={service}")
    return dict(raw_record)


def _load_existing_manifest_with_presence(
    path: Path, project: str
) -> tuple[bool, dict[str, dict[str, object]]]:
    """Read the whole prior rollback inventory and retain its presence bit."""
    metadata = _validate_existing_manifest(path)
    if metadata is None:
        return False, {}

    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        opened = os.fstat(descriptor)
        if (
            (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
            or opened.st_nlink != 1
            or not stat.S_ISREG(opened.st_mode)
            or (opened.st_uid, opened.st_gid) != (ROOT_UID, ROOT_GID)
            or _mode(opened) != MANIFEST_MODE
            or opened.st_size > MAX_MANIFEST_BYTES
        ):
            raise PreserveError("rollback manifest changed while it was opened")
        payload = b""
        while len(payload) <= MAX_MANIFEST_BYTES:
            chunk = os.read(descriptor, min(65536, MAX_MANIFEST_BYTES + 1 - len(payload)))
            if not chunk:
                break
            payload += chunk
        if len(payload) > MAX_MANIFEST_BYTES:
            raise PreserveError("existing rollback manifest exceeds the 4 MiB bound")
    except OSError as exc:
        raise PreserveError(f"cannot safely read existing rollback manifest: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)

    try:
        decoded = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PreserveError("existing rollback manifest is not valid UTF-8 JSON") from exc
    if (
        not isinstance(decoded, dict)
        or set(decoded) != {"project", "schema", "services"}
        or decoded.get("schema") != ROLLBACK_SCHEMA
        or decoded.get("project") != project
        or not isinstance(decoded.get("services"), dict)
        or len(decoded["services"]) > MAX_SERVICES
    ):
        raise PreserveError("existing rollback manifest envelope is invalid")

    records: dict[str, dict[str, object]] = {}
    rollback_references: set[str] = set()
    for service, raw_record in decoded["services"].items():
        if not isinstance(service, str):
            raise PreserveError("existing rollback manifest service key is invalid")
        record = _validated_manifest_record(service, raw_record, project)
        if record["status"] == "preserved":
            rollback_image = str(record["rollback_image"])
            if rollback_image in rollback_references:
                raise PreserveError("existing rollback manifest reuses a rollback reference")
            rollback_references.add(rollback_image)
        records[service] = record
    return True, records


def _load_existing_manifest(path: Path, project: str) -> dict[str, dict[str, object]]:
    """Read and validate the whole prior per-service generation before mutation."""
    return _load_existing_manifest_with_presence(path, project)[1]


def _load_completed_build_inputs(
    path: Path, project: str
) -> tuple[bool, dict[str, dict[str, str | None]]]:
    """Read the root-only finalized build receipt used to close first deploy.

    The planner intentionally treats a missing or malformed prior input receipt
    as an empty hint so it can plan a repair. This preservation boundary is
    different: it must distinguish a clean first deploy from historical state,
    so any present receipt is a strict security input and is never repaired or
    treated as absent.
    """
    metadata = _validate_existing_build_inputs(path)
    if metadata is None:
        return False, {}

    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        opened = os.fstat(descriptor)
        if (
            (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
            or opened.st_nlink != 1
            or not stat.S_ISREG(opened.st_mode)
            or (opened.st_uid, opened.st_gid) != (ROOT_UID, ROOT_GID)
            or _mode(opened) != MANIFEST_MODE
            or opened.st_size > MAX_MANIFEST_BYTES
        ):
            raise PreserveError("build-input receipt changed while it was opened")
        payload = b""
        while len(payload) <= MAX_MANIFEST_BYTES:
            chunk = os.read(
                descriptor, min(65536, MAX_MANIFEST_BYTES + 1 - len(payload))
            )
            if not chunk:
                break
            payload += chunk
        if len(payload) > MAX_MANIFEST_BYTES:
            raise PreserveError("existing build-input receipt exceeds the 4 MiB bound")
    except OSError as exc:
        raise PreserveError(
            f"cannot safely read existing build-input receipt: {exc}"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)

    try:
        decoded = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PreserveError(
            "existing build-input receipt is not valid UTF-8 JSON"
        ) from exc
    if (
        not isinstance(decoded, dict)
        or set(decoded) != {"schema", "services"}
        or decoded.get("schema") != BUILD_INPUTS_SCHEMA
        or not isinstance(decoded.get("services"), dict)
        or len(decoded["services"]) > MAX_SERVICES
    ):
        raise PreserveError("existing build-input receipt envelope is invalid")

    if not decoded["services"]:
        return True, {}

    try:
        records = validate_plan(
            {
                "manifest": decoded,
                "services": sorted(decoded["services"]),
            },
            project,
        )
    except PreserveError as exc:
        raise PreserveError(
            f"existing build-input receipt records are invalid: {exc}"
        ) from exc
    completed: dict[str, dict[str, str | None]] = {}
    for record in records:
        if record["planned_image_id"] is None:
            raise PreserveError(
                "existing build-input receipt contains a missing image ID"
            )
        completed[str(record["service"])] = record
    return True, completed


def _require_recorded_rollback_tags(
    docker: Any, records: dict[str, dict[str, object]]
) -> None:
    for service, record in records.items():
        if record["status"] == "preserved":
            rollback_image = str(record["rollback_image"])
            if docker.inspect_image(rollback_image) != record["source_image_id"]:
                raise PreserveError(
                    f"existing rollback tag no longer matches service={service}"
                )


def _atomic_manifest_write(
    path: Path,
    manifest: dict[str, object],
    *,
    project: str,
    expected_existing: dict[str, dict[str, object]],
) -> None:
    if _load_existing_manifest(path, project) != expected_existing:
        raise PreserveError("rollback manifest changed during preservation")
    payload = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(payload) > MAX_MANIFEST_BYTES:
        raise PreserveError("rollback manifest exceeds the 4 MiB bound")
    temporary_name: str | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
        )
        with os.fdopen(descriptor, "wb") as output:
            os.fchmod(output.fileno(), MANIFEST_MODE)
            os.fchown(output.fileno(), ROOT_UID, ROOT_GID)
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_name, path)
        temporary_name = None
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        written = _load_existing_manifest(path, project)
        if written != manifest["services"]:
            raise PreserveError("persisted rollback manifest verification failed")
    except OSError as exc:
        raise PreserveError(f"cannot persist rollback manifest: {exc}") from exc
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def _container_image(
    docker: Any,
    record: dict[str, str | None],
    project: str,
    identifier: str,
) -> str:
    service = str(record["service"])
    desired_image = str(record["desired_image"])
    container = docker.inspect_container(identifier)
    if container.get("Id") != identifier:
        raise PreserveError(f"container inspection ID mismatch for service={service}")
    labels = (container.get("Config") or {}).get("Labels")
    state = container.get("State")
    if not isinstance(labels, dict) or not isinstance(state, dict):
        raise PreserveError(f"container inspection is incomplete for service={service}")
    if (
        labels.get("com.docker.compose.project") != project
        or labels.get("com.docker.compose.service") != service
        or labels.get("com.docker.compose.oneoff") != "False"
        or labels.get("com.docker.compose.container-number") != "1"
    ):
        raise PreserveError(f"container labels violate single-replica service={service}")
    if (container.get("Config") or {}).get("Image") != desired_image:
        raise PreserveError(f"container image reference drifted for service={service}")
    if (
        state.get("Running") is not True
        or state.get("Status") != "running"
        or state.get("Restarting") is True
        or state.get("Dead") is True
    ):
        raise PreserveError(f"service={service} container is not stably running")
    restart_count = container.get("RestartCount")
    if (
        isinstance(restart_count, bool)
        or not isinstance(restart_count, int)
        or restart_count != 0
    ):
        raise PreserveError(f"service={service} container has restarted")
    health = state.get("Health")
    healthy = isinstance(health, dict) and health.get("Status") == "healthy"
    dependency_gated = (
        service == KEY_ROTATOR_SERVICE
        and isinstance(health, dict)
        and health.get("Status") == "unhealthy"
        and docker.prove_key_rotator_dependency_gate(
            project, identifier, container
        )
    )
    if not healthy and not dependency_gated:
        raise PreserveError(f"service={service} container is not healthy")
    image_id = container.get("Image")
    if not isinstance(image_id, str) or IMAGE_ID_RE.fullmatch(image_id) is None:
        raise PreserveError(f"container has invalid immutable image ID for service={service}")
    return image_id


def preserve_rollbacks(
    raw_plan: object,
    *,
    stack: Path,
    project: str,
    docker: Any,
) -> dict[str, object]:
    """Pin all running pre-build images, then persist the verified manifest."""
    planned = validate_plan(raw_plan, project)
    state_dir = _validate_state_directory(stack)
    manifest_path = state_dir / MANIFEST_NAME
    build_inputs_path = state_dir / BUILD_INPUTS_NAME
    # This validates the destination inode and every retained record before a
    # Docker tag is created. An unsafe or malformed prior file is never repaired
    # by overwriting it as a side effect of an image mutation.
    rollback_manifest_exists, existing_records = _load_existing_manifest_with_presence(
        manifest_path, project
    )
    (
        completed_build_inputs_exist,
        completed_builds,
    ) = _load_completed_build_inputs(build_inputs_path, project)
    docker.ensure_ready()

    # The file is an inventory of one generation per service, not merely the
    # subset selected by this invocation's build plan. Prove every retained
    # mapping before creating any new content-addressed tag.
    _require_recorded_rollback_tags(docker, existing_records)

    preserved: list[dict[str, object]] = []
    for record in planned:
        service = str(record["service"])
        desired_image = str(record["desired_image"])
        planned_id = record["planned_image_id"]
        existing_record = existing_records.get(service)
        identifiers = docker.list_service_containers(project, service)
        if len(identifiers) > 1:
            raise PreserveError(
                f"service={service} has multiple containers; single-host rollback is ambiguous"
            )
        if not identifiers:
            desired_id = docker.inspect_image(desired_image, allow_missing=True)
            # A committed first-build record proves that this service had no
            # prior runtime generation before an earlier attempt. If that build
            # moved the desired tag and was interrupted before its build marker
            # or deployment, retrying remains safe: there is no old runtime
            # image to preserve.
            is_first_build_retry = (
                existing_record is not None
                and existing_record["status"] == "first-build"
                and existing_record["desired_image"] == desired_image
                and service not in completed_builds
            )
            if desired_id != planned_id:
                raise PreserveError(
                    f"service={service} desired tag no longer matches its build plan"
                )
            # Offline clean deploys seed reviewed custom images before the
            # first Compose build. An exact planned tag alone is not proof of
            # an old runtime generation in that narrow state. Once a completed
            # receipt exists, only a newly introduced service omitted from that
            # receipt can begin its first build. If the receipt is absent, an
            # existing rollback manifest (even empty) proves this is not a
            # clean deployment unless its explicit first-build retry record
            # above still authorizes the retry.
            may_begin_first_build = (
                existing_record is None
                and (
                    (
                        not completed_build_inputs_exist
                        and not rollback_manifest_exists
                    )
                    or (
                        completed_build_inputs_exist
                        and service not in completed_builds
                    )
                )
            )
            if not is_first_build_retry and not may_begin_first_build:
                raise PreserveError(
                    f"service={service} has image state but no authoritative container"
                )
            preserved.append(
                {
                    **record,
                    "status": "first-build",
                    "container_id": None,
                    "source_image_id": None,
                    "rollback_image": None,
                }
            )
            continue

        identifier = identifiers[0]
        source_image_id = _container_image(
            docker, record, project, identifier
        )
        desired_id = docker.inspect_image(desired_image)
        if desired_id != planned_id:
            raise PreserveError(
                f"service={service} desired tag no longer matches its build plan"
            )
        if docker.inspect_image(source_image_id) != source_image_id:
            raise PreserveError(f"running image is not inspectable for service={service}")
        rollback_image = rollback_reference(
            desired_image, project, service, source_image_id
        )
        # When a previous build moved the mutable desired tag but Ansible was
        # interrupted before recording/deploying it, the committed manifest and
        # content tag still protect the authoritative running image. Accept only
        # that exact proof; arbitrary desired/running drift remains fail-closed.
        if desired_id != source_image_id and not (
            existing_record is not None
            and existing_record["status"] == "preserved"
            and existing_record["desired_image"] == desired_image
            and existing_record["source_image_id"] == source_image_id
            and existing_record["rollback_image"] == rollback_image
        ):
            raise PreserveError(
                f"service={service} has unpreserved desired/running image drift"
            )
        preserved.append(
            {
                **record,
                "status": "preserved",
                "container_id": identifier,
                "source_image_id": source_image_id,
                "rollback_image": rollback_image,
            }
        )

    # Validate the complete next manifest and its reference uniqueness before
    # creating even a content-addressed tag. Retained single-service generations
    # remain present when another service is planned.
    merged_records = dict(existing_records)
    merged_records.update(
        {str(record["service"]): record for record in preserved}
    )
    verified_records = {
        service: _validated_manifest_record(service, record, project)
        for service, record in sorted(merged_records.items())
    }
    rollback_references = [
        str(record["rollback_image"])
        for record in verified_records.values()
        if record["status"] == "preserved"
    ]
    if len(rollback_references) != len(set(rollback_references)):
        raise PreserveError("next rollback manifest reuses a rollback reference")

    # Validation above is deliberately complete before the first tag changes.
    for record in preserved:
        if record["status"] != "preserved":
            continue
        source_image_id = str(record["source_image_id"])
        rollback_image = str(record["rollback_image"])
        existing_rollback_id = docker.inspect_image(
            rollback_image, allow_missing=True
        )
        if existing_rollback_id is None:
            docker.tag_image(source_image_id, rollback_image)
        elif existing_rollback_id != source_image_id:
            raise PreserveError(
                f"content-addressed rollback tag collision for service={record['service']}"
            )
        if docker.inspect_image(rollback_image) != source_image_id:
            raise PreserveError(
                f"rollback tag verification failed for service={record['service']}"
            )

    # Close the inspect/tag race before blessing the rollback manifest.
    for record in preserved:
        service = str(record["service"])
        identifiers = docker.list_service_containers(project, service)
        if record["status"] == "first-build":
            if (
                identifiers
                or docker.inspect_image(
                    str(record["desired_image"]), allow_missing=True
                )
                != record["planned_image_id"]
            ):
                raise PreserveError(
                    f"service={service} changed during first-build preservation"
                )
            continue
        if identifiers != [record["container_id"]]:
            raise PreserveError(f"service={service} container changed during preservation")
        if _container_image(
            docker, record, project, str(record["container_id"])
        ) != record["source_image_id"]:
            raise PreserveError(f"service={service} image changed during preservation")
        if (
            docker.inspect_image(str(record["desired_image"]))
            != record["planned_image_id"]
            or docker.inspect_image(str(record["rollback_image"]))
            != record["source_image_id"]
        ):
            raise PreserveError(
                f"service={service} desired or rollback tag changed during preservation"
            )

    planned_services = {str(record["service"]) for record in preserved}
    retained_records = {
        service: record
        for service, record in existing_records.items()
        if service not in planned_services
    }
    _require_recorded_rollback_tags(docker, retained_records)
    manifest: dict[str, object] = {
        "schema": ROLLBACK_SCHEMA,
        "project": project,
        "services": verified_records,
    }
    _atomic_manifest_write(
        manifest_path,
        manifest,
        project=project,
        expected_existing=existing_records,
    )
    # Keep the persistent file a strict inventory while making the exact
    # invocation delta explicit to Ansible. The full services map can contain
    # retained generations from earlier one-service builds.
    return {
        **manifest,
        "updated_services": sorted(str(record["service"]) for record in preserved),
    }


def retire_first_build_records(
    successful_build_manifest: object,
    *,
    stack: Path,
    project: str,
) -> dict[str, object]:
    """Retire no-prior-generation proofs after their build marker commits.

    A first-build record is needed only while a build can be retried before the
    successful build-input marker is durable. Leaving that proof indefinitely
    would be unsafe: a later missing container could be mistaken for the same
    initial attempt after the service had already run. The finalized manifest
    contains every custom image and its post-build immutable ID, so it is the
    exact bounded evidence that the retry window has closed.
    """
    if not isinstance(successful_build_manifest, dict):
        raise PreserveError("successful build manifest must be an object")
    services = successful_build_manifest.get("services")
    if not isinstance(services, dict):
        raise PreserveError("successful build manifest has no services object")
    successful_records = validate_plan(
        {
            "manifest": successful_build_manifest,
            "services": sorted(services),
        },
        project,
    )
    successful_by_service = {
        str(record["service"]): record for record in successful_records
    }
    if any(
        record["planned_image_id"] is None
        for record in successful_by_service.values()
    ):
        raise PreserveError("successful build manifest contains a missing image ID")

    state_dir = _validate_state_directory(stack)
    manifest_path = state_dir / MANIFEST_NAME
    existing_records = _load_existing_manifest(manifest_path, project)
    retired: list[str] = []
    retained: dict[str, dict[str, object]] = {}
    for service, record in existing_records.items():
        if record["status"] != "first-build":
            retained[service] = record
            continue
        successful = successful_by_service.get(service)
        if (
            successful is None
            or successful["desired_image"] != record["desired_image"]
        ):
            raise PreserveError(
                f"successful build manifest does not match first-build service={service}"
            )
        retired.append(service)

    manifest: dict[str, object] = {
        "schema": ROLLBACK_SCHEMA,
        "project": project,
        "services": dict(sorted(retained.items())),
    }
    if retired:
        _atomic_manifest_write(
            manifest_path,
            manifest,
            project=project,
            expected_existing=existing_records,
        )
    return {
        **manifest,
        "retired_services": sorted(retired),
    }


def _read_plan() -> object:
    payload = sys.stdin.buffer.read(MAX_PLAN_BYTES + 1)
    if len(payload) > MAX_PLAN_BYTES:
        raise PreserveError("build plan exceeds the 4 MiB input bound")
    try:
        return json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PreserveError("build plan is not valid UTF-8 JSON") from exc


def main() -> None:
    if os.geteuid() != ROOT_UID:
        raise SystemExit("rollback preservation must run as root")
    try:
        if len(sys.argv) == 4 and sys.argv[1] == "--retire-first-builds":
            result = retire_first_build_records(
                _read_plan(),
                stack=Path(sys.argv[2]),
                project=sys.argv[3],
            )
        elif len(sys.argv) == 3:
            executable = shutil.which("docker", path=FIXED_PATH)
            if executable is None:
                raise PreserveError("Docker CLI is unavailable in the fixed system PATH")
            result = preserve_rollbacks(
                _read_plan(),
                stack=Path(sys.argv[1]),
                project=sys.argv[2],
                docker=DockerClient(executable),
            )
        else:
            raise PreserveError(
                f"usage: {Path(sys.argv[0]).name} "
                "[--retire-first-builds] STACK_DIR PROJECT"
            )
    except PreserveError as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
