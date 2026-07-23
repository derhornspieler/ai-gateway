#!/usr/bin/env python3
"""Build, test, deploy, validate, and safely roll back image releases.

This is a controller-side operator tool. It has three commands:

  prepare       Pull every exact pin, build every custom image, and write a
                schema-v2 offline release. It can also test that exact release
                in local Ansible preprod.
  test-preprod  With --load-archive, clean local preprod, load an existing
                schema-v2 release, and run its Ansible acceptance test. Without
                that flag, run only a quick development check of loaded images.
  upgrade       Stage a candidate release on a Rocky host, take an encrypted
                state backup, deploy with Ansible, run the external acceptance
                gate, and automatically restore the prior release on failure.

Remote upgrades are always treated as stateful. A binary-only rollback is not
accepted because Keycloak, PostgreSQL, and other services can change data on
disk. The upgrade command therefore requires all of these before it mutates the
running stack:

* a fresh encrypted state backup destination and age recipient;
* the matching age identity on independent, root-only recovery storage;
* a clean checkout of the previous reviewed source;
* the previous schema-v2 offline release, loaded and checked on the target.

PostgreSQL major changes are refused. They need a separate migration plan.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import datetime as dt
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any
import uuid


ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts/rebuild-offline-image-seed.py"
LOADER_REMOTE = "/usr/local/sbin/aigw-load-offline-image-seed"
STACK_REMOTE = "/opt/ai-gateway"
REMOTE_MARKER_DIR = "/opt/ai-gateway/.state/offline-image-seeds"
REMOTE_SEED_ROOT = "/var/lib/ai-gateway/image-seeds"
REMOTE_RECOVERY_IDENTITY = "/run/ai-gateway-image-update/rollback.agekey"
PREPROD_INVENTORY = ROOT / "ansible/inventory/preprod.yml"
PREPROD_PLAYBOOK = ROOT / "ansible/preprod.yml"
PREPROD_CLEAN_ROOM_PLAYBOOK = ROOT / "ansible/preprod-clean-room.yml"
STAGE_PLAYBOOK = ROOT / "ansible/stage-offline-image-seed.yml"
RECOVERY_IDENTITY_PLAYBOOK = ROOT / "ansible/manage-update-recovery-identity.yml"
LIFECYCLE_AUDIT_PLAYBOOK = ROOT / "ansible/record-controller-lifecycle.yml"
PREPROD_SEED_STAGE_PLAYBOOK = ROOT / "ansible/stage-preprod-image-seed.yml"
DEPLOY_PLAYBOOK = ROOT / "ansible/deploy-stack-only.yml"
EXTERNAL_E2E = ROOT / "scripts/e2e-fresh-vm-check.sh"

HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
SAFE_ALIAS = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
SAFE_REMOTE_PATH = re.compile(r"^/[A-Za-z0-9._/-]+$")
SAFE_SSH_TARGET = re.compile(
    r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}@"
    r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$"
)
SAFE_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
AGE_RECIPIENT = re.compile(r"^age1[0-9a-z]{58}$")
IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
PIN = re.compile(
    r"^(?!ai-gateway/)(?:[a-z0-9]+(?:[._-]+[a-z0-9]+)*/)*"
    r"[a-z0-9]+(?:[._-]+[a-z0-9]+)*:"
    r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}@sha256:[0-9a-f]{64}$"
)
RELEASE_SCOPE_PRODUCTION = "production"
RELEASE_SCOPE_PREPROD = "preprod"
RELEASE_SCOPES = {RELEASE_SCOPE_PRODUCTION, RELEASE_SCOPE_PREPROD}
PREPROD_IMAGE_BY_SERVICE = {
    "samba-ad": "ai-gateway/samba-ad:preprod",
    "wif-provider-mock": "ai-gateway/wif-provider-mock:preprod",
}
PREPROD_CLEAN_ROOM_CONFIRMATION = "DESTROY_AIGW_PREPROD_RELEASE_IMAGES"


class WorkflowError(RuntimeError):
    """A release gate failed."""


@dataclass(frozen=True)
class Release:
    archive: Path
    manifest: Path
    archive_sha256: str
    manifest_sha256: str
    platform: str
    document: dict[str, Any]


@dataclass(frozen=True)
class RemoteRelease:
    archive: str
    manifest: str
    archive_sha256: str
    manifest_sha256: str


@dataclass(frozen=True)
class BackupReceipt:
    path: str
    sha256: str
    created_at: str


def fail(message: str) -> None:
    raise WorkflowError(message)


def failure_summary(error: BaseException) -> str:
    """Return one bounded line for operator-facing rollback errors."""

    message = " ".join(str(error).split())
    if len(message) > 500:
        message = message[:497] + "..."
    if isinstance(error, WorkflowError):
        return message or "workflow error"
    name = type(error).__name__
    return f"{name}: {message}" if message else name


def safe_remote_path(value: str, label: str) -> PurePosixPath:
    """Accept one canonical absolute path with no broad or magic components."""

    if (
        SAFE_REMOTE_PATH.fullmatch(value) is None
        or value == "/"
        or "//" in value
        or value.endswith("/")
    ):
        fail(f"{label} must be one canonical absolute remote path")
    path = PurePosixPath(value)
    if str(path) != value or any(part in {"", ".", ".."} for part in path.parts[1:]):
        fail(f"{label} contains an empty, dot, or traversal component")
    return path


def require_strict_descendant(value: str, root: str, label: str) -> PurePosixPath:
    path = safe_remote_path(value, label)
    boundary = safe_remote_path(root, f"{label} boundary")
    try:
        relative = path.relative_to(boundary)
    except ValueError as exc:
        raise WorkflowError(f"{label} must stay below {boundary}") from exc
    if str(relative) in {"", "."}:
        fail(f"{label} must name a file or child below {boundary}")
    return path


def command_error(label: str, result: subprocess.CompletedProcess[str]) -> WorkflowError:
    detail = (result.stderr or result.stdout or "").strip().splitlines()
    suffix = f": {detail[-1][:500]}" if detail else ""
    return WorkflowError(f"{label} failed with exit code {result.returncode}{suffix}")


def run_checked(
    command: list[str],
    *,
    cwd: Path = ROOT,
    capture: bool = False,
    interactive: bool = False,
    label: str,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            text=True,
            stdin=None if interactive else subprocess.DEVNULL,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            check=False,
        )
    except OSError as exc:
        raise WorkflowError(f"{label} could not start: {exc}") from exc
    if result.returncode != 0:
        raise command_error(label, result)
    return result


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise WorkflowError(f"cannot hash {path}: {exc}") from exc
    return digest.hexdigest()


def require_caller_owned_parent(path: Path, label: str) -> None:
    """Reject any replaceable directory between a controller file and ``/``."""

    directory = path.parent
    if not directory.is_absolute() or ".." in directory.parts:
        fail(f"{label} parent path must be canonical and absolute")
    trusted_uids = {0, os.geteuid()}
    cursor = directory
    while True:
        try:
            metadata = cursor.lstat()
        except FileNotFoundError as exc:
            raise WorkflowError(
                f"{label} directory lineage does not exist: {cursor}"
            ) from exc
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            fail(
                f"{label} directory lineage must contain only real directories, "
                f"not a symlink: {cursor}"
            )
        if metadata.st_uid not in trusted_uids:
            fail(
                f"{label} directory lineage has an untrusted owner: {cursor}"
                " (fix: move the release files into a directory you own,"
                " such as a folder in your home directory)"
            )
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            root_sticky = metadata.st_uid == 0 and bool(
                metadata.st_mode & stat.S_ISVTX
            )
            if not root_sticky:
                fail(
                    f"{label} directory lineage is group/other writable without "
                    f"a root-owned sticky boundary: {cursor}"
                    f" (fix: chmod go-w {cursor}, or move the release files"
                    " to a private directory)"
                )
        if cursor == cursor.parent:
            return
        cursor = cursor.parent


def require_local_file(path: Path, suffix: str, label: str, maximum: int | None = None) -> Path:
    if not path.is_absolute() or not str(path).endswith(suffix):
        fail(f"{label} must be an absolute path ending in {suffix}")
    require_caller_owned_parent(path, label)
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise WorkflowError(f"{label} does not exist: {path}") from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail(f"{label} must be a regular file, not a symlink")
    if metadata.st_uid != os.geteuid():
        fail(
            f"{label} must be owned by the user running this command"
            f" (fix: sudo chown \"$(id -un)\" {path})"
        )
    # Integrity comes from the SHA-256 checks; the mode only has to stop other
    # users from rewriting the file. Read bits on a release artifact are safe,
    # so a normal copied file (0644) is accepted as-is.
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        fail(
            f"{label} must not be group- or world-writable"
            f" (fix: chmod go-w {path})"
        )
    if metadata.st_size < 1:
        fail(f"{label} must not be empty")
    if maximum is not None and metadata.st_size > maximum:
        fail(f"{label} is larger than {maximum} bytes")
    if SAFE_NAME.fullmatch(path.name) is None:
        fail(f"{label} has an unsafe filename")
    resolved = path.resolve()
    try:
        resolved_metadata = resolved.lstat()
    except FileNotFoundError as exc:
        raise WorkflowError(f"{label} changed while it was being checked: {path}") from exc
    if (metadata.st_dev, metadata.st_ino) != (
        resolved_metadata.st_dev,
        resolved_metadata.st_ino,
    ):
        fail(f"{label} changed while it was being checked")
    return resolved


def require_release_scope(release: Release, expected_scope: str) -> None:
    """Fail before transfer when a release crosses its deployment boundary."""

    if expected_scope not in RELEASE_SCOPES:
        fail(f"unsupported release scope: {expected_scope}")
    actual_scope = release.document.get("release_scope")
    if actual_scope != expected_scope:
        fail(
            f"this workflow requires a {expected_scope}-scoped image release; "
            f"got {actual_scope!r}"
        )
    custom = release.document.get("custom_images")
    build_inputs = release.document.get("build_inputs")
    if not isinstance(custom, list) or not isinstance(build_inputs, dict):
        fail("release manifest lacks its custom image boundary")
    services = build_inputs.get("services")
    if not isinstance(services, dict):
        fail("release manifest lacks its custom build-input services")

    custom_by_name: dict[str, dict[str, object]] = {}
    for record in custom:
        if not isinstance(record, dict) or not isinstance(record.get("image"), str):
            fail("release manifest contains an invalid custom image record")
        custom_by_name[record["image"]] = record
    if len(custom_by_name) != len(custom):
        fail("release manifest contains duplicate custom image records")

    preprod_names = set(PREPROD_IMAGE_BY_SERVICE.values())
    if expected_scope == RELEASE_SCOPE_PRODUCTION:
        if preprod_names.intersection(custom_by_name) or set(
            PREPROD_IMAGE_BY_SERVICE
        ).intersection(services):
            fail("production release contains preproduction-only images or build inputs")
        if any(
            record.get("deployment_scope") != "production"
            or record.get("target_activation") != "active-compose"
            for record in custom
        ):
            fail("production release contains archive-only or preproduction image data")
        return

    if not preprod_names.issubset(custom_by_name):
        fail("preprod release omits the Samba AD or WIF mock image")
    for service, image in PREPROD_IMAGE_BY_SERVICE.items():
        record = custom_by_name[image]
        service_record = services.get(service)
        if (
            record.get("deployment_scope") != "preprod-only"
            or record.get("target_activation") != "archive-only"
            or not isinstance(service_record, dict)
            or service_record.get("image") != image
        ):
            fail("preprod release contains an invalid preproduction image boundary")


def read_release(
    archive: Path,
    manifest: Path,
    *,
    required_scope: str = RELEASE_SCOPE_PRODUCTION,
) -> Release:
    archive = require_local_file(archive, ".docker.tar.zst", "release archive")
    manifest = require_local_file(
        manifest, ".manifest.json", "release manifest", 1024 * 1024
    )
    if archive.parent != manifest.parent:
        fail("release archive and manifest must be in the same directory")
    try:
        document = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise WorkflowError("release manifest is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict) or document.get("schema_version") != 2:
        fail("this workflow requires a schema-v2 offline image release")
    if document.get("bundle") != archive.name:
        fail("release manifest bundle does not match the archive filename")
    platform = document.get("platform")
    if platform not in {"linux/amd64", "linux/arm64"}:
        fail("release platform must be linux/amd64 or linux/arm64")
    images = document.get("images")
    custom_images = document.get("custom_images")
    build_inputs = document.get("build_inputs")
    if not isinstance(images, list) or not images:
        fail("release manifest has no external images")
    if not isinstance(custom_images, list) or not custom_images:
        fail("release manifest has no custom images")
    if not isinstance(build_inputs, dict):
        fail("release manifest has no custom build-input receipt")
    for image in images:
        if (
            not isinstance(image, dict)
            or set(image) != {"reference", "image_id"}
            or not isinstance(image.get("reference"), str)
            or PIN.fullmatch(image["reference"]) is None
            or not isinstance(image.get("image_id"), str)
            or IMAGE_ID.fullmatch(image["image_id"]) is None
        ):
            fail("release manifest contains an invalid external image record")
    release = Release(
        archive=archive,
        manifest=manifest,
        archive_sha256=sha256_file(archive),
        manifest_sha256=sha256_file(manifest),
        platform=platform,
        document=document,
    )
    require_release_scope(release, required_scope)
    loader = load_loader_module(ROOT)
    try:
        loader.validate_manifest_document(document, archive, platform)
    except (OSError, loader.SeedError) as exc:
        raise WorkflowError(f"release manifest contract is invalid: {exc}") from exc
    return release


def load_builder_module(root: Path):
    path = root / "scripts/rebuild-offline-image-seed.py"
    token = hashlib.sha256(str(root).encode("utf-8")).hexdigest()[:16]
    spec = importlib.util.spec_from_file_location(
        f"_aigw_release_builder_{token}", path
    )
    if spec is None or spec.loader is None:
        fail(f"cannot load the image builder from {root}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_loader_module(root: Path):
    path = root / "scripts/load-offline-image-seed.py"
    token = hashlib.sha256(str(root).encode("utf-8")).hexdigest()[:16]
    spec = importlib.util.spec_from_file_location(
        f"_aigw_release_loader_{token}", path
    )
    if spec is None or spec.loader is None:
        fail(f"cannot load the image loader from {root}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def validate_release_archive_allowlist(release: Release) -> None:
    """Prove archive tags/descriptors match the manifest before any copy."""

    if sha256_file(release.archive) != release.archive_sha256:
        fail("release archive changed after it was selected")
    if sha256_file(release.manifest) != release.manifest_sha256:
        fail("release manifest changed after it was selected")
    zstd = shutil.which("zstd")
    if zstd is None:
        fail("zstd is required to prove the release archive allow-list")
    loader = load_loader_module(ROOT)
    try:
        document = loader.validate_manifest_document(
            release.document, release.archive, release.platform
        )
        loader.validate_archive_document_allowlist(release.archive, zstd, document)
    except (OSError, loader.SeedError) as exc:
        raise WorkflowError(f"release archive allow-list is invalid: {exc}") from exc


def validate_release_source_pins(release: Release, root: Path) -> None:
    require_release_scope(
        release,
        str(release.document.get("release_scope")),
    )
    builder = load_builder_module(root)
    try:
        expected = builder.collect_project_image_reference_scopes(root)[
            release.document["release_scope"]
        ]
    except (OSError, builder.SeedBuildError) as exc:
        raise WorkflowError(f"cannot collect release pins from {root}: {exc}") from exc
    actual = {record["reference"] for record in release.document["images"]}
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        fail(
            "offline release does not match the source pins; "
            f"missing={missing[:3]} extra={extra[:3]}"
        )

    docker = shutil.which("docker")
    if docker is None:
        fail("Docker CLI is required to verify release build inputs against source")
    environment = dict(os.environ)
    environment.pop("COMPOSE_FILE", None)
    environment.pop("COMPOSE_PROFILES", None)
    client = builder.DockerClient(docker, tuple(), environment)
    try:
        egress_plan = builder.egress_plan_from_release_receipt(
            release.document["egress_policy"]
        )
        model, _, _ = builder.render_deployable_compose_model(
            client, root, release.platform, egress_plan
        )
        if release.document["release_scope"] == RELEASE_SCOPE_PREPROD:
            builder.add_preprod_build_services(model, root)
    except (OSError, builder.SeedBuildError) as exc:
        raise WorkflowError(f"cannot render release source in {root}: {exc}") from exc
    custom = release.document["custom_images"]
    expected_ids = {
        record.get("image"): record.get("image_id")
        for record in custom
        if isinstance(record, dict)
    }

    def image_id(image: str) -> str:
        value = expected_ids.get(image)
        if not isinstance(value, str) or IMAGE_ID.fullmatch(value) is None:
            raise builder.SeedBuildError(f"release has no image ID for {image}")
        return value

    planner = builder._load_build_planner(
        root,
        privileged=os.geteuid() == builder.ROOT_UID,
    )
    try:
        with tempfile.TemporaryDirectory(prefix="aigw-update-source-proof-") as temporary:
            plan = planner.plan_compose_builds(
                model,
                stack=root,
                state_path=Path(temporary) / "absent.json",
                project=builder.COMPOSE_PROJECT_NAME,
                image_inspector=image_id,
            )
    except (OSError, builder.SeedBuildError, planner.PlanError) as exc:
        raise WorkflowError(f"cannot prove release build inputs in {root}: {exc}") from exc
    if plan.get("manifest") != release.document["build_inputs"]:
        fail("offline release build inputs do not match the selected source checkout")


def write_extra_vars(values: dict[str, object]):
    class ExtraVarsFile:
        def __init__(self, document: dict[str, object]) -> None:
            descriptor, name = tempfile.mkstemp(prefix="aigw-ansible-vars-", suffix=".json")
            self.path = Path(name)
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(document, handle, sort_keys=True, separators=(",", ":"))
                handle.write("\n")

        def __enter__(self) -> Path:
            return self.path

        def __exit__(self, *_: object) -> None:
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass

    return ExtraVarsFile(values)


def ansible_command(
    *,
    root: Path,
    inventory: Path,
    playbook: Path,
    limit: str | None,
    vault_id: str | None,
    extra_vars: dict[str, object],
    ask_become_pass: bool = False,
    become_password_file: Path | None = None,
) -> None:
    if ask_become_pass and become_password_file is not None:
        fail("choose --ask-become-pass or --become-password-file, not both")
    with write_extra_vars(extra_vars) as variables:
        command = [
            "ansible-playbook",
            "-i",
            str(inventory),
            str(playbook),
        ]
        if limit is not None:
            command.extend(["--limit", limit])
        if vault_id is not None:
            command.extend(["--vault-id", vault_id])
        if ask_become_pass:
            command.append("--ask-become-pass")
        if become_password_file is not None:
            command.extend(["--become-password-file", str(become_password_file)])
        command.extend(["--extra-vars", f"@{variables}"])
        run_checked(
            command,
            cwd=root,
            interactive=ask_become_pass,
            label=f"Ansible playbook {playbook.name}",
        )


def preprod_staged_paths(release: Release) -> tuple[Path, Path, Path]:
    directory = Path("/var/tmp/ai-gateway-preprod-seeds") / release.manifest_sha256[:16]
    return directory, directory / release.archive.name, directory / release.manifest.name


def preprod_release_paths(
    archive: Path,
    manifest: Path,
    explicit_archive: Path | None,
    explicit_manifest: Path | None,
) -> tuple[Path, Path]:
    """Match the builder's deterministic sibling naming contract."""

    if (explicit_archive is None) != (explicit_manifest is None):
        fail("--preprod-archive and --preprod-manifest must be supplied together")
    if explicit_archive is not None and explicit_manifest is not None:
        return explicit_archive, explicit_manifest
    archive_suffix = ".docker.tar.zst"
    manifest_suffix = ".manifest.json"
    if not archive.name.endswith(archive_suffix) or not manifest.name.endswith(
        manifest_suffix
    ):
        fail("production release paths use an invalid suffix")
    return (
        archive.with_name(archive.name[: -len(archive_suffix)] + ".preprod" + archive_suffix),
        manifest.with_name(
            manifest.name[: -len(manifest_suffix)] + ".preprod" + manifest_suffix
        ),
    )


def stage_preprod_release(
    release: Release,
    *,
    state: str,
    ask_become_pass: bool,
    become_password_file: Path | None = None,
) -> tuple[Path, Path]:
    require_release_scope(release, RELEASE_SCOPE_PREPROD)
    if state == "present":
        validate_release_archive_allowlist(release)
    directory, archive, manifest = preprod_staged_paths(release)
    ansible_command(
        root=ROOT,
        inventory=PREPROD_INVENTORY,
        playbook=PREPROD_SEED_STAGE_PLAYBOOK,
        limit=None,
        vault_id=None,
        extra_vars={
            "preprod_seed_stage_state": state,
            "preprod_seed_stage_controller_archive": str(release.archive),
            "preprod_seed_stage_archive_sha256": release.archive_sha256,
            "preprod_seed_stage_controller_manifest": str(release.manifest),
            "preprod_seed_stage_manifest_sha256": release.manifest_sha256,
            "preprod_seed_stage_directory": str(directory),
            "preprod_seed_stage_archive": str(archive),
            "preprod_seed_stage_manifest": str(manifest),
        },
        ask_become_pass=ask_become_pass,
        become_password_file=become_password_file,
    )
    return archive, manifest


def clean_room_preprod_release(
    release: Release,
    *,
    ask_become_pass: bool,
    become_password_file: Path | None = None,
) -> None:
    """Remove only release-owned preprod state and prove seed images are absent."""

    require_release_scope(release, RELEASE_SCOPE_PREPROD)
    validate_release_archive_allowlist(release)
    ansible_command(
        root=ROOT,
        inventory=PREPROD_INVENTORY,
        playbook=PREPROD_CLEAN_ROOM_PLAYBOOK,
        limit=None,
        vault_id=None,
        extra_vars={
            "preprod_seed_archive": str(release.archive),
            "preprod_seed_archive_sha256": release.archive_sha256,
            "preprod_seed_manifest": str(release.manifest),
            "preprod_seed_manifest_sha256": release.manifest_sha256,
            "preprod_clean_room_confirmation": PREPROD_CLEAN_ROOM_CONFIRMATION,
        },
        ask_become_pass=ask_become_pass,
        become_password_file=become_password_file,
    )


def test_preprod(
    release: Release,
    *,
    load_archive: bool,
    ask_become_pass: bool,
    become_password_file: Path | None = None,
) -> None:
    require_release_scope(release, RELEASE_SCOPE_PREPROD)
    validate_release_source_pins(release, ROOT)
    loader_archive: Path | None = None
    loader_manifest: Path | None = None
    staged = False
    privileged_stage = load_archive and sys.platform != "darwin"
    if load_archive:
        # A release rehearsal starts from proved absence. If this cleanup
        # fails, no root staging directory is created and no deploy starts.
        clean_room_preprod_release(
            release,
            ask_become_pass=ask_become_pass,
            become_password_file=become_password_file,
        )
    if privileged_stage:
        loader_archive, loader_manifest = stage_preprod_release(
            release,
            state="present",
            ask_become_pass=ask_become_pass,
            become_password_file=become_password_file,
        )
        staged = True
    elif load_archive:
        # Docker Desktop's CLI and socket belong to the desktop user. Keep the
        # production loader root-only, and let the local preprod loader verify
        # and consume the caller-owned 0600 release directly.
        loader_archive, loader_manifest = release.archive, release.manifest
    values = {
        "preprod_image_mode": "seed",
        "preprod_build_images": False,
        "preprod_pull_images": False,
        # Root loads the staged copies. The normal operator then validates the
        # release receipt against the ordinary checkout and original files.
        "preprod_seed_archive": str(release.archive),
        "preprod_seed_archive_sha256": release.archive_sha256,
        "preprod_seed_manifest": str(release.manifest),
        "preprod_seed_manifest_sha256": release.manifest_sha256,
        "preprod_seed_load_archive": load_archive,
        # Clean-room mode must consume archive bytes. A stale loader marker or
        # surviving image would yield SKIPPED/RELOADED and fail the play.
        "preprod_seed_require_fresh_load": load_archive,
        "preprod_seed_loader_archive": str(loader_archive or ""),
        "preprod_seed_loader_manifest": str(loader_manifest or ""),
    }
    try:
        ansible_command(
            root=ROOT,
            inventory=PREPROD_INVENTORY,
            playbook=PREPROD_PLAYBOOK,
            limit=None,
            vault_id=None,
            extra_vars=values,
            ask_become_pass=ask_become_pass,
            become_password_file=become_password_file,
        )
    finally:
        if staged:
            stage_preprod_release(
                release,
                state="absent",
                ask_become_pass=ask_become_pass,
                become_password_file=become_password_file,
            )
    print("SEEDED_PREPROD_E2E_PASSED")


def cmd_prepare(args: argparse.Namespace) -> int:
    if not args.archive.is_absolute() or not args.manifest.is_absolute():
        fail("--archive and --manifest must be absolute paths")
    preprod_archive, preprod_manifest = preprod_release_paths(
        args.archive,
        args.manifest,
        args.preprod_archive,
        args.preprod_manifest,
    )
    if not preprod_archive.is_absolute() or not preprod_manifest.is_absolute():
        fail("--preprod-archive and --preprod-manifest must be absolute paths")
    if len(
        {args.archive, args.manifest, preprod_archive, preprod_manifest}
    ) != 4:
        fail("production and preprod release paths must be distinct")
    if (
        args.ask_become_pass or args.become_password_file is not None
    ) and not args.test_preprod:
        fail("--ask-become-pass and --become-password-file require --test-preprod")
    become_password_file = (
        normalize_become_password_file(args.become_password_file)
        if args.become_password_file is not None
        else None
    )
    command = [
        sys.executable,
        "-I",
        str(BUILDER),
        "--prepare-release",
        # Docker sometimes pulls a digest without restoring its ordinary tag.
        # This narrow option creates that tag only after digest verification.
        "--materialize-missing-source-tags",
        "--platform",
        args.platform,
    ]
    for provider in args.provider:
        command.extend(["--provider", provider])
    if os.geteuid() != 0:
        command.append("--allow-unprivileged-controller")
    if args.docker_context:
        command.extend(["--docker-context", args.docker_context])
    if args.docker_host:
        command.extend(["--docker-host", args.docker_host])
    command.extend(
        [
            "--preprod-archive",
            str(preprod_archive),
            "--preprod-manifest",
            str(preprod_manifest),
        ]
    )
    command.extend([str(args.archive), str(args.manifest)])
    run_checked(command, label="offline image release build")
    release = read_release(
        args.archive,
        args.manifest,
        required_scope=RELEASE_SCOPE_PRODUCTION,
    )
    preprod_release = read_release(
        preprod_archive,
        preprod_manifest,
        required_scope=RELEASE_SCOPE_PREPROD,
    )
    validate_release_source_pins(release, ROOT)
    validate_release_source_pins(preprod_release, ROOT)
    print(
        json.dumps(
            {
                "archive": str(release.archive),
                "archive_sha256": release.archive_sha256,
                "manifest": str(release.manifest),
                "manifest_sha256": release.manifest_sha256,
                "platform": release.platform,
                "release_scope": RELEASE_SCOPE_PRODUCTION,
                "schema_version": 2,
                "preprod_archive": str(preprod_release.archive),
                "preprod_archive_sha256": preprod_release.archive_sha256,
                "preprod_manifest": str(preprod_release.manifest),
                "preprod_manifest_sha256": preprod_release.manifest_sha256,
            },
            sort_keys=True,
        )
    )
    if args.test_preprod:
        test_preprod(
            preprod_release,
            load_archive=True,
            ask_become_pass=args.ask_become_pass,
            become_password_file=become_password_file,
        )
    return 0


def cmd_test_preprod(args: argparse.Namespace) -> int:
    release = read_release(
        args.archive,
        args.manifest,
        required_scope=RELEASE_SCOPE_PREPROD,
    )
    test_preprod(
        release,
        load_archive=args.load_archive,
        ask_become_pass=args.ask_become_pass,
        become_password_file=(
            normalize_become_password_file(args.become_password_file)
            if args.become_password_file is not None
            else None
        ),
    )
    return 0


def normalize_regular_controller_file(path: Path, label: str) -> Path:
    """Check the leaf before resolving it so a symlink cannot hide itself."""

    candidate = path.expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    require_caller_owned_parent(candidate, label)
    try:
        metadata = candidate.lstat()
    except FileNotFoundError as exc:
        raise WorkflowError(f"{label} does not exist: {candidate}") from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail(f"{label} must be a regular file, not a symlink: {candidate}")
    resolved = candidate.resolve()
    try:
        resolved_metadata = resolved.lstat()
    except FileNotFoundError as exc:
        raise WorkflowError(f"{label} changed while it was being checked: {candidate}") from exc
    if (metadata.st_dev, metadata.st_ino) != (
        resolved_metadata.st_dev,
        resolved_metadata.st_ino,
    ):
        fail(f"{label} changed while it was being checked")
    return resolved


def normalize_inventory(path: Path) -> Path:
    return normalize_regular_controller_file(path, "inventory")


def normalize_root_ca(path: Path) -> Path:
    return normalize_regular_controller_file(path, "--root-ca")


def normalize_become_password_file(path: Path) -> Path:
    """Validate a sudo password file without opening or copying it."""

    candidate = path.expanduser()
    if not candidate.is_absolute():
        fail("--become-password-file must be an absolute controller path")
    require_caller_owned_parent(candidate, "become password file")
    try:
        metadata = candidate.lstat()
    except FileNotFoundError as exc:
        raise WorkflowError(
            f"become password file does not exist: {candidate}"
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail("become password file must be a regular file, not a symlink")
    if metadata.st_uid != os.geteuid():
        fail("become password file must be owned by the current user")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        fail("become password file must have mode 0600")
    if metadata.st_nlink != 1:
        fail("become password file must have exactly one hard link")
    resolved = candidate.resolve()
    try:
        resolved_metadata = resolved.lstat()
    except FileNotFoundError as exc:
        raise WorkflowError(
            "become password file changed while it was being checked"
        ) from exc
    if (metadata.st_dev, metadata.st_ino) != (
        resolved_metadata.st_dev,
        resolved_metadata.st_ino,
    ):
        fail("become password file changed while it was being checked")
    if (
        not stat.S_ISREG(resolved_metadata.st_mode)
        or stat.S_ISLNK(resolved_metadata.st_mode)
        or resolved_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(resolved_metadata.st_mode) != 0o600
        or resolved_metadata.st_nlink != 1
    ):
        fail("become password file changed while it was being checked")
    return resolved


def normalize_vault_id(value: str) -> str:
    alias, separator, raw_path = value.partition("@")
    if separator != "@" or SAFE_ALIAS.fullmatch(alias) is None or not raw_path:
        fail("--vault-id must be ALIAS@/absolute/path/to/vault-password-file")
    password_file = Path(raw_path).expanduser()
    if not password_file.is_absolute():
        fail("the password file inside --vault-id must be absolute")
    require_caller_owned_parent(password_file, "vault password file")
    try:
        metadata = password_file.lstat()
    except FileNotFoundError as exc:
        raise WorkflowError(f"vault password file does not exist: {password_file}") from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail("vault password file must be a regular file, not a symlink")
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        fail("vault password file must be owned by this user and not group/other accessible")
    return f"{alias}@{password_file.resolve()}"


def normalize_age_identity(path: Path, recipient: str) -> Path:
    path = path.expanduser()
    if not path.is_absolute():
        fail("--rollback-age-identity must be an absolute controller path")
    require_caller_owned_parent(path, "rollback age identity")
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise WorkflowError(f"rollback age identity does not exist: {path}") from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail("rollback age identity must be a regular file, not a symlink")
    if (
        metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size < 1
        or metadata.st_size > 16 * 1024
    ):
        fail("rollback age identity must be caller-owned, mode 0600, and at most 16 KiB")
    resolved = path.resolve()
    if resolved.is_relative_to(ROOT.resolve()):
        fail("rollback age identity must be held outside the source checkout")
    if shutil.which("age-keygen") is None:
        fail("age-keygen is required to prove the rollback identity recipient")
    derived = run_checked(
        ["age-keygen", "-y", str(resolved)],
        capture=True,
        label="derive public recipient from rollback age identity",
    ).stdout.strip()
    if derived != recipient:
        fail("rollback age identity does not match --backup-recipient")
    return resolved


def git_release(root: Path, label: str) -> str:
    root = root.expanduser().resolve()
    required = (
        root / "ansible.cfg",
        root / "ansible/site.yml",
        root / "ansible/deploy-stack-only.yml",
        root / "compose/docker-compose.yml",
    )
    if any(not path.is_file() for path in required):
        fail(f"{label} is not a complete AI Gateway source checkout: {root}")
    release_paths = ("ansible", "compose", "scripts", "services", "ansible.cfg")
    status = run_checked(
        [
            "git", "-C", str(root), "status", "--porcelain=v1",
            "--untracked-files=all", "--", *release_paths,
        ],
        capture=True,
        label=f"inspect {label}",
    ).stdout.strip()
    if status:
        fail(f"{label} has tracked or untracked changes in release-bearing paths")
    return run_checked(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        capture=True,
        label=f"read {label} commit",
    ).stdout.strip()


def require_inventory_ssh_target(
    inventory: Path,
    limit: str,
    vault_id: str,
    ssh_target: str,
    ssh_port: int,
    domain: str,
    adm_ip: str,
    internal_ip: str,
    vault_ui: bool,
) -> None:
    result = run_checked(
        [
            "ansible-inventory",
            "-i",
            str(inventory),
            "--host",
            limit,
            "--vault-id",
            vault_id,
        ],
        capture=True,
        label="resolve the selected inventory host",
    )
    try:
        host = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise WorkflowError("Ansible returned invalid selected-host inventory data") from exc
    if not isinstance(host, dict):
        fail("selected inventory host data is incomplete")
    user = host.get("ansible_user")
    address = host.get("ansible_host", limit)
    port = host.get("ansible_port", 22)
    try:
        inventory_port = int(port)
    except (TypeError, ValueError) as exc:
        raise WorkflowError("selected inventory host has an invalid ansible_port") from exc
    if f"{user}@{address}" != ssh_target or inventory_port != ssh_port:
        fail(
            "--ssh-target/--ssh-port must exactly match ansible_user, "
            "ansible_host, and ansible_port for --limit"
        )
    expected_topology = {
        "aigw_domain": domain,
        "eth1_ip": adm_ip,
        "eth2_ip": internal_ip,
        "aigw_vault_ui_enabled": vault_ui,
    }
    mismatched = {
        name: {"inventory": host.get(name), "explicit": expected}
        for name, expected in expected_topology.items()
        if host.get(name) != expected
    }
    if mismatched:
        fail(
            "explicit validation topology must exactly match inventory: "
            + json.dumps(mismatched, sort_keys=True)
        )


def require_pipelining(root: Path) -> None:
    output = run_checked(
        ["ansible-config", "dump"],
        cwd=root,
        capture=True,
        label=f"read Ansible configuration in {root}",
    ).stdout
    lines = [line for line in output.splitlines() if line.startswith("ANSIBLE_PIPELINING(")]
    if len(lines) != 1 or not lines[0].rstrip().endswith("= True"):
        fail(f"Ansible pipelining is not proven enabled in {root}")


def postgres_major(root: Path) -> int:
    text = (root / "compose/docker-compose.yml").read_text(encoding="utf-8")
    matches = re.findall(r"(?m)^\s*image:\s*\S*postgres:(\d+)[^\n]*@sha256:[0-9a-f]{64}\s*$", text)
    if len(set(matches)) != 1:
        fail(f"cannot read one exact PostgreSQL major from {root}")
    return int(matches[0])


def validate_upgrade_inputs(
    args: argparse.Namespace,
) -> tuple[Path, str, Path, Path, str, str]:
    if SAFE_ALIAS.fullmatch(args.limit) is None:
        fail("--limit must be one lowercase inventory host alias")
    if SAFE_SSH_TARGET.fullmatch(args.ssh_target) is None:
        fail("--ssh-target must be USER@HOST with no shell characters")
    if args.ssh_port < 1 or args.ssh_port > 65535:
        fail("--ssh-port must be between 1 and 65535")
    if SAFE_DOMAIN.fullmatch(args.domain) is None:
        fail("--domain must be a canonical lowercase FQDN")
    for value, label in ((args.adm_ip, "--adm-ip"), (args.internal_ip, "--internal-ip")):
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError as exc:
            raise WorkflowError(f"{label} must be an IP address") from exc
        if parsed.version != 4:
            fail(f"{label} must be an IPv4 address")
    if AGE_RECIPIENT.fullmatch(args.backup_recipient) is None:
        fail("--backup-recipient must be one age X25519 recipient")
    backup_root = safe_remote_path(args.remote_backup_root, "--remote-backup-root")
    broad_roots = {
        "/", "/bin", "/boot", "/dev", "/etc", "/home", "/opt", "/proc",
        "/root", "/run", "/sbin", "/srv", "/sys", "/tmp", "/usr", "/var",
        "/var/lib", "/var/tmp", "/mnt", "/media",
    }
    if str(backup_root) in broad_roots:
        fail("--remote-backup-root must be a dedicated mounted backup directory")
    backup_path = require_strict_descendant(
        args.remote_backup_path, str(backup_root), "--remote-backup-path"
    )
    if not str(backup_path).endswith(".age"):
        fail("--remote-backup-path must end in .age")
    if backup_path.parent != backup_root:
        fail("--remote-backup-path must be a direct child of --remote-backup-root")
    safe_remote_path(REMOTE_SEED_ROOT, "fixed remote seed root")
    safe_remote_path(REMOTE_RECOVERY_IDENTITY, "fixed recovery identity path")
    root_ca = normalize_root_ca(args.root_ca)
    args.root_ca = root_ca
    inventory = normalize_inventory(args.inventory)
    vault_id = normalize_vault_id(args.vault_id)
    require_inventory_ssh_target(
        inventory,
        args.limit,
        vault_id,
        args.ssh_target,
        args.ssh_port,
        args.domain,
        args.adm_ip,
        args.internal_ip,
        args.vault_ui,
    )
    age_identity = normalize_age_identity(
        args.rollback_age_identity, args.backup_recipient
    )
    previous_root = args.previous_release_dir.expanduser().resolve()
    current_root = ROOT.resolve()
    if (
        previous_root == current_root
        or previous_root.is_relative_to(current_root)
        or current_root.is_relative_to(previous_root)
    ):
        fail("--previous-release-dir must be a separate checkout or git worktree")
    current_commit = git_release(ROOT, "candidate source")
    previous_commit = git_release(previous_root, "previous release source")
    if current_commit == previous_commit:
        fail("candidate and previous release source point to the same commit")
    require_pipelining(ROOT)
    require_pipelining(previous_root)
    if postgres_major(ROOT) != postgres_major(previous_root):
        fail(
            "automatic upgrades refuse PostgreSQL major changes; use a reviewed "
            "pg_upgrade or logical migration procedure"
        )
    return (
        inventory,
        vault_id,
        previous_root,
        age_identity,
        current_commit,
        previous_commit,
    )


def remote_paths(release: Release, base: str, label: str) -> RemoteRelease:
    if base != REMOTE_SEED_ROOT:
        fail("remote image seeds must stay below the fixed release directory")
    directory = f"{base.rstrip('/')}/{label}-{release.manifest_sha256[:16]}"
    require_strict_descendant(directory, REMOTE_SEED_ROOT, "remote release directory")
    archive = f"{directory}/{release.archive.name}"
    manifest = f"{directory}/{release.manifest.name}"
    require_strict_descendant(archive, REMOTE_SEED_ROOT, "remote release archive")
    require_strict_descendant(manifest, REMOTE_SEED_ROOT, "remote release manifest")
    return RemoteRelease(
        archive=archive,
        manifest=manifest,
        archive_sha256=release.archive_sha256,
        manifest_sha256=release.manifest_sha256,
    )


def stage_release(
    release: Release,
    remote: RemoteRelease,
    *,
    inventory: Path,
    limit: str,
    vault_id: str,
) -> None:
    require_release_scope(release, RELEASE_SCOPE_PRODUCTION)
    validate_release_archive_allowlist(release)
    values = {
        "image_seed_stage_controller_archive": str(release.archive),
        "image_seed_stage_archive_sha256": release.archive_sha256,
        "image_seed_stage_controller_manifest": str(release.manifest),
        "image_seed_stage_manifest_sha256": release.manifest_sha256,
        "image_seed_stage_remote_directory": str(Path(remote.archive).parent),
        "image_seed_stage_remote_archive": remote.archive,
        "image_seed_stage_remote_manifest": remote.manifest,
    }
    ansible_command(
        root=ROOT,
        inventory=inventory,
        playbook=STAGE_PLAYBOOK,
        limit=limit,
        vault_id=vault_id,
        extra_vars=values,
    )


def manage_remote_recovery_identity(
    *,
    state: str,
    controller_identity: Path,
    inventory: Path,
    limit: str,
    vault_id: str,
) -> None:
    ansible_command(
        root=ROOT,
        inventory=inventory,
        playbook=RECOVERY_IDENTITY_PLAYBOOK,
        limit=limit,
        vault_id=vault_id,
        extra_vars={
            "update_recovery_identity_state": state,
            "update_recovery_identity_controller_path": str(controller_identity),
            "update_recovery_identity_remote_path": REMOTE_RECOVERY_IDENTITY,
        },
    )


def ssh_command(
    target: str,
    port: int,
    remote_argv: list[str],
    *,
    capture: bool,
    label: str,
) -> str:
    result = run_checked(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ClearAllForwardings=yes",
            "-p",
            str(port),
            target,
            shlex.join(remote_argv),
        ],
        capture=capture,
        label=label,
    )
    return result.stdout if capture else ""


def validate_remote_backup_boundary(
    target: str, port: int, root: str, output: str
) -> None:
    program = (
        "import pathlib,stat,sys; "
        "r=pathlib.Path(sys.argv[1]); o=pathlib.Path(sys.argv[2]); "
        "s=r.lstat(); "
        "assert stat.S_ISDIR(s.st_mode) and not stat.S_ISLNK(s.st_mode); "
        "assert s.st_uid==0 and s.st_gid==0 and stat.S_IMODE(s.st_mode)&0o022==0; "
        "assert r.resolve(strict=True)==r and o.parent==r; "
        "assert not o.exists() and not o.is_symlink()"
    )
    ssh_command(
        target,
        port,
        ["sudo", "-n", "python3", "-I", "-c", program, root, output],
        capture=True,
        label="validate the dedicated remote backup boundary",
    )


def preload_previous_release(target: str, port: int, release: RemoteRelease) -> None:
    ssh_command(
        target,
        port,
        [
            "sudo", "-n",
            "python3",
            "-I",
            LOADER_REMOTE,
            release.archive,
            release.archive_sha256,
            release.manifest,
            release.manifest_sha256,
            REMOTE_MARKER_DIR,
        ],
        capture=True,
        label="load previous offline release before upgrade",
    )
    raw = ssh_command(
        target,
        port,
        [
            "sudo", "-n",
            "python3",
            "-I",
            LOADER_REMOTE,
            "release-receipt",
            release.archive,
            release.manifest,
            release.manifest_sha256,
            STACK_REMOTE,
        ],
        capture=True,
        label="match previous offline release to the running source",
    )
    try:
        receipt = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise WorkflowError("target returned an invalid previous-release receipt") from exc
    if receipt.get("schema_version") != 2:
        fail("target did not verify the previous schema-v2 release")


def take_backup(target: str, port: int, recipient: str, output: str) -> BackupReceipt:
    ssh_command(
        target,
        port,
        [
            "sudo", "-n",
            f"{STACK_REMOTE}/scripts/state-backup.sh",
            "--recipient",
            recipient,
            "--output",
            output,
        ],
        capture=False,
        label="encrypted pre-upgrade state backup",
    )
    raw = ssh_command(
        target,
        port,
        ["sudo", "-n", "cat", f"{STACK_REMOTE}/.state/last-backup.json"],
        capture=True,
        label="read pre-upgrade backup receipt",
    )
    try:
        receipt = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise WorkflowError("target returned an invalid backup receipt") from exc
    if (
        receipt.get("format") != "aigw-state-backup-receipt-v1"
        or receipt.get("path") != output
        or not isinstance(receipt.get("sha256"), str)
        or HEX64.fullmatch(receipt["sha256"]) is None
        or not isinstance(receipt.get("created_at"), str)
    ):
        fail("pre-upgrade backup receipt does not match the requested backup")
    try:
        created = dt.datetime.fromisoformat(receipt["created_at"])
    except ValueError as exc:
        raise WorkflowError("pre-upgrade backup receipt has an invalid timestamp") from exc
    if created.tzinfo is None or created.utcoffset() is None:
        fail("pre-upgrade backup receipt timestamp has no timezone")
    age = (dt.datetime.now(dt.timezone.utc) - created).total_seconds()
    if age < 0 or age > 300:
        fail("pre-upgrade backup receipt is not fresh")
    return BackupReceipt(output, receipt["sha256"], receipt["created_at"])


def seed_extra_vars(release: RemoteRelease, *, skip_backup_gate: bool = False) -> dict[str, object]:
    values: dict[str, object] = {
        "offline_image_seed_enabled": True,
        "offline_image_seed_remote_path": release.archive,
        "offline_image_seed_sha256": release.archive_sha256,
        "offline_image_seed_manifest_remote_path": release.manifest,
        "offline_image_seed_manifest_sha256": release.manifest_sha256,
    }
    if skip_backup_gate:
        # The authenticated restore itself is the rollback gate. The normal
        # pre-upgrade check refuses its restore marker by design.
        values["require_preupgrade_backup"] = False
    return values


def lifecycle_release_fields(release: Release, commit: str) -> dict[str, str]:
    """Return only immutable, non-secret identifiers allowed in target audit."""

    if HEX64.fullmatch(release.manifest_sha256) is None:
        fail("release manifest digest is not lowercase SHA-256")
    egress = release.document.get("egress_policy")
    if not isinstance(egress, dict):
        fail("release manifest lacks its egress policy receipt")
    image_id = egress.get("envoy_image_id")
    policy_digest = egress.get("egress_policy_sha256")
    if not isinstance(image_id, str) or IMAGE_ID.fullmatch(image_id) is None:
        fail("release manifest has an invalid Envoy image ID")
    if not isinstance(policy_digest, str) or HEX64.fullmatch(policy_digest) is None:
        fail("release manifest has an invalid egress policy digest")
    if re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", commit) is None:
        fail("release source commit is not a lowercase Git object ID")
    return {
        "controller_lifecycle_manifest_sha256": release.manifest_sha256,
        "controller_lifecycle_release_commit": commit,
        "controller_lifecycle_envoy_image_id": image_id,
        "controller_lifecycle_egress_policy_sha256": policy_digest,
    }


def record_remote_lifecycle(
    *,
    action: str,
    outcome: str,
    operation_id: str,
    release: Release,
    commit: str,
    inventory: Path,
    limit: str,
    vault_id: str,
) -> None:
    """Ask Ansible to append one fixed-schema record on the target."""

    values: dict[str, object] = lifecycle_release_fields(release, commit)
    values.update(
        {
            "controller_lifecycle_action": action,
            "controller_lifecycle_outcome": outcome,
            "controller_lifecycle_operation_id": operation_id,
        }
    )
    ansible_command(
        root=ROOT,
        inventory=inventory,
        playbook=LIFECYCLE_AUDIT_PLAYBOOK,
        limit=limit,
        vault_id=vault_id,
        extra_vars=values,
    )


def deploy_candidate(
    release: RemoteRelease,
    *,
    inventory: Path,
    limit: str,
    vault_id: str,
) -> None:
    ansible_command(
        root=ROOT,
        inventory=inventory,
        playbook=DEPLOY_PLAYBOOK,
        limit=limit,
        vault_id=vault_id,
        extra_vars=seed_extra_vars(release),
    )


def run_external_validation(args: argparse.Namespace) -> None:
    command = [
        "bash",
        str(EXTERNAL_E2E),
        "--domain",
        args.domain,
        "--adm-ip",
        args.adm_ip,
        "--internal-ip",
        args.internal_ip,
        "--root-ca",
        str(args.root_ca),
        "--ssh",
        args.ssh_target,
        "--ssh-port",
        str(args.ssh_port),
    ]
    if args.vault_ui:
        command.append("--vault-ui")
    run_checked(command, label="remote end-to-end acceptance gate")
    if args.validation_program is not None:
        program = args.validation_program.expanduser().resolve()
        if not program.is_file() or not os.access(program, os.X_OK):
            fail("--validation-program must be an executable regular file")
        run_checked(
            [str(program), *args.validation_arg],
            label="operator-supplied additional validation",
        )


def remove_restore_marker(target: str, port: int, backup_sha256: str) -> None:
    program = (
        "import os,pathlib,stat,sys; "
        "p=pathlib.Path('/opt/ai-gateway/.state/restore-required-unseal'); "
        "s=p.lstat(); "
        "assert stat.S_ISREG(s.st_mode) and not stat.S_ISLNK(s.st_mode); "
        "assert s.st_uid==0 and s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600; "
        "assert p.read_text(encoding='ascii')==sys.argv[1]+'\\n'; "
        "p.unlink()"
    )
    ssh_command(
        target,
        port,
        ["sudo", "-n", "python3", "-I", "-c", program, backup_sha256],
        capture=True,
        label="retire verified restore marker",
    )


def automatic_rollback(
    args: argparse.Namespace,
    *,
    inventory: Path,
    vault_id: str,
    previous_root: Path,
    previous_release: RemoteRelease,
    backup: BackupReceipt,
) -> None:
    print("Candidate validation failed. Restoring the authenticated state backup.")
    ssh_command(
        args.ssh_target,
        args.ssh_port,
        [
            "sudo", "-n",
            f"{STACK_REMOTE}/scripts/state-restore.sh",
            "--input",
            backup.path,
            "--identity",
            REMOTE_RECOVERY_IDENTITY,
            "--sha256",
            backup.sha256,
            "--confirm",
            "RESTORE_AI_GATEWAY_STATE",
        ],
        capture=False,
        label="authenticated state restore",
    )
    ansible_command(
        root=previous_root,
        inventory=inventory,
        playbook=previous_root / "ansible/site.yml",
        limit=args.limit,
        vault_id=vault_id,
        extra_vars=seed_extra_vars(previous_release, skip_backup_gate=True),
    )
    run_external_validation(args)
    remove_restore_marker(args.ssh_target, args.ssh_port, backup.sha256)
    print("AUTOMATIC_ROLLBACK_PASSED previous release restored and validated")


def cmd_upgrade(args: argparse.Namespace) -> int:
    (
        inventory,
        vault_id,
        previous_root,
        age_identity,
        current_commit,
        previous_commit,
    ) = validate_upgrade_inputs(args)
    candidate = read_release(
        args.archive,
        args.manifest,
        required_scope=RELEASE_SCOPE_PRODUCTION,
    )
    previous = read_release(
        args.previous_archive,
        args.previous_manifest,
        required_scope=RELEASE_SCOPE_PRODUCTION,
    )
    validate_release_source_pins(candidate, ROOT)
    validate_release_source_pins(previous, previous_root)
    if candidate.platform != previous.platform:
        fail("candidate and previous offline releases target different platforms")
    operation_id = str(uuid.uuid4())

    candidate_remote = remote_paths(candidate, REMOTE_SEED_ROOT, "candidate")
    previous_remote = remote_paths(previous, REMOTE_SEED_ROOT, "previous")
    validate_remote_backup_boundary(
        args.ssh_target,
        args.ssh_port,
        args.remote_backup_root,
        args.remote_backup_path,
    )
    stage_release(
        previous,
        previous_remote,
        inventory=inventory,
        limit=args.limit,
        vault_id=vault_id,
    )
    stage_release(
        candidate,
        candidate_remote,
        inventory=inventory,
        limit=args.limit,
        vault_id=vault_id,
    )
    preload_previous_release(args.ssh_target, args.ssh_port, previous_remote)
    identity_staged = False
    backup: BackupReceipt | None = None
    output: dict[str, object] | None = None
    try:
        manage_remote_recovery_identity(
            state="present",
            controller_identity=age_identity,
            inventory=inventory,
            limit=args.limit,
            vault_id=vault_id,
        )
        identity_staged = True
        backup = take_backup(
            args.ssh_target,
            args.ssh_port,
            args.backup_recipient,
            args.remote_backup_path,
        )

        record_remote_lifecycle(
            action="upgrade",
            outcome="started",
            operation_id=operation_id,
            release=candidate,
            commit=current_commit,
            inventory=inventory,
            limit=args.limit,
            vault_id=vault_id,
        )
        try:
            deploy_candidate(
                candidate_remote,
                inventory=inventory,
                limit=args.limit,
                vault_id=vault_id,
            )
            run_external_validation(args)
            manage_remote_recovery_identity(
                state="absent",
                controller_identity=age_identity,
                inventory=inventory,
                limit=args.limit,
                vault_id=vault_id,
            )
            identity_staged = False
        except (Exception, KeyboardInterrupt) as candidate_error:
            candidate_failure = failure_summary(candidate_error)
            audit_failures: list[str] = []
            try:
                record_remote_lifecycle(
                    action="upgrade",
                    outcome="failed",
                    operation_id=operation_id,
                    release=candidate,
                    commit=current_commit,
                    inventory=inventory,
                    limit=args.limit,
                    vault_id=vault_id,
                )
            except (Exception, KeyboardInterrupt) as audit_error:
                audit_failures.append(
                    "upgrade failure record: " + failure_summary(audit_error)
                )
            try:
                record_remote_lifecycle(
                    action="rollback",
                    outcome="started",
                    operation_id=operation_id,
                    release=previous,
                    commit=previous_commit,
                    inventory=inventory,
                    limit=args.limit,
                    vault_id=vault_id,
                )
            except (Exception, KeyboardInterrupt) as audit_error:
                audit_failures.append(
                    "rollback start record: " + failure_summary(audit_error)
                )
            try:
                automatic_rollback(
                    args,
                    inventory=inventory,
                    vault_id=vault_id,
                    previous_root=previous_root,
                    previous_release=previous_remote,
                    backup=backup,
                )
                manage_remote_recovery_identity(
                    state="absent",
                    controller_identity=age_identity,
                    inventory=inventory,
                    limit=args.limit,
                    vault_id=vault_id,
                )
                identity_staged = False
            except (Exception, KeyboardInterrupt) as rollback_error:
                rollback_failure = failure_summary(rollback_error)
                try:
                    record_remote_lifecycle(
                        action="rollback",
                        outcome="failed",
                        operation_id=operation_id,
                        release=previous,
                        commit=previous_commit,
                        inventory=inventory,
                        limit=args.limit,
                        vault_id=vault_id,
                    )
                except (Exception, KeyboardInterrupt) as audit_error:
                    audit_failures.append(
                        "rollback failure record: " + failure_summary(audit_error)
                    )
                audit_suffix = (
                    ". Lifecycle audit was incomplete: " + "; ".join(audit_failures)
                    if audit_failures
                    else ""
                )
                raise WorkflowError(
                    "AUTOMATIC ROLLBACK FAILED. Keep ingress closed and preserve the "
                    f"backup. Candidate failure: {candidate_failure}. Rollback failure: "
                    f"{rollback_failure}{audit_suffix}"
                ) from rollback_error
            try:
                record_remote_lifecycle(
                    action="rollback",
                    outcome="success",
                    operation_id=operation_id,
                    release=previous,
                    commit=previous_commit,
                    inventory=inventory,
                    limit=args.limit,
                    vault_id=vault_id,
                )
            except (Exception, KeyboardInterrupt) as audit_error:
                audit_failures.append(
                    "rollback success record: " + failure_summary(audit_error)
                )
            audit_suffix = (
                ". Lifecycle audit was incomplete: " + "; ".join(audit_failures)
                if audit_failures
                else ""
            )
            raise WorkflowError(
                "candidate release failed validation and was rolled back: "
                f"{candidate_failure}{audit_suffix}"
            ) from candidate_error

        try:
            record_remote_lifecycle(
                action="upgrade",
                outcome="success",
                operation_id=operation_id,
                release=candidate,
                commit=current_commit,
                inventory=inventory,
                limit=args.limit,
                vault_id=vault_id,
            )
        except (Exception, KeyboardInterrupt) as audit_error:
            raise WorkflowError(
                "candidate release passed validation and the temporary recovery "
                "identity was removed, but the terminal lifecycle record failed; "
                "leave the validated candidate running and repair the audit path: "
                f"{failure_summary(audit_error)}"
            ) from audit_error

        output = {
            "status": "REMOTE_IMAGE_UPGRADE_PASSED",
            "operation_id": operation_id,
            "candidate_commit": current_commit,
            "previous_commit": previous_commit,
            "candidate_manifest_sha256": candidate.manifest_sha256,
            "backup": backup.path,
            "backup_sha256": backup.sha256,
        }
    finally:
        if identity_staged:
            original = sys.exc_info()[1]
            try:
                manage_remote_recovery_identity(
                    state="absent",
                    controller_identity=age_identity,
                    inventory=inventory,
                    limit=args.limit,
                    vault_id=vault_id,
                )
                identity_staged = False
            except WorkflowError as cleanup_error:
                if original is None:
                    raise WorkflowError(
                        "release workflow finished, but the temporary recovery "
                        f"identity could not be removed: {cleanup_error}"
                    ) from cleanup_error
                raise WorkflowError(
                    f"{original}; temporary recovery identity cleanup also failed: "
                    f"{cleanup_error}"
                ) from cleanup_error

    assert output is not None
    print(json.dumps(output, sort_keys=True))
    return 0


def add_release_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--archive", required=True, type=Path,
        help="absolute .docker.tar.zst path",
    )
    parser.add_argument(
        "--manifest", required=True, type=Path,
        help="absolute .manifest.json path",
    )


def add_preprod_become_arguments(parser: argparse.ArgumentParser) -> None:
    become = parser.add_mutually_exclusive_group()
    become.add_argument(
        "--ask-become-pass",
        action="store_true",
        help="ask for sudo when preprod manages its owned local resources",
    )
    become.add_argument(
        "--become-password-file",
        type=Path,
        metavar="PATH",
        help=(
            "absolute caller-owned mode-0600 password file passed only to "
            "ansible-playbook"
        ),
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        epilog=(
            "Start with 'update-images.py COMMAND --help'. Remote upgrade flags "
            "have no environment defaults: inventory, host, domain, networks, custody, "
            "and both releases must be explicit."
        ),
    )
    commands = result.add_subparsers(dest="command", required=True)

    prepare = commands.add_parser(
        "prepare",
        help="pull exact pins, build all custom images, and export schema v2",
        epilog=(
            "Example:\n  python3 -I scripts/update-images.py prepare "
            "--provider anthropic --platform linux/amd64 "
            "--archive /srv/aigw/candidate.docker.tar.zst "
            "--manifest /srv/aigw/candidate.manifest.json --test-preprod"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_release_arguments(prepare)
    prepare.add_argument(
        "--preprod-archive",
        type=Path,
        help=(
            "optional full preprod archive; defaults to --archive with .preprod "
            "before .docker.tar.zst"
        ),
    )
    prepare.add_argument(
        "--preprod-manifest",
        type=Path,
        help=(
            "optional full preprod manifest; defaults to --manifest with .preprod "
            "before .manifest.json"
        ),
    )
    prepare.add_argument(
        "--platform", required=True, choices=("linux/amd64", "linux/arm64")
    )
    prepare.add_argument(
        "--provider",
        action="append",
        required=True,
        metavar="NAME",
        help=(
            "reviewed egress provider name; repeat for each provider. The seed "
            "builder validates names against the committed catalog"
        ),
    )
    endpoint = prepare.add_mutually_exclusive_group()
    endpoint.add_argument("--docker-context")
    endpoint.add_argument("--docker-host")
    prepare.add_argument(
        "--test-preprod",
        action="store_true",
        help=(
            "clean local preprod, load the just-built archive, and run Ansible "
            "acceptance"
        ),
    )
    add_preprod_become_arguments(prepare)
    prepare.set_defaults(function=cmd_prepare)

    preprod = commands.add_parser(
        "test-preprod",
        help="deploy an existing schema-v2 release to local Ansible preprod",
        epilog=(
            "Release example:\n  python3 -I scripts/update-images.py test-preprod "
            "--archive /srv/aigw/candidate.preprod.docker.tar.zst "
            "--manifest /srv/aigw/candidate.preprod.manifest.json --load-archive"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_release_arguments(preprod)
    preprod.add_argument(
        "--load-archive",
        action="store_true",
        help=(
            "release-grade clean-room purge, fresh archive load, and Ansible "
            "acceptance; without this flag the check is development-only"
        ),
    )
    add_preprod_become_arguments(preprod)
    preprod.set_defaults(function=cmd_test_preprod)

    upgrade = commands.add_parser(
        "upgrade",
        help="stage, back up, deploy, validate, and automatically roll back",
        epilog=(
            "See docs/image-update-workflow.md for one complete command. Every "
            "target, custody, release, network, and inventory value is required."
        ),
    )
    add_release_arguments(upgrade)
    upgrade.add_argument("--previous-archive", required=True, type=Path)
    upgrade.add_argument("--previous-manifest", required=True, type=Path)
    upgrade.add_argument("--previous-release-dir", required=True, type=Path)
    upgrade.add_argument("--inventory", required=True, type=Path)
    upgrade.add_argument("--limit", required=True)
    upgrade.add_argument(
        "--vault-id",
        required=True,
        help="ALIAS@/absolute/path/to/private-vault-password-file",
    )
    upgrade.add_argument("--ssh-target", required=True, help="USER@HOST")
    upgrade.add_argument("--ssh-port", required=True, type=int)
    upgrade.add_argument("--domain", required=True)
    upgrade.add_argument("--adm-ip", required=True)
    upgrade.add_argument("--internal-ip", required=True)
    upgrade.add_argument("--root-ca", required=True, type=Path)
    upgrade.add_argument("--vault-ui", action="store_true")
    upgrade.add_argument("--backup-recipient", required=True)
    upgrade.add_argument(
        "--rollback-age-identity",
        required=True,
        type=Path,
        help="controller-held 0600 age identity matching --backup-recipient",
    )
    upgrade.add_argument(
        "--remote-backup-root",
        required=True,
        help="dedicated mounted backup directory containing --remote-backup-path",
    )
    upgrade.add_argument("--remote-backup-path", required=True)
    upgrade.add_argument(
        "--validation-program",
        type=Path,
        help="optional executable run after the mandatory built-in acceptance gate",
    )
    upgrade.add_argument(
        "--validation-arg",
        action="append",
        default=[],
        help="one literal argument for --validation-program; repeat as needed",
    )
    upgrade.set_defaults(function=cmd_upgrade)
    return result


def main(argv: list[str] | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        return args.function(args)
    except WorkflowError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
