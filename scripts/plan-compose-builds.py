#!/usr/bin/env python3
"""Plan content-addressed Compose builds without mutating Docker state.

The same planner is consumed by the pre-upgrade backup gate and by Ansible's
later build step.  Its JSON output contains only build-input digests, image
names, and image IDs; the effective Compose model (which can contain rendered
environment secrets) is accepted only on stdin and is never echoed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import stat
import struct
# subprocess is used only for the fixed exec-form Docker CLI invocation below.
import subprocess  # nosec B404
import sys
from typing import Any, Callable


PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
DOCKER_BINARY = "/usr/bin/docker"
LOCAL_DOCKER_HOST = "unix:///run/docker.sock"
FIXED_DOCKER_ENV = {
    "HOME": "/",
    "LC_ALL": "C",
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
}

# Keep this set in lockstep with the services-tree exclusions and stale-file
# cleanup in ansible/roles/docker_stack/tasks/main.yml. These are workstation
# or secret artifacts, not reviewed image inputs, and Ansible deliberately
# never stages them on the target. Hashing them on the release builder would
# make a locally tested seed impossible to reconcile on the clean target.
UNSAFE_DIRECTORY_NAMES = frozenset(
    {
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "venv",
        ".tox",
        "node_modules",
        ".git",
        "secrets",
    }
)
UNSAFE_FILE_NAMES = frozenset({".env"})
UNSAFE_FILE_PREFIXES = (".env.",)
UNSAFE_FILE_SUFFIXES = (".pyc", ".pyo", ".pyd", ".key", ".p12", ".pfx")
STAGED_EXECUTABLE_NAMES = frozenset(
    {
        "policy-rc.d",
        "samba-ad-entrypoint",
        "samba-ad-healthcheck",
        "samba-ad-secret-tool",
    }
)
STAGED_DIRECTORY_MODE = 0o755
STAGED_FILE_MODE = 0o644
STAGED_EXECUTABLE_MODE = 0o755
GENERATED_BIND_ONLY_FILES = {
    "platform-dns": frozenset(
        {
            "Corefile",
            "db.aigw.internal",
            "db.aigw.internal.adm",
        }
    )
}
DOCKER_IGNORED_PREFIXES = {
    "dev-portal": ("tests/",),
    "key-rotator": ("tests/",),
}
DOCKERIGNORE_RULES = {
    "dev-portal": (
        ".env",
        ".env.*",
        "secrets/",
        "**/.env",
        "**/.env.*",
        "**/secrets/",
        "**/*.key",
        "**/*.p12",
        "**/*.pfx",
        "**/__pycache__/",
        "**/*.py[cod]",
        "**/.pytest_cache/",
        "**/.ruff_cache/",
        "**/.venv/",
        "**/venv/",
        "**/.tox/",
        "**/node_modules/",
        "**/.git/",
        "tests/",
    ),
    "dhi-health-probe": (
        "*",
        "!Dockerfile",
        "!Dockerfile.litellm",
        "!Dockerfile.open-webui",
        "!Dockerfile.grafana",
        "!go.mod",
        "!main.go",
        "!main_test.go",
        "!cmd/",
        "!cmd/extract-plugin/",
        "!cmd/extract-plugin/main.go",
        "!cmd/extract-plugin/main_test.go",
        "!patch_openwebui_oauth.py",
        "!verify_openwebui_oauth.py",
        "!patch_openwebui_chroma.py",
        "!verify_openwebui_chroma.py",
        "!openwebui-wheels/",
        "!openwebui-wheels/SHA256SUMS",
        "!openwebui-wheels/README.md",
        "!openwebui-wheels/amd64/",
        "!openwebui-wheels/amd64/*.whl",
        "!openwebui-wheels/arm64/",
        "!openwebui-wheels/arm64/*.whl",
        "!openwebui-wheels/any/",
        "!openwebui-wheels/any/*.whl",
        "!runtime-security-wheels/",
        "!runtime-security-wheels/SHA256SUMS",
        "!runtime-security-wheels/README.md",
        "!runtime-security-wheels/*.whl",
    ),
    "egress-proxy": (
        "*",
        "!Dockerfile",
        "!go.mod",
        "!entrypoint.go",
        "!entrypoint_test.go",
        "!envoy.yaml",
        "!envoy.yaml.tmpl",
        "!cmd/",
        "!cmd/policygen/",
        "!cmd/policygen/*.go",
        "!internal/",
        "!internal/egresspolicy/",
        "!internal/egresspolicy/*.go",
        "!providers/",
        "!providers/catalog.json",
        "!providers/provenance/",
        "!providers/provenance/*.json",
        "!certs/",
        "!certs/*.pem",
    ),
    "key-rotator": (
        ".env",
        ".env.*",
        "secrets/",
        "**/.env",
        "**/.env.*",
        "**/secrets/",
        "**/*.key",
        "**/*.p12",
        "**/*.pfx",
        "**/__pycache__/",
        "**/*.py[cod]",
        "**/.pytest_cache/",
        "**/.ruff_cache/",
        "**/.venv/",
        "**/venv/",
        "**/.tox/",
        "**/node_modules/",
        "**/.git/",
        "tests/",
    ),
    "platform-dns": ("*", "!Dockerfile", "!healthcheck.go"),
    "samba-ad-preprod": (
        "*",
        "!Dockerfile",
        "!policy-rc.d",
        "!samba-ad-entrypoint",
        "!samba-ad-healthcheck",
        "!samba-ad-secret-tool",
    ),
    "traefik": ("*", "!Dockerfile"),
    "vault-ui-proxy": (
        "*",
        "!Dockerfile",
        "!go.mod",
        "!main.go",
        "!main_test.go",
        "!upstream-provenance.json",
        "!cmd/",
        "!cmd/extract-ui/",
        "!cmd/extract-ui/main.go",
        "!cmd/extract-ui/main_test.go",
    ),
    "wif-provider-mock": (
        "*",
        "!go.mod",
        "!main.go",
        "!main_test.go",
        "!Dockerfile",
    ),
}


class PlanError(RuntimeError):
    """Raised when a build model or local build input is unsafe/invalid."""


def _is_unsafe_context_entry(name: str, *, directory: bool) -> bool:
    """Return true for artifacts that never cross Ansible's staging boundary."""

    if directory:
        return name in UNSAFE_DIRECTORY_NAMES
    return (
        name in UNSAFE_FILE_NAMES
        or name.startswith(UNSAFE_FILE_PREFIXES)
        or name.endswith(UNSAFE_FILE_SUFFIXES)
    )


def _star_context_path_is_included(
    context_name: str, relative: str, *, directory: bool
) -> bool:
    """Apply the bounded allow-list form used by reviewed ``*`` contexts."""

    if relative == ".dockerignore":
        # Docker always reads this file, and the planner separately pins every
        # rule byte. Keep it in the build-definition digest.
        return True
    path = relative.removesuffix("/")
    rules = DOCKERIGNORE_RULES[context_name]
    allowed = [rule.removeprefix("!").removesuffix("/") for rule in rules[1:]]
    if directory:
        # Traverse only a directory that is itself re-included or contains a
        # reviewed re-included path.
        return any(rule == path or rule.startswith(f"{path}/") for rule in allowed)
    return any(
        path == rule or ("*" in rule and PurePosixPath(path).match(rule))
        for rule in allowed
    )


def _is_docker_ignored_path(
    context_name: str, relative: str, *, directory: bool = False
) -> bool:
    rules = DOCKERIGNORE_RULES.get(context_name, ())
    if rules and rules[0] == "*":
        return not _star_context_path_is_included(
            context_name, relative, directory=directory
        )
    return relative.startswith(DOCKER_IGNORED_PREFIXES.get(context_name, ()))


def _validate_dockerignore(context: Path, context_name: str) -> None:
    """Keep the digest inventory aligned with each reviewed Docker context."""

    expected = DOCKERIGNORE_RULES.get(context_name)
    dockerignore = context / ".dockerignore"
    if expected is None:
        if dockerignore.exists():
            raise PlanError(f"unreviewed .dockerignore for build context: {context_name}")
        return
    try:
        actual = tuple(dockerignore.read_text(encoding="utf-8").splitlines())
    except (OSError, UnicodeError) as exc:
        raise PlanError(f"cannot read reviewed .dockerignore: {context_name}") from exc
    if actual != expected:
        raise PlanError(
            f".dockerignore changed without a matching planner update: {context_name}"
        )


def _staged_mode(relative: str, metadata: os.stat_result) -> int:
    """Return the exact mode used by docker_stack's source staging policy."""

    if stat.S_ISDIR(metadata.st_mode):
        return STAGED_DIRECTORY_MODE
    if stat.S_ISREG(metadata.st_mode):
        name = Path(relative).name
        if name in STAGED_EXECUTABLE_NAMES or name.endswith(".sh"):
            return STAGED_EXECUTABLE_MODE
        return STAGED_FILE_MODE
    if stat.S_ISLNK(metadata.st_mode):
        raise PlanError(f"build-context symlinks are not staged: {relative}")
    raise PlanError(f"unsupported build-context entry: {relative}")


def _validate_context_entry(entry: Path, metadata: os.stat_result) -> None:
    if stat.S_ISLNK(metadata.st_mode):
        raise PlanError(f"build-context symlinks are not staged: {entry}")
    if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
        raise PlanError(f"unsupported build-context entry: {entry}")


def inspect_image(image: str) -> str | None:
    """Return the immutable local image ID, or None when the tag is absent."""
    # The image is one argv element from the already-rendered Compose model;
    # shell execution is never enabled. The invocation clears context-bearing
    # environment and pins the local UNIX socket, so root's persisted Docker
    # context cannot inspect an unrelated remote daemon.
    result = subprocess.run(  # nosec B603 B607
        [DOCKER_BINARY, "--host", LOCAL_DOCKER_HOST, "image", "inspect", image],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
        env=FIXED_DOCKER_ENV,
    )
    if result.returncode != 0:
        return None
    try:
        payload = json.loads(result.stdout)
        image_id = payload[0]["Id"]
    except (IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise PlanError(f"docker returned invalid inspection data for {image}") from exc
    if not isinstance(image_id, str) or not image_id:
        raise PlanError(f"docker returned an invalid image ID for {image}")
    return image_id


def _previous_manifest(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {"schema": 1, "services": {}}
    if not isinstance(payload, dict) or not isinstance(payload.get("services"), dict):
        return {"schema": 1, "services": {}}
    return payload


def _context_record(
    *,
    stack: Path,
    build_root: Path,
    project: str,
    service_name: str,
    service: dict[str, Any],
    image_inspector: Callable[[str], str | None],
) -> tuple[dict[str, str | None], str]:
    build = service.get("build")
    if isinstance(build, str):
        build = {"context": build}
    if not isinstance(build, dict):
        raise PlanError(f"invalid build definition for {service_name}")

    raw_context = build.get("context", ".")
    if not isinstance(raw_context, str) or not raw_context:
        raise PlanError(f"invalid build context for {service_name}")
    context = Path(raw_context)
    if not context.is_absolute():
        context = stack / context
    context = context.resolve()
    try:
        relative_context = context.relative_to(build_root)
    except ValueError as exc:
        raise PlanError(
            f"refusing build context outside {build_root}: {context}"
        ) from exc
    if not context.is_dir():
        raise PlanError(f"missing build context for {service_name}: {context}")

    # Compose expands contexts to absolute paths. Canonicalize back to the
    # stack-relative location so moving stack_dir alone is not an image input.
    # Every other effective build key remains part of the digest.
    canonical_build = dict(build)
    canonical_build["context"] = f"services/{relative_context.as_posix()}"
    context_name = relative_context.as_posix()
    _validate_dockerignore(context, context_name)
    build_payload = json.dumps(
        canonical_build,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    # Keep the legacy stream only for a one-converge, no-build migration of
    # existing root-owned manifests. Its unframed file payloads were
    # structurally ambiguous. The persisted digest is always the v2 stream,
    # whose domain and length framing make every inventory unambiguous.
    legacy_digest = hashlib.sha256()
    legacy_digest.update(build_payload)
    digest = hashlib.sha256(b"aigw-compose-build-input/v2\0")

    def frame(kind: bytes, relative: str, mode: int, size: int) -> None:
        encoded = relative.encode()
        digest.update(kind)
        digest.update(struct.pack(">I", len(encoded)))
        digest.update(encoded)
        digest.update(struct.pack(">IQ", mode, size))

    frame(b"B", "", 0, len(build_payload))
    digest.update(build_payload)

    for directory, dirnames, filenames in os.walk(context):
        dirnames.sort()
        filenames.sort()
        base = Path(directory)
        # Validate before filtering. An ignored cache or secret path must not
        # be able to hide a symlink or special file from this root process.
        for entry_name in [*dirnames, *filenames]:
            entry = base / entry_name
            _validate_context_entry(entry, entry.lstat())
        # Prune before hashing so transient local caches cannot enter the
        # release receipt. Do not traverse an excluded directory even when it
        # contains a very large virtualenv or node_modules tree.
        dirnames[:] = [
            name
            for name in dirnames
            if not _is_unsafe_context_entry(name, directory=True)
        ]
        generated_bind_only = GENERATED_BIND_ONLY_FILES.get(
            relative_context.as_posix(), frozenset()
        )
        dirnames[:] = [
            name
            for name in dirnames
            if not _is_docker_ignored_path(
                context_name,
                (base / name).relative_to(context).as_posix() + "/",
                directory=True,
            )
        ]
        filenames = [
            name
            for name in filenames
            if not _is_unsafe_context_entry(name, directory=False)
            and (base / name).relative_to(context).as_posix()
            not in generated_bind_only
            and not _is_docker_ignored_path(
                context_name,
                (base / name).relative_to(context).as_posix(),
            )
        ]
        for entry_name in dirnames + filenames:
            entry = base / entry_name
            relative = entry.relative_to(context).as_posix()
            metadata = entry.lstat()
            mode = _staged_mode(relative, metadata)
            legacy_digest.update(relative.encode() + b"\0")
            legacy_digest.update(f"{mode:04o}".encode())
            if stat.S_ISREG(metadata.st_mode):
                legacy_digest.update(b"F")
                frame(b"F", relative, mode, metadata.st_size)
                with entry.open("rb") as source:
                    opened = os.fstat(source.fileno())
                    if (
                        not stat.S_ISREG(opened.st_mode)
                        or (opened.st_dev, opened.st_ino)
                        != (metadata.st_dev, metadata.st_ino)
                    ):
                        raise PlanError(
                            f"build-context file changed identity for {service_name}: {entry}"
                        )
                    total = 0
                    for chunk in iter(lambda: source.read(1024 * 1024), b""):
                        total += len(chunk)
                        legacy_digest.update(chunk)
                        digest.update(chunk)
                    final = os.fstat(source.fileno())
                    stable_fields = (
                        "st_dev", "st_ino", "st_mode", "st_size",
                        "st_mtime_ns", "st_ctime_ns",
                    )
                    if total != metadata.st_size or any(
                        getattr(metadata, field) != getattr(final, field)
                        for field in stable_fields
                    ):
                        raise PlanError(
                            f"build-context file changed while hashing for {service_name}: {entry}"
                        )
            elif stat.S_ISDIR(metadata.st_mode):
                legacy_digest.update(b"D")
                frame(b"D", relative, mode, 0)
            else:
                # _staged_mode rejects symlinks and special files before their
                # contents or targets can influence a reviewed release.
                raise PlanError(f"unsupported build-context entry for {service_name}: {entry}")

    raw_image = service.get("image")
    if raw_image is not None and (not isinstance(raw_image, str) or not raw_image):
        raise PlanError(f"invalid image name for {service_name}")
    image = raw_image or f"{project}-{service_name}"
    image_id = image_inspector(image)
    return (
        {
            "digest": digest.hexdigest(),
            "image": image,
            "image_id": image_id,
        },
        legacy_digest.hexdigest(),
    )


def plan_compose_builds(
    model: dict[str, Any],
    *,
    stack: Path,
    state_path: Path,
    project: str,
    image_inspector: Callable[[str], str | None] = inspect_image,
) -> dict[str, Any]:
    """Return the current manifest and services requiring a local build."""
    if PROJECT_RE.fullmatch(project) is None:
        raise PlanError("unsafe Compose project name")
    stack = stack.resolve()
    build_root = (stack / "services").resolve()
    services = model.get("services")
    if not isinstance(services, dict):
        raise PlanError("effective Compose model has no services object")

    previous = _previous_manifest(state_path)
    current: dict[str, Any] = {"schema": 1, "services": {}}
    planned: list[str] = []

    for name, service in sorted(services.items()):
        if not isinstance(name, str) or not isinstance(service, dict):
            raise PlanError("effective Compose model contains an invalid service")
        if not service.get("build"):
            continue
        record, legacy_digest = _context_record(
            stack=stack,
            build_root=build_root,
            project=project,
            service_name=name,
            service=service,
            image_inspector=image_inspector,
        )
        current["services"][name] = record
        legacy_record = dict(record)
        legacy_record["digest"] = legacy_digest
        previous_record = previous.get("services", {}).get(name)
        if (
            previous_record not in (record, legacy_record)
            or record["image_id"] is None
        ):
            planned.append(name)

    return {"manifest": current, "services": planned}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("stack", type=Path)
    parser.add_argument("state_path", type=Path)
    parser.add_argument("project")
    args = parser.parse_args()
    try:
        model = json.load(sys.stdin)
        if not isinstance(model, dict):
            raise PlanError("effective Compose model is not an object")
        result = plan_compose_builds(
            model,
            stack=args.stack,
            state_path=args.state_path,
            project=args.project,
        )
    except (OSError, PlanError, json.JSONDecodeError) as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
