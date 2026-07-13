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
import re
import stat
import struct
# subprocess is used only for the fixed exec-form Docker CLI invocation below.
import subprocess  # nosec B404
import sys
from typing import Any, Callable


PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")


class PlanError(RuntimeError):
    """Raised when a build model or local build input is unsafe/invalid."""


def inspect_image(image: str) -> str | None:
    """Return the immutable local image ID, or None when the tag is absent."""
    # The image is one argv element from the already-rendered Compose model;
    # shell execution is never enabled. Docker is the reviewed host CLI and is
    # intentionally PATH-resolved consistently with every deployment script.
    result = subprocess.run(  # nosec B603 B607
        ["docker", "image", "inspect", image],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
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
        for entry_name in dirnames + filenames:
            entry = base / entry_name
            relative = entry.relative_to(context).as_posix()
            metadata = entry.lstat()
            mode = stat.S_IMODE(metadata.st_mode)
            legacy_digest.update(relative.encode() + b"\0")
            legacy_digest.update(f"{mode:04o}".encode())
            if entry.is_symlink():
                target = os.readlink(entry).encode()
                legacy_digest.update(b"L" + target)
                frame(b"L", relative, mode, len(target))
                digest.update(target)
            elif entry.is_file():
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
            elif entry.is_dir():
                legacy_digest.update(b"D")
                frame(b"D", relative, mode, 0)
            else:
                raise PlanError(
                    f"unsupported build-context entry for {service_name}: {entry}"
                )

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
