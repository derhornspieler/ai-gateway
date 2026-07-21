#!/usr/bin/env python3
"""Small shared helpers for the release container-security jobs."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from types import ModuleType


PROVIDER_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
SUPPORTED_PLATFORMS = {"linux/amd64", "linux/arm64"}


class ReleaseSecurityError(RuntimeError):
    """The committed release-security configuration is not safe to use."""


@dataclass(frozen=True)
class ReleaseSecurityConfig:
    """The exact release configuration exercised by GitHub Actions."""

    platform: str
    providers: tuple[str, ...]
    sha256: str


def load_module(path: Path, name: str) -> ModuleType:
    """Load one reviewed repository script whose filename contains a dash."""

    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ReleaseSecurityError(f"cannot load reviewed helper: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def load_config(path: Path) -> ReleaseSecurityConfig:
    """Read and strictly validate the committed CI release selection."""

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for name, value in pairs:
            if name in result:
                raise ReleaseSecurityError(
                    f"release container-security config repeats key: {name}"
                )
            result[name] = value
        return result

    try:
        raw = path.read_bytes()
        if raw.startswith(b"\xef\xbb\xbf"):
            raise ReleaseSecurityError(
                "release container-security config must not contain a UTF-8 BOM"
            )
        payload = json.loads(raw, object_pairs_hook=unique_object)
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseSecurityError("cannot read release container-security config") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "schema",
        "platform",
        "providers",
    }:
        raise ReleaseSecurityError("release container-security config has an invalid shape")
    platform = payload.get("platform")
    providers = payload.get("providers")
    if payload.get("schema") != 1 or platform not in SUPPORTED_PLATFORMS:
        raise ReleaseSecurityError("release container-security platform is unsupported")
    if (
        not isinstance(providers, list)
        or not providers
        or any(
            not isinstance(provider, str) or PROVIDER_RE.fullmatch(provider) is None
            for provider in providers
        )
        or providers != sorted(set(providers))
    ):
        raise ReleaseSecurityError(
            "release container-security providers must be a non-empty canonical list"
        )
    return ReleaseSecurityConfig(
        platform=platform,
        providers=tuple(providers),
        sha256=hashlib.sha256(raw).hexdigest(),
    )


def repository_helpers(root: Path) -> tuple[ModuleType, ModuleType]:
    """Load the same seed builder and build planner used by release creation."""

    builder = load_module(
        root / "scripts" / "rebuild-offline-image-seed.py",
        "_aigw_ci_seed_builder",
    )
    planner = load_module(
        root / "scripts" / "plan-compose-builds.py",
        "_aigw_ci_build_planner",
    )
    return builder, planner


def docker_client(builder: ModuleType):
    """Select and validate the hosted runner's local Unix Docker endpoint."""

    policy = builder.output_policy(allow_unprivileged_controller=True)
    return builder.resolve_docker_client(
        policy=policy,
        docker_path=None,
        docker_config=None,
        docker_context=None,
        docker_host=None,
    )


def write_github_output(path: Path | None, values: dict[str, str]) -> None:
    """Append single-line, non-secret values to GitHub's job output file."""

    if path is None:
        return
    with path.open("a", encoding="utf-8") as stream:
        for name, value in values.items():
            if "\n" in name or "\n" in value:
                raise ReleaseSecurityError("GitHub output values must fit on one line")
            stream.write(f"{name}={value}\n")
