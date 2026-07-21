#!/usr/bin/env python3
"""Plan exact external and custom image scans for one committed release."""

from __future__ import annotations

import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))

from release_security_common import (
    ReleaseSecurityError,
    docker_client,
    load_config,
    repository_helpers,
    write_github_output,
)


DHI_IMAGE_RE = re.compile(
    r"^dhi\.io/[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9][A-Za-z0-9._-]*"
    r"@sha256:[0-9a-f]{64}$"
)
DOCKERFILE_VAR_RE = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")


def _build_definition(service_name: str, service: dict[str, object]) -> dict[str, object]:
    build = service.get("build")
    if isinstance(build, str):
        return {"context": build}
    if not isinstance(build, dict):
        raise ReleaseSecurityError(f"service has no safe build definition: {service_name}")
    return build


def dockerfile_dhi_bases(
    root: Path, service_name: str, service: dict[str, object]
) -> list[str]:
    """Return the exact DHI stages used by one reviewed Dockerfile.

    This intentionally supports only the simple ARG and FROM forms used in
    this repository. A new Dockerfile form fails closed until it is reviewed.
    """

    build = _build_definition(service_name, service)
    raw_context = build.get("context", ".")
    raw_dockerfile = build.get("dockerfile", "Dockerfile")
    raw_args = build.get("args", {})
    if (
        not isinstance(raw_context, str)
        or not raw_context
        or not isinstance(raw_dockerfile, str)
        or not raw_dockerfile
        or not isinstance(raw_args, dict)
        or any(not isinstance(k, str) or not isinstance(v, str) for k, v in raw_args.items())
    ):
        raise ReleaseSecurityError(f"service has invalid build inputs: {service_name}")
    context = Path(raw_context)
    if not context.is_absolute():
        context = root / context
    context = context.resolve()
    dockerfile = (context / raw_dockerfile).resolve()
    try:
        context.relative_to((root / "services").resolve())
        dockerfile.relative_to(context)
    except ValueError as exc:
        raise ReleaseSecurityError(
            f"service build leaves the reviewed services tree: {service_name}"
        ) from exc
    try:
        lines = dockerfile.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ReleaseSecurityError(f"cannot read Dockerfile for {service_name}") from exc

    values = dict(raw_args)
    final_base = ""
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        instruction, separator, remainder = stripped.partition(" ")
        if not separator:
            continue
        if instruction.upper() == "ARG":
            name, has_default, default = remainder.strip().partition("=")
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                raise ReleaseSecurityError(
                    f"Dockerfile has an unsafe ARG for {service_name}: {name}"
                )
            if name not in values and has_default:
                values[name] = default
            continue
        if instruction.upper() != "FROM":
            continue
        token = remainder.split()[0]

        def replace(match: re.Match[str]) -> str:
            name = match.group(1) or match.group(2)
            if name not in values:
                raise ReleaseSecurityError(
                    f"Dockerfile FROM uses an unresolved ARG for {service_name}: {name}"
                )
            return values[name]

        reference = DOCKERFILE_VAR_RE.sub(replace, token)
        if "$" in reference:
            raise ReleaseSecurityError(
                f"Dockerfile FROM uses an unsupported expansion for {service_name}"
            )
        final_base = reference
        if final_base.startswith("dhi.io/"):
            if DHI_IMAGE_RE.fullmatch(final_base) is None:
                raise ReleaseSecurityError(
                    f"DHI build stage is not tag-and-digest pinned: {service_name}"
                )
    return [final_base] if DHI_IMAGE_RE.fullmatch(final_base) else []


def artifact_slug(kind: str, value: str) -> str:
    """Return a short artifact-safe name without trusting an image reference."""

    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
    return f"{kind}-{digest}"


def custom_matrix(
    manifest: dict[str, object],
    preprod_only: set[str],
    platform: str,
    dhi_bases_by_service: dict[str, list[str]] | None = None,
) -> list[dict[str, object]]:
    """Collapse shared service builds into one scan for each final image."""

    services = manifest.get("services")
    if manifest.get("schema") != 1 or not isinstance(services, dict):
        raise ReleaseSecurityError("build planner returned an invalid manifest")
    grouped: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for service, record in sorted(services.items()):
        if not isinstance(service, str) or not isinstance(record, dict):
            raise ReleaseSecurityError("build planner returned an invalid service")
        image = record.get("image")
        digest = record.get("digest")
        if (
            not isinstance(image, str)
            or not image
            or not isinstance(digest, str)
            or len(digest) != 64
        ):
            raise ReleaseSecurityError("build planner returned incomplete image evidence")
        grouped[image].append((service, digest))

    matrix: list[dict[str, object]] = []
    for image, records in sorted(grouped.items()):
        digests = {digest for _, digest in records}
        if len(digests) != 1:
            raise ReleaseSecurityError(
                f"shared custom image has different build inputs: {image}"
            )
        service_names = sorted(service for service, _ in records)
        bases_by_service = dhi_bases_by_service or {}
        dhi_bases = sorted(
            {
                base
                for service_name in service_names
                for base in bases_by_service.get(service_name, [])
            }
        )
        is_preprod_only = any(name in preprod_only for name in service_names)
        if is_preprod_only and not all(name in preprod_only for name in service_names):
            raise ReleaseSecurityError(
                f"custom image crosses production and preprod scopes: {image}"
            )
        matrix.append(
            {
                "image": image,
                "service": service_names[0],
                "services": service_names,
                "input_digest": next(iter(digests)),
                "platform": platform,
                "dhi_bases": dhi_bases,
                "scope": "preprod-only" if is_preprod_only else "production",
                "slug": artifact_slug("custom", image),
            }
        )
    if not matrix:
        raise ReleaseSecurityError("release contains no custom images to scan")
    return matrix


def build_inventory(
    root: Path,
    config_path: Path,
    output_path: Path,
    github_output: Path | None,
) -> None:
    """Resolve the exact release graph through the authoritative seed code."""

    config = load_config(config_path)
    builder, planner = repository_helpers(root)
    client = docker_client(builder)
    requested_platform = builder.platform(client, config.platform)
    egress_plan = builder.plan_egress_policy(
        client,
        root,
        requested_platform,
        list(config.providers),
    )
    model, _, _ = builder.render_deployable_compose_model(
        client,
        root,
        requested_platform,
        egress_plan,
    )
    builder.add_preprod_build_services(model, root)
    with tempfile.TemporaryDirectory(prefix="aigw-ci-security-plan-") as temporary:
        plan = planner.plan_compose_builds(
            model,
            stack=root,
            state_path=Path(temporary) / "absent.json",
            project=builder.COMPOSE_PROJECT_NAME,
            image_inspector=lambda _image: None,
        )
    manifest = plan.get("manifest")
    if not isinstance(manifest, dict):
        raise ReleaseSecurityError("build planner omitted the custom image manifest")

    scopes = builder.collect_project_image_reference_scopes(root)
    references = sorted(scopes[builder.RELEASE_SCOPE_PREPROD])
    external = [
        {
            "reference": reference,
            "platform": requested_platform,
            "dhi_bases": [reference] if DHI_IMAGE_RE.fullmatch(reference) else [],
            "scope": (
                "production"
                if reference in scopes[builder.RELEASE_SCOPE_PRODUCTION]
                else "preprod-only"
            ),
            "slug": artifact_slug("external", reference),
        }
        for reference in references
    ]
    model_services = model.get("services")
    if not isinstance(model_services, dict):
        raise ReleaseSecurityError("rendered release model has no services")
    dhi_bases_by_service = {
        name: dockerfile_dhi_bases(root, name, service)
        for name, service in sorted(model_services.items())
        if isinstance(name, str)
        and isinstance(service, dict)
        and service.get("build")
    }
    custom = custom_matrix(
        manifest,
        set(builder.PREPROD_ONLY_SERVICES),
        requested_platform,
        dhi_bases_by_service,
    )
    dhi_images = sorted(
        {
            base
            for item in [*external, *custom]
            for base in item["dhi_bases"]
        }
    )
    inventory = {
        "schema": 1,
        "release_scope": "preprod-union",
        "platform": requested_platform,
        "providers": list(config.providers),
        "release_security_config_sha256": config.sha256,
        "egress_policy": egress_plan.receipt,
        "external_images": external,
        "custom_images": custom,
        "dhi_images": dhi_images,
        "limitations": [
            "This hosted scan rebuilds candidates from the commit; it does not receive an operator's local offline archive.",
            "The evidence is GitHub Actions metadata, not signed SLSA provenance.",
            "Vulnerability results use the Trivy database available when the workflow runs.",
            "DHI findings are filtered only by signed VEX for the exact reviewed base image.",
        ],
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(inventory, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_github_output(
        github_output,
        {
            "external_matrix": json.dumps(
                {"include": external}, sort_keys=True, separators=(",", ":")
            ),
            "custom_matrix": json.dumps(
                {"include": custom}, sort_keys=True, separators=(",", ":")
            ),
        },
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    try:
        build_inventory(
            args.root.resolve(strict=True),
            args.config.resolve(strict=True),
            args.output,
            args.github_output,
        )
    except (OSError, ReleaseSecurityError, RuntimeError) as exc:
        raise SystemExit(str(exc)) from None


if __name__ == "__main__":
    main()
