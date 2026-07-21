#!/usr/bin/env python3
"""Plan exact external and custom image scans for one committed release."""

from __future__ import annotations

import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
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


def artifact_slug(kind: str, value: str) -> str:
    """Return a short artifact-safe name without trusting an image reference."""

    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
    return f"{kind}-{digest}"


def custom_matrix(
    manifest: dict[str, object], preprod_only: set[str], platform: str
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
            "scope": (
                "production"
                if reference in scopes[builder.RELEASE_SCOPE_PRODUCTION]
                else "preprod-only"
            ),
            "slug": artifact_slug("external", reference),
        }
        for reference in references
    ]
    custom = custom_matrix(
        manifest, set(builder.PREPROD_ONLY_SERVICES), requested_platform
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
        "limitations": [
            "This hosted scan rebuilds candidates from the commit; it does not receive an operator's local offline archive.",
            "The evidence is GitHub Actions metadata, not signed SLSA provenance.",
            "Vulnerability results use the Trivy database available when the workflow runs.",
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
