#!/usr/bin/env python3
"""Build one exact custom release image for the container scan matrix."""

from __future__ import annotations

import argparse
import hashlib
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


def placeholder_egress_plan(builder, providers: tuple[str, ...]):
    """Supply valid interpolation for builds that do not consume Envoy policy."""

    return builder.EgressPolicyPlan(
        receipt={},
        providers_csv=",".join(providers),
        policy_sha256=hashlib.sha256(b"ci-non-envoy-build").hexdigest(),
    )


def require_build_recipe(service_name: str, service: object) -> None:
    """Require one rendered Compose build without duplicating image naming.

    Compose may leave ``image`` unset. The authoritative build planner turns
    that supported shape into ``<project>-<service>``. Its record is checked
    separately below, so rejecting an implicit name here would disagree with
    the release builder without adding a security check.
    """

    if not isinstance(service, dict) or not service.get("build"):
        raise ReleaseSecurityError(
            f"scan matrix no longer matches the release build for {service_name}"
        )


def require_planned_build(
    service_name: str,
    build_record: object,
    expected_image: str,
    expected_input_digest: str,
) -> None:
    """Bind a matrix entry to the planner's exact image and source digest."""

    if (
        not isinstance(build_record, dict)
        or build_record.get("image") != expected_image
        or build_record.get("digest") != expected_input_digest
    ):
        raise ReleaseSecurityError(
            f"scan matrix build-input digest no longer matches {service_name}"
        )


def build_image(
    root: Path,
    config_path: Path,
    service_name: str,
    expected_image: str,
    expected_input_digest: str,
    github_output: Path | None,
) -> None:
    """Build and inspect one matrix entry using the release builder's rules."""

    config = load_config(config_path)
    if re.fullmatch(r"[0-9a-f]{64}", expected_input_digest) is None:
        raise ReleaseSecurityError("custom image build-input digest is malformed")
    builder, planner = repository_helpers(root)
    client = docker_client(builder)
    requested_platform = builder.platform(client, config.platform)

    if service_name == builder.ENVOY_SERVICE:
        egress_plan = builder.plan_egress_policy(
            client,
            root,
            requested_platform,
            list(config.providers),
        )
    else:
        egress_plan = placeholder_egress_plan(builder, config.providers)

    model, compose_client, compose_files = builder.render_deployable_compose_model(
        client,
        root,
        requested_platform,
        egress_plan,
    )
    preprod_builds = builder.add_preprod_build_services(model, root)
    services = model.get("services")
    service = services.get(service_name) if isinstance(services, dict) else None
    require_build_recipe(service_name, service)

    with tempfile.TemporaryDirectory(prefix="aigw-ci-build-proof-") as temporary:
        build_plan = planner.plan_compose_builds(
            model,
            stack=root,
            state_path=Path(temporary) / "absent.json",
            project=builder.COMPOSE_PROJECT_NAME,
            image_inspector=lambda _image: None,
        )
    manifest = build_plan.get("manifest")
    manifest_services = manifest.get("services") if isinstance(manifest, dict) else None
    build_record = (
        manifest_services.get(service_name)
        if isinstance(manifest_services, dict)
        else None
    )
    require_planned_build(
        service_name,
        build_record,
        expected_image,
        expected_input_digest,
    )

    if service_name == builder.ENVOY_SERVICE:
        image_id = builder.build_immutable_envoy_image(
            compose_client,
            root,
            requested_platform,
            egress_plan,
        )
        policy_sha256 = egress_plan.policy_sha256
    elif service_name in builder.PREPROD_ONLY_SERVICES:
        selected = [entry for entry in preprod_builds if entry[0] == service_name]
        if len(selected) != 1:
            raise ReleaseSecurityError(f"missing preprod build recipe: {service_name}")
        _, context, image, network = selected[0]
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
            str(context / "Dockerfile"),
            str(context),
        )
        if result.returncode:
            detail = result.stderr.strip().splitlines()
            tail = detail[-1][:2048] if detail else "no diagnostic"
            raise ReleaseSecurityError(
                f"preprod custom image build failed for {service_name}: {tail}"
            )
        image_id = builder._inspect_custom_image(
            compose_client, expected_image, requested_platform
        )
        policy_sha256 = ""
    else:
        result = compose_client.run(
            *builder._compose_command(root, compose_files),
            "build",
            "--pull=false",
            "--no-cache",
            "--provenance=false",
            "--sbom=false",
            service_name,
        )
        if result.returncode:
            detail = result.stderr.strip().splitlines()
            tail = detail[-1][:2048] if detail else "no diagnostic"
            raise ReleaseSecurityError(
                f"custom image build failed for {service_name}: {tail}"
            )
        image_id = builder._inspect_custom_image(
            compose_client, expected_image, requested_platform
        )
        policy_sha256 = ""

    write_github_output(
        github_output,
        {
            "image_id": image_id,
            "input_digest": expected_input_digest,
            "policy_sha256": policy_sha256,
        },
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--service", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--input-digest", required=True)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    try:
        build_image(
            args.root.resolve(strict=True),
            args.config.resolve(strict=True),
            args.service,
            args.image,
            args.input_digest,
            args.github_output,
        )
    except (OSError, ReleaseSecurityError, RuntimeError) as exc:
        raise SystemExit(str(exc)) from None


if __name__ == "__main__":
    main()
