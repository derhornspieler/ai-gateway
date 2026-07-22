"""Canonical LiteLLM deployment projections for governed models."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Any

from app.model_catalog import ALLOWED_EGRESS_ORIGINS


MAX_LITELLM_MODELS = 10_200
MODEL_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")


class ModelProjectionError(RuntimeError):
    """LiteLLM's deployment projection is unsafe or has drifted."""


@dataclass(frozen=True)
class RuntimeDeployment:
    deployment_id: str
    model_name: str
    db_model: bool
    litellm_model: str | None
    api_base: str | None
    credential_name: str | None
    cache_control_injection_points: tuple[tuple[str, str], ...] | None
    managed: bool
    projection_sha256: str | None


def _canonical_json_sha256(value: dict[str, Any]) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def desired_deployment(model: dict[str, Any]) -> dict[str, Any]:
    """Build the only LiteLLM row allowed for one active governed model."""

    deployment_id = str(model.get("operation_id") or "")
    model_name = model.get("gateway_model_name")
    litellm_model = model.get("litellm_model")
    api_base = model.get("api_base")
    credential_name = model.get("litellm_credential_name")
    points = model.get("cache_control_injection_points")
    allowed_api_prefixes = tuple(
        f"{origin}/" for origin in sorted(ALLOWED_EGRESS_ORIGINS)
    )
    if (
        MODEL_ID_RE.fullmatch(deployment_id) is None
        or not isinstance(model_name, str)
        or MODEL_ID_RE.fullmatch(model_name) is None
        or not isinstance(litellm_model, str)
        or not litellm_model
        or not isinstance(api_base, str)
        or not api_base.startswith(allowed_api_prefixes)
        or not isinstance(credential_name, str)
        or not credential_name
        or not isinstance(points, list)
    ):
        raise ModelProjectionError("governed model projection is malformed")

    canonical_points: list[dict[str, str]] = []
    for point in points:
        if (
            not isinstance(point, dict)
            or set(point) != {"location", "role"}
            or point.get("location") != "message"
            or point.get("role") != "system"
        ):
            raise ModelProjectionError("governed cache policy is malformed")
        canonical_points.append({"location": "message", "role": "system"})

    projection = {
        "api_base": api_base,
        "cache_control_injection_points": canonical_points,
        "deployment_id": deployment_id,
        "litellm_credential_name": credential_name,
        "litellm_model": litellm_model,
        "model_name": model_name,
    }
    projection_sha256 = _canonical_json_sha256(projection)
    return {
        "model_name": model_name,
        "litellm_params": {
            "model": litellm_model,
            "api_base": api_base,
            "litellm_credential_name": credential_name,
            "cache_control_injection_points": canonical_points,
        },
        "model_info": {
            "id": deployment_id,
            "aigw_managed": True,
            "aigw_projection_sha256": projection_sha256,
        },
    }


def _optional_string(value: Any, *, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value.encode("utf-8")) > 1024:
        raise ModelProjectionError(f"LiteLLM {label} is malformed")
    return value


def _parse_points(value: Any) -> tuple[tuple[str, str], ...] | None:
    if value is None:
        return None
    if not isinstance(value, list) or len(value) > 8:
        raise ModelProjectionError("LiteLLM cache policy is malformed")
    result: list[tuple[str, str]] = []
    for point in value:
        if not isinstance(point, dict):
            raise ModelProjectionError("LiteLLM cache policy is malformed")
        location = point.get("location")
        role = point.get("role")
        if not isinstance(location, str) or not isinstance(role, str):
            raise ModelProjectionError("LiteLLM cache policy is malformed")
        result.append((location, role))
    return tuple(result)


def parse_runtime_deployments(rows: Any) -> tuple[RuntimeDeployment, ...]:
    """Parse the bounded `/v2/model/info` data array without guessing."""

    if not isinstance(rows, list) or len(rows) > MAX_LITELLM_MODELS:
        raise ModelProjectionError("LiteLLM model inventory is malformed")
    deployments: list[RuntimeDeployment] = []
    seen_ids: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ModelProjectionError("LiteLLM model inventory row is malformed")
        model_name = row.get("model_name")
        model_info = row.get("model_info")
        params = row.get("litellm_params")
        if (
            not isinstance(model_name, str)
            or MODEL_ID_RE.fullmatch(model_name) is None
            or not isinstance(model_info, dict)
            or not isinstance(params, dict)
        ):
            raise ModelProjectionError("LiteLLM model inventory row is malformed")
        deployment_id = model_info.get("id")
        db_model = model_info.get("db_model")
        if (
            not isinstance(deployment_id, str)
            or MODEL_ID_RE.fullmatch(deployment_id) is None
            or type(db_model) is not bool
            or deployment_id in seen_ids
        ):
            raise ModelProjectionError("LiteLLM model identity is malformed")
        seen_ids.add(deployment_id)
        managed = model_info.get("aigw_managed")
        if managed not in (None, True, False):
            raise ModelProjectionError("LiteLLM model ownership marker is malformed")
        raw_digest = model_info.get("aigw_projection_sha256")
        if raw_digest is not None and (
            not isinstance(raw_digest, str) or SHA256_RE.fullmatch(raw_digest) is None
        ):
            raise ModelProjectionError("LiteLLM model projection digest is malformed")
        deployments.append(
            RuntimeDeployment(
                deployment_id=deployment_id,
                model_name=model_name,
                db_model=db_model,
                litellm_model=_optional_string(
                    params.get("model"), label="provider model"
                ),
                api_base=_optional_string(params.get("api_base"), label="API base"),
                credential_name=_optional_string(
                    params.get("litellm_credential_name"),
                    label="credential name",
                ),
                cache_control_injection_points=_parse_points(
                    params.get("cache_control_injection_points")
                ),
                managed=managed is True,
                projection_sha256=raw_digest,
            )
        )
    return tuple(deployments)


def deployment_matches(
    actual: RuntimeDeployment,
    desired: dict[str, Any],
) -> bool:
    """Compare every field LiteLLM safely returns plus the full digest."""

    info = desired["model_info"]
    params = desired["litellm_params"]
    expected_points = tuple(
        (point["location"], point["role"])
        for point in params["cache_control_injection_points"]
    )
    # LiteLLM deliberately redacts api_base in some management responses.
    # When present it must match.  The immutable full projection digest still
    # binds the redacted value and is written only by this controller.
    api_base_matches = actual.api_base is None or actual.api_base == params["api_base"]
    return (
        actual.db_model
        and actual.managed
        and actual.deployment_id == info["id"]
        and actual.model_name == desired["model_name"]
        and actual.litellm_model == params["model"]
        and actual.credential_name == params["litellm_credential_name"]
        and actual.cache_control_injection_points == expected_points
        and api_base_matches
        and actual.projection_sha256 is not None
        and hmac.compare_digest(
            actual.projection_sha256,
            info["aigw_projection_sha256"],
        )
    )
