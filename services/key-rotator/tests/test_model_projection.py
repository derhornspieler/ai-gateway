from __future__ import annotations

import copy

import pytest

from app.model_projection import (
    ModelProjectionError,
    deployment_matches,
    desired_deployment,
    parse_runtime_deployments,
)


def _model(**changes):
    row = {
        "operation_id": "00000000-0000-4000-8000-000000000001",
        "gateway_model_name": "claude-test",
        "litellm_model": "anthropic/claude-test",
        "api_base": "http://envoy-egress:8080/anthropic",
        "litellm_credential_name": "anthropic-primary",
        "cache_control_injection_points": [
            {"location": "message", "role": "system"}
        ],
    }
    row.update(changes)
    return row


def _runtime(desired):
    row = copy.deepcopy(desired)
    row["model_info"]["db_model"] = True
    return row


def test_draft_operation_id_is_the_exact_runtime_deployment_id() -> None:
    desired = desired_deployment(_model())
    assert desired["model_info"]["id"] == _model()["operation_id"]
    assert desired["model_info"]["aigw_managed"] is True
    assert len(desired["model_info"]["aigw_projection_sha256"]) == 64


def test_identical_input_has_a_deterministic_projection() -> None:
    assert desired_deployment(_model()) == desired_deployment(_model())
    changed = desired_deployment(_model(api_base="http://envoy-egress:8080/other"))
    assert (
        changed["model_info"]["aigw_projection_sha256"]
        != desired_deployment(_model())["model_info"]["aigw_projection_sha256"]
    )


def test_preprod_projection_accepts_only_the_fixed_wif_mock_origin() -> None:
    preprod = desired_deployment(
        _model(api_base="http://wif-egress-mock:8080/anthropic")
    )
    assert preprod["litellm_params"]["api_base"] == (
        "http://wif-egress-mock:8080/anthropic"
    )

    with pytest.raises(ModelProjectionError, match="malformed"):
        desired_deployment(_model(api_base="https://attacker.test/anthropic"))


def test_exact_runtime_projection_matches_with_redacted_api_base() -> None:
    desired = desired_deployment(_model())
    runtime = _runtime(desired)
    runtime["litellm_params"].pop("api_base")
    parsed = parse_runtime_deployments([runtime])[0]
    assert deployment_matches(parsed, desired) is True


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("model_name",), "changed"),
        (("model_info", "aigw_managed"), False),
        (("model_info", "aigw_projection_sha256"), "0" * 64),
        (("litellm_params", "model"), "anthropic/changed"),
        (("litellm_params", "api_base"), "http://envoy-egress:8080/changed"),
        (("litellm_params", "litellm_credential_name"), "other"),
        (("litellm_params", "cache_control_injection_points"), []),
    ],
)
def test_any_returned_projection_drift_fails(path, value) -> None:
    desired = desired_deployment(_model())
    runtime = _runtime(desired)
    target = runtime
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    parsed = parse_runtime_deployments([runtime])[0]
    assert deployment_matches(parsed, desired) is False


def test_duplicate_and_malformed_runtime_rows_fail_closed() -> None:
    runtime = _runtime(desired_deployment(_model()))
    with pytest.raises(ModelProjectionError):
        parse_runtime_deployments([runtime, runtime])
    broken = copy.deepcopy(runtime)
    broken["model_info"]["db_model"] = "true"
    with pytest.raises(ModelProjectionError):
        parse_runtime_deployments([broken])
