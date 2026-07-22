from __future__ import annotations

import copy

import pytest

from app.model_projection import ModelProjectionError, desired_deployment
from app.model_reconciler import ModelReconciler


def _model(operation_id: str, *, active: bool = True, visible: bool = False):
    return {
        "operation_id": operation_id,
        "gateway_model_name": f"model-{operation_id[-1]}",
        "provider_name": "anthropic",
        "provider_model_id": f"provider-{operation_id[-1]}",
        "egress_policy_sha256": "a" * 64,
        "litellm_model": f"anthropic/provider-{operation_id[-1]}",
        "api_base": "http://envoy-egress:8080/anthropic",
        "litellm_credential_name": "anthropic-primary",
        "cache_control_injection_points": [
            {"location": "message", "role": "system"}
        ],
        "lifecycle_state": "active" if active else "draft",
        "active": active,
        "visible_in_discovery": visible,
    }


def _runtime(model):
    row = desired_deployment(model)
    row["model_info"]["db_model"] = True
    return row


class FakeDB:
    def __init__(self, models):
        self.models = models

    async def list_governed_models(self, **_kwargs):
        return copy.deepcopy(self.models)


class FakeLiteLLM:
    def __init__(self, rows=()):
        self.rows = list(copy.deepcopy(rows))
        self.created = []
        self.deleted = []

    async def list_model_deployments(self):
        return copy.deepcopy(self.rows)

    async def create_model_deployment(self, deployment):
        self.created.append(copy.deepcopy(deployment))
        row = copy.deepcopy(deployment)
        row["model_info"]["db_model"] = True
        self.rows.append(row)

    async def delete_model_deployment(self, deployment_id):
        self.deleted.append(deployment_id)
        self.rows = [
            row
            for row in self.rows
            if row["model_info"]["id"] != deployment_id
        ]


@pytest.mark.asyncio
async def test_missing_active_model_is_created_and_retry_is_idempotent() -> None:
    model = _model("00000000-0000-4000-8000-000000000001")
    litellm = FakeLiteLLM()
    reconciler = ModelReconciler(FakeDB([model]), litellm, egress_policy_sha256="a" * 64)
    await reconciler.reconcile()
    await reconciler.reconcile()
    assert len(litellm.created) == 1
    assert litellm.created[0]["model_info"]["id"] == model["operation_id"]
    assert reconciler.ready is True


@pytest.mark.asyncio
async def test_draft_and_retired_deployments_are_removed() -> None:
    model = _model(
        "00000000-0000-4000-8000-000000000002", active=False
    )
    litellm = FakeLiteLLM([_runtime(model)])
    reconciler = ModelReconciler(FakeDB([model]), litellm, egress_policy_sha256="a" * 64)
    await reconciler.reconcile()
    assert litellm.deleted == [model["operation_id"]]
    assert reconciler.ready is True


@pytest.mark.asyncio
async def test_unmanaged_database_model_fails_closed_without_deleting_it() -> None:
    unmanaged = _runtime(
        _model("00000000-0000-4000-8000-000000000003")
    )
    litellm = FakeLiteLLM([unmanaged])
    reconciler = ModelReconciler(FakeDB([]), litellm, egress_policy_sha256="a" * 64)
    with pytest.raises(ModelProjectionError, match="unmanaged"):
        await reconciler.reconcile()
    assert litellm.deleted == []
    assert reconciler.ready is False


@pytest.mark.asyncio
async def test_exact_projection_drift_fails_without_overwriting() -> None:
    model = _model("00000000-0000-4000-8000-000000000004")
    drifted = _runtime(model)
    drifted["litellm_params"]["model"] = "anthropic/changed"
    litellm = FakeLiteLLM([drifted])
    reconciler = ModelReconciler(FakeDB([model]), litellm, egress_policy_sha256="a" * 64)
    with pytest.raises(ModelProjectionError, match="drifted"):
        await reconciler.reconcile()
    assert litellm.created == []
    assert litellm.deleted == []


@pytest.mark.asyncio
async def test_static_model_name_collision_fails_before_creation() -> None:
    model = _model("00000000-0000-4000-8000-000000000006")
    static = _runtime(model)
    static["model_info"]["id"] = "static-deployment"
    static["model_info"]["db_model"] = False
    static["model_info"].pop("aigw_managed")
    static["model_info"].pop("aigw_projection_sha256")
    litellm = FakeLiteLLM([static])
    reconciler = ModelReconciler(
        FakeDB([model]), litellm, egress_policy_sha256="a" * 64
    )

    with pytest.raises(ModelProjectionError, match="collides"):
        await reconciler.reconcile()

    assert litellm.created == []
    assert litellm.deleted == []
    assert reconciler.ready is False


@pytest.mark.asyncio
async def test_visibility_does_not_change_runtime_projection() -> None:
    hidden = _model(
        "00000000-0000-4000-8000-000000000005", visible=False
    )
    visible = {**hidden, "visible_in_discovery": True}
    assert desired_deployment(hidden) == desired_deployment(visible)
