from __future__ import annotations

import json

import httpx
import pytest

from app.config import Settings
from app.litellm_client import LiteLLMClient, LiteLLMError


DEPLOYMENT_ID = "00000000-0000-4000-8000-000000000001"


def _settings() -> Settings:
    return Settings(
        ROTATOR_INTERNAL_TOKEN="0123456789abcdef0123456789abcdef",
        PORTAL_IDENTITY_TOKEN="abcdef0123456789abcdef0123456789",
        VAULT_TOKEN="vault-token",
        LITELLM_MASTER_KEY="litellm-master-key",
    )


@pytest.mark.asyncio
async def test_model_inventory_uses_fixed_paging_and_checks_counters() -> None:
    row = {
        "model_name": "claude-test",
        "model_info": {"id": DEPLOYMENT_ID, "db_model": True},
        "litellm_params": {"model": "anthropic/claude-test"},
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/v2/model/info"
        assert dict(request.url.params) == {"page": "1", "size": "500"}
        assert request.headers["authorization"] == "Bearer litellm-master-key"
        return httpx.Response(
            200,
            json={
                "data": [row],
                "total_count": 1,
                "total_pages": 1,
                "current_page": 1,
                "size": 500,
            },
        )

    client = LiteLLMClient(
        _settings(), transport=httpx.MockTransport(handler)
    )
    assert await client.list_model_deployments() == [row]


@pytest.mark.asyncio
async def test_model_inventory_rejects_inconsistent_counters() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": [],
                "total_count": 1,
                "total_pages": 1,
                "current_page": 1,
                "size": 500,
            },
        )

    client = LiteLLMClient(
        _settings(), transport=httpx.MockTransport(handler)
    )
    with pytest.raises(LiteLLMError, match="counters disagree"):
        await client.list_model_deployments()


@pytest.mark.asyncio
async def test_create_and_delete_use_exact_governed_deployment_id() -> None:
    deployment = {
        "model_name": "claude-test",
        "litellm_params": {"model": "anthropic/claude-test"},
        "model_info": {"id": DEPLOYMENT_ID},
    }
    seen: list[tuple[str, str, dict[str, object]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append((request.method, request.url.path, body))
        if request.url.path == "/model/new":
            return httpx.Response(200, json={"model_id": DEPLOYMENT_ID})
        return httpx.Response(200, json={"message": "deleted"})

    client = LiteLLMClient(
        _settings(), transport=httpx.MockTransport(handler)
    )
    await client.create_model_deployment(deployment)
    await client.delete_model_deployment(DEPLOYMENT_ID)

    assert seen == [
        ("POST", "/model/new", deployment),
        ("POST", "/model/delete", {"id": DEPLOYMENT_ID}),
    ]


@pytest.mark.asyncio
async def test_create_rejects_an_unexpected_returned_id() -> None:
    deployment = {
        "model_name": "claude-test",
        "litellm_params": {"model": "anthropic/claude-test"},
        "model_info": {"id": DEPLOYMENT_ID},
    }

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"model_id": "different-id"})

    client = LiteLLMClient(
        _settings(), transport=httpx.MockTransport(handler)
    )
    with pytest.raises(LiteLLMError, match="unexpected model ID"):
        await client.create_model_deployment(deployment)
