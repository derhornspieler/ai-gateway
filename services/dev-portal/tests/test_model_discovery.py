from __future__ import annotations

import httpx
import pytest

from app import model_discovery
from app.main import app


def _public(name: str) -> dict[str, object]:
    return {
        "id": name,
        "object": "model",
        "created": 1,
        "owned_by": "aigw",
    }


def _deployment(name: str, deployment_id: str, *, db_model: bool) -> dict:
    return {
        "model_name": name,
        "litellm_params": {"model": f"anthropic/{name}"},
        "model_info": {"id": deployment_id, "db_model": db_model},
    }


@pytest.mark.asyncio
async def test_filter_keeps_static_and_active_visible_governed_models(
    monkeypatch,
) -> None:
    async def inputs(_bearer):
        return (
            [_public("static-model"), _public("dynamic-model")],
            [
                _deployment("static-model", "static-id", db_model=False),
                _deployment("dynamic-model", "dynamic-id", db_model=True),
            ],
            {"dynamic-model": "dynamic-id"},
        )

    monkeypatch.setattr(model_discovery, "_gather_discovery_inputs", inputs)
    document = await model_discovery.filtered_model_document("s" * 32)
    assert [row["id"] for row in document["data"]] == [
        "static-model",
        "dynamic-model",
    ]


@pytest.mark.asyncio
async def test_filter_strips_hidden_retired_and_unmanaged_db_rows(
    monkeypatch,
) -> None:
    async def inputs(_bearer):
        return (
            [
                _public("hidden-model"),
                _public("retired-model"),
                _public("unmanaged-model"),
            ],
            [
                _deployment("hidden-model", "hidden-id", db_model=True),
                _deployment("retired-model", "retired-id", db_model=True),
                _deployment("unmanaged-model", "unmanaged-id", db_model=True),
            ],
            {},
        )

    monkeypatch.setattr(model_discovery, "_gather_discovery_inputs", inputs)
    document = await model_discovery.filtered_model_document("s" * 32)
    assert document == {"object": "list", "data": []}


@pytest.mark.asyncio
async def test_filter_rejects_ambiguous_static_and_db_model_name(
    monkeypatch,
) -> None:
    async def inputs(_bearer):
        return (
            [_public("duplicate-name")],
            [
                _deployment("duplicate-name", "static-id", db_model=False),
                _deployment("duplicate-name", "db-id", db_model=True),
            ],
            {"duplicate-name": "db-id"},
        )

    monkeypatch.setattr(model_discovery, "_gather_discovery_inputs", inputs)
    with pytest.raises(model_discovery.DiscoveryError, match="ambiguous"):
        await model_discovery.filtered_model_document("s" * 32)


@pytest.mark.asyncio
async def test_public_routes_require_one_bearer_and_reject_query_options(
    monkeypatch,
) -> None:
    async def document(_bearer):
        return {
            "object": "list",
            "data": [_public("static-model"), _public("vendor/model")],
        }

    monkeypatch.setattr(model_discovery, "filtered_model_document", document)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://portal"
    ) as client:
        missing = await client.get("/v1/models")
        duplicate = await client.get(
            "/v1/models",
            headers=[
                ("Authorization", "Bearer " + "a" * 32),
                ("Authorization", "Bearer " + "b" * 32),
            ],
        )
        query = await client.get(
            "/v1/models?provider=anything",
            headers={"Authorization": "Bearer " + "a" * 32},
        )
        listed = await client.get(
            "/v1/models",
            headers={"Authorization": "Bearer " + "a" * 32},
        )
        found = await client.get(
            "/v1/models/static-model",
            headers={"Authorization": "Bearer " + "a" * 32},
        )
        found_with_slash = await client.get(
            "/v1/models/vendor/model",
            headers={"Authorization": "Bearer " + "a" * 32},
        )
        absent = await client.get(
            "/v1/models/hidden-model",
            headers={"Authorization": "Bearer " + "a" * 32},
        )
    assert missing.status_code == 401
    assert duplicate.status_code == 401
    assert query.status_code == 400
    assert listed.json()["data"][0]["id"] == "static-model"
    assert "no-store" in listed.headers["cache-control"]
    assert found.status_code == 200
    assert found_with_slash.status_code == 200
    assert found_with_slash.json()["id"] == "vendor/model"
    assert absent.status_code == 404
