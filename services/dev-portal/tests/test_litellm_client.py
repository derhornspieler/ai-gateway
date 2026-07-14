from __future__ import annotations

import json

import httpx
import pytest

from app import litellm_client


def _mock_client(monkeypatch, handler):
    real_async_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)

    def factory(*args, **kwargs):
        assert kwargs.get("trust_env") is False
        assert kwargs.get("follow_redirects") is False
        kwargs["transport"] = transport
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr(litellm_client.httpx, "AsyncClient", factory)


@pytest.mark.asyncio
async def test_key_list_uses_get_exact_subject_and_bounded_pagination(monkeypatch):
    requests = []

    def handler(request: httpx.Request):
        requests.append(request)
        assert request.method == "GET"
        assert request.url.params["user_id"] == "oidc-subject"
        assert request.url.params["return_full_object"] == "true"
        assert request.url.params["size"] == "100"
        page = int(request.url.params["page"])
        if page == 1:
            keys = [
                {"token": f"hash-{i}", "user_id": "oidc-subject"} for i in range(100)
            ]
            return httpx.Response(
                200,
                json={
                    "keys": keys,
                    "total_count": 101,
                    "current_page": 1,
                    "total_pages": 2,
                },
            )
        return httpx.Response(
            200,
            json={
                "keys": [{"token": "hash-100", "user_id": "oidc-subject"}],
                "total_count": 101,
                "current_page": 2,
                "total_pages": 2,
            },
        )

    _mock_client(monkeypatch, handler)

    keys = await litellm_client.key_list("oidc-subject")

    assert len(keys) == 101
    assert len(requests) == 2


@pytest.mark.asyncio
async def test_key_list_fails_closed_instead_of_authorizing_from_partial_pages(
    monkeypatch,
):
    monkeypatch.setattr(litellm_client, "KEY_LIST_PAGE_SIZE", 2)
    monkeypatch.setattr(litellm_client, "KEY_LIST_MAX_PAGES", 2)

    def handler(request: httpx.Request):
        return httpx.Response(
            200,
            json=[
                {"token": "one", "user_id": "oidc-subject"},
                {"token": "two", "user_id": "oidc-subject"},
            ],
        )

    _mock_client(monkeypatch, handler)

    with pytest.raises(litellm_client.LiteLLMError, match="safety limit"):
        await litellm_client.key_list("oidc-subject")


@pytest.mark.asyncio
async def test_key_list_rejects_short_counter_declared_nonfinal_page(monkeypatch):
    """A hidden page must not make an existing active key look absent."""

    requests = 0

    def handler(request: httpx.Request):
        nonlocal requests
        requests += 1
        assert request.url.params["page"] == "1"
        return httpx.Response(
            200,
            json={
                "keys": [],
                "current_page": 1,
                "total_pages": 2,
            },
        )

    _mock_client(monkeypatch, handler)

    with pytest.raises(litellm_client.LiteLLMError, match="declared final page"):
        await litellm_client.key_list("oidc-subject")
    assert requests == 1


@pytest.mark.asyncio
async def test_key_list_rejects_inconsistent_counted_page(monkeypatch):
    def handler(_request: httpx.Request):
        return httpx.Response(
            200,
            json={
                "keys": [{"token": "hash-1", "user_id": "oidc-subject"}],
                "current_page": 1,
                "total_pages": 1,
                "total_count": 2,
            },
        )

    _mock_client(monkeypatch, handler)

    with pytest.raises(litellm_client.LiteLLMError, match="declared final page"):
        await litellm_client.key_list("oidc-subject")


@pytest.mark.asyncio
async def test_key_list_rejects_cross_owner_or_unattributed_results(monkeypatch):
    for returned in (
        [{"token": "victim-hash", "user_id": "victim"}],
        [{"token": "owner-missing"}],
        ["hash-with-no-owner"],
    ):

        def handler(request: httpx.Request, body=returned):
            return httpx.Response(200, json={"keys": body, "total_pages": 1})

        _mock_client(monkeypatch, handler)
        with pytest.raises(litellm_client.LiteLLMError, match="outside"):
            await litellm_client.key_list("oidc-subject")


@pytest.mark.asyncio
async def test_key_generate_binds_namespaced_project_metadata(monkeypatch):
    body = None

    def handler(request: httpx.Request):
        nonlocal body
        assert request.method == "POST"
        body = json.loads(request.content)
        return httpx.Response(200, json={"key": "sk-once", "key_alias": "laptop"})

    _mock_client(monkeypatch, handler)

    await litellm_client.key_generate("owner-sub", "laptop", "ai-gateway")

    assert body == {
        "user_id": "owner-sub",
        "key_alias": "laptop",
        "metadata": {
            "created_via": "dev-portal",
            "aigw_project_id": "ai-gateway",
        },
    }


@pytest.mark.asyncio
async def test_key_deactivate_sends_only_pre_authorized_concrete_hash(monkeypatch):
    body = None

    def handler(request: httpx.Request):
        nonlocal body
        assert request.method == "POST"
        assert request.url.path == "/key/update"
        body = json.loads(request.content)
        return httpx.Response(200, json={"key": "owned-hash", "blocked": True})

    _mock_client(monkeypatch, handler)

    await litellm_client.key_deactivate("owned-hash")

    assert body == {"key": "owned-hash", "blocked": True}
