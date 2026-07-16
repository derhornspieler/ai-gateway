from __future__ import annotations

import json

import httpx
import pytest

from app.config import Settings
from app.litellm_client import (
    KEY_LIST_MAX_PAGES,
    LiteLLMClient,
    LiteLLMError,
    PortalKeyBinding,
)


def settings(**overrides) -> Settings:
    values = {
        "ROTATOR_INTERNAL_TOKEN": "0123456789abcdef0123456789abcdef",
        "PORTAL_IDENTITY_TOKEN": "abcdef0123456789abcdef0123456789",
        "VAULT_TOKEN": "vault-token",
        "LITELLM_MASTER_KEY": "litellm-master-key",
    }
    values.update(overrides)
    return Settings(**values)


# LiteLLM v1.91.3 exact response bodies. The PATCH endpoint `return`s (does
# not raise) handle_exception_on_proxy(), so its failures — including "not
# found" — arrive as HTTP 200 whose body is the serialized ProxyException.
UPDATE_OK = {"success": True, "message": "Credential updated successfully"}
CREATE_OK = {"success": True, "message": "Credential created successfully"}
MASKED_NOT_FOUND = {
    "message": "Credential not found in DB.",
    "type": "internal_server_error",
    "param": "None",
    "openai_code": 404,
    "code": "404",
    "headers": {},
    "provider_specific_fields": None,
}


@pytest.mark.asyncio
async def test_upsert_credential_patch_uses_complete_litellm_credential_item(
    caplog,
) -> None:
    secret = "sk-ant-oat-full-secret-value"
    expected = {
        "credential_name": "anthropic-primary",
        "credential_values": {"api_key": secret},
        "credential_info": {"managed_by": "key-rotator"},
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "PATCH"
        assert request.url.path == "/credentials/anthropic-primary"
        assert json.loads(request.content) == expected
        return httpx.Response(200, json=UPDATE_OK)

    client = LiteLLMClient(settings(), transport=httpx.MockTransport(handler))
    with caplog.at_level("INFO", logger="key_rotator.litellm"):
        await client.upsert_credential("anthropic-primary", {"api_key": secret})

    assert secret not in caplog.text
    assert "<redacted>" in caplog.text


@pytest.mark.asyncio
async def test_upsert_credential_patch_404_falls_back_to_complete_post_create() -> None:
    expected = {
        "credential_name": "anthropic-primary",
        "credential_values": {"api_key": "anthropic-token"},
        "credential_info": {"managed_by": "key-rotator"},
    }
    requests: list[tuple[str, str, dict[str, object]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(
            (request.method, request.url.path, json.loads(request.content))
        )
        if request.method == "PATCH":
            return httpx.Response(404)
        return httpx.Response(200, json=CREATE_OK)

    client = LiteLLMClient(settings(), transport=httpx.MockTransport(handler))
    await client.upsert_credential(
        "anthropic-primary", {"api_key": "anthropic-token"}
    )

    assert requests == [
        ("PATCH", "/credentials/anthropic-primary", expected),
        ("POST", "/credentials", expected),
    ]


@pytest.mark.asyncio
async def test_upsert_credential_masked_patch_404_falls_back_to_post_create() -> None:
    """A missing credential arrives as HTTP 200 + serialized ProxyException
    (code "404") on LiteLLM v1.91.3 — the create fallback must still fire.
    This is the exact live body that left anthropic-primary permanently
    absent while every rotation reported success."""
    expected = {
        "credential_name": "anthropic-primary",
        "credential_values": {"api_key": "anthropic-token"},
        "credential_info": {"managed_by": "key-rotator"},
    }
    requests: list[tuple[str, str, dict[str, object]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(
            (request.method, request.url.path, json.loads(request.content))
        )
        if request.method == "PATCH":
            return httpx.Response(200, json=MASKED_NOT_FOUND)
        return httpx.Response(200, json=CREATE_OK)

    client = LiteLLMClient(settings(), transport=httpx.MockTransport(handler))
    await client.upsert_credential(
        "anthropic-primary", {"api_key": "anthropic-token"}
    )

    assert requests == [
        ("PATCH", "/credentials/anthropic-primary", expected),
        ("POST", "/credentials", expected),
    ]


@pytest.mark.asyncio
async def test_upsert_credential_masked_non_404_patch_error_raises() -> None:
    masked_error = dict(MASKED_NOT_FOUND, code="500", openai_code=500)
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.method)
        return httpx.Response(200, json=masked_error)

    client = LiteLLMClient(settings(), transport=httpx.MockTransport(handler))
    with pytest.raises(LiteLLMError):
        await client.upsert_credential(
            "anthropic-primary", {"api_key": "anthropic-token"}
        )

    assert requests == ["PATCH"]


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [b"", b"null", b"[]", b"not-json"])
async def test_upsert_credential_ambiguous_patch_2xx_raises(body: bytes) -> None:
    """A 2xx without success=true proves nothing — fail closed rather than
    report a rotation that may not have persisted."""
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.method)
        return httpx.Response(200, content=body)

    client = LiteLLMClient(settings(), transport=httpx.MockTransport(handler))
    with pytest.raises(LiteLLMError):
        await client.upsert_credential(
            "anthropic-primary", {"api_key": "anthropic-token"}
        )

    assert requests == ["PATCH"]


@pytest.mark.asyncio
async def test_upsert_credential_create_without_success_body_raises() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "PATCH":
            return httpx.Response(404)
        return httpx.Response(200, json=MASKED_NOT_FOUND)

    client = LiteLLMClient(settings(), transport=httpx.MockTransport(handler))
    with pytest.raises(LiteLLMError):
        await client.upsert_credential(
            "anthropic-primary", {"api_key": "anthropic-token"}
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code", [422, 500])
async def test_upsert_credential_non_404_patch_error_raises(status_code: int) -> None:
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.method)
        return httpx.Response(status_code)

    client = LiteLLMClient(settings(), transport=httpx.MockTransport(handler))
    with pytest.raises(httpx.HTTPStatusError):
        await client.upsert_credential(
            "anthropic-primary", {"api_key": "anthropic-token"}
        )

    assert requests == ["PATCH"]


def portal_key(
    token: str,
    owner: str,
    project: str,
    *,
    blocked: bool = False,
    metadata: object | None = None,
) -> dict[str, object]:
    return {
        "token": token,
        "user_id": owner,
        "blocked": blocked,
        "metadata": (
            metadata
            if metadata is not None
            else {"created_via": "dev-portal", "aigw_project_id": project}
        ),
    }


@pytest.mark.asyncio
async def test_revoke_portal_project_keys_blocks_only_exact_active_binding() -> None:
    owner = "subject-1"
    rows = [
        portal_key("target-hash", owner, "project-a"),
        portal_key("already-blocked", owner, "project-a", blocked=True),
        portal_key("other-project", owner, "project-b"),
        {
            "token": "operator-key",
            "user_id": owner,
            "blocked": False,
            "metadata": {"created_via": "operator", "aigw_project_id": "project-a"},
        },
    ]
    updates: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer litellm-master-key"
        if request.method == "GET":
            assert request.url.path == "/key/list"
            assert request.url.params.get("user_id") == owner
            return httpx.Response(200, json={"keys": rows, "current_page": 1, "total_pages": 1})
        if request.method == "POST":
            assert request.url.path == "/key/update"
            body = json.loads(request.content)
            updates.append(body["key"])
            assert body == {"key": "target-hash", "blocked": True}
            rows[0]["blocked"] = True
            return httpx.Response(200, json={"blocked": True})
        raise AssertionError(f"unexpected request {request.method} {request.url}")

    client = LiteLLMClient(settings(), transport=httpx.MockTransport(handler))
    await client.revoke_portal_project_keys(owner, "project-a")

    assert updates == ["target-hash"]
    assert rows[0]["blocked"] is True
    assert rows[2]["blocked"] is False
    assert rows[3]["blocked"] is False


@pytest.mark.asyncio
async def test_revocation_rejects_malformed_portal_metadata_before_any_update() -> None:
    owner = "subject-1"
    updates: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "keys": [
                        portal_key(
                            "target-hash",
                            owner,
                            "project-a",
                            metadata="{not-json",
                        )
                    ]
                },
            )
        if request.method == "POST":
            updates.append(json.loads(request.content))
            return httpx.Response(200, json={"blocked": True})
        raise AssertionError(f"unexpected request {request.method} {request.url}")

    client = LiteLLMClient(settings(), transport=httpx.MockTransport(handler))
    with pytest.raises(LiteLLMError, match="metadata is not valid JSON"):
        await client.revoke_portal_project_keys(owner, "project-a")

    assert updates == []


@pytest.mark.asyncio
async def test_revocation_refuses_partial_owner_inventory_at_pagination_limit() -> None:
    owner = "subject-1"
    pages: list[int] = []
    updates: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            pages.append(int(request.url.params["page"]))
            return httpx.Response(
                200,
                json={
                    "keys": [portal_key(f"hash-{index}", owner, "project-a") for index in range(100)]
                },
            )
        if request.method == "POST":
            updates.append(json.loads(request.content))
            return httpx.Response(200, json={"blocked": True})
        raise AssertionError(f"unexpected request {request.method} {request.url}")

    client = LiteLLMClient(settings(), transport=httpx.MockTransport(handler))
    with pytest.raises(LiteLLMError, match="exceeded the safety limit"):
        await client.revoke_portal_project_keys(owner, "project-a")

    assert pages == list(range(1, KEY_LIST_MAX_PAGES + 1))
    assert updates == []


@pytest.mark.asyncio
async def test_global_inventory_page_retains_only_current_page_binding_and_counters() -> None:
    owner = "subject-1"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/key/list"
        assert dict(request.url.params) == {
            "return_full_object": "true",
            "page": "1",
            "size": "100",
        }
        return httpx.Response(
            200,
            json={
                "keys": [portal_key("target-hash", owner, "project-a")],
                "current_page": 1,
                "total_count": 1,
                "total_pages": 1,
            },
        )

    client = LiteLLMClient(settings(), transport=httpx.MockTransport(handler))
    inventory = await client.active_portal_key_inventory_page(1)

    assert inventory.page == 1
    assert inventory.total_count == 1
    assert inventory.total_pages == 1
    assert inventory.bindings == (
        PortalKeyBinding(owner, "project-a", "target-hash"),
    )


@pytest.mark.asyncio
async def test_targeted_global_revocation_verifies_a_lost_update_response() -> None:
    owner = "subject-1"
    row = portal_key("target-hash", owner, "project-a")
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.method)
        if request.method == "POST":
            assert request.url.path == "/key/update"
            assert json.loads(request.content) == {"key": "target-hash", "blocked": True}
            # Model a control-plane response lost after LiteLLM committed the
            # block. The exact-hash read must prove the safe outcome.
            row["blocked"] = True
            return httpx.Response(504)
        assert request.method == "GET"
        assert request.url.path == "/key/list"
        assert dict(request.url.params) == {
            "return_full_object": "true",
            "page": "1",
            "size": "100",
            "key_hash": "target-hash",
        }
        return httpx.Response(
            200,
            json={
                "keys": [row],
                "current_page": 1,
                "total_count": 1,
                "total_pages": 1,
            },
        )

    client = LiteLLMClient(settings(), transport=httpx.MockTransport(handler))
    await client.revoke_portal_key_binding(
        PortalKeyBinding(owner, "project-a", "target-hash")
    )

    assert requests == ["POST", "GET"]
