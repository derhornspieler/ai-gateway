from __future__ import annotations

import json

import httpx
import pytest

from app import litellm_client

# Captured before the conftest autouse fixture stubs it for route tests,
# so the direct client tests below exercise the real implementation.
REAL_MODEL_NAMES = litellm_client.model_names


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
async def test_key_generate_defaults_to_unlimited_with_project_metadata(
    monkeypatch,
):
    body = None

    def handler(request: httpx.Request):
        nonlocal body
        assert request.method == "POST"
        body = json.loads(request.content)
        return httpx.Response(200, json={"key": "sk-once", "key_alias": "laptop"})

    _mock_client(monkeypatch, handler)

    await litellm_client.key_generate("owner-sub", "laptop", "ai-gateway")

    # Owner decision: the platform default is UNLIMITED. No budget, rate
    # limit, model restriction, or expiry is applied unless the runtime
    # project policy (or an explicit static override) sets one — and no
    # default budget is ever applied (cost is an admin-only concept).
    assert body == {
        "user_id": "owner-sub",
        "key_alias": "laptop",
        "metadata": {
            "created_via": "dev-portal",
            "aigw_project_id": "ai-gateway",
        },
    }


@pytest.mark.asyncio
async def test_key_generate_applies_the_runtime_project_policy(monkeypatch):
    body = None

    def handler(request: httpx.Request):
        nonlocal body
        body = json.loads(request.content)
        return httpx.Response(200, json={"key": "sk-once"})

    _mock_client(monkeypatch, handler)

    await litellm_client.key_generate(
        "owner-sub",
        "laptop",
        "ai-gateway",
        {
            "tpm_limit": 50000,
            "rpm_limit": 30,
            "allowed_models": ["claude-sonnet", "claude-haiku"],
            "default_model": "claude-haiku",
        },
    )

    assert body["tpm_limit"] == 50000
    assert body["rpm_limit"] == 30
    assert body["models"] == ["claude-haiku", "claude-sonnet"]
    # The default model is a portal-surfaced concept, never a key field.
    assert "default_model" not in body
    assert "max_budget" not in body


@pytest.mark.asyncio
async def test_key_generate_rejects_malformed_runtime_policy(monkeypatch):
    called = False

    def handler(request: httpx.Request):
        nonlocal called
        called = True
        return httpx.Response(200, json={"key": "sk-never"})

    _mock_client(monkeypatch, handler)

    for policy in (
        {"tpm_limit": -1},
        {"rpm_limit": True},
        {"allowed_models": []},
        {"allowed_models": ["bad model"]},
        "restricted",
    ):
        with pytest.raises(litellm_client.LiteLLMError):
            await litellm_client.key_generate(
                "owner-sub", "laptop", "ai-gateway", policy
            )
    assert called is False


@pytest.mark.asyncio
async def test_key_generate_runtime_policy_wins_over_static_backstop(
    monkeypatch,
):
    from app.config import settings

    monkeypatch.setattr(
        settings,
        "_key_limit_defaults",
        {"tpm_limit": 1000, "duration": "7d"},
    )
    body = None

    def handler(request: httpx.Request):
        nonlocal body
        body = json.loads(request.content)
        return httpx.Response(200, json={"key": "sk-once"})

    _mock_client(monkeypatch, handler)

    await litellm_client.key_generate(
        "owner-sub",
        "laptop",
        "ai-gateway",
        {"tpm_limit": 50000, "rpm_limit": None, "allowed_models": None},
    )

    # The runtime policy overrides the static backstop where set; static
    # knobs it does not govern (duration) still apply.
    assert body["tpm_limit"] == 50000
    assert body["duration"] == "7d"
    assert "rpm_limit" not in body


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


@pytest.mark.asyncio
async def test_admin_key_list_page_requires_native_counters(monkeypatch):
    def handler(request: httpx.Request):
        assert "user_id" not in request.url.params
        assert request.url.params["return_full_object"] == "true"
        return httpx.Response(200, json={"keys": [{"token": "hash-1"}]})

    _mock_client(monkeypatch, handler)

    with pytest.raises(litellm_client.LiteLLMError, match="pagination counters"):
        await litellm_client.admin_key_list_page(1)


@pytest.mark.asyncio
async def test_admin_key_list_page_rejects_inconsistent_or_wrong_pages(monkeypatch):
    current: dict = {}

    def handler(request: httpx.Request):
        return httpx.Response(200, json=current)

    _mock_client(monkeypatch, handler)

    for payload in (
        # Echoed page differs from the requested one.
        {"keys": [], "current_page": 2, "total_pages": 1, "total_count": 1},
        # Declared counters disagree with each other.
        {"keys": [], "current_page": 1, "total_pages": 3, "total_count": 1},
        # Short non-final page hides keys.
        {
            "keys": [{"token": "hash-1"}],
            "current_page": 1,
            "total_pages": 2,
            "total_count": 51,
        },
    ):
        current.clear()
        current.update(payload)
        with pytest.raises(litellm_client.LiteLLMError):
            await litellm_client.admin_key_list_page(1)


@pytest.mark.asyncio
async def test_admin_key_list_page_returns_one_counter_checked_page(monkeypatch):
    keys = [{"token": f"hash-{i}", "user_id": f"owner-{i}"} for i in range(50)]

    def handler(request: httpx.Request):
        assert request.url.params["page"] == "2"
        assert request.url.params["size"] == "50"
        return httpx.Response(
            200,
            json={
                "keys": keys,
                "current_page": 2,
                "total_pages": 3,
                "total_count": 130,
            },
        )

    _mock_client(monkeypatch, handler)

    listing = await litellm_client.admin_key_list_page(2)

    assert listing["page"] == 2
    assert listing["total_pages"] == 3
    assert listing["total_count"] == 130
    assert len(listing["keys"]) == 50


@pytest.mark.asyncio
async def test_admin_key_lookup_requires_exactly_one_exact_match(monkeypatch):
    current: dict = {
        "keys": [{"token": "hash-abc", "user_id": "owner"}],
        "current_page": 1,
        "total_pages": 1,
        "total_count": 1,
    }

    def handler(request: httpx.Request):
        assert request.url.params["key_hash"] == "hash-abc"
        return httpx.Response(200, json=current)

    _mock_client(monkeypatch, handler)
    entry = await litellm_client.admin_key_lookup("hash-abc")
    assert entry["token"] == "hash-abc"

    for bad in (
        {"keys": [], "total_count": 0},
        {"keys": [{"token": "a"}, {"token": "b"}], "total_count": 2},
        {"keys": [{"token": "different"}], "total_count": 1},
    ):
        current.clear()
        current.update(bad)
        with pytest.raises(litellm_client.LiteLLMError):
            await litellm_client.admin_key_lookup("hash-abc")


@pytest.mark.asyncio
async def test_key_update_allows_only_reviewed_fields_and_bounded_values(
    monkeypatch,
):
    called = False

    def handler(request: httpx.Request):
        nonlocal called
        called = True
        return httpx.Response(200, json={})

    _mock_client(monkeypatch, handler)

    for updates in (
        {},
        {"models": "all"},
        {"models": ["bad model"]},
        {"metadata": {"created_via": "dev-portal"}},
        {"user_id": "someone-else"},
        {"blocked": "true"},
        {"max_budget": -1},
        {"max_budget": True},
        {"tpm_limit": 0},
        {"rpm_limit": 10.5},
        {"duration": "forever"},
        {"duration": None},
    ):
        with pytest.raises(litellm_client.LiteLLMError):
            await litellm_client.key_update("hash-abc", updates)
    assert called is False


@pytest.mark.asyncio
async def test_key_update_sends_allowlisted_payload(monkeypatch):
    body = None

    def handler(request: httpx.Request):
        nonlocal body
        assert request.url.path == "/key/update"
        body = json.loads(request.content)
        return httpx.Response(200, json={})

    _mock_client(monkeypatch, handler)

    await litellm_client.key_update(
        "hash-abc",
        {"max_budget": 50.0, "tpm_limit": None, "rpm_limit": 120, "blocked": False},
    )

    assert body == {
        "key": "hash-abc",
        "max_budget": 50.0,
        "tpm_limit": None,
        "rpm_limit": 120,
        "blocked": False,
    }


def test_settings_fail_closed_on_malformed_key_guardrails():
    from app.config import Settings

    for overrides in (
        {"portal_key_default_duration": "forever"},
        {"portal_key_default_max_budget": "0"},
        {"portal_key_default_tpm_limit": "-5"},
        {"portal_key_default_rpm_limit": "sixty"},
        {"portal_key_project_limits": "not-json"},
        {"portal_key_project_limits": "[]"},
        {"portal_key_project_limits": '{"UPPER": {"max_budget": "5"}}'},
        {"portal_key_project_limits": '{"ok": {"models": ["x"]}}'},
        {"portal_key_project_limits": '{"ok": {"duration": "eternal"}}'},
    ):
        with pytest.raises(ValueError, match="key-issuance guardrails"):
            Settings(**overrides)


def test_settings_default_to_unlimited_and_merge_static_overrides():
    from app.config import Settings

    # Owner decision: the shipped default is UNLIMITED on every knob.
    unlimited = Settings()
    assert unlimited.key_limits_for_project("any-project") == {}

    parsed = Settings(
        portal_key_default_tpm_limit="100000",
        portal_key_project_limits=(
            '{"ml-research": {"tpm_limit": null, "rpm_limit": "120"}}'
        ),
    )

    assert parsed.key_limits_for_project("other-project") == {"tpm_limit": 100000}
    assert parsed.key_limits_for_project("ml-research") == {"rpm_limit": 120}


@pytest.mark.asyncio
async def test_model_names_returns_bounded_validated_ids(monkeypatch):
    monkeypatch.setattr(litellm_client, "model_names", REAL_MODEL_NAMES)

    def handler(request: httpx.Request):
        assert request.url.path == "/v1/models"
        return httpx.Response(
            200,
            json={
                "data": [
                    {"id": "claude-sonnet"},
                    {"id": "claude-haiku"},
                    {"id": "claude-sonnet"},
                ]
            },
        )

    _mock_client(monkeypatch, handler)

    assert await litellm_client.model_names() == ["claude-haiku", "claude-sonnet"]


@pytest.mark.asyncio
async def test_model_names_fails_closed_on_malformed_entries(monkeypatch):
    monkeypatch.setattr(litellm_client, "model_names", REAL_MODEL_NAMES)
    current: list = [{}]

    def handler(request: httpx.Request):
        return httpx.Response(200, json=current[0])

    _mock_client(monkeypatch, handler)

    for payload in (
        {"data": [{"id": "bad model"}]},
        {"data": [{"id": 42}]},
        {"data": "claude-sonnet"},
        [],
    ):
        current[0] = payload
        with pytest.raises(litellm_client.LiteLLMError):
            await litellm_client.model_names()
