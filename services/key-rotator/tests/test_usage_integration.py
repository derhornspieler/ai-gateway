from __future__ import annotations

import httpx
import pytest

from app.config import Settings
from app.main import app, state
from app.usage import UsageWriteResult


USAGE_TOKEN = "c" * 64
INTERNAL_TOKEN = "0123456789abcdef0123456789abcdef"


class UsageStore:
    def __init__(self) -> None:
        self.calls = 0

    async def record_usage(self, event) -> UsageWriteResult:
        self.calls += 1
        return UsageWriteResult(event_id=event.event_id, created=True)


def usage_event() -> dict[str, object]:
    return {
        "schema_version": 1,
        "event_id": "a" * 64,
        "request_id": "call-123",
        "request_id_source": "litellm_call_id",
        "provider_response_id": "msg-123",
        "trace_id": "trace-123",
        "provider": "anthropic",
        "requested_model": "claude-sonnet-4-5",
        "actual_model": "claude-sonnet-4-5-20250929",
        "stable_user_id": "keycloak-subject-1",
        "project_id": "project-blue",
        "status": "success",
        "stream": False,
        "retry_count": 0,
        "occurred_at": "2026-07-22T12:00:00Z",
        "normal_input_tokens": 10,
        "cache_creation_5m_tokens": 20,
        "cache_creation_1h_tokens": 30,
        "cache_read_tokens": 40,
        "output_tokens": 50,
        "usage_completeness": "complete",
        "litellm_cost_usd": "0.00123",
        "provider_cost_usd": None,
        "source_version": "litellm-1.93.0",
    }


@pytest.fixture()
def configured_state():
    old_state = dict(state)
    store = UsageStore()
    state.clear()
    state.update(
        {
            "settings": Settings(
                ROTATOR_INTERNAL_TOKEN=INTERNAL_TOKEN,
                PORTAL_IDENTITY_TOKEN="abcdef0123456789abcdef0123456789",
                VAULT_TOKEN="vault-token",
                LITELLM_MASTER_KEY="litellm-master-key",
            ),
            "usage_token": USAGE_TOKEN,
            "usage_store": store,
        }
    )
    try:
        yield store
    finally:
        state.clear()
        state.update(old_state)


@pytest.mark.asyncio
async def test_exact_usage_route_uses_only_the_usage_credential(
    configured_state,
) -> None:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://rotator"
    ) as client:
        response = await client.post(
            "/usage/events",
            headers={"X-AIGW-Usage-Auth": USAGE_TOKEN},
            json=usage_event(),
        )
        internal_only = await client.post(
            "/usage/events",
            headers={"X-Internal-Auth": INTERNAL_TOKEN},
            json=usage_event(),
        )

    assert response.status_code == 201
    assert response.headers["cache-control"] == "no-store"
    assert internal_only.status_code == 401
    assert configured_state.calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/usage/events"),
        ("POST", "/usage/events/extra"),
        ("GET", "/status"),
    ],
)
async def test_usage_credential_has_no_authority_outside_exact_route(
    configured_state,
    method: str,
    path: str,
) -> None:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://rotator"
    ) as client:
        response = await client.request(
            method,
            path,
            headers={"X-AIGW-Usage-Auth": USAGE_TOKEN},
        )

    assert response.status_code == 401
    assert configured_state.calls == 0
