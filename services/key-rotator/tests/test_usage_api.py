from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.usage import (
    UsageConflict,
    UsageStoreUnavailable,
    UsageWriteResult,
    canonical_event_sha256,
)
from app.usage_api import MAX_USAGE_BODY_BYTES, router


FIXTURE = json.loads(
    (
        Path(__file__).parent
        / "fixtures/litellm-1.93.0-anthropic-usage.json"
    ).read_text()
)
TOKEN = "c" * 64


def event() -> dict:
    payload = FIXTURE["kwargs"]["standard_logging_object"]
    return {
        "schema_version": 1,
        "event_id": "a" * 64,
        "request_id": payload["litellm_call_id"],
        "request_id_source": "litellm_call_id",
        "provider_response_id": payload["id"],
        "trace_id": payload["trace_id"],
        "provider": payload["custom_llm_provider"],
        "requested_model": payload["model_group"],
        "actual_model": payload["hidden_params"]["litellm_model_name"],
        "stable_user_id": payload["metadata"]["user_api_key_user_id"],
        "project_id": "project-blue",
        "status": "success",
        "stream": False,
        "retry_count": 2,
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


class MemoryUsageStore:
    def __init__(self) -> None:
        self.documents: dict[str, str] = {}
        self.calls = 0
        self.unavailable = False

    async def record_usage(self, usage_event) -> UsageWriteResult:
        self.calls += 1
        if self.unavailable:
            raise UsageStoreUnavailable("database unavailable")
        digest = canonical_event_sha256(usage_event)
        old = self.documents.get(usage_event.event_id)
        if old is not None and old != digest:
            raise UsageConflict("event ID was reused")
        created = old is None
        self.documents[usage_event.event_id] = digest
        return UsageWriteResult(event_id=usage_event.event_id, created=created)


@pytest.fixture()
def client_and_store() -> tuple[TestClient, MemoryUsageStore]:
    app = FastAPI()
    app.include_router(router)
    store = MemoryUsageStore()
    app.state.aigw_services = {"usage_token": TOKEN, "usage_store": store}

    @app.get("/unrelated")
    async def unrelated() -> dict[str, bool]:
        return {"ok": True}

    return TestClient(app), store


def post(client: TestClient, document: dict, token: str = TOKEN):
    return client.post(
        "/usage/events",
        headers={"X-AIGW-Usage-Auth": token},
        json=document,
    )


def test_create_and_exact_replay_are_idempotent(client_and_store) -> None:
    client, store = client_and_store

    created = post(client, event())
    replayed = post(client, event())

    assert created.status_code == 201
    assert created.json() == {"event_id": "a" * 64, "created": True}
    assert created.headers["cache-control"] == "no-store"
    assert replayed.status_code == 200
    assert replayed.json()["created"] is False
    assert store.calls == 2
    assert len(store.documents) == 1


def test_same_event_id_with_changed_evidence_is_a_conflict(client_and_store) -> None:
    client, _ = client_and_store
    assert post(client, event()).status_code == 201
    changed = event()
    changed["output_tokens"] = 51

    response = post(client, changed)

    assert response.status_code == 409
    assert response.json() == {"detail": "usage event ID was reused"}


def test_authentication_happens_before_json_validation(client_and_store) -> None:
    client, store = client_and_store

    response = client.post(
        "/usage/events",
        headers={"X-AIGW-Usage-Auth": "d" * 64},
        content=b"not-json",
    )

    assert response.status_code == 401
    assert store.calls == 0


def test_usage_token_has_no_authority_on_other_routes(client_and_store) -> None:
    client, store = client_and_store

    response = client.get(
        "/unrelated", headers={"X-AIGW-Usage-Auth": TOKEN}
    )

    assert response.status_code == 200
    assert store.calls == 0


@pytest.mark.parametrize(
    "raw",
    [
        b"not-json",
        b"[]",
        b'{"schema_version":1,"schema_version":1}',
        b'{"schema_version":NaN}',
    ],
)
def test_malformed_json_is_rejected_before_the_store(client_and_store, raw) -> None:
    client, store = client_and_store

    response = client.post(
        "/usage/events",
        headers={"X-AIGW-Usage-Auth": TOKEN},
        content=raw,
    )

    assert response.status_code == 422
    assert store.calls == 0


def test_sensitive_or_unknown_fields_are_rejected(client_and_store) -> None:
    client, store = client_and_store
    unsafe = event()
    unsafe["prompt"] = "never-store-this"

    response = post(client, unsafe)

    assert response.status_code == 422
    assert "never-store-this" not in response.text
    assert store.calls == 0


def test_body_size_is_bounded_before_the_store(client_and_store) -> None:
    client, store = client_and_store

    response = client.post(
        "/usage/events",
        headers={"X-AIGW-Usage-Auth": TOKEN},
        content=b"{" + b" " * MAX_USAGE_BODY_BYTES + b"}",
    )

    assert response.status_code == 413
    assert store.calls == 0


def test_database_failure_is_generic_and_prompt_free(client_and_store, caplog) -> None:
    client, store = client_and_store
    store.unavailable = True

    with caplog.at_level(logging.INFO, logger="key_rotator.usage"):
        response = post(client, event())

    assert response.status_code == 503
    assert response.json() == {"detail": "usage accounting is unavailable"}
    assert "database unavailable" not in caplog.text


def test_audit_projection_has_only_bounded_join_fields(client_and_store, caplog) -> None:
    client, _ = client_and_store

    with caplog.at_level(logging.INFO, logger="key_rotator.usage"):
        response = post(client, event())

    assert response.status_code == 201
    line = next(
        record.message
        for record in caplog.records
        if record.message.startswith("AIGW_SECURITY_EVENT ")
    )
    audit = json.loads(line.removeprefix("AIGW_SECURITY_EVENT "))
    assert set(audit) == {
        "schema_version",
        "event",
        "action",
        "outcome",
        "event_id",
        "request_id",
        "provider",
        "model",
        "project",
        "subject",
        "completeness",
    }
    assert audit["request_id"] == "call-123"
    assert "prompt" not in line.lower()
    assert "authorization" not in line.lower()
