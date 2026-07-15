from __future__ import annotations

import asyncio
import json
import re
import time
from base64 import b64decode
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httpx
import pytest
from itsdangerous import TimestampSigner

from app import litellm_client
from app.config import settings
from app import main
from conftest import portal_user, session_cookie


# The autouse test fixture supplies a normal live membership decision for most
# route tests. Keep the real helper so dedicated fail-closed tests can exercise
# its upstream and payload validation directly.
LIVE_PROJECT_IDS = main._live_project_ids


def portal_key(
    *,
    owner: str,
    token: str = "owned-hash",
    alias: str = "laptop",
    project: str = "ai-gateway",
    blocked: bool | None = None,
    expires: str | None = None,
    default_model: str | None = None,
) -> dict:
    metadata = {
        "created_via": "dev-portal",
        "aigw_project_id": project,
    }
    if default_model is not None:
        metadata["aigw_default_model"] = default_model
    return {
        "token": token,
        "key_alias": alias,
        "user_id": owner,
        "blocked": blocked,
        "expires": expires,
        "metadata": metadata,
    }


def decoded_session(client) -> dict:
    signed = next(
        (
            cookie.value
            for cookie in reversed(list(client.cookies.jar))
            if cookie.name == "aigw_portal_session" and cookie.domain == "portal.test"
        ),
        None,
    )
    assert signed is not None
    payload = TimestampSigner(settings.session_secret).unsign(signed)
    return json.loads(b64decode(payload))


def sealed_authorization_error() -> httpx.HTTPStatusError:
    request = httpx.Request("GET", "http://key-rotator/identity/authorization/test")
    response = httpx.Response(
        423,
        json={"detail": "vault_sealed"},
        request=request,
    )
    return httpx.HTTPStatusError(
        "sealed authorization controller", request=request, response=response
    )


def test_ordinary_authenticated_user_cannot_access_key_management(
    client, set_session, monkeypatch
):
    called = False

    async def key_list(_user_id):
        nonlocal called
        called = True
        return []

    monkeypatch.setattr(litellm_client, "key_list", key_list)
    set_session(
        {
            "user": portal_user(roles=["default-roles-aigw"]),
            "csrf_token": "c" * 43,
        }
    )

    response = client.get("/")

    assert response.status_code == 403
    assert called is False


def test_key_creation_uses_immutable_subject_and_rejects_bad_csrf(
    client, set_session, monkeypatch
):
    calls = []
    inventory = []

    async def key_list(user_id):
        assert user_id == "stable-oidc-sub"
        return list(inventory)

    async def key_generate(user_id, alias, project_id, project_policy=None):
        calls.append((user_id, alias, project_id))
        listed = portal_key(
            owner=user_id,
            token="hash-generated",
            alias=alias,
            project=project_id,
        )
        # Even a regressed upstream list object carrying a `key` field must not
        # cause later GETs to render that field.
        listed["key"] = "sk-generated"
        inventory.append(listed)
        return {"key": "sk-generated", "key_alias": alias}

    monkeypatch.setattr(litellm_client, "key_list", key_list)
    monkeypatch.setattr(litellm_client, "key_generate", key_generate)
    csrf = "c" * 43
    set_session({"user": portal_user(subject="stable-oidc-sub"), "csrf_token": csrf})

    bad = client.post(
        "/keys",
        data={
            "alias": "laptop",
            "project_id": "ai-gateway",
            "csrf_token": "x" * 43,
        },
        follow_redirects=False,
    )
    assert bad.status_code == 303
    assert calls == []

    good = client.post(
        "/keys",
        data={
            "alias": "laptop",
            "project_id": "ai-gateway",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    assert good.status_code == 201
    assert good.headers["content-location"] == "/"
    assert calls == [("stable-oidc-sub", "laptop", "ai-gateway")]
    assert "sk-generated" in good.text
    assert "history.replaceState" in good.text
    assert "pagehide" in good.text

    # The signed cookie is readable by the browser/user; it must contain no
    # plaintext key or key inventory/cache under any name.
    session = decoded_session(client)
    assert "sk-generated" not in json.dumps(session)
    assert "last_key" not in session
    assert "session_keys" not in session

    # Later GETs and tool-template navigation can never redisplay the key.
    later_index = client.get("/")
    later_snippets = client.get("/snippets")
    assert "sk-generated" not in later_index.text
    assert "sk-generated" not in later_snippets.text
    assert "YOUR_KEY" in later_snippets.text

    assert "no-store" in good.headers["cache-control"]
    assert good.headers["referrer-policy"] == "no-referrer"
    assert "default-src 'none'" in good.headers["content-security-policy"]


def test_post_generation_membership_failure_revokes_without_disclosure(
    client, set_session, monkeypatch
):
    """A lost live-membership decision cannot leave a disclosed static key."""

    owner = "post-generation-owner"
    inventory: list[dict] = []
    deactivated: list[str] = []
    membership_checks = 0

    async def live_projects(_request, _user):
        nonlocal membership_checks
        membership_checks += 1
        if membership_checks == 1:
            return ("ai-gateway",)
        raise main.HTTPException(
            status_code=503,
            detail="Current project membership could not be verified.",
        )

    async def key_list(user_id):
        assert user_id == owner
        return [dict(entry) for entry in inventory]

    async def key_generate(user_id, alias, project_id, project_policy=None):
        inventory.append(
            portal_key(
                owner=user_id,
                token="post-generation-hash",
                alias=alias,
                project=project_id,
            )
        )
        return {"key": "sk-must-not-disclose", "key_alias": alias}

    async def key_deactivate(key):
        deactivated.append(key)
        return {"key": key, "blocked": True}

    monkeypatch.setattr(main, "_live_project_ids", live_projects)
    monkeypatch.setattr(litellm_client, "key_list", key_list)
    monkeypatch.setattr(litellm_client, "key_generate", key_generate)
    monkeypatch.setattr(litellm_client, "key_deactivate", key_deactivate)
    csrf = "c" * 43
    set_session({"user": portal_user(subject=owner), "csrf_token": csrf})

    response = client.post(
        "/keys",
        data={
            "alias": "laptop",
            "project_id": "ai-gateway",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )

    assert response.status_code == 503
    assert membership_checks == 2
    assert deactivated == ["sk-must-not-disclose"]
    assert "sk-must-not-disclose" not in response.text
    assert all(
        "sk-must-not-disclose" not in cookie.value for cookie in client.cookies.jar
    )


def test_post_generation_cleanup_failure_never_discloses_plaintext(
    client, set_session, monkeypatch, caplog
):
    """Cleanup uncertainty remains fail-closed even if LiteLLM is unavailable."""

    owner = "cleanup-failure-owner"
    inventory: list[dict] = []
    deactivation_attempts: list[str] = []
    membership_checks = 0

    async def live_projects(_request, _user):
        nonlocal membership_checks
        membership_checks += 1
        if membership_checks == 1:
            return ("ai-gateway",)
        raise main.HTTPException(status_code=503, detail="membership unavailable")

    async def key_list(user_id):
        assert user_id == owner
        return [dict(entry) for entry in inventory]

    async def key_generate(user_id, alias, project_id, project_policy=None):
        inventory.append(
            portal_key(
                owner=user_id,
                token="cleanup-failure-hash",
                alias=alias,
                project=project_id,
            )
        )
        return {"key": "sk-cleanup-failure-secret", "key_alias": alias}

    async def key_deactivate(key):
        deactivation_attempts.append(key)
        raise litellm_client.LiteLLMError("upstream unavailable")

    monkeypatch.setattr(main, "_live_project_ids", live_projects)
    monkeypatch.setattr(litellm_client, "key_list", key_list)
    monkeypatch.setattr(litellm_client, "key_generate", key_generate)
    monkeypatch.setattr(litellm_client, "key_deactivate", key_deactivate)
    csrf = "c" * 43
    set_session({"user": portal_user(subject=owner), "csrf_token": csrf})

    response = client.post(
        "/keys",
        data={
            "alias": "laptop",
            "project_id": "ai-gateway",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )

    assert response.status_code == 503
    assert deactivation_attempts == ["sk-cleanup-failure-secret"]
    assert "sk-cleanup-failure-secret" not in response.text
    assert "sk-cleanup-failure-secret" not in caplog.text
    assert all(
        "sk-cleanup-failure-secret" not in cookie.value for cookie in client.cookies.jar
    )


@pytest.mark.asyncio
async def test_shielded_post_generation_liveness_survives_waiter_cancellation(
    monkeypatch,
):
    """A client disconnect does not cancel the already-issued-key cleanup path."""

    started = asyncio.Event()
    release = asyncio.Event()
    deactivated: list[str] = []

    async def live_projects(_request, _user):
        return ()

    async def key_deactivate(key):
        deactivated.append(key)
        started.set()
        await release.wait()
        return {"key": key, "blocked": True}

    monkeypatch.setattr(main, "_live_project_ids", live_projects)
    monkeypatch.setattr(litellm_client, "key_deactivate", key_deactivate)
    verification = main._retain_post_generation_liveness_task(
        asyncio.create_task(
            main._verify_post_generation_liveness(
                SimpleNamespace(session={}),
                portal_user(subject="cancelled-owner"),
                "ai-gateway",
                "sk-cancelled-secret",
            )
        )
    )

    async def wait_for_verification():
        await asyncio.shield(verification)

    waiter = asyncio.create_task(wait_for_verification())
    await started.wait()
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter

    assert verification.done() is False
    release.set()
    with pytest.raises(litellm_client.LiteLLMError, match="membership changed"):
        await verification
    assert deactivated == ["sk-cancelled-secret"]


def test_deactivate_denies_cross_owner_and_cross_project(
    client, set_session, monkeypatch
):
    deactivated = []

    async def key_list(user_id):
        assert user_id == "attacker-sub"
        return [
            portal_key(owner="victim-sub", token="victim-hash"),
            portal_key(
                owner="attacker-sub",
                token="other-project-hash",
                project="other-project",
            ),
        ]

    async def key_deactivate(key):
        deactivated.append(key)
        return {"key": key, "blocked": True}

    monkeypatch.setattr(litellm_client, "key_list", key_list)
    monkeypatch.setattr(litellm_client, "key_deactivate", key_deactivate)
    csrf = "c" * 43
    set_session({"user": portal_user(subject="attacker-sub"), "csrf_token": csrf})

    response = client.post(
        "/keys/deactivate",
        data={
            "token": "victim-hash",
            "project_id": "ai-gateway",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )

    # A malicious upstream owner-filter response fails the entire operation
    # closed before either victim or other-project objects can be mutated.
    assert response.status_code == 303
    assert deactivated == []


def test_existing_active_key_blocks_generation(client, set_session, monkeypatch):
    generated = False

    async def key_list(user_id):
        return [portal_key(owner=user_id, token="already-active")]

    async def key_generate(_user_id, _alias, _project_id, _project_policy=None):
        nonlocal generated
        generated = True
        return {"key": "must-not-exist"}

    monkeypatch.setattr(litellm_client, "key_list", key_list)
    monkeypatch.setattr(litellm_client, "key_generate", key_generate)
    csrf = "c" * 43
    set_session({"user": portal_user(subject="owner-sub"), "csrf_token": csrf})

    response = client.post(
        "/keys",
        data={
            "alias": "replacement",
            "project_id": "ai-gateway",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert generated is False


def test_project_identifier_cannot_authorize_another_project(monkeypatch):
    inventory = main._portal_key_inventory(
        [
            portal_key(
                owner="owner-sub",
                token="other-project-hash",
                project="other-project",
            )
        ],
        "owner-sub",
        ("ai-gateway", "other-project"),
    )

    assert (
        main._resolve_owned_project_key(inventory, "other-project-hash", "ai-gateway")
        is None
    )
    assert (
        main._resolve_owned_project_key(
            inventory, "other-project-hash", "other-project"
        )
        == "other-project-hash"
    )


def test_inactive_and_expired_keys_do_not_count_as_active():
    now = main.datetime(2026, 7, 12, tzinfo=main.timezone.utc)

    assert main._is_active_key({"blocked": True}, now=now) is False
    assert (
        main._is_active_key(
            {"blocked": False, "expires": "2026-07-12T00:00:00Z"}, now=now
        )
        is False
    )
    assert (
        main._is_active_key(
            {"blocked": False, "expires": "2026-07-13T00:00:00Z"}, now=now
        )
        is True
    )
    # Malformed upstream lifecycle data fails safe and blocks duplicates.
    assert main._is_active_key({"expires": "not-a-date"}, now=now) is True


def test_deactivation_then_regeneration(client, set_session, monkeypatch):
    owner = "owner-sub"
    state = [portal_key(owner=owner, token="old-hash", alias="old")]
    deactivated = []

    async def key_list(user_id):
        assert user_id == owner
        return [dict(entry) for entry in state]

    async def key_deactivate(key):
        deactivated.append(key)
        for entry in state:
            if entry["token"] == key:
                entry["blocked"] = True
        return {"key": key, "blocked": True}

    async def key_generate(user_id, alias, project_id, project_policy=None):
        state.append(
            portal_key(
                owner=user_id,
                token="new-hash",
                alias=alias,
                project=project_id,
            )
        )
        return {"key": "sk-new-once", "key_alias": alias}

    monkeypatch.setattr(litellm_client, "key_list", key_list)
    monkeypatch.setattr(litellm_client, "key_deactivate", key_deactivate)
    monkeypatch.setattr(litellm_client, "key_generate", key_generate)
    csrf = "c" * 43
    set_session({"user": portal_user(subject=owner), "csrf_token": csrf})

    deactivate = client.post(
        "/keys/deactivate",
        data={
            "token": "old-hash",
            "project_id": "ai-gateway",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    assert deactivate.status_code == 303
    assert deactivated == ["old-hash"]

    create = client.post(
        "/keys",
        data={
            "alias": "new",
            "project_id": "ai-gateway",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    assert create.status_code == 201
    assert "sk-new-once" in create.text
    inventory = main._portal_key_inventory(state, owner, ("ai-gateway",))
    assert len(main._active_project_keys(inventory, "ai-gateway")) == 1


def test_two_concurrent_generations_create_only_one(monkeypatch):
    owner = "concurrent-owner"
    state = []
    generate_calls = 0

    async def key_list(user_id):
        assert user_id == owner
        await asyncio.sleep(0)
        return [dict(entry) for entry in state]

    async def key_generate(user_id, alias, project_id, project_policy=None):
        nonlocal generate_calls
        generate_calls += 1
        await asyncio.sleep(0.01)
        state.append(
            portal_key(
                owner=user_id,
                token="only-hash",
                alias=alias,
                project=project_id,
            )
        )
        return {"key": "sk-only-once", "key_alias": alias}

    monkeypatch.setattr(litellm_client, "key_list", key_list)
    monkeypatch.setattr(litellm_client, "key_generate", key_generate)

    async def race():
        return await asyncio.gather(
            main._generate_project_key(owner, "only", "ai-gateway", ("ai-gateway",)),
            main._generate_project_key(owner, "second", "ai-gateway", ("ai-gateway",)),
            return_exceptions=True,
        )

    results = asyncio.run(race())

    assert generate_calls == 1
    assert sum(isinstance(result, tuple) for result in results) == 1
    assert (
        sum(isinstance(result, main.ActiveProjectKeyExists) for result in results) == 1
    )
    inventory = main._portal_key_inventory(state, owner, ("ai-gateway",))
    assert len(main._active_project_keys(inventory, "ai-gateway")) == 1


def test_malformed_generate_response_deactivates_unverified_candidate(monkeypatch):
    owner = "malformed-owner"
    state = []
    deactivated = []

    async def key_list(user_id):
        assert user_id == owner
        return [dict(entry) for entry in state]

    async def key_generate(user_id, alias, project_id, project_policy=None):
        state.append(
            portal_key(
                owner=user_id,
                token="unverified-hash",
                alias=alias,
                project=project_id,
            )
        )
        state.append(
            {
                **portal_key(
                    owner=user_id,
                    token="concurrent-operator-hash",
                    alias=alias,
                    project=project_id,
                ),
                "metadata": {
                    "created_via": "operator",
                    "aigw_project_id": project_id,
                },
            }
        )
        # `token` is the persisted identifier/hash, not the plaintext key.
        return {"token": "unverified-hash", "key_alias": alias}

    async def key_deactivate(key):
        deactivated.append(key)
        for entry in state:
            if entry["token"] == key:
                entry["blocked"] = True
        return {"key": key, "blocked": True}

    monkeypatch.setattr(litellm_client, "key_list", key_list)
    monkeypatch.setattr(litellm_client, "key_generate", key_generate)
    monkeypatch.setattr(litellm_client, "key_deactivate", key_deactivate)

    async def generate():
        return await main._generate_project_key(
            owner, "broken", "ai-gateway", ("ai-gateway",)
        )

    with pytest.raises(litellm_client.LiteLLMError, match="no bounded plaintext"):
        asyncio.run(generate())

    assert deactivated == ["unverified-hash"]
    inventory = main._portal_key_inventory(state, owner, ("ai-gateway",))
    active = main._active_project_keys(inventory, "ai-gateway")
    # The portal may not list, count, or subsequently deactivate an
    # operator-managed key even when it shares the owner/project metadata.
    assert active == []


def test_committed_key_after_generate_disconnect_is_deactivated(monkeypatch, caplog):
    owner = "disconnect-owner"
    state = [
        portal_key(
            owner=owner,
            token="preexisting-inactive-hash",
            alias="lost-response",
            blocked=True,
        )
    ]
    deactivated = []

    async def key_list(user_id):
        assert user_id == owner
        return [dict(entry) for entry in state]

    async def key_generate(user_id, alias, project_id, project_policy=None):
        # Model LiteLLM committing before the response connection is lost.
        state.append(
            portal_key(
                owner=user_id,
                token="committed-undisclosed-hash",
                alias=alias,
                project=project_id,
            )
        )
        # A concurrent non-portal key must never be swept up by reconciliation,
        # even though it is new, active, and has the same owner/project/alias.
        state.append(
            {
                **portal_key(
                    owner=user_id,
                    token="concurrent-operator-hash",
                    alias=alias,
                    project=project_id,
                ),
                "metadata": {
                    "created_via": "operator",
                    "aigw_project_id": project_id,
                },
            }
        )
        raise litellm_client.LiteLLMError("could not reach LiteLLM")

    async def key_deactivate(key):
        deactivated.append(key)
        for entry in state:
            if entry["token"] == key:
                entry["blocked"] = True
        return {"key": key, "blocked": True}

    monkeypatch.setattr(litellm_client, "key_list", key_list)
    monkeypatch.setattr(litellm_client, "key_generate", key_generate)
    monkeypatch.setattr(litellm_client, "key_deactivate", key_deactivate)

    async def generate():
        return await main._generate_project_key(
            owner, "lost-response", "ai-gateway", ("ai-gateway",)
        )

    with pytest.raises(litellm_client.LiteLLMError, match="could not reach"):
        asyncio.run(generate())

    assert deactivated == ["committed-undisclosed-hash"]
    assert state[0]["blocked"] is True
    assert state[1]["blocked"] is True
    assert state[2]["blocked"] is not True
    assert "committed-undisclosed-hash" not in caplog.text
    assert "concurrent-operator-hash" not in caplog.text


def test_ambiguous_generate_cleanup_refuses_unbounded_candidate_set(
    monkeypatch, caplog
):
    owner = "ambiguous-flood-owner"
    state = []
    deactivated = []

    async def key_list(user_id):
        assert user_id == owner
        return [dict(entry) for entry in state]

    async def key_generate(user_id, alias, project_id, project_policy=None):
        state.extend(
            portal_key(
                owner=user_id,
                token=f"candidate-{index}",
                alias=alias,
                project=project_id,
            )
            for index in range(main.AMBIGUOUS_GENERATE_CLEANUP_LIMIT + 1)
        )
        raise litellm_client.LiteLLMError("could not reach LiteLLM")

    async def key_deactivate(key):
        deactivated.append(key)
        return {"key": key, "blocked": True}

    monkeypatch.setattr(litellm_client, "key_list", key_list)
    monkeypatch.setattr(litellm_client, "key_generate", key_generate)
    monkeypatch.setattr(litellm_client, "key_deactivate", key_deactivate)

    async def generate():
        return await main._generate_project_key(
            owner, "flood", "ai-gateway", ("ai-gateway",)
        )

    with pytest.raises(litellm_client.LiteLLMError, match="could not reach"):
        asyncio.run(generate())

    assert deactivated == []
    assert "candidate-" not in caplog.text


def test_post_generate_duplicate_is_cleaned_up_without_disclosure(monkeypatch):
    owner = "verification-owner"
    state = []
    deactivated = []

    async def key_list(user_id):
        assert user_id == owner
        return [dict(entry) for entry in state]

    async def key_generate(user_id, alias, project_id, project_policy=None):
        # Model a future unsupported second replica racing this worker after
        # both observed an empty inventory.
        state.extend(
            [
                portal_key(
                    owner=user_id,
                    token="our-hash",
                    alias=alias,
                    project=project_id,
                ),
                portal_key(
                    owner=user_id,
                    token="racer-hash",
                    alias="racer",
                    project=project_id,
                ),
            ]
        )
        return {"key": "sk-unverified", "key_alias": alias}

    async def key_deactivate(key):
        deactivated.append(key)
        # LiteLLM accepts the newly generated plaintext for /key/update.
        if key == "sk-unverified":
            state[0]["blocked"] = True
        return {"key": key, "blocked": True}

    monkeypatch.setattr(litellm_client, "key_list", key_list)
    monkeypatch.setattr(litellm_client, "key_generate", key_generate)
    monkeypatch.setattr(litellm_client, "key_deactivate", key_deactivate)

    async def generate():
        return await main._generate_project_key(
            owner, "ours", "ai-gateway", ("ai-gateway",)
        )

    with pytest.raises(litellm_client.LiteLLMError, match="one-active-key"):
        asyncio.run(generate())

    assert deactivated == ["sk-unverified"]
    inventory = main._portal_key_inventory(state, owner, ("ai-gateway",))
    active = main._active_project_keys(inventory, "ai-gateway")
    assert [entry["token"] for entry in active] == ["racer-hash"]


def test_portal_inventory_never_exposes_or_deactivates_operator_key(
    client, set_session, monkeypatch
):
    owner = "owner-sub"
    deactivated: list[str] = []
    operator_key = {
        "token": "operator-controlled-hash",
        "key_alias": "break-glass",
        "user_id": owner,
        # A native project ID is not portal provenance.  Nor is an arbitrary
        # metadata project copied from a different control-plane workflow.
        "project_id": "ai-gateway",
        "metadata": {
            "created_via": "operator",
            "aigw_project_id": "ai-gateway",
        },
    }

    assert main._portal_key_inventory([operator_key], owner, ("ai-gateway",)) == []

    async def key_list(user_id):
        assert user_id == owner
        return [operator_key]

    async def key_deactivate(key):
        deactivated.append(key)
        return {"key": key, "blocked": True}

    monkeypatch.setattr(litellm_client, "key_list", key_list)
    monkeypatch.setattr(litellm_client, "key_deactivate", key_deactivate)
    csrf = "c" * 43
    set_session({"user": portal_user(subject=owner), "csrf_token": csrf})

    response = client.post(
        "/keys/deactivate",
        data={
            "token": "operator-controlled-hash",
            "project_id": "ai-gateway",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )

    assert response.status_code == 403
    assert deactivated == []


def test_malformed_portal_metadata_fails_closed_for_key_lifecycle():
    malformed_portal_key = {
        "token": "opaque-hash",
        "user_id": "owner-sub",
        "metadata": {"created_via": "dev-portal", "aigw_project_id": "Bad ID"},
    }

    with pytest.raises(litellm_client.LiteLLMError, match="unambiguous project"):
        main._portal_key_inventory([malformed_portal_key], "owner-sub", ("ai-gateway",))


def test_admin_template_contains_injection_and_cache_defenses(
    admin_client, set_admin_session, monkeypatch
):
    malicious_vendor = "x');alert(document.domain);('"
    malicious_history = "<img src=x onerror=alert(1)>"

    async def rotator_get(path):
        if path == "/identity/authorization/subject-123":
            return {"admin": True}
        if path == "/status":
            return {"ok": True}
        if path == "/settings":
            return {
                "vendors": [
                    {"vendor": malicious_vendor, "enabled": True},
                    {"vendor": "openai", "enabled": True, "interval_seconds": 3600},
                ]
            }
        if path.startswith("/history"):
            return {"history": [{"detail": malicious_history}]}
        raise AssertionError(path)

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    set_admin_session({"user": portal_user(roles=[settings.admin_role])})

    response = admin_client.get("/admin")

    assert response.status_code == 200
    assert malicious_vendor not in response.text
    assert malicious_history not in response.text
    assert "&lt;img src=x onerror=alert(1)&gt;" in response.text
    assert "onsubmit=" not in response.text
    assert "no-store" in response.headers["cache-control"]
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    nonce = re.search(
        r"script-src 'nonce-([^']+)'", response.headers["content-security-policy"]
    )
    assert nonce and f'nonce="{nonce.group(1)}"' in response.text


def test_admin_template_cannot_toggle_anthropic_outside_typed_lifecycle(
    admin_client, set_admin_session, monkeypatch
):
    async def rotator_get(path):
        if path == "/identity/authorization/subject-123":
            return {"admin": True}
        if path == "/status":
            return []
        if path == "/settings":
            return [
                {
                    "vendor": "anthropic",
                    "enabled": True,
                    "interval_seconds": 3000,
                    "grace_seconds": 300,
                }
            ]
        if path.startswith("/history"):
            return []
        if path == "/providers/anthropic":
            return {
                "vendor": "anthropic",
                "state": "configured",
                "configured": True,
                "enabled": True,
                "private_key_jwt_ready": True,
                "nonsecret_ids": {},
                "setup_bundle": {},
            }
        if path == "/identity/status":
            return None
        raise AssertionError(path)

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    set_admin_session({"user": portal_user(roles=[settings.admin_role])})

    response = admin_client.get("/admin")

    assert response.status_code == 200
    assert (
        "Enable/disable is managed only by the confirmed Anthropic WIF" in response.text
    )
    assert '<input type="hidden" name="enabled" value="1">' in response.text
    assert "Rotation enabled" not in response.text


def test_invalid_vendor_path_never_reaches_rotator(
    admin_client, set_admin_session, monkeypatch
):
    called = False

    async def rotator_post(_path):
        nonlocal called
        called = True
        return {}

    async def rotator_get(path):
        assert path == "/identity/authorization/subject-123"
        return {"admin": True}

    monkeypatch.setattr(main, "_rotator_post", rotator_post)
    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    csrf = "c" * 43
    set_admin_session(
        {"user": portal_user(roles=[settings.admin_role]), "csrf_token": csrf}
    )

    response = admin_client.post(
        "/admin/rotate/bad%24vendor",
        data={"csrf_token": csrf},
    )

    assert response.status_code == 422
    assert called is False


def test_api_documentation_surface_is_disabled(client):
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_session_cookie_is_lax_for_oidc_callback_state(
    client, set_session, monkeypatch
):
    async def key_list(_user_id):
        return []

    monkeypatch.setattr(litellm_client, "key_list", key_list)
    set_session({"user": portal_user()})

    # Rendering the page creates a CSRF token and therefore reissues the
    # session cookie. OIDC's cross-site top-level callback needs SameSite=Lax;
    # Strict would omit Authlib's state/nonce cookie and fail every login.
    response = client.get("/")
    assert response.status_code == 200
    assert "samesite=lax" in response.headers["set-cookie"].lower()


def test_rotator_client_does_not_inherit_proxy_or_follow_redirects(monkeypatch):
    captured = {}

    class FakeClient:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, url, headers):
            request = httpx.Request("GET", url)
            return httpx.Response(200, json={"ok": True}, request=request)

    monkeypatch.setattr(main.httpx, "AsyncClient", FakeClient)

    import asyncio

    assert asyncio.run(main._rotator_get("/status")) == {"ok": True}
    assert captured["trust_env"] is False
    assert captured["follow_redirects"] is False


def test_identity_mutation_requires_fresh_keycloak_step_up(
    admin_client, set_admin_session, monkeypatch
):
    called = False

    async def rotator_post(path, payload=None):
        nonlocal called
        called = True
        return {}

    async def rotator_get(path):
        assert path == "/identity/authorization/subject-123"
        return {"admin": True}

    monkeypatch.setattr(main, "_rotator_post", rotator_post)
    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    csrf = "c" * 43
    set_admin_session(
        {"user": portal_user(roles=[settings.admin_role]), "csrf_token": csrf}
    )

    response = admin_client.post(
        "/admin/identity/groups",
        data={
            "name": "platform-team",
            "capabilities": "aigw-developers",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/admin/reauth"
    assert called is False


def test_recent_step_up_allows_only_allowlisted_group_capabilities(
    admin_client, set_admin_session, monkeypatch
):
    calls = []

    async def rotator_post(path, payload=None):
        calls.append((path, payload))
        return {}

    async def rotator_get(path):
        assert path == "/identity/authorization/subject-123"
        return {"admin": True}

    monkeypatch.setattr(main, "_rotator_post", rotator_post)
    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    csrf = "c" * 43
    base_session = {
        "user": portal_user(roles=[settings.admin_role]),
        "csrf_token": csrf,
        "admin_reauth_at": int(time.time()),
    }
    set_admin_session(base_session)

    rejected = admin_client.post(
        "/admin/identity/groups",
        data={
            "name": "bad-team",
            "capabilities": "realm-admin",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    assert rejected.status_code == 303
    assert calls == []

    # The first response re-signed the session with a flash; restore a clean,
    # fresh marker and submit an allowlisted capability.
    set_admin_session(base_session)
    accepted = admin_client.post(
        "/admin/identity/groups",
        data={
            "name": "platform-team",
            "capabilities": ["aigw-developers", "aigw-users"],
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    assert accepted.status_code == 303
    assert calls == [
        (
            "/identity/groups",
            {
                "name": "platform-team",
                "capabilities": ["aigw-developers", "aigw-users"],
            },
        )
    ]


def test_revoked_admin_cookie_cannot_mutate_or_restore_membership(
    admin_client, set_admin_session, monkeypatch
):
    called = False

    async def rotator_get(path):
        assert path == "/identity/authorization/revoked-admin"
        return {"admin": False}

    async def rotator_put(path, payload):
        nonlocal called
        called = True
        return None

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(main, "_rotator_put", rotator_put)
    csrf = "c" * 43
    set_admin_session(
        {
            "user": portal_user(subject="revoked-admin", roles=[settings.admin_role]),
            "csrf_token": csrf,
            "admin_reauth_at": int(time.time()),
        }
    )

    response = admin_client.post(
        "/admin/identity/groups/admins/members",
        data={"user_id": "revoked-admin", "csrf_token": csrf},
        follow_redirects=False,
    )

    assert response.status_code == 403
    assert called is False
    assert "aigw_admin_session=" in response.headers.get("set-cookie", "")


def test_revoked_admin_cookie_cannot_change_rotation_controls(
    admin_client, set_admin_session, monkeypatch
):
    called = False

    async def rotator_get(path):
        assert path == "/identity/authorization/revoked-admin"
        return {"admin": False}

    async def rotator_post(path, payload=None):
        nonlocal called
        called = True
        return None

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(main, "_rotator_post", rotator_post)
    csrf = "c" * 43
    set_admin_session(
        {
            "user": portal_user(subject="revoked-admin", roles=[settings.admin_role]),
            "csrf_token": csrf,
        }
    )

    response = admin_client.post(
        "/admin/rotate/openai",
        data={"csrf_token": csrf},
        follow_redirects=False,
    )

    assert response.status_code == 403
    assert called is False


def test_revoked_admin_cookie_cannot_read_admin_control_plane(
    admin_client, set_admin_session, monkeypatch
):
    requested: list[str] = []

    async def rotator_get(path):
        requested.append(path)
        if path == "/identity/authorization/revoked-admin":
            return {"admin": False}
        raise AssertionError("revoked admin reached sensitive control-plane reads")

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    set_admin_session(
        {"user": portal_user(subject="revoked-admin", roles=[settings.admin_role])}
    )

    response = admin_client.get("/admin", follow_redirects=False)

    assert response.status_code == 403
    assert requested == ["/identity/authorization/revoked-admin"]
    assert "aigw_admin_session=" in response.headers.get("set-cookie", "")


def test_signed_admin_sees_only_bounded_controls_while_vault_is_sealed(
    admin_client, set_admin_session, monkeypatch
):
    requested: list[str] = []

    async def rotator_get(path):
        requested.append(path)
        if path == "/identity/authorization/subject-123":
            raise sealed_authorization_error()
        if path == "/vault/public-status":
            return {"initialized": True, "sealed": True}
        raise AssertionError("sealed maintenance page reached a data endpoint")

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    set_admin_session(
        {
            "user": portal_user(roles=[settings.admin_role]),
            "csrf_token": "c" * 43,
        }
    )

    response = admin_client.get("/admin", follow_redirects=False)

    assert response.status_code == 200
    assert requested == [
        "/identity/authorization/subject-123",
        "/vault/public-status",
    ]
    assert "Vault is sealed" in response.text
    assert "Managed groups" in response.text
    assert "Create project group" in response.text
    assert "Directory-user assignment" in response.text
    assert "State:</strong> unavailable" in response.text
    assert "disabled" in response.text
    assert "developer@example.test" not in response.text
    assert "subject-123" not in response.text
    assert "Developer" not in response.text
    assert "<form" not in response.text


@pytest.mark.parametrize(
    "public_status",
    [
        {"initialized": True, "sealed": False},
        {"initialized": False, "sealed": True},
        {"initialized": True, "sealed": True, "unexpected": "field"},
        None,
    ],
)
def test_admin_maintenance_fails_closed_without_exact_sealed_vault_state(
    admin_client, set_admin_session, monkeypatch, public_status
):
    async def rotator_get(path):
        if path == "/identity/authorization/subject-123":
            raise sealed_authorization_error()
        if path == "/vault/public-status":
            return public_status
        raise AssertionError(path)

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    set_admin_session({"user": portal_user(roles=[settings.admin_role])})

    response = admin_client.get("/admin", follow_redirects=False)

    assert response.status_code == 503
    assert "Vault is sealed" not in response.text


def test_non_vault_authorization_failure_cannot_enter_sealed_maintenance(
    admin_client, set_admin_session, monkeypatch
):
    requested: list[str] = []

    async def rotator_get(path):
        requested.append(path)
        if path in {
            "/identity/authorization/subject-123",
            "/identity/status",
        }:
            raise httpx.ConnectError("non-Vault control-plane failure")
        if path == "/vault/public-status":
            raise AssertionError("generic failure probed the maintenance state")
        raise AssertionError(path)

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    set_admin_session({"user": portal_user(roles=[settings.admin_role])})

    response = admin_client.get("/admin", follow_redirects=False)

    assert response.status_code == 503
    assert "Vault is sealed" not in response.text
    assert requested == [
        "/identity/authorization/subject-123",
        "/identity/status",
    ]


def test_roleless_and_expired_sessions_never_probe_sealed_maintenance_state(
    admin_client, set_admin_session, monkeypatch
):
    requested: list[str] = []

    async def rotator_get(path):
        requested.append(path)
        raise AssertionError("unauthorized session reached the rotator")

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    set_admin_session({"user": portal_user(roles=[settings.developer_role])})
    assert admin_client.get("/admin", follow_redirects=False).status_code == 403
    assert requested == []

    admin_client.cookies.clear()
    old_timestamp = int(time.time()) - settings.session_max_age_seconds - 60
    with monkeypatch.context() as old_clock:
        old_clock.setattr(
            "itsdangerous.timed.time.time",
            lambda: old_timestamp,
        )
        stale = session_cookie(
            {"user": portal_user(roles=[settings.admin_role])}
        )
    admin_client.cookies.set("aigw_admin_session", stale)

    response = admin_client.get("/admin", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert requested == []


def test_sealed_maintenance_never_relaxes_admin_mutation_dependencies(
    admin_client, set_admin_session, monkeypatch
):
    requested: list[str] = []
    mutated = False

    async def rotator_get(path):
        requested.append(path)
        if path == "/identity/authorization/subject-123":
            raise sealed_authorization_error()
        raise AssertionError(path)

    async def rotator_post(_path, _payload=None):
        nonlocal mutated
        mutated = True

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(main, "_rotator_post", rotator_post)
    csrf = "c" * 43
    set_admin_session(
        {
            "user": portal_user(roles=[settings.admin_role]),
            "admin_reauth_at": int(time.time()),
            "csrf_token": csrf,
        }
    )

    response = admin_client.post(
        "/admin/identity/groups",
        data={"name": "project-a", "capabilities": "aigw-users", "csrf_token": csrf},
        follow_redirects=False,
    )

    assert response.status_code == 503
    assert mutated is False
    assert requested == ["/identity/authorization/subject-123"]


def test_user_and_admin_route_surfaces_are_disjoint(client, admin_client):
    assert client.get("/admin", follow_redirects=False).status_code == 404
    assert admin_client.get("/keys", follow_redirects=False).status_code == 404
    assert admin_client.get("/snippets", follow_redirects=False).status_code == 404


def test_user_and_admin_session_cookies_cannot_cross_authorize(
    client, admin_client, set_session, set_admin_session
):
    set_admin_session(
        {"user": portal_user(subject="admin-sub", roles=[settings.admin_role])}
    )
    admin_cookie = next(
        cookie.value
        for cookie in admin_client.cookies.jar
        if cookie.name == "aigw_admin_session"
    )
    admin_client.cookies.clear()
    client.cookies.clear()
    client.cookies.set(
        "aigw_admin_session", admin_cookie, domain="portal.test", path="/"
    )

    user_response = client.get("/", follow_redirects=False)
    assert user_response.status_code == 303
    assert user_response.headers["location"] == "/login"

    set_session({"user": portal_user(subject="admin-sub", roles=[settings.admin_role])})
    portal_cookie = next(
        cookie.value
        for cookie in client.cookies.jar
        if cookie.name == "aigw_portal_session"
    )
    client.cookies.clear()
    admin_client.cookies.set(
        "aigw_portal_session",
        portal_cookie,
        domain="admin.test",
        path="/",
    )

    admin_response = admin_client.get("/admin", follow_redirects=False)
    assert admin_response.status_code == 303
    assert admin_response.headers["location"] == "/login"


@pytest.mark.asyncio
async def test_live_project_lookup_sorts_canonical_membership(monkeypatch):
    async def rotator_get(path):
        assert path == "/identity/projects/subject-123"
        return {"projects": ["project-b", "project-a"]}

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    request = SimpleNamespace(session={})

    assert await LIVE_PROJECT_IDS(request, portal_user()) == (
        "project-a",
        "project-b",
    )


def test_provider_status_allowlists_only_public_enrollment_material() -> None:
    raw = {
        "vendor": "anthropic",
        "state": "configured",
        "configured": True,
        "enabled": True,
        "private_key_jwt_ready": True,
        "nonsecret_ids": {
            "organization_id": "org_test",
            "service_account_id": "svcacct_test",
            "federation_rule_id": "rule_test",
            "workspace_id": "workspace_test",
            "admin_api_key": "must-not-cross",
        },
        "client_certificate_sha256": "a" * 64,
        "current_jwks_sha256": "b" * 64,
        "approved_jwks_sha256": "b" * 64,
        "private_key_pem": "-----BEGIN PRIVATE KEY-----",
        "kc_token_url": "http://keycloak:8080/token",
        "setup_bundle": {
            "issuer": "https://idp.wif.example/realms/anthropic-wif",
            "client_id": "anthropic-token-broker",
            "subject": "service-account-anthropic-token-broker",
            "audience": "https://api.anthropic.com",
            "jwks": {
                "keys": [
                    {
                        "kty": "RSA",
                        "kid": "public-kid",
                        "alg": "RS256",
                        "use": "sig",
                        "n": "public-modulus",
                        "e": "AQAB",
                        "private_key_pem": "must-not-cross",
                    }
                ]
            },
            "client_secret": "must-not-cross",
        },
    }

    safe = main._safe_provider_status(raw)

    assert safe is not None
    encoded = json.dumps(safe)
    assert "org_test" in encoded
    assert "public-modulus" in encoded
    for forbidden in (
        "PRIVATE KEY",
        "must-not-cross",
        "client_secret",
        "admin_api_key",
        "kc_token_url",
        "private_key_pem",
    ):
        assert forbidden not in encoded


def test_provider_configure_is_step_up_csrf_and_schema_bounded(
    admin_client, set_admin_session, monkeypatch
):
    calls: list[tuple[str, dict]] = []

    async def rotator_get(path):
        assert path == "/identity/authorization/subject-123"
        return {"admin": True}

    async def rotator_put(path, payload):
        calls.append((path, payload))
        return {"changed": True}

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(main, "_rotator_put", rotator_put)
    csrf = "c" * 43
    set_admin_session(
        {
            "user": portal_user(roles=[settings.admin_role]),
            "csrf_token": csrf,
            "admin_reauth_at": int(time.time()),
        }
    )

    response = admin_client.post(
        "/admin/providers/anthropic",
        data={
            "organization_id": "org_test",
            "service_account_id": "svcacct_test",
            "federation_rule_id": "rule_test",
            "workspace_id": "workspace_test",
            "federation_jwks_sha256": "b" * 64,
            "enrollment_confirmation": "ENROLLED",
            "kc_token_url": "https://evil.example/token",
            "private_key_pem": "must-not-cross",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert calls == [
        (
            "/providers/anthropic",
            {
                "organization_id": "org_test",
                "service_account_id": "svcacct_test",
                "federation_rule_id": "rule_test",
                "workspace_id": "workspace_test",
                "federation_jwks_sha256": "b" * 64,
                "enrollment_confirmation": "ENROLLED",
            },
        )
    ]


def test_provider_mutations_reject_wrong_confirmation_before_rotator(
    admin_client, set_admin_session, monkeypatch
):
    called = False

    async def rotator_get(path):
        assert path == "/identity/authorization/subject-123"
        return {"admin": True}

    async def unexpected(*_args, **_kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(main, "_rotator_post", unexpected)
    monkeypatch.setattr(main, "_rotator_delete", unexpected)
    csrf = "c" * 43
    session = {
        "user": portal_user(roles=[settings.admin_role]),
        "csrf_token": csrf,
        "admin_reauth_at": int(time.time()),
    }

    set_admin_session(session)
    disable = admin_client.post(
        "/admin/providers/anthropic/disable",
        data={"confirmation": "DISABLE", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert disable.status_code == 303

    set_admin_session(session)
    delete = admin_client.post(
        "/admin/providers/anthropic/delete",
        data={"confirmation": "delete", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert delete.status_code == 303
    assert called is False


def test_user_portal_has_no_provider_admin_routes(client) -> None:
    assert client.post("/admin/providers/anthropic").status_code == 404
    assert client.post("/admin/providers/anthropic/disable").status_code == 404
    assert client.post("/admin/providers/anthropic/delete").status_code == 404


@pytest.mark.asyncio
async def test_live_project_lookup_upstream_failure_is_503(monkeypatch):
    async def rotator_get(_path):
        raise httpx.ConnectError("identity controller unavailable")

    monkeypatch.setattr(main, "_rotator_get", rotator_get)

    with pytest.raises(main.HTTPException) as caught:
        await LIVE_PROJECT_IDS(SimpleNamespace(session={}), portal_user())

    assert caught.value.status_code == 503
    assert caught.value.detail == "Current project membership could not be verified."


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"projects": "project-a"},
        {"projects": ["project-a", "project-a"]},
        {"projects": ["Project-A"]},
        {"projects": ["../unmanaged"]},
    ],
)
async def test_live_project_lookup_ambiguous_payload_is_503(monkeypatch, payload):
    async def rotator_get(_path):
        return payload

    monkeypatch.setattr(main, "_rotator_get", rotator_get)

    with pytest.raises(main.HTTPException) as caught:
        await LIVE_PROJECT_IDS(SimpleNamespace(session={}), portal_user())

    assert caught.value.status_code == 503
    assert caught.value.detail == "Current project membership was ambiguous."


def test_admin_reauth_requests_prompt_login_and_max_age_zero(
    admin_client, set_admin_session, monkeypatch
):
    captured = {}

    async def ensure_client():
        return None

    class FakeKeycloak:
        async def authorize_redirect(self, request, redirect_uri, **kwargs):
            captured["redirect_uri"] = redirect_uri
            captured["kwargs"] = kwargs
            captured["session"] = dict(request.session)
            return main.RedirectResponse("https://idp.test/authorize", status_code=302)

    monkeypatch.setattr(main.auth, "ensure_oauth_client", ensure_client)
    monkeypatch.setattr(main.auth, "oauth", SimpleNamespace(keycloak=FakeKeycloak()))
    set_admin_session(
        {"user": portal_user(subject="admin-sub", roles=[settings.admin_role])}
    )

    response = admin_client.get("/admin/reauth", follow_redirects=False)

    assert response.status_code == 302
    assert captured["kwargs"] == {"prompt": "login", "max_age": 0}
    assert captured["session"]["admin_step_up_subject"] == "admin-sub"
    assert captured["redirect_uri"].endswith("/auth/callback")


def test_identity_upstream_group_ambiguity_fails_closed(
    admin_client, set_admin_session, monkeypatch
):
    async def rotator_get(path):
        if path == "/identity/authorization/subject-123":
            return {"admin": True}
        if path == "/status":
            return []
        if path == "/settings":
            return []
        if path.startswith("/history"):
            return []
        if path == "/identity/status":
            return {
                "configured": True,
                "controller_usable": True,
                "bootstrap_available": False,
                "ldap_configured": True,
                "controller_certificate_sha256": "a" * 64,
                "broker_certificate_sha256": "PRIVATE KEY",
            }
        if path == "/identity/groups":
            return [
                {
                    "id": "../../admin",
                    "name": "malicious",
                    "capabilities": ["aigw-admins"],
                    "member_count": 0,
                },
                {
                    "id": "safe-group-id",
                    "name": "Safe Group",
                    "capabilities": ["aigw-users"],
                    "member_count": 0,
                },
            ]
        if path.startswith("/identity/users?"):
            return []
        raise AssertionError(path)

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    set_admin_session({"user": portal_user(roles=[settings.admin_role])})

    response = admin_client.get("/admin")

    assert response.status_code == 200
    assert "../../admin" not in response.text
    assert "malicious" not in response.text
    assert "safe-group-id" not in response.text
    assert "Could not reach the identity controller" in response.text
    assert "PRIVATE KEY" not in response.text


def test_admin_page_surfaces_break_glass_escrow_state(
    admin_client, set_admin_session, monkeypatch
):
    """The runbook's portal confirmation step needs the escrow state visible,
    and a brownfield policy gap must render as actionable, not as healthy."""

    status = {
        "configured": True,
        "controller_usable": True,
        "bootstrap_available": False,
        "ldap_configured": True,
        "break_glass_escrowed": True,
        "break_glass_escrow_readable": True,
        "vault_oidc_rp_escrowed": True,
        "vault_oidc_rp_escrow_readable": True,
        "controller_certificate_sha256": "a" * 64,
        "broker_certificate_sha256": "b" * 64,
    }

    async def rotator_get(path):
        if path == "/identity/authorization/subject-123":
            return {"admin": True}
        if path in {"/status", "/settings"} or path.startswith("/history"):
            return []
        if path == "/identity/status":
            return dict(status)
        if path == "/identity/groups" or path.startswith("/identity/users?"):
            return []
        raise AssertionError(path)

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    set_admin_session({"user": portal_user(roles=[settings.admin_role])})

    escrowed = admin_client.get("/admin")
    assert escrowed.status_code == 200
    assert "Break-glass escrow: escrowed" in escrowed.text
    assert "Vault OIDC client escrow: escrowed" in escrowed.text

    status["break_glass_escrowed"] = False
    status["break_glass_escrow_readable"] = False
    unreadable = admin_client.get("/admin")
    assert unreadable.status_code == 200
    assert "rotator Vault policy predates the escrow path" in unreadable.text

    status["break_glass_escrow_readable"] = True
    missing = admin_client.get("/admin")
    assert missing.status_code == 200
    assert "Break-glass escrow: not escrowed" in missing.text

    status["vault_oidc_rp_escrowed"] = False
    status["vault_oidc_rp_escrow_readable"] = True
    vault_missing = admin_client.get("/admin")
    assert vault_missing.status_code == 200
    assert "Vault OIDC client escrow: not escrowed" in vault_missing.text


def test_safe_identity_status_maps_break_glass_booleans_only():
    mapped = main._safe_identity_status(
        {
            "configured": True,
            "break_glass_escrowed": True,
            "break_glass_escrow_readable": False,
            "vault_oidc_rp_escrowed": True,
            "vault_oidc_rp_escrow_readable": False,
            "password": "must-never-cross",
            "client_secret": "must-never-cross-either",
        }
    )
    assert mapped["break_glass_escrowed"] is True
    assert mapped["break_glass_escrow_readable"] is False
    assert mapped["vault_oidc_rp_escrowed"] is True
    assert mapped["vault_oidc_rp_escrow_readable"] is False
    assert "password" not in mapped
    assert "client_secret" not in mapped
    # A pre-upgrade rotator that omits the readable field must not render as
    # a policy gap: absence defaults to readable.
    legacy = main._safe_identity_status({"configured": True})
    assert legacy["break_glass_escrowed"] is False
    assert legacy["break_glass_escrow_readable"] is True
    assert legacy["vault_oidc_rp_escrowed"] is False
    assert legacy["vault_oidc_rp_escrow_readable"] is True


# --- admin / gateway key inventory ------------------------------------------


def full_key_object(**overrides) -> dict:
    entry = {
        "token": "inv-hash-1",
        "key_name": "sk-...abcd",
        "key_alias": "ops-key",
        "user_id": "owner-1",
        "team_id": "",
        "models": ["claude-sonnet"],
        "spend": 1.25,
        "max_budget": 25.0,
        "tpm_limit": 100000,
        "rpm_limit": 60,
        "expires": "2027-01-01T00:00:00+00:00",
        "created_at": "2026-07-01T00:00:00+00:00",
        "blocked": False,
        "metadata": {},
    }
    entry.update(overrides)
    return entry


def test_user_portal_has_no_admin_key_routes(client) -> None:
    assert client.get("/admin/keys", follow_redirects=False).status_code == 404
    assert (
        client.post("/admin/keys/block", follow_redirects=False).status_code == 404
    )
    assert (
        client.post("/admin/keys/unblock", follow_redirects=False).status_code == 404
    )
    assert (
        client.post("/admin/keys/limits", follow_redirects=False).status_code == 404
    )


def test_admin_key_inventory_denies_revoked_admin_before_litellm(
    admin_client, set_admin_session, monkeypatch
):
    called = False

    async def rotator_get(path):
        assert path == "/identity/authorization/revoked-admin"
        return {"admin": False}

    async def admin_key_list_page(page):
        nonlocal called
        called = True
        return {"keys": [], "page": 1, "total_pages": 0, "total_count": 0}

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(litellm_client, "admin_key_list_page", admin_key_list_page)
    set_admin_session(
        {"user": portal_user(subject="revoked-admin", roles=[settings.admin_role])}
    )

    response = admin_client.get("/admin/keys", follow_redirects=False)

    assert response.status_code == 403
    assert called is False


def test_admin_key_inventory_fails_closed_while_vault_is_sealed(
    admin_client, set_admin_session, monkeypatch
):
    async def rotator_get(path):
        if path == "/identity/authorization/subject-123":
            raise sealed_authorization_error()
        raise AssertionError("sealed inventory request reached a data endpoint")

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    set_admin_session({"user": portal_user(roles=[settings.admin_role])})

    response = admin_client.get("/admin/keys", follow_redirects=False)

    # No maintenance fallback here: the inventory is sensitive data, not a
    # bounded unseal control, so a sealed Vault keeps it entirely closed.
    assert response.status_code == 503


def test_admin_key_inventory_lists_without_rendering_plaintext(
    admin_client, set_admin_session, monkeypatch
):
    async def rotator_get(path):
        assert path == "/identity/authorization/subject-123"
        return {"admin": True}

    async def admin_key_list_page(page):
        assert page == 1
        return {
            "keys": [
                # A regressed upstream shape must never surface a plaintext
                # credential or unescaped markup through this page.
                full_key_object(
                    key="sk-plaintext-LEAK-me",
                    key_alias="<script>alert(1)</script>",
                ),
                full_key_object(
                    token="portal-hash-2",
                    key_alias="dev-key",
                    user_id="dev-subject",
                    metadata={
                        "created_via": "dev-portal",
                        "aigw_project_id": "ai-gateway",
                    },
                ),
            ],
            "page": 1,
            "total_pages": 1,
            "total_count": 2,
        }

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(litellm_client, "admin_key_list_page", admin_key_list_page)
    set_admin_session({"user": portal_user(roles=[settings.admin_role])})

    response = admin_client.get("/admin/keys")

    assert response.status_code == 200
    assert "sk-plaintext-LEAK-me" not in response.text
    assert "<script>alert(1)</script>" not in response.text
    assert "portal: ai-gateway" in response.text
    assert "operator" in response.text
    assert "inv-hash-1"[:16] in response.text


def test_admin_key_mutations_require_fresh_step_up(
    admin_client, set_admin_session, monkeypatch
):
    called = False

    async def rotator_get(path):
        return {"admin": True}

    async def admin_key_lookup(token):
        nonlocal called
        called = True
        return full_key_object()

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(litellm_client, "admin_key_lookup", admin_key_lookup)
    csrf = "c" * 43
    set_admin_session(
        {"user": portal_user(roles=[settings.admin_role]), "csrf_token": csrf}
    )

    for path in ("/admin/keys/block", "/admin/keys/unblock", "/admin/keys/limits"):
        response = admin_client.post(
            path,
            data={"token": "inv-hash-1", "csrf_token": csrf, "max_budget": "10"},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert response.headers["location"] == "/admin/reauth"
    assert called is False


def test_admin_key_mutations_reject_bad_csrf_before_litellm(
    admin_client, set_admin_session, monkeypatch
):
    called = False

    async def rotator_get(path):
        return {"admin": True}

    async def admin_key_lookup(token):
        nonlocal called
        called = True
        return full_key_object()

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(litellm_client, "admin_key_lookup", admin_key_lookup)
    set_admin_session(
        {
            "user": portal_user(roles=[settings.admin_role]),
            "csrf_token": "c" * 43,
            "admin_reauth_at": int(time.time()),
        }
    )

    response = admin_client.post(
        "/admin/keys/block",
        data={"token": "inv-hash-1", "csrf_token": "x" * 43},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/admin/keys?page=1"
    assert called is False


def test_admin_key_block_resolves_exact_hash_and_verifies_the_effect(
    admin_client, set_admin_session, monkeypatch
):
    state = {"blocked": False}
    updates_sent = []
    lookups = []

    async def rotator_get(path):
        return {"admin": True}

    async def admin_key_lookup(token):
        lookups.append(token)
        return full_key_object(blocked=state["blocked"])

    async def key_update(key, updates):
        assert key == "inv-hash-1"
        updates_sent.append(updates)
        state["blocked"] = updates.get("blocked", state["blocked"])
        return {}

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(litellm_client, "admin_key_lookup", admin_key_lookup)
    monkeypatch.setattr(litellm_client, "key_update", key_update)
    csrf = "c" * 43
    set_admin_session(
        {
            "user": portal_user(roles=[settings.admin_role]),
            "csrf_token": csrf,
            "admin_reauth_at": int(time.time()),
        }
    )

    response = admin_client.post(
        "/admin/keys/block",
        data={"token": "inv-hash-1", "csrf_token": csrf, "page": "2"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/admin/keys?page=2"
    assert lookups == ["inv-hash-1", "inv-hash-1"]
    assert updates_sent == [{"blocked": True}]


def test_admin_key_block_failure_to_verify_reports_an_error(
    admin_client, set_admin_session, monkeypatch
):
    async def rotator_get(path):
        return {"admin": True}

    async def admin_key_lookup(token):
        # The key never reads back as blocked.
        return full_key_object(blocked=False)

    async def key_update(key, updates):
        return {}

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(litellm_client, "admin_key_lookup", admin_key_lookup)
    monkeypatch.setattr(litellm_client, "key_update", key_update)
    csrf = "c" * 43
    set_admin_session(
        {
            "user": portal_user(roles=[settings.admin_role]),
            "csrf_token": csrf,
            "admin_reauth_at": int(time.time()),
        }
    )

    response = admin_client.post(
        "/admin/keys/block",
        data={"token": "inv-hash-1", "csrf_token": csrf},
        follow_redirects=True,
    )

    assert "Could not verify that key was blocked" in response.text


def test_admin_key_limits_reject_malformed_values_before_litellm(
    admin_client, set_admin_session, monkeypatch
):
    called = False

    async def rotator_get(path):
        return {"admin": True}

    async def admin_key_lookup(token):
        nonlocal called
        called = True
        return full_key_object()

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(litellm_client, "admin_key_lookup", admin_key_lookup)
    csrf = "c" * 43
    base_session = {
        "user": portal_user(roles=[settings.admin_role]),
        "csrf_token": csrf,
        "admin_reauth_at": int(time.time()),
    }

    for fields in (
        {"duration": "forever"},
        {"max_budget": "-5"},
        {"tpm_limit": "10.5"},
        {"rpm_limit": "0"},
        {"duration": "none"},
        {},
    ):
        set_admin_session(base_session)
        response = admin_client.post(
            "/admin/keys/limits",
            data={"token": "inv-hash-1", "csrf_token": csrf, **fields},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert response.headers["location"] == "/admin/keys?page=1"
    assert called is False


def test_admin_key_limits_send_parsed_allowlisted_updates(
    admin_client, set_admin_session, monkeypatch
):
    entry_state = full_key_object()
    updates_sent = []

    async def rotator_get(path):
        return {"admin": True}

    async def admin_key_lookup(token):
        return dict(entry_state)

    async def key_update(key, updates):
        assert key == "inv-hash-1"
        updates_sent.append(updates)
        for field, value in updates.items():
            entry_state[field] = value
        if "duration" in updates:
            # LiteLLM computes expires = now + duration on a duration update.
            entry_state["expires"] = (
                datetime.now(timezone.utc)
                + timedelta(seconds=main._duration_seconds(updates["duration"]))
            ).isoformat()
        return {}

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(litellm_client, "admin_key_lookup", admin_key_lookup)
    monkeypatch.setattr(litellm_client, "key_update", key_update)
    csrf = "c" * 43
    set_admin_session(
        {
            "user": portal_user(roles=[settings.admin_role]),
            "csrf_token": csrf,
            "admin_reauth_at": int(time.time()),
        }
    )

    response = admin_client.post(
        "/admin/keys/limits",
        data={
            "token": "inv-hash-1",
            "csrf_token": csrf,
            "max_budget": "50",
            "tpm_limit": "none",
            "rpm_limit": "",
            "duration": "30d",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert updates_sent == [
        {"max_budget": 50.0, "tpm_limit": None, "duration": "30d"}
    ]


def test_admin_key_limits_duration_is_effect_verified(
    admin_client, set_admin_session, monkeypatch
):
    """A duration edit must verify the resulting expiry, tolerantly."""

    entry_state = full_key_object()

    async def rotator_get(path):
        return {"admin": True}

    async def admin_key_lookup(token):
        return dict(entry_state)

    async def key_update(key, updates):
        # The update is acknowledged but the expiry never moves: the stale
        # 2027 timestamp is nowhere near now + 30d, so verification fails.
        return {}

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(litellm_client, "admin_key_lookup", admin_key_lookup)
    monkeypatch.setattr(litellm_client, "key_update", key_update)
    csrf = "c" * 43
    set_admin_session(
        {
            "user": portal_user(roles=[settings.admin_role]),
            "csrf_token": csrf,
            "admin_reauth_at": int(time.time()),
        }
    )

    response = admin_client.post(
        "/admin/keys/limits",
        data={"token": "inv-hash-1", "csrf_token": csrf, "duration": "30d"},
        follow_redirects=True,
    )

    assert "Could not verify the key limit change" in response.text


def test_expiry_property_check_tolerates_format_but_not_wrong_lifetimes():
    now = datetime.now(timezone.utc)
    in_30_days = now + timedelta(days=30)
    assert main._expiry_matches_duration(in_30_days.isoformat(), "30d", now=now)
    # Z-suffix and naive-UTC formats are tolerated; the property is the value.
    assert main._expiry_matches_duration(
        in_30_days.strftime("%Y-%m-%dT%H:%M:%SZ"), "30d", now=now
    )
    assert main._expiry_matches_duration(
        in_30_days.replace(tzinfo=None).isoformat(), "30d", now=now
    )
    assert main._expiry_matches_duration(in_30_days, "30d", now=now)
    # Wrong lifetime, garbage, and absent expiry all fail the property.
    assert not main._expiry_matches_duration(
        (now + timedelta(days=29)).isoformat(), "30d", now=now
    )
    assert not main._expiry_matches_duration("not-a-date", "30d", now=now)
    assert not main._expiry_matches_duration(None, "30d", now=now)


# --- runtime per-project policy ----------------------------------------------


RESTRICTED_POLICY = {
    "tpm_limit": 50000,
    "rpm_limit": 30,
    "allowed_models": ["claude-haiku"],
    "default_model": "claude-haiku",
}


def test_index_shows_rate_limits_and_models_but_never_cost(
    client, set_session, monkeypatch
):
    async def live_policies(_request, _user, project_ids):
        return {project_id: dict(RESTRICTED_POLICY) for project_id in project_ids}

    async def key_list(user_id):
        return [
            portal_key(owner="subject-123")
            | {"tpm_limit": 50000, "rpm_limit": 30, "spend": 12.34, "max_budget": 99.0}
        ]

    monkeypatch.setattr(main, "_live_project_policies", live_policies)
    monkeypatch.setattr(litellm_client, "key_list", key_list)
    set_session({"user": portal_user()})

    response = client.get("/")

    assert response.status_code == 200
    assert "50000" in response.text and "30" in response.text
    assert "claude-haiku" in response.text
    assert "default" in response.text
    # Cost is an admin-only concept: no dollars, spend, or budget on the
    # user surface.
    for forbidden in ("$", "12.34", "99.0", "spend", "budget", "Budget"):
        assert forbidden not in response.text, forbidden


def test_index_shows_unlimited_defaults_without_policy_restrictions(
    client, set_session, monkeypatch
):
    async def key_list(user_id):
        return [portal_key(owner="subject-123")]

    monkeypatch.setattr(litellm_client, "key_list", key_list)
    set_session({"user": portal_user()})

    response = client.get("/")

    assert response.status_code == 200
    assert "Unlimited" in response.text
    # Unrestricted projects list every configured model from the gateway.
    assert "claude-sonnet" in response.text and "claude-haiku" in response.text


def test_key_mint_carries_the_projects_runtime_policy(
    client, set_session, monkeypatch
):
    generated = []
    inventory: list[dict] = []

    async def live_policies(_request, _user, project_ids):
        return {project_id: dict(RESTRICTED_POLICY) for project_id in project_ids}

    async def key_list(user_id):
        return [dict(entry) for entry in inventory]

    async def key_generate(user_id, alias, project_id, project_policy=None):
        generated.append(project_policy)
        inventory.append(
            portal_key(
                owner=user_id,
                token="minted-hash",
                alias=alias,
                default_model=(project_policy or {}).get("default_model"),
            )
        )
        return {"key": "sk-minted-once", "key_alias": alias}

    monkeypatch.setattr(main, "_live_project_policies", live_policies)
    monkeypatch.setattr(litellm_client, "key_list", key_list)
    monkeypatch.setattr(litellm_client, "key_generate", key_generate)
    csrf = "c" * 43
    set_session({"user": portal_user(), "csrf_token": csrf})

    response = client.post(
        "/keys",
        data={"alias": "laptop", "project_id": "ai-gateway", "csrf_token": csrf},
        follow_redirects=False,
    )

    assert response.status_code == 201
    assert generated == [RESTRICTED_POLICY]


def test_unreadable_project_policy_fails_the_mint_closed(
    client, set_session, monkeypatch
):
    called = False

    async def live_policies(_request, _user, project_ids):
        raise main.HTTPException(
            status_code=503, detail="Current project policy could not be verified."
        )

    async def key_generate(user_id, alias, project_id, project_policy=None):
        nonlocal called
        called = True
        return {"key": "sk-never"}

    monkeypatch.setattr(main, "_live_project_policies", live_policies)
    monkeypatch.setattr(litellm_client, "key_generate", key_generate)
    csrf = "c" * 43
    set_session({"user": portal_user(), "csrf_token": csrf})

    response = client.post(
        "/keys",
        data={"alias": "laptop", "project_id": "ai-gateway", "csrf_token": csrf},
        follow_redirects=False,
    )

    assert response.status_code == 503
    assert called is False


def test_policy_payload_validation_fails_closed_on_ambiguity():
    valid = main._validated_policy_object(dict(RESTRICTED_POLICY))
    assert valid == RESTRICTED_POLICY
    for malformed in (
        None,
        [],
        {},
        {**RESTRICTED_POLICY, "max_budget": 5},
        {**RESTRICTED_POLICY, "tpm_limit": -1},
        {**RESTRICTED_POLICY, "tpm_limit": True},
        {**RESTRICTED_POLICY, "allowed_models": []},
        {**RESTRICTED_POLICY, "allowed_models": ["bad model"]},
        {**RESTRICTED_POLICY, "default_model": "claude-opus"},
    ):
        assert main._validated_policy_object(malformed) is None


def test_admin_unblock_denies_resurrecting_a_membership_revoked_portal_key(
    admin_client, set_admin_session, monkeypatch
):
    updated = False

    async def rotator_get(path):
        if path == "/identity/authorization/subject-123":
            return {"admin": True}
        assert path == "/identity/projects/dev-subject"
        return {"projects": ["another-project"], "policies": {}}

    async def admin_key_lookup(token):
        return full_key_object(
            token="portal-hash-2",
            user_id="dev-subject",
            blocked=True,
            metadata={
                "created_via": "dev-portal",
                "aigw_project_id": "ai-gateway",
            },
        )

    async def key_update(key, updates):
        nonlocal updated
        updated = True
        return {}

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(litellm_client, "admin_key_lookup", admin_key_lookup)
    monkeypatch.setattr(litellm_client, "key_update", key_update)
    csrf = "c" * 43
    set_admin_session(
        {
            "user": portal_user(roles=[settings.admin_role]),
            "csrf_token": csrf,
            "admin_reauth_at": int(time.time()),
        }
    )

    response = admin_client.post(
        "/admin/keys/unblock",
        data={"token": "portal-hash-2", "csrf_token": csrf},
        follow_redirects=True,
    )

    assert updated is False
    assert "Unblock denied" in response.text
    assert "ai-gateway" in response.text


def test_admin_unblock_denies_on_membership_ambiguity_but_allows_operator_keys(
    admin_client, set_admin_session, monkeypatch
):
    updated_keys: list[str] = []

    async def rotator_get(path):
        if path == "/identity/authorization/subject-123":
            return {"admin": True}
        raise RuntimeError("identity controller unavailable")

    lookup_entry = {}

    async def admin_key_lookup(token):
        return dict(lookup_entry)

    async def key_update(key, updates):
        updated_keys.append(key)
        return {}

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(litellm_client, "admin_key_lookup", admin_key_lookup)
    monkeypatch.setattr(litellm_client, "key_update", key_update)
    csrf = "c" * 43
    base_session = {
        "user": portal_user(roles=[settings.admin_role]),
        "csrf_token": csrf,
        "admin_reauth_at": int(time.time()),
    }

    # Portal key + unreachable membership decision: ambiguity denies.
    lookup_entry.update(
        full_key_object(
            token="portal-hash-2",
            user_id="dev-subject",
            blocked=True,
            metadata={
                "created_via": "dev-portal",
                "aigw_project_id": "ai-gateway",
            },
        )
    )
    set_admin_session(base_session)
    denied = admin_client.post(
        "/admin/keys/unblock",
        data={"token": "portal-hash-2", "csrf_token": csrf},
        follow_redirects=True,
    )
    assert "Unblock denied" in denied.text
    assert updated_keys == []

    # Operator keys are outside membership revocation; unblock proceeds.
    lookup_entry.clear()
    lookup_entry.update(full_key_object(blocked=False, metadata={}))
    set_admin_session(base_session)
    allowed = admin_client.post(
        "/admin/keys/unblock",
        data={"token": "inv-hash-1", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert allowed.status_code == 303
    assert updated_keys == ["inv-hash-1"]


def test_project_policy_route_requires_step_up_and_csrf(
    admin_client, set_admin_session, monkeypatch
):
    called = False

    async def rotator_get(path):
        return {"admin": True}

    async def rotator_put(path, payload):
        nonlocal called
        called = True
        return {}

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(main, "_rotator_put", rotator_put)
    csrf = "c" * 43

    # No fresh step-up: redirected to reauthentication before any mutation.
    set_admin_session(
        {"user": portal_user(roles=[settings.admin_role]), "csrf_token": csrf}
    )
    stale = admin_client.post(
        "/admin/identity/groups/group-1/policy",
        data={"tpm_limit": "1000", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert stale.status_code == 303
    assert stale.headers["location"] == "/admin/reauth"

    # Fresh step-up but a stale CSRF token: rejected before the controller.
    set_admin_session(
        {
            "user": portal_user(roles=[settings.admin_role]),
            "csrf_token": csrf,
            "admin_reauth_at": int(time.time()),
        }
    )
    bad_csrf = admin_client.post(
        "/admin/identity/groups/group-1/policy",
        data={"tpm_limit": "1000", "csrf_token": "x" * 43},
        follow_redirects=False,
    )
    assert bad_csrf.status_code == 303
    assert called is False


def test_project_policy_save_retunes_existing_project_keys(
    admin_client, set_admin_session, monkeypatch
):
    puts = []
    key_updates = []
    key_state: dict[str, dict] = {
        "portal-1": full_key_object(
            token="portal-1",
            user_id="dev-a",
            metadata={"created_via": "dev-portal", "aigw_project_id": "ai-gateway"},
        ),
        "portal-other": full_key_object(
            token="portal-other",
            user_id="dev-b",
            metadata={"created_via": "dev-portal", "aigw_project_id": "other-project"},
        ),
        "operator-1": full_key_object(token="operator-1", metadata={}),
    }

    async def rotator_get(path):
        if path == "/identity/groups":
            return [
                {
                    "id": "group-1",
                    "name": "ai-gateway",
                    "capabilities": ["aigw-developers"],
                    "member_count": 1,
                    "policy": {
                        "tpm_limit": None,
                        "rpm_limit": None,
                        "allowed_models": None,
                        "default_model": None,
                    },
                }
            ]
        return {"admin": True}

    async def rotator_put(path, payload):
        puts.append((path, payload))
        return {
            "id": "group-1",
            "name": "ai-gateway",
            "policy": {
                "tpm_limit": 50000,
                "rpm_limit": 30,
                "allowed_models": ["claude-haiku"],
                "default_model": "claude-haiku",
            },
        }

    async def admin_key_list_page(page):
        assert page == 1
        keys = [dict(entry) for entry in key_state.values()]
        return {"keys": keys, "page": 1, "total_pages": 1, "total_count": len(keys)}

    async def key_update(key, updates):
        key_updates.append((key, updates))
        key_state[key].update(updates)
        return {}

    async def admin_key_lookup(token):
        return dict(key_state[token])

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(main, "_rotator_put", rotator_put)
    monkeypatch.setattr(litellm_client, "admin_key_list_page", admin_key_list_page)
    monkeypatch.setattr(litellm_client, "key_update", key_update)
    monkeypatch.setattr(litellm_client, "admin_key_lookup", admin_key_lookup)
    csrf = "c" * 43
    set_admin_session(
        {
            "user": portal_user(roles=[settings.admin_role]),
            "csrf_token": csrf,
            "admin_reauth_at": int(time.time()),
        }
    )

    response = admin_client.post(
        "/admin/identity/groups/group-1/policy",
        data={
            "tpm_limit": "50000",
            "rpm_limit": "30",
            "allowed_models": "claude-haiku",
            "default_model": "claude-haiku",
            "csrf_token": csrf,
        },
        follow_redirects=True,
    )

    assert puts == [
        (
            "/identity/groups/group-1/policy",
            {
                "tpm_limit": 50000,
                "rpm_limit": 30,
                "allowed_models": ["claude-haiku"],
                "default_model": "claude-haiku",
            },
        )
    ]
    # Retroactive re-tune touches exactly the project's portal keys — never
    # operator keys or other projects — and re-stamps the enforced default
    # onto the key metadata the LiteLLM pre-call hook reads, preserving the
    # portal provenance fields byte-for-byte.
    assert key_updates == [
        (
            "portal-1",
            {
                "tpm_limit": 50000,
                "rpm_limit": 30,
                "models": ["claude-haiku"],
                "metadata": {
                    "created_via": "dev-portal",
                    "aigw_project_id": "ai-gateway",
                    "aigw_default_model": "claude-haiku",
                },
            },
        )
    ]
    assert "1 existing keys re-tuned" in response.text


def test_key_mint_is_not_disclosed_when_the_default_model_stamp_is_missing(
    client, set_session, monkeypatch
):
    """A minted key that cannot prove its enforced default is revoked, not shown."""

    deactivated: list[str] = []
    inventory: list[dict] = []

    async def live_policies(_request, _user, project_ids):
        return {project_id: dict(RESTRICTED_POLICY) for project_id in project_ids}

    async def key_list(user_id):
        return [dict(entry) for entry in inventory]

    async def key_generate(user_id, alias, project_id, project_policy=None):
        # Upstream drops the metadata stamp the pre-call hook enforces from.
        inventory.append(
            portal_key(owner=user_id, token="minted-hash", alias=alias)
        )
        return {"key": "sk-unstamped", "key_alias": alias}

    async def key_deactivate(key):
        deactivated.append(key)
        return {}

    monkeypatch.setattr(main, "_live_project_policies", live_policies)
    monkeypatch.setattr(litellm_client, "key_list", key_list)
    monkeypatch.setattr(litellm_client, "key_generate", key_generate)
    monkeypatch.setattr(litellm_client, "key_deactivate", key_deactivate)
    csrf = "c" * 43
    set_session({"user": portal_user(), "csrf_token": csrf})

    response = client.post(
        "/keys",
        data={"alias": "laptop", "project_id": "ai-gateway", "csrf_token": csrf},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert deactivated == ["sk-unstamped"]
    assert "sk-unstamped" not in response.text


def test_project_policy_retune_counts_an_unverified_default_stamp_as_failed(
    admin_client, set_admin_session, monkeypatch
):
    """A re-tune whose default stamp does not land verifies closed, not silent."""

    key_state = {
        "portal-1": full_key_object(
            token="portal-1",
            user_id="dev-a",
            tpm_limit=50000,
            rpm_limit=30,
            models=["claude-haiku"],
            metadata={"created_via": "dev-portal", "aigw_project_id": "ai-gateway"},
        ),
    }

    async def rotator_get(path):
        if path == "/identity/groups":
            return [_unlimited_group()]
        return {"admin": True}

    async def rotator_put(path, payload):
        return {
            "id": "group-1",
            "name": "ai-gateway",
            "policy": {
                "tpm_limit": 50000,
                "rpm_limit": 30,
                "allowed_models": ["claude-haiku"],
                "default_model": "claude-haiku",
            },
        }

    async def admin_key_list_page(page):
        keys = [dict(entry) for entry in key_state.values()]
        return {"keys": keys, "page": 1, "total_pages": 1, "total_count": len(keys)}

    async def key_update(key, updates):
        # Upstream accepts the update but silently drops the metadata stamp.
        applied = {name: value for name, value in updates.items() if name != "metadata"}
        key_state[key].update(applied)
        return {}

    async def admin_key_lookup(token):
        return dict(key_state[token])

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(main, "_rotator_put", rotator_put)
    monkeypatch.setattr(litellm_client, "admin_key_list_page", admin_key_list_page)
    monkeypatch.setattr(litellm_client, "key_update", key_update)
    monkeypatch.setattr(litellm_client, "admin_key_lookup", admin_key_lookup)
    csrf = "c" * 43
    set_admin_session(
        {
            "user": portal_user(roles=[settings.admin_role]),
            "csrf_token": csrf,
            "admin_reauth_at": int(time.time()),
        }
    )

    response = admin_client.post(
        "/admin/identity/groups/group-1/policy",
        data={
            "tpm_limit": "50000",
            "rpm_limit": "30",
            "allowed_models": "claude-haiku",
            "default_model": "claude-haiku",
            "csrf_token": csrf,
        },
        follow_redirects=True,
    )

    assert "1 could not be verified" in response.text


def _unlimited_group(group_id="group-1", name="ai-gateway", **policy_overrides):
    policy = {
        "tpm_limit": None,
        "rpm_limit": None,
        "allowed_models": None,
        "default_model": None,
    }
    policy.update(policy_overrides)
    return {
        "id": group_id,
        "name": name,
        "capabilities": ["aigw-developers"],
        "member_count": 1,
        "policy": policy,
    }


def test_project_policy_rejects_unconfigured_models_before_the_controller(
    admin_client, set_admin_session, monkeypatch
):
    called = False

    async def rotator_get(path):
        if path == "/identity/groups":
            return [_unlimited_group()]
        return {"admin": True}

    async def rotator_put(path, payload):
        nonlocal called
        called = True
        return {}

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(main, "_rotator_put", rotator_put)
    csrf = "c" * 43
    set_admin_session(
        {
            "user": portal_user(roles=[settings.admin_role]),
            "csrf_token": csrf,
            "admin_reauth_at": int(time.time()),
        }
    )

    for fields in (
        {"allowed_models": "gpt-4o"},
        {"tpm_limit": "-5"},
        {"tpm_limit": "0"},
        {"allowed_models": "claude-haiku", "default_model": "claude-opus"},
    ):
        response = admin_client.post(
            "/admin/identity/groups/group-1/policy",
            data={"csrf_token": csrf, **fields},
            follow_redirects=False,
        )
        assert response.status_code == 303
        set_admin_session(
            {
                "user": portal_user(roles=[settings.admin_role]),
                "csrf_token": csrf,
                "admin_reauth_at": int(time.time()),
            }
        )
    assert called is False


def test_project_policy_refuses_silent_widening_of_deconfigured_restriction(
    admin_client, set_admin_session, monkeypatch
):
    """A stored restriction to a now-deconfigured model cannot be silently widened."""

    put_called = False

    async def rotator_get(path):
        if path == "/identity/groups":
            # Restricted to a model that is no longer in the live model list
            # (conftest reports only claude-haiku/claude-sonnet).
            return [
                _unlimited_group(
                    allowed_models=["claude-opus"], default_model="claude-opus"
                )
            ]
        return {"admin": True}

    async def rotator_put(path, payload):
        nonlocal put_called
        put_called = True
        return {}

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(main, "_rotator_put", rotator_put)
    csrf = "c" * 43
    set_admin_session(
        {
            "user": portal_user(roles=[settings.admin_role]),
            "csrf_token": csrf,
            "admin_reauth_at": int(time.time()),
        }
    )

    # A plain submit (e.g. just changing TPM) must be refused, not silently
    # widen the model restriction to unlimited.
    response = admin_client.post(
        "/admin/identity/groups/group-1/policy",
        data={"tpm_limit": "1000", "csrf_token": csrf},
        follow_redirects=True,
    )
    assert put_called is False
    assert "no longer configured in LiteLLM" in response.text
    assert "claude-opus" in response.text


def test_project_policy_widens_deconfigured_restriction_only_with_explicit_optout(
    admin_client, set_admin_session, monkeypatch
):
    puts = []

    async def rotator_get(path):
        if path == "/identity/groups":
            return [
                _unlimited_group(
                    allowed_models=["claude-opus"], default_model="claude-opus"
                )
            ]
        return {"admin": True}

    async def rotator_put(path, payload):
        puts.append(payload)
        return {
            "id": "group-1",
            "name": "ai-gateway",
            "policy": {
                "tpm_limit": 1000,
                "rpm_limit": None,
                "allowed_models": None,
                "default_model": None,
            },
        }

    async def admin_key_list_page(page):
        return {"keys": [], "page": 1, "total_pages": 1, "total_count": 0}

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(main, "_rotator_put", rotator_put)
    monkeypatch.setattr(litellm_client, "admin_key_list_page", admin_key_list_page)
    csrf = "c" * 43
    set_admin_session(
        {
            "user": portal_user(roles=[settings.admin_role]),
            "csrf_token": csrf,
            "admin_reauth_at": int(time.time()),
        }
    )

    response = admin_client.post(
        "/admin/identity/groups/group-1/policy",
        data={
            "tpm_limit": "1000",
            "remove_model_restrictions": "1",
            "csrf_token": csrf,
        },
        follow_redirects=True,
    )

    # The explicit opt-out widens deliberately: allowed_models cleared to None.
    assert puts == [
        {
            "tpm_limit": 1000,
            "rpm_limit": None,
            "allowed_models": None,
            "default_model": None,
        }
    ]
    assert "Project policy saved" in response.text
