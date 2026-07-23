from __future__ import annotations

import asyncio
import json
import re
import time
from base64 import b64decode
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any
from uuid import UUID

import httpx
import pytest
from itsdangerous import TimestampSigner

from app import litellm_client, model_admin
from app.config import settings
from app import main
from conftest import portal_user, session_cookie


# The autouse test fixture supplies a normal live membership decision for most
# route tests. Keep the real helper so dedicated fail-closed tests can exercise
# its upstream and payload validation directly.
LIVE_PROJECT_IDS = main._live_project_ids
LIVE_PROJECT_POLICIES = main._live_project_policies


def security_events(caplog) -> list[dict]:
    """Return only the structured security records emitted by the portal."""

    marker = "AIGW_SECURITY_EVENT "
    return [
        json.loads(message.split(marker, 1)[1])
        for record in caplog.records
        if marker in (message := record.getMessage())
    ]


def _status_error(status_code: int) -> httpx.HTTPStatusError:
    request = httpx.Request("POST", "http://key-rotator/internal")
    response = httpx.Response(status_code, request=request)
    return httpx.HTTPStatusError(
        "fixed test status", request=request, response=response
    )


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (_status_error(400), "failure"),
        (_status_error(409), "failure"),
        (_status_error(500), "indeterminate"),
        (_status_error(418), "indeterminate"),
        (RuntimeError("unknown"), "indeterminate"),
        (ValueError("malformed"), "indeterminate"),
        (
            httpx.ReadTimeout(
                "lost response",
                request=httpx.Request("POST", "http://key-rotator/internal"),
            ),
            "indeterminate",
        ),
    ],
)
def test_identity_mutation_result_is_fail_closed(
    error: Exception, expected: str
) -> None:
    assert main._identity_mutation_result(error) == expected


def test_rotator_response_rejects_malformed_and_oversized_documents() -> None:
    for response in (
        httpx.Response(200, content=b"{"),
        httpx.Response(200, content=b"x" * (main.ROTATOR_RESPONSE_MAX_BYTES + 1)),
    ):
        with pytest.raises(ValueError) as caught:
            main._rotator_response(response)
        assert main._identity_mutation_result(caught.value) == "indeterminate"


def test_operation_id_requires_canonical_rfc4122_uuid4() -> None:
    operation_id = "123e4567-e89b-42d3-a456-426614174000"
    assert main._canonical_operation_id(operation_id)
    assert not main._canonical_operation_id("123E4567-E89B-42D3-A456-426614174000")
    assert not main._canonical_operation_id("00000000-0000-4000-0000-000000000000")
    assert main._rotator_headers(operation_id)["X-AIGW-Operation-ID"] == operation_id
    with pytest.raises(ValueError, match="invalid identity mutation operation ID"):
        main._rotator_headers("not-a-uuid")


def test_governance_actor_header_is_bounded_and_requires_an_operation() -> None:
    operation_id = "123e4567-e89b-42d3-a456-426614174000"
    headers = main._rotator_headers(operation_id, "admin-subject:1")
    assert headers["X-AIGW-Operation-ID"] == operation_id
    assert headers["X-AIGW-Actor-ID"] == "admin-subject:1"
    with pytest.raises(ValueError, match="invalid model-governance actor ID"):
        main._rotator_headers(None, "admin-subject:1")
    with pytest.raises(ValueError, match="invalid model-governance actor ID"):
        main._rotator_headers(operation_id, "bad/actor")


def portal_key(
    *,
    owner: str,
    token: str = "owned-hash",
    alias: str = "laptop",
    project: str = "ai-gateway",
    blocked: bool | None = None,
    expires: str | None = None,
    default_model: str | None = None,
    policy_revision: str | None = None,
) -> dict:
    if policy_revision is None:
        policy_revision = litellm_client.project_policy_revision(
            {
                "tpm_limit": None,
                "rpm_limit": None,
                "allowed_models": None,
                "default_model": None,
                "model_limits": {},
            }
        )
    metadata = {
        "created_via": "dev-portal",
        "aigw_project_id": project,
        "aigw_policy_revision_v1": policy_revision,
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
    # A non-developer arrives here via shared SSO (already signed into chat).
    # The 403 must offer a working escape, not a self-looping link back to the
    # keys page they cannot see. Sign out clears the session and RP-logs-out.
    assert 'href="/logout"' in response.text
    assert 'href="/"' not in response.text


def test_key_creation_uses_immutable_subject_and_rejects_bad_csrf(
    client, set_session, monkeypatch
):
    calls = []
    inventory = []

    async def key_list(user_id):
        assert user_id == "stable-oidc-sub"
        return list(inventory)

    async def key_generate(user_id, alias, project_id, project_policy=None, username=None):
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


def test_one_time_key_is_destroyed_before_tab_exit_or_browser_history_restore():
    loader = main.templates.env.loader
    base = loader.get_source(main.templates.env, "base.html")[0]
    index = loader.get_source(main.templates.env, "index.html")[0]

    # The history entry records whether its reveal has been consumed. This
    # covers non-BFCache history reconstruction where pageshow.persisted is
    # false, which the former guard missed.
    assert "state.aigwOneTimeSecretConsumed === true" in base
    assert 'entries[0].type === "back_forward"' in base
    assert "alreadyConsumed || restoredFromBrowserHistory()" in base
    # Scrub the text and remove its whole reveal before a tab switch, form
    # submit, page hide, popstate, or normal same-window link navigation.
    assert 'if (name !== "keys") consumeOneTimeSecret();' in base
    assert 'document.addEventListener("submit"' in base
    assert 'window.addEventListener("pagehide", consumeOneTimeSecret);' in base
    assert 'window.addEventListener("popstate", consumeOneTimeSecret);' in base
    assert "reveal.remove();" in base
    assert "window.location.replace(destination);" in base
    assert "[data-one-time-secret][hidden] { display: none !important; }" in base
    assert "reveal.hidden = false;" in base
    assert 'class="card reveal" data-one-time-secret hidden' in index
    # Tab hash updates must preserve the consumed marker instead of replacing
    # it with null.
    assert (
        'window.history.replaceState(window.history.state, "", "#tab-" + name);'
        in base
    )
    assert 'window.history.replaceState(null, "", "#tab-" + name);' not in base


@pytest.mark.parametrize(
    ("path", "form", "action"),
    [
        (
            "/keys",
            {"alias": "laptop", "project_id": "unassigned-project"},
            "key.generate",
        ),
        (
            "/keys/deactivate",
            {"token": "opaque-key-reference", "project_id": "unassigned-project"},
            "key.deactivate",
        ),
    ],
)
def test_key_mutation_membership_denials_are_audited(
    client, set_session, monkeypatch, caplog, path, form, action
):
    async def live_projects(_request, _user):
        return ("ai-gateway",)

    monkeypatch.setattr(main, "_live_project_ids", live_projects)
    csrf = "c" * 43
    set_session({"user": portal_user(subject="member-sub"), "csrf_token": csrf})

    with caplog.at_level("INFO", logger="dev-portal"):
        response = client.post(
            path,
            data={**form, "csrf_token": csrf},
            follow_redirects=False,
        )

    assert response.status_code == 403
    assert security_events(caplog) == [
        {
            "schema_version": 1,
            "event": "aigw.portal.audit",
            "action": action,
            "outcome": "denied-membership",
            "subject": "member-sub",
            "project": "unassigned-project",
        }
    ]
    assert "opaque-key-reference" not in caplog.text


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

    async def key_generate(user_id, alias, project_id, project_policy=None, username=None):
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

    async def key_generate(user_id, alias, project_id, project_policy=None, username=None):
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
                "a" * 64,
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
    with pytest.raises(
        litellm_client.LiteLLMError, match="membership or policy changed"
    ):
        await verification
    assert deactivated == ["sk-cancelled-secret"]


@pytest.mark.asyncio
async def test_post_generation_policy_revision_race_revokes_before_disclosure(
    monkeypatch,
):
    """A key minted under the old policy is blocked when cutover wins."""

    old_policy = dict(RESTRICTED_POLICY)
    new_policy = {**RESTRICTED_POLICY, "rpm_limit": 10}
    expected_revision = litellm_client.project_policy_revision(old_policy)
    deactivated: list[str] = []

    async def live_projects(_request, _user):
        return ("ai-gateway",)

    async def live_policies(_request, _user, _project_ids):
        return {"ai-gateway": new_policy}

    async def key_deactivate(key):
        deactivated.append(key)
        return {"blocked": True}

    monkeypatch.setattr(main, "_live_project_ids", live_projects)
    monkeypatch.setattr(main, "_live_project_policies", live_policies)
    monkeypatch.setattr(litellm_client, "key_deactivate", key_deactivate)

    with pytest.raises(
        litellm_client.LiteLLMError,
        match="membership or policy changed",
    ):
        await main._verify_post_generation_liveness(
            SimpleNamespace(session={}),
            portal_user(subject="policy-race-owner"),
            "ai-gateway",
            "sk-policy-race-secret",
            expected_revision,
        )
    assert deactivated == ["sk-policy-race-secret"]


@pytest.mark.asyncio
async def test_post_deactivation_waits_out_cutover_and_repairs_stale_unblock(
    monkeypatch,
):
    """A stale policy writer cannot undo a developer's durable deactivation."""

    policy = dict(RESTRICTED_POLICY)
    state = portal_key(
        owner="deactivation-race-owner",
        token="deactivation-race-hash",
        blocked=False,
        policy_revision=litellm_client.project_policy_revision(policy),
    )
    policy_reads = 0
    updates: list[dict] = []

    async def live_policies(_request, _user, _project_ids):
        nonlocal policy_reads
        policy_reads += 1
        if policy_reads == 1:
            # The admin container has staged a revision. Model the stale
            # retune write that removed the first block marker and unblocked.
            raise main.HTTPException(
                status_code=503,
                detail="Project policy reconciliation is incomplete.",
            )
        return {"ai-gateway": policy}

    async def admin_key_lookup(_token):
        return dict(state)

    async def key_update(_token, update):
        updates.append(dict(update))
        state.update(update)
        return {}

    monkeypatch.setattr(main, "_live_project_policies", live_policies)
    monkeypatch.setattr(litellm_client, "admin_key_lookup", admin_key_lookup)
    monkeypatch.setattr(litellm_client, "key_update", key_update)
    monkeypatch.setattr(main, "DEACTIVATION_POLICY_POLL_SECONDS", 0)

    await main._verify_post_deactivation_liveness(
        SimpleNamespace(session={}),
        portal_user(subject="deactivation-race-owner"),
        "ai-gateway",
        "deactivation-race-hash",
    )

    assert policy_reads >= 3
    assert state["blocked"] is True
    assert state["metadata"][
        litellm_client.PORTAL_MANUAL_BLOCK_METADATA_KEY
    ] is True
    assert litellm_client.PORTAL_POLICY_GATE_METADATA_KEY not in state["metadata"]
    assert len(updates) == 1


@pytest.mark.asyncio
async def test_developer_deactivation_survives_a_cross_container_stale_write(
    monkeypatch,
):
    """The developer marker and post-check beat a stale admin retune snapshot."""

    monkeypatch.setattr(main, "_admin_key_policy_lock", asyncio.Lock())
    monkeypatch.setattr(main, "DEACTIVATION_POLICY_POLL_SECONDS", 0)
    policy = dict(RESTRICTED_POLICY)
    revision = litellm_client.project_policy_revision(policy)
    state = portal_key(
        owner="cross-container-owner",
        token="cross-container-hash",
        blocked=False,
        policy_revision=revision,
    )
    pending = {"value": True}
    stale_read = asyncio.Event()
    release_stale_write = asyncio.Event()

    async def rotator_put(_path, _payload, *, operation_id=None):
        return _staged_policy_result(policy)

    async def gate(_project_id, _revision):
        return 0

    async def transition(path, _payload, *, operation_id=None, actor_id=None):
        is_activate = path.endswith("/activate")
        pending["value"] = is_activate
        intended = _normalized_test_policy(policy)
        return {
            "active_policy": intended,
            "policy": intended,
            "policy_revision": revision,
            "reconciliation_pending": is_activate,
        }

    async def stale_retune(_project_id, _policy, _models):
        snapshot = dict(state)
        snapshot["metadata"] = dict(state["metadata"])
        stale_read.set()
        await release_stale_write.wait()
        # This models the admin container writing a snapshot it read before
        # the developer container added its durable block marker.
        snapshot["blocked"] = False
        snapshot["metadata"].pop(
            litellm_client.PORTAL_MANUAL_BLOCK_METADATA_KEY, None
        )
        state.clear()
        state.update(snapshot)
        return 0, 0

    async def live_policies(_request, _user, _project_ids):
        if pending["value"]:
            raise main.HTTPException(
                status_code=503,
                detail="Project policy reconciliation is incomplete.",
            )
        return {"ai-gateway": policy}

    async def lookup(_token):
        return dict(state) | {"metadata": dict(state["metadata"])}

    async def update(_token, changes):
        state.update(changes)
        if "metadata" in changes:
            state["metadata"] = dict(changes["metadata"])
        return {}

    monkeypatch.setattr(main, "_rotator_put", rotator_put)
    monkeypatch.setattr(main, "_rotator_post", transition)
    monkeypatch.setattr(main, "_gate_project_keys", gate)
    monkeypatch.setattr(main, "_retune_project_keys", stale_retune)
    monkeypatch.setattr(main, "_live_project_policies", live_policies)
    monkeypatch.setattr(litellm_client, "admin_key_lookup", lookup)
    monkeypatch.setattr(litellm_client, "key_update", update)

    policy_task = asyncio.create_task(
        main._apply_project_policy("group-1", policy, "operation-1", ["claude-haiku"])
    )
    await stale_read.wait()
    await main._block_key_with_durable_intent(dict(state))
    post_check = asyncio.create_task(
        main._verify_post_deactivation_liveness(
            SimpleNamespace(session={}),
            portal_user(subject="cross-container-owner"),
            "ai-gateway",
            "cross-container-hash",
        )
    )
    await asyncio.sleep(0)
    release_stale_write.set()
    await policy_task
    await post_check

    assert state["blocked"] is True
    assert state["metadata"][
        litellm_client.PORTAL_MANUAL_BLOCK_METADATA_KEY
    ] is True
    assert litellm_client.PORTAL_POLICY_GATE_METADATA_KEY not in state["metadata"]


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

    async def key_generate(_user_id, _alias, _project_id, _project_policy=None, username=None):
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

    async def key_update(key, updates):
        for entry in state:
            if entry["token"] == key:
                entry.update(updates)
                if (
                    updates.get("blocked") is True
                    and updates.get("metadata", {}).get(
                        litellm_client.PORTAL_MANUAL_BLOCK_METADATA_KEY
                    )
                    is True
                ):
                    deactivated.append(key)
                return {}
        raise AssertionError("unknown key")

    async def admin_key_lookup(key):
        return dict(next(entry for entry in state if entry["token"] == key))

    async def key_generate(user_id, alias, project_id, project_policy=None, username=None):
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
    monkeypatch.setattr(litellm_client, "key_update", key_update)
    monkeypatch.setattr(litellm_client, "admin_key_lookup", admin_key_lookup)
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

    async def key_generate(user_id, alias, project_id, project_policy=None, username=None):
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

    async def key_generate(user_id, alias, project_id, project_policy=None, username=None):
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

    async def key_generate(user_id, alias, project_id, project_policy=None, username=None):
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

    async def key_generate(user_id, alias, project_id, project_policy=None, username=None):
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

    async def key_generate(user_id, alias, project_id, project_policy=None, username=None):
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
    client, set_session, monkeypatch, caplog
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

    with caplog.at_level("INFO", logger="dev-portal"):
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
    assert security_events(caplog) == [
        {
            "schema_version": 1,
            "event": "aigw.portal.audit",
            "action": "key.deactivate",
            "outcome": "denied-ownership",
            "subject": owner,
            "project": "ai-gateway",
        }
    ]
    assert "operator-controlled-hash" not in caplog.text


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
                    {"vendor": "static-anthropic", "enabled": True, "interval_seconds": 3600},
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


@pytest.mark.parametrize(
    ("path", "form"),
    [
        ("/admin/rotate/openai", {}),
        (
            "/admin/settings/openai",
            {"enabled": "1", "interval_seconds": "3600", "grace_seconds": "300"},
        ),
    ],
)
def test_unregistered_openai_provider_never_reaches_rotator(
    admin_client, set_admin_session, monkeypatch, path, form
):
    called = False

    async def rotator_get(request_path):
        assert request_path == "/identity/authorization/subject-123"
        return {"admin": True}

    async def unexpected(*_args, **_kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(main, "_rotator_post", unexpected)
    monkeypatch.setattr(main, "_rotator_put", unexpected)
    csrf = "c" * 43
    set_admin_session(
        {"user": portal_user(roles=[settings.admin_role]), "csrf_token": csrf}
    )

    response = admin_client.post(path, data={**form, "csrf_token": csrf})

    assert response.status_code == 404
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
    admin_client, set_admin_session, monkeypatch, caplog
):
    called = False

    async def rotator_post(path, payload=None, *, operation_id=None):
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

    with caplog.at_level("INFO", logger="dev-portal"):
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
    assert security_events(caplog) == [
        {
            "schema_version": 1,
            "event": "aigw.portal.audit",
            "action": "authorization.step_up.required",
            "outcome": "failure",
            "subject": "subject-123",
        }
    ]


def test_recent_step_up_allows_only_allowlisted_group_capabilities(
    admin_client, set_admin_session, monkeypatch, caplog
):
    calls = []

    async def rotator_post(path, payload=None, *, operation_id=None):
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
    with caplog.at_level("INFO", logger="dev-portal"):
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
    events = security_events(caplog)
    operation_id = events[0]["operation_id"]
    assert str(UUID(operation_id)) == operation_id
    assert events == [
        {
            "schema_version": 1,
            "event": "aigw.portal.audit",
            "action": "identity.group.create",
            "outcome": outcome,
            "subject": "subject-123",
            "group": "platform-team",
            "operation_id": operation_id,
        }
        for outcome in ("intent", "success")
    ]


@pytest.mark.parametrize(
    ("path", "rotator_name", "form", "action"),
    [
        (
            "/admin/identity/groups",
            "_rotator_post",
            {"name": "platform-team", "capabilities": "aigw-developers"},
            "identity.group.create",
        ),
        (
            "/admin/identity/groups/group-1/delete",
            "_rotator_delete",
            {},
            "identity.group.delete",
        ),
        (
            "/admin/identity/groups/group-1/members",
            "_rotator_put",
            {"user_id": "user-1"},
            "identity.member.add",
        ),
    ],
)
@pytest.mark.parametrize("result_outcome", ["success", "failure", "indeterminate"])
def test_identity_group_mutations_emit_correlated_actor_audit_events(
    admin_client,
    set_admin_session,
    monkeypatch,
    caplog,
    path,
    rotator_name,
    form,
    action,
    result_outcome,
):
    forwarded_operation_ids = []

    async def rotator_get(request_path):
        assert request_path == "/identity/authorization/subject-123"
        return {"admin": True}

    async def mutate(*_args, **_kwargs):
        forwarded_operation_ids.append(_kwargs.get("operation_id"))
        if result_outcome == "failure":
            request = httpx.Request("POST", "http://key-rotator/internal")
            response = httpx.Response(409, request=request)
            raise httpx.HTTPStatusError(
                "upstream detail must stay local",
                request=request,
                response=response,
            )
        if result_outcome == "indeterminate":
            raise httpx.ReadTimeout(
                "token=transport-secret",
                request=httpx.Request("POST", "http://key-rotator/internal"),
            )
        return {}

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(main, rotator_name, mutate)
    csrf = "c" * 43
    set_admin_session(
        {
            "user": portal_user(roles=[settings.admin_role]),
            "csrf_token": csrf,
            "admin_reauth_at": int(time.time()),
        }
    )

    with caplog.at_level("INFO", logger="dev-portal"):
        response = admin_client.post(
            path,
            data={**form, "csrf_token": csrf},
            follow_redirects=False,
        )

    assert response.status_code == 303
    expected = {
        "schema_version": 1,
        "event": "aigw.portal.audit",
        "action": action,
        "outcome": result_outcome,
        "subject": "subject-123",
        "group": form.get("name", "group-1"),
    }
    if "user_id" in form:
        expected["target_subject"] = form["user_id"]
    events = security_events(caplog)
    operation_id = events[0]["operation_id"]
    assert str(UUID(operation_id)) == operation_id
    assert forwarded_operation_ids == [operation_id]
    expected["operation_id"] = operation_id
    intent = dict(expected, outcome="intent")
    assert events == [intent, expected]
    assert "upstream detail must stay local" not in caplog.text
    assert "transport-secret" not in caplog.text


def test_identity_member_remove_audit_names_group_and_target(
    admin_client, set_admin_session, monkeypatch, caplog
):
    calls = []

    async def rotator_get(path):
        assert path == "/identity/authorization/subject-123"
        return {"admin": True}

    async def managed_project(group_id):
        assert group_id == "group-1"
        return "project-1"

    async def deactivate(user_id, project_id):
        calls.append(("deactivate", user_id, project_id))

    async def rotator_delete(path, payload=None, *, operation_id=None):
        calls.append(("delete", path, payload))

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(main, "_managed_project_for_group", managed_project)
    monkeypatch.setattr(main, "_deactivate_subject_project_keys", deactivate)
    monkeypatch.setattr(main, "_rotator_delete", rotator_delete)
    csrf = "c" * 43
    set_admin_session(
        {
            "user": portal_user(roles=[settings.admin_role]),
            "csrf_token": csrf,
            "admin_reauth_at": int(time.time()),
        }
    )

    with caplog.at_level("INFO", logger="dev-portal"):
        response = admin_client.post(
            "/admin/identity/groups/group-1/members/user-1/remove",
            data={"csrf_token": csrf},
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert calls == [
        ("deactivate", "user-1", "project-1"),
        (
            "delete",
            "/identity/groups/group-1/members/user-1",
            None,
        ),
        ("deactivate", "user-1", "project-1"),
    ]
    events = security_events(caplog)
    operation_id = events[0]["operation_id"]
    assert str(UUID(operation_id)) == operation_id
    assert events == [
        {
            "schema_version": 1,
            "event": "aigw.portal.audit",
            "action": "identity.member.remove",
            "outcome": "intent",
            "subject": "subject-123",
            "group": "group-1",
            "target_subject": "user-1",
            "operation_id": operation_id,
        },
        {
            "schema_version": 1,
            "event": "aigw.portal.audit",
            "action": "identity.member.remove",
            "outcome": "success",
            "subject": "subject-123",
            "group": "group-1",
            "project": "project-1",
            "target_subject": "user-1",
            "operation_id": operation_id,
        },
    ]


def test_identity_member_remove_post_revoke_failure_is_indeterminate(
    admin_client, set_admin_session, monkeypatch, caplog
):
    deactivate_calls = 0

    async def rotator_get(path):
        assert path == "/identity/authorization/subject-123"
        return {"admin": True}

    async def managed_project(group_id):
        assert group_id == "group-1"
        return "project-1"

    async def deactivate(user_id, project_id):
        nonlocal deactivate_calls
        assert (user_id, project_id) == ("user-1", "project-1")
        deactivate_calls += 1
        if deactivate_calls == 2:
            raise litellm_client.LiteLLMError(
                "api_key=do-not-export-post-revoke-secret"
            )

    async def rotator_delete(path, payload=None, *, operation_id=None):
        assert path == "/identity/groups/group-1/members/user-1"
        assert operation_id is not None

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(main, "_managed_project_for_group", managed_project)
    monkeypatch.setattr(main, "_deactivate_subject_project_keys", deactivate)
    monkeypatch.setattr(main, "_rotator_delete", rotator_delete)
    csrf = "c" * 43
    set_admin_session(
        {
            "user": portal_user(roles=[settings.admin_role]),
            "csrf_token": csrf,
            "admin_reauth_at": int(time.time()),
        }
    )

    with caplog.at_level("INFO", logger="dev-portal"):
        response = admin_client.post(
            "/admin/identity/groups/group-1/members/user-1/remove",
            data={"csrf_token": csrf},
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert deactivate_calls == 2
    events = security_events(caplog)
    assert [event["outcome"] for event in events] == ["intent", "indeterminate"]
    assert len({event["operation_id"] for event in events}) == 1
    assert not any(event["outcome"] == "success" for event in events)
    assert "do-not-export-post-revoke-secret" not in caplog.text


def test_revoked_admin_cookie_cannot_mutate_or_restore_membership(
    admin_client, set_admin_session, monkeypatch, caplog
):
    called = False

    async def rotator_get(path):
        assert path == "/identity/authorization/revoked-admin"
        return {"admin": False}

    async def rotator_put(path, payload, *, operation_id=None):
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

    with caplog.at_level("INFO", logger="dev-portal"):
        response = admin_client.post(
            "/admin/identity/groups/admins/members",
            data={"user_id": "revoked-admin", "csrf_token": csrf},
            follow_redirects=False,
        )

    assert response.status_code == 403
    assert called is False
    assert "aigw_admin_session=" in response.headers.get("set-cookie", "")
    assert security_events(caplog) == [
        {
            "schema_version": 1,
            "event": "aigw.portal.audit",
            "action": "authorization.role.denied",
            "outcome": "failure",
            "subject": "revoked-admin",
        }
    ]


def test_revoked_admin_cookie_cannot_change_rotation_controls(
    admin_client, set_admin_session, monkeypatch
):
    called = False

    async def rotator_get(path):
        assert path == "/identity/authorization/revoked-admin"
        return {"admin": False}

    async def rotator_post(path, payload=None, *, operation_id=None):
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
        "/admin/rotate/anthropic",
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


@pytest.mark.asyncio
async def test_live_project_policy_requires_ready_matching_revision(monkeypatch):
    policy = dict(RESTRICTED_POLICY)
    revision = litellm_client.project_policy_revision(policy)

    async def rotator_get(path):
        assert path == "/identity/projects/subject-123"
        return {
            "projects": ["ai-gateway"],
            "policies": {"ai-gateway": policy},
            "policy_reconciliation": {
                "ai-gateway": {"ready": True, "revision": revision}
            },
        }

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    assert await LIVE_PROJECT_POLICIES(
        SimpleNamespace(session={}), portal_user(), ("ai-gateway",)
    ) == {"ai-gateway": policy}


@pytest.mark.asyncio
@pytest.mark.parametrize("ready,revision", [(False, "valid"), (True, "wrong")])
async def test_live_project_policy_fails_closed_during_reconciliation(
    monkeypatch, ready, revision
):
    policy = dict(RESTRICTED_POLICY)
    expected_revision = litellm_client.project_policy_revision(policy)

    async def rotator_get(_path):
        return {
            "projects": ["ai-gateway"],
            "policies": {"ai-gateway": policy},
            "policy_reconciliation": {
                "ai-gateway": {
                    "ready": ready,
                    "revision": (
                        expected_revision if revision == "valid" else "0" * 64
                    ),
                }
            },
        }

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    with pytest.raises(main.HTTPException) as caught:
        await LIVE_PROJECT_POLICIES(
            SimpleNamespace(session={}), portal_user(), ("ai-gateway",)
        )
    assert caught.value.status_code == 503


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

    async def rotator_put(path, payload, *, operation_id=None):
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
    "model_limits": {},
}


def _normalized_test_policy(policy: dict) -> dict:
    normalized = dict(policy)
    normalized.setdefault("default_model", None)
    normalized.setdefault("model_limits", {})
    return normalized


def _staged_policy_result(policy: dict) -> dict:
    intended = _normalized_test_policy(policy)
    return {
        "id": "group-1",
        "name": "ai-gateway",
        "active_policy": {
            "tpm_limit": None,
            "rpm_limit": None,
            "allowed_models": None,
            "default_model": None,
            "model_limits": {},
        },
        "policy": intended,
        "policy_revision": litellm_client.project_policy_revision(intended),
        "reconciliation_pending": True,
    }


def _policy_transition_stub(policy: dict, calls: list) -> Any:
    intended = _normalized_test_policy(policy)
    revision = litellm_client.project_policy_revision(intended)

    async def transition(path, payload, *, operation_id=None, actor_id=None):
        calls.append((path, payload, operation_id))
        assert payload == {"policy_revision": revision}
        pending = path.endswith("/activate")
        assert pending or path.endswith("/complete")
        return {
            "id": "group-1",
            "name": "ai-gateway",
            "active_policy": intended,
            "policy": intended,
            "policy_revision": revision,
            "reconciliation_pending": pending,
        }

    return transition


@pytest.mark.asyncio
async def test_admin_key_block_waits_for_complete_policy_cutover(monkeypatch):
    """The admin process never interleaves a manual edit with reconciliation."""

    monkeypatch.setattr(main, "_admin_key_policy_lock", asyncio.Lock())
    policy = dict(RESTRICTED_POLICY)
    gate_started = asyncio.Event()
    release_gate = asyncio.Event()
    events: list[str] = []
    key_state = portal_key(
        owner="admin-block-owner",
        token="admin-block-hash",
        blocked=False,
    )

    async def rotator_put(_path, _payload, *, operation_id=None):
        events.append("stage")
        return _staged_policy_result(policy)

    async def gate(_project_id, _revision):
        events.append("gate")
        gate_started.set()
        await release_gate.wait()
        return 0

    async def transition(path, _payload, *, operation_id=None, actor_id=None):
        phase = "activate" if path.endswith("/activate") else "complete"
        events.append(phase)
        intended = _normalized_test_policy(policy)
        return {
            "active_policy": intended,
            "policy": intended,
            "policy_revision": litellm_client.project_policy_revision(intended),
            "reconciliation_pending": phase == "activate",
        }

    async def retune(_project_id, _policy, _models):
        events.append("retune")
        return 0, 0

    async def lookup(_token):
        events.append("admin-lookup")
        return dict(key_state)

    async def update(_token, changes):
        events.append("admin-update")
        key_state.update(changes)
        return {}

    monkeypatch.setattr(main, "_rotator_put", rotator_put)
    monkeypatch.setattr(main, "_rotator_post", transition)
    monkeypatch.setattr(main, "_gate_project_keys", gate)
    monkeypatch.setattr(main, "_retune_project_keys", retune)
    monkeypatch.setattr(litellm_client, "admin_key_lookup", lookup)
    monkeypatch.setattr(litellm_client, "key_update", update)

    policy_task = asyncio.create_task(
        main._apply_project_policy("group-1", policy, "operation-1", ["claude-haiku"])
    )
    await gate_started.wait()
    block_task = asyncio.create_task(main._admin_block_key("admin-block-hash"))
    await asyncio.sleep(0)
    assert "admin-lookup" not in events

    release_gate.set()
    await policy_task
    await block_task
    assert events.index("complete") < events.index("admin-lookup")
    assert key_state["blocked"] is True
    assert key_state["metadata"][
        litellm_client.PORTAL_MANUAL_BLOCK_METADATA_KEY
    ] is True


@pytest.mark.asyncio
async def test_membership_removal_waits_for_complete_policy_cutover(monkeypatch):
    """Both membership-revocation key passes share the admin policy lock."""

    monkeypatch.setattr(main, "_admin_key_policy_lock", asyncio.Lock())
    policy = dict(RESTRICTED_POLICY)
    gate_started = asyncio.Event()
    release_gate = asyncio.Event()
    events: list[str] = []

    async def rotator_put(_path, _payload, *, operation_id=None):
        events.append("stage")
        return _staged_policy_result(policy)

    async def gate(_project_id, _revision):
        events.append("gate")
        gate_started.set()
        await release_gate.wait()
        return 0

    async def transition(path, _payload, *, operation_id=None, actor_id=None):
        phase = "activate" if path.endswith("/activate") else "complete"
        events.append(phase)
        intended = _normalized_test_policy(policy)
        return {
            "active_policy": intended,
            "policy": intended,
            "policy_revision": litellm_client.project_policy_revision(intended),
            "reconciliation_pending": phase == "activate",
        }

    async def retune(_project_id, _policy, _models):
        events.append("retune")
        return 0, 0

    async def managed_project(_group_id):
        events.append("resolve-member-project")
        return "ai-gateway"

    async def deactivate(_user_id, _project_id):
        events.append("deactivate")

    async def remove(_path, *, operation_id=None):
        events.append("remove-member")
        return {}

    monkeypatch.setattr(main, "_rotator_put", rotator_put)
    monkeypatch.setattr(main, "_rotator_post", transition)
    monkeypatch.setattr(main, "_gate_project_keys", gate)
    monkeypatch.setattr(main, "_retune_project_keys", retune)
    monkeypatch.setattr(main, "_managed_project_for_group", managed_project)
    monkeypatch.setattr(main, "_deactivate_subject_project_keys", deactivate)
    monkeypatch.setattr(main, "_rotator_delete", remove)

    policy_task = asyncio.create_task(
        main._apply_project_policy("group-1", policy, "operation-1", ["claude-haiku"])
    )
    await gate_started.wait()
    removal_task = asyncio.create_task(
        main._remove_member_and_deactivate_keys(
            "group-1", "developer-1", "operation-2"
        )
    )
    await asyncio.sleep(0)
    assert "resolve-member-project" not in events

    release_gate.set()
    await policy_task
    assert await removal_task == "ai-gateway"
    assert events.index("complete") < events.index("resolve-member-project")
    assert events[-3:] == ["deactivate", "remove-member", "deactivate"]


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

    async def key_generate(user_id, alias, project_id, project_policy=None, username=None):
        generated.append(project_policy)
        inventory.append(
            portal_key(
                owner=user_id,
                token="minted-hash",
                alias=alias,
                default_model=(project_policy or {}).get("default_model"),
                policy_revision=(project_policy or {}).get(
                    litellm_client.PROJECT_POLICY_REVISION_FIELD
                ),
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
    assert generated == [
        {
            **RESTRICTED_POLICY,
            litellm_client.PROJECT_POLICY_REVISION_FIELD: (
                litellm_client.project_policy_revision(RESTRICTED_POLICY)
            ),
        }
    ]


def test_unrestricted_policy_mints_an_explicit_current_model_scope(
    client, set_session, monkeypatch
):
    generated = []
    inventory: list[dict] = []

    async def key_list(_user_id):
        return [dict(entry) for entry in inventory]

    async def key_generate(
        user_id, alias, project_id, project_policy=None, username=None
    ):
        generated.append(project_policy)
        inventory.append(
            portal_key(
                owner=user_id,
                token="minted-hash",
                alias=alias,
                policy_revision=(project_policy or {}).get(
                    litellm_client.PROJECT_POLICY_REVISION_FIELD
                ),
            )
        )
        return {"key": "sk-minted-once"}

    monkeypatch.setattr(litellm_client, "key_list", key_list)
    monkeypatch.setattr(litellm_client, "key_generate", key_generate)
    csrf = "c" * 43
    set_session({"user": portal_user(), "csrf_token": csrf})

    response = client.post(
        "/keys",
        data={"alias": "laptop", "project_id": "ai-gateway", "csrf_token": csrf},
    )

    assert response.status_code == 201
    assert generated == [
        {
            "tpm_limit": None,
            "rpm_limit": None,
            "allowed_models": ["claude-haiku", "claude-sonnet"],
            "default_model": None,
            "model_limits": {},
            litellm_client.PROJECT_POLICY_REVISION_FIELD: (
                litellm_client.project_policy_revision(
                    {
                        "tpm_limit": None,
                        "rpm_limit": None,
                        "allowed_models": None,
                        "default_model": None,
                        "model_limits": {},
                    }
                )
            ),
        }
    ]


def test_unreadable_project_policy_fails_the_mint_closed(
    client, set_session, monkeypatch
):
    called = False

    async def live_policies(_request, _user, project_ids):
        raise main.HTTPException(
            status_code=503, detail="Current project policy could not be verified."
        )

    async def key_generate(user_id, alias, project_id, project_policy=None, username=None):
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

    async def rotator_put(path, payload, *, operation_id=None):
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
    posts = []
    key_updates = []
    policy = {
        "tpm_limit": 50000,
        "rpm_limit": 30,
        "allowed_models": ["claude-haiku"],
        "default_model": "claude-haiku",
        "model_limits": {
            "claude-haiku": {
                "max_output_tokens_per_request": 4096,
                "output_tokens_per_utc_minute": 100000,
            }
        },
    }
    revision = litellm_client.project_policy_revision(policy)
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

    async def rotator_put(path, payload, *, operation_id=None):
        puts.append((path, payload))
        return _staged_policy_result(policy)

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
    monkeypatch.setattr(main, "_rotator_post", _policy_transition_stub(policy, posts))
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
            "limit_models": "claude-haiku",
            "max_output_tokens_per_request": "4096",
            "output_tokens_per_utc_minute": "100000",
            "csrf_token": csrf,
        },
        follow_redirects=True,
    )

    assert puts == [
        (
            "/identity/groups/group-1/policy",
            policy,
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
                "blocked": True,
                "metadata": {
                    "created_via": "dev-portal",
                    "aigw_project_id": "ai-gateway",
                    "aigw_policy_gate_v1": revision,
                },
            },
        ),
        (
            "portal-1",
            {
                "tpm_limit": 50000,
                "rpm_limit": 30,
                "models": ["claude-haiku"],
                "blocked": True,
                "metadata": {
                    "created_via": "dev-portal",
                    "aigw_project_id": "ai-gateway",
                    "aigw_default_model": "claude-haiku",
                    "aigw_model_limits_v1": (
                        '{"claude-haiku":{'
                        '"max_output_tokens_per_request":4096,'
                        '"output_tokens_per_utc_minute":100000}}'
                    ),
                    "aigw_policy_revision_v1": revision,
                    "aigw_policy_gate_v1": revision,
                },
            },
        ),
        ("portal-1", {"blocked": False}),
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
                    "aigw_model_limits_v1": (
                        '{"claude-haiku":{'
                        '"max_output_tokens_per_request":4096,'
                        '"output_tokens_per_utc_minute":100000}}'
                    ),
                    "aigw_policy_revision_v1": revision,
                },
            },
        ),
    ]
    assert [call[0] for call in posts] == [
        "/identity/groups/group-1/policy/activate",
        "/identity/groups/group-1/policy/complete",
    ]
    assert len({call[2] for call in posts}) == 1
    assert "1 active keys gated and 1 keys reconciled" in response.text


def test_project_policy_deny_all_models_scopes_keys_to_the_sentinel(
    admin_client, set_admin_session, monkeypatch
):
    """The 'No model access' option must scope the group to a reserved sentinel
    that matches no real model, so API/tooling keys can call nothing. Chat is
    gated separately by the aigw-chat role."""
    puts = []
    posts = []
    key_updates = []
    policy = {
        "tpm_limit": None,
        "rpm_limit": None,
        "allowed_models": [litellm_client.NO_MODELS_SENTINEL],
        "default_model": None,
        "model_limits": {},
    }
    key_state = {
        "portal-1": full_key_object(
            token="portal-1",
            user_id="dev-a",
            metadata={
                "created_via": "dev-portal",
                "aigw_project_id": "ai-gateway",
            },
        )
    }

    async def rotator_get(path):
        if path == "/identity/groups":
            return [{
                "id": "group-1", "name": "ai-gateway",
                "capabilities": ["aigw-developers"], "member_count": 1,
                "policy": {"tpm_limit": None, "rpm_limit": None,
                           "allowed_models": None, "default_model": None},
            }]
        return {"admin": True}

    async def rotator_put(path, payload, *, operation_id=None):
        puts.append((path, payload))
        return _staged_policy_result(policy)

    async def admin_key_list_page(page):
        return {
            "keys": [dict(entry) for entry in key_state.values()],
            "page": 1,
            "total_pages": 1,
            "total_count": 1,
        }

    async def key_update(key, updates):
        key_updates.append((key, updates))
        key_state[key].update(updates)
        return {}

    async def admin_key_lookup(token):
        return dict(key_state[token])

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(main, "_rotator_put", rotator_put)
    monkeypatch.setattr(main, "_rotator_post", _policy_transition_stub(policy, posts))
    monkeypatch.setattr(litellm_client, "admin_key_list_page", admin_key_list_page)
    monkeypatch.setattr(litellm_client, "key_update", key_update)
    monkeypatch.setattr(litellm_client, "admin_key_lookup", admin_key_lookup)
    csrf = "c" * 43
    set_admin_session({"user": portal_user(roles=[settings.admin_role]),
                       "csrf_token": csrf, "admin_reauth_at": int(time.time())})

    admin_client.post(
        "/admin/identity/groups/group-1/policy",
        data={"tpm_limit": "", "rpm_limit": "", "deny_all_models": "1",
              "default_model": "", "csrf_token": csrf},
        follow_redirects=True)

    assert puts == [("/identity/groups/group-1/policy", policy)]
    # The re-tuned key is scoped to the sentinel — no real model is callable.
    assert key_state["portal-1"]["models"] == [litellm_client.NO_MODELS_SENTINEL]
    assert key_state["portal-1"]["blocked"] is False
    assert len(key_updates) == 4
    assert len(posts) == 2


def test_project_policy_all_and_none_are_mutually_exclusive(
    admin_client, set_admin_session, monkeypatch
):
    async def rotator_get(path):
        if path == "/identity/groups":
            return [{"id": "group-1", "name": "ai-gateway",
                     "capabilities": ["aigw-developers"], "member_count": 1,
                     "policy": {"tpm_limit": None, "rpm_limit": None,
                                "allowed_models": None, "default_model": None}}]
        return {"admin": True}

    async def rotator_put(path, payload, *, operation_id=None):
        raise AssertionError("must not persist an ambiguous all+none policy")

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(main, "_rotator_put", rotator_put)
    csrf = "c" * 43
    set_admin_session({"user": portal_user(roles=[settings.admin_role]),
                       "csrf_token": csrf, "admin_reauth_at": int(time.time())})
    resp = admin_client.post(
        "/admin/identity/groups/group-1/policy",
        data={"tpm_limit": "", "rpm_limit": "", "deny_all_models": "1",
              "remove_model_restrictions": "1", "csrf_token": csrf},
        follow_redirects=True)
    assert "not both" in resp.text


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

    async def key_generate(user_id, alias, project_id, project_policy=None, username=None):
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
    admin_client, set_admin_session, monkeypatch, caplog
):
    """A failed re-tune stays gated and the same-policy retry can finish."""

    policy = {
        "tpm_limit": 50000,
        "rpm_limit": 30,
        "allowed_models": ["claude-haiku"],
        "default_model": "claude-haiku",
        "model_limits": {},
    }
    posts = []
    drop_retune_metadata = {"value": True}

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

    async def rotator_put(path, payload, *, operation_id=None):
        return _staged_policy_result(policy)

    async def admin_key_list_page(page):
        keys = [dict(entry) for entry in key_state.values()]
        return {"keys": keys, "page": 1, "total_pages": 1, "total_count": len(keys)}

    async def key_update(key, updates):
        # The gate lands. On the first re-tune attempt, upstream accepts the
        # update but silently drops the new policy metadata.
        drops_stamp = (
            drop_retune_metadata["value"]
            and litellm_client.PORTAL_POLICY_REVISION_METADATA_KEY
            in updates.get("metadata", {})
        )
        applied = {
            name: value
            for name, value in updates.items()
            if not (drops_stamp and name == "metadata")
        }
        key_state[key].update(applied)
        return {}

    async def admin_key_lookup(token):
        return dict(key_state[token])

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(main, "_rotator_put", rotator_put)
    monkeypatch.setattr(main, "_rotator_post", _policy_transition_stub(policy, posts))
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

    with caplog.at_level("INFO", logger="dev-portal"):
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

    assert "Policy reconciliation is incomplete" in response.text
    assert key_state["portal-1"]["blocked"] is True
    assert litellm_client.PORTAL_POLICY_GATE_METADATA_KEY in key_state[
        "portal-1"
    ]["metadata"]
    events = security_events(caplog)
    operation_id = events[0]["operation_id"]
    assert events == [
        {
            "schema_version": 1,
            "event": "aigw.portal.audit",
            "action": "identity.group.policy",
            "outcome": outcome,
            "subject": "subject-123",
            "group": "group-1",
            "operation_id": operation_id,
            **({"project": "ai-gateway"} if outcome == "indeterminate" else {}),
        }
        for outcome in ("intent", "indeterminate")
    ]

    # A retry of the same pending policy resumes safely. The key receives the
    # complete policy while blocked and is unblocked only after verification.
    drop_retune_metadata["value"] = False
    caplog.clear()
    with caplog.at_level("INFO", logger="dev-portal"):
        retried = admin_client.post(
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
    assert "Project policy saved" in retried.text
    assert key_state["portal-1"]["blocked"] is False
    assert key_state["portal-1"]["metadata"][
        litellm_client.PORTAL_POLICY_REVISION_METADATA_KEY
    ] == litellm_client.project_policy_revision(policy)
    assert litellm_client.PORTAL_POLICY_GATE_METADATA_KEY not in key_state[
        "portal-1"
    ]["metadata"]


@pytest.mark.asyncio
async def test_project_policy_failed_unblock_keeps_durable_gate_for_retry(
    monkeypatch,
):
    policy = {
        **RESTRICTED_POLICY,
        litellm_client.PROJECT_POLICY_REVISION_FIELD: (
            litellm_client.project_policy_revision(RESTRICTED_POLICY)
        ),
    }
    revision = policy[litellm_client.PROJECT_POLICY_REVISION_FIELD]
    key_state = full_key_object(
        token="portal-1",
        user_id="dev-a",
        blocked=True,
        metadata={
            "created_via": "dev-portal",
            "aigw_project_id": "ai-gateway",
            litellm_client.PORTAL_POLICY_GATE_METADATA_KEY: revision,
        },
    )
    fail_unblock = {"value": True}

    async def admin_key_list_page(page):
        assert page == 1
        return {
            "keys": [dict(key_state)],
            "page": 1,
            "total_pages": 1,
            "total_count": 1,
        }

    async def key_update(_key, updates):
        if updates == {"blocked": False} and fail_unblock["value"]:
            raise litellm_client.LiteLLMError("lost unblock response")
        key_state.update(updates)
        return {}

    async def admin_key_lookup(_key):
        return dict(key_state)

    monkeypatch.setattr(
        litellm_client, "admin_key_list_page", admin_key_list_page
    )
    monkeypatch.setattr(litellm_client, "key_update", key_update)
    monkeypatch.setattr(litellm_client, "admin_key_lookup", admin_key_lookup)

    assert await main._retune_project_keys(
        "ai-gateway", policy, ["claude-haiku"]
    ) == (0, 1)
    assert key_state["blocked"] is True
    assert key_state["metadata"][
        litellm_client.PORTAL_POLICY_GATE_METADATA_KEY
    ] == revision

    fail_unblock["value"] = False
    assert await main._retune_project_keys(
        "ai-gateway", policy, ["claude-haiku"]
    ) == (1, 0)
    assert key_state["blocked"] is False
    assert litellm_client.PORTAL_POLICY_GATE_METADATA_KEY not in key_state[
        "metadata"
    ]


@pytest.mark.asyncio
async def test_policy_retry_preserves_a_durable_manual_block(monkeypatch):
    """A later policy retry never mistakes a manual block for its own gate."""

    policy = {
        **RESTRICTED_POLICY,
        litellm_client.PROJECT_POLICY_REVISION_FIELD: (
            litellm_client.project_policy_revision(RESTRICTED_POLICY)
        ),
    }
    key_state = full_key_object(
        token="portal-manual-block",
        user_id="dev-a",
        blocked=True,
        models=["claude-sonnet"],
        metadata={
            "created_via": "dev-portal",
            "aigw_project_id": "ai-gateway",
            litellm_client.PORTAL_POLICY_REVISION_METADATA_KEY: "0" * 64,
            litellm_client.PORTAL_MANUAL_BLOCK_METADATA_KEY: True,
        },
    )
    updates: list[dict] = []

    async def admin_key_list_page(_page):
        return {
            "keys": [dict(key_state)],
            "page": 1,
            "total_pages": 1,
            "total_count": 1,
        }

    async def key_update(_key, change):
        updates.append(dict(change))
        key_state.update(change)
        return {}

    async def admin_key_lookup(_key):
        return dict(key_state)

    monkeypatch.setattr(litellm_client, "admin_key_list_page", admin_key_list_page)
    monkeypatch.setattr(litellm_client, "key_update", key_update)
    monkeypatch.setattr(litellm_client, "admin_key_lookup", admin_key_lookup)

    assert await main._retune_project_keys(
        "ai-gateway", policy, ["claude-haiku"]
    ) == (1, 0)
    assert key_state["blocked"] is True
    assert key_state["metadata"][
        litellm_client.PORTAL_MANUAL_BLOCK_METADATA_KEY
    ] is True
    assert all(change.get("blocked") is not False for change in updates)


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


@pytest.mark.parametrize(
    "retune_failure",
    [
        litellm_client.LiteLLMError(
            "api_key=do-not-export-post-policy-secret"
        ),
        RuntimeError("token=do-not-export-post-policy-secret"),
    ],
)
def test_project_policy_retune_exception_is_correlated_indeterminate(
    admin_client, set_admin_session, monkeypatch, caplog, retune_failure
):
    policy = {
        "tpm_limit": 1000,
        "rpm_limit": None,
        "allowed_models": None,
        "default_model": None,
        "model_limits": {},
    }
    posts = []

    async def rotator_get(path):
        if path == "/identity/groups":
            return [_unlimited_group()]
        return {"admin": True}

    async def rotator_put(path, payload, *, operation_id=None):
        return _staged_policy_result(policy)

    async def gate_keys(_project_id, _policy_revision):
        return 0

    async def fail_retune(_project_id, _policy, _configured_models=None):
        raise retune_failure

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(main, "_rotator_put", rotator_put)
    monkeypatch.setattr(main, "_rotator_post", _policy_transition_stub(policy, posts))
    monkeypatch.setattr(main, "_gate_project_keys", gate_keys)
    monkeypatch.setattr(main, "_retune_project_keys", fail_retune)
    csrf = "c" * 43
    set_admin_session(
        {
            "user": portal_user(roles=[settings.admin_role]),
            "csrf_token": csrf,
            "admin_reauth_at": int(time.time()),
        }
    )

    with caplog.at_level("INFO", logger="dev-portal"):
        response = admin_client.post(
            "/admin/identity/groups/group-1/policy",
            data={"tpm_limit": "1000", "csrf_token": csrf},
            follow_redirects=False,
        )

    assert response.status_code == 303
    events = security_events(caplog)
    operation_id = events[0]["operation_id"]
    assert [event["outcome"] for event in events] == ["intent", "indeterminate"]
    assert {event["operation_id"] for event in events} == {operation_id}
    assert events[-1]["project"] == "ai-gateway"
    assert "do-not-export-post-policy-secret" not in caplog.text


def test_project_policy_rejects_unconfigured_models_before_the_controller(
    admin_client, set_admin_session, monkeypatch
):
    called = False

    async def rotator_get(path):
        if path == "/identity/groups":
            return [_unlimited_group()]
        return {"admin": True}

    async def rotator_put(path, payload, *, operation_id=None):
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

    async def rotator_put(path, payload, *, operation_id=None):
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


# --- model-governance admin surface ------------------------------------------


def _governed_model_row(**overrides):
    row = {
        "operation_id": "11111111-1111-4111-8111-111111111111",
        "gateway_model_name": "claude-sonnet-4-5",
        "provider_name": "anthropic",
        "provider_model_id": "claude-sonnet-4-5",
        "initial_visible_in_discovery": False,
        "visible_in_discovery": False,
        "lifecycle_state": "draft",
        "active": False,
        "last_event_sequence": None,
        "source_reference": "anthropic-model-catalog-2026-07-22",
        "review_note": "Reviewed against the approved provider catalog.",
        "document_sha256": "a" * 64,
        "created_at": "2026-07-22T12:00:00Z",
        # These server-owned fields must never enter the portal view model.
        "api_base": "http://envoy-egress:8080/anthropic",
        "litellm_credential_name": "anthropic-primary",
    }
    row.update(overrides)
    return row


def _governed_price_row(**overrides):
    row = {
        "version_id": "anthropic-sonnet-input-2026-08-01",
        "operation_id": "22222222-2222-4222-8222-222222222222",
        "gateway_model_name": "claude-sonnet-4-5",
        "provider_name": "anthropic",
        "usage_class": "normal_input",
        "token_unit": 1_000_000,
        "amount": "30",
        "currency": "USD",
        "explicit_free": False,
        "effective_at": "2026-08-01T00:00:00Z",
        "source_reference": "anthropic-pricing-2026-07-22",
        "review_note": "Reviewed by the platform pricing owner.",
        "document_sha256": "b" * 64,
    }
    row.update(overrides)
    return row


def _governance_audit_row(**overrides):
    row = {
        "operation_id": "11111111-1111-4111-8111-111111111111",
        "actor": "subject-123",
        "action": "model_version_created",
        "resource_type": "model_version",
        "resource_id": "claude-sonnet-4-5",
        "document_sha256": "a" * 64,
        "created_at": "2026-07-22T12:00:00Z",
    }
    row.update(overrides)
    return row


def test_model_and_price_views_are_bounded_allowlists() -> None:
    models = model_admin.safe_governed_models([_governed_model_row()])
    assert models[0]["gateway_model_name"] == "claude-sonnet-4-5"
    assert "api_base" not in models[0]
    assert "litellm_credential_name" not in models[0]

    prices = model_admin.safe_governed_prices(
        [_governed_price_row()], gateway_model_name="claude-sonnet-4-5"
    )
    assert prices[0]["amount"] == "30"
    assert prices[0]["token_unit"] == 1_000_000
    assert prices[0]["usage_class_label"] == "Normal input"

    audit = model_admin.safe_governance_audit([_governance_audit_row()])
    assert audit[0]["action"] == "model_version_created"


@pytest.mark.parametrize(
    "document",
    [
        [_governed_model_row(provider_name="unreviewed")],
        [_governed_model_row(operation_id="not-a-uuid")],
        [_governed_model_row(source_reference="https://provider.test/models")],
        [_governed_model_row(document_sha256="0" * 63)],
    ],
)
def test_model_view_rejects_malformed_or_unreviewed_rows(document) -> None:
    with pytest.raises(ValueError, match="governed model row"):
        model_admin.safe_governed_models(document)


@pytest.mark.parametrize(
    "document",
    [
        [_governed_price_row(gateway_model_name="other-model")],
        [_governed_price_row(usage_class="blended-input")],
        [_governed_price_row(token_unit=3, amount="1")],
        [_governed_price_row(amount="0", explicit_free=False)],
        [_governed_price_row(currency="EUR")],
    ],
)
def test_price_view_rejects_ambiguous_or_inexact_rows(document) -> None:
    with pytest.raises(ValueError, match="governed price row"):
        model_admin.safe_governed_prices(
            document, gateway_model_name="claude-sonnet-4-5"
        )


def _backdate_preview_row(**overrides):
    row = {
        "preview_id": "33333333-3333-4333-8333-333333333333",
        "candidate_sha256": "c" * 64,
        "preview_sha256": "d" * 64,
        "gateway_model_name": "claude-sonnet-4-5",
        "usage_class": "normal_input",
        "token_unit": 1_000_000,
        "amount": "30",
        "explicit_free": False,
        "effective_at": "2026-07-01T00:00:00Z",
        "effective_to": "2026-08-01T00:00:00Z",
        "source_reference": "anthropic-pricing-correction-2026-07-22",
        "review_note": "Corrects the reviewed price on this date.",
        "affected_count": 1,
        "shown_affected_count": 1,
        "affected_rows_truncated": False,
        "old_total_usd": "0.0003",
        "new_total_usd": "0.0004",
        "delta_usd": "0.0001",
        "old_unknown_count": 0,
        "new_unknown_count": 0,
        "affected_rows": [
            {
                "usage_event_id": "e" * 64,
                "usage_class": "normal_input",
                "units": 10,
                "previous_component_cost_usd": "0.0003",
                "new_component_cost_usd": "0.0004",
                "component_delta_usd": "0.0001",
                "previous_total_cost_usd": "0.0003",
                "new_total_cost_usd": "0.0004",
                "row_sha256": "f" * 64,
            }
        ],
    }
    row.update(overrides)
    return row


def test_backdate_preview_view_preserves_unknown_and_signed_delta() -> None:
    row = _backdate_preview_row(
        old_total_usd=None,
        delta_usd=None,
        old_unknown_count=1,
        affected_rows=[
            {
                **_backdate_preview_row()["affected_rows"][0],
                "previous_component_cost_usd": None,
                "component_delta_usd": None,
                "previous_total_cost_usd": None,
            }
        ],
    )

    preview = model_admin.safe_backdate_preview(row)

    assert preview["old_total_usd"] is None
    assert preview["delta_usd"] is None
    assert preview["affected_rows"][0]["component_delta_usd"] is None

    negative = model_admin.safe_backdate_preview(
        _backdate_preview_row(
            old_total_usd="0.0004",
            new_total_usd="0.0003",
            delta_usd="-0.0001",
            affected_rows=[
                {
                    **_backdate_preview_row()["affected_rows"][0],
                    "previous_component_cost_usd": "0.0004",
                    "new_component_cost_usd": "0.0003",
                    "component_delta_usd": "-0.0001",
                    "previous_total_cost_usd": "0.0004",
                    "new_total_cost_usd": "0.0003",
                }
            ],
        )
    )
    assert negative["delta_usd"] == "-0.0001"


@pytest.mark.parametrize(
    "document",
    [
        _backdate_preview_row(candidate_sha256="c" * 63),
        _backdate_preview_row(old_total_usd="-0.0001"),
        _backdate_preview_row(shown_affected_count=0),
        _backdate_preview_row(old_total_usd=None, old_unknown_count=0),
    ],
)
def test_backdate_preview_view_rejects_malformed_or_inconsistent_rows(
    document,
) -> None:
    with pytest.raises(ValueError, match="backdate"):
        model_admin.safe_backdate_preview(document)


def _model_governance_admin_rotator(monkeypatch):
    async def rotator_get(path):
        if path == "/identity/authorization/subject-123":
            return {"admin": True}
        if path in {"/status", "/settings"} or path.startswith("/history"):
            return []
        if path == "/providers/anthropic":
            return {
                "vendor": "anthropic",
                "state": "awaiting_enrollment",
                "configured": False,
                "enabled": False,
                "private_key_jwt_ready": True,
                "nonsecret_ids": {},
            }
        if path == "/identity/status":
            return None
        if path == "/model-governance/models":
            return [_governed_model_row()]
        if path == (
            "/model-governance/models/claude-sonnet-4-5/prices"
        ):
            return [_governed_price_row()]
        if path == "/model-governance/audit?limit=50":
            return [_governance_audit_row()]
        raise AssertionError(path)

    monkeypatch.setattr(main, "_rotator_get", rotator_get)


def test_admin_page_renders_governed_models_prices_and_backdate_preview(
    admin_client, set_admin_session, monkeypatch
):
    _model_governance_admin_rotator(monkeypatch)
    set_admin_session(
        {
            "user": portal_user(roles=[settings.admin_role]),
            "csrf_token": "c" * 43,
            "admin_reauth_at": int(time.time()),
        }
    )

    response = admin_client.get("/admin#tab-models")

    assert response.status_code == 200
    assert "Models &amp; pricing" in response.text
    assert "claude-sonnet-4-5" in response.text
    assert "$30" in response.text
    assert "1,000,000 tokens" in response.text
    assert "Backdating never rewrites history" in response.text
    assert 'action="/admin/model-governance/models"' in response.text
    assert 'action="/admin/model-governance/lifecycle"' in response.text
    assert 'value="activate"' in response.text
    assert 'action="/admin/model-governance/prices"' in response.text
    assert (
        'action="/admin/model-governance/prices/backdate/preview"'
        in response.text
    )
    for forbidden in (
        'name="actor_id"',
        'name="hostname"',
        'name="api_base"',
        'name="ca_file"',
        'name="credential"',
    ):
        assert forbidden not in response.text


def test_model_create_uses_oidc_actor_uuid4_and_hidden_default(
    admin_client, set_admin_session, monkeypatch, caplog
):
    captured = {}

    async def rotator_get(path):
        assert path == "/identity/authorization/subject-123"
        return {"admin": True}

    async def rotator_post(
        path, payload=None, *, operation_id=None, actor_id=None
    ):
        captured.update(
            path=path,
            payload=payload,
            operation_id=operation_id,
            actor_id=actor_id,
        )
        return {}

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(main, "_rotator_post", rotator_post)
    csrf = "c" * 43
    set_admin_session(
        {
            "user": portal_user(roles=[settings.admin_role]),
            "csrf_token": csrf,
            "admin_reauth_at": int(time.time()),
        }
    )

    with caplog.at_level("INFO", logger="dev-portal"):
        response = admin_client.post(
            "/admin/model-governance/models",
            data={
                "gateway_model_name": "claude-sonnet-4-5",
                "provider_name": "anthropic",
                "provider_model_id": "claude-sonnet-4-5",
                "source_reference": "anthropic-model-catalog-2026-07-22",
                "review_note": "Reviewed against the approved provider catalog.",
                "csrf_token": csrf,
                # Extra browser fields never become controller input.
                "actor_id": "spoofed-admin",
                "hostname": "attacker.test",
                "api_base": "https://attacker.test",
                "ca_file": "/tmp/unreviewed.pem",
                "visible_in_discovery": "true",
            },
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert captured["path"] == "/model-governance/models"
    assert captured["actor_id"] == "subject-123"
    assert main._canonical_operation_id(captured["operation_id"])
    assert captured["payload"] == {
        "gateway_model_name": "claude-sonnet-4-5",
        "provider_name": "anthropic",
        "provider_model_id": "claude-sonnet-4-5",
        "visible_in_discovery": False,
        "source_reference": "anthropic-model-catalog-2026-07-22",
        "review_note": "Reviewed against the approved provider catalog.",
    }
    assert [event["outcome"] for event in security_events(caplog)] == [
        "intent",
        "success",
    ]
    assert {
        event["action"] for event in security_events(caplog)
    } == {"model.governance.create"}


@pytest.mark.parametrize("action", ["activate", "show", "hide", "retire"])
def test_model_lifecycle_uses_step_up_actor_csrf_and_uuid4(
    admin_client, set_admin_session, monkeypatch, caplog, action
):
    captured = {}

    async def rotator_get(path):
        assert path == "/identity/authorization/subject-123"
        return {"admin": True}

    async def rotator_post(
        path, payload=None, *, operation_id=None, actor_id=None
    ):
        captured.update(
            path=path,
            payload=payload,
            operation_id=operation_id,
            actor_id=actor_id,
        )
        return {}

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(main, "_rotator_post", rotator_post)
    csrf = "c" * 43
    set_admin_session(
        {
            "user": portal_user(roles=[settings.admin_role]),
            "csrf_token": csrf,
            "admin_reauth_at": int(time.time()),
        }
    )

    with caplog.at_level("INFO", logger="dev-portal"):
        response = admin_client.post(
            "/admin/model-governance/lifecycle",
            data={
                "gateway_model_name": "claude-sonnet-4-5",
                "action": action,
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert captured["path"] == (
        f"/model-governance/models/claude-sonnet-4-5/{action}"
    )
    assert captured["payload"] == {}
    assert captured["actor_id"] == "subject-123"
    assert main._canonical_operation_id(captured["operation_id"])
    assert [event["outcome"] for event in security_events(caplog)] == [
        "intent",
        "success",
    ]
    assert {
        event["action"] for event in security_events(caplog)
    } == {f"model.governance.{action}"}


def test_model_lifecycle_rejects_bad_csrf_before_controller_call(
    admin_client, set_admin_session, monkeypatch
):
    called = False

    async def rotator_get(path):
        assert path == "/identity/authorization/subject-123"
        return {"admin": True}

    async def rotator_post(*args, **kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(main, "_rotator_post", rotator_post)
    set_admin_session(
        {
            "user": portal_user(roles=[settings.admin_role]),
            "csrf_token": "c" * 43,
            "admin_reauth_at": int(time.time()),
        }
    )
    response = admin_client.post(
        "/admin/model-governance/lifecycle",
        data={
            "gateway_model_name": "claude-sonnet-4-5",
            "action": "activate",
            "csrf_token": "x" * 43,
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert called is False


@pytest.mark.parametrize(
    ("provider_name", "csrf_ok", "fresh_step_up", "expected_location"),
    [
        ("unreviewed", True, True, "/admin?price_model=claude-sonnet-4-5#tab-models"),
        ("anthropic", False, True, "/admin?price_model=claude-sonnet-4-5#tab-models"),
        ("anthropic", True, False, "/admin/reauth"),
    ],
)
def test_model_create_rejects_unapproved_provider_bad_csrf_or_stale_step_up(
    admin_client,
    set_admin_session,
    monkeypatch,
    provider_name,
    csrf_ok,
    fresh_step_up,
    expected_location,
):
    called = False

    async def rotator_get(path):
        assert path == "/identity/authorization/subject-123"
        return {"admin": True}

    async def rotator_post(*_args, **_kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(main, "_rotator_post", rotator_post)
    csrf = "c" * 43
    session = {
        "user": portal_user(roles=[settings.admin_role]),
        "csrf_token": csrf,
    }
    if fresh_step_up:
        session["admin_reauth_at"] = int(time.time())
    set_admin_session(session)

    response = admin_client.post(
        "/admin/model-governance/models",
        data={
            "gateway_model_name": "claude-sonnet-4-5",
            "provider_name": provider_name,
            "provider_model_id": "claude-sonnet-4-5",
            "source_reference": "anthropic-model-catalog-2026-07-22",
            "review_note": "Reviewed against the approved provider catalog.",
            "csrf_token": csrf if csrf_ok else "x" * 43,
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == expected_location
    assert called is False


@pytest.mark.parametrize(
    ("amount", "explicit_free", "expected_free"),
    [("30", None, False), ("0", "1", True)],
)
def test_future_price_uses_exact_text_and_oidc_actor(
    admin_client,
    set_admin_session,
    monkeypatch,
    amount,
    explicit_free,
    expected_free,
    caplog,
):
    captured = {}

    async def rotator_get(path):
        assert path == "/identity/authorization/subject-123"
        return {"admin": True}

    async def rotator_post(
        path, payload=None, *, operation_id=None, actor_id=None
    ):
        captured.update(
            path=path,
            payload=payload,
            operation_id=operation_id,
            actor_id=actor_id,
        )
        return {}

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(main, "_rotator_post", rotator_post)
    csrf = "c" * 43
    set_admin_session(
        {
            "user": portal_user(roles=[settings.admin_role]),
            "csrf_token": csrf,
            "admin_reauth_at": int(time.time()),
        }
    )
    form = {
        "gateway_model_name": "claude-sonnet-4-5",
        "usage_class": "normal_input",
        "token_unit": "1000000",
        "amount": amount,
        "effective_at_utc": (
            datetime.now(timezone.utc) + timedelta(days=2)
        ).strftime("%Y-%m-%dT%H:%M"),
        "source_reference": "anthropic-pricing-2026-07-22",
        "review_note": "Reviewed by the platform pricing owner.",
        "csrf_token": csrf,
        "actor_id": "spoofed-admin",
        "currency": "EUR",
        "version_id": "attacker-controlled",
    }
    if explicit_free is not None:
        form["explicit_free"] = explicit_free

    with caplog.at_level("INFO", logger="dev-portal"):
        response = admin_client.post(
            "/admin/model-governance/prices",
            data=form,
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert captured["path"] == "/model-governance/prices"
    assert captured["actor_id"] == "subject-123"
    assert main._canonical_operation_id(captured["operation_id"])
    assert captured["payload"]["version_id"] == (
        "price-" + captured["operation_id"]
    )
    assert captured["payload"]["amount"] == amount
    assert captured["payload"]["token_unit"] == 1_000_000
    assert captured["payload"]["explicit_free"] is expected_free
    assert captured["payload"]["effective_at"].endswith("Z")
    assert "currency" not in captured["payload"]
    assert [event["outcome"] for event in security_events(caplog)] == [
        "intent",
        "success",
    ]
    assert {event["action"] for event in security_events(caplog)} == {
        "model.price.create"
    }


def test_backdate_preview_uses_stored_controller_receipt(
    admin_client, set_admin_session, monkeypatch, caplog
):
    captured = {}

    async def rotator_get(path):
        assert path == "/identity/authorization/subject-123"
        return {"admin": True}

    async def rotator_post(
        path, payload=None, *, operation_id=None, actor_id=None
    ):
        captured.update(
            path=path,
            payload=payload,
            operation_id=operation_id,
            actor_id=actor_id,
        )
        return _backdate_preview_row(preview_id=operation_id)

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(main, "_rotator_post", rotator_post)
    csrf = "c" * 43
    set_admin_session(
        {
            "user": portal_user(roles=[settings.admin_role]),
            "csrf_token": csrf,
            "admin_reauth_at": int(time.time()),
        }
    )

    with caplog.at_level("INFO", logger="dev-portal"):
        response = admin_client.post(
            "/admin/model-governance/prices/backdate/preview",
            data={
                "gateway_model_name": "claude-sonnet-4-5",
                "usage_class": "normal_input",
                "token_unit": "1000000",
                "amount": "30",
                "effective_at_utc": (
                    datetime.now(timezone.utc) - timedelta(days=2)
                ).strftime("%Y-%m-%dT%H:%M"),
                "source_reference": "anthropic-pricing-correction-2026-07-22",
                "review_note": "Corrects the reviewed price on this date.",
                "csrf_token": csrf,
                "candidate_sha256": "0" * 64,
                "preview_sha256": "0" * 64,
                "actor_id": "spoofed-admin",
            },
            follow_redirects=False,
        )

    assert response.status_code == 200
    assert "Review the backdated price" in response.text
    assert "30 USD per 1000000 tokens" in response.text
    assert "anthropic-pricing-correction-2026-07-22" in response.text
    assert "Corrects the reviewed price on this date." in response.text
    assert "0.0001 USD" in response.text
    assert "CONFIRM BACKDATED PRICE" in response.text
    assert f'name="preview_id" value="{captured["operation_id"]}"' in response.text
    assert captured["path"] == "/model-governance/prices/backdate/preview"
    assert captured["actor_id"] == "subject-123"
    assert main._canonical_operation_id(captured["operation_id"])
    assert captured["payload"]["version_id"] == (
        "price-" + captured["operation_id"]
    )
    assert captured["payload"]["amount"] == "30"
    assert captured["payload"]["explicit_free"] is False
    assert "candidate_sha256" not in captured["payload"]
    assert "preview_sha256" not in captured["payload"]
    assert [event["outcome"] for event in security_events(caplog)] == [
        "intent",
        "success",
    ]
    assert {event["action"] for event in security_events(caplog)} == {
        "model.price.backdate.preview"
    }


def test_backdate_confirm_binds_both_digests_and_new_operation(
    admin_client, set_admin_session, monkeypatch, caplog
):
    captured = {}
    preview_id = "33333333-3333-4333-8333-333333333333"

    async def rotator_get(path):
        assert path == "/identity/authorization/subject-123"
        return {"admin": True}

    async def rotator_post(
        path, payload=None, *, operation_id=None, actor_id=None
    ):
        captured.update(
            path=path,
            payload=payload,
            operation_id=operation_id,
            actor_id=actor_id,
        )
        return {
            "preview_id": preview_id,
            "candidate_sha256": "c" * 64,
            "preview_sha256": "d" * 64,
            "confirmation_operation_id": operation_id,
            "version_id": f"price-{preview_id}",
            "gateway_model_name": "claude-sonnet-4-5",
            "usage_class": "normal_input",
            "affected_count": 1,
            "adjustment_count": 1,
            "delta_usd": "-0.0001",
        }

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(main, "_rotator_post", rotator_post)
    csrf = "c" * 43
    set_admin_session(
        {
            "user": portal_user(roles=[settings.admin_role]),
            "csrf_token": csrf,
            "admin_reauth_at": int(time.time()),
        }
    )

    with caplog.at_level("INFO", logger="dev-portal"):
        response = admin_client.post(
            "/admin/model-governance/prices/backdate/confirm",
            data={
                "preview_id": preview_id,
                "candidate_sha256": "c" * 64,
                "preview_sha256": "d" * 64,
                "gateway_model_name": "forged-model",
                "usage_class": "output",
                "confirmation": "CONFIRM BACKDATED PRICE",
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert captured["path"] == (
        f"/model-governance/prices/backdate/{preview_id}/confirm"
    )
    assert captured["actor_id"] == "subject-123"
    assert main._canonical_operation_id(captured["operation_id"])
    assert captured["payload"] == {
        "candidate_sha256": "c" * 64,
        "preview_sha256": "d" * 64,
        "confirmation": "CONFIRM BACKDATED PRICE",
    }
    assert [event["outcome"] for event in security_events(caplog)] == [
        "intent",
        "success",
    ]
    assert {event["action"] for event in security_events(caplog)} == {
        "model.price.backdate.confirm"
    }
    success_event = next(
        event
        for event in security_events(caplog)
        if event["outcome"] == "success"
    )
    assert success_event["model"] == "claude-sonnet-4-5"
    assert success_event["usage_class"] == "normal_input"
    assert "forged-model" not in response.headers["location"]


@pytest.mark.parametrize(
    ("fresh_step_up", "confirmation", "expected_location"),
    [
        (False, "CONFIRM BACKDATED PRICE", "/admin/reauth"),
        (
            True,
            "CONFIRM BACKDATED COST!",
            "/admin#tab-models",
        ),
    ],
)
def test_backdate_confirm_rejects_stale_step_up_or_wrong_phrase(
    admin_client,
    set_admin_session,
    monkeypatch,
    fresh_step_up,
    confirmation,
    expected_location,
):
    called = False

    async def rotator_get(path):
        assert path == "/identity/authorization/subject-123"
        return {"admin": True}

    async def rotator_post(*_args, **_kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(main, "_rotator_post", rotator_post)
    csrf = "c" * 43
    session = {
        "user": portal_user(roles=[settings.admin_role]),
        "csrf_token": csrf,
    }
    if fresh_step_up:
        session["admin_reauth_at"] = int(time.time())
    set_admin_session(session)

    response = admin_client.post(
        "/admin/model-governance/prices/backdate/confirm",
        data={
            "preview_id": "33333333-3333-4333-8333-333333333333",
            "candidate_sha256": "c" * 64,
            "preview_sha256": "d" * 64,
            "gateway_model_name": "claude-sonnet-4-5",
            "usage_class": "normal_input",
            "confirmation": confirmation,
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == expected_location
    assert called is False


@pytest.mark.parametrize(
    ("csrf_ok", "fresh_step_up", "expected_location"),
    [
        (False, True, "/admin?price_model=claude-sonnet-4-5#tab-models"),
        (True, False, "/admin/reauth"),
    ],
)
def test_price_create_rejects_bad_csrf_or_stale_step_up(
    admin_client,
    set_admin_session,
    monkeypatch,
    csrf_ok,
    fresh_step_up,
    expected_location,
):
    called = False

    async def rotator_get(path):
        assert path == "/identity/authorization/subject-123"
        return {"admin": True}

    async def rotator_post(*_args, **_kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(main, "_rotator_post", rotator_post)
    csrf = "c" * 43
    session = {
        "user": portal_user(roles=[settings.admin_role]),
        "csrf_token": csrf,
    }
    if fresh_step_up:
        session["admin_reauth_at"] = int(time.time())
    set_admin_session(session)

    response = admin_client.post(
        "/admin/model-governance/prices",
        data={
            "gateway_model_name": "claude-sonnet-4-5",
            "usage_class": "normal_input",
            "token_unit": "1000000",
            "amount": "30",
            "effective_at_utc": (
                datetime.now(timezone.utc) + timedelta(days=2)
            ).strftime("%Y-%m-%dT%H:%M"),
            "source_reference": "anthropic-pricing-2026-07-22",
            "review_note": "Reviewed by the platform pricing owner.",
            "csrf_token": csrf if csrf_ok else "x" * 43,
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == expected_location
    assert called is False


@pytest.mark.parametrize(
    ("amount", "unit", "effective_delta"),
    [("1", "3", timedelta(days=2)), ("30", "1000000", timedelta(days=-1))],
)
def test_price_rejects_inexact_unit_or_backdate_without_controller_call(
    admin_client,
    set_admin_session,
    monkeypatch,
    amount,
    unit,
    effective_delta,
):
    called = False

    async def rotator_get(path):
        assert path == "/identity/authorization/subject-123"
        return {"admin": True}

    async def rotator_post(*_args, **_kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(main, "_rotator_post", rotator_post)
    csrf = "c" * 43
    set_admin_session(
        {
            "user": portal_user(roles=[settings.admin_role]),
            "csrf_token": csrf,
            "admin_reauth_at": int(time.time()),
        }
    )

    response = admin_client.post(
        "/admin/model-governance/prices",
        data={
            "gateway_model_name": "claude-sonnet-4-5",
            "usage_class": "normal_input",
            "token_unit": unit,
            "amount": amount,
            "effective_at_utc": (
                datetime.now(timezone.utc) + effective_delta
            ).strftime("%Y-%m-%dT%H:%M"),
            "source_reference": "anthropic-pricing-2026-07-22",
            "review_note": "Reviewed by the platform pricing owner.",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert called is False


# --- tabbed console surface ---------------------------------------------------


def _happy_admin_rotator(monkeypatch, *, status=None, settings_payload=None):
    """Install a bounded happy-path rotator mock for admin page renders."""

    async def rotator_get(path):
        if path == "/identity/authorization/subject-123":
            return {"admin": True}
        if path == "/status":
            return status if status is not None else []
        if path == "/settings":
            return settings_payload if settings_payload is not None else []
        if path.startswith("/history"):
            return []
        if path == "/providers/anthropic":
            return {
                "vendor": "anthropic",
                "state": "awaiting_enrollment",
                "configured": False,
                "enabled": False,
                "private_key_jwt_ready": True,
                "nonsecret_ids": {},
            }
        if path == "/identity/status":
            return None
        if path == "/model-governance/models":
            return []
        if path == "/model-governance/audit?limit=50":
            return []
        raise AssertionError(path)

    monkeypatch.setattr(main, "_rotator_get", rotator_get)


def test_dev_portal_renders_the_two_tab_rail_with_inline_connect_panel(
    client, set_session, monkeypatch
):
    async def key_list(_user_id):
        return []

    monkeypatch.setattr(litellm_client, "key_list", key_list)
    set_session({"user": portal_user()})

    response = client.get("/")

    assert response.status_code == 200
    assert 'role="tablist"' in response.text
    for pinned in (
        'data-tab="keys"',
        'data-tab="connect"',
        'id="tab-keys" role="tabpanel"',
        'id="tab-connect" role="tabpanel"',
    ):
        assert pinned in response.text, pinned
    # The connect tab is server-rendered inline with placeholder snippets and
    # never exposes admin surfaces.
    assert "YOUR_KEY" in response.text
    assert "/admin" not in response.text


def test_admin_console_renders_the_six_tab_rail(
    admin_client, set_admin_session, monkeypatch
):
    _happy_admin_rotator(monkeypatch)
    set_admin_session({"user": portal_user(roles=[settings.admin_role])})

    response = admin_client.get("/admin")

    assert response.status_code == 200
    assert 'role="tablist"' in response.text
    for pinned in (
        'data-tab="identity"',
        'href="/admin/keys"',
        'data-tab="models"',
        'data-tab="providers"',
        'data-tab="rotation"',
        'data-tab="audit"',
        'id="tab-identity" role="tabpanel"',
        'id="tab-models" role="tabpanel"',
        'id="tab-providers" role="tabpanel"',
        'id="tab-rotation" role="tabpanel"',
        'id="tab-audit" role="tabpanel"',
    ):
        assert pinned in response.text, pinned


def test_admin_key_inventory_carries_the_tab_rail(
    admin_client, set_admin_session, monkeypatch
):
    async def rotator_get(path):
        assert path == "/identity/authorization/subject-123"
        return {"admin": True}

    async def admin_key_list_page(page):
        return {"keys": [], "page": 1, "total_pages": 0, "total_count": 0}

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(litellm_client, "admin_key_list_page", admin_key_list_page)
    set_admin_session({"user": portal_user(roles=[settings.admin_role])})

    response = admin_client.get("/admin/keys")

    assert response.status_code == 200
    for pinned in (
        'href="/admin/keys" aria-selected="true"',
        'href="/admin#tab-providers"',
        'href="/admin#tab-rotation"',
        'href="/admin#tab-audit"',
    ):
        assert pinned in response.text, pinned


def test_connect_surface_shows_no_cost_and_models_populate_dynamically(
    client, set_session, monkeypatch
):
    async def key_list(_user_id):
        return []

    async def model_names():
        # A model newly configured in LiteLLM must appear with no code change.
        return ["claude-haiku", "claude-newly-configured", "claude-sonnet"]

    monkeypatch.setattr(litellm_client, "key_list", key_list)
    monkeypatch.setattr(litellm_client, "model_names", model_names)
    set_session({"user": portal_user()})

    index = client.get("/")
    snippets = client.get("/snippets")

    assert index.status_code == 200
    assert snippets.status_code == 200
    for response in (index, snippets):
        assert "claude-newly-configured" in response.text
        for forbidden in ("$", "spend", "budget", "Budget"):
            assert forbidden not in response.text, forbidden


def test_rotation_tab_renders_status_table_without_raw_dump_or_internal_rows(
    admin_client, set_admin_session, monkeypatch
):
    status = [
        {
            "vendor": "anthropic",
            "enabled": True,
            "interval_seconds": 3000,
            "grace_seconds": 300,
            "last_rotation": {
                "timestamp": "2026-07-14T05:36:43Z",
                "status": "skipped",
            },
            "next_run_time": "2026-07-15T05:36:43+00:00",
            "rotation_in_progress": False,
            "alerts": [],
        },
        {
            "vendor": "portal-key-reconciliation-state",
            "enabled": False,
            "interval_seconds": 0,
            "last_rotation": None,
            "next_run_time": None,
            "rotation_in_progress": False,
            "alerts": [],
        },
    ]
    settings_payload = [
        {"vendor": "anthropic", "enabled": True, "interval_seconds": 3000,
         "grace_seconds": 300},
        {"vendor": "static-anthropic", "enabled": False, "interval_seconds": 3600,
         "grace_seconds": 300},
        {"vendor": "portal-key-reconciliation-state", "enabled": False,
         "interval_seconds": 0, "grace_seconds": 0},
    ]
    _happy_admin_rotator(
        monkeypatch, status=status, settings_payload=settings_payload
    )
    set_admin_session({"user": portal_user(roles=[settings.admin_role])})

    response = admin_client.get("/admin")

    assert response.status_code == 200
    # Scheduler facts render as a table, never as a raw Python-dict dump.
    assert "2026-07-15T05:36:43+00:00" in response.text
    assert "2026-07-14T05:36:43Z" in response.text
    assert "rotation_in_progress" not in response.text
    assert "'vendor':" not in response.text
    # The internal reconciliation bookkeeping row is not an operator control.
    assert "portal-key-reconciliation-state" not in response.text
    # Static fallbacks live behind the advanced disclosure.
    assert "Static fallback keys (advanced)" in response.text
    assert "static-anthropic" in response.text


def _identity_admin_rotator(monkeypatch, group):
    """Rotator mock with a configured identity controller and one group."""

    async def rotator_get(path):
        if path == "/identity/authorization/subject-123":
            return {"admin": True}
        if path in {"/status", "/settings"} or path.startswith("/history"):
            return []
        if path == "/providers/anthropic":
            return {
                "vendor": "anthropic",
                "state": "awaiting_enrollment",
                "configured": False,
                "enabled": False,
                "private_key_jwt_ready": True,
                "nonsecret_ids": {},
            }
        if path == "/identity/status":
            return {
                "configured": True,
                "controller_usable": True,
                "bootstrap_available": False,
                "ldap_configured": True,
                "break_glass_escrowed": True,
                "vault_oidc_rp_escrowed": True,
            }
        if path == "/identity/groups":
            return [dict(group)]
        if path.startswith("/identity/users?"):
            return [
                {
                    "id": "user-1",
                    "username": "directory-developer",
                    "email": "directory-developer@example.test",
                    "enabled": True,
                }
            ]
        if path == f"/identity/groups/{group['id']}/members":
            return [
                {
                    "id": "member-1",
                    "username": "directory-developer",
                    "email": "directory-developer@example.test",
                    "enabled": True,
                }
            ]
        raise AssertionError(path)

    monkeypatch.setattr(main, "_rotator_get", rotator_get)


def test_selected_group_renders_policy_form_and_members_inline(
    admin_client, set_admin_session, monkeypatch
):
    _identity_admin_rotator(
        monkeypatch,
        _unlimited_group(
            allowed_models=["claude-haiku"], default_model="claude-haiku"
        ),
    )
    set_admin_session(
        {
            "user": portal_user(roles=[settings.admin_role]),
            "csrf_token": "c" * 43,
            "admin_reauth_at": int(time.time()),
        }
    )

    response = admin_client.get("/admin?group_id=group-1")

    assert response.status_code == 200
    # Re-homed policy form: same route and field names, now master-detail.
    assert 'action="/admin/identity/groups/group-1/policy"' in response.text
    for field in (
        'name="tpm_limit"',
        'name="rpm_limit"',
        'name="allowed_models"',
        'name="default_model"',
    ):
        assert field in response.text, field
    # Inline member management for the selected group.
    assert 'action="/admin/identity/groups/group-1/members"' in response.text
    assert (
        'action="/admin/identity/groups/group-1/members/member-1/remove"'
        in response.text
    )
    assert "directory-developer@example.test" in response.text


def test_selected_group_deconfigured_restriction_renders_the_widening_guard(
    admin_client, set_admin_session, monkeypatch
):
    _identity_admin_rotator(
        monkeypatch,
        _unlimited_group(
            allowed_models=["claude-opus"], default_model="claude-opus"
        ),
    )
    set_admin_session(
        {
            "user": portal_user(roles=[settings.admin_role]),
            "csrf_token": "c" * 43,
            "admin_reauth_at": int(time.time()),
        }
    )

    response = admin_client.get("/admin?group_id=group-1")

    assert response.status_code == 200
    assert "no longer configured in LiteLLM" in response.text
    assert 'name="remove_model_restrictions"' in response.text


# --- active custom (non-discovery) governed model assignability ---------------


def _identity_and_governance_rotator(monkeypatch, *, groups, governed_models):
    """Configured identity controller plus a governed-model catalog.

    Mirrors the two internal control planes admin_page reads: the identity
    controller (groups/members) and the append-only governance catalog.
    """

    async def rotator_get(path):
        if path == "/identity/authorization/subject-123":
            return {"admin": True}
        if path in {"/status", "/settings"} or path.startswith("/history"):
            return []
        if path == "/providers/anthropic":
            return {
                "vendor": "anthropic",
                "state": "awaiting_enrollment",
                "configured": False,
                "enabled": False,
                "private_key_jwt_ready": True,
                "nonsecret_ids": {},
            }
        if path == "/identity/status":
            return {
                "configured": True,
                "controller_usable": True,
                "bootstrap_available": False,
                "ldap_configured": True,
                "break_glass_escrowed": True,
                "vault_oidc_rp_escrowed": True,
            }
        if path == "/identity/groups":
            return [dict(group) for group in groups]
        if path.startswith("/identity/users?"):
            return []
        if path.endswith("/members") and path.startswith("/identity/groups/"):
            return []
        if path == "/model-governance/models":
            return list(governed_models)
        if path.startswith("/model-governance/models/") and path.endswith(
            "/prices"
        ):
            return []
        if path == "/model-governance/audit?limit=50":
            return []
        raise AssertionError(path)

    monkeypatch.setattr(main, "_rotator_get", rotator_get)


def test_project_policy_checklist_offers_active_custom_models_badged(
    admin_client, set_admin_session, monkeypatch
):
    """Active custom (non-discovery) models are assignable and badged; draft
    and retired models are not offered at all."""

    async def model_names():
        # Public discovery: static plus the active-visible governed model.
        return ["claude-haiku", "claude-sonnet", "claude-visible-5"]

    monkeypatch.setattr(litellm_client, "model_names", model_names)
    _identity_and_governance_rotator(
        monkeypatch,
        groups=[_unlimited_group()],
        governed_models=[
            _governed_model_row(
                gateway_model_name="claude-mythos-5",
                lifecycle_state="active",
                active=True,
                visible_in_discovery=False,
                last_event_sequence=3,
            ),
            _governed_model_row(
                gateway_model_name="claude-visible-5",
                lifecycle_state="active",
                active=True,
                visible_in_discovery=True,
                last_event_sequence=2,
            ),
            _governed_model_row(
                gateway_model_name="claude-draft-9",
                lifecycle_state="draft",
            ),
            _governed_model_row(
                gateway_model_name="claude-retired-9",
                lifecycle_state="retired",
                active=False,
                visible_in_discovery=False,
                last_event_sequence=5,
            ),
        ],
    )
    set_admin_session(
        {
            "user": portal_user(roles=[settings.admin_role]),
            "csrf_token": "c" * 43,
            "admin_reauth_at": int(time.time()),
        }
    )

    response = admin_client.get("/admin?group_id=group-1")

    assert response.status_code == 200
    # The active custom model IS an assignable checkbox, badged "custom".
    assert 'name="allowed_models" value="claude-mythos-5"' in response.text
    assert 'claude-mythos-5 <span class="chip">custom</span>' in response.text
    # An active visible governed model is assignable but NOT badged custom.
    assert 'name="allowed_models" value="claude-visible-5"' in response.text
    assert 'claude-visible-5 <span class="chip">custom</span>' not in response.text
    # Draft and retired models are never offered as an allowed-models checkbox.
    assert 'name="allowed_models" value="claude-draft-9"' not in response.text
    assert 'name="allowed_models" value="claude-retired-9"' not in response.text
    # Copy makes the never-implicit rule explicit, and the state badge reads
    # "custom", never "hidden".
    assert "custom models always need an explicit check" in response.text
    assert "active · custom" in response.text
    assert "active · hidden" not in response.text


def test_project_policy_save_accepts_active_custom_model_selection(
    admin_client, set_admin_session, monkeypatch
):
    """An operator may explicitly assign an active custom model; the implicit
    'all public models' re-tune scope stays public-only."""

    captured: dict[str, Any] = {}

    async def rotator_get(path):
        if path == "/identity/authorization/subject-123":
            return {"admin": True}
        if path == "/identity/groups":
            return [_unlimited_group()]
        if path == "/model-governance/models":
            return [
                _governed_model_row(
                    gateway_model_name="claude-mythos-5",
                    lifecycle_state="active",
                    active=True,
                    visible_in_discovery=False,
                    last_event_sequence=3,
                )
            ]
        return {"admin": True}

    async def fake_apply(group_id, payload, operation_id, available_models):
        captured["payload"] = payload
        captured["available"] = available_models
        return ("ai-gateway", 0, 0)

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(main, "_apply_project_policy", fake_apply)
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
        data={"allowed_models": "claude-mythos-5", "csrf_token": csrf},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "Choose only configured models" not in response.text
    assert "no longer configured in LiteLLM" not in response.text
    assert captured["payload"]["allowed_models"] == ["claude-mythos-5"]
    # The re-tune "all public models" fallback never folds in the custom model.
    assert captured["available"] == ["claude-haiku", "claude-sonnet"]


def test_project_policy_save_keeps_assigned_custom_model_not_deconfigured(
    admin_client, set_admin_session, monkeypatch
):
    """A stored restriction to an active custom model is still assignable, so a
    plain resubmit is not blocked by the anti-silent-widening guard."""

    captured: dict[str, Any] = {}

    async def rotator_get(path):
        if path == "/identity/authorization/subject-123":
            return {"admin": True}
        if path == "/identity/groups":
            return [
                _unlimited_group(
                    allowed_models=["claude-mythos-5"],
                    default_model="claude-mythos-5",
                )
            ]
        if path == "/model-governance/models":
            return [
                _governed_model_row(
                    gateway_model_name="claude-mythos-5",
                    lifecycle_state="active",
                    active=True,
                    visible_in_discovery=False,
                    last_event_sequence=3,
                )
            ]
        return {"admin": True}

    async def fake_apply(group_id, payload, operation_id, available_models):
        captured["payload"] = payload
        return ("ai-gateway", 0, 0)

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(main, "_apply_project_policy", fake_apply)
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
            "allowed_models": "claude-mythos-5",
            "default_model": "claude-mythos-5",
            "csrf_token": csrf,
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "no longer configured in LiteLLM" not in response.text
    assert captured["payload"]["allowed_models"] == ["claude-mythos-5"]
    assert captured["payload"]["default_model"] == "claude-mythos-5"


def test_governed_models_list_collapses_retired_records_behind_a_toggle(
    admin_client, set_admin_session, monkeypatch
):
    """Append-only retired records stay, but collapse behind a default-closed
    'Show retired (N)' disclosure so the live catalog stays readable."""

    _identity_and_governance_rotator(
        monkeypatch,
        groups=[_unlimited_group()],
        governed_models=[
            _governed_model_row(
                gateway_model_name="claude-active-5",
                lifecycle_state="active",
                active=True,
                visible_in_discovery=True,
                last_event_sequence=2,
            ),
            _governed_model_row(
                gateway_model_name="claude-preprod-f0b8c0fc6008",
                lifecycle_state="retired",
                active=False,
                visible_in_discovery=False,
                last_event_sequence=4,
            ),
            _governed_model_row(
                gateway_model_name="claude-usage-a1a9336ea65f",
                lifecycle_state="retired",
                active=False,
                visible_in_discovery=False,
                last_event_sequence=5,
            ),
        ],
    )
    set_admin_session(
        {
            "user": portal_user(roles=[settings.admin_role]),
            "csrf_token": "c" * 43,
            "admin_reauth_at": int(time.time()),
        }
    )

    response = admin_client.get("/admin#tab-models")

    assert response.status_code == 200
    # Retired records are collapsed behind a counted toggle, not deleted.
    assert "Show retired (2)" in response.text
    assert "claude-preprod-f0b8c0fc6008" in response.text
    assert "claude-usage-a1a9336ea65f" in response.text
    # The live catalog still shows active models with their lifecycle controls.
    assert "claude-active-5" in response.text
    assert 'value="hide"' in response.text


# --- egress trust pin ---------------------------------------------------------


def test_egress_trust_status_verifies_the_shipped_bundle():
    trust = main._egress_trust_status()

    assert trust["verified"] is True
    assert [pin["sha256"] for pin in trust["pins"]] == [
        pin["sha256"] for pin in main.ANTHROPIC_EGRESS_CA_PINS
    ]
    assert trust["pins"][0]["display"].startswith("1D:FC:16:05:")


@pytest.mark.parametrize(
    "content",
    [
        None,  # missing bundle
        "no certificates at all",
        "-----BEGIN CERTIFICATE-----\n!!!not-base64!!!\n-----END CERTIFICATE-----\n",
        # Valid PEM shape, wrong certificate content: fingerprint mismatch.
        "-----BEGIN CERTIFICATE-----\nbm90LWEtcmVhbC1jZXJ0aWZpY2F0ZQ==\n"
        "-----END CERTIFICATE-----\n",
    ],
)
def test_egress_trust_status_fails_closed_on_missing_or_tampered_bundle(
    monkeypatch, tmp_path, content
):
    bundle = tmp_path / "anthropic-egress-ca.pem"
    if content is not None:
        bundle.write_text(content)
    monkeypatch.setattr(main, "ANTHROPIC_EGRESS_CA_BUNDLE_PATH", bundle)

    trust = main._egress_trust_status()

    assert trust["verified"] is False
    # The reviewed pins are still rendered so the operator can compare.
    assert [pin["sha256"] for pin in trust["pins"]] == [
        pin["sha256"] for pin in main.ANTHROPIC_EGRESS_CA_PINS
    ]


def test_admin_page_renders_the_verified_egress_pin(
    admin_client, set_admin_session, monkeypatch
):
    _happy_admin_rotator(monkeypatch)
    set_admin_session({"user": portal_user(roles=[settings.admin_role])})

    response = admin_client.get("/admin")

    assert response.status_code == 200
    assert "Pin verified" in response.text
    assert "Google Trust Services WE1" in response.text
    assert "GTS Root R4" in response.text
    assert 'action="/admin/egress-trust/verify"' in response.text
    # The periodic canary replaced the old "not yet wired" disclaimer. The
    # TestClient fixture does not enter the lifespan, so the canary task never
    # starts here and the panel shows the awaiting-first-check state.
    assert "not yet wired" not in response.text
    assert "Continuous canary" in response.text
    assert "Awaiting first check" in response.text


def test_egress_trust_verify_requires_live_admin_and_csrf(
    admin_client, set_admin_session, monkeypatch
):
    async def rotator_get(path):
        if path == "/identity/authorization/subject-123":
            return {"admin": True}
        if path == "/identity/authorization/revoked-admin":
            return {"admin": False}
        raise AssertionError(path)

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    csrf = "c" * 43

    # A revoked admin session is denied before any verification runs.
    set_admin_session(
        {
            "user": portal_user(subject="revoked-admin", roles=[settings.admin_role]),
            "csrf_token": csrf,
        }
    )
    revoked = admin_client.post(
        "/admin/egress-trust/verify",
        data={"csrf_token": csrf},
        follow_redirects=False,
    )
    assert revoked.status_code == 403

    # A bad CSRF token is rejected; a valid one re-verifies and redirects to
    # the Providers tab.
    admin_client.cookies.clear()
    set_admin_session(
        {"user": portal_user(roles=[settings.admin_role]), "csrf_token": csrf}
    )
    bad_csrf = admin_client.post(
        "/admin/egress-trust/verify",
        data={"csrf_token": "x" * 43},
        follow_redirects=False,
    )
    assert bad_csrf.status_code == 303

    set_admin_session(
        {"user": portal_user(roles=[settings.admin_role]), "csrf_token": csrf}
    )
    verified = admin_client.post(
        "/admin/egress-trust/verify",
        data={"csrf_token": csrf},
        follow_redirects=False,
    )
    assert verified.status_code == 303
    assert verified.headers["location"] == "/admin#tab-providers"


def test_user_portal_has_no_egress_trust_or_tabbed_admin_routes(client) -> None:
    assert (
        client.post("/admin/egress-trust/verify", follow_redirects=False).status_code
        == 404
    )
    assert client.get("/admin", follow_redirects=False).status_code == 404


def test_project_policy_widens_deconfigured_restriction_only_with_explicit_optout(
    admin_client, set_admin_session, monkeypatch
):
    puts = []
    posts = []
    policy = {
        "tpm_limit": 1000,
        "rpm_limit": None,
        "allowed_models": None,
        "default_model": None,
        "model_limits": {},
    }

    async def rotator_get(path):
        if path == "/identity/groups":
            return [
                _unlimited_group(
                    allowed_models=["claude-opus"], default_model="claude-opus"
                )
            ]
        return {"admin": True}

    async def rotator_put(path, payload, *, operation_id=None):
        puts.append(payload)
        return _staged_policy_result(policy)

    async def admin_key_list_page(page):
        return {"keys": [], "page": 1, "total_pages": 1, "total_count": 0}

    monkeypatch.setattr(main, "_rotator_get", rotator_get)
    monkeypatch.setattr(main, "_rotator_put", rotator_put)
    monkeypatch.setattr(main, "_rotator_post", _policy_transition_stub(policy, posts))
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
    assert puts == [policy]
    assert len(posts) == 2
    assert "Project policy saved" in response.text


# --- step-up countdown (Item A) ----------------------------------------------


def test_admin_page_renders_a_fixed_step_up_countdown_target(
    admin_client, set_admin_session, monkeypatch
):
    # The badge must carry a server-computed ABSOLUTE expiry the browser counts
    # down against — marker time plus the configured window — never a value the
    # client re-bases. admin_reauthentication_expires_at adds the window to the
    # stored marker, so the target is deterministic regardless of render time.
    _happy_admin_rotator(monkeypatch)
    now = int(time.time())
    set_admin_session(
        {
            "user": portal_user(roles=[settings.admin_role]),
            "admin_reauth_at": now,
        }
    )

    response = admin_client.get("/admin")

    assert response.status_code == 200
    expected = now + settings.admin_step_up_seconds
    assert f'data-stepup-expires="{expected}"' in response.text
    assert "Step-up active" in response.text
    assert "data-stepup-remaining" in response.text


def test_admin_page_without_step_up_has_no_countdown_target(
    admin_client, set_admin_session, monkeypatch
):
    _happy_admin_rotator(monkeypatch)
    set_admin_session({"user": portal_user(roles=[settings.admin_role])})

    response = admin_client.get("/admin")

    assert response.status_code == 200
    # No recent step-up marker: the badge itself is not rendered (the countdown
    # script is always present, so we check for the badge element, not the
    # attribute string it references).
    assert 'class="stepup"' not in response.text


# --- connect-panel tool cards (Item B) ---------------------------------------


def test_tools_yaml_includes_python_sdk_and_cursor_following_the_schema():
    from app import tools

    loaded = {tool["id"]: tool for tool in tools.load_tools()}
    assert "python-sdk" in loaded
    assert "cursor" in loaded

    for tool_id in ("python-sdk", "cursor"):
        tool = loaded[tool_id]
        # Same schema every other entry uses: id/name/description/snippet, with
        # an optional note. Missing keys would render blank cards.
        assert set(("id", "name", "description", "snippet")) <= set(tool)
        assert isinstance(tool["name"], str) and tool["name"]
        assert isinstance(tool["snippet"], str) and tool["snippet"]

    # Both must use the {api_base}/{key} placeholder convention so the generic
    # renderer substitutes them; a hard-coded host would leak past the gateway.
    rendered = {
        tool["id"]: tool
        for tool in tools.rendered_tools("https://gw.test", "sk-TESTKEY")
    }
    assert "{api_base}" not in rendered["python-sdk"]["snippet"]
    assert "{key}" not in rendered["python-sdk"]["snippet"]
    assert "https://gw.test" in rendered["python-sdk"]["snippet"]
    assert "sk-TESTKEY" in rendered["python-sdk"]["snippet"]
    # Cursor points its OpenAI-compatible override at the gateway's /v1 root.
    assert "https://gw.test/v1" in rendered["cursor"]["snippet"]
    assert "sk-TESTKEY" in rendered["cursor"]["snippet"]


def test_python_sdk_snippet_targets_the_gateway_base_url_not_anthropic():
    from app import tools

    rendered = {
        tool["id"]: tool
        for tool in tools.rendered_tools("https://gw.test", "sk-TESTKEY")
    }
    snippet = rendered["python-sdk"]["snippet"]
    assert "api.anthropic.com" not in snippet
    assert 'base_url="https://gw.test"' in snippet


# --- egress-trust periodic canary (Item C) -----------------------------------


def _reset_canary_state(monkeypatch, **overrides):
    """Install a fresh, isolated canary state dict for one test."""
    state = {
        "last_checked": None,
        "last_checked_epoch": None,
        "verified": None,
        "detail": None,
        "last_error": None,
    }
    state.update(overrides)
    monkeypatch.setattr(main, "_egress_trust_canary_state", state)
    return state


def test_canary_snapshot_is_stale_before_the_first_check(monkeypatch):
    _reset_canary_state(monkeypatch)
    snap = main._egress_trust_canary_snapshot()
    assert snap["last_checked"] is None
    assert snap["stale"] is True
    assert snap["age_seconds"] is None
    assert snap["verified"] is None
    # interval is always surfaced so the panel can explain the cadence.
    assert snap["interval_seconds"] == settings.egress_trust_canary_interval_seconds


def test_canary_snapshot_fresh_result_is_not_stale(monkeypatch):
    now = datetime.now(timezone.utc)
    _reset_canary_state(
        monkeypatch,
        last_checked=now.isoformat(),
        last_checked_epoch=now.timestamp(),
        verified=True,
        detail="ok",
    )
    snap = main._egress_trust_canary_snapshot()
    assert snap["stale"] is False
    assert snap["verified"] is True


def test_canary_snapshot_old_result_becomes_stale(monkeypatch):
    interval = settings.egress_trust_canary_interval_seconds
    old = datetime.now(timezone.utc).timestamp() - (interval * 2 + 10)
    _reset_canary_state(
        monkeypatch,
        last_checked="2000-01-01T00:00:00+00:00",
        last_checked_epoch=old,
        verified=True,
        detail="ok",
    )
    snap = main._egress_trust_canary_snapshot()
    assert snap["stale"] is True
    assert snap["age_seconds"] >= interval * 2


def test_canary_run_records_pass(monkeypatch):
    state = _reset_canary_state(monkeypatch)
    monkeypatch.setattr(
        main, "_egress_trust_status", lambda: {"verified": True, "detail": "matches"}
    )
    main._run_egress_trust_canary_once()
    assert state["verified"] is True
    assert state["last_error"] is None
    assert state["last_checked"] is not None
    assert isinstance(state["last_checked_epoch"], float)


def test_canary_run_records_failure_loudly(monkeypatch, caplog):
    state = _reset_canary_state(monkeypatch)
    monkeypatch.setattr(
        main,
        "_egress_trust_status",
        lambda: {"verified": False, "detail": "bundle mismatch"},
    )
    with caplog.at_level("ERROR"):
        main._run_egress_trust_canary_once()
    assert state["verified"] is False
    # The failure is captured as a non-secret error and logged, never swallowed.
    assert state["last_error"] == "bundle mismatch"
    assert any("canary" in rec.message.lower() for rec in caplog.records)


def test_canary_run_never_raises_when_the_check_throws(monkeypatch, caplog):
    state = _reset_canary_state(monkeypatch)

    def boom():
        raise RuntimeError("disk gone")

    monkeypatch.setattr(main, "_egress_trust_status", boom)
    with caplog.at_level("ERROR"):
        main._run_egress_trust_canary_once()  # must not raise
    assert state["verified"] is False
    assert "disk gone" in state["last_error"]


@pytest.mark.asyncio
async def test_start_canary_is_idempotent_and_process_local(monkeypatch):
    # dev-portal runs uvicorn --workers 1, so a single process-local task owns
    # the canary. Starting twice must not spawn a second competing loop.
    monkeypatch.setattr(main, "_egress_trust_canary_task", None)

    async def _idle():
        await asyncio.sleep(3600)

    monkeypatch.setattr(main, "_egress_trust_canary_loop", _idle)
    try:
        main._start_egress_trust_canary()
        first = main._egress_trust_canary_task
        assert first is not None
        main._start_egress_trust_canary()
        assert main._egress_trust_canary_task is first
    finally:
        main._stop_egress_trust_canary()
        assert main._egress_trust_canary_task is None
        # Give the event loop a tick to process the cancellation.
        await asyncio.sleep(0)
        assert first.cancelled() or first.done()


def test_admin_page_surfaces_a_failing_canary_loudly(
    admin_client, set_admin_session, monkeypatch
):
    _happy_admin_rotator(monkeypatch)
    now = datetime.now(timezone.utc)
    _reset_canary_state(
        monkeypatch,
        last_checked=now.isoformat(),
        last_checked_epoch=now.timestamp(),
        verified=False,
        detail="bundle mismatch",
        last_error="bundle mismatch",
    )
    set_admin_session({"user": portal_user(roles=[settings.admin_role])})

    response = admin_client.get("/admin")

    assert response.status_code == 200
    assert "Continuous canary" in response.text
    assert "Egress-trust canary FAILED" in response.text
    # Rendered inside the existing loud alert styling.
    assert 'class="flash error"' in response.text
    assert "not yet wired" not in response.text
