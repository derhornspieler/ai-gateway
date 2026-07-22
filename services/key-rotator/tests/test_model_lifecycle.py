from __future__ import annotations

import pytest

from app.model_lifecycle import (
    ModelLifecycleAction,
    ModelLifecycleError,
    apply_model_action,
    initial_model_state,
    lifecycle_document_sha256,
    project_model_state,
    with_projected_state,
)


def _event(sequence: int, action: str) -> dict[str, object]:
    return {"event_sequence": sequence, "action": action}


def test_draft_is_inert_even_when_initial_visibility_is_true() -> None:
    state = project_model_state([], initial_visibility=True)
    assert state.lifecycle_state == "draft"
    assert state.active is False
    assert state.visible_in_discovery is False


def test_activate_uses_reviewed_initial_visibility() -> None:
    hidden = project_model_state(
        [_event(7, "activate")], initial_visibility=False
    )
    visible = project_model_state(
        [_event(8, "activate")], initial_visibility=True
    )
    assert hidden.active is True and hidden.visible_in_discovery is False
    assert visible.active is True and visible.visible_in_discovery is True


def test_visibility_and_retirement_are_append_only_projections() -> None:
    state = project_model_state(
        [
            _event(1, "activate"),
            _event(2, "show"),
            _event(3, "hide"),
            _event(4, "retire"),
        ],
        initial_visibility=False,
    )
    assert state.lifecycle_state == "retired"
    assert state.active is False
    assert state.visible_in_discovery is False
    assert state.last_event_sequence == 4


@pytest.mark.parametrize(
    "events",
    [
        [_event(1, "show")],
        [_event(1, "hide")],
        [_event(1, "activate"), _event(2, "activate")],
        [_event(1, "retire"), _event(2, "activate")],
        [_event(2, "activate"), _event(1, "hide")],
        [_event(1, "unknown")],
    ],
)
def test_invalid_or_malformed_histories_fail_closed(events) -> None:
    with pytest.raises(ModelLifecycleError):
        project_model_state(events, initial_visibility=True)


def test_direct_transition_validation_is_clear() -> None:
    active = apply_model_action(
        initial_model_state(),
        ModelLifecycleAction.ACTIVATE,
        initial_visibility=False,
    )
    with pytest.raises(ModelLifecycleError, match="active visible"):
        apply_model_action(
            active,
            ModelLifecycleAction.HIDE,
            initial_visibility=False,
        )


def test_lifecycle_digest_is_deterministic_and_action_bound() -> None:
    values = {
        "model_operation_id": "00000000-0000-4000-8000-000000000001",
        "gateway_model_name": "claude-test",
        "egress_policy_sha256": "a" * 64,
    }
    first = lifecycle_document_sha256(
        **values, action=ModelLifecycleAction.ACTIVATE
    )
    second = lifecycle_document_sha256(
        **values, action=ModelLifecycleAction.ACTIVATE
    )
    hidden = lifecycle_document_sha256(
        **values, action=ModelLifecycleAction.HIDE
    )
    assert first == second
    assert len(first) == 64
    assert hidden != first


def test_projection_keeps_the_immutable_initial_choice() -> None:
    row = with_projected_state(
        {
            "operation_id": "00000000-0000-4000-8000-000000000001",
            "initial_visible_in_discovery": True,
        },
        [_event(1, "activate"), _event(2, "hide")],
    )
    assert row["initial_visible_in_discovery"] is True
    assert row["visible_in_discovery"] is False
    assert row["active"] is True
