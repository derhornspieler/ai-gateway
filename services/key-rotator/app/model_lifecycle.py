"""Pure lifecycle rules for governed LiteLLM models.

The database stores an immutable draft plus append-only events.  This module
folds those records into the current state.  Keeping the rules here makes the
API, reconciliation loop, and tests use the same small state machine.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Iterable


class ModelLifecycleError(RuntimeError):
    """A requested model transition is not allowed."""


class ModelLifecycleAction(StrEnum):
    ACTIVATE = "activate"
    SHOW = "show"
    HIDE = "hide"
    RETIRE = "retire"


@dataclass(frozen=True)
class GovernedModelState:
    lifecycle_state: str
    active: bool
    visible_in_discovery: bool
    last_event_sequence: int | None


def initial_model_state() -> GovernedModelState:
    """A draft never serves traffic and never appears in discovery."""

    return GovernedModelState(
        lifecycle_state="draft",
        active=False,
        visible_in_discovery=False,
        last_event_sequence=None,
    )


def apply_model_action(
    state: GovernedModelState,
    action: ModelLifecycleAction,
    *,
    initial_visibility: bool,
    event_sequence: int | None = None,
) -> GovernedModelState:
    """Apply one validated append-only event to a projected state."""

    if action is ModelLifecycleAction.ACTIVATE:
        if state.lifecycle_state != "draft":
            raise ModelLifecycleError("only a draft model can be activated")
        return GovernedModelState(
            lifecycle_state="active",
            active=True,
            visible_in_discovery=initial_visibility,
            last_event_sequence=event_sequence,
        )

    if action is ModelLifecycleAction.SHOW:
        if not state.active or state.visible_in_discovery:
            raise ModelLifecycleError("only an active hidden model can be shown")
        return GovernedModelState(
            lifecycle_state="active",
            active=True,
            visible_in_discovery=True,
            last_event_sequence=event_sequence,
        )

    if action is ModelLifecycleAction.HIDE:
        if not state.active or not state.visible_in_discovery:
            raise ModelLifecycleError("only an active visible model can be hidden")
        return GovernedModelState(
            lifecycle_state="active",
            active=True,
            visible_in_discovery=False,
            last_event_sequence=event_sequence,
        )

    if action is ModelLifecycleAction.RETIRE:
        if state.lifecycle_state == "retired":
            raise ModelLifecycleError("model is already retired")
        return GovernedModelState(
            lifecycle_state="retired",
            active=False,
            visible_in_discovery=False,
            last_event_sequence=event_sequence,
        )

    raise ModelLifecycleError("model lifecycle action is unsupported")


def project_model_state(
    events: Iterable[dict[str, Any]],
    *,
    initial_visibility: bool,
) -> GovernedModelState:
    """Fold ordered database events and reject gaps or malformed rows."""

    state = initial_model_state()
    previous_sequence = 0
    for event in events:
        sequence = event.get("event_sequence")
        raw_action = event.get("action")
        if (
            type(sequence) is not int
            or sequence <= previous_sequence
            or not isinstance(raw_action, str)
        ):
            raise ModelLifecycleError("model lifecycle history is malformed")
        try:
            action = ModelLifecycleAction(raw_action)
        except ValueError:
            raise ModelLifecycleError(
                "model lifecycle history has an unknown action"
            ) from None
        state = apply_model_action(
            state,
            action,
            initial_visibility=initial_visibility,
            event_sequence=sequence,
        )
        previous_sequence = sequence
    return state


def lifecycle_document_sha256(
    *,
    model_operation_id: str,
    gateway_model_name: str,
    egress_policy_sha256: str,
    action: ModelLifecycleAction,
) -> str:
    """Return the stable audit digest for one lifecycle command."""

    document = {
        "action": action.value,
        "egress_policy_sha256": egress_policy_sha256,
        "gateway_model_name": gateway_model_name,
        "model_operation_id": model_operation_id,
    }
    encoded = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def with_projected_state(
    model: dict[str, Any],
    events: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """Copy a model row and attach its derived lifecycle fields."""

    projected = project_model_state(
        events,
        initial_visibility=model.get("initial_visible_in_discovery") is True,
    )
    result = dict(model)
    result["lifecycle_state"] = projected.lifecycle_state
    result["active"] = projected.active
    result["visible_in_discovery"] = projected.visible_in_discovery
    result["last_event_sequence"] = projected.last_event_sequence
    return result
