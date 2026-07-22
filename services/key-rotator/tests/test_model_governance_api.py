from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest

from app.config import Settings
from app.db import (
    GovernanceConflict,
    GovernanceNotFound,
)
from app import main as main_module
from app.main import _configured_provider_policy, app, state
from app.model_catalog import parse_provider_policy_receipt
from app.model_lifecycle import (
    GovernedModelState,
    ModelLifecycleError,
    apply_model_action,
    with_projected_state,
)
from app.pricing import PriceVersion, UsageClass
from app.pricing_api import _emit_price_audit


FIXTURE = Path(__file__).parent / "fixtures" / "provider-policy-receipt.anthropic.json"
POLICY_SHA256 = "8c553d83bc98edeee4e1157368b8620ec6234e557b59a8195be6390677cdada6"
AUTH_TOKEN = "0123456789abcdef0123456789abcdef"
ACTOR = "admin@example.internal"


def test_trusted_price_audit_hashes_the_free_form_review_note(caplog) -> None:
    operation_id = str(uuid.uuid4())
    review_note = "Reviewed note with a value that must stay in PostgreSQL only."
    row = {
        "gateway_model_name": "claude-sonnet-4-5",
        "provider_name": "anthropic",
        "usage_class": "normal_input",
        "amount": Decimal("30.000000000000"),
        "token_unit": 1_000_000,
        "effective_at": datetime(2026, 8, 1, tzinfo=timezone.utc),
        "source_reference": "anthropic-price-review-2026-08-01",
        "review_note": review_note,
        "baseline_price_policy_sha256": "a" * 64,
        "document_sha256": "b" * 64,
    }

    with caplog.at_level("INFO", logger="key_rotator.pricing"):
        _emit_price_audit(
            row,
            action="create",
            operation_id=operation_id,
            actor=ACTOR,
        )

    assert len(caplog.records) == 1
    rendered = caplog.records[0].getMessage()
    assert review_note not in rendered
    event = json.loads(rendered.split("AIGW_SECURITY_EVENT ", 1)[1])
    assert event == {
        "schema_version": 1,
        "event": "aigw.price.audit",
        "action": "create",
        "outcome": "success",
        "operation_id": operation_id,
        "subject": ACTOR,
        "model": "claude-sonnet-4-5",
        "provider": "anthropic",
        "usage_class": "normal_input",
        "amount_usd": "30.000000000000",
        "token_unit": "1000000",
        "effective_at": "2026-08-01T00:00:00Z",
        "source_reference": "anthropic-price-review-2026-08-01",
        "review_note_sha256": hashlib.sha256(review_note.encode()).hexdigest(),
        "old_policy_sha256": "a" * 64,
        "candidate_sha256": "b" * 64,
    }


def _settings() -> Settings:
    return Settings(
        ROTATOR_INTERNAL_TOKEN=AUTH_TOKEN,
        PORTAL_IDENTITY_TOKEN="abcdef0123456789abcdef0123456789",
        VAULT_TOKEN="vault-token",
        LITELLM_MASTER_KEY="litellm-master-key",
    )


def _receipt():
    return parse_provider_policy_receipt(
        FIXTURE.read_bytes(), expected_policy_sha256=POLICY_SHA256
    )


def test_source_mode_leaves_model_governance_fail_closed() -> None:
    assert _configured_provider_policy(_settings()) is None


def test_startup_policy_loader_uses_separate_trusted_digest(monkeypatch) -> None:
    expected = _receipt()
    calls: list[tuple[str, str]] = []

    def fake_load(path: str, *, expected_policy_sha256: str):
        calls.append((path, expected_policy_sha256))
        return expected

    monkeypatch.setattr(main_module, "load_provider_policy_receipt", fake_load)
    configured = Settings(
        ROTATOR_INTERNAL_TOKEN=AUTH_TOKEN,
        PORTAL_IDENTITY_TOKEN="abcdef0123456789abcdef0123456789",
        VAULT_TOKEN="vault-token",
        LITELLM_MASTER_KEY="litellm-master-key",
        PROVIDER_POLICY_RECEIPT_FILE=(
            "/run/secrets/provider_policy_receipt.json"
        ),
        AIGW_EGRESS_POLICY_SHA256=POLICY_SHA256,
    )

    assert _configured_provider_policy(configured) is expected
    assert calls == [
        ("/run/secrets/provider_policy_receipt.json", POLICY_SHA256)
    ]


def _headers(operation_id: str | None = None) -> dict[str, str]:
    return {
        "X-Internal-Auth": AUTH_TOKEN,
        "X-AIGW-Actor-ID": ACTOR,
        "X-AIGW-Operation-ID": operation_id or str(uuid.uuid4()),
    }


def _model_body(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "gateway_model_name": "claude-sonnet-4-5",
        "provider_name": "anthropic",
        "provider_model_id": "claude-sonnet-4-5",
        "visible_in_discovery": False,
        "source_reference": "anthropic-model-catalog-2026-07-22",
        "review_note": "Reviewed against the approved provider catalog.",
    }
    body.update(overrides)
    return body


def _price_body(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "version_id": "anthropic-sonnet-input-2026-08-01",
        "gateway_model_name": "claude-sonnet-4-5",
        "usage_class": "normal_input",
        "token_unit": 1_000_000,
        "amount": "30",
        "effective_at": (
            datetime.now(timezone.utc) + timedelta(days=10)
        ).isoformat(),
        "explicit_free": False,
        "source_reference": "anthropic-pricing-2026-07-22",
        "review_note": "Reviewed by the platform pricing owner.",
    }
    body.update(overrides)
    return body


def _digest(document: dict[str, Any]) -> str:
    encoded = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


class MemoryGovernanceStore:
    """A restart-stable fake of the insert-only Database API."""

    def __init__(self, storage: dict[str, Any] | None = None) -> None:
        self.storage = storage or {
            "models": {},
            "model_events": [],
            "prices": {},
            "previews": {},
            "confirmations": {},
            "audit": [],
        }

    def _audit(
        self,
        *,
        operation_id: str,
        actor: str,
        action: str,
        resource_id: str,
        document_sha256: str,
    ) -> None:
        if any(
            row["operation_id"] == operation_id for row in self.storage["audit"]
        ):
            raise GovernanceConflict("operation already exists")
        self.storage["audit"].append(
            {
                "id": len(self.storage["audit"]) + 1,
                "operation_id": operation_id,
                "actor": actor,
                "action": action,
                "resource_type": "governance_test_record",
                "resource_id": resource_id,
                "document_sha256": document_sha256,
                "created_at": datetime.now(timezone.utc),
            }
        )

    async def create_governed_model(
        self,
        model,
        *,
        operation_id,
        actor,
        source_reference,
        review_note,
    ):
        replay = next(
            (
                row
                for row in self.storage["models"].values()
                if row["operation_id"] == operation_id
            ),
            None,
        )
        if replay is not None:
            if (
                replay["actor"] == actor
                and replay["gateway_model_name"] == model.gateway_model_name
                and replay["provider_name"] == model.provider_name
                and replay["provider_model_id"] == model.provider_model_id
                and replay["initial_visible_in_discovery"]
                == model.visible_in_discovery
                and replay["source_reference"] == source_reference
                and replay["review_note"] == review_note
            ):
                return self._project(replay)
            raise GovernanceConflict("governance operation ID was reused")
        key = (model.gateway_model_name, model.egress_policy_sha256)
        provider_key = (
            model.provider_name,
            model.provider_model_id,
            model.egress_policy_sha256,
        )
        if key in self.storage["models"] or any(
            (
                row["provider_name"],
                row["provider_model_id"],
                row["egress_policy_sha256"],
            )
            == provider_key
            for row in self.storage["models"].values()
        ):
            raise GovernanceConflict("model version or operation already exists")
        row = {
            "operation_id": operation_id,
            "gateway_model_name": model.gateway_model_name,
            "provider_name": model.provider_name,
            "provider_model_id": model.provider_model_id,
            "initial_visible_in_discovery": model.visible_in_discovery,
            "egress_policy_sha256": model.egress_policy_sha256,
            "litellm_model": model.target.model,
            "api_base": model.target.api_base,
            "litellm_credential_name": model.target.litellm_credential_name,
            "cache_control_injection_points": [
                {"location": point.location, "role": point.role}
                for point in model.target.cache_control_injection_points
            ],
            "source_reference": source_reference,
            "review_note": review_note,
            "actor": actor,
        }
        row["document_sha256"] = _digest(row)
        self._audit(
            operation_id=operation_id,
            actor=actor,
            action="model_version_created",
            resource_id=model.gateway_model_name,
            document_sha256=row["document_sha256"],
        )
        self.storage["models"][key] = row
        return self._project(row)

    def _project(self, row):
        events = [
            event
            for event in self.storage["model_events"]
            if event["model_operation_id"] == row["operation_id"]
        ]
        return with_projected_state(row, events)

    async def list_governed_models(
        self, *, egress_policy_sha256, visible_only, limit, offset
    ):
        rows = [
            self._project(row)
            for row in self.storage["models"].values()
            if row["egress_policy_sha256"] == egress_policy_sha256
            and (
                not visible_only
                or (
                    self._project(row)["active"]
                    and self._project(row)["visible_in_discovery"]
                )
            )
        ]
        return sorted(rows, key=lambda row: row["gateway_model_name"])[
            offset : offset + limit
        ]

    async def get_governed_model(
        self, gateway_model_name, *, egress_policy_sha256
    ):
        row = self.storage["models"].get(
            (gateway_model_name, egress_policy_sha256)
        )
        return self._project(row) if row is not None else None

    async def append_model_lifecycle_event(
        self,
        gateway_model_name,
        *,
        egress_policy_sha256,
        action,
        operation_id,
        actor,
    ):
        row = self.storage["models"].get(
            (gateway_model_name, egress_policy_sha256)
        )
        if row is None:
            raise GovernanceNotFound("governed model version does not exist")
        replay = next(
            (
                event
                for event in self.storage["model_events"]
                if event["operation_id"] == operation_id
            ),
            None,
        )
        if replay is not None:
            if (
                replay["model_operation_id"] == row["operation_id"]
                and replay["action"] == action.value
                and replay["actor"] == actor
            ):
                return self._project(row)
            raise GovernanceConflict("governance operation ID was reused")

        projected = self._project(row)
        current = GovernedModelState(
            lifecycle_state=projected["lifecycle_state"],
            active=projected["active"],
            visible_in_discovery=projected["visible_in_discovery"],
            last_event_sequence=projected["last_event_sequence"],
        )
        try:
            apply_model_action(
                current,
                action,
                initial_visibility=row["initial_visible_in_discovery"],
            )
        except ModelLifecycleError as exc:
            raise GovernanceConflict(str(exc)) from exc
        event = {
            "event_sequence": len(self.storage["model_events"]) + 1,
            "operation_id": operation_id,
            "model_operation_id": row["operation_id"],
            "action": action.value,
            "actor": actor,
            "document_sha256": _digest(
                {"model": row["operation_id"], "action": action.value}
            ),
        }
        self.storage["model_events"].append(event)
        self._audit(
            operation_id=operation_id,
            actor=actor,
            action=f"model_{action.value}",
            resource_id=gateway_model_name,
            document_sha256=event["document_sha256"],
        )
        return self._project(row)

    def _price_row(
        self,
        price: PriceVersion,
        *,
        model_operation_id,
        gateway_model_name,
        egress_policy_sha256,
        operation_id,
        actor,
        source_reference,
        review_note,
        document_sha256=None,
    ):
        replay = next(
            (
                row
                for row in self.storage["prices"].values()
                if row["operation_id"] == operation_id
            ),
            None,
        )
        if replay is not None:
            if (
                replay["actor"] == actor
                and replay["version_id"] == price.version_id
                and replay["model_operation_id"] == model_operation_id
                and replay["egress_policy_sha256"] == egress_policy_sha256
                and replay["gateway_model_name"] == gateway_model_name
                and replay["usage_class"] == price.usage_class.value
                and replay["token_unit"] == price.token_unit
                and replay["amount"] == price.amount
                and replay["effective_at"] == price.effective_at
            ):
                return replay
            raise GovernanceConflict("governance operation ID was reused")
        if price.version_id in self.storage["prices"]:
            raise GovernanceConflict("price version or operation already exists")
        row = {
            "version_id": price.version_id,
            "operation_id": operation_id,
            "model_operation_id": model_operation_id,
            "egress_policy_sha256": egress_policy_sha256,
            "gateway_model_name": gateway_model_name,
            "provider_name": price.provider,
            "usage_class": price.usage_class.value,
            "token_unit": price.token_unit,
            "amount": price.amount,
            "currency": price.currency,
            "explicit_free": price.explicit_free,
            "effective_at": price.effective_at,
            "source_reference": source_reference,
            "review_note": review_note,
            "actor": actor,
        }
        row["document_sha256"] = document_sha256 or _digest(row)
        self.storage["prices"][price.version_id] = row
        return row

    async def create_governed_price(self, price, **kwargs):
        row = self._price_row(price, **kwargs)
        row["baseline_price_policy_sha256"] = "1" * 64
        if any(
            audit["operation_id"] == kwargs["operation_id"]
            for audit in self.storage["audit"]
        ):
            row["_operation_replayed"] = True
            return row
        self._audit(
            operation_id=kwargs["operation_id"],
            actor=kwargs["actor"],
            action="price_version_created",
            resource_id=price.version_id,
            document_sha256=row["document_sha256"],
        )
        return row

    async def list_governed_prices(
        self, *, model_operation_id, limit, offset
    ):
        rows = [
            row
            for row in self.storage["prices"].values()
            if row["model_operation_id"] == model_operation_id
        ]
        return rows[offset : offset + limit]

    async def create_price_backdate_preview(self, price, **kwargs):
        preview_id = kwargs["preview_id"]
        row = {
            "preview_id": preview_id,
            "model_operation_id": kwargs["model_operation_id"],
            "egress_policy_sha256": kwargs["egress_policy_sha256"],
            "candidate_version_id": price.version_id,
            "gateway_model_name": kwargs["gateway_model_name"],
            "provider_name": price.provider,
            "usage_class": price.usage_class.value,
            "token_unit": price.token_unit,
            "amount": price.amount,
            "currency": price.currency,
            "explicit_free": price.explicit_free,
            "effective_at": price.effective_at,
            "source_reference": kwargs["source_reference"],
            "review_note": kwargs["review_note"],
            "actor": kwargs["actor"],
        }
        row["candidate_sha256"] = _digest(row)
        row.update(
            {
                "baseline_price_policy_sha256": "1" * 64,
                "baseline_adjustments_sha256": "2" * 64,
                "preview_sha256": _digest(
                    {
                        "candidate_sha256": row["candidate_sha256"],
                        "affected_rows": [],
                    }
                ),
                "effective_to": None,
                "affected_count": 0,
                "old_total_usd": Decimal("0"),
                "new_total_usd": Decimal("0"),
                "delta_usd": Decimal("0"),
                "old_unknown_count": 0,
                "new_unknown_count": 0,
                "affected_rows": [],
                "shown_affected_count": 0,
                "affected_rows_truncated": False,
            }
        )
        existing = self.storage["previews"].get(preview_id)
        if existing is not None:
            if (
                existing["candidate_sha256"] == row["candidate_sha256"]
                and existing["actor"] == row["actor"]
            ):
                existing["_operation_replayed"] = True
                return existing
            raise GovernanceConflict("backdate preview operation ID was reused")
        self._audit(
            operation_id=preview_id,
            actor=kwargs["actor"],
            action="price_backdate_previewed",
            resource_id=preview_id,
            document_sha256=row["candidate_sha256"],
        )
        self.storage["previews"][preview_id] = row
        return row

    async def confirm_price_backdate(
        self,
        *,
        preview_id,
        candidate_sha256,
        preview_sha256,
        confirmation_operation_id,
        actor,
        expected_egress_policy_sha256,
    ):
        preview = self.storage["previews"].get(preview_id)
        if preview is None:
            raise GovernanceNotFound("backdate preview does not exist")
        if preview["candidate_sha256"] != candidate_sha256:
            raise GovernanceConflict("backdate preview digest does not match")
        if preview["preview_sha256"] != preview_sha256:
            raise GovernanceConflict("backdate usage preview digest does not match")
        if preview["egress_policy_sha256"] != expected_egress_policy_sha256:
            raise GovernanceConflict("backdate preview belongs to another policy")
        replay = self.storage["confirmations"].get(confirmation_operation_id)
        if replay is not None:
            if replay["preview_id"] != preview_id or replay["actor"] != actor:
                raise GovernanceConflict(
                    "backdate confirmation operation ID was reused"
                )
            replay["row"]["_operation_replayed"] = True
            return replay["row"]
        if any(
            item["preview_id"] == preview_id
            for item in self.storage["confirmations"].values()
        ):
            raise GovernanceConflict("backdate preview was already confirmed")
        price = PriceVersion(
            version_id=preview["candidate_version_id"],
            provider=preview["provider_name"],
            model=preview["gateway_model_name"],
            usage_class=UsageClass(preview["usage_class"]),
            token_unit=preview["token_unit"],
            amount=Decimal(preview["amount"]),
            effective_at=preview["effective_at"],
            explicit_free=preview["explicit_free"],
        )
        row = self._price_row(
            price,
            model_operation_id=preview["model_operation_id"],
            gateway_model_name=preview["gateway_model_name"],
            egress_policy_sha256=preview["egress_policy_sha256"],
            operation_id=confirmation_operation_id,
            actor=actor,
            source_reference=preview["source_reference"],
            review_note=preview["review_note"],
            document_sha256=candidate_sha256,
        )
        self._audit(
            operation_id=confirmation_operation_id,
            actor=actor,
            action="price_backdate_confirmed",
            resource_id=price.version_id,
            document_sha256=candidate_sha256,
        )
        row.update(
            {
                "preview_id": preview_id,
                "candidate_sha256": candidate_sha256,
                "preview_sha256": preview_sha256,
                "confirmation_operation_id": confirmation_operation_id,
                "adjustment_count": 0,
                "affected_count": 0,
                "delta_usd": Decimal("0"),
                "baseline_price_policy_sha256": preview[
                    "baseline_price_policy_sha256"
                ],
            }
        )
        self.storage["confirmations"][confirmation_operation_id] = {
            "preview_id": preview_id,
            "actor": actor,
            "row": row,
        }
        return row

    async def governance_audit(self, limit=100):
        return list(reversed(self.storage["audit"][-limit:]))


class FakeModelReconciler:
    def __init__(self) -> None:
        self.calls = 0

    async def reconcile(self) -> None:
        self.calls += 1


class FakeIdentity:
    def __init__(self) -> None:
        self.assignments: dict[str, list[str]] = {}
        self.policy_writes: list[dict[str, Any]] = []

    async def projects_assigning_model(self, model_name: str) -> list[str]:
        return self.assignments.get(model_name, [])

    async def set_group_policy(self, group_id, policy, operation_id):
        self.policy_writes.append(
            {"group_id": group_id, "policy": policy, "operation_id": operation_id}
        )
        return policy


@pytest.fixture
def governance_state():
    previous = dict(state)
    db = MemoryGovernanceStore()
    db.reconciler = FakeModelReconciler()
    db.identity = FakeIdentity()
    state.clear()
    state.update(
        {
            "settings": _settings(),
            "db": db,
            "provider_policy": _receipt(),
            "model_reconciler": db.reconciler,
            "identity": db.identity,
        }
    )
    try:
        yield db
    finally:
        state.clear()
        state.update(previous)


@pytest.mark.asyncio
async def test_governance_is_unavailable_without_separately_trusted_policy() -> None:
    previous = dict(state)
    try:
        state.clear()
        state.update({"settings": _settings(), "db": MemoryGovernanceStore()})
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://rotator"
        ) as client:
            response = await client.get(
                "/model-governance/models",
                headers={"X-Internal-Auth": AUTH_TOKEN},
            )
        assert response.status_code == 503
        assert response.json() == {
            "detail": "model governance is unavailable: provider policy is not trusted"
        }
    finally:
        state.clear()
        state.update(previous)


@pytest.mark.asyncio
async def test_hidden_model_stays_out_of_discovery_and_survives_restart(
    governance_state,
) -> None:
    transport = httpx.ASGITransport(app=app)
    hidden_operation = str(uuid.uuid4())
    visible_operation = str(uuid.uuid4())
    async with httpx.AsyncClient(
        transport=transport, base_url="http://rotator"
    ) as client:
        hidden = await client.post(
            "/model-governance/models",
            headers=_headers(hidden_operation),
            json=_model_body(),
        )
        assert hidden.status_code == 201
        assert hidden.json()["api_base"] == "http://envoy-egress:8080/anthropic"

        exact_retry = await client.post(
            "/model-governance/models",
            headers=_headers(hidden_operation),
            json=_model_body(),
        )
        assert exact_retry.status_code == 201
        assert exact_retry.json()["operation_id"] == hidden_operation

        visible = await client.post(
            "/model-governance/models",
            headers=_headers(visible_operation),
            json=_model_body(
                gateway_model_name="claude-haiku-4-5",
                provider_model_id="claude-haiku-4-5",
                visible_in_discovery=True,
            ),
        )
        assert visible.status_code == 201
        assert visible.json()["lifecycle_state"] == "draft"

        draft_discovery = await client.get(
            "/model-governance/discovery",
            headers={"X-Internal-Auth": AUTH_TOKEN},
        )
        assert draft_discovery.json() == {"models": []}

        hidden_activation = str(uuid.uuid4())
        visible_activation = str(uuid.uuid4())
        activated_hidden = await client.post(
            "/model-governance/models/claude-sonnet-4-5/activate",
            headers=_headers(hidden_activation),
        )
        activated_visible = await client.post(
            "/model-governance/models/claude-haiku-4-5/activate",
            headers=_headers(visible_activation),
        )
        assert activated_hidden.status_code == 200
        assert activated_hidden.json()["active"] is True
        assert activated_hidden.json()["visible_in_discovery"] is False
        assert activated_visible.status_code == 200
        assert activated_visible.json()["visible_in_discovery"] is True
        assert governance_state.reconciler.calls == 2

        duplicate = await client.post(
            "/model-governance/models",
            headers=_headers(),
            json=_model_body(),
        )
        assert duplicate.status_code == 409

        reused_operation = await client.post(
            "/model-governance/models",
            headers=_headers(hidden_operation),
            json=_model_body(
                gateway_model_name="claude-opus-4-5",
                provider_model_id="claude-opus-4-5",
            ),
        )
        assert reused_operation.status_code == 409

        discovery = await client.get(
            "/model-governance/discovery",
            headers={"X-Internal-Auth": AUTH_TOKEN},
        )
        assert discovery.json() == {
            "models": [
                {
                    "id": "claude-haiku-4-5",
                    "provider": "anthropic",
                    "deployment_id": visible_operation,
                }
            ]
        }

        # A new repository object models a process restart over the same
        # durable storage. Hidden state remains durable but not discoverable.
        state["db"] = MemoryGovernanceStore(governance_state.storage)
        listed = await client.get(
            "/model-governance/models",
            headers={"X-Internal-Auth": AUTH_TOKEN},
        )
        assert {row["gateway_model_name"] for row in listed.json()} == {
            "claude-sonnet-4-5",
            "claude-haiku-4-5",
        }
        rediscovered = await client.get(
            "/model-governance/discovery",
            headers={"X-Internal-Auth": AUTH_TOKEN},
        )
        assert rediscovered.json() == discovery.json()

        audit = await client.get(
            "/model-governance/audit",
            headers={"X-Internal-Auth": AUTH_TOKEN},
        )
        assert audit.status_code == 200
        assert {row["operation_id"] for row in audit.json()} == {
            hidden_operation,
            visible_operation,
            hidden_activation,
            visible_activation,
        }
        assert all(row["actor"] == ACTOR for row in audit.json())
        assert all(len(row["document_sha256"]) == 64 for row in audit.json())


@pytest.mark.asyncio
async def test_visibility_assignment_and_retirement_gates(governance_state) -> None:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://rotator"
    ) as client:
        created = await client.post(
            "/model-governance/models",
            headers=_headers(),
            json=_model_body(),
        )
        assert created.status_code == 201
        activated = await client.post(
            "/model-governance/models/claude-sonnet-4-5/activate",
            headers=_headers(),
        )
        assert activated.status_code == 200

        governance_state.identity.assignments["claude-sonnet-4-5"] = [
            "project-1"
        ]
        hidden = await client.get(
            "/model-governance/discovery",
            headers={
                "X-Internal-Auth": _settings().portal_identity_token,
            },
        )
        assert hidden.status_code == 200
        assert hidden.json() == {"models": []}

        shown = await client.post(
            "/model-governance/models/claude-sonnet-4-5/show",
            headers=_headers(),
        )
        assert shown.status_code == 200
        assert shown.json()["visible_in_discovery"] is True
        hidden_again = await client.post(
            "/model-governance/models/claude-sonnet-4-5/hide",
            headers=_headers(),
        )
        assert hidden_again.status_code == 200
        assert hidden_again.json()["visible_in_discovery"] is False

        assigned_retirement = await client.post(
            "/model-governance/models/claude-sonnet-4-5/retire",
            headers=_headers(),
        )
        assert assigned_retirement.status_code == 409

        governance_state.identity.assignments.clear()
        retirement_operation = str(uuid.uuid4())
        retired = await client.post(
            "/model-governance/models/claude-sonnet-4-5/retire",
            headers=_headers(retirement_operation),
        )
        assert retired.status_code == 200
        assert retired.json()["lifecycle_state"] == "retired"
        assert retired.json()["active"] is False
        retry = await client.post(
            "/model-governance/models/claude-sonnet-4-5/retire",
            headers=_headers(retirement_operation),
        )
        assert retry.status_code == 200
        after_retirement = await client.post(
            "/model-governance/models/claude-sonnet-4-5/show",
            headers=_headers(),
        )
        assert after_retirement.status_code == 409


@pytest.mark.asyncio
async def test_portal_token_can_read_discovery_but_cannot_mutate(
    governance_state,
) -> None:
    transport = httpx.ASGITransport(app=app)
    portal_headers = {
        "X-Internal-Auth": _settings().portal_identity_token,
        "X-AIGW-Actor-ID": ACTOR,
        "X-AIGW-Operation-ID": str(uuid.uuid4()),
    }
    async with httpx.AsyncClient(
        transport=transport, base_url="http://rotator"
    ) as client:
        discovery = await client.get(
            "/model-governance/discovery", headers=portal_headers
        )
        mutation = await client.post(
            "/model-governance/models",
            headers=portal_headers,
            json=_model_body(),
        )
    assert discovery.status_code == 200
    assert mutation.status_code == 401


@pytest.mark.asyncio
async def test_only_active_governed_models_can_be_assigned(governance_state) -> None:
    transport = httpx.ASGITransport(app=app)
    policy = {
        "allowed_models": ["claude-sonnet-4-5"],
        "default_model": "claude-sonnet-4-5",
    }
    async with httpx.AsyncClient(
        transport=transport, base_url="http://rotator"
    ) as client:
        await client.post(
            "/model-governance/models",
            headers=_headers(),
            json=_model_body(),
        )
        draft_assignment = await client.put(
            "/identity/groups/group-1/policy",
            headers=_headers(),
            json=policy,
        )
        assert draft_assignment.status_code == 409
        await client.post(
            "/model-governance/models/claude-sonnet-4-5/activate",
            headers=_headers(),
        )
        hidden_assignment = await client.put(
            "/identity/groups/group-1/policy",
            headers=_headers(),
            json=policy,
        )
    assert hidden_assignment.status_code == 200
    assert governance_state.identity.policy_writes[0]["policy"][
        "allowed_models"
    ] == ["claude-sonnet-4-5"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("api_base", "https://attacker.invalid"),
        ("provider_hostname", "attacker.invalid"),
        ("ca_path", "/tmp/attacker.pem"),
        ("vault_path", "secret/arbitrary"),
    ],
)
async def test_model_api_rejects_all_client_owned_network_and_trust_fields(
    governance_state, field, value
) -> None:
    body = _model_body()
    body[field] = value
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://rotator"
    ) as client:
        response = await client.post(
            "/model-governance/models", headers=_headers(), json=body
        )
    assert response.status_code == 422
    assert governance_state.storage["models"] == {}


@pytest.mark.asyncio
async def test_model_api_rejects_unknown_provider_and_untrusted_source_url(
    governance_state,
) -> None:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://rotator"
    ) as client:
        unknown = await client.post(
            "/model-governance/models",
            headers=_headers(),
            json=_model_body(provider_name="unknown"),
        )
        source_url = await client.post(
            "/model-governance/models",
            headers=_headers(),
            json=_model_body(source_reference="https://attacker.invalid/catalog"),
        )
    assert unknown.status_code == 422
    assert source_url.status_code == 422


@pytest.mark.asyncio
async def test_governance_writes_require_one_canonical_actor_and_operation(
    governance_state,
) -> None:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://rotator"
    ) as client:
        missing_actor = await client.post(
            "/model-governance/models",
            headers={
                "X-Internal-Auth": AUTH_TOKEN,
                "X-AIGW-Operation-ID": str(uuid.uuid4()),
            },
            json=_model_body(),
        )
        bad_actor = await client.post(
            "/model-governance/models",
            headers={**_headers(), "X-AIGW-Actor-ID": "../../spoofed"},
            json=_model_body(),
        )
        non_v4_operation = await client.post(
            "/model-governance/models",
            headers=_headers(str(uuid.uuid1())),
            json=_model_body(),
        )
        portal_token = await client.post(
            "/model-governance/models",
            headers={
                **_headers(),
                "X-Internal-Auth": _settings().portal_identity_token,
            },
            json=_model_body(),
        )
    assert missing_actor.status_code == 400
    assert bad_actor.status_code == 400
    assert non_v4_operation.status_code == 400
    assert portal_token.status_code == 401
    assert governance_state.storage["models"] == {}


@pytest.mark.asyncio
async def test_price_api_supports_every_usage_class_with_exact_decimal_strings(
    governance_state, caplog,
) -> None:
    caplog.set_level("INFO", logger="key_rotator.pricing")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://rotator"
    ) as client:
        assert (
            await client.post(
                "/model-governance/models",
                headers=_headers(),
                json=_model_body(),
            )
        ).status_code == 201

        usage_classes = (
            "normal_input",
            "cache_creation_5m",
            "cache_creation_1h",
            "cache_read",
            "output",
        )
        for index, usage_class in enumerate(usage_classes):
            operation_id = str(uuid.uuid4())
            body = _price_body(
                version_id=f"sonnet-{usage_class}-2026-08-01",
                usage_class=usage_class,
                amount="0" if usage_class == "cache_read" else str(index + 1),
                explicit_free=usage_class == "cache_read",
            )
            response = await client.post(
                "/model-governance/prices",
                headers=_headers(operation_id),
                json=body,
            )
            assert response.status_code == 201, response.text
            assert isinstance(response.json()["amount"], str)
            retry = await client.post(
                "/model-governance/prices",
                headers=_headers(operation_id),
                json=body,
            )
            assert retry.status_code == 201
            assert retry.json()["operation_id"] == operation_id

        listed = await client.get(
            "/model-governance/models/claude-sonnet-4-5/prices",
            headers={"X-Internal-Auth": AUTH_TOKEN},
        )
        assert {row["usage_class"] for row in listed.json()} == set(usage_classes)
    price_events = [
        json.loads(record.getMessage().split("AIGW_SECURITY_EVENT ", 1)[1])
        for record in caplog.records
        if "AIGW_SECURITY_EVENT " in record.getMessage()
    ]
    assert len(price_events) == len(usage_classes)
    assert {event["action"] for event in price_events} == {"create"}
    assert len({event["operation_id"] for event in price_events}) == len(
        usage_classes
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "patch",
    [
        {"amount": 30},
        {"amount": "1", "token_unit": 3},
        {"amount": "0", "explicit_free": False},
        {"provider_name": "anthropic"},
        {"api_base": "https://attacker.invalid"},
        {"source_reference": "https://attacker.invalid/price"},
    ],
)
async def test_price_api_rejects_inexact_or_client_owned_fields(
    governance_state, patch
) -> None:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://rotator"
    ) as client:
        await client.post(
            "/model-governance/models", headers=_headers(), json=_model_body()
        )
        response = await client.post(
            "/model-governance/prices",
            headers=_headers(),
            json=_price_body(**patch),
        )
    assert response.status_code == 422
    assert governance_state.storage["prices"] == {}


@pytest.mark.asyncio
async def test_backdating_previews_then_confirms_exact_immutable_evidence(
    governance_state, caplog,
) -> None:
    caplog.set_level("INFO", logger="key_rotator.pricing")
    transport = httpx.ASGITransport(app=app)
    preview_id = str(uuid.uuid4())
    past = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    async with httpx.AsyncClient(
        transport=transport, base_url="http://rotator"
    ) as client:
        await client.post(
            "/model-governance/models", headers=_headers(), json=_model_body()
        )
        direct = await client.post(
            "/model-governance/prices",
            headers=_headers(),
            json=_price_body(effective_at=past),
        )
        assert direct.status_code == 409
        assert governance_state.storage["prices"] == {}

        preview = await client.post(
            "/model-governance/prices/backdate/preview",
            headers=_headers(preview_id),
            json=_price_body(effective_at=past),
        )
        assert preview.status_code == 201, preview.text
        preview_receipt = preview.json()
        assert preview_receipt["preview_id"] == preview_id
        assert preview_receipt["affected_count"] == 0
        assert preview_receipt["old_total_usd"] == "0"
        assert preview_receipt["new_total_usd"] == "0"
        assert preview_receipt["delta_usd"] == "0"
        assert preview_receipt["affected_rows"] == []
        assert governance_state.storage["prices"] == {}

        retry = await client.post(
            "/model-governance/prices/backdate/preview",
            headers=_headers(preview_id),
            json=_price_body(effective_at=past),
        )
        assert retry.status_code == 201
        assert retry.json()["preview_sha256"] == preview_receipt["preview_sha256"]

        changed_retry = await client.post(
            "/model-governance/prices/backdate/preview",
            headers=_headers(preview_id),
            json=_price_body(effective_at=past, amount="31"),
        )
        assert changed_retry.status_code == 409

        confirm_id = str(uuid.uuid4())
        bad_digest = await client.post(
            f"/model-governance/prices/backdate/{preview_id}/confirm",
            headers=_headers(confirm_id),
            json={
                "candidate_sha256": preview_receipt["candidate_sha256"],
                "preview_sha256": "0" * 64,
                "confirmation": "CONFIRM BACKDATED PRICE",
            },
        )
        assert bad_digest.status_code == 409

        confirm = await client.post(
            f"/model-governance/prices/backdate/{preview_id}/confirm",
            headers=_headers(confirm_id),
            json={
                "candidate_sha256": preview_receipt["candidate_sha256"],
                "preview_sha256": preview_receipt["preview_sha256"],
                "confirmation": "CONFIRM BACKDATED PRICE",
            },
        )
        assert confirm.status_code == 201, confirm.text
        assert confirm.json()["confirmation_operation_id"] == confirm_id
        assert confirm.json()["adjustment_count"] == 0

        confirm_retry = await client.post(
            f"/model-governance/prices/backdate/{preview_id}/confirm",
            headers=_headers(confirm_id),
            json={
                "candidate_sha256": preview_receipt["candidate_sha256"],
                "preview_sha256": preview_receipt["preview_sha256"],
                "confirmation": "CONFIRM BACKDATED PRICE",
            },
        )
        assert confirm_retry.status_code == 201
        assert confirm_retry.json() == confirm.json()

        duplicate_confirm = await client.post(
            f"/model-governance/prices/backdate/{preview_id}/confirm",
            headers=_headers(),
            json={
                "candidate_sha256": preview_receipt["candidate_sha256"],
                "preview_sha256": preview_receipt["preview_sha256"],
                "confirmation": "CONFIRM BACKDATED PRICE",
            },
        )
        assert duplicate_confirm.status_code == 409
        assert len(governance_state.storage["prices"]) == 1
        assert len(governance_state.storage["previews"]) == 1
        assert len(governance_state.storage["confirmations"]) == 1
    price_events = [
        json.loads(record.getMessage().split("AIGW_SECURITY_EVENT ", 1)[1])
        for record in caplog.records
        if "AIGW_SECURITY_EVENT " in record.getMessage()
    ]
    assert [event["action"] for event in price_events] == [
        "backdate_preview",
        "backdate_confirm",
    ]


def test_governance_schema_is_idempotent_append_only_and_audited() -> None:
    schema = (
        Path(__file__).parents[3]
        / "compose/postgres/init/02-governance.sql"
    ).read_text()
    assert schema.count("CREATE TABLE IF NOT EXISTS") == 7
    assert "operation_id uuid PRIMARY KEY" in schema
    assert "document_sha256 varchar(64) NOT NULL" in schema
    assert "source_reference varchar(256) NOT NULL" in schema
    assert "review_note varchar(500) NOT NULL" in schema
    assert "baseline_price_policy_sha256 varchar(64) NOT NULL" in schema
    assert "amount BETWEEN 0 AND 1000000" in schema
    assert "amount = 0 AND explicit_free" in schema
    assert "currency = 'USD'" in schema
    assert "UPDATE governed_" not in schema
    assert "DELETE FROM governed_" not in schema
    assert "BEFORE UPDATE OR DELETE" in schema
    assert "BEFORE TRUNCATE" in schema
    for table in (
        "governed_model_versions",
        "governed_model_events",
        "governed_price_versions",
        "price_backdate_previews",
        "price_backdate_confirmations",
        "governance_audit",
    ):
        assert table in schema
