"""Append-only model and pricing persistence for key-rotator."""

from __future__ import annotations

import hashlib
import json
from decimal import Context, Decimal, ROUND_HALF_EVEN, localcontext
from typing import Any, Optional

import psycopg
from psycopg import sql

from app.model_catalog import ResolvedModelDraft
from app.model_lifecycle import (
    GovernedModelState,
    ModelLifecycleAction,
    ModelLifecycleError,
    apply_model_action,
    lifecycle_document_sha256,
    with_projected_state,
)
from app.pricing import (
    PriceVersion,
    UsageClass,
    canonical_adjustment_digest,
    canonical_price_digest,
    canonical_reprice_preview_digest,
    confirmed_adjustments,
    preview_reprice,
)
from app.usage_repricing import (
    TOKEN_COLUMNS,
    adjustment_from_row,
    apply_adjustment_history,
    booked_cost_from_row,
    preview_row_sha256,
    price_from_row,
)


class GovernanceConflict(RuntimeError):
    """An immutable governance identity is already present."""


class GovernanceNotFound(RuntimeError):
    """A referenced immutable governance record does not exist."""


def _governance_document_sha256(document: dict[str, Any]) -> str:
    encoded = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _price_document(
    price: PriceVersion,
    *,
    model_operation_id: str,
    egress_policy_sha256: str,
    gateway_model_name: str,
    source_reference: str,
    review_note: str,
) -> dict[str, Any]:
    amount = format(price.amount, "f")
    if "." in amount:
        amount = amount.rstrip("0").rstrip(".")
    return {
        "amount": amount or "0",
        "currency": price.currency,
        "egress_policy_sha256": egress_policy_sha256,
        "effective_at": price.effective_at.isoformat(timespec="microseconds"),
        "explicit_free": price.explicit_free,
        "gateway_model_name": gateway_model_name,
        "model_operation_id": model_operation_id,
        "provider_name": price.provider,
        "source_reference": source_reference,
        "review_note": review_note,
        "token_unit": price.token_unit,
        "usage_class": price.usage_class.value,
        "version_id": price.version_id,
    }


MAX_BACKDATE_AFFECTED_ROWS = 10_000
MAX_BACKDATE_ADJUSTMENT_ROWS = 10_000
MAX_BACKDATE_RESPONSE_ROWS = 100


def _backdate_usage_query(
    usage_class: UsageClass,
    *,
    has_effective_to: bool,
) -> sql.Composed:
    """Build the bounded query from closed enum and SQL-fragment catalogs."""

    if type(usage_class) is not UsageClass or type(has_effective_to) is not bool:
        raise TypeError("backdate query inputs must use reviewed types")
    upper_bound = (
        sql.SQL("AND occurred_at < %s")
        if has_effective_to
        else sql.SQL("")
    )
    return sql.SQL(
        """
        SELECT *
        FROM aigw_governance.usage_events
        WHERE provider_name = %s
          AND requested_model = %s
          AND egress_policy_sha256 = %s
          AND usage_completeness = 'complete'
          AND occurred_at >= %s
          {}
          AND {} > 0
        ORDER BY occurred_at, event_id
        LIMIT %s
        """
    ).format(
        upper_bound,
        sql.Identifier(TOKEN_COLUMNS[usage_class]),
    )


def _subtract_exact(left: Decimal, right: Decimal) -> Decimal:
    """Use the same bounded precision as the pure pricing engine."""

    with localcontext(Context(prec=60, rounding=ROUND_HALF_EVEN)):
        return left - right


def _preview_component(change: Any, usage_class: UsageClass, *, proposed: bool) -> Any:
    configured = change.proposed if proposed else change.original
    return next(
        component
        for component in configured.components
        if component.usage_class == usage_class
    )


def _preview_row_documents(
    preview: Any,
    *,
    preview_id: str,
    usage_class: UsageClass,
) -> list[dict[str, Any]]:
    """Return the exact append-only rows represented by a pure preview."""

    rows: list[dict[str, Any]] = []
    for change in preview.changes:
        old = _preview_component(change, usage_class, proposed=False)
        new = _preview_component(change, usage_class, proposed=True)
        if new.cost is None or new.price_version_id is None:
            raise ValueError("backdate candidate did not produce a known cost")
        component_delta = (
            None if old.cost is None else _subtract_exact(new.cost, old.cost)
        )
        row = {
            "preview_id": preview_id,
            "usage_event_id": change.original.usage_id,
            "usage_class": usage_class.value,
            "units": old.units,
            "supersedes_adjustment_id": old.adjustment_id,
            "previous_price_version_id": old.price_version_id,
            "new_price_version_id": new.price_version_id,
            "previous_component_cost_usd": old.cost,
            "new_component_cost_usd": new.cost,
            "component_delta_usd": component_delta,
            "previous_total_cost_usd": change.original.total,
            "new_total_cost_usd": change.proposed.total,
        }
        row["row_sha256"] = preview_row_sha256(
            preview_id=preview_id,
            usage_event_id=change.original.usage_id,
            usage_class=usage_class,
            units=old.units,
            supersedes_adjustment_id=old.adjustment_id,
            previous_price_version_id=old.price_version_id,
            new_price_version_id=new.price_version_id,
            previous_component_cost=old.cost,
            new_component_cost=new.cost,
            previous_total_cost=change.original.total,
            new_total_cost=change.proposed.total,
        )
        rows.append(row)
    return rows


def _preview_receipt(
    preview_row: dict[str, Any],
    impact_row: dict[str, Any],
    affected_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build one bounded response from already stored immutable evidence."""

    receipt = dict(preview_row)
    receipt.update(impact_row)
    receipt["affected_rows"] = affected_rows[:MAX_BACKDATE_RESPONSE_ROWS]
    receipt["shown_affected_count"] = min(
        len(affected_rows), MAX_BACKDATE_RESPONSE_ROWS
    )
    receipt["affected_rows_truncated"] = (
        len(affected_rows) > MAX_BACKDATE_RESPONSE_ROWS
    )
    return receipt


async def _load_price_policy(
    cur: Any,
    model_operation_id: str,
) -> tuple[PriceVersion, ...]:
    await cur.execute(
        """
        SELECT *
        FROM aigw_governance.governed_price_versions
        WHERE model_operation_id = %s::uuid
        ORDER BY effective_at, usage_class, version_id
        """,
        (model_operation_id,),
    )
    return tuple(price_from_row(dict(row)) for row in await cur.fetchall())


async def _compute_backdate_impact(
    cur: Any,
    *,
    price: PriceVersion,
    model_operation_id: str,
    egress_policy_sha256: str,
    preview_id: str,
    baseline_price_policy_sha256: str,
) -> dict[str, Any]:
    """Recompute the complete candidate window from immutable evidence."""

    prices = await _load_price_policy(cur, model_operation_id)
    if canonical_price_digest(prices) != baseline_price_policy_sha256:
        raise GovernanceConflict("price policy changed after the backdate preview")
    try:
        empty_preview = preview_reprice((), prices, candidate_price=price)
    except ValueError as exc:
        raise GovernanceConflict(str(exc)) from exc

    parameters: list[Any] = [
        price.provider,
        price.model,
        egress_policy_sha256,
        price.effective_at,
    ]
    if empty_preview.effective_to is not None:
        parameters.append(empty_preview.effective_to)
    parameters.append(MAX_BACKDATE_AFFECTED_ROWS + 1)
    await cur.execute(
        _backdate_usage_query(
            price.usage_class,
            has_effective_to=empty_preview.effective_to is not None,
        ),
        tuple(parameters),
    )
    usage_rows = [dict(row) for row in await cur.fetchall()]
    if len(usage_rows) > MAX_BACKDATE_AFFECTED_ROWS:
        raise GovernanceConflict(
            "backdate affects more than 10000 usage rows; split the price window"
        )

    event_ids = [row["event_id"] for row in usage_rows]
    adjustment_rows: list[dict[str, Any]] = []
    if event_ids:
        await cur.execute(
            """
            SELECT *
            FROM aigw_governance.usage_cost_adjustments
            WHERE usage_event_id = ANY(%s::varchar[])
            ORDER BY adjustment_id
            LIMIT %s
            """,
            (event_ids, MAX_BACKDATE_ADJUSTMENT_ROWS + 1),
        )
        adjustment_rows = [dict(row) for row in await cur.fetchall()]
        if len(adjustment_rows) > MAX_BACKDATE_ADJUSTMENT_ROWS:
            raise GovernanceConflict(
                "backdate reads more than 10000 cost adjustments; "
                "split the price window"
            )

    prices_by_id = {item.version_id: item for item in prices}
    adjustments = tuple(
        adjustment_from_row(row, prices_by_id) for row in adjustment_rows
    )
    adjustments_by_event: dict[str, list[Any]] = {}
    for adjustment in adjustments:
        adjustments_by_event.setdefault(adjustment.usage_id, []).append(adjustment)

    current_results = []
    for row in usage_rows:
        booked = booked_cost_from_row(row, prices_by_id)
        current_results.append(
            apply_adjustment_history(
                booked,
                adjustments_by_event.get(booked.usage_id, ()),
            )
        )
    try:
        preview = preview_reprice(
            current_results,
            prices,
            candidate_price=price,
        )
    except ValueError as exc:
        raise GovernanceConflict(str(exc)) from exc
    baseline_adjustments_sha256 = canonical_adjustment_digest(adjustments)
    preview_sha256 = canonical_reprice_preview_digest(
        preview,
        candidate_price=price,
        baseline_price_policy_sha256=baseline_price_policy_sha256,
        baseline_adjustments_sha256=baseline_adjustments_sha256,
    )
    return {
        "preview": preview,
        "rows": _preview_row_documents(
            preview,
            preview_id=preview_id,
            usage_class=price.usage_class,
        ),
        "adjustments": adjustments,
        "baseline_adjustments_sha256": baseline_adjustments_sha256,
        "preview_sha256": preview_sha256,
    }


async def _load_stored_preview(
    cur: Any,
    preview_id: str,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, list[dict[str, Any]]]:
    await cur.execute(
        """
        SELECT *
        FROM aigw_governance.price_backdate_previews
        WHERE preview_id = %s::uuid
        """,
        (preview_id,),
    )
    raw_preview = await cur.fetchone()
    if raw_preview is None:
        return None, None, []
    await cur.execute(
        """
        SELECT baseline_adjustments_sha256, preview_sha256, effective_to,
               affected_count, old_total_usd, new_total_usd, delta_usd,
               old_unknown_count, new_unknown_count
        FROM aigw_governance.usage_reprice_previews
        WHERE preview_id = %s::uuid
        """,
        (preview_id,),
    )
    raw_impact = await cur.fetchone()
    await cur.execute(
        """
        SELECT preview_id, usage_event_id, usage_class, units,
               supersedes_adjustment_id, previous_price_version_id,
               new_price_version_id, previous_component_cost_usd,
               new_component_cost_usd, component_delta_usd,
               previous_total_cost_usd, new_total_cost_usd, row_sha256
        FROM aigw_governance.usage_reprice_preview_rows
        WHERE preview_id = %s::uuid
        ORDER BY usage_event_id
        """,
        (preview_id,),
    )
    return (
        dict(raw_preview),
        None if raw_impact is None else dict(raw_impact),
        [dict(row) for row in await cur.fetchall()],
    )


def _stored_impact_matches(
    stored: dict[str, Any],
    stored_rows: list[dict[str, Any]],
    computed: dict[str, Any],
) -> bool:
    preview = computed["preview"]
    expected_summary = {
        "baseline_adjustments_sha256": computed[
            "baseline_adjustments_sha256"
        ],
        "preview_sha256": computed["preview_sha256"],
        "effective_to": preview.effective_to,
        "affected_count": preview.affected_count,
        "old_total_usd": preview.old_total,
        "new_total_usd": preview.new_total,
        "delta_usd": preview.delta,
        "old_unknown_count": preview.old_unknown_count,
        "new_unknown_count": preview.new_unknown_count,
    }
    if any(stored.get(key) != value for key, value in expected_summary.items()):
        return False
    expected_rows = computed["rows"]
    if len(stored_rows) != len(expected_rows):
        return False
    expected_by_event = {row["usage_event_id"]: row for row in expected_rows}
    for row in stored_rows:
        expected = expected_by_event.get(row["usage_event_id"])
        if expected is None:
            return False
        for key, value in expected.items():
            actual = str(row[key]) if key == "preview_id" else row[key]
            if actual != value:
                return False
    return True


class GovernanceStoreMixin:
    """Database methods for immutable model, lifecycle, and price evidence."""

    async def create_governed_model(
        self,
        model: ResolvedModelDraft,
        *,
        operation_id: str,
        actor: str,
        source_reference: str,
        review_note: str,
    ) -> dict[str, Any]:
        """Append one model version and its audit proof in one transaction."""

        document = {
            "api_base": model.target.api_base,
            "cache_control_injection_points": [
                {
                    "location": point.location,
                    "role": point.role,
                }
                for point in model.target.cache_control_injection_points
            ],
            "egress_policy_sha256": model.egress_policy_sha256,
            "gateway_model_name": model.gateway_model_name,
            "litellm_credential_name": model.target.litellm_credential_name,
            "litellm_model": model.target.model,
            "provider_model_id": model.provider_model_id,
            "provider_name": model.provider_name,
            "review_note": review_note,
            "source_reference": source_reference,
            "initial_visible_in_discovery": model.visible_in_discovery,
        }
        digest = _governance_document_sha256(document)
        conn = await self._ensure_conn()
        try:
            async with self._lock:
                async with conn.transaction():
                    async with conn.cursor() as cur:
                        existing = await self._model_operation_replay(
                            cur,
                            operation_id=operation_id,
                            actor=actor,
                            document_sha256=digest,
                        )
                        if existing is not None:
                            return await self._project_governed_model(cur, existing)
                        await cur.execute(
                            """
                            INSERT INTO aigw_governance.governed_model_versions (
                                operation_id,
                                gateway_model_name,
                                provider_name,
                                provider_model_id,
                                initial_visible_in_discovery,
                                egress_policy_sha256,
                                litellm_model,
                                api_base,
                                litellm_credential_name,
                                cache_control_injection_points,
                                source_reference,
                                review_note,
                                actor,
                                document_sha256
                            )
                            VALUES (
                                %s::uuid, %s, %s, %s, %s, %s, %s, %s,
                                %s, %s::jsonb, %s, %s, %s, %s
                            )
                            RETURNING *
                            """,
                            (
                                operation_id,
                                model.gateway_model_name,
                                model.provider_name,
                                model.provider_model_id,
                                model.visible_in_discovery,
                                model.egress_policy_sha256,
                                model.target.model,
                                model.target.api_base,
                                model.target.litellm_credential_name,
                                json.dumps(
                                    document["cache_control_injection_points"],
                                    separators=(",", ":"),
                                ),
                                source_reference,
                                review_note,
                                actor,
                                digest,
                            ),
                        )
                        row = await cur.fetchone()
                        if row is None:
                            raise RuntimeError("model insert returned no row")
                        await self._insert_governance_audit(
                            cur,
                            operation_id=operation_id,
                            actor=actor,
                            action="model_version_created",
                            resource_type="model_version",
                            resource_id=model.gateway_model_name,
                            document_sha256=digest,
                        )
                        return await self._project_governed_model(cur, dict(row))
        except psycopg.errors.UniqueViolation as exc:
            async with self._lock:
                async with conn.cursor() as cur:
                    existing = await self._model_operation_replay(
                        cur,
                        operation_id=operation_id,
                        actor=actor,
                        document_sha256=digest,
                    )
            if existing is not None:
                return await self._project_model_after_conflict(existing)
            raise GovernanceConflict("model version or operation already exists") from exc

    async def list_governed_models(
        self,
        *,
        egress_policy_sha256: str,
        visible_only: bool,
        limit: int,
        offset: int,
    ) -> list[dict[str, Any]]:
        """List projected model states bound to the active immutable policy."""

        conn = await self._ensure_conn()
        async with self._lock:
            async with conn.cursor() as cur:
                await cur.execute(
                    """
                    SELECT *
                    FROM aigw_governance.governed_model_versions
                    WHERE egress_policy_sha256 = %s
                    ORDER BY gateway_model_name
                    LIMIT 10201
                    """,
                    (egress_policy_sha256,),
                )
                raw_rows = [dict(row) for row in await cur.fetchall()]
                if len(raw_rows) > 10_200:
                    raise RuntimeError("governed model catalog exceeds its safe bound")
                rows = await self._project_governed_models(cur, raw_rows)
                if visible_only:
                    rows = [
                        row
                        for row in rows
                        if row["active"] and row["visible_in_discovery"]
                    ]
                return rows[offset : offset + limit]

    async def get_governed_model(
        self,
        gateway_model_name: str,
        *,
        egress_policy_sha256: str,
    ) -> Optional[dict[str, Any]]:
        conn = await self._ensure_conn()
        async with self._lock:
            async with conn.cursor() as cur:
                await cur.execute(
                    """
                    SELECT *
                    FROM aigw_governance.governed_model_versions
                    WHERE gateway_model_name = %s
                      AND egress_policy_sha256 = %s
                    """,
                    (gateway_model_name, egress_policy_sha256),
                )
                row = await cur.fetchone()
                if row is None:
                    return None
                return await self._project_governed_model(cur, dict(row))

    async def append_model_lifecycle_event(
        self,
        gateway_model_name: str,
        *,
        egress_policy_sha256: str,
        action: ModelLifecycleAction,
        operation_id: str,
        actor: str,
    ) -> dict[str, Any]:
        """Append one lifecycle event and its audit row atomically."""

        conn = await self._ensure_conn()
        try:
            async with self._lock:
                async with conn.transaction():
                    async with conn.cursor() as cur:
                        await cur.execute(
                            """
                            SELECT pg_advisory_xact_lock(
                                hashtextextended(%s, 0)
                            )
                            """,
                            (f"aigw-governance-model:{gateway_model_name}",),
                        )
                        await cur.execute(
                            """
                            SELECT *
                            FROM aigw_governance.governed_model_versions
                            WHERE gateway_model_name = %s
                              AND egress_policy_sha256 = %s
                            """,
                            (gateway_model_name, egress_policy_sha256),
                        )
                        raw_model = await cur.fetchone()
                        if raw_model is None:
                            raise GovernanceNotFound(
                                "governed model version does not exist"
                            )
                        model = dict(raw_model)
                        digest = lifecycle_document_sha256(
                            model_operation_id=str(model["operation_id"]),
                            gateway_model_name=gateway_model_name,
                            egress_policy_sha256=egress_policy_sha256,
                            action=action,
                        )
                        replay = await self._model_event_operation_replay(
                            cur,
                            operation_id=operation_id,
                            model_operation_id=str(model["operation_id"]),
                            action=action,
                            actor=actor,
                            document_sha256=digest,
                        )
                        if replay:
                            return await self._project_governed_model(cur, model)

                        current = await self._project_governed_model(cur, model)
                        try:
                            apply_model_action(
                                GovernedModelState(
                                    lifecycle_state=current["lifecycle_state"],
                                    active=current["active"],
                                    visible_in_discovery=current[
                                        "visible_in_discovery"
                                    ],
                                    last_event_sequence=current[
                                        "last_event_sequence"
                                    ],
                                ),
                                action,
                                initial_visibility=(
                                    model["initial_visible_in_discovery"] is True
                                ),
                            )
                        except ModelLifecycleError as exc:
                            raise GovernanceConflict(str(exc)) from exc

                        await cur.execute(
                            """
                            INSERT INTO aigw_governance.governed_model_events (
                                operation_id,
                                model_operation_id,
                                action,
                                actor,
                                document_sha256
                            )
                            VALUES (%s::uuid, %s::uuid, %s, %s, %s)
                            """,
                            (
                                operation_id,
                                str(model["operation_id"]),
                                action.value,
                                actor,
                                digest,
                            ),
                        )
                        await self._insert_governance_audit(
                            cur,
                            operation_id=operation_id,
                            actor=actor,
                            action=f"model_{action.value}",
                            resource_type="model_version",
                            resource_id=gateway_model_name,
                            document_sha256=digest,
                        )
                        return await self._project_governed_model(cur, model)
        except psycopg.errors.UniqueViolation as exc:
            async with self._lock:
                async with conn.cursor() as cur:
                    await cur.execute(
                        """
                        SELECT *
                        FROM aigw_governance.governed_model_versions
                        WHERE gateway_model_name = %s
                          AND egress_policy_sha256 = %s
                        """,
                        (gateway_model_name, egress_policy_sha256),
                    )
                    raw_model = await cur.fetchone()
                    if raw_model is not None:
                        model = dict(raw_model)
                        digest = lifecycle_document_sha256(
                            model_operation_id=str(model["operation_id"]),
                            gateway_model_name=gateway_model_name,
                            egress_policy_sha256=egress_policy_sha256,
                            action=action,
                        )
                        replay = await self._model_event_operation_replay(
                            cur,
                            operation_id=operation_id,
                            model_operation_id=str(model["operation_id"]),
                            action=action,
                            actor=actor,
                            document_sha256=digest,
                        )
                        if replay:
                            return await self._project_governed_model(cur, model)
            raise GovernanceConflict(
                "model lifecycle operation already exists"
            ) from exc

    async def _project_model_after_conflict(
        self, model: dict[str, Any]
    ) -> dict[str, Any]:
        conn = await self._ensure_conn()
        async with self._lock:
            async with conn.cursor() as cur:
                return await self._project_governed_model(cur, model)

    async def _project_governed_model(
        self,
        cur: Any,
        model: dict[str, Any],
    ) -> dict[str, Any]:
        rows = await self._project_governed_models(cur, [model])
        if len(rows) != 1:
            raise RuntimeError("governed model projection returned no row")
        return rows[0]

    async def _project_governed_models(
        self,
        cur: Any,
        models: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        if not models:
            return []
        model_ids = [str(model["operation_id"]) for model in models]
        await cur.execute(
            """
            SELECT event_sequence, operation_id, model_operation_id,
                   action, actor, document_sha256, created_at
            FROM aigw_governance.governed_model_events
            WHERE model_operation_id = ANY(%s::uuid[])
            ORDER BY event_sequence
            """,
            (model_ids,),
        )
        events_by_model: dict[str, list[dict[str, Any]]] = {
            model_id: [] for model_id in model_ids
        }
        for event in await cur.fetchall():
            key = str(event["model_operation_id"])
            if key not in events_by_model:
                raise RuntimeError("model lifecycle event references an unknown model")
            events_by_model[key].append(dict(event))
        return [
            with_projected_state(
                model,
                events_by_model[str(model["operation_id"])],
            )
            for model in models
        ]

    async def _model_event_operation_replay(
        self,
        cur: Any,
        *,
        operation_id: str,
        model_operation_id: str,
        action: ModelLifecycleAction,
        actor: str,
        document_sha256: str,
    ) -> bool:
        """Accept an exact retry only when event and audit proof both exist."""

        await cur.execute(
            """
            SELECT event.model_operation_id,
                   event.action,
                   event.actor,
                   event.document_sha256,
                   audit.operation_id AS audit_operation_id,
                   audit.actor AS audit_actor,
                   audit.action AS audit_action,
                   audit.resource_type,
                   audit.document_sha256 AS audit_document_sha256
            FROM aigw_governance.governed_model_events event
            LEFT JOIN aigw_governance.governance_audit audit
              ON audit.operation_id = event.operation_id
            WHERE event.operation_id = %s::uuid
            """,
            (operation_id,),
        )
        row = await cur.fetchone()
        if row is None:
            return False
        expected_action = f"model_{action.value}"
        if (
            str(row["model_operation_id"]) != model_operation_id
            or row["action"] != action.value
            or row["actor"] != actor
            or row["document_sha256"] != document_sha256
            or row["audit_operation_id"] is None
            or row["audit_actor"] != actor
            or row["audit_action"] != expected_action
            or row["resource_type"] != "model_version"
            or row["audit_document_sha256"] != document_sha256
        ):
            raise GovernanceConflict("governance operation ID was reused")
        return True

    async def create_governed_price(
        self,
        price: PriceVersion,
        *,
        model_operation_id: str,
        gateway_model_name: str,
        egress_policy_sha256: str,
        operation_id: str,
        actor: str,
        source_reference: str,
        review_note: str,
    ) -> dict[str, Any]:
        """Append a current/future price and its audit proof atomically."""

        document = _price_document(
            price,
            model_operation_id=model_operation_id,
            egress_policy_sha256=egress_policy_sha256,
            gateway_model_name=gateway_model_name,
            source_reference=source_reference,
            review_note=review_note,
        )
        digest = _governance_document_sha256(document)
        conn = await self._ensure_conn()
        try:
            async with self._lock:
                async with conn.transaction():
                    async with conn.cursor() as cur:
                        existing = await self._price_operation_replay(
                            cur,
                            operation_id=operation_id,
                            actor=actor,
                            document_sha256=digest,
                        )
                        if existing is not None:
                            existing["_operation_replayed"] = True
                            return existing
                        await self._lock_governed_model(cur, model_operation_id)
                        baseline_price_policy_sha256 = (
                            await self._current_price_policy_sha256(
                                cur, model_operation_id
                            )
                        )
                        row = await self._insert_governed_price(
                            cur,
                            price,
                            model_operation_id=model_operation_id,
                            gateway_model_name=gateway_model_name,
                            egress_policy_sha256=egress_policy_sha256,
                            operation_id=operation_id,
                            actor=actor,
                            source_reference=source_reference,
                            review_note=review_note,
                            document_sha256=digest,
                        )
                        row["baseline_price_policy_sha256"] = (
                            baseline_price_policy_sha256
                        )
                        row["_operation_replayed"] = False
                        await self._insert_governance_audit(
                            cur,
                            operation_id=operation_id,
                            actor=actor,
                            action="price_version_created",
                            resource_type="price_version",
                            resource_id=price.version_id,
                            document_sha256=digest,
                        )
                        return row
        except psycopg.errors.ForeignKeyViolation as exc:
            raise GovernanceNotFound("governed model version does not exist") from exc
        except psycopg.errors.UniqueViolation as exc:
            async with self._lock:
                async with conn.cursor() as cur:
                    existing = await self._price_operation_replay(
                        cur,
                        operation_id=operation_id,
                        actor=actor,
                        document_sha256=digest,
                    )
            if existing is not None:
                existing["_operation_replayed"] = True
                return existing
            raise GovernanceConflict("price version or operation already exists") from exc

    async def create_price_backdate_preview(
        self,
        price: PriceVersion,
        *,
        model_operation_id: str,
        gateway_model_name: str,
        egress_policy_sha256: str,
        preview_id: str,
        actor: str,
        source_reference: str,
        review_note: str,
    ) -> dict[str, Any]:
        """Store the exact affected rows without changing live prices."""

        document = _price_document(
            price,
            model_operation_id=model_operation_id,
            egress_policy_sha256=egress_policy_sha256,
            gateway_model_name=gateway_model_name,
            source_reference=source_reference,
            review_note=review_note,
        )
        candidate_sha256 = _governance_document_sha256(document)
        conn = await self._ensure_conn()
        try:
            async with self._lock:
                async with conn.transaction():
                    async with conn.cursor() as cur:
                        existing, existing_impact, existing_rows = (
                            await _load_stored_preview(cur, preview_id)
                        )
                        if existing is not None:
                            await cur.execute(
                                """
                                SELECT actor, action, resource_type,
                                       resource_id, document_sha256
                                FROM aigw_governance.governance_audit
                                WHERE operation_id = %s::uuid
                                """,
                                (preview_id,),
                            )
                            audit = await cur.fetchone()
                            if (
                                existing_impact is None
                                or audit is None
                                or existing["actor"] != actor
                                or existing["candidate_sha256"]
                                != candidate_sha256
                                or str(existing["model_operation_id"])
                                != model_operation_id
                                or existing["egress_policy_sha256"]
                                != egress_policy_sha256
                                or audit["actor"] != actor
                                or audit["action"]
                                != "price_backdate_previewed"
                                or audit["resource_type"]
                                != "price_backdate_preview"
                                or audit["resource_id"] != preview_id
                                or audit["document_sha256"]
                                != candidate_sha256
                            ):
                                raise GovernanceConflict(
                                    "backdate preview operation ID was reused"
                                )
                            receipt = _preview_receipt(
                                existing,
                                existing_impact,
                                existing_rows,
                            )
                            receipt["_operation_replayed"] = True
                            return receipt

                        model = await self._lock_governed_model(
                            cur, model_operation_id
                        )
                        if (
                            model["gateway_model_name"] != gateway_model_name
                            or model["provider_name"] != price.provider
                            or model["egress_policy_sha256"]
                            != egress_policy_sha256
                        ):
                            raise GovernanceConflict(
                                "backdate candidate does not match its governed model"
                            )
                        baseline_price_policy_sha256 = (
                            await self._current_price_policy_sha256(
                                cur, model_operation_id
                            )
                        )
                        impact = await _compute_backdate_impact(
                            cur,
                            price=price,
                            model_operation_id=model_operation_id,
                            egress_policy_sha256=egress_policy_sha256,
                            preview_id=preview_id,
                            baseline_price_policy_sha256=(
                                baseline_price_policy_sha256
                            ),
                        )
                        await cur.execute(
                            """
                            INSERT INTO aigw_governance.price_backdate_previews (
                                preview_id,
                                model_operation_id,
                                egress_policy_sha256,
                                candidate_version_id,
                                gateway_model_name,
                                provider_name,
                                usage_class,
                                token_unit,
                                amount,
                                currency,
                                explicit_free,
                                effective_at,
                                source_reference,
                                review_note,
                                actor,
                                baseline_price_policy_sha256,
                                candidate_sha256
                            )
                            VALUES (
                                %s::uuid, %s::uuid, %s, %s, %s, %s, %s, %s,
                                %s, %s, %s, %s, %s, %s, %s, %s, %s
                            )
                            RETURNING *
                            """,
                            (
                                preview_id,
                                model_operation_id,
                                egress_policy_sha256,
                                price.version_id,
                                gateway_model_name,
                                price.provider,
                                price.usage_class.value,
                                price.token_unit,
                                price.amount,
                                price.currency,
                                price.explicit_free,
                                price.effective_at,
                                source_reference,
                                review_note,
                                actor,
                                baseline_price_policy_sha256,
                                candidate_sha256,
                            ),
                        )
                        row = await cur.fetchone()
                        if row is None:
                            raise RuntimeError("backdate preview insert returned no row")
                        preview = impact["preview"]
                        await cur.execute(
                            """
                            INSERT INTO aigw_governance.usage_reprice_previews (
                                preview_id,
                                baseline_adjustments_sha256,
                                preview_sha256,
                                effective_to,
                                affected_count,
                                old_total_usd,
                                new_total_usd,
                                delta_usd,
                                old_unknown_count,
                                new_unknown_count
                            )
                            VALUES (
                                %s::uuid, %s, %s, %s, %s, %s, %s, %s,
                                %s, %s
                            )
                            RETURNING baseline_adjustments_sha256,
                                      preview_sha256, effective_to,
                                      affected_count, old_total_usd,
                                      new_total_usd, delta_usd,
                                      old_unknown_count, new_unknown_count
                            """,
                            (
                                preview_id,
                                impact["baseline_adjustments_sha256"],
                                impact["preview_sha256"],
                                preview.effective_to,
                                preview.affected_count,
                                preview.old_total,
                                preview.new_total,
                                preview.delta,
                                preview.old_unknown_count,
                                preview.new_unknown_count,
                            ),
                        )
                        impact_row = await cur.fetchone()
                        if impact_row is None:
                            raise RuntimeError(
                                "backdate impact insert returned no row"
                            )
                        for affected in impact["rows"]:
                            await cur.execute(
                                """
                                INSERT INTO
                                    aigw_governance.usage_reprice_preview_rows (
                                        preview_id,
                                        usage_event_id,
                                        usage_class,
                                        units,
                                        supersedes_adjustment_id,
                                        previous_price_version_id,
                                        new_price_version_id,
                                        previous_component_cost_usd,
                                        new_component_cost_usd,
                                        component_delta_usd,
                                        previous_total_cost_usd,
                                        new_total_cost_usd,
                                        row_sha256
                                    )
                                VALUES (
                                    %s::uuid, %s, %s, %s, %s, %s, %s,
                                    %s, %s, %s, %s, %s, %s
                                )
                                """,
                                (
                                    affected["preview_id"],
                                    affected["usage_event_id"],
                                    affected["usage_class"],
                                    affected["units"],
                                    affected["supersedes_adjustment_id"],
                                    affected["previous_price_version_id"],
                                    affected["new_price_version_id"],
                                    affected["previous_component_cost_usd"],
                                    affected["new_component_cost_usd"],
                                    affected["component_delta_usd"],
                                    affected["previous_total_cost_usd"],
                                    affected["new_total_cost_usd"],
                                    affected["row_sha256"],
                                ),
                            )
                        await self._insert_governance_audit(
                            cur,
                            operation_id=preview_id,
                            actor=actor,
                            action="price_backdate_previewed",
                            resource_type="price_backdate_preview",
                            resource_id=preview_id,
                            document_sha256=candidate_sha256,
                        )
                        receipt = _preview_receipt(
                            dict(row),
                            dict(impact_row),
                            impact["rows"],
                        )
                        receipt["_operation_replayed"] = False
                        return receipt
        except psycopg.errors.ForeignKeyViolation as exc:
            raise GovernanceNotFound("governed model version does not exist") from exc
        except psycopg.errors.UniqueViolation as exc:
            raise GovernanceConflict(
                "backdate preview or operation already exists"
            ) from exc

    async def confirm_price_backdate(
        self,
        *,
        preview_id: str,
        candidate_sha256: str,
        preview_sha256: str,
        confirmation_operation_id: str,
        actor: str,
        expected_egress_policy_sha256: str,
    ) -> dict[str, Any]:
        """Append one price and its exact cost adjustments atomically."""

        conn = await self._ensure_conn()
        try:
            async with self._lock:
                async with conn.transaction():
                    async with conn.cursor() as cur:
                        await cur.execute(
                            """
                            SELECT *
                            FROM aigw_governance.price_backdate_confirmations
                            WHERE confirmation_operation_id = %s::uuid
                            """,
                            (confirmation_operation_id,),
                        )
                        replay = await cur.fetchone()
                        if replay is not None:
                            stored_preview, stored_impact, stored_rows = (
                                await _load_stored_preview(cur, preview_id)
                            )
                            if (
                                stored_preview is None
                                or stored_impact is None
                                or str(replay["preview_id"]) != preview_id
                                or replay["candidate_sha256"]
                                != candidate_sha256
                                or replay["actor"] != actor
                                or stored_preview["egress_policy_sha256"]
                                != expected_egress_policy_sha256
                                or stored_impact["preview_sha256"]
                                != preview_sha256
                            ):
                                raise GovernanceConflict(
                                    "backdate confirmation operation ID was reused"
                                )
                            await cur.execute(
                                """
                                SELECT *
                                FROM aigw_governance.governed_price_versions
                                WHERE version_id = %s
                                """,
                                (replay["version_id"],),
                            )
                            price_row = await cur.fetchone()
                            await cur.execute(
                                """
                                SELECT count(*) AS adjustment_count
                                FROM aigw_governance.usage_cost_adjustments
                                WHERE confirmation_operation_id = %s::uuid
                                """,
                                (confirmation_operation_id,),
                            )
                            count_row = await cur.fetchone()
                            if (
                                price_row is None
                                or count_row is None
                                or count_row["adjustment_count"]
                                != stored_impact["affected_count"]
                                or len(stored_rows)
                                != stored_impact["affected_count"]
                            ):
                                raise RuntimeError(
                                    "stored backdate confirmation is incomplete"
                                )
                            result = dict(price_row)
                            result.update(
                                {
                                    "preview_id": preview_id,
                                    "candidate_sha256": candidate_sha256,
                                    "preview_sha256": preview_sha256,
                                    "confirmation_operation_id": (
                                        confirmation_operation_id
                                    ),
                                    "adjustment_count": count_row[
                                        "adjustment_count"
                                    ],
                                    "affected_count": stored_impact[
                                        "affected_count"
                                    ],
                                    "delta_usd": stored_impact["delta_usd"],
                                    "baseline_price_policy_sha256": (
                                        stored_preview[
                                            "baseline_price_policy_sha256"
                                        ]
                                    ),
                                    "_operation_replayed": True,
                                }
                            )
                            return result

                        stored_preview, stored_impact, stored_rows = (
                            await _load_stored_preview(cur, preview_id)
                        )
                        if stored_preview is None:
                            raise GovernanceNotFound(
                                "backdate preview does not exist"
                            )
                        if stored_impact is None:
                            raise RuntimeError(
                                "backdate preview has no usage impact evidence"
                            )
                        preview = stored_preview
                        if preview["candidate_sha256"] != candidate_sha256:
                            raise GovernanceConflict(
                                "backdate preview digest does not match"
                            )
                        if stored_impact["preview_sha256"] != preview_sha256:
                            raise GovernanceConflict(
                                "backdate usage preview digest does not match"
                            )
                        if (
                            preview["egress_policy_sha256"]
                            != expected_egress_policy_sha256
                        ):
                            raise GovernanceConflict(
                                "backdate preview belongs to another provider policy"
                            )
                        await cur.execute(
                            """
                            SELECT confirmation_operation_id
                            FROM aigw_governance.price_backdate_confirmations
                            WHERE preview_id = %s::uuid
                            """,
                            (preview_id,),
                        )
                        prior_confirmation = await cur.fetchone()
                        if prior_confirmation is not None:
                            raise GovernanceConflict(
                                "backdate preview was already confirmed"
                            )

                        await self._lock_governed_model(
                            cur, str(preview["model_operation_id"])
                        )
                        current_policy_sha256 = (
                            await self._current_price_policy_sha256(
                                cur, str(preview["model_operation_id"])
                            )
                        )
                        if (
                            current_policy_sha256
                            != preview["baseline_price_policy_sha256"]
                        ):
                            raise GovernanceConflict(
                                "price policy changed after the backdate preview"
                            )

                        price = PriceVersion(
                            version_id=preview["candidate_version_id"],
                            provider=preview["provider_name"],
                            model=preview["gateway_model_name"],
                            usage_class=UsageClass(preview["usage_class"]),
                            token_unit=preview["token_unit"],
                            amount=Decimal(preview["amount"]),
                            effective_at=preview["effective_at"],
                            currency=preview["currency"],
                            explicit_free=preview["explicit_free"],
                        )
                        computed = await _compute_backdate_impact(
                            cur,
                            price=price,
                            model_operation_id=str(
                                preview["model_operation_id"]
                            ),
                            egress_policy_sha256=preview[
                                "egress_policy_sha256"
                            ],
                            preview_id=preview_id,
                            baseline_price_policy_sha256=(
                                preview["baseline_price_policy_sha256"]
                            ),
                        )
                        if (
                            computed["preview_sha256"] != preview_sha256
                            or not _stored_impact_matches(
                                stored_impact,
                                stored_rows,
                                computed,
                            )
                        ):
                            raise GovernanceConflict(
                                "usage or cost adjustments changed after the backdate preview"
                            )
                        row = await self._insert_governed_price(
                            cur,
                            price,
                            model_operation_id=str(preview["model_operation_id"]),
                            gateway_model_name=preview["gateway_model_name"],
                            egress_policy_sha256=preview["egress_policy_sha256"],
                            operation_id=confirmation_operation_id,
                            actor=actor,
                            source_reference=preview["source_reference"],
                            review_note=preview["review_note"],
                            document_sha256=candidate_sha256,
                        )
                        await cur.execute(
                            """
                            INSERT INTO aigw_governance.price_backdate_confirmations (
                                confirmation_operation_id,
                                preview_id,
                                version_id,
                                candidate_sha256,
                                actor
                            )
                            VALUES (%s::uuid, %s::uuid, %s, %s, %s)
                            """,
                            (
                                confirmation_operation_id,
                                preview_id,
                                price.version_id,
                                candidate_sha256,
                                actor,
                            ),
                        )
                        adjustments = confirmed_adjustments(
                            computed["preview"],
                            candidate_price=price,
                            preview_id=preview_id,
                            confirmation_operation_id=(
                                confirmation_operation_id
                            ),
                        )
                        if len(adjustments) != stored_impact["affected_count"]:
                            raise RuntimeError(
                                "backdate adjustment count does not match preview"
                            )
                        for adjustment in adjustments:
                            await cur.execute(
                                """
                                INSERT INTO
                                    aigw_governance.usage_cost_adjustments (
                                        adjustment_id,
                                        preview_id,
                                        confirmation_operation_id,
                                        usage_event_id,
                                        usage_class,
                                        units,
                                        supersedes_adjustment_id,
                                        previous_price_version_id,
                                        new_price_version_id,
                                        previous_cost_usd,
                                        new_cost_usd,
                                        delta_usd,
                                        new_price_sha256,
                                        actor
                                    )
                                VALUES (
                                    %s, %s::uuid, %s::uuid, %s, %s, %s,
                                    %s, %s, %s, %s, %s, %s, %s, %s
                                )
                                """,
                                (
                                    adjustment.adjustment_id,
                                    adjustment.preview_id,
                                    adjustment.confirmation_operation_id,
                                    adjustment.usage_id,
                                    adjustment.usage_class.value,
                                    adjustment.units,
                                    adjustment.supersedes_adjustment_id,
                                    adjustment.previous_price_version_id,
                                    adjustment.new_price_version_id,
                                    adjustment.previous_cost,
                                    adjustment.new_cost,
                                    adjustment.delta,
                                    adjustment.new_price_digest,
                                    actor,
                                ),
                            )
                        await self._insert_governance_audit(
                            cur,
                            operation_id=confirmation_operation_id,
                            actor=actor,
                            action="price_backdate_confirmed",
                            resource_type="price_version",
                            resource_id=price.version_id,
                            document_sha256=candidate_sha256,
                        )
                        row.update(
                            {
                                "preview_id": preview_id,
                                "candidate_sha256": candidate_sha256,
                                "preview_sha256": preview_sha256,
                                "confirmation_operation_id": (
                                    confirmation_operation_id
                                ),
                                "adjustment_count": len(adjustments),
                                "affected_count": stored_impact[
                                    "affected_count"
                                ],
                                "delta_usd": stored_impact["delta_usd"],
                                "baseline_price_policy_sha256": preview[
                                    "baseline_price_policy_sha256"
                                ],
                                "_operation_replayed": False,
                            }
                        )
                        return row
        except (GovernanceConflict, GovernanceNotFound):
            raise
        except psycopg.errors.ForeignKeyViolation as exc:
            raise GovernanceNotFound("backdate preview dependency is missing") from exc
        except psycopg.errors.UniqueViolation as exc:
            raise GovernanceConflict(
                "backdate, price version, or operation already exists"
            ) from exc

    async def list_governed_prices(
        self,
        *,
        model_operation_id: str,
        limit: int,
        offset: int,
    ) -> list[dict[str, Any]]:
        conn = await self._ensure_conn()
        async with self._lock:
            async with conn.cursor() as cur:
                await cur.execute(
                    """
                    SELECT *
                    FROM aigw_governance.governed_price_versions
                    WHERE model_operation_id = %s::uuid
                    ORDER BY effective_at, usage_class, version_id
                    LIMIT %s OFFSET %s
                    """,
                    (model_operation_id, limit, offset),
                )
                return [dict(row) for row in await cur.fetchall()]

    async def governance_audit(self, limit: int = 100) -> list[dict[str, Any]]:
        conn = await self._ensure_conn()
        async with self._lock:
            async with conn.cursor() as cur:
                await cur.execute(
                    """
                    SELECT *
                    FROM aigw_governance.governance_audit
                    ORDER BY id DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
                return [dict(row) for row in await cur.fetchall()]

    async def _insert_governed_price(
        self,
        cur: Any,
        price: PriceVersion,
        *,
        model_operation_id: str,
        gateway_model_name: str,
        egress_policy_sha256: str,
        operation_id: str,
        actor: str,
        source_reference: str,
        review_note: str,
        document_sha256: str,
    ) -> dict[str, Any]:
        model = await self._lock_governed_model(cur, model_operation_id)
        if (
            model["gateway_model_name"] != gateway_model_name
            or model["provider_name"] != price.provider
            or model["egress_policy_sha256"] != egress_policy_sha256
        ):
            raise GovernanceConflict(
                "price identity does not match its governed model version"
            )
        await cur.execute(
            """
            INSERT INTO aigw_governance.governed_price_versions (
                version_id,
                operation_id,
                model_operation_id,
                egress_policy_sha256,
                gateway_model_name,
                provider_name,
                usage_class,
                token_unit,
                amount,
                currency,
                explicit_free,
                effective_at,
                source_reference,
                review_note,
                actor,
                document_sha256
            )
            VALUES (
                %s, %s::uuid, %s::uuid, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s
            )
            RETURNING *
            """,
            (
                price.version_id,
                operation_id,
                model_operation_id,
                egress_policy_sha256,
                gateway_model_name,
                price.provider,
                price.usage_class.value,
                price.token_unit,
                price.amount,
                price.currency,
                price.explicit_free,
                price.effective_at,
                source_reference,
                review_note,
                actor,
                document_sha256,
            ),
        )
        row = await cur.fetchone()
        if row is None:
            raise RuntimeError("price insert returned no row")
        return dict(row)

    async def _model_operation_replay(
        self,
        cur: Any,
        *,
        operation_id: str,
        actor: str,
        document_sha256: str,
    ) -> dict[str, Any] | None:
        """Return an exact prior model write, or reject operation-ID reuse."""

        await cur.execute(
            """
            SELECT *
            FROM aigw_governance.governed_model_versions
            WHERE operation_id = %s::uuid
            """,
            (operation_id,),
        )
        row = await cur.fetchone()
        if row is None:
            return None
        if row["actor"] != actor or row["document_sha256"] != document_sha256:
            raise GovernanceConflict("governance operation ID was reused")
        return dict(row)

    async def _price_operation_replay(
        self,
        cur: Any,
        *,
        operation_id: str,
        actor: str,
        document_sha256: str,
    ) -> dict[str, Any] | None:
        """Return an exact prior price write, or reject operation-ID reuse."""

        await cur.execute(
            """
            SELECT *
            FROM aigw_governance.governed_price_versions
            WHERE operation_id = %s::uuid
            """,
            (operation_id,),
        )
        row = await cur.fetchone()
        if row is None:
            return None
        if row["actor"] != actor or row["document_sha256"] != document_sha256:
            raise GovernanceConflict("governance operation ID was reused")
        return dict(row)

    async def _lock_governed_model(
        self, cur: Any, model_operation_id: str
    ) -> dict[str, Any]:
        # A transaction-scoped advisory lock avoids granting the application
        # UPDATE solely for SELECT ... FOR UPDATE once governance tables move
        # under their non-login migration owner.
        await cur.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
            (f"aigw-governance-model:{model_operation_id}",),
        )
        await cur.execute(
            """
            SELECT operation_id, gateway_model_name, provider_name,
                   egress_policy_sha256
            FROM aigw_governance.governed_model_versions
            WHERE operation_id = %s::uuid
            """,
            (model_operation_id,),
        )
        row = await cur.fetchone()
        if row is None:
            raise GovernanceNotFound("governed model version does not exist")
        return dict(row)

    async def _current_price_policy_sha256(
        self,
        cur: Any,
        model_operation_id: str,
    ) -> str:
        await cur.execute(
            """
            SELECT *
            FROM aigw_governance.governed_price_versions
            WHERE model_operation_id = %s::uuid
            ORDER BY effective_at, usage_class, version_id
            """,
            (model_operation_id,),
        )
        rows = await cur.fetchall()
        prices = tuple(
            PriceVersion(
                version_id=row["version_id"],
                provider=row["provider_name"],
                model=row["gateway_model_name"],
                usage_class=UsageClass(row["usage_class"]),
                token_unit=row["token_unit"],
                amount=Decimal(row["amount"]),
                effective_at=row["effective_at"],
                currency=row["currency"],
                explicit_free=row["explicit_free"],
            )
            for row in rows
        )
        return canonical_price_digest(prices)

    async def _insert_governance_audit(
        self,
        cur: Any,
        *,
        operation_id: str,
        actor: str,
        action: str,
        resource_type: str,
        resource_id: str,
        document_sha256: str,
    ) -> None:
        await cur.execute(
            """
            INSERT INTO aigw_governance.governance_audit (
                operation_id,
                actor,
                action,
                resource_type,
                resource_id,
                document_sha256
            )
            VALUES (%s::uuid, %s, %s, %s, %s, %s)
            """,
            (
                operation_id,
                actor,
                action,
                resource_type,
                resource_id,
                document_sha256,
            ),
        )
