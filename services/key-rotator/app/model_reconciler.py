"""Retrying reconciliation for governed LiteLLM DB models."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from app.model_projection import (
    ModelProjectionError,
    RuntimeDeployment,
    deployment_matches,
    desired_deployment,
    parse_runtime_deployments,
)


logger = logging.getLogger("key_rotator.model_reconciler")


class ModelReconciler:
    """Keep LiteLLM's DB rows equal to the append-only governance state."""

    def __init__(
        self,
        db: Any,
        litellm: Any,
        *,
        egress_policy_sha256: str,
        retry_seconds: float = 15.0,
    ) -> None:
        self._db = db
        self._litellm = litellm
        self._policy_sha256 = egress_policy_sha256
        self._retry_seconds = retry_seconds
        self._lock = asyncio.Lock()
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._ready = False

    @property
    def ready(self) -> bool:
        return self._ready

    async def reconcile(self) -> None:
        """Repair absence, then prove the exact projection or fail closed."""

        async with self._lock:
            self._ready = False
            try:
                models = await self._db.list_governed_models(
                    egress_policy_sha256=self._policy_sha256,
                    visible_only=False,
                    limit=10_200,
                    offset=0,
                )
                if len(models) > 10_200:
                    raise ModelProjectionError(
                        "governed model catalog exceeds its safe bound"
                    )
                governed = {str(model["operation_id"]): model for model in models}
                if len(governed) != len(models):
                    raise ModelProjectionError("governed model IDs are duplicated")
                desired = {
                    deployment_id: desired_deployment(model)
                    for deployment_id, model in governed.items()
                }
                active_ids = {
                    deployment_id
                    for deployment_id, model in governed.items()
                    if model.get("active") is True
                }

                runtime = parse_runtime_deployments(
                    await self._litellm.list_model_deployments()
                )
                self._reject_static_name_collisions(runtime, governed)
                runtime_db = {
                    deployment.deployment_id: deployment
                    for deployment in runtime
                    if deployment.db_model
                }
                self._validate_existing(runtime_db, governed, desired, active_ids)

                for deployment_id in sorted(set(runtime_db) - active_ids):
                    await self._litellm.delete_model_deployment(deployment_id)
                for deployment_id in sorted(active_ids - set(runtime_db)):
                    await self._litellm.create_model_deployment(
                        desired[deployment_id]
                    )

                verified = parse_runtime_deployments(
                    await self._litellm.list_model_deployments()
                )
                verified_db = {
                    deployment.deployment_id: deployment
                    for deployment in verified
                    if deployment.db_model
                }
                self._validate_exact(verified_db, governed, desired, active_ids)
            except Exception:
                self._ready = False
                raise
            self._ready = True

    @staticmethod
    def _reject_static_name_collisions(
        runtime: tuple[RuntimeDeployment, ...],
        governed: dict[str, dict[str, Any]],
    ) -> None:
        """Refuse a name that LiteLLM also loads from static config."""

        governed_names = {
            str(model.get("gateway_model_name") or "")
            for model in governed.values()
        }
        static_names = {
            deployment.model_name
            for deployment in runtime
            if not deployment.db_model
        }
        if governed_names & static_names:
            raise ModelProjectionError(
                "a governed model name collides with static LiteLLM config"
            )

    @staticmethod
    def _validate_existing(
        runtime: dict[str, RuntimeDeployment],
        governed: dict[str, dict[str, Any]],
        desired: dict[str, dict[str, Any]],
        active_ids: set[str],
    ) -> None:
        unmanaged = set(runtime) - set(governed)
        if unmanaged:
            raise ModelProjectionError(
                "LiteLLM contains an unmanaged DB model deployment"
            )
        for deployment_id, actual in runtime.items():
            if not deployment_matches(actual, desired[deployment_id]):
                raise ModelProjectionError(
                    "LiteLLM governed model projection has drifted"
                )
            if deployment_id in active_ids and governed[deployment_id].get(
                "lifecycle_state"
            ) != "active":
                raise ModelProjectionError("governed model state is inconsistent")

    @staticmethod
    def _validate_exact(
        runtime: dict[str, RuntimeDeployment],
        governed: dict[str, dict[str, Any]],
        desired: dict[str, dict[str, Any]],
        active_ids: set[str],
    ) -> None:
        if set(runtime) != active_ids:
            raise ModelProjectionError(
                "LiteLLM governed model inventory does not match desired state"
            )
        ModelReconciler._validate_existing(
            runtime, governed, desired, active_ids
        )

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._stop.clear()
            self._task = asyncio.create_task(self._retry_loop())

    async def _retry_loop(self) -> None:
        while not self._stop.is_set():
            try:
                await self.reconcile()
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "governed model reconciliation failed (%s)",
                    type(exc).__name__,
                )
            try:
                await asyncio.wait_for(
                    self._stop.wait(), timeout=self._retry_seconds
                )
            except TimeoutError:
                continue

    async def shutdown(self) -> None:
        self._stop.set()
        task = self._task
        if task is not None:
            await task
        self._task = None
