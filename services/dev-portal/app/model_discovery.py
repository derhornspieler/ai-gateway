"""Fail-closed public model discovery for the internal API edge."""

from __future__ import annotations

import asyncio
import re
from collections import defaultdict
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from .config import settings


router = APIRouter()

MAX_RESPONSE_BYTES = 1024 * 1024
MAX_PUBLIC_MODELS = 256
MAX_INVENTORY_MODELS = 10_200
INVENTORY_PAGE_SIZE = 500
INVENTORY_MAX_PAGES = 21
MODEL_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_./:-]{0,127}")
DEPLOYMENT_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
BEARER_RE = re.compile(r"Bearer ([A-Za-z0-9_.~+/-]{16,512})")
RESERVED_MODELS = frozenset(
    {"aigw-auto", "aigw-default", "aigw-no-models", "all-proxy-models"}
)


class DiscoveryError(RuntimeError):
    def __init__(self, message: str, *, status_code: int = 503) -> None:
        super().__init__(message)
        self.status_code = status_code


def _bounded_json(response: httpx.Response, label: str) -> Any:
    if len(response.content) > MAX_RESPONSE_BYTES:
        raise DiscoveryError(f"{label} response exceeded its size bound")
    try:
        return response.json()
    except ValueError as exc:
        raise DiscoveryError(f"{label} returned invalid JSON") from exc


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=10.0,
        trust_env=False,
        follow_redirects=False,
    )


async def _user_model_rows(bearer: str) -> list[dict[str, Any]]:
    url = settings.litellm_url.rstrip("/") + "/v1/models"
    try:
        async with _client() as client:
            response = await client.get(
                url, headers={"Authorization": f"Bearer {bearer}"}
            )
    except httpx.HTTPError as exc:
        raise DiscoveryError("LiteLLM model discovery is unavailable") from exc
    if response.status_code in {401, 403}:
        raise DiscoveryError("gateway credential was rejected", status_code=401)
    if response.status_code != 200:
        raise DiscoveryError("LiteLLM model discovery is unavailable")
    document = _bounded_json(response, "LiteLLM model discovery")
    rows = document.get("data") if isinstance(document, dict) else None
    if not isinstance(rows, list) or len(rows) > MAX_PUBLIC_MODELS:
        raise DiscoveryError("LiteLLM model discovery shape is invalid")

    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise DiscoveryError("LiteLLM model discovery row is invalid")
        model_id = row.get("id")
        object_type = row.get("object")
        created = row.get("created")
        owned_by = row.get("owned_by")
        if (
            not isinstance(model_id, str)
            or MODEL_NAME_RE.fullmatch(model_id) is None
            or model_id in RESERVED_MODELS
            or model_id in seen
            or object_type != "model"
            or type(created) is not int
            or created < 0
            or not isinstance(owned_by, str)
            or not 1 <= len(owned_by) <= 128
        ):
            raise DiscoveryError("LiteLLM model discovery row is invalid")
        seen.add(model_id)
        result.append(
            {
                "id": model_id,
                "object": "model",
                "created": created,
                "owned_by": owned_by,
            }
        )
    return result


async def _deployment_inventory() -> list[dict[str, Any]]:
    if not settings.litellm_master_key:
        raise DiscoveryError("model inventory credential is unavailable")
    base = settings.litellm_url.rstrip("/")
    rows: list[dict[str, Any]] = []
    expected_total: int | None = None
    expected_pages: int | None = None
    try:
        async with _client() as client:
            for page in range(1, INVENTORY_MAX_PAGES + 1):
                response = await client.get(
                    f"{base}/v2/model/info",
                    params={"page": page, "size": INVENTORY_PAGE_SIZE},
                    headers={
                        "Authorization": f"Bearer {settings.litellm_master_key}"
                    },
                )
                if response.status_code != 200:
                    raise DiscoveryError("LiteLLM model inventory is unavailable")
                document = _bounded_json(response, "LiteLLM model inventory")
                data = document.get("data") if isinstance(document, dict) else None
                total = document.get("total_count") if isinstance(document, dict) else None
                total_pages = (
                    document.get("total_pages") if isinstance(document, dict) else None
                )
                current_page = (
                    document.get("current_page") if isinstance(document, dict) else None
                )
                size = document.get("size") if isinstance(document, dict) else None
                if (
                    not isinstance(data, list)
                    or type(total) is not int
                    or type(total_pages) is not int
                    or current_page != page
                    or size != INVENTORY_PAGE_SIZE
                    or not 0 <= total <= MAX_INVENTORY_MODELS
                    or not 0 <= total_pages <= INVENTORY_MAX_PAGES
                ):
                    raise DiscoveryError("LiteLLM model inventory shape is invalid")
                if expected_total is None:
                    expected_total = total
                    expected_pages = total_pages
                    calculated = (
                        (total + INVENTORY_PAGE_SIZE - 1) // INVENTORY_PAGE_SIZE
                    )
                    if calculated != total_pages:
                        raise DiscoveryError(
                            "LiteLLM model inventory counters disagree"
                        )
                elif total != expected_total or total_pages != expected_pages:
                    raise DiscoveryError(
                        "LiteLLM model inventory changed during the scan"
                    )
                if len(data) > INVENTORY_PAGE_SIZE or any(
                    not isinstance(row, dict) for row in data
                ):
                    raise DiscoveryError("LiteLLM model inventory row is invalid")
                rows.extend(data)
                if total_pages == 0 or page == total_pages:
                    break
                if len(data) != INVENTORY_PAGE_SIZE:
                    raise DiscoveryError(
                        "LiteLLM model inventory ended before its final page"
                    )
            else:
                raise DiscoveryError("LiteLLM model inventory is too large")
    except httpx.HTTPError as exc:
        raise DiscoveryError("LiteLLM model inventory is unavailable") from exc
    if expected_total is None or len(rows) != expected_total:
        raise DiscoveryError("LiteLLM model inventory counters disagree")
    return rows


async def _governed_discovery() -> dict[str, str]:
    token = settings.rotator_internal_token
    if not token:
        raise DiscoveryError("governed model discovery token is unavailable")
    url = settings.rotator_url.rstrip("/") + "/model-governance/discovery"
    try:
        async with _client() as client:
            response = await client.get(
                url, headers={"X-Internal-Auth": token}
            )
    except httpx.HTTPError as exc:
        raise DiscoveryError("governed model discovery is unavailable") from exc
    if response.status_code != 200:
        raise DiscoveryError("governed model discovery is unavailable")
    document = _bounded_json(response, "governed model discovery")
    rows = document.get("models") if isinstance(document, dict) else None
    if not isinstance(rows, list) or len(rows) > MAX_PUBLIC_MODELS:
        raise DiscoveryError("governed model discovery shape is invalid")
    result: dict[str, str] = {}
    seen_deployments: set[str] = set()
    for row in rows:
        model_name = row.get("id") if isinstance(row, dict) else None
        deployment_id = row.get("deployment_id") if isinstance(row, dict) else None
        provider = row.get("provider") if isinstance(row, dict) else None
        if (
            not isinstance(model_name, str)
            or MODEL_NAME_RE.fullmatch(model_name) is None
            or not isinstance(deployment_id, str)
            or DEPLOYMENT_ID_RE.fullmatch(deployment_id) is None
            or not isinstance(provider, str)
            or not 1 <= len(provider) <= 63
            or model_name in result
            or deployment_id in seen_deployments
        ):
            raise DiscoveryError("governed model discovery row is invalid")
        result[model_name] = deployment_id
        seen_deployments.add(deployment_id)
    return result


def _inventory_by_name(rows: list[dict[str, Any]]) -> dict[str, list[tuple[str, bool]]]:
    result: dict[str, list[tuple[str, bool]]] = defaultdict(list)
    seen: set[str] = set()
    for row in rows:
        model_name = row.get("model_name")
        model_info = row.get("model_info")
        if (
            not isinstance(model_name, str)
            or MODEL_NAME_RE.fullmatch(model_name) is None
            or not isinstance(model_info, dict)
        ):
            raise DiscoveryError("LiteLLM model inventory row is invalid")
        deployment_id = model_info.get("id")
        db_model = model_info.get("db_model")
        if (
            not isinstance(deployment_id, str)
            or DEPLOYMENT_ID_RE.fullmatch(deployment_id) is None
            or type(db_model) is not bool
            or deployment_id in seen
        ):
            raise DiscoveryError("LiteLLM model inventory identity is invalid")
        seen.add(deployment_id)
        result[model_name].append((deployment_id, db_model))
    return result


async def filtered_model_document(bearer: str) -> dict[str, Any]:
    public_rows, inventory_rows, governed = await _gather_discovery_inputs(bearer)
    inventory = _inventory_by_name(inventory_rows)
    filtered: list[dict[str, Any]] = []
    for row in public_rows:
        model_name = row["id"]
        deployments = inventory.get(model_name)
        if not deployments:
            raise DiscoveryError("public model is absent from deployment inventory")
        config_ids = [model_id for model_id, db_model in deployments if not db_model]
        db_ids = [model_id for model_id, db_model in deployments if db_model]
        if config_ids and db_ids:
            raise DiscoveryError("public model has an ambiguous deployment source")
        if config_ids:
            filtered.append(row)
            continue
        expected_id = governed.get(model_name)
        if expected_id is not None and db_ids == [expected_id]:
            filtered.append(row)
        # Hidden, inactive, retired, and unmanaged DB rows are omitted.
    return {"object": "list", "data": filtered}


async def _gather_discovery_inputs(
    bearer: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, str]]:
    # Run independent internal reads together so the public list stays quick.
    public_rows, inventory_rows, governed = await asyncio.gather(
        _user_model_rows(bearer),
        _deployment_inventory(),
        _governed_discovery(),
    )
    return public_rows, inventory_rows, governed


def _bearer(request: Request) -> str:
    values = request.headers.getlist("authorization")
    if len(values) != 1:
        raise HTTPException(status_code=401, detail="one bearer credential is required")
    match = BEARER_RE.fullmatch(values[0])
    if match is None:
        raise HTTPException(status_code=401, detail="one bearer credential is required")
    if request.url.query:
        raise HTTPException(status_code=400, detail="model discovery has no query options")
    return match.group(1)


async def _document_for_request(request: Request) -> dict[str, Any]:
    try:
        return await filtered_model_document(_bearer(request))
    except DiscoveryError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail="model discovery is unavailable"
            if exc.status_code == 503
            else "gateway credential was rejected",
        ) from exc


@router.get("/v1/models")
@router.get("/models")
async def list_models(request: Request) -> JSONResponse:
    document = await _document_for_request(request)
    return JSONResponse(document, headers={"Cache-Control": "no-store"})


@router.get("/v1/models/{model_id:path}")
@router.get("/models/{model_id:path}")
async def get_model(model_id: str, request: Request) -> JSONResponse:
    if MODEL_NAME_RE.fullmatch(model_id) is None:
        raise HTTPException(status_code=404, detail="model not found")
    document = await _document_for_request(request)
    for row in document["data"]:
        if row["id"] == model_id:
            return JSONResponse(row, headers={"Cache-Control": "no-store"})
    raise HTTPException(status_code=404, detail="model not found")
