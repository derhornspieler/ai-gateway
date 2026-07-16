#!/usr/bin/env python3
"""Reconcile the fixed Open WebUI workload key without logging plaintext."""

from __future__ import annotations

import hashlib
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request


BASE = "http://litellm:4000"
ALIAS = "aigw-open-webui-service"
USER_ID = "svc-open-webui"
# Unrestricted model scope (owner decision 2026-07-16): the shared chat key may
# reach every model in the LiteLLM catalog — the admin portal governs access,
# not a hardcoded per-key allowlist, and new models must appear in chat without
# re-scoping. "all-proxy-models" is LiteLLM's all-models wildcard (see
# compose/litellm/aigw_default_model_hook.py ALL_PROXY_MODELS). The ROUTES scope
# below still restricts the key to listing models and chat only.
MODELS = ["all-proxy-models"]
ROUTES = ["/v1/models", "/v1/chat/completions"]
METADATA = {
    "aigw_key_kind": "service",
    "aigw_service": "open-webui",
    "aigw_project_id": "open-webui",
}
KEY_RE = re.compile(r"^sk-[A-Za-z0-9_-]{16,256}$")


def fail(message: str) -> None:
    raise SystemExit(message)


def request(path: str, master: str, *, method: str = "GET", payload=None):
    body = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(
        BASE + path,
        data=body,
        method=method,
        headers={
            "Authorization": "Bearer " + master,
            "Accept": "application/json",
            **({"Content-Type": "application/json"} if body is not None else {}),
        },
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=20) as response:
            raw = response.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                fail("LiteLLM management response exceeded 1 MiB")
            return response.status, json.loads(raw)
    except urllib.error.HTTPError as exc:
        fail(f"LiteLLM management request failed: HTTP {exc.code}")
    except (OSError, ValueError, json.JSONDecodeError):
        fail("LiteLLM management request failed or returned invalid JSON")


def records(data) -> list[dict]:
    if isinstance(data, list):
        values = data
    elif isinstance(data, dict):
        values = data.get("keys", data.get("data", []))
    else:
        fail("key/list returned an invalid response shape")
    if not isinstance(values, list) or any(not isinstance(item, dict) for item in values):
        fail("key/list returned invalid key objects")
    return values


def lookup(master: str, field: str, value: str) -> list[dict]:
    query = urllib.parse.urlencode(
        {field: value, "return_full_object": "true", "page": 1, "size": 100}
    )
    _, data = request("/key/list?" + query, master)
    return records(data)


def normalized_json(value):
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def exact_record(record: dict, token_hash: str) -> None:
    if record.get("token") != token_hash:
        fail("Open WebUI key token hash drifted")
    if record.get("key_alias") != ALIAS or record.get("user_id") != USER_ID:
        fail("Open WebUI key identity drifted")
    if record.get("models") != MODELS or record.get("allowed_routes") != ROUTES:
        fail("Open WebUI key scope drifted after reconciliation")
    if normalized_json(record.get("metadata")) != METADATA:
        fail("Open WebUI key metadata drifted after reconciliation")
    if normalized_json(record.get("permissions")) != {}:
        fail("Open WebUI key permissions drifted after reconciliation")
    if record.get("blocked") is not False:
        fail("Open WebUI key is blocked after reconciliation")


def main() -> int:
    raw = sys.stdin.buffer.read(8193)
    if not raw or len(raw) > 8192:
        fail("bounded reconciliation input required")
    try:
        secrets = json.loads(raw)
    except json.JSONDecodeError:
        fail("invalid reconciliation input")
    master = secrets.get("master_key") if isinstance(secrets, dict) else None
    candidate = secrets.get("candidate_key") if isinstance(secrets, dict) else None
    if not isinstance(master, str) or len(master) < 24:
        fail("master credential unavailable")
    if not isinstance(candidate, str) or KEY_RE.fullmatch(candidate) is None:
        fail("Open WebUI workload key has an invalid shape")
    if candidate == master:
        fail("Open WebUI workload key must not equal the master key")
    token_hash = hashlib.sha256(candidate.encode()).hexdigest()

    by_alias = [item for item in lookup(master, "key_alias", ALIAS) if item.get("key_alias") == ALIAS]
    by_hash = [item for item in lookup(master, "key_hash", token_hash) if item.get("token") == token_hash]
    if len(by_alias) > 1 or len(by_hash) > 1:
        fail("Open WebUI workload key lookup was not unique")
    if bool(by_alias) != bool(by_hash):
        fail("Open WebUI workload key alias/hash collision detected")
    if by_alias and by_alias[0].get("token") != by_hash[0].get("token"):
        fail("Open WebUI workload key lookups resolved different tokens")

    payload = {
        "key_alias": ALIAS,
        "user_id": USER_ID,
        "models": MODELS,
        "allowed_routes": ROUTES,
        "metadata": METADATA,
        "permissions": {},
        "blocked": False,
    }
    created = not by_alias
    if created:
        _, generated = request(
            "/key/generate", master, method="POST", payload={**payload, "key": candidate}
        )
        returned = generated.get("key") if isinstance(generated, dict) else None
        if not isinstance(returned, str) or hashlib.sha256(returned.encode()).hexdigest() != token_hash:
            fail("key/generate did not return the exact requested workload key")
    else:
        request(
            "/key/update",
            master,
            method="POST",
            payload={**payload, "key": token_hash},
        )

    final_alias = [item for item in lookup(master, "key_alias", ALIAS) if item.get("key_alias") == ALIAS]
    final_hash = [item for item in lookup(master, "key_hash", token_hash) if item.get("token") == token_hash]
    if len(final_alias) != 1 or len(final_hash) != 1:
        fail("Open WebUI workload key was not uniquely reconciled")
    if final_alias[0].get("token") != final_hash[0].get("token"):
        fail("Open WebUI final lookups resolved different tokens")
    exact_record(final_alias[0], token_hash)

    # The workload key may use inference routes only, never proxy management.
    req = urllib.request.Request(
        BASE + "/key/list",
        headers={"Authorization": "Bearer " + candidate},
    )
    try:
        urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=10)
    except urllib.error.HTTPError as exc:
        if exc.code != 403:
            fail("Open WebUI workload key management denial returned an unexpected status")
    else:
        fail("Open WebUI workload key reached a management endpoint")

    print(f"OPENWEBUI_SERVICE_KEY_RECONCILED created={str(created).lower()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
