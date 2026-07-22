#!/usr/bin/env python3
"""Exercise the governed model lifecycle in an already verified seed PreProd."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import subprocess


ROOT = Path(__file__).resolve().parents[1]
COMPOSE_DIR = ROOT / "compose"
ENV_FILE = COMPOSE_DIR / "secrets/preprod.env"
SEED_OVERLAY = COMPOSE_DIR / "secrets/preprod-seed-images.yml"
POSTGRES16_OVERLAY = COMPOSE_DIR / "docker-compose.preprod-postgres16.yml"
PROJECT = "aigw-preprod"
MAX_OUTPUT_BYTES = 1024 * 1024


LIFECYCLE_HELPER = r"""
import http.client
import json
import os
import secrets
import sys
import uuid

suffix = json.load(sys.stdin)["suffix"]
model = "claude-preprod-" + suffix
provider_model = model
project = "preprod-lifecycle-" + suffix
actor = "preprod-model-lifecycle"
rotator_token = os.environ.get("ROTATOR_INTERNAL_TOKEN", "")
master_key = os.environ.get("LITELLM_MASTER_KEY", "")
if len(rotator_token) < 16 or not master_key.startswith("sk-"):
    raise SystemExit("required internal credentials are unavailable")


def request(
    host,
    port,
    method,
    path,
    *,
    token,
    body=None,
    actor_headers=False,
    operation_id=None,
):
    headers = {"Authorization": "Bearer " + token}
    if host == "key-rotator":
        headers = {"X-Internal-Auth": token}
        if actor_headers:
            headers["X-AIGW-Operation-ID"] = operation_id or str(uuid.uuid4())
            headers["X-AIGW-Actor-ID"] = actor
    encoded = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        encoded = json.dumps(body, separators=(",", ":"))
    connection = http.client.HTTPConnection(host, port, timeout=30)
    connection.request(method, path, body=encoded, headers=headers)
    response = connection.getresponse()
    raw = response.read(1048577)
    status = response.status
    connection.close()
    if len(raw) > 1048576:
        raise SystemExit("an internal response exceeded 1 MiB")
    try:
        document = json.loads(raw) if raw else None
    except json.JSONDecodeError:
        raise SystemExit("an internal service returned invalid JSON")
    return status, document


def control(method, path, body=None, *, write=False, operation_id=None):
    return request(
        "key-rotator",
        8080,
        method,
        path,
        token=rotator_token,
        body=body,
        actor_headers=write,
        operation_id=operation_id,
    )


def litellm(path, body, token=master_key):
    return request(
        "litellm", 4000, "POST", path, token=token, body=body
    )


def discovery(token):
    status, document = request(
        "dev-portal", 8080, "GET", "/v1/models", token=token
    )
    if status != 200 or not isinstance(document, dict):
        raise SystemExit("filtered discovery was unavailable")
    rows = document.get("data")
    if not isinstance(rows, list):
        raise SystemExit("filtered discovery returned an invalid list")
    return {row.get("id") for row in rows if isinstance(row, dict)}


key = "sk-" + secrets.token_hex(24)
key_created = False
model_created = False
model_active = False
group_id = None
try:
    status, draft = control(
        "POST",
        "/model-governance/models",
        {
            "gateway_model_name": model,
            "provider_name": "anthropic",
            "provider_model_id": provider_model,
            "visible_in_discovery": False,
            "source_reference": "preprod-model-lifecycle",
            "review_note": "Local seed lifecycle acceptance model.",
        },
        write=True,
    )
    if status != 201 or not isinstance(draft, dict):
        raise SystemExit("the controller did not create a model draft")
    if draft.get("lifecycle_state") != "draft" or draft.get("active") is not False:
        raise SystemExit("a new model was not inert")
    model_created = True
    status, visible = control("GET", "/model-governance/discovery")
    if status != 200 or model in {
        row.get("id") for row in visible.get("models", [])
        if isinstance(row, dict)
    }:
        raise SystemExit("a draft model entered discovery")
    print("PREPROD_MODEL_DRAFT_HIDDEN_PASSED")

    status, active = control(
        "POST",
        "/model-governance/models/" + model + "/activate",
        {},
        write=True,
    )
    if status != 200 or active.get("lifecycle_state") != "active":
        raise SystemExit("the model did not activate")
    model_active = True

    status, created_key = litellm(
        "/key/generate",
        {
            "key": key,
            "key_alias": "preprod-model-lifecycle-" + suffix,
            "user_id": "preprod-model-lifecycle-" + suffix,
            "models": [model],
            "allowed_routes": ["/v1/messages"],
            "metadata": {
                "created_via": "dev-portal",
                "aigw_project_id": "preprod-model-lifecycle-" + suffix,
            },
            "permissions": {},
            "blocked": False,
        },
    )
    if status != 200 or created_key.get("key") != key:
        raise SystemExit("the test key was not created")
    key_created = True

    if model in discovery(key):
        raise SystemExit("a hidden active model entered discovery")
    status, answer = litellm(
        "/v1/messages",
        {
            "model": model,
            "max_tokens": 8,
            "messages": [{"role": "user", "content": "Reply with pong."}],
        },
        token=key,
    )
    content = answer.get("content") if isinstance(answer, dict) else None
    if status != 200 or not isinstance(content, list) or not any(
        isinstance(item, dict) and item.get("text") == "pong" for item in content
    ):
        raise SystemExit("the hidden exact-name model call failed")
    print("PREPROD_MODEL_HIDDEN_CALL_PASSED")

    status, shown = control(
        "POST",
        "/model-governance/models/" + model + "/show",
        {},
        write=True,
    )
    if status != 200 or shown.get("visible_in_discovery") is not True:
        raise SystemExit("the model did not become visible")
    if model not in discovery(key):
        raise SystemExit("a shown model was absent from discovery")

    status, hidden = control(
        "POST",
        "/model-governance/models/" + model + "/hide",
        {},
        write=True,
    )
    if status != 200 or hidden.get("visible_in_discovery") is not False:
        raise SystemExit("the model did not become hidden")
    if model in discovery(key):
        raise SystemExit("a hidden model remained in discovery")
    print("PREPROD_MODEL_DISCOVERY_PASSED")

    status, _ = litellm("/key/delete", {"keys": [key]})
    if status != 200:
        raise SystemExit("the test key was not deleted")
    key_created = False

    status, group = control(
        "POST",
        "/identity/groups",
        {"name": project, "capabilities": ["chat"]},
        write=True,
    )
    if status != 201 or not isinstance(group, dict):
        raise SystemExit("the temporary project was not created")
    group_id = group.get("id")
    if not isinstance(group_id, str) or not group_id:
        raise SystemExit("the temporary project ID was invalid")

    policy_operation_id = str(uuid.uuid4())
    status, policy = control(
        "PUT",
        "/identity/groups/" + group_id + "/policy",
        {
            "tpm_limit": None,
            "rpm_limit": None,
            "allowed_models": [model],
            "default_model": model,
            "model_limits": {},
        },
        write=True,
        operation_id=policy_operation_id,
    )
    revision = policy.get("policy_revision") if isinstance(policy, dict) else None
    if (
        status != 200
        or not isinstance(revision, str)
        or len(revision) != 64
        or policy.get("reconciliation_pending") is not True
    ):
        raise SystemExit("the temporary project policy was not staged")
    intended_policy = policy.get("policy")

    status, activated = control(
        "POST",
        "/identity/groups/" + group_id + "/policy/activate",
        {"policy_revision": revision},
        write=True,
        operation_id=policy_operation_id,
    )
    if (
        status != 200
        or not isinstance(activated, dict)
        or activated.get("reconciliation_pending") is not True
        or activated.get("policy_revision") != revision
        or activated.get("active_policy") != intended_policy
    ):
        raise SystemExit("the temporary project policy was not activated")

    status, completed = control(
        "POST",
        "/identity/groups/" + group_id + "/policy/complete",
        {"policy_revision": revision},
        write=True,
        operation_id=policy_operation_id,
    )
    if (
        status != 200
        or not isinstance(completed, dict)
        or completed.get("reconciliation_pending") is not False
        or completed.get("policy_revision") != revision
        or completed.get("active_policy") != intended_policy
    ):
        raise SystemExit("the temporary project policy was not completed")

    status, denied_retirement = control(
        "POST",
        "/model-governance/models/" + model + "/retire",
        {},
        write=True,
    )
    denied_detail = (
        denied_retirement.get("detail")
        if isinstance(denied_retirement, dict)
        else None
    )
    if status != 409 or denied_detail != (
        "model is still assigned to one or more projects"
    ):
        raise SystemExit("an assigned model was allowed to retire")
    print("PREPROD_MODEL_ASSIGNMENT_GATE_PASSED")

    status, _ = control(
        "DELETE",
        "/identity/groups/" + group_id,
        write=True,
    )
    if status != 204:
        raise SystemExit("the temporary project was not deleted")
    group_id = None

    status, retired = control(
        "POST",
        "/model-governance/models/" + model + "/retire",
        {},
        write=True,
    )
    if status != 200 or retired.get("lifecycle_state") != "retired":
        raise SystemExit("the model did not retire")
    model_active = False
    if model in discovery(master_key):
        raise SystemExit("a retired model remained in discovery")
    print("PREPROD_MODEL_RETIREMENT_PASSED")
finally:
    if key_created:
        litellm("/key/delete", {"keys": [key]})
    if group_id is not None:
        control("DELETE", "/identity/groups/" + group_id, write=True)
    if model_created:
        if model_active:
            control(
                "POST",
                "/model-governance/models/" + model + "/hide",
                {},
                write=True,
            )
        control(
            "POST",
            "/model-governance/models/" + model + "/retire",
            {},
            write=True,
        )

print("PREPROD_MODEL_LIFECYCLE_PASSED")
""".strip()


def fail(message: str) -> None:
    raise SystemExit(f"ERROR: {message}")


def clean_environment() -> dict[str, str]:
    allowed = (
        "DOCKER_CONFIG",
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LOGNAME",
        "PATH",
        "TMPDIR",
        "USER",
        "XDG_CONFIG_HOME",
    )
    return {name: os.environ[name] for name in allowed if name in os.environ}


def read_environment() -> dict[str, str]:
    if not ENV_FILE.is_file():
        fail("the generated preprod environment is missing")
    values: dict[str, str] = {}
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        name, separator, value = line.partition("=")
        if not separator:
            continue
        if name in values:
            fail(f"the generated preprod environment repeats {name}")
        values[name] = value
    return values


def compose_prefix(postgres_major: str) -> list[str]:
    if shutil.which("docker") is None:
        fail("docker is required for the model lifecycle test")
    values = read_environment()
    endpoint = values.get("PREPROD_DOCKER_ENDPOINT", "")
    if not endpoint.startswith("unix:///"):
        fail("the prepared local Docker endpoint is missing")
    socket_path = Path(endpoint.removeprefix("unix://"))
    try:
        metadata = socket_path.lstat()
    except FileNotFoundError:
        fail("the prepared local Docker socket is missing")
    if (
        not socket_path.is_absolute()
        or ".." in socket_path.parts
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
    ):
        fail("the prepared local Docker socket is unsafe")
    if not SEED_OVERLAY.is_file():
        fail("the activated seed image overlay is missing")

    command = [
        "docker",
        "--host",
        endpoint,
        "compose",
        "--project-name",
        PROJECT,
        "--env-file",
        str(ENV_FILE),
        "-f",
        str(COMPOSE_DIR / "docker-compose.yml"),
        "-f",
        str(COMPOSE_DIR / "docker-compose.preprod.yml"),
        "-f",
        str(SEED_OVERLAY),
    ]
    if postgres_major == "16":
        command.extend(["-f", str(POSTGRES16_OVERLAY)])
    command.extend(["--profile", "preprod"])
    return command


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-mode", choices=("seed",), default="seed")
    parser.add_argument("--postgres-major", choices=("16", "18"), default="18")
    args = parser.parse_args()

    command = [
        *compose_prefix(args.postgres_major),
        "exec",
        "-T",
        "admin-portal",
        "/opt/venv/bin/python",
        "-c",
        LIFECYCLE_HELPER,
    ]
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=clean_environment(),
        input=json.dumps({"suffix": secrets.token_hex(6)}),
        text=True,
        capture_output=True,
        check=False,
    )
    if (
        len(result.stdout.encode()) > MAX_OUTPUT_BYTES
        or len(result.stderr.encode()) > MAX_OUTPUT_BYTES
    ):
        fail("the model lifecycle test output exceeded its bound")
    if result.returncode != 0:
        fail("the model lifecycle acceptance helper failed")
    required = (
        "PREPROD_MODEL_DRAFT_HIDDEN_PASSED",
        "PREPROD_MODEL_HIDDEN_CALL_PASSED",
        "PREPROD_MODEL_DISCOVERY_PASSED",
        "PREPROD_MODEL_ASSIGNMENT_GATE_PASSED",
        "PREPROD_MODEL_RETIREMENT_PASSED",
        "PREPROD_MODEL_LIFECYCLE_PASSED",
    )
    for marker in required:
        if result.stdout.count(marker) != 1:
            fail(f"the model lifecycle test omitted {marker}")
        print(marker)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
