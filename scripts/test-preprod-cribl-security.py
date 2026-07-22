#!/usr/bin/env python3
"""Prove the local preprod SOC allow-list, redaction, queue, and recovery."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
COMPOSE_DIR = ROOT / "compose"
ENV_FILE = COMPOSE_DIR / "secrets/preprod.env"
SEED_OVERLAY = COMPOSE_DIR / "secrets/preprod-seed-images.yml"
PROJECT = "aigw-preprod"
OWNER_LABEL = "com.aigw.preprod.project"
CONFIG_LABEL = "com.aigw.preprod.config-digest"
FIXTURE_VOLUME = "preprod_empty_docker_logs"
MAX_COMMAND_OUTPUT = 16 * 1024 * 1024
MAX_TEST_CERT_BYTES = 64 * 1024
CRIBL_CERT = COMPOSE_DIR / "secrets/preprod-cribl.crt"
CRIBL_KEY = COMPOSE_DIR / "secrets/preprod-cribl.key"
WRONG_SAN_CERT = COMPOSE_DIR / "secrets/preprod-wif.crt"
WRONG_SAN_KEY = COMPOSE_DIR / "secrets/preprod-wif.key"
ANTHROPIC_CA_FINGERPRINTS = (
    "1dfc1605fbad358d8bc844f76d15203fac9ca5c1a79fd4857ffaf2864fbebf96,"
    "349dfa4058c5e263123b398ae795573c4e1313c83fe68f93556cd5e8031b3c7d"
)


OTLP_FIXTURE_HELPER = r"""
import http.client
import json
import os
import sys
import time

test = json.load(sys.stdin)
token = test["token"]
now = str(time.time_ns())

descriptor = os.open(
    "/run/secrets/litellm_otel_token",
    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
)
try:
    otlp_token = os.read(descriptor, 65).decode("ascii")
finally:
    os.close(descriptor)
if len(otlp_token) != 64 or any(character not in "0123456789abcdef" for character in otlp_token):
    raise SystemExit("LiteLLM OTLP token is malformed")

def text(key, value):
    return {"key": key, "value": {"stringValue": value}}

def integer(key, value):
    return {"key": key, "value": {"intValue": str(value)}}

def string_array(key, value):
    return {
        "key": key,
        "value": {"arrayValue": {"values": [{"stringValue": value}]}},
    }

def nested_string(key, value):
    return {
        "key": key,
        "value": {
            "kvlistValue": {
                "values": [{"key": "content", "value": {"stringValue": value}}]
            }
        },
    }

def post(path, document, authenticated=False):
    body = json.dumps(document, separators=(",", ":"))
    port = 4319 if authenticated else 4318
    headers = {"Content-Type": "application/json"}
    if authenticated:
        headers["Authorization"] = "Bearer " + otlp_token
    connection = http.client.HTTPConnection("alloy", port, timeout=10)
    connection.request("POST", path, body=body, headers=headers)
    response = connection.getresponse()
    response.read(1048577)
    connection.close()
    if response.status != 200:
        raise SystemExit("OTLP receiver rejected a preprod fixture")

trace_id = token * 2
allowed_span = {
    "traceId": trace_id,
    "spanId": token,
    "name": "litellm_request",
    "kind": 2,
    "startTimeUnixNano": now,
    "endTimeUnixNano": str(int(now) + 1000),
    "attributes": [
        text("metadata.user_api_key_user_id", "receipt-user-" + token),
        text("metadata.user_api_key_hash", "a" * 64),
        text("metadata.user_api_key_project_id", "receipt-project"),
        text("metadata.user_api_key_end_user_id", "receipt-user-" + token),
        text("litellm.call_id", "receipt-call-" + token),
        text("gen_ai.request.model", "receipt-model"),
        text("gen_ai.response.model", "receipt-model"),
        integer("gen_ai.usage.input_tokens", 2),
        integer("gen_ai.usage.output_tokens", 1),
        integer("gen_ai.usage.total_tokens", 3),
        text(
            "gen_ai.input.messages",
            "allowed-ai-input-"
            + token
            + " password=PROMPT_PASSWORD_"
            + token
            + " sk-ant-"
            + token
            + token,
        ),
        text(
            "gen_ai.output.messages",
            "allowed-ai-output-" + token + " Bearer PROMPT_BEARER_" + token,
        ),
        text("authorization", "Bearer TRACE_SECRET_" + token),
    ],
}
denied_span = {
    "traceId": trace_id,
    "spanId": token[::-1],
    "parentSpanId": allowed_span["spanId"],
    "name": "raw_gen_ai_request",
    "kind": 2,
    "startTimeUnixNano": now,
    "endTimeUnixNano": str(int(now) + 1000),
    "attributes": [text("receipt.denied", "DENIED_RAW_TRACE_" + token)],
}
unattributed_span = {
    "traceId": trace_id,
    "spanId": token[1:] + token[:1],
    "name": "litellm_request",
    "kind": 2,
    "startTimeUnixNano": now,
    "endTimeUnixNano": str(int(now) + 1000),
    "attributes": [
        text("gen_ai.input.messages", "DENIED_UNATTRIBUTED_TRACE_" + token)
    ],
}
nested_prompt_span = {
    "traceId": trace_id,
    "spanId": token[3:] + token[:3],
    "name": "litellm_request",
    "kind": 2,
    "startTimeUnixNano": now,
    "endTimeUnixNano": str(int(now) + 1000),
    "attributes": [
        text("metadata.user_api_key_user_id", "nested-user-" + token),
        text("metadata.user_api_key_hash", "c" * 64),
        text("metadata.user_api_key_project_id", "receipt-project"),
        text("metadata.user_api_key_end_user_id", "nested-user-" + token),
        text("litellm.call_id", "nested-call-" + token),
        text("gen_ai.request.model", "receipt-model"),
        string_array(
            "gen_ai.input.messages", "NESTED_PROMPT_ARRAY_SECRET_" + token
        ),
        nested_string(
            "gen_ai.output.messages", "NESTED_PROMPT_MAP_SECRET_" + token
        ),
    ],
}
post(
    "/v1/traces",
    {
        "resourceSpans": [{
            "resource": {"attributes": [text("service.name", "litellm")]},
            "scopeSpans": [{
                "scope": {"name": "aigw.preprod.receipt"},
                "spans": [
                    allowed_span,
                    denied_span,
                    unattributed_span,
                    nested_prompt_span,
                ],
            }],
        }]
    },
    authenticated=True,
)
post(
    "/v1/metrics",
    {
        "resourceMetrics": [{
            "resource": {"attributes": [text("service.name", "receipt-test")]},
            "scopeMetrics": [{
                "scope": {"name": "aigw.preprod.receipt"},
                "metrics": [{
                    "name": "denied_raw_metric_" + token,
                    "gauge": {"dataPoints": [{"timeUnixNano": now, "asInt": "1"}]},
                }],
            }],
        }]
    },
)
post(
    "/v1/logs",
    {
        "resourceLogs": [{
            "resource": {"attributes": [text("service.name", "receipt-test")]},
            "scopeLogs": [{
                "scope": {"name": "aigw.preprod.receipt"},
                "logRecords": [{
                    "timeUnixNano": now,
                    "severityNumber": 9,
                    "body": {"stringValue": "DENIED_RAW_LOG_" + token},
                }],
            }],
        }]
    },
)
print("OTLP_FIXTURES_ACCEPTED")
""".strip()


OTLP_OUTAGE_HELPER = r"""
import http.client
import json
import os
import sys
import time

test = json.load(sys.stdin)
token = test["token"]

descriptor = os.open(
    "/run/secrets/litellm_otel_token",
    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
)
try:
    otlp_token = os.read(descriptor, 65).decode("ascii")
finally:
    os.close(descriptor)
if len(otlp_token) != 64 or any(character not in "0123456789abcdef" for character in otlp_token):
    raise SystemExit("LiteLLM OTLP token is malformed")

def text(key, value):
    return {"key": key, "value": {"stringValue": value}}

for sequence in range(6):
    now = str(time.time_ns())
    suffix = token + "-" + str(sequence)
    document = {
        "resourceSpans": [{
            "resource": {"attributes": [text("service.name", "litellm")]},
            "scopeSpans": [{
                "scope": {"name": "aigw.preprod.outage"},
                "spans": [{
                    "traceId": token * 2,
                    "spanId": token,
                    "name": "litellm_request",
                    "kind": 2,
                    "startTimeUnixNano": now,
                    "endTimeUnixNano": str(int(now) + 1000),
                    "attributes": [
                        text("metadata.user_api_key_user_id", "outage-user"),
                        text("metadata.user_api_key_hash", "b" * 64),
                        text("metadata.user_api_key_project_id", "receipt-project"),
                        text("metadata.user_api_key_end_user_id", "outage-user"),
                        text("litellm.call_id", "outage-call-" + suffix),
                        text("gen_ai.request.model", "receipt-model"),
                        text("gen_ai.input.messages", "queued-ai-input-" + suffix),
                        text("gen_ai.output.messages", "queued-ai-output-" + suffix),
                    ],
                }],
            }],
        }]
    }
    connection = http.client.HTTPConnection("alloy", 4319, timeout=10)
    body = json.dumps(document, separators=(",", ":"))
    connection.request(
        "POST", "/v1/traces", body=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + otlp_token,
        },
    )
    response = connection.getresponse()
    response.read(1048577)
    connection.close()
    if response.status != 200:
        raise SystemExit("OTLP receiver rejected an outage fixture")
    time.sleep(1.2)
print("OTLP_OUTAGE_FIXTURES_ACCEPTED")
""".strip()


OTLP_SPOOF_HELPER = r"""
import http.client
import json
import sys
import time

test = json.load(sys.stdin)
token = test["token"]
now = str(time.time_ns())

def text(key, value):
    return {"key": key, "value": {"stringValue": value}}

document = {
    "resourceSpans": [{
        "resource": {"attributes": [text("service.name", "litellm")]},
        "scopeSpans": [{
            "scope": {"name": "aigw.preprod.untrusted"},
            "spans": [{
                "traceId": token * 2,
                "spanId": token,
                "name": "litellm_request",
                "kind": 2,
                "startTimeUnixNano": now,
                "endTimeUnixNano": str(int(now) + 1000),
                "attributes": [
                    text("aigw.security.source_authenticated", "FORGED_AUTH_MARKER_" + token),
                    text("metadata.user_api_key_user_id", "spoof-user-" + token),
                    text("metadata.user_api_key_hash", "d" * 64),
                    text("metadata.user_api_key_project_id", "receipt-project"),
                    text("metadata.user_api_key_end_user_id", "spoof-user-" + token),
                    text("litellm.call_id", "untrusted-call-" + token),
                    text("gen_ai.request.model", "receipt-model"),
                    text("gen_ai.input.messages", "DENIED_UNTRUSTED_SOURCE_" + token),
                ],
            }],
        }],
    }]
}
body = json.dumps(document, separators=(",", ":"))

def post(port, authorization=None):
    headers = {"Content-Type": "application/json"}
    if authorization is not None:
        headers["Authorization"] = authorization
    connection = http.client.HTTPConnection("alloy", port, timeout=10)
    connection.request("POST", "/v1/traces", body=body, headers=headers)
    response = connection.getresponse()
    response.read(1048577)
    connection.close()
    return response.status

if post(4318) != 200:
    raise SystemExit("open OTLP receiver rejected the untrusted fixture")
for authorization in (None, "Bearer " + "0" * 64):
    if post(4319, authorization) not in {401, 403}:
        raise SystemExit("authenticated OTLP receiver accepted a bad credential")
print("OTLP_SPOOF_REJECTED")
""".strip()


LITELLM_REAL_REQUEST_HELPER = r"""
import http.client
import json
import sys

test = json.load(sys.stdin)
marker = test["marker"]
master_key = test["master_key"]
virtual_key = test["virtual_key"]
username = "receipt-user-" + marker

def request(path, bearer, document, *, user=None):
    headers = {
        "Authorization": "Bearer " + bearer,
        "Content-Type": "application/json",
    }
    if user is not None:
        headers["X-OpenWebUI-User-Email"] = user
    body = json.dumps(document, separators=(",", ":"))
    connection = http.client.HTTPConnection("litellm", 4000, timeout=30)
    connection.request("POST", path, body=body, headers=headers)
    response = connection.getresponse()
    raw = response.read(1048577)
    connection.close()
    if len(raw) > 1048576:
        raise SystemExit("LiteLLM returned an oversized response")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        raise SystemExit("LiteLLM returned invalid JSON")
    return response.status, parsed

created = False
problem = None
try:
    status, generated = request(
        "/key/generate",
        master_key,
        {
            "key": virtual_key,
            "key_alias": "receipt-" + marker,
            "user_id": "default_user_id",
            "models": ["claude-sonnet-4-5"],
            "allowed_routes": ["/v1/chat/completions"],
            "metadata": {
                "aigw_project_id": "receipt-project",
                "aigw_username": username,
            },
            "permissions": {},
            "blocked": False,
        },
    )
    if status != 200 or generated.get("key") != virtual_key:
        raise RuntimeError("LiteLLM did not create the exact receipt key")
    created = True
    status, inference = request(
        "/v1/chat/completions",
        virtual_key,
        {
            "model": "claude-sonnet-4-5",
            "max_tokens": 8,
            "messages": [{"role": "user", "content": "real-ai-input-" + marker}],
        },
        user=username,
    )
    choices = inference.get("choices")
    reply = ""
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        message = choices[0].get("message")
        if isinstance(message, dict):
            reply = message.get("content", "")
    if status != 200 or reply.strip() != "pong":
        raise RuntimeError("the real LiteLLM request did not return pong")
except Exception as error:
    problem = str(error)
finally:
    if created:
        delete_status, _ = request(
            "/key/delete", master_key, {"keys": [virtual_key]}
        )
        if delete_status != 200 and problem is None:
            problem = "LiteLLM did not delete the receipt key"

if problem is not None:
    raise SystemExit(problem)
print("LITELLM_REAL_REQUEST_ACCEPTED")
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


def run(
    command: list[str],
    *,
    input_text: str | None = None,
    sensitive: bool = False,
    include_stderr: bool = False,
) -> str:
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=clean_environment(),
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )
    if len(result.stdout.encode()) > MAX_COMMAND_OUTPUT or len(result.stderr.encode()) > MAX_COMMAND_OUTPUT:
        fail("a preprod receipt command exceeded its output limit")
    if result.returncode != 0:
        if sensitive:
            fail("a sensitive preprod receipt command failed")
        if result.stdout:
            print(result.stdout, end="", file=sys.stderr)
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        fail(f"preprod receipt command failed: {command[0]}")
    return result.stdout + (result.stderr if include_stderr else "")


def env_values() -> dict[str, str]:
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


def docker_endpoint(values: dict[str, str]) -> str:
    endpoint = values.get("PREPROD_DOCKER_ENDPOINT", "")
    if not endpoint.startswith("unix:///"):
        fail("preprod receipt testing requires the prepared local Unix socket")
    path = Path(endpoint.removeprefix("unix://"))
    if not path.is_absolute() or ".." in path.parts:
        fail("the prepared Docker endpoint is not canonical")
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        fail("the prepared Docker socket is missing")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISSOCK(metadata.st_mode):
        fail("the prepared Docker endpoint is not a real socket")
    if metadata.st_uid not in {0, os.geteuid()}:
        fail("the prepared Docker socket has an unexpected owner")
    return endpoint


class Preprod:
    def __init__(self, image_mode: str) -> None:
        if shutil.which("docker") is None:
            fail("docker is required for the preprod Cribl receipt test")
        self.image_mode = image_mode
        self.values = env_values()
        self.endpoint = docker_endpoint(self.values)
        self.docker_prefix = ["docker", "--host", self.endpoint]
        self.compose_prefix = [
            *self.docker_prefix,
            "compose",
            "--project-name",
            PROJECT,
            "--env-file",
            str(ENV_FILE),
            "-f",
            str(COMPOSE_DIR / "docker-compose.yml"),
            "-f",
            str(COMPOSE_DIR / "docker-compose.preprod.yml"),
        ]
        if image_mode == "seed":
            if not SEED_OVERLAY.is_file():
                fail("seed receipt testing requires the activated seed overlay")
            self.compose_prefix.extend(["-f", str(SEED_OVERLAY)])
        self.compose_prefix.extend(["--profile", "preprod"])
        self.config_digest = self.values.get("AIGW_PREPROD_CONFIG_DIGEST", "")
        if re.fullmatch(r"[0-9a-f]{64}", self.config_digest) is None:
            fail("the preprod configuration digest is missing or invalid")

    def docker(
        self,
        *arguments: str,
        input_text: str | None = None,
        sensitive: bool = False,
        include_stderr: bool = False,
    ) -> str:
        return run(
            [*self.docker_prefix, *arguments],
            input_text=input_text,
            sensitive=sensitive,
            include_stderr=include_stderr,
        )

    def compose(self, *arguments: str, input_text: str | None = None, sensitive: bool = False) -> str:
        return run(
            [*self.compose_prefix, *arguments],
            input_text=input_text,
            sensitive=sensitive,
        )

    def model(self) -> dict[str, Any]:
        try:
            model = json.loads(self.compose("config", "--format", "json"))
        except json.JSONDecodeError:
            fail("Docker Compose returned an invalid preprod model")
        if not isinstance(model, dict):
            fail("Docker Compose returned an incomplete preprod model")
        return model

    def container_id(self, service: str) -> str:
        identifiers = self.compose("ps", "-q", service).splitlines()
        if len(identifiers) != 1 or not re.fullmatch(r"[0-9a-f]{64}", identifiers[0]):
            fail(f"preprod service {service} does not have one container")
        identifier = identifiers[0]
        try:
            document = json.loads(self.docker("inspect", identifier))[0]
        except (json.JSONDecodeError, IndexError, TypeError):
            fail(f"Docker returned invalid state for {service}")
        labels = document.get("Config", {}).get("Labels") or {}
        if labels.get("com.docker.compose.project") != PROJECT or labels.get(OWNER_LABEL) != PROJECT:
            fail(f"preprod service {service} escaped the owned project")
        return identifier

    def wait_healthy(self, service: str, timeout: int = 90) -> None:
        identifier = self.container_id(service)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                state = json.loads(self.docker("inspect", identifier))[0]["State"]
            except (json.JSONDecodeError, IndexError, KeyError, TypeError):
                fail(f"Docker returned invalid health state for {service}")
            health = state.get("Health", {}).get("Status")
            if state.get("Status") == "running" and health == "healthy":
                return
            if state.get("Status") in {"dead", "exited", "removing"} or health == "unhealthy":
                fail(f"preprod service {service} failed during the receipt test")
            time.sleep(1)
        fail(f"preprod service {service} did not become healthy")


def docker_log_line(service: str, message: str, timestamp: str) -> str:
    return json.dumps(
        {
            "log": message + "\n",
            "stream": "stdout",
            "attrs": {
                "com.docker.compose.project": PROJECT,
                "com.docker.compose.service": service,
            },
            "time": timestamp,
        },
        separators=(",", ":"),
    )


def fixture_lines(token: str) -> str:
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    keycloak = json.dumps(
        {
            "log.logger": "org.keycloak.events",
            "message": (
                "type=LOGIN, realmId=aigw, clientId=portal, "
                f"userId=receipt-{token}, access_token=KEYCLOAK_SECRET_{token}"
            ),
        },
        separators=(",", ":"),
    )
    keycloak_missing_user = json.dumps(
        {
            "log.logger": "org.keycloak.events",
            "message": (
                "type=LOGIN, realmId=aigw, clientId=portal, "
                f"note=DENIED_KEYCLOAK_MISSING_USER_{token}"
            ),
        },
        separators=(",", ":"),
    )
    portal = (
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.portal.audit",'
        '"action":"rotation.trigger","outcome":"success",'
        f'"subject":"receipt-{token}","vendor":"anthropic",'
        f'"unreviewed":"UNAPPROVED_FIELD_{token}",'
        f'"nested":{{"private_key":"NESTED_SECRET_{token}"}},'
        f'"note":"Bearer PORTAL_SECRET_{token}"}}'
    )
    identity = (
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.identity.audit",'
        '"action":"deployment_converge","outcome":"success","changed":true,'
        f'"project":"receipt-{token}"}}'
    )
    identity_failure = (
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.identity.audit",'
        '"action":"deployment_converge","outcome":"failed",'
        f'"error_type":"ReceiptFailure","project":"failed-{token}"}}'
    )
    break_glass = (
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.identity.audit",'
        '"action":"break_glass_use","outcome":"success",'
        '"purpose":"deployment_converge"}'
    )
    rotation = (
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.provider.rotation",'
        '"action":"rotate","outcome":"success","vendor":"anthropic",'
        '"rotation_status":"success"}'
    )
    vault_state = (
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.vault.state",'
        '"action":"state_observed","outcome":"success","state":"unsealed"}'
    )
    egress = (
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.egress.trust",'
        '"action":"startup_gate","outcome":"success",'
        f'"policy_sha256":"{token * 4}","providers":"anthropic",'
        '"sni":"api.anthropic.com","exact_sans":"api.anthropic.com",'
        f'"ca_sha256_fingerprints":"{ANTHROPIC_CA_FINGERPRINTS}"}}'
    )
    egress_tls = json.dumps(
        {
            "upstream": "anthropic",
            "flags": "UF",
            "upstream_transport_failure_reason": (
                "TLS_error: CERTIFICATE_VERIFY_FAILED receipt-" + token
            ),
        },
        separators=(",", ":"),
    )
    denied = (
        ("keycloak", keycloak_missing_user),
        ("dev-portal", f"DENIED_ORDINARY_LOG_{token}"),
        (
            "dev-portal",
            'AIGW_SECURITY_EVENT {"schema_version":9,"event":"aigw.portal.audit",'
            f'"action":"rotation.trigger","outcome":"success","marker":"DENIED_SCHEMA_{token}"}}',
        ),
        (
            "dev-portal",
            'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.portal.audit",'
            f'"action":"not.approved","outcome":"success","marker":"DENIED_ACTION_{token}"}}',
        ),
        (
            "key-rotator",
            'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.provider.rotation",'
            '"action":"rotate","outcome":"success","vendor":"openai",'
            f'"rotation_status":"success","marker":"DENIED_VENDOR_{token}"}}',
        ),
        (
            "key-rotator",
            'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.vault.state",'
            '"action":"state_observed","outcome":"failure","state":"tampered",'
            f'"marker":"DENIED_VAULT_STATE_{token}"}}',
        ),
        ("dev-portal", f"AIGW_SECURITY_EVENT not-json DENIED_MALFORMED_{token}"),
        (
            "envoy-egress",
            json.dumps(
                {
                    "upstream": "openai",
                    "flags": "UF",
                    "upstream_transport_failure_reason": "TLS_error: DENIED_PROVIDER",
                },
                separators=(",", ":"),
            ),
        ),
    )
    records = [
        docker_log_line("keycloak", keycloak, timestamp),
        docker_log_line("dev-portal", portal, timestamp),
        docker_log_line("key-rotator", identity, timestamp),
        docker_log_line("key-rotator", identity_failure, timestamp),
        docker_log_line("key-rotator", break_glass, timestamp),
        docker_log_line("key-rotator", rotation, timestamp),
        docker_log_line("key-rotator", vault_state, timestamp),
        docker_log_line("envoy-egress", egress, timestamp),
        docker_log_line("envoy-egress", egress_tls, timestamp),
    ]
    records.extend(docker_log_line(service, message, timestamp) for service, message in denied)
    return "\n".join(records) + "\n"


def write_log_fixtures(preprod: Preprod, model: dict[str, Any], token: str) -> None:
    volumes = model.get("volumes")
    services = model.get("services")
    if not isinstance(volumes, dict) or not isinstance(services, dict):
        fail("the preprod model has no service or volume inventory")
    volume = volumes.get(FIXTURE_VOLUME)
    volume_init = services.get("volume-init")
    if not isinstance(volume, dict) or not isinstance(volume_init, dict):
        fail("the preprod security fixture boundary is missing")
    volume_name = volume.get("name")
    image = volume_init.get("image")
    if volume_name != f"{PROJECT}_{FIXTURE_VOLUME}" or not isinstance(image, str):
        fail("the preprod security fixture boundary is invalid")
    try:
        inspected = json.loads(preprod.docker("volume", "inspect", volume_name))[0]
    except (json.JSONDecodeError, IndexError, TypeError):
        fail("Docker returned invalid security fixture volume state")
    labels = inspected.get("Labels") or {}
    if labels.get(OWNER_LABEL) != PROJECT or labels.get("com.docker.compose.project") != PROJECT:
        fail("the security fixture volume is not owned by preprod")
    writer_name = f"{PROJECT}-security-fixture-writer"
    existing = preprod.docker(
        "container", "ls", "-a", "--filter", f"name=^{writer_name}$", "--format", "{{.ID}}"
    ).strip()
    if existing:
        fail("a stale preprod security fixture writer exists")
    script = (
        "umask 022; "
        "rm -rf /fixtures/aigw-security-fixtures; "
        "mkdir -p /fixtures/aigw-security-fixtures; "
        f"cat > /fixtures/aigw-security-fixtures/receipt-{token}-json.log; "
        f"chmod 0644 /fixtures/aigw-security-fixtures/receipt-{token}-json.log; sync"
    )
    preprod.docker(
        "run",
        "--rm",
        "-i",
        "--pull=never",
        "--name",
        writer_name,
        "--network",
        "none",
        "--read-only",
        "--user",
        "0:0",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--label",
        f"com.docker.compose.project={PROJECT}",
        "--label",
        f"{OWNER_LABEL}={PROJECT}",
        "--label",
        f"{CONFIG_LABEL}={preprod.config_digest}",
        "--mount",
        f"type=volume,src={volume_name},dst=/fixtures",
        image,
        "/bin/sh",
        "-ceu",
        script,
        input_text=fixture_lines(token),
        sensitive=True,
    )


def send_otlp_fixtures(
    preprod: Preprod,
    helper: str,
    token: str,
    marker: str,
    *,
    service: str = "litellm",
) -> None:
    output = preprod.compose(
        "exec",
        "-T",
        service,
        "python3",
        "-c",
        helper,
        input_text=json.dumps({"token": token}, separators=(",", ":")),
        sensitive=True,
    )
    if output.strip() != marker:
        fail("the OTLP fixture helper returned an invalid receipt")


def send_real_litellm_request(preprod: Preprod, token: str) -> None:
    values = env_values()
    master_key = values.get("LITELLM_MASTER_KEY")
    if not master_key:
        fail("the generated preprod environment has no LiteLLM master key")
    output = preprod.compose(
        "exec",
        "-T",
        "key-rotator",
        "/opt/venv/bin/python",
        "-c",
        LITELLM_REAL_REQUEST_HELPER,
        input_text=json.dumps(
            {
                "marker": token,
                "master_key": master_key,
                "virtual_key": "sk-" + secrets.token_hex(24),
            },
            separators=(",", ":"),
        ),
        sensitive=True,
    )
    if output.strip() != "LITELLM_REAL_REQUEST_ACCEPTED":
        fail("the real LiteLLM request helper returned an invalid receipt")


def assert_otel_token_is_file_only(preprod: Preprod) -> None:
    path = COMPOSE_DIR / "secrets/litellm_otel_token"
    try:
        metadata = path.lstat()
        token = path.read_text(encoding="ascii")
    except OSError:
        fail("the generated LiteLLM OTLP token is unreadable")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or re.fullmatch(r"[0-9a-f]{64}", token) is None
    ):
        fail("the generated LiteLLM OTLP token boundary is invalid")

    if token in ENV_FILE.read_text(encoding="utf-8"):
        fail("the LiteLLM OTLP token entered the preprod environment file")
    for service in ("litellm", "alloy"):
        identifier = preprod.container_id(service)
        document = json.loads(preprod.docker("inspect", identifier))[0]
        config = document.get("Config") or {}
        metadata_text = json.dumps(
            {"Env": config.get("Env"), "Cmd": config.get("Cmd")},
            separators=(",", ":"),
        )
        if token in metadata_text:
            fail("the LiteLLM OTLP token entered Docker configuration metadata")
        logs = preprod.docker("logs", identifier, include_stderr=True)
        if token in logs:
            fail("the LiteLLM OTLP token entered container logs")


def log_cursor() -> str:
    """Return a Docker --since cursor for one bounded receipt phase."""

    return datetime.now(timezone.utc).isoformat()


def cribl_logs(preprod: Preprod, since: str) -> str:
    identifier = preprod.container_id("cribl-mock")
    return preprod.docker(
        "logs", "--since", since, identifier, include_stderr=True
    )


def wait_for_receipts(
    preprod: Preprod,
    markers: tuple[str, ...],
    since: str,
    timeout: int = 90,
) -> str:
    deadline = time.monotonic() + timeout
    latest = ""
    while time.monotonic() < deadline:
        latest = cribl_logs(preprod, since)
        if all(marker in latest for marker in markers):
            return latest
        time.sleep(1)
    fail("Cribl mock did not receive every approved security record")


def assert_initial_receipts(logs: str, token: str) -> None:
    allowed = (
        f"allowed-ai-input-{token}",
        f"allowed-ai-output-{token}",
        f"nested-call-{token}",
        "<redacted-credential>",
        "<redacted-authorization>",
        "<redacted-vendor-key>",
        f"receipt-call-{token}",
        "aigw.security.event_class: Str(ai_request_audit)",
        f"event_type=LOGIN realm_id=aigw client_id=portal user_id=receipt-{token}",
        f"event=aigw.portal.audit action=rotation.trigger outcome=success subject=receipt-{token} vendor=anthropic",
        f"event=aigw.identity.audit action=deployment_converge outcome=success project=receipt-{token} changed=true",
        f"event=aigw.identity.audit action=deployment_converge outcome=failed project=failed-{token} error_type=ReceiptFailure",
        "event=aigw.identity.audit action=break_glass_use outcome=success purpose=deployment_converge",
        "event=aigw.provider.rotation action=rotate outcome=success vendor=anthropic rotation_status=success",
        "event=aigw.vault.state action=state_observed outcome=success state=unsealed",
        "event=aigw.vault.audit",
        "hmac_protected=true",
        f"event=aigw.egress.trust action=startup_gate outcome=success policy_sha256={token * 4}",
        "providers=anthropic sni=api.anthropic.com exact_sans=api.anthropic.com",
        f"ca_sha256_fingerprints={ANTHROPIC_CA_FINGERPRINTS}",
        "event=aigw.egress.trust action=upstream_tls_failure outcome=failed provider=anthropic reason=tls_transport_failure",
    )
    missing = [marker for marker in allowed if marker not in logs]
    if missing:
        fail("the Cribl receipt is missing one or more approved fields")
    forbidden = (
        f"TRACE_SECRET_{token}",
        f"PROMPT_PASSWORD_{token}",
        f"PROMPT_BEARER_{token}",
        f"sk-ant-{token}{token}",
        f"NESTED_PROMPT_ARRAY_SECRET_{token}",
        f"NESTED_PROMPT_MAP_SECRET_{token}",
        f"KEYCLOAK_SECRET_{token}",
        f"PORTAL_SECRET_{token}",
        f"UNAPPROVED_FIELD_{token}",
        f"NESTED_SECRET_{token}",
        f"DENIED_ORDINARY_LOG_{token}",
        f"DENIED_SCHEMA_{token}",
        f"DENIED_ACTION_{token}",
        f"DENIED_VENDOR_{token}",
        f"DENIED_VAULT_STATE_{token}",
        f"DENIED_MALFORMED_{token}",
        f"DENIED_RAW_TRACE_{token}",
        f"DENIED_UNATTRIBUTED_TRACE_{token}",
        f"DENIED_UNTRUSTED_SOURCE_{token}",
        f"FORGED_AUTH_MARKER_{token}",
        f"untrusted-call-{token}",
        f"DENIED_KEYCLOAK_MISSING_USER_{token}",
        f"denied_raw_metric_{token}",
        f"DENIED_RAW_LOG_{token}",
        "provider=openai reason=tls_transport_failure",
    )
    leaked = [marker for marker in forbidden if marker in logs]
    if leaked:
        fail("Cribl received a secret or a signal outside the allow-list")


def read_alloy_metrics(preprod: Preprod, model: dict[str, Any]) -> str:
    services = model.get("services")
    networks = model.get("networks")
    if not isinstance(services, dict) or not isinstance(networks, dict):
        fail("the preprod model has no metrics-probe boundary")
    image = services.get("key-rotator", {}).get("image")
    network = networks.get("net-observability", {}).get("name")
    if not isinstance(image, str) or network != "aigw-preprod-net-observability":
        fail("the preprod metrics-probe boundary is invalid")
    helper = (
        "import urllib.request; "
        "data=urllib.request.urlopen('http://alloy:12345/metrics',timeout=5).read(8388609); "
        "assert len(data)<=8388608; print(data.decode(),end='')"
    )
    return preprod.docker(
        "run",
        "--rm",
        "--pull=never",
        "--name",
        f"{PROJECT}-security-metrics-probe",
        "--network",
        network,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--label",
        f"com.docker.compose.project={PROJECT}",
        "--label",
        f"{OWNER_LABEL}={PROJECT}",
        "--entrypoint",
        "/opt/venv/bin/python",
        image,
        "-c",
        helper,
    )


def cribl_queue_size(metrics: str) -> float:
    matches: list[float] = []
    for line in metrics.splitlines():
        if not line.startswith("otelcol_exporter_queue_size{"):
            continue
        labels, separator, value = line.rpartition(" ")
        if not separator:
            continue
        if (
            'component_id="otelcol.exporter.otlp.cribl"' in labels
            and 'data_type="logs"' in labels
        ):
            try:
                matches.append(float(value))
            except ValueError:
                fail("Alloy returned an invalid Cribl queue metric")
    if len(matches) != 1:
        fail("Alloy did not expose one Cribl log queue metric")
    return matches[0]


def wait_for_queue(preprod: Preprod, model: dict[str, Any], *, populated: bool) -> None:
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        size = cribl_queue_size(read_alloy_metrics(preprod, model))
        if (populated and size > 0) or (not populated and size == 0):
            return
        time.sleep(1)
    state = "grow" if populated else "drain"
    fail(f"the persistent Cribl queue did not {state}")


def replace_test_certificate(path: Path, content: bytes) -> None:
    """Replace one generated preprod certificate file without changing its inode."""

    try:
        metadata = path.lstat()
    except FileNotFoundError:
        fail("a generated preprod Cribl certificate file is missing")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or not content
        or len(content) > MAX_TEST_CERT_BYTES
    ):
        fail("a generated preprod Cribl certificate file is unsafe")
    flags = os.O_WRONLY | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)


def recreate_cribl(preprod: Preprod) -> None:
    preprod.compose(
        "up",
        "-d",
        "--no-deps",
        "--force-recreate",
        "--no-build",
        "--pull",
        "never",
        "cribl-mock",
    )
    preprod.wait_healthy("cribl-mock")


def exercise_tls_server_name_failure(
    preprod: Preprod, model: dict[str, Any], token: str
) -> None:
    """Prove Alloy queues records when the trusted server has the wrong SAN."""

    since = log_cursor()
    paths = (CRIBL_CERT, CRIBL_KEY, WRONG_SAN_CERT, WRONG_SAN_KEY)
    try:
        original_cert, original_key, wrong_cert, wrong_key = (
            path.read_bytes() for path in paths
        )
    except OSError:
        fail("the generated preprod TLS test material is unreadable")
    wait_for_queue(preprod, model, populated=False)
    cribl = preprod.container_id("cribl-mock")
    replaced = False
    restored = False
    try:
        preprod.docker("stop", "--time", "10", cribl)
        replace_test_certificate(CRIBL_CERT, wrong_cert)
        replace_test_certificate(CRIBL_KEY, wrong_key)
        replaced = True
        recreate_cribl(preprod)
        send_otlp_fixtures(
            preprod,
            OTLP_OUTAGE_HELPER,
            token,
            "OTLP_OUTAGE_FIXTURES_ACCEPTED",
        )
        wait_for_queue(preprod, model, populated=True)
        marker = f"queued-ai-input-{token}-0"
        time.sleep(3)
        if marker in cribl_logs(preprod, since):
            fail("Alloy accepted a Cribl certificate with the wrong server name")

        replace_test_certificate(CRIBL_CERT, original_cert)
        replace_test_certificate(CRIBL_KEY, original_key)
        restored = True
        recreate_cribl(preprod)
        wait_for_receipts(preprod, (marker,), since)
        wait_for_queue(preprod, model, populated=False)
    finally:
        if replaced and not restored:
            replace_test_certificate(CRIBL_CERT, original_cert)
            replace_test_certificate(CRIBL_KEY, original_key)
            recreate_cribl(preprod)


def exercise_outage_recovery(preprod: Preprod, model: dict[str, Any], token: str) -> None:
    since = log_cursor()
    cribl = preprod.container_id("cribl-mock")
    alloy = preprod.container_id("alloy")
    cribl_stopped = False
    try:
        preprod.docker("stop", "--time", "10", cribl)
        cribl_stopped = True
        send_otlp_fixtures(
            preprod,
            OTLP_OUTAGE_HELPER,
            token,
            "OTLP_OUTAGE_FIXTURES_ACCEPTED",
        )
        wait_for_queue(preprod, model, populated=True)

        # The receiver remains down while Alloy restarts. A queue that lives
        # only in memory would lose the six accepted records at this point.
        preprod.docker("restart", "--time", "10", alloy)
        preprod.wait_healthy("alloy")
        wait_for_queue(preprod, model, populated=True)

        preprod.docker("start", cribl)
        cribl_stopped = False
        preprod.wait_healthy("cribl-mock")
        wait_for_receipts(preprod, (f"queued-ai-input-{token}-0",), since)
        wait_for_queue(preprod, model, populated=False)
    finally:
        if cribl_stopped:
            preprod.docker("start", cribl)
            preprod.wait_healthy("cribl-mock")
        # A failed restart can leave Alloy stopped. Restore the exact owned
        # container so a failed test does not damage the rest of preprod.
        state = json.loads(preprod.docker("inspect", alloy))[0].get("State", {})
        if state.get("Status") != "running":
            preprod.docker("start", alloy)
        preprod.wait_healthy("alloy")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-mode", choices=("source", "seed"), default="source")
    args = parser.parse_args()
    token = secrets.token_hex(8)
    tls_token = secrets.token_hex(8)
    outage_token = secrets.token_hex(8)

    preprod = Preprod(args.image_mode)
    # Reuse the main preprod guard before this script performs any mutation.
    guard = run(
        [
            sys.executable,
            str(ROOT / "scripts/preprod.py"),
            "--image-mode",
            args.image_mode,
            "compose-config",
        ]
    )
    if "PREPROD_COMPOSE_VALID" not in guard:
        fail("the preprod Compose ownership guard did not pass")
    model = preprod.model()
    preprod.wait_healthy("alloy")
    preprod.wait_healthy("cribl-mock")
    assert_otel_token_is_file_only(preprod)

    receipt_since = log_cursor()
    # Generate a fresh, real Vault audit record after the Docker log cursor.
    # Depending on an old audit line makes repeated preprod runs flaky because
    # Alloy correctly resumes the file at its saved position.
    verification = run(
        [
            sys.executable,
            str(ROOT / "scripts/preprod.py"),
            "--image-mode",
            args.image_mode,
            "verify",
        ]
    )
    if "PREPROD_VERIFIED" not in verification:
        fail("the live Vault audit receipt could not be generated")
    write_log_fixtures(preprod, model, token)
    send_otlp_fixtures(preprod, OTLP_FIXTURE_HELPER, token, "OTLP_FIXTURES_ACCEPTED")
    send_otlp_fixtures(
        preprod,
        OTLP_SPOOF_HELPER,
        token,
        "OTLP_SPOOF_REJECTED",
        service="key-rotator",
    )
    send_real_litellm_request(preprod, token)
    logs = wait_for_receipts(
        preprod,
        (
            f"allowed-ai-input-{token}",
            f"real-ai-input-{token}",
            f"nested-call-{token}",
            f"event_type=LOGIN realm_id=aigw client_id=portal user_id=receipt-{token}",
            f"event=aigw.portal.audit action=rotation.trigger outcome=success subject=receipt-{token}",
            f"event=aigw.identity.audit action=deployment_converge outcome=success project=receipt-{token}",
            "event=aigw.provider.rotation action=rotate outcome=success vendor=anthropic",
            "event=aigw.vault.state action=state_observed outcome=success state=unsealed",
            "event=aigw.vault.audit",
            f"event=aigw.egress.trust action=startup_gate outcome=success policy_sha256={token * 4}",
            "event=aigw.egress.trust action=upstream_tls_failure",
        ),
        receipt_since,
    )
    # One extra file-source interval proves denied records did not merely lag.
    time.sleep(12)
    assert_initial_receipts(cribl_logs(preprod, receipt_since), token)
    exercise_tls_server_name_failure(preprod, model, tls_token)
    exercise_outage_recovery(preprod, model, outage_token)

    print("PREPROD_CRIBL_SECURITY_FEED_PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
