#!/usr/bin/env python3
"""Prove local Cribl telemetry scope, redaction, TLS, queue, and recovery."""

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
PREPROD_ROOT_CA_FILE = COMPOSE_DIR / "secrets/preprod-root-ca.pem"
PREPROD_DEVELOPER_PASSWORD_FILE = (
    COMPOSE_DIR / "secrets/samba_user_preprod-developer_password"
)
PORTAL_LOGIN_SCRIPT = ROOT / "scripts/test-portal-login.py"
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
CONTROLLER_AUDIT_DIR = COMPOSE_DIR / "secrets/preprod-controller-lifecycle"
CONTROLLER_AUDIT_CURRENT = CONTROLLER_AUDIT_DIR / "lifecycle.jsonl"
CONTROLLER_AUDIT_ROTATED = CONTROLLER_AUDIT_DIR / "lifecycle.jsonl.1"
ANTHROPIC_CA_FINGERPRINTS = (
    "1dfc1605fbad358d8bc844f76d15203fac9ca5c1a79fd4857ffaf2864fbebf96,"
    "349dfa4058c5e263123b398ae795573c4e1313c83fe68f93556cd5e8031b3c7d"
)

NATURAL_KEYCLOAK_EVENT = re.compile(
    r'^type="(?P<event>LOGIN|LOGIN_ERROR|LOGOUT)", '
    r'realmId="(?P<realm>[A-Za-z0-9_.:@-]{1,128})", '
    r'realmName="aigw", clientId="dev-portal", '
    r'userId="(?P<user>[A-Za-z0-9_.:@-]{1,128})"(?:,|$)'
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
stale = str(int(now) - 25 * 60 * 60 * 1_000_000_000)
future = str(int(now) + 5 * 60 * 1_000_000_000)
recent_past = str(int(now) - (24 * 60 - 5) * 60 * 1_000_000_000)
allowed_clock_skew = str(int(now) + 30 * 1_000_000_000)

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
jwt_secret = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2lnbmF0dXJlMTIzNDU2"
vault_token_secret = "hvs.ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
legacy_vault_token_s = "s.ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
legacy_vault_token_b = "b.ZYXWVUTSRQPONMLKJIHGFEDCBA543210"
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
        text("metadata.user_api_key_end_user_id", "FORGED_ENDUSER_" + token),
        text("metadata.user_api_key_alias", "FORGED_ALIAS_" + token),
        text(
            "metadata.user_api_key_auth_metadata",
            '{"aigw_username":"FORGED_AUTH_NAME_' + token + '"}',
        ),
        text("aigw.server.user.name", "receipt-user-" + token),
        text("aigw.server.user.name_source", "portal_key_metadata"),
        text("aigw.user.name", "FORGED_NORMALIZED_NAME_" + token),
        text("aigw.user.name_source", "key_subject"),
        text("metadata.headers", "Bearer METADATA_HEADERS_SECRET_" + token),
        text(
            "metadata.request_headers",
            "Bearer METADATA_REQUEST_HEADERS_SECRET_" + token,
        ),
        text("request_headers", "Bearer REQUEST_HEADERS_SECRET_" + token),
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
            + token
            + " session_token=SESSION_TOKEN_SECRET_"
            + token
            + " vault_unseal_share=VAULT_UNSEAL_SECRET_"
            + token
            + " client_assertion=CLIENT_ASSERTION_SECRET_"
            + token
            + ' password="QUOTED_MULTIWORD_INPUT_'
            + token
            + ' correct horse battery staple"'
            + ' nested={\\"client_secret\\":\\"ESCAPED_MULTIWORD_INPUT_'
            + token
            + ' alpha beta gamma\\"}'
            + " "
            + jwt_secret
            + " "
            + vault_token_secret
            + " "
            + legacy_vault_token_s
            + " "
            + legacy_vault_token_b
            + " -----BEGIN PRIVATE KEY-----\nPEM_SECRET_"
            + token
            + "\n-----END PRIVATE KEY-----"
            + " -----BEGIN DSA PRIVATE KEY-----\nDSA_PEM_SECRET_"
            + token
            + "\n-----END DSA PRIVATE KEY-----"
            + " session_count=SAFE_SESSION_COUNT_"
            + token
            + " vault_status=SAFE_VAULT_STATUS_"
            + token
            + " client_assertiveness=SAFE_CLIENT_ASSERTIVENESS_"
            + token
            + " jwt-like=eyJabc.def hvs.short s.short b.short"
            + " -----BEGIN PUBLIC KEY-----\nSAFE_PUBLIC_KEY_"
            + token
            + "\n-----END PUBLIC KEY-----"
            + " -----BEGIN CERTIFICATE-----\nSAFE_CERTIFICATE_"
            + token
            + "\n-----END CERTIFICATE-----",
        ),
        text(
            "gen_ai.output.messages",
            "allowed-ai-output-"
            + token
            + " Bearer PROMPT_BEARER_"
            + token
            + " SAFE_PRIVATE_KEY_WORDS_"
            + token
            + " access_token='QUOTED_MULTIWORD_OUTPUT_"
            + token
            + " delta echo foxtrot'"
            + " -----BEGIN ENCRYPTED PRIVATE KEY-----\nENCRYPTED_PEM_SECRET_"
            + token
            + "\n-----END ENCRYPTED PRIVATE KEY-----"
            + " -----BEGIN RSA PRIVATE KEY-----\nTRUNCATED_PEM_SECRET_"
            + token,
        ),
        text(
            "gen_ai.prompt.0.content",
            'password="QUOTED_MULTIWORD_LEGACY_PROMPT_'
            + token
            + ' golf hotel india" password policy=SAFE_PASSWORD_POLICY_'
            + token,
        ),
        text(
            "gen_ai.completion.0.content",
            'nested={\\"vault_token\\":\\"ESCAPED_MULTIWORD_LEGACY_COMPLETION_'
            + token
            + ' juliet kilo lima\\"} vault status=SAFE_VAULT_WORDS_'
            + token,
        ),
        text("authorization", "Bearer TRACE_SECRET_" + token),
        integer("aigw.security.schema_version", 9),
        text("aigw.security.producer", "FORGED_PRODUCER_" + token),
        text("deployment.environment", "FORGED_LOG_ENV_" + token),
        text("service.name", "FORGED_LOG_SERVICE_" + token),
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
    "attributes": [text("receipt.marker", "ADMITTED_SANITIZED_TRACE_" + token)],
}
unattributed_span = {
    "traceId": trace_id,
    "spanId": token[1:] + token[:1],
    "name": "litellm_request",
    "kind": 2,
    "startTimeUnixNano": now,
    "endTimeUnixNano": str(int(now) + 1000),
    "attributes": [
        text("gen_ai.input.messages", "ADMITTED_UNATTRIBUTED_TRACE_" + token)
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
        text("aigw.server.user.name", "nested-user-" + token),
        text("aigw.server.user.name_source", "key_subject"),
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

def bad_time_span(span_id, timestamp, marker):
    return {
        "traceId": trace_id,
        "spanId": span_id,
        "name": "litellm_request",
        "kind": 2,
        "startTimeUnixNano": timestamp,
        "endTimeUnixNano": timestamp,
        "attributes": [
            text("metadata.user_api_key_user_id", "bad-time-user"),
            text("metadata.user_api_key_hash", "e" * 64),
            text("metadata.user_api_key_project_id", "receipt-project"),
            text("metadata.user_api_key_end_user_id", "bad-time-user"),
            text("aigw.server.user.name", "bad-time-user"),
            text("aigw.server.user.name_source", "key_subject"),
            text("litellm.call_id", "bad-time-call-" + marker + token),
            text("gen_ai.request.model", "receipt-model"),
            text("gen_ai.input.messages", marker + token),
        ],
    }

def bad_attribution_span(span_id, user_name, user_name_source, marker):
    return {
        "traceId": trace_id,
        "spanId": span_id,
        "name": "litellm_request",
        "kind": 2,
        "startTimeUnixNano": now,
        "endTimeUnixNano": str(int(now) + 1000),
        "attributes": [
            text("metadata.user_api_key_user_id", "bad-attribution-user"),
            text("metadata.user_api_key_hash", "f" * 64),
            text("metadata.user_api_key_project_id", "receipt-project"),
            text("aigw.server.user.name", user_name),
            text("aigw.server.user.name_source", user_name_source),
            text("aigw.user.name", "FORGED_PREEXISTING_NAME_" + token),
            text("aigw.user.name_source", "key_subject"),
            text("litellm.call_id", "bad-attribution-call-" + marker + token),
            text("gen_ai.input.messages", marker + token),
        ],
    }

post(
    "/v1/traces",
    {
        "resourceSpans": [{
            "resource": {"attributes": [
                text("service.name", "litellm"),
                text("deployment.environment", "FORGED_RESOURCE_ENV_" + token),
            ]},
            "scopeSpans": [{
                "scope": {"name": "aigw.preprod.receipt"},
                "spans": [
                    allowed_span,
                    denied_span,
                    unattributed_span,
                    nested_prompt_span,
                    bad_attribution_span(
                        token[2:] + token[:2],
                        "unresolved-user",
                        "unresolved",
                        "DENIED_UNREVIEWED_NAME_SOURCE_",
                    ),
                    bad_attribution_span(
                        token[9:] + token[:9],
                        "name with spaces",
                        "key_subject",
                        "DENIED_MALFORMED_SERVER_NAME_",
                    ),
                    bad_time_span(token[4:] + token[:4], "0", "DENIED_ZERO_TIMESTAMP_"),
                    bad_time_span(token[5:] + token[:5], stale, "DENIED_STALE_TIMESTAMP_"),
                    bad_time_span(token[6:] + token[:6], future, "DENIED_FUTURE_TIMESTAMP_"),
                    bad_time_span(token[7:] + token[:7], recent_past, "ALLOWED_RECENT_PAST_TIMESTAMP_"),
                    bad_time_span(token[8:] + token[:8], allowed_clock_skew, "ALLOWED_CLOCK_SKEW_TIMESTAMP_"),
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
            "resource": {"attributes": [
                text("service.name", "receipt-test"),
                text("deployment.environment", "FORGED_METRIC_ENV_" + token),
                text("session_token", "METRIC_RESOURCE_SECRET_" + token),
            ]},
            "scopeMetrics": [{
                "scope": {
                    "name": "aigw.preprod.receipt",
                    "attributes": [
                        text("client_assertion", "METRIC_SCOPE_SECRET_" + token),
                    ],
                },
                "metrics": [{
                    "name": "admitted_metric_" + token,
                    "gauge": {"dataPoints": [{
                        "timeUnixNano": now,
                        "asInt": "1",
                        "attributes": [
                            text("tls.private_key_pem", "METRIC_POINT_SECRET_" + token),
                        ],
                    }]},
                }],
            }],
        }]
    },
)
post(
    "/v1/logs",
    {
        "resourceLogs": [{
            "resource": {"attributes": [
                text("service.name", "receipt-test"),
                text("deployment.environment", "FORGED_OTLP_LOG_ENV_" + token),
                text("vault_unseal_share", "OTLP_LOG_RESOURCE_SECRET_" + token),
            ]},
            "scopeLogs": [{
                "scope": {"name": "aigw.preprod.receipt"},
                "logRecords": [{
                    "timeUnixNano": now,
                    "severityNumber": 9,
                    "body": {
                        "stringValue": (
                            "ADMITTED_LOG_" + token +
                            " password=OTLP_LOG_BODY_SECRET_" + token
                        ),
                    },
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
                        text("aigw.server.user.name", "outage-user"),
                        text("aigw.server.user.name_source", "key_subject"),
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
partial_key = test["partial_key"]
username = "natural-portal-" + marker
owner = "portal-owner-" + marker

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
partial_created = False
problem = None
try:
    status, generated = request(
        "/key/generate",
        master_key,
        {
            "key": virtual_key,
            "key_alias": "receipt-" + marker,
            "user_id": owner,
            "models": ["claude-sonnet-4-5"],
            "allowed_routes": ["/v1/chat/completions"],
            "metadata": {
                "created_via": "dev-portal",
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
            "user": "FORGED_BODY_USER_" + marker,
        },
        user="FORGED_PLAIN_HEADER_USER_" + marker,
    )
    choices = inference.get("choices")
    reply = ""
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        message = choices[0].get("message")
        if isinstance(message, dict):
            reply = message.get("content", "")
    if status != 200 or reply.strip() != "pong":
        raise RuntimeError("the real LiteLLM request did not return pong")

    status, generated = request(
        "/key/generate",
        master_key,
        {
            "key": partial_key,
            "key_alias": "partial-openwebui-" + marker,
            "user_id": owner,
            "models": ["claude-sonnet-4-5"],
            "allowed_routes": ["/v1/chat/completions"],
            "metadata": {"aigw_service": "open-webui"},
            "permissions": {},
            "blocked": False,
        },
    )
    if status != 200 or generated.get("key") != partial_key:
        raise RuntimeError("LiteLLM did not create the partial-marker key")
    partial_created = True
    status, _ = request(
        "/v1/chat/completions",
        partial_key,
        {
            "model": "claude-sonnet-4-5",
            "max_tokens": 8,
            "messages": [{
                "role": "user",
                "content": "REJECTED_OPENWEBUI_PARTIAL_MARKER_" + marker,
            }],
        },
    )
    if not 400 <= status < 500:
        raise RuntimeError("LiteLLM accepted a partial Open WebUI key marker")
except Exception as error:
    problem = str(error)
finally:
    keys = []
    if created:
        keys.append(virtual_key)
    if partial_created:
        keys.append(partial_key)
    if keys:
        delete_status, _ = request(
            "/key/delete", master_key, {"keys": keys}
        )
        if delete_status != 200 and problem is None:
            problem = "LiteLLM did not delete the receipt keys"

if problem is not None:
    raise SystemExit(problem)
print("LITELLM_REAL_REQUEST_ACCEPTED")
""".strip()


OPENWEBUI_HEADER_RUNTIME_REQUEST_HELPER = r"""
import json
import http.client
import os
import time
from types import SimpleNamespace
import urllib.error
import urllib.parse
import urllib.request
import jwt
from open_webui.utils.headers import include_user_info_headers

test = json.load(__import__("sys").stdin)
marker = test["marker"]
mode = test["mode"]
api_key = os.environ.get("OPENAI_API_KEY", "")
api_base = os.environ.get("OPENAI_API_BASE_URL", "").rstrip("/")
if not api_key.startswith("sk-") or not api_base:
    raise SystemExit("Open WebUI runtime identity inputs are unavailable")

username = "natural.openwebui." + marker
user = SimpleNamespace(
    id="oidc-" + marker,
    email=username,
    name="Natural OpenWebUI 用户",
    role="user",
)
headers = include_user_info_headers(
    {
        "Authorization": "Bearer " + api_key,
        "Content-Type": "application/json",
    },
    user,
)
if (
    "X-OpenWebUI-User-Jwt" not in headers
    or any(
        name in headers
        for name in (
            "X-OpenWebUI-User-Email",
            "X-OpenWebUI-User-Id",
            "X-OpenWebUI-User-Name",
            "X-OpenWebUI-User-Role",
        )
    )
):
    raise SystemExit("Open WebUI did not build the exact signed header contract")
# Add caller-controlled conflicts only after proving what the installed helper
# naturally emitted. The signed assertion must remain the sole name authority.
headers["X-OpenWebUI-User-Email"] = "FORGED_OPENWEBUI_PLAIN_USER_" + marker
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
if mode == "valid":
    document = {
        "model": "claude-sonnet-4-5",
        "max_tokens": 8,
        "messages": [
            {"role": "user", "content": "runtime-openwebui-ai-input-" + marker}
        ],
        "user": "FORGED_OPENWEBUI_BODY_USER_" + marker,
    }
    request = urllib.request.Request(
        api_base + "/chat/completions",
        data=json.dumps(document, separators=(",", ":")).encode(),
        headers=headers,
    )
    with opener.open(request, timeout=30) as response:
        raw = response.read(1048577)
        status = response.status
    if len(raw) > 1048576:
        raise SystemExit("LiteLLM returned an oversized Open WebUI response")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        raise SystemExit("LiteLLM returned invalid Open WebUI JSON")
    choices = parsed.get("choices")
    reply = ""
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        message = choices[0].get("message")
        if isinstance(message, dict):
            reply = message.get("content", "")
    if status != 200 or reply.strip() != "pong":
        raise SystemExit("the Open WebUI header-runtime request did not return pong")
    print("OPENWEBUI_HEADER_RUNTIME_REQUEST_ACCEPTED")
elif mode == "denied":
    secret = os.environ.get("FORWARD_USER_INFO_HEADER_JWT_SECRET", "")
    if len(secret) != 64:
        raise SystemExit("Open WebUI signing inputs are unavailable")
    now = int(time.time())
    expired_token = jwt.encode(
        {
            "sub": "expired-" + marker,
            "email": "expired." + marker,
            "name": "Expired Open WebUI User",
            "role": "user",
            "iss": "open-webui",
            "iat": now - 240,
            "exp": now - 120,
        },
        secret,
        algorithm="HS256",
    )
    base_headers = {
        "Authorization": "Bearer " + api_key,
        "Content-Type": "application/json",
    }
    valid_token = headers["X-OpenWebUI-User-Jwt"]
    rejected = (
        ("REJECTED_OPENWEBUI_MISSING_JWT_", base_headers),
        (
            "REJECTED_OPENWEBUI_INVALID_JWT_",
            {**base_headers, "X-OpenWebUI-User-Jwt": "not-a-jwt"},
        ),
        (
            "REJECTED_OPENWEBUI_EXPIRED_JWT_",
            {**base_headers, "X-OpenWebUI-User-Jwt": expired_token},
        ),
    )
    for rejected_marker, rejected_headers in rejected:
        rejected_document = {
            "model": "claude-sonnet-4-5",
            "max_tokens": 8,
            "messages": [
                {"role": "user", "content": rejected_marker + marker}
            ],
        }
        rejected_request = urllib.request.Request(
            api_base + "/chat/completions",
            data=json.dumps(rejected_document, separators=(",", ":")).encode(),
            headers=rejected_headers,
        )
        try:
            with opener.open(rejected_request, timeout=30) as rejected_response:
                rejected_raw = rejected_response.read(1048577)
                rejected_status = rejected_response.status
        except urllib.error.HTTPError as error:
            rejected_status = error.code
            rejected_raw = error.read(1048577)
        if len(rejected_raw) > 1048576 or not 400 <= rejected_status < 500:
            raise SystemExit("LiteLLM did not reject an invalid identity request")

    # Send two physical header fields through the real HTTP parser. LiteLLM
    # keeps the first raw value separately from its cleaned header mapping;
    # the pre-call gate must compare both views and reject disagreement.
    duplicate_document = {
        "model": "claude-sonnet-4-5",
        "max_tokens": 8,
        "messages": [{
            "role": "user",
            "content": "REJECTED_OPENWEBUI_CONFLICTING_JWT_" + marker,
        }],
    }
    duplicate_body = json.dumps(
        duplicate_document, separators=(",", ":")
    ).encode()
    parsed_base = urllib.parse.urlsplit(api_base)
    if parsed_base.scheme != "http" or not parsed_base.hostname:
        raise SystemExit("Open WebUI test requires the internal HTTP API base")
    duplicate_path = parsed_base.path.rstrip("/") + "/chat/completions"
    duplicate_connection = http.client.HTTPConnection(
        parsed_base.hostname, parsed_base.port or 80, timeout=30
    )
    duplicate_connection.putrequest("POST", duplicate_path)
    duplicate_connection.putheader("Authorization", "Bearer " + api_key)
    duplicate_connection.putheader("Content-Type", "application/json")
    duplicate_connection.putheader("Content-Length", str(len(duplicate_body)))
    duplicate_connection.putheader("X-OpenWebUI-User-Jwt", "not-a-jwt")
    duplicate_connection.putheader("x-openwebui-user-jwt", valid_token)
    duplicate_connection.endheaders(duplicate_body)
    duplicate_response = duplicate_connection.getresponse()
    duplicate_raw = duplicate_response.read(1048577)
    duplicate_status = duplicate_response.status
    duplicate_connection.close()
    if len(duplicate_raw) > 1048576 or not 400 <= duplicate_status < 500:
        raise SystemExit("LiteLLM accepted conflicting physical JWT headers")
    print("OPENWEBUI_INVALID_IDENTITY_REQUESTS_REJECTED")
else:
    raise SystemExit("invalid Open WebUI runtime helper mode")
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
    def __init__(self, image_mode: str, postgres_major: str = "18") -> None:
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
        if postgres_major == "16":
            self.compose_prefix.extend(
                ["-f", str(COMPOSE_DIR / "docker-compose.preprod-postgres16.yml")]
            )
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
    rotation_id = "123e4567-e89b-42d3-a456-426614174000"
    portal_create_op = "123e4567-e89b-42d3-a456-426614174010"
    portal_delete_op = "123e4567-e89b-42d3-a456-426614174011"
    portal_add_op = "123e4567-e89b-42d3-a456-426614174012"
    portal_remove_op = "123e4567-e89b-42d3-a456-426614174013"
    portal_policy_op = "123e4567-e89b-42d3-a456-426614174014"
    portal_model_op = "123e4567-e89b-42d3-a456-426614174015"
    portal_price_op = "123e4567-e89b-42d3-a456-426614174016"
    portal_backdate_preview_op = "123e4567-e89b-42d3-a456-426614174017"
    portal_backdate_confirm_op = "123e4567-e89b-42d3-a456-426614174018"
    portal_model_activate_op = "123e4567-e89b-42d3-a456-426614174019"
    identity_create_op = "123e4567-e89b-42d3-a456-426614174020"
    identity_delete_op = "123e4567-e89b-42d3-a456-426614174021"
    identity_add_op = "123e4567-e89b-42d3-a456-426614174022"
    identity_remove_op = "123e4567-e89b-42d3-a456-426614174023"
    identity_policy_op = "123e4567-e89b-42d3-a456-426614174024"
    managed_planned_op = "123e4567-e89b-42d3-a456-426614174025"
    managed_drift_op = "123e4567-e89b-42d3-a456-426614174026"
    keycloak = json.dumps(
        {
            "log.logger": "org.keycloak.events",
            "message": (
                'type="LOGIN", realmId="aigw", clientId="portal", '
                f'userId="receipt-{token}", '
                f'ipAddress="DENIED_KEYCLOAK_IP_{token}", '
                f'username="DENIED_KEYCLOAK_USERNAME_{token}", '
                f'email="DENIED_KEYCLOAK_EMAIL_{token}", '
                f'access_token="KEYCLOAK_SECRET_{token}"'
            ),
        },
        separators=(",", ":"),
    )
    keycloak_missing_user = json.dumps(
        {
            "log.logger": "org.keycloak.events",
            "message": (
                'type="LOGIN", realmId="aigw", clientId="portal", '
                f"note=DENIED_KEYCLOAK_MISSING_USER_{token}"
            ),
        },
        separators=(",", ":"),
    )
    keycloak_unquoted = json.dumps(
        {
            "log.logger": "org.keycloak.events",
            "message": (
                "type=LOGIN, realmId=aigw, clientId=portal, "
                f"userId=receipt-{token}, note=DENIED_KEYCLOAK_UNQUOTED_{token}"
            ),
        },
        separators=(",", ":"),
    )
    portal = (
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.portal.audit",'
        '"action":"rotation.trigger","outcome":"success",'
        f'"subject":"receipt-{token}","vendor":"anthropic",'
        f'"producer":"FORGED_BODY_PRODUCER_{token}",'
        f'"deployment.environment":"FORGED_BODY_ENV_{token}",'
        f'"service.name":"FORGED_BODY_SERVICE_{token}",'
        f'"unreviewed":"UNAPPROVED_FIELD_{token}",'
        f'"nested":{{"private_key":"NESTED_SECRET_{token}"}},'
        f'"note":"Bearer PORTAL_SECRET_{token}"}}'
    )
    admin_portal = (
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.portal.audit",'
        '"action":"rotation.settings.update","outcome":"success",'
        f'"subject":"admin-receipt-{token}","vendor":"anthropic"}}'
    )
    identity = (
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.identity.audit",'
        '"action":"deployment_converge","outcome":"success","changed":true,'
        f'"project":"receipt-{token}"}}'
    )
    identity_unchanged = (
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.identity.audit",'
        '"action":"deployment_converge","outcome":"success","changed":false,'
        f'"project":"unchanged-{token}"}}'
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
    portal_natural_events = (
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.portal.audit",'
        f'"action":"authorization.role.denied","outcome":"failure","subject":"role-denied-{token}"}}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.portal.audit",'
        f'"action":"authorization.step_up.required","outcome":"failure","subject":"step-up-{token}"}}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.portal.audit",'
        f'"action":"identity.group.create","outcome":"intent","subject":"group-create-ok-{token}","group":"team-create-ok-{token}","operation_id":"{portal_create_op}"}}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.portal.audit",'
        f'"action":"identity.group.create","outcome":"success","subject":"group-create-ok-{token}","group":"team-create-ok-{token}","operation_id":"{portal_create_op}"}}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.portal.audit",'
        f'"action":"identity.group.delete","outcome":"intent","subject":"group-delete-fail-{token}","group":"team-delete-fail-{token}","operation_id":"{portal_delete_op}"}}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.portal.audit",'
        f'"action":"identity.group.delete","outcome":"failure","subject":"group-delete-fail-{token}","group":"team-delete-fail-{token}","operation_id":"{portal_delete_op}"}}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.portal.audit",'
        f'"action":"identity.member.add","outcome":"intent","subject":"member-add-unknown-{token}","group":"team-add-unknown-{token}","target_subject":"target-add-unknown-{token}","operation_id":"{portal_add_op}"}}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.portal.audit",'
        f'"action":"identity.member.add","outcome":"indeterminate","subject":"member-add-unknown-{token}","group":"team-add-unknown-{token}","target_subject":"target-add-unknown-{token}","operation_id":"{portal_add_op}"}}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.portal.audit",'
        f'"action":"identity.member.remove","outcome":"intent","subject":"member-remove-ok-{token}","group":"team-remove-ok-{token}","target_subject":"target-remove-ok-{token}","operation_id":"{portal_remove_op}"}}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.portal.audit",'
        f'"action":"identity.member.remove","outcome":"success","subject":"member-remove-ok-{token}","group":"team-remove-ok-{token}","target_subject":"target-remove-ok-{token}","project":"receipt-project","operation_id":"{portal_remove_op}"}}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.portal.audit",'
        f'"action":"identity.group.policy","outcome":"intent","subject":"group-policy-ok-{token}","group":"team-policy-ok-{token}","operation_id":"{portal_policy_op}"}}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.portal.audit",'
        f'"action":"identity.group.policy","outcome":"success","subject":"group-policy-ok-{token}","group":"team-policy-ok-{token}","project":"receipt-project","operation_id":"{portal_policy_op}"}}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.portal.audit",'
        f'"action":"model.governance.create","outcome":"intent","subject":"model-admin-{token}","model":"claude-sonnet-4-5","provider":"anthropic","operation_id":"{portal_model_op}"}}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.portal.audit",'
        f'"action":"model.governance.create","outcome":"success","subject":"model-admin-{token}","model":"claude-sonnet-4-5","provider":"anthropic","operation_id":"{portal_model_op}"}}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.portal.audit",'
        f'"action":"model.governance.activate","outcome":"intent","subject":"model-admin-{token}","model":"claude-sonnet-4-5","operation_id":"{portal_model_activate_op}"}}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.portal.audit",'
        f'"action":"model.governance.activate","outcome":"success","subject":"model-admin-{token}","model":"claude-sonnet-4-5","operation_id":"{portal_model_activate_op}"}}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.portal.audit",'
        f'"action":"model.price.create","outcome":"intent","subject":"price-admin-{token}","model":"claude-sonnet-4-5","usage_class":"cache_read","operation_id":"{portal_price_op}"}}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.portal.audit",'
        f'"action":"model.price.create","outcome":"success","subject":"price-admin-{token}","model":"claude-sonnet-4-5","usage_class":"cache_read","operation_id":"{portal_price_op}"}}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.portal.audit",'
        f'"action":"model.price.backdate.preview","outcome":"intent","subject":"price-admin-{token}","model":"claude-sonnet-4-5","usage_class":"cache_read","operation_id":"{portal_backdate_preview_op}"}}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.portal.audit",'
        f'"action":"model.price.backdate.preview","outcome":"success","subject":"price-admin-{token}","model":"claude-sonnet-4-5","usage_class":"cache_read","operation_id":"{portal_backdate_preview_op}"}}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.portal.audit",'
        f'"action":"model.price.backdate.confirm","outcome":"intent","subject":"price-admin-{token}","operation_id":"{portal_backdate_confirm_op}"}}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.portal.audit",'
        f'"action":"model.price.backdate.confirm","outcome":"success","subject":"price-admin-{token}","model":"claude-sonnet-4-5","usage_class":"cache_read","operation_id":"{portal_backdate_confirm_op}"}}',
    )
    price_events = tuple(
        "AIGW_SECURITY_EVENT "
        + json.dumps(
            {
                "schema_version": 1,
                "event": "aigw.price.audit",
                "action": action,
                "outcome": "success",
                "operation_id": operation_id,
                "subject": f"trusted-price-{token}",
                "model": "claude-sonnet-4-5",
                "provider": "anthropic",
                "usage_class": "cache_read",
                "amount_usd": "30.000000000000",
                "token_unit": "1000000",
                "effective_at": "2026-07-01T00:00:00Z",
                "source_reference": "anthropic-price-review-2026-07-22",
                "review_note_sha256": token * 4,
                "old_policy_sha256": token[::-1] * 4,
                "candidate_sha256": candidate,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        for action, operation_id, candidate in (
            ("create", "123e4567-e89b-42d3-a456-426614174030", "a" * 64),
            (
                "backdate_preview",
                "123e4567-e89b-42d3-a456-426614174031",
                "b" * 64,
            ),
            (
                "backdate_confirm",
                "123e4567-e89b-42d3-a456-426614174032",
                "b" * 64,
            ),
        )
    )
    portal_key_denials = (
        ("key.generate", "denied-membership", f"generate-membership-{token}"),
        ("key.deactivate", "denied-membership", f"deactivate-membership-{token}"),
        ("key.deactivate", "denied-ownership", f"deactivate-ownership-{token}"),
    )
    identity_natural_events = (
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.identity.audit",'
        '"action":"bootstrap_cleanup","outcome":"success","changed":true}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.identity.audit",'
        '"action":"break_glass_activate","outcome":"success"}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.identity.audit",'
        '"action":"break_glass_activate","outcome":"failed","error_type":"IdentityConflict"}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.identity.audit",'
        '"action":"break_glass_disable","outcome":"success"}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.identity.audit",'
        '"action":"break_glass_disable","outcome":"failed","error_type":"IdentityConflict"}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.identity.audit",'
        '"action":"ldap_check","outcome":"failed","error_type":"IdentityConflict",'
        '"ldap_provider":"corp-ad"}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.identity.audit",'
        f'"action":"ldap_drift_detected","outcome":"failed","ldap_provider":"corp-ad","operation_id":"{managed_drift_op}"}}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.identity.audit",'
        f'"action":"ldap_recovery","outcome":"success","ldap_provider":"corp-ad","operation_id":"{managed_drift_op}"}}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.identity.audit",'
        f'"action":"managed_identity_change_planned","outcome":"success","changed":true,"change_kind":"planned_change","operation_id":"{managed_planned_op}"}}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.identity.audit",'
        f'"action":"managed_identity_change_applied","outcome":"success","changed":true,"change_kind":"planned_change","operation_id":"{managed_planned_op}"}}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.identity.audit",'
        f'"action":"managed_identity_drift_detected","outcome":"failed","changed":true,"change_kind":"security_drift","operation_id":"{managed_drift_op}"}}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.identity.audit",'
        f'"action":"managed_identity_recovery","outcome":"success","changed":true,"change_kind":"security_drift","operation_id":"{managed_drift_op}"}}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.identity.audit",'
        f'"action":"group_create","outcome":"success","group":"identity-create-{token}","operation_id":"{identity_create_op}"}}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.identity.audit",'
        f'"action":"group_delete","outcome":"failed","error_type":"IdentityConflict","operation_id":"{identity_delete_op}"}}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.identity.audit",'
        f'"action":"group_member_add","outcome":"success","group":"identity-add-{token}","target_subject":"identity-target-add-{token}","operation_id":"{identity_add_op}"}}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.identity.audit",'
        f'"action":"group_member_remove","outcome":"success","group":"identity-remove-{token}","target_subject":"identity-target-remove-{token}","project":"receipt-project","operation_id":"{identity_remove_op}"}}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.identity.audit",'
        f'"action":"group_policy_update","outcome":"success","project":"receipt-project","operation_id":"{identity_policy_op}"}}',
    )
    rotations = (
        (
            'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.provider.rotation",'
            '"action":"start","outcome":"success","vendor":"anthropic",'
            f'"rotation_id":"{rotation_id}","rotation_status":"started"}}'
        ),
        (
            'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.provider.rotation",'
            '"action":"attempt","outcome":"failure","vendor":"anthropic",'
            f'"rotation_id":"{rotation_id}","attempt":1,"rotation_status":"failed"}}'
        ),
        (
            'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.provider.rotation",'
            '"action":"attempt","outcome":"success","vendor":"anthropic",'
            f'"rotation_id":"{rotation_id}","attempt":2,"rotation_status":"success"}}'
        ),
        (
            'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.provider.rotation",'
            '"action":"rotate","outcome":"success","vendor":"anthropic",'
            f'"rotation_id":"{rotation_id}","attempt":2,"rotation_status":"success"}}'
        ),
        (
            'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.provider.rotation",'
            '"action":"recovery","outcome":"success","vendor":"anthropic",'
            f'"rotation_id":"{rotation_id}","attempt":2,"rotation_status":"recovered"}}'
        ),
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
    model_limits = (
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.model.limit",'
        '"action":"reserve","outcome":"success","project":"receipt-project",'
        '"model":"claude-sonnet-4-5","control":"output_tokens_per_utc_minute",'
        '"reason":"capacity_reserved"}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.model.limit",'
        '"action":"deny","outcome":"denied","project":"receipt-project",'
        '"model":"claude-sonnet-4-5","control":"max_output_per_request",'
        '"reason":"request_cap_exceeded"}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.model.limit",'
        '"action":"deny","outcome":"denied","project":"receipt-project",'
        '"model":"claude-sonnet-4-5","control":"output_tokens_per_utc_minute",'
        '"reason":"minute_quota_exceeded"}',
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.model.limit",'
        '"action":"fail_closed","outcome":"failure","project":"receipt-project",'
        '"model":"claude-sonnet-4-5","control":"output_tokens_per_utc_minute",'
        '"reason":"redis_unavailable"}',
    )
    denied = (
        ("keycloak", keycloak_missing_user),
        ("keycloak", keycloak_unquoted),
        (
            "dev-portal",
            f"ADMITTED_ORDINARY_LOG_{token} "
            f"session_token=DOCKER_SESSION_SECRET_{token} "
            f"eyJkb2NrZXI.RG9ja2VyUGF5bG9hZA.RG9ja2VyU2lnbmF0dXJl{token} "
            f"hvs.DOCKER_VAULT_TOKEN_{token} "
            "-----BEGIN PRIVATE KEY-----\n"
            f"DOCKER_PEM_SECRET_{token}\n"
            "-----END PRIVATE KEY-----",
        ),
        (
            "admin-portal",
            'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.portal.audit",'
            '"action":"model.governance.create","outcome":"success",'
            f'"subject":"model-admin-{token}","model":"claude-sonnet-4-5",'
            f'"operation_id":"{portal_model_op}","marker":"DENIED_MODEL_PROVIDER_{token}"}}',
        ),
        (
            "admin-portal",
            'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.portal.audit",'
            '"action":"model.price.create","outcome":"success",'
            f'"subject":"price-admin-{token}","model":"claude-sonnet-4-5",'
            f'"usage_class":"unreviewed","operation_id":"{portal_price_op}",'
            f'"marker":"DENIED_MODEL_USAGE_CLASS_{token}"}}',
        ),
        (
            "admin-portal",
            'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.portal.audit",'
            '"action":"rotation.trigger","outcome":"success",'
            f'"subject":"model-admin-{token}","model":"claude-sonnet-4-5",'
            f'"marker":"DENIED_UNEXPECTED_MODEL_{token}"}}',
        ),
        (
            "litellm",
            'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.model.limit",'
            '"action":"reserve","outcome":"success","project":"receipt-project",'
            '"model":"claude-sonnet-4-5","control":"output_tokens_per_utc_minute",'
            '"reason":"capacity_reserved",'
            f'"prompt":"MODEL_LIMIT_PROMPT_SECRET_{token}",'
            f'"marker":"DENIED_MODEL_LIMIT_EXTRA_{token}"}}',
        ),
        (
            "litellm",
            'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.model.limit",'
            '"action":"deny","outcome":"success","project":"receipt-project",'
            '"model":"claude-sonnet-4-5","control":"max_output_per_request",'
            f'"reason":"request_cap_exceeded","marker":"DENIED_MODEL_LIMIT_OUTCOME_{token}"}}',
        ),
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
            'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.price.audit",'
            '"action":"create","outcome":"success",'
            f'"operation_id":"123e4567-e89b-42d3-a456-426614174033",'
            f'"subject":"trusted-price-{token}","model":"claude-sonnet-4-5",'
            '"provider":"anthropic","usage_class":"cache_read",'
            '"amount_usd":"30.000000000000","token_unit":"1000000",'
            '"effective_at":"2026-07-01T00:00:00Z",'
            '"source_reference":"anthropic-price-review-2026-07-22",'
            f'"review_note":"PRICE_REVIEW_NOTE_SECRET_{token}",'
            f'"review_note_sha256":"{token * 4}",'
            f'"old_policy_sha256":"{token[::-1] * 4}",'
            f'"candidate_sha256":"{"c" * 64}"}}',
        ),
        (
            "key-rotator",
            'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.provider.rotation",'
            '"action":"rotate","outcome":"success","vendor":"openai",'
            f'"rotation_id":"{rotation_id}","attempt":1,"rotation_status":"success",'
            f'"marker":"DENIED_VENDOR_{token}"}}',
        ),
        (
            "key-rotator",
            'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.provider.rotation",'
            '"action":"rotate","outcome":"success","vendor":"anthropic",'
            f'"rotation_id":"NOT-A-UUID","attempt":1,"rotation_status":"success",'
            f'"marker":"DENIED_ROTATION_ID_{token}"}}',
        ),
        (
            "key-rotator",
            'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.provider.rotation",'
            '"action":"attempt","outcome":"success","vendor":"anthropic",'
            f'"rotation_id":"{rotation_id}","attempt":"1","rotation_status":"success",'
            f'"marker":"DENIED_ROTATION_ATTEMPT_TYPE_{token}"}}',
        ),
        (
            "key-rotator",
            'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.provider.rotation",'
            '"action":"start","outcome":"success","vendor":"anthropic",'
            f'"rotation_id":"{rotation_id}","attempt":1,"rotation_status":"started",'
            f'"marker":"DENIED_ROTATION_START_ATTEMPT_{token}"}}',
        ),
        (
            "key-rotator",
            'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.provider.rotation",'
            '"action":"start","outcome":"failure","vendor":"anthropic",'
            f'"rotation_id":"{rotation_id}","rotation_status":"started",'
            f'"marker":"DENIED_ROTATION_START_OUTCOME_{token}"}}',
        ),
        (
            "key-rotator",
            'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.provider.rotation",'
            '"action":"recovery","outcome":"failure","vendor":"anthropic",'
            f'"rotation_id":"{rotation_id}","attempt":2,"rotation_status":"recovered",'
            f'"marker":"DENIED_ROTATION_RECOVERY_OUTCOME_{token}"}}',
        ),
        (
            "key-rotator",
            'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.provider.rotation",'
            '"action":"attempt","outcome":"failure","vendor":"anthropic",'
            f'"rotation_id":"{rotation_id}","attempt":2,"rotation_status":"success",'
            f'"marker":"DENIED_ROTATION_SUCCESS_OUTCOME_{token}"}}',
        ),
        (
            "key-rotator",
            'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.provider.rotation",'
            '"action":"rotate","outcome":"success","vendor":"anthropic",'
            f'"rotation_id":"{rotation_id}","attempt":2,"rotation_status":"failed",'
            f'"marker":"DENIED_ROTATION_FAILURE_OUTCOME_{token}"}}',
        ),
        (
            "admin-portal",
            'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.portal.audit",'
            '"action":"authorization.role.denied","outcome":"success",'
            f'"subject":"DENIED_PORTAL_OUTCOME_{token}"}}',
        ),
        (
            "admin-portal",
            'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.portal.audit",'
            '"action":"identity.group.create","outcome":"failed",'
            f'"subject":"DENIED_PORTAL_MUTATION_OUTCOME_{token}"}}',
        ),
        (
            "admin-portal",
            'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.portal.audit",'
            '"action":"authorization.step_up.required","outcome":"failure",'
            f'"subject":"DENIED_PORTAL_DETAIL_{token}","vendor":"anthropic"}}',
        ),
        (
            "admin-portal",
            'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.portal.audit",'
            '"action":"rotation.trigger","outcome":"denied-ownership",'
            f'"subject":"DENIED_OWNERSHIP_OTHER_ACTION_{token}"}}',
        ),
        (
            "dev-portal",
            'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.portal.audit",'
            '"action":"key.generate","outcome":"denied-ownership",'
            f'"subject":"DENIED_OWNERSHIP_GENERATE_{token}","project":"aigw-users"}}',
        ),
        (
            "admin-portal",
            'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.portal.audit",'
            '"action":"identity.group.create","outcome":"denied-membership",'
            f'"subject":"DENIED_MEMBERSHIP_OTHER_ACTION_{token}"}}',
        ),
        (
            "key-rotator",
            'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.identity.audit",'
            '"action":"bootstrap_cleanup","outcome":"failed","changed":true,'
            f'"project":"DENIED_BOOTSTRAP_OUTCOME_{token}"}}',
        ),
        (
            "key-rotator",
            'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.identity.audit",'
            '"action":"break_glass_activate","outcome":"failed",'
            f'"project":"DENIED_BREAK_GLASS_SCHEMA_{token}"}}',
        ),
        (
            "key-rotator",
            'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.identity.audit",'
            '"action":"ldap_check","outcome":"success","error_type":"IdentityConflict",'
            f'"ldap_provider":"DENIED_LDAP_CHECK_OUTCOME_{token}"}}',
        ),
        (
            "key-rotator",
            'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.identity.audit",'
            '"action":"ldap_recovery","outcome":"failed",'
            f'"ldap_provider":"DENIED_LDAP_RECOVERY_OUTCOME_{token}"}}',
        ),
        (
            "key-rotator",
            'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.identity.audit",'
            '"action":"managed_identity_recovery","outcome":"failed","changed":true,'
            f'"project":"DENIED_MANAGED_RECOVERY_{token}"}}',
        ),
        (
            "key-rotator",
            'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.identity.audit",'
            '"action":"deployment_converge","outcome":"success",'
            f'"changed":"true","project":"denied-changed-string-{token}"}}',
        ),
        (
            "key-rotator",
            'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.identity.audit",'
            '"action":"deployment_converge","outcome":"success",'
            f'"changed":null,"project":"denied-changed-null-{token}"}}',
        ),
        (
            "key-rotator",
            'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.identity.audit",'
            '"action":"deployment_converge","outcome":"success",'
            f'"changed":1,"project":"denied-changed-number-{token}"}}',
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
        docker_log_line("admin-portal", admin_portal, timestamp),
        docker_log_line("key-rotator", identity, timestamp),
        docker_log_line("key-rotator", identity_unchanged, timestamp),
        docker_log_line("key-rotator", identity_failure, timestamp),
        docker_log_line("key-rotator", break_glass, timestamp),
        docker_log_line("key-rotator", vault_state, timestamp),
        docker_log_line("envoy-egress", egress, timestamp),
        docker_log_line("envoy-egress", egress_tls, timestamp),
    ]
    records.extend(
        docker_log_line("key-rotator", rotation, timestamp)
        for rotation in rotations
    )
    records.extend(
        docker_log_line("litellm", event, timestamp) for event in model_limits
    )
    records.extend(
        docker_log_line("key-rotator", event, timestamp) for event in price_events
    )
    records.extend(
        docker_log_line("admin-portal", event, timestamp)
        for event in portal_natural_events
    )
    records.extend(
        docker_log_line(
            "dev-portal",
            'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.portal.audit",'
            f'"action":"{action}","outcome":"{outcome}","subject":"{subject}",'
            '"project":"aigw-users"}',
            timestamp,
        )
        for action, outcome, subject in portal_key_denials
    )
    records.extend(
        docker_log_line("key-rotator", event, timestamp)
        for event in identity_natural_events
    )
    records.extend(docker_log_line(service, message, timestamp) for service, message in denied)
    return "\n".join(records) + "\n"


def controller_lifecycle_file_identities() -> dict[Path, tuple[int, int]]:
    """Validate both stable fixture paths and return their exact identities."""

    try:
        directory = CONTROLLER_AUDIT_DIR.lstat()
    except OSError:
        fail("the generated preprod controller audit directory is unavailable")
    if (
        not stat.S_ISDIR(directory.st_mode)
        or stat.S_ISLNK(directory.st_mode)
        or directory.st_uid != os.geteuid()
        or directory.st_gid != os.getegid()
        or stat.S_IMODE(directory.st_mode) != 0o755
    ):
        fail("the generated preprod controller audit directory is unsafe")

    expected_files: dict[Path, tuple[int, int]] = {}
    for path in (CONTROLLER_AUDIT_CURRENT, CONTROLLER_AUDIT_ROTATED):
        try:
            metadata = path.lstat()
        except OSError:
            fail("a generated preprod controller audit file is unavailable")
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_gid != os.getegid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o644
        ):
            fail("a generated preprod controller audit file is unsafe")
        expected_files[path] = (metadata.st_dev, metadata.st_ino)
    return expected_files


def mutate_controller_lifecycle_fixtures(
    content_by_path: dict[Path, bytes],
) -> None:
    """Truncate both validated fixture files in place and optionally refill them."""

    paths = (CONTROLLER_AUDIT_CURRENT, CONTROLLER_AUDIT_ROTATED)
    if set(content_by_path) != set(paths):
        fail("the controller audit fixture mutation is incomplete")
    if any(len(content_by_path[path]) > 16 * 1024 for path in paths):
        fail("the controller audit fixture exceeded its fixed bound")

    expected_files = controller_lifecycle_file_identities()
    descriptors: dict[Path, int] = {}
    try:
        # Open and validate both paths before mutating either one. This keeps a
        # failed boundary check from partially changing Alloy's two sources.
        for path in paths:
            flags = os.O_WRONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(path, flags)
            except OSError:
                fail("a generated preprod controller audit file is unavailable")
            descriptors[path] = descriptor
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or (metadata.st_dev, metadata.st_ino) != expected_files[path]
                or metadata.st_uid != os.geteuid()
                or metadata.st_gid != os.getegid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o644
            ):
                fail("a generated preprod controller audit file is unsafe")

        for path in paths:
            descriptor = descriptors[path]
            content = content_by_path[path]
            os.ftruncate(descriptor, 0)
            if content:
                written = os.write(descriptor, content)
                if written != len(content):
                    fail("the controller audit fixture write was incomplete")
            os.fsync(descriptor)
    finally:
        for descriptor in descriptors.values():
            os.close(descriptor)


def empty_controller_lifecycle_fixtures() -> None:
    """Empty both Alloy sources without replacing or unlinking either path."""

    mutate_controller_lifecycle_fixtures(
        {
            CONTROLLER_AUDIT_CURRENT: b"",
            CONTROLLER_AUDIT_ROTATED: b"",
        }
    )


def write_controller_lifecycle_fixtures(token: str) -> None:
    """Write reviewed current/rotated controller records plus denied shapes."""

    timestamp = datetime.now(timezone.utc).isoformat(
        timespec="milliseconds"
    ).replace("+00:00", "Z")
    common = {
        "schema_version": 1,
        "event": "aigw.controller.lifecycle",
        "timestamp": timestamp,
        "egress_policy_sha256": token * 4,
        "envoy_image_id": "sha256:" + token * 4,
        "release_commit": token * 2 + token[:8],
        "release_manifest_sha256": token[::-1] * 4,
    }
    upgrade = {
        **common,
        "action": "upgrade",
        "outcome": "success",
        "operation_id": "123e4567-e89b-42d3-a456-426614174000",
    }
    rollback = {
        **common,
        "action": "rollback",
        "outcome": "failed",
        "operation_id": "123e4567-e89b-42d3-a456-426614174001",
    }
    extra = {**upgrade, "unexpected": f"DENIED_CONTROLLER_EXTRA_{token}"}
    unknown_action = {
        **upgrade,
        "action": f"DENIED_CONTROLLER_ACTION_{token}",
    }
    quoted_schema = {
        **upgrade,
        "schema_version": "1",
        "unexpected": f"DENIED_CONTROLLER_SCHEMA_TYPE_{token}",
    }
    missing_digest = dict(upgrade)
    del missing_digest["egress_policy_sha256"]
    missing_digest["unexpected"] = f"DENIED_CONTROLLER_MISSING_{token}"

    def encode(records: tuple[dict[str, object], ...]) -> bytes:
        return "".join(
            json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
            for record in records
        ).encode("ascii")

    mutate_controller_lifecycle_fixtures(
        {
            CONTROLLER_AUDIT_CURRENT: encode((upgrade, extra, unknown_action)),
            CONTROLLER_AUDIT_ROTATED: encode(
                (rollback, quoted_schema, missing_digest)
            ),
        }
    )


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
    before = wif_provider_request_count(preprod)
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
                "partial_key": "sk-" + secrets.token_hex(24),
            },
            separators=(",", ":"),
        ),
        sensitive=True,
    )
    if output.strip() != "LITELLM_REAL_REQUEST_ACCEPTED":
        fail("the real LiteLLM request helper returned an invalid receipt")
    after = wif_provider_request_count(preprod)
    if after != before + 1:
        fail("portal and partial-marker requests crossed the provider gate incorrectly")


def wif_provider_request_count(preprod: Preprod) -> int:
    helper = r'''import re
import urllib.request
text = urllib.request.urlopen(
    "http://wif-egress-mock:9902/stats/prometheus", timeout=5
).read(1048577).decode("utf-8")
match = re.search(
    r'^envoy_cluster_upstream_rq_total\{envoy_cluster_name="preprod_anthropic"\} ([0-9]+)$',
    text,
    re.MULTILINE,
)
if match is None:
    raise SystemExit("the preprod provider request counter is unavailable")
print(match.group(1))'''
    value = preprod.compose(
        "exec", "-T", "key-rotator", "/opt/venv/bin/python", "-c", helper
    ).strip()
    if re.fullmatch(r"[0-9]+", value) is None:
        fail("the preprod provider request counter was invalid")
    return int(value)


def send_openwebui_header_runtime_request(preprod: Preprod, token: str) -> None:
    before_rejections = wif_provider_request_count(preprod)
    rejected = preprod.compose(
        "exec",
        "-T",
        "open-webui",
        "python3",
        "-c",
        OPENWEBUI_HEADER_RUNTIME_REQUEST_HELPER,
        input_text=json.dumps(
            {"marker": token, "mode": "denied"}, separators=(",", ":")
        ),
        sensitive=True,
    )
    after_rejections = wif_provider_request_count(preprod)
    if rejected.strip() != "OPENWEBUI_INVALID_IDENTITY_REQUESTS_REJECTED":
        fail("the Open WebUI invalid-identity helper returned an invalid receipt")
    if after_rejections != before_rejections:
        fail("an invalid Open WebUI identity request reached the provider")

    accepted = preprod.compose(
        "exec",
        "-T",
        "open-webui",
        "python3",
        "-c",
        OPENWEBUI_HEADER_RUNTIME_REQUEST_HELPER,
        input_text=json.dumps(
            {"marker": token, "mode": "valid"}, separators=(",", ":")
        ),
        sensitive=True,
    )
    after_accepted = wif_provider_request_count(preprod)
    if accepted.strip() != "OPENWEBUI_HEADER_RUNTIME_REQUEST_ACCEPTED":
        fail("the Open WebUI header-runtime helper returned an invalid receipt")
    if after_accepted != after_rejections + 1:
        fail("the valid Open WebUI identity did not make exactly one provider request")


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
    fail("Cribl mock did not receive every admitted telemetry receipt")


def read_preprod_developer_password() -> str:
    """Read the fixed test password without following a replaced file."""

    try:
        before = PREPROD_DEVELOPER_PASSWORD_FILE.lstat()
    except OSError:
        fail("the generated preprod developer password is unavailable")
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_uid != os.geteuid()
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != 0o600
    ):
        fail("the generated preprod developer password file is unsafe")

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(PREPROD_DEVELOPER_PASSWORD_FILE, flags)
    except OSError:
        fail("the generated preprod developer password could not be opened")
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o600
        ):
            fail("the generated preprod developer password changed while opening")
        content = os.read(descriptor, 513)
    finally:
        os.close(descriptor)
    if not content.endswith(b"\n") or b"\n" in content[:-1] or len(content) > 512:
        fail("the generated preprod developer password is malformed")
    try:
        password = content[:-1].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        fail("the generated preprod developer password is not UTF-8")
    if not 12 <= len(password) <= 511:
        fail("the generated preprod developer password has an invalid length")
    return password


def natural_keycloak_events(
    raw_logs: str,
) -> tuple[str, str, tuple[str, str, str]] | None:
    """Return one coherent set of natural Keycloak event documents."""

    event_details: dict[str, tuple[str, str, str]] = {}
    for line in raw_logs.splitlines():
        try:
            document = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (
            not isinstance(document, dict)
            or document.get("log.logger") != "org.keycloak.events"
        ):
            continue
        message = document.get("message")
        if not isinstance(message, str):
            continue
        match = NATURAL_KEYCLOAK_EVENT.match(message)
        if match is None:
            continue
        event_details[match.group("event")] = (
            match.group("realm"),
            match.group("user"),
            line,
        )
    event_order = ("LOGIN", "LOGIN_ERROR", "LOGOUT")
    if set(event_details) != set(event_order):
        return None
    identities = {(detail[0], detail[1]) for detail in event_details.values()}
    if len(identities) != 1:
        fail("the natural Keycloak events did not identify one user and realm")
    realm_id, user_id = next(iter(identities))
    return realm_id, user_id, tuple(
        event_details[event][2] for event in event_order
    )


def natural_keycloak_receipts(raw_logs: str) -> tuple[str, str, str] | None:
    """Return the fixed Cribl projection expected for natural events."""

    events = natural_keycloak_events(raw_logs)
    if events is None:
        return None
    realm_id, user_id, _documents = events
    return tuple(
        "schema_version=1 event=aigw.keycloak.authentication "
        f"event_type={event} realm_id={realm_id} "
        f"client_id=dev-portal user_id={user_id}"
        for event in ("LOGIN", "LOGIN_ERROR", "LOGOUT")
    )


def set_natural_keycloak_fixture(
    preprod: Preprod,
    model: dict[str, Any],
    token: str,
    content: str | None,
) -> None:
    """Create or remove one test-only file containing real Keycloak logs."""

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
    if (
        labels.get(OWNER_LABEL) != PROJECT
        or labels.get("com.docker.compose.project") != PROJECT
    ):
        fail("the security fixture volume is not owned by preprod")

    writer_name = f"{PROJECT}-natural-keycloak-fixture-{token}"
    existing = preprod.docker(
        "container",
        "ls",
        "-a",
        "--filter",
        f"name=^{writer_name}$",
        "--format",
        "{{.ID}}",
    ).strip()
    if existing:
        fail("a stale natural Keycloak fixture writer exists")
    fixture_path = (
        f"/fixtures/aigw-security-fixtures/natural-keycloak-{token}-json.log"
    )
    if content is None:
        script = f"rm -f {fixture_path}; sync"
        input_text = None
    else:
        script = (
            "umask 022; mkdir -p /fixtures/aigw-security-fixtures; "
            f"test ! -e {fixture_path}; cat > {fixture_path}; "
            f"chmod 0644 {fixture_path}; sync"
        )
        input_text = content
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
        "--entrypoint",
        "/bin/sh",
        image,
        "-ceu",
        script,
        input_text=input_text,
        sensitive=True,
    )


def exercise_natural_keycloak_auth(
    preprod: Preprod, model: dict[str, Any]
) -> None:
    """Prove real password success, failure, and logout reach Cribl safely."""

    password = read_preprod_developer_password()
    since = log_cursor()
    success = run(
        [
            sys.executable,
            str(PORTAL_LOGIN_SCRIPT),
            "--ca",
            str(PREPROD_ROOT_CA_FILE),
            "--username",
            "preprod-developer",
            "--expect-path",
            "/",
            "--logout",
        ],
        input_text=password,
        sensitive=True,
    )
    if (
        "PORTAL_DIRECTORY_LOGIN_PASS username=preprod-developer result=/" not in success
        or "PORTAL_LOGOUT_PASS username=preprod-developer" not in success
    ):
        fail("the natural Keycloak success/logout flow returned an invalid receipt")

    wrong_password = "Wrong-" + secrets.token_urlsafe(24)
    denied = run(
        [
            sys.executable,
            str(PORTAL_LOGIN_SCRIPT),
            "--ca",
            str(PREPROD_ROOT_CA_FILE),
            "--username",
            "preprod-developer",
            "--expect-path",
            "denied",
        ],
        input_text=wrong_password,
        sensitive=True,
    )
    if "PORTAL_LOCAL_LOGIN_DENIED_PASS username=preprod-developer" not in denied:
        fail("the natural Keycloak failed-login flow returned an invalid receipt")

    keycloak = preprod.container_id("keycloak")
    deadline = time.monotonic() + 30
    events = None
    while time.monotonic() < deadline:
        raw_logs = preprod.docker(
            "logs", "--since", since, keycloak, include_stderr=True
        )
        events = natural_keycloak_events(raw_logs)
        if events is not None:
            break
        time.sleep(1)
    if events is None:
        fail("Keycloak did not emit the expected natural authentication events")

    realm_id, user_id, documents = events
    receipts = tuple(
        "schema_version=1 event=aigw.keycloak.authentication "
        f"event_type={event} realm_id={realm_id} "
        f"client_id=dev-portal user_id={user_id}"
        for event in ("LOGIN", "LOGIN_ERROR", "LOGOUT")
    )
    # Docker Desktop keeps json-file logs inside its Linux VM. Preprod does
    # not expose that private host path to Alloy. Copy the exact, naturally
    # emitted Keycloak JSON documents into the isolated log-test volume so
    # the real Alloy pipeline is exercised without granting host-log access.
    fixture_token = secrets.token_hex(8)
    fixture_timestamp = (
        datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    )
    fixture = "\n".join(
        docker_log_line("keycloak", document, fixture_timestamp)
        for document in documents
    ) + "\n"
    fixture_created = False
    try:
        set_natural_keycloak_fixture(preprod, model, fixture_token, fixture)
        fixture_created = True
        forwarded = wait_for_receipts(preprod, receipts, since)
    finally:
        if fixture_created:
            set_natural_keycloak_fixture(preprod, model, fixture_token, None)
    for raw_field in (
        "preprod-developer",
        "ipAddress",
        "realmId",
        "realmName",
        "clientId",
        "userId",
        "redirect_uri",
        "sessionId",
        "code_id",
        "authSessionParentId",
        "authSessionTabId",
        "invalid_user_credentials",
        "username=",
        "email=",
        "email:",
        "profile email",
        'type="LOGIN"',
        'type="LOGIN_ERROR"',
        'type="LOGOUT"',
        "log.logger",
    ):
        if raw_field in forwarded:
            fail("a raw Keycloak authentication field reached Cribl")
    print("KEYCLOAK_NATURAL_AUTH_EVENTS_ACCEPTED")


def assert_initial_receipts(logs: str, token: str) -> None:
    allowed = (
        f"allowed-ai-input-{token}",
        f"allowed-ai-output-{token}",
        f"real-ai-input-{token}",
        f"runtime-openwebui-ai-input-{token}",
        f"nested-call-{token}",
        f"ALLOWED_RECENT_PAST_TIMESTAMP_{token}",
        f"ALLOWED_CLOCK_SKEW_TIMESTAMP_{token}",
        f"REJECTED_OPENWEBUI_MISSING_JWT_{token}",
        f"REJECTED_OPENWEBUI_INVALID_JWT_{token}",
        f"REJECTED_OPENWEBUI_EXPIRED_JWT_{token}",
        f"REJECTED_OPENWEBUI_CONFLICTING_JWT_{token}",
        f"REJECTED_OPENWEBUI_PARTIAL_MARKER_{token}",
        "<redacted-credential>",
        "<redacted-authorization>",
        "<redacted-vendor-key>",
        "<redacted-jwt>",
        "<redacted-vault-token>",
        "<redacted-private-key>",
        f"SAFE_SESSION_COUNT_{token}",
        f"SAFE_VAULT_STATUS_{token}",
        f"SAFE_CLIENT_ASSERTIVENESS_{token}",
        f"SAFE_PUBLIC_KEY_{token}",
        f"SAFE_PRIVATE_KEY_WORDS_{token}",
        f"SAFE_CERTIFICATE_{token}",
        f"SAFE_PASSWORD_POLICY_{token}",
        f"SAFE_VAULT_WORDS_{token}",
        "jwt-like=eyJabc.def",
        "hvs.short",
        "s.short",
        "b.short",
        f"receipt-call-{token}",
        f"aigw.user.name: Str(receipt-user-{token})",
        f"aigw.user.name: Str(natural-portal-{token})",
        f"aigw.user.name: Str(natural.openwebui.{token})",
        "aigw.user.name_source: Str(portal_key_metadata)",
        "aigw.user.name_source: Str(open_webui_signed_oidc)",
        "aigw.security.event_class: Str(ai_request_audit)",
        "aigw.security.schema_version: Int(1)",
        "deployment.environment: Str(preprod)",
        "aigw.security.producer: Str(litellm)",
        "aigw.security.producer: Str(keycloak)",
        "aigw.security.producer: Str(dev-portal)",
        "aigw.security.producer: Str(admin-portal)",
        "aigw.security.producer: Str(key-rotator)",
        "aigw.security.producer: Str(envoy-egress)",
        "aigw.security.producer: Str(vault)",
        "aigw.security.producer: Str(controller)",
        "service.name: Str(litellm)",
        "service.name: Str(keycloak)",
        "service.name: Str(dev-portal)",
        "service.name: Str(admin-portal)",
        "service.name: Str(key-rotator)",
        "service.name: Str(envoy-egress)",
        "service.name: Str(vault)",
        "service.name: Str(controller)",
        f"event_type=LOGIN realm_id=aigw client_id=portal user_id=receipt-{token}",
        f"event=aigw.portal.audit action=rotation.trigger outcome=success subject=receipt-{token} vendor=anthropic",
        f"event=aigw.portal.audit action=rotation.settings.update outcome=success subject=admin-receipt-{token} vendor=anthropic",
        f"event=aigw.portal.audit action=authorization.role.denied outcome=failure subject=role-denied-{token}",
        f"event=aigw.portal.audit action=authorization.step_up.required outcome=failure subject=step-up-{token}",
        f"event=aigw.portal.audit action=identity.group.create outcome=intent subject=group-create-ok-{token} group=team-create-ok-{token} operation_id=123e4567-e89b-42d3-a456-426614174010",
        f"event=aigw.portal.audit action=identity.group.create outcome=success subject=group-create-ok-{token} group=team-create-ok-{token} operation_id=123e4567-e89b-42d3-a456-426614174010",
        f"event=aigw.portal.audit action=identity.group.delete outcome=intent subject=group-delete-fail-{token} group=team-delete-fail-{token} operation_id=123e4567-e89b-42d3-a456-426614174011",
        f"event=aigw.portal.audit action=identity.group.delete outcome=failure subject=group-delete-fail-{token} group=team-delete-fail-{token} operation_id=123e4567-e89b-42d3-a456-426614174011",
        f"event=aigw.portal.audit action=identity.member.add outcome=intent subject=member-add-unknown-{token} group=team-add-unknown-{token} target_subject=target-add-unknown-{token} operation_id=123e4567-e89b-42d3-a456-426614174012",
        f"event=aigw.portal.audit action=identity.member.add outcome=indeterminate subject=member-add-unknown-{token} group=team-add-unknown-{token} target_subject=target-add-unknown-{token} operation_id=123e4567-e89b-42d3-a456-426614174012",
        f"event=aigw.portal.audit action=identity.member.remove outcome=intent subject=member-remove-ok-{token} group=team-remove-ok-{token} target_subject=target-remove-ok-{token} operation_id=123e4567-e89b-42d3-a456-426614174013",
        f"event=aigw.portal.audit action=identity.member.remove outcome=success subject=member-remove-ok-{token} group=team-remove-ok-{token} target_subject=target-remove-ok-{token} project=receipt-project operation_id=123e4567-e89b-42d3-a456-426614174013",
        f"event=aigw.portal.audit action=identity.group.policy outcome=intent subject=group-policy-ok-{token} group=team-policy-ok-{token} operation_id=123e4567-e89b-42d3-a456-426614174014",
        f"event=aigw.portal.audit action=identity.group.policy outcome=success subject=group-policy-ok-{token} group=team-policy-ok-{token} project=receipt-project operation_id=123e4567-e89b-42d3-a456-426614174014",
        f"event=aigw.portal.audit action=model.governance.create outcome=intent subject=model-admin-{token} model=claude-sonnet-4-5 provider=anthropic operation_id=123e4567-e89b-42d3-a456-426614174015",
        f"event=aigw.portal.audit action=model.governance.create outcome=success subject=model-admin-{token} model=claude-sonnet-4-5 provider=anthropic operation_id=123e4567-e89b-42d3-a456-426614174015",
        f"event=aigw.portal.audit action=model.governance.activate outcome=intent subject=model-admin-{token} model=claude-sonnet-4-5 operation_id=123e4567-e89b-42d3-a456-426614174019",
        f"event=aigw.portal.audit action=model.governance.activate outcome=success subject=model-admin-{token} model=claude-sonnet-4-5 operation_id=123e4567-e89b-42d3-a456-426614174019",
        f"event=aigw.portal.audit action=model.price.create outcome=intent subject=price-admin-{token} model=claude-sonnet-4-5 usage_class=cache_read operation_id=123e4567-e89b-42d3-a456-426614174016",
        f"event=aigw.portal.audit action=model.price.create outcome=success subject=price-admin-{token} model=claude-sonnet-4-5 usage_class=cache_read operation_id=123e4567-e89b-42d3-a456-426614174016",
        f"event=aigw.portal.audit action=model.price.backdate.preview outcome=intent subject=price-admin-{token} model=claude-sonnet-4-5 usage_class=cache_read operation_id=123e4567-e89b-42d3-a456-426614174017",
        f"event=aigw.portal.audit action=model.price.backdate.preview outcome=success subject=price-admin-{token} model=claude-sonnet-4-5 usage_class=cache_read operation_id=123e4567-e89b-42d3-a456-426614174017",
        f"event=aigw.portal.audit action=model.price.backdate.confirm outcome=intent subject=price-admin-{token} operation_id=123e4567-e89b-42d3-a456-426614174018",
        f"event=aigw.portal.audit action=model.price.backdate.confirm outcome=success subject=price-admin-{token} model=claude-sonnet-4-5 usage_class=cache_read operation_id=123e4567-e89b-42d3-a456-426614174018",
        f"event=aigw.price.audit action=create outcome=success subject=trusted-price-{token} model=claude-sonnet-4-5 provider=anthropic usage_class=cache_read amount_usd=30.000000000000 token_unit=1000000 effective_at=2026-07-01T00:00:00Z source_reference=anthropic-price-review-2026-07-22 review_note_sha256={token * 4} old_policy_sha256={token[::-1] * 4} candidate_sha256={'a' * 64} operation_id=123e4567-e89b-42d3-a456-426614174030",
        f"event=aigw.price.audit action=backdate_preview outcome=success subject=trusted-price-{token} model=claude-sonnet-4-5 provider=anthropic usage_class=cache_read amount_usd=30.000000000000 token_unit=1000000 effective_at=2026-07-01T00:00:00Z source_reference=anthropic-price-review-2026-07-22 review_note_sha256={token * 4} old_policy_sha256={token[::-1] * 4} candidate_sha256={'b' * 64} operation_id=123e4567-e89b-42d3-a456-426614174031",
        f"event=aigw.price.audit action=backdate_confirm outcome=success subject=trusted-price-{token} model=claude-sonnet-4-5 provider=anthropic usage_class=cache_read amount_usd=30.000000000000 token_unit=1000000 effective_at=2026-07-01T00:00:00Z source_reference=anthropic-price-review-2026-07-22 review_note_sha256={token * 4} old_policy_sha256={token[::-1] * 4} candidate_sha256={'b' * 64} operation_id=123e4567-e89b-42d3-a456-426614174032",
        f"event=aigw.portal.audit action=key.generate outcome=denied-membership subject=generate-membership-{token} project=aigw-users",
        f"event=aigw.portal.audit action=key.deactivate outcome=denied-membership subject=deactivate-membership-{token} project=aigw-users",
        f"event=aigw.portal.audit action=key.deactivate outcome=denied-ownership subject=deactivate-ownership-{token} project=aigw-users",
        f"event=aigw.identity.audit action=deployment_converge outcome=success project=receipt-{token} changed=true",
        f"event=aigw.identity.audit action=deployment_converge outcome=success project=unchanged-{token} changed=false",
        f"event=aigw.identity.audit action=deployment_converge outcome=failed project=failed-{token} error_type=ReceiptFailure",
        "event=aigw.identity.audit action=break_glass_use outcome=success purpose=deployment_converge",
        "event=aigw.identity.audit action=bootstrap_cleanup outcome=success changed=true",
        "event=aigw.identity.audit action=break_glass_activate outcome=success",
        "event=aigw.identity.audit action=break_glass_activate outcome=failed error_type=IdentityConflict",
        "event=aigw.identity.audit action=break_glass_disable outcome=success",
        "event=aigw.identity.audit action=break_glass_disable outcome=failed error_type=IdentityConflict",
        "event=aigw.identity.audit action=ldap_check outcome=failed error_type=IdentityConflict ldap_provider=corp-ad",
        "event=aigw.identity.audit action=ldap_drift_detected outcome=failed operation_id=123e4567-e89b-42d3-a456-426614174026 ldap_provider=corp-ad",
        "event=aigw.identity.audit action=ldap_recovery outcome=success operation_id=123e4567-e89b-42d3-a456-426614174026 ldap_provider=corp-ad",
        "event=aigw.identity.audit action=managed_identity_change_planned outcome=success changed=true change_kind=planned_change operation_id=123e4567-e89b-42d3-a456-426614174025",
        "event=aigw.identity.audit action=managed_identity_change_applied outcome=success changed=true change_kind=planned_change operation_id=123e4567-e89b-42d3-a456-426614174025",
        "event=aigw.identity.audit action=managed_identity_drift_detected outcome=failed changed=true change_kind=security_drift operation_id=123e4567-e89b-42d3-a456-426614174026",
        "event=aigw.identity.audit action=managed_identity_recovery outcome=success changed=true change_kind=security_drift operation_id=123e4567-e89b-42d3-a456-426614174026",
        f"event=aigw.identity.audit action=group_create outcome=success group=identity-create-{token} operation_id=123e4567-e89b-42d3-a456-426614174020",
        "event=aigw.identity.audit action=group_delete outcome=failed operation_id=123e4567-e89b-42d3-a456-426614174021 error_type=IdentityConflict",
        f"event=aigw.identity.audit action=group_member_add outcome=success group=identity-add-{token} target_subject=identity-target-add-{token} operation_id=123e4567-e89b-42d3-a456-426614174022",
        f"event=aigw.identity.audit action=group_member_remove outcome=success group=identity-remove-{token} target_subject=identity-target-remove-{token} project=receipt-project operation_id=123e4567-e89b-42d3-a456-426614174023",
        "event=aigw.identity.audit action=group_policy_update outcome=success project=receipt-project operation_id=123e4567-e89b-42d3-a456-426614174024",
        "event=aigw.provider.rotation action=start outcome=success vendor=anthropic rotation_id=123e4567-e89b-42d3-a456-426614174000 rotation_status=started",
        "event=aigw.provider.rotation action=attempt outcome=failure vendor=anthropic rotation_id=123e4567-e89b-42d3-a456-426614174000 attempt=1 rotation_status=failed",
        "event=aigw.provider.rotation action=attempt outcome=success vendor=anthropic rotation_id=123e4567-e89b-42d3-a456-426614174000 attempt=2 rotation_status=success",
        "event=aigw.provider.rotation action=rotate outcome=success vendor=anthropic rotation_id=123e4567-e89b-42d3-a456-426614174000 attempt=2 rotation_status=success",
        "event=aigw.provider.rotation action=recovery outcome=success vendor=anthropic rotation_id=123e4567-e89b-42d3-a456-426614174000 attempt=2 rotation_status=recovered",
        "event=aigw.vault.state action=state_observed outcome=success state=unsealed",
        "event=aigw.model.limit action=reserve outcome=success model=claude-sonnet-4-5 control=output_tokens_per_utc_minute project=receipt-project reason=capacity_reserved",
        "event=aigw.model.limit action=deny outcome=denied model=claude-sonnet-4-5 control=max_output_per_request project=receipt-project reason=request_cap_exceeded",
        "event=aigw.model.limit action=deny outcome=denied model=claude-sonnet-4-5 control=output_tokens_per_utc_minute project=receipt-project reason=minute_quota_exceeded",
        "event=aigw.model.limit action=fail_closed outcome=failure model=claude-sonnet-4-5 control=output_tokens_per_utc_minute project=receipt-project reason=redis_unavailable",
        "event=aigw.vault.audit",
        "hmac_protected=true",
        f"event=aigw.controller.lifecycle action=upgrade outcome=success operation_id=123e4567-e89b-42d3-a456-426614174000 release_manifest_sha256={token[::-1] * 4} release_commit={token * 2 + token[:8]} envoy_image_id=sha256:{token * 4} egress_policy_sha256={token * 4}",
        f"event=aigw.controller.lifecycle action=rollback outcome=failed operation_id=123e4567-e89b-42d3-a456-426614174001 release_manifest_sha256={token[::-1] * 4} release_commit={token * 2 + token[:8]} envoy_image_id=sha256:{token * 4} egress_policy_sha256={token * 4}",
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
        f"SESSION_TOKEN_SECRET_{token}",
        f"VAULT_UNSEAL_SECRET_{token}",
        f"CLIENT_ASSERTION_SECRET_{token}",
        f"QUOTED_MULTIWORD_INPUT_{token}",
        f"ESCAPED_MULTIWORD_INPUT_{token}",
        f"QUOTED_MULTIWORD_OUTPUT_{token}",
        f"QUOTED_MULTIWORD_LEGACY_PROMPT_{token}",
        f"ESCAPED_MULTIWORD_LEGACY_COMPLETION_{token}",
        "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2lnbmF0dXJlMTIzNDU2",
        "hvs.ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
        "s.ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
        "b.ZYXWVUTSRQPONMLKJIHGFEDCBA543210",
        f"PEM_SECRET_{token}",
        f"DSA_PEM_SECRET_{token}",
        f"ENCRYPTED_PEM_SECRET_{token}",
        f"TRUNCATED_PEM_SECRET_{token}",
        f"DOCKER_SESSION_SECRET_{token}",
        f"RG9ja2VyU2lnbmF0dXJl{token}",
        f"hvs.DOCKER_VAULT_TOKEN_{token}",
        f"DOCKER_PEM_SECRET_{token}",
        f"METADATA_HEADERS_SECRET_{token}",
        f"METADATA_REQUEST_HEADERS_SECRET_{token}",
        f"REQUEST_HEADERS_SECRET_{token}",
        f"FORGED_ENDUSER_{token}",
        f"FORGED_ALIAS_{token}",
        f"FORGED_AUTH_NAME_{token}",
        f"FORGED_NORMALIZED_NAME_{token}",
        f"FORGED_PREEXISTING_NAME_{token}",
        f"FORGED_BODY_USER_{token}",
        f"FORGED_PLAIN_HEADER_USER_{token}",
        f"FORGED_OPENWEBUI_BODY_USER_{token}",
        f"FORGED_OPENWEBUI_PLAIN_USER_{token}",
        f"NESTED_PROMPT_ARRAY_SECRET_{token}",
        f"NESTED_PROMPT_MAP_SECRET_{token}",
        f"KEYCLOAK_SECRET_{token}",
        f"DENIED_KEYCLOAK_IP_{token}",
        f"DENIED_KEYCLOAK_USERNAME_{token}",
        f"DENIED_KEYCLOAK_EMAIL_{token}",
        f"DENIED_KEYCLOAK_UNQUOTED_{token}",
        f"PORTAL_SECRET_{token}",
        f"UNAPPROVED_FIELD_{token}",
        f"NESTED_SECRET_{token}",
        f"DENIED_SCHEMA_{token}",
        f"DENIED_ACTION_{token}",
        f"DENIED_VENDOR_{token}",
        f"DENIED_ROTATION_ID_{token}",
        f"DENIED_ROTATION_ATTEMPT_TYPE_{token}",
        f"DENIED_ROTATION_START_ATTEMPT_{token}",
        f"DENIED_ROTATION_START_OUTCOME_{token}",
        f"DENIED_ROTATION_RECOVERY_OUTCOME_{token}",
        f"DENIED_ROTATION_SUCCESS_OUTCOME_{token}",
        f"DENIED_ROTATION_FAILURE_OUTCOME_{token}",
        f"DENIED_PORTAL_OUTCOME_{token}",
        f"DENIED_PORTAL_MUTATION_OUTCOME_{token}",
        f"DENIED_PORTAL_DETAIL_{token}",
        f"DENIED_OWNERSHIP_OTHER_ACTION_{token}",
        f"DENIED_OWNERSHIP_GENERATE_{token}",
        f"DENIED_MEMBERSHIP_OTHER_ACTION_{token}",
        f"DENIED_BOOTSTRAP_OUTCOME_{token}",
        f"DENIED_BREAK_GLASS_SCHEMA_{token}",
        f"DENIED_LDAP_CHECK_OUTCOME_{token}",
        f"DENIED_LDAP_RECOVERY_OUTCOME_{token}",
        f"DENIED_MANAGED_RECOVERY_{token}",
        f"DENIED_MODEL_PROVIDER_{token}",
        f"DENIED_MODEL_USAGE_CLASS_{token}",
        f"DENIED_UNEXPECTED_MODEL_{token}",
        f"PRICE_REVIEW_NOTE_SECRET_{token}",
        f"MODEL_LIMIT_PROMPT_SECRET_{token}",
        f"DENIED_MODEL_LIMIT_EXTRA_{token}",
        f"DENIED_MODEL_LIMIT_OUTCOME_{token}",
        f"DENIED_VAULT_STATE_{token}",
        f"DENIED_MALFORMED_{token}",
        f"DENIED_CONTROLLER_EXTRA_{token}",
        f"DENIED_CONTROLLER_ACTION_{token}",
        f"DENIED_CONTROLLER_SCHEMA_TYPE_{token}",
        f"DENIED_CONTROLLER_MISSING_{token}",
        f"DENIED_UNTRUSTED_SOURCE_{token}",
        f"FORGED_AUTH_MARKER_{token}",
        f"FORGED_PRODUCER_{token}",
        f"FORGED_LOG_ENV_{token}",
        f"FORGED_LOG_SERVICE_{token}",
        f"FORGED_RESOURCE_ENV_{token}",
        f"FORGED_METRIC_ENV_{token}",
        f"METRIC_RESOURCE_SECRET_{token}",
        f"METRIC_SCOPE_SECRET_{token}",
        f"METRIC_POINT_SECRET_{token}",
        f"FORGED_OTLP_LOG_ENV_{token}",
        f"OTLP_LOG_RESOURCE_SECRET_{token}",
        f"OTLP_LOG_BODY_SECRET_{token}",
        f"FORGED_BODY_PRODUCER_{token}",
        f"FORGED_BODY_ENV_{token}",
        f"FORGED_BODY_SERVICE_{token}",
        "aigw.security.source_time_unix_nano",
        f"denied-changed-string-{token}",
        f"denied-changed-null-{token}",
        f"denied-changed-number-{token}",
        f"untrusted-call-{token}",
        f"DENIED_KEYCLOAK_MISSING_USER_{token}",
        "provider=openai reason=tls_transport_failure",
    )
    leaked = [marker for marker in forbidden if marker in logs]
    if leaked:
        fail("Cribl received a secret or a rejected structured record")


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


def cribl_queue_sizes(metrics: str) -> dict[str, float]:
    matches: dict[str, float] = {}
    for line in metrics.splitlines():
        if not line.startswith("otelcol_exporter_queue_size{"):
            continue
        labels, separator, value = line.rpartition(" ")
        if not separator:
            continue
        if 'component_id="otelcol.exporter.otlp.cribl"' not in labels:
            continue
        signal = next(
            (
                candidate
                for candidate in ("logs", "metrics", "traces")
                if f'data_type="{candidate}"' in labels
            ),
            None,
        )
        if signal is None or signal in matches:
            fail("Alloy returned an ambiguous Cribl queue metric")
        try:
            matches[signal] = float(value)
        except ValueError:
            fail("Alloy returned an invalid Cribl queue metric")
    if set(matches) != {"logs", "metrics", "traces"}:
        fail("Alloy did not expose all three Cribl signal queue metrics")
    return matches


def wait_for_queue(preprod: Preprod, model: dict[str, Any], *, populated: bool) -> None:
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        sizes = cribl_queue_sizes(read_alloy_metrics(preprod, model))
        if (populated and all(size > 0 for size in sizes.values())) or (
            not populated and all(size == 0 for size in sizes.values())
        ):
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
    parser.add_argument("--postgres-major", choices=("16", "18"), default="18")
    parser.add_argument("--confirm-postgres16-rehearsal", action="store_true")
    args = parser.parse_args()
    if (args.postgres_major == "16") != args.confirm_postgres16_rehearsal:
        fail("PostgreSQL 16 acceptance requires its fixed rehearsal confirmation")
    token = secrets.token_hex(8)
    tls_token = secrets.token_hex(8)
    outage_token = secrets.token_hex(8)

    preprod = Preprod(args.image_mode, args.postgres_major)
    preprod_arguments = [
        sys.executable,
        str(ROOT / "scripts/preprod.py"),
        "--image-mode",
        args.image_mode,
        "--postgres-major",
        args.postgres_major,
    ]
    if args.postgres_major == "16":
        preprod_arguments.append("--confirm-postgres16-rehearsal")
    # Reuse the main preprod guard before this script performs any mutation.
    guard = run([*preprod_arguments, "compose-config"])
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
            *preprod_arguments,
            "verify",
        ]
    )
    if "PREPROD_VERIFIED" not in verification:
        fail("the live Vault audit receipt could not be generated")
    exercise_natural_keycloak_auth(preprod, model)
    write_log_fixtures(preprod, model, token)
    try:
        write_controller_lifecycle_fixtures(token)
        send_otlp_fixtures(
            preprod, OTLP_FIXTURE_HELPER, token, "OTLP_FIXTURES_ACCEPTED"
        )
        send_otlp_fixtures(
            preprod,
            OTLP_SPOOF_HELPER,
            token,
            "OTLP_SPOOF_REJECTED",
            service="key-rotator",
        )
        send_real_litellm_request(preprod, token)
        send_openwebui_header_runtime_request(preprod, token)
        logs = wait_for_receipts(
            preprod,
            (
                f"allowed-ai-input-{token}",
                f"ADMITTED_SANITIZED_TRACE_{token}",
                f"ADMITTED_UNATTRIBUTED_TRACE_{token}",
                f"admitted_metric_{token}",
                f"ADMITTED_LOG_{token}",
                f"ADMITTED_ORDINARY_LOG_{token}",
                f"real-ai-input-{token}",
                f"runtime-openwebui-ai-input-{token}",
                f"aigw.user.name: Str(natural-portal-{token})",
                f"aigw.user.name: Str(natural.openwebui.{token})",
                "aigw.user.name_source: Str(open_webui_signed_oidc)",
                f"nested-call-{token}",
                f"ALLOWED_RECENT_PAST_TIMESTAMP_{token}",
                f"ALLOWED_CLOCK_SKEW_TIMESTAMP_{token}",
                f"event_type=LOGIN realm_id=aigw client_id=portal user_id=receipt-{token}",
                f"event=aigw.portal.audit action=rotation.trigger outcome=success subject=receipt-{token}",
                f"event=aigw.portal.audit action=authorization.role.denied outcome=failure subject=role-denied-{token}",
                f"event=aigw.portal.audit action=key.deactivate outcome=denied-ownership subject=deactivate-ownership-{token}",
                f"event=aigw.identity.audit action=deployment_converge outcome=success project=receipt-{token}",
                f"event=aigw.identity.audit action=deployment_converge outcome=success project=unchanged-{token} changed=false",
                "event=aigw.identity.audit action=ldap_recovery outcome=success operation_id=123e4567-e89b-42d3-a456-426614174026 ldap_provider=corp-ad",
                "event=aigw.identity.audit action=managed_identity_change_applied outcome=success changed=true change_kind=planned_change operation_id=123e4567-e89b-42d3-a456-426614174025",
                "event=aigw.provider.rotation action=start outcome=success vendor=anthropic",
                "event=aigw.provider.rotation action=attempt outcome=failure vendor=anthropic",
                "event=aigw.provider.rotation action=rotate outcome=success vendor=anthropic",
                "event=aigw.provider.rotation action=recovery outcome=success vendor=anthropic",
                "event=aigw.vault.state action=state_observed outcome=success state=unsealed",
                "event=aigw.model.limit action=reserve outcome=success model=claude-sonnet-4-5 control=output_tokens_per_utc_minute project=receipt-project reason=capacity_reserved",
                "event=aigw.vault.audit",
                "event=aigw.controller.lifecycle action=upgrade outcome=success",
                "event=aigw.controller.lifecycle action=rollback outcome=failed",
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
    finally:
        empty_controller_lifecycle_fixtures()

    print("PREPROD_CRIBL_TELEMETRY_PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
