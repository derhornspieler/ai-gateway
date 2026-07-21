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


OTLP_FIXTURE_HELPER = r"""
import http.client
import json
import sys
import time

test = json.load(sys.stdin)
token = test["token"]
now = str(time.time_ns())

def text(key, value):
    return {"key": key, "value": {"stringValue": value}}

def integer(key, value):
    return {"key": key, "value": {"intValue": str(value)}}

def post(path, document):
    body = json.dumps(document, separators=(",", ":"))
    connection = http.client.HTTPConnection("alloy", 4318, timeout=10)
    connection.request(
        "POST", path, body=body, headers={"Content-Type": "application/json"}
    )
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
        text("gen_ai.input.messages", "allowed-ai-input-" + token),
        text("gen_ai.output.messages", "allowed-ai-output-" + token),
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
post(
    "/v1/traces",
    {
        "resourceSpans": [{
            "resource": {"attributes": [text("service.name", "litellm")]},
            "scopeSpans": [{
                "scope": {"name": "aigw.preprod.receipt"},
                "spans": [allowed_span, denied_span],
            }],
        }]
    },
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
import sys
import time

test = json.load(sys.stdin)
token = test["token"]

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
    connection = http.client.HTTPConnection("alloy", 4318, timeout=10)
    body = json.dumps(document, separators=(",", ":"))
    connection.request(
        "POST", "/v1/traces", body=body,
        headers={"Content-Type": "application/json"},
    )
    response = connection.getresponse()
    response.read(1048577)
    connection.close()
    if response.status != 200:
        raise SystemExit("OTLP receiver rejected an outage fixture")
    time.sleep(1.2)
print("OTLP_OUTAGE_FIXTURES_ACCEPTED")
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
    portal = (
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.portal.audit",'
        '"action":"rotation.trigger","outcome":"success",'
        f'"subject":"receipt-{token}","note":"Bearer PORTAL_SECRET_{token}"}}'
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
        f'"purpose":"deployment_converge","receipt":"break-glass-{token}"}}'
    )
    rotation = (
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.provider.rotation",'
        '"action":"rotate","outcome":"success","vendor":"anthropic",'
        f'"rotation_status":"success","receipt":"rotation-{token}"}}'
    )
    vault_state = (
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.vault.state",'
        '"action":"state_observed","outcome":"success","state":"unsealed",'
        f'"receipt":"vault-state-{token}"}}'
    )
    egress = (
        'AIGW_SECURITY_EVENT {"schema_version":1,"event":"aigw.egress.trust",'
        '"action":"startup_gate","outcome":"success",'
        f'"policy_sha256":"{token * 4}"}}'
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


def send_otlp_fixtures(preprod: Preprod, helper: str, token: str, marker: str) -> None:
    output = preprod.compose(
        "exec",
        "-T",
        "key-rotator",
        "/opt/venv/bin/python",
        "-c",
        helper,
        input_text=json.dumps({"token": token}, separators=(",", ":")),
        sensitive=True,
    )
    if output.strip() != marker:
        fail("the OTLP fixture helper returned an invalid receipt")


def cribl_logs(preprod: Preprod) -> str:
    identifier = preprod.container_id("cribl-mock")
    return preprod.docker(
        "logs", "--tail", "8000", identifier, include_stderr=True
    )


def wait_for_receipts(preprod: Preprod, markers: tuple[str, ...], timeout: int = 45) -> str:
    deadline = time.monotonic() + timeout
    latest = ""
    while time.monotonic() < deadline:
        latest = cribl_logs(preprod)
        if all(marker in latest for marker in markers):
            return latest
        time.sleep(1)
    fail("Cribl mock did not receive every approved security record")


def assert_initial_receipts(logs: str, token: str) -> None:
    allowed = (
        f"allowed-ai-input-{token}",
        f"allowed-ai-output-{token}",
        f"receipt-call-{token}",
        "aigw.security.event_class: Str(ai_request_audit)",
        f"event_type=LOGIN realm_id=aigw client_id=portal user_id=receipt-{token}",
        '"event":"aigw.portal.audit"',
        '"action":"rotation.trigger"',
        '"note":"Bearer <redacted-authorization>"',
        '"event":"aigw.identity.audit"',
        f'"project":"receipt-{token}"',
        f'"project":"failed-{token}"',
        f'"receipt":"break-glass-{token}"',
        '"event":"aigw.provider.rotation"',
        f'"receipt":"rotation-{token}"',
        '"event":"aigw.vault.state"',
        f'"receipt":"vault-state-{token}"',
        "event=aigw.vault.audit",
        "hmac_protected=true",
        '"event":"aigw.egress.trust"',
        f'"policy_sha256":"{token * 4}"',
        "event=aigw.egress.trust action=upstream_tls_failure outcome=failed provider=anthropic reason=tls_transport_failure",
    )
    missing = [marker for marker in allowed if marker not in logs]
    if missing:
        fail("the Cribl receipt is missing one or more approved fields")
    forbidden = (
        f"TRACE_SECRET_{token}",
        f"KEYCLOAK_SECRET_{token}",
        f"PORTAL_SECRET_{token}",
        f"DENIED_ORDINARY_LOG_{token}",
        f"DENIED_SCHEMA_{token}",
        f"DENIED_ACTION_{token}",
        f"DENIED_VENDOR_{token}",
        f"DENIED_VAULT_STATE_{token}",
        f"DENIED_MALFORMED_{token}",
        f"DENIED_RAW_TRACE_{token}",
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
        if marker in cribl_logs(preprod):
            fail("Alloy accepted a Cribl certificate with the wrong server name")

        replace_test_certificate(CRIBL_CERT, original_cert)
        replace_test_certificate(CRIBL_KEY, original_key)
        restored = True
        recreate_cribl(preprod)
        wait_for_receipts(preprod, (marker,))
        wait_for_queue(preprod, model, populated=False)
    finally:
        if replaced and not restored:
            replace_test_certificate(CRIBL_CERT, original_cert)
            replace_test_certificate(CRIBL_KEY, original_key)
            recreate_cribl(preprod)


def exercise_outage_recovery(preprod: Preprod, model: dict[str, Any], token: str) -> None:
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
        wait_for_receipts(preprod, (f"queued-ai-input-{token}-0",))
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

    write_log_fixtures(preprod, model, token)
    send_otlp_fixtures(preprod, OTLP_FIXTURE_HELPER, token, "OTLP_FIXTURES_ACCEPTED")
    logs = wait_for_receipts(
        preprod,
        (
            f"allowed-ai-input-{token}",
            f"event_type=LOGIN realm_id=aigw client_id=portal user_id=receipt-{token}",
            f'"subject":"receipt-{token}"',
            f'"project":"receipt-{token}"',
            f'"receipt":"rotation-{token}"',
            f'"receipt":"vault-state-{token}"',
            "event=aigw.vault.audit",
            f'"policy_sha256":"{token * 4}"',
            "event=aigw.egress.trust action=upstream_tls_failure",
        ),
    )
    # One extra file-source interval proves denied records did not merely lag.
    time.sleep(12)
    assert_initial_receipts(cribl_logs(preprod), token)
    exercise_tls_server_name_failure(preprod, model, tls_token)
    exercise_outage_recovery(preprod, model, outage_token)

    print("PREPROD_CRIBL_SECURITY_FEED_PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
