#!/usr/bin/env python3
"""Exercise per-project, per-model output limits in local PreProd."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
COMPOSE_DIR = ROOT / "compose"
ENV_FILE = COMPOSE_DIR / "secrets/preprod.env"
SEED_OVERLAY = COMPOSE_DIR / "secrets/preprod-seed-images.yml"
POSTGRES16_OVERLAY = COMPOSE_DIR / "docker-compose.preprod-postgres16.yml"
PROJECT = "aigw-preprod"
OWNER_LABEL = "com.aigw.preprod.project"
MODEL = "claude-sonnet-4-5"
MAX_OUTPUT = 8
OUTPUTS_PER_MINUTE = 12
MAX_COMMAND_OUTPUT = 1024 * 1024


REQUEST_HELPER = r"""
import http.client
import json
import sys

item = json.load(sys.stdin)
headers = {
    "Authorization": "Bearer " + item["bearer"],
    "Content-Type": "application/json",
}
body = json.dumps(item["body"], separators=(",", ":"))
connection = http.client.HTTPConnection("litellm", 4000, timeout=30)
connection.request("POST", item["path"], body=body, headers=headers)
response = connection.getresponse()
raw = response.read(1048577)
status = response.status
connection.close()
if len(raw) > 1048576:
    raise SystemExit("LiteLLM response exceeded 1 MiB")
try:
    document = json.loads(raw)
except json.JSONDecodeError:
    raise SystemExit("LiteLLM returned invalid JSON")
print(json.dumps({"status": status, "body": document}, separators=(",", ":")))
""".strip()


PROVIDER_COUNT_HELPER = r"""
import re
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
    raise SystemExit("the provider request counter is unavailable")
print(match.group(1))
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


def run(command: list[str], *, input_text: str | None = None) -> str:
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=clean_environment(),
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )
    if (
        len(result.stdout.encode()) > MAX_COMMAND_OUTPUT
        or len(result.stderr.encode()) > MAX_COMMAND_OUTPUT
    ):
        fail("a model-limit test command exceeded its output bound")
    if result.returncode != 0:
        fail("a sensitive model-limit test command failed")
    return result.stdout


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


class Preprod:
    """Run commands against one exact, already verified PreProd project."""

    def __init__(self, image_mode: str, postgres_major: str) -> None:
        if shutil.which("docker") is None:
            fail("docker is required for the model-limit test")
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

        self.master_key = values.get("LITELLM_MASTER_KEY", "")
        if not self.master_key.startswith("sk-") or len(self.master_key) < 24:
            fail("the preprod LiteLLM master key is unavailable")
        self.docker_prefix = ["docker", "--host", endpoint]
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
                fail("seed mode requires the activated preprod image overlay")
            self.compose_prefix.extend(["-f", str(SEED_OVERLAY)])
        if postgres_major == "16":
            self.compose_prefix.extend(["-f", str(POSTGRES16_OVERLAY)])
        self.compose_prefix.extend(["--profile", "preprod"])

    def docker(self, *arguments: str) -> str:
        return run([*self.docker_prefix, *arguments])

    def compose(self, *arguments: str, input_text: str | None = None) -> str:
        return run([*self.compose_prefix, *arguments], input_text=input_text)

    def container_id(self, service: str) -> str:
        identifiers = self.compose("ps", "-q", service).splitlines()
        if (
            len(identifiers) != 1
            or re.fullmatch(r"[0-9a-f]{64}", identifiers[0]) is None
        ):
            fail(f"preprod service {service} does not have one container")
        identifier = identifiers[0]
        try:
            document = json.loads(self.docker("inspect", identifier))[0]
        except (json.JSONDecodeError, IndexError, TypeError):
            fail(f"Docker returned invalid state for {service}")
        labels = document.get("Config", {}).get("Labels") or {}
        if (
            labels.get("com.docker.compose.project") != PROJECT
            or labels.get("com.docker.compose.service") != service
            or labels.get(OWNER_LABEL) != PROJECT
        ):
            fail(f"preprod service {service} escaped the owned project")
        return identifier

    def wait_healthy(self, service: str, timeout: int = 60) -> None:
        identifier = self.container_id(service)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                state = json.loads(self.docker("inspect", identifier))[0]["State"]
            except (json.JSONDecodeError, IndexError, KeyError, TypeError):
                fail(f"Docker returned invalid health state for {service}")
            if (
                state.get("Status") == "running"
                and state.get("Health", {}).get("Status") == "healthy"
            ):
                return
            if state.get("Status") in {"dead", "exited", "removing"}:
                fail(f"preprod service {service} failed to recover")
            time.sleep(1)
        fail(f"preprod service {service} did not recover")


def litellm_request(
    preprod: Preprod, path: str, bearer: str, body: dict[str, Any]
) -> tuple[int, Any]:
    raw = preprod.compose(
        "exec",
        "-T",
        "key-rotator",
        "/opt/venv/bin/python",
        "-c",
        REQUEST_HELPER,
        input_text=json.dumps(
            {"path": path, "bearer": bearer, "body": body},
            separators=(",", ":"),
        ),
    )
    try:
        response = json.loads(raw)
    except json.JSONDecodeError:
        fail("the LiteLLM test helper returned invalid JSON")
    status = response.get("status") if isinstance(response, dict) else None
    if not isinstance(status, int) or isinstance(status, bool):
        fail("the LiteLLM test helper returned an invalid status")
    return status, response.get("body")


def provider_count(preprod: Preprod) -> int:
    raw = preprod.compose(
        "exec",
        "-T",
        "key-rotator",
        "/opt/venv/bin/python",
        "-c",
        PROVIDER_COUNT_HELPER,
    ).strip()
    if re.fullmatch(r"[0-9]+", raw) is None:
        fail("the provider request counter is invalid")
    return int(raw)


def chat_body(max_tokens: int) -> dict[str, Any]:
    return {
        "model": MODEL,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": "Reply with pong."}],
    }


def expect_error(status: int, body: Any, expected: int, message: str) -> None:
    if status != expected or message not in json.dumps(body).lower():
        fail(f"the model-limit gate did not return its safe HTTP {expected} denial")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-mode", choices=("source", "seed"), default="source")
    parser.add_argument("--postgres-major", choices=("16", "18"), default="18")
    args = parser.parse_args()

    preprod = Preprod(args.image_mode, args.postgres_major)
    marker = secrets.token_hex(8)
    virtual_key = "sk-" + secrets.token_hex(24)
    project = "preprod-limit-" + marker
    policy = json.dumps(
        {
            MODEL: {
                "max_output_tokens_per_request": MAX_OUTPUT,
                "output_tokens_per_utc_minute": OUTPUTS_PER_MINUTE,
            }
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    key_created = False
    redis_stopped = False
    redis_id = preprod.container_id("redis")

    try:
        status, response = litellm_request(
            preprod,
            "/key/generate",
            preprod.master_key,
            {
                "key": virtual_key,
                "key_alias": "preprod-model-limit-" + marker,
                "user_id": "preprod-model-limit-" + marker,
                "models": [MODEL],
                "allowed_routes": ["/v1/chat/completions"],
                "metadata": {
                    "created_via": "dev-portal",
                    "aigw_project_id": project,
                    "aigw_model_limits_v1": policy,
                },
                "permissions": {},
                "blocked": False,
            },
        )
        if (
            status != 200
            or not isinstance(response, dict)
            or response.get("key") != virtual_key
        ):
            fail("LiteLLM did not create the exact temporary limit-test key")
        key_created = True

        before = provider_count(preprod)
        denied_status, denied_body = litellm_request(
            preprod, "/v1/chat/completions", virtual_key, chat_body(MAX_OUTPUT + 1)
        )
        expect_error(
            denied_status,
            denied_body,
            400,
            "requested output exceeds this project's model limit",
        )
        if provider_count(preprod) != before:
            fail("the request-cap denial reached the provider")
        print("PREPROD_MODEL_REQUEST_CAP_PASSED")

        # Keep both reservations in one fixed UTC minute. Docker Desktop and its
        # containers share the host clock, so waiting here removes a rare test
        # failure when the two requests would otherwise cross :00.
        second = int(time.time()) % 60
        if second > 40:
            time.sleep(61 - second)

        with ThreadPoolExecutor(max_workers=2) as pool:
            calls = [
                pool.submit(
                    litellm_request,
                    preprod,
                    "/v1/chat/completions",
                    virtual_key,
                    chat_body(7),
                )
                for _ in range(2)
            ]
            results = [call.result() for call in calls]
        statuses = sorted(status for status, _body in results)
        if statuses != [200, 429]:
            fail("parallel output reservations did not allow one request and deny one")
        denied_parallel = next(body for status, body in results if status == 429)
        if (
            "this project's model output limit is reached"
            not in json.dumps(denied_parallel).lower()
        ):
            fail("the minute-limit denial did not use the safe error contract")
        accepted = next(body for status, body in results if status == 200)
        choices = accepted.get("choices") if isinstance(accepted, dict) else None
        if not isinstance(choices, list) or not choices:
            fail("the allowed parallel request returned no completion")
        if provider_count(preprod) != before + 1:
            fail("parallel reservation denial crossed the provider boundary")
        print("PREPROD_MODEL_MINUTE_RESERVATION_PASSED")

        stopped = preprod.docker("stop", "--time", "10", redis_id).strip()
        if stopped != redis_id:
            fail("Docker did not stop the exact preprod Redis container")
        redis_stopped = True
        unavailable_before = provider_count(preprod)
        unavailable_status, unavailable_body = litellm_request(
            preprod, "/v1/chat/completions", virtual_key, chat_body(1)
        )
        expect_error(
            unavailable_status,
            unavailable_body,
            503,
            "model output capacity is unavailable",
        )
        if provider_count(preprod) != unavailable_before:
            fail("the Redis-unavailable request reached the provider")
        print("PREPROD_MODEL_REDIS_FAILURE_PASSED")

        started = preprod.docker("start", redis_id).strip()
        if started != redis_id:
            fail("Docker did not restart the exact preprod Redis container")
        preprod.wait_healthy("redis")
        redis_stopped = False

        # Redis intentionally denies the rest of the minute in which it
        # restarted. Wait for a new UTC-minute bucket, then prove requests
        # recover and reach the provider exactly once.
        restart_minute = int(time.time()) // 60
        while int(time.time()) // 60 == restart_minute:
            time.sleep(1)
        recovered_before = provider_count(preprod)
        recovered_status, recovered_body = litellm_request(
            preprod, "/v1/chat/completions", virtual_key, chat_body(1)
        )
        recovered_choices = (
            recovered_body.get("choices")
            if isinstance(recovered_body, dict)
            else None
        )
        if recovered_status != 200 or not isinstance(recovered_choices, list):
            fail("the model-limit gate did not recover after Redis restarted")
        if not recovered_choices:
            fail("the recovered model request returned no completion")
        if provider_count(preprod) != recovered_before + 1:
            fail("the recovered request did not cross the provider exactly once")
        print("PREPROD_MODEL_REDIS_RECOVERY_PASSED")
    finally:
        if redis_stopped:
            started = preprod.docker("start", redis_id).strip()
            if started != redis_id:
                fail("Docker did not restart the exact preprod Redis container")
            preprod.wait_healthy("redis")
        if key_created:
            status, _ = litellm_request(
                preprod,
                "/key/delete",
                preprod.master_key,
                {"keys": [virtual_key]},
            )
            if status != 200:
                fail("LiteLLM did not delete the temporary limit-test key")

    print("PREPROD_MODEL_LIMITS_PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
