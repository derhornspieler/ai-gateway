#!/usr/bin/env python3
"""Run the local preprod checks that cross the TLS edge and WIF mock."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = ROOT / "compose/secrets/preprod.env"
CA_FILE = ROOT / "compose/secrets/preprod-root-ca.pem"
PASSWORD_DIR = ROOT / "compose/secrets"
ENABLED_ADM_OIDC_TARGETS = ("litellm-admin", "grafana", "prometheus")


def fail(message: str) -> None:
    raise SystemExit(f"ERROR: {message}")


def env_value(name: str) -> str:
    if not ENV_FILE.is_file():
        fail("the generated preprod environment is missing")
    matches = [
        line.partition("=")[2]
        for line in ENV_FILE.read_text().splitlines()
        if line.startswith(name + "=")
    ]
    if len(matches) != 1 or not matches[0]:
        fail(f"the generated preprod environment has no unique {name}")
    return matches[0]


def directory_password(username: str) -> str:
    """Read one generated test password without following links."""

    if username not in {"preprod-admin", "preprod-developer", "preprod-user"}:
        fail("the requested preprod username is not allowed")
    path = PASSWORD_DIR / f"samba_user_{username}_password"
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        fail(f"the generated password file is missing for {username}")
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != os.geteuid()
            or metadata.st_gid != os.getegid()
        ):
            fail(f"the generated password file is unsafe for {username}")
        raw = os.read(descriptor, 514)
    finally:
        os.close(descriptor)
    if len(raw) > 513:
        fail(f"the generated password is too long for {username}")
    try:
        password = raw.strip().decode("utf-8")
    except UnicodeDecodeError:
        fail(f"the generated password is invalid for {username}")
    if not 16 <= len(password) <= 512:
        fail(f"the generated password length is invalid for {username}")
    return password


def run(command: list[str], *, body: str | None = None) -> str:
    result = subprocess.run(
        command,
        cwd=ROOT,
        input=body,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        fail(f"preprod check failed: {command[0]}")
    return result.stdout


def curl_json(
    hostname: str,
    address: str,
    path: str,
    *,
    body: dict | None = None,
    expected_status: int = 200,
) -> object:
    if type(expected_status) is not int or not 100 <= expected_status <= 599:
        fail("the expected HTTP status is invalid")
    command = [
        "curl",
        "--disable",
        "--silent",
        "--show-error",
        "--http1.1",
        "--connect-timeout",
        "10",
        "--max-time",
        "60",
        "--noproxy",
        "*",
        "--cacert",
        str(CA_FILE),
        "--resolve",
        f"{hostname}:443:{address}",
        "--write-out",
        "\n%{http_code}",
    ]
    curl_config = None
    if body is not None:

        def quoted(value: str) -> str:
            return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

        curl_config = (
            "\n".join(
                [
                    'request = "POST"',
                    'header = "Content-Type: application/json"',
                    'header = "Authorization: Bearer '
                    + quoted(env_value("LITELLM_MASTER_KEY"))
                    + '"',
                    'data-binary = "'
                    + quoted(json.dumps(body, separators=(",", ":")))
                    + '"',
                ]
            )
            + "\n"
        )
        command.extend(["--config", "-"])
    command.append(f"https://{hostname}{path}")
    raw = run(command, body=curl_config)
    try:
        response_body, status_text = raw.rsplit("\n", 1)
        status = int(status_text)
    except (ValueError, TypeError):
        fail(f"{hostname}{path} returned no valid HTTP status")
    if status != expected_status:
        fail(f"{hostname}{path} returned HTTP {status}, expected {expected_status}")
    try:
        return json.loads(response_body)
    except json.JSONDecodeError:
        fail(f"{hostname}{path} returned invalid JSON")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-mode", choices=("source", "seed"), default="source")
    args = parser.parse_args()
    if shutil.which("curl") is None:
        fail("curl is required for the edge TLS checks")
    if not CA_FILE.is_file():
        fail("the persistent preprod test CA is missing")

    preprod_arguments = [
        sys.executable,
        str(ROOT / "scripts/preprod.py"),
        "--image-mode",
        args.image_mode,
    ]
    verification = run([*preprod_arguments, "verify"])
    if "PREPROD_VERIFIED" not in verification:
        fail("the complete preprod service graph was not verified")

    discovery = curl_json(
        "auth.aigw.internal",
        "127.0.3.1",
        "/realms/aigw/.well-known/openid-configuration",
    )
    if not isinstance(discovery, dict) or discovery.get("issuer") != (
        "https://auth.aigw.internal/realms/aigw"
    ):
        fail("Keycloak advertised the wrong preprod issuer")

    fixtures = (
        (
            "preprod-admin",
            "/",
            "/admin",
            "PORTAL_DIRECTORY_ADMIN_PASS",
        ),
        (
            "preprod-developer",
            "/",
            "forbidden",
            "PORTAL_DIRECTORY_ADMIN_DENIED_PASS",
        ),
        (
            "preprod-user",
            "forbidden",
            "forbidden",
            "PORTAL_DIRECTORY_ADMIN_DENIED_PASS",
        ),
    )
    for username, portal_path, admin_path, admin_marker in fixtures:
        password = directory_password(username)
        portal_acceptance = run(
            [
                sys.executable,
                "-I",
                str(ROOT / "scripts/test-portal-login.py"),
                "--ca",
                str(CA_FILE),
                "--username",
                username,
                "--expect-path",
                portal_path,
                "--verify-admin",
                "--expect-admin-path",
                admin_path,
                "--logout",
            ],
            body=password + "\n",
        )
        for marker in (
            f"PORTAL_DIRECTORY_LOGIN_PASS username={username} result={portal_path}",
            f"{admin_marker} username={username}",
            f"PORTAL_LOGOUT_PASS username={username}",
            f"ADMIN_PORTAL_LOGOUT_PASS username={username}",
        ):
            if marker not in portal_acceptance:
                fail(f"preprod OIDC acceptance omitted {marker}")

        chat_acceptance = run(
            [
                sys.executable,
                "-I",
                str(ROOT / "scripts/test-oidc-callbacks.py"),
                "--ca",
                str(CA_FILE),
                "--target",
                "chat",
                "--username",
                username,
            ],
            body=password + "\n",
        )
        for marker in (
            f"OIDC_CALLBACK_PASS target=chat username={username}",
            "OIDC_CALLBACK_ALL_PASS count=1",
        ):
            if marker not in chat_acceptance:
                fail(f"preprod chat acceptance omitted {marker}")

        for target in ENABLED_ADM_OIDC_TARGETS:
            if username == "preprod-admin":
                admin_ui_acceptance = run(
                    [
                        sys.executable,
                        "-I",
                        str(ROOT / "scripts/test-oidc-callbacks.py"),
                        "--ca",
                        str(CA_FILE),
                        "--target",
                        target,
                        "--username",
                        username,
                    ],
                    body=password + "\n",
                )
                expected_admin_ui_markers = (
                    f"OIDC_CALLBACK_PASS target={target} username={username}",
                    "OIDC_CALLBACK_ALL_PASS count=1",
                )
            else:
                admin_ui_acceptance = run(
                    [
                        sys.executable,
                        "-I",
                        str(ROOT / "scripts/test-admin-denial.py"),
                        "--ca",
                        str(CA_FILE),
                        "--target",
                        target,
                        "--username",
                        username,
                    ],
                    body=password + "\n",
                )
                expected_admin_ui_markers = (
                    f"ADMIN_DENIAL_PASS target={target} username={username}",
                    f"ADMIN_DENIAL_ALL_PASS count=1 username={username}",
                )
            for marker in expected_admin_ui_markers:
                if marker not in admin_ui_acceptance:
                    fail(f"preprod admin UI acceptance omitted {marker}")

    response = curl_json(
        "api.aigw.internal",
        "127.0.2.1",
        "/v1/messages",
        body={
            "model": "claude-sonnet-4-5",
            "max_tokens": 8,
            "messages": [{"role": "user", "content": "Reply with pong."}],
        },
    )
    content = response.get("content") if isinstance(response, dict) else None
    if not isinstance(content, list) or not any(
        isinstance(item, dict) and item.get("text") == "pong" for item in content
    ):
        fail("the end-to-end WIF inference path did not return pong")

    denied = curl_json(
        "api.aigw.internal",
        "127.0.2.1",
        "/v1/messages",
        expected_status=400,
        body={
            "model": "aigw-auto",
            "max_tokens": 8,
            "messages": [{"role": "user", "content": "Do not dispatch."}],
        },
    )
    if "automatic model routing is not enabled" not in json.dumps(denied).lower():
        fail("the reserved automatic-routing model did not fail closed")
    print("PREPROD_AUTO_ROUTER_DENIAL_PASSED")

    limit_arguments = [
        sys.executable,
        "-I",
        str(ROOT / "scripts/test-preprod-model-limits.py"),
        "--image-mode",
        args.image_mode,
    ]
    limit_acceptance = run(limit_arguments)
    for marker in (
        "PREPROD_MODEL_REQUEST_CAP_PASSED",
        "PREPROD_MODEL_MINUTE_RESERVATION_PASSED",
        "PREPROD_MODEL_REDIS_FAILURE_PASSED",
        "PREPROD_MODEL_REDIS_RECOVERY_PASSED",
        "PREPROD_MODEL_LIMITS_PASSED",
    ):
        if marker not in limit_acceptance:
            fail(f"preprod model-limit acceptance omitted {marker}")
        print(marker)

    if args.image_mode == "seed":
        lifecycle_acceptance = run(
            [
                sys.executable,
                "-I",
                str(ROOT / "scripts/test-preprod-model-lifecycle.py"),
                "--image-mode",
                "seed",
            ]
        )
        for marker in (
            "PREPROD_MODEL_DRAFT_HIDDEN_PASSED",
            "PREPROD_MODEL_HIDDEN_CALL_PASSED",
            "PREPROD_MODEL_DISCOVERY_PASSED",
            "PREPROD_MODEL_ASSIGNMENT_GATE_PASSED",
            "PREPROD_MODEL_RETIREMENT_PASSED",
            "PREPROD_MODEL_POLICY_CHUNKS_PASSED",
            "PREPROD_MODEL_LIFECYCLE_PASSED",
        ):
            if marker not in lifecycle_acceptance:
                fail(f"preprod model lifecycle acceptance omitted {marker}")
            print(marker)

        usage_acceptance = run(
            [
                sys.executable,
                "-I",
                str(ROOT / "scripts/test-preprod-usage-accounting.py"),
                "--image-mode",
                "seed",
            ],
            body=directory_password("preprod-admin") + "\n",
        )
        for marker in (
            "PREPROD_PRICE_PORTAL_STEP_UP_PASSED",
            "PREPROD_PRICE_PORTAL_PREVIEW_PASSED",
            "PREPROD_PRICE_PORTAL_CSRF_PASSED",
            "PREPROD_PRICE_PORTAL_CONFIRM_PASSED",
            "PREPROD_PRICE_PORTAL_CLEANUP_PASSED",
            "PREPROD_PRICE_PORTAL_PASSED",
            "PREPROD_PRICE_AUDIT_SOURCE_PASSED",
            "PREPROD_PRICE_AUDIT_EXPORT_PASSED",
            "PREPROD_USAGE_REPLAY_GUARD_PASSED",
            "PREPROD_USAGE_UNKNOWN_PASSED",
            "PREPROD_USAGE_BACKDATE_PASSED",
            "PREPROD_USAGE_REPORTING_PASSED",
            "PREPROD_USAGE_GRAFANA_RO_PASSED",
            "PREPROD_USAGE_APPEND_ONLY_PASSED",
            "PREPROD_USAGE_REAL_REQUEST_PASSED",
            "PREPROD_USAGE_STREAM_PASSED",
            "PREPROD_USAGE_RETRY_PASSED",
            "PREPROD_USAGE_MISSING_PASSED",
            "PREPROD_USAGE_MISSING_STREAM_PASSED",
            "PREPROD_USAGE_MALFORMED_PASSED",
            "PREPROD_USAGE_MALFORMED_STREAM_PASSED",
            "PREPROD_USAGE_FAILURE_PASSED",
            "PREPROD_USAGE_ACCOUNTING_CORE_PASSED",
            "PREPROD_USAGE_AUDIT_EXPORT_PASSED",
            "PREPROD_USAGE_DELIVERY_GAP_REQUEST_PASSED",
            "PREPROD_USAGE_DELIVERY_GAP_PASSED",
            "PREPROD_USAGE_ACCOUNTING_PASSED",
        ):
            if marker not in usage_acceptance:
                fail(f"preprod usage acceptance omitted {marker}")
            print(marker)

    print("PREPROD_E2E_PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
