#!/usr/bin/env python3
"""Run the local preprod checks that cross the TLS edge and WIF mock."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = ROOT / "compose/secrets/preprod.env"
CA_FILE = ROOT / "compose/secrets/preprod-root-ca.pem"
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


def curl_json(hostname: str, address: str, path: str, *, body: dict | None = None) -> object:
    command = [
        "curl",
        "--disable",
        "--silent",
        "--show-error",
        "--fail-with-body",
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
    ]
    curl_config = None
    if body is not None:
        def quoted(value: str) -> str:
            return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

        curl_config = "\n".join(
            [
                'request = "POST"',
                'header = "Content-Type: application/json"',
                'header = "Authorization: Bearer '
                + quoted(env_value("LITELLM_MASTER_KEY"))
                + '"',
                'data-binary = "' + quoted(json.dumps(body, separators=(",", ":"))) + '"',
            ]
        ) + "\n"
        command.extend(["--config", "-"])
    command.append(f"https://{hostname}{path}")
    raw = run(command, body=curl_config)
    try:
        return json.loads(raw)
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
            "OnlyForTesting1!PreprodAdmin",
            "/",
            "/admin",
            "PORTAL_DIRECTORY_ADMIN_PASS",
        ),
        (
            "preprod-developer",
            "OnlyForTesting1!PreprodDeveloper",
            "/",
            "forbidden",
            "PORTAL_DIRECTORY_ADMIN_DENIED_PASS",
        ),
        (
            "preprod-user",
            "OnlyForTesting1!PreprodUser",
            "forbidden",
            "forbidden",
            "PORTAL_DIRECTORY_ADMIN_DENIED_PASS",
        ),
    )
    for username, password, portal_path, admin_path, admin_marker in fixtures:
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

    print("PREPROD_E2E_PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
