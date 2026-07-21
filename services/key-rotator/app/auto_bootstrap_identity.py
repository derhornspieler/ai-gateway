"""Ask the running key-rotator to deploy and verify Keycloak identity control.

The running one-worker service owns the shared bootstrap lock. This helper is
only a loopback client for Ansible: it reads the existing internal token from
the container environment, follows no redirects, and prints fixed markers.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request


CONFIRMATION = "AUTO_BOOTSTRAP_IDENTITY"
APPLIED_MARKER = "IDENTITY_AUTO_BOOTSTRAP_APPLIED"
VERIFIED_MARKER = "IDENTITY_AUTO_BOOTSTRAP_VERIFIED"
FAILED_MARKER = "IDENTITY_AUTO_BOOTSTRAP_FAILED"
DEPLOYMENT_URL = "http://127.0.0.1:8080/identity/deployment"
MAX_RESPONSE_BYTES = 16 * 1024


class NoRedirects(urllib.request.HTTPRedirectHandler):
    """Treat every redirect as a failure; the token must stay on loopback."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def converge() -> str:
    """Call the locked deployment route and return one fixed success marker."""

    token = os.environ.get("ROTATOR_INTERNAL_TOKEN", "")
    if not token or len(token) > 4096 or any(ord(char) < 32 for char in token):
        raise RuntimeError("internal deployment authentication is unavailable")
    body = json.dumps(
        {"confirmation": CONFIRMATION}, separators=(",", ":")
    ).encode("ascii")
    request = urllib.request.Request(
        DEPLOYMENT_URL,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Internal-Auth": token,
        },
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        NoRedirects(),
    )
    try:
        with opener.open(request, timeout=300) as response:
            if response.status != 200:
                raise RuntimeError("identity deployment route did not succeed")
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
        raise RuntimeError("identity deployment route failed") from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise RuntimeError("identity deployment response was too large")
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("identity deployment response was invalid") from exc
    if not isinstance(payload, dict) or set(payload) != {"result"}:
        raise RuntimeError("identity deployment response had an invalid shape")
    if payload["result"] == "applied":
        return APPLIED_MARKER
    if payload["result"] == "verified":
        return VERIFIED_MARKER
    raise RuntimeError("identity deployment response had an invalid result")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Ansible-only idempotent Keycloak/LDAPS identity deployment"
    )
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        raise SystemExit(f"exact confirmation {CONFIRMATION} is required")
    try:
        marker = converge()
    except Exception:  # noqa: BLE001
        # Never print a URL response, token, credential, or wrapped exception.
        print(FAILED_MARKER, file=sys.stderr)
        return 1
    print(marker)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
