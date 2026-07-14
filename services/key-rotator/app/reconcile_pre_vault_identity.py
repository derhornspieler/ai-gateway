"""Apply the root-owned, pre-Vault Keycloak recovery baseline.

The runner accepts one bounded JSON document on stdin and a fixed destructive
acknowledgement on argv.  Docker Compose supplies the existing temporary
Keycloak bootstrap-client credential through the reviewed service environment;
neither that credential nor the input document is logged.  HashiCorp Vault is
never instantiated or contacted by this process.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import Any

from app.config import Settings
from app.identity import KeycloakAdmin


CONFIRMATION = "RECONCILE_PRE_VAULT_MANAGED_IDENTITY_BASELINE"
MAX_SPEC_BYTES = 64 * 1024


def read_spec() -> dict[str, Any]:
    if sys.stdin.isatty():
        raise ValueError("pre-Vault identity specification must be piped on stdin")
    encoded = sys.stdin.buffer.read(MAX_SPEC_BYTES + 1)
    if not encoded or len(encoded) > MAX_SPEC_BYTES:
        raise ValueError("pre-Vault identity specification size is invalid")
    try:
        value = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("pre-Vault identity specification is invalid") from exc
    if not isinstance(value, dict):
        raise ValueError("pre-Vault identity specification is invalid")
    return value


async def reconcile(spec: dict[str, Any]) -> bool:
    settings = Settings()
    identity = KeycloakAdmin(settings, None, None)
    return await identity.reconcile_pre_vault_identity_baseline(spec)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        raise SystemExit(f"exact confirmation {CONFIRMATION} is required")
    try:
        spec = read_spec()
        applied = asyncio.run(reconcile(spec))
    except Exception:  # noqa: BLE001
        # The temporary Keycloak credential and directory details must never
        # escape into Ansible, Docker logs, or CI exception output.
        print("PRE_VAULT_IDENTITY_BASELINE_RECONCILIATION_FAILED", file=sys.stderr)
        return 1
    print(
        "PRE_VAULT_IDENTITY_BASELINE_RECONCILIATION_APPLIED"
        if applied
        else "PRE_VAULT_IDENTITY_BASELINE_RECONCILIATION_VERIFIED"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
