"""Run the one-time, pre-bootstrap OIDC role-scope repair.

This module is intentionally invoked only by the root-owned Ansible migration
task through the existing key-rotator Compose service definition.  It accepts
no credentials on argv or stdin: Docker Compose supplies the already-reviewed
temporary bootstrap credential as service environment, and this process emits
only fixed status markers suitable for an automation log.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from app.config import Settings
from app.identity import KeycloakAdmin
from app.vault_client import VaultClient


CONFIRMATION = "RECONCILE_PREBOOTSTRAP_OIDC_ROLE_SCOPES"


async def reconcile() -> bool:
    """Run the narrowly gated reconciliation without starting application state."""

    settings = Settings()
    identity = KeycloakAdmin(settings, VaultClient(settings), None)
    return await identity.reconcile_prebootstrap_relying_party_role_scopes()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        raise SystemExit(f"exact confirmation {CONFIRMATION} is required")
    try:
        applied = asyncio.run(reconcile())
    except Exception:  # noqa: BLE001
        # This utility runs with the temporary Keycloak bootstrap credential.
        # Do not leak a traceback, exception text, or dependency details into
        # an Ansible/Docker log if configuration, Vault, or a dependency fails
        # unexpectedly. The fixed marker is the complete public failure API.
        print("OIDC_ROLE_SCOPE_PREBOOTSTRAP_RECONCILIATION_FAILED", file=sys.stderr)
        return 1
    print(
        "OIDC_ROLE_SCOPE_PREBOOTSTRAP_RECONCILIATION_APPLIED"
        if applied
        else "OIDC_ROLE_SCOPE_PREBOOTSTRAP_RECONCILIATION_NOT_APPLICABLE"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
