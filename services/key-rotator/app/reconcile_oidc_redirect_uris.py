"""Reconcile the managed OIDC callback allow-lists to the configured domain.

This module is intentionally invoked only by the root-owned Ansible converge
through the existing key-rotator Compose service definition.  It accepts no
credentials on argv or stdin: Docker Compose supplies the already-reviewed
temporary bootstrap credential and the configured ``AIGW_DOMAIN`` as service
environment, and this process emits only fixed status markers suitable for an
automation log.  It never instantiates or contacts HashiCorp Vault.

While the temporary master-realm bootstrap client still exists (the interactive
identity bootstrap has not yet deleted it) the four managed first-party OIDC
clients have their ``redirectUris`` / ``webOrigins`` realigned to the deployed
domain; once that client is consumed, this reports that a domain migration
requires re-running the identity bootstrap ceremony rather than failing.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from app.config import Settings
from app.identity import KeycloakAdmin


CONFIRMATION = "RECONCILE_PREBOOTSTRAP_OIDC_REDIRECT_URIS"

_MARKERS = {
    "applied": "OIDC_REDIRECT_URI_PREBOOTSTRAP_RECONCILIATION_APPLIED",
    "verified": "OIDC_REDIRECT_URI_PREBOOTSTRAP_RECONCILIATION_VERIFIED",
    "rebootstrap_required": (
        "OIDC_REDIRECT_URI_PREBOOTSTRAP_RECONCILIATION_REBOOTSTRAP_REQUIRED"
    ),
}


async def reconcile() -> str:
    """Run the narrowly gated redirect-URI reconciliation without Vault."""

    settings = Settings()
    identity = KeycloakAdmin(settings, None, None)
    return await identity.reconcile_prebootstrap_relying_party_redirect_uris()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        raise SystemExit(f"exact confirmation {CONFIRMATION} is required")
    try:
        marker = _MARKERS[asyncio.run(reconcile())]
    except Exception:  # noqa: BLE001
        # This utility runs with the temporary Keycloak bootstrap credential.
        # Do not leak a traceback, exception text, or dependency details into an
        # Ansible/Docker log if configuration, Keycloak, or a dependency fails
        # unexpectedly. The fixed marker is the complete public failure API.
        print(
            "OIDC_REDIRECT_URI_PREBOOTSTRAP_RECONCILIATION_FAILED",
            file=sys.stderr,
        )
        return 1
    print(marker)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
