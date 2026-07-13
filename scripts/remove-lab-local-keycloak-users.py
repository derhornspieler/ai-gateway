#!/usr/bin/env python3
"""Remove disposable Keycloak-local lab users after Samba admin validation.

Run this only in the key-rotator service environment. The durable
private_key_jwt controller is read from Vault; no credential is accepted on
argv, stdin, or the environment by this script.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import urllib.parse
from typing import Any

sys.path.insert(0, "/app")

from app.config import Settings  # noqa: E402
from app.identity import IdentityError, KeycloakAdmin  # noqa: E402
from app.security import path_segment  # noqa: E402
from app.vault_client import VaultClient  # noqa: E402


FIXTURES = ("testadmin", "testuser")


async def remove_local_fixtures() -> None:
    settings = Settings()
    vault = VaultClient(settings)
    admin = KeycloakAdmin(settings, vault, None)
    token = await admin._controller_token()  # noqa: SLF001 - operator recovery tool
    realm = path_segment(settings.identity_realm, label="Keycloak realm")
    auth_host = (
        urllib.parse.urlsplit(settings.keycloak_public_url).hostname or ""
    ).lower()
    if not auth_host.startswith("auth.") or len(auth_host) <= len("auth."):
        raise IdentityError("KEYCLOAK_PUBLIC_URL does not use the auth domain")
    domain = auth_host.removeprefix("auth.")

    # Validate every target before deleting either one. This prevents a broad
    # search or name collision from partially deleting an unexpected account.
    targets: list[tuple[str, str]] = []
    for username in FIXTURES:
        response = await admin._request(  # noqa: SLF001
            "GET",
            f"/admin/realms/{realm}/users",
            token=token,
            params={"username": username, "exact": "true", "max": 2},
            expected=(200,),
        )
        payload: Any = admin._json(response, "local user lookup")  # noqa: SLF001
        matches = [
            user
            for user in payload
            if isinstance(user, dict) and user.get("username") == username
        ] if isinstance(payload, list) else []
        if len(matches) != 1:
            raise IdentityError(f"expected exactly one local fixture {username}")
        user = matches[0]
        if user.get("federationLink"):
            raise IdentityError(f"refusing to delete federated user {username}")
        if str(user.get("email") or "").lower() != f"{username}@{domain}":
            raise IdentityError(f"local fixture email mismatch for {username}")
        targets.append(
            (username, path_segment(user.get("id"), label="local user UUID"))
        )

    for _, user_id in targets:
        await admin._request(  # noqa: SLF001
            "DELETE",
            f"/admin/realms/{realm}/users/{user_id}",
            token=token,
            expected=(204,),
        )

    for username, _ in targets:
        response = await admin._request(  # noqa: SLF001
            "GET",
            f"/admin/realms/{realm}/users",
            token=token,
            params={"username": username, "exact": "true", "max": 1},
            expected=(200,),
        )
        payload = admin._json(response, "local user deletion check")  # noqa: SLF001
        if payload:
            raise IdentityError(f"local fixture still exists: {username}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    if args.confirm != "REMOVE_LOCAL_TEST_USERS":
        raise SystemExit("exact confirmation REMOVE_LOCAL_TEST_USERS is required")
    asyncio.run(remove_local_fixtures())
    print("LOCAL_KEYCLOAK_TEST_USERS_REMOVED_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
