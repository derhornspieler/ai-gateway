#!/usr/bin/env python3
"""Assert the retained Rocky lab identity state from the portal network."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request


BASE = "http://key-rotator:8080"
EXPECTED = {
    "lab-admins": ("aigw-admins", "lab-admin"),
    "lab-developers": ("aigw-developers", "lab-developer"),
    "lab-users": ("aigw-users", "lab-user"),
}


def get(path: str):
    token = os.environ.get("ROTATOR_INTERNAL_TOKEN", "")
    if len(token) < 16:
        raise RuntimeError("rotator service authentication is unavailable")
    request = urllib.request.Request(
        BASE + path,
        headers={"X-Internal-Auth": token, "Accept": "application/json"},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=15) as response:
            if response.status != 200:
                raise RuntimeError(
                    f"identity API {path} returned HTTP {response.status}"
                )
            return json.load(response)
    except urllib.error.HTTPError as error:
        # Endpoint-level failure, distinct from a boolean assertion below:
        # the rotator could not compute the answer at all (Vault sealed or
        # unreachable, or a control-plane fault) — remediation starts at the
        # rotator/Vault, not at Keycloak.
        raise RuntimeError(
            f"identity API {path} failed with HTTP {error.code}: the rotator "
            "could not compute identity status (check Vault health and the "
            "rotator logs)"
        ) from error


def main() -> int:
    status = get("/identity/status")
    expected_status = {
        "configured": True,
        "controller_usable": True,
        "bootstrap_available": False,
        "bootstrap_cleanup_required": False,
        "ldap_configured": True,
        # The durable break-glass administrator's credential must be escrowed
        # in Vault; the boolean is derived from the escrow document alone.
        "break_glass_escrowed": True,
        # The `vault` relying-party client secret must be escrowed for the
        # vault-oidc-setup.sh ceremony; also a pure escrow-presence boolean.
        "vault_oidc_rp_escrowed": True,
    }
    for field, expected in expected_status.items():
        actual = status.get(field)
        if actual is not expected:
            hint = ""
            if field == "break_glass_escrowed":
                if status.get("break_glass_escrow_readable") is False:
                    hint = (
                        " — the rotator's Vault policy predates the escrow "
                        "path; run the one-time policy amendment, then the "
                        "re-initialization ceremony (docs/identity-operations"
                        ".md, 'Upgrading an existing deployment')"
                    )
                else:
                    hint = (
                        " — no valid escrow document; re-run the identity "
                        "initialization ceremony (docs/identity-operations.md"
                        ", 'Break-glass administrator')"
                    )
            elif field == "vault_oidc_rp_escrowed":
                if status.get("vault_oidc_rp_escrow_readable") is False:
                    hint = (
                        " — the rotator's Vault policy predates the vault "
                        "OIDC escrow path; run the one-time policy amendment,"
                        " then the re-initialization ceremony "
                        "(docs/identity-operations.md, 'Vault OIDC login')"
                    )
                else:
                    hint = (
                        " — no valid vault OIDC escrow; re-run the identity "
                        "initialization ceremony, then "
                        "scripts/vault-oidc-setup.sh "
                        "(docs/identity-operations.md, 'Vault OIDC login')"
                    )
            raise RuntimeError(
                "unexpected identity status field: "
                f"{field} (expected {expected}, got {actual}){hint}"
            )

    users = get("/identity/users?" + urllib.parse.urlencode({"search": ""}))
    if {user.get("username") for user in users} != {
        "lab-admin",
        "lab-developer",
        "lab-user",
    } or len(users) != 3:
        raise RuntimeError("federated user inventory is not the exact three fixtures")

    groups = get("/identity/groups")
    if {group.get("name") for group in groups} != set(EXPECTED) or len(groups) != 3:
        raise RuntimeError("managed group inventory is not the retained three groups")
    for group in groups:
        capability, username = EXPECTED[group["name"]]
        if group.get("capabilities") != [capability] or group.get("member_count") != 1:
            raise RuntimeError("managed group capability or count drifted")
        members = get(f"/identity/groups/{group['id']}/members")
        if len(members) != 1 or members[0].get("username") != username:
            raise RuntimeError("managed group member drifted")

    print("LIVE_LAB_IDENTITY_EXACT_STATE_PASS users=3 groups=3 bootstrap=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
