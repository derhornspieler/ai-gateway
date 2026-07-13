#!/usr/bin/env python3
"""Static release assertions for password-spray controls."""

from __future__ import annotations

import json
import os
import pathlib
import re
import sys


if sys.flags.optimize != 0:
    raise SystemExit("identity policy validation requires Python optimization disabled")


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE_REALMS = ROOT / "compose/keycloak/realms"
DEPLOYED_REALMS = ROOT / "keycloak/realms"
SOURCE_TEMPLATES = ROOT / "ansible/roles/docker_stack/templates/keycloak-realms"
KEYCLOAK_POLICY = {
    "bruteForceProtected": True,
    "permanentLockout": False,
    "maxTemporaryLockouts": 0,
    "bruteForceStrategy": "MULTIPLE",
    "failureFactor": 5,
    "waitIncrementSeconds": 60,
    "quickLoginCheckMilliSeconds": 1000,
    "minimumQuickLoginWaitSeconds": 60,
    "maxFailureWaitSeconds": 900,
    "maxDeltaTimeSeconds": 43200,
}


def require_keycloak_policy(path: pathlib.Path, *, template: bool) -> None:
    text = path.read_text()
    if template:
        for key, expected in KEYCLOAK_POLICY.items():
            literal = json.dumps(expected)
            matches = re.findall(rf'"{re.escape(key)}"\s*:\s*{re.escape(literal)}', text)
            assert len(matches) == 1, f"{path}: {key} must occur once as {literal}"
        return
    realm = json.loads(text)
    actual = {key: realm.get(key) for key in KEYCLOAK_POLICY}
    assert actual == KEYCLOAK_POLICY, f"{path}: unexpected brute-force policy: {actual}"


source_layout = SOURCE_REALMS.is_dir()
deployed_layout = DEPLOYED_REALMS.is_dir()
if source_layout == deployed_layout:
    raise SystemExit(
        "identity policy validation requires exactly one source or deployed realm layout"
    )

realm_dir = SOURCE_REALMS if source_layout else DEPLOYED_REALMS
for filename in ("aigw-realm.json", "anthropic-wif-realm.json"):
    require_keycloak_policy(realm_dir / filename, template=False)
    if source_layout:
        require_keycloak_policy(SOURCE_TEMPLATES / f"{filename}.j2", template=True)

static_realm = json.loads((realm_dir / "aigw-realm.json").read_text())
portal_clients = [
    client for client in static_realm["clients"] if client.get("clientId") == "dev-portal"
]
assert len(portal_clients) == 1, "static realm must contain exactly one dev-portal client"
if source_layout:
    expected_logout = "https://portal.aigw.example.internal/login"
    realm_template = (SOURCE_TEMPLATES / "aigw-realm.json.j2").read_text()
    assert realm_template.count(
        '"post.logout.redirect.uris": "https://portal.{{ aigw_domain }}/login"'
    ) == 1
else:
    # On an existing deployment, read only the exact non-secret DOMAIN line;
    # never parse or emit credential lines. A pristine Ansible converge runs
    # this render-only gate before `.env` exists, so it supplies the reviewed
    # inventory domain explicitly. Once `.env` exists, requiring both sources
    # to agree detects callback drift instead of trusting an ambient override.
    inventory_domain = os.environ.get("AIGW_VALIDATION_DOMAIN", "")
    deployed_env = ROOT / ".env"
    if deployed_env.exists():
        assert not deployed_env.is_symlink(), "deployed .env must not be a symlink"
        domain_lines = [
            line.removeprefix("DOMAIN=")
            for line in deployed_env.read_text().splitlines()
            if line.startswith("DOMAIN=")
        ]
        assert len(domain_lines) == 1, "deployed .env must contain exactly one DOMAIN"
        domain = domain_lines[0]
        if inventory_domain:
            assert inventory_domain == domain, "inventory and deployed DOMAIN disagree"
    else:
        assert inventory_domain, (
            "pristine deployed-layout validation requires AIGW_VALIDATION_DOMAIN"
        )
        domain = inventory_domain
    assert re.fullmatch(
        r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
        r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?",
        domain,
    ), "deployed DOMAIN is not a safe DNS name"
    expected_logout = f"https://portal.{domain}/login"

assert (
    portal_clients[0].get("attributes", {}).get("post.logout.redirect.uris")
    == expected_logout
), "dev-portal post-logout redirect does not match the selected deployment layout"

entrypoint = (ROOT / "services/samba-ad-lab/samba-ad-entrypoint").read_text()
for assignment in (
    "LOCKOUT_THRESHOLD=5",
    "LOCKOUT_DURATION_MINUTES=15",
    "LOCKOUT_RESET_MINUTES=15",
):
    assert entrypoint.count(assignment) == 1, f"missing fixed Samba policy: {assignment}"

print("Identity password-spray policies are exact and present in every deployment source.")
