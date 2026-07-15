#!/usr/bin/env python3
"""Static release assertions for password-spray controls."""

from __future__ import annotations

import ast
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
CAPABILITY_ROLE_SCOPE = ["aigw-admins", "aigw-developers", "aigw-users"]
FIRST_PARTY_OIDC_CLIENTS = {
    "open-webui",
    "dev-portal",
    "admin-portal",
    "admin-ui",
    "vault",
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

# The master realm is never file-imported, so its brute-force policy is
# reconciled at bootstrap by the identity controller. Pin the LIVE constant
# to the same values by parsing the assignment itself — a substring count
# would accept a weakened constant shadowed by dead text elsewhere in the
# module. The key-rotator source only ships in the source layout.
if source_layout:
    controller_source = (
        ROOT / "services/key-rotator/app/identity.py"
    ).read_text()
    master_policies = []
    for node in ast.walk(ast.parse(controller_source)):
        targets = []
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets = [node.target]
        for target in targets:
            if getattr(target, "id", "") == "MASTER_BRUTE_FORCE_POLICY":
                master_policies.append(ast.literal_eval(node.value))
    assert len(master_policies) == 1, (
        "identity.py must define MASTER_BRUTE_FORCE_POLICY exactly once"
    )
    assert master_policies[0] == KEYCLOAK_POLICY, (
        "identity.py MASTER_BRUTE_FORCE_POLICY drifted from the pinned "
        f"brute-force policy: {master_policies[0]}"
    )

static_realm = json.loads((realm_dir / "aigw-realm.json").read_text())
if source_layout:
    domain = "aigw.example.internal"
    realm_template = (SOURCE_TEMPLATES / "aigw-realm.json.j2").read_text()
    for hostname in ("portal", "admin"):
        assert realm_template.count(
            f'"post.logout.redirect.uris": "https://{hostname}.{{{{ aigw_domain }}}}/login"'
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

clients = static_realm.get("clients", [])
assert isinstance(clients, list)
clients_by_id = {client.get("clientId"): client for client in clients}
assert len(clients_by_id) == len(clients), "duplicate OIDC client id"
assert set(clients_by_id) == FIRST_PARTY_OIDC_CLIENTS, (
    "first-party OIDC client allow-list drifted"
)

expected = {
    "open-webui": {
        "redirectUris": [f"https://chat.{domain}/oauth/oidc/callback"],
        "webOrigins": [f"https://chat.{domain}"],
    },
    "dev-portal": {
        "redirectUris": [f"https://portal.{domain}/auth/callback"],
        "webOrigins": [f"https://portal.{domain}"],
        "logout": f"https://portal.{domain}/login",
    },
    "admin-portal": {
        "redirectUris": [f"https://admin.{domain}/auth/callback"],
        "webOrigins": [f"https://admin.{domain}"],
        "logout": f"https://admin.{domain}/login",
    },
    "admin-ui": {
        "redirectUris": [
            f"https://litellm-admin.{domain}/oauth2/callback",
            f"https://grafana.{domain}/oauth2/callback",
            f"https://prometheus.{domain}/oauth2/callback",
            f"https://vault.{domain}/oauth2/callback",
        ],
        "webOrigins": [
            f"https://litellm-admin.{domain}",
            f"https://grafana.{domain}",
            f"https://prometheus.{domain}",
            f"https://vault.{domain}",
        ],
    },
    # Vault's inner OIDC login behind the admin-ui oauth2-proxy gate. The
    # loopback callback serves the CLI's `vault login -method=oidc` through a
    # deliberate operator SSH tunnel; the code is useless without the
    # confidential client secret that only Vault holds.
    "vault": {
        "redirectUris": [
            f"https://vault.{domain}/ui/vault/auth/oidc/oidc/callback",
            "http://localhost:8250/oidc/callback",
        ],
        "webOrigins": [f"https://vault.{domain}"],
    },
}
for client_id, contract in expected.items():
    client = clients_by_id[client_id]
    assert client.get("redirectUris") == contract["redirectUris"], client_id
    assert client.get("webOrigins") == contract["webOrigins"], client_id
    assert client.get("standardFlowEnabled") is True, client_id
    assert client.get("directAccessGrantsEnabled") is False, client_id
    assert client.get("fullScopeAllowed") is False, client_id
    if "logout" in contract:
        assert (
            client.get("attributes", {}).get("post.logout.redirect.uris")
            == contract["logout"]
        ), client_id
    mappers = client.get("protocolMappers", [])
    assert len(mappers) == 1 and mappers[0].get("config", {}).get("claim.name") == "roles", client_id

scope_mappings = static_realm.get("scopeMappings")
assert isinstance(scope_mappings, list), "OIDC realm-role scope mappings are missing"
scope_mappings_by_client = {
    mapping.get("client"): mapping
    for mapping in scope_mappings
    if isinstance(mapping, dict)
}
assert len(scope_mappings_by_client) == len(scope_mappings), (
    "duplicate or invalid OIDC realm-role scope mapping"
)
assert set(scope_mappings_by_client) == FIRST_PARTY_OIDC_CLIENTS, (
    "OIDC realm-role scope mapping allow-list drifted"
)
for client_id in sorted(FIRST_PARTY_OIDC_CLIENTS):
    assert scope_mappings_by_client[client_id].get("roles") == CAPABILITY_ROLE_SCOPE, (
        f"{client_id}: OIDC realm-role scope mapping drifted"
    )

if source_layout:
    assert realm_template.count('"scopeMappings"') == 1, (
        "realm template must have one OIDC realm-role scope mapping block"
    )
    assert len(re.findall(r'"client"\s*:', realm_template)) == len(
        FIRST_PARTY_OIDC_CLIENTS
    ), "realm template OIDC realm-role scope mappings drifted"
    for client_id in FIRST_PARTY_OIDC_CLIENTS:
        pattern = (
            rf'"client"\s*:\s*"{re.escape(client_id)}"\s*,\s*'
            r'"roles"\s*:\s*\[\s*"aigw-admins"\s*,\s*'
            r'"aigw-developers"\s*,\s*"aigw-users"\s*\]'
        )
        assert len(re.findall(pattern, realm_template, flags=re.DOTALL)) == 1, (
            f"realm template scope mapping drifted for {client_id}"
        )

entrypoint = (ROOT / "services/samba-ad-lab/samba-ad-entrypoint").read_text()
for assignment in (
    "LOCKOUT_THRESHOLD=5",
    "LOCKOUT_DURATION_MINUTES=15",
    "LOCKOUT_RESET_MINUTES=15",
):
    assert entrypoint.count(assignment) == 1, f"missing fixed Samba policy: {assignment}"

print("Identity password-spray policies are exact and present in every deployment source.")
