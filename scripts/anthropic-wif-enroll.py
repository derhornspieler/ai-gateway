#!/usr/bin/env python3
"""Manage the Anthropic-side WIF enrollment programmatically (Admin API).

Drives https://api.anthropic.com/v1/organizations/{service_accounts,
federation_issuers,federation_rules} — the documented WIF Admin API — so the
issuer, inline JWKS, service account, and federation rule can be created,
checked, and rotated from the controller instead of clicked through the
Claude Console. See docs/anthropic-wif-bootstrap.md and
https://platform.claude.com/docs/en/manage-claude/wif-admin-api.

Authority boundary (unchanged from the runbook): every call needs a
short-lived `org:admin` OAuth bearer minted by a HUMAN org admin —
    ant auth login --profile admin --scope "org:admin"
    ant auth print-credentials --profile admin --access-token | \
        python3 scripts/anthropic-wif-enroll.py <mode> ...
The token is accepted on STDIN ONLY, held in memory, and never stored,
logged, or forwarded anywhere but api.anthropic.com. The inference path
still never holds org:admin; this script only automates the operator's own
console clicks. Admin API keys are rejected by these endpoints by design.

Modes:
  check        Read-only: locate the issuer by issuer URL, list its rules,
               and (with --jwks-json) compare the live inline JWKS canonical
               SHA-256 against the local export. Safe to run any time.
  enroll       Find-or-create the service account (+ workspace membership),
               the inline-JWKS issuer, and the workspace:inference rule with
               the exact broker subject. --dry-run prints the plan only.
               Prints the identifiers and the Vault record command.
  rotate-jwks  Replace the issuer's inline `keys` array from a fresh export
               (the old+new / key-removal ceremony) and print the new
               canonical hash for the Vault `kv patch`.
  self-test    Prove the API contract end-to-end WITHOUT touching the real
               enrollment: creates uniquely-named throwaway resources (fake
               issuer URL, RFC 7517 example public key, unmatched subject),
               reads them back, then archives rule -> issuer -> account.

Controller-side, hyphenated (excluded from unittest discovery / the VM
manifest / validate-compose). The --jwks-json file is the exact output of
the VM JWKS export helper in docs/anthropic-wif-bootstrap.md (JSON followed
by issuer_url=/federation_jwks_sha256= lines) or a bare
{"type": "inline", "keys": [...]} document — public keys only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.anthropic.com/v1/organizations"
DEFAULT_ISSUER_URL = "https://idp.wif-a.example.invalid/realms/anthropic-wif"
DEFAULT_SUBJECT = "service-account-anthropic-token-broker"

# RFC 7517 appendix A.1 public RSA key: structurally valid, publicly known,
# verifies nothing. Used only by self-test's throwaway issuer.
SELFTEST_JWK = {
    "kty": "RSA",
    "alg": "RS256",
    "use": "sig",
    "kid": "aigw-selftest",
    "n": (
        "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFF"
        "xuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt"
        "7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6"
        "qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksIN"
        "HaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
    ),
    "e": "AQAB",
}


def read_token() -> str:
    if sys.stdin.isatty():
        raise SystemExit(
            "pipe the org:admin OAuth bearer on stdin, e.g.\n"
            "  ant auth print-credentials --profile admin --access-token | "
            "python3 scripts/anthropic-wif-enroll.py <mode> ..."
        )
    raw = sys.stdin.buffer.read(8193)
    if not raw or len(raw) > 8192:
        raise SystemExit("invalid token length on stdin")
    token = raw.strip().decode("utf-8")
    if not token or any(ord(c) < 33 for c in token):
        raise SystemExit("token must be a single opaque line")
    return token


def canonical_jwks_sha256(keys: list) -> str:
    """Exact algorithm from docs/anthropic-wif-bootstrap.md and the
    key-rotator JWKS watcher — the three must never disagree."""
    ordered = sorted(
        keys, key=lambda key: (str(key.get("kid", "")), str(key.get("alg", "")))
    )
    canonical = json.dumps(ordered, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def load_jwks_file(path: str) -> tuple[list, str | None, str | None]:
    """Accept the VM export helper's exact output (JSON + issuer_url= and
    federation_jwks_sha256= lines) or a bare inline-JWKS JSON document.
    Returns (keys, issuer_url_or_None, recorded_hash_or_None)."""
    text = open(path, "r", encoding="utf-8").read()
    issuer_url = None
    recorded = None
    json_part = text
    marker = text.find("issuer_url=")
    if marker != -1:
        json_part = text[:marker]
        for line in text[marker:].splitlines():
            if line.startswith("issuer_url="):
                issuer_url = line.split("=", 1)[1].strip()
            elif line.startswith("federation_jwks_sha256="):
                recorded = line.split("=", 1)[1].strip()
    doc = json.loads(json_part)
    if isinstance(doc, dict) and isinstance(doc.get("keys"), list):
        keys = doc["keys"]
    elif isinstance(doc, list):
        keys = doc
    else:
        raise SystemExit(f"{path}: expected an inline JWKS document with 'keys'")
    for key in keys:
        if not isinstance(key, dict) or "kty" not in key:
            raise SystemExit(f"{path}: entry without 'kty' — not a public JWK set?")
        for private_member in ("d", "p", "q", "dp", "dq", "qi", "k"):
            if private_member in key:
                raise SystemExit(
                    f"{path}: key '{key.get('kid', '?')}' carries private material "
                    f"('{private_member}') — refuse to upload; export public keys only"
                )
    return keys, issuer_url, recorded


class Client:
    def __init__(self, token: str) -> None:
        self._token = token
        self._ctx = ssl.create_default_context()
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=self._ctx),
        )

    def call(self, method: str, path: str, body: dict | None = None):
        req = urllib.request.Request(
            API + path,
            data=None if body is None else json.dumps(body).encode(),
            headers={
                "anthropic-version": "2023-06-01",
                "authorization": "Bearer " + self._token,
                "content-type": "application/json",
                "user-agent": "aigw-wif-enroll/1",
            },
            method=method,
        )
        try:
            with self._opener.open(req, timeout=60) as resp:
                data = resp.read().decode()
                return resp.status, json.loads(data) if data else {}
        except urllib.error.HTTPError as exc:
            data = exc.read().decode(errors="replace")
            try:
                return exc.code, json.loads(data)
            except ValueError:
                return exc.code, {"raw": data[:500]}

    def require(self, method: str, path: str, body: dict | None = None) -> dict:
        status, payload = self.call(method, path, body)
        if status not in (200, 201):
            raise SystemExit(
                f"{method} {path} -> HTTP {status}: "
                + json.dumps(payload)[:600]
            )
        return payload

    def list_all(self, path: str, params: dict | None = None):
        items: list = []
        page = None
        while True:
            query = dict(params or {})
            query["limit"] = "100"
            if page:
                query["page"] = page
            payload = self.require("GET", path + "?" + urllib.parse.urlencode(query))
            items.extend(payload.get("data", []))
            page = payload.get("next_page")
            if not page:
                return items


def find_by(items: list, field: str, value: str):
    return next((i for i in items if i.get(field) == value), None)


def mode_check(client: Client, args) -> int:
    issuers = client.list_all("/federation_issuers")
    issuer = find_by(issuers, "issuer_url", args.issuer_url)
    if issuer is None:
        print(f"ISSUER_ABSENT issuer_url={args.issuer_url}")
        print("known issuers: " + ", ".join(sorted(i.get("issuer_url", "?") for i in issuers)) if issuers else "no issuers registered")
        return 1
    print(f"ISSUER id={issuer['id']} name={issuer.get('name')}")
    live_keys = (issuer.get("jwks") or {}).get("keys")
    if isinstance(live_keys, list):
        print(f"ISSUER_JWKS_SHA256 {canonical_jwks_sha256(live_keys)} (keys={len(live_keys)})")
    else:
        print(f"ISSUER_JWKS type={ (issuer.get('jwks') or {}).get('type', '?') } (keys not returned)")
    if args.jwks_json:
        keys, _, recorded = load_jwks_file(args.jwks_json)
        local = canonical_jwks_sha256(keys)
        print(f"LOCAL_JWKS_SHA256 {local} (keys={len(keys)})")
        if recorded and recorded != local:
            print(f"WARN local file's recorded hash {recorded} != recomputed {local}")
        if isinstance(live_keys, list):
            verdict = "MATCH" if canonical_jwks_sha256(live_keys) == local else "DRIFT"
            print(f"JWKS_{verdict}")
    rules = client.list_all("/federation_rules", {"issuer_id": issuer["id"]})
    if not rules:
        print("RULES none for this issuer")
        return 1
    for rule in rules:
        match = rule.get("match") or {}
        print(
            "RULE id=%s name=%s subject_prefix=%r oauth_scope=%s lifetime=%s target=%s archived=%s"
            % (
                rule.get("id"),
                rule.get("name"),
                match.get("subject_prefix"),
                rule.get("oauth_scope"),
                rule.get("token_lifetime_seconds"),
                (rule.get("target") or {}).get("service_account_id"),
                bool(rule.get("archived_at")),
            )
        )
    print("CHECK_OK")
    return 0


def vault_record_hint(issuer_id, rule_id, svac_id, workspace_id, jwks_hash) -> str:
    return (
        "\nVault record (run on the VM per docs/anthropic-wif-bootstrap.md §3):\n"
        "  scripts/aigw-compose.sh exec -T -e VAULT_TOKEN vault vault kv put \\\n"
        "    kv/ai-gateway/anthropic-wif \\\n"
        "    kc_token_url=http://keycloak:8080/realms/anthropic-wif/protocol/openid-connect/token \\\n"
        "    kc_client_id=anthropic-token-broker \\\n"
        f"    federation_issuer_id={issuer_id} \\\n"
        f"    federation_rule_id={rule_id} \\\n"
        "    organization_id=<org-uuid-from-console> \\\n"
        f"    service_account_id={svac_id} \\\n"
        f"    workspace_id={workspace_id} \\\n"
        f"    federation_jwks_sha256={jwks_hash}"
    )


def mode_enroll(client: Client, args) -> int:
    keys, file_issuer_url, _ = load_jwks_file(args.jwks_json)
    issuer_url = args.issuer_url or file_issuer_url
    if not issuer_url:
        raise SystemExit("no issuer URL: pass --issuer-url or a helper-format JWKS file")
    jwks_hash = canonical_jwks_sha256(keys)
    plan = [
        f"service account  name={args.name_prefix} role=developer",
        f"workspace member workspace_id={args.workspace_id}",
        f"issuer           name={args.name_prefix} issuer_url={issuer_url} inline keys={len(keys)} sha256={jwks_hash}",
        f"rule             name={args.name_prefix} subject_prefix={args.subject!r} (exact, no wildcard) "
        f"scope=workspace:inference lifetime={args.token_lifetime}s",
    ]
    print("PLAN:\n  " + "\n  ".join(plan))
    if args.dry_run:
        print("DRY_RUN no mutations performed")
        return 0

    accounts = client.list_all("/service_accounts")
    svac = find_by(accounts, "name", args.name_prefix)
    if svac is None:
        svac = client.require(
            "POST", "/service_accounts",
            {"name": args.name_prefix, "organization_role": "developer"},
        )
        print(f"CREATED service_account {svac['id']}")
    else:
        print(f"EXISTS service_account {svac['id']}")
    status, payload = client.call(
        "POST", f"/service_accounts/{svac['id']}/workspaces",
        {"workspace_id": args.workspace_id},
    )
    if status in (200, 201):
        print(f"WORKSPACE_MEMBERSHIP_OK {args.workspace_id}")
    else:
        # Default-workspace and already-a-member cases surface as 4xx.
        print(f"WORKSPACE_MEMBERSHIP status={status} detail={json.dumps(payload)[:300]}")

    issuers = client.list_all("/federation_issuers")
    issuer = find_by(issuers, "issuer_url", issuer_url)
    if issuer is None:
        issuer = client.require(
            "POST", "/federation_issuers",
            {
                "name": args.name_prefix,
                "issuer_url": issuer_url,
                "jwks": {"type": "inline", "keys": keys},
            },
        )
        print(f"CREATED issuer {issuer['id']}")
    else:
        print(f"EXISTS issuer {issuer['id']} (use rotate-jwks to update its keys)")

    rules = client.list_all("/federation_rules", {"issuer_id": issuer["id"]})
    rule = next(
        (r for r in rules if (r.get("match") or {}).get("subject_prefix") == args.subject
         and not r.get("archived_at")),
        None,
    )
    if rule is None:
        rule = client.require(
            "POST", "/federation_rules",
            {
                "name": args.name_prefix,
                "issuer_id": issuer["id"],
                "match": {"subject_prefix": args.subject},
                "target": {"type": "service_account", "service_account_id": svac["id"]},
                "workspace_id": args.workspace_id,
                "oauth_scope": "workspace:inference",
                "token_lifetime_seconds": args.token_lifetime,
            },
        )
        print(f"CREATED rule {rule['id']}")
    else:
        print(f"EXISTS rule {rule['id']}")

    print(
        f"\nENROLL_OK issuer={issuer['id']} rule={rule['id']} "
        f"service_account={svac['id']} workspace={args.workspace_id} "
        f"federation_jwks_sha256={jwks_hash}"
    )
    print(vault_record_hint(issuer["id"], rule["id"], svac["id"], args.workspace_id, jwks_hash))
    return 0


def mode_rotate(client: Client, args) -> int:
    keys, file_issuer_url, _ = load_jwks_file(args.jwks_json)
    issuer_url = args.issuer_url or file_issuer_url
    if not issuer_url:
        raise SystemExit("no issuer URL: pass --issuer-url or a helper-format JWKS file")
    jwks_hash = canonical_jwks_sha256(keys)
    issuers = client.list_all("/federation_issuers")
    issuer = find_by(issuers, "issuer_url", issuer_url)
    if issuer is None:
        raise SystemExit(f"issuer not found for {issuer_url}; run enroll first")
    print(f"ROTATE issuer={issuer['id']} new keys={len(keys)} sha256={jwks_hash}")
    if args.dry_run:
        print("DRY_RUN no mutations performed")
        return 0
    client.require(
        "POST", f"/federation_issuers/{issuer['id']}",
        {"jwks": {"type": "inline", "keys": keys}},
    )
    print(f"ROTATE_OK federation_jwks_sha256={jwks_hash}")
    print(
        "\nRecord the approved hash (VM, per the rotation ceremony):\n"
        "  scripts/aigw-compose.sh exec -T -e VAULT_TOKEN vault vault kv patch \\\n"
        f"    kv/ai-gateway/anthropic-wif federation_jwks_sha256={jwks_hash}"
    )
    return 0


def mode_selftest(client: Client, args) -> int:
    suffix = time.strftime("%Y%m%d%H%M%S", time.gmtime())
    name = f"aigw-selftest-{suffix}"
    fake_issuer_url = f"https://selftest-{suffix}.example.invalid/realms/selftest"
    fake_subject = f"selftest-subject-{suffix}"
    created: list[tuple[str, str]] = []  # (path-prefix, id) in creation order
    ok = True
    try:
        svac = client.require(
            "POST", "/service_accounts",
            {"name": name, "organization_role": "developer"},
        )
        created.append(("/service_accounts", svac["id"]))
        print(f"PASS create service_account {svac['id']}")

        issuer = client.require(
            "POST", "/federation_issuers",
            {
                "name": name,
                "issuer_url": fake_issuer_url,
                "jwks": {"type": "inline", "keys": [SELFTEST_JWK]},
            },
        )
        created.append(("/federation_issuers", issuer["id"]))
        print(f"PASS create issuer {issuer['id']} (inline JWKS accepted)")

        rule = client.require(
            "POST", "/federation_rules",
            {
                "name": name,
                "issuer_id": issuer["id"],
                "match": {"subject_prefix": fake_subject},
                "target": {"type": "service_account", "service_account_id": svac["id"]},
                "workspace_id": args.workspace_id,
                "oauth_scope": "workspace:inference",
                "token_lifetime_seconds": 600,
            },
        )
        created.append(("/federation_rules", rule["id"]))
        print(f"PASS create rule {rule['id']} (workspace:inference)")

        got = client.require("GET", f"/federation_issuers/{issuer['id']}")
        live_keys = (got.get("jwks") or {}).get("keys")
        if isinstance(live_keys, list) and canonical_jwks_sha256(live_keys) == canonical_jwks_sha256([SELFTEST_JWK]):
            print("PASS read-back issuer JWKS hash matches upload")
        else:
            print("NOTE read-back issuer did not return inline keys verbatim; "
                  "verify hash via Console once for this org")

        client.require(
            "POST", f"/federation_issuers/{issuer['id']}",
            {"jwks": {"type": "inline", "keys": [dict(SELFTEST_JWK, kid="aigw-selftest-2")]}},
        )
        print("PASS update issuer inline JWKS (rotation path)")
    except SystemExit as exc:
        ok = False
        print(f"FAIL {exc}")
    finally:
        if args.keep:
            print("KEEP requested; not archiving self-test resources")
        else:
            for prefix, rid in reversed(created):
                status, payload = client.call("POST", f"{prefix}/{rid}/archive")
                label = "archived" if status in (200, 201) else f"ARCHIVE_FAILED({status})"
                print(f"CLEANUP {label} {prefix}/{rid}")
                if status not in (200, 201):
                    ok = False
    print("SELF_TEST_OVERALL: %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="mode", required=True)

    p_check = sub.add_parser("check", help="read-only enrollment/drift check")
    p_check.add_argument("--issuer-url", default=DEFAULT_ISSUER_URL)
    p_check.add_argument("--jwks-json", help="local JWKS export to diff against")

    p_enroll = sub.add_parser("enroll", help="find-or-create the full enrollment")
    p_enroll.add_argument("--issuer-url", default=None)
    p_enroll.add_argument("--jwks-json", required=True)
    p_enroll.add_argument("--workspace-id", required=True)
    p_enroll.add_argument("--name-prefix", default="ai-gateway")
    p_enroll.add_argument("--subject", default=DEFAULT_SUBJECT)
    p_enroll.add_argument("--token-lifetime", type=int, default=600)
    p_enroll.add_argument("--dry-run", action="store_true")

    p_rotate = sub.add_parser("rotate-jwks", help="replace the issuer's inline keys")
    p_rotate.add_argument("--issuer-url", default=None)
    p_rotate.add_argument("--jwks-json", required=True)
    p_rotate.add_argument("--dry-run", action="store_true")

    p_self = sub.add_parser("self-test", help="throwaway end-to-end API proof + cleanup")
    p_self.add_argument("--workspace-id", required=True)
    p_self.add_argument("--keep", action="store_true")

    args = parser.parse_args()
    client = Client(read_token())
    if args.mode == "check":
        return mode_check(client, args)
    if args.mode == "enroll":
        return mode_enroll(client, args)
    if args.mode == "rotate-jwks":
        return mode_rotate(client, args)
    return mode_selftest(client, args)


if __name__ == "__main__":
    raise SystemExit(main())
