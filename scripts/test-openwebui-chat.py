#!/usr/bin/env python3
"""Prove Open WebUI chat end-to-end as a lab identity over public HTTPS.

Logs into chat.aigw.aegisgroup.ch through the real Keycloak OIDC flow,
lists the models Open WebUI exposes, and requires a real Claude (haiku)
completion via POST /api/chat/completions — exercising Open WebUI's
scoped workload key -> LiteLLM -> Envoy -> Anthropic (WIF credential).

Controller-side, hyphenated (excluded from unittest discovery / the VM
manifest / validate-compose). The disposable lab password is accepted only
on stdin and never logged; the Open WebUI session token is never printed.

Usage:
  ... password on stdin ... test-openwebui-chat.py --ca <root-ca> [--user lab-developer]
"""

from __future__ import annotations

import argparse
import http.cookiejar
import importlib.util
import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


HERE = Path(__file__).resolve().parent
flow = _load("aigw_portal_flow", HERE / "test-portal-identity-flow.py")

CHAT_ORIGIN = "https://chat.aigw.aegisgroup.ch"
CHAT_ALLOWED_HOSTS = frozenset({"chat.aigw.aegisgroup.ch", flow.AUTH_HOST})


class ChatRestrictedRedirects(urllib.request.HTTPRedirectHandler):
    """Same semantics as the portal flow's RestrictedRedirects, but for the
    chat/Keycloak boundary (the portal class only accepts its own reviewed
    host sets)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if parsed.scheme != "https" or parsed.hostname not in CHAT_ALLOWED_HOSTS:
            raise RuntimeError("OIDC redirect left the reviewed chat/Keycloak hosts")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def read_page(opener, url: str) -> tuple[str, str]:
    request = urllib.request.Request(url, headers={"User-Agent": "aigw-acceptance/1"})
    with opener.open(request, timeout=30) as response:
        final_url = response.geturl()
        body = response.read(2 * 1024 * 1024 + 1)
    if len(body) > 2 * 1024 * 1024:
        raise RuntimeError("acceptance response exceeded 2 MiB")
    return final_url, body.decode("utf-8", errors="strict")


def post_form(opener, base_url: str, form: dict, fields: dict[str, str]):
    """flow.post_form, restricted to the chat/Keycloak boundary."""
    action = urllib.parse.urljoin(base_url, str(form["action"]))
    parsed = urllib.parse.urlsplit(action)
    if parsed.scheme != "https" or parsed.hostname not in CHAT_ALLOWED_HOSTS:
        raise RuntimeError("form action left the reviewed chat/Keycloak hosts")
    values = dict(form["inputs"])
    values.update(fields)
    data = urllib.parse.urlencode(values).encode("utf-8")
    request = urllib.request.Request(
        action,
        data=data,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "aigw-acceptance/1",
        },
        method="POST",
    )
    with opener.open(request, timeout=30) as response:
        final_url = response.geturl()
        body = response.read(2 * 1024 * 1024 + 1)
    if len(body) > 2 * 1024 * 1024:
        raise RuntimeError("acceptance response exceeded 2 MiB")
    return final_url, body.decode("utf-8", errors="strict")


def api(opener, token: str, path: str, payload: dict | None = None, timeout: int = 90):
    req = urllib.request.Request(
        CHAT_ORIGIN + path,
        data=None if payload is None else json.dumps(payload).encode(),
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="GET" if payload is None else "POST",
    )
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "{}")
        except Exception:
            return e.code, {}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ca", required=True)
    ap.add_argument("--user", default="lab-developer")
    args = ap.parse_args()
    if sys.stdin.isatty():
        raise SystemExit("pipe the lab password on stdin")
    raw = sys.stdin.buffer.read(513)
    if not raw or len(raw) > 512:
        raise SystemExit("invalid lab password length")
    password = raw.strip().decode("utf-8")

    ctx = ssl.create_default_context(cafile=args.ca)
    cookies = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ctx),
        urllib.request.HTTPCookieProcessor(cookies),
        ChatRestrictedRedirects(),
    )

    # OIDC login: Open WebUI -> Keycloak -> callback -> session cookie.
    page_url, body = read_page(opener, CHAT_ORIGIN + "/oauth/oidc/login")
    forms = [
        f for f in flow.parse_forms(body)
        if "/login-actions/authenticate" in str(f["action"])
    ]
    if len(forms) != 1:
        raise RuntimeError("expected exactly one Keycloak login form")
    page_url, body = post_form(
        opener,
        page_url,
        forms[0],
        {"username": args.user, "password": password},
    )
    if urllib.parse.urlsplit(page_url).hostname != "chat.aigw.aegisgroup.ch":
        raise RuntimeError("OIDC login did not return to Open WebUI")

    token = next(
        (c.value for c in cookies if c.name == "token" and c.value), None
    )
    if not token:
        raise RuntimeError("Open WebUI session cookie was not established")
    print("LOGIN_OK user=%s (session cookie present, value withheld)" % args.user)

    status, me = api(opener, token, "/api/v1/auths/")
    role = me.get("role") if isinstance(me, dict) else None
    print("SESSION status=%s role=%s" % (status, role))
    if status != 200 or role not in {"user", "admin"}:
        print("FAIL: session not active (role=%r)" % role)
        return 1

    status, models = api(opener, token, "/api/models")
    ids = [
        m.get("id")
        for m in (models.get("data", []) if isinstance(models, dict) else [])
        if isinstance(m, dict) and m.get("id")
    ]
    print("MODELS (%d): %s" % (len(ids), ", ".join(ids[:16])))
    haiku = next((i for i in ids if "haiku" in i.lower()), None)
    if not haiku:
        print("FAIL: no haiku model visible in Open WebUI")
        print("models raw status=%s body=%s" % (status, json.dumps(models)[:400]))
        return 1

    status, reply = api(opener, token, "/api/chat/completions", {
        "model": haiku,
        "messages": [{"role": "user", "content": "Reply with exactly one word: pong"}],
        "stream": False,
    })
    text = ""
    choices = reply.get("choices") if isinstance(reply, dict) else None
    if isinstance(choices, list) and choices:
        text = (choices[0].get("message") or {}).get("content", "") or ""
    if status == 200 and text.strip():
        print("CHAT_PASS status=200 model=%s reply=%r" % (haiku, text[:80]))
        print("OPENWEBUI_CHAT_OVERALL: PASS")
        return 0
    print("CHAT_FAIL status=%s body=%s" % (status, json.dumps(reply)[:300]))
    print("OPENWEBUI_CHAT_OVERALL: FAIL")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
