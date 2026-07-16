#!/usr/bin/env python3
"""Prove WIF-backed Anthropic inference through the gateway as lab-developer.

Mints a one-time portal key for lab-developer, then proves a real Claude
(haiku) completion returns via BOTH the Anthropic Messages format
(POST /v1/messages) and the OpenAI Chat format (POST /v1/chat/completions) —
exercising LiteLLM -> Envoy -> Anthropic through the WIF-minted
`anthropic-primary` credential. Deactivates the key on exit.

Controller-side, hyphenated (excluded from unittest discovery / the VM
manifest / validate-compose). The disposable lab password is accepted only on
stdin and is never logged; the minted key is masked and deactivated.
"""

from __future__ import annotations

import argparse
import http.cookiejar
import importlib.util
import json
import ssl
import sys
import time
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
klc = _load("aigw_key_lifecycle", HERE / "test-portal-key-lifecycle.py")
flow = klc.flow
API = klc.API_ORIGIN  # https://api.aigw.aegisgroup.ch


def _plain_opener(ctx: ssl.SSLContext):
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ctx),
    )


def list_models(ctx, key: str):
    req = urllib.request.Request(
        API + "/v1/models", headers={"Authorization": "Bearer " + key}
    )
    with _plain_opener(ctx).open(req, timeout=30) as r:
        data = json.load(r)
    ids = [m.get("id") for m in data.get("data", []) if isinstance(m, dict) and m.get("id")]
    haiku = next((i for i in ids if "haiku" in i.lower()), None)
    return haiku, ids


def infer(ctx, key: str, path: str, payload: dict):
    req = urllib.request.Request(
        API + path,
        data=json.dumps(payload).encode(),
        headers={
            "Authorization": "Bearer " + key,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with _plain_opener(ctx).open(req, timeout=90) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "{}")
        except Exception:
            return e.code, {}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ca", required=True)
    args = ap.parse_args()
    if sys.stdin.isatty():
        raise SystemExit("pipe the lab-developer password on stdin")
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
        flow.RestrictedRedirects(flow.PORTAL_ALLOWED_HOSTS),
    )

    # OIDC login as lab-developer -> land on the key page.
    page_url, body = flow.read_page(opener, flow.PORTAL_ORIGIN + "/login/start")
    forms = [
        f for f in flow.parse_forms(body)
        if "/login-actions/authenticate" in str(f["action"])
    ]
    if len(forms) != 1:
        raise RuntimeError("expected exactly one Keycloak login form")
    page_url, body = flow.post_form(
        opener,
        page_url,
        forms[0],
        {"username": "lab-developer", "password": password},
        allowed_hosts=flow.PORTAL_ALLOWED_HOSTS,
    )
    if urllib.parse.urlsplit(page_url).path != "/":
        raise RuntimeError("lab-developer login did not reach the key page")

    # One active key per user per project: a crashed prior run can leave a
    # stale active key that blocks the mint. Deactivate it first if present.
    try:
        klc.exact_form(page_url, body, "/keys/deactivate")
    except RuntimeError:
        pass
    else:
        klc.deactivate(opener, page_url, body)
        print("STALE_KEY_DEACTIVATED (pre-clean)")
        page_url, body = flow.read_page(opener, flow.PORTAL_ORIGIN + "/")

    # LiteLLM key aliases are unique across ALL keys, including deactivated
    # ones — a fixed alias would collide with prior runs' blocked keys.
    alias = "wif-inference-probe-" + time.strftime("%Y%m%d%H%M%S", time.gmtime())
    key, _, post = klc.generate(opener, page_url, body, alias)
    if key not in post:
        raise RuntimeError("minted key not present in creation response")
    print("MINTED lab-developer key (masked): %s...%s" % (key[:10], key[-4:]))

    ok = True
    try:
        model, ids = list_models(ctx, key)
        shown = ", ".join([i for i in ids][:16])
        print("MODELS (%d): %s" % (len(ids), shown))
        if not model:
            print("FAIL: no haiku model in the key's allowlist")
            return 1
        print("HAIKU model id: %s" % model)

        msg = "Reply with exactly one word: pong"
        # 1) Anthropic Messages format (native).
        s1, r1 = infer(ctx, key, "/v1/messages", {
            "model": model, "max_tokens": 24,
            "messages": [{"role": "user", "content": msg}],
        })
        text1 = ""
        if isinstance(r1.get("content"), list):
            text1 = " ".join(
                b.get("text", "") for b in r1["content"] if isinstance(b, dict)
            )
        if s1 == 200 and text1.strip():
            print("ANTHROPIC_MESSAGES_PASS status=200 model=%s reply=%r" % (
                r1.get("model", model), text1[:80]))
        else:
            print("ANTHROPIC_MESSAGES_FAIL status=%s body=%s" % (s1, json.dumps(r1)[:300]))
            ok = False

        # 2) OpenAI Chat Completions format (the opencode / OpenAI-client path).
        s2, r2 = infer(ctx, key, "/v1/chat/completions", {
            "model": model,
            "messages": [{"role": "user", "content": msg}],
            "max_tokens": 24,
        })
        text2 = ""
        choices = r2.get("choices")
        if isinstance(choices, list) and choices:
            text2 = (choices[0].get("message") or {}).get("content", "") or ""
        if s2 == 200 and text2.strip():
            print("OPENAI_CHAT_PASS status=200 model=%s reply=%r" % (
                r2.get("model", model), text2[:80]))
        else:
            print("OPENAI_CHAT_FAIL status=%s body=%s" % (s2, json.dumps(r2)[:300]))
            ok = False
    finally:
        try:
            purl, pbody = flow.read_page(opener, flow.PORTAL_ORIGIN + "/")
            klc.deactivate(opener, purl, pbody)
            print("KEY_DEACTIVATED (no residue)")
        except Exception as e:  # noqa: BLE001
            print("cleanup-note: %s %s" % (type(e).__name__, str(e)[:120]))

    print("WIF_INFERENCE_OVERALL: %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
