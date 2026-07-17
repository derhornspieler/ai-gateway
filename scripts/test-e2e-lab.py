#!/usr/bin/env python3
"""End-to-end lab gate: one PASS/FAIL over the user-facing and backend surfaces.

Controller-side orchestrator that chains the already-reviewed single-purpose
live-lab harnesses plus the checks the 2026-07-16 rehearsals added, so a single
command re-proves the whole stack after any converge or image bump:

  * OIDC RP-logout round-trips  — chat end_session -> login, and each admin
    host's /oauth2/sign_out -> Keycloak end_session -> app root (unauthenticated
    302 assertions; no secrets)
  * WIF-backed Anthropic inference (Messages + OpenAI-chat) as lab-developer
  * Open WebUI chat for each lab role
  * (optional, --vm) the stack-internal identity baseline via the existing
    verify-live-lab-identity.py, run over SSH because it speaks the rotator's
    internal API

Hyphenated on purpose (excluded from unittest discovery / the VM manifest /
validate-compose) — this hits a real deployed lab. Passwords are read only as a
JSON map on stdin, forwarded to each sub-harness on its own stdin, and never
logged. Exit 0 iff every step passes.

  echo '{"lab-admin":"..","lab-developer":"..","lab-user":".."}' \
    | python3 scripts/test-e2e-lab.py --ca compose/certs/ca.pem \
        [--domain aigw.aegisgroup.ch] [--vm ansible@10.8.10.10]

To source the disposable lab passwords from the VM instead of typing them:

  ssh <vm> 'for u in lab-admin lab-developer lab-user; do
      printf "%s\0" "$u"; sudo cat /opt/ai-gateway/secrets/samba_user_${u}_password; printf "\0";
    done' | python3 -c 'import sys,json;b=sys.stdin.buffer.read().split(b"\0");\
      print(json.dumps({b[i].decode():b[i+1].decode() for i in range(0,len(b)-1,2)}))' \
    | python3 scripts/test-e2e-lab.py --ca compose/certs/ca.pem --vm <vm>
"""
from __future__ import annotations

import argparse
import json
import ssl
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ADMIN_HOSTS = ("litellm-admin", "grafana", "prometheus", "vault")
ROLES = ("lab-admin", "lab-developer", "lab-user")


class Results:
    def __init__(self) -> None:
        self.rows: list[tuple[str, bool, str]] = []

    def record(self, name: str, ok: bool, detail: str = "") -> None:
        self.rows.append((name, ok, detail))
        print(f"[{'PASS' if ok else 'FAIL'}] {name}{'  — ' + detail if detail else ''}")

    def ok(self) -> bool:
        return all(ok for _, ok, _ in self.rows)


def _opener(ca: str) -> urllib.request.OpenerDirector:
    ctx = ssl.create_default_context(cafile=ca)
    # We assert on the 3xx Location without following it, so redirects to a
    # different host are inspected rather than chased.
    return urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx), _NoRedirect()
    )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # noqa: D401 - urllib hook
        return None


def _location(opener, url: str) -> tuple[int, str]:
    try:
        resp = opener.open(url, timeout=15)
        return resp.status, resp.headers.get("Location", "")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get("Location", "")


def check_logout_chains(res: Results, ca: str, domain: str) -> None:
    opener = _opener(ca)
    # Admin hosts: /oauth2/sign_out?rd=<Keycloak end_session> must 302 to the
    # auth edge, and that end_session must 302 back to the host root.
    for host in ADMIN_HOSTS:
        app_root = f"https://{host}.{domain}/"
        end_session = (
            f"https://auth.{domain}/realms/aigw/protocol/openid-connect/logout"
            f"?client_id=admin-ui&post_logout_redirect_uri="
            + urllib.parse.quote(app_root, safe="")
        )
        signout = (
            f"https://{host}.{domain}/oauth2/sign_out?rd="
            + urllib.parse.quote(end_session, safe="")
        )
        s1, l1 = _location(opener, signout)
        hop_ok = s1 == 302 and l1.startswith(f"https://auth.{domain}/")
        s2, l2 = _location(opener, end_session)
        back_ok = s2 == 302 and l2.rstrip("/") == app_root.rstrip("/")
        res.record(
            f"logout:{host}", hop_ok and back_ok,
            f"sign_out={s1}->auth end_session={s2}->{l2 or '(none)'}",
        )
    # Chat: end_session with the open-webui client must 302 to the chat root.
    chat_root = f"https://chat.{domain}/"
    chat_es = (
        f"https://auth.{domain}/realms/aigw/protocol/openid-connect/logout"
        f"?client_id=open-webui&post_logout_redirect_uri="
        + urllib.parse.quote(chat_root, safe="")
    )
    s, loc = _location(opener, chat_es)
    res.record(
        "logout:chat", s == 302 and loc.rstrip("/") == chat_root.rstrip("/"),
        f"end_session={s}->{loc or '(none)'}",
    )


def _run_harness(script: str, args: list[str], password: str) -> tuple[bool, str]:
    proc = subprocess.run(
        [sys.executable, str(HERE / script), *args],
        input=(password + "\n").encode(),
        capture_output=True,
        timeout=180,
    )
    out = proc.stdout.decode(errors="replace")
    tail = out.strip().splitlines()[-1] if out.strip() else proc.stderr.decode()[-200:]
    return proc.returncode == 0, tail


def check_inference(res: Results, ca: str, pw: str) -> None:
    ok, tail = _run_harness("test-wif-inference.py", ["--ca", ca], pw)
    res.record("wif-inference:lab-developer", ok and "PASS" in tail, tail)


def check_chat(res: Results, ca: str, pwmap: dict) -> None:
    for role in ROLES:
        pw = pwmap.get(role)
        if not pw:
            res.record(f"chat:{role}", False, "no password provided")
            continue
        ok, tail = _run_harness(
            "test-openwebui-chat.py", ["--ca", ca, "--user", role], pw
        )
        res.record(f"chat:{role}", ok and "PASS" in tail, tail)


def check_identity_over_ssh(res: Results, vm: str) -> None:
    # verify-live-lab-identity.py speaks the rotator's internal API, so it runs
    # inside the stack. Invoke it on the VM the same way an operator would,
    # forwarding the internal token from the running key-rotator's environment.
    # The rotator image is distroless (no shell/printenv), so read its internal
    # token from the container config (host root, kept in a shell var) and run
    # the verifier in a throwaway python container that JOINS the rotator's
    # network namespace — so the script's hardcoded key-rotator:8080 resolves
    # and localhost works. The script arrives on stdin; no bind mount needed.
    remote = (
        "sudo bash -c '"
        "T=$(docker inspect -f \"{{range .Config.Env}}{{println .}}{{end}}\" "
        "ai-gateway-key-rotator-1 | sed -n \"s/^ROTATOR_INTERNAL_TOKEN=//p\"); "
        "docker run --rm -i --network container:ai-gateway-key-rotator-1 "
        "-e ROTATOR_INTERNAL_TOKEN=\"$T\" --entrypoint python3 "
        "dhi.io/python:3.12.13 - < /opt/ai-gateway/scripts/verify-live-lab-identity.py'"
    )
    try:
        proc = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", vm, remote],
            capture_output=True, timeout=60,
        )
        out = (proc.stdout + proc.stderr).decode(errors="replace").strip()
        tail = out.splitlines()[-1] if out else "(no output)"
        res.record(
            "identity-baseline", proc.returncode == 0 and "PASS" in out, tail
        )
    except Exception as exc:  # noqa: BLE001 - report, don't abort the gate
        res.record("identity-baseline", False, f"ssh error: {exc}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ca", required=True, help="Aegis root CA PEM")
    ap.add_argument("--domain", default="aigw.aegisgroup.ch")
    ap.add_argument("--vm", default="", help="SSH target for the internal identity check")
    args = ap.parse_args()

    if sys.stdin.isatty():
        raise SystemExit("pipe a JSON {user: password} map on stdin")
    try:
        pwmap = json.loads(sys.stdin.read() or "{}")
        assert isinstance(pwmap, dict)
    except Exception:
        raise SystemExit("stdin must be a JSON object of {user: password}")

    res = Results()
    print("== OIDC RP-logout round-trips ==")
    check_logout_chains(res, args.ca, args.domain)
    print("== WIF-backed Anthropic inference ==")
    check_inference(res, args.ca, pwmap.get("lab-developer", ""))
    print("== Open WebUI chat per role ==")
    check_chat(res, args.ca, pwmap)
    if args.vm:
        print("== stack-internal identity baseline ==")
        check_identity_over_ssh(res, args.vm)

    passed = sum(1 for _, ok, _ in res.rows if ok)
    print(f"\nE2E_LAB_OVERALL: {'PASS' if res.ok() else 'FAIL'} "
          f"({passed}/{len(res.rows)} steps)")
    return 0 if res.ok() else 1


if __name__ == "__main__":
    raise SystemExit(main())
