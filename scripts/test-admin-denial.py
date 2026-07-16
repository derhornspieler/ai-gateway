#!/usr/bin/env python3
"""Prove non-admin identities are DENIED at every ADM-gated admin surface.

Companion to test-oidc-callbacks.py, which proves the ALLOW path for an
aigw-admins identity. This harness proves the converse: lab-user and
lab-developer each authenticate with a real Samba-backed password through
Keycloak -- so a genuine credential and a genuine Keycloak login are proven,
never a broken-login false pass -- and are then rejected because neither
carries aigw-admins:

  * oauth2-proxy's OAUTH2_PROXY_ALLOWED_GROUPS="aigw-admins" check denies the
    four ADM relying parties (litellm-admin, grafana, prometheus, vault) at
    their own /oauth2/callback, after Keycloak has already issued a real
    authorization code;
  * admin-portal's own require_admin dependency (services/dev-portal/app/
    auth.py) denies admin.<domain>/admin with a 403 after establishing a real
    portal session (services/dev-portal/app/main.py FORBIDDEN_HTML).

This is a denial-only harness and deliberately accepts no admin fixture as
--username: pointing it at an admin identity would prove nothing (or worse,
mask a broken deny path behind an unrelated allow).

The disposable lab password is accepted only on stdin and is never logged,
persisted, placed in argv, or included in an exception message.
"""

from __future__ import annotations

import argparse
import http.cookiejar
import importlib.util
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


OIDC_PATH = Path(__file__).with_name("test-oidc-callbacks.py")
_OIDC_SPEC = importlib.util.spec_from_file_location("aigw_oidc_callbacks", OIDC_PATH)
if _OIDC_SPEC is None or _OIDC_SPEC.loader is None:
    raise RuntimeError("could not load the reviewed OIDC callback targets")
oidc = importlib.util.module_from_spec(_OIDC_SPEC)
# Register before exec: oidc.py's @dataclass(frozen=True) target definitions
# resolve their own module via sys.modules during class creation on newer
# Python, which requires the module to already be registered there.
sys.modules[_OIDC_SPEC.name] = oidc
_OIDC_SPEC.loader.exec_module(oidc)

FLOW_PATH = Path(__file__).with_name("test-portal-identity-flow.py")
_FLOW_SPEC = importlib.util.spec_from_file_location("aigw_portal_flow", FLOW_PATH)
if _FLOW_SPEC is None or _FLOW_SPEC.loader is None:
    raise RuntimeError("could not load portal acceptance helpers")
flow = importlib.util.module_from_spec(_FLOW_SPEC)
sys.modules[_FLOW_SPEC.name] = flow
_FLOW_SPEC.loader.exec_module(flow)


# Deliberately narrow: only the two non-admin lab fixtures. An admin fixture
# here would defeat the point of a denial harness.
DENIED_USERNAMES = frozenset({"lab-user", "lab-developer"})
ADM_TARGET_NAMES = ("litellm-admin", "grafana", "prometheus", "vault")
ALL_TARGET_NAMES = (*ADM_TARGET_NAMES, "admin-portal")


class DenialAssertionError(RuntimeError):
    """A deliberately non-sensitive live-acceptance denial-check failure."""


def oauth2_proxy_denial(
    context: ssl.SSLContext, target_name: str, username: str, password: str
) -> None:
    """Prove one ADM relying party denies a real, authenticated non-admin."""

    target = oidc.TARGET_BY_NAME[target_name]
    cookies = http.cookiejar.CookieJar()
    redirects = oidc.RestrictedRedirects(target)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        urllib.request.HTTPCookieProcessor(cookies),
        redirects,
    )
    login_url, login_html = oidc.read_response(opener, oidc.start_url(target))
    login_parts = oidc.reviewed_https_url(login_url, target.allowed_hosts)
    if login_parts.hostname != oidc.AUTH_HOST:
        raise DenialAssertionError("OIDC start did not reach the Keycloak password form")
    form = oidc.find_keycloak_login_form(login_html)
    action = oidc.reviewed_login_action(login_url, form, target)
    values = dict(form["inputs"])
    values.update({"username": username, "password": password})
    request = urllib.request.Request(
        action,
        data=urllib.parse.urlencode(values).encode("utf-8"),
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "aigw-acceptance/1",
        },
        method="POST",
    )
    try:
        with opener.open(request, timeout=45) as response:
            raise DenialAssertionError(
                f"{target.name} accepted the non-admin session with status "
                f"{response.getcode()} instead of denying it"
            )
    except urllib.error.HTTPError as exc:
        status = exc.code
        final_url = exc.geturl()
        body = exc.read(oidc.MAX_RESPONSE_BYTES + 1).decode("utf-8", errors="replace")
    except (OSError, ssl.SSLError, urllib.error.URLError) as exc:
        raise DenialAssertionError(f"{target.name} denial request could not be completed") from exc

    if status != 403:
        raise DenialAssertionError(f"{target.name} denial returned unexpected status {status}")
    parsed = oidc.reviewed_https_url(final_url, target.allowed_hosts)
    if parsed.hostname != target.host or parsed.path != target.callback_path:
        raise DenialAssertionError(
            f"{target.name} denial did not occur at its own OAuth callback boundary"
        )
    query_names = {name for name, _ in urllib.parse.parse_qsl(parsed.query)}
    if "code" not in query_names:
        # Landing on /oauth2/callback without a code would mean Keycloak never
        # authenticated the user at all -- a broken-login false pass, not
        # proof that the role-gate denied a real session.
        raise DenialAssertionError(
            f"{target.name} denial happened before Keycloak issued an authorization "
            "code -- this would prove a broken login, not a role denial"
        )
    if "403 Forbidden" not in body:
        raise DenialAssertionError(
            f"{target.name} denial body did not match the expected oauth2-proxy 403 page"
        )
    if any(cookie.name == target.session_cookie for cookie in cookies):
        raise DenialAssertionError(
            f"{target.name} established its application session despite denial"
        )


def admin_portal_denial(context: ssl.SSLContext, username: str, password: str) -> None:
    """Prove admin-portal's /admin denies a real, authenticated non-admin."""

    cookies = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        urllib.request.HTTPCookieProcessor(cookies),
        flow.RestrictedRedirects(flow.ADMIN_PORTAL_ALLOWED_HOSTS),
    )
    try:
        final_url, _ = flow.keycloak_login(
            opener,
            flow.ADMIN_PORTAL_ORIGIN + "/login/start",
            password,
            allowed_hosts=flow.ADMIN_PORTAL_ALLOWED_HOSTS,
            username=username,
        )
        raise DenialAssertionError(
            f"admin-portal accepted the non-admin session and reached {final_url!r} "
            "instead of denying it"
        )
    except urllib.error.HTTPError as exc:
        status = exc.code
        final_url = exc.geturl()
        body = exc.read(2 * 1024 * 1024 + 1).decode("utf-8", errors="replace")
    except (OSError, ssl.SSLError, urllib.error.URLError) as exc:
        raise DenialAssertionError("admin-portal denial request could not be completed") from exc

    if status != 403:
        raise DenialAssertionError(f"admin-portal denial returned unexpected status {status}")
    parsed = urllib.parse.urlsplit(final_url)
    if parsed.hostname != "admin.aigw.aegisgroup.ch" or parsed.path != "/admin":
        raise DenialAssertionError("admin-portal denial did not occur at /admin")
    if "403 Forbidden" not in body:
        raise DenialAssertionError("admin-portal denial body did not match the expected forbidden page")
    if "INITIALIZE" in body or "identity-confirmation" in body:
        raise DenialAssertionError("admin-portal denial body leaked real admin page content")
    if not any(cookie.name == "aigw_admin_session" for cookie in cookies):
        # No session at all would mean the login itself failed (bad
        # credentials/CSRF/etc.), not that require_admin denied a real one.
        raise DenialAssertionError(
            "admin-portal denial happened before a session was established -- this "
            "would prove a broken login, not a role denial"
        )


def read_password() -> str:
    if sys.stdin.isatty():
        raise SystemExit("pipe the disposable lab password on stdin")
    raw = sys.stdin.buffer.read(513)
    if not raw or len(raw) > 512:
        raise SystemExit("invalid lab password length")
    try:
        password = raw.strip().decode("utf-8")
    except UnicodeDecodeError:
        raise SystemExit("lab password is not UTF-8") from None
    if not password:
        raise SystemExit("invalid lab password")
    return password


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ca", required=True)
    parser.add_argument("--username", choices=sorted(DENIED_USERNAMES), required=True)
    parser.add_argument("--target", choices=("all", *ALL_TARGET_NAMES), default="all")
    args = parser.parse_args()
    password = read_password()
    try:
        context = ssl.create_default_context(cafile=args.ca)
    except (OSError, ssl.SSLError) as exc:
        raise SystemExit("could not load the reviewed CA file") from exc

    selected = ALL_TARGET_NAMES if args.target == "all" else (args.target,)
    for name in selected:
        try:
            if name == "admin-portal":
                admin_portal_denial(context, args.username, password)
            else:
                oauth2_proxy_denial(context, name, args.username, password)
        except Exception:
            # Keep query strings, cookies, forms, and password-derived details
            # out of CI and terminal output.
            print(f"ADMIN_DENIAL_FAIL target={name} username={args.username}", file=sys.stderr)
            return 1
        print(f"ADMIN_DENIAL_PASS target={name} username={args.username}")
    print(f"ADMIN_DENIAL_ALL_PASS count={len(selected)} username={args.username}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
