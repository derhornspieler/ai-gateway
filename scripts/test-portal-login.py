#!/usr/bin/env python3
"""Verify a lab directory password through the real portal OIDC callback."""

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


FLOW_PATH = Path(__file__).with_name("test-portal-identity-flow.py")
SPEC = importlib.util.spec_from_file_location("aigw_portal_flow", FLOW_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load portal acceptance helpers")
flow = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(flow)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ca", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument(
        "--expect-path",
        choices=("/", "forbidden", "denied"),
        required=True,
    )
    parser.add_argument("--verify-admin", action="store_true")
    parser.add_argument(
        "--logout",
        action="store_true",
        help="finish the accepted login by exercising the portal/Keycloak logout redirect",
    )
    args = parser.parse_args()
    if args.username not in {"lab-admin", "lab-developer", "lab-user", "testadmin", "testuser"}:
        raise SystemExit("invalid acceptance username")
    if args.verify_admin and args.username not in {"lab-admin", "testadmin"}:
        raise SystemExit("admin verification is allowed only for an admin fixture")
    if args.verify_admin and args.expect_path == "denied":
        raise SystemExit("admin verification and denied login are mutually exclusive")
    if sys.stdin.isatty():
        raise SystemExit("pipe the lab password on stdin")
    raw = sys.stdin.buffer.read(513)
    if not raw or len(raw) > 512:
        raise SystemExit("invalid lab password length")
    password = raw.strip().decode("utf-8")

    context = ssl.create_default_context(cafile=args.ca)
    cookies = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        urllib.request.HTTPCookieProcessor(cookies),
        flow.RestrictedRedirects(flow.PORTAL_ALLOWED_HOSTS),
    )
    final_url, html = flow.read_page(opener, flow.PORTAL_ORIGIN + "/login/start")
    forms = [
        form for form in flow.parse_forms(html)
        if "/login-actions/authenticate" in str(form["action"])
    ]
    if len(forms) != 1:
        raise RuntimeError("expected one Keycloak login form")
    try:
        final_url, html = flow.post_form(
            opener,
            final_url,
            forms[0],
            {"username": args.username, "password": password},
            allowed_hosts=flow.PORTAL_ALLOWED_HOSTS,
        )
        actual_path = urllib.parse.urlsplit(final_url).path
    except urllib.error.HTTPError as exc:
        if exc.code != 403 or urllib.parse.urlsplit(exc.geturl()).hostname != "portal.aigw.internal":
            raise
        actual_path = "forbidden"
    if args.expect_path == "denied":
        denied_host = urllib.parse.urlsplit(final_url).hostname
        denied_form = any(
            "/login-actions/authenticate" in str(form["action"])
            for form in flow.parse_forms(html)
        )
        if denied_host != flow.AUTH_HOST or not denied_form:
            raise RuntimeError("removed local identity was not denied by Keycloak")
        # The portal creates a signed pre-auth transaction cookie at
        # /login/start, so cookie presence alone is not evidence of an
        # authenticated session. Remaining on Keycloak's password form (and
        # never reaching the callback) is the authoritative denial proof.
        print(f"PORTAL_LOCAL_LOGIN_DENIED_PASS username={args.username}")
        return 0
    if actual_path != args.expect_path:
        raise RuntimeError(f"unexpected post-login portal path: {actual_path}")
    if not any(cookie.name == "aigw_portal_session" for cookie in cookies):
        raise RuntimeError("portal OIDC callback did not establish a session")
    if args.verify_admin:
        admin_cookies = http.cookiejar.CookieJar()
        admin_opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=context),
            urllib.request.HTTPCookieProcessor(admin_cookies),
            flow.RestrictedRedirects(flow.ADMIN_PORTAL_ALLOWED_HOSTS),
        )
        admin_url, _ = flow.keycloak_login(
            admin_opener,
            flow.ADMIN_PORTAL_ORIGIN + "/login/start",
            password,
            allowed_hosts=flow.ADMIN_PORTAL_ALLOWED_HOSTS,
            username=args.username,
        )
        parsed_admin = urllib.parse.urlsplit(admin_url)
        if (
            parsed_admin.hostname != "admin.aigw.internal"
            or parsed_admin.path != "/admin"
        ):
            raise RuntimeError("directory administrator could not access /admin")
        if not any(
            cookie.name == "aigw_admin_session" for cookie in admin_cookies
        ):
            raise RuntimeError("admin OIDC callback did not establish its own session")
        print(f"PORTAL_DIRECTORY_ADMIN_PASS username={args.username}")
    if args.logout:
        logout_url, logout_html = flow.read_page(opener, flow.PORTAL_ORIGIN + "/logout")
        parsed_logout = urllib.parse.urlsplit(logout_url)
        if (
            parsed_logout.hostname == flow.AUTH_HOST
            and parsed_logout.path.endswith("/protocol/openid-connect/logout")
        ):
            confirmation_forms = [
                form
                for form in flow.parse_forms(logout_html)
                if "/logout-confirm" in str(form["action"])
            ]
            if len(confirmation_forms) != 1:
                raise RuntimeError("Keycloak logout confirmation form was not unique")
            logout_url, _ = flow.post_form(
                opener,
                logout_url,
                confirmation_forms[0],
                {},
                allowed_hosts=flow.PORTAL_ALLOWED_HOSTS,
            )
            parsed_logout = urllib.parse.urlsplit(logout_url)
        if parsed_logout.hostname != "portal.aigw.internal" or parsed_logout.path != "/login":
            raise RuntimeError(
                "portal logout did not complete the reviewed Keycloak redirect: "
                f"host={parsed_logout.hostname} path={parsed_logout.path}"
            )
        if any(cookie.name == "aigw_portal_session" for cookie in cookies):
            raise RuntimeError("portal session cookie survived logout")
        print(f"PORTAL_LOGOUT_PASS username={args.username}")
    print(f"PORTAL_SAMBA_LOGIN_PASS username={args.username} result={actual_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
