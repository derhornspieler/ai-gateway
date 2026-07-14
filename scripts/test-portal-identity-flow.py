#!/usr/bin/env python3
"""Exercise the real portal OIDC step-up and INITIALIZE form flow.

The disposable lab password is accepted only on stdin and is never logged,
persisted, placed in argv, or included in an exception message.
"""

from __future__ import annotations

import argparse
import http.cookiejar
import ssl
import sys
import urllib.parse
import urllib.request
from html.parser import HTMLParser


PORTAL_ORIGIN = "https://portal.aigw.aegisgroup.ch"
ADMIN_PORTAL_ORIGIN = "https://admin.aigw.aegisgroup.ch"
AUTH_HOST = "auth.aigw.aegisgroup.ch"
PORTAL_ALLOWED_HOSTS = frozenset({"portal.aigw.aegisgroup.ch", AUTH_HOST})
ADMIN_PORTAL_ALLOWED_HOSTS = frozenset(
    {"admin.aigw.aegisgroup.ch", AUTH_HOST}
)
REVIEWED_HOST_SETS = frozenset(
    {PORTAL_ALLOWED_HOSTS, ADMIN_PORTAL_ALLOWED_HOSTS}
)


class RestrictedRedirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_hosts: frozenset[str]) -> None:
        super().__init__()
        if allowed_hosts not in REVIEWED_HOST_SETS:
            raise ValueError("redirect hosts must match one reviewed portal boundary")
        self.allowed_hosts = allowed_hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if parsed.scheme != "https" or parsed.hostname not in self.allowed_hosts:
            raise RuntimeError("OIDC redirect left the reviewed portal/Keycloak hosts")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict[str, object]] = []
        self._form: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs) -> None:
        values = dict(attrs)
        if tag == "form":
            self._form = {
                "action": values.get("action", ""),
                "method": values.get("method", "get").lower(),
                "inputs": {},
            }
            self.forms.append(self._form)
        elif tag == "input" and self._form is not None:
            name = values.get("name")
            if name:
                self._form["inputs"][name] = values.get("value", "")

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None


def read_page(opener, url: str) -> tuple[str, str]:
    request = urllib.request.Request(url, headers={"User-Agent": "aigw-acceptance/1"})
    with opener.open(request, timeout=20) as response:
        final_url = response.geturl()
        body = response.read(2 * 1024 * 1024 + 1)
    if len(body) > 2 * 1024 * 1024:
        raise RuntimeError("acceptance response exceeded 2 MiB")
    return final_url, body.decode("utf-8", errors="strict")


def parse_forms(html: str) -> list[dict[str, object]]:
    parser = FormParser()
    parser.feed(html)
    return parser.forms


def post_form(
    opener,
    base_url: str,
    form: dict[str, object],
    fields: dict[str, str],
    *,
    allowed_hosts: frozenset[str],
):
    if allowed_hosts not in REVIEWED_HOST_SETS:
        raise ValueError("form hosts must match one reviewed portal boundary")
    action = urllib.parse.urljoin(base_url, str(form["action"]))
    parsed = urllib.parse.urlsplit(action)
    if parsed.scheme != "https" or parsed.hostname not in allowed_hosts:
        raise RuntimeError("form action left the reviewed portal/Keycloak hosts")
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


def keycloak_login(
    opener,
    start_url: str,
    password: str,
    *,
    allowed_hosts: frozenset[str],
    username: str = "testadmin",
) -> tuple[str, str]:
    final_url, html = read_page(opener, start_url)
    forms = [
        form
        for form in parse_forms(html)
        if "/login-actions/authenticate" in str(form["action"])
    ]
    if len(forms) != 1 or urllib.parse.urlsplit(final_url).hostname != AUTH_HOST:
        raise RuntimeError("expected exactly one Keycloak password form")
    return post_form(
        opener,
        final_url,
        forms[0],
        {"username": username, "password": password},
        allowed_hosts=allowed_hosts,
    )


def identity_flow(portal_opener, admin_opener, password: str) -> None:
    # A fresh deployment deliberately fails closed for developer-project
    # lookups until the one-time identity controller has been initialized.
    # Bootstrap through the separate administrator application first; testing
    # a normal developer landing page before that would correctly produce a
    # 503 rather than test the OIDC callback.
    #
    # The administrator application has its own OIDC client, signing key, and
    # cookie name. Establish that independent session before requesting its
    # prompt=login/max_age=0 step-up route.
    final_url, _ = keycloak_login(
        admin_opener,
        ADMIN_PORTAL_ORIGIN + "/login/start",
        password,
        allowed_hosts=ADMIN_PORTAL_ALLOWED_HOSTS,
    )
    parsed = urllib.parse.urlsplit(final_url)
    if parsed.hostname != "admin.aigw.aegisgroup.ch" or parsed.path != "/admin":
        raise RuntimeError("ordinary admin OIDC login did not reach /admin")
    print("ADMIN_PORTAL_OIDC_LOGIN_PASS")

    final_url, html = keycloak_login(
        admin_opener,
        ADMIN_PORTAL_ORIGIN + "/admin/reauth",
        password,
        allowed_hosts=ADMIN_PORTAL_ALLOWED_HOSTS,
    )
    parsed = urllib.parse.urlsplit(final_url)
    if parsed.hostname != "admin.aigw.aegisgroup.ch" or parsed.path != "/admin":
        raise RuntimeError("forced OIDC reauthentication did not return to /admin")
    print("PORTAL_FORCED_REAUTH_PASS")

    bootstrap_forms = [
        form
        for form in parse_forms(html)
        if urllib.parse.urlsplit(
            urllib.parse.urljoin(final_url, str(form["action"]))
        ).path
        == "/admin/identity/bootstrap"
    ]
    if len(bootstrap_forms) != 1:
        raise RuntimeError("portal did not expose exactly one INITIALIZE form")
    csrf = str(bootstrap_forms[0]["inputs"].get("csrf_token", ""))
    if len(csrf) < 32:
        raise RuntimeError("portal INITIALIZE form had no valid CSRF token")
    final_url, html = post_form(
        admin_opener,
        final_url,
        bootstrap_forms[0],
        {"confirmation": "INITIALIZE", "csrf_token": csrf},
        allowed_hosts=ADMIN_PORTAL_ALLOWED_HOSTS,
    )
    parsed = urllib.parse.urlsplit(final_url)
    if parsed.hostname != "admin.aigw.aegisgroup.ch" or parsed.path != "/admin":
        raise RuntimeError("INITIALIZE did not return to the admin portal")
    if "Keycloak identity setup completed." not in html:
        raise RuntimeError("portal did not report successful identity setup")
    print("PORTAL_IDENTITY_INITIALIZE_PASS")

    # Only after the controller state is durable should the developer portal
    # be expected to perform its fail-closed live project-membership lookup.
    final_url, _ = keycloak_login(
        portal_opener,
        PORTAL_ORIGIN + "/login/start",
        password,
        allowed_hosts=PORTAL_ALLOWED_HOSTS,
    )
    parsed = urllib.parse.urlsplit(final_url)
    if parsed.hostname != "portal.aigw.aegisgroup.ch" or parsed.path != "/":
        raise RuntimeError("ordinary OIDC login did not reach the portal home page")
    print("PORTAL_OIDC_LOGIN_PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ca", required=True)
    args = parser.parse_args()
    if sys.stdin.isatty():
        raise SystemExit("pipe the disposable lab password on stdin")
    raw_password = sys.stdin.buffer.read(513)
    if not raw_password or len(raw_password) > 512:
        raise SystemExit("invalid lab password length")
    try:
        password = raw_password.strip().decode("utf-8")
    except UnicodeDecodeError:
        raise SystemExit("lab password is not UTF-8") from None

    context = ssl.create_default_context(cafile=args.ca)
    portal_opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
        RestrictedRedirects(PORTAL_ALLOWED_HOSTS),
    )
    admin_opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
        RestrictedRedirects(ADMIN_PORTAL_ALLOWED_HOSTS),
    )
    identity_flow(portal_opener, admin_opener, password)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
