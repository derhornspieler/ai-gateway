#!/usr/bin/env python3
"""Exercise the real portal one-time-key lifecycle over public HTTPS."""

from __future__ import annotations

import argparse
import html
import http.cookiejar
import importlib.util
import ssl
import sys
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from pathlib import Path


FLOW_PATH = Path(__file__).with_name("test-portal-identity-flow.py")
SPEC = importlib.util.spec_from_file_location("aigw_portal_flow", FLOW_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load portal acceptance helpers")
flow = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(flow)


class OneTimeSecretParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._capture = False
        self.values: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        values = dict(attrs)
        if tag == "code" and values.get("id") == "new-key-value":
            self._capture = True
            self.values.append("")

    def handle_data(self, data: str) -> None:
        if self._capture:
            self.values[-1] += data

    def handle_endtag(self, tag: str) -> None:
        if tag == "code" and self._capture:
            self._capture = False


def exact_form(page_url: str, body: str, path: str):
    forms = [
        form
        for form in flow.parse_forms(body)
        if urllib.parse.urlsplit(
            urllib.parse.urljoin(page_url, str(form["action"]))
        ).path
        == path
    ]
    if len(forms) != 1:
        raise RuntimeError(f"expected exactly one portal form for {path}")
    return forms[0]


def submit(opener, page_url: str, form, fields: dict[str, str]):
    action = urllib.parse.urljoin(page_url, str(form["action"]))
    parsed = urllib.parse.urlsplit(action)
    if parsed.scheme != "https" or parsed.hostname not in flow.ALLOWED_HOSTS:
        raise RuntimeError("portal form action left the reviewed HTTPS hosts")
    values = dict(form["inputs"])
    values.update(fields)
    request = urllib.request.Request(
        action,
        data=urllib.parse.urlencode(values).encode("utf-8"),
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "aigw-key-acceptance/1",
        },
        method="POST",
    )
    with opener.open(request, timeout=30) as response:
        body = response.read(2 * 1024 * 1024 + 1)
        result = (
            response.status,
            response.geturl(),
            body.decode("utf-8", errors="strict"),
            response.headers,
        )
    if len(body) > 2 * 1024 * 1024:
        raise RuntimeError("acceptance response exceeded 2 MiB")
    return result


def one_time_secret(body: str) -> str:
    parser = OneTimeSecretParser()
    parser.feed(body)
    values = [html.unescape(value.strip()) for value in parser.values]
    if len(values) != 1 or not 20 <= len(values[0]) <= 2048:
        raise RuntimeError("POST response did not contain exactly one bounded key")
    return values[0]


def assert_not_retained(secret: str, body: str, cookies) -> None:
    if secret in body:
        raise RuntimeError("plaintext key was retained in a later response")
    if any(secret in cookie.value for cookie in cookies):
        raise RuntimeError("plaintext key was retained in a cookie")


def generate(opener, page_url: str, body: str, alias: str):
    form = exact_form(page_url, body, "/keys")
    csrf = str(form["inputs"].get("csrf_token", ""))
    project = str(form["inputs"].get("project_id", ""))
    if len(csrf) < 32 or not project:
        raise RuntimeError("key form is missing CSRF or project binding")
    status, url, generated, headers = submit(
        opener,
        page_url,
        form,
        {"alias": alias, "project_id": project, "csrf_token": csrf},
    )
    if status != 201 or headers.get("Content-Location") != "/":
        raise RuntimeError("key creation was not a one-time 201 POST response")
    if "no-store" not in headers.get("Cache-Control", ""):
        raise RuntimeError("one-time key response was cacheable")
    return one_time_secret(generated), url, generated


def deactivate(opener, page_url: str, body: str) -> tuple[str, str]:
    form = exact_form(page_url, body, "/keys/deactivate")
    csrf = str(form["inputs"].get("csrf_token", ""))
    token = str(form["inputs"].get("token", ""))
    project = str(form["inputs"].get("project_id", ""))
    if len(csrf) < 32 or not token or not project:
        raise RuntimeError("deactivation form was incomplete")
    status, url, result, _ = submit(
        opener,
        page_url,
        form,
        {"csrf_token": csrf, "token": token, "project_id": project},
    )
    if status != 200 or "Key deactivated. You may now generate another." not in result:
        raise RuntimeError("portal did not verify key deactivation")
    return url, result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ca", required=True)
    args = parser.parse_args()
    if sys.stdin.isatty():
        raise SystemExit("pipe the lab-developer Samba password on stdin")
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
        flow.RestrictedRedirects(),
    )
    page_url, body = flow.read_page(opener, flow.PORTAL_ORIGIN + "/login/start")
    login_forms = [
        form
        for form in flow.parse_forms(body)
        if "/login-actions/authenticate" in str(form["action"])
    ]
    if len(login_forms) != 1:
        raise RuntimeError("expected exactly one Keycloak login form")
    page_url, body = flow.post_form(
        opener,
        page_url,
        login_forms[0],
        {"username": "lab-developer", "password": password},
    )
    if urllib.parse.urlsplit(page_url).path != "/":
        raise RuntimeError("Samba developer login did not reach the key page")

    first, _, first_post = generate(opener, page_url, body, "acceptance-first")
    if first not in first_post:
        raise RuntimeError("new key was not present in its creation response")
    assert_not_retained(first, "", cookies)
    print("PORTAL_ONE_TIME_KEY_POST_PASS")

    page_url, body = flow.read_page(opener, flow.PORTAL_ORIGIN + "/")
    assert_not_retained(first, body, cookies)
    if "active" not in body:
        raise RuntimeError("generated key was not shown as active metadata")
    snippets_url, snippets = flow.read_page(opener, flow.PORTAL_ORIGIN + "/snippets")
    assert_not_retained(first, snippets, cookies)
    if urllib.parse.urlsplit(snippets_url).path != "/snippets" or "YOUR_KEY" not in snippets:
        raise RuntimeError("later snippets did not use the safe placeholder")
    print("PORTAL_KEY_NOT_RETAINED_PASS")

    form = exact_form(page_url, body, "/keys")
    csrf = str(form["inputs"].get("csrf_token", ""))
    project = str(form["inputs"].get("project_id", ""))
    status, denied_url, denied, _ = submit(
        opener,
        page_url,
        form,
        {"alias": "acceptance-denied", "project_id": project, "csrf_token": csrf},
    )
    assert_not_retained(first, denied, cookies)
    if status != 200 or urllib.parse.urlsplit(denied_url).path != "/":
        raise RuntimeError("active-key denial did not return safely to the inventory")
    if "This project already has an active key." not in denied:
        raise RuntimeError("second active key was not denied")
    if "new-key-value" in denied:
        raise RuntimeError("denied generation unexpectedly rendered a key")
    print("PORTAL_ACTIVE_KEY_DENIAL_PASS")

    page_url, body = deactivate(opener, denied_url, denied)
    assert_not_retained(first, body, cookies)
    second, _, second_post = generate(
        opener, page_url, body, "acceptance-regenerated"
    )
    if second == first or second not in second_post:
        raise RuntimeError("regeneration did not produce a distinct one-time key")
    assert_not_retained(second, "", cookies)
    page_url, body = flow.read_page(opener, flow.PORTAL_ORIGIN + "/")
    assert_not_retained(first, body, cookies)
    assert_not_retained(second, body, cookies)
    snippets_url, snippets = flow.read_page(opener, flow.PORTAL_ORIGIN + "/snippets")
    assert_not_retained(first, snippets, cookies)
    assert_not_retained(second, snippets, cookies)
    if "YOUR_KEY" not in snippets:
        raise RuntimeError("regenerated key appeared in later snippets")
    deactivate(opener, page_url, body)
    print("PORTAL_DEACTIVATE_REGENERATE_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
