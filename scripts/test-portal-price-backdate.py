#!/usr/bin/env python3
"""Exercise future and backdated prices through the real PreProd admin portal."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import http.cookiejar
import importlib.util
from pathlib import Path
import re
import ssl
import sys
import urllib.parse
import urllib.request


FLOW_PATH = Path(__file__).with_name("test-portal-identity-flow.py")
SPEC = importlib.util.spec_from_file_location("aigw_portal_flow", FLOW_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load portal acceptance helpers")
flow = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(flow)


def exact_form(html: str, path: str, *, model: str | None = None):
    """Return one exact form, optionally bound to one rendered model."""

    forms = []
    for form in flow.parse_forms(html):
        action = urllib.parse.urlsplit(
            urllib.parse.urljoin(
                flow.ADMIN_PORTAL_ORIGIN + "/admin", str(form["action"])
            )
        ).path
        if action != path:
            continue
        if model is not None and form["inputs"].get("gateway_model_name") != model:
            continue
        forms.append(form)
    if len(forms) != 1:
        raise RuntimeError(f"expected exactly one portal form for {path}")
    return forms[0]


def page_csrf(html: str) -> str:
    values = {
        str(form["inputs"].get("csrf_token", ""))
        for form in flow.parse_forms(html)
        if form["inputs"].get("csrf_token")
    }
    if len(values) != 1:
        raise RuntimeError("the portal did not render one session CSRF value")
    value = values.pop()
    if len(value) < 32:
        raise RuntimeError("the portal rendered a short CSRF value")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ca", required=True)
    parser.add_argument("--suffix", required=True)
    args = parser.parse_args()
    if re.fullmatch(r"[0-9a-f]{12}", args.suffix) is None:
        raise SystemExit("the acceptance suffix is invalid")
    if sys.stdin.isatty():
        raise SystemExit("pipe the static preprod-admin password on stdin")
    raw = sys.stdin.buffer.read(513)
    if not raw or len(raw) > 512:
        raise SystemExit("the preprod-admin password length is invalid")
    try:
        password = raw.strip().decode("utf-8")
    except UnicodeDecodeError:
        raise SystemExit("the preprod-admin password is invalid") from None

    context = ssl.create_default_context(cafile=args.ca)
    flow.install_preprod_resolution()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
        flow.RestrictedRedirects(flow.ADMIN_PORTAL_ALLOWED_HOSTS),
    )

    final_url, ordinary_html = flow.keycloak_login(
        opener,
        flow.ADMIN_PORTAL_ORIGIN + "/login/start",
        password,
        allowed_hosts=flow.ADMIN_PORTAL_ALLOWED_HOSTS,
    )
    if urllib.parse.urlsplit(final_url).path != "/admin":
        raise RuntimeError("ordinary admin login did not reach the portal")
    if any(
        form["action"] == "/admin/model-governance/models"
        for form in flow.parse_forms(ordinary_html)
    ):
        raise RuntimeError("price controls appeared before Keycloak step-up")

    final_url, html = flow.keycloak_login(
        opener,
        flow.ADMIN_PORTAL_ORIGIN + "/admin/reauth",
        password,
        allowed_hosts=flow.ADMIN_PORTAL_ALLOWED_HOSTS,
    )
    if urllib.parse.urlsplit(final_url).path != "/admin":
        raise RuntimeError("admin step-up did not return to the portal")
    print("PREPROD_PRICE_PORTAL_STEP_UP_PASSED")

    model = "claude-portal-price-" + args.suffix
    model_form = exact_form(html, "/admin/model-governance/models")
    csrf = page_csrf(html)
    selected_url, html = flow.post_form(
        opener,
        final_url,
        model_form,
        {
            "gateway_model_name": model,
            "provider_name": "anthropic",
            "provider_model_id": model,
            "source_reference": "preprod-portal-price-" + args.suffix,
            "review_note": "Seeded PreProd portal pricing acceptance model.",
            "csrf_token": csrf,
        },
        allowed_hosts=flow.ADMIN_PORTAL_ALLOWED_HOSTS,
    )
    if (
        "Hidden model version created." not in html
        or model not in html
        or urllib.parse.urlsplit(selected_url).path != "/admin"
    ):
        raise RuntimeError("the portal did not create the hidden pricing model")

    future_form = exact_form(html, "/admin/model-governance/prices")
    future_time = (datetime.now(timezone.utc) + timedelta(days=1)).strftime(
        "%Y-%m-%dT%H:%M"
    )
    selected_url, html = flow.post_form(
        opener,
        selected_url,
        future_form,
        {
            "gateway_model_name": model,
            "usage_class": "normal_input",
            "token_unit": "1000000",
            "amount": "7.25",
            "effective_at_utc": future_time,
            "source_reference": "preprod-future-price-" + args.suffix,
            "review_note": "Seeded PreProd future price review.",
            "csrf_token": page_csrf(html),
        },
        allowed_hosts=flow.ADMIN_PORTAL_ALLOWED_HOSTS,
    )
    if "Future USD price version created." not in html:
        raise RuntimeError("the portal did not append the future price")

    preview_form = exact_form(
        html, "/admin/model-governance/prices/backdate/preview"
    )
    backdate_time = (datetime.now(timezone.utc) - timedelta(minutes=2)).strftime(
        "%Y-%m-%dT%H:%M"
    )
    review_note = "Seeded PreProd backdated price review."
    source_reference = "preprod-backdated-price-" + args.suffix
    preview_url, preview_html = flow.post_form(
        opener,
        selected_url,
        preview_form,
        {
            "gateway_model_name": model,
            "usage_class": "output",
            "token_unit": "1000000",
            "amount": "9.75",
            "effective_at_utc": backdate_time,
            "source_reference": source_reference,
            "review_note": review_note,
            "csrf_token": page_csrf(html),
        },
        allowed_hosts=flow.ADMIN_PORTAL_ALLOWED_HOSTS,
    )
    required_preview = (
        "Review the backdated price",
        model,
        "9.75 USD per 1000000 tokens",
        source_reference,
        review_note,
        "CONFIRM BACKDATED PRICE",
        "Affected usage rows</th><td class=\"tnum\">0</td>",
    )
    if any(value not in preview_html for value in required_preview):
        raise RuntimeError("the portal did not render the exact stored preview")
    confirmation_form = exact_form(
        preview_html, "/admin/model-governance/prices/backdate/confirm"
    )
    if {
        "gateway_model_name",
        "usage_class",
    } & set(confirmation_form["inputs"]):
        raise RuntimeError("the confirmation form trusted a browser target field")
    print("PREPROD_PRICE_PORTAL_PREVIEW_PASSED")

    _, rejected_html = flow.post_form(
        opener,
        preview_url,
        confirmation_form,
        {
            "confirmation": "CONFIRM BACKDATED PRICE",
            "csrf_token": "x" * 43,
        },
        allowed_hosts=flow.ADMIN_PORTAL_ALLOWED_HOSTS,
    )
    if (
        "Your session expired" not in rejected_html
        or "Backdated price confirmed." in rejected_html
    ):
        raise RuntimeError("the confirmation route did not reject bad CSRF")
    print("PREPROD_PRICE_PORTAL_CSRF_PASSED")

    stepped_url, stepped_html = flow.keycloak_login(
        opener,
        flow.ADMIN_PORTAL_ORIGIN + "/admin/reauth",
        password,
        allowed_hosts=flow.ADMIN_PORTAL_ALLOWED_HOSTS,
    )
    if urllib.parse.urlsplit(stepped_url).path != "/admin":
        raise RuntimeError("confirmation step-up did not return to the portal")
    confirmed_url, confirmed_html = flow.post_form(
        opener,
        preview_url,
        confirmation_form,
        {
            "confirmation": "CONFIRM BACKDATED PRICE",
            "csrf_token": page_csrf(stepped_html),
        },
        allowed_hosts=flow.ADMIN_PORTAL_ALLOWED_HOSTS,
    )
    if (
        "Backdated price confirmed. 0 immutable cost adjustments were appended."
        not in confirmed_html
        or model not in confirmed_url
    ):
        raise RuntimeError("the portal did not confirm the stored preview")
    print("PREPROD_PRICE_PORTAL_CONFIRM_PASSED")

    lifecycle = exact_form(
        confirmed_html,
        "/admin/model-governance/lifecycle",
        model=model,
    )
    _, retired_html = flow.post_form(
        opener,
        confirmed_url,
        lifecycle,
        {
            "action": "retire",
            "csrf_token": page_csrf(confirmed_html),
        },
        allowed_hosts=flow.ADMIN_PORTAL_ALLOWED_HOSTS,
    )
    if "Model retired." not in retired_html:
        raise RuntimeError("the portal did not retire its acceptance model")
    print("PREPROD_PRICE_PORTAL_CLEANUP_PASSED")
    print("PREPROD_PRICE_PORTAL_PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
