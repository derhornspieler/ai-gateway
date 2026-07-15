#!/usr/bin/env python3
"""Exercise portal group create/assign/remove/delete with real OIDC step-up."""

from __future__ import annotations

import argparse
import importlib.util
import re
import sys
import urllib.parse
from pathlib import Path


FLOW_PATH = Path(__file__).with_name("test-portal-identity-flow.py")
SPEC = importlib.util.spec_from_file_location("aigw_portal_flow", FLOW_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load portal acceptance helpers")
flow = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(flow)


def exact_form(html: str, path: str):
    forms = [
        form
        for form in flow.parse_forms(html)
        if urllib.parse.urlsplit(
            urllib.parse.urljoin(
                flow.ADMIN_PORTAL_ORIGIN + "/admin", str(form["action"])
            )
        ).path
        == path
    ]
    if len(forms) != 1:
        raise RuntimeError(f"expected exactly one portal form for {path}")
    return forms[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ca", required=True)
    parser.add_argument("--group", required=True)
    parser.add_argument("--capability", required=True)
    parser.add_argument("--directory-user", required=True)
    parser.add_argument("--cleanup", action="store_true")
    parser.add_argument("--delete-existing", action="store_true")
    parser.add_argument("--expect-last-admin-protection", action="store_true")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_. -]{0,63}", args.group):
        raise SystemExit("invalid acceptance group name")
    if args.capability not in {
        "aigw-users",
        "aigw-developers",
        "aigw-admins",
        "aigw-chat",
    }:
        raise SystemExit("invalid acceptance capability")
    if not re.fullmatch(r"lab-(?:admin|developer|user)", args.directory_user):
        raise SystemExit("invalid acceptance directory user")
    if sum(
        bool(value)
        for value in (
            args.cleanup,
            args.delete_existing,
            args.expect_last_admin_protection,
        )
    ) > 1:
        raise SystemExit("cleanup modes and last-admin protection are mutually exclusive")
    if sys.stdin.isatty():
        raise SystemExit("pipe the disposable testadmin password on stdin")
    raw = sys.stdin.buffer.read(513)
    if not raw or len(raw) > 512:
        raise SystemExit("invalid testadmin password length")
    password = raw.strip().decode("utf-8")

    import http.cookiejar
    import ssl
    import urllib.request

    context = ssl.create_default_context(cafile=args.ca)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
        flow.RestrictedRedirects(flow.ADMIN_PORTAL_ALLOWED_HOSTS),
    )
    flow.keycloak_login(
        opener,
        flow.ADMIN_PORTAL_ORIGIN + "/login/start",
        password,
        allowed_hosts=flow.ADMIN_PORTAL_ALLOWED_HOSTS,
    )
    final_url, html = flow.keycloak_login(
        opener,
        flow.ADMIN_PORTAL_ORIGIN + "/admin/reauth",
        password,
        allowed_hosts=flow.ADMIN_PORTAL_ALLOWED_HOSTS,
    )
    parsed = urllib.parse.urlsplit(final_url)
    if parsed.hostname != "admin.aigw.aegisgroup.ch" or parsed.path != "/admin":
        raise RuntimeError("portal step-up did not return to /admin")

    group_pattern = re.compile(
        re.escape(args.group)
        + r".*?href=\"/admin\?group_id=([A-Za-z0-9._-]{1,128})\"",
        re.DOTALL,
    )
    if args.delete_existing:
        match = group_pattern.search(html)
        if not match:
            raise RuntimeError("existing acceptance group was not rendered")
        group_id = match.group(1)
        selected_url, html = flow.read_page(
            opener,
            flow.ADMIN_PORTAL_ORIGIN
            + "/admin?"
            + urllib.parse.urlencode({"group_id": group_id}),
        )
        prefix = f"/admin/identity/groups/{group_id}/members/"
        remove_forms = [
            form
            for form in flow.parse_forms(html)
            if (path := urllib.parse.urlsplit(
                urllib.parse.urljoin(selected_url, str(form["action"]))
            ).path).startswith(prefix)
            and path.endswith("/remove")
        ]
        if len(remove_forms) != 1:
            raise RuntimeError("acceptance group did not contain exactly one member")
        csrf = str(remove_forms[0]["inputs"].get("csrf_token", ""))
        _, html = flow.post_form(
            opener,
            selected_url,
            remove_forms[0],
            {"csrf_token": csrf},
            allowed_hosts=flow.ADMIN_PORTAL_ALLOWED_HOSTS,
        )
        if "User removed from the group." not in html:
            raise RuntimeError("portal did not report member removal")
        # The tabbed console renders the empty-group delete control in the
        # selected-group detail pane, not on the group list.
        admin_url, html = flow.read_page(
            opener,
            flow.ADMIN_PORTAL_ORIGIN
            + "/admin?"
            + urllib.parse.urlencode({"group_id": group_id}),
        )
        delete_path = f"/admin/identity/groups/{group_id}/delete"
        delete = exact_form(html, delete_path)
        csrf = str(delete["inputs"].get("csrf_token", ""))
        _, html = flow.post_form(
            opener,
            admin_url,
            delete,
            {"csrf_token": csrf},
            allowed_hosts=flow.ADMIN_PORTAL_ALLOWED_HOSTS,
        )
        if "Authorization group deleted." not in html:
            raise RuntimeError("portal did not report empty group deletion")
        print("PORTAL_EXISTING_GROUP_REMOVE_DELETE_PASS")
        return 0

    create = exact_form(html, "/admin/identity/groups")
    csrf = str(create["inputs"].get("csrf_token", ""))
    _, html = flow.post_form(
        opener,
        final_url,
        create,
        {
            "name": args.group,
            "capabilities": args.capability,
            "csrf_token": csrf,
        },
        allowed_hosts=flow.ADMIN_PORTAL_ALLOWED_HOSTS,
    )
    if "Authorization group created." not in html:
        raise RuntimeError("portal did not report group creation")

    match = group_pattern.search(html)
    if not match:
        raise RuntimeError("created group was not rendered by the portal")
    group_id = match.group(1)
    selected_url = (
        flow.ADMIN_PORTAL_ORIGIN
        + "/admin?"
        + urllib.parse.urlencode(
            {"group_id": group_id, "user_search": args.directory_user}
        )
    )
    selected_url, html = flow.read_page(opener, selected_url)
    option = re.search(
        r'<option value="([A-Za-z0-9._-]{1,128})">'
        + re.escape(args.directory_user)
        + r"(?:\s|—|<)",
        html,
    )
    if not option:
        raise RuntimeError("federated user was not offered by the group UI")
    user_id = option.group(1)
    assign = exact_form(html, f"/admin/identity/groups/{group_id}/members")
    csrf = str(assign["inputs"].get("csrf_token", ""))
    _, html = flow.post_form(
        opener,
        selected_url,
        assign,
        {"user_id": user_id, "csrf_token": csrf},
        allowed_hosts=flow.ADMIN_PORTAL_ALLOWED_HOSTS,
    )
    if "User assigned to the group." not in html:
        raise RuntimeError("portal did not report user assignment")
    print("PORTAL_GROUP_CREATE_ASSIGN_PASS")

    if args.cleanup or args.expect_last_admin_protection:
        remove_path = f"/admin/identity/groups/{group_id}/members/{user_id}/remove"
        remove = exact_form(html, remove_path)
        csrf = str(remove["inputs"].get("csrf_token", ""))
        _, html = flow.post_form(
            opener,
            selected_url,
            remove,
            {"csrf_token": csrf},
            allowed_hosts=flow.ADMIN_PORTAL_ALLOWED_HOSTS,
        )
        if args.expect_last_admin_protection:
            if "the last administrator is protected" not in html:
                raise RuntimeError("last managed administrator removal was not rejected")
            print("PORTAL_LAST_ADMIN_PROTECTION_PASS")
            return 0
        if "User removed from the group." not in html:
            raise RuntimeError("portal did not report member removal")
        # The tabbed console renders the empty-group delete control in the
        # selected-group detail pane, not on the group list.
        admin_url, html = flow.read_page(
            opener,
            flow.ADMIN_PORTAL_ORIGIN
            + "/admin?"
            + urllib.parse.urlencode({"group_id": group_id}),
        )
        delete_path = f"/admin/identity/groups/{group_id}/delete"
        delete = exact_form(html, delete_path)
        csrf = str(delete["inputs"].get("csrf_token", ""))
        _, html = flow.post_form(
            opener,
            admin_url,
            delete,
            {"csrf_token": csrf},
            allowed_hosts=flow.ADMIN_PORTAL_ALLOWED_HOSTS,
        )
        if "Authorization group deleted." not in html:
            raise RuntimeError("portal did not report empty group deletion")
        print("PORTAL_GROUP_REMOVE_DELETE_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
