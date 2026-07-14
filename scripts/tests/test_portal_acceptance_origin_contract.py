from __future__ import annotations

import importlib.util
import io
from pathlib import Path
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
FLOW_PATH = ROOT / "scripts/test-portal-identity-flow.py"
SPEC = importlib.util.spec_from_file_location("aigw_acceptance_flow", FLOW_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load portal acceptance flow")
flow = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(flow)


class PortalAcceptanceOriginTests(unittest.TestCase):
    def test_user_and_admin_redirect_boundaries_are_distinct(self) -> None:
        self.assertEqual(
            flow.PORTAL_ALLOWED_HOSTS,
            frozenset({"portal.aigw.internal", "auth.aigw.internal"}),
        )
        self.assertEqual(
            flow.ADMIN_PORTAL_ALLOWED_HOSTS,
            frozenset({"admin.aigw.internal", "auth.aigw.internal"}),
        )
        with self.assertRaises(ValueError):
            flow.RestrictedRedirects(
                flow.PORTAL_ALLOWED_HOSTS | flow.ADMIN_PORTAL_ALLOWED_HOSTS
            )

        user_redirects = flow.RestrictedRedirects(flow.PORTAL_ALLOWED_HOSTS)
        with self.assertRaises(RuntimeError):
            user_redirects.redirect_request(
                None,
                None,
                302,
                "Found",
                {},
                flow.ADMIN_PORTAL_ORIGIN + "/admin",
            )

        admin_redirects = flow.RestrictedRedirects(
            flow.ADMIN_PORTAL_ALLOWED_HOSTS
        )
        with self.assertRaises(RuntimeError):
            admin_redirects.redirect_request(
                None,
                None,
                302,
                "Found",
                {},
                flow.PORTAL_ORIGIN + "/",
            )

    def test_bootstrap_uses_separate_sessions_and_admin_step_up(self) -> None:
        portal_opener = object()
        admin_opener = object()
        csrf = "c" * 32
        admin_html = (
            '<form method="post" action="/admin/identity/bootstrap">'
            f'<input name="csrf_token" value="{csrf}">'
            "</form>"
        )
        login_results = [
            (flow.ADMIN_PORTAL_ORIGIN + "/admin", ""),
            (flow.ADMIN_PORTAL_ORIGIN + "/admin", admin_html),
            (flow.PORTAL_ORIGIN + "/", ""),
        ]
        initialized = (
            flow.ADMIN_PORTAL_ORIGIN + "/admin",
            "Keycloak identity setup completed.",
        )

        with (
            mock.patch.object(
                flow, "keycloak_login", side_effect=login_results
            ) as login,
            mock.patch.object(flow, "post_form", return_value=initialized) as post,
            mock.patch("sys.stdout", new_callable=io.StringIO) as output,
        ):
            flow.identity_flow(portal_opener, admin_opener, "not-logged")

        self.assertEqual(
            login.call_args_list,
            [
                mock.call(
                    admin_opener,
                    flow.ADMIN_PORTAL_ORIGIN + "/login/start",
                    "not-logged",
                    allowed_hosts=flow.ADMIN_PORTAL_ALLOWED_HOSTS,
                ),
                mock.call(
                    admin_opener,
                    flow.ADMIN_PORTAL_ORIGIN + "/admin/reauth",
                    "not-logged",
                    allowed_hosts=flow.ADMIN_PORTAL_ALLOWED_HOSTS,
                ),
                mock.call(
                    portal_opener,
                    flow.PORTAL_ORIGIN + "/login/start",
                    "not-logged",
                    allowed_hosts=flow.PORTAL_ALLOWED_HOSTS,
                ),
            ],
        )
        post.assert_called_once_with(
            admin_opener,
            flow.ADMIN_PORTAL_ORIGIN + "/admin",
            mock.ANY,
            {"confirmation": "INITIALIZE", "csrf_token": csrf},
            allowed_hosts=flow.ADMIN_PORTAL_ALLOWED_HOSTS,
        )
        self.assertNotIn("not-logged", output.getvalue())

    def test_admin_group_harness_has_no_user_portal_admin_routes(self) -> None:
        source = (ROOT / "scripts/test-portal-group-flow.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn('flow.PORTAL_ORIGIN + "/admin', source)
        self.assertIn('flow.ADMIN_PORTAL_ORIGIN + "/login/start"', source)
        self.assertIn('flow.ADMIN_PORTAL_ORIGIN + "/admin/reauth"', source)

    def test_key_lifecycle_harness_exercises_the_public_gateway_and_revocation(self) -> None:
        source = (ROOT / "scripts/test-portal-key-lifecycle.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('API_ORIGIN = "https://api.aigw.internal"', source)
        self.assertIn('API_ORIGIN + "/v1/models"', source)
        self.assertIn('"Authorization": f"Bearer {secret}"', source)
        self.assertIn("require_gateway_key_accepted(context, first)", source)
        self.assertIn("require_gateway_key_revoked(context, first)", source)
        self.assertIn("require_gateway_key_accepted(context, second)", source)
        self.assertIn("require_gateway_key_revoked(context, second)", source)
        self.assertIn("RejectRedirects", source)


if __name__ == "__main__":
    unittest.main()
