from __future__ import annotations

import importlib.util
from pathlib import Path
import socket
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
LOGIN = ROOT / "scripts/test-portal-login.py"
E2E = ROOT / "scripts/test-e2e-preprod.py"


def load_login_module():
    spec = importlib.util.spec_from_file_location("aigw_preprod_portal_login", LOGIN)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_e2e_module():
    spec = importlib.util.spec_from_file_location("aigw_preprod_e2e", E2E)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PreprodPortalAcceptanceTests(unittest.TestCase):
    def test_resolution_is_exact_and_preserves_the_tls_hostname_boundary(self) -> None:
        module = load_login_module()
        resolver = mock.Mock(return_value=[("resolved",)])
        with mock.patch.object(module, "_SYSTEM_GETADDRINFO", resolver):
            self.assertEqual(
                module.preprod_getaddrinfo(
                    "portal.aigw.internal", 443, socket.AF_INET, socket.SOCK_STREAM
                ),
                [("resolved",)],
            )
        resolver.assert_called_once_with(
            "127.0.2.1", 443, socket.AF_INET, socket.SOCK_STREAM, 0, 0
        )
        self.assertEqual(
            module.PREPROD_HOST_ADDRESSES,
            {
                "api.aigw.internal": "127.0.2.1",
                "portal.aigw.internal": "127.0.2.1",
                "admin.aigw.internal": "127.0.3.1",
                "auth.aigw.internal": "127.0.3.1",
            },
        )
        with self.assertRaises(socket.gaierror):
            module.preprod_getaddrinfo("unreviewed.aigw.internal", 443)

    def test_e2e_proves_each_static_users_authorization_boundary(self) -> None:
        module = load_e2e_module()
        source = E2E.read_text(encoding="utf-8")
        self.assertEqual(
            module.ENABLED_ADM_OIDC_TARGETS,
            ("litellm-admin", "grafana", "prometheus"),
        )
        for username in ("preprod-admin", "preprod-developer", "preprod-user"):
            self.assertIn(f'"{username}"', source)
        self.assertIn('"PORTAL_DIRECTORY_ADMIN_DENIED_PASS"', source)
        self.assertIn('"PORTAL_DIRECTORY_ADMIN_PASS"', source)
        self.assertIn('"forbidden",', source)
        self.assertIn('"/admin",', source)
        self.assertIn('"--target",\n                "chat"', source)
        self.assertIn('"OIDC_CALLBACK_PASS target=chat username={username}"', source)
        self.assertIn("for target in ENABLED_ADM_OIDC_TARGETS:", source)
        self.assertIn('f"OIDC_CALLBACK_PASS target={target} username={username}"', source)
        self.assertIn('f"ADMIN_DENIAL_PASS target={target} username={username}"', source)

    def test_e2e_curl_ignores_user_configuration(self) -> None:
        module = load_e2e_module()
        with mock.patch.object(module, "run", return_value='{"ok":true}') as run:
            self.assertEqual(
                module.curl_json("auth.aigw.internal", "127.0.3.1", "/health"),
                {"ok": True},
            )
        command = run.call_args.args[0]
        self.assertEqual(command[:2], ["curl", "--disable"])


if __name__ == "__main__":
    unittest.main()
