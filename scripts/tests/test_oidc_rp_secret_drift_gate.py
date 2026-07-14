from __future__ import annotations

import base64
import json
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
TASKS = ROOT / "ansible/roles/docker_stack/tasks/main.yml"
ENV_TEMPLATE = ROOT / "ansible/roles/docker_stack/templates/env.j2"

RP_SECRETS = {
    "WEBUI_OIDC_CLIENT_SECRET": "WebuiOIDCSecret_0123456789_ABCDEFGHI",
    "PORTAL_OIDC_CLIENT_SECRET": "PortalOIDCSecret_0123456789_ABCDEFGH",
    "ADMIN_PORTAL_OIDC_CLIENT_SECRET": (
        "AdminPortalOIDCSecret_0123456789_ABCDE"
    ),
    "OAUTH2_PROXY_CLIENT_SECRET": "OAuth2ProxySecret_0123456789_ABCDEFGHI",
}


class OidcRelyingPartySecretDriftGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = TASKS.read_text(encoding="utf-8")
        section = cls.source.split(
            "- name: Reject ordinary converge when a Keycloak relying-party secret drifts",
            1,
        )[1].split("  args:\n", 1)[0]
        literal = section.split("      - |\n", 1)[1]
        cls.script = "\n".join(
            line[8:] if line.startswith("        ") else line
            for line in literal.splitlines()
        )

    def run_gate(
        self,
        deployed: str,
        desired: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        request = {
            "deployed_b64": base64.b64encode(deployed.encode()).decode(),
            "desired": desired if desired is not None else RP_SECRETS,
        }
        return subprocess.run(
            ["python3", "-I", "-c", self.script],
            input=json.dumps(request),
            text=True,
            capture_output=True,
            check=False,
        )

    @staticmethod
    def environment(values: dict[str, str] | None = None) -> str:
        selected = values if values is not None else RP_SECRETS
        return "\n".join(f"{key}={value}" for key, value in selected.items()) + "\n"

    def test_matching_distinct_secrets_pass_without_output(self) -> None:
        result = self.run_gate(self.environment())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")

    def test_changed_missing_duplicate_and_reused_secrets_fail_silently(self) -> None:
        cases = []

        changed = dict(RP_SECRETS)
        changed["PORTAL_OIDC_CLIENT_SECRET"] = (
            "ChangedPortalOIDCSecret_0123456789_ABCDE"
        )
        cases.append(self.environment(changed))

        cases.append(
            self.environment().replace(
                "ADMIN_PORTAL_OIDC_CLIENT_SECRET="
                + RP_SECRETS["ADMIN_PORTAL_OIDC_CLIENT_SECRET"]
                + "\n",
                "",
            )
        )
        cases.append(
            self.environment()
            + "WEBUI_OIDC_CLIENT_SECRET="
            + RP_SECRETS["WEBUI_OIDC_CLIENT_SECRET"]
            + "\n"
        )
        cases.append(
            self.environment().replace(
                "PORTAL_OIDC_CLIENT_SECRET="
                + RP_SECRETS["PORTAL_OIDC_CLIENT_SECRET"],
                "PORTAL_OIDC_CLIENT_SECRET="
                + RP_SECRETS["WEBUI_OIDC_CLIENT_SECRET"],
            )
        )
        cases.append(
            self.environment().replace(
                "OAUTH2_PROXY_CLIENT_SECRET=",
                "export OAUTH2_PROXY_CLIENT_SECRET = ",
            )
        )

        for deployed in cases:
            with self.subTest(deployed=deployed.splitlines()[-1].split("=", 1)[0]):
                result = self.run_gate(deployed)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, "")

    def test_gate_precedes_secret_bearing_or_runtime_deployment_writes(self) -> None:
        gate = self.source.index(
            "- name: Inspect the existing stack environment before any deployment write"
        )
        for later in (
            "- name: Create allow-listed compose config directories",
            "- name: Template Keycloak realm imports",
            "- name: Template .env only after every bind-source digest is final",
        ):
            self.assertLess(gate, self.source.index(later))

        gate_section = self.source[gate : self.source.index(
            "- name: Create allow-listed compose config directories"
        )]
        for required in (
            "follow: false",
            "stat.mode == '0600'",
            "stat.nlink | int) == 1",
            "stat.size | int) <= 262144",
            "/usr/bin/docker",
            '"{{ compose_project_name }}_pg_data"',
            "no such volume",
            "stdin_add_newline: false",
            "no_log: true",
        ):
            self.assertIn(required, gate_section)
        self.assertNotIn("allow_oidc", gate_section.lower())
        self.assertNotIn("rotate_oidc", gate_section.lower())
        self.assertNotIn("aigw_existing_env.content | b64decode", gate_section)

    def test_lab_dns_adm_view_is_rendered_and_bound_as_deployed_state(self) -> None:
        template = ENV_TEMPLATE.read_text(encoding="utf-8")
        self.assertIn("LAB_DNS_ADM_CIDR={{ vpn_client_cidr }}", template)
        self.assertIn("Validate the platform DNS administrative view selector", self.source)
        self.assertIn("db\\.aigw\\.internal(?:\\.adm)?", self.source)
        self.assertIn(
            "stack_dir ~ '/services/lab-dns/db.aigw.internal.adm'",
            self.source,
        )


if __name__ == "__main__":
    unittest.main()
