"""Contracts for authenticating LiteLLM traces before they enter Alloy."""

from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
COMPOSE = (ROOT / "compose/docker-compose.yml").read_text(encoding="utf-8")
PREPROD = (ROOT / "compose/docker-compose.preprod.yml").read_text(encoding="utf-8")
ALLOY = (ROOT / "compose/alloy/config.alloy").read_text(encoding="utf-8")
CALLBACK = (ROOT / "compose/litellm/aigw_otel_callback.py").read_text(
    encoding="utf-8"
)
CONFIG = (ROOT / "compose/litellm/config.yaml").read_text(encoding="utf-8")
STACK = (
    ROOT / "ansible/roles/docker_stack/tasks/main.yml"
).read_text(encoding="utf-8")
PREPROD_SCRIPT = (ROOT / "scripts/preprod.py").read_text(encoding="utf-8")
STATE_RESTORE = (ROOT / "scripts/state-restore.sh").read_text(encoding="utf-8")
RESTORE_ARCHIVE = (ROOT / "scripts/restore_archive.py").read_text(encoding="utf-8")
MANIFEST = json.loads(
    (ROOT / "compose/bind-source-digest-inputs.json").read_text(encoding="utf-8")
)


class LiteLLMOtelAuthenticationContractTests(unittest.TestCase):
    def test_callback_reads_one_fixed_file_and_has_no_network_choice(self) -> None:
        compile(CALLBACK, "aigw_otel_callback.py", "exec")
        for required in (
            'TOKEN_PATH = "/run/secrets/litellm_otel_token"',
            'TOKEN_PATTERN = re.compile(r"[0-9a-f]{64}")',
            'ALLOY_TRACES_URL = "http://alloy:4319/v1/traces"',
            'getattr(os, "O_NOFOLLOW", 0)',
            "stat.S_ISREG(details.st_mode)",
            "details.st_nlink != 1",
            "os.read(descriptor, 65)",
            "TOKEN_PATTERN.fullmatch(token)",
            'headers={"Authorization": f"Bearer {token}"}',
            "return BatchSpanProcessor(self._aigw_exporter)",
            'environment not in {"preprod", "production"}',
            'raise RuntimeError("dynamic OTLP headers are not allowed")',
        ):
            self.assertIn(required, CALLBACK)
        for forbidden in (
            "subprocess",
            "socket",
            "urllib",
            "requests",
            "http.client",
            "OTEL_EXPORTER_OTLP_HEADERS",
        ):
            self.assertNotIn(forbidden, CALLBACK)

    def test_litellm_uses_only_the_reviewed_callback(self) -> None:
        self.assertIn(
            'callbacks: ["aigw_otel_callback.aigw_otel", '
            '"aigw_default_model_hook.aigw_default_model_enforcer"]',
            CONFIG,
        )
        block = COMPOSE.split("  litellm:\n", 1)[1].split("\n  open-webui:", 1)[0]
        self.assertIn('AIGW_DEPLOYMENT_ENVIRONMENT: ${AIGW_DEPLOYMENT_ENVIRONMENT:-production}', block)
        self.assertIn('DEBUG_OTEL: "false"', block)
        self.assertIn('USE_OTEL_LITELLM_REQUEST_SPAN: "true"', block)
        for forbidden in (
            "OTEL_EXPORTER_OTLP_HEADERS",
            "OTEL_HEADERS",
            "OTEL_EXPORTER_OTLP_ENDPOINT",
        ):
            self.assertNotIn(forbidden, block)
        self.assertIn(
            "./litellm/aigw_openwebui_identity.py:"
            "/app/aigw_openwebui_identity.py:ro,Z",
            block,
        )
        self.assertIn(
            "./litellm/aigw_otel_callback.py:/app/aigw_otel_callback.py:ro,Z",
            block,
        )
        self.assertIn(
            "./secrets/litellm_otel_token:/run/secrets/litellm_otel_token:ro,z",
            block,
        )

    def test_alloy_has_separate_open_and_authenticated_receivers(self) -> None:
        for required in (
            'local.file "litellm_otel_token"',
            'filename  = "/run/secrets/litellm_otel_token"',
            "is_secret = true",
            'otelcol.auth.bearer "litellm"',
            'otelcol.receiver.otlp "default"',
            'sys.env("ALLOY_TELEMETRY_IP") + ":4318"',
            'otelcol.receiver.otlp "litellm"',
            'sys.env("ALLOY_TELEMETRY_IP") + ":4319"',
            "auth     = otelcol.auth.bearer.litellm.handler",
        ):
            self.assertIn(required, ALLOY)

        untrusted_attributes = ALLOY.split(
            'otelcol.processor.attributes "untrusted_source"', 1
        )[1].split('otelcol.processor.filter "untrusted_source"', 1)[0]
        self.assertIn('key    = "aigw.security.source_authenticated"', untrusted_attributes)
        self.assertIn('action = "delete"', untrusted_attributes)
        self.assertIn("otelcol.processor.filter.untrusted_source.input", untrusted_attributes)

        untrusted_filter = ALLOY.split(
            'otelcol.processor.filter "untrusted_source"', 1
        )[1].split('otelcol.processor.attributes "authenticated_litellm"', 1)[0]
        self.assertIn('error_mode = "propagate"', untrusted_filter)
        self.assertIn(
            '`resource.attributes["service.name"] == "litellm"`',
            untrusted_filter,
        )

        authenticated = ALLOY.split(
            'otelcol.processor.attributes "authenticated_litellm"', 1
        )[1].split('otelcol.processor.memory_limiter "default"', 1)[0]
        self.assertIn('action = "upsert"', authenticated)
        self.assertIn('value  = "litellm_bearer_v1"', authenticated)

        request_filter = ALLOY.split(
            'otelcol.processor.filter "aigw_request_spans"', 1
        )[1].split("\n}\n", 1)[0]
        self.assertIn(
            '`attributes["aigw.security.source_authenticated"] != '
            '"litellm_bearer_v1"`',
            request_filter,
        )

    def test_token_is_a_digested_shared_read_only_bind(self) -> None:
        self.assertEqual(
            MANIFEST["base"]["alloy"],
            [
                "alloy/config.alloy",
                "certs/cribl-ca.pem",
                "secrets/litellm_otel_token",
            ],
        )
        self.assertEqual(
            MANIFEST["base"]["litellm"],
            [
                "litellm/config.yaml",
                "litellm/aigw_default_model_hook.py",
                "litellm/aigw_openwebui_identity.py",
                "litellm/aigw_otel_callback.py",
                "secrets/litellm_otel_token",
            ],
        )
        alloy = COMPOSE.split("  alloy:\n", 1)[1].split("\n  prometheus:", 1)[0]
        # Alloy is label-disabled for Docker log access, so it must not request
        # a second SELinux relabel of the shared source inode.
        self.assertIn(
            "./secrets/litellm_otel_token:/run/secrets/litellm_otel_token:ro",
            alloy,
        )
        self.assertNotIn(
            "./secrets/litellm_otel_token:/run/secrets/litellm_otel_token:ro,z",
            alloy,
        )

    def test_production_generates_one_stable_private_token(self) -> None:
        section = STACK.split(
            "- name: Inspect the stable LiteLLM telemetry token", 1
        )[1].split(
            "- name: Materialize Redis authentication files", 1
        )[0]
        for required in (
            "O_EXCL",
            "O_NOFOLLOW",
            "secrets.token_hex(32)",
            "os.fchown(descriptor, 0, 473)",
            "os.fchmod(descriptor, 0o440)",
            "mode == '0440'",
            "stat.nlink | int) == 1",
            "stat.size | int) == 64",
            're.fullmatch(rb"[0-9a-f]{64}", payload)',
            "no_log: true",
        ):
            self.assertIn(required, section)
        self.assertNotIn("{{ litellm_otel", section)

    def test_restored_token_is_validated_before_group_normalization(self) -> None:
        section = STACK.split(
            "- name: Inspect the stable LiteLLM telemetry token", 1
        )[1].split(
            "- name: Materialize Redis authentication files", 1
        )[0]
        validate = "- name: Validate the stable LiteLLM telemetry token content"
        normalize = "- name: Normalize the validated LiteLLM telemetry token boundary"
        final_stat = "- name: Require the exact stable LiteLLM telemetry token boundary"

        self.assertIn("litellm_otel_token_before.stat.gid in [0, 473]", section)
        self.assertIn('group: "473"', section)
        self.assertIn('mode: "0440"', section)
        self.assertIn("follow: false", section)
        self.assertLess(section.index(validate), section.index(normalize))
        self.assertLess(section.index(normalize), section.index(final_stat))

        # Restore deliberately extracts regular files as root-owned and then
        # requires a current-source converge. The role must therefore repair
        # only this reviewed ownership transition after checking the secret.
        self.assertIn("preserve_modes=True", RESTORE_ARCHIVE)
        self.assertIn("current-source Ansible converge", STATE_RESTORE)

    def test_preprod_uses_a_private_seeded_token_and_both_mounts(self) -> None:
        self.assertIn(
            'SECRETS_DIR / "litellm_otel_token",\n'
            '        credential_hex("litellm-otel", 64),\n'
            "        0o600,",
            PREPROD_SCRIPT,
        )
        self.assertIn('"secrets/litellm_otel_token",', PREPROD_SCRIPT)
        litellm = PREPROD.split("  litellm:\n", 1)[1].split("\n  # Build paths", 1)[0]
        alloy = PREPROD.split("  alloy:\n", 1)[1].split("\n  prometheus:", 1)[0]
        for block in (litellm, alloy):
            self.assertIn(
                "./secrets/litellm_otel_token:/run/secrets/litellm_otel_token:ro,z",
                block,
            )
        self.assertIn("AIGW_DEPLOYMENT_ENVIRONMENT: preprod", litellm)


if __name__ == "__main__":
    unittest.main()
