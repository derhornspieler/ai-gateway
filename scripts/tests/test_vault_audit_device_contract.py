#!/usr/bin/env python3
"""Contracts for the Vault file audit device and sanitized SOC branch."""

from __future__ import annotations

from pathlib import Path
import stat
import unittest


ROOT = Path(__file__).resolve().parents[2]


class VaultAuditDeviceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.helper_path = ROOT / "scripts/vault-enable-audit.sh"
        cls.helper = cls.helper_path.read_text(encoding="utf-8")
        cls.preprod = (ROOT / "scripts/preprod.py").read_text(encoding="utf-8")
        cls.stack = (
            ROOT / "ansible/roles/docker_stack/tasks/main.yml"
        ).read_text(encoding="utf-8")
        cls.alloy = (ROOT / "compose/alloy/config.alloy").read_text(
            encoding="utf-8"
        )
        cls.runbook = (ROOT / "docs/deploy-runbook.md").read_text(
            encoding="utf-8"
        )

    def test_root_token_helper_is_stdin_only_and_hardened(self) -> None:
        self.assertEqual(stat.S_IMODE(self.helper_path.stat().st_mode), 0o755)
        for required in (
            'exec "${docker_cmd[@]}" run --rm -i',
            "--network net-vault",
            "--read-only",
            "--cap-drop ALL",
            "--log-driver none",
            "sys.stdin.buffer.read(8193)",
            "RejectRedirects()",
            '"file_path": "/vault/logs/audit.log"',
            '"hmac_accessor": "true"',
            '"log_raw": "false"',
            '"mode": "0640"',
        ):
            self.assertIn(required, self.helper)
        self.assertNotIn("VAULT_TOKEN=", self.helper)
        self.assertNotIn("--env", self.helper)

    def test_preprod_enables_and_reads_back_the_same_device(self) -> None:
        for required in (
            '"GET", "/v1/sys/audit"',
            '"PUT",\n            "/v1/sys/audit/file"',
            '"file_path": "/vault/logs/audit.log"',
            '"hmac_accessor": "true"',
            '"log_raw": "false"',
            '"mode": "0640"',
            "Vault file audit-device configuration did not verify",
        ):
            self.assertIn(required, self.preprod)

    def test_production_converge_requires_a_readable_nonempty_json_file(self) -> None:
        block = self.stack.split(
            "Require the reviewed Vault file audit device after initialization",
            1,
        )[1].split("# A genuinely fresh Vault", 1)[0]
        for required in (
            "{{ compose_project_name }}_vault_audit:/audit:ro",
            "--network\n      - none",
            "--read-only",
            "test -f /audit/audit.log",
            "test ! -L /audit/audit.log",
            "test -r /audit/audit.log",
            "test -s /audit/audit.log",
            "head -c 1 /audit/audit.log",
            "failed_when: false",
            "vault_status_before_unseal.stdout",
        ):
            self.assertIn(required, block)
        self.assertIn(
            "Explain how to repair a missing Vault audit device",
            self.stack,
        )
        self.assertIn("scripts/vault-enable-audit.sh", self.stack)

    def test_soc_receives_only_reconstructed_audit_metadata(self) -> None:
        source = self.alloy.split('loki.source.file "vault_audit"', 1)[1].split(
            'loki.process "cribl_vault_audit"', 1
        )[0]
        sanitized = self.alloy.split(
            'loki.process "cribl_vault_audit"', 1
        )[1].split('otelcol.receiver.loki "cribl_security_logs"', 1)[0]
        self.assertIn("loki.write.local.receiver", source)
        self.assertIn("loki.process.cribl_vault_audit.receiver", source)
        self.assertIn("event=aigw.vault.audit", sanitized)
        self.assertIn("hmac_protected=true", sanitized)
        self.assertNotIn("{{ .vault_error }}", sanitized)
        self.assertNotIn("{{ .vault_path }}", sanitized)

    def test_runbook_uses_the_stdin_only_helper(self) -> None:
        self.assertIn(
            'printf \'%s\\n\' "$AIGW_FIRST_ROOT_TOKEN" | sudo '
            "scripts/vault-enable-audit.sh",
            self.runbook,
        )
        self.assertIn("raw values HMAC-protected", self.runbook)


if __name__ == "__main__":
    unittest.main()
