from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOP = ROOT / "docs/sop/vault-unseal-after-reboot.md"
OPERATIONS = ROOT / "docs/operations.md"
BACKLOG = ROOT / "docs/backlog.md"


class OperatorBacklogContractTests(unittest.TestCase):
    def test_reboot_sop_uses_the_safe_ansible_auto_unseal_path(self) -> None:
        sop = SOP.read_text(encoding="utf-8")
        for text in (
            "ansible-config dump | grep PIPELINING",
            "ansible/deploy-stack-only.yml",
            "ansible/site.yml",
            "--vault-id mygateway@/secure/path/mygateway.vault-password",
            "scripts/vault-unseal.sh",
            "unset AIGW_UNSEAL_SHARE",
            "Do not initialize Vault again",
        ):
            self.assertIn(text, sop)
        self.assertNotIn("--extra-vars vault_unseal_key", sop)
        self.assertIn("sop/vault-unseal-after-reboot.md", OPERATIONS.read_text())

    def test_backlog_keeps_the_requested_follow_up_work_visible(self) -> None:
        backlog = BACKLOG.read_text(encoding="utf-8")
        for heading in (
            "## Finish the plain-language documentation review",
            "## Run a full security audit",
            "## Rehearse the PostgreSQL 18 migration with production-sized data",
            "## Review every container image version",
        ):
            self.assertIn(heading, backlog)
        for requirement in (
            "plain language",
            "diagram",
            "heading bookmarks",
            "local Docker preprod",
            "Trivy",
            "every exact upstream and custom image",
            "PostgreSQL `18.4`",
            "pre-cutover PostgreSQL 16 rollback",
            "DHI and non-DHI image",
        ):
            self.assertIn(requirement, backlog)


if __name__ == "__main__":
    unittest.main()
