from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOP = ROOT / "docs/sop/vault-unseal-after-reboot.md"
OPERATIONS = ROOT / "docs/operations.md"
BACKLOG = ROOT / "docs/backlog.md"
TASKS = ROOT / "TASKS.md"
VERSION_REVIEW = ROOT / "docs/image-version-review.md"


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

    def test_backlog_keeps_open_follow_up_work_visible(self) -> None:
        backlog = BACKLOG.read_text(encoding="utf-8")
        for heading in (
            "## Finish the plain-language documentation review",
            "## Run a full security audit",
        ):
            self.assertIn(heading, backlog)
        for requirement in (
            "plain language",
            "diagram",
            "heading bookmarks",
            "local Docker preprod",
            "Trivy",
            "every exact upstream and custom image",
        ):
            self.assertIn(requirement, backlog)

    def test_completed_image_review_remains_recorded(self) -> None:
        backlog = BACKLOG.read_text(encoding="utf-8")
        normalized_backlog = " ".join(backlog.split())
        tasks = TASKS.read_text(encoding="utf-8")
        version_review = VERSION_REVIEW.read_text(encoding="utf-8")

        self.assertIn("image/dependency version review", normalized_backlog)
        self.assertIn("PostgreSQL `18.4`", tasks)
        self.assertIn("## DHI release images", version_review)
        self.assertIn("## Other release images", version_review)


if __name__ == "__main__":
    unittest.main()
