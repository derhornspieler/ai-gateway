"""Focused contracts for the local documentation validation gate."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_PATH = ROOT / ".github/scripts/validate-docs.py"
HYGIENE_WORKFLOW = ROOT / ".github/workflows/repo-hygiene.yml"


def load_validator():
    spec = importlib.util.spec_from_file_location("validate_docs", VALIDATOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


VALIDATOR = load_validator()


class DocumentationValidationTests(unittest.TestCase):
    def make_root(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        (root / "docs").mkdir()
        return temporary, root

    def test_discovers_active_docs_and_skips_archive_generated_and_private(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        (root / "README.md").write_text("# Home\n", encoding="utf-8")
        (root / "CLAUDE.md").write_text("# Contributor guide\n", encoding="utf-8")
        (root / "TASKS.md").write_text("# Tasks\n", encoding="utf-8")
        (root / ".claude/agents").mkdir(parents=True)
        (root / ".claude/agents/reviewer.md").write_text(
            "# Reviewer\n", encoding="utf-8"
        )
        (root / "services/egress-proxy").mkdir(parents=True)
        (root / "services/egress-proxy/README.md").write_text(
            "# Egress proxy\n", encoding="utf-8"
        )
        (root / "services/other").mkdir()
        (root / "services/other/README.md").write_text(
            "# Other service\n", encoding="utf-8"
        )
        (root / "docs/guide.md").write_text("# Guide\n", encoding="utf-8")
        (root / "docs/page.html").write_text('<h1 id="page">Page</h1>\n', encoding="utf-8")
        (root / "docs/archive").mkdir()
        (root / "docs/archive/old.md").write_text("[broken](missing.md)\n", encoding="utf-8")
        (root / "docs/generated").mkdir()
        (root / "docs/generated/export.md").write_text("[broken](missing.md)\n", encoding="utf-8")
        (root / "docs/private").mkdir()
        (root / "docs/private/notes.md").write_text("[broken](missing.md)\n", encoding="utf-8")
        (root / "docs/export.html").write_text(
            '<body for="html-export"><a href="missing.md">generated</a></body>\n',
            encoding="utf-8",
        )

        names = {
            path.relative_to(root).as_posix()
            for path in VALIDATOR.discover_documents(root)
        }

        self.assertEqual(
            names,
            {
                ".claude/agents/reviewer.md",
                "CLAUDE.md",
                "README.md",
                "TASKS.md",
                "docs/guide.md",
                "docs/page.html",
                "services/egress-proxy/README.md",
                "services/other/README.md",
            },
        )

    def test_accepts_declared_flowchart_nodes_and_subgraphs(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        (root / "README.md").write_text(
            "# Home\n\n"
            "```mermaid\n"
            "flowchart LR\n"
            "  subgraph release [Release boundary]\n"
            "    CAT[Reviewed catalog] -.reviewed.-> BUILD[Immutable build]\n"
            "    BUILD -- approved --> REVIEW[Release review]\n"
            "  end\n"
            "  BUILD -->|network disabled| SEED[(Offline seed)]\n"
            "  REVIEW --- SEED\n"
            "```\n",
            encoding="utf-8",
        )

        _, issues = VALIDATOR.validate(root)

        self.assertEqual(issues, [])

    def test_reports_undefined_flowchart_node_at_its_reference_line(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        (root / "README.md").write_text(
            "# Home\n\n"
            "```mermaid\n"
            "flowchart LR\n"
            "  LK[(Loki)]\n"
            "  PR[(Prometheus)]\n"
            "  GF[Grafana] --> TP & LK & PR\n"
            "```\n",
            encoding="utf-8",
        )

        _, issues = VALIDATOR.validate(root)

        self.assertEqual(
            [(issue.line, issue.message) for issue in issues],
            [(7, "Mermaid flowchart references undefined node 'TP'")],
        )

    def test_component_readme_checks_links_anchors_images_and_fences(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        (root / "docs/guide.md").write_text(
            "# Guide\n\n## Correct anchor\n", encoding="utf-8"
        )
        component = root / "services/egress-proxy"
        component.mkdir(parents=True)
        (component / "README.md").write_text(
            "# Egress proxy\n\n"
            "[Bad anchor](../../docs/guide.md#wrong)\n"
            "![Missing diagram](missing.svg)\n\n"
            "```text\n"
            "not closed\n",
            encoding="utf-8",
        )

        _, issues = VALIDATOR.validate(root)

        self.assertEqual(
            [(issue.line, issue.message) for issue in issues],
            [
                (3, "anchor '#wrong' was not found in docs/guide.md"),
                (4, "local image target does not exist: missing.svg"),
                (6, "code fence is not closed"),
            ],
        )

    def test_validates_relative_files_images_and_github_heading_anchors(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        (root / "docs/images").mkdir()
        (root / "docs/images/flow.svg").write_text("<svg/>\n", encoding="utf-8")
        (root / "README.md").write_text(
            "# Home\n\n"
            "[Run it](docs/guide.md#install--run)\n\n"
            "![Flow](docs/images/flow.svg)\n",
            encoding="utf-8",
        )
        (root / "docs/guide.md").write_text(
            "# Guide\n\n## Install — run\n\n## Repeat\n\n## Repeat\n\n## Cost $100\n",
            encoding="utf-8",
        )

        _, issues = VALIDATOR.validate(root)

        self.assertEqual(issues, [])
        anchors = VALIDATOR.markdown_heading_anchors(
            (root / "docs/guide.md").read_text(encoding="utf-8").splitlines()
        )
        self.assertIn("repeat-1", anchors)
        self.assertIn("cost-100", anchors)

    def test_reports_missing_file_and_anchor_at_the_link_lines(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        (root / "README.md").write_text(
            "# Home\n\n[missing](docs/nope.md)\n[bad mark](docs/guide.md#wrong)\n",
            encoding="utf-8",
        )
        (root / "docs/guide.md").write_text("# Right\n", encoding="utf-8")

        _, issues = VALIDATOR.validate(root)

        messages = [(issue.line, issue.message) for issue in issues]
        self.assertEqual(
            messages,
            [
                (3, "local link target does not exist: docs/nope.md"),
                (4, "anchor '#wrong' was not found in docs/guide.md"),
            ],
        )

    def test_html_links_images_and_ids_use_their_exact_lines(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        (root / "README.md").write_text("# Home\n", encoding="utf-8")
        (root / "docs/image.png").write_bytes(b"not important")
        (root / "docs/page.html").write_text(
            '<h1 id="top">Page</h1>\n'
            '<a href="other.html#details">Details</a>\n'
            '<img src="image.png" alt="diagram">\n',
            encoding="utf-8",
        )
        (root / "docs/other.html").write_text(
            '<h2 id="details">Details</h2>\n', encoding="utf-8"
        )

        _, issues = VALIDATOR.validate(root)

        self.assertEqual(issues, [])

    def test_reports_unclosed_mermaid_and_plain_code_fences(self) -> None:
        for opening in ("```mermaid", "~~~text"):
            with self.subTest(opening=opening):
                temporary, root = self.make_root()
                try:
                    (root / "README.md").write_text(
                        f"# Home\n\n{opening}\ncontent\n", encoding="utf-8"
                    )
                    _, issues = VALIDATOR.validate(root)
                    self.assertEqual(
                        [(issue.line, issue.message) for issue in issues],
                        [(3, "code fence is not closed")],
                    )
                finally:
                    temporary.cleanup()

    def test_does_not_treat_code_examples_or_external_urls_as_local_links(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        (root / "README.md").write_text(
            "# Home\n\n"
            "`[inline](missing-inline.md)`\n\n"
            "```text\n[example](missing-example.md)\n```\n\n"
            "[web](https://example.com/missing)\n",
            encoding="utf-8",
        )

        _, issues = VALIDATOR.validate(root)

        self.assertEqual(issues, [])

    def test_rejects_links_that_leave_the_repository(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        (root / "README.md").write_text("[outside](../secret.txt)\n", encoding="utf-8")

        _, issues = VALIDATOR.validate(root)

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].line, 1)
        self.assertIn("local link leaves repository", issues[0].message)

    def test_root_readme_accepts_only_existing_owner_neutral_workflow_badges(
        self,
    ) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        workflows = root / ".github/workflows"
        workflows.mkdir(parents=True)
        (workflows / "checks.yml").write_text("name: Checks\n", encoding="utf-8")
        (root / "README.md").write_text(
            "[![Checks](../../actions/workflows/checks.yml/badge.svg?branch=main)]"
            "(../../actions/workflows/checks.yml)\n",
            encoding="utf-8",
        )

        _, issues = VALIDATOR.validate(root)

        self.assertEqual(issues, [])

        (root / "README.md").write_text(
            "[![Missing](../../actions/workflows/missing.yml/badge.svg?branch=main)]"
            "(../../actions/workflows/missing.yml)\n",
            encoding="utf-8",
        )
        _, issues = VALIDATOR.validate(root)
        self.assertEqual(len(issues), 2)
        self.assertTrue(all("leaves repository" in issue.message for issue in issues))

    def test_root_readme_has_one_owner_neutral_badge_per_workflow(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        badge_files = set(
            re.findall(
                r"\.\./\.\./actions/workflows/"
                r"([A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml)/badge\.svg\?branch=main",
                readme,
            )
        )
        workflow_files = {
            path.name for path in (ROOT / ".github/workflows").glob("*.yml")
        }
        workflow_files.update(
            path.name for path in (ROOT / ".github/workflows").glob("*.yaml")
        )
        self.assertEqual(badge_files, workflow_files)

    def test_cli_prints_machine_readable_file_and_line_errors(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        (root / "README.md").write_text("# Home\n[broken](no.md)\n", encoding="utf-8")

        result = subprocess.run(
            [sys.executable, "-I", str(VALIDATOR_PATH), "--root", str(root)],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("README.md:2: local link target does not exist: no.md", result.stdout)
        self.assertIn("DOCS_INVALID files=1 errors=1", result.stdout)

    def test_repo_hygiene_runs_the_blocking_validator(self) -> None:
        workflow = HYGIENE_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("name: Documentation links and diagrams", workflow)
        self.assertIn("run: python3 -I .github/scripts/validate-docs.py", workflow)


if __name__ == "__main__":
    unittest.main()
