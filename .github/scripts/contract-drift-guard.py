#!/usr/bin/env python3
"""Advisory reviewer prompt: reviewed surface changed, contract suite did not.

The repository convention this enforces: exact-string contract tests pin the
reviewed text of the deployment surfaces, so most edits there require a
matching test/validator update — by design, not test brittleness.

Nothing mechanically reminds a reviewer of that. `scripts/tests` only fails when
a pinned string *moves*; it stays green when a pull request adds a brand-new
Ansible task, Compose service, or workflow step that simply has no assertion
behind it. That silent gap is how unreviewed behaviour reaches a converge.

This guard therefore reports — never blocks — when a pull request edits a
reviewed surface without touching any contract test or validator. A pull request
can legitimately trip it (a comment-only edit, a pure revert); the annotation
exists so a human says so out loud in review, not so CI can veto it.

Reads changed paths on stdin, one per line. Always exits 0.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# Surfaces whose reviewed text the contract suite is supposed to pin.
GUARDED_SURFACES: dict[str, str] = {
    "ansible/": "Ansible roles, playbooks, and inventory contracts",
    "compose/": "the Compose model and its bind-mounted configuration",
    "scripts/": "operational scripts that ship to the VM",
    ".github/workflows/": "CI workflows (pinned by scripts/tests)",
}

# Evidence that the author kept the contract layer coherent. The contract suite
# itself, plus the two release-gate validators that assert the same reviewed
# text from outside `unittest`.
COHERENCE_EVIDENCE: tuple[str, ...] = (
    "scripts/tests/",
    "scripts/validate-compose.sh",
    "scripts/validate-identity-policy.py",
    "scripts/validate-build-contract.py",
    "scripts/validate-vault-config.sh",
)


def classify(paths: list[str]) -> tuple[dict[str, list[str]], list[str]]:
    """Split changed paths into guarded-surface hits and coherence evidence."""
    evidence = sorted(
        {path for path in paths if path.startswith(COHERENCE_EVIDENCE)}
    )
    touched: dict[str, list[str]] = {}
    for path in sorted(paths):
        if path in evidence or path.startswith(COHERENCE_EVIDENCE):
            continue
        for surface in GUARDED_SURFACES:
            if path.startswith(surface):
                touched.setdefault(surface, []).append(path)
                break
    return touched, evidence


def report(touched: dict[str, list[str]], evidence: list[str]) -> list[str]:
    if not touched:
        return [
            "## Contract-test drift guard",
            "",
            "No reviewed surface changed. Nothing to check.",
            "",
        ]
    if evidence:
        return [
            "## Contract-test drift guard",
            "",
            "Reviewed surfaces changed **and** the contract layer moved with them:",
            "",
            *[f"- `{path}`" for path in evidence],
            "",
        ]

    lines = [
        "## Contract-test drift guard — ADVISORY",
        "",
        "This pull request changes reviewed surfaces but touches **no** contract "
        "test and **no** validator:",
        "",
    ]
    for surface, paths in sorted(touched.items()):
        lines.append(f"- **{surface}** — {GUARDED_SURFACES[surface]}")
        for path in paths[:10]:
            lines.append(f"  - `{path}`")
        if len(paths) > 10:
            lines.append(f"  - …and {len(paths) - 10} more")
    lines += [
        "",
        "By repository convention, edits to these surfaces normally require a matching "
        "contract-test or validator update. If this change is genuinely "
        "assertion-free (a comment, a revert, a pure rename), say so in the "
        "review and move on — this guard never blocks a merge.",
        "",
        "Contract layer: `scripts/tests/`, `scripts/validate-compose.sh`, "
        "`scripts/validate-identity-policy.py`.",
        "",
    ]
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", type=Path, default=None)
    args = parser.parse_args()

    paths = [line.strip() for line in sys.stdin.read().splitlines() if line.strip()]
    touched, evidence = classify(paths)
    lines = report(touched, evidence)

    text = "\n".join(lines) + "\n"
    print(text)

    summary = args.summary or (
        Path(os.environ["GITHUB_STEP_SUMMARY"])
        if os.environ.get("GITHUB_STEP_SUMMARY")
        else None
    )
    if summary is not None:
        with summary.open("a", encoding="utf-8") as handle:
            handle.write(text)

    if touched and not evidence:
        surfaces = ", ".join(sorted(touched))
        print(
            f"::warning title=Contract-test drift::{surfaces} changed with no "
            "matching contract test or validator update. Exact-string "
            "contract tests pin the reviewed text of these surfaces."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
