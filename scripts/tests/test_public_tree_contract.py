"""Keep customer and operator identity out of the public repository tree."""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

# Split these literals so this test can scan its own source without an allowlist.
FORBIDDEN = (
    ("customer brand", re.compile("ae" + "gis", re.IGNORECASE)),
    ("personal account", re.compile("der" + "hornspieler", re.IGNORECASE)),
    (
        "personal name",
        re.compile("james" + r"[._ -]?" + "rudisill", re.IGNORECASE),
    ),
    (
        "personal macOS home",
        re.compile(r"/Us" + r"ers/[A-Za-z0-9._-]+"),
    ),
)


def tracked_paths() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    )
    return [ROOT / name for name in result.stdout.decode().split("\0") if name]


class PublicTreeContractTests(unittest.TestCase):
    def test_tracked_paths_and_contents_use_neutral_identifiers(self) -> None:
        violations: list[str] = []

        for path in tracked_paths():
            # A plain `mv` leaves the old index entry missing until the change is
            # staged. Skip that deleted working-tree path during local checks.
            if not path.is_file():
                continue

            relative = path.relative_to(ROOT).as_posix()
            for label, pattern in FORBIDDEN:
                if pattern.search(relative):
                    violations.append(f"{relative}: path contains {label}")

            text = path.read_bytes().decode("utf-8", errors="ignore")
            for line_number, line in enumerate(text.splitlines(), start=1):
                for label, pattern in FORBIDDEN:
                    if pattern.search(line):
                        violations.append(
                            f"{relative}:{line_number}: content contains {label}"
                        )

        self.assertEqual([], violations, "\n" + "\n".join(violations))


if __name__ == "__main__":
    unittest.main()
