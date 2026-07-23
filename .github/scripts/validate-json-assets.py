#!/usr/bin/env python3
"""Encoding and duplicate-key gate for every reviewed JSON asset.

Plain parse-validity is already enforced elsewhere: `scripts/tests` loads the
Grafana dashboards, the generic-rocky9 contract, the bind-source digest inputs
and the vault-ui-proxy provenance file, and `validate-identity-policy.py` loads
the Keycloak realms. A dedicated "is it JSON" job would be pure duplication.

What nothing covers is the way these files actually rot. They are hand-edited
security artefacts, and `json.loads` is *silent* about the two failure modes
that matter:

  * A duplicate object key. The last one silently wins, so a realm that
    declares `"bruteForceProtected": true` and later repeats
    `"bruteForceProtected": false`, or a dashboard panel that repeats a
    `datasource`, parses cleanly and reviews cleanly while deploying the value
    nobody approved.
  * A UTF-8 BOM. Every consumer here (Grafana's provisioner, Keycloak's realm
    import, `json.loads` on bytes) treats a leading BOM differently; some fail
    only at converge time, on the host.

Both are cheap to reject at the source.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def tracked_json_files() -> list[Path]:
    listed = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", "-C", str(ROOT), "ls-files", "-z", "*.json"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [ROOT / name for name in listed.split("\0") if name]


def reject_duplicate_keys(path: Path):
    def hook(pairs: list[tuple[str, object]]) -> dict:
        seen: set[str] = set()
        for key, _ in pairs:
            if key in seen:
                raise ValueError(f"duplicate object key {key!r}")
            seen.add(key)
        return dict(pairs)

    return hook


def main() -> int:
    failures: list[str] = []
    files = tracked_json_files()
    if not files:
        print("::error title=JSON assets::no tracked JSON assets were found")
        return 2

    for path in sorted(files):
        relative = path.relative_to(ROOT)
        raw = path.read_bytes()
        if raw.startswith(b"\xef\xbb\xbf"):
            failures.append(f"{relative}: leading UTF-8 BOM")
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            failures.append(f"{relative}: not valid UTF-8 ({error})")
            continue
        if not text.endswith("\n"):
            failures.append(f"{relative}: missing trailing newline")
        try:
            json.loads(text, object_pairs_hook=reject_duplicate_keys(path))
        except ValueError as error:
            failures.append(f"{relative}: {error}")

    for failure in failures:
        print(f"::error title=JSON asset defect::{failure}")
    print(f"checked {len(files)} tracked JSON assets; {len(failures)} defective")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
