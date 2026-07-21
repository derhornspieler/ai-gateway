#!/usr/bin/env python3
"""Retired compatibility entry point for the old single-service upgrade tool."""

from __future__ import annotations

import sys


def main() -> int:
    print(
        "ERROR: upgrade-service.py was retired because it had unsafe implicit "
        "hosts, inventory, and incomplete rollback behavior.\n"
        "Use scripts/update-images.py instead:\n"
        "  python3 scripts/update-images.py prepare --help\n"
        "  python3 scripts/update-images.py test-preprod --help\n"
        "  python3 scripts/update-images.py upgrade --help",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
