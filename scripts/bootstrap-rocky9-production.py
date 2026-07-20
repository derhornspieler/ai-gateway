#!/usr/bin/env python3
"""Create a separate, deployable rocky9-production Ansible inventory.

This is the canonical entry point for generating a production inventory. It is
a thin wrapper that loads and runs the shared implementation in
``scripts/bootstrap-generic-rocky9.py`` (the DEPRECATED compatibility name),
defaulting to the canonical ``rocky9-production`` profile and the
``production_rocky9`` Ansible group. It is intentionally not a fork: the
generator logic lives in exactly one module.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


_IMPL = Path(__file__).resolve().with_name("bootstrap-generic-rocky9.py")


def _load_implementation():
    spec = importlib.util.spec_from_file_location("_aigw_rocky9_bootstrap", _IMPL)
    if spec is None or spec.loader is None:
        print(f"FATAL: cannot load bootstrap implementation at {_IMPL}", file=sys.stderr)
        raise SystemExit(2)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


if __name__ == "__main__":
    raise SystemExit(_load_implementation().main(default_profile="rocky9-production"))
