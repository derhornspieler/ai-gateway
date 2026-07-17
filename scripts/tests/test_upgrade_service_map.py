"""The operator upgrade tool's family map must track the real pin topology.

scripts/upgrade-service.py encodes, per upgradeable image family, the exact
repo and the files its tag@digest appears in. If a pin moves (a new bind of
the same repo, a family added or retired, a file dropped) the map must move
in the same change — otherwise `plan` silently edits a subset and the seed /
reset-map drift gates fail later, at converge time instead of review time.
"""

from __future__ import annotations

import importlib.util
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "aigw_upgrade_service", ROOT / "scripts/upgrade-service.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["aigw_upgrade_service"] = mod
    spec.loader.exec_module(mod)
    return mod


TOOL = _load_tool()
PIN = re.compile(r"([a-z0-9./-]+/[a-z0-9._/-]+|traefik):"
                 r"([A-Za-z0-9._-]+)@(sha256:[0-9a-f]{64})")


class UpgradeServiceMapContractTest(unittest.TestCase):
    def test_every_family_pin_exists_in_each_declared_file(self) -> None:
        for family in TOOL.FAMILIES.values():
            pin = TOOL.current_pin(family)  # raises on missing or ambiguous
            tag, digest = pin.rsplit("@", 1)
            mapping_form = f"{tag}: {digest}"  # reset seed map YAML form
            for path in family.files:
                text = path.read_text()
                self.assertTrue(
                    pin in text or mapping_form in text,
                    f"{family.key}: pin absent from declared file {path.name}",
                )

    def test_every_composed_external_pin_belongs_to_a_family(self) -> None:
        compose = (ROOT / "compose/docker-compose.yml").read_text()
        known_repos = {f.repo for f in TOOL.FAMILIES.values()}
        # volume-init's helper image is deliberately unmanaged here: bumping
        # busybox is part of the hardening-baseline review, not a service
        # upgrade cycle.
        exempt = {"dhi.io/busybox"}
        found = {
            m.group(1)
            for m in PIN.finditer(compose)
            if not m.group(1).startswith("ai-gateway")
        }
        unmapped = found - known_repos - exempt
        self.assertFalse(
            unmapped,
            f"external pins with no upgrade-tool family: {sorted(unmapped)}",
        )

    def test_family_services_exist_in_compose(self) -> None:
        compose = (ROOT / "compose/docker-compose.yml").read_text()
        lab_dns = (ROOT / "compose/docker-compose.platform-dns.yml").read_text()
        for family in TOOL.FAMILIES.values():
            for service in family.services:
                self.assertTrue(
                    f"\n  {service}:\n" in compose or f"\n  {service}:\n" in lab_dns,
                    f"{family.key}: unknown compose service {service}",
                )

    def test_stable_local_tags_are_not_editable_by_the_tool(self) -> None:
        """The owner decision (2026-07-17): local build tags never carry the
        version — the tool must not know how to rename them."""
        source = (ROOT / "scripts/upgrade-service.py").read_text()
        self.assertNotIn("-probe", source.replace("dhi-*-probe", ""))
        self.assertIn("deliberately NOT renamed", source)


if __name__ == "__main__":
    unittest.main()
