"""Repo-hardening contracts surfaced by the 2026-07-16 upgrade-durability audit.

Two classes of silent drift the rest of the suite did not previously pin:

1. The Traefik image is a locally built DHI derivative whose BASE_IMAGE and
   PATCH_IMAGE digests are declared in THREE places that must agree — the
   Dockerfile ARG defaults and BOTH per-edge Compose build-arg blocks (the
   internal and ADM Traefiks share one image tag). The audit found zero guards
   here, so a partial bump could ship whichever build ran last.

2. The Ansible services-tree sync copies every allow-listed source file; a
   local dev virtualenv (services/*/.venv) otherwise matches the *.py rule and
   floods the deployed tree (observed live: ~4,660 files, minutes per
   converge, dev tooling on the host). Both the directory and file sync tasks
   must exclude virtualenv/build-cache directories.
"""

from __future__ import annotations

import re
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = (ROOT / "compose/docker-compose.yml").read_text(encoding="utf-8")
TRAEFIK_DOCKERFILE = (ROOT / "services/traefik/Dockerfile").read_text(
    encoding="utf-8"
)
STACK = (ROOT / "ansible/roles/docker_stack/tasks/main.yml").read_text(
    encoding="utf-8"
)
STATE_RESTORE = (ROOT / "scripts/state-restore.sh").read_text(encoding="utf-8")
STATE_BACKUP = (ROOT / "scripts/state-backup.sh").read_text(encoding="utf-8")


class TraefikImagePinContractTest(unittest.TestCase):
    def _dockerfile_arg(self, name: str) -> str:
        match = re.search(rf"^ARG {name}=(\S+)$", TRAEFIK_DOCKERFILE, re.M)
        self.assertIsNotNone(match, f"{name} ARG missing from traefik Dockerfile")
        value = match.group(1)
        self.assertRegex(value, r"@sha256:[0-9a-f]{64}$", f"{name} is not digest-pinned")
        return value

    def test_traefik_build_pins_agree_across_all_three_declarations(self) -> None:
        base = self._dockerfile_arg("BASE_IMAGE")
        patch = self._dockerfile_arg("PATCH_IMAGE")
        # Both Compose build blocks (internal + ADM edge) must carry the exact
        # same BASE_IMAGE and PATCH_IMAGE as the Dockerfile defaults. Two
        # occurrences each — one per edge — and never any other value.
        self.assertEqual(
            COMPOSE.count(f"BASE_IMAGE: {base}"), 2,
            "both traefik Compose build blocks must pin the Dockerfile BASE_IMAGE",
        )
        self.assertEqual(
            COMPOSE.count(f"PATCH_IMAGE: {patch}"), 2,
            "both traefik Compose build blocks must pin the Dockerfile PATCH_IMAGE",
        )
        # No stray traefik BASE/PATCH pin may diverge from the Dockerfile.
        for line in COMPOSE.splitlines():
            stripped = line.strip()
            if stripped.startswith("BASE_IMAGE:") and "traefik" in stripped:
                self.assertEqual(stripped, f"BASE_IMAGE: {base}", stripped)
            if stripped.startswith("PATCH_IMAGE:"):
                self.assertEqual(stripped, f"PATCH_IMAGE: {patch}", stripped)

    def test_traefik_version_label_matches_the_patched_binary(self) -> None:
        patch = self._dockerfile_arg("PATCH_IMAGE")
        version = re.search(r"traefik:v([0-9.]+)@", patch).group(1)
        self.assertIn(
            f'org.opencontainers.image.version="{version}"', TRAEFIK_DOCKERFILE
        )


class StackSyncHygieneContractTest(unittest.TestCase):
    EXCLUSION = (
        r"(^|/)(__pycache__|\.pytest_cache|\.ruff_cache|\.venv|venv|\.tox|"
        r"node_modules|\.git|secrets)(/|$)"
    )

    def test_both_service_sync_tasks_exclude_virtualenvs_and_caches(self) -> None:
        # The exact exclusion regex must guard BOTH the directory-create and
        # file-copy sync loops — excluding it from only one still floods the
        # tree. Pin the literal so a future edit to one copies to the other.
        occurrences = STACK.count(
            f"item.path is not regex('{self.EXCLUSION}')"
        )
        self.assertEqual(
            occurrences, 2,
            "both services-tree sync tasks must carry the identical "
            "virtualenv/cache exclusion regex",
        )
        # Guard the specific token that bit us: a dev virtualenv under a
        # service dir.
        self.assertIn(r"\.venv", self.EXCLUSION)


class RestoreVersionGuardContractTest(unittest.TestCase):
    """Audit 2026-07-16 risk 2: a cross-major PostgreSQL restore is unsafe (a
    logical dump from major N cannot load into a different major's server), and
    the converge's rollback manifest keeps the old image one edit away. The
    backup records server_version; the restore must refuse a major mismatch
    against the deployed pin BEFORE any destructive step."""

    def test_backup_records_the_postgres_version(self) -> None:
        self.assertIn('"postgres_version"', STATE_BACKUP)
        self.assertIn("show server_version", STATE_BACKUP)

    def test_restore_refuses_cross_major_before_destruction(self) -> None:
        # The guard must read both majors and refuse a mismatch.
        self.assertIn("backup_pg_major", STATE_RESTORE)
        self.assertIn("target_pg_major", STATE_RESTORE)
        self.assertIn('"postgres_version"', STATE_RESTORE)
        self.assertIn("restore refused: backup PostgreSQL major", STATE_RESTORE)
        # It must sit before the destructive stop, not after.
        guard = STATE_RESTORE.index('restore refused: backup PostgreSQL major')
        destruct = STATE_RESTORE.index(
            "Stopping the current stack for destructive restore"
        )
        self.assertLess(
            guard, destruct,
            "the version guard must run before the stack is stopped",
        )


if __name__ == "__main__":
    unittest.main()
