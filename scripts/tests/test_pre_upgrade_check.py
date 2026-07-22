from __future__ import annotations

import datetime
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest


REPO_SCRIPTS = Path(__file__).resolve().parents[1]
CHECK = REPO_SCRIPTS / "pre-upgrade-check.sh"
PLANNER = REPO_SCRIPTS / "plan-compose-builds.py"


class PreUpgradeCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.stack = Path(temporary.name) / "stack"
        self.scripts = self.stack / "scripts"
        self.context = self.stack / "services" / "stateful-app"
        self.state = self.stack / ".state"
        self.fakebin = Path(temporary.name) / "bin"
        for directory in (self.scripts, self.context, self.state, self.fakebin):
            directory.mkdir(parents=True, exist_ok=True)

        self.planner = self.scripts / PLANNER.name
        shutil.copy2(PLANNER, self.planner)
        self.dockerfile = self.context / "Dockerfile"
        self.dockerfile.write_text("FROM scratch\n")
        self.model_path = self.stack / "model.json"
        self.image = "ai-gateway/open-webui:stable"
        self.model = {
            "services": {
                "open-webui": {
                    "build": {"context": str(self.context), "network": "none"},
                    "image": self.image,
                }
            }
        }
        self.model_path.write_text(json.dumps(self.model))

        wrapper = self.scripts / "aigw-compose.sh"
        wrapper.write_text(
            "#!/usr/bin/env bash\nset -euo pipefail\nexec /bin/cat \"$FAKE_MODEL\"\n"
        )
        wrapper.chmod(0o750)

        fake_id = self.fakebin / "id"
        fake_id.write_text(
            "#!/usr/bin/env bash\n"
            "if [[ ${1:-} == -u ]]; then echo 0; else exec /usr/bin/id \"$@\"; fi\n"
        )
        fake_id.chmod(0o755)

        fake_docker = self.fakebin / "docker"
        fake_docker.write_text(
            """#!/usr/bin/env bash
set -euo pipefail
if [[ ${1:-} == --host ]]; then
  [[ ${2:-} == unix:///run/docker.sock ]] || exit 64
  shift 2
fi
if [[ ${1:-} == ps ]]; then
  service=""
  for argument in "$@"; do
    case "$argument" in
      label=com.docker.compose.service=*) service=${argument##*=} ;;
    esac
  done
  if [[ ",${FAKE_EXISTING_SERVICES:-}," == *",${service},"* ]]; then
    printf 'cid-%s\n' "$service"
  fi
  exit 0
fi
if [[ ${1:-} == inspect ]]; then
  printf '%s\n' "$FAKE_CURRENT_IMAGE"
  exit 0
fi
if [[ ${1:-} == image && ${2:-} == inspect ]]; then
  printf '[{"Id":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]\n'
  exit 0
fi
exit 64
"""
        )
        fake_docker.chmod(0o755)

        # Production code pins the root-owned Rocky Docker binary. Patch only
        # the disposable copied test fixtures so the isolated subprocesses can
        # exercise the same argv contract without depending on a local daemon.
        self.planner.write_text(
            self.planner.read_text(encoding="utf-8").replace(
                'DOCKER_BINARY = "/usr/bin/docker"',
                f"DOCKER_BINARY = {str(fake_docker)!r}",
            ),
            encoding="utf-8",
        )
        self.check = self.scripts / CHECK.name
        self.check.write_text(
            CHECK.read_text(encoding="utf-8").replace(
                "docker_cmd=(docker --host unix:///run/docker.sock)",
                f"docker_cmd=({shlex.quote(str(fake_docker))} --host unix:///run/docker.sock)",
            ),
            encoding="utf-8",
        )
        self.check.chmod(0o750)

        self.env = os.environ.copy()
        self.env.update(
            {
                "PATH": f"{self.fakebin}:{self.env['PATH']}",
                "STACK_DIR": str(self.stack),
                "COMPOSE_PROJECT_NAME": "ai-gateway",
                "FAKE_MODEL": str(self.model_path),
                "FAKE_CURRENT_IMAGE": self.image,
                "FAKE_IMAGE_ID": "sha256:" + "a" * 64,
                "FAKE_IMAGE_PRESENT": "1",
                "FAKE_EXISTING_SERVICES": "open-webui",
            }
        )

    def run_planner(self) -> dict:
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                str(self.planner),
                str(self.stack),
                str(self.state / "compose-build-inputs.json"),
                "ai-gateway",
            ],
            input=self.model_path.read_text(),
            text=True,
            capture_output=True,
            env=self.env,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def prepare_source_only_drift(self) -> None:
        baseline = self.run_planner()
        (self.state / "compose-build-inputs.json").write_text(
            json.dumps(baseline["manifest"])
        )
        unchanged = self.run_planner()
        self.assertEqual(unchanged["services"], [])
        self.dockerfile.write_text("FROM scratch\nLABEL revision=two\n")

    def write_receipt(self, *, age_days: int = 0, tamper: bool = False) -> None:
        artifact = self.stack / "backup.tar.gz.age"
        artifact.write_bytes(b"authenticated encrypted backup")
        expected = hashlib.sha256(artifact.read_bytes()).hexdigest()
        receipt = {
            "format": "aigw-state-backup-receipt-v1",
            "created_at": (
                datetime.datetime.now(datetime.timezone.utc)
                - datetime.timedelta(days=age_days)
            ).isoformat(),
            "path": str(artifact),
            "sha256": expected,
        }
        (self.state / "last-backup.json").write_text(json.dumps(receipt))
        if tamper:
            artifact.write_bytes(b"tampered encrypted backup")

    def run_check(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(self.check)],
            text=True,
            capture_output=True,
            env=self.env,
            check=False,
        )

    def test_source_only_drift_with_stable_tag_requires_backup(self) -> None:
        self.prepare_source_only_drift()
        result = self.run_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires scripts/state-backup.sh", result.stderr)
        self.assertIn("open-webui", result.stderr)

    def test_direct_image_reference_drift_still_requires_backup(self) -> None:
        baseline = self.run_planner()
        (self.state / "compose-build-inputs.json").write_text(
            json.dumps(baseline["manifest"])
        )
        self.env["FAKE_CURRENT_IMAGE"] = "ai-gateway/open-webui:previous"
        result = self.run_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires scripts/state-backup.sh", result.stderr)
        self.assertIn("open-webui", result.stderr)

    def test_source_only_drift_rejects_stale_receipt(self) -> None:
        self.prepare_source_only_drift()
        self.write_receipt(age_days=2)
        result = self.run_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("receipt is stale", result.stderr)

    def test_source_only_drift_rejects_tampered_artifact(self) -> None:
        self.prepare_source_only_drift()
        self.write_receipt(tamper=True)
        result = self.run_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no longer matches", result.stderr)

    def test_source_only_drift_accepts_fresh_matching_receipt(self) -> None:
        self.prepare_source_only_drift()
        self.write_receipt()
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("recent encrypted backup verified", result.stderr)

    def test_first_deploy_with_no_container_needs_no_receipt(self) -> None:
        self.env["FAKE_EXISTING_SERVICES"] = ""
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("no stateful image change detected", result.stderr)

    def test_observability_state_and_lab_samba_are_in_stateful_gate(self) -> None:
        source = CHECK.read_text()
        stateful = source.split("stateful=(", 1)[1].split(")", 1)[0].split()
        self.assertIn("alloy", stateful)
        self.assertIn("alertmanager", stateful)
        self.assertIn("samba-ad", stateful)


if __name__ == "__main__":
    unittest.main()
