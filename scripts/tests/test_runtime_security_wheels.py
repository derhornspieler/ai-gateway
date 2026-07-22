from __future__ import annotations

import hashlib
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
WHEELS = ROOT / "services/dhi-health-probe/runtime-security-wheels"
DOCKERIGNORE = ROOT / "services/dhi-health-probe/.dockerignore"
DOCKER_STACK = ROOT / "ansible/roles/docker_stack/tasks/main.yml"
LITELLM_DOCKERFILE = ROOT / "services/dhi-health-probe/Dockerfile.litellm"
OPENWEBUI_DOCKERFILE = ROOT / "services/dhi-health-probe/Dockerfile.open-webui"


class RuntimeSecurityWheelTests(unittest.TestCase):
    def test_every_wheel_has_one_matching_reviewed_hash(self) -> None:
        records: dict[str, str] = {}
        for line in (WHEELS / "SHA256SUMS").read_text(encoding="ascii").splitlines():
            digest, filename = line.split("  ", 1)
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
            self.assertNotIn(filename, records)
            records[filename] = digest
        self.assertEqual(
            set(records),
            {path.name for path in WHEELS.glob("*.whl")},
        )
        for filename, expected in records.items():
            with self.subTest(wheel=filename):
                actual = hashlib.sha256((WHEELS / filename).read_bytes()).hexdigest()
                self.assertEqual(actual, expected)

    def test_litellm_replaces_only_pyasn1_offline(self) -> None:
        source = LITELLM_DOCKERFILE.read_text(encoding="utf-8")
        self.assertIn("source=runtime-security-wheels", source)
        self.assertIn("sha256sum -c SHA256SUMS", source)
        self.assertIn("python -I -m zipfile -e", source)
        self.assertIn("pyasn1-0.6.3.dist-info", source)
        self.assertIn("pyasn1-0.6.4-py3-none-any.whl", source)
        self.assertIn("version('pyasn1') == '0.6.4'", source)
        self.assertIn("USER 65532:65532", source)
        self.assertNotIn("pip install", source)

    def test_build_context_includes_the_security_wheels(self) -> None:
        source = DOCKERIGNORE.read_text(encoding="utf-8")
        self.assertIn("!Dockerfile.litellm", source)
        self.assertIn("!runtime-security-wheels/*.whl", source)
        self.assertIn("!runtime-security-wheels/SHA256SUMS", source)

    def test_ansible_stages_the_litellm_dockerfile(self) -> None:
        source = DOCKER_STACK.read_text(encoding="utf-8")
        self.assertIn(
            r"Dockerfile(?:\.open-webui|\.grafana|\.litellm)?",
            source,
        )

    def test_openwebui_installs_both_reviewed_security_fixes(self) -> None:
        source = OPENWEBUI_DOCKERFILE.read_text(encoding="utf-8")
        self.assertIn("source=runtime-security-wheels", source)
        self.assertIn("/tmp/aigw-security-wheels/*.whl", source)
        self.assertIn("version('GitPython') == '3.1.54'", source)
        self.assertIn("version('pyasn1') == '0.6.4'", source)


if __name__ == "__main__":
    unittest.main()
