from __future__ import annotations

import hashlib
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
WHEELS = ROOT / "services/dhi-health-probe/openwebui-wheels"
DOCKERFILE = ROOT / "services/dhi-health-probe/Dockerfile.open-webui"


class OpenWebUiSecurityWheelTests(unittest.TestCase):
    def test_every_committed_wheel_has_one_matching_hash(self) -> None:
        records: dict[str, str] = {}
        for line in (WHEELS / "SHA256SUMS").read_text(encoding="ascii").splitlines():
            digest, relative = line.split("  ", 1)
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
            self.assertNotIn(relative, records)
            records[relative] = digest
        actual = {
            str(path.relative_to(WHEELS))
            for path in WHEELS.glob("*/*.whl")
        }
        self.assertEqual(set(records), actual)
        for relative, expected in records.items():
            with self.subTest(wheel=relative):
                self.assertEqual(
                    hashlib.sha256((WHEELS / relative).read_bytes()).hexdigest(),
                    expected,
                )

    def test_both_release_platforms_have_the_same_fixed_packages(self) -> None:
        for platform in ("amd64", "arm64"):
            names = {path.name.lower() for path in (WHEELS / platform).glob("*.whl")}
            self.assertEqual(len(names), 2)
            self.assertTrue(any(name.startswith("cryptography-48.0.1-") for name in names))
            self.assertTrue(any(name.startswith("pillow-12.3.0-") for name in names))
        universal = {path.name.lower() for path in (WHEELS / "any").glob("*.whl")}
        self.assertEqual(
            universal,
            {
                "mcp-1.28.1-py3-none-any.whl",
                "python_multipart-0.0.30-py3-none-any.whl",
            },
        )

    def test_docker_build_checks_hashes_and_uses_no_package_index(self) -> None:
        source = DOCKERFILE.read_text(encoding="utf-8")
        self.assertIn("sha256sum -c SHA256SUMS", source)
        self.assertIn("pip install --no-index --no-deps --force-reinstall", source)
        self.assertIn("source=openwebui-wheels", source)
        self.assertNotIn("pip install --upgrade", source)


if __name__ == "__main__":
    unittest.main()
