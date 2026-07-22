from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
PATCH_PATH = (
    ROOT / "services/dhi-health-probe/patch_litellm_anthropic_usage.py"
)
SPEC = importlib.util.spec_from_file_location("litellm_usage_patch", PATCH_PATH)
assert SPEC is not None and SPEC.loader is not None
patcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(patcher)


class LiteLLMAnthropicUsagePatchTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "transformation.py"

    def test_exact_source_is_patched_once(self) -> None:
        self.path.write_text("prefix\n" + patcher.BEFORE + "suffix\n")

        patcher.patch(self.path)

        source = self.path.read_text()
        self.assertNotIn(patcher.BEFORE, source)
        self.assertEqual(source.count(patcher.AFTER), 1)

    def test_changed_or_already_patched_source_fails_closed(self) -> None:
        for source in ("changed upstream\n", patcher.AFTER):
            with self.subTest(source=source[:16]):
                self.path.write_text(source)
                with self.assertRaises(SystemExit):
                    patcher.patch(self.path)


if __name__ == "__main__":
    unittest.main()
