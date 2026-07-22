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
        self.package = Path(temporary.name) / "litellm"
        self.transformation = (
            self.package / "llms/anthropic/chat/transformation.py"
        )
        self.handler = self.package / "llms/anthropic/chat/handler.py"
        self.streaming = self.package / "litellm_core_utils/streaming_handler.py"
        self.chunk_builder = (
            self.package
            / "litellm_core_utils/streaming_chunk_builder_utils.py"
        )
        self.router_headers = (
            self.package / "router_utils/add_retry_fallback_headers.py"
        )
        self.transformation.parent.mkdir(parents=True)
        self.streaming.parent.mkdir(parents=True)
        self.router_headers.parent.mkdir(parents=True)
        self._write_original_sources()

    def _write_original_sources(self) -> None:
        transformation = (
            "from __future__ import annotations\n\n"
            "class AnthropicConfig:\n"
            + patcher.VALIDATOR_BEFORE
            + "        self, usage_object, reasoning_content=None, "
            "completion_response=None, speed=None\n"
            "    ):\n"
            "        return {}\n\n"
            "    def transform(self, completion_response, reasoning_content, speed):\n"
            + patcher.NONSTREAM_BEFORE
            + "        return usage\n"
        )
        handler = (
            "from __future__ import annotations\n\n"
            "class ModelResponseIterator:\n"
            + patcher.STREAM_USAGE_BEFORE
            + "\n    def parse(self, chunk):\n"
            "        if True:\n"
            + patcher.MESSAGE_START_BEFORE
            + "        return usage\n\n"
            "    def delta(self, chunk):\n"
            "        message_delta = chunk\n"
            + patcher.MESSAGE_DELTA_BEFORE
            + "        return usage\n"
        )
        self.transformation.write_text(transformation)
        self.handler.write_text(handler)
        self.streaming.write_text(
            "from __future__ import annotations\n\n" + patcher.TOTAL_USAGE_BEFORE
        )
        self.chunk_builder.write_text(
            "from __future__ import annotations\n\n"
            "class Usage(dict):\n"
            "    def __init__(self, **values):\n"
            "        super().__init__(values)\n"
            "    def model_dump(self):\n"
            "        return dict(self)\n\n"
            "class ChunkProcessor:\n"
            "    def calculate_usage(self, chunks):\n"
            "        returned_usage = Usage(prompt_tokens=0, "
            "completion_tokens=0, total_tokens=0)\n"
            + patcher.CHUNK_BUILDER_USAGE_BEFORE
        )
        self.router_headers.write_text(
            "from __future__ import annotations\n\n"
            + patcher.ROUTER_TOKEN_COUNT_BEFORE
        )

    def test_exact_sources_are_patched_once_and_compile(self) -> None:
        patcher.patch(self.package)

        transformation = self.transformation.read_text()
        handler = self.handler.read_text()
        streaming = self.streaming.read_text()
        chunk_builder = self.chunk_builder.read_text()
        router_headers = self.router_headers.read_text()
        for expected in (patcher.VALIDATOR_AFTER, patcher.NONSTREAM_AFTER):
            self.assertIn(expected, transformation)
        for expected in (
            patcher.STREAM_USAGE_AFTER,
            patcher.MESSAGE_START_AFTER,
            patcher.MESSAGE_DELTA_AFTER,
        ):
            self.assertIn(expected, handler)
        self.assertIn(patcher.TOTAL_USAGE_AFTER, streaming)
        self.assertIn(patcher.CHUNK_BUILDER_USAGE_AFTER, chunk_builder)
        self.assertIn(patcher.ROUTER_TOKEN_COUNT_AFTER, router_headers)
        for path in (
            self.transformation,
            self.handler,
            self.streaming,
            self.chunk_builder,
            self.router_headers,
        ):
            compile(path.read_text(), str(path), "exec")

    def test_stream_chunk_builder_preserves_the_unusable_receipt(self) -> None:
        patcher.patch(self.package)
        namespace: dict[str, object] = {}
        exec(self.chunk_builder.read_text(), namespace)
        processor = namespace["ChunkProcessor"]()
        usage_type = namespace["Usage"]

        usable = processor.calculate_usage(
            [{"usage": usage_type(prompt_tokens=0, completion_tokens=1)}]
        )
        self.assertIsNone(usable.get("aigw_provider_usage_unusable"))

        unusable = processor.calculate_usage(
            [
                {
                    "usage": usage_type(
                        prompt_tokens=0,
                        completion_tokens=1,
                        aigw_provider_usage_unusable=True,
                    )
                }
            ]
        )
        self.assertIs(unusable.get("aigw_provider_usage_unusable"), True)

    def test_router_header_count_does_not_crash_on_untrusted_usage(self) -> None:
        patcher.patch(self.package)
        namespace: dict[str, object] = {}
        exec(self.router_headers.read_text(), namespace)
        count = namespace["response_in_flight_token_count"]

        self.assertEqual(count({"usage": {"input_tokens": 2, "output_tokens": 3}}), 5)
        self.assertEqual(count({"usage": {"total_tokens": 9}}), 9)
        for value in ("5", True, -1, 9_223_372_036_854_775_808):
            with self.subTest(value=value):
                self.assertEqual(
                    count(
                        {
                            "usage": {
                                "input_tokens": value,
                                "output_tokens": 3,
                            }
                        }
                    ),
                    3,
                )

    def test_raw_usage_validation_rejects_every_false_zero_shape(self) -> None:
        patcher.patch(self.package)
        namespace: dict[str, object] = {}
        exec(self.transformation.read_text(), namespace)
        validator = namespace["AnthropicConfig"].aigw_usage_is_valid
        required = ("input_tokens", "output_tokens")

        self.assertTrue(
            validator({"input_tokens": 0, "output_tokens": 0}, required)
        )
        self.assertTrue(
            validator(
                {
                    "input_tokens": 9_223_372_036_854_775_807,
                    "output_tokens": 1,
                },
                required,
            )
        )
        invalid = (
            {},
            {"input_tokens": 1},
            {"input_tokens": "1", "output_tokens": 1},
            {"input_tokens": True, "output_tokens": 1},
            {"input_tokens": -1, "output_tokens": 1},
            {"input_tokens": 1, "output_tokens": 9_223_372_036_854_775_808},
            {
                "input_tokens": 1,
                "output_tokens": 1,
                "cache_read_input_tokens": "2",
            },
            {
                "input_tokens": 1,
                "output_tokens": 1,
                "cache_creation": {"ephemeral_5m_input_tokens": False},
            },
            {
                "input_tokens": 1,
                "output_tokens": 1,
                "iterations": [{"input_tokens": -1}],
            },
        )
        for usage in invalid:
            with self.subTest(usage=usage):
                self.assertFalse(validator(usage, required))

    def test_changed_or_already_patched_source_fails_closed(self) -> None:
        source = self.transformation.read_text()
        self.transformation.write_text(
            source.replace(patcher.NONSTREAM_BEFORE, "        changed = True\n")
        )
        with self.assertRaises(SystemExit):
            patcher.patch(self.package)

        self._write_original_sources()
        patcher.patch(self.package)
        with self.assertRaises(SystemExit):
            patcher.patch(self.package)


if __name__ == "__main__":
    unittest.main()
