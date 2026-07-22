#!/usr/bin/env python3
"""Keep unusable Anthropic usage visible to the AI Gateway callback."""

from __future__ import annotations

from pathlib import Path
import sys


VALIDATOR_BEFORE = '''    def calculate_usage(
'''

VALIDATOR_AFTER = '''    @staticmethod
    def aigw_usage_is_valid(
        usage_object: object, required_fields: tuple[str, ...]
    ) -> bool:
        if not isinstance(usage_object, dict):
            return False
        if any(field not in usage_object for field in required_fields):
            return False

        token_fields = (
            "input_tokens",
            "output_tokens",
            "cache_creation_input_tokens",
            "cache_read_input_tokens",
        )
        for field in token_fields:
            if field not in usage_object:
                continue
            value = usage_object[field]
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 <= value <= 9_223_372_036_854_775_807
            ):
                return False

        cache_creation = usage_object.get("cache_creation")
        if cache_creation is not None:
            if not isinstance(cache_creation, dict):
                return False
            for field in (
                "ephemeral_5m_input_tokens",
                "ephemeral_1h_input_tokens",
            ):
                if field not in cache_creation:
                    continue
                value = cache_creation[field]
                if (
                    isinstance(value, bool)
                    or not isinstance(value, int)
                    or not 0 <= value <= 9_223_372_036_854_775_807
                ):
                    return False

        iterations = usage_object.get("iterations")
        if iterations is not None:
            if not isinstance(iterations, list):
                return False
            for iteration in iterations:
                if not isinstance(iteration, dict):
                    return False
                for field in token_fields:
                    if field not in iteration:
                        continue
                    value = iteration[field]
                    if (
                        isinstance(value, bool)
                        or not isinstance(value, int)
                        or not 0 <= value <= 9_223_372_036_854_775_807
                    ):
                        return False
        return True

    def calculate_usage(
'''

NONSTREAM_BEFORE = '''        usage = self.calculate_usage(
            usage_object=completion_response["usage"],
            reasoning_content=reasoning_content,
            completion_response=completion_response,
            speed=speed,
        )
'''

NONSTREAM_AFTER = '''        provider_usage = completion_response.get("usage")
        provider_usage_unusable = not self.aigw_usage_is_valid(
            provider_usage, ("input_tokens", "output_tokens")
        )
        if provider_usage_unusable:
            provider_usage = {}
        usage = self.calculate_usage(
            usage_object=provider_usage,
            reasoning_content=reasoning_content,
            completion_response=completion_response,
            speed=speed,
        )
        if provider_usage_unusable:
            usage["aigw_provider_usage_unusable"] = True
'''

STREAM_USAGE_BEFORE = '''    def _handle_usage(self, anthropic_usage_chunk: Union[dict, UsageDelta]) -> Usage:
        reasoning_content = "".join(self.reasoning_content_chunks) if self.reasoning_content_chunks else None
        return AnthropicConfig().calculate_usage(
            usage_object=cast(dict, anthropic_usage_chunk),
            reasoning_content=reasoning_content,
            speed=self.speed,
        )
'''

STREAM_USAGE_AFTER = '''    def _handle_usage(
        self,
        anthropic_usage_chunk: object,
        required_fields: tuple[str, ...],
    ) -> Usage:
        reasoning_content = "".join(self.reasoning_content_chunks) if self.reasoning_content_chunks else None
        usage_is_unusable = not AnthropicConfig.aigw_usage_is_valid(
            anthropic_usage_chunk, required_fields
        )
        usage_object = anthropic_usage_chunk if not usage_is_unusable else {}
        usage = AnthropicConfig().calculate_usage(
            usage_object=cast(dict, usage_object),
            reasoning_content=reasoning_content,
            speed=self.speed,
        )
        if usage_is_unusable:
            usage["aigw_provider_usage_unusable"] = True
        return usage
'''

MESSAGE_START_BEFORE = '''                message_start_block = MessageStartBlock(**chunk)  # type: ignore
                if "usage" in message_start_block["message"]:
                    usage = self._handle_usage(anthropic_usage_chunk=message_start_block["message"]["usage"])
'''

MESSAGE_START_AFTER = '''                message_start_block = MessageStartBlock(**chunk)  # type: ignore
                usage = self._handle_usage(
                    anthropic_usage_chunk=message_start_block["message"].get("usage"),
                    required_fields=("input_tokens", "output_tokens"),
                )
'''

MESSAGE_DELTA_BEFORE = '''        usage = self._handle_usage(anthropic_usage_chunk=message_delta["usage"])
'''

MESSAGE_DELTA_AFTER = '''        usage = self._handle_usage(
            anthropic_usage_chunk=chunk.get("usage"),
            required_fields=("output_tokens",),
        )
'''

TOTAL_USAGE_BEFORE = '''def calculate_total_usage(chunks: List[ModelResponse]) -> Usage:
    """Assume most recent usage chunk has total usage uptil then."""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    for chunk in chunks:
        if "usage" in chunk and chunk["usage"] is not None:
            if "prompt_tokens" in chunk["usage"]:
                prompt_tokens = chunk["usage"].get("prompt_tokens", 0) or 0
            if "completion_tokens" in chunk["usage"]:
                completion_tokens = chunk["usage"].get("completion_tokens", 0) or 0

    returned_usage_chunk = Usage(
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=prompt_tokens + completion_tokens,
    )

    return returned_usage_chunk
'''

TOTAL_USAGE_AFTER = '''def calculate_total_usage(chunks: List[ModelResponse]) -> Usage:
    """Assume most recent usage chunk has total usage uptil then."""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    provider_usage_unusable = False
    for chunk in chunks:
        if "usage" in chunk and chunk["usage"] is not None:
            if "prompt_tokens" in chunk["usage"]:
                prompt_tokens = chunk["usage"].get("prompt_tokens", 0) or 0
            if "completion_tokens" in chunk["usage"]:
                completion_tokens = chunk["usage"].get("completion_tokens", 0) or 0
            if chunk["usage"].get("aigw_provider_usage_unusable") is True:
                provider_usage_unusable = True

    returned_usage_chunk = Usage(
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=prompt_tokens + completion_tokens,
    )
    if provider_usage_unusable:
        returned_usage_chunk["aigw_provider_usage_unusable"] = True

    return returned_usage_chunk
'''

CHUNK_BUILDER_USAGE_BEFORE = '''        returned_usage = Usage(**returned_usage.model_dump())

        return returned_usage
'''

CHUNK_BUILDER_USAGE_AFTER = '''        provider_usage_unusable = False
        for chunk in chunks:
            chunk_usage = (
                chunk.get("usage")
                if isinstance(chunk, dict)
                else getattr(chunk, "usage", None)
            )
            usage_get = getattr(chunk_usage, "get", None)
            if (
                callable(usage_get)
                and usage_get("aigw_provider_usage_unusable") is True
            ):
                provider_usage_unusable = True
                break

        returned_usage = Usage(**returned_usage.model_dump())
        if provider_usage_unusable:
            returned_usage["aigw_provider_usage_unusable"] = True

        return returned_usage
'''

ROUTER_TOKEN_COUNT_BEFORE = '''def response_in_flight_token_count(response: object) -> int:
    usage = response.get("usage") if isinstance(response, dict) else getattr(response, "usage", None)
    if usage is None:
        return 0
    if isinstance(usage, dict):
        total = int(usage.get("total_tokens") or 0)
        if total:
            return total
        return int(usage.get("input_tokens") or 0) + int(usage.get("output_tokens") or 0)
    return int(getattr(usage, "total_tokens", 0) or 0)
'''

ROUTER_TOKEN_COUNT_AFTER = '''def response_in_flight_token_count(response: object) -> int:
    usage = response.get("usage") if isinstance(response, dict) else getattr(response, "usage", None)
    if usage is None:
        return 0

    def safe_count(value: object) -> int:
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= 9_223_372_036_854_775_807
        ):
            return 0
        return value

    if isinstance(usage, dict):
        total = safe_count(usage.get("total_tokens"))
        if total:
            return total
        return safe_count(usage.get("input_tokens")) + safe_count(
            usage.get("output_tokens")
        )
    return safe_count(getattr(usage, "total_tokens", None))
'''

PATCHES = {
    Path("llms/anthropic/chat/transformation.py"): (
        (VALIDATOR_BEFORE, VALIDATOR_AFTER),
        (NONSTREAM_BEFORE, NONSTREAM_AFTER),
    ),
    Path("llms/anthropic/chat/handler.py"): (
        (STREAM_USAGE_BEFORE, STREAM_USAGE_AFTER),
        (MESSAGE_START_BEFORE, MESSAGE_START_AFTER),
        (MESSAGE_DELTA_BEFORE, MESSAGE_DELTA_AFTER),
    ),
    Path("litellm_core_utils/streaming_handler.py"): (
        (TOTAL_USAGE_BEFORE, TOTAL_USAGE_AFTER),
    ),
    Path("litellm_core_utils/streaming_chunk_builder_utils.py"): (
        (CHUNK_BUILDER_USAGE_BEFORE, CHUNK_BUILDER_USAGE_AFTER),
    ),
    Path("router_utils/add_retry_fallback_headers.py"): (
        (ROUTER_TOKEN_COUNT_BEFORE, ROUTER_TOKEN_COUNT_AFTER),
    ),
}


def patch(package_root: Path) -> None:
    updates: dict[Path, str] = {}
    for relative, replacements in PATCHES.items():
        path = package_root / relative
        source = path.read_text(encoding="utf-8")
        updated = source
        for before, after in replacements:
            if updated.count(before) != 1 or after in updated:
                raise SystemExit(f"the pinned LiteLLM source changed: {relative}")
            updated = updated.replace(before, after)
        compile(updated, str(path), "exec")
        updates[path] = updated

    for path, updated in updates.items():
        path.write_text(updated, encoding="utf-8")
        if path.read_text(encoding="utf-8") != updated:
            raise SystemExit(f"the LiteLLM patch did not persist: {path.name}")


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: patch_litellm_anthropic_usage.py LITELLM_PACKAGE")
    patch(Path(sys.argv[1]))


if __name__ == "__main__":
    main()
