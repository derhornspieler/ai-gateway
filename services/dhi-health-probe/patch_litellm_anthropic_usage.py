#!/usr/bin/env python3
"""Keep missing Anthropic usage visible to the AI Gateway callback."""

from __future__ import annotations

from pathlib import Path
import sys


BEFORE = '''        usage = self.calculate_usage(
            usage_object=completion_response["usage"],
            reasoning_content=reasoning_content,
            completion_response=completion_response,
            speed=speed,
        )
'''

AFTER = '''        provider_usage = completion_response.get("usage")
        if not isinstance(provider_usage, dict):
            _hidden_params["additional_headers"][
                "aigw-provider-usage-missing"
            ] = "true"
            provider_usage = {}
        usage = self.calculate_usage(
            usage_object=provider_usage,
            reasoning_content=reasoning_content,
            completion_response=completion_response,
            speed=speed,
        )
'''


def patch(path: Path) -> None:
    source = path.read_text(encoding="utf-8")
    if source.count(BEFORE) != 1 or AFTER in source:
        raise SystemExit("the pinned LiteLLM Anthropic usage code changed")
    path.write_text(source.replace(BEFORE, AFTER), encoding="utf-8")
    updated = path.read_text(encoding="utf-8")
    if BEFORE in updated or updated.count(AFTER) != 1:
        raise SystemExit("the LiteLLM Anthropic usage patch did not apply exactly once")


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: patch_litellm_anthropic_usage.py FILE")
    patch(Path(sys.argv[1]))


if __name__ == "__main__":
    main()
