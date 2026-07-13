"""Data-driven tool-config snippet rendering, loaded from tools.yaml.

Design intent (docs/solution-map.md §1.4 / §1.9, "Mantle-style" generator):
adding a new coding tool should be a YAML addition, not a code change.

Snippet templates use plain `{api_base}` / `{key}` placeholders. We
deliberately do NOT use str.format() for substitution, because several
templates are JSON blocks containing many other `{`/`}` characters that
would confuse .format()'s field parser — a simple two-token replace is both
correct and predictable.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

TOOLS_FILE = Path(__file__).parent / "tools.yaml"


def load_tools() -> list[dict[str, Any]]:
    with TOOLS_FILE.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    tools = data.get("tools", [])
    return tools if isinstance(tools, list) else []


def _substitute(template: str, api_base: str, key: str) -> str:
    return (template or "").replace("{api_base}", api_base).replace("{key}", key)


def rendered_tools(api_base: str, key: str) -> list[dict[str, Any]]:
    """Render every tool's snippet + note with the given api_base/key."""
    rendered: list[dict[str, Any]] = []
    for tool in load_tools():
        rendered.append(
            {
                "id": tool.get("id", ""),
                "name": tool.get("name", tool.get("id", "")),
                "description": tool.get("description", ""),
                "snippet": _substitute(tool.get("snippet", ""), api_base, key),
                "note": _substitute(tool.get("note", ""), api_base, key),
            }
        )
    return rendered
