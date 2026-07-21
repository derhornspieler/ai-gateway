#!/usr/bin/env python3
"""Verify the patched Open WebUI Chroma client without starting the service."""

from __future__ import annotations

import ast
from pathlib import Path
import sys


FORBIDDEN_NAMES = {
    "CHROMA_CLIENT_AUTH_CREDENTIALS",
    "CHROMA_CLIENT_AUTH_PROVIDER",
    "CHROMA_HTTP_HEADERS",
    "CHROMA_HTTP_HOST",
    "CHROMA_HTTP_PORT",
    "CHROMA_HTTP_SSL",
}


def verify(path: Path) -> None:
    source = path.read_bytes()
    tree = ast.parse(source, filename=str(path))
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    attributes = {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    if names & FORBIDDEN_NAMES or "HttpClient" in attributes:
        raise AssertionError("remote Chroma configuration remains reachable")
    if "PersistentClient" not in attributes:
        raise AssertionError("the embedded Chroma client is missing")

    collection_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get_or_create_collection"
    ]
    if len(collection_calls) != 2:
        raise AssertionError("expected exactly two fixed collection call sites")
    for call in collection_calls:
        if call.args or {item.arg for item in call.keywords} != {"name", "metadata"}:
            raise AssertionError("collection creation accepts unreviewed configuration")
        values = {item.arg: item.value for item in call.keywords}
        name = values["name"]
        metadata = values["metadata"]
        if not isinstance(name, ast.Name) or name.id != "collection_name":
            raise AssertionError("collection name source drifted")
        if (
            not isinstance(metadata, ast.Dict)
            or len(metadata.keys) != 1
            or not isinstance(metadata.keys[0], ast.Constant)
            or metadata.keys[0].value != "hnsw:space"
            or not isinstance(metadata.values[0], ast.Constant)
            or metadata.values[0].value != "cosine"
        ):
            raise AssertionError("collection metadata is not the fixed cosine policy")

    explicit_embedding_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and any(item.arg in {"embeddings", "query_embeddings"} for item in node.keywords)
    ]
    if len(explicit_embedding_calls) < 3:
        raise AssertionError("vector operations no longer supply reviewed embeddings")


def main() -> int:
    if len(sys.argv) != 2:
        return 2
    verify(Path(sys.argv[1]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
