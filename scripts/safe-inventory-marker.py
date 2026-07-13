#!/usr/bin/env python3
"""Canonicalize and compare bounded, non-secret persistence inventories.

This is deliberately a controller-only evidence tool.  It reads one explicitly
named file (or stdin), performs no service discovery, and imports no Docker,
database, network, or credential clients.  Capture commands should emit only
reviewed safe facts and pipe their JSON into this program.

Canonical input schema::

    {"schema":"aigw.safe-inventory/v1","facts":{"realm_id":"..."}}

``canonicalize`` writes canonical JSON to stdout and a canonical SHA-256/count
receipt to stderr.  Redirect the two streams to separate evidence files.
``compare`` is exact by default.  Volatile scalar leaves and append-only list
prefixes must be declared with explicit JSON pointers; every other field is
compared byte-for-value without normalization.
"""

from __future__ import annotations

import argparse
import copy
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import unicodedata
from typing import Any, NoReturn, Sequence


SCHEMA = "aigw.safe-inventory/v1"
MAX_INPUT_BYTES = 1024 * 1024
MAX_DEPTH = 16
MAX_NODES = 20_000
MAX_FACTS = 2_048
MAX_COLLECTION_ITEMS = 4_096
MAX_KEY_CHARS = 128
MAX_STRING_CHARS = 4_096
MIN_INTEGER = -(2**63)
MAX_INTEGER = 2**63 - 1

KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
HASH_FIELD_RE = re.compile(r"(?:^|[_.-])(sha256|hash|digest|checksum)$", re.I)
SENSITIVE_FIELD_FRAGMENTS = (
    "password",
    "token",
    "secret",
    "private",
    "prompt",
    "content",
    "authorization",
)


class InventoryError(ValueError):
    """Raised when an input or policy violates the safe-inventory contract."""


def _reject_float(_value: str) -> NoReturn:
    raise InventoryError("floating-point values are forbidden")


def _reject_constant(_value: str) -> NoReturn:
    raise InventoryError("non-finite numeric values are forbidden")


def _parse_integer(value: str) -> int:
    # Bound the lexeme before int() so extremely large JSON integers cannot
    # reach interpreter digit-limit errors or consume disproportionate CPU.
    if len(value) > 20:
        raise InventoryError("integer is outside the signed 64-bit range")
    parsed = int(value, 10)
    if not MIN_INTEGER <= parsed <= MAX_INTEGER:
        raise InventoryError("integer is outside the signed 64-bit range")
    return parsed


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InventoryError("duplicate JSON object key is forbidden")
        result[key] = value
    return result


def read_bounded_input(source: str) -> bytes:
    """Read at most MAX_INPUT_BYTES from stdin or a non-symlink regular file."""
    if source == "-":
        payload = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if len(payload) > MAX_INPUT_BYTES:
            raise InventoryError("input exceeds the 1048576-byte limit")
        return payload

    path = Path(source)
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise InventoryError("cannot inspect input file") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise InventoryError("input file must not be a symlink")
    if not stat.S_ISREG(metadata.st_mode):
        raise InventoryError("input must be a regular file")
    if metadata.st_size > MAX_INPUT_BYTES:
        raise InventoryError("input exceeds the 1048576-byte limit")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise InventoryError("input file must not be a symlink") from exc
        raise InventoryError("cannot open input file") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise InventoryError("input must remain a regular file")
        chunks: list[bytes] = []
        remaining = MAX_INPUT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
    finally:
        os.close(descriptor)
    if len(payload) > MAX_INPUT_BYTES:
        raise InventoryError("input exceeds the 1048576-byte limit")
    return payload


def _parse_json(payload: bytes) -> Any:
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise InventoryError("input is not strict UTF-8") from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_int=_parse_integer,
            parse_constant=_reject_constant,
        )
    except InventoryError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise InventoryError("input is not valid bounded JSON") from exc


def _validate_key(key: Any) -> str:
    if not isinstance(key, str) or KEY_RE.fullmatch(key) is None:
        raise InventoryError("field names must use the bounded ASCII identifier form")
    lowered = key.casefold()
    if any(fragment in lowered for fragment in SENSITIVE_FIELD_FRAGMENTS):
        raise InventoryError("sensitive field name is forbidden")
    return key


def _validate_string(value: str) -> None:
    if len(value) > MAX_STRING_CHARS:
        raise InventoryError("string value exceeds the 4096-character limit")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise InventoryError("string value is not valid Unicode") from exc
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise InventoryError("control, format, private-use, and surrogate characters are forbidden")


def _validate_value(value: Any, *, key: str | None, depth: int, counter: list[int]) -> None:
    if depth > MAX_DEPTH:
        raise InventoryError("inventory exceeds the maximum nesting depth")
    counter[0] += 1
    if counter[0] > MAX_NODES:
        raise InventoryError("inventory exceeds the 20000-node limit")

    if key is not None and HASH_FIELD_RE.search(key):
        if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
            raise InventoryError("hash-like fields must be exactly 64 lowercase hex characters")

    if value is None or isinstance(value, float):
        raise InventoryError("null and floating-point values are forbidden")
    if isinstance(value, bool):
        return
    if isinstance(value, int):
        if not MIN_INTEGER <= value <= MAX_INTEGER:
            raise InventoryError("integer is outside the signed 64-bit range")
        return
    if isinstance(value, str):
        _validate_string(value)
        return
    if isinstance(value, list):
        if len(value) > MAX_COLLECTION_ITEMS:
            raise InventoryError("array exceeds the 4096-item limit")
        for item in value:
            _validate_value(item, key=None, depth=depth + 1, counter=counter)
        return
    if isinstance(value, dict):
        if len(value) > MAX_COLLECTION_ITEMS:
            raise InventoryError("object exceeds the 4096-field limit")
        for child_key, child_value in value.items():
            checked_key = _validate_key(child_key)
            _validate_value(
                child_value,
                key=checked_key,
                depth=depth + 1,
                counter=counter,
            )
        return
    raise InventoryError("unsupported JSON value type")


def load_inventory_bytes(payload: bytes) -> dict[str, Any]:
    document = _parse_json(payload)
    if not isinstance(document, dict):
        raise InventoryError("safe inventory must be a JSON object")
    if set(document) != {"schema", "facts"}:
        raise InventoryError("root object must contain exactly schema and facts")
    if document["schema"] != SCHEMA:
        raise InventoryError("unsupported safe-inventory schema")
    facts = document["facts"]
    if not isinstance(facts, dict):
        raise InventoryError("facts must be a JSON object")
    if len(facts) > MAX_FACTS:
        raise InventoryError("facts exceeds the 2048-field limit")
    counter = [0]
    for key, value in facts.items():
        checked_key = _validate_key(key)
        _validate_value(value, key=checked_key, depth=1, counter=counter)
    return document


def load_inventory(source: str) -> dict[str, Any]:
    return load_inventory_bytes(read_bounded_input(source))


def canonical_bytes(document: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            document,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _leaf_count(value: Any) -> int:
    if isinstance(value, dict):
        return sum(_leaf_count(child) for child in value.values())
    if isinstance(value, list):
        return sum(_leaf_count(child) for child in value)
    return 1


def receipt(document: dict[str, Any]) -> dict[str, Any]:
    canonical = canonical_bytes(document)
    return {
        "byte_count": len(canonical),
        "canonical_sha256": hashlib.sha256(canonical).hexdigest(),
        "fact_count": len(document["facts"]),
        "leaf_count": _leaf_count(document["facts"]),
        "schema": SCHEMA,
    }


def _pointer_parts(pointer: str) -> tuple[str, ...]:
    if not pointer.startswith("/") or pointer == "/":
        raise InventoryError("policy paths must be non-root JSON pointers")
    result: list[str] = []
    for raw_part in pointer[1:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        # Reject malformed escapes instead of partially interpreting them.
        if re.search(r"~(?![01])", raw_part):
            raise InventoryError("policy path contains an invalid JSON-pointer escape")
        if not part:
            raise InventoryError("policy path contains an empty component")
        result.append(part)
    return tuple(result)


def _resolve_parent(document: dict[str, Any], pointer: str) -> tuple[dict[str, Any], str]:
    parts = _pointer_parts(pointer)
    current: Any = document
    for part in parts[:-1]:
        if not isinstance(current, dict) or part not in current:
            raise InventoryError("declared policy path does not exist")
        current = current[part]
    if not isinstance(current, dict) or parts[-1] not in current:
        raise InventoryError("declared policy path does not exist")
    return current, parts[-1]


def _require_nonoverlapping(paths: Sequence[str]) -> None:
    if len(set(paths)) != len(paths):
        raise InventoryError("duplicate comparison policy path")
    decoded = [(path, _pointer_parts(path)) for path in paths]
    for index, (left_name, left) in enumerate(decoded):
        for right_name, right in decoded[index + 1 :]:
            shorter = min(len(left), len(right))
            if left[:shorter] == right[:shorter]:
                raise InventoryError(
                    f"overlapping comparison policy paths are forbidden: {left_name}, {right_name}"
                )


def compare_inventories(
    expected: dict[str, Any],
    candidate: dict[str, Any],
    *,
    volatile: Sequence[str] = (),
    append_only_prefix: Sequence[str] = (),
) -> bool:
    all_paths = tuple(volatile) + tuple(append_only_prefix)
    _require_nonoverlapping(all_paths)
    left = copy.deepcopy(expected)
    right = copy.deepcopy(candidate)

    for pointer in volatile:
        left_parent, left_key = _resolve_parent(left, pointer)
        right_parent, right_key = _resolve_parent(right, pointer)
        left_value = left_parent[left_key]
        right_value = right_parent[right_key]
        if isinstance(left_value, (dict, list)) or isinstance(right_value, (dict, list)):
            raise InventoryError("volatile policies may exclude scalar leaves only")
        if type(left_value) is not type(right_value):
            raise InventoryError("volatile values must retain their JSON type")
        left_parent[left_key] = right_parent[right_key] = "__AIGW_DECLARED_VOLATILE__"

    for pointer in append_only_prefix:
        left_parent, left_key = _resolve_parent(left, pointer)
        right_parent, right_key = _resolve_parent(right, pointer)
        left_value = left_parent[left_key]
        right_value = right_parent[right_key]
        if not isinstance(left_value, list) or not isinstance(right_value, list):
            raise InventoryError("append-only-prefix policies require arrays")
        if len(right_value) < len(left_value) or right_value[: len(left_value)] != left_value:
            return False
        left_parent[left_key] = right_parent[right_key] = ["__AIGW_APPEND_PREFIX_VERIFIED__"]

    return left == right


def _canonical_line(value: dict[str, Any]) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ) + "\n"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Canonicalize or compare bounded non-secret persistence inventories; "
            "the program performs no Docker, database, network, or credential access."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    canonicalize = subparsers.add_parser(
        "canonicalize",
        help="write canonical inventory to stdout and its receipt to stderr",
        description=(
            'Accept exactly {"schema":"aigw.safe-inventory/v1","facts":{...}}; '
            "write canonical JSON to stdout and its SHA-256/count receipt to stderr."
        ),
        epilog=(
            "Example: safe-fact-query | safe-inventory-marker.py canonicalize "
            "> before.json 2> before.receipt.json"
        ),
    )
    canonicalize.add_argument(
        "input",
        nargs="?",
        default="-",
        help="regular non-symlink JSON file, or - for stdin (default: -)",
    )

    compare = subparsers.add_parser(
        "compare",
        help="compare two inventories exactly except for explicit policies",
        description=(
            "Compare validated inventories exactly. Every exception must name an "
            "existing JSON pointer and all undeclared facts remain durable."
        ),
        epilog=(
            "Example: safe-inventory-marker.py compare before.json after.json "
            "--volatile /facts/captured_at --append-only-prefix /facts/events"
        ),
    )
    compare.add_argument("expected", help="baseline inventory file")
    compare.add_argument("candidate", help="candidate inventory file")
    compare.add_argument(
        "--volatile",
        action="append",
        default=[],
        metavar="JSON_POINTER",
        help="exclude one existing scalar leaf; repeat for additional leaves",
    )
    compare.add_argument(
        "--append-only-prefix",
        action="append",
        default=[],
        metavar="JSON_POINTER",
        help="require a baseline array to be an exact prefix of the candidate array",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "canonicalize":
            document = load_inventory(arguments.input)
            sys.stdout.buffer.write(canonical_bytes(document))
            sys.stderr.write(_canonical_line(receipt(document)))
            return 0

        if arguments.expected == "-" or arguments.candidate == "-":
            raise InventoryError("compare requires two named regular files")
        expected = load_inventory(arguments.expected)
        candidate = load_inventory(arguments.candidate)
        matches = compare_inventories(
            expected,
            candidate,
            volatile=arguments.volatile,
            append_only_prefix=arguments.append_only_prefix,
        )
        result = {
            "append_only_prefix": sorted(arguments.append_only_prefix),
            "candidate_sha256": receipt(candidate)["canonical_sha256"],
            "comparison": "match" if matches else "mismatch",
            "expected_sha256": receipt(expected)["canonical_sha256"],
            "schema": SCHEMA,
            "volatile": sorted(arguments.volatile),
        }
        sys.stdout.write(_canonical_line(result))
        return 0 if matches else 1
    except InventoryError as exc:
        parser.exit(2, f"safe-inventory error: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
