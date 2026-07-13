from __future__ import annotations

import ast
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "safe-inventory-marker.py"
SPEC = importlib.util.spec_from_file_location("safe_inventory_marker", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
marker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(marker)


def encoded(facts, **extra):
    document = {"schema": marker.SCHEMA, "facts": facts, **extra}
    return json.dumps(document, separators=(",", ":")).encode("utf-8")


class SafeInventoryMarkerTests(unittest.TestCase):
    def load(self, facts):
        return marker.load_inventory_bytes(encoded(facts))

    def assert_rejected(self, payload: bytes, message: str) -> None:
        with self.assertRaisesRegex(marker.InventoryError, message):
            marker.load_inventory_bytes(payload)

    def test_canonical_json_and_receipt_are_stable_and_newline_terminated(self) -> None:
        document = self.load(
            {
                "z_count": 2,
                "a": {"enabled": True, "alias_digest": "a" * 64},
            }
        )
        canonical = marker.canonical_bytes(document)
        self.assertEqual(
            canonical,
            (
                '{"facts":{"a":{"alias_digest":"'
                + "a" * 64
                + '","enabled":true},"z_count":2},'
                '"schema":"aigw.safe-inventory/v1"}\n'
            ).encode(),
        )
        receipt = marker.receipt(document)
        self.assertEqual(receipt["byte_count"], len(canonical))
        self.assertRegex(receipt["canonical_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(receipt["fact_count"], 2)
        self.assertEqual(receipt["leaf_count"], 3)

    def test_duplicate_keys_at_any_depth_are_rejected(self) -> None:
        self.assert_rejected(
            b'{"schema":"aigw.safe-inventory/v1","facts":{"x":{"n":1,"n":2}}}',
            "duplicate",
        )

    def test_non_utf8_and_floats_null_and_nonfinite_numbers_are_rejected(self) -> None:
        self.assert_rejected(b"\xff", "UTF-8")
        self.assert_rejected(encoded({"latency": 1.5}), "floating-point")
        self.assert_rejected(encoded({"missing": None}), "null")
        self.assert_rejected(
            b'{"schema":"aigw.safe-inventory/v1","facts":{"n":NaN}}',
            "non-finite",
        )

    def test_unknown_root_fields_and_wrong_schema_are_rejected(self) -> None:
        self.assert_rejected(encoded({}, normalized=True), "exactly schema and facts")
        self.assert_rejected(
            b'{"schema":"aigw.safe-inventory/v2","facts":{}}',
            "unsupported",
        )

    def test_every_sensitive_field_fragment_is_rejected_case_insensitively(self) -> None:
        names = (
            "db_password_hash",
            "accessTokenId",
            "secret_ref",
            "privateKeyId",
            "prompt_length",
            "request_content",
            "AuthorizationHeader",
        )
        for name in names:
            with self.subTest(name=name):
                self.assert_rejected(encoded({name: "redacted"}), "sensitive")

    def test_malformed_63_character_digest_is_rejected(self) -> None:
        self.assert_rejected(encoded({"rotator_digest": "a" * 63}), "64 lowercase hex")
        accepted = self.load({"rotator_digest": "a" * 64})
        self.assertEqual(accepted["facts"]["rotator_digest"], "a" * 64)
        self.assert_rejected(encoded({"rotator_digest": "A" * 64}), "lowercase")
        self.assert_rejected(encoded({"rotator_digest": ["a" * 64]}), "64 lowercase")

    def test_bounded_strings_integers_depth_and_collections(self) -> None:
        self.assert_rejected(encoded({"text": "x" * 4097}), "4096-character")
        self.assert_rejected(encoded({"n": 2**63}), "signed 64-bit")
        self.assert_rejected(
            (
                '{"schema":"aigw.safe-inventory/v1","facts":{"n":'
                + "9" * 10_000
                + "}}"
            ).encode(),
            "signed 64-bit",
        )
        self.assert_rejected(encoded({"text": "safe\nunsafe"}), "control")
        nested = "leaf"
        for _ in range(marker.MAX_DEPTH + 1):
            nested = {"next": nested}
        self.assert_rejected(encoded({"root": nested}), "nesting depth")

    def test_file_reader_rejects_symlink_and_oversize_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real.json"
            real.write_bytes(encoded({"count": 1}))
            linked = root / "linked.json"
            linked.symlink_to(real)
            with self.assertRaisesRegex(marker.InventoryError, "symlink"):
                marker.read_bounded_input(str(linked))

            oversized = root / "oversized.json"
            with oversized.open("wb") as destination:
                destination.truncate(marker.MAX_INPUT_BYTES + 1)
            with self.assertRaisesRegex(marker.InventoryError, "1048576-byte"):
                marker.read_bounded_input(str(oversized))

    def test_exact_compare_detects_unknown_durable_field_changes(self) -> None:
        expected = self.load({"realm_id": "one", "count": 7})
        changed = self.load({"realm_id": "two", "count": 7})
        added = self.load({"realm_id": "one", "count": 7, "new_fact": True})
        self.assertFalse(marker.compare_inventories(expected, changed))
        self.assertFalse(marker.compare_inventories(expected, added))

    def test_declared_volatile_leaf_does_not_hide_a_durable_mismatch(self) -> None:
        expected = self.load({"captured_at": "2026-07-13T01:00:00Z", "realm_id": "one"})
        only_volatile = self.load(
            {"captured_at": "2026-07-13T02:00:00Z", "realm_id": "one"}
        )
        durable_too = self.load(
            {"captured_at": "2026-07-13T02:00:00Z", "realm_id": "two"}
        )
        policy = ["/facts/captured_at"]
        self.assertTrue(marker.compare_inventories(expected, only_volatile, volatile=policy))
        self.assertFalse(marker.compare_inventories(expected, durable_too, volatile=policy))

    def test_volatile_policy_rejects_unknown_collection_type_and_overlap(self) -> None:
        baseline = self.load({"captured_at": "one", "events": ["a"]})
        candidate = self.load({"captured_at": "two", "events": ["a", "b"]})
        with self.assertRaisesRegex(marker.InventoryError, "does not exist"):
            marker.compare_inventories(
                baseline, candidate, volatile=["/facts/not_declared"]
            )
        with self.assertRaisesRegex(marker.InventoryError, "scalar leaves"):
            marker.compare_inventories(baseline, candidate, volatile=["/facts/events"])
        with self.assertRaisesRegex(marker.InventoryError, "overlapping"):
            marker.compare_inventories(
                baseline,
                candidate,
                volatile=["/facts/captured_at"],
                append_only_prefix=["/facts"],
            )

    def test_append_only_prefix_accepts_only_an_unchanged_prefix(self) -> None:
        baseline = self.load({"events": ["a", {"id": "b"}], "realm_id": "one"})
        appended = self.load(
            {"events": ["a", {"id": "b"}, "c"], "realm_id": "one"}
        )
        rewritten = self.load({"events": ["x", {"id": "b"}], "realm_id": "one"})
        durable_change = self.load(
            {"events": ["a", {"id": "b"}, "c"], "realm_id": "two"}
        )
        policy = ["/facts/events"]
        self.assertTrue(
            marker.compare_inventories(
                baseline, appended, append_only_prefix=policy
            )
        )
        self.assertFalse(
            marker.compare_inventories(
                baseline, rewritten, append_only_prefix=policy
            )
        )
        self.assertFalse(
            marker.compare_inventories(
                baseline, durable_change, append_only_prefix=policy
            )
        )

    def test_cli_emits_separate_canonical_inventory_and_receipt(self) -> None:
        result = subprocess.run(
            [sys.executable, "-I", str(SCRIPT), "canonicalize"],
            input=encoded({"count": 3}),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertTrue(result.stdout.endswith(b"\n"))
        self.assertTrue(result.stderr.endswith(b"\n"))
        canonical = json.loads(result.stdout)
        receipt = json.loads(result.stderr)
        self.assertEqual(canonical["facts"]["count"], 3)
        self.assertEqual(receipt["canonical_sha256"], marker.receipt(canonical)["canonical_sha256"])

    def test_cli_compare_returns_nonzero_for_durable_drift_and_accepts_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected = root / "expected.json"
            candidate = root / "candidate.json"
            expected.write_bytes(encoded({"captured_at": "one", "realm_id": "stable"}))
            candidate.write_bytes(encoded({"captured_at": "two", "realm_id": "stable"}))

            exact = subprocess.run(
                [sys.executable, "-I", str(SCRIPT), "compare", str(expected), str(candidate)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(exact.returncode, 1)
            self.assertEqual(json.loads(exact.stdout)["comparison"], "mismatch")

            declared = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(SCRIPT),
                    "compare",
                    str(expected),
                    str(candidate),
                    "--volatile",
                    "/facts/captured_at",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(declared.returncode, 0, declared.stderr.decode())
            self.assertEqual(json.loads(declared.stdout)["comparison"], "match")

    def test_source_has_no_process_network_database_or_credential_clients(self) -> None:
        tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".", 1)[0])
        self.assertTrue(
            imported.isdisjoint(
                {
                    "docker",
                    "http",
                    "psycopg",
                    "requests",
                    "socket",
                    "sqlite3",
                    "subprocess",
                    "urllib",
                }
            ),
            imported,
        )


if __name__ == "__main__":
    unittest.main()
