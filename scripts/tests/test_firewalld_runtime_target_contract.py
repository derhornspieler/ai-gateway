"""Regression coverage for Rocky 9's runtime firewalld target query."""

from __future__ import annotations

from pathlib import Path
import re
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
TASKS = ROOT / "ansible" / "roles" / "firewalld_zones" / "tasks" / "main.yml"


class FirewalldRuntimeTargetContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        source = TASKS.read_text(encoding="utf-8")
        start = source.index("        def canonical_zone_target(target):")
        end = source.index("\n        def words(value):", start)
        cls.target_reader = textwrap.dedent(source[start:end])

    def reader(self, calls: list[tuple[str, tuple[str, ...]]]):
        def invoke(scope: str, *arguments: str, allowed: tuple[int, ...] = (0,)):
            del allowed
            calls.append((scope, arguments))
            if arguments[-1] == "--list-all":
                return (
                    0,
                    "aigw-adm (active)\n"
                    "  target: %%REJECT%%\n"
                    "  interfaces: enp0s7\n"
                    "  rich rules: \n",
                )
            if arguments[-1] == "--get-target":
                return 0, "REJECT"
            raise AssertionError(arguments)

        namespace: dict[str, object] = {"re": re, "invoke": invoke}
        exec(self.target_reader, namespace)
        return namespace

    def test_runtime_uses_list_all_and_canonicalizes_rocky9_reject(self) -> None:
        calls: list[tuple[str, tuple[str, ...]]] = []
        reader = self.reader(calls)

        self.assertEqual(reader["zone_target"]("runtime", "aigw-adm"), "REJECT")
        self.assertEqual(calls, [("runtime", ("--zone=aigw-adm", "--list-all"))])

    def test_permanent_keeps_get_target_and_matches_runtime_canonical_form(self) -> None:
        calls: list[tuple[str, tuple[str, ...]]] = []
        reader = self.reader(calls)

        self.assertEqual(reader["zone_target"]("permanent", "aigw-adm"), "REJECT")
        self.assertEqual(calls, [("permanent", ("--zone=aigw-adm", "--get-target"))])

    def test_runtime_parser_fails_closed_on_malformed_or_unknown_target(self) -> None:
        reader = self.reader([])
        parse = reader["runtime_zone_target"]
        for output in (
            "aigw-egress\n  interfaces: enp0s5\n",
            "target: DROP\ntarget: REJECT\n",
            "target: DROP unexpected\n",
            "target: ACCEPT_ANYTHING\n",
        ):
            with self.subTest(output=output), self.assertRaises(RuntimeError):
                parse(output)


if __name__ == "__main__":
    unittest.main()
