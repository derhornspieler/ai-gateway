import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "compute-bind-source-digests.py"
SPEC = importlib.util.spec_from_file_location("compute_bind_source_digests", SCRIPT)
assert SPEC and SPEC.loader
digests = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(digests)


class BindSourceDigestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.key = b"a" * 64

    def test_atomic_replacement_changes_only_the_exact_consumer(self) -> None:
        (self.root / "a.conf").write_text("old-a", encoding="utf-8")
        (self.root / "b.conf").write_text("stable-b", encoding="utf-8")
        manifest = {"service-a": ["a.conf"], "service-b": ["b.conf"]}
        before = digests.compute_digests(self.root, manifest, self.key)

        replacement = self.root / "replacement"
        replacement.write_text("new-a", encoding="utf-8")
        os.replace(replacement, self.root / "a.conf")
        after = digests.compute_digests(self.root, manifest, self.key)

        self.assertNotEqual(before["service-a"], after["service-a"])
        self.assertEqual(before["service-b"], after["service-b"])

    def test_key_loss_intentionally_changes_every_marker(self) -> None:
        (self.root / "a.conf").write_text("a", encoding="utf-8")
        (self.root / "b.conf").write_text("b", encoding="utf-8")
        manifest = {"service-a": ["a.conf"], "service-b": ["b.conf"]}
        before = digests.compute_digests(self.root, manifest, self.key)
        after = digests.compute_digests(self.root, manifest, b"b" * 64)
        self.assertEqual(set(before), set(after))
        self.assertTrue(all(before[name] != after[name] for name in before))

    def test_security_metadata_and_directory_inventory_are_framed(self) -> None:
        directory = self.root / "tree"
        directory.mkdir()
        source = directory / "config.yml"
        source.write_text("same", encoding="utf-8")
        manifest = {"service": ["tree"]}
        before = digests.compute_digests(self.root, manifest, self.key)["service"]
        source.chmod(0o600)
        after_mode = digests.compute_digests(self.root, manifest, self.key)["service"]
        self.assertNotEqual(before, after_mode)
        (directory / "new.yml").write_text("new", encoding="utf-8")
        after_inventory = digests.compute_digests(self.root, manifest, self.key)["service"]
        self.assertNotEqual(after_mode, after_inventory)

    def test_symlinks_hardlinks_and_special_objects_fail_closed(self) -> None:
        regular = self.root / "regular"
        regular.write_text("x", encoding="utf-8")
        symlink = self.root / "symlink"
        symlink.symlink_to(regular)
        with self.assertRaisesRegex(digests.DigestError, "symlink"):
            digests.compute_digests(self.root, {"service": ["symlink"]}, self.key)

        outside = self.root / "outside"
        outside.mkdir()
        (outside / "config").write_text("x", encoding="utf-8")
        linked_directory = self.root / "linked-directory"
        linked_directory.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(digests.DigestError, "symlink component"):
            digests.compute_digests(
                self.root,
                {"service": ["linked-directory/config"]},
                self.key,
            )

        hardlink = self.root / "hardlink"
        os.link(regular, hardlink)
        with self.assertRaisesRegex(digests.DigestError, "hard-linked"):
            digests.compute_digests(self.root, {"service": ["regular"]}, self.key)

        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(digests.DigestError, "regular file/directory"):
            digests.compute_digests(self.root, {"service": ["fifo"]}, self.key)

    def test_duplicate_nested_and_oversized_inventories_fail_closed(self) -> None:
        directory = self.root / "tree"
        directory.mkdir()
        (directory / "config").write_text("x", encoding="utf-8")
        with self.assertRaisesRegex(digests.DigestError, "duplicate"):
            digests.compute_digests(
                self.root, {"service": ["tree", "tree"]}, self.key
            )
        with self.assertRaisesRegex(digests.DigestError, "nested"):
            digests.compute_digests(
                self.root, {"service": ["tree", "tree/config"]}, self.key
            )
        with mock.patch.object(digests, "MAX_OBJECTS_PER_SERVICE", 1):
            with self.assertRaisesRegex(digests.DigestError, "object cap"):
                digests.compute_digests(
                    self.root, {"service": ["tree"]}, self.key
                )
        with mock.patch.object(digests, "MAX_BYTES_PER_SERVICE", 0):
            with self.assertRaisesRegex(digests.DigestError, "byte cap"):
                digests.compute_digests(
                    self.root, {"service": ["tree/config"]}, self.key
                )

    def test_in_place_mutation_during_read_fails_closed(self) -> None:
        source = self.root / "config"
        source.write_bytes(b"content")
        real_read = os.read
        mutated = False

        def racing_read(descriptor: int, size: int) -> bytes:
            nonlocal mutated
            if not mutated:
                mutated = True
                source.chmod(0o600)
            return real_read(descriptor, size)

        with mock.patch.object(digests.os, "read", side_effect=racing_read):
            with self.assertRaisesRegex(digests.DigestError, "changed while hashing"):
                digests.compute_digests(
                    self.root, {"service": ["config"]}, self.key
                )

    def test_byte_cap_is_enforced_before_oversized_file_io(self) -> None:
        source = self.root / "config"
        source.write_bytes(b"oversized")
        with mock.patch.object(digests, "MAX_BYTES_PER_SERVICE", 1):
            with mock.patch.object(
                digests.os, "read", side_effect=AssertionError("must not read")
            ):
                with self.assertRaisesRegex(digests.DigestError, "byte cap"):
                    digests.compute_digests(
                        self.root, {"service": ["config"]}, self.key
                    )


if __name__ == "__main__":
    unittest.main()
