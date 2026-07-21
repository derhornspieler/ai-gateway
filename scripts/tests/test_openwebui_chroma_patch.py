from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
PATCHER_PATH = ROOT / "services/dhi-health-probe/patch_openwebui_chroma.py"
VERIFIER_PATH = ROOT / "services/dhi-health-probe/verify_openwebui_chroma.py"
FIXTURE_PATH = ROOT / "services/dhi-health-probe/chroma-v0.10.2.sha256-fixture"
DOCKERFILE_PATH = ROOT / "services/dhi-health-probe/Dockerfile.open-webui"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {path.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


patcher = load(PATCHER_PATH, "aigw_openwebui_chroma_patcher")
verifier = load(VERIFIER_PATH, "aigw_openwebui_chroma_verifier")


class OpenWebUiChromaPatchTests(unittest.TestCase):
    @staticmethod
    def synthetic_source() -> bytes:
        return (
            b"import chromadb\nfrom chromadb import Settings\n"
            + patcher.REMOTE_CONFIG_IMPORTS
            + b"class ChromaClient:\n    def __init__(self):\n"
            + patcher.OPTIONAL_REMOTE_CLIENT
            + b"    def insert(self, collection_name, embeddings):\n"
            + b"        collection = self.client.get_or_create_collection(name=collection_name, metadata={'hnsw:space': 'cosine'})\n"
            + b"        collection.add(embeddings=embeddings)\n"
            + b"    def upsert(self, collection_name, embeddings):\n"
            + b"        collection = self.client.get_or_create_collection(name=collection_name, metadata={'hnsw:space': 'cosine'})\n"
            + b"        collection.upsert(embeddings=embeddings)\n"
            + b"    def search(self, vectors):\n"
            + b"        return self.client.query(query_embeddings=vectors)\n"
        )

    def transform_synthetic(self, source: bytes) -> bytes:
        patched = source.replace(
            patcher.REMOTE_CONFIG_IMPORTS, patcher.LOCAL_CONFIG_IMPORTS, 1
        ).replace(patcher.OPTIONAL_REMOTE_CLIENT, patcher.LOCAL_CLIENT_ONLY, 1)
        with (
            mock.patch.object(
                patcher,
                "EXPECTED_SOURCE_SHA256",
                hashlib.sha256(source).hexdigest(),
            ),
            mock.patch.object(
                patcher,
                "EXPECTED_PATCHED_SHA256",
                hashlib.sha256(patched).hexdigest(),
            ),
        ):
            return patcher.transform(source)

    def test_exact_upstream_and_output_digests_are_pinned(self) -> None:
        self.assertEqual(
            FIXTURE_PATH.read_text(encoding="ascii").strip(),
            patcher.EXPECTED_SOURCE_SHA256,
        )
        self.assertEqual(len(patcher.EXPECTED_PATCHED_SHA256), 64)

    def test_transform_removes_every_remote_client_input(self) -> None:
        patched = self.transform_synthetic(self.synthetic_source())
        for forbidden in (
            b"HttpClient",
            b"CHROMA_HTTP_",
            b"CHROMA_CLIENT_AUTH_",
            b"chroma_client_auth_",
        ):
            self.assertNotIn(forbidden, patched)
        self.assertEqual(patched.count(b"chromadb.PersistentClient("), 1)
        self.assertEqual(patched.count(b"metadata={'hnsw:space': 'cosine'}"), 2)

    def test_verifier_accepts_only_fixed_collection_policy(self) -> None:
        patched = self.transform_synthetic(self.synthetic_source())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "chroma.py"
            path.write_bytes(patched)
            verifier.verify(path)
            path.write_bytes(
                patched.replace(b"'cosine'", b"user_configuration", 1)
            )
            with self.assertRaises((AssertionError, SyntaxError)):
                verifier.verify(path)

    def test_source_digest_or_client_snippet_drift_fails_closed(self) -> None:
        source = self.synthetic_source()
        for drifted in (
            source + b"# drift\n",
            source.replace(b"HttpClient", b"RemoteClient", 1),
            source.replace(b"CHROMA_HTTP_HOST", b"CHROMA_REMOTE_HOST", 1),
        ):
            with self.subTest(digest=hashlib.sha256(drifted).hexdigest()):
                with self.assertRaises(ValueError):
                    patcher.transform(drifted)

    def test_build_runs_exact_patcher_and_verifier_offline(self) -> None:
        dockerfile = DOCKERFILE_PATH.read_text(encoding="utf-8")
        self.assertIn("source=patch_openwebui_chroma.py", dockerfile)
        self.assertIn("source=verify_openwebui_chroma.py", dockerfile)
        self.assertIn("python3 -I /tmp/patch_openwebui_chroma.py", dockerfile)
        self.assertIn("python3 -I /tmp/verify_openwebui_chroma.py", dockerfile)
        self.assertNotIn("apt-get update", dockerfile)


if __name__ == "__main__":
    unittest.main()
