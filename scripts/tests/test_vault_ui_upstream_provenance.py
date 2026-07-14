from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SERVICE = ROOT / "services/vault-ui-proxy"
PROVENANCE_PATH = SERVICE / "upstream-provenance.json"
PROVENANCE_BYTES = PROVENANCE_PATH.read_bytes()
PROVENANCE = json.loads(PROVENANCE_BYTES)
DOCKERFILE = (SERVICE / "Dockerfile").read_text(encoding="utf-8")


class VaultUIUpstreamProvenanceTests(unittest.TestCase):
    def test_signed_release_and_source_image_are_immutably_identified(self) -> None:
        self.assertEqual(PROVENANCE["schema"], 1)
        self.assertEqual(PROVENANCE["vault_version"], "2.0.3")
        self.assertEqual(
            PROVENANCE["signed_checksums"]["signer_primary_fingerprint"],
            "C874011F0AB405110D02105534365D9472D7468F",
        )
        self.assertEqual(
            PROVENANCE["signed_checksums"]["signing_subkey_fingerprint"],
            "374EC75B485913604A831CC7C820C6D5CD27AB87",
        )
        source = PROVENANCE["source_image"]
        self.assertEqual(
            source["reference"],
            "hashicorp/vault:2.0.3@sha256:"
            "a296a888b118615dc01d5f1a6846e6d4a7277946caaed5b447008fff5fe06b54",
        )
        self.assertEqual(
            set(source["platform_manifests"]), {"linux/amd64", "linux/arm64"}
        )
        self.assertIn(f"FROM {source['reference']} AS upstream-vault-ui", DOCKERFILE)

    def test_both_supported_source_binaries_match_signed_archives(self) -> None:
        expected = {
            "linux/amd64": {
                "archive_sha256": "1e0ffb7a82491219c7242da6e05e2d756b05d1097c29799a42228661f229bc2a",
                "binary_sha256": "7e8731db316124619ff2e64aee6957df6d54b824dfdc3494466193cb7bde0ac4",
                "binary_size": 536903029,
            },
            "linux/arm64": {
                "archive_sha256": "9423a715aea0689f9e498fe7cc5ea692aa1eff282f8b9bc26af28cad69d6d841",
                "binary_sha256": "8495a9215c20030c0f054699d52f6c1cf09dd3a663068bce57939adc193f564b",
                "binary_size": 507703909,
            },
        }
        self.assertEqual(set(PROVENANCE["platforms"]), set(expected))
        for platform, locked in expected.items():
            with self.subTest(platform=platform):
                record = PROVENANCE["platforms"][platform]
                self.assertTrue(
                    record["source_image_binary_byte_matches_signed_archive"]
                )
                for field, value in locked.items():
                    self.assertEqual(record[field], value)
                self.assertIn(record["binary_sha256"], DOCKERFILE)

    def test_ui_extraction_and_provenance_file_are_build_gates(self) -> None:
        ui = PROVENANCE["embedded_ui"]
        self.assertEqual(
            ui,
            {
                "entries": 132,
                "directories": 27,
                "files": 105,
                "bytes": 20549720,
                "compiler_hashes_verified": 105,
                "sorted_manifest_sha256": "7902aff69dccdea5096e05b7b6bdcfa218113ae6314f7574f955e417e9c34198",
            },
        )
        self.assertIn(ui["sorted_manifest_sha256"], DOCKERFILE)
        provenance_sha256 = hashlib.sha256(PROVENANCE_BYTES).hexdigest()
        self.assertIn(
            f"{provenance_sha256}  upstream-provenance.json", DOCKERFILE
        )
        self.assertIn(
            "/licenses/vault/UPSTREAM-PROVENANCE.json", DOCKERFILE
        )

    def test_runtime_stage_remains_dhi_only(self) -> None:
        stages = [
            line
            for line in DOCKERFILE.splitlines()
            if line.startswith("FROM ")
        ]
        self.assertEqual(len(stages), 3)
        self.assertTrue(
            stages[-1].startswith(
                "FROM dhi.io/vault:2.0.3@sha256:"
                "743791e1bf99025aae045b3155fecf0542e7fd1bde7bbfbaf76eb4b9ff2555a6"
            )
        )


if __name__ == "__main__":
    unittest.main()
