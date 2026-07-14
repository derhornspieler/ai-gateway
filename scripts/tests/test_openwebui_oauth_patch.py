from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
PATCHER_PATH = ROOT / "services/dhi-health-probe/patch_openwebui_oauth.py"
FIXTURE_PATH = ROOT / "services/dhi-health-probe/oauth-v0.10.2.sha256-fixture"
DOCKERFILE_PATH = ROOT / "services/dhi-health-probe/Dockerfile.open-webui"
SPEC = importlib.util.spec_from_file_location("aigw_openwebui_oauth_patcher", PATCHER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the Open WebUI OAuth patcher")
patcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(patcher)


class OpenWebUiOauthPatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture_digest = FIXTURE_PATH.read_text(encoding="ascii").strip()

    @staticmethod
    def synthetic_source() -> bytes:
        return (
            b"async def get_user_role():\n"
            + patcher.FIRST_USER_ROLE_BYPASS
            + b"        if auth_config.ENABLE_OAUTH_ROLE_MANAGEMENT:\n"
            + patcher.ROLE_GATE_ANCHOR
            + b"                for admin_role in oauth_admin_roles:\n"
            + b"                    if admin_role in oauth_roles:\n"
            + b"                        role = 'admin'\n"
            + patcher.POST_INSERT_ADMIN_PROMOTION
        )

    def transform_synthetic(self, source: bytes) -> bytes:
        patched = source.replace(patcher.FIRST_USER_ROLE_BYPASS, b"", 1).replace(
            patcher.POST_INSERT_ADMIN_PROMOTION, b"", 1
        )
        patched = patched.replace(
            patcher.ROLE_GATE_ANCHOR, patcher.ROLE_GATE_REPLACEMENT, 1
        )
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

    def test_exact_pinned_upstream_digest_is_documented(self) -> None:
        self.assertEqual(self.fixture_digest, patcher.EXPECTED_SOURCE_SHA256)
        self.assertEqual(len(patcher.EXPECTED_SOURCE_SHA256), 64)
        self.assertEqual(len(patcher.EXPECTED_PATCHED_SHA256), 64)

    def test_both_first_user_promotion_paths_are_removed(self) -> None:
        patched = self.transform_synthetic(self.synthetic_source())
        self.assertNotIn(b"Assigning the only user the admin role", patched)
        self.assertNotIn(b"get_num_users(db=db) == 1", patched)
        self.assertNotIn(b"return 'admin'", patched)

    def test_admin_role_mapping_remains_claim_gated(self) -> None:
        patched = self.transform_synthetic(self.synthetic_source())
        self.assertIn(b"if not oauth_roles:", patched)
        self.assertIn(b"status.HTTP_403_FORBIDDEN", patched)
        self.assertIn(b"for admin_role in oauth_admin_roles:", patched)
        self.assertIn(b"if admin_role in oauth_roles:", patched)
        self.assertIn(b"role = 'admin'", patched)
        self.assertNotIn(b"get_num_users", patched)

    def test_first_non_admin_has_no_count_based_admin_path(self) -> None:
        patched = self.transform_synthetic(self.synthetic_source())
        self.assertIn(b"ENABLE_OAUTH_ROLE_MANAGEMENT", patched)
        self.assertNotIn(b"user_count", patched)
        self.assertNotIn(b"update_user_role_by_id", patched)

    def test_source_or_snippet_drift_fails_closed(self) -> None:
        source = self.synthetic_source()
        for drifted in (
            source + b"# upstream drift\n",
            source.replace(b"only user", b"sole user", 1),
            source.replace(b"post-insert", b"after-insert", 1),
            source.replace(b"If roles are present", b"When roles are present", 1),
        ):
            with self.subTest(digest=hashlib.sha256(drifted).hexdigest()):
                with self.assertRaises(ValueError):
                    patcher.transform(drifted)

    def test_file_boundary_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "oauth.py"
            target.write_bytes(self.synthetic_source())
            link = Path(directory) / "oauth-link.py"
            link.symlink_to(target)
            with self.assertRaises(ValueError):
                patcher.patch_file(link)

    def test_build_runs_the_behavioral_verifier(self) -> None:
        dockerfile = DOCKERFILE_PATH.read_text(encoding="utf-8")
        self.assertIn("--network=none", dockerfile)
        self.assertIn("source=verify_openwebui_oauth.py", dockerfile)
        self.assertIn("python3 -I /tmp/verify_openwebui_oauth.py", dockerfile)

    def test_derivative_drops_to_a_nonroot_runtime_identity(self) -> None:
        dockerfile = DOCKERFILE_PATH.read_text(encoding="utf-8")
        self.assertIn("chown -R 65532:65532 /app/backend/data", dockerfile)
        self.assertIn("chmod 0700 /app/backend/data", dockerfile)
        self.assertTrue(dockerfile.rstrip().endswith("USER 65532:65532"))


if __name__ == "__main__":
    unittest.main()
