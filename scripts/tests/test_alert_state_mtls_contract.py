from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
HELPER = (
    ROOT
    / "ansible/roles/docker_stack/files/ensure-alert-state-mtls.py"
)


def load_helper():
    spec = importlib.util.spec_from_file_location("alert_state_mtls", HELPER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class AlertStateMTLSContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_helper()
        self.module.ROOT_UID = os.getuid()
        self.module.ROOT_GID = os.getgid()
        self.original_files = self.module.FILES
        uid = os.getuid()
        gid = os.getgid()
        self.module.FILES = {
            name: (location, filename, uid, gid, mode)
            for name, (location, filename, _uid, _gid, mode) in self.original_files.items()
        }
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.secrets = self.root / "secrets"
        self.state = self.root / "state"
        self.secrets.mkdir(mode=0o700)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def generate(self) -> dict[str, Path]:
        self.assertTrue(self.module.reconcile(self.secrets, self.state))
        self.assertFalse(self.module.reconcile(self.secrets, self.state))
        return self.module.material_paths(self.secrets, self.state)

    def sign_leaf(
        self,
        paths: dict[str, Path],
        *,
        key: Path,
        output: Path,
        common_name: str,
        usage: str,
        san: str | None,
        days: int = 825,
    ) -> None:
        work = self.root / f"sign-{common_name}"
        work.mkdir()
        csr = work / "leaf.csr"
        extension = work / "leaf.cnf"
        lines = [
            "basicConstraints=critical,CA:FALSE",
            "keyUsage=critical,digitalSignature,keyEncipherment",
            f"extendedKeyUsage={usage}",
        ]
        if san is not None:
            lines.append(f"subjectAltName=DNS:{san}")
        extension.write_text("\n".join(lines) + "\n", encoding="ascii")
        subprocess.run(
            [
                "openssl", "req", "-new", "-sha256", "-key", str(key),
                "-subj", f"/CN={common_name}", "-out", str(csr),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        candidate = work / "leaf.crt"
        subprocess.run(
            [
                "openssl", "x509", "-req", "-sha256", "-days", str(days),
                "-in", str(csr), "-CA", str(paths["ca_cert"]),
                "-CAkey", str(paths["ca_key"]), "-CAcreateserial",
                "-extfile", str(extension), "-out", str(candidate),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        shutil.copyfile(candidate, output)
        output.chmod(0o644)

    def test_fresh_material_is_complete_and_idempotent(self) -> None:
        paths = self.generate()
        self.assertEqual(set(paths), set(self.module.FILES))
        for name, path in paths.items():
            self.assertTrue(path.is_file(), name)

    def test_partial_material_fails_closed(self) -> None:
        (self.secrets / "alert_state_ca.pem").write_text("partial", encoding="ascii")
        with self.assertRaisesRegex(SystemExit, "material is incomplete"):
            self.module.reconcile(self.secrets, self.state)

    def test_symlink_hardlink_mode_and_owner_drift_fail_closed(self) -> None:
        paths = self.generate()

        original = paths["client_cert"].read_bytes()
        paths["client_cert"].unlink()
        paths["client_cert"].symlink_to(paths["server_cert"])
        with self.assertRaisesRegex(SystemExit, "unsafe alert-state mTLS file"):
            self.module.validate(paths)
        paths["client_cert"].unlink()
        paths["client_cert"].write_bytes(original)
        paths["client_cert"].chmod(0o644)

        extra_link = self.root / "extra-link"
        os.link(paths["server_cert"], extra_link)
        with self.assertRaisesRegex(SystemExit, "unsafe alert-state mTLS file"):
            self.module.validate(paths)
        extra_link.unlink()

        paths["server_key"].chmod(0o600)
        with self.assertRaisesRegex(SystemExit, "unsafe alert-state mTLS file"):
            self.module.validate(paths)
        paths["server_key"].chmod(0o440)

        location, filename, uid, gid, mode = self.module.FILES["server_cert"]
        self.module.FILES["server_cert"] = (
            location,
            filename,
            uid + 1,
            gid,
            mode,
        )
        with self.assertRaisesRegex(SystemExit, "unsafe alert-state mTLS file"):
            self.module.validate(paths)

    def test_ca_private_key_must_match_the_ca_certificate(self) -> None:
        paths = self.generate()
        subprocess.run(
            [
                "openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
                "rsa_keygen_bits:2048", "-out", str(paths["ca_key"]),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        paths["ca_key"].chmod(0o600)
        with self.assertRaisesRegex(SystemExit, "ca_key does not match ca_cert"):
            self.module.validate(paths)

    def test_server_san_and_client_eku_are_enforced(self) -> None:
        paths = self.generate()
        self.sign_leaf(
            paths,
            key=paths["server_key"],
            output=paths["server_cert"],
            common_name="wrong-server",
            usage="serverAuth",
            san="wrong-server",
        )
        with self.assertRaisesRegex(SystemExit, "SAN is not exactly"):
            self.module.validate(paths)

        shutil.rmtree(self.state)
        for path in self.secrets.iterdir():
            path.unlink()
        paths = self.generate()
        self.sign_leaf(
            paths,
            key=paths["client_key"],
            output=paths["client_cert"],
            common_name="prometheus-alert-state",
            usage="serverAuth",
            san="prometheus-alert-state",
        )
        with self.assertRaisesRegex(SystemExit, "OpenSSL rejected"):
            self.module.validate(paths)

    def test_expiring_certificate_fails_closed_without_replacement(self) -> None:
        paths = self.generate()
        original_key = paths["client_key"].read_bytes()
        self.sign_leaf(
            paths,
            key=paths["client_key"],
            output=paths["client_cert"],
            common_name="prometheus-alert-state",
            usage="clientAuth",
            san=None,
            days=1,
        )
        with self.assertRaisesRegex(SystemExit, "OpenSSL rejected"):
            self.module.reconcile(self.secrets, self.state)
        self.assertEqual(paths["client_key"].read_bytes(), original_key)


if __name__ == "__main__":
    unittest.main()
