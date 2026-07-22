from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = ROOT / "services/samba-ad-preprod/Dockerfile"


class SambaRuntimePackageTests(unittest.TestCase):
    def test_unused_vulnerable_cli_packages_are_removed_after_install(self) -> None:
        source = DOCKERFILE.read_text(encoding="utf-8")
        install = source.index("apt-get install")
        remove = source.index("dpkg --purge", install)
        cleanup = source.index("rm -rf /var/lib/apt/lists", remove)
        self.assertLess(install, remove)
        self.assertLess(remove, cleanup)
        for package in (
            "dirmngr",
            "gnupg",
            "gpg-agent",
            "gzip",
            "ncurses-bin",
            "perl-base",
        ):
            with self.subTest(package=package):
                self.assertIn(package, source[remove:cleanup])

    def test_build_rechecks_the_required_samba_runtime(self) -> None:
        source = DOCKERFILE.read_text(encoding="utf-8")
        for check in (
            "! command -v perl",
            "! command -v gzip",
            "! command -v infocmp",
            "! command -v gpg",
            'from samba.netcmd.main import samba_tool',
            "samba-tool --help",
            "samba --version",
            "openssl version",
        ):
            with self.subTest(check=check):
                self.assertIn(check, source)


if __name__ == "__main__":
    unittest.main()
