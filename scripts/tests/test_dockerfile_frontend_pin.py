from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
EXPECTED_FRONTEND = (
    "# syntax=docker/dockerfile:1.25.0@sha256:"
    "0adf442eae370b6087e08edc7c50b552d80ddf261576f4ebd6421006b2461f12"
)
EXPECTED_DOCKERFILES = {
    Path("services/dev-portal/Dockerfile"),
    Path("services/dhi-health-probe/Dockerfile"),
    Path("services/dhi-health-probe/Dockerfile.grafana"),
    Path("services/dhi-health-probe/Dockerfile.open-webui"),
    Path("services/egress-proxy/Dockerfile"),
    Path("services/key-rotator/Dockerfile"),
    Path("services/platform-dns/Dockerfile"),
    Path("services/vault-ui-proxy/Dockerfile"),
    Path("services/wif-provider-mock/Dockerfile"),
}


class DockerfileFrontendPinTests(unittest.TestCase):
    def test_every_declared_service_frontend_is_immutable(self) -> None:
        dockerfiles = sorted((ROOT / "services").glob("**/Dockerfile*"))
        self.assertGreater(len(dockerfiles), 0)
        found: set[Path] = set()
        for dockerfile in dockerfiles:
            with self.subTest(dockerfile=dockerfile.relative_to(ROOT)):
                self.assertTrue(dockerfile.is_file())
                first_line = dockerfile.read_text(encoding="utf-8").splitlines()[0]
                if first_line.startswith("# syntax="):
                    found.add(dockerfile.relative_to(ROOT))
                    self.assertEqual(first_line, EXPECTED_FRONTEND)
        self.assertEqual(found, EXPECTED_DOCKERFILES)


if __name__ == "__main__":
    unittest.main()
