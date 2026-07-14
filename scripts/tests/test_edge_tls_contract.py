"""Contract + functional coverage for the production edge TLS / PKI path.

Two halves:

* Exact-string pins prove the reviewed wiring stays in place across the
  contract JSON, os-prep.yml (site.yml host-prep phase), the preflight, the
  docker_stack cert block ordering,
  the verify gate, the compose model, and the three PKI scripts.
* Functional tests drive scripts/edge-tls.py against a real OpenSSL-built PKI
  (root -> intermediate -> leaf) and assert every accept/reject decision, that
  install is atomic and idempotent, and that no private-key bytes ever reach a
  stream.

The functional half needs a real OpenSSL 3 binary (the validator refuses
LibreSSL semantics). CI ships one at /usr/bin/openssl; macOS controllers have
it via Homebrew. Following the ansible-playbook precedent, the suite fails
loudly if none is found rather than silently skipping crypto coverage.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "ansible" / "generic-rocky9-contract.json"
GROUP_VARS = ROOT / "ansible" / "group_vars" / "all.yml"
OS_PREP = ROOT / "ansible" / "os-prep.yml"
PREFLIGHT = ROOT / "ansible" / "preflight-generic-rocky9.yml"
DOCKER_STACK = ROOT / "ansible" / "roles" / "docker_stack" / "tasks" / "main.yml"
VERIFY = ROOT / "ansible" / "roles" / "verify" / "tasks" / "main.yml"
ENV_J2 = ROOT / "ansible" / "roles" / "docker_stack" / "templates" / "env.j2"
COMPOSE = ROOT / "compose" / "docker-compose.yml"
DIGEST_INPUTS = ROOT / "compose" / "bind-source-digest-inputs.json"
BOOTSTRAP = ROOT / "scripts" / "bootstrap-generic-rocky9.py"
LAB_VARS = ROOT / "ansible" / "inventory" / "host_vars" / "lab-aigw01.yml"
EDGE_TLS = ROOT / "scripts" / "edge-tls.py"
VAULT_PKI = ROOT / "scripts" / "vault-pki-intermediate.sh"
SIGN_SCRIPT = ROOT / "scripts" / "sign-vault-intermediate.sh"
VAULT_BOOTSTRAP = ROOT / "scripts" / "vault-bootstrap.sh"


def find_openssl3() -> str | None:
    candidates = [
        os.environ.get("AIGW_TEST_OPENSSL"),
        "openssl",
        "/opt/homebrew/opt/openssl@3/bin/openssl",
        "/opt/homebrew/bin/openssl",
        "/usr/local/opt/openssl@3/bin/openssl",
        "/usr/bin/openssl",
    ]
    for candidate in candidates:
        if not candidate:
            continue
        resolved = shutil.which(candidate) or (candidate if Path(candidate).is_file() else None)
        if not resolved:
            continue
        try:
            version = subprocess.run(
                [resolved, "version"], capture_output=True, text=True, check=False
            ).stdout
        except OSError:
            continue
        if version.startswith("OpenSSL 3."):
            return resolved
    return None


class EdgeTlsContractTests(unittest.TestCase):
    def test_contract_and_inventory_expose_exactly_one_edge_tls_mode(self) -> None:
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertIn("aigw_edge_tls_mode", contract["required_nonsecret_keys"])
        self.assertEqual(contract["schema"], "aigw.generic-rocky9/v1")

        group_vars = GROUP_VARS.read_text(encoding="utf-8")
        self.assertIn(
            "aigw_edge_tls_mode: \"{{ 'lab' if deployment_profile == 'rocky9-lab' else '' }}\"",
            group_vars,
        )
        self.assertIn('cribl_otlp_ca_file: "/etc/ssl/certs/aigw-cribl-ca.pem"', group_vars)
        self.assertIn('cribl_otlp_ca_pem_file: ""', group_vars)
        self.assertIn("aigw_edge_tls_min_days_remaining: 30", group_vars)

        env_j2 = ENV_J2.read_text(encoding="utf-8")
        self.assertIn("AIGW_EDGE_TLS_MODE={{ aigw_edge_tls_mode }}", env_j2)
        self.assertIn(
            "AIGW_EDGE_TLS_MIN_DAYS_REMAINING={{ aigw_edge_tls_min_days_remaining }}", env_j2
        )
        # The private key is never rendered into .env.
        self.assertNotIn("aigw_edge_tls_private_key_file }}", env_j2)

        bootstrap = BOOTSTRAP.read_text(encoding="utf-8")
        for key in (
            "aigw_edge_tls_mode: \"\"",
            "aigw_edge_tls_leaf_cert_file: \"\"",
            "aigw_edge_tls_private_key_file: \"\"",
            "aigw_edge_tls_chain_file: \"\"",
            "aigw_edge_tls_min_days_remaining: 30",
            "cribl_otlp_ca_pem_file: \"\"",
        ):
            self.assertIn(key, bootstrap)

        # The committed lab opts into the real customer-CA path.
        self.assertIn("aigw_edge_tls_mode: vault-intermediate", LAB_VARS.read_text(encoding="utf-8"))

    def test_site_gate_is_fail_closed_and_lab_may_use_the_real_ca_path(self) -> None:
        site = OS_PREP.read_text(encoding="utf-8")
        self.assertIn("Preflight — require exactly one reviewed edge TLS mode", site)
        self.assertIn(
            "(deployment_profile == 'rocky9-lab' and\n"
            "             aigw_edge_tls_mode in ['lab', 'vault-intermediate']) or",
            site,
        )
        self.assertIn(
            "(deployment_profile != 'rocky9-lab' and\n"
            "             aigw_edge_tls_mode in ['customer-supplied', 'vault-intermediate'])",
            site,
        )
        self.assertIn("aigw_edge_tls_min_days_remaining | int >= 7", site)
        # Controller-side lstat of the customer files, before any role runs.
        self.assertIn("Preflight — inspect customer edge TLS inputs on the controller", site)
        self.assertIn("not (item.stat.islnk | default(false))", site)
        self.assertIn("item.stat.mode == '0600'", site)

    def test_preflight_reports_invalid_edge_tls(self) -> None:
        preflight = PREFLIGHT.read_text(encoding="utf-8")
        self.assertIn("aigw_generic_invalid_edge_tls", preflight)
        self.assertIn("'invalid_edge_tls': aigw_generic_invalid_edge_tls", preflight)
        self.assertIn("aigw_generic_invalid_edge_tls | length == 0", preflight)

    def test_docker_stack_orders_validation_before_mutation(self) -> None:
        source = DOCKER_STACK.read_text(encoding="utf-8")
        stage_key = source.index("Stage the customer edge private key without logging")
        install = source.index("Validate and atomically install the customer edge TLS material")
        placeholder = source.index("Self-signed placeholder cert so traefik/open-webui start")
        self.assertLess(stage_key, install)
        self.assertLess(install, placeholder)

        # The key copy is never logged.
        key_block = source[stage_key : stage_key + 400]
        self.assertIn("no_log: true", key_block)

        # Both placeholder tasks are gated on mode + marker absence.
        self.assertEqual(
            2,
            source.count(
                "aigw_edge_tls_mode in ['lab', 'vault-intermediate'] and\n"
                "    not (aigw_edge_tls_issued_marker.stat.exists | default(false))"
            ),
        )
        # The staging boundary is always removed.
        self.assertIn("Remove the edge TLS staging boundary", source)
        # The pre-start production gate rejects placeholders.
        self.assertIn("Prove installed production edge TLS material before starting the stack", source)
        gate = source.index("Prove installed production edge TLS material before starting the stack")
        self.assertIn("--reject-self-signed", source[gate : gate + 600])
        # The lost-material refusal exists.
        self.assertIn("Refuse to mask lost production edge material with a placeholder", source)
        # The manifest ships edge-tls.py + the ceremony, never the offline signer.
        self.assertIn("- edge-tls.py", source)
        self.assertIn("- vault-pki-intermediate.sh", source)
        self.assertNotIn("- sign-vault-intermediate.sh", source)

    def test_docker_stack_gates_edge_removal_to_lab_and_asserts_before_deletion(self) -> None:
        """Real-CA edge material is validated before any deletion (finding #1).

        The removal task used to run in ALL modes and BEFORE the marker assert
        and the customer-supplied install, so a domain change on a real-CA
        profile deleted the live cert/key/chain and left certs/ empty for
        Traefik's self-signed default to fill. The removal is now confined to
        lab mode (free regeneration); on the real-CA modes the material is
        never deleted — a vault-intermediate mismatch fails the assert first,
        and customer-supplied is overwritten atomically only after validation.
        """
        source = DOCKER_STACK.read_text(encoding="utf-8")
        marker = source.index("Inspect the vault-intermediate issuance marker")
        refuse = source.index(
            "Refuse to mask lost production edge material with a placeholder"
        )
        remove = source.index("Remove edge material that belongs to a different lab domain")
        # Marker inspection and the hard-fail SAN assert both precede the removal.
        self.assertLess(marker, refuse)
        self.assertLess(refuse, remove)
        # The removal only runs in lab mode; it never deletes real-CA material.
        removal_block = source[remove : source.index("- name:", remove + 1)]
        self.assertIn("aigw_edge_tls_mode == 'lab' and", removal_block)
        self.assertIn("state: absent", removal_block)

    def test_docker_stack_separates_the_cribl_export_ca(self) -> None:
        source = DOCKER_STACK.read_text(encoding="utf-8")
        self.assertIn(
            "cribl_otlp_ca_file == '/etc/ssl/certs/aigw-cribl-ca.pem'", source
        )
        self.assertIn("(cribl_otlp_ca_pem_file | length > 0)", source)
        self.assertIn("Install the external Cribl export CA bundle", source)
        self.assertIn("validate-ca-bundle", source)
        self.assertIn("certs/cribl-ca.pem", source)

    def test_compose_gives_alloy_only_the_dedicated_cribl_ca(self) -> None:
        compose = COMPOSE.read_text(encoding="utf-8")
        self.assertIn("./certs/cribl-ca.pem:/etc/ssl/certs/aigw-cribl-ca.pem:ro", compose)
        self.assertIn(
            "CRIBL_OTLP_CA_FILE: ${CRIBL_OTLP_CA_FILE:-/etc/ssl/certs/aigw-cribl-ca.pem}", compose
        )
        digest = json.loads(DIGEST_INPUTS.read_text(encoding="utf-8"))
        self.assertEqual(digest["base"]["alloy"], ["alloy/config.alloy", "certs/cribl-ca.pem"])

    def test_verify_rejects_placeholder_on_real_ca_profiles(self) -> None:
        verify = VERIFY.read_text(encoding="utf-8")
        self.assertIn(
            "Reject placeholder, self-signed, or expiring edge certificates on real-CA profiles",
            verify,
        )
        self.assertIn("--reject-self-signed", verify)
        self.assertIn('"certs/cribl-ca.pem": ("file", 0, 0, 0o644),', verify)
        self.assertIn("(vault_public_status.stdout | from_json).initialized | bool", verify)

    def test_vault_pki_intermediate_never_touches_root_or_private_keys(self) -> None:
        text = VAULT_PKI.read_text(encoding="utf-8")
        subprocess.run(["bash", "-n", str(VAULT_PKI)], check=True)
        for required in (
            "pki_int/intermediate/generate/internal",
            "pki_int/intermediate/set-signed",
            'allowed_domains="$DOMAIN" allow_subdomains=true allow_bare_domains=true',
            "AIGW_EDGE_TLS_MODE",
            "read -r VAULT_TOKEN",
            "PRIVATE KEY",
            "vault-pki-intermediate.sh requires aigw_edge_tls_mode=vault-intermediate",
        ):
            self.assertIn(required, text)
        self.assertNotIn("pki/root/generate", text)
        self.assertNotIn("pki/root/sign-intermediate", text)
        self.assertNotIn("--token", text)
        self.assertNotIn("--root-key", text)

    def test_the_customer_signed_issuer_is_promoted_not_merely_imported(self) -> None:
        # set-signed only IMPORTS an issuer. A mount previously bootstrapped with
        # the self-signed TEST root -- the brownfield case, an existing deployment
        # migrating onto the customer CA -- already holds issuers, and Vault's
        # default_follows_latest_issuer is false. Without an explicit promotion the
        # mount keeps signing leaves with the OLD test intermediate while the
        # customer-signed issuer sits unused, and every leaf chains to the test
        # root. Observed on the live lab before this was fixed.
        text = VAULT_PKI.read_text(encoding="utf-8")
        for required in (
            "imported_issuers",
            "pki_int/config/issuers",
            "default_follows_latest_issuer=false",
            # the role is pinned to the promoted issuer, so a later default change
            # cannot silently move issuance back onto a stale CA
            'issuer_ref="$imported"',
            # #18: the promotion proof reads the mount's DEFAULT issuer and asserts
            # IT resolves to the customer cert. Re-reading pki_int/issuer/$imported
            # was vacuous — set-signed already guarantees it — so it could not
            # catch a `default=` write that silently did not take.
            "vlt read -format=json pki_int/config/issuers",
            'get("default")',
            'pki_int/issuer/$default_issuer',
            "could not read the mount default issuer after promotion",
            # promotion is proven, not assumed
            "the promoted Vault issuer is not the customer-signed intermediate",
            # set-signed is idempotent: a re-run imports nothing, so the issuer is
            # resolved by certificate identity and the ceremony stays re-runnable
            "pki_int/issuers",
            "Vault holds no issuer matching --signed-intermediate",
        ):
            self.assertIn(required, text)
        # The vacuous re-read of the imported issuer as the promotion proof is
        # gone: the fingerprint compare now reads whatever the DEFAULT resolves to.
        self.assertNotIn(
            'promoted_fp="$(vlt read -field=certificate "pki_int/issuer/$imported"',
            text,
        )

    def test_sign_script_is_offline_only_and_pins_the_intermediate_extensions(self) -> None:
        text = SIGN_SCRIPT.read_text(encoding="utf-8")
        subprocess.run(["bash", "-n", str(SIGN_SCRIPT)], check=True)
        self.assertIn("basicConstraints = critical,CA:true,pathlen:0", text)
        self.assertIn("keyUsage = critical,digitalSignature,cRLSign,keyCertSign", text)
        self.assertIn("PRIVATE KEY", text)  # refuses key material in the CSR

    def test_vault_bootstrap_defers_edge_pki_in_vault_intermediate_mode(self) -> None:
        text = VAULT_BOOTSTRAP.read_text(encoding="utf-8")
        subprocess.run(["bash", "-n", str(VAULT_BOOTSTRAP)], check=True)
        self.assertIn('if [[ "$AIGW_EDGE_TLS_MODE" == "lab" ]]; then', text)
        # The test root is only minted in lab mode; it lives inside that branch.
        lab_branch = text.split('if [[ "$AIGW_EDGE_TLS_MODE" == "lab" ]]; then', 1)[1]
        self.assertIn("pki/root/generate/internal", lab_branch)


class EdgeTlsValidatorFunctionalTests(unittest.TestCase):
    openssl: str
    workspace: Path
    root_cert: Path
    intermediate: Path
    chain: Path
    leaf: Path
    leaf_key: Path
    domain = "example.internal"

    @classmethod
    def setUpClass(cls) -> None:
        cls.openssl = find_openssl3()  # type: ignore[assignment]
        # Fail loudly rather than skip: crypto coverage is a release gate.
        assert cls.openssl is not None, (
            "a real OpenSSL 3 binary is required for edge-tls functional tests; "
            "install one (brew install openssl@3) or set AIGW_TEST_OPENSSL"
        )
        cls._tmp = tempfile.TemporaryDirectory(prefix="edge-tls-fixture-")
        cls.workspace = Path(cls._tmp.name)
        cls._build_pki()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    @classmethod
    def _ossl(cls, *args: str, stdin: str | None = None) -> str:
        result = subprocess.run(
            [cls.openssl, *args], input=stdin, capture_output=True, text=True, check=False
        )
        if result.returncode != 0:
            raise AssertionError(f"openssl {' '.join(args)} failed: {result.stderr}")
        return result.stdout

    @classmethod
    def _build_pki(cls, days: int = 90) -> None:
        work = cls.workspace
        cls.root_cert = work / "root.pem"
        root_key = work / "root.key"
        cls.intermediate = work / "intermediate.pem"
        int_key = work / "intermediate.key"
        cls.chain = work / "chain.pem"
        cls.leaf = work / "leaf.pem"
        cls.leaf_key = work / "leaf.key"
        domain = cls.domain

        # Self-signed root.
        cls._ossl(
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
            "-subj", "/CN=Fixture Root CA",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout", str(root_key), "-out", str(cls.root_cert),
        )
        # Intermediate signed by the root.
        int_csr = work / "intermediate.csr"
        cls._ossl(
            "req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-subj", "/CN=Fixture Intermediate CA",
            "-keyout", str(int_key), "-out", str(int_csr),
        )
        int_ext = work / "intermediate.ext"
        int_ext.write_text(
            "basicConstraints=critical,CA:TRUE,pathlen:0\n"
            "keyUsage=critical,digitalSignature,cRLSign,keyCertSign\n",
            encoding="utf-8",
        )
        cls._ossl(
            "x509", "-req", "-in", str(int_csr), "-CA", str(cls.root_cert),
            "-CAkey", str(root_key), "-CAcreateserial", "-days", "1825",
            "-extfile", str(int_ext), "-out", str(cls.intermediate),
        )
        # Leaf issued by the intermediate.
        leaf_csr = work / "leaf.csr"
        cls._ossl(
            "req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-subj", f"/CN=*.{domain}",
            "-keyout", str(cls.leaf_key), "-out", str(leaf_csr),
        )
        os.chmod(cls.leaf_key, 0o600)
        leaf_ext = work / "leaf.ext"
        leaf_ext.write_text(
            f"subjectAltName=DNS:*.{domain},DNS:{domain}\n"
            "extendedKeyUsage=serverAuth\n"
            "basicConstraints=critical,CA:FALSE\n",
            encoding="utf-8",
        )
        cls._ossl(
            "x509", "-req", "-in", str(leaf_csr), "-CA", str(cls.intermediate),
            "-CAkey", str(int_key), "-CAcreateserial", "-days", str(days),
            "-extfile", str(leaf_ext), "-out", str(cls.leaf),
        )
        cls.chain.write_text(
            cls.intermediate.read_text(encoding="utf-8") + cls.root_cert.read_text(encoding="utf-8"),
            encoding="utf-8",
        )

    def run_edge_tls(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-I", str(EDGE_TLS), "--openssl", self.openssl, *args],
            capture_output=True,
            text=True,
            check=False,
        )

    def validate(self, **overrides: str) -> subprocess.CompletedProcess[str]:
        params = {
            "--leaf": str(self.leaf),
            "--key": str(self.leaf_key),
            "--chain": str(self.chain),
            "--domain": self.domain,
            "--min-days-remaining": "30",
            "--expect-key-mode": "0600",
        }
        params.update(overrides)
        argv: list[str] = ["validate"]
        for key, value in params.items():
            argv.extend([key, value])
        return self.run_edge_tls(*argv)

    def assert_no_key_bytes(self, result: subprocess.CompletedProcess[str]) -> None:
        for stream in (result.stdout, result.stderr):
            self.assertNotIn("BEGIN PRIVATE KEY", stream)
            self.assertNotIn("BEGIN RSA PRIVATE KEY", stream)
            self.assertNotIn("BEGIN EC PRIVATE KEY", stream)

    def mint_leaf(self, name: str, keygen: list[str]) -> tuple[Path, Path]:
        """Issue a *.domain leaf with a caller-chosen key type off the fixture
        intermediate, with a valid SAN/EKU/basic-constraints so the ONLY thing
        under test is the key-strength decision. Returns (cert, key)."""
        work = self.workspace
        csr = work / f"{name}.csr"
        key = work / f"{name}.key"
        cert = work / f"{name}.pem"
        self._ossl(
            "req", "-new", *keygen, "-nodes",
            "-subj", f"/CN=*.{self.domain}", "-keyout", str(key), "-out", str(csr),
        )
        os.chmod(key, 0o600)
        ext = work / f"{name}.ext"
        ext.write_text(
            f"subjectAltName=DNS:*.{self.domain},DNS:{self.domain}\n"
            "extendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\n",
            encoding="utf-8",
        )
        self._ossl(
            "x509", "-req", "-in", str(csr), "-CA", str(self.intermediate),
            "-CAkey", str(self.workspace / "intermediate.key"), "-CAcreateserial",
            "-days", "90", "-extfile", str(ext), "-out", str(cert),
        )
        return cert, key

    def test_valid_material_passes(self) -> None:
        result = self.validate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("edge-tls=valid", result.stdout)
        self.assert_no_key_bytes(result)

    def test_strong_p521_ec_leaf_passes(self) -> None:
        # A NIST P-521 leaf is a STRONGER key than P-256, not a weaker one. The
        # pre-fix strength rule compared its 521-bit field against the 2048-bit
        # RSA floor and refused a perfectly valid customer EC leaf (finding #10).
        # This asserts the false-negative is gone.
        cert, key = self.mint_leaf(
            "p521", ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:secp521r1"]
        )
        result = self.validate(**{"--leaf": str(cert), "--key": str(key)})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("edge-tls=valid", result.stdout)
        self.assert_no_key_bytes(result)

    def test_weak_rsa1024_leaf_still_rejected(self) -> None:
        # The EC fix must not weaken the genuine floor: a 1024-bit RSA leaf is
        # still refused by the key-strength check.
        cert, key = self.mint_leaf("rsa1024", ["-newkey", "rsa:1024"])
        result = self.validate(**{"--leaf": str(cert), "--key": str(key)})
        self.assertEqual(result.returncode, 1)
        self.assertIn("key-strength", result.stderr)
        self.assertIn("1024 bits", result.stderr)
        self.assert_no_key_bytes(result)

    def test_wrong_key_rejected(self) -> None:
        other_key = self.workspace / "other.key"
        self._ossl("genrsa", "-out", str(other_key), "2048")
        os.chmod(other_key, 0o600)
        result = self.validate(**{"--key": str(other_key)})
        self.assertEqual(result.returncode, 1)
        self.assertIn("key-match", result.stderr)
        self.assert_no_key_bytes(result)

    def test_missing_apex_san_rejected(self) -> None:
        work = self.workspace
        csr = work / "wildcard-only.csr"
        key = work / "wildcard-only.key"
        cert = work / "wildcard-only.pem"
        self._ossl(
            "req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-subj", f"/CN=*.{self.domain}", "-keyout", str(key), "-out", str(csr),
        )
        os.chmod(key, 0o600)
        ext = work / "wildcard-only.ext"
        ext.write_text(
            f"subjectAltName=DNS:*.{self.domain}\nextendedKeyUsage=serverAuth\n"
            "basicConstraints=critical,CA:FALSE\n",
            encoding="utf-8",
        )
        self._ossl(
            "x509", "-req", "-in", str(csr), "-CA", str(self.intermediate),
            "-CAkey", str(self.workspace / "intermediate.key"), "-CAcreateserial",
            "-days", "90", "-extfile", str(ext), "-out", str(cert),
        )
        result = self.validate(**{"--leaf": str(cert), "--key": str(key)})
        self.assertEqual(result.returncode, 1)
        self.assertIn("san", result.stderr)

    def test_missing_serverauth_rejected(self) -> None:
        work = self.workspace
        csr = work / "noeku.csr"
        key = work / "noeku.key"
        cert = work / "noeku.pem"
        self._ossl(
            "req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-subj", f"/CN=*.{self.domain}", "-keyout", str(key), "-out", str(csr),
        )
        os.chmod(key, 0o600)
        ext = work / "noeku.ext"
        ext.write_text(
            f"subjectAltName=DNS:*.{self.domain},DNS:{self.domain}\n"
            "extendedKeyUsage=clientAuth\nbasicConstraints=critical,CA:FALSE\n",
            encoding="utf-8",
        )
        self._ossl(
            "x509", "-req", "-in", str(csr), "-CA", str(self.intermediate),
            "-CAkey", str(self.workspace / "intermediate.key"), "-CAcreateserial",
            "-days", "90", "-extfile", str(ext), "-out", str(cert),
        )
        result = self.validate(**{"--leaf": str(cert), "--key": str(key)})
        self.assertEqual(result.returncode, 1)
        self.assertIn("eku", result.stderr)

    def test_leaf_as_ca_rejected(self) -> None:
        work = self.workspace
        csr = work / "leafca.csr"
        key = work / "leafca.key"
        cert = work / "leafca.pem"
        self._ossl(
            "req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-subj", f"/CN=*.{self.domain}", "-keyout", str(key), "-out", str(csr),
        )
        os.chmod(key, 0o600)
        ext = work / "leafca.ext"
        ext.write_text(
            f"subjectAltName=DNS:*.{self.domain},DNS:{self.domain}\n"
            "extendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:TRUE\n",
            encoding="utf-8",
        )
        self._ossl(
            "x509", "-req", "-in", str(csr), "-CA", str(self.intermediate),
            "-CAkey", str(self.workspace / "intermediate.key"), "-CAcreateserial",
            "-days", "90", "-extfile", str(ext), "-out", str(cert),
        )
        result = self.validate(**{"--leaf": str(cert), "--key": str(key)})
        self.assertEqual(result.returncode, 1)
        self.assertIn("leaf-basic-constraints", result.stderr)

    def test_chain_without_root_rejected(self) -> None:
        no_root = self.workspace / "no-root.pem"
        no_root.write_text(self.intermediate.read_text(encoding="utf-8"), encoding="utf-8")
        result = self.validate(**{"--chain": str(no_root)})
        self.assertEqual(result.returncode, 1)
        self.assertIn("ca-constraints", result.stderr)
        self.assertIn("self-signed root", result.stderr)

    def test_near_expiry_rejected(self) -> None:
        short = tempfile.TemporaryDirectory(prefix="edge-tls-short-")
        self.addCleanup(short.cleanup)
        # A leaf valid for 5 days fails a 30-day horizon.
        work = Path(short.name)
        csr = work / "short.csr"
        key = work / "short.key"
        cert = work / "short.pem"
        self._ossl(
            "req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-subj", f"/CN=*.{self.domain}", "-keyout", str(key), "-out", str(csr),
        )
        os.chmod(key, 0o600)
        ext = work / "short.ext"
        ext.write_text(
            f"subjectAltName=DNS:*.{self.domain},DNS:{self.domain}\n"
            "extendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\n",
            encoding="utf-8",
        )
        self._ossl(
            "x509", "-req", "-in", str(csr), "-CA", str(self.intermediate),
            "-CAkey", str(self.workspace / "intermediate.key"), "-CAcreateserial",
            "-days", "5", "-extfile", str(ext), "-out", str(cert),
        )
        result = self.validate(**{"--leaf": str(cert), "--key": str(key)})
        self.assertEqual(result.returncode, 1)
        self.assertIn("validity", result.stderr)

    def test_symlinked_key_rejected(self) -> None:
        link = self.workspace / "linked.key"
        if link.exists() or link.is_symlink():
            link.unlink()
        link.symlink_to(self.leaf_key)
        result = self.validate(**{"--key": str(link)})
        self.assertEqual(result.returncode, 1)
        self.assertIn("symlink", result.stderr)

    def test_world_readable_key_rejected(self) -> None:
        loose = self.workspace / "loose.key"
        loose.write_text(self.leaf_key.read_text(encoding="utf-8"), encoding="utf-8")
        os.chmod(loose, 0o644)
        result = self.validate(**{"--key": str(loose)})
        self.assertEqual(result.returncode, 1)
        self.assertIn("mode 0644", result.stderr)

    def test_private_key_in_cert_input_is_fatal(self) -> None:
        poisoned = self.workspace / "poisoned.pem"
        poisoned.write_text(
            self.chain.read_text(encoding="utf-8")
            + (self.workspace / "intermediate.key").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        result = self.validate(**{"--chain": str(poisoned)})
        self.assertEqual(result.returncode, 1)
        self.assertIn("the customer CA signing key must never be supplied", result.stderr)

    def test_install_is_atomic_and_idempotent_and_reject_self_signed(self) -> None:
        certs_dir = Path(tempfile.mkdtemp(prefix="edge-tls-install-"))
        self.addCleanup(shutil.rmtree, certs_dir, ignore_errors=True)
        common = [
            "install", "--leaf", str(self.leaf), "--key", str(self.leaf_key),
            "--chain", str(self.chain), "--certs-dir", str(certs_dir),
            "--domain", self.domain, "--min-days-remaining", "30",
            "--expect-key-mode", "0600",
        ]
        first = self.run_edge_tls(*common)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertIn("edge-tls=changed", first.stdout)
        self.assert_no_key_bytes(first)

        second = self.run_edge_tls(*common)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertIn("edge-tls=unchanged", second.stdout)

        # int.crt = leaf + chain; ca.pem = chain only.
        int_crt = (certs_dir / "int.crt").read_text(encoding="utf-8")
        self.assertIn("BEGIN CERTIFICATE", int_crt)
        self.assertEqual(
            (certs_dir / "int.key").read_text(encoding="utf-8"),
            self.leaf_key.read_text(encoding="utf-8"),
        )

        # install writes the key 0640 (the Traefik runtime group boundary), so the
        # installed material must satisfy validate-installed --reject-self-signed
        # at exactly that mode with no further reconciliation.
        self.assertEqual(stat.S_IMODE((certs_dir / "int.key").stat().st_mode), 0o640)
        self.assertEqual(stat.S_IMODE((certs_dir / "int.crt").stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE((certs_dir / "ca.pem").stat().st_mode), 0o644)
        owner = f"{os.getuid()}:{os.getgid()}"
        proof = self.run_edge_tls(
            "validate-installed", "--certs-dir", str(certs_dir), "--domain", self.domain,
            "--min-days-remaining", "30", "--reject-self-signed",
            "--expect-key-owner", owner, "--expect-key-mode", "0640",
        )
        self.assertEqual(proof.returncode, 0, proof.stderr)

    def test_self_signed_placeholder_rejected_by_validate_installed(self) -> None:
        certs_dir = Path(tempfile.mkdtemp(prefix="edge-tls-placeholder-"))
        self.addCleanup(shutil.rmtree, certs_dir, ignore_errors=True)
        # Reproduce the bootstrap placeholder: a self-signed cert that is its own
        # CA bundle.
        self._ossl(
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "7",
            "-subj", f"/CN=*.{self.domain}",
            "-addext", f"subjectAltName=DNS:*.{self.domain},DNS:{self.domain}",
            "-addext", "extendedKeyUsage=serverAuth",
            "-keyout", str(certs_dir / "int.key"), "-out", str(certs_dir / "int.crt"),
        )
        (certs_dir / "ca.pem").write_text(
            (certs_dir / "int.crt").read_text(encoding="utf-8"), encoding="utf-8"
        )
        os.chmod(certs_dir / "int.key", 0o640)
        os.chmod(certs_dir / "int.crt", 0o644)
        os.chmod(certs_dir / "ca.pem", 0o644)
        owner = f"{os.getuid()}:{os.getgid()}"
        result = self.run_edge_tls(
            "validate-installed", "--certs-dir", str(certs_dir), "--domain", self.domain,
            "--min-days-remaining", "30", "--reject-self-signed",
            "--expect-key-owner", owner, "--expect-key-mode", "0640",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("not-self-signed", result.stderr)
        self.assert_no_key_bytes(result)


if __name__ == "__main__":
    unittest.main()
