"""Contracts for the local preprod directory's root-CA-backed LDAPS path."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
PREPROD_OVERLAY = ROOT / "compose" / "docker-compose.preprod.yml"
PREPROD_SCRIPT = ROOT / "scripts" / "preprod.py"
ENTRYPOINT = ROOT / "services" / "samba-ad-preprod" / "samba-ad-entrypoint"
HEALTHCHECK = ROOT / "services" / "samba-ad-preprod" / "samba-ad-healthcheck"
ROTATOR_IDENTITY = ROOT / "services" / "key-rotator" / "app" / "identity.py"


class PreprodLdapsTopologyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.overlay = PREPROD_OVERLAY.read_text(encoding="utf-8")

    def test_directory_is_addressed_by_the_certificate_fqdn(self) -> None:
        self.assertIn(
            'IDENTITY_LDAP_URL: "ldaps://samba-ad.${DOMAIN}:636"',
            self.overlay,
        )
        self.assertIn('SAMBA_LDAPS_FQDN: "samba-ad.${DOMAIN}"', self.overlay)
        self.assertIn('aliases: ["samba-ad.${DOMAIN}"]', self.overlay)
        self.assertNotIn("ldap://samba-ad", self.overlay)
        self.assertNotIn("ldaps://samba-ad:636", self.overlay)

    def test_keycloak_uses_only_the_generated_root_and_strict_hostname_checks(self) -> None:
        keycloak = self.overlay.split("\n  keycloak:", 1)[1].split(
            "\n  dev-portal:", 1
        )[0]
        self.assertIn(
            "KC_TRUSTSTORE_PATHS: /etc/aigw/preprod-root-ca.pem", keycloak
        )
        self.assertIn("KC_TLS_HOSTNAME_VERIFIER: DEFAULT", keycloak)
        self.assertIn(
            "./secrets/preprod-root-ca.pem:/etc/aigw/preprod-root-ca.pem:ro",
            keycloak,
        )
        self.assertNotIn("KC_TLS_HOSTNAME_VERIFIER: ANY", keycloak)
        self.assertNotIn("/var/lib/samba-public/ca.pem,", keycloak)

    def test_keycloak_waits_for_the_healthy_directory(self) -> None:
        keycloak = self.overlay.split("\n  keycloak:", 1)[1].split(
            "\n  dev-portal:", 1
        )[0]
        self.assertIn(
            "samba-ad: { condition: service_healthy, required: true }", keycloak
        )

    def test_ldap_provider_consults_the_keycloak_truststore(self) -> None:
        identity = ROTATOR_IDENTITY.read_text(encoding="utf-8")
        self.assertIn('"useTruststoreSpi": ["always"]', identity)
        self.assertIn('"useTruststoreSpi": "always"', identity)


class PreprodCertificateGenerationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.script = PREPROD_SCRIPT.read_text(encoding="utf-8")

    def test_prepare_generates_a_persistent_test_root_and_samba_leaf(self) -> None:
        self.assertIn('"root_key": SECRETS_DIR / "preprod-root-ca.key"', self.script)
        self.assertIn('"root_cert": SECRETS_DIR / "preprod-root-ca.pem"', self.script)
        self.assertIn("basicConstraints=critical,CA:TRUE,pathlen:1", self.script)
        self.assertIn(
            'paths, "samba_key", "samba_cert", f"samba-ad.{domain}", '
            '[f"samba-ad.{domain}"]',
            self.script,
        )
        self.assertIn(
            '"openssl", "verify", "-CAfile", str(paths["root_cert"])',
            self.script,
        )
        self.assertIn('marker = "X509v3 Subject Alternative Name:"', self.script)
        self.assertIn("if actual_sans != expected_sans:", self.script)

    def test_partial_ca_or_leaf_state_fails_closed(self) -> None:
        self.assertIn(
            'fail("the persistent preprod root CA is incomplete; restore its missing file")',
            self.script,
        )
        self.assertIn(
            'fail(f"the preprod certificate for {common_name} is incomplete")',
            self.script,
        )

    def test_private_keys_and_public_certificates_have_bounded_modes(self) -> None:
        self.assertIn('paths["root_key"].chmod(0o600)', self.script)
        self.assertIn('paths["root_cert"].chmod(0o644)', self.script)
        self.assertIn("key_mode: int = 0o600", self.script)
        self.assertIn("key_path.chmod(key_mode)", self.script)
        self.assertEqual(self.script.count("key_mode=0o644"), 2)
        self.assertIn("ensure_private_directory(SECRETS_DIR)", self.script)
        self.assertIn("cert_path.chmod(0o644)", self.script)


class SambaCertificateAdoptionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.entrypoint = ENTRYPOINT.read_text(encoding="utf-8")
        self.healthcheck = HEALTHCHECK.read_text(encoding="utf-8")

    def test_delivered_leaf_requires_a_valid_matching_key_and_hostname(self) -> None:
        for requirement in (
            'SAMBA_TLS_CERT_FILE',
            'SAMBA_TLS_KEY_FILE',
            'SAMBA_TLS_CA_FILE',
            'openssl x509 -in "$tls_cert_src" -noout',
            'openssl pkey -in "$tls_key_src" -noout',
            '-noout -pubkey',
            '-pubout',
            'openssl verify -CAfile "$tls_ca_src" -verify_hostname "$ldaps_fqdn"',
        ):
            self.assertIn(requirement, self.entrypoint)

    def test_missing_or_invalid_material_has_no_self_signed_fallback(self) -> None:
        self.assertIn("required LDAPS file is missing or empty", self.entrypoint)
        self.assertIn("no self-signed fallback", self.entrypoint)
        self.assertNotIn("openssl req -x509", self.entrypoint)
        self.assertNotIn("samba-public", self.entrypoint)

    def test_ca_key_permissions_match_sambas_strict_requirement(self) -> None:
        self.assertIn('install -m 0600 "$tls_key_src" "$TLS_DIR/key.pem"', self.entrypoint)
        self.assertIn('install -m 0644 "$tls_cert_src" "$TLS_DIR/cert.pem"', self.entrypoint)
        self.assertIn('install -m 0644 "$tls_ca_src" "$TLS_DIR/ca.pem"', self.entrypoint)

    def test_healthcheck_verifies_the_exact_hostname_and_real_chain(self) -> None:
        self.assertIn('fqdn=${SAMBA_LDAPS_FQDN:-', self.healthcheck)
        self.assertIn('-verify_hostname "$fqdn"', self.healthcheck)
        self.assertIn("-verify_return_error", self.healthcheck)
        self.assertIn(
            'verify_cafile=${SAMBA_TLS_CA_FILE:-/run/secrets/preprod_root_ca}',
            self.healthcheck,
        )
        self.assertIn('-CAfile "$verify_cafile"', self.healthcheck)


if __name__ == "__main__":
    unittest.main()
