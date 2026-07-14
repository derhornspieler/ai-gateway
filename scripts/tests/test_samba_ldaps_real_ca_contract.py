"""Contract coverage for lab Samba AD LDAPS served by the REAL customer CA.

Before this change the lab DC self-signed its LDAPS certificate and Keycloak
trusted that exact self-signed cert — a shortcut that never exercised the
production trust path. The claims pinned here are the ones that make the lab
exercise the SAME path production uses:

* the LDAPS endpoint is addressed by an FQDN under the lab domain — never the
  bare `samba-ad` container name — because the customer (Aegis) root CA carries
  CRITICAL name constraints that make a bare-hostname SAN unusable (proven here
  with openssl: error 47, permitted subtree violation);
* Keycloak trusts the REAL Aegis chain (certs/ca.pem) for LDAPS, mounted with
  the shared lowercase `:ro,z` relabel it must share with its certs/ peers, and
  keeps LDAPS hostname verification strict and meaningful;
* the DC serves a Vault-issued leaf when present and self-signs only as a
  first-converge bootstrap fallback, without deadlocking the bootstrap;
* the Keycloak LDAP federation provider sets useTruststoreSpi=always, so
  KC_TRUSTSTORE_PATHS is actually consulted for LDAPS;
* the bind-digest / SELinux boundary stays coherent across all five places.
"""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
LAB_OVERLAY = ROOT / "compose" / "docker-compose.lab.yml"
ENTRYPOINT = ROOT / "services" / "samba-ad-lab" / "samba-ad-entrypoint"
HEALTHCHECK = ROOT / "services" / "samba-ad-lab" / "samba-ad-healthcheck"
DIGEST_INPUTS = ROOT / "compose" / "bind-source-digest-inputs.json"
PKI_CEREMONY = ROOT / "scripts" / "vault-pki-intermediate.sh"
STACK_TASKS = ROOT / "ansible" / "roles" / "docker_stack" / "tasks" / "main.yml"
ROTATOR_IDENTITY = ROOT / "services" / "key-rotator" / "app" / "identity.py"
ROTATOR_CONFIG = ROOT / "services" / "key-rotator" / "app" / "config.py"
VALIDATE = ROOT / "scripts" / "validate-compose.sh"


class LabLdapsFqdnUrlTests(unittest.TestCase):
    """The endpoint must be an FQDN under the lab domain, not the bare host."""

    def setUp(self) -> None:
        self.lab = LAB_OVERLAY.read_text(encoding="utf-8")

    def test_the_key_rotator_ldap_url_is_the_fqdn(self) -> None:
        self.assertIn(
            "LAB_SAMBA_LDAP_URL: ldaps://samba-ad.${DOMAIN:?DOMAIN must be set}:636",
            self.lab,
        )
        # The bare-host URL is gone: hostname verification against `samba-ad`
        # could never be satisfied by a customer-CA-signed certificate.
        self.assertNotIn("ldaps://samba-ad:636", self.lab)
        # No plaintext ldap:// anywhere in the overlay.
        self.assertNotIn("ldap://samba-ad", self.lab)

    def test_the_key_rotator_default_url_is_also_the_fqdn(self) -> None:
        config = ROTATOR_CONFIG.read_text(encoding="utf-8")
        self.assertIn(
            'default="ldaps://samba-ad.aigw.aegisgroup.ch:636", alias="LAB_SAMBA_LDAP_URL"',
            config,
        )

    def test_the_fqdn_resolves_via_a_docker_network_alias(self) -> None:
        samba_block = self.lab.split("  samba-ad:", 1)[1].split("\n  keycloak:", 1)[0]
        # The short name keeps working (Docker registers the service name); this
        # only ADDS the FQDN alias the CA-signed cert bears.
        self.assertIn("aliases:", samba_block)
        self.assertIn("- samba-ad.${DOMAIN:?DOMAIN must be set}", samba_block)

    def test_the_dc_knows_the_ldaps_fqdn_for_its_certificate(self) -> None:
        self.assertIn(
            "SAMBA_LDAPS_FQDN: samba-ad.${DOMAIN:?DOMAIN must be set}", self.lab
        )


class KeycloakRealCaTrustTests(unittest.TestCase):
    """Keycloak must trust the real Aegis chain, with the shared certs relabel."""

    def setUp(self) -> None:
        self.lab = LAB_OVERLAY.read_text(encoding="utf-8")
        self.keycloak = self.lab.split("\n  keycloak:", 1)[1].split(
            "\n  key-rotator:", 1
        )[0]

    def test_the_truststore_points_at_the_real_chain(self) -> None:
        # The real customer CA chain leads; the self-signed DC cert stays only as
        # a comma-separated bootstrap-window anchor.
        self.assertIn(
            "KC_TRUSTSTORE_PATHS: /etc/aigw/aegis-ca.pem,/var/lib/samba-public/ca.pem",
            self.keycloak,
        )

    def test_the_certs_mount_uses_the_shared_lowercase_relabel(self) -> None:
        # certs/ is SHARED with traefik-int/traefik-adm/open-webui/alloy; a
        # private `:ro,Z` would steal the SELinux label from those peers, so the
        # shared lowercase category `:ro,z` is mandatory here.
        self.assertIn("./certs/ca.pem:/etc/aigw/aegis-ca.pem:ro,z", self.keycloak)
        self.assertNotIn("./certs/ca.pem:/etc/aigw/aegis-ca.pem:ro,Z", self.keycloak)

    def test_hostname_verification_stays_strict(self) -> None:
        self.assertIn("KC_TLS_HOSTNAME_VERIFIER: DEFAULT", self.keycloak)
        self.assertNotIn("KC_TLS_HOSTNAME_VERIFIER: ANY", self.keycloak)

    def test_the_self_signed_public_volume_is_still_mounted_for_bootstrap(
        self,
    ) -> None:
        self.assertIn("samba_ad_public:/var/lib/samba-public:ro", self.keycloak)


class LabProviderUsesTruststoreSpiTests(unittest.TestCase):
    """Without useTruststoreSpi=always Keycloak ignores KC_TRUSTSTORE_PATHS for LDAP."""

    def test_the_federation_provider_always_uses_the_keycloak_truststore(self) -> None:
        identity = ROTATOR_IDENTITY.read_text(encoding="utf-8")
        # Both the create path and the drift-verification expectation pin it.
        self.assertIn('"useTruststoreSpi": ["always"]', identity)
        self.assertIn('"useTruststoreSpi": "always"', identity)
        # The lab and production providers share this single spec-driven builder,
        # so the lab provider inherits useTruststoreSpi=always by construction.
        self.assertIn("provider_name=LAB_LDAP_PROVIDER_NAME", identity)


class SambaServesTheCertTests(unittest.TestCase):
    """The DC serves the CA-issued leaf when present and self-signs otherwise."""

    def setUp(self) -> None:
        self.entrypoint = ENTRYPOINT.read_text(encoding="utf-8")

    def test_ca_issued_material_is_preferred_when_present(self) -> None:
        self.assertIn("use_ca_material=true", self.entrypoint)
        self.assertIn('SAMBA_TLS_CERT_FILE', self.entrypoint)
        self.assertIn('SAMBA_TLS_KEY_FILE', self.entrypoint)
        # It is only adopted if it actually certifies the LDAPS FQDN.
        self.assertIn('-checkhost "$ldaps_fqdn"', self.entrypoint)

    def test_self_signed_fallback_carries_the_ldaps_fqdn_san(self) -> None:
        # The bootstrap-window self-signed cert must include the FQDN SAN so
        # Keycloak's hostname verification passes before the CA leaf is issued.
        self.assertIn(
            '-addext "subjectAltName=DNS:$ldaps_fqdn,DNS:$hostname_short,DNS:$realm_fqdn"',
            self.entrypoint,
        )
        self.assertIn("openssl req -x509", self.entrypoint)

    def test_the_bootstrap_is_not_deadlocked(self) -> None:
        # A fresh converge must self-sign (Vault is uninitialized): the fallback
        # branch has no dependency on delivered material existing.
        self.assertIn(
            "elif [ ! -s \"$TLS_DIR/key.pem\" ] || [ ! -s \"$TLS_DIR/cert.pem\" ]",
            self.entrypoint,
        )

    def test_the_healthcheck_verifies_the_ldaps_fqdn(self) -> None:
        healthcheck = HEALTHCHECK.read_text(encoding="utf-8")
        self.assertIn("fqdn=${SAMBA_LDAPS_FQDN:-", healthcheck)
        self.assertIn('-verify_hostname "$fqdn"', healthcheck)
        self.assertIn("-verify_return_error", healthcheck)


class SambaTlsCeremonyTests(unittest.TestCase):
    """Issuance is a token-on-stdin ceremony from the customer-CA intermediate."""

    def setUp(self) -> None:
        self.ceremony = PKI_CEREMONY.read_text(encoding="utf-8")

    def test_the_leaf_is_issued_for_the_fqdn_with_no_bare_hostname_san(self) -> None:
        self.assertIn("samba-tls", self.ceremony)
        self.assertIn('common_name="samba-ad.$DOMAIN"', self.ceremony)
        # A bare-hostname alt name would poison the leaf under the Aegis name
        # constraints, so it must never be requested for the samba leaf.
        self.assertNotIn('common_name="samba-ad.$DOMAIN" alt_names', self.ceremony)
        self.assertIn("pki_int/issue/aigw", self.ceremony)

    def test_the_material_is_delivered_root_owned_and_key_is_not_world_readable(
        self,
    ) -> None:
        self.assertIn(
            'install -m 0644 -- "$staging/tls.crt" "$STACK_DIR/secrets/samba_ad_tls_cert"',
            self.ceremony,
        )
        self.assertIn(
            'install -m 0640 -- "$staging/tls.key" "$STACK_DIR/secrets/samba_ad_tls_key"',
            self.ceremony,
        )

    def test_the_ceremony_recreates_the_dc_and_is_lab_only(self) -> None:
        self.assertIn("--force-recreate samba-ad", self.ceremony)
        self.assertIn('[[ "$profile" == rocky9-lab ]]', self.ceremony)

    def test_the_token_is_read_only_from_stdin(self) -> None:
        # The converge holds no Vault token; issuance uses the same stdin-only
        # token discipline as the edge-cert ceremony.
        self.assertIn("read -r VAULT_TOKEN", self.ceremony)


class BindDigestAndSelinuxBoundaryTests(unittest.TestCase):
    """All five bind-digest places stay coherent for the new mounts."""

    def test_the_lab_digest_manifest_captures_the_new_sources(self) -> None:
        import json

        manifest = json.loads(DIGEST_INPUTS.read_text(encoding="utf-8"))
        self.assertEqual(
            manifest["lab_identity"]["keycloak"], ["certs/ca.pem", "keycloak/realms"]
        )
        self.assertEqual(
            manifest["lab_identity"]["samba-ad"],
            [
                "secrets/samba_ad_admin_password",
                "secrets/samba_ad_bind_password",
                "secrets/samba_ad_tls_cert",
                "secrets/samba_ad_tls_key",
                "secrets/samba_user_lab-admin_password",
                "secrets/samba_user_lab-developer_password",
                "secrets/samba_user_lab-user_password",
            ],
        )

    def test_the_selinux_boundary_covers_the_new_samba_tls_sources(self) -> None:
        boundary = STACK_TASKS.read_text(encoding="utf-8").split(
            "- name: Define the exact SELinux read-only bind-source boundary", 1
        )[1]
        self.assertIn("'/secrets/samba_ad_tls_cert'", boundary)
        self.assertIn("'/secrets/samba_ad_tls_key'", boundary)

    def test_the_placeholder_material_has_a_root_owned_boundary(self) -> None:
        source = STACK_TASKS.read_text(encoding="utf-8")
        self.assertIn(
            "- name: Provide empty Samba LDAPS certificate placeholders on first converge",
            source,
        )
        block = source.split(
            "- name: Require exact Samba LDAPS certificate material ownership and modes",
            1,
        )[1].split("- name:", 1)[0]
        self.assertIn("item.stat.uid == 0", block)
        self.assertIn("item.stat.gid == 0", block)
        self.assertIn("not (item.stat.islnk | default(false))", block)
        # force=false so a converge never clobbers the ceremony's CA material.
        self.assertIn("force: false", source)


class NameConstraintRealityTests(unittest.TestCase):
    """PROVE the crux: a bare-hostname SAN is unusable under the Aegis CA.

    This is the reason the whole change exists. Rather than assert it in prose,
    reconstruct a root CA with the SAME critical name constraints the Aegis root
    carries and show, with openssl, that a leaf whose SAN is the bare container
    hostname fails verification (error 47, permitted subtree violation) while a
    leaf whose SAN is the FQDN under the permitted domain verifies cleanly.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.openssl = shutil.which("openssl")
        if cls.openssl is None:
            raise unittest.SkipTest("openssl is required")

    def _run(self, *args: str, cwd: Path, stdin: str | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            [self.openssl, *args],
            cwd=cwd,
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )

    def _make_ca(self, work: Path) -> None:
        root_cnf = work / "root.cnf"
        root_cnf.write_text(
            "[req]\ndistinguished_name=dn\nx509_extensions=v3_ca\nprompt=no\n"
            "[dn]\nO=Aegis Group\nCN=Aegis Group Root CA\n"
            "[v3_ca]\nbasicConstraints=critical,CA:true\n"
            "keyUsage=critical,keyCertSign,cRLSign\n"
            # The exact permitted subtrees the orchestrator established.
            "nameConstraints=critical,permitted;DNS:aegisgroup.ch,"
            "permitted;DNS:cluster.local,permitted;IP:10.0.0.0/255.0.0.0,"
            "permitted;IP:172.16.0.0/255.240.0.0,"
            "permitted;IP:192.168.0.0/255.255.0.0\n",
            encoding="utf-8",
        )
        result = self._run(
            "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", "root.key", "-out", "root.pem", "-days", "3650",
            "-config", "root.cnf", cwd=work,
        )
        self.assertEqual(result.returncode, 0, result.stdout)

    def _sign_leaf(self, work: Path, san: str, out: str) -> None:
        self._run(
            "req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-keyout", f"{out}.key", "-out", f"{out}.csr", "-subj", f"/CN={san}",
            cwd=work,
        )
        ext = work / f"{out}.ext"
        ext.write_text(
            f"subjectAltName=DNS:{san}\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n",
            encoding="utf-8",
        )
        result = self._run(
            "x509", "-req", "-in", f"{out}.csr", "-CA", "root.pem", "-CAkey",
            "root.key", "-CAcreateserial", "-out", f"{out}.pem", "-days", "365",
            "-extfile", f"{out}.ext", cwd=work,
        )
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_a_bare_hostname_san_cannot_be_signed_but_the_fqdn_can(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            self._make_ca(work)
            self._sign_leaf(work, "samba-ad", "bare")
            self._sign_leaf(work, "samba-ad.aigw.aegisgroup.ch", "fqdn")

            bare = self._run("verify", "-CAfile", "root.pem", "bare.pem", cwd=work)
            self.assertNotEqual(bare.returncode, 0)
            # error 47 == X509_V_ERR_PERMITTED_VIOLATION (permitted subtree)
            self.assertIn("permitted subtree violation", bare.stdout)

            fqdn = self._run("verify", "-CAfile", "root.pem", "fqdn.pem", cwd=work)
            self.assertEqual(fqdn.returncode, 0, fqdn.stdout)
            self.assertIn("fqdn.pem: OK", fqdn.stdout)


if __name__ == "__main__":
    unittest.main()
