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

    def test_present_but_invalid_ca_material_is_not_silently_self_signed(self) -> None:
        # #4: when CA material is DELIVERED but partial/truncated/mismatched or
        # does not certify the FQDN, the DC must fail LOUD and greppable, never
        # drop silently to a self-signed cert (which converge/verify/healthcheck
        # would all leave green).
        self.assertIn("ca_material_present=false", self.entrypoint)
        self.assertIn("ca_material_present=true", self.entrypoint)
        self.assertIn("TLS-DOWNGRADE-REFUSED", self.entrypoint)
        self.assertIn(
            'if [ "$use_ca_material" != true ] && [ "$ca_material_present" = true ]; then',
            self.entrypoint,
        )
        # The refusal is a hard die() on that path, not a self-sign.
        self.assertIn(
            'die "TLS-DOWNGRADE-REFUSED: delivered LDAPS material for $ldaps_fqdn is partial/invalid/mismatched',
            self.entrypoint,
        )

    def test_ca_material_adoption_requires_a_matching_keypair(self) -> None:
        # #15's partial window (a new cert paired with a stale key) is caught
        # here too: material is only adopted when the certificate public key
        # matches the private key.
        self.assertIn("-noout -pubkey", self.entrypoint)
        self.assertIn("-pubout", self.entrypoint)

    def test_ca_material_state_is_recorded_and_guards_a_later_downgrade(self) -> None:
        # Once CA material is in force a persistent marker is written, so a later
        # start that finds it missing is a regression, never a fresh bootstrap.
        self.assertIn(
            "CA_MATERIAL_MARKER=/var/lib/samba/.aigw-ca-material-in-force",
            self.entrypoint,
        )
        self.assertIn(': > "$CA_MATERIAL_MARKER"', self.entrypoint)
        self.assertIn(
            'if [ "$use_ca_material" != true ] && [ -f "$CA_MATERIAL_MARKER" ]; then',
            self.entrypoint,
        )

    def test_downgrade_guards_precede_the_bootstrap_self_sign(self) -> None:
        # Both loud guards run BEFORE the self-sign fallback, so the fallback is
        # reachable only on a genuine first converge (no CA material ever
        # delivered) — the self-sign path is never a silent downgrade.
        guard = self.entrypoint.index("TLS-DOWNGRADE-REFUSED")
        self_sign = self.entrypoint.index('elif [ ! -s "$TLS_DIR/key.pem"')
        self.assertLess(guard, self_sign)

    def test_the_healthcheck_verifies_the_ldaps_fqdn(self) -> None:
        healthcheck = HEALTHCHECK.read_text(encoding="utf-8")
        self.assertIn("fqdn=${SAMBA_LDAPS_FQDN:-", healthcheck)
        self.assertIn('-verify_hostname "$fqdn"', healthcheck)
        self.assertIn("-verify_return_error", healthcheck)

    def test_healthcheck_anchors_on_the_real_chain_when_ca_material_expected(self) -> None:
        # #5: /var/lib/samba-public/ca.pem is the DC's own self-published anchor —
        # it republishes whatever cert the DC serves, so a self-signed fallback
        # would verify against itself. Once CA material is in force the
        # healthcheck must anchor on the REAL delivered customer material and FAIL
        # on a self-signed downgrade.
        healthcheck = HEALTHCHECK.read_text(encoding="utf-8")
        self.assertIn(
            "ca_material_marker=/var/lib/samba/.aigw-ca-material-in-force",
            healthcheck,
        )
        self.assertIn('if [ -f "$ca_material_marker" ]; then', healthcheck)
        self.assertIn("verify_cafile=$tls_cert_src", healthcheck)
        self.assertIn('-CAfile "$verify_cafile"', healthcheck)
        # The self-published anchor is now ONLY the bootstrap-window else-branch,
        # never the unconditional CAfile it used to be.
        self.assertIn("verify_cafile=/var/lib/samba-public/ca.pem", healthcheck)
        self.assertNotIn(
            "-CAfile /var/lib/samba-public/ca.pem", healthcheck
        )


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

    def test_the_material_is_delivered_atomically_and_key_is_not_world_readable(
        self,
    ) -> None:
        # #15: cert+key were previously installed via two non-atomic `install`
        # calls straight onto the live paths, so a crash between them left a new
        # cert paired with a stale key — the partial window the DC then silently
        # self-signed over. Stage each under a temp name in the SAME destination
        # directory and rename: a same-directory rename is atomic.
        self.assertIn('cert_dst="$STACK_DIR/secrets/samba_ad_tls_cert"', self.ceremony)
        self.assertIn('key_dst="$STACK_DIR/secrets/samba_ad_tls_key"', self.ceremony)
        # Samba's CVE-2013-4476 guard rejects any group/other bit on the LDAPS
        # private key, so the ceremony must stage it 0600 — matching the
        # entrypoint's CA-adoption and self-signed-fallback paths.
        self.assertIn('install -m 0600 -- "$staging/tls.key" "$key_dst.tmp"', self.ceremony)
        self.assertIn('install -m 0644 -- "$staging/tls.crt" "$cert_dst.tmp"', self.ceremony)
        self.assertIn('mv -f -- "$key_dst.tmp" "$key_dst"', self.ceremony)
        self.assertIn('mv -f -- "$cert_dst.tmp" "$cert_dst"', self.ceremony)
        # The old direct, non-atomic installs are gone.
        self.assertNotIn(
            'install -m 0644 -- "$staging/tls.crt" "$STACK_DIR/secrets/samba_ad_tls_cert"',
            self.ceremony,
        )
        self.assertNotIn(
            'install -m 0600 -- "$staging/tls.key" "$STACK_DIR/secrets/samba_ad_tls_key"',
            self.ceremony,
        )

    def test_the_issued_leaf_and_key_are_pubkey_matched_before_install(self) -> None:
        # #15: the two installs had no pair-match check, so a wrong/truncated key
        # could be delivered alongside a good cert. A public-key comparison now
        # proves the pair matches BEFORE either file is written.
        self.assertIn('cert_pubkey="$(openssl x509 -in "$staging/tls.crt" -noout -pubkey)"', self.ceremony)
        self.assertIn('key_pubkey="$(openssl pkey -in "$staging/tls.key" -pubout', self.ceremony)
        self.assertIn("issued leaf and private key do not match (public-key mismatch)", self.ceremony)

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


class HealthcheckRealChainVerificationTests(unittest.TestCase):
    """PROVE the #5 fix makes the real-CA trust path load-bearing.

    The healthcheck now verifies the served LDAPS cert against the REAL delivered
    customer material ($tls_cert_src = leaf+intermediate+root) once CA material is
    in force, instead of against /var/lib/samba-public/ca.pem — the DC's own
    anchor, which republishes whatever cert the DC serves. Reconstruct both
    anchors with openssl and show, concretely, that:

    * anchoring on the REAL delivered chain ACCEPTS the CA-issued leaf but
      REJECTS a self-signed cert for the same FQDN (the silent downgrade); while
    * anchoring on the DC's self-published anchor (the self-signed cert itself,
      the OLD behavior) ACCEPTS that same self-signed cert — which is exactly why
      the path was never load-bearing before this fix.
    """

    FQDN = "samba-ad.aigw.aegisgroup.ch"

    @classmethod
    def setUpClass(cls) -> None:
        cls.openssl = shutil.which("openssl")
        if cls.openssl is None:
            raise unittest.SkipTest("openssl is required")

    def _run(self, *args: str, cwd: Path) -> subprocess.CompletedProcess:
        return subprocess.run(
            [self.openssl, *args],
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )

    def _leaf_ext(self, work: Path, name: str) -> Path:
        ext = work / f"{name}.ext"
        ext.write_text(
            f"subjectAltName=DNS:{self.FQDN}\n"
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n",
            encoding="utf-8",
        )
        return ext

    def _build(self, work: Path) -> None:
        # Self-signed customer root.
        self.assertEqual(
            0,
            self._run(
                "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
                "-subj", "/CN=Aegis Group Root CA",
                "-addext", "basicConstraints=critical,CA:true",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-keyout", "root.key", "-out", "root.pem", cwd=work,
            ).returncode,
        )
        # Intermediate signed by the root.
        self._run(
            "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=AIGW Intermediate CA",
            "-keyout", "int.key", "-out", "int.csr", cwd=work,
        )
        (work / "int.ext").write_text(
            "basicConstraints=critical,CA:true,pathlen:0\n"
            "keyUsage=critical,digitalSignature,cRLSign,keyCertSign\n",
            encoding="utf-8",
        )
        self.assertEqual(
            0,
            self._run(
                "x509", "-req", "-in", "int.csr", "-CA", "root.pem", "-CAkey", "root.key",
                "-CAcreateserial", "-days", "1825", "-extfile", "int.ext", "-out", "int.pem",
                cwd=work,
            ).returncode,
        )
        # CA-issued leaf for the FQDN, signed by the intermediate.
        self._run(
            "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={self.FQDN}",
            "-keyout", "leaf.key", "-out", "leaf.csr", cwd=work,
        )
        self.assertEqual(
            0,
            self._run(
                "x509", "-req", "-in", "leaf.csr", "-CA", "int.pem", "-CAkey", "int.key",
                "-CAcreateserial", "-days", "365", "-extfile", str(self._leaf_ext(work, "leaf")),
                "-out", "leaf.pem", cwd=work,
            ).returncode,
        )
        # Self-signed cert for the SAME FQDN: the silent downgrade AND the exact
        # thing the DC would republish as its own /var/lib/samba-public anchor.
        self.assertEqual(
            0,
            self._run(
                "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "825",
                "-subj", f"/CN={self.FQDN}",
                "-addext", f"subjectAltName=DNS:{self.FQDN}",
                "-addext", "extendedKeyUsage=serverAuth",
                "-keyout", "self.key", "-out", "self.pem", cwd=work,
            ).returncode,
        )
        # The delivered real customer material the healthcheck anchors on.
        (work / "delivered_bundle.pem").write_text(
            (work / "leaf.pem").read_text(encoding="utf-8")
            + (work / "int.pem").read_text(encoding="utf-8")
            + (work / "root.pem").read_text(encoding="utf-8"),
            encoding="utf-8",
        )

    def test_real_chain_rejects_self_signed_but_accepts_the_ca_leaf(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            self._build(work)

            # NEW healthcheck anchor (delivered real chain) ACCEPTS the CA leaf.
            good = self._run("verify", "-CAfile", "delivered_bundle.pem", "leaf.pem", cwd=work)
            self.assertEqual(good.returncode, 0, good.stdout)
            self.assertIn("leaf.pem: OK", good.stdout)

            # NEW healthcheck anchor REJECTS a self-signed cert for the same FQDN:
            # a silent downgrade now fails the healthcheck.
            downgrade = self._run(
                "verify", "-CAfile", "delivered_bundle.pem", "self.pem", cwd=work
            )
            self.assertNotEqual(downgrade.returncode, 0)

            # OLD behavior — anchoring on the DC's own self-published anchor (the
            # self-signed cert itself) — would have ACCEPTED the downgrade, which
            # is exactly why the real-CA path was never load-bearing.
            old = self._run("verify", "-CAfile", "self.pem", "self.pem", cwd=work)
            self.assertEqual(old.returncode, 0, old.stdout)


if __name__ == "__main__":
    unittest.main()
