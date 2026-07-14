"""Contract coverage for external production AD/LDAPS federation.

The claims pinned here are the ones an operator's directory depends on:

* the feature is inventory-owned and fail-closed — enabling it without every
  input stops the controller preflight before any host is touched;
* plaintext ``ldap://`` is refused at every layer that can still stop a deploy;
* the bind credential exists only as a root-owned file mounted into the single
  reconciliation component — never in Compose environment, argv, or ``.env``;
* the CA bundle is validated before it becomes Keycloak's LDAPS trust anchor
  and hostname verification is never disabled;
* exactly one Keycloak -> directory tcp/636 firewall allowance exists, in both
  independent backends, and none exists while the feature is off;
* the lab federation keeps its exact ``lab-samba-ad`` provider identity.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "ansible" / "generic-rocky9-contract.json"
PREFLIGHT = ROOT / "ansible" / "preflight-generic-rocky9.yml"
SITE = ROOT / "ansible" / "site.yml"
STACK_TASKS = ROOT / "ansible" / "roles" / "docker_stack" / "tasks" / "main.yml"
VERIFY_TASKS = ROOT / "ansible" / "roles" / "verify" / "tasks" / "main.yml"
ENV_TEMPLATE = ROOT / "ansible" / "roles" / "docker_stack" / "templates" / "env.j2"
DOCKER_USER = (
    ROOT / "ansible" / "roles" / "firewalld_zones" / "templates" / "docker-user-rules.sh.j2"
)
NFT_GUARD = (
    ROOT
    / "ansible"
    / "roles"
    / "firewalld_zones"
    / "templates"
    / "aigw-host-input-rules.sh.j2"
)
OVERLAY = ROOT / "compose" / "docker-compose.identity-ldap.yml"
DIGEST_INPUTS = ROOT / "compose" / "bind-source-digest-inputs.json"
WRAPPER = ROOT / "scripts" / "aigw-compose.sh"
HELPER = ROOT / "scripts" / "store-identity-ldap-bind-password.py"
BOOTSTRAP = ROOT / "scripts" / "bootstrap-generic-rocky9.py"
ROTATOR_CONFIG = ROOT / "services" / "key-rotator" / "app" / "config.py"
ROTATOR_IDENTITY = ROOT / "services" / "key-rotator" / "app" / "identity.py"
GROUP_VARS = ROOT / "ansible" / "group_vars" / "all.yml"

# Claims that can only be proven by a real LDAPS handshake against a real
# directory. They are enumerated here — never simulated — so that a green
# fixture suite is never mistaken for a proven federation. Each entry is
# (claim, why it cannot be proven here, the exact live check that closes it).
# IdentityLdapLiveVerificationRequiredTests keeps this honest.
LIVE_VERIFICATION_REQUIRED: tuple[tuple[str, str, str], ...] = (
    (
        "A wrong CA bundle fails closed with no Keycloak component left behind",
        "Only a real DC certificate chain can be mis-signed; a self-made chain "
        "would prove our own fixture, not the customer's PKI.",
        "Converge with a valid-but-unrelated CA bundle: bootstrap must fail on "
        "testLDAPConnection (PKIX path failure in the Keycloak log), and the "
        "realm must hold no ldap component afterwards.",
    ),
    (
        "Keycloak enforces LDAPS hostname verification (KC_TLS_HOSTNAME_VERIFIER)",
        "The contract pins DEFAULT and forbids ANY, but only a live handshake "
        "proves this Keycloak build honours it for LDAP (26.x semantics).",
        "Point identity_ldap_url at an FQDN absent from the DC certificate's "
        "SANs while trusting its real CA: the converge must fail closed.",
    ),
    (
        "A wrong bind DN or password fails closed before any component is written",
        "Keycloak's testLDAPConnection response is mocked at unit level; the "
        "real 4xx shape varies across Keycloak majors.",
        "Store a wrong credential with the helper and converge: bootstrap must "
        "raise IdentityConflict and create no provider.",
    ),
    (
        "The single tcp/636 allowance is sufficient AND necessary",
        "No fixture can prove that Keycloak reaches the directory while every "
        "other container is denied — that is a live packet-path property.",
        "With the feature on: Keycloak connects; a socket from another "
        "container to directory:636 times out; DOCKER-USER and aigw_guard each "
        "hold exactly one 636 tuple. With it off: zero 636 tuples.",
    ),
    (
        "Users import and federated OIDC login works end to end, idempotently",
        "Requires a populated customer directory.",
        "Converge twice: the provider keeps its id, users import READ_ONLY, an "
        "AD user completes an OIDC login, and the second converge is no-op.",
    ),
    (
        "The lab federation keeps its exact lab-samba-ad component id on converge",
        "Pinned byte-for-byte by unit tests, but only a live lab converge "
        "proves no reprovision occurs.",
        "On the live lab: capture the lab-samba-ad component UUID before and "
        "after a full converge — it must be unchanged.",
    ),
)

VALID_HOST_VARS = """---
aigw_generic_inventory_alias: customer-aigw01
deployment_profile: generic-rocky9
require_encrypted_state: true
samba_lab_enabled: false
aigw_seed_test_users: false
retain_bootstrap_admin_user: false
aigw_prebootstrap_oidc_scope_reconciliation: false
aigw_prebootstrap_oidc_scope_reconciliation_ack: ""
platform_authoritative_dns_enabled: false
aigw_vault_ui_enabled: false
aigw_lab_reset_handoff_drop_interfaces: []
"""


def _load_bootstrap_module():
    spec = importlib.util.spec_from_file_location("_aigw_bootstrap_identity_ldap", BOOTSTRAP)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class IdentityLdapContractJsonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def test_the_feature_flag_is_a_required_production_input(self) -> None:
        self.assertIn("identity_ldap_enabled", self.contract["required_nonsecret_keys"])

    def test_the_conditional_feature_block_is_exact(self) -> None:
        self.assertEqual(
            self.contract["conditional_feature_keys"]["identity_ldap"],
            {
                "enabled_by": "identity_ldap_enabled",
                "required_nonsecret_keys": [
                    "identity_ldap_provider_name",
                    "identity_ldap_url",
                    "identity_ldap_users_dn",
                    "identity_ldap_bind_dn",
                    "identity_ldap_ca_bundle_src",
                    "identity_ldap_directory_ip",
                    "identity_ldap_vendor",
                    "identity_ldap_username_attribute",
                    "identity_ldap_rdn_attribute",
                    "identity_ldap_uuid_attribute",
                    "identity_ldap_user_object_classes",
                    "identity_ldap_user_filter",
                ],
                "operator_supplied_secret_keys": [
                    {
                        "name": "identity_ldap_bind_password",
                        "source": "customer-directory-bind-account",
                        "generated_by_inventory_bootstrap": False,
                    }
                ],
            },
        )

    def test_the_bind_credential_is_never_randomly_generated(self) -> None:
        """It belongs to the customer's directory; the bootstrap cannot mint it."""
        generated = [entry["name"] for entry in self.contract["required_secret_keys"]]
        self.assertNotIn("identity_ldap_bind_password", generated)

    def test_the_bootstrap_template_ships_the_feature_disabled(self) -> None:
        """Both generated host_vars documents carry the full contract, disabled.

        The canonical rocky9-production document (SECTION 4) and the deprecated
        generic-rocky9 compatibility document must agree: every conditional
        input present and empty, the feature off, and the bind credential
        delegated to the stdin-only helper — never templated as a key.
        """
        module = _load_bootstrap_module()
        documents = {
            "rocky9-production": module.production_host_vars_document("customer-prod01"),
            "generic-rocky9": module.host_vars_document("customer-aigw01"),
        }
        for profile, document in documents.items():
            with self.subTest(profile=profile):
                self.assertIn("identity_ldap_enabled: false", document)
                for key in self.contract["conditional_feature_keys"]["identity_ldap"][
                    "required_nonsecret_keys"
                ]:
                    self.assertIn(f"{key}:", document)
                self.assertIn("store-identity-ldap-bind-password.py", document)
                # The generated host_vars must never carry the credential itself.
                self.assertNotIn("identity_ldap_bind_password:", document)
                # ldaps-only is stated where the operator fills the value in.
                self.assertIn("ldaps://", document)

        # The canonical document points at the canonical overlay group.
        self.assertIn(
            "group_vars/production_rocky9/identity-ldap.yml", documents["rocky9-production"]
        )
        self.assertIn(
            "group_vars/generic_rocky9/identity-ldap.yml", documents["generic-rocky9"]
        )

    def test_group_vars_default_the_feature_off_without_a_credential(self) -> None:
        source = GROUP_VARS.read_text(encoding="utf-8")
        self.assertIn("identity_ldap_enabled: false", source)
        self.assertIn("keycloak_internal_ip: 172.28.2.3", source)
        self.assertNotIn("\nidentity_ldap_bind_password:", source)


class IdentityLdapPlaintextRejectionTests(unittest.TestCase):
    def test_every_mutation_gate_anchors_on_ldaps(self) -> None:
        for source_file in (PREFLIGHT, SITE, STACK_TASKS):
            with self.subTest(path=source_file.name):
                self.assertIn("^ldaps://", source_file.read_text(encoding="utf-8"))

    def test_the_overlay_carries_no_plaintext_ldap_origin(self) -> None:
        self.assertNotIn("ldap://", OVERLAY.read_text(encoding="utf-8"))

    def test_the_key_rotator_refuses_a_non_ldaps_origin(self) -> None:
        source = ROTATOR_CONFIG.read_text(encoding="utf-8")
        self.assertIn("_validate_ldaps_origin", source)
        self.assertIn("must be a bare ldaps:// origin", source)
        self.assertIn("IDENTITY_LDAP_URL", source)


class IdentityLdapSecretBoundaryTests(unittest.TestCase):
    def test_the_credential_is_a_file_and_never_compose_environment(self) -> None:
        overlay = OVERLAY.read_text(encoding="utf-8")
        self.assertIn(
            "IDENTITY_LDAP_BIND_PASSWORD_FILE: /run/secrets/identity_ldap_bind_password",
            overlay,
        )
        self.assertNotIn("IDENTITY_LDAP_BIND_PASSWORD:", overlay)
        self.assertIn(
            "./secrets/identity_ldap_bind_password:"
            "/run/secrets/identity_ldap_bind_password:ro,Z",
            overlay,
        )

    def test_the_credential_is_mounted_only_into_the_reconciliation_component(
        self,
    ) -> None:
        overlay = OVERLAY.read_text(encoding="utf-8")
        keycloak_block = overlay.split("  keycloak:", 1)[1].split("  key-rotator:", 1)[0]
        self.assertNotIn("identity_ldap_bind_password", keycloak_block)

    def test_the_credential_is_never_rendered_into_env(self) -> None:
        env_source = ENV_TEMPLATE.read_text(encoding="utf-8")
        self.assertNotIn("{{ identity_ldap_bind_password", env_source)
        self.assertNotIn("IDENTITY_LDAP_BIND_PASSWORD=", env_source)
        self.assertIn(
            "IDENTITY_LDAP_ENABLED={{ identity_ldap_enabled | bool | lower }}",
            env_source,
        )

    def test_the_secret_file_boundary_is_root_owned_and_group_readable(self) -> None:
        source = STACK_TASKS.read_text(encoding="utf-8")
        block = source.split(
            "- name: Materialize the external directory bind credential outside "
            "command and environment metadata",
            1,
        )[1].split("- name: Inspect the external directory secret-file boundary", 1)[0]
        self.assertIn("no_log: true", block)
        self.assertIn('group: "65532"', block)
        self.assertIn('mode: "0440"', block)
        self.assertIn("owner: root", block)
        assertion = source.split(
            "- name: Require exact external directory secret-file ownership and mode", 1
        )[1].split("- name:", 1)[0]
        self.assertIn("identity_ldap_secret_file.stat.uid == 0", assertion)
        self.assertIn("identity_ldap_secret_file.stat.gid == 65532", assertion)
        self.assertIn("identity_ldap_secret_file.stat.mode == '0440'", assertion)

    def test_the_selinux_boundary_covers_both_new_bind_sources(self) -> None:
        boundary = STACK_TASKS.read_text(encoding="utf-8").split(
            "- name: Define the exact SELinux read-only bind-source boundary", 1
        )[1]
        self.assertIn("'/keycloak/identity-ldap-ca.pem'", boundary)
        self.assertIn("'/secrets/identity_ldap_bind_password'", boundary)

    def test_the_digest_manifest_group_is_exact(self) -> None:
        manifest = json.loads(DIGEST_INPUTS.read_text(encoding="utf-8"))
        self.assertEqual(
            manifest["identity_ldap"],
            {
                "keycloak": ["keycloak/identity-ldap-ca.pem", "keycloak/realms"],
                "key-rotator": ["secrets/identity_ldap_bind_password"],
            },
        )


class IdentityLdapTrustBoundaryTests(unittest.TestCase):
    def test_keycloak_trusts_only_the_supplied_bundle_and_verifies_the_hostname(
        self,
    ) -> None:
        overlay = OVERLAY.read_text(encoding="utf-8")
        self.assertIn("KC_TRUSTSTORE_PATHS: /etc/aigw/identity-ldap-ca.pem", overlay)
        self.assertIn("KC_TLS_HOSTNAME_VERIFIER: DEFAULT", overlay)
        self.assertNotIn("KC_TLS_HOSTNAME_VERIFIER: ANY", overlay)
        self.assertIn(
            "./keycloak/identity-ldap-ca.pem:/etc/aigw/identity-ldap-ca.pem:ro,Z",
            overlay,
        )

    def test_the_ca_bundle_is_validated_before_it_is_trusted(self) -> None:
        source = STACK_TASKS.read_text(encoding="utf-8")
        self.assertIn("Require a certificates-only external directory trust bundle", source)
        block = source.split(
            "- name: Require a certificates-only external directory trust bundle", 1
        )[1].split("- name:", 1)[0]
        self.assertIn("openssl", block)
        self.assertIn("storeutl", block)
        self.assertIn("Total found: 0", block)
        self.assertIn("PRIVATE KEY", block)
        preflight = PREFLIGHT.read_text(encoding="utf-8")
        self.assertIn("certificates_only_pem", preflight)
        self.assertIn("-----BEGIN CERTIFICATE-----", preflight)

    def test_the_provider_is_read_only_and_never_self_registers(self) -> None:
        identity = ROTATOR_IDENTITY.read_text(encoding="utf-8")
        self.assertIn('"editMode": ["READ_ONLY"]', identity)
        self.assertIn('"syncRegistrations": ["false"]', identity)
        self.assertIn('"useTruststoreSpi": ["always"]', identity)
        self.assertIn('"startTls": ["false"]', identity)
        # A wrong CA, a failed hostname check, or wrong credentials must be
        # proved against the directory before any component is written. The
        # live call order is exercised in the key-rotator suite; pin the source
        # ordering inside the reconciliation method here.
        self.assertIn("testLDAPConnection", identity)
        self.assertIn("testAuthentication", identity)
        self.assertIn("the directory connection or bind credential failed verification", identity)
        body = identity.split("async def _ensure_ldap_federation", 1)[1].split(
            "def _verify_ldap_component", 1
        )[0]
        self.assertLess(
            body.index("_prove_ldap_directory("),
            body.index('f"/admin/realms/{safe_realm}/components"'),
        )


class IdentityLdapFirewallTests(unittest.TestCase):
    def test_exactly_one_gated_ldaps_allowance_exists_in_docker_user(self) -> None:
        template = DOCKER_USER.read_text(encoding="utf-8")
        self.assertEqual(template.count("--dport 636"), 1)
        self.assertEqual(template.count("{% if identity_ldap_enabled | bool %}"), 1)
        self.assertIn(
            "-A DOCKER-USER -i {{ _internal_net.bridge }} "
            "-s {{ keycloak_internal_ip }}/32 -o {{ nic_internal }} "
            "-d {{ identity_ldap_directory_ip }}/32 -p tcp --dport 636 -j RETURN",
            template,
        )

    def test_exactly_one_gated_ldaps_allowance_exists_in_the_nft_guard(self) -> None:
        template = NFT_GUARD.read_text(encoding="utf-8")
        self.assertEqual(template.count("tcp dport 636"), 1)
        self.assertEqual(template.count("{% if identity_ldap_enabled | bool %}"), 1)
        self.assertIn(
            'iifname "{{ _internal_net.bridge }}" oifname "{{ nic_internal }}" '
            "ip saddr {{ keycloak_internal_ip }} "
            "ip daddr {{ identity_ldap_directory_ip }} tcp dport 636 accept",
            template,
        )

    def test_verify_asserts_the_tuple_and_its_absence(self) -> None:
        verify = VERIFY_TASKS.read_text(encoding="utf-8")
        self.assertIn(
            "External directory LDAPS is pinned to the exact Keycloak identity", verify
        )
        self.assertIn(
            "No external directory allowance exists while federation is disabled", verify
        )
        self.assertIn("du.stdout.count('--dport 636') == 1", verify)
        self.assertIn("'--dport 636' not in du.stdout", verify)
        self.assertIn('"keycloak/identity-ldap-ca.pem": ("file", 0, 65532, 0o440)', verify)
        self.assertIn(
            '"secrets/identity_ldap_bind_password": ("file", 0, 65532, 0o440)', verify
        )

    def test_site_proves_the_directory_uses_the_internal_leg(self) -> None:
        site = SITE.read_text(encoding="utf-8")
        self.assertIn(
            "Preflight — prove the external directory uses the internal physical leg",
            site,
        )
        self.assertIn("check_workload_ip(\"keycloak_internal_ip\"", site)
        self.assertIn("identity_ldap_directory_ip ~ '/32'", site)


class IdentityLdapMutualExclusionTests(unittest.TestCase):
    def test_docker_stack_refuses_both_identity_sources(self) -> None:
        block = STACK_TASKS.read_text(encoding="utf-8").split(
            "- name: Validate the external directory federation inventory contract", 1
        )[1].split("- name: Validate per-gate oauth2-proxy cookie secret shapes", 1)[0]
        self.assertIn("not (samba_lab_enabled | bool)", block)
        self.assertIn("identity_ldap_provider_name != 'lab-samba-ad'", block)

    def test_site_refuses_both_identity_sources(self) -> None:
        site = SITE.read_text(encoding="utf-8")
        self.assertIn(
            "not (identity_ldap_enabled | bool) or not (samba_lab_enabled | bool)", site
        )

    def test_the_compose_wrapper_refuses_the_lab_profile_combination(self) -> None:
        wrapper = WRAPPER.read_text(encoding="utf-8")
        self.assertIn("expected exactly one IDENTITY_LDAP_ENABLED selector", wrapper)
        self.assertIn("external identity overlay conflicts with the lab profile", wrapper)
        self.assertIn("docker-compose.identity-ldap.yml", wrapper)

    def test_the_key_rotator_refuses_both_identity_sources(self) -> None:
        config = ROTATOR_CONFIG.read_text(encoding="utf-8")
        self.assertIn("exactly one LDAP federation source may be enabled", config)
        self.assertIn('LAB_LDAP_PROVIDER_NAME = "lab-samba-ad"', config)


class IdentityLdapLabProviderIdentityTests(unittest.TestCase):
    """A regression here would silently reprovision the live lab directory."""

    def test_the_lab_provider_name_and_filter_are_unchanged(self) -> None:
        identity = ROTATOR_IDENTITY.read_text(encoding="utf-8")
        self.assertIn("LAB_LDAP_USER_FILTER", identity)
        self.assertIn("(!(sAMAccountName=svc-keycloak-ldap)))", identity)
        self.assertIn("provider_name=LAB_LDAP_PROVIDER_NAME", identity)
        config = ROTATOR_CONFIG.read_text(encoding="utf-8")
        self.assertIn('LAB_LDAP_PROVIDER_NAME = "lab-samba-ad"', config)

    def test_the_lab_creation_path_gains_no_new_admin_call(self) -> None:
        """The directory probe is a production-only gate.

        The lab DC is an in-stack, healthcheck-gated dependency with a
        published CA. Introducing a new Keycloak admin call into the lab's
        provider-creation path could regress a fresh lab build for no benefit.
        """
        identity = ROTATOR_IDENTITY.read_text(encoding="utf-8")
        self.assertIn("prove_directory_before_create: bool", identity)
        self.assertIn("if spec.prove_directory_before_create:", identity)
        lab_branch = identity.split("if settings.lab_samba_ldap_enabled:", 1)[1].split(
            "if settings.identity_ldap_enabled:", 1
        )[0]
        self.assertIn("prove_directory_before_create=False", lab_branch)
        generic_branch = identity.split("if settings.identity_ldap_enabled:", 1)[
            1
        ].split("return None", 1)[0]
        self.assertIn("prove_directory_before_create=True", generic_branch)

    def test_the_lab_overlay_is_untouched_by_the_production_feature(self) -> None:
        lab = (ROOT / "compose" / "docker-compose.lab.yml").read_text(encoding="utf-8")
        self.assertIn("LAB_SAMBA_LDAP_ENABLED", lab)
        self.assertIn("KC_TRUSTSTORE_PATHS: /var/lib/samba-public/ca.pem", lab)
        self.assertNotIn("IDENTITY_LDAP", lab)


class IdentityLdapPreflightExecutionTests(unittest.TestCase):
    """Drive the real controller preflight; it must fail closed before mutation."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.ansible_playbook = shutil.which("ansible-playbook")
        if cls.ansible_playbook is None:
            raise unittest.SkipTest("ansible-playbook is required")

    def run_preflight(self, host_vars: str, ca_bundle: str | None = None) -> str:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "host_vars").mkdir()
            (root / "hosts.yml").write_text(
                "---\nall:\n  children:\n    generic_rocky9:\n"
                "      hosts:\n        customer-aigw01:\n",
                encoding="utf-8",
            )
            if ca_bundle is not None:
                (root / "ca.pem").write_text(ca_bundle, encoding="utf-8")
                host_vars = host_vars.replace("@CA@", str(root / "ca.pem"))
            (root / "host_vars" / "customer-aigw01.yml").write_text(
                host_vars, encoding="utf-8"
            )
            result = subprocess.run(
                [self.ansible_playbook, "-i", str(root / "hosts.yml"), str(PREFLIGHT)],
                cwd=ROOT,
                env={**os.environ, "ANSIBLE_NOCOLOR": "1"},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            return result.stdout + result.stderr

    def test_enabling_the_feature_without_inputs_names_every_missing_key(self) -> None:
        combined = self.run_preflight(VALID_HOST_VARS + "identity_ldap_enabled: true\n")
        self.assertIn('"missing_identity_ldap"', combined)
        for key in (
            "identity_ldap_provider_name",
            "identity_ldap_url",
            "identity_ldap_users_dn",
            "identity_ldap_bind_dn",
            "identity_ldap_ca_bundle_src",
            "identity_ldap_directory_ip",
            "identity_ldap_user_filter",
            "identity_ldap_bind_password",
        ):
            self.assertIn(key, combined)

    def test_a_plaintext_ldap_url_is_refused_without_echoing_the_credential(
        self,
    ) -> None:
        host_vars = (
            VALID_HOST_VARS
            + """identity_ldap_enabled: true
identity_ldap_provider_name: corp-ad
identity_ldap_url: "ldap://dc1.corp.example.com"
identity_ldap_users_dn: "OU=Users,DC=corp,DC=example,DC=com"
identity_ldap_bind_dn: "CN=svc,OU=Service,DC=corp,DC=example,DC=com"
identity_ldap_ca_bundle_src: "@CA@"
identity_ldap_directory_ip: 10.20.5.10
identity_ldap_user_filter: "(objectClass=user)"
identity_ldap_bind_password: "Directory-Bind-Secret-9"
"""
        )
        combined = self.run_preflight(
            host_vars, "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
        )
        self.assertIn("bounded_ldaps_directory_contract", combined)
        self.assertNotIn("Directory-Bind-Secret-9", combined)

    def test_a_ca_bundle_holding_a_private_key_is_refused(self) -> None:
        host_vars = (
            VALID_HOST_VARS
            + """identity_ldap_enabled: true
identity_ldap_provider_name: corp-ad
identity_ldap_url: "ldaps://dc1.corp.example.com:636"
identity_ldap_users_dn: "OU=Users,DC=corp,DC=example,DC=com"
identity_ldap_bind_dn: "CN=svc,OU=Service,DC=corp,DC=example,DC=com"
identity_ldap_ca_bundle_src: "@CA@"
identity_ldap_directory_ip: 10.20.5.10
identity_ldap_user_filter: "(objectClass=user)"
identity_ldap_bind_password: "Directory-Bind-Secret-9"
"""
        )
        combined = self.run_preflight(
            host_vars,
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
            "-----BEGIN PRIVATE KEY-----\nBBBB\n-----END PRIVATE KEY-----\n",
        )
        self.assertIn("certificates_only_pem", combined)

    def test_a_disabled_feature_demands_no_directory_input(self) -> None:
        combined = self.run_preflight(VALID_HOST_VARS + "identity_ldap_enabled: false\n")
        self.assertIn('"missing_identity_ldap": []', combined)
        self.assertIn('"invalid_identity_ldap": {}', combined)


class IdentityLdapCustodyHelperTests(unittest.TestCase):
    """The bind credential reaches the overlay on stdin only."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.ansible_vault = shutil.which("ansible-vault")
        if cls.ansible_vault is None:
            raise unittest.SkipTest("ansible-vault is required")

    def test_the_helper_never_accepts_a_credential_from_argv_or_the_environment(
        self,
    ) -> None:
        source = HELPER.read_text(encoding="utf-8")
        self.assertIn("sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)", source)
        self.assertIn("interactive input is disabled", source)
        self.assertIn("sys.stdin.isatty()", source)
        for flag in (
            "--vault-file",
            "--vault-id",
            "--vault-password-file",
            "--ansible-vault",
        ):
            self.assertIn(flag, source)
        # The only argparse arguments are the four boundary flags above.
        self.assertEqual(source.count("parser.add_argument("), 4)
        self.assertNotIn("os.environ", source)

    def invoke(self, overlay: Path, password_file: Path, value: bytes):
        return subprocess.run(
            [
                sys.executable,
                "-I",
                str(HELPER),
                "--vault-file",
                str(overlay),
                "--vault-id",
                "customer-prod",
                "--vault-password-file",
                str(password_file),
            ],
            input=value,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_the_helper_stores_verifies_and_refuses_a_second_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            password_file = root / "vault-password"
            password_file.write_text("test-only-password\n", encoding="utf-8")
            password_file.chmod(0o600)
            overlay = root / "identity-ldap.yml"

            stored = self.invoke(overlay, password_file, b"Directory-Bind-Secret-9\n")
            self.assertEqual(stored.returncode, 0, stored.stderr)
            content = overlay.read_text(encoding="utf-8")
            self.assertIn("identity_ldap_bind_password: !vault |", content)
            self.assertIn("$ANSIBLE_VAULT;", content)
            # The plaintext never lands on disk.
            self.assertNotIn("Directory-Bind-Secret-9", content)
            self.assertNotIn("Directory-Bind-Secret-9", stored.stdout.decode())

            duplicate = self.invoke(overlay, password_file, b"Another-Bind-Secret-9\n")
            self.assertEqual(duplicate.returncode, 2)
            self.assertIn("already exists", duplicate.stderr.decode())

    def test_the_helper_refuses_malformed_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            password_file = root / "vault-password"
            password_file.write_text("test-only-password\n", encoding="utf-8")
            password_file.chmod(0o600)
            for label, value in (
                ("too_short", b"short\n"),
                ("control_character", b"has\x01control-character\n"),
                ("leading_space", b" leading-whitespace-value\n"),
                ("oversized", b"a" * 600 + b"\n"),
                ("empty", b"\n"),
            ):
                with self.subTest(label=label):
                    overlay = root / f"overlay-{label}.yml"
                    result = self.invoke(overlay, password_file, value)
                    self.assertEqual(result.returncode, 2)
                    self.assertFalse(overlay.exists())


class IdentityLdapLiveVerificationRequiredTests(unittest.TestCase):
    """The claims this suite deliberately does NOT pretend to have proven.

    Everything above is provable against the reviewed sources and the rendered
    Compose model. The claims below terminate in a real LDAPS handshake against
    a real directory: proving them here would mean standing up a fake directory
    and asserting against our own stub, which proves nothing about a customer's
    Active Directory. They are listed instead of faked, and each one names the
    exact live check that closes it.
    """

    def test_the_live_verification_list_is_explicit_and_bounded(self) -> None:
        for claim, why, live_check in LIVE_VERIFICATION_REQUIRED:
            with self.subTest(claim=claim):
                self.assertTrue(claim and why and live_check)
                self.assertLess(len(claim), 120)

    def test_the_fixture_suite_never_stands_up_a_fake_directory(self) -> None:
        """A stub LDAPS listener would turn the list above into a false green.

        No test in this repository may open a TLS socket and call it a
        directory: the fixture suite asserts the *contract* (sources, rendered
        model, admin-API call shapes), never a simulated handshake. Imports are
        inspected structurally so this rule cannot be satisfied by a comment.
        """
        forbidden = {"ssl", "ldap3", "ldap", "ldaptor", "socket", "socketserver"}
        federation_tests = (
            ROOT / "services" / "key-rotator" / "tests" / "test_identity_ldap_federation.py"
        )
        for source_file in (Path(__file__), federation_tests):
            with self.subTest(path=source_file.name):
                tree = ast.parse(source_file.read_text(encoding="utf-8"))
                imported: set[str] = set()
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        imported.update(alias.name.split(".")[0] for alias in node.names)
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        imported.add(node.module.split(".")[0])
                self.assertEqual(imported & forbidden, set(), sorted(imported & forbidden))

    def test_the_operator_documentation_states_the_remaining_gap(self) -> None:
        status = (ROOT / "docs" / "project-status.md").read_text(encoding="utf-8")
        self.assertIn("directory-equipped", status)
        self.assertIn("fixture- and unit-validated today", status)
        self.assertIn("LIVE_VERIFICATION_REQUIRED", status)


if __name__ == "__main__":
    unittest.main()
