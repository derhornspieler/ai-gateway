"""Configuration for key-rotator (pydantic-settings, env-var driven).

Design ref: docs/solution-map.md §1.7 / §3 — key-rotator lives on segmented
internal networks with no direct internet route. ALL vendor-bound HTTP calls MUST
be routed through EGRESS_BASE (envoy-egress, CA-pinned per §"Egress proxy
+ cert pinning" in the component table). Never call vendor domains
(api.anthropic.com, api.openai.com) directly from this service.
"""
from __future__ import annotations

import hmac
import re
from functools import lru_cache
from urllib.parse import SplitResult, urlsplit

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# The lab Samba federation owns this exact Keycloak component name. A
# production external-directory converge must never be able to adopt it: the
# lab provider identity (component id/name) has to survive lab converges
# untouched, and reusing the name would silently reprovision that directory.
LAB_LDAP_PROVIDER_NAME = "lab-samba-ad"

# Bounded LDAP filter grammar. `$` is deliberately excluded so a value carried
# through Compose interpolation can never be re-expanded.
_LDAP_FILTER_RE = re.compile(r"[A-Za-z0-9()&|!=<>~*.,:@ _\\-]+")
_LDAP_ATTRIBUTE_RE = re.compile(r"[A-Za-z][A-Za-z0-9-]{0,59}")
_LDAP_OBJECT_CLASSES_RE = re.compile(
    r"[A-Za-z][A-Za-z0-9-]{0,63}(, [A-Za-z][A-Za-z0-9-]{0,63}){0,7}"
)
_LDAP_PROVIDER_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
# Hostname verification is only meaningful against a real name, so an IP
# literal is refused for the production directory origin.
_LDAP_FQDN_RE = re.compile(
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
)
_IPV4_LITERAL_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")


def _validate_ldaps_origin(value: str, field_name: str) -> str:
    """Reject anything that is not a bare ldaps:// origin.

    Plaintext ``ldap://`` is refused here as the last of four independent
    layers (controller preflight, site.yml, docker_stack, and this service).
    """
    parsed = urlsplit(value)
    if (
        parsed.scheme.lower() != "ldaps"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"{field_name} must be a bare ldaps:// origin")
    return value.rstrip("/")


def _is_single_ldap_group(value: str) -> bool:
    """True iff the filter is exactly one balanced top-level parenthesis group.

    A valid LDAP filter is a single parenthesized expression. Requiring the
    depth to return to zero only at the final character rejects both
    unbalanced input and content that escapes the outer group
    (``()a=b(x=y)`` or two sibling groups ``(a=b)(c=d)``).
    """
    depth = 0
    for index, character in enumerate(value):
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth < 0:
                return False
            if depth == 0 and index != len(value) - 1:
                return False
    return depth == 0

# Values that must never be accepted as the internal auth token (compared
# case-insensitively). Anything under 16 chars is rejected too.
_PLACEHOLDER_TOKENS = {
    "changeme",
    "change-me",
    "change_me_internal_token",
    "placeholder",
    "rotator-internal-token",
    "secret",
    "token",
    "todo",
    "unset",
}

# Substrings that mark a value as an obvious placeholder even if it is long
# enough and not an exact match against the set above. This closes the gap
# where the shipped ansible default "dev-rotator-token-change-me" (27 chars,
# not in the exact set) would otherwise pass. Compared case-insensitively.
_PLACEHOLDER_SUBSTRINGS = (
    "change-me",
    "changeme",
    "change_me",
    "placeholder",
    "replace-me",
    "replaceme",
)

# Prefixes that mark a value as a non-production/dev token.
_PLACEHOLDER_PREFIXES = (
    "dev-",
    "test-",
    "example-",
    "sample-",
)


def _parse_service_url(value: str, *, field_name: str, base_only: bool) -> SplitResult:
    """Parse and constrain a service URL before it can carry credentials.

    These URLs are deployment configuration, not request input, but a typo
    such as ``http://proxy/path?next=`` changes how later path concatenation
    is interpreted. Userinfo is forbidden because libraries include the URL
    in exception text and logs. Only HTTP(S) is supported by the clients.
    """
    if not isinstance(value, str) or not value or any(ord(ch) < 32 for ch in value):
        raise ValueError(f"{field_name} must be a non-empty HTTP(S) URL")
    if "\\" in value:
        raise ValueError(f"{field_name} must not contain backslashes")

    parsed = urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError(f"{field_name} scheme must be http or https")
    if not parsed.hostname:
        raise ValueError(f"{field_name} must include a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(f"{field_name} must not contain URL userinfo")
    if parsed.query or parsed.fragment:
        raise ValueError(f"{field_name} must not contain a query string or fragment")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError(f"{field_name} contains an invalid port") from exc
    if base_only and parsed.path not in {"", "/"}:
        raise ValueError(f"{field_name} must be an origin URL with no path")
    return parsed


def _origin(parsed: SplitResult) -> tuple[str, str, int]:
    scheme = parsed.scheme.lower()
    default_port = 443 if scheme == "https" else 80
    return scheme, (parsed.hostname or "").lower(), parsed.port or default_port


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="", case_sensitive=False, extra="ignore")

    # Vault CE (docs/solution-map.md §1.3) — KV v2 mount "kv".
    vault_addr: str = Field(default="http://vault:8200", alias="VAULT_ADDR")
    vault_token: str = Field(default="", alias="VAULT_TOKEN")

    # LiteLLM proxy — rotation lands here via the OSS /credentials API
    # (hot in-process swap, no restart; docs/solution-map.md §1.2/§1.7).
    litellm_url: str = Field(default="http://litellm:4000", alias="LITELLM_URL")
    litellm_master_key: str = Field(default="", alias="LITELLM_MASTER_KEY")

    # Postgres — rotator_settings + rotation_history only (see app/db.py).
    database_url: str = Field(
        default="postgresql://rotator:pass@postgres:5432/rotator", alias="DATABASE_URL"
    )

    # Keycloak — INTERNAL call only for the Anthropic WIF client-credentials
    # exchange (docs/anthropic-wif-bootstrap.md Phase 1 step 1). Keycloak is
    # not a "vendor" in the egress-pinning sense; it's called directly.
    keycloak_url: str = Field(default="http://keycloak:8080", alias="KEYCLOAK_URL")
    # Keycloak validates private_key_jwt `aud` against its canonical public
    # hostname even though the HTTP request itself stays on the segmented
    # internal origin above.
    keycloak_public_url: str = Field(
        default="http://keycloak:8080", alias="KEYCLOAK_PUBLIC_URL"
    )
    # The isolated WIF realm deliberately advertises a distinct fabricated
    # issuer. Keycloak validates private_key_jwt audience against that realm's
    # frontend URL while the actual POST remains on KEYCLOAK_URL.
    wif_keycloak_public_url: str = Field(
        default="https://idp.wif-a.example.invalid",
        alias="WIF_KEYCLOAK_PUBLIC_URL",
    )

    # One-time Keycloak bootstrap controller. Keycloak creates this temporary
    # master-realm service account only on the first start. The identity setup
    # wizard consumes it, creates a narrower private_key_jwt controller in the
    # aigw realm, then deletes the temporary client. A configured secret is
    # inert after that deletion and is never sent to the browser/dev-portal.
    keycloak_bootstrap_admin_client_id: str = Field(
        default="aigw-bootstrap-controller",
        alias="KC_BOOTSTRAP_ADMIN_CLIENT_ID",
    )
    keycloak_bootstrap_admin_username: str = Field(
        default="admin", alias="KC_BOOTSTRAP_ADMIN_USERNAME"
    )
    keycloak_bootstrap_admin_client_secret: str = Field(
        default="", alias="KC_BOOTSTRAP_ADMIN_CLIENT_SECRET"
    )
    identity_controller_key_vault_path: str = Field(
        default="ai-gateway/keycloak/identity-controller-key",
        alias="IDENTITY_CONTROLLER_KEY_VAULT_PATH",
    )
    identity_state_vault_path: str = Field(
        default="ai-gateway/keycloak/identity-state",
        alias="IDENTITY_STATE_VAULT_PATH",
    )
    identity_realm: str = Field(default="aigw", alias="IDENTITY_REALM")
    identity_managed_root_group: str = Field(
        default="aigw-managed", alias="IDENTITY_MANAGED_ROOT_GROUP"
    )
    identity_controller_client_id: str = Field(
        default="aigw-identity-controller",
        alias="IDENTITY_CONTROLLER_CLIENT_ID",
    )
    aigw_domain: str = Field(
        default="aigw.example.internal", alias="AIGW_DOMAIN"
    )
    webui_oidc_client_secret: str = Field(
        default="", alias="WEBUI_OIDC_CLIENT_SECRET"
    )
    portal_oidc_client_secret: str = Field(
        default="", alias="PORTAL_OIDC_CLIENT_SECRET"
    )
    admin_portal_oidc_client_secret: str = Field(
        default="", alias="ADMIN_PORTAL_OIDC_CLIENT_SECRET"
    )
    oauth2_proxy_client_secret: str = Field(
        default="", alias="OAUTH2_PROXY_CLIENT_SECRET"
    )
    # Confidential OIDC client for Vault's own auth/oidc login (UI "Sign in
    # with OIDC Provider" + CLI loopback). Vault never reads this from the
    # environment: the rotator reconciles the Keycloak client and escrows the
    # secret at VAULT_OIDC_RP_VAULT_PATH, where the root-token ceremony
    # scripts/vault-oidc-setup.sh consumes it.
    vault_oidc_client_secret: str = Field(
        default="", alias="VAULT_OIDC_CLIENT_SECRET"
    )
    vault_oidc_rp_vault_path: str = Field(
        default="ai-gateway/keycloak/vault-oidc-rp",
        alias="VAULT_OIDC_RP_VAULT_PATH",
    )
    # Disposable lab only: keep the password-backed bootstrap user
    # as a durable ADM-console recovery operator while still deleting the
    # much broader temporary bootstrap service client. Customer profiles keep
    # this false and use their reviewed Keycloak break-glass process.
    retain_bootstrap_admin_user: bool = Field(
        default=False, alias="RETAIN_BOOTSTRAP_ADMIN_USER"
    )
    # Durable group-gated Keycloak administration. During the one-time
    # bootstrap window the rotator provisions a marked master-realm
    # administrators group carrying master's composite admin role plus a
    # marked break-glass user whose generated password is escrowed in Vault
    # before the account is enabled. Unlike RETAIN_BOOTSTRAP_ADMIN_USER this
    # applies to every profile: without it no interactive Keycloak
    # administrator exists after the temporary principals are deleted.
    break_glass_admin_enabled: bool = Field(
        default=True, alias="BREAK_GLASS_ADMIN_ENABLED"
    )
    break_glass_admin_username: str = Field(
        default="break-glass-admin", alias="BREAK_GLASS_ADMIN_USERNAME"
    )
    break_glass_admin_group: str = Field(
        default="keycloak-admins", alias="BREAK_GLASS_ADMIN_GROUP"
    )
    break_glass_admin_vault_path: str = Field(
        default="ai-gateway/keycloak/break-glass-admin",
        alias="BREAK_GLASS_ADMIN_VAULT_PATH",
    )
    # Reserved: master-realm directory federation for per-person Keycloak
    # administrators. The ensure path is not implemented; enabling the flag
    # must fail at configuration time rather than deploy without the
    # promised directory gate.
    admin_realm_ldap_enabled: bool = Field(
        default=False, alias="ADMIN_REALM_LDAP_ENABLED"
    )
    wif_realm: str = Field(default="anthropic-wif", alias="WIF_REALM")
    wif_broker_client_id: str = Field(
        default="anthropic-token-broker", alias="WIF_BROKER_CLIENT_ID"
    )

    # Lab-only AD federation. Generic/customer deployments leave this false
    # and configure their real directory through a separately reviewed
    # deployment overlay. The URL and DNs are not browser input, preventing
    # the setup wizard from becoming an LDAP SSRF primitive.
    lab_samba_ldap_enabled: bool = Field(
        default=False, alias="LAB_SAMBA_LDAP_ENABLED"
    )
    # FQDN, never the bare `samba-ad` container name: the lab DC's LDAPS leaf is
    # issued from the customer (Aegis) CA, whose critical name constraints
    # forbid a bare-hostname SAN, so hostname verification is only meaningful
    # against samba-ad.<lab-domain>. The committed lab domain is
    # aigw.aegisgroup.ch; the Compose lab overlay renders this from ${DOMAIN}.
    lab_samba_ldap_url: str = Field(
        default="ldaps://samba-ad.aigw.aegisgroup.ch:636", alias="LAB_SAMBA_LDAP_URL"
    )
    lab_samba_users_dn: str = Field(
        # Human lab identities live in a dedicated OU.  Using AD's broad
        # built-in CN=Users container also imports the domain Administrator
        # and other system principals into Keycloak's assignable user list.
        default="OU=AIGWUsers,DC=lab,DC=aigw,DC=internal",
        alias="LAB_SAMBA_USERS_DN",
    )
    lab_samba_bind_dn: str = Field(
        default="CN=svc-keycloak-ldap,CN=Users,DC=lab,DC=aigw,DC=internal",
        alias="LAB_SAMBA_BIND_DN",
    )
    lab_samba_bind_password_file: str = Field(
        default="/run/secrets/samba_keycloak_bind_password",
        alias="LAB_SAMBA_BIND_PASSWORD_FILE",
    )

    # Production external directory federation. Mutually exclusive with the lab
    # Samba path; the reserved lab provider name is refused here so a production
    # converge can never adopt the lab component identity. Every value is
    # inventory-owned and reaches this service only through Ansible-rendered
    # Compose environment, except the bind credential, which is read from a
    # root-owned file bind-mounted at IDENTITY_LDAP_BIND_PASSWORD_FILE.
    identity_ldap_enabled: bool = Field(
        default=False, alias="IDENTITY_LDAP_ENABLED"
    )
    identity_ldap_provider_name: str = Field(
        default="", alias="IDENTITY_LDAP_PROVIDER_NAME"
    )
    identity_ldap_url: str = Field(default="", alias="IDENTITY_LDAP_URL")
    identity_ldap_users_dn: str = Field(default="", alias="IDENTITY_LDAP_USERS_DN")
    identity_ldap_bind_dn: str = Field(default="", alias="IDENTITY_LDAP_BIND_DN")
    identity_ldap_bind_password_file: str = Field(
        default="/run/secrets/identity_ldap_bind_password",
        alias="IDENTITY_LDAP_BIND_PASSWORD_FILE",
    )
    identity_ldap_vendor: str = Field(default="ad", alias="IDENTITY_LDAP_VENDOR")
    identity_ldap_username_attribute: str = Field(
        default="sAMAccountName", alias="IDENTITY_LDAP_USERNAME_ATTRIBUTE"
    )
    identity_ldap_rdn_attribute: str = Field(
        default="cn", alias="IDENTITY_LDAP_RDN_ATTRIBUTE"
    )
    identity_ldap_uuid_attribute: str = Field(
        default="objectGUID", alias="IDENTITY_LDAP_UUID_ATTRIBUTE"
    )
    identity_ldap_user_object_classes: str = Field(
        default="person, organizationalPerson, user",
        alias="IDENTITY_LDAP_USER_OBJECT_CLASSES",
    )
    identity_ldap_user_filter: str = Field(
        default="", alias="IDENTITY_LDAP_USER_FILTER"
    )

    # Keycloak client authentication for the anthropic-token-broker client
    # is private_key_jwt (RFC 7523) with a Vault-PKI-issued key — NO static
    # client secret (docs/anthropic-wif-bootstrap.md Phase 0 step 2).
    # The signing key is loaded from a mounted PEM file if
    # KC_CLIENT_ASSERTION_KEY_FILE is set, otherwise from Vault KV v2 at
    # KC_CLIENT_ASSERTION_KEY_VAULT_PATH (fields: private_key_pem,
    # optional kid).
    kc_client_assertion_key_file: str = Field(
        default="", alias="KC_CLIENT_ASSERTION_KEY_FILE"
    )
    kc_client_assertion_key_vault_path: str = Field(
        default="ai-gateway/anthropic-wif-client-key",
        alias="KC_CLIENT_ASSERTION_KEY_VAULT_PATH",
    )
    # DEV ESCAPE HATCH ONLY: allow falling back to a static kc_client_secret
    # from the Vault bootstrap doc. Defaults off; enabling it logs an ERROR
    # on every token request. Never enable in production.
    anthropic_wif_allow_insecure_client_secret: bool = Field(
        default=False, alias="ANTHROPIC_WIF_ALLOW_INSECURE_CLIENT_SECRET"
    )

    # JWKS-rotation watcher (docs/anthropic-wif-bootstrap.md Phase 1a):
    # how often to poll the Keycloak realm JWKS for drift vs. what was last
    # pushed to the Anthropic federation issuer.
    jwks_watch_interval_seconds: int = Field(
        default=300, alias="JWKS_WATCH_INTERVAL_SECONDS"
    )

    # OpenAI orphaned-credential cleanup pass: how often to retry deleting /
    # verifying revocation of service accounts left behind by a rotation
    # whose old-account teardown failed.
    openai_orphan_cleanup_interval_seconds: int = Field(
        default=3600, alias="OPENAI_ORPHAN_CLEANUP_INTERVAL_SECONDS"
    )

    # Direct Keycloak ADM-console mutations are intentionally possible for
    # break-glass administration.  Reconcile portal-issued static LiteLLM
    # keys against live managed-project membership on this bounded cadence so
    # an out-of-band removal is eventually revoked without trusting a stale
    # browser/OIDC claim.
    portal_key_reconcile_interval_seconds: int = Field(
        default=60,
        ge=60,
        le=86400,
        alias="PORTAL_KEY_RECONCILE_INTERVAL_SECONDS",
    )

    # OTel collector (Grafana Alloy) — OTLP HTTP/protobuf, docs/solution-map.md §1.8.
    otel_exporter_otlp_endpoint: str = Field(
        default="http://alloy:4318", alias="OTEL_EXPORTER_OTLP_ENDPOINT"
    )

    # Pinned egress forward proxy (Envoy). All Anthropic/OpenAI calls route
    # through path-based mappings on this base URL — see anthropic_base /
    # openai_base below.
    egress_base: str = Field(default="http://envoy-egress:8080", alias="EGRESS_BASE")

    # REQUIRED shared-secret header check (X-Internal-Auth). The service
    # fails closed: startup refuses to schedule anything and every request
    # (except /healthz) is rejected while this is unset or an obvious
    # placeholder — segmented internal network placement is defense-in-depth,
    # not the auth boundary.
    rotator_internal_token: str = Field(default="", alias="ROTATOR_INTERNAL_TOKEN")
    # Distinct least-privilege credential held by the user-facing portal.  It
    # authorizes only the live read of that subject's managed projects; it
    # cannot invoke rotation, bootstrap, user search, or membership mutation.
    portal_identity_token: str = Field(default="", alias="PORTAL_IDENTITY_TOKEN")

    @field_validator(
        "vault_addr",
        "litellm_url",
        "keycloak_url",
        "keycloak_public_url",
        "wif_keycloak_public_url",
        "otel_exporter_otlp_endpoint",
        "egress_base",
    )
    @classmethod
    def validate_service_urls(cls, value: str, info) -> str:
        # Every configured value above is used as a bare origin and has
        # paths appended by this service. Reject ambiguous URL forms early.
        _parse_service_url(value, field_name=info.field_name, base_only=True)
        return value.rstrip("/")

    @field_validator(
        "keycloak_bootstrap_admin_client_id",
        "keycloak_bootstrap_admin_username",
        "break_glass_admin_username",
        "break_glass_admin_group",
        "identity_realm",
        "identity_managed_root_group",
        "identity_controller_client_id",
        "wif_realm",
        "wif_broker_client_id",
    )
    @classmethod
    def validate_identity_names(cls, value: str, info) -> str:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value):
            raise ValueError(f"{info.field_name} contains unsupported characters")
        return value

    @model_validator(mode="after")
    def validate_break_glass_admin_boundary(self) -> "Settings":
        """Refuse break-glass configuration that collides with teardown.

        Bootstrap teardown looks up the temporary administrator by the exact
        bootstrap username and hard-fails on an unmarked match, so a durable
        break-glass user sharing that name would brick every idempotent
        bootstrap re-run. The collision is refused even while the feature is
        disabled: the names are deployment contract, not runtime state.
        """
        if self.break_glass_admin_username == self.keycloak_bootstrap_admin_username:
            raise ValueError(
                "BREAK_GLASS_ADMIN_USERNAME must differ from "
                "KC_BOOTSTRAP_ADMIN_USERNAME"
            )
        if self.admin_realm_ldap_enabled:
            raise ValueError(
                "ADMIN_REALM_LDAP_ENABLED is reserved and not implemented; "
                "master-realm administrators are the Vault-escrowed "
                "break-glass user until the directory overlay ships"
            )
        # The five identity Vault paths must be pairwise distinct. An aliased
        # escrow path is silently destructive: bootstrap overwrites the state
        # and key documents after the escrows are written, and the
        # ai-gateway/anthropic-wif enrollment record is the one rotator path
        # whose policy permits deletion — an escrow parked there could be
        # permanently destroyed by the provider teardown flow.
        identity_paths = {
            "IDENTITY_CONTROLLER_KEY_VAULT_PATH": (
                self.identity_controller_key_vault_path
            ),
            "IDENTITY_STATE_VAULT_PATH": self.identity_state_vault_path,
            "KC_CLIENT_ASSERTION_KEY_VAULT_PATH": (
                self.kc_client_assertion_key_vault_path
            ),
            "BREAK_GLASS_ADMIN_VAULT_PATH": self.break_glass_admin_vault_path,
            "VAULT_OIDC_RP_VAULT_PATH": self.vault_oidc_rp_vault_path,
        }
        if len(set(identity_paths.values())) != len(identity_paths):
            raise ValueError(
                "identity Vault paths must be pairwise distinct: "
                + ", ".join(sorted(identity_paths))
            )
        for alias, value in identity_paths.items():
            for reserved in ("ai-gateway/anthropic-wif",):
                if value == reserved or value.startswith(reserved + "/"):
                    raise ValueError(
                        f"{alias} must not alias the deletable reserved "
                        f"record {reserved}"
                    )
        return self

    @field_validator("aigw_domain")
    @classmethod
    def validate_aigw_domain(cls, value: str) -> str:
        if (
            len(value) > 253
            or re.fullmatch(
                r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
                value,
            )
            is None
        ):
            raise ValueError("AIGW_DOMAIN is not a canonical lowercase DNS name")
        return value

    @field_validator(
        "identity_controller_key_vault_path",
        "identity_state_vault_path",
        "break_glass_admin_vault_path",
        "vault_oidc_rp_vault_path",
    )
    @classmethod
    def validate_identity_vault_paths(cls, value: str, info) -> str:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./-]{0,254}", value):
            raise ValueError(f"{info.field_name} is not a safe Vault KV path")
        if ".." in value.split("/") or value.endswith("/"):
            raise ValueError(f"{info.field_name} must be a canonical Vault KV path")
        return value

    @field_validator("lab_samba_ldap_url")
    @classmethod
    def validate_lab_ldap_url(cls, value: str) -> str:
        return _validate_ldaps_origin(value, "LAB_SAMBA_LDAP_URL")

    @field_validator(
        "lab_samba_users_dn",
        "lab_samba_bind_dn",
        "identity_ldap_users_dn",
        "identity_ldap_bind_dn",
    )
    @classmethod
    def validate_lab_dns(cls, value: str, info) -> str:
        # The external directory DNs are empty when the feature is disabled;
        # validate_ldap_federation_boundary enforces non-empty when enabled.
        if not value and info.field_name.startswith("identity_ldap"):
            return value
        if not value or len(value) > 512 or any(ord(ch) < 32 for ch in value):
            raise ValueError(f"{info.field_name} is invalid")
        if not value.upper().startswith(("CN=", "OU=")) or "DC=" not in value.upper():
            raise ValueError(f"{info.field_name} must be an explicit LDAP DN")
        return value

    @field_validator(
        "lab_samba_bind_password_file", "identity_ldap_bind_password_file"
    )
    @classmethod
    def validate_lab_bind_password_file(cls, value: str, info) -> str:
        if not re.fullmatch(r"/run/secrets/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value):
            raise ValueError(
                f"{info.field_name} must name a file under /run/secrets"
            )
        return value

    @model_validator(mode="after")
    def validate_ldap_federation_boundary(self) -> "Settings":
        """Fail closed on any ambiguous or unsafe directory federation input.

        Exactly one LDAP federation source may be enabled: the lab Samba
        overlay and the production external directory would otherwise contend
        for the Keycloak truststore and the same reconciliation inputs.
        """
        if self.identity_ldap_enabled and self.lab_samba_ldap_enabled:
            raise ValueError("exactly one LDAP federation source may be enabled")
        if not self.identity_ldap_enabled:
            return self

        for field_name, alias in (
            ("identity_ldap_provider_name", "IDENTITY_LDAP_PROVIDER_NAME"),
            ("identity_ldap_url", "IDENTITY_LDAP_URL"),
            ("identity_ldap_users_dn", "IDENTITY_LDAP_USERS_DN"),
            ("identity_ldap_bind_dn", "IDENTITY_LDAP_BIND_DN"),
            ("identity_ldap_user_filter", "IDENTITY_LDAP_USER_FILTER"),
        ):
            if not getattr(self, field_name):
                raise ValueError(f"{alias} is required when IDENTITY_LDAP_ENABLED")

        url = _validate_ldaps_origin(self.identity_ldap_url, "IDENTITY_LDAP_URL")
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower()
        # An IP literal makes certificate hostname verification meaningless, so
        # the directory origin must be a real FQDN covered by the DC's SANs.
        if (
            _LDAP_FQDN_RE.fullmatch(host) is None
            or _IPV4_LITERAL_RE.fullmatch(host) is not None
        ):
            raise ValueError("IDENTITY_LDAP_URL must name a directory FQDN")
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("IDENTITY_LDAP_URL contains an invalid port") from exc
        if port not in (None, 636):
            raise ValueError("IDENTITY_LDAP_URL must use the standard LDAPS port 636")

        if _LDAP_PROVIDER_NAME_RE.fullmatch(self.identity_ldap_provider_name) is None:
            raise ValueError("IDENTITY_LDAP_PROVIDER_NAME contains unsupported characters")
        if self.identity_ldap_provider_name == LAB_LDAP_PROVIDER_NAME:
            raise ValueError(
                "IDENTITY_LDAP_PROVIDER_NAME must not reuse the reserved lab "
                "federation provider name"
            )

        if self.identity_ldap_vendor not in {"ad", "rhds", "other"}:
            raise ValueError("IDENTITY_LDAP_VENDOR is not a supported directory vendor")
        for field_name, alias in (
            ("identity_ldap_username_attribute", "IDENTITY_LDAP_USERNAME_ATTRIBUTE"),
            ("identity_ldap_rdn_attribute", "IDENTITY_LDAP_RDN_ATTRIBUTE"),
            ("identity_ldap_uuid_attribute", "IDENTITY_LDAP_UUID_ATTRIBUTE"),
        ):
            if _LDAP_ATTRIBUTE_RE.fullmatch(getattr(self, field_name)) is None:
                raise ValueError(f"{alias} is not a bounded LDAP attribute name")
        if (
            _LDAP_OBJECT_CLASSES_RE.fullmatch(self.identity_ldap_user_object_classes)
            is None
        ):
            raise ValueError(
                "IDENTITY_LDAP_USER_OBJECT_CLASSES is not a bounded object-class list"
            )

        user_filter = self.identity_ldap_user_filter
        if (
            len(user_filter) > 512
            or not user_filter.startswith("(")
            or not user_filter.endswith(")")
            or _LDAP_FILTER_RE.fullmatch(user_filter) is None
            or not _is_single_ldap_group(user_filter)
        ):
            raise ValueError("IDENTITY_LDAP_USER_FILTER is not a bounded LDAP filter")
        return self

    @staticmethod
    def _token_ok(value: str) -> bool:
        token = value.strip()
        if len(token) < 16:
            return False
        lowered = token.lower()
        if lowered in _PLACEHOLDER_TOKENS:
            return False
        if any(sub in lowered for sub in _PLACEHOLDER_SUBSTRINGS):
            return False
        if any(lowered.startswith(pre) for pre in _PLACEHOLDER_PREFIXES):
            return False
        return True

    def internal_token_ok(self) -> bool:
        """True iff ROTATOR_INTERNAL_TOKEN is a non-placeholder credential.

        Placeholder rejection is substring/prefix-based, not just an exact
        set match: the shipped ansible default "dev-rotator-token-change-me"
        is long enough and not in the exact set, but contains "change-me"
        and starts with "dev-", so it must still be rejected. Fail closed.
        """
        return self._token_ok(self.rotator_internal_token)

    def portal_token_ok(self) -> bool:
        return self._token_ok(self.portal_identity_token) and not hmac.compare_digest(
            self.portal_identity_token.strip().encode(),
            self.rotator_internal_token.strip().encode(),
        )

    def bootstrap_admin_secret_ok(self) -> bool:
        """Whether a usable one-time bootstrap service secret is present."""
        token = self.keycloak_bootstrap_admin_client_secret.strip()
        if len(token) < 32:
            return False
        lowered = token.lower()
        if lowered in _PLACEHOLDER_TOKENS:
            return False
        if any(sub in lowered for sub in _PLACEHOLDER_SUBSTRINGS):
            return False
        if any(lowered.startswith(pre) for pre in _PLACEHOLDER_PREFIXES):
            return False
        return True

    def relying_party_secrets_ok(self) -> bool:
        values = (
            self.webui_oidc_client_secret,
            self.portal_oidc_client_secret,
            self.admin_portal_oidc_client_secret,
            self.oauth2_proxy_client_secret,
            self.vault_oidc_client_secret,
        )
        normalized = tuple(value.strip() for value in values)
        return (
            len(set(normalized)) == len(normalized)
            and all(self._token_ok(value) and len(value) >= 32 for value in normalized)
        )

    def validated_keycloak_token_url(self, value: str) -> str:
        """Return a Vault-provided Keycloak token URL only if it is confined
        to the configured Keycloak origin and canonical OIDC token path.

        ``kc_token_url`` is bootstrap data in Vault. Without this check, a
        compromised or accidentally over-broad Vault writer can turn the
        token exchange and JWKS watcher into SSRF and, when the explicit
        static-secret escape hatch is enabled, exfiltrate that client secret.
        """
        candidate = _parse_service_url(value, field_name="kc_token_url", base_only=False)
        expected = _parse_service_url(
            self.keycloak_url, field_name="keycloak_url", base_only=True
        )
        if _origin(candidate) != _origin(expected):
            raise ValueError("kc_token_url must use the configured KEYCLOAK_URL origin")

        suffix = "/protocol/openid-connect/token"
        path = candidate.path.rstrip("/")
        if not path.startswith("/realms/") or not path.endswith(suffix):
            raise ValueError(
                "kc_token_url must be a /realms/<realm>/protocol/openid-connect/token path"
            )
        realm = path[len("/realms/") : -len(suffix)]
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", realm):
            raise ValueError("kc_token_url contains an invalid realm path segment")
        return candidate.geturl()

    def keycloak_assertion_audience(self, realm: str) -> str:
        """Canonical token audience for a realm, separate from transport."""
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", realm):
            raise ValueError("Keycloak assertion realm is invalid")
        base = (
            self.wif_keycloak_public_url
            if realm == self.wif_realm
            else self.keycloak_public_url
        )
        return f"{base}/realms/{realm}/protocol/openid-connect/token"

    def keycloak_assertion_audience_for_token_url(self, value: str) -> str:
        """Map a validated internal token URL to its canonical public aud."""
        internal_url = self.validated_keycloak_token_url(value)
        path = urlsplit(internal_url).path.rstrip("/")
        suffix = "/protocol/openid-connect/token"
        realm = path[len("/realms/") : -len(suffix)]
        return self.keycloak_assertion_audience(realm)

    @property
    def anthropic_base(self) -> str:
        """Anthropic API, routed through the pinned egress proxy.

        {EGRESS_BASE}/anthropic/... maps to https://api.anthropic.com/...
        at envoy-egress. Never call api.anthropic.com directly.
        """
        return f"{self.egress_base.rstrip('/')}/anthropic"

    @property
    def openai_base(self) -> str:
        """OpenAI API, routed through the pinned egress proxy.

        {EGRESS_BASE}/openai/... maps to https://api.openai.com/... at
        envoy-egress. Never call api.openai.com directly.
        """
        return f"{self.egress_base.rstrip('/')}/openai"


@lru_cache
def get_settings() -> Settings:
    """Cached Settings singleton (env vars don't change at runtime)."""
    return Settings()
