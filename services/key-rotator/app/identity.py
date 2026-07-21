"""Keycloak identity administration behind the ADM-only portal.

The browser and dev-portal never receive a Keycloak administration credential
or a private key.  The rotator consumes Keycloak's one-time temporary bootstrap
service account, creates a narrower private_key_jwt controller, stores that
controller key in Vault, and deletes the temporary master-realm client.  All
ongoing group operations are constrained to children of one managed root and
to users imported from the configured LDAP federation component.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import re
import secrets
import stat
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx
import jwt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from app.config import Settings
from app.security import (
    path_segment,
    service_account_subject,
    validate_wif_token_claims,
)

logger = logging.getLogger("key_rotator.identity")

# aigw-chat is the DEDICATED Open WebUI chat capability (aigw-users no
# longer gates chat and is retained only for existing assignments).
CAPABILITY_ROLES = frozenset(
    {"aigw-users", "aigw-developers", "aigw-admins", "aigw-chat"}
)
# These are the only browser-facing OIDC clients managed by this controller.
# Keep this explicit rather than deriving it from a Keycloak search result: a
# temporary bootstrap administrator is intentionally powerful, so a recovery
# reconciliation must never broaden to an operator-created client.
RELYING_PARTY_CLIENT_IDS = (
    "open-webui",
    "dev-portal",
    "admin-portal",
    "admin-ui",
    "vault",
)
# Vault's own OIDC login (auth/oidc) authenticates against this confidential
# client. Vault cannot read Compose environment, so the reconciled secret is
# escrowed to VAULT_OIDC_RP_VAULT_PATH for the root-token ceremony
# scripts/vault-oidc-setup.sh — the same custody model as the break-glass
# administrator credential.
VAULT_RP_CLIENT_ID = "vault"
VAULT_OIDC_RP_SCHEMA = 1
CONTROLLER_ADMIN_ROLES = (
    "manage-users",
    "query-groups",
    "query-users",
    # Group capability assignment must resolve the allow-listed realm roles
    # before mapping them. This read-only realm permission does not permit
    # creating, changing, or deleting realm roles or clients.
    "view-realm",
    "view-users",
)
CONTROLLER_KEY_SCHEMA = 1
IDENTITY_STATE_SCHEMA = 1
MAX_KEYSTORE_BYTES = 1024 * 1024
MAX_KEY_PEM_BYTES = 32 * 1024
MAX_PAGE_COUNT = 100
PAGE_SIZE = 100
PRE_VAULT_IDENTITY_SCHEMA = 1
MAX_PRE_VAULT_BASELINE_GROUPS = 32
MAX_PRE_VAULT_BOOTSTRAP_IDENTITIES = 16
# The pre-Vault reconcile fires the instant the Keycloak *container* reports
# health-green, but the admin REST API can still lag a freshly-imported realm
# by a few seconds. Bound the retry well under any caller's timeout: worst
# case is 7 sleeps of 0.5, 1, 2, 4, 4, 4, 4 seconds (~19.5s) plus 8 bounded
# HTTP attempts.
BOOTSTRAP_TOKEN_MAX_ATTEMPTS = 8
BOOTSTRAP_TOKEN_INITIAL_DELAY_SECONDS = 0.5
BOOTSTRAP_TOKEN_MAX_DELAY_SECONDS = 4.0
# A managed Keycloak group is the project security boundary.  Its direct-child
# name is therefore the canonical project identifier copied into LiteLLM key
# metadata and audit records.  Lowercase-only prevents case-fold collisions
# across Keycloak, PostgreSQL, log queries, and filesystem/tool configuration.
PROJECT_ID_RE = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}")
# Per-project issuance policy lives as attributes ON the managed project
# group, exactly like the other durable markers this controller owns
# (aigw.managed-root, aigw.managed-admin-group). The group IS the project
# security boundary, so its policy travels with the same object that grants
# membership — no second store to drift.
POLICY_TPM_ATTRIBUTE = "aigw.policy.tpm_limit"
POLICY_RPM_ATTRIBUTE = "aigw.policy.rpm_limit"
POLICY_MODELS_ATTRIBUTE = "aigw.policy.allowed_models"
POLICY_DEFAULT_MODEL_ATTRIBUTE = "aigw.policy.default_model"
POLICY_ATTRIBUTES = frozenset(
    {
        POLICY_TPM_ATTRIBUTE,
        POLICY_RPM_ATTRIBUTE,
        POLICY_MODELS_ATTRIBUTE,
        POLICY_DEFAULT_MODEL_ATTRIBUTE,
    }
)
MODEL_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_./:-]{0,127}")
MAX_POLICY_MODELS = 32
POLICY_LIMIT_MAX = 1_000_000_000
# The dedicated Open WebUI chat gate role. Open WebUI's OAUTH_ALLOWED_ROLES is
# pinned to exactly this role, so a realm that lacks it (or a client that does
# not map it) silently 403s every non-admin chat login.
CHAT_CAPABILITY_ROLE = "aigw-chat"
BOOTSTRAP_IDENTITY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}")
FEDERATION_PROVIDER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_. -]{0,127}")
MANAGED_ROOT_ATTRIBUTE = "aigw.managed-root"
# Durable master-realm administration objects are marked like the managed
# root: automation only ever adopts or mutates an object it provably owns.
MANAGED_ADMIN_GROUP_ATTRIBUTE = "aigw.managed-admin-group"
BREAK_GLASS_ATTRIBUTE = "aigw.break-glass"
BREAK_GLASS_SCHEMA = 1
# Master's built-in composite role. The break-glass group is the instance
# recovery principal: repairing a broken federation, the WIF realm, or the
# bootstrap client requires cross-realm authority that only master-realm
# principals can hold, so a fine-grained subset would defeat its purpose.
MASTER_ADMIN_ROLE = "admin"
# Pinned password-spray policy, value-equal to KEYCLOAK_POLICY in
# scripts/validate-identity-policy.py (that validator asserts the parity).
# Only the two imported realm files carry the policy via --import-realm; the
# master realm is never file-imported, so without this reconcile it runs with
# Keycloak's default (brute-force detection OFF) — untenable once master
# holds a password-backed break-glass administrator.
MASTER_BRUTE_FORCE_POLICY: dict[str, Any] = {
    "bruteForceProtected": True,
    "permanentLockout": False,
    "maxTemporaryLockouts": 0,
    "bruteForceStrategy": "MULTIPLE",
    "failureFactor": 5,
    "waitIncrementSeconds": 60,
    "quickLoginCheckMilliSeconds": 1000,
    "minimumQuickLoginWaitSeconds": 60,
    "maxFailureWaitSeconds": 900,
    "maxDeltaTimeSeconds": 43200,
}
# Keycloak 26.7 EventType names reviewed for the SOC authentication feed.
# Keep this tuple sorted and identical to both realm imports. The dynamic
# reconcile is required because --import-realm skips an existing database.
KEYCLOAK_SECURITY_EVENT_TYPES = (
    "CLIENT_LOGIN",
    "CLIENT_LOGIN_ERROR",
    "CODE_TO_TOKEN",
    "CODE_TO_TOKEN_ERROR",
    "IDENTITY_PROVIDER_FIRST_LOGIN",
    "IDENTITY_PROVIDER_FIRST_LOGIN_ERROR",
    "IDENTITY_PROVIDER_LOGIN",
    "IDENTITY_PROVIDER_LOGIN_ERROR",
    "IDENTITY_PROVIDER_POST_LOGIN",
    "IDENTITY_PROVIDER_POST_LOGIN_ERROR",
    "IMPERSONATE",
    "IMPERSONATE_ERROR",
    "LOGIN",
    "LOGIN_ERROR",
    "LOGOUT",
    "LOGOUT_ERROR",
    "REFRESH_TOKEN",
    "REFRESH_TOKEN_ERROR",
    "USER_DISABLED_BY_PERMANENT_LOCKOUT",
    "USER_DISABLED_BY_PERMANENT_LOCKOUT_ERROR",
    "USER_DISABLED_BY_TEMPORARY_LOCKOUT",
    "USER_DISABLED_BY_TEMPORARY_LOCKOUT_ERROR",
)
KEYCLOAK_SECURITY_EVENT_REALMS = ("master", "aigw", "anthropic-wif")
BROKER_SUBJECT_MAPPER_NAME = "anthropic-stable-subject"
@dataclass(frozen=True)
class LdapFederationSpec:
    """The one resolved directory federation source for this deployment."""

    provider_name: str
    connection_url: str
    users_dn: str
    bind_dn: str
    bind_password_file: str
    vendor: str
    username_attribute: str
    rdn_attribute: str
    uuid_attribute: str
    user_object_classes: str
    user_filter: str
def ldap_federation_spec(settings: Settings) -> LdapFederationSpec | None:
    """Resolve the inventory-owned production directory, or None."""
    if settings.identity_ldap_enabled:
        return LdapFederationSpec(
            provider_name=settings.identity_ldap_provider_name,
            connection_url=settings.identity_ldap_url,
            users_dn=settings.identity_ldap_users_dn,
            bind_dn=settings.identity_ldap_bind_dn,
            bind_password_file=settings.identity_ldap_bind_password_file,
            vendor=settings.identity_ldap_vendor,
            username_attribute=settings.identity_ldap_username_attribute,
            rdn_attribute=settings.identity_ldap_rdn_attribute,
            uuid_attribute=settings.identity_ldap_uuid_attribute,
            user_object_classes=settings.identity_ldap_user_object_classes,
            user_filter=settings.identity_ldap_user_filter,
        )
    return None


class IdentityError(RuntimeError):
    """Safe, non-secret identity-control failure."""


class IdentityNotFound(IdentityError):
    pass


class IdentityConflict(IdentityError):
    pass


class TransientIdentityError(IdentityError):
    """A transient Keycloak-side failure (a 5xx / server error).

    Distinct from a semantic refusal so a caller that must not mistake a network
    blip or server error for a definitive answer can fail loudly instead of
    drawing a wrong conclusion. It is a subclass of :class:`IdentityError`, so
    every existing ``except IdentityError`` still catches it unchanged; only a
    handler that explicitly distinguishes it (the prebootstrap OIDC
    redirect-URI reconcile, which otherwise reads a definitive refusal as "the
    temporary bootstrap client was consumed") behaves differently.
    """


PortalKeyRevoker = Callable[[str, str], Awaitable[None]]


class KeycloakAdmin:
    def __init__(
        self,
        settings: Settings,
        vault: Any,
        db: Any,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        portal_key_revoker: PortalKeyRevoker | None = None,
    ) -> None:
        self.settings = settings
        self.vault = vault
        self.db = db
        self._transport = transport
        # LiteLLM virtual keys are static bearer credentials.  The identity
        # controller is therefore the authoritative removal path and must
        # prove revocation before it removes a managed-project membership.
        # Production wires this to LiteLLMClient.revoke_portal_project_keys;
        # retaining an optional constructor parameter keeps the HTTP boundary
        # testable without smuggling the LiteLLM master key into this module.
        self._portal_key_revoker = portal_key_revoker
        self._bootstrap_lock = asyncio.Lock()
        # One topology lock covers every managed-group mutation. Protecting
        # only removal left a last-admin TOCTOU: an empty admin group could be
        # checked for deletion, receive a member while a separate removal saw
        # that member as the recovery admin, and then be deleted, leaving no
        # managed administrator. The deployed service is deliberately one
        # process/worker; a scaled profile must replace this with a distributed
        # fenced lock before admitting multiple writers.
        self._group_topology_lock = asyncio.Lock()

    async def _request(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        form: dict[str, str] | None = None,
        expected: tuple[int, ...] = (200, 201, 204),
    ) -> httpx.Response:
        if not path.startswith("/") or "\\" in path or any(ord(c) < 32 for c in path):
            raise IdentityError("refusing an invalid Keycloak request path")
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        async with httpx.AsyncClient(
            base_url=self.settings.keycloak_url,
            timeout=20.0,
            trust_env=False,
            follow_redirects=False,
            transport=self._transport,
        ) as client:
            response = await client.request(
                method,
                path,
                headers=headers,
                params=params,
                json=json_body,
                data=form,
            )
        if response.status_code not in expected:
            # Keycloak error bodies can echo DNs, usernames, or credential
            # configuration. Keep those out of portal errors and telemetry.
            detail = (
                f"Keycloak rejected {method.upper()} {path} "
                f"(HTTP {response.status_code})"
            )
            if 500 <= response.status_code < 600:
                # A 5xx is a transient server-side failure, never a definitive
                # semantic answer. Surface it as the transient subclass so a
                # caller that must not confuse it with a genuine refusal (e.g. a
                # deleted bootstrap client) can fail loudly rather than draw a
                # wrong conclusion.
                raise TransientIdentityError(detail)
            raise IdentityError(detail)
        return response

    @staticmethod
    def _json(response: httpx.Response, label: str) -> Any:
        try:
            return response.json()
        except (TypeError, ValueError) as exc:
            raise IdentityError(f"Keycloak returned invalid JSON for {label}") from exc

    async def _bootstrap_token(self) -> str:
        if not self.settings.bootstrap_admin_secret_ok():
            raise IdentityConflict(
                "the one-time Keycloak bootstrap controller is unavailable or consumed"
            )
        delay = BOOTSTRAP_TOKEN_INITIAL_DELAY_SECONDS
        for attempt in range(1, BOOTSTRAP_TOKEN_MAX_ATTEMPTS + 1):
            try:
                response = await self._request(
                    "POST",
                    "/realms/master/protocol/openid-connect/token",
                    form={
                        "grant_type": "client_credentials",
                        "client_id": self.settings.keycloak_bootstrap_admin_client_id,
                        "client_secret": self.settings.keycloak_bootstrap_admin_client_secret,
                    },
                    expected=(200,),
                )
            except (TransientIdentityError, httpx.TransportError):
                # Only a network-level failure to reach Keycloak or a 5xx
                # (``_request`` already classifies those, never a semantic
                # answer, as TransientIdentityError) is worth retrying: they
                # are exactly what a container that is health-green but whose
                # admin REST API has not finished coming up after a
                # freshly-imported realm looks like. A 4xx (bad client_id /
                # client_secret) is a definitive credential refusal and must
                # propagate on the first attempt, not be retried into a
                # slower, quieter failure.
                if attempt == BOOTSTRAP_TOKEN_MAX_ATTEMPTS:
                    raise
                await asyncio.sleep(delay)
                delay = min(delay * 2, BOOTSTRAP_TOKEN_MAX_DELAY_SECONDS)
                continue
            payload = self._json(response, "bootstrap token")
            token = payload.get("access_token") if isinstance(payload, dict) else None
            if not isinstance(token, str) or not token:
                raise IdentityError("Keycloak did not issue a bootstrap access token")
            return token
        # Unreachable: the loop above always returns or raises before falling
        # off the end (the final attempt re-raises instead of continuing).
        raise IdentityError("Keycloak did not issue a bootstrap access token")

    @staticmethod
    def _private_key_assertion(
        client_id: str, token_url: str, key_doc: dict[str, Any]
    ) -> str:
        pem = key_doc.get("private_key_pem")
        if not isinstance(pem, str) or not pem or len(pem.encode()) > MAX_KEY_PEM_BYTES:
            raise IdentityError(
                "the private_key_jwt key in Vault is missing or invalid"
            )
        now = int(time.time())
        headers: dict[str, str] = {}
        kid = key_doc.get("kid")
        if isinstance(kid, str) and kid:
            headers["kid"] = kid
        return jwt.encode(
            {
                "iss": client_id,
                "sub": client_id,
                "aud": token_url,
                "iat": now,
                "exp": now + 60,
                "jti": str(uuid.uuid4()),
            },
            pem,
            algorithm="RS256",
            headers=headers or None,
        )

    async def _client_credentials_with_key(
        self, realm: str, client_id: str, key_doc: dict[str, Any]
    ) -> str:
        safe_realm = path_segment(realm, label="Keycloak realm")
        token_path = f"/realms/{safe_realm}/protocol/openid-connect/token"
        token_audience = self.settings.keycloak_assertion_audience(safe_realm)
        assertion = self._private_key_assertion(client_id, token_audience, key_doc)
        response = await self._request(
            "POST",
            token_path,
            form={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_assertion_type": (
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                ),
                "client_assertion": assertion,
            },
            expected=(200,),
        )
        payload = self._json(response, "client credentials token")
        token = payload.get("access_token") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token:
            raise IdentityError("Keycloak did not issue a client credentials token")
        return token

    async def _controller_token(self) -> str:
        try:
            key_doc = self.vault.read(self.settings.identity_controller_key_vault_path)
        except Exception as exc:  # noqa: BLE001
            raise IdentityError("could not read the identity controller key") from exc
        if not isinstance(key_doc, dict):
            raise IdentityConflict("identity setup has not been completed")
        return await self._client_credentials_with_key(
            self.settings.identity_realm,
            self.settings.identity_controller_client_id,
            key_doc,
        )

    async def _find_client(
        self, realm: str, client_id: str, admin_token: str
    ) -> dict[str, Any] | None:
        safe_realm = path_segment(realm, label="Keycloak realm")
        response = await self._request(
            "GET",
            f"/admin/realms/{safe_realm}/clients",
            token=admin_token,
            params={"clientId": client_id, "search": "true"},
            expected=(200,),
        )
        payload = self._json(response, "client lookup")
        if not isinstance(payload, list):
            raise IdentityError("Keycloak client lookup was not a list")
        matches = [
            c for c in payload if isinstance(c, dict) and c.get("clientId") == client_id
        ]
        if len(matches) > 1:
            raise IdentityConflict(f"multiple Keycloak clients are named {client_id}")
        return matches[0] if matches else None

    async def _create_client(
        self, realm: str, representation: dict[str, Any], admin_token: str
    ) -> dict[str, Any]:
        safe_realm = path_segment(realm, label="Keycloak realm")
        await self._request(
            "POST",
            f"/admin/realms/{safe_realm}/clients",
            token=admin_token,
            json_body=representation,
            expected=(201,),
        )
        found = await self._find_client(
            realm, str(representation["clientId"]), admin_token
        )
        if found is None:
            raise IdentityError(
                "Keycloak created a client but it could not be resolved"
            )
        return found

    async def _put_client(
        self, realm: str, client: dict[str, Any], admin_token: str
    ) -> None:
        client_uuid = path_segment(client.get("id"), label="Keycloak client UUID")
        safe_realm = path_segment(realm, label="Keycloak realm")
        await self._request(
            "PUT",
            f"/admin/realms/{safe_realm}/clients/{client_uuid}",
            token=admin_token,
            json_body=client,
            expected=(204,),
        )

    async def _get_client(
        self, realm: str, client: dict[str, Any], admin_token: str
    ) -> dict[str, Any]:
        """Fetch a fresh full representation before a mutating PUT.

        Key generation changes `jwt.credential.certificate` server-side. A
        subsequent PUT of the stale pre-generation representation silently
        restores the old public key and makes the new Vault private key
        unusable.
        """
        client_uuid = path_segment(client.get("id"), label="Keycloak client UUID")
        safe_realm = path_segment(realm, label="Keycloak realm")
        response = await self._request(
            "GET",
            f"/admin/realms/{safe_realm}/clients/{client_uuid}",
            token=admin_token,
            expected=(200,),
        )
        fresh = self._json(response, "Keycloak client")
        if not isinstance(fresh, dict) or fresh.get("id") != client_uuid:
            raise IdentityError("Keycloak returned an invalid client representation")
        return fresh

    @staticmethod
    def _realm_roles_mapper() -> dict[str, Any]:
        return {
            "name": "realm-roles-to-roles-claim",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-realm-role-mapper",
            "config": {
                "claim.name": "roles",
                "jsonType.label": "String",
                "multivalued": "true",
                "id.token.claim": "true",
                "access.token.claim": "true",
                "userinfo.token.claim": "true",
            },
        }

    @classmethod
    def _verify_realm_roles_mapper(cls, client: dict[str, Any], client_id: str) -> None:
        """Require exactly the managed role mapper after a Keycloak PUT.

        Keycloak accepts a client update with a 204 even when it normalizes or
        drops protocol mappers.  The mapper is the only reviewed path from the
        narrowly scoped realm roles to the browser-facing ``roles`` claim, so
        treating the client PUT as sufficient could leave every login
        successful but unauthorized.  Keycloak may add representation metadata
        such as ``id``; all security-relevant mapper fields must still match
        exactly and no second mapper may remain.
        """

        mappers = client.get("protocolMappers")
        expected = cls._realm_roles_mapper()
        if not isinstance(mappers, list) or len(mappers) != 1:
            raise IdentityError(
                f"Keycloak did not verify OIDC client {client_id} role mapper"
            )
        mapper = mappers[0]
        if not isinstance(mapper, dict) or any(
            mapper.get(field) != expected[field]
            for field in ("name", "protocol", "protocolMapper", "config")
        ):
            raise IdentityError(
                f"Keycloak did not verify OIDC client {client_id} role mapper"
            )

    async def _capability_role_representations(
        self, realm: str, admin_token: str
    ) -> list[dict[str, Any]]:
        """Resolve the exact realm-role representations accepted by Keycloak.

        The scope-mapping API validates both the role name and the internal
        role ID.  Fetching the representations first avoids guessing IDs or
        sending a partial role object that a Keycloak upgrade could reject.
        """

        safe_realm = path_segment(realm, label="Keycloak realm")
        roles: list[dict[str, Any]] = []
        for role_name in sorted(CAPABILITY_ROLES):
            response = await self._request(
                "GET",
                f"/admin/realms/{safe_realm}/roles/{path_segment(role_name, label='capability role')}",
                token=admin_token,
                expected=(200,),
            )
            role = self._json(response, "capability role")
            if not isinstance(role, dict) or role.get("name") != role_name:
                raise IdentityError(f"capability role {role_name} is missing")
            # An ID-less object cannot be safely submitted to Keycloak's
            # mapping endpoint.  ``path_segment`` also bounds/control-checks
            # the server-returned value before it can be echoed elsewhere.
            path_segment(role.get("id"), label="capability role UUID")
            roles.append(role)
        return roles

    async def _client_realm_role_scope_mappings(
        self, realm: str, client: dict[str, Any], admin_token: str
    ) -> list[dict[str, Any]]:
        """Read and validate direct realm-role scope mappings for one client."""

        safe_realm = path_segment(realm, label="Keycloak realm")
        client_uuid = path_segment(client.get("id"), label="Keycloak client UUID")
        response = await self._request(
            "GET",
            f"/admin/realms/{safe_realm}/clients/{client_uuid}/scope-mappings/realm",
            token=admin_token,
            expected=(200,),
        )
        payload = self._json(response, "OIDC client realm-role scope mappings")
        if not isinstance(payload, list):
            raise IdentityError("Keycloak OIDC client scope mappings were invalid")
        roles: list[dict[str, Any]] = []
        seen_names: set[str] = set()
        for role in payload:
            name = role.get("name") if isinstance(role, dict) else None
            if not isinstance(name, str) or not name or name in seen_names:
                raise IdentityError("Keycloak OIDC client scope mappings were invalid")
            # A response is later used as the DELETE representation. Refuse a
            # partial/malformed role rather than reflecting it into a mutation.
            path_segment(role.get("id"), label="scoped realm role UUID")
            seen_names.add(name)
            roles.append(role)
        return roles

    async def _reconcile_client_realm_role_scope_mappings(
        self,
        realm: str,
        client: dict[str, Any],
        desired_roles: list[dict[str, Any]],
        admin_token: str,
        *,
        remove_extras: bool = True,
    ) -> bool:
        """Converge one OIDC client to only the three capability roles.

        ``fullScopeAllowed`` remains disabled, so Keycloak emits role claims
        only for explicit direct scope mappings.  Delete unexpected mappings
        before adding missing ones: a transient API failure then fails closed
        (temporary loss of a claim) rather than retaining an over-broad claim.
        """

        safe_realm = path_segment(realm, label="Keycloak realm")
        client_uuid = path_segment(client.get("id"), label="Keycloak client UUID")
        client_id = client.get("clientId")
        if client_id not in RELYING_PARTY_CLIENT_IDS:
            raise IdentityError("refusing to reconcile an unapproved OIDC client")
        if client.get("fullScopeAllowed") is not False:
            raise IdentityConflict(
                f"OIDC client {client_id} must retain fullScopeAllowed=false"
            )

        desired_by_name: dict[str, dict[str, Any]] = {}
        for role in desired_roles:
            name = role.get("name") if isinstance(role, dict) else None
            if not isinstance(name, str) or name not in CAPABILITY_ROLES:
                raise IdentityError(
                    "Keycloak capability role representation was invalid"
                )
            path_segment(role.get("id"), label="capability role UUID")
            if name in desired_by_name:
                raise IdentityError(
                    "Keycloak capability role representation was invalid"
                )
            desired_by_name[name] = role
        if set(desired_by_name) != CAPABILITY_ROLES:
            raise IdentityError(
                "Keycloak capability role representation was incomplete"
            )

        current_roles = await self._client_realm_role_scope_mappings(
            realm, client, admin_token
        )
        current_names = {str(role["name"]) for role in current_roles}
        endpoint = (
            f"/admin/realms/{safe_realm}/clients/{client_uuid}/scope-mappings/realm"
        )
        extras = [
            role for role in current_roles if str(role["name"]) not in CAPABILITY_ROLES
        ]
        changed = False
        if extras:
            if not remove_extras:
                raise IdentityConflict(
                    f"OIDC client {client_id} has unmanaged realm-role scope mappings"
                )
            await self._request(
                "DELETE",
                endpoint,
                token=admin_token,
                json_body=extras,
                expected=(204,),
            )
            changed = True
        missing = [
            desired_by_name[name]
            for name in sorted(CAPABILITY_ROLES)
            if name not in current_names
        ]
        if missing:
            await self._request(
                "POST",
                endpoint,
                token=admin_token,
                json_body=missing,
                expected=(204,),
            )
            changed = True

        verified_roles = await self._client_realm_role_scope_mappings(
            realm, client, admin_token
        )
        verified_by_name = {str(role["name"]): role for role in verified_roles}
        if (
            len(verified_roles) != len(CAPABILITY_ROLES)
            or set(verified_by_name) != CAPABILITY_ROLES
            or any(
                verified_by_name[name].get("id") != desired_by_name[name].get("id")
                for name in CAPABILITY_ROLES
            )
        ):
            raise IdentityError(
                f"Keycloak did not verify OIDC client {client_id} role scope mappings"
            )
        return changed

    async def _reconcile_relying_party_redirect_uris(self, admin_token: str) -> bool:
        """Converge ONLY the domain-derived callback allow-lists of the five
        managed first-party OIDC clients.

        A domain migration moves only the callback hostnames, so this is
        deliberately far narrower than :meth:`_ensure_relying_parties`: it
        rewrites only ``redirectUris`` / ``webOrigins`` (and the RP-initiated
        logout allow-list where the spec already manages it) and never disturbs
        confidential client credentials, flow flags, protocol mappers, realm
        role scope mappings, the durable controller, the WIF broker, Vault, or
        any client outside ``RELYING_PARTY_CLIENT_IDS``.  Each managed client is
        fetched fresh, mutated in place, PUT only when it drifts, then read back
        and verified before the next client.  Set-like URL lists are compared
        sorted so a harmless Keycloak response reordering is not mistaken for
        drift and cannot turn this into a churning privileged PUT.
        """

        realm = self.settings.identity_realm
        specs = {str(spec["clientId"]): spec for spec in self._relying_party_specs()}
        changed = False
        for client_id in RELYING_PARTY_CLIENT_IDS:
            desired = specs.get(client_id)
            if desired is None:
                raise IdentityError(f"missing managed OIDC client spec for {client_id}")
            found = await self._find_client(realm, client_id, admin_token)
            if found is None:
                raise IdentityError(f"OIDC client {client_id} is missing")
            current = await self._get_client(realm, found, admin_token)
            desired_redirects = list(desired["redirectUris"])
            desired_origins = list(desired["webOrigins"])
            desired_logout = desired["attributes"].get("post.logout.redirect.uris")
            needs_update = False
            for field, want in (
                ("redirectUris", desired_redirects),
                ("webOrigins", desired_origins),
            ):
                have = current.get(field)
                if not isinstance(have, list) or sorted(have) != sorted(want):
                    current[field] = want
                    needs_update = True
            # Only clients whose spec declares an RP-initiated logout
            # allow-list have that attribute managed here.  Never invent one on
            # a client that does not use it, and never disturb any other
            # operator- or Keycloak-owned attribute on the representation.
            if desired_logout is not None:
                attributes = dict(current.get("attributes") or {})
                if attributes.get("post.logout.redirect.uris") != desired_logout:
                    attributes["post.logout.redirect.uris"] = desired_logout
                    current["attributes"] = attributes
                    needs_update = True
            if needs_update:
                await self._put_client(realm, current, admin_token)
                changed = True

            verified = await self._get_client(realm, current, admin_token)
            if sorted(verified.get("redirectUris") or []) != sorted(
                desired_redirects
            ) or sorted(verified.get("webOrigins") or []) != sorted(desired_origins):
                raise IdentityError(
                    f"Keycloak did not verify OIDC client {client_id} URLs"
                )
            if desired_logout is not None:
                verified_attributes = verified.get("attributes")
                if (
                    not isinstance(verified_attributes, dict)
                    or verified_attributes.get("post.logout.redirect.uris")
                    != desired_logout
                ):
                    raise IdentityError(
                        f"Keycloak did not verify OIDC client {client_id} logout URLs"
                    )
        return changed

    async def _reconcile_wif_frontend_url(self, admin_token: str) -> bool:
        """Keep the isolated WIF issuer on this deployment's domain."""

        realm = path_segment(self.settings.wif_realm, label="WIF realm")
        desired = f"https://idp.wif.{self.settings.aigw_domain}"
        if self.settings.wif_keycloak_public_url != desired:
            raise IdentityConflict(
                "the WIF public URL does not match the configured AI Gateway domain"
            )

        response = await self._request(
            "GET",
            f"/admin/realms/{realm}",
            token=admin_token,
            expected=(200,),
        )
        current = self._json(response, "WIF realm representation")
        if not isinstance(current, dict) or current.get("realm") != self.settings.wif_realm:
            raise IdentityError("Keycloak returned an invalid WIF realm")
        raw_attributes = current.get("attributes")
        if raw_attributes is not None and not isinstance(raw_attributes, dict):
            raise IdentityConflict("the WIF realm attributes are invalid")
        attributes = dict(raw_attributes or {})
        changed = attributes.get("frontendUrl") != desired
        if changed:
            attributes["frontendUrl"] = desired
            updated = dict(current)
            updated["attributes"] = attributes
            await self._request(
                "PUT",
                f"/admin/realms/{realm}",
                token=admin_token,
                json_body=updated,
                expected=(204,),
            )

        verified_response = await self._request(
            "GET",
            f"/admin/realms/{realm}",
            token=admin_token,
            expected=(200,),
        )
        verified = self._json(verified_response, "verified WIF realm representation")
        verified_attributes = (
            verified.get("attributes") if isinstance(verified, dict) else None
        )
        if (
            not isinstance(verified_attributes, dict)
            or verified_attributes.get("frontendUrl") != desired
        ):
            raise IdentityError("Keycloak did not verify the WIF realm frontend URL")
        return changed

    async def _reconcile_security_event_logging(self, admin_token: str) -> bool:
        """Enable only the reviewed Keycloak user-event log contract.

        Realm imports apply only to an empty database. Every deployment also
        reads, updates, and verifies all three managed realms so an upgrade or
        brownfield converge cannot silently lose authentication events.
        """

        changed = False
        desired_types = list(KEYCLOAK_SECURITY_EVENT_TYPES)
        for realm_name in KEYCLOAK_SECURITY_EVENT_REALMS:
            realm = path_segment(realm_name, label="security event realm")
            path = f"/admin/realms/{realm}"
            current = self._json(
                await self._request(
                    "GET", path, token=admin_token, expected=(200,)
                ),
                "Keycloak security event realm",
            )
            if not isinstance(current, dict) or current.get("realm") != realm_name:
                raise IdentityError("Keycloak returned an invalid security event realm")
            desired = {
                "eventsEnabled": True,
                "eventsExpiration": 86400,
                "eventsListeners": ["jboss-logging"],
                "enabledEventTypes": desired_types,
                "adminEventsEnabled": False,
                "adminEventsDetailsEnabled": False,
            }
            if any(current.get(key) != value for key, value in desired.items()):
                updated = dict(current)
                updated.update(desired)
                await self._request(
                    "PUT",
                    path,
                    token=admin_token,
                    json_body=updated,
                    expected=(204,),
                )
                changed = True
            verified = self._json(
                await self._request(
                    "GET", path, token=admin_token, expected=(200,)
                ),
                "verified Keycloak security event realm",
            )
            if not isinstance(verified, dict) or any(
                verified.get(key) != value for key, value in desired.items()
            ):
                raise IdentityError(
                    "Keycloak did not verify the security event logging policy"
                )
        return changed

    async def reconcile_prebootstrap_relying_party_redirect_uris(self) -> str:
        """Realign managed OIDC callbacks to ``aigw_domain`` while bootstrap is
        still available, or fail closed toward the re-bootstrap ceremony.

        A domain migration on an existing realm leaves every first-party
        client's ``redirectUris`` / ``webOrigins`` pinned to the old domain,
        because Keycloak imports realm JSON only into an empty database.
        Browser SSO then fails with ``Invalid parameter: redirect_uri``.  This
        repair uses ONLY the already-reviewed temporary master-realm bootstrap
        client (``aigw-bootstrap-controller``); it grants no standing authority,
        and the durable post-bootstrap controller keeps no ``manage-clients``
        role, so it can never perform this from a routine converge.

        Returns one of ``"applied"`` (callbacks were realigned), ``"verified"``
        (already correct), or ``"rebootstrap_required"``.  The last is the
        fail-closed outcome for a host whose interactive bootstrap has already
        consumed the temporary client: this converge then holds no
        client-management authority, so a later domain change must be repaired
        by re-running the documented identity bootstrap ceremony rather than
        silently leaving SSO broken or crashing the converge.  The state is
        detected, never assumed.
        """

        if not self.settings.bootstrap_admin_secret_ok():
            return "rebootstrap_required"
        try:
            admin_token = await self._bootstrap_token()
        except TransientIdentityError:
            # A Keycloak 5xx at the token endpoint is a transient server-side
            # failure, NOT proof the temporary bootstrap client was consumed.
            # Failing closed to rebootstrap_required here would go GREEN with
            # stale SSO callbacks and misdirect the operator to re-run the
            # identity bootstrap when the real cause was a blip. Fail the
            # converge loudly instead so it is retried. (A connection error or
            # timeout is likewise not an IdentityError and already propagates
            # loudly past this handler.)
            raise
        except IdentityError:
            # The temporary master-realm client answered definitively that it no
            # longer exists / is unauthorized (e.g. 401 invalid_client): the
            # interactive bootstrap ceremony has consumed it. This routine
            # converge holds no client-management authority; report the required
            # operator ceremony instead of failing or falsely claiming success
            # while SSO stays broken. This is the designed non-fatal path.
            return "rebootstrap_required"
        changed = await self._reconcile_relying_party_redirect_uris(admin_token)
        return "applied" if changed else "verified"

    @staticmethod
    def _validate_pre_vault_identity_spec(
        spec: dict[str, Any],
    ) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
        """Validate the complete, inventory-owned pre-Vault mutation set.

        The temporary master-realm client is intentionally powerful.  This
        parser therefore rejects unknown fields and non-canonical values
        before obtaining its token.  It never derives groups or users from a
        Keycloak search result: every writable object must be named in the
        root-owned Ansible input.
        """

        if not isinstance(spec, dict) or set(spec) != {
            "schema",
            "groups",
            "bootstrap_admin_identities",
        }:
            raise IdentityConflict("pre-Vault identity specification is invalid")
        if spec.get("schema") != PRE_VAULT_IDENTITY_SCHEMA:
            raise IdentityConflict("pre-Vault identity specification schema is invalid")
        raw_groups = spec.get("groups")
        if (
            not isinstance(raw_groups, list)
            or not raw_groups
            or len(raw_groups) > MAX_PRE_VAULT_BASELINE_GROUPS
        ):
            raise IdentityConflict("pre-Vault baseline groups are invalid")
        groups: list[dict[str, Any]] = []
        group_roles: dict[str, frozenset[str]] = {}
        for raw in raw_groups:
            if not isinstance(raw, dict) or set(raw) != {"name", "roles"}:
                raise IdentityConflict("pre-Vault baseline group is invalid")
            name = raw.get("name")
            roles = raw.get("roles")
            if (
                not isinstance(name, str)
                or PROJECT_ID_RE.fullmatch(name) is None
                or name in group_roles
                or not isinstance(roles, list)
                or not roles
                or roles != sorted(set(roles))
                or not set(roles) <= CAPABILITY_ROLES
            ):
                raise IdentityConflict("pre-Vault baseline group is invalid")
            role_set = frozenset(roles)
            group_roles[name] = role_set
            groups.append({"name": name, "roles": list(roles)})

        raw_identities = spec.get("bootstrap_admin_identities")
        if (
            not isinstance(raw_identities, list)
            or not raw_identities
            or len(raw_identities) > MAX_PRE_VAULT_BOOTSTRAP_IDENTITIES
        ):
            raise IdentityConflict("pre-Vault bootstrap identities are invalid")
        identities: list[dict[str, str]] = []
        seen_users: set[str] = set()
        for raw in raw_identities:
            if not isinstance(raw, dict) or set(raw) != {
                "username",
                "group",
                "federation_provider",
            }:
                raise IdentityConflict("pre-Vault bootstrap identity is invalid")
            username = raw.get("username")
            group = raw.get("group")
            provider = raw.get("federation_provider")
            if (
                not isinstance(username, str)
                or BOOTSTRAP_IDENTITY_RE.fullmatch(username) is None
                or username in seen_users
                or not isinstance(group, str)
                or group not in group_roles
                # The bootstrap identity's group must be a pure admin gate:
                # aigw-admins is mandatory, and only the dedicated aigw-chat
                # capability may accompany it now that chat is its own
                # assignable capability granted to admin groups as well.
                or "aigw-admins" not in group_roles[group]
                or not group_roles[group] <= frozenset(
                    {"aigw-admins", CHAT_CAPABILITY_ROLE}
                )
                or not isinstance(provider, str)
                or FEDERATION_PROVIDER_RE.fullmatch(provider) is None
            ):
                raise IdentityConflict("pre-Vault bootstrap identity is invalid")
            seen_users.add(username)
            identities.append(
                {
                    "username": username,
                    "group": group,
                    "federation_provider": provider,
                }
            )
        return groups, identities

    async def _pre_vault_direct_child(
        self, root_id: str, group_name: str, admin_token: str
    ) -> dict[str, Any] | None:
        realm = path_segment(self.settings.identity_realm, label="Keycloak realm")
        safe_root = path_segment(root_id, label="managed root UUID")
        response = await self._request(
            "GET",
            f"/admin/realms/{realm}/groups/{safe_root}/children",
            token=admin_token,
            params={
                "search": group_name,
                "exact": "true",
                "first": 0,
                "max": 20,
                "briefRepresentation": "false",
            },
            expected=(200,),
        )
        payload = self._json(response, "pre-Vault managed group lookup")
        if not isinstance(payload, list):
            raise IdentityError("pre-Vault managed group lookup was invalid")
        expected_path = f"/{self.settings.identity_managed_root_group}/{group_name}"
        matches = [
            group
            for group in payload
            if isinstance(group, dict)
            and group.get("name") == group_name
            and group.get("path") in (None, expected_path)
        ]
        if len(matches) > 1:
            raise IdentityConflict("multiple pre-Vault managed groups exist")
        return matches[0] if matches else None

    async def _pre_vault_require_leaf_group(
        self, group: dict[str, Any], admin_token: str
    ) -> None:
        realm = path_segment(self.settings.identity_realm, label="Keycloak realm")
        group_id = path_segment(group.get("id"), label="managed group UUID")
        response = await self._request(
            "GET",
            f"/admin/realms/{realm}/groups/{group_id}/children",
            token=admin_token,
            params={"first": 0, "max": 1, "briefRepresentation": "true"},
            expected=(200,),
        )
        children = self._json(response, "pre-Vault managed group children")
        if not isinstance(children, list) or children:
            raise IdentityConflict("pre-Vault managed baseline group is not a leaf")

    async def _pre_vault_group_roles(
        self, group_id: str, admin_token: str
    ) -> list[dict[str, Any]]:
        realm = path_segment(self.settings.identity_realm, label="Keycloak realm")
        safe_group = path_segment(group_id, label="managed group UUID")
        response = await self._request(
            "GET",
            f"/admin/realms/{realm}/groups/{safe_group}/role-mappings/realm",
            token=admin_token,
            expected=(200,),
        )
        payload = self._json(response, "pre-Vault managed group role mappings")
        if not isinstance(payload, list):
            raise IdentityError("pre-Vault managed group role mappings were invalid")
        roles: list[dict[str, Any]] = []
        seen: set[str] = set()
        for role in payload:
            name = role.get("name") if isinstance(role, dict) else None
            if not isinstance(name, str) or not name or name in seen:
                raise IdentityError(
                    "pre-Vault managed group role mappings were invalid"
                )
            path_segment(role.get("id"), label="managed group realm role UUID")
            seen.add(name)
            roles.append(role)
        return roles

    async def _pre_vault_federated_user(
        self,
        username: str,
        federation_provider: str,
        admin_token: str,
    ) -> dict[str, Any]:
        realm = path_segment(self.settings.identity_realm, label="Keycloak realm")
        provider = await self._find_component(
            self.settings.identity_realm, federation_provider, admin_token
        )
        if provider is None:
            raise IdentityError("configured pre-Vault federation provider is missing")
        # Bind the provider by the same inventory identity contract the reconcile
        # path uses, not by display name alone. A restored or operator-created
        # provider that merely reuses the configured name (pointing at a
        # different directory, or carrying a write-back mapper) must not be able
        # to redirect this pre-Vault admin's federation link.
        provider_id = await self._verify_bound_ldap_component(provider, admin_token)
        response = await self._request(
            "GET",
            f"/admin/realms/{realm}/users",
            token=admin_token,
            params={
                "username": username,
                "exact": "true",
                "first": 0,
                "max": 20,
                "briefRepresentation": "false",
            },
            expected=(200,),
        )
        payload = self._json(response, "pre-Vault bootstrap identity lookup")
        if not isinstance(payload, list):
            raise IdentityError("pre-Vault bootstrap identity lookup was invalid")
        matches = [
            user
            for user in payload
            if isinstance(user, dict) and user.get("username") == username
        ]
        if len(matches) != 1:
            raise IdentityConflict("pre-Vault bootstrap identity was not unique")
        user = matches[0]
        if user.get("enabled") is not True or user.get("federationLink") != provider_id:
            raise IdentityConflict(
                "pre-Vault bootstrap identity is not an enabled federated user"
            )
        path_segment(user.get("id"), label="bootstrap identity UUID")
        return user

    async def _pre_vault_user_has_group(
        self,
        user_id: str,
        group_id: str,
        group_name: str,
        admin_token: str,
    ) -> bool:
        realm = path_segment(self.settings.identity_realm, label="Keycloak realm")
        safe_user = path_segment(user_id, label="bootstrap identity UUID")
        safe_group = path_segment(group_id, label="managed group UUID")
        response = await self._request(
            "GET",
            f"/admin/realms/{realm}/users/{safe_user}/groups",
            token=admin_token,
            params={
                "search": group_name,
                "exact": "true",
                "first": 0,
                "max": 20,
                "briefRepresentation": "true",
            },
            expected=(200,),
        )
        payload = self._json(response, "pre-Vault bootstrap group membership")
        if not isinstance(payload, list):
            raise IdentityError("pre-Vault bootstrap group membership was invalid")
        matches = [
            group
            for group in payload
            if isinstance(group, dict)
            and group.get("id") == safe_group
            and group.get("name") == group_name
        ]
        if len(matches) > 1:
            raise IdentityConflict("pre-Vault bootstrap group membership was ambiguous")
        return len(matches) == 1

    async def _pre_vault_group_members(
        self, group_id: str, admin_token: str
    ) -> list[dict[str, Any]]:
        """Return the complete bounded member set for one baseline admin group."""

        realm = path_segment(self.settings.identity_realm, label="Keycloak realm")
        safe_group = path_segment(group_id, label="managed group UUID")
        response = await self._request(
            "GET",
            f"/admin/realms/{realm}/groups/{safe_group}/members",
            token=admin_token,
            params={
                "first": 0,
                "max": MAX_PRE_VAULT_BOOTSTRAP_IDENTITIES + 1,
                "briefRepresentation": "false",
            },
            expected=(200,),
        )
        payload = self._json(response, "pre-Vault managed admin membership")
        if (
            not isinstance(payload, list)
            or len(payload) > MAX_PRE_VAULT_BOOTSTRAP_IDENTITIES
        ):
            raise IdentityConflict("pre-Vault managed admin membership is unbounded")
        members: list[dict[str, Any]] = []
        seen: set[str] = set()
        for member in payload:
            member_id = member.get("id") if isinstance(member, dict) else None
            safe_member = path_segment(member_id, label="bootstrap identity UUID")
            if safe_member in seen:
                raise IdentityConflict(
                    "pre-Vault managed admin membership is ambiguous"
                )
            seen.add(safe_member)
            members.append(member)
        return members

    async def reconcile_pre_vault_identity_baseline(self, spec: dict[str, Any]) -> bool:
        """Create only the inventory-declared recovery group memberships.

        This path deliberately does not read or write HashiCorp Vault, create
        the durable identity controller, delete any Keycloak object, or infer
        users/groups from existing state.  Its sole purpose is to make an
        explicitly named federated administrator able to cross the existing
        OAuth gate while Vault is sealed.  Normal lifecycle ownership remains
        with the durable controller after the regular bootstrap completes.
        """

        groups, identities = self._validate_pre_vault_identity_spec(spec)

        admin_token = await self._bootstrap_token()
        changed = False
        changed = (
            await self._ensure_relying_parties(admin_token, preserve_unmanaged=True)
            or changed
        )
        resolved_identities: list[tuple[dict[str, str], str]] = []
        expected_members: dict[str, set[str]] = {}
        for identity in identities:
            user = await self._pre_vault_federated_user(
                identity["username"],
                identity["federation_provider"],
                admin_token,
            )
            user_id = path_segment(user.get("id"), label="bootstrap identity UUID")
            resolved_identities.append((identity, user_id))
            expected_members.setdefault(identity["group"], set()).add(user_id)

        realm = path_segment(self.settings.identity_realm, label="Keycloak realm")
        desired_roles = await self._capability_role_representations(realm, admin_token)
        desired_by_name = {str(role["name"]): role for role in desired_roles}

        root = await self._root_group(admin_token, create=False)
        if root is None:
            root = await self._root_group(admin_token, create=True)
            changed = True
        if root is None:
            raise IdentityError("managed identity root group was not created")
        root_id = path_segment(root.get("id"), label="managed root group UUID")

        groups_by_name: dict[str, dict[str, Any]] = {}
        for group_spec in groups:
            name = str(group_spec["name"])
            group = await self._pre_vault_direct_child(root_id, name, admin_token)
            if group is None:
                await self._request(
                    "POST",
                    f"/admin/realms/{realm}/groups/{root_id}/children",
                    token=admin_token,
                    json_body={"name": name},
                    expected=(201, 204),
                )
                group = await self._pre_vault_direct_child(root_id, name, admin_token)
                changed = True
            if group is None:
                raise IdentityError("pre-Vault managed group was not created")
            await self._pre_vault_require_leaf_group(group, admin_token)
            group_id = path_segment(group.get("id"), label="managed group UUID")
            current_members = await self._pre_vault_group_members(group_id, admin_token)
            current_member_ids = {str(member["id"]) for member in current_members}
            if not current_member_ids <= expected_members.get(name, set()):
                raise IdentityConflict(
                    "pre-Vault managed baseline group has undeclared members"
                )
            current_roles = await self._pre_vault_group_roles(group_id, admin_token)
            current_names = {str(role["name"]) for role in current_roles}
            desired_names = set(group_spec["roles"])
            if not current_names <= desired_names:
                raise IdentityConflict(
                    "pre-Vault managed group has undeclared realm-role mappings"
                )
            missing = [
                desired_by_name[name] for name in sorted(desired_names - current_names)
            ]
            if missing:
                await self._request(
                    "POST",
                    f"/admin/realms/{realm}/groups/{group_id}/role-mappings/realm",
                    token=admin_token,
                    json_body=missing,
                    expected=(204,),
                )
                changed = True
            verified_roles = await self._pre_vault_group_roles(group_id, admin_token)
            if {str(role["name"]) for role in verified_roles} != desired_names:
                raise IdentityError(
                    "Keycloak did not verify pre-Vault managed group role mappings"
                )
            groups_by_name[name] = group

        for identity, user_id in resolved_identities:
            group = groups_by_name[identity["group"]]
            group_id = path_segment(group.get("id"), label="managed group UUID")
            has_group = await self._pre_vault_user_has_group(
                user_id, group_id, identity["group"], admin_token
            )
            if not has_group:
                await self._request(
                    "PUT",
                    f"/admin/realms/{realm}/users/{user_id}/groups/{group_id}",
                    token=admin_token,
                    expected=(204,),
                )
                changed = True
            if not await self._pre_vault_user_has_group(
                user_id, group_id, identity["group"], admin_token
            ):
                raise IdentityError(
                    "Keycloak did not verify pre-Vault bootstrap membership"
                )

        for group_name, group in groups_by_name.items():
            group_id = path_segment(group.get("id"), label="managed group UUID")
            verified_members = await self._pre_vault_group_members(
                group_id, admin_token
            )
            if {str(member["id"]) for member in verified_members} != (
                expected_members.get(group_name, set())
            ):
                raise IdentityError(
                    "Keycloak did not verify exact pre-Vault baseline membership"
                )
        return changed

    def _relying_party_specs(self) -> list[dict[str, Any]]:
        """Exact first-party OIDC clients required by the deployed edges."""
        if not self.settings.relying_party_secrets_ok():
            raise IdentityConflict(
                "OIDC relying-party secrets are missing, weak, reused, or placeholders"
            )
        domain = self.settings.aigw_domain

        def client(
            client_id: str,
            name: str,
            secret: str,
            redirects: list[str],
            origins: list[str],
            *,
            logout_redirects: list[str] | None = None,
        ) -> dict[str, Any]:
            attributes: dict[str, str] = {}
            if logout_redirects:
                attributes["post.logout.redirect.uris"] = "##".join(logout_redirects)
            return {
                "clientId": client_id,
                "name": name,
                "enabled": True,
                "protocol": "openid-connect",
                "publicClient": False,
                "clientAuthenticatorType": "client-secret",
                "secret": secret,
                "standardFlowEnabled": True,
                "implicitFlowEnabled": False,
                "directAccessGrantsEnabled": False,
                "serviceAccountsEnabled": False,
                "fullScopeAllowed": False,
                "redirectUris": redirects,
                "webOrigins": origins,
                "attributes": attributes,
                "protocolMappers": [self._realm_roles_mapper()],
            }

        return [
            client(
                "open-webui",
                "Open WebUI",
                self.settings.webui_oidc_client_secret,
                [f"https://chat.{domain}/oauth/oidc/callback"],
                [f"https://chat.{domain}"],
                # RP-initiated logout: Open WebUI's /signout sends the browser
                # to Keycloak's end_session_endpoint with this exact
                # post_logout_redirect_uri (WEBUI_AUTH_SIGNOUT_REDIRECT_URL in
                # compose). Keycloak only honours it when it is on this
                # allow-list; the trailing slash must match the compose value.
                logout_redirects=[f"https://chat.{domain}/"],
            ),
            client(
                "dev-portal",
                "Developer self-service portal",
                self.settings.portal_oidc_client_secret,
                [f"https://portal.{domain}/auth/callback"],
                [f"https://portal.{domain}"],
                logout_redirects=[f"https://portal.{domain}/login"],
            ),
            client(
                "admin-portal",
                "AI Gateway identity administration portal",
                self.settings.admin_portal_oidc_client_secret,
                [f"https://admin.{domain}/auth/callback"],
                [f"https://admin.{domain}"],
                logout_redirects=[f"https://admin.{domain}/login"],
            ),
            client(
                "admin-ui",
                "ADM reverse-proxy OIDC gates",
                self.settings.oauth2_proxy_client_secret,
                [
                    f"https://litellm-admin.{domain}/oauth2/callback",
                    f"https://grafana.{domain}/oauth2/callback",
                    f"https://prometheus.{domain}/oauth2/callback",
                    f"https://vault.{domain}/oauth2/callback",
                ],
                [
                    f"https://litellm-admin.{domain}",
                    f"https://grafana.{domain}",
                    f"https://prometheus.{domain}",
                    f"https://vault.{domain}",
                ],
                # Each admin host's oauth2-proxy chains /oauth2/sign_out into
                # Keycloak's end_session endpoint with its own host root as
                # post_logout_redirect_uri; landing there cookie-less brings
                # the Keycloak login straight back. Trailing slashes must
                # match the sign-out URLs end to end.
                logout_redirects=[
                    f"https://litellm-admin.{domain}/",
                    f"https://grafana.{domain}/",
                    f"https://prometheus.{domain}/",
                    f"https://vault.{domain}/",
                ],
            ),
            # Vault's inner OIDC login, behind the admin-ui oauth2-proxy gate.
            # The loopback callback serves `vault login -method=oidc` through
            # a deliberate operator SSH tunnel; the code arriving there is
            # useless without this confidential client's secret, which only
            # Vault holds.
            client(
                VAULT_RP_CLIENT_ID,
                "Vault UI and CLI OIDC login",
                self.settings.vault_oidc_client_secret,
                [
                    f"https://vault.{domain}/ui/vault/auth/oidc/oidc/callback",
                    "http://localhost:8250/oidc/callback",
                ],
                [f"https://vault.{domain}"],
            ),
        ]

    async def _ensure_relying_parties(
        self, admin_token: str, *, preserve_unmanaged: bool = False
    ) -> bool:
        """Create/update and verify exact OIDC clients on restored realms.

        ``start --import-realm`` intentionally skips an existing realm, so a
        JSON template alone cannot repair callbacks or secrets after restore.
        The one-time/recovery bootstrap token performs this reconciliation and
        is deleted only after every client and secret has been read back.
        """
        realm = self.settings.identity_realm
        safe_realm = path_segment(realm, label="Keycloak realm")
        desired_scope_roles = await self._capability_role_representations(
            realm, admin_token
        )
        changed = False
        for desired in self._relying_party_specs():
            found = await self._find_client(
                realm, str(desired["clientId"]), admin_token
            )
            if found is None:
                found = await self._create_client(realm, desired, admin_token)
                changed = True
            current = await self._get_client(realm, found, admin_token)
            expected_mapper = self._realm_roles_mapper()
            current_mappers = current.get("protocolMappers")
            if preserve_unmanaged:
                if current_mappers is None:
                    current_mappers = []
                if not isinstance(current_mappers, list):
                    raise IdentityError(
                        f"OIDC client {desired['clientId']} protocol mappers are invalid"
                    )
                unmanaged_mappers = [
                    mapper
                    for mapper in current_mappers
                    if not isinstance(mapper, dict)
                    or mapper.get("name") != expected_mapper["name"]
                ]
                if unmanaged_mappers or len(current_mappers) > 1:
                    raise IdentityConflict(
                        f"OIDC client {desired['clientId']} has unmanaged protocol mappers"
                    )

            client_uuid = path_segment(current.get("id"), label="Keycloak client UUID")
            secret_response = await self._request(
                "GET",
                f"/admin/realms/{safe_realm}/clients/{client_uuid}/client-secret",
                token=admin_token,
                expected=(200,),
            )
            secret_doc = self._json(secret_response, "OIDC client secret")
            actual_secret = (
                secret_doc.get("value") if isinstance(secret_doc, dict) else None
            )
            secret_matches = isinstance(actual_secret, str) and hmac.compare_digest(
                actual_secret.encode(), str(desired["secret"]).encode()
            )

            needs_update = False
            for field in (
                "clientId",
                "name",
                "enabled",
                "protocol",
                "publicClient",
                "clientAuthenticatorType",
                "standardFlowEnabled",
                "implicitFlowEnabled",
                "directAccessGrantsEnabled",
                "serviceAccountsEnabled",
                "fullScopeAllowed",
            ):
                if current.get(field) != desired[field]:
                    current[field] = desired[field]
                    needs_update = True
            # Keycloak does not preserve the caller's ordering for these
            # set-like URL allow-lists.  Compare their complete sorted forms
            # so a harmless response-order normalization cannot turn this
            # recovery bridge into a recurring privileged client PUT.  A
            # duplicate or genuinely different URL still changes the sorted
            # list and is reconciled.
            for field in ("redirectUris", "webOrigins"):
                current_urls = current.get(field)
                if not isinstance(current_urls, list) or sorted(current_urls) != sorted(
                    desired[field]
                ):
                    current[field] = desired[field]
                    needs_update = True
            desired_attributes = desired["attributes"]
            if preserve_unmanaged:
                current_attributes = current.get("attributes")
                if not isinstance(current_attributes, dict):
                    current_attributes = {}
                merged_attributes = dict(current_attributes)
                merged_attributes.update(desired_attributes)
            else:
                merged_attributes = dict(desired_attributes)
            if current.get("attributes") != merged_attributes:
                current["attributes"] = merged_attributes
                needs_update = True
            try:
                self._verify_realm_roles_mapper(current, str(desired["clientId"]))
            except IdentityError:
                current["protocolMappers"] = [expected_mapper]
                needs_update = True
            if not secret_matches:
                current["secret"] = desired["secret"]
                needs_update = True
            if needs_update:
                await self._put_client(realm, current, admin_token)
                changed = True

            verified = await self._get_client(realm, current, admin_token)
            for field in (
                "clientId",
                "enabled",
                "protocol",
                "publicClient",
                "clientAuthenticatorType",
                "standardFlowEnabled",
                "implicitFlowEnabled",
                "directAccessGrantsEnabled",
                "serviceAccountsEnabled",
                "fullScopeAllowed",
            ):
                if verified.get(field) != desired[field]:
                    raise IdentityError(
                        f"Keycloak did not verify OIDC client {desired['clientId']}"
                    )
            if sorted(verified.get("redirectUris") or []) != sorted(
                desired["redirectUris"]
            ) or sorted(verified.get("webOrigins") or []) != sorted(
                desired["webOrigins"]
            ):
                raise IdentityError(
                    f"Keycloak did not verify OIDC client {desired['clientId']} URLs"
                )
            self._verify_realm_roles_mapper(verified, str(desired["clientId"]))
            # Keycloak accepts the update as a 204 even when a realm policy or
            # version-specific attribute normalization drops the RP-initiated
            # logout allow-list.  Without this read-back, portal logout
            # appears to succeed locally then Keycloak rejects the requested
            # post_logout_redirect_uri as invalid.  Verify only the managed
            # attributes so unrelated Keycloak defaults do not cause churn.
            verified_attributes = verified.get("attributes")
            if desired_attributes and (
                not isinstance(verified_attributes, dict)
                or any(
                    verified_attributes.get(name) != value
                    for name, value in desired_attributes.items()
                )
            ):
                raise IdentityError(
                    f"Keycloak did not verify OIDC client {desired['clientId']} logout URLs"
                )
            client_uuid = path_segment(verified.get("id"), label="Keycloak client UUID")
            secret_response = await self._request(
                "GET",
                f"/admin/realms/{safe_realm}/clients/{client_uuid}/client-secret",
                token=admin_token,
                expected=(200,),
            )
            secret_doc = self._json(secret_response, "OIDC client secret")
            actual_secret = (
                secret_doc.get("value") if isinstance(secret_doc, dict) else None
            )
            if not isinstance(actual_secret, str) or not hmac.compare_digest(
                actual_secret.encode(), str(desired["secret"]).encode()
            ):
                raise IdentityError(
                    f"Keycloak did not verify OIDC client {desired['clientId']} secret"
                )
            if preserve_unmanaged:
                scope_changed = await self._reconcile_client_realm_role_scope_mappings(
                    realm,
                    verified,
                    desired_scope_roles,
                    admin_token,
                    remove_extras=False,
                )
            else:
                scope_changed = await self._reconcile_client_realm_role_scope_mappings(
                    realm, verified, desired_scope_roles, admin_token
                )
            if scope_changed is True:
                changed = True
        return changed

    async def _generate_client_key(
        self,
        realm: str,
        client: dict[str, Any],
        admin_token: str,
        vault_path: str,
    ) -> dict[str, Any]:
        safe_realm = path_segment(realm, label="Keycloak realm")
        client_uuid = path_segment(client.get("id"), label="Keycloak client UUID")
        client_id = str(client.get("clientId") or "")
        if not client_id:
            raise IdentityError("Keycloak client has no clientId")
        # A PKCS#12 archive exposes one integrity/privacy password to common
        # loaders (including cryptography/OpenSSL).  Supplying distinct store
        # and key-entry passwords can produce an archive that Keycloak accepts
        # but the controller cannot safely consume.  Use one random, one-use
        # value for both fields and discard it immediately after parsing.
        store_password = secrets.token_urlsafe(32)
        key_password = store_password
        response = await self._request(
            "POST",
            (
                f"/admin/realms/{safe_realm}/clients/{client_uuid}"
                "/certificates/jwt.credential/generate-and-download"
            ),
            token=admin_token,
            json_body={
                "format": "PKCS12",
                "keyAlias": client_id,
                "storePassword": store_password,
                "keyPassword": key_password,
                "keySize": 3072,
                "validity": 2,
            },
            expected=(200,),
        )
        if not response.content or len(response.content) > MAX_KEYSTORE_BYTES:
            raise IdentityError("Keycloak returned an invalid private-key archive")
        try:
            private_key, certificate, _ = pkcs12.load_key_and_certificates(
                response.content, store_password.encode()
            )
        except (TypeError, ValueError) as exc:
            raise IdentityError(
                "Keycloak returned an unreadable private-key archive"
            ) from exc
        finally:
            # Python strings/bytes cannot be reliably zeroized. Bound their
            # lifetime and never persist the one-use archive passwords.
            store_password = ""
            key_password = ""
        if private_key is None or certificate is None:
            raise IdentityError("Keycloak private-key archive had no keypair")

        info_response = await self._request(
            "GET",
            (
                f"/admin/realms/{safe_realm}/clients/{client_uuid}"
                "/certificates/jwt.credential"
            ),
            token=admin_token,
            expected=(200,),
        )
        info = self._json(info_response, "client certificate")
        kid = info.get("kid") if isinstance(info, dict) else None
        if kid is not None and (not isinstance(kid, str) or len(kid) > 256):
            raise IdentityError("Keycloak returned an invalid certificate key id")
        private_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("ascii")
        fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
        key_doc = {
            "schema_version": CONTROLLER_KEY_SCHEMA,
            "private_key_pem": private_pem,
            "kid": kid or "",
            "certificate_sha256": fingerprint,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "client_id": client_id,
            "realm": realm,
        }
        try:
            written = self.vault.write_verified(vault_path, key_doc)
        except Exception as exc:  # noqa: BLE001
            raise IdentityError("Vault rejected the generated private key") from exc
        if not written:
            raise IdentityError("Vault did not verify the generated private key write")
        return key_doc

    async def _grant_controller_roles(
        self, realm: str, controller: dict[str, Any], admin_token: str
    ) -> None:
        safe_realm = path_segment(realm, label="Keycloak realm")
        controller_uuid = path_segment(
            controller.get("id"), label="identity controller UUID"
        )
        service_response = await self._request(
            "GET",
            f"/admin/realms/{safe_realm}/clients/{controller_uuid}/service-account-user",
            token=admin_token,
            expected=(200,),
        )
        service_user = self._json(service_response, "service account user")
        service_user_id = path_segment(
            service_user.get("id") if isinstance(service_user, dict) else None,
            label="service account user UUID",
        )
        management = await self._find_client(realm, "realm-management", admin_token)
        if management is None:
            raise IdentityError("realm-management client is missing")
        management_uuid = path_segment(
            management.get("id"), label="realm-management UUID"
        )
        roles: list[dict[str, Any]] = []
        for role_name in CONTROLLER_ADMIN_ROLES:
            role_response = await self._request(
                "GET",
                (
                    f"/admin/realms/{safe_realm}/clients/{management_uuid}"
                    f"/roles/{path_segment(role_name, label='admin role')}"
                ),
                token=admin_token,
                expected=(200,),
            )
            role = self._json(role_response, "realm-management role")
            if not isinstance(role, dict) or role.get("name") != role_name:
                raise IdentityError(f"realm-management role {role_name} is missing")
            roles.append(role)
        await self._request(
            "POST",
            (
                f"/admin/realms/{safe_realm}/users/{service_user_id}"
                f"/role-mappings/clients/{management_uuid}"
            ),
            token=admin_token,
            json_body=roles,
            expected=(204,),
        )

    async def _ensure_controller(self, admin_token: str) -> dict[str, Any]:
        try:
            existing_key = self.vault.read(
                self.settings.identity_controller_key_vault_path
            )
        except Exception:
            existing_key = None
        controller = await self._find_client(
            self.settings.identity_realm,
            self.settings.identity_controller_client_id,
            admin_token,
        )
        if controller is None:
            controller = await self._create_client(
                self.settings.identity_realm,
                {
                    "clientId": self.settings.identity_controller_client_id,
                    "name": "AI Gateway identity controller",
                    "enabled": False,
                    "protocol": "openid-connect",
                    "publicClient": False,
                    "serviceAccountsEnabled": True,
                    "standardFlowEnabled": False,
                    "directAccessGrantsEnabled": False,
                    "fullScopeAllowed": True,
                    "clientAuthenticatorType": "client-jwt",
                    "attributes": {
                        "token.endpoint.auth.signing.alg": "RS256",
                        "use.jwks.url": "false",
                    },
                },
                admin_token,
            )

        controller["enabled"] = False
        controller["publicClient"] = False
        controller["serviceAccountsEnabled"] = True
        controller["standardFlowEnabled"] = False
        controller["directAccessGrantsEnabled"] = False
        controller["fullScopeAllowed"] = True
        controller["clientAuthenticatorType"] = "client-jwt"
        attributes = dict(controller.get("attributes") or {})
        attributes.update(
            {"token.endpoint.auth.signing.alg": "RS256", "use.jwks.url": "false"}
        )
        controller["attributes"] = attributes
        await self._put_client(self.settings.identity_realm, controller, admin_token)
        await self._grant_controller_roles(
            self.settings.identity_realm, controller, admin_token
        )

        key_doc = existing_key if isinstance(existing_key, dict) else None
        if key_doc is not None:
            try:
                controller["enabled"] = True
                await self._put_client(
                    self.settings.identity_realm, controller, admin_token
                )
                await self._client_credentials_with_key(
                    self.settings.identity_realm,
                    self.settings.identity_controller_client_id,
                    key_doc,
                )
                return key_doc
            except (IdentityError, ValueError):
                controller["enabled"] = False
                await self._put_client(
                    self.settings.identity_realm, controller, admin_token
                )

        key_doc = await self._generate_client_key(
            self.settings.identity_realm,
            controller,
            admin_token,
            self.settings.identity_controller_key_vault_path,
        )
        # Do not PUT the stale pre-generation representation: it may contain
        # the previous jwt.credential.certificate attribute.
        controller = await self._get_client(
            self.settings.identity_realm, controller, admin_token
        )
        controller["enabled"] = True
        await self._put_client(self.settings.identity_realm, controller, admin_token)
        try:
            await self._client_credentials_with_key(
                self.settings.identity_realm,
                self.settings.identity_controller_client_id,
                key_doc,
            )
        except Exception:
            controller["enabled"] = False
            await self._put_client(
                self.settings.identity_realm, controller, admin_token
            )
            raise
        return key_doc

    async def _ensure_broker(self, admin_token: str) -> dict[str, Any]:
        await self._reconcile_wif_frontend_url(admin_token)
        broker = await self._find_client(
            self.settings.wif_realm,
            self.settings.wif_broker_client_id,
            admin_token,
        )
        if broker is None:
            raise IdentityNotFound(
                "the imported Anthropic WIF broker client is missing"
            )
        safe_realm = self.settings.wif_realm
        try:
            existing_key = self.vault.read(
                self.settings.kc_client_assertion_key_vault_path
            )
        except Exception:
            existing_key = None
        if broker.get("enabled") and isinstance(existing_key, dict):
            try:
                await self._ensure_broker_subject_mapper(broker, admin_token)
                issued_token = await self._client_credentials_with_key(
                    safe_realm, self.settings.wif_broker_client_id, existing_key
                )
                validate_wif_token_claims(
                    issued_token, client_id=self.settings.wif_broker_client_id
                )
                return existing_key
            except (IdentityError, ValueError):
                # A broker whose configured public key no longer matches the
                # Vault-held private key must not remain enabled while setup
                # attempts to repair it.
                broker["enabled"] = False
                await self._put_client(safe_realm, broker, admin_token)

        broker["enabled"] = False
        broker["publicClient"] = False
        broker["serviceAccountsEnabled"] = True
        broker["standardFlowEnabled"] = False
        broker["directAccessGrantsEnabled"] = False
        broker["clientAuthenticatorType"] = "client-jwt"
        attributes = dict(broker.get("attributes") or {})
        attributes.update(
            {"token.endpoint.auth.signing.alg": "RS256", "use.jwks.url": "false"}
        )
        broker["attributes"] = attributes
        await self._put_client(safe_realm, broker, admin_token)
        await self._ensure_broker_subject_mapper(broker, admin_token)
        key_doc = await self._generate_client_key(
            safe_realm,
            broker,
            admin_token,
            self.settings.kc_client_assertion_key_vault_path,
        )
        # Refresh after generation so enabling cannot restore a stale public
        # certificate over the key that now lives in Vault.
        broker = await self._get_client(safe_realm, broker, admin_token)
        broker["enabled"] = True
        await self._put_client(safe_realm, broker, admin_token)
        try:
            issued_token = await self._client_credentials_with_key(
                safe_realm, self.settings.wif_broker_client_id, key_doc
            )
            validate_wif_token_claims(
                issued_token, client_id=self.settings.wif_broker_client_id
            )
        except Exception:
            broker["enabled"] = False
            await self._put_client(safe_realm, broker, admin_token)
            raise
        return key_doc

    async def _ensure_broker_subject_mapper(
        self, broker: dict[str, Any], admin_token: str
    ) -> None:
        """Reconcile the stable access-token subject used by Anthropic WIF.

        Keycloak's native client_credentials subject is the internal service
        account user UUID, not the service-account username. UUIDs change on a
        realm restore and therefore cannot safely back an Anthropic subject
        rule. Keycloak officially supports overriding `sub` with its hardcoded
        claim mapper; reject competing subject mappers to keep the result
        deterministic.
        """
        realm = path_segment(self.settings.wif_realm, label="WIF realm")
        client_uuid = path_segment(broker.get("id"), label="WIF broker UUID")
        response = await self._request(
            "GET",
            (f"/admin/realms/{realm}/clients/{client_uuid}/protocol-mappers/models"),
            token=admin_token,
            expected=(200,),
        )
        payload = self._json(response, "broker protocol mappers")
        if not isinstance(payload, list):
            raise IdentityError("Keycloak broker protocol mappers were invalid")
        subject_mappers = [
            mapper
            for mapper in payload
            if isinstance(mapper, dict)
            and isinstance(mapper.get("config"), dict)
            and mapper["config"].get("claim.name") == "sub"
        ]
        unexpected = [
            mapper
            for mapper in subject_mappers
            if mapper.get("name") != BROKER_SUBJECT_MAPPER_NAME
        ]
        if unexpected or len(subject_mappers) > 1:
            raise IdentityConflict(
                "the WIF broker has a competing subject protocol mapper"
            )
        desired = {
            "name": BROKER_SUBJECT_MAPPER_NAME,
            "protocol": "openid-connect",
            "protocolMapper": "oidc-hardcoded-claim-mapper",
            "consentRequired": False,
            "config": {
                "claim.name": "sub",
                "claim.value": service_account_subject(
                    self.settings.wif_broker_client_id
                ),
                "jsonType.label": "String",
                "access.token.claim": "true",
                "id.token.claim": "false",
                "userinfo.token.claim": "false",
                "introspection.token.claim": "true",
            },
        }
        existing = subject_mappers[0] if subject_mappers else None
        base = f"/admin/realms/{realm}/clients/{client_uuid}/protocol-mappers/models"
        if existing is None:
            await self._request(
                "POST",
                base,
                token=admin_token,
                json_body=desired,
                expected=(201, 204),
            )
            return
        mapper_id = path_segment(existing.get("id"), label="subject mapper UUID")
        desired["id"] = mapper_id
        await self._request(
            "PUT",
            f"{base}/{mapper_id}",
            token=admin_token,
            json_body=desired,
            expected=(204,),
        )

    async def _find_component(
        self, realm: str, name: str, admin_token: str
    ) -> dict[str, Any] | None:
        safe_realm = path_segment(realm, label="Keycloak realm")
        response = await self._request(
            "GET",
            f"/admin/realms/{safe_realm}/components",
            token=admin_token,
            params={
                "name": name,
                "type": "org.keycloak.storage.UserStorageProvider",
            },
            expected=(200,),
        )
        payload = self._json(response, "component lookup")
        if not isinstance(payload, list):
            raise IdentityError("Keycloak component lookup was not a list")
        matches = [c for c in payload if isinstance(c, dict) and c.get("name") == name]
        if len(matches) > 1:
            raise IdentityConflict(
                f"multiple user federation providers are named {name}"
            )
        return matches[0] if matches else None

    async def _prove_ldap_directory(
        self, spec: LdapFederationSpec, admin_token: str, bind_password: str
    ) -> None:
        """Prove the directory, its trust chain, and the bind credential first.

        Keycloak performs the real LDAPS handshake here, against the mounted
        truststore and with hostname verification on.  A wrong CA bundle, a
        certificate whose SANs do not cover the configured host, or a wrong
        bind DN/password therefore fails *before* any provider is persisted,
        instead of leaving a broken federation component behind.
        """
        probe = {
            "action": "testConnection",
            "connectionUrl": spec.connection_url,
            "authType": "simple",
            "bindDn": spec.bind_dn,
            "bindCredential": bind_password,
            "useTruststoreSpi": "always",
            "startTls": "false",
        }
        safe_realm = path_segment(self.settings.identity_realm, label="Keycloak realm")
        for action in ("testConnection", "testAuthentication"):
            try:
                await self._request(
                    "POST",
                    f"/admin/realms/{safe_realm}/testLDAPConnection",
                    token=admin_token,
                    json_body={**probe, "action": action},
                    expected=(204,),
                )
            except IdentityError as exc:
                raise IdentityConflict(
                    "the directory connection or bind credential failed verification"
                ) from exc

    async def _clear_realm_user_cache(self, admin_token: str) -> None:
        """Evict already-imported federated users for the realm.

        A changed connection/config only takes effect for users Keycloak has
        already imported once the realm user cache is cleared; without this a
        reconciled connectionUrl keeps serving the stale cached user and the
        LDAPS endpoint move appears not to have taken.
        """
        safe_realm = path_segment(self.settings.identity_realm, label="Keycloak realm")
        await self._request(
            "POST",
            f"/admin/realms/{safe_realm}/clear-user-cache",
            token=admin_token,
            expected=(204,),
        )

    async def _reconcile_ldap_component_config(
        self, existing: dict[str, Any], spec: LdapFederationSpec, admin_token: str
    ) -> str:
        """Push the spec-owned managed LDAP config onto an existing provider.

        Only the non-secret, inventory-owned fields in
        :meth:`_managed_ldap_config` are managed; the component id, name,
        providerId, parentId, and every unmanaged/secret field (Keycloak masks
        ``bindCredential`` on reads) are preserved untouched. Idempotent: no PUT
        is issued when the managed fields already match, so a correctly
        provisioned provider never churns and no user cache is cleared. When a
        field DID drift, the update is applied, the realm user cache is cleared,
        and the component is re-fetched, then the strict inventory-bound + mapper
        verification runs against the reconciled representation.
        """
        safe_realm = path_segment(self.settings.identity_realm, label="Keycloak realm")
        component_id = path_segment(existing.get("id"), label="LDAP provider UUID")
        current_config = existing.get("config")
        current_config = (
            dict(current_config) if isinstance(current_config, dict) else {}
        )
        desired = {
            name: [value] for name, value in self._managed_ldap_config(spec).items()
        }
        changed = any(
            current_config.get(name) != value for name, value in desired.items()
        )
        if changed:
            merged = dict(current_config)
            merged.update(desired)
            updated = dict(existing)
            updated["config"] = merged
            await self._request(
                "PUT",
                f"/admin/realms/{safe_realm}/components/{component_id}",
                token=admin_token,
                json_body=updated,
                expected=(204,),
            )
            await self._clear_realm_user_cache(admin_token)
            refreshed = await self._find_component(
                self.settings.identity_realm, spec.provider_name, admin_token
            )
            if refreshed is None:
                raise IdentityError(
                    "the LDAP federation component vanished during reconcile"
                )
        else:
            refreshed = existing
        return await self._verify_bound_ldap_component(refreshed, admin_token)

    async def _refresh_ldap_bind_credential(
        self,
        component: dict[str, Any],
        spec: LdapFederationSpec,
        admin_token: str,
        bind_password: str,
    ) -> str:
        """Store the current bind password without comparing masked readback.

        Keycloak returns a placeholder instead of the saved password. Comparing
        that placeholder with the mounted secret would report drift forever, so
        an existing managed component receives the supplied password on every
        converge. The caller proves the password against LDAPS before this write.
        """

        safe_realm = path_segment(self.settings.identity_realm, label="Keycloak realm")
        component_id = path_segment(component.get("id"), label="LDAP provider UUID")
        current_config = component.get("config")
        if not isinstance(current_config, dict):
            raise IdentityConflict("the LDAP federation component config is invalid")

        updated = dict(component)
        updated_config = dict(current_config)
        updated_config["bindCredential"] = [bind_password]
        updated["config"] = updated_config
        await self._request(
            "PUT",
            f"/admin/realms/{safe_realm}/components/{component_id}",
            token=admin_token,
            json_body=updated,
            expected=(204,),
        )

        refreshed = await self._find_component(
            self.settings.identity_realm, spec.provider_name, admin_token
        )
        if refreshed is None:
            raise IdentityError(
                "the LDAP federation component vanished during credential refresh"
            )
        verified_id = await self._verify_bound_ldap_component(refreshed, admin_token)
        if verified_id != component_id:
            raise IdentityError("Keycloak returned a different LDAP provider after update")
        return verified_id

    def _require_ldap_bind_password(self, bind_password: str | None) -> str:
        if (
            not isinstance(bind_password, str)
            or len(bind_password) < 16
            or len(bind_password) > 512
            or any(ord(ch) < 32 for ch in bind_password)
        ):
            raise IdentityConflict("the LDAP bind password is required")
        return bind_password

    async def _ensure_ldap_federation(
        self, admin_token: str, bind_password: str | None
    ) -> str | None:
        spec = ldap_federation_spec(self.settings)
        if spec is None:
            return None
        existing = await self._find_component(
            self.settings.identity_realm, spec.provider_name, admin_token
        )
        if existing is not None:
            # Reconcile drifted managed config on an already-existing provider
            # before verifying it. A changed LDAPS endpoint can leave a stale
            # connection URL that breaks hostname verification while the
            # component still appears provisioned. Push the spec-owned fields
            # (connectionUrl,
            # editMode, vendor, usersDn, bindDn, useTruststoreSpi, ...) to the
            # desired values, clearing the realm user cache when anything changed
            # so the new connection takes effect for already-imported users, then
            # run the strict inventory-bound + mapper verification (which now
            # matches).
            component_id = await self._reconcile_ldap_component_config(
                existing, spec, admin_token
            )
            # An EXISTING provider whose managed config equals the
            # inventory contract is still NOT proof that a login will succeed:
            # a rotated DC certificate, a swapped/wrong CA truststore, or a
            # rotated bind credential all keep the persisted config identical
            # while breaking the live LDAPS handshake or bind. Re-exercise the
            # read-only, idempotent live proof on every reconcile.
            bind_password = self._require_ldap_bind_password(bind_password)
            await self._prove_ldap_directory(spec, admin_token, bind_password)
            refreshed = await self._find_component(
                self.settings.identity_realm, spec.provider_name, admin_token
            )
            if refreshed is None:
                raise IdentityError(
                    "the LDAP federation component vanished before credential refresh"
                )
            refreshed_id = await self._refresh_ldap_bind_credential(
                refreshed, spec, admin_token, bind_password
            )
            if refreshed_id != component_id:
                raise IdentityError("Keycloak changed the LDAP provider during reconcile")
            return refreshed_id
        bind_password = self._require_ldap_bind_password(bind_password)
        safe_realm = path_segment(self.settings.identity_realm, label="Keycloak realm")
        await self._prove_ldap_directory(spec, admin_token, bind_password)
        realm_response = await self._request(
            "GET",
            f"/admin/realms/{safe_realm}",
            token=admin_token,
            expected=(200,),
        )
        realm_rep = self._json(realm_response, "realm representation")
        realm_id = path_segment(
            realm_rep.get("id") if isinstance(realm_rep, dict) else None,
            label="realm UUID",
        )
        representation = {
            "name": spec.provider_name,
            "providerId": "ldap",
            "providerType": "org.keycloak.storage.UserStorageProvider",
            "parentId": realm_id,
            "config": {
                "enabled": ["true"],
                "priority": ["0"],
                "fullSyncPeriod": ["-1"],
                "changedSyncPeriod": ["-1"],
                "cachePolicy": ["DEFAULT"],
                "batchSizeForSync": ["1000"],
                # This gateway never writes to a customer directory. READ_ONLY
                # plus syncRegistrations=false are deliberately not tunable.
                "editMode": ["READ_ONLY"],
                "importEnabled": ["true"],
                "syncRegistrations": ["false"],
                "vendor": [spec.vendor],
                "usernameLDAPAttribute": [spec.username_attribute],
                "rdnLDAPAttribute": [spec.rdn_attribute],
                "uuidLDAPAttribute": [spec.uuid_attribute],
                "userObjectClasses": [spec.user_object_classes],
                "connectionUrl": [spec.connection_url],
                "usersDn": [spec.users_dn],
                "authType": ["simple"],
                "bindDn": [spec.bind_dn],
                "bindCredential": [bind_password],
                "searchScope": ["2"],
                # Use the mounted truststore and keep hostname verification on.
                "useTruststoreSpi": ["always"],
                "connectionPooling": ["true"],
                "pagination": ["true"],
                "startTls": ["false"],
                "connectionTimeout": ["5000"],
                "readTimeout": ["10000"],
                "allowKerberosAuthentication": ["false"],
                "useKerberosForPasswordAuthentication": ["false"],
                "customUserSearchFilter": [spec.user_filter],
            },
        }
        await self._request(
            "POST",
            f"/admin/realms/{safe_realm}/components",
            token=admin_token,
            json_body=representation,
            expected=(201, 204),
        )
        created = await self._find_component(
            self.settings.identity_realm, spec.provider_name, admin_token
        )
        if created is None:
            raise IdentityError("Keycloak created LDAP federation but it was not found")
        component_id = await self._verify_bound_ldap_component(created, admin_token)
        try:
            await self._request(
                "POST",
                f"/admin/realms/{safe_realm}/user-storage/{component_id}/sync",
                token=admin_token,
                params={"action": "triggerFullSync"},
                expected=(200,),
            )
        except Exception:
            # The just-created component already holds the bind credential.
            # If the compensating delete also fails we must NOT swallow the
            # error and converge green: that would strand a credentialed,
            # unproven provider. Raise a clear fatal that names the component
            # and the realm so an operator can remove it by hand before retry.
            try:
                await self._request(
                    "DELETE",
                    f"/admin/realms/{safe_realm}/components/{component_id}",
                    token=admin_token,
                    expected=(204,),
                )
            except Exception as cleanup_exc:
                raise IdentityError(
                    "the new LDAP federation failed its initial sync and the "
                    f"compensating delete also failed; remove Keycloak component "
                    f"{component_id} from realm {self.settings.identity_realm} "
                    "manually before retrying"
                ) from cleanup_exc
            raise
        return component_id

    @staticmethod
    def _managed_ldap_config(spec: LdapFederationSpec) -> dict[str, str]:
        """The exact spec-owned, NON-SECRET LDAP config fields this controller
        manages, as scalar values.

        Single source of truth for both the strict inventory-bound verification
        (:meth:`_verify_ldap_component`) and the drift reconcile
        (:meth:`_reconcile_ldap_component_config`), so a reconcile always
        converges to a state the verification accepts, with no churn. The bind
        credential is deliberately excluded: Keycloak masks it on reads, so it
        can neither be verified nor idempotently reconciled here.
        """
        return {
            "enabled": "true",
            # Security-critical values stay literal: a drifted provider that
            # writes back to the directory or self-registers users is refused.
            "editMode": "READ_ONLY",
            "importEnabled": "true",
            "syncRegistrations": "false",
            "authType": "simple",
            "searchScope": "2",
            "useTruststoreSpi": "always",
            "startTls": "false",
            "allowKerberosAuthentication": "false",
            "useKerberosForPasswordAuthentication": "false",
            "vendor": spec.vendor,
            "usernameLDAPAttribute": spec.username_attribute,
            "rdnLDAPAttribute": spec.rdn_attribute,
            "uuidLDAPAttribute": spec.uuid_attribute,
            "userObjectClasses": spec.user_object_classes,
            "connectionUrl": spec.connection_url,
            "usersDn": spec.users_dn,
            "bindDn": spec.bind_dn,
            "customUserSearchFilter": spec.user_filter,
        }

    def _verify_ldap_component(self, component: dict[str, Any]) -> str:
        """Fail closed if the inventory-bound federation name points elsewhere.

        Bootstrap membership is trusted only when the user's federation link
        resolves to this inventory-bound LDAP federation component.  Merely
        matching the display name is insufficient: a restored or
        operator-created provider could otherwise redirect authentication to a
        different directory.  Keycloak masks the bind credential on reads, so
        that one secret field is deliberately excluded while every
        security-relevant non-secret setting is checked exactly.
        """

        spec = ldap_federation_spec(self.settings)
        if spec is None:
            raise IdentityConflict("the LDAP federation is not inventory-bound")
        if (
            component.get("name") != spec.provider_name
            or component.get("providerId") != "ldap"
            or component.get("providerType")
            != "org.keycloak.storage.UserStorageProvider"
        ):
            raise IdentityConflict("the LDAP federation is not inventory-bound")
        config = component.get("config")
        if not isinstance(config, dict):
            raise IdentityConflict("the LDAP federation is not inventory-bound")
        expected = self._managed_ldap_config(spec)
        if any(config.get(name) != [value] for name, value in expected.items()):
            raise IdentityConflict("the LDAP federation is not inventory-bound")
        return path_segment(component.get("id"), label="LDAP provider UUID")

    @staticmethod
    def _ldap_mapper_scalar(value: Any) -> Any:
        """Return the single value of a Keycloak MultivaluedHashMap entry.

        Component config is serialized as ``{"read.only": ["true"]}``.  A
        malformed multi-valued entry is returned unchanged so the caller
        compares it against the expected scalar and fails closed.
        """
        if isinstance(value, list):
            return value[0] if len(value) == 1 else value
        return value

    async def _verify_ldap_mappers(self, component_id: str, admin_token: str) -> None:
        """Refuse any LDAP mapper sub-component that can write to the directory.

        :meth:`_verify_ldap_component` proves the top-level READ_ONLY /
        syncRegistrations=false posture, but that check does not cover the
        provider's mapper sub-components.  A user-attribute or full-name mapper
        with ``read.only`` disabled writes attribute changes back to the
        customer directory, and a group- or role-ldap-mapper whose ``mode`` is
        anything other than ``READ_ONLY`` writes membership back regardless of
        editMode.  Enumerate the provider's mappers and fail closed on any that
        introduces write-back beyond the reviewed read-only managed set.  The
        Keycloak defaults for a READ_ONLY provider carry ``read.only=true`` (or
        no ``read.only`` at all) and no ``mode``, so this does not churn a
        correctly provisioned federation.
        """

        safe_realm = path_segment(self.settings.identity_realm, label="Keycloak realm")
        safe_component = path_segment(component_id, label="LDAP provider UUID")
        mapper_type = "org.keycloak.storage.ldap.mappers.LDAPStorageMapper"
        response = await self._request(
            "GET",
            f"/admin/realms/{safe_realm}/components",
            token=admin_token,
            params={"parent": safe_component, "type": mapper_type},
            expected=(200,),
        )
        payload = self._json(response, "LDAP federation mappers")
        if not isinstance(payload, list):
            raise IdentityError("Keycloak LDAP federation mappers were invalid")
        for mapper in payload:
            if not isinstance(mapper, dict):
                raise IdentityConflict("the LDAP federation has a write-capable mapper")
            # A server-side parent/type filter is requested above; re-check it
            # locally so a lax response cannot smuggle a foreign-parented or
            # non-mapper component through this gate.
            if mapper.get("providerType") != mapper_type:
                continue
            if mapper.get("parentId") not in (None, safe_component):
                continue
            config = mapper.get("config")
            config = config if isinstance(config, dict) else {}
            read_only = self._ldap_mapper_scalar(config.get("read.only"))
            mode = self._ldap_mapper_scalar(config.get("mode"))
            if (read_only is not None and read_only != "true") or (
                mode is not None and mode != "READ_ONLY"
            ):
                raise IdentityConflict("the LDAP federation has a write-capable mapper")

    async def _verify_bound_ldap_component(
        self, component: dict[str, Any], admin_token: str
    ) -> str:
        """Bind a federation component to the full inventory identity contract.

        Combines the non-secret top-level configuration check with the live
        enumeration of the provider's mapper sub-components, so no reconcile,
        recovery, or pre-Vault path can adopt a provider whose top-level
        posture matches while a write-back mapper hides underneath it.
        """
        component_id = self._verify_ldap_component(component)
        await self._verify_ldap_mappers(component_id, admin_token)
        return component_id

    def _ldap_bind_password(self) -> str | None:
        spec = ldap_federation_spec(self.settings)
        if spec is None:
            return None
        path = spec.bind_password_file
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 513:
                    raise IdentityConflict("the LDAP bind secret file is invalid")
                raw = os.read(descriptor, 514)
            finally:
                os.close(descriptor)
        except IdentityError:
            raise
        except OSError as exc:
            raise IdentityConflict("the LDAP bind secret is unavailable") from exc
        try:
            return raw.decode("utf-8").rstrip("\r\n")
        except UnicodeDecodeError as exc:
            raise IdentityConflict("the LDAP bind secret is invalid") from exc

    async def _root_group(
        self, admin_token: str, *, create: bool
    ) -> dict[str, Any] | None:
        realm = path_segment(self.settings.identity_realm, label="Keycloak realm")
        response = await self._request(
            "GET",
            f"/admin/realms/{realm}/groups",
            token=admin_token,
            params={
                "search": self.settings.identity_managed_root_group,
                "exact": "true",
                "first": 0,
                "max": 20,
                "briefRepresentation": "false",
            },
            expected=(200,),
        )
        payload = self._json(response, "managed group lookup")
        if not isinstance(payload, list):
            raise IdentityError("Keycloak group lookup was not a list")
        expected_path = "/" + self.settings.identity_managed_root_group
        matches = [
            g
            for g in payload
            if isinstance(g, dict)
            and g.get("name") == self.settings.identity_managed_root_group
            and g.get("path") in (None, expected_path)
        ]
        if len(matches) > 1:
            raise IdentityConflict("multiple managed identity root groups exist")
        if matches:
            group = matches[0]
            attrs = group.get("attributes") or {}
            if attrs.get(MANAGED_ROOT_ATTRIBUTE) not in (["true"], "true"):
                raise IdentityConflict(
                    "the reserved managed group name belongs to an unmanaged group"
                )
            return group
        if not create:
            return None
        await self._request(
            "POST",
            f"/admin/realms/{realm}/groups",
            token=admin_token,
            json_body={
                "name": self.settings.identity_managed_root_group,
                "attributes": {MANAGED_ROOT_ATTRIBUTE: ["true"]},
            },
            expected=(201, 204),
        )
        return await self._root_group(admin_token, create=False)

    async def _master_group_by_name(
        self, name: str, admin_token: str
    ) -> dict[str, Any] | None:
        response = await self._request(
            "GET",
            "/admin/realms/master/groups",
            token=admin_token,
            params={
                "search": name,
                "exact": "true",
                "first": 0,
                "max": 20,
                "briefRepresentation": "false",
            },
            expected=(200,),
        )
        payload = self._json(response, "master admin group lookup")
        if not isinstance(payload, list):
            raise IdentityError("Keycloak master group lookup was not a list")
        matches = [
            group
            for group in payload
            if isinstance(group, dict)
            and group.get("name") == name
            and group.get("path") in (None, "/" + name)
        ]
        if len(matches) > 1:
            raise IdentityConflict("multiple master-realm administrator groups exist")
        return matches[0] if matches else None

    async def _ensure_break_glass_group(self, admin_token: str) -> str:
        name = self.settings.break_glass_admin_group
        group = await self._master_group_by_name(name, admin_token)
        if group is None:
            await self._request(
                "POST",
                "/admin/realms/master/groups",
                token=admin_token,
                json_body={
                    "name": name,
                    "attributes": {MANAGED_ADMIN_GROUP_ATTRIBUTE: ["true"]},
                },
                expected=(201, 204),
            )
            group = await self._master_group_by_name(name, admin_token)
        if group is None:
            raise IdentityError("the master administrators group was not created")
        attributes = group.get("attributes") or {}
        if attributes.get(MANAGED_ADMIN_GROUP_ATTRIBUTE) not in (["true"], "true"):
            raise IdentityConflict(
                "refusing to adopt an unmarked master-realm administrators group"
            )
        group_id = path_segment(group.get("id"), label="master admin group UUID")
        # Group membership is the single source of administrative authority:
        # the composite admin role rides the marked group, never a user.
        role_response = await self._request(
            "GET",
            f"/admin/realms/master/roles/{MASTER_ADMIN_ROLE}",
            token=admin_token,
            expected=(200,),
        )
        role = self._json(role_response, "master admin role")
        if not isinstance(role, dict) or role.get("name") != MASTER_ADMIN_ROLE:
            raise IdentityError("the master admin composite role is missing")
        # A role merely NAMED admin proves nothing: composite mappings can be
        # stripped, leaving the group without functional authority while every
        # name-based check still passes. Require the effective composite to
        # carry `create-realm` (the stable realm-role member of master's
        # built-in admin composite) plus at least one per-realm client role.
        # Full authority is additionally proven live by the acceptance step in
        # docs/test-runbook.md (console shows the group's effective roles).
        composites = self._json(
            await self._request(
                "GET",
                f"/admin/realms/master/roles/{MASTER_ADMIN_ROLE}/composites",
                token=admin_token,
                expected=(200,),
            ),
            "master admin composite roles",
        )
        composite_entries = (
            [entry for entry in composites if isinstance(entry, dict)]
            if isinstance(composites, list)
            else []
        )
        if not any(
            entry.get("name") == "create-realm" for entry in composite_entries
        ) or not any(
            entry.get("clientRole") is True for entry in composite_entries
        ):
            raise IdentityError(
                "the master admin composite role has been stripped of its "
                "cross-realm authority"
            )
        mappings_path = f"/admin/realms/master/groups/{group_id}/role-mappings/realm"
        mapped = self._json(
            await self._request(
                "GET", mappings_path, token=admin_token, expected=(200,)
            ),
            "master admin group roles",
        )
        mapped_names = (
            {entry.get("name") for entry in mapped if isinstance(entry, dict)}
            if isinstance(mapped, list)
            else set()
        )
        if MASTER_ADMIN_ROLE not in mapped_names:
            await self._request(
                "POST",
                mappings_path,
                token=admin_token,
                json_body=[{"id": role.get("id"), "name": MASTER_ADMIN_ROLE}],
                expected=(204,),
            )
            verified = self._json(
                await self._request(
                    "GET", mappings_path, token=admin_token, expected=(200,)
                ),
                "master admin group roles",
            )
            verified_names = (
                {entry.get("name") for entry in verified if isinstance(entry, dict)}
                if isinstance(verified, list)
                else set()
            )
            if MASTER_ADMIN_ROLE not in verified_names:
                raise IdentityError(
                    "Keycloak did not verify the master admin role mapping"
                )
        return group_id

    async def _ensure_master_brute_force_policy(self, admin_token: str) -> None:
        realm = self._json(
            await self._request(
                "GET", "/admin/realms/master", token=admin_token, expected=(200,)
            ),
            "master realm",
        )
        if not isinstance(realm, dict):
            raise IdentityError("Keycloak master realm representation was invalid")
        if all(
            realm.get(key) == value
            for key, value in MASTER_BRUTE_FORCE_POLICY.items()
        ):
            return
        updated = dict(realm)
        updated.update(MASTER_BRUTE_FORCE_POLICY)
        await self._request(
            "PUT",
            "/admin/realms/master",
            token=admin_token,
            json_body=updated,
            expected=(204,),
        )
        verified = self._json(
            await self._request(
                "GET", "/admin/realms/master", token=admin_token, expected=(200,)
            ),
            "master realm",
        )
        if not isinstance(verified, dict) or any(
            verified.get(key) != value
            for key, value in MASTER_BRUTE_FORCE_POLICY.items()
        ):
            raise IdentityError(
                "Keycloak did not verify the master brute-force policy"
            )

    async def _master_user_by_username(
        self, username: str, admin_token: str
    ) -> dict[str, Any] | None:
        response = await self._request(
            "GET",
            "/admin/realms/master/users",
            token=admin_token,
            params={
                "username": username,
                "exact": "true",
                "first": 0,
                "max": 20,
                "briefRepresentation": "false",
            },
            expected=(200,),
        )
        users = self._json(response, "break-glass user lookup")
        if not isinstance(users, list):
            raise IdentityError("Keycloak break-glass user lookup was invalid")
        matches = [
            user
            for user in users
            if isinstance(user, dict) and user.get("username") == username
        ]
        if len(matches) > 1:
            raise IdentityConflict("multiple break-glass administrator users exist")
        return matches[0] if matches else None

    def _break_glass_escrow_doc(self) -> dict[str, Any] | None:
        try:
            doc = self.vault.read(self.settings.break_glass_admin_vault_path)
        except Exception as exc:  # noqa: BLE001
            raise IdentityError(
                "could not read the break-glass escrow from Vault"
            ) from exc
        if (
            isinstance(doc, dict)
            and doc.get("schema_version") == BREAK_GLASS_SCHEMA
            and doc.get("username") == self.settings.break_glass_admin_username
            and isinstance(doc.get("password"), str)
            and len(doc["password"]) >= 32
        ):
            return doc
        return None

    async def _break_glass_admin_token(self) -> str:
        """Log in with the escrowed administrator for deployment repair."""

        escrow = self._break_glass_escrow_doc()
        if escrow is None:
            raise IdentityConflict(
                "the break-glass administrator is unavailable for deployment repair"
            )
        response = await self._request(
            "POST",
            "/realms/master/protocol/openid-connect/token",
            form={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": str(escrow["username"]),
                "password": str(escrow["password"]),
            },
            expected=(200,),
        )
        payload = self._json(response, "break-glass administrator token")
        token = payload.get("access_token") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token:
            raise IdentityError(
                "Keycloak did not issue a deployment-repair administrator token"
            )
        return token

    async def _set_break_glass_enabled(
        self, user: dict[str, Any], enabled: bool, admin_token: str
    ) -> None:
        user_id = path_segment(user.get("id"), label="break-glass user UUID")
        representation = dict(user)
        representation["enabled"] = enabled
        await self._request(
            "PUT",
            f"/admin/realms/master/users/{user_id}",
            token=admin_token,
            json_body=representation,
            expected=(204,),
        )

    async def _ensure_master_profile_marker(self, admin_token: str) -> None:
        """Declare the break-glass marker in master's user profile.

        Keycloak 24+ runs every realm under the declarative user profile, and
        the master realm — never file-imported — keeps the default
        unmanaged-attribute policy, under which an undeclared custom attribute
        supplied on an admin user create/update is silently dropped. Without
        this declaration the marker never persists, the read-back ownership
        check refuses the freshly created user, and every bootstrap bricks.
        Declared admin-only, so only master administrators can see or edit it.
        Read-back verified: the marker either provably persists or bootstrap
        fails loudly before any user is created.
        """
        profile = self._json(
            await self._request(
                "GET",
                "/admin/realms/master/users/profile",
                token=admin_token,
                expected=(200,),
            ),
            "master user profile",
        )
        if not isinstance(profile, dict):
            raise IdentityError("Keycloak master user profile was invalid")
        declared = profile.get("attributes")
        declared = declared if isinstance(declared, list) else []
        if any(
            isinstance(entry, dict) and entry.get("name") == BREAK_GLASS_ATTRIBUTE
            for entry in declared
        ):
            return
        updated = dict(profile)
        updated["attributes"] = [
            *declared,
            {
                "name": BREAK_GLASS_ATTRIBUTE,
                "displayName": "AI Gateway break-glass marker",
                "multivalued": False,
                "permissions": {"view": ["admin"], "edit": ["admin"]},
            },
        ]
        await self._request(
            "PUT",
            "/admin/realms/master/users/profile",
            token=admin_token,
            json_body=updated,
            expected=(200, 204),
        )
        verified = self._json(
            await self._request(
                "GET",
                "/admin/realms/master/users/profile",
                token=admin_token,
                expected=(200,),
            ),
            "master user profile",
        )
        verified_attributes = (
            verified.get("attributes") if isinstance(verified, dict) else None
        )
        if not isinstance(verified_attributes, list) or not any(
            isinstance(entry, dict) and entry.get("name") == BREAK_GLASS_ATTRIBUTE
            for entry in verified_attributes
        ):
            raise IdentityError(
                "Keycloak did not verify the master user profile marker"
            )

    async def _break_glass_has_password(
        self, user_id: str, admin_token: str
    ) -> bool:
        """Whether the master-realm user holds any password credential.

        A recreated or asymmetrically restored account can coexist with a
        shape-valid Vault escrow that no longer corresponds to any installed
        credential. Enabling such an account would leave a dead break-glass
        reporting healthy, so credential absence forces a rotation.
        """
        safe_user = path_segment(user_id, label="break-glass user UUID")
        credentials = self._json(
            await self._request(
                "GET",
                f"/admin/realms/master/users/{safe_user}/credentials",
                token=admin_token,
                expected=(200,),
            ),
            "break-glass credentials",
        )
        if not isinstance(credentials, list):
            raise IdentityError("Keycloak break-glass credential list was invalid")
        return any(
            isinstance(entry, dict) and entry.get("type") == "password"
            for entry in credentials
        )

    async def _ensure_break_glass_admin(
        self, admin_token: str
    ) -> dict[str, Any] | None:
        """Provision the durable, group-gated master-realm administrator.

        Runs only inside the one-time bootstrap window: the durable aigw
        controller deliberately holds no master-realm authority, so
        out-of-band drift is repaired by re-running this ceremony, never by
        widening the controller. Fail-closed credential ordering: the user is
        created disabled, the generated password is escrowed to Vault with a
        verified write, and only then is the account enabled. Any failure
        disables the account and fails bootstrap. The password exists only in
        the Vault escrow document — never in logs, audit records, status
        output, or the process environment.
        """
        if not self.settings.break_glass_admin_enabled:
            return None
        username = self.settings.break_glass_admin_username
        if username == self.settings.keycloak_bootstrap_admin_username:
            # Settings already refuses this; re-check so no alternate
            # construction path can race teardown's exact-username lookup.
            raise IdentityConflict(
                "the break-glass username collides with the bootstrap admin"
            )
        # Ordering is load-bearing. The brute-force policy is proven FIRST:
        # every later step either restores authority (group role mapping,
        # membership) or installs a password, and none of those may land on a
        # master realm whose lockout protection is still Keycloak's default
        # (off). The profile marker declaration comes next, before any user
        # exists to be marked.
        await self._ensure_master_brute_force_policy(admin_token)
        await self._ensure_master_profile_marker(admin_token)
        group_id = await self._ensure_break_glass_group(admin_token)

        user = await self._master_user_by_username(username, admin_token)
        created_this_run = False
        if user is None:
            await self._request(
                "POST",
                "/admin/realms/master/users",
                token=admin_token,
                json_body={
                    "username": username,
                    "enabled": False,
                    "attributes": {BREAK_GLASS_ATTRIBUTE: ["true"]},
                },
                expected=(201, 204),
            )
            user = await self._master_user_by_username(username, admin_token)
            created_this_run = True
        if user is None:
            raise IdentityError("the break-glass administrator was not created")
        attributes = user.get("attributes") or {}
        if attributes.get(BREAK_GLASS_ATTRIBUTE) not in (["true"], "true"):
            raise IdentityConflict(
                "refusing to adopt an unmarked master-realm user as break-glass"
            )
        user_id = path_segment(user.get("id"), label="break-glass user UUID")

        try:
            # An escrow document is trustworthy only when the account still
            # holds a credential this run can vouch for. A recreated user
            # (this run) or one with no password credential (asymmetric
            # restore) forces a rotation regardless of the document's shape.
            escrow = self._break_glass_escrow_doc()
            has_password = await self._break_glass_has_password(
                user_id, admin_token
            )
            needs_rotation = (
                escrow is None or created_this_run or not has_password
            )
            if needs_rotation and user.get("enabled"):
                await self._set_break_glass_enabled(user, False, admin_token)
                user["enabled"] = False

            # Membership is the authority grant, so it is attached only after
            # the account is proven disabled-or-escrowed: at this point the
            # user is either disabled (rotation pending) or carries a
            # credential whose escrow was just validated.
            await self._request(
                "PUT",
                f"/admin/realms/master/users/{user_id}/groups/{group_id}",
                token=admin_token,
                expected=(204,),
            )
            memberships = self._json(
                await self._request(
                    "GET",
                    f"/admin/realms/master/users/{user_id}/groups",
                    token=admin_token,
                    expected=(200,),
                ),
                "break-glass groups",
            )
            member_ids = (
                {group.get("id") for group in memberships if isinstance(group, dict)}
                if isinstance(memberships, list)
                else set()
            )
            if group_id not in member_ids:
                raise IdentityError(
                    "Keycloak did not verify break-glass group membership"
                )

            if needs_rotation:
                password = secrets.token_urlsafe(48)
                await self._request(
                    "PUT",
                    f"/admin/realms/master/users/{user_id}/reset-password",
                    token=admin_token,
                    json_body={
                        "type": "password",
                        "value": password,
                        "temporary": False,
                    },
                    expected=(204,),
                )
                escrow = {
                    "schema_version": BREAK_GLASS_SCHEMA,
                    "username": username,
                    "password": password,
                    "group": self.settings.break_glass_admin_group,
                    "realm": "master",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
                try:
                    written = self.vault.write_verified(
                        self.settings.break_glass_admin_vault_path, escrow
                    )
                except Exception as exc:  # noqa: BLE001
                    raise IdentityError(
                        "Vault rejected the break-glass escrow"
                    ) from exc
                if not written:
                    raise IdentityError(
                        "Vault did not verify the break-glass escrow write"
                    )
                await self._set_break_glass_enabled(user, True, admin_token)
            elif not user.get("enabled"):
                # Escrow valid and a credential is installed; the only writer
                # of that credential is this flow, which escrows immediately
                # after setting it, so re-enabling is safe.
                await self._set_break_glass_enabled(user, True, admin_token)
        except Exception:
            # Never leave a password-backed master administrator enabled
            # without a proven Vault escrow. Best-effort disable, then fail.
            try:
                await self._set_break_glass_enabled(user, False, admin_token)
            except Exception:  # noqa: BLE001 - the original failure wins
                pass
            raise

        return {
            "username": username,
            "group": self.settings.break_glass_admin_group,
            "escrowed_at": str(escrow.get("created_at", "")),
        }

    async def _bootstrap_admin_users(self, admin_token: str) -> list[dict[str, Any]]:
        """Return exact matches for the configured temporary admin username."""

        users_response = await self._request(
            "GET",
            "/admin/realms/master/users",
            token=admin_token,
            params={
                "username": self.settings.keycloak_bootstrap_admin_username,
                "exact": "true",
                "first": 0,
                "max": 20,
                "briefRepresentation": "false",
            },
            expected=(200,),
        )
        users = self._json(users_response, "bootstrap user lookup")
        if not isinstance(users, list):
            raise IdentityError("Keycloak bootstrap user lookup was invalid")
        matches = [
            user
            for user in users
            if isinstance(user, dict)
            and user.get("username") == self.settings.keycloak_bootstrap_admin_username
        ]
        if len(matches) > 1:
            raise IdentityConflict("multiple bootstrap administrator users exist")
        return matches

    async def _delete_bootstrap_principals(self, admin_token: str) -> None:
        """Delete only marked temporary bootstrap principals."""
        matches = await self._bootstrap_admin_users(admin_token)
        if matches:
            attributes = matches[0].get("attributes") or {}
            if attributes.get("is_temporary_admin") not in (["true"], "true"):
                raise IdentityConflict(
                    "refusing to delete an unmarked master-realm administrator"
                )
            user_id = path_segment(matches[0].get("id"), label="bootstrap user UUID")
            await self._request(
                "DELETE",
                f"/admin/realms/master/users/{user_id}",
                token=admin_token,
                expected=(204,),
            )

        client = await self._find_client(
            "master", self.settings.keycloak_bootstrap_admin_client_id, admin_token
        )
        if client is None:
            return
        client_uuid = path_segment(client.get("id"), label="bootstrap client UUID")
        client_response = await self._request(
            "GET",
            f"/admin/realms/master/clients/{client_uuid}",
            token=admin_token,
            expected=(200,),
        )
        full_client = self._json(client_response, "bootstrap client")
        attributes = (
            full_client.get("attributes") if isinstance(full_client, dict) else {}
        )
        if not isinstance(attributes, dict) or attributes.get(
            "is_temporary_admin"
        ) not in ("true", ["true"]):
            raise IdentityConflict("refusing to delete an unmarked master-realm client")
        await self._request(
            "DELETE",
            f"/admin/realms/master/clients/{client_uuid}",
            token=admin_token,
            expected=(204,),
        )

    async def _reconcile_deployment_bootstrap_cleanup(
        self, admin_token: str
    ) -> bool:
        """Remove only marked temporary principals and prove they are retired."""

        changed = False
        matches = await self._bootstrap_admin_users(admin_token)
        if matches:
            attributes = matches[0].get("attributes") or {}
            if attributes.get("is_temporary_admin") in (["true"], "true"):
                await self._delete_bootstrap_principals(admin_token)
                changed = True
            else:
                raise IdentityConflict(
                    "the bootstrap administrator username is held by an "
                    "unmarked master-realm user"
                )

        client = await self._find_client(
            "master", self.settings.keycloak_bootstrap_admin_client_id, admin_token
        )
        if client is not None:
            client_uuid = path_segment(client.get("id"), label="bootstrap client UUID")
            response = await self._request(
                "GET",
                f"/admin/realms/master/clients/{client_uuid}",
                token=admin_token,
                expected=(200,),
            )
            full_client = self._json(response, "bootstrap client")
            attributes = (
                full_client.get("attributes")
                if isinstance(full_client, dict)
                else None
            )
            if not isinstance(attributes, dict) or attributes.get(
                "is_temporary_admin"
            ) not in ("true", ["true"]):
                raise IdentityConflict(
                    "refusing to delete an unmarked master-realm client"
                )
            await self._request(
                "DELETE",
                f"/admin/realms/master/clients/{client_uuid}",
                token=admin_token,
                expected=(204,),
            )
            changed = True

        if await self._find_client(
            "master", self.settings.keycloak_bootstrap_admin_client_id, admin_token
        ) is not None:
            raise IdentityError("Keycloak did not remove the temporary bootstrap client")
        final_users = await self._bootstrap_admin_users(admin_token)
        if final_users:
            raise IdentityError(
                "Keycloak did not retire the temporary bootstrap administrator"
            )
        return changed

    def _vault_oidc_rp_escrow_doc(self) -> dict[str, Any] | None:
        try:
            doc = self.vault.read(self.settings.vault_oidc_rp_vault_path)
        except Exception as exc:  # noqa: BLE001
            raise IdentityError(
                "could not read the Vault OIDC relying-party escrow from Vault"
            ) from exc
        if (
            isinstance(doc, dict)
            and doc.get("schema_version") == VAULT_OIDC_RP_SCHEMA
            and doc.get("client_id") == VAULT_RP_CLIENT_ID
            and isinstance(doc.get("client_secret"), str)
            and len(doc["client_secret"]) >= 32
        ):
            return doc
        return None

    def _escrow_vault_oidc_rp_secret(self) -> str:
        """Escrow the verified ``vault`` relying-party secret for the ceremony.

        Vault's own OIDC login cannot read Compose environment, so the
        root-token ceremony ``scripts/vault-oidc-setup.sh`` consumes this
        escrow instead — the client secret never crosses argv, environment
        listings, or logs. Called only after ``_ensure_relying_parties`` has
        read the secret back from Keycloak, so the escrow always describes a
        credential Keycloak provably holds. An escrow that already matches is
        left untouched to avoid KV version churn on idempotent re-runs.
        """
        secret = self.settings.vault_oidc_client_secret
        # Defense in depth: _ensure_relying_parties already gates on the full
        # relying-party secret policy, but this escrow is consumed by a root
        # ceremony and must never park a missing or weak credential even if a
        # future caller reorders the bootstrap.
        if len(secret) < 32 or not self.settings.relying_party_secrets_ok():
            raise IdentityConflict(
                "refusing to escrow a missing or weak vault OIDC "
                "relying-party secret"
            )
        existing = self._vault_oidc_rp_escrow_doc()
        if existing is not None and hmac.compare_digest(
            existing["client_secret"].encode(), secret.encode()
        ):
            return str(existing.get("created_at", ""))
        escrow = {
            "schema_version": VAULT_OIDC_RP_SCHEMA,
            "client_id": VAULT_RP_CLIENT_ID,
            "client_secret": secret,
            "realm": self.settings.identity_realm,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        try:
            written = self.vault.write_verified(
                self.settings.vault_oidc_rp_vault_path, escrow
            )
        except Exception as exc:  # noqa: BLE001
            raise IdentityError(
                "Vault rejected the vault OIDC relying-party escrow"
            ) from exc
        if not written:
            raise IdentityError(
                "Vault did not verify the vault OIDC relying-party escrow write"
            )
        return str(escrow["created_at"])

    async def _audit(self, action: str, status: str, detail: dict[str, Any]) -> None:
        try:
            await self.db.record_history(
                "identity",
                action,
                status,
                json.dumps(detail, separators=(",", ":"), sort_keys=True),
            )
        except Exception:  # noqa: BLE001 - control action already completed
            pass
        # Database history remains the detailed local record. The SOC copy is
        # an explicit, bounded summary and never serializes nested policy or a
        # credential-bearing exception.
        safe_detail = {
            key: value
            for key, value in detail.items()
            if isinstance(value, (bool, int, str))
            and key
            in {
                "changed",
                "error_type",
                "federation_configured",
                "ldap_provider",
                "project",
                "temporary_bootstrap_service_deleted",
                "break_glass_admin_ensured",
                "vault_oidc_rp_escrowed",
            }
        }
        event = {
            "schema_version": 1,
            "event": "aigw.identity.audit",
            "action": action,
            "outcome": status,
            **safe_detail,
        }
        logger.info(
            "AIGW_SECURITY_EVENT %s",
            json.dumps(event, separators=(",", ":"), sort_keys=True),
        )

    async def _bootstrap_locked(self) -> dict[str, Any]:
        """Establish durable controls while ``_bootstrap_lock`` is held."""

        try:
            admin_token = await self._bootstrap_token()
            await self._ensure_relying_parties(admin_token)
            controller_key = await self._ensure_controller(admin_token)
            controller_token = await self._client_credentials_with_key(
                self.settings.identity_realm,
                self.settings.identity_controller_client_id,
                controller_key,
            )
            root = await self._root_group(controller_token, create=True)
            if root is None:
                raise IdentityError("managed identity root group was not created")
            federation_id = await self._ensure_ldap_federation(
                admin_token, self._ldap_bind_password()
            )
            federation_spec = ldap_federation_spec(self.settings)
            broker_key = await self._ensure_broker(admin_token)
            # The temporary administrator is never destroyed until the durable
            # administrator is proven and escrowed.
            break_glass = await self._ensure_break_glass_admin(admin_token)
            if break_glass is None:
                raise IdentityConflict(
                    "refusing to consume the bootstrap without a durable "
                    "administrator: BREAK_GLASS_ADMIN_ENABLED must remain true"
                )
            vault_oidc_rp_escrowed_at = self._escrow_vault_oidc_rp_secret()
            state_doc = {
                "schema_version": IDENTITY_STATE_SCHEMA,
                "managed_root_group_id": path_segment(
                    root.get("id"), label="managed root group UUID"
                ),
                "federation_provider_id": federation_id or "",
                "federation_provider_name": (
                    federation_spec.provider_name
                    if (federation_id and federation_spec is not None)
                    else ""
                ),
                "identity_controller_client_id": (
                    self.settings.identity_controller_client_id
                ),
                "controller_certificate_sha256": controller_key.get(
                    "certificate_sha256", ""
                ),
                "broker_certificate_sha256": broker_key.get(
                    "certificate_sha256", ""
                ),
                "relying_parties_reconciled": True,
                "break_glass_username": break_glass["username"],
                "break_glass_escrowed_at": break_glass["escrowed_at"],
                "vault_oidc_rp_escrowed_at": vault_oidc_rp_escrowed_at,
                "completed_at": datetime.now(timezone.utc).isoformat(),
            }
            if not self.vault.write_verified(
                self.settings.identity_state_vault_path, state_doc
            ):
                raise IdentityError("Vault did not verify identity state")
            await self._delete_bootstrap_principals(admin_token)
            await self._audit(
                "bootstrap",
                "success",
                {
                    "managed_root_group_id": state_doc["managed_root_group_id"],
                    "federation_configured": bool(federation_id),
                    "temporary_bootstrap_service_deleted": True,
                    "break_glass_admin_ensured": True,
                    "vault_oidc_rp_escrowed": True,
                },
            )
            return await self.status()
        except Exception as exc:
            await self._audit(
                "bootstrap", "failed", {"error_type": type(exc).__name__}
            )
            raise

    async def bootstrap(self) -> dict[str, Any]:
        """Consume the one-time Keycloak admin and establish durable controls."""

        async with self._bootstrap_lock:
            return await self._bootstrap_locked()

    async def status(self) -> dict[str, Any]:
        try:
            state_doc = self.vault.read(self.settings.identity_state_vault_path)
            controller_key = self.vault.read(
                self.settings.identity_controller_key_vault_path
            )
            broker_key = self.vault.read(
                self.settings.kc_client_assertion_key_vault_path
            )
        except Exception as exc:  # noqa: BLE001
            raise IdentityError("could not read identity status from Vault") from exc
        break_glass_doc = None
        break_glass_escrow_readable = True
        try:
            break_glass_doc = self.vault.read(
                self.settings.break_glass_admin_vault_path
            )
        except Exception:  # noqa: BLE001
            # A pre-feature rotator Vault policy cannot read the escrow path
            # (permission denied, not path-missing). The three reads above
            # already proved Vault itself is reachable, so degrade to honest
            # booleans instead of failing the whole status endpoint — a
            # brownfield host must keep converging while the documented
            # policy-amendment ceremony is pending.
            break_glass_escrow_readable = False
        vault_oidc_rp_doc = None
        vault_oidc_rp_escrow_readable = True
        try:
            vault_oidc_rp_doc = self.vault.read(
                self.settings.vault_oidc_rp_vault_path
            )
        except Exception:  # noqa: BLE001
            # Same brownfield degradation as the break-glass escrow above.
            vault_oidc_rp_escrow_readable = False
        controller_usable = False
        if isinstance(controller_key, dict):
            try:
                await self._controller_token()
                controller_usable = True
            except IdentityError:
                controller_usable = False
        bootstrap_available = False
        if self.settings.bootstrap_admin_secret_ok():
            try:
                await self._bootstrap_token()
                bootstrap_available = True
            except IdentityError:
                bootstrap_available = False
        configured = isinstance(state_doc, dict) and controller_usable
        return {
            "configured": configured,
            # Keep the raw presence test separate from ``configured``.  The
            # one-time pre-bootstrap OIDC scope repair must fail closed after
            # *any* durable identity-state write, even if the controller
            # credential is temporarily unavailable.
            "identity_state_absent": state_doc is None,
            "controller_usable": controller_usable,
            "bootstrap_available": bootstrap_available,
            "bootstrap_cleanup_required": configured and bootstrap_available,
            "ldap_configured": bool(
                isinstance(state_doc, dict) and state_doc.get("federation_provider_id")
            ),
            "controller_certificate_sha256": (
                controller_key.get("certificate_sha256", "")
                if isinstance(controller_key, dict)
                else ""
            ),
            "broker_certificate_sha256": (
                broker_key.get("certificate_sha256", "")
                if isinstance(broker_key, dict)
                else ""
            ),
            # The durable controller has no master-realm authority, so
            # presence of a valid Vault escrow is the honest observable for
            # the break-glass administrator. Booleans only — the escrow
            # document itself never leaves Vault through this API. The
            # readable flag distinguishes "no escrow yet" from "this rotator's
            # Vault policy predates the escrow path" (brownfield upgrade).
            "break_glass_escrow_readable": break_glass_escrow_readable,
            "break_glass_escrowed": (
                break_glass_escrow_readable
                and isinstance(break_glass_doc, dict)
                and break_glass_doc.get("schema_version") == BREAK_GLASS_SCHEMA
                and break_glass_doc.get("username")
                == self.settings.break_glass_admin_username
                and isinstance(break_glass_doc.get("password"), str)
                and len(break_glass_doc["password"]) >= 32
            ),
            # Presence booleans for the escrowed `vault` relying-party client
            # secret consumed by the vault-oidc-setup.sh ceremony. The secret
            # itself never leaves Vault through this API.
            "vault_oidc_rp_escrow_readable": vault_oidc_rp_escrow_readable,
            "vault_oidc_rp_escrowed": (
                vault_oidc_rp_escrow_readable
                and isinstance(vault_oidc_rp_doc, dict)
                and vault_oidc_rp_doc.get("schema_version") == VAULT_OIDC_RP_SCHEMA
                and vault_oidc_rp_doc.get("client_id") == VAULT_RP_CLIENT_ID
                and isinstance(vault_oidc_rp_doc.get("client_secret"), str)
                and len(vault_oidc_rp_doc["client_secret"]) >= 32
            ),
        }

    @staticmethod
    def _deployment_status_verified(status: dict[str, Any]) -> bool:
        """Return whether the durable, non-secret identity status is complete."""

        required = (
            "configured",
            "controller_usable",
            "ldap_configured",
            "break_glass_escrow_readable",
            "break_glass_escrowed",
            "vault_oidc_rp_escrow_readable",
            "vault_oidc_rp_escrowed",
        )
        return (
            all(status.get(name) is True for name in required)
            and status.get("bootstrap_available") is False
            and status.get("bootstrap_cleanup_required") is False
        )

    def _update_deployment_federation_state(
        self, federation_id: str, provider_name: str
    ) -> bool:
        """Keep Vault's provider pointer aligned after a safe recreation."""

        state_doc = self._identity_state()
        if (
            state_doc.get("schema_version") != IDENTITY_STATE_SCHEMA
            or state_doc.get("identity_controller_client_id")
            != self.settings.identity_controller_client_id
        ):
            raise IdentityConflict("the durable identity state contract is invalid")
        if (
            state_doc.get("federation_provider_id") == federation_id
            and state_doc.get("federation_provider_name") == provider_name
        ):
            return False
        updated = dict(state_doc)
        updated["federation_provider_id"] = federation_id
        updated["federation_provider_name"] = provider_name
        if not self.vault.write_verified(
            self.settings.identity_state_vault_path, updated
        ):
            raise IdentityError("Vault did not verify the reconciled identity state")
        return True

    async def converge_deployment_identity(self) -> str:
        """Idempotently deploy and prove Keycloak identity control.

        This is the single Ansible entry point. The same process-local lock used
        by the legacy internal bootstrap route serializes the one-time client,
        live LDAPS proof, callback repair, and temporary-principal cleanup.
        """

        async with self._bootstrap_lock:
            changed = False
            before = await self.status()
            if not self._deployment_status_verified(before):
                await self._bootstrap_locked()
                changed = True

            admin_token = await self._break_glass_admin_token()
            changed = (
                await self._reconcile_security_event_logging(admin_token) or changed
            )
            changed = await self._reconcile_wif_frontend_url(admin_token) or changed
            spec = ldap_federation_spec(self.settings)
            if spec is None:
                raise IdentityConflict(
                    "automatic identity deployment requires one LDAPS source"
                )
            bind_password = self._ldap_bind_password()
            existing = await self._find_component(
                self.settings.identity_realm, spec.provider_name, admin_token
            )
            desired_config = {
                name: [value]
                for name, value in self._managed_ldap_config(spec).items()
            }
            current_config = (
                existing.get("config") if isinstance(existing, dict) else None
            )
            ldap_changed = (
                existing is None
                or not isinstance(current_config, dict)
                or any(
                    current_config.get(name) != value
                    for name, value in desired_config.items()
                )
            )
            federation_id = await self._ensure_ldap_federation(
                admin_token, bind_password
            )
            if not isinstance(federation_id, str) or not federation_id:
                raise IdentityError("Keycloak did not return an LDAPS provider ID")
            changed = ldap_changed or changed
            changed = (
                self._update_deployment_federation_state(
                    federation_id, spec.provider_name
                )
                or changed
            )
            changed = (
                await self._reconcile_relying_party_redirect_uris(admin_token)
                or changed
            )
            changed = (
                await self._reconcile_deployment_bootstrap_cleanup(admin_token)
                or changed
            )

            after = await self.status()
            if not self._deployment_status_verified(after):
                raise IdentityError("automatic identity deployment did not verify")
            state_doc = self._identity_state()
            if (
                state_doc.get("federation_provider_id") != federation_id
                or state_doc.get("federation_provider_name") != spec.provider_name
            ):
                raise IdentityError("durable identity state does not match live LDAPS")
            await self._audit(
                "deployment_converge",
                "success",
                {"changed": changed, "ldap_provider": spec.provider_name},
            )
            return "applied" if changed else "verified"

    def _identity_state(self) -> dict[str, Any]:
        try:
            doc = self.vault.read(self.settings.identity_state_vault_path)
        except Exception as exc:  # noqa: BLE001
            raise IdentityError("could not read identity state") from exc
        if not isinstance(doc, dict):
            raise IdentityConflict("identity setup has not been completed")
        path_segment(doc.get("managed_root_group_id"), label="managed root UUID")
        if ldap_federation_spec(self.settings) is not None:
            path_segment(doc.get("federation_provider_id"), label="LDAP provider UUID")
        return doc

    async def _managed_group(self, group_id: str, token: str) -> dict[str, Any]:
        state_doc = self._identity_state()
        safe_group = path_segment(group_id, label="group UUID")
        if safe_group == state_doc["managed_root_group_id"]:
            raise IdentityConflict("the managed root group cannot be modified")
        realm = path_segment(self.settings.identity_realm, label="Keycloak realm")
        try:
            response = await self._request(
                "GET",
                f"/admin/realms/{realm}/groups/{safe_group}",
                token=token,
                expected=(200,),
            )
        except IdentityError as exc:
            raise IdentityNotFound("managed group was not found") from exc
        group = self._json(response, "managed group")
        path = group.get("path") if isinstance(group, dict) else None
        prefix = f"/{self.settings.identity_managed_root_group}/"
        if not isinstance(path, str) or not path.startswith(prefix):
            raise IdentityConflict("group is outside the managed authorization tree")
        self._managed_project_id(group)
        return group

    def _managed_project_id(self, group: dict[str, Any]) -> str:
        """Return the canonical direct-child project ID for a managed group.

        Managed groups are also the authorization binding carried by portal
        virtual keys.  Accepting nested groups here would make a membership
        mutation impossible to map unambiguously to the credential project,
        so reject it before any mutation is attempted.
        """

        path = group.get("path")
        prefix = f"/{self.settings.identity_managed_root_group}/"
        if not isinstance(path, str) or not path.startswith(prefix):
            raise IdentityConflict("group is outside the managed authorization tree")
        project_id = path.removeprefix(prefix)
        if "/" in project_id or PROJECT_ID_RE.fullmatch(project_id) is None:
            raise IdentityConflict(
                "managed group is nested or has an invalid project ID"
            )
        return project_id

    @staticmethod
    def _single_policy_attribute(
        attributes: dict[str, Any], name: str
    ) -> str | None:
        """Read one single-valued policy attribute or fail on ambiguity."""

        raw = attributes.get(name)
        if raw is None:
            return None
        if not isinstance(raw, list) or any(
            not isinstance(value, str) for value in raw
        ):
            raise IdentityConflict("group policy attribute is invalid")
        values = [value.strip() for value in raw if value.strip()]
        if not values:
            return None
        if len(values) > 1:
            raise IdentityConflict("group policy attribute has multiple values")
        return values[0]

    @classmethod
    def _group_policy(cls, group: dict[str, Any]) -> dict[str, Any]:
        """Parse the issuance policy carried by one managed group.

        Absent attributes mean the platform default: unlimited rate and every
        configured model. A malformed attribute is a hard conflict, never a
        silent fallback — a broken restriction must not mint unlimited keys.
        """

        attributes = group.get("attributes") or {}
        if not isinstance(attributes, dict):
            raise IdentityConflict("group attributes were invalid")

        policy: dict[str, Any] = {
            "tpm_limit": None,
            "rpm_limit": None,
            "allowed_models": None,
            "default_model": None,
        }
        for attribute, knob in (
            (POLICY_TPM_ATTRIBUTE, "tpm_limit"),
            (POLICY_RPM_ATTRIBUTE, "rpm_limit"),
        ):
            raw = cls._single_policy_attribute(attributes, attribute)
            if raw is None:
                continue
            if not raw.isdigit() or not 1 <= int(raw) <= POLICY_LIMIT_MAX:
                raise IdentityConflict("group rate-limit policy is invalid")
            policy[knob] = int(raw)

        raw_models = cls._single_policy_attribute(attributes, POLICY_MODELS_ATTRIBUTE)
        if raw_models is not None:
            names = [name.strip() for name in raw_models.split(",")]
            if (
                not names
                or len(names) > MAX_POLICY_MODELS
                or len(set(names)) != len(names)
                or any(MODEL_NAME_RE.fullmatch(name) is None for name in names)
            ):
                raise IdentityConflict("group model policy is invalid")
            policy["allowed_models"] = sorted(names)

        raw_default = cls._single_policy_attribute(
            attributes, POLICY_DEFAULT_MODEL_ATTRIBUTE
        )
        if raw_default is not None:
            if MODEL_NAME_RE.fullmatch(raw_default) is None:
                raise IdentityConflict("group default-model policy is invalid")
            allowed = policy["allowed_models"]
            if allowed is not None and raw_default not in allowed:
                raise IdentityConflict(
                    "group default model is outside its allowed models"
                )
            policy["default_model"] = raw_default
        return policy

    @staticmethod
    def _validated_policy_input(policy: dict[str, Any]) -> dict[str, Any]:
        """Normalize a requested policy or fail before any Keycloak write."""

        if not isinstance(policy, dict) or set(policy) != {
            "tpm_limit",
            "rpm_limit",
            "allowed_models",
            "default_model",
        }:
            raise IdentityConflict("group policy update has an invalid shape")

        normalized: dict[str, Any] = {}
        for knob in ("tpm_limit", "rpm_limit"):
            value = policy[knob]
            if value is not None and (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 1 <= value <= POLICY_LIMIT_MAX
            ):
                raise IdentityConflict("group rate-limit policy is invalid")
            normalized[knob] = value

        models = policy["allowed_models"]
        if models is not None:
            if (
                not isinstance(models, list)
                or not 1 <= len(models) <= MAX_POLICY_MODELS
                or any(
                    not isinstance(name, str)
                    or MODEL_NAME_RE.fullmatch(name) is None
                    for name in models
                )
                or len(set(models)) != len(models)
            ):
                raise IdentityConflict("group model policy is invalid")
            models = sorted(models)
        normalized["allowed_models"] = models

        default_model = policy["default_model"]
        if default_model is not None:
            if (
                not isinstance(default_model, str)
                or MODEL_NAME_RE.fullmatch(default_model) is None
            ):
                raise IdentityConflict("group default-model policy is invalid")
            if models is not None and default_model not in models:
                raise IdentityConflict(
                    "group default model is outside its allowed models"
                )
        normalized["default_model"] = default_model
        return normalized

    async def set_group_policy(
        self, group_id: str, policy: dict[str, Any]
    ) -> dict[str, Any]:
        async with self._group_topology_lock:
            return await self._set_group_policy_locked(group_id, policy)

    async def _set_group_policy_locked(
        self, group_id: str, policy: dict[str, Any]
    ) -> dict[str, Any]:
        """Write and verify one managed group's issuance policy attributes."""

        normalized = self._validated_policy_input(policy)
        token = await self._controller_token()
        group = await self._managed_group(group_id, token)
        project_id = self._managed_project_id(group)

        raw_attributes = group.get("attributes") or {}
        if not isinstance(raw_attributes, dict):
            raise IdentityConflict("group attributes were invalid")
        # Preserve every non-policy attribute byte-for-byte; this controller
        # only owns the aigw.policy.* namespace on managed project groups.
        attributes = {
            name: value
            for name, value in raw_attributes.items()
            if name not in POLICY_ATTRIBUTES
        }
        if normalized["tpm_limit"] is not None:
            attributes[POLICY_TPM_ATTRIBUTE] = [str(normalized["tpm_limit"])]
        if normalized["rpm_limit"] is not None:
            attributes[POLICY_RPM_ATTRIBUTE] = [str(normalized["rpm_limit"])]
        if normalized["allowed_models"] is not None:
            attributes[POLICY_MODELS_ATTRIBUTE] = [
                ",".join(normalized["allowed_models"])
            ]
        if normalized["default_model"] is not None:
            attributes[POLICY_DEFAULT_MODEL_ATTRIBUTE] = [
                normalized["default_model"]
            ]

        realm = path_segment(self.settings.identity_realm, label="Keycloak realm")
        safe_group = path_segment(group_id, label="group UUID")
        await self._request(
            "PUT",
            f"/admin/realms/{realm}/groups/{safe_group}",
            token=token,
            json_body={
                "id": group.get("id"),
                "name": group.get("name"),
                "attributes": attributes,
            },
            expected=(204,),
        )
        # Verify the effect from a fresh authoritative read: a 204 alone must
        # not be trusted to have persisted the exact restriction.
        applied = self._group_policy(await self._managed_group(group_id, token))
        if applied != normalized:
            raise IdentityError("group policy did not verify after update")
        await self._audit(
            "group_policy_update",
            "success",
            {"group_id": safe_group, "project": project_id, "policy": applied},
        )
        return {
            "id": safe_group,
            "name": str(group.get("name") or ""),
            "policy": applied,
        }

    async def _revoke_portal_project_keys(self, user_id: str, project_id: str) -> None:
        """Fail closed unless LiteLLM confirms portal-key revocation.

        This deliberately converts every control-plane failure into a safe,
        non-secret identity error.  Removing group membership while a static
        bearer key may still be active would create an authorization bypass.
        """

        if self._portal_key_revoker is None:
            raise IdentityError("portal-key revocation control is unavailable")
        try:
            await self._portal_key_revoker(user_id, project_id)
        except Exception as exc:  # noqa: BLE001
            raise IdentityError("could not verify portal-key revocation") from exc

    async def _group_capabilities(self, group_id: str, token: str) -> list[str]:
        realm = path_segment(self.settings.identity_realm, label="Keycloak realm")
        safe_group = path_segment(group_id, label="group UUID")
        response = await self._request(
            "GET",
            f"/admin/realms/{realm}/groups/{safe_group}/role-mappings/realm",
            token=token,
            expected=(200,),
        )
        roles = self._json(response, "group role mappings")
        if not isinstance(roles, list):
            raise IdentityError("Keycloak group role mappings were invalid")
        return sorted(
            {
                str(role.get("name"))
                for role in roles
                if isinstance(role, dict) and role.get("name") in CAPABILITY_ROLES
            }
        )

    async def _members(self, group_id: str, token: str) -> list[dict[str, Any]]:
        realm = path_segment(self.settings.identity_realm, label="Keycloak realm")
        safe_group = path_segment(group_id, label="group UUID")
        result: list[dict[str, Any]] = []
        for page in range(MAX_PAGE_COUNT):
            response = await self._request(
                "GET",
                f"/admin/realms/{realm}/groups/{safe_group}/members",
                token=token,
                params={"first": page * PAGE_SIZE, "max": PAGE_SIZE},
                expected=(200,),
            )
            payload = self._json(response, "group members")
            if not isinstance(payload, list):
                raise IdentityError("Keycloak group members were invalid")
            result.extend(member for member in payload if isinstance(member, dict))
            if len(payload) < PAGE_SIZE:
                return result
        raise IdentityConflict("group membership exceeds the supported safety bound")

    async def _federated_user(self, user_id: str, token: str) -> dict[str, Any]:
        state_doc = self._identity_state()
        provider_id = state_doc.get("federation_provider_id")
        if not provider_id:
            raise IdentityConflict("no LDAP federation provider is configured")
        realm = path_segment(self.settings.identity_realm, label="Keycloak realm")
        safe_user = path_segment(user_id, label="user UUID")
        try:
            response = await self._request(
                "GET",
                f"/admin/realms/{realm}/users/{safe_user}",
                token=token,
                expected=(200,),
            )
        except IdentityError as exc:
            raise IdentityNotFound("federated user was not found") from exc
        user = self._json(response, "federated user")
        if not isinstance(user, dict) or user.get("federationLink") != provider_id:
            raise IdentityConflict(
                "only users from the configured LDAP federation may be managed"
            )
        return user

    async def user_has_admin_role(self, user_id: str) -> bool:
        """Resolve current administrator authorization from Keycloak.

        The browser portal stores a signed snapshot of OIDC roles.  That is
        sufficient for ordinary page rendering, but it must not authorize a
        mutation after the user's directory/group access has been revoked.
        This method deliberately reads the user and *composite* realm roles on
        every admin mutation so direct and group-derived mappings are treated
        exactly as Keycloak would treat them in a newly issued token.
        """
        token = await self._controller_token()
        realm = path_segment(self.settings.identity_realm, label="Keycloak realm")
        safe_user = path_segment(user_id, label="user UUID")

        user_response = await self._request(
            "GET",
            f"/admin/realms/{realm}/users/{safe_user}",
            token=token,
            expected=(200, 404),
        )
        if user_response.status_code == 404:
            return False
        user = self._json(user_response, "authorization user")
        if not isinstance(user, dict) or user.get("enabled") is not True:
            return False

        roles_response = await self._request(
            "GET",
            (f"/admin/realms/{realm}/users/{safe_user}/role-mappings/realm/composite"),
            token=token,
            expected=(200, 404),
        )
        if roles_response.status_code == 404:
            return False
        roles = self._json(roles_response, "authorization roles")
        if not isinstance(roles, list):
            raise IdentityError("Keycloak composite role mappings were invalid")
        return any(
            isinstance(role, dict) and role.get("name") == "aigw-admins"
            for role in roles
        )

    async def user_projects(self, user_id: str) -> list[str]:
        """Resolve live developer projects from direct managed-group membership."""
        token = await self._controller_token()
        return sorted(await self._user_project_bindings(user_id, token))

    async def user_project_policies(self, user_id: str) -> dict[str, Any]:
        """Live projects plus each project's parsed, non-secret issuance policy.

        The policy is read from a fresh authoritative per-group GET (never
        from a possibly-brief membership representation): the portal uses it
        to decide the caps and model set minted onto a static bearer key, so
        an ambiguous read must fail closed rather than default to unlimited.
        """
        token = await self._controller_token()
        bindings = await self._user_project_bindings(user_id, token)
        realm = path_segment(self.settings.identity_realm, label="Keycloak realm")
        policies: dict[str, Any] = {}
        for project_id in sorted(bindings):
            response = await self._request(
                "GET",
                f"/admin/realms/{realm}/groups/{bindings[project_id]}",
                token=token,
                expected=(200,),
            )
            group = self._json(response, "project policy group")
            if not isinstance(group, dict):
                raise IdentityError("Keycloak project group was invalid")
            policies[project_id] = self._group_policy(group)
        return {"projects": sorted(bindings), "policies": policies}

    async def chat_capability_health(self) -> dict[str, Any]:
        """Report whether the live realm wires the dedicated aigw-chat gate.

        Open WebUI's OAUTH_ALLOWED_ROLES is pinned to ``aigw-chat``. A realm
        bootstrapped before that role existed carries neither the realm role,
        the client scope mapping, nor a group grant, so flipping the gate
        silently 403s every non-admin chat login. The converge's verify role
        turns that into a loud failure that points at the break-glass realm
        migration SOP. This read is authoritative for the realm-role gate and
        best-effort for the client scope mapping (the durable controller holds
        view-realm, which reads realm roles and groups, but not necessarily
        the client detail needed for a scope-mapping read — an unreadable
        mapping is reported, never guessed).
        """
        token = await self._controller_token()
        realm = path_segment(self.settings.identity_realm, label="Keycloak realm")

        role_response = await self._request(
            "GET",
            f"/admin/realms/{realm}/roles/{CHAT_CAPABILITY_ROLE}",
            token=token,
            expected=(200, 404),
        )
        chat_role_present = role_response.status_code == 200
        if chat_role_present:
            role = self._json(role_response, "chat capability role")
            if not isinstance(role, dict) or role.get("name") != CHAT_CAPABILITY_ROLE:
                raise IdentityError("Keycloak chat capability role was invalid")

        open_webui_scope_readable = False
        open_webui_scope_ok = False
        if chat_role_present:
            try:
                client = await self._find_client(realm, "open-webui", token)
                if client is not None:
                    mappings = await self._client_realm_role_scope_mappings(
                        realm, client, token
                    )
                    open_webui_scope_readable = True
                    open_webui_scope_ok = any(
                        str(role.get("name")) == CHAT_CAPABILITY_ROLE
                        for role in mappings
                    )
            except IdentityError:
                # view-realm may not cover the client scope-mapping sub-resource
                # on every Keycloak build. Report unreadable rather than fail:
                # the realm-role gate above already proves the migration ran,
                # and the same SOP step adds the client mapping.
                open_webui_scope_readable = False

        chat_groups = sorted(
            group["name"]
            for group in await self.list_groups()
            if CHAT_CAPABILITY_ROLE in group.get("capabilities", [])
        )

        return {
            "chat_role_present": chat_role_present,
            "open_webui_scope_readable": open_webui_scope_readable,
            "open_webui_scope_ok": open_webui_scope_ok,
            "chat_groups": chat_groups,
        }

    async def _user_project_bindings(
        self, user_id: str, token: str
    ) -> dict[str, str]:
        """Map live developer project IDs to their managed group UUIDs.

        A project is exactly one direct child of ``/aigw-managed`` whose group
        has the ``aigw-developers`` capability.  Nested groups, malformed
        names, or two distinct group UUIDs claiming the same project ID are an
        ambiguous authorization state and fail closed.  The portal calls this
        for every key page and mutation, so a stale browser role/group claim
        cannot mint a key after membership removal.
        """
        state_doc = self._identity_state()
        provider_id = state_doc.get("federation_provider_id")
        if not isinstance(provider_id, str) or not provider_id:
            return {}
        realm = path_segment(self.settings.identity_realm, label="Keycloak realm")
        safe_user = path_segment(user_id, label="user UUID")
        user_response = await self._request(
            "GET",
            f"/admin/realms/{realm}/users/{safe_user}",
            token=token,
            expected=(200, 404),
        )
        if user_response.status_code == 404:
            return {}
        user = self._json(user_response, "project authorization user")
        if (
            not isinstance(user, dict)
            or user.get("enabled") is not True
            or user.get("federationLink") != provider_id
        ):
            return {}

        memberships: list[dict[str, Any]] = []
        for page in range(MAX_PAGE_COUNT):
            response = await self._request(
                "GET",
                f"/admin/realms/{realm}/users/{safe_user}/groups",
                token=token,
                params={
                    "first": page * PAGE_SIZE,
                    "max": PAGE_SIZE,
                    "briefRepresentation": "false",
                },
                expected=(200,),
            )
            payload = self._json(response, "project group memberships")
            if not isinstance(payload, list):
                raise IdentityError("Keycloak group memberships were invalid")
            if any(not isinstance(group, dict) for group in payload):
                raise IdentityError("Keycloak group membership was not an object")
            memberships.extend(payload)
            if len(payload) < PAGE_SIZE:
                break
        else:
            raise IdentityConflict(
                "user group membership exceeds the supported safety bound"
            )

        root = self.settings.identity_managed_root_group
        managed_prefix = f"/{root}/"
        projects: dict[str, str] = {}
        for group in memberships:
            group_path = group.get("path")
            if group_path == f"/{root}":
                raise IdentityConflict(
                    "the managed root cannot be a user project membership"
                )
            if not isinstance(group_path, str) or not group_path.startswith(
                managed_prefix
            ):
                continue
            project_id = group_path.removeprefix(managed_prefix)
            if "/" in project_id or PROJECT_ID_RE.fullmatch(project_id) is None:
                raise IdentityConflict(
                    "managed project membership is nested or has an invalid ID"
                )
            group_id = path_segment(group.get("id"), label="project group UUID")
            if "aigw-developers" not in await self._group_capabilities(group_id, token):
                continue
            previous = projects.get(project_id)
            if previous is not None and previous != group_id:
                raise IdentityConflict(
                    "multiple managed groups claim the same project ID"
                )
            projects[project_id] = group_id
        return projects

    async def _logout_user_sessions(self, user_id: str, token: str) -> None:
        """Invalidate Keycloak sessions after a role-removing mutation."""
        realm = path_segment(self.settings.identity_realm, label="Keycloak realm")
        safe_user = path_segment(user_id, label="user UUID")
        await self._request(
            "POST",
            f"/admin/realms/{realm}/users/{safe_user}/logout",
            token=token,
            expected=(204,),
        )

    @staticmethod
    def _safe_user(user: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": user.get("id", ""),
            "username": user.get("username", ""),
            "email": user.get("email", ""),
            "first_name": user.get("firstName", ""),
            "last_name": user.get("lastName", ""),
            "enabled": bool(user.get("enabled")),
        }

    async def list_groups(self) -> list[dict[str, Any]]:
        token = await self._controller_token()
        state_doc = self._identity_state()
        root_id = path_segment(
            state_doc.get("managed_root_group_id"), label="managed root UUID"
        )
        realm = path_segment(self.settings.identity_realm, label="Keycloak realm")
        result: list[dict[str, Any]] = []
        for page in range(MAX_PAGE_COUNT):
            response = await self._request(
                "GET",
                f"/admin/realms/{realm}/groups/{root_id}/children",
                token=token,
                params={
                    "first": page * PAGE_SIZE,
                    "max": PAGE_SIZE,
                    "briefRepresentation": "false",
                },
                expected=(200,),
            )
            payload = self._json(response, "managed groups")
            if not isinstance(payload, list):
                raise IdentityError("Keycloak managed groups were invalid")
            for group in payload:
                if not isinstance(group, dict):
                    continue
                group_id = path_segment(group.get("id"), label="group UUID")
                members = await self._members(group_id, token)
                result.append(
                    {
                        "id": group_id,
                        "name": str(group.get("name") or ""),
                        "capabilities": await self._group_capabilities(group_id, token),
                        "member_count": len(members),
                        # Non-secret issuance policy for the admin console.
                        # The children listing is a full representation, so
                        # the same attribute parser applies; a malformed
                        # policy fails the listing closed instead of showing
                        # a restricted project as unlimited.
                        "policy": self._group_policy(group),
                    }
                )
            if len(payload) < PAGE_SIZE:
                return sorted(result, key=lambda group: group["name"].lower())
        raise IdentityConflict("managed group count exceeds the supported safety bound")

    async def search_users(self, query: str = "") -> list[dict[str, Any]]:
        if len(query) > 64 or any(ord(ch) < 32 for ch in query):
            raise IdentityConflict("user search is invalid")
        token = await self._controller_token()
        state_doc = self._identity_state()
        provider_id = state_doc.get("federation_provider_id")
        if not provider_id:
            return []
        realm = path_segment(self.settings.identity_realm, label="Keycloak realm")
        response = await self._request(
            "GET",
            f"/admin/realms/{realm}/users",
            token=token,
            params={
                "search": query.strip(),
                "first": 0,
                "max": 50,
                "briefRepresentation": "false",
            },
            expected=(200,),
        )
        payload = self._json(response, "user search")
        if not isinstance(payload, list):
            raise IdentityError("Keycloak user search was invalid")
        return [
            self._safe_user(user)
            for user in payload
            if isinstance(user, dict) and user.get("federationLink") == provider_id
        ]

    async def group_members(self, group_id: str) -> list[dict[str, Any]]:
        token = await self._controller_token()
        await self._managed_group(group_id, token)
        state_doc = self._identity_state()
        provider_id = state_doc.get("federation_provider_id")
        return [
            self._safe_user(member)
            for member in await self._members(group_id, token)
            if member.get("federationLink") == provider_id
        ]

    async def create_group(self, name: str, capabilities: list[str]) -> dict[str, Any]:
        async with self._group_topology_lock:
            return await self._create_group_locked(name, capabilities)

    async def _create_group_locked(
        self, name: str, capabilities: list[str]
    ) -> dict[str, Any]:
        """Create one group while the managed topology lock is held."""
        clean_name = name.strip()
        if PROJECT_ID_RE.fullmatch(clean_name) is None:
            raise IdentityConflict(
                "project group ID must match [a-z0-9][a-z0-9_.-]{0,63}"
            )
        capability_set = set(capabilities)
        if not capability_set or not capability_set <= CAPABILITY_ROLES:
            raise IdentityConflict("group capabilities are missing or invalid")
        token = await self._controller_token()
        state_doc = self._identity_state()
        root_id = path_segment(
            state_doc.get("managed_root_group_id"), label="managed root UUID"
        )
        realm = path_segment(self.settings.identity_realm, label="Keycloak realm")
        try:
            response = await self._request(
                "POST",
                f"/admin/realms/{realm}/groups/{root_id}/children",
                token=token,
                json_body={"name": clean_name},
                expected=(201, 204),
            )
        except IdentityError as exc:
            raise IdentityConflict("group name already exists or was rejected") from exc
        location = response.headers.get("location", "")
        group_id = location.rstrip("/").rsplit("/", 1)[-1]
        if not group_id:
            raise IdentityError("Keycloak did not identify the new group")
        group_id = path_segment(group_id, label="new group UUID")
        try:
            roles: list[dict[str, Any]] = []
            for capability in sorted(capability_set):
                role_response = await self._request(
                    "GET",
                    f"/admin/realms/{realm}/roles/{capability}",
                    token=token,
                    expected=(200,),
                )
                role = self._json(role_response, "capability role")
                if not isinstance(role, dict) or role.get("name") != capability:
                    raise IdentityError(f"capability role {capability} is missing")
                roles.append(role)
            await self._request(
                "POST",
                f"/admin/realms/{realm}/groups/{group_id}/role-mappings/realm",
                token=token,
                json_body=roles,
                expected=(204,),
            )
        except Exception:
            await self._request(
                "DELETE",
                f"/admin/realms/{realm}/groups/{group_id}",
                token=token,
                expected=(204,),
            )
            raise
        await self._audit(
            "group_create",
            "success",
            {"group_id": group_id, "capabilities": sorted(capability_set)},
        )
        return {
            "id": group_id,
            "name": clean_name,
            "capabilities": sorted(capability_set),
            "member_count": 0,
        }

    async def delete_group(self, group_id: str) -> None:
        async with self._group_topology_lock:
            await self._delete_group_locked(group_id)

    async def _delete_group_locked(self, group_id: str) -> None:
        """Delete an empty group while the managed topology lock is held."""
        token = await self._controller_token()
        await self._managed_group(group_id, token)
        if await self._members(group_id, token):
            raise IdentityConflict("remove every member before deleting a group")
        realm = path_segment(self.settings.identity_realm, label="Keycloak realm")
        safe_group = path_segment(group_id, label="group UUID")
        await self._request(
            "DELETE",
            f"/admin/realms/{realm}/groups/{safe_group}",
            token=token,
            expected=(204,),
        )
        await self._audit("group_delete", "success", {"group_id": safe_group})

    async def add_member(self, group_id: str, user_id: str) -> None:
        async with self._group_topology_lock:
            await self._add_member_locked(group_id, user_id)

    async def _add_member_locked(self, group_id: str, user_id: str) -> None:
        """Add a federated user while the managed topology lock is held."""
        token = await self._controller_token()
        await self._managed_group(group_id, token)
        user = await self._federated_user(user_id, token)
        if user.get("enabled") is not True:
            raise IdentityConflict(
                "only an enabled federated user may be assigned to a managed group"
            )
        realm = path_segment(self.settings.identity_realm, label="Keycloak realm")
        safe_group = path_segment(group_id, label="group UUID")
        safe_user = path_segment(user_id, label="user UUID")
        await self._request(
            "PUT",
            f"/admin/realms/{realm}/users/{safe_user}/groups/{safe_group}",
            token=token,
            expected=(204,),
        )
        await self._audit(
            "group_member_add",
            "success",
            {"group_id": safe_group, "user_id": safe_user},
        )

    async def _managed_admin_user_ids(
        self,
        token: str,
        *,
        excluded_group_id: str = "",
        excluded_user_id: str = "",
    ) -> set[str]:
        state_doc = self._identity_state()
        provider_id = state_doc.get("federation_provider_id")
        if not isinstance(provider_id, str) or not provider_id:
            raise IdentityConflict("no LDAP federation provider is configured")
        admin_users: set[str] = set()
        for group in await self.list_groups():
            if "aigw-admins" not in group["capabilities"]:
                continue
            for member in await self._members(group["id"], token):
                member_id = member.get("id")
                if not isinstance(member_id, str) or not member_id:
                    continue
                # Model the prospective removal from only this group. A user
                # who remains in another managed admin group still provides a
                # valid recovery administrator, but a disabled, stale, or local
                # Keycloak principal does not. Counting those identities could
                # authorize removal of the final usable directory admin.
                if (
                    group["id"] == excluded_group_id
                    and member_id == excluded_user_id
                ):
                    continue
                if await self._is_current_enabled_federated_admin(
                    member_id,
                    token,
                    provider_id,
                ):
                    admin_users.add(member_id)
        return admin_users

    async def _is_current_enabled_federated_admin(
        self,
        user_id: str,
        token: str,
        provider_id: str,
    ) -> bool:
        """Resolve a recovery-admin candidate from fresh Keycloak state.

        Group-member representations are snapshots and can retain a stale
        principal reference.  Count a candidate only when Keycloak currently
        resolves it as enabled, links it to the inventory-bound federation,
        and reports the composite administrator role.  A definite 404 is a
        stale/non-current candidate; malformed or unreachable state raises so
        the caller refuses the last-admin mutation rather than guessing.

        This proves the current Keycloak federated-principal view.  It does
        not claim to authenticate the user's upstream directory password.
        """

        realm = path_segment(self.settings.identity_realm, label="Keycloak realm")
        safe_user = path_segment(user_id, label="user UUID")
        user_response = await self._request(
            "GET",
            f"/admin/realms/{realm}/users/{safe_user}",
            token=token,
            expected=(200, 404),
        )
        if user_response.status_code == 404:
            return False
        user = self._json(user_response, "managed administrator candidate")
        if not isinstance(user, dict):
            raise IdentityError(
                "Keycloak managed administrator candidate was invalid"
            )
        if (
            user.get("enabled") is not True
            or user.get("federationLink") != provider_id
        ):
            return False

        roles_response = await self._request(
            "GET",
            (
                f"/admin/realms/{realm}/users/{safe_user}"
                "/role-mappings/realm/composite"
            ),
            token=token,
            expected=(200, 404),
        )
        if roles_response.status_code == 404:
            return False
        roles = self._json(
            roles_response,
            "managed administrator candidate composite roles",
        )
        if not isinstance(roles, list) or any(
            not isinstance(role, dict) for role in roles
        ):
            raise IdentityError(
                "Keycloak managed administrator composite roles were invalid"
            )
        return any(role.get("name") == "aigw-admins" for role in roles)

    async def remove_member(self, group_id: str, user_id: str) -> None:
        async with self._group_topology_lock:
            await self._remove_member_locked(group_id, user_id)

    async def _remove_member_locked(self, group_id: str, user_id: str) -> None:
        """Check last-admin state and remove while the topology lock is held."""
        token = await self._controller_token()
        group = await self._managed_group(group_id, token)
        project_id = self._managed_project_id(group)
        await self._federated_user(user_id, token)
        capabilities = await self._group_capabilities(group_id, token)
        safe_user = path_segment(user_id, label="user UUID")
        if "aigw-admins" in capabilities:
            current_members = {
                member.get("id")
                for member in await self._members(group_id, token)
                if isinstance(member.get("id"), str)
            }
            remaining_admins = await self._managed_admin_user_ids(
                token,
                excluded_group_id=group_id,
                excluded_user_id=safe_user,
            )
            if safe_user in current_members and not remaining_admins:
                raise IdentityConflict(
                    "refusing to remove the last managed administrator"
                )

        # LiteLLM accepts virtual keys as static bearer credentials and does
        # not consult Keycloak on inference requests. Revoke first so a
        # successful membership mutation cannot leave a known portal key
        # usable; repeat after the mutation to close a concurrent generation
        # window. The revoker inventories and verifies both passes.
        await self._revoke_portal_project_keys(safe_user, project_id)
        realm = path_segment(self.settings.identity_realm, label="Keycloak realm")
        safe_group = path_segment(group_id, label="group UUID")
        delete_error: Exception | None = None
        post_revoke_error: Exception | None = None
        logout_error: Exception | None = None
        try:
            await self._request(
                "DELETE",
                f"/admin/realms/{realm}/users/{safe_user}/groups/{safe_group}",
                token=token,
                expected=(204,),
            )
        except Exception as exc:  # noqa: BLE001
            # A timeout or error response can arrive after Keycloak committed
            # the mutation. Do not mistake that ambiguous transport outcome for
            # proof that the membership — and a concurrently minted static key
            # — are still intact.
            delete_error = exc
        finally:
            try:
                # Run this even after an ambiguous DELETE. It both closes the
                # mint/removal race and verifies that a static bearer key is no
                # longer active before an error is returned to the caller.
                await self._revoke_portal_project_keys(safe_user, project_id)
            except Exception as exc:  # noqa: BLE001
                post_revoke_error = exc
            try:
                # The DELETE may have committed even when its response was
                # lost, so logging the subject out is the safe outcome here as
                # well. A failed/unknown deletion only forces a fresh login;
                # it never preserves a stale role-bearing session.
                await self._logout_user_sessions(safe_user, token)
            except Exception as exc:  # noqa: BLE001
                logout_error = exc

        if delete_error is not None:
            if post_revoke_error is not None:
                raise IdentityError(
                    "could not verify portal-key revocation after membership removal"
                ) from post_revoke_error
            raise IdentityError(
                "could not verify Keycloak membership removal"
            ) from delete_error
        if post_revoke_error is not None:
            raise IdentityError(
                "could not verify portal-key revocation after membership removal"
            ) from post_revoke_error
        if logout_error is not None:
            raise IdentityError(
                "could not invalidate Keycloak user sessions"
            ) from logout_error
        await self._audit(
            "group_member_remove",
            "success",
            {"group_id": safe_group, "user_id": safe_user, "project": project_id},
        )
