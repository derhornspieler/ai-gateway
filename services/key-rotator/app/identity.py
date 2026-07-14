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

from app.config import LAB_LDAP_PROVIDER_NAME, Settings
from app.security import (
    path_segment,
    service_account_subject,
    validate_wif_token_claims,
)

CAPABILITY_ROLES = frozenset({"aigw-users", "aigw-developers", "aigw-admins"})
# These are the only browser-facing OIDC clients managed by this controller.
# Keep this explicit rather than deriving it from a Keycloak search result: a
# temporary bootstrap administrator is intentionally powerful, so a recovery
# reconciliation must never broaden to an operator-created client.
RELYING_PARTY_CLIENT_IDS = (
    "open-webui",
    "dev-portal",
    "admin-portal",
    "admin-ui",
)
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
# A managed Keycloak group is the project security boundary.  Its direct-child
# name is therefore the canonical project identifier copied into LiteLLM key
# metadata and audit records.  Lowercase-only prevents case-fold collisions
# across Keycloak, PostgreSQL, log queries, and filesystem/tool configuration.
PROJECT_ID_RE = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}")
BOOTSTRAP_IDENTITY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}")
FEDERATION_PROVIDER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_. -]{0,127}")
MANAGED_ROOT_ATTRIBUTE = "aigw.managed-root"
BROKER_SUBJECT_MAPPER_NAME = "anthropic-stable-subject"
# The lab federation's user filter, kept byte-identical to the representation
# that existing lab components already carry. Changing it would make an
# existing lab provider fail verification and be reprovisioned.
LAB_LDAP_USER_FILTER = (
    "(&(objectCategory=person)(objectClass=user)"
    "(!(sAMAccountName=svc-keycloak-ldap)))"
)


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
    # Prove the directory, its trust chain, and the bind credential against
    # Keycloak before persisting a provider. This guards an EXTERNAL customer
    # directory, where a wrong CA bundle, a certificate that fails hostname
    # verification, or wrong bind credentials must fail closed rather than
    # leave a broken component behind. The lab DC is an in-stack,
    # healthcheck-gated dependency with a published CA and is deliberately
    # exempt: its creation path is unchanged, so a lab converge cannot regress.
    prove_directory_before_create: bool


def ldap_federation_spec(settings: Settings) -> LdapFederationSpec | None:
    """Resolve the single enabled federation source, or None.

    Settings already refuses to enable both sources at once. The lab branch
    reproduces today's hardcoded lab representation exactly, so the existing
    ``lab-samba-ad`` component keeps its id, name, and config across converges.
    """
    if settings.lab_samba_ldap_enabled:
        return LdapFederationSpec(
            provider_name=LAB_LDAP_PROVIDER_NAME,
            connection_url=settings.lab_samba_ldap_url,
            users_dn=settings.lab_samba_users_dn,
            bind_dn=settings.lab_samba_bind_dn,
            bind_password_file=settings.lab_samba_bind_password_file,
            vendor="ad",
            username_attribute="sAMAccountName",
            rdn_attribute="cn",
            uuid_attribute="objectGUID",
            user_object_classes="person, organizationalPerson, user",
            user_filter=LAB_LDAP_USER_FILTER,
            prove_directory_before_create=False,
        )
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
            prove_directory_before_create=True,
        )
    return None


class IdentityError(RuntimeError):
    """Safe, non-secret identity-control failure."""


class IdentityNotFound(IdentityError):
    pass


class IdentityConflict(IdentityError):
    pass


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
            raise IdentityError(
                f"Keycloak rejected {method.upper()} {path} "
                f"(HTTP {response.status_code})"
            )
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
        payload = self._json(response, "bootstrap token")
        token = payload.get("access_token") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token:
            raise IdentityError("Keycloak did not issue a bootstrap access token")
        return token

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

    async def reconcile_prebootstrap_relying_party_role_scopes(self) -> bool:
        """Repair only RP role scopes before the interactive identity bootstrap.

        This is deliberately narrower than :meth:`bootstrap`: it never writes
        Vault, creates a controller, mutates client settings, or deletes the
        temporary master-realm bootstrap client.  It is usable only while the
        exact pre-bootstrap state is positively observed, preventing an
        Ansible migration helper from becoming a recurring privileged client
        reconciler after normal identity setup has completed.
        """

        status = await self.status()
        if not (
            # ``configured`` deliberately includes a controller-token probe so
            # the admin UI can report a broken durable controller.  It is not
            # by itself proof that bootstrap never progressed: an existing
            # state document plus a transiently unusable controller also
            # reports configured=false.  This privileged recovery bridge is
            # allowed only before that document has ever been written.
            status.get("identity_state_absent") is True
            and status.get("configured") is False
            and status.get("controller_usable") is False
            and status.get("bootstrap_available") is True
        ):
            return False

        admin_token = await self._bootstrap_token()
        realm = self.settings.identity_realm
        desired_roles = await self._capability_role_representations(realm, admin_token)
        for client_id in RELYING_PARTY_CLIENT_IDS:
            found = await self._find_client(realm, client_id, admin_token)
            if found is None:
                raise IdentityError(f"OIDC client {client_id} is missing")
            client = await self._get_client(realm, found, admin_token)
            if client.get("fullScopeAllowed") is not False:
                raise IdentityConflict(
                    f"OIDC client {client_id} must retain fullScopeAllowed=false"
                )
            await self._reconcile_client_realm_role_scope_mappings(
                realm, client, desired_roles, admin_token
            )
            verified = await self._get_client(realm, client, admin_token)
            if verified.get("fullScopeAllowed") is not False:
                raise IdentityConflict(
                    f"OIDC client {client_id} must retain fullScopeAllowed=false"
                )
            self._verify_realm_roles_mapper(verified, client_id)
        return True

    async def _reconcile_relying_party_redirect_uris(self, admin_token: str) -> bool:
        """Converge ONLY the domain-derived callback allow-lists of the four
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
            # Only the two clients whose spec declares an RP-initiated logout
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
        except IdentityError:
            # The temporary master-realm client has been deleted by the
            # interactive bootstrap ceremony (or Keycloak is transiently
            # unreachable — the converge waits for Keycloak health first).
            # Either way this routine converge cannot manage clients; report the
            # required operator ceremony instead of failing or falsely claiming
            # success while SSO stays broken.
            return "rebootstrap_required"
        changed = await self._reconcile_relying_party_redirect_uris(admin_token)
        return "applied" if changed else "verified"

    @staticmethod
    def _validate_pre_vault_identity_spec(
        spec: dict[str, Any],
    ) -> tuple[list[dict[str, Any]], list[dict[str, str]], bool]:
        """Validate the complete, inventory-owned pre-Vault mutation set.

        The temporary master-realm client is intentionally powerful.  This
        parser therefore rejects unknown fields and non-canonical values
        before obtaining its token.  It never derives groups or users from a
        Keycloak search result: every writable object must be named in the
        root-owned Ansible input.
        """

        if not isinstance(spec, dict) or set(spec) != {
            "schema",
            "ensure_lab_federation",
            "groups",
            "bootstrap_admin_identities",
        }:
            raise IdentityConflict("pre-Vault identity specification is invalid")
        if spec.get("schema") != PRE_VAULT_IDENTITY_SCHEMA:
            raise IdentityConflict("pre-Vault identity specification schema is invalid")
        ensure_lab_federation = spec.get("ensure_lab_federation")
        if not isinstance(ensure_lab_federation, bool):
            raise IdentityConflict("pre-Vault federation policy is invalid")

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
                or group_roles[group] != frozenset({"aigw-admins"})
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
        if ensure_lab_federation and {
            identity["federation_provider"] for identity in identities
        } != {LAB_LDAP_PROVIDER_NAME}:
            raise IdentityConflict("lab federation bootstrap identity is invalid")
        return groups, identities, ensure_lab_federation

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

        groups, identities, ensure_lab_federation = (
            self._validate_pre_vault_identity_spec(spec)
        )
        if ensure_lab_federation and not self.settings.lab_samba_ldap_enabled:
            raise IdentityConflict("lab federation bootstrap is not enabled")

        admin_token = await self._bootstrap_token()
        changed = False
        changed = (
            await self._ensure_relying_parties(admin_token, preserve_unmanaged=True)
            or changed
        )
        if ensure_lab_federation:
            before = await self._find_component(
                self.settings.identity_realm, LAB_LDAP_PROVIDER_NAME, admin_token
            )
            await self._ensure_ldap_federation(admin_token, self._ldap_bind_password())
            changed = changed or before is None

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
            component_id = await self._verify_bound_ldap_component(
                existing, admin_token
            )
            # An EXISTING external provider whose top-level config still equals
            # the inventory contract is NOT proof that a login will succeed: a
            # rotated DC certificate, a swapped/wrong CA truststore, or a
            # rotated bind credential all keep the persisted config identical
            # while breaking the live LDAPS handshake or bind. Re-exercise the
            # read-only, idempotent live proof on every reconcile so the
            # converge fails closed here instead of converging green and
            # failing at first login. The in-stack lab DC is deliberately
            # exempt (prove_directory_before_create=False), so a lab converge
            # is unchanged.
            if spec.prove_directory_before_create:
                await self._prove_ldap_directory(
                    spec, admin_token, self._require_ldap_bind_password(bind_password)
                )
            return component_id
        bind_password = self._require_ldap_bind_password(bind_password)
        safe_realm = path_segment(self.settings.identity_realm, label="Keycloak realm")
        if spec.prove_directory_before_create:
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
        expected = {
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

    async def _delete_bootstrap_principals(self, admin_token: str) -> bool:
        """Delete temporary principals; optionally retain a lab UI operator.

        Returns true only when the marked password-backed bootstrap user was
        deliberately converted to the lab recovery operator.  The
        broad temporary service client is always deleted.
        """
        retained_user = False
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
        if matches:
            attributes = matches[0].get("attributes") or {}
            if attributes.get("is_temporary_admin") not in (["true"], "true"):
                raise IdentityConflict(
                    "refusing to delete an unmarked master-realm administrator"
                )
            user_id = path_segment(matches[0].get("id"), label="bootstrap user UUID")
            if self.settings.retain_bootstrap_admin_user:
                user = dict(matches[0])
                updated_attributes = dict(attributes)
                updated_attributes.pop("is_temporary_admin", None)
                updated_attributes["aigw.lab-recovery-operator"] = ["true"]
                user["attributes"] = updated_attributes
                await self._request(
                    "PUT",
                    f"/admin/realms/master/users/{user_id}",
                    token=admin_token,
                    json_body=user,
                    expected=(204,),
                )
                verified_response = await self._request(
                    "GET",
                    f"/admin/realms/master/users/{user_id}",
                    token=admin_token,
                    expected=(200,),
                )
                verified_user = self._json(verified_response, "lab recovery operator")
                verified_attributes = (
                    verified_user.get("attributes")
                    if isinstance(verified_user, dict)
                    else None
                )
                if (
                    not isinstance(verified_attributes, dict)
                    or "is_temporary_admin" in verified_attributes
                    or verified_attributes.get("aigw.lab-recovery-operator")
                    not in (["true"], "true")
                ):
                    raise IdentityError(
                        "Keycloak did not verify the lab recovery operator"
                    )
                retained_user = True
            else:
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
            return retained_user
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
        return retained_user

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

    async def bootstrap(self) -> dict[str, Any]:
        """Consume the one-time Keycloak admin and establish durable controls."""
        async with self._bootstrap_lock:
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
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                }
                if not self.vault.write_verified(
                    self.settings.identity_state_vault_path, state_doc
                ):
                    raise IdentityError("Vault did not verify identity state")
                bootstrap_user_retained = await self._delete_bootstrap_principals(
                    admin_token
                )
                await self._audit(
                    "bootstrap",
                    "success",
                    {
                        "managed_root_group_id": state_doc["managed_root_group_id"],
                        "federation_configured": bool(federation_id),
                        "temporary_bootstrap_service_deleted": True,
                        "lab_recovery_operator_retained": bootstrap_user_retained,
                    },
                )
                return await self.status()
            except Exception as exc:
                await self._audit(
                    "bootstrap", "failed", {"error_type": type(exc).__name__}
                )
                raise

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
        }

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
        """Resolve live developer projects from direct managed-group membership.

        A project is exactly one direct child of ``/aigw-managed`` whose group
        has the ``aigw-developers`` capability.  Nested groups, malformed
        names, or two distinct group UUIDs claiming the same project ID are an
        ambiguous authorization state and fail closed.  The portal calls this
        for every key page and mutation, so a stale browser role/group claim
        cannot mint a key after membership removal.
        """
        token = await self._controller_token()
        state_doc = self._identity_state()
        provider_id = state_doc.get("federation_provider_id")
        if not isinstance(provider_id, str) or not provider_id:
            return []
        realm = path_segment(self.settings.identity_realm, label="Keycloak realm")
        safe_user = path_segment(user_id, label="user UUID")
        user_response = await self._request(
            "GET",
            f"/admin/realms/{realm}/users/{safe_user}",
            token=token,
            expected=(200, 404),
        )
        if user_response.status_code == 404:
            return []
        user = self._json(user_response, "project authorization user")
        if (
            not isinstance(user, dict)
            or user.get("enabled") is not True
            or user.get("federationLink") != provider_id
        ):
            return []

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
        return sorted(projects)

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
