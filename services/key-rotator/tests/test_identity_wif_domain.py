from __future__ import annotations

import copy
import json

import httpx
import pytest
from pydantic import ValidationError

from app.config import Settings
from app.identity import (
    IdentityError,
    IdentityNotFound,
    KeycloakAdmin,
)


DOMAIN = "customer.example.internal"
WIF_URL = f"https://idp.wif.{DOMAIN}"


def settings(**overrides) -> Settings:
    values = {
        "AIGW_DOMAIN": DOMAIN,
        "WIF_KEYCLOAK_PUBLIC_URL": WIF_URL,
        "ROTATOR_INTERNAL_TOKEN": "0123456789abcdef0123456789abcdef",
        "PORTAL_IDENTITY_TOKEN": "abcdef0123456789abcdef0123456789",
        "LITELLM_MASTER_KEY": "litellm-master-key",
        "KC_BOOTSTRAP_ADMIN_CLIENT_SECRET": (
            "Bootstrap-Secret!0123456789-ABCDEFGHIJKLMN"
        ),
    }
    values.update(overrides)
    return Settings(**values)


class RealmAPI:
    def __init__(self, frontend_url: str, *, ignore_put: bool = False) -> None:
        self.realm = {
            "id": "wif-realm-id",
            "realm": "anthropic-wif",
            "enabled": True,
            "attributes": {
                "frontendUrl": frontend_url,
                "unmanaged": "preserved",
            },
        }
        self.ignore_put = ignore_put
        self.calls: list[tuple[str, str]] = []
        self.updates: list[dict] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append((request.method, request.url.path))
        if request.url.path != "/admin/realms/anthropic-wif":
            raise AssertionError(f"unexpected path: {request.url.path}")
        if request.method == "GET":
            return httpx.Response(200, json=copy.deepcopy(self.realm))
        if request.method == "PUT":
            update = json.loads(request.content)
            self.updates.append(update)
            if not self.ignore_put:
                self.realm = copy.deepcopy(update)
            return httpx.Response(204)
        raise AssertionError(f"unexpected method: {request.method}")


def admin_for(api: RealmAPI, **overrides) -> KeycloakAdmin:
    return KeycloakAdmin(
        settings(**overrides),
        None,
        None,
        transport=httpx.MockTransport(api.handler),
    )


@pytest.mark.asyncio
async def test_existing_wif_realm_is_moved_to_the_inventory_domain() -> None:
    api = RealmAPI("https://idp.wif.old.example.internal")

    assert await admin_for(api)._reconcile_wif_frontend_url("admin-token") is True

    assert len(api.updates) == 1
    assert api.updates[0]["attributes"] == {
        "frontendUrl": WIF_URL,
        "unmanaged": "preserved",
    }
    assert api.calls == [
        ("GET", "/admin/realms/anthropic-wif"),
        ("PUT", "/admin/realms/anthropic-wif"),
        ("GET", "/admin/realms/anthropic-wif"),
    ]


@pytest.mark.asyncio
async def test_matching_wif_realm_is_read_back_without_a_put() -> None:
    api = RealmAPI(WIF_URL)

    assert await admin_for(api)._reconcile_wif_frontend_url("admin-token") is False

    assert api.updates == []
    assert api.calls == [
        ("GET", "/admin/realms/anthropic-wif"),
        ("GET", "/admin/realms/anthropic-wif"),
    ]


@pytest.mark.asyncio
async def test_wif_realm_update_must_be_visible_on_readback() -> None:
    api = RealmAPI("https://idp.wif.old.example.internal", ignore_put=True)

    with pytest.raises(IdentityError, match="did not verify"):
        await admin_for(api)._reconcile_wif_frontend_url("admin-token")


def test_wif_public_url_cannot_disagree_with_aigw_domain() -> None:
    with pytest.raises(ValidationError, match="WIF_KEYCLOAK_PUBLIC_URL"):
        settings(
            WIF_KEYCLOAK_PUBLIC_URL="https://idp.wif.somewhere-else.internal",
        )


@pytest.mark.asyncio
async def test_broker_setup_reconciles_the_wif_realm_before_client_lookup() -> None:
    events: list[str] = []

    class OrderedAdmin(KeycloakAdmin):
        async def _reconcile_wif_frontend_url(
            self, admin_token, before_change=None
        ):
            events.append("realm")
            return False

        async def _find_client(self, realm, client_id, admin_token):
            events.append("client")
            return None

    admin = OrderedAdmin(settings(), None, None)
    with pytest.raises(IdentityNotFound, match="broker client is missing"):
        await admin._ensure_broker("admin-token")

    assert events == ["realm", "client"]
