from __future__ import annotations

import json
import os
import sys
from base64 import b64encode
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from itsdangerous import TimestampSigner


SERVICE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVICE_ROOT))

# config.py fails closed at import, so tests deliberately use strong, obviously
# non-production values before importing the application.
os.environ.setdefault("SESSION_SECRET", "Test-Session-Secret!0123456789-ABCDEFG")
os.environ.setdefault("LITELLM_MASTER_KEY", "sk-Test-LiteLLM-Master!0123456789-XYZ")
os.environ.setdefault("OIDC_CLIENT_SECRET", "Test-OIDC-Client!0123456789-Secret-XYZ")
os.environ.setdefault("OIDC_ISSUER", "https://idp.test/realms/aigw")

from app.config import settings  # noqa: E402
from app.main import app  # noqa: E402


def session_cookie(session: dict[str, Any]) -> str:
    payload = b64encode(json.dumps(session).encode("utf-8"))
    return TimestampSigner(settings.session_secret).sign(payload).decode("utf-8")


def portal_user(
    *, subject: str = "subject-123", roles: list[str] | None = None
) -> dict[str, Any]:
    return {
        "sub": subject,
        "email": "developer@example.test",
        "name": "Developer",
        "roles": roles if roles is not None else [settings.developer_role],
    }


@pytest.fixture
def client() -> TestClient:
    # HTTPS is required so httpx sends the middleware's Secure session cookie.
    return TestClient(app, base_url="https://portal.test")


@pytest.fixture
def set_session(client: TestClient):
    def _set(data: dict[str, Any]) -> None:
        client.cookies.set("session", session_cookie(data))

    return _set
