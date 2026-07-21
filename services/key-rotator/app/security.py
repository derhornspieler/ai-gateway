"""Small security-boundary helpers shared by outbound clients."""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

import jwt


_RESOURCE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


def path_segment(value: Any, *, label: str) -> str:
    """Validate and encode an opaque identifier used in an outbound path.

    Project, organization, issuer, and service-account IDs originate in
    Vault or in a vendor response. Treating them as trusted path text lets a
    compromised peer inject ``/``, ``..``, a query, or a fragment and make an
    admin credential authorize a different endpoint than intended.
    """
    if not isinstance(value, str) or not _RESOURCE_ID.fullmatch(value):
        raise ValueError(
            f"{label} must be 1-128 characters containing only letters, digits, '.', '_', or '-'"
        )
    return quote(value, safe="")


def service_account_subject(client_id: str) -> str:
    """Stable WIF subject explicitly emitted by the Keycloak mapper."""
    path_segment(client_id, label="Keycloak client id")
    return f"service-account-{client_id}"


def validate_wif_token_claims(
    token: str, *, client_id: str, audience: str = "https://api.anthropic.com"
) -> dict[str, Any]:
    """Fail before vendor exchange if Keycloak emitted unstable WIF claims.

    Signature verification remains Anthropic's job and Keycloak was reached
    over the isolated internal service network. This local decode is a runtime
    configuration assertion: the stable hard-coded subject mapper and audience
    mapper must actually have affected the issued access token.
    """
    try:
        claims = jwt.decode(
            token,
            options={
                "verify_signature": False,
                "verify_aud": False,
                "verify_exp": False,
                "verify_iss": False,
            },
        )
    except Exception as exc:  # noqa: BLE001
        raise ValueError("Keycloak returned an unreadable WIF access token") from exc
    if claims.get("sub") != service_account_subject(client_id):
        raise ValueError("Keycloak WIF access token has an unstable subject claim")
    raw_audience = claims.get("aud")
    exact_audience = raw_audience == audience or raw_audience == [audience]
    if not exact_audience:
        raise ValueError(
            "Keycloak WIF access token does not have the exact Anthropic audience"
        )
    return claims
