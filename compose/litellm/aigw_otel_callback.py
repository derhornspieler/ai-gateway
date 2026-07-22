"""Send LiteLLM audit spans only to Alloy's authenticated receiver."""

from __future__ import annotations

import os
import re
import stat

from litellm.integrations.opentelemetry import OpenTelemetry, OpenTelemetryConfig
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from aigw_openwebui_identity import (
    KEY_OWNER_PATTERN,
    OPENWEBUI_KEY_ALIAS,
    OPENWEBUI_KEY_METADATA,
    OPENWEBUI_KEY_OWNER,
    PORTAL_USERNAME_PATTERN,
    openwebui_jwt_from_headers,
    read_openwebui_forward_jwt_secret,
    verified_openwebui_identity,
)


TOKEN_PATH = "/run/secrets/litellm_otel_token"
TOKEN_PATTERN = re.compile(r"[0-9a-f]{64}")
ALLOY_TRACES_URL = "http://alloy:4319/v1/traces"
PORTAL_NAME_SOURCE = "portal_key_metadata"
OPENWEBUI_NAME_SOURCE = "open_webui_signed_oidc"
KEY_OWNER_NAME_SOURCE = "key_subject"
UNRESOLVED_NAME_SOURCE = "unresolved"


def _read_token() -> str:
    """Read one fixed-shape token without following a link."""

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(TOKEN_PATH, flags)
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise RuntimeError("LiteLLM OTLP token must be one regular file")
        raw_token = os.read(descriptor, 65)
    finally:
        os.close(descriptor)

    try:
        token = raw_token.decode("ascii")
    except UnicodeDecodeError as error:
        raise RuntimeError("LiteLLM OTLP token must be ASCII") from error
    if TOKEN_PATTERN.fullmatch(token) is None:
        raise RuntimeError("LiteLLM OTLP token must be 64 lowercase hex characters")
    return token


def _standard_logging_metadata(kwargs) -> dict:
    standard_logging = kwargs.get("standard_logging_object")
    if isinstance(standard_logging, dict):
        metadata = standard_logging.get("metadata")
    else:
        metadata = getattr(standard_logging, "metadata", None)
    return metadata if isinstance(metadata, dict) else {}


def _request_jwt_header(kwargs) -> str | None:
    """Return one unambiguous bounded JWT header from LiteLLM request state."""

    litellm_params = kwargs.get("litellm_params")
    if not isinstance(litellm_params, dict):
        return None

    proxy_request = litellm_params.get("proxy_server_request")
    if isinstance(proxy_request, dict):
        proxy_headers = proxy_request.get("headers")
        return openwebui_jwt_from_headers(proxy_headers)
    return None


def _resolved_server_identity(
    kwargs, secret: str, *, now: int | None = None
) -> tuple[str | None, str, str] | None:
    """Resolve one server-controlled readable identity for an audit span."""

    metadata = _standard_logging_metadata(kwargs)
    key_owner = metadata.get("user_api_key_user_id")
    bounded_key_owner = (
        key_owner
        if isinstance(key_owner, str) and KEY_OWNER_PATTERN.fullmatch(key_owner)
        else None
    )
    key_alias = metadata.get("user_api_key_alias")
    auth_metadata = metadata.get("user_api_key_auth_metadata")
    auth_metadata = auth_metadata if isinstance(auth_metadata, dict) else {}

    portal_key = auth_metadata.get("created_via") == "dev-portal"
    service_markers = (
        key_owner == OPENWEBUI_KEY_OWNER
        or key_alias == OPENWEBUI_KEY_ALIAS
        or "aigw_key_kind" in auth_metadata
        or "aigw_service" in auth_metadata
    )
    if portal_key and not service_markers:
        username = auth_metadata.get("aigw_username")
        if (
            isinstance(username, str)
            and PORTAL_USERNAME_PATTERN.fullmatch(username) is not None
        ):
            return None, username, PORTAL_NAME_SOURCE

    openwebui_key = (
        key_owner == OPENWEBUI_KEY_OWNER
        and key_alias == OPENWEBUI_KEY_ALIAS
        and auth_metadata == OPENWEBUI_KEY_METADATA
    )
    if openwebui_key and not portal_key:
        token = _request_jwt_header(kwargs)
        if token is not None:
            identity = verified_openwebui_identity(token, secret, now=now)
            if identity is not None:
                subject, username = identity
                return subject, username, OPENWEBUI_NAME_SOURCE
        return None

    if bounded_key_owner is not None:
        return None, bounded_key_owner, KEY_OWNER_NAME_SOURCE
    return None


class AigwOpenTelemetry(OpenTelemetry):
    """Authenticate telemetry and stamp only reviewed audit identities."""

    def __init__(self) -> None:
        environment = os.getenv("AIGW_DEPLOYMENT_ENVIRONMENT", "production")
        if environment not in {"preprod", "production"}:
            raise RuntimeError("AIGW_DEPLOYMENT_ENVIRONMENT must be preprod or production")

        token = _read_token()
        self._openwebui_forward_jwt_secret = read_openwebui_forward_jwt_secret()
        self._aigw_exporter = OTLPSpanExporter(
            endpoint=ALLOY_TRACES_URL,
            headers={"Authorization": f"Bearer {token}"},
        )
        super().__init__(
            config=OpenTelemetryConfig(
                exporter=self._aigw_exporter,
                service_name="litellm",
                deployment_environment=environment,
                capture_message_content="SPAN_ONLY",
            )
        )

    def _get_span_processor(self, dynamic_headers=None):
        """Use batching without giving LiteLLM a printable header string."""

        if dynamic_headers:
            raise RuntimeError("dynamic OTLP headers are not allowed")
        return BatchSpanProcessor(self._aigw_exporter)

    def set_attributes(self, span, kwargs, response_obj):
        """Overwrite the bounded server-owned audit identity fields."""

        super().set_attributes(span, kwargs, response_obj)
        identity = _resolved_server_identity(
            kwargs, self._openwebui_forward_jwt_secret
        )
        user_id, username, source = (
            identity
            if identity is not None
            else (None, "", UNRESOLVED_NAME_SOURCE)
        )
        self.safe_set_attribute(span, "aigw.server.user.id", user_id or "")
        self.safe_set_attribute(span, "aigw.server.user.name", username)
        self.safe_set_attribute(span, "aigw.server.user.name_source", source)


aigw_otel = AigwOpenTelemetry()
