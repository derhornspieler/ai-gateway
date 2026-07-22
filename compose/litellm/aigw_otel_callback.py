"""Send LiteLLM audit spans only to Alloy's authenticated receiver."""

from __future__ import annotations

import os
import re
import stat

from litellm.integrations.opentelemetry import OpenTelemetry, OpenTelemetryConfig
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace.export import BatchSpanProcessor


TOKEN_PATH = "/run/secrets/litellm_otel_token"
TOKEN_PATTERN = re.compile(r"[0-9a-f]{64}")
ALLOY_TRACES_URL = "http://alloy:4319/v1/traces"


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


class AigwOpenTelemetry(OpenTelemetry):
    """Keep the bearer token out of LiteLLM config, environment, and logs."""

    def __init__(self) -> None:
        environment = os.getenv("AIGW_DEPLOYMENT_ENVIRONMENT", "production")
        if environment not in {"preprod", "production"}:
            raise RuntimeError("AIGW_DEPLOYMENT_ENVIRONMENT must be preprod or production")

        token = _read_token()
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


aigw_otel = AigwOpenTelemetry()
