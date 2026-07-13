"""OpenTelemetry setup for key-rotator.

Design ref: docs/solution-map.md §1.8 — "dev-portal / key-rotator /
cert-monitor: instrumented with OTel SDK from day one (custom code, our
rules)"; §1.2 — "every action emits an OTel audit event." Exports OTLP
HTTP/protobuf to OTEL_EXPORTER_OTLP_ENDPOINT (Grafana Alloy), which fans
out to local Prometheus/Loki/Grafana and dual-exports to Cribl.

Setup is optional/fail-open: if the collector endpoint is unreachable at
startup or during export, the SDK's exporter fails in the background
without raising into request/rotation code paths — rotation logic and the
rotation_history DB audit trail (app/db.py) never depend on telemetry
succeeding.
"""
from __future__ import annotations

import logging

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from app.config import Settings

logger = logging.getLogger("key_rotator.otel")

_tracer: "trace.Tracer | None" = None


def setup_otel(settings: Settings, app) -> None:
    """Configure the global tracer provider + instrument the FastAPI app.

    Never raises: any failure here is logged and the service continues
    with a no-op tracer (spans become cheap no-ops via the OTel API's
    default ProxyTracerProvider behavior).
    """
    global _tracer
    try:
        resource = Resource.create({"service.name": "key-rotator"})
        provider = TracerProvider(resource=resource)
        endpoint = f"{settings.otel_exporter_otlp_endpoint.rstrip('/')}/v1/traces"
        exporter = OTLPSpanExporter(endpoint=endpoint)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        FastAPIInstrumentor.instrument_app(app)
        _tracer = trace.get_tracer("key_rotator")
        logger.info("otel configured, exporting traces to %s", endpoint)
    except Exception as exc:  # noqa: BLE001
        logger.warning("otel setup failed, continuing without tracing: %s", exc)
        _tracer = trace.get_tracer("key_rotator")


def get_tracer() -> trace.Tracer:
    global _tracer
    if _tracer is None:
        _tracer = trace.get_tracer("key_rotator")
    return _tracer
