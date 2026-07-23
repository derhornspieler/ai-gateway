#!/usr/bin/env python3
"""Exercise usage, pricing, reporting, and backdating in seeded PreProd."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
COMPOSE_DIR = ROOT / "compose"
ENV_FILE = COMPOSE_DIR / "secrets/preprod.env"
SEED_OVERLAY = COMPOSE_DIR / "secrets/preprod-seed-images.yml"
CA_FILE = COMPOSE_DIR / "secrets/preprod-root-ca.pem"
PROJECT = "aigw-preprod"
OWNER_LABEL = "com.aigw.preprod.project"
CONFIG_LABEL = "com.aigw.preprod.config-digest"
FIXTURE_VOLUME = "preprod_empty_docker_logs"
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_FIXTURE_BYTES = 64 * 1024
CRIBL_LOG_TAIL = 50_000


ACCOUNTING_HELPER = r'''
import hashlib
import http.client
import json
import os
import stat
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import psycopg
from psycopg.rows import dict_row


test_input = json.load(sys.stdin)
suffix = test_input["suffix"]
grafana_password = test_input["grafana_password"]
model = "claude-usage-" + suffix
provider_model = model
project = "preprod-usage-" + suffix
synthetic_user = "preprod-synthetic-" + suffix
real_user = "preprod-real-" + suffix
actor = "preprod-usage-accounting"
rotator_token = os.environ.get("ROTATOR_INTERNAL_TOKEN", "")
master_key = os.environ.get("LITELLM_MASTER_KEY", "")
database_url = os.environ.get("DATABASE_URL", "")
if len(rotator_token) < 16 or not master_key.startswith("sk-"):
    raise SystemExit("required internal credentials are unavailable")
if not database_url.startswith("postgresql://rotator:"):
    raise SystemExit("the rotator database connection is unavailable")
if (
    not isinstance(grafana_password, str)
    or len(grafana_password) != 48
    or any(character not in "0123456789abcdef" for character in grafana_password)
):
    raise SystemExit("the Grafana reporting credential is unavailable")


def request(host, port, method, path, *, headers=None, body=None):
    request_headers = dict(headers or {})
    encoded = None
    if body is not None:
        request_headers["Content-Type"] = "application/json"
        encoded = json.dumps(body, separators=(",", ":"))
    connection = http.client.HTTPConnection(host, port, timeout=45)
    connection.request(method, path, body=encoded, headers=request_headers)
    response = connection.getresponse()
    raw = response.read(1048577)
    status = response.status
    content_type = response.getheader("Content-Type", "")
    connection.close()
    if len(raw) > 1048576:
        raise SystemExit("an internal response exceeded 1 MiB")
    if "application/json" in content_type and raw:
        try:
            document = json.loads(raw)
        except json.JSONDecodeError:
            raise SystemExit("an internal service returned invalid JSON")
    else:
        document = raw.decode("utf-8", errors="strict")
    return status, document


def control(method, path, body=None, *, operation_id=None):
    headers = {"X-Internal-Auth": rotator_token}
    if operation_id is not None:
        headers["X-AIGW-Operation-ID"] = operation_id
        headers["X-AIGW-Actor-ID"] = actor
    return request(
        "key-rotator", 8080, method, path, headers=headers, body=body
    )


def new_operation():
    return str(uuid.uuid4())


def read_usage_token():
    path = "/run/secrets/litellm_usage_token"
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise SystemExit("the usage token file is unsafe")
        raw = os.read(descriptor, 65)
    finally:
        os.close(descriptor)
    try:
        token = raw.decode("ascii")
    except UnicodeDecodeError:
        raise SystemExit("the usage token is malformed")
    if len(token) != 64 or any(character not in "0123456789abcdef" for character in token):
        raise SystemExit("the usage token is malformed")
    return token


usage_token = read_usage_token()


def send_usage(event):
    return request(
        "key-rotator",
        8080,
        "POST",
        "/usage/events",
        headers={"X-AIGW-Usage-Auth": usage_token},
        body=event,
    )


def litellm(path, body, *, token=master_key):
    return request(
        "litellm",
        4000,
        "POST",
        path,
        headers={"Authorization": "Bearer " + token},
        body=body,
    )


def event_id(name):
    return hashlib.sha256((suffix + "|" + name).encode("ascii")).hexdigest()


def utc_text(value):
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def usage_event(name, occurred_at, **changes):
    event = {
        "schema_version": 1,
        "event_id": event_id(name),
        "request_id": "preprod-" + name + "-" + suffix,
        "request_id_source": "litellm_call_id",
        "provider_response_id": "msg-" + name + "-" + suffix,
        "trace_id": None,
        "provider": "anthropic",
        "requested_model": model,
        "actual_model": provider_model,
        "stable_user_id": synthetic_user,
        "project_id": project,
        "status": "success",
        "stream": False,
        "retry_count": 0,
        "occurred_at": utc_text(occurred_at),
        "normal_input_tokens": 10,
        "cache_creation_5m_tokens": 20,
        "cache_creation_1h_tokens": 30,
        "cache_read_tokens": 40,
        "output_tokens": 50,
        "usage_completeness": "complete",
        "litellm_cost_usd": "0.00077",
        "provider_cost_usd": None,
        "source_version": "litellm-1.93.0",
    }
    event.update(changes)
    return event


def fetchone(connection, query, parameters):
    with connection.cursor() as cursor:
        cursor.execute(query, parameters)
        row = cursor.fetchone()
    return None if row is None else dict(row)


def fetchall(connection, query, parameters):
    with connection.cursor() as cursor:
        cursor.execute(query, parameters)
        return [dict(row) for row in cursor.fetchall()]


def price_body(usage_class, amount, effective_at, version):
    return {
        "version_id": version,
        "gateway_model_name": model,
        "usage_class": usage_class,
        "token_unit": 1000,
        "amount": amount,
        "effective_at": utc_text(effective_at),
        "explicit_free": False,
        "source_reference": "preprod-usage-accounting",
        "review_note": "Seeded PreProd usage accounting acceptance price.",
    }


def preview_price(body, operation_id=None):
    preview_id = operation_id or new_operation()
    status, document = control(
        "POST",
        "/model-governance/prices/backdate/preview",
        body,
        operation_id=preview_id,
    )
    if status != 201 or not isinstance(document, dict):
        raise SystemExit("the controller did not create a backdate preview")
    if document.get("preview_id") != preview_id:
        raise SystemExit("the backdate preview returned the wrong identity")
    return document


def confirm_price(preview, operation_id=None, confirmation="CONFIRM BACKDATED PRICE"):
    confirm_id = operation_id or new_operation()
    status, document = control(
        "POST",
        "/model-governance/prices/backdate/"
        + preview["preview_id"]
        + "/confirm",
        {
            "candidate_sha256": preview["candidate_sha256"],
            "preview_sha256": preview["preview_sha256"],
            "confirmation": confirmation,
        },
        operation_id=confirm_id,
    )
    return confirm_id, status, document


def real_rows(connection):
    return fetchall(
        connection,
        """
        SELECT event_id, request_id, status, stream, retry_count,
               usage_completeness, configured_cost_status,
               normal_input_tokens, cache_creation_5m_tokens,
               cache_creation_1h_tokens, cache_read_tokens, output_tokens
        FROM aigw_governance.usage_events
        WHERE requested_model = %s AND stable_user_id = %s
        ORDER BY received_at, event_id
        """,
        (model, real_user),
    )


def wait_for_new_real_rows(connection, known_request_ids, matches, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rows = [
            row
            for row in real_rows(connection)
            if row["request_id"] not in known_request_ids
        ]
        if any(matches(row) for row in rows):
            return rows
        time.sleep(0.5)
    raise SystemExit("the LiteLLM usage callback did not reach PostgreSQL")


model_created = False
model_active = False
key_created = False
test_key = "sk-" + os.urandom(24).hex()
connection = psycopg.connect(database_url, autocommit=True, row_factory=dict_row)
try:
    status, draft = control(
        "POST",
        "/model-governance/models",
        {
            "gateway_model_name": model,
            "provider_name": "anthropic",
            "provider_model_id": provider_model,
            "visible_in_discovery": False,
            "source_reference": "preprod-usage-accounting",
            "review_note": "Seeded PreProd usage accounting acceptance model.",
        },
        operation_id=new_operation(),
    )
    if status != 201 or not isinstance(draft, dict):
        raise SystemExit("the controller did not create the usage test model")
    model_created = True
    status, active = control(
        "POST",
        "/model-governance/models/" + model + "/activate",
        {},
        operation_id=new_operation(),
    )
    if status != 200 or active.get("lifecycle_state") != "active":
        raise SystemExit("the usage test model did not activate")
    model_active = True

    now = datetime.now(timezone.utc)
    missing_price_time = now - timedelta(minutes=30)
    first_price_time = now - timedelta(minutes=20)
    backdate_time = now - timedelta(minutes=15)
    complete_time = now - timedelta(minutes=10)
    prices = (
        ("normal_input", "0.001", "normal-input-v1"),
        ("cache_creation_5m", "0.002", "cache-5m-v1"),
        ("cache_creation_1h", "0.003", "cache-1h-v1"),
        ("cache_read", "0.004", "cache-read-v1"),
        ("output", "0.005", "output-v1"),
    )
    for usage_class, amount, version_suffix in prices:
        preview = preview_price(
            price_body(
                usage_class,
                amount,
                first_price_time,
                "preprod-" + suffix + "-" + version_suffix,
            )
        )
        if preview.get("affected_count") != 0:
            raise SystemExit("an initial price unexpectedly affected old usage")
        _, status, confirmation = confirm_price(preview)
        if status != 201 or confirmation.get("adjustment_count") != 0:
            raise SystemExit("an initial governed price did not confirm")

    complete = usage_event("complete", complete_time)
    status, receipt = send_usage(complete)
    if status != 201 or receipt != {"event_id": complete["event_id"], "created": True}:
        raise SystemExit("complete usage did not append")
    status, replay = send_usage(complete)
    if status != 200 or replay != {"event_id": complete["event_id"], "created": False}:
        raise SystemExit("an exact usage replay did not return its saved receipt")
    changed = dict(complete)
    changed["output_tokens"] = 51
    status, _ = send_usage(changed)
    if status != 409:
        raise SystemExit("a changed usage replay did not fail closed")
    print("PREPROD_USAGE_REPLAY_GUARD_PASSED")

    missing_price = usage_event("missing-price", missing_price_time)
    status, _ = send_usage(missing_price)
    if status != 201:
        raise SystemExit("missing-price usage did not append")
    unknown = usage_event(
        "unknown",
        complete_time + timedelta(seconds=1),
        normal_input_tokens=None,
        cache_creation_5m_tokens=None,
        cache_creation_1h_tokens=None,
        cache_read_tokens=None,
        output_tokens=None,
        usage_completeness="unknown",
        litellm_cost_usd=None,
    )
    status, _ = send_usage(unknown)
    if status != 201:
        raise SystemExit("unknown usage did not append")
    failure = usage_event(
        "failure",
        complete_time + timedelta(seconds=2),
        status="failure",
        normal_input_tokens=None,
        cache_creation_5m_tokens=None,
        cache_creation_1h_tokens=None,
        cache_read_tokens=None,
        output_tokens=None,
        usage_completeness="not_applicable",
        litellm_cost_usd=None,
    )
    status, _ = send_usage(failure)
    if status != 201:
        raise SystemExit("failure usage did not append")

    complete_row = fetchone(
        connection,
        """
        SELECT * FROM aigw_governance.usage_reporting WHERE event_id = %s
        """,
        (complete["event_id"],),
    )
    missing_row = fetchone(
        connection,
        """
        SELECT * FROM aigw_governance.usage_reporting WHERE event_id = %s
        """,
        (missing_price["event_id"],),
    )
    unknown_row = fetchone(
        connection,
        """
        SELECT * FROM aigw_governance.usage_reporting WHERE event_id = %s
        """,
        (unknown["event_id"],),
    )
    failure_row = fetchone(
        connection,
        """
        SELECT * FROM aigw_governance.usage_reporting WHERE event_id = %s
        """,
        (failure["event_id"],),
    )
    if complete_row is None or Decimal(complete_row["booked_configured_total_cost_usd"]) != Decimal("0.00055"):
        raise SystemExit("the configured five-part cost was not exact")
    if any(
        row is None
        or row["current_configured_cost_status"] != "unknown"
        or row["current_configured_total_cost_usd"] is not None
        for row in (missing_row, unknown_row, failure_row)
    ):
        raise SystemExit("missing usage or price was changed into zero cost")
    components = fetchall(
        connection,
        """
        SELECT usage_class, token_count, booked_cost_usd,
               current_cost_usd, current_price_version_id
        FROM aigw_governance.usage_component_reporting
        WHERE event_id = %s ORDER BY usage_class
        """,
        (complete["event_id"],),
    )
    expected_tokens = {
        "normal_input": 10,
        "cache_creation_5m": 20,
        "cache_creation_1h": 30,
        "cache_read": 40,
        "output": 50,
    }
    if len(components) != 5 or any(
        expected_tokens.get(row["usage_class"]) != row["token_count"]
        or row["booked_cost_usd"] is None
        or row["current_price_version_id"] is None
        for row in components
    ):
        raise SystemExit("the reporting view lost a token class or price")
    print("PREPROD_USAGE_UNKNOWN_PASSED")

    output_preview = preview_price(
        price_body(
            "output",
            "0.010",
            backdate_time,
            "preprod-" + suffix + "-output-v2",
        )
    )
    stale_preview = preview_price(
        price_body(
            "normal_input",
            "0.009",
            backdate_time,
            "preprod-" + suffix + "-normal-input-stale",
        )
    )
    if (
        output_preview.get("affected_count") != 1
        or output_preview.get("shown_affected_count") != 1
        or output_preview.get("affected_rows_truncated") is not False
        or Decimal(output_preview["old_total_usd"]) != Decimal("0.00055")
        or Decimal(output_preview["new_total_usd"]) != Decimal("0.00080")
        or Decimal(output_preview["delta_usd"]) != Decimal("0.00025")
        or output_preview["affected_rows"][0]["usage_event_id"] != complete["event_id"]
    ):
        raise SystemExit("the stored backdate preview was not exact")

    bad_phrase_id = new_operation()
    _, bad_phrase_status, _ = confirm_price(
        output_preview,
        operation_id=bad_phrase_id,
        confirmation="confirm backdated price",
    )
    if bad_phrase_status != 422:
        raise SystemExit("the backdate confirmation phrase did not fail closed")

    confirmation_id = new_operation()
    _, status, confirmed = confirm_price(
        output_preview, operation_id=confirmation_id
    )
    if (
        status != 201
        or confirmed.get("adjustment_count") != 1
        or confirmed.get("affected_count") != 1
        or Decimal(confirmed["delta_usd"]) != Decimal("0.00025")
    ):
        raise SystemExit("the backdated price did not append its adjustment")
    _, replay_status, replayed = confirm_price(
        output_preview, operation_id=confirmation_id
    )
    if replay_status != 201 or replayed != confirmed:
        raise SystemExit("an exact backdate confirmation replay changed its receipt")
    changed_preview = dict(output_preview)
    changed_preview["preview_sha256"] = "0" * 64
    _, changed_status, _ = confirm_price(
        changed_preview, operation_id=confirmation_id
    )
    if changed_status != 409:
        raise SystemExit("a changed backdate confirmation replay did not fail closed")
    _, stale_status, _ = confirm_price(stale_preview)
    if stale_status != 409:
        raise SystemExit("a stale backdate preview did not fail closed")
    print("PREPROD_USAGE_BACKDATE_PASSED")

    adjusted = fetchone(
        connection,
        """
        SELECT booked_configured_total_cost_usd,
               current_configured_total_cost_usd,
               current_configured_cost_status, adjustment_count
        FROM aigw_governance.usage_reporting WHERE event_id = %s
        """,
        (complete["event_id"],),
    )
    output_component = fetchone(
        connection,
        """
        SELECT booked_cost_usd, current_cost_usd, current_adjustment_id
        FROM aigw_governance.usage_component_reporting
        WHERE event_id = %s AND usage_class = 'output'
        """,
        (complete["event_id"],),
    )
    if (
        adjusted is None
        or Decimal(adjusted["booked_configured_total_cost_usd"]) != Decimal("0.00055")
        or Decimal(adjusted["current_configured_total_cost_usd"]) != Decimal("0.00080")
        or adjusted["current_configured_cost_status"] != "complete"
        or adjusted["adjustment_count"] != 1
        or output_component is None
        or Decimal(output_component["booked_cost_usd"]) != Decimal("0.00025")
        or Decimal(output_component["current_cost_usd"]) != Decimal("0.00050")
        or output_component["current_adjustment_id"] is None
    ):
        raise SystemExit("the reporting views did not apply the immutable adjustment")
    print("PREPROD_USAGE_REPORTING_PASSED")

    # Use the exact role configured as Grafana's data source. This proves the
    # dashboard views are readable without granting access to private ledger
    # tables.
    grafana_connection = psycopg.connect(
        host="postgres",
        dbname="rotator",
        user="grafana_ro",
        password=grafana_password,
        autocommit=True,
        row_factory=dict_row,
    )
    try:
        grafana_row = fetchone(
            grafana_connection,
            """
            SELECT booked_configured_total_cost_usd,
                   current_configured_total_cost_usd,
                   current_configured_cost_status, adjustment_count
            FROM aigw_governance.usage_reporting WHERE event_id = %s
            """,
            (complete["event_id"],),
        )
        grafana_components = fetchall(
            grafana_connection,
            """
            SELECT usage_class, token_count, booked_cost_usd,
                   current_cost_usd, current_price_version_id
            FROM aigw_governance.usage_component_reporting
            WHERE event_id = %s ORDER BY usage_class
            """,
            (complete["event_id"],),
        )
        grafana_by_class = {
            row["usage_class"]: row for row in grafana_components
        }
        grafana_output = grafana_by_class.get("output")
        if (
            grafana_row is None
            or Decimal(grafana_row["booked_configured_total_cost_usd"])
            != Decimal("0.00055")
            or Decimal(grafana_row["current_configured_total_cost_usd"])
            != Decimal("0.00080")
            or grafana_row["current_configured_cost_status"] != "complete"
            or grafana_row["adjustment_count"] != 1
            or set(grafana_by_class) != set(expected_tokens)
            or any(
                row["token_count"] != expected_tokens[usage_class]
                for usage_class, row in grafana_by_class.items()
            )
            or grafana_output is None
            or Decimal(grafana_output["booked_cost_usd"])
            != Decimal("0.00025")
            or Decimal(grafana_output["current_cost_usd"])
            != Decimal("0.00050")
            or grafana_output["current_price_version_id"]
            != "preprod-" + suffix + "-output-v2"
        ):
            raise SystemExit("the Grafana login did not read the exact report totals")
        try:
            fetchone(
                grafana_connection,
                "SELECT event_id FROM aigw_governance.usage_events WHERE event_id = %s",
                (complete["event_id"],),
            )
        except psycopg.errors.InsufficientPrivilege:
            pass
        else:
            raise SystemExit("the Grafana login read a private usage table")
    finally:
        grafana_connection.close()
    print("PREPROD_USAGE_GRAFANA_RO_PASSED")

    before_digest = fetchone(
        connection,
        "SELECT document_sha256 FROM aigw_governance.usage_events WHERE event_id = %s",
        (complete["event_id"],),
    )
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE aigw_governance.usage_events SET output_tokens = 99 WHERE event_id = %s",
                (complete["event_id"],),
            )
    except psycopg.Error:
        pass
    else:
        raise SystemExit("the application login changed append-only usage")
    after_digest = fetchone(
        connection,
        "SELECT document_sha256 FROM aigw_governance.usage_events WHERE event_id = %s",
        (complete["event_id"],),
    )
    if before_digest != after_digest:
        raise SystemExit("the failed mutation changed usage evidence")
    print("PREPROD_USAGE_APPEND_ONLY_PASSED")

    status, created_key = litellm(
        "/key/generate",
        {
            "key": test_key,
            "key_alias": "preprod-usage-" + suffix,
            "user_id": real_user,
            "models": [model],
            "allowed_routes": ["/v1/messages"],
            "metadata": {
                "created_via": "dev-portal",
                "aigw_project_id": project,
            },
            "permissions": {},
            "blocked": False,
        },
    )
    if status != 200 or created_key.get("key") != test_key:
        raise SystemExit("the usage test key was not created")
    key_created = True

    def call(marker, *, stream=False):
        return litellm(
            "/v1/messages",
            {
                "model": model,
                "max_tokens": 8,
                "stream": stream,
                "messages": [{"role": "user", "content": marker + suffix}],
            },
            token=test_key,
        )

    def require_unknown_provider_usage(marker, *, stream=False):
        known_request_ids = {
            row["request_id"] for row in real_rows(connection)
        }
        status, answer = call(marker, stream=stream)
        if status != 200:
            raise SystemExit("the unusable-usage provider response failed")
        if stream and "pong" not in str(answer):
            raise SystemExit("the unusable-usage provider stream was incomplete")
        if not stream and not isinstance(answer, dict):
            raise SystemExit("the unusable-usage provider response was invalid")
        rows = wait_for_new_real_rows(
            connection,
            known_request_ids,
            lambda row: row["status"] == "success"
            and row["stream"] is stream
            and row["usage_completeness"] == "unknown"
            and row["configured_cost_status"] == "unknown",
        )
        if not any(
            row["status"] == "success"
            and row["stream"] is stream
            and row["usage_completeness"] == "unknown"
            and row["configured_cost_status"] == "unknown"
            for row in rows
        ):
            raise SystemExit("unusable provider usage was not preserved as unknown")

    known_request_ids = {row["request_id"] for row in real_rows(connection)}
    status, answer = call("AIGW_PREPROD_NORMAL_")
    content = answer.get("content") if isinstance(answer, dict) else None
    if status != 200 or not isinstance(content, list) or not any(
        isinstance(item, dict) and item.get("text") == "pong" for item in content
    ):
        raise SystemExit("the real usage request failed")
    normal_rows = wait_for_new_real_rows(
        connection,
        known_request_ids,
        lambda row: row["status"] == "success"
        and row["stream"] is False
        and row["usage_completeness"] == "complete",
    )
    normal = next(
        row
        for row in normal_rows
        if row["status"] == "success"
        and row["stream"] is False
        and row["usage_completeness"] == "complete"
    )
    if (
        normal["status"] != "success"
        or normal["stream"] is not False
        or normal["usage_completeness"] != "complete"
        or [
            normal["normal_input_tokens"],
            normal["cache_creation_5m_tokens"],
            normal["cache_creation_1h_tokens"],
            normal["cache_read_tokens"],
            normal["output_tokens"],
        ] != [10, 20, 30, 40, 50]
    ):
        raise SystemExit("the real callback lost the five provider token classes")
    print("PREPROD_USAGE_REAL_REQUEST_PASSED")

    known_request_ids = {row["request_id"] for row in real_rows(connection)}
    status, stream_answer = call("AIGW_PREPROD_STREAM_", stream=True)
    if status != 200 or "pong" not in str(stream_answer):
        raise SystemExit("the real streaming usage request failed")
    stream_rows = wait_for_new_real_rows(
        connection,
        known_request_ids,
        lambda row: row["status"] == "success" and row["stream"] is True,
    )
    if not any(
        row["status"] == "success" and row["stream"] is True
        for row in stream_rows
    ):
        raise SystemExit("the streaming callback was not recorded as a stream")
    print("PREPROD_USAGE_STREAM_PASSED")

    known_request_ids = {row["request_id"] for row in real_rows(connection)}
    status, retry_answer = call("AIGW_PREPROD_RETRY_ONCE_")
    retry_content = (
        retry_answer.get("content") if isinstance(retry_answer, dict) else None
    )
    if status != 200 or not isinstance(retry_content, list):
        raise SystemExit("the planned provider retry did not recover")
    retry_rows = wait_for_new_real_rows(
        connection,
        known_request_ids,
        lambda row: row["status"] == "success"
        and isinstance(row["retry_count"], int)
        and row["retry_count"] >= 1,
    )
    if not any(
        isinstance(row["retry_count"], int) and row["retry_count"] >= 1
        for row in retry_rows
    ):
        raise SystemExit("the internal provider retry count was not recorded")
    print("PREPROD_USAGE_RETRY_PASSED")

    require_unknown_provider_usage("AIGW_PREPROD_NO_USAGE_")
    print("PREPROD_USAGE_MISSING_PASSED")
    require_unknown_provider_usage("AIGW_PREPROD_NO_USAGE_", stream=True)
    print("PREPROD_USAGE_MISSING_STREAM_PASSED")
    require_unknown_provider_usage("AIGW_PREPROD_INVALID_USAGE_")
    print("PREPROD_USAGE_MALFORMED_PASSED")
    require_unknown_provider_usage(
        "AIGW_PREPROD_INVALID_USAGE_", stream=True
    )
    print("PREPROD_USAGE_MALFORMED_STREAM_PASSED")

    known_request_ids = {row["request_id"] for row in real_rows(connection)}
    status, _ = call("AIGW_PREPROD_FAIL_ALWAYS_")
    if status < 400:
        raise SystemExit("the planned provider failure unexpectedly succeeded")
    failure_rows = wait_for_new_real_rows(
        connection,
        known_request_ids,
        lambda row: row["status"] == "failure"
        and row["usage_completeness"] == "not_applicable",
    )
    if not any(
        row["status"] == "failure"
        and row["usage_completeness"] == "not_applicable"
        for row in failure_rows
    ):
        raise SystemExit("the provider failure was not recorded safely")
    print("PREPROD_USAGE_FAILURE_PASSED")
finally:
    if key_created:
        litellm("/key/delete", {"keys": [test_key]})
    if model_created:
        if model_active:
            control(
                "POST",
                "/model-governance/models/" + model + "/hide",
                {},
                operation_id=new_operation(),
            )
        control(
            "POST",
            "/model-governance/models/" + model + "/retire",
            {},
            operation_id=new_operation(),
        )
    connection.close()

print("PREPROD_USAGE_ACCOUNTING_CORE_PASSED")
'''.strip()


DELIVERY_GAP_HELPER = r"""
import http.client
import json
import os
import secrets
import sys

suffix = json.load(sys.stdin)["suffix"]
master_key = os.environ.get("LITELLM_MASTER_KEY", "")
if not master_key.startswith("sk-"):
    raise SystemExit("the LiteLLM master key is unavailable")
test_key = "sk-" + secrets.token_hex(24)
user = "preprod-gap-" + suffix
project = "preprod-gap-" + suffix


def post(path, token, document):
    connection = http.client.HTTPConnection("litellm", 4000, timeout=45)
    connection.request(
        "POST",
        path,
        body=json.dumps(document, separators=(",", ":")),
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
        },
    )
    response = connection.getresponse()
    raw = response.read(1048577)
    status = response.status
    connection.close()
    if len(raw) > 1048576:
        raise SystemExit("a LiteLLM response exceeded 1 MiB")
    try:
        body = json.loads(raw) if raw else None
    except json.JSONDecodeError:
        raise SystemExit("LiteLLM returned invalid JSON")
    return status, body


created = False
try:
    status, body = post(
        "/key/generate",
        master_key,
        {
            "key": test_key,
            "key_alias": "preprod-gap-" + suffix,
            "user_id": user,
            "models": ["claude-sonnet-4-5"],
            "allowed_routes": ["/v1/messages"],
            "metadata": {
                "created_via": "dev-portal",
                "aigw_project_id": project,
            },
            "permissions": {},
            "blocked": False,
        },
    )
    if status != 200 or body.get("key") != test_key:
        raise SystemExit("the delivery-gap key was not created")
    created = True
    status, answer = post(
        "/v1/messages",
        test_key,
        {
            "model": "claude-sonnet-4-5",
            "max_tokens": 8,
            "messages": [
                {"role": "user", "content": "AIGW_PREPROD_DELIVERY_GAP_" + suffix}
            ],
        },
    )
    content = answer.get("content") if isinstance(answer, dict) else None
    if status != 200 or not isinstance(content, list) or not any(
        isinstance(item, dict) and item.get("text") == "pong" for item in content
    ):
        raise SystemExit("accounting failure changed the provider response")
finally:
    if created:
        post("/key/delete", master_key, {"keys": [test_key]})

print("PREPROD_USAGE_DELIVERY_GAP_REQUEST_PASSED")
""".strip()


def fail(message: str) -> None:
    raise SystemExit(f"ERROR: {message}")


def clean_environment() -> dict[str, str]:
    allowed = (
        "DOCKER_CONFIG",
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LOGNAME",
        "PATH",
        "TMPDIR",
        "USER",
        "XDG_CONFIG_HOME",
    )
    return {name: os.environ[name] for name in allowed if name in os.environ}


def run(command: list[str], *, input_text: str | None = None) -> tuple[str, str]:
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=clean_environment(),
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )
    if (
        len(result.stdout.encode()) > MAX_OUTPUT_BYTES
        or len(result.stderr.encode()) > MAX_OUTPUT_BYTES
    ):
        fail("a usage-accounting test command exceeded its output bound")
    if result.returncode != 0:
        fail("a sensitive usage-accounting test command failed")
    return result.stdout, result.stderr


def read_environment() -> dict[str, str]:
    if not ENV_FILE.is_file():
        fail("the generated preprod environment is missing")
    values: dict[str, str] = {}
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        name, separator, value = line.partition("=")
        if not separator:
            continue
        if name in values:
            fail(f"the generated preprod environment repeats {name}")
        values[name] = value
    return values


def read_admin_password() -> str:
    """Read the local test password without putting it in argv or an env var."""

    if sys.stdin.isatty():
        fail("pipe the static preprod-admin password on stdin")
    raw = sys.stdin.buffer.read(513)
    if not raw or len(raw) > 512:
        fail("the preprod-admin password length is invalid")
    try:
        password = raw.strip().decode("utf-8")
    except UnicodeDecodeError:
        fail("the preprod-admin password is invalid")
    if not 16 <= len(password) <= 512:
        fail("the preprod-admin password length is invalid")
    return password


class Preprod:
    """Run bounded commands against one exact seeded PreProd project."""

    def __init__(self) -> None:
        if shutil.which("docker") is None:
            fail("docker is required for the usage-accounting test")
        values = read_environment()
        self.values = values
        endpoint = values.get("PREPROD_DOCKER_ENDPOINT", "")
        if not endpoint.startswith("unix:///"):
            fail("the prepared local Docker endpoint is missing")
        socket_path = Path(endpoint.removeprefix("unix://"))
        try:
            metadata = socket_path.lstat()
        except FileNotFoundError:
            fail("the prepared local Docker socket is missing")
        if (
            not socket_path.is_absolute()
            or ".." in socket_path.parts
            or stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISSOCK(metadata.st_mode)
            or metadata.st_uid not in {0, os.geteuid()}
        ):
            fail("the prepared local Docker socket is unsafe")
        if not SEED_OVERLAY.is_file():
            fail("seed mode requires the activated preprod image overlay")

        self.config_digest = values.get("AIGW_PREPROD_CONFIG_DIGEST", "")
        if re.fullmatch(r"[0-9a-f]{64}", self.config_digest) is None:
            fail("the preprod configuration digest is missing or invalid")

        self.docker_prefix = ["docker", "--host", endpoint]
        self.compose_prefix = [
            *self.docker_prefix,
            "compose",
            "--project-name",
            PROJECT,
            "--env-file",
            str(ENV_FILE),
            "-f",
            str(COMPOSE_DIR / "docker-compose.yml"),
            "-f",
            str(COMPOSE_DIR / "docker-compose.preprod.yml"),
            "-f",
            str(SEED_OVERLAY),
        ]
        self.compose_prefix.extend(["--profile", "preprod"])

    def docker(
        self, *arguments: str, input_text: str | None = None
    ) -> tuple[str, str]:
        return run([*self.docker_prefix, *arguments], input_text=input_text)

    def compose(
        self, *arguments: str, input_text: str | None = None
    ) -> tuple[str, str]:
        return run([*self.compose_prefix, *arguments], input_text=input_text)

    def model(self) -> dict[str, object]:
        stdout, _ = self.compose("config", "--format", "json")
        try:
            model = json.loads(stdout)
        except json.JSONDecodeError:
            fail("Docker Compose returned an invalid preprod model")
        if not isinstance(model, dict):
            fail("Docker Compose returned an incomplete preprod model")
        return model

    def container_id(self, service: str) -> str:
        stdout, _ = self.compose("ps", "-q", service)
        identifiers = stdout.splitlines()
        if (
            len(identifiers) != 1
            or re.fullmatch(r"[0-9a-f]{64}", identifiers[0]) is None
        ):
            fail(f"preprod service {service} does not have one container")
        identifier = identifiers[0]
        stdout, _ = self.docker("inspect", identifier)
        try:
            document = json.loads(stdout)[0]
        except (json.JSONDecodeError, IndexError, TypeError):
            fail(f"Docker returned invalid state for {service}")
        labels = document.get("Config", {}).get("Labels") or {}
        if (
            labels.get("com.docker.compose.project") != PROJECT
            or labels.get("com.docker.compose.service") != service
            or labels.get(OWNER_LABEL) != PROJECT
        ):
            fail(f"preprod service {service} escaped the owned project")
        return identifier

    def wait_healthy(self, service: str, timeout: int = 90) -> None:
        identifier = self.container_id(service)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            stdout, _ = self.docker("inspect", identifier)
            try:
                state = json.loads(stdout)[0]["State"]
            except (json.JSONDecodeError, IndexError, KeyError, TypeError):
                fail(f"Docker returned invalid health state for {service}")
            health = state.get("Health", {}).get("Status")
            if state.get("Status") == "running" and health == "healthy":
                return
            if state.get("Status") in {"dead", "exited", "removing"} or health == "unhealthy":
                fail(f"preprod service {service} failed while recovering")
            time.sleep(1)
        fail(f"preprod service {service} did not become healthy")

    def logs_since(
        self, service: str, since: int, *, tail: int | None = None
    ) -> str:
        identifier = self.container_id(service)
        arguments = ["logs", "--since", str(since)]
        if tail is not None:
            if type(tail) is not int or not 1 <= tail <= CRIBL_LOG_TAIL:
                fail("the Docker log tail is invalid")
            arguments.extend(("--tail", str(tail)))
        stdout, stderr = self.docker(*arguments, identifier)
        return stdout + stderr

    def timestamped_logs_since(
        self, service: str, since: int
    ) -> tuple[tuple[str, str], ...]:
        """Return exact Docker CLI lines with their original stream."""

        identifier = self.container_id(service)
        stdout, stderr = self.docker(
            "logs", "--timestamps", "--since", str(since), identifier
        )
        records: list[tuple[str, str]] = []
        for stream, output in (("stdout", stdout), ("stderr", stderr)):
            records.extend((stream, line) for line in output.splitlines())
        return tuple(records)


def require_markers(output: str, markers: tuple[str, ...]) -> None:
    for marker in markers:
        if output.count(marker) != 1:
            fail(f"the usage-accounting helper omitted {marker}")
        print(marker)


def wait_for_log_receipt(
    preprod: Preprod,
    service: str,
    since: int,
    required: tuple[str, ...],
    *,
    timeout: int = 60,
) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        tail = CRIBL_LOG_TAIL if service == "cribl-mock" else None
        document = preprod.logs_since(service, since, tail=tail)
        if all(value in document for value in required):
            return document
        time.sleep(1)
    fail(f"{service} did not receive the bounded usage audit receipt")


PRICE_AUDIT_FIELDS = {
    "action",
    "amount_usd",
    "candidate_sha256",
    "effective_at",
    "event",
    "model",
    "old_policy_sha256",
    "operation_id",
    "outcome",
    "provider",
    "review_note_sha256",
    "schema_version",
    "source_reference",
    "subject",
    "token_unit",
    "usage_class",
}
USAGE_AUDIT_FIELDS = {
    "action",
    "completeness",
    "event",
    "event_id",
    "model",
    "outcome",
    "project",
    "provider",
    "request_id",
    "schema_version",
    "subject",
}
SAFE_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}")
SAFE_MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}")
SAFE_HASH = re.compile(r"[0-9a-f]{64}")
SAFE_UUID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("duplicate JSON key")
        document[key] = value
    return document


def source_security_records(
    preprod: Preprod, service: str, since: int
) -> list[dict[str, object]]:
    """Parse only fresh, canonical security records from one real producer."""

    records: list[dict[str, object]] = []
    now = time.time()
    for stream, line in preprod.timestamped_logs_since(service, since):
        timestamp, separator, message = line.partition(" ")
        if not separator or message.count("AIGW_SECURITY_EVENT ") != 1:
            continue
        if len(message.encode("utf-8")) > 8192:
            fail("a source security event exceeded 8 KiB")
        try:
            parsed_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            fail("a source security event had an invalid Docker timestamp")
        if (
            parsed_time.tzinfo is None
            or parsed_time.utcoffset() != timezone.utc.utcoffset(parsed_time)
            or parsed_time.timestamp() < since - 5
            or parsed_time.timestamp() > now + 30
        ):
            fail("a source security event was outside the live test window")
        payload = message.split("AIGW_SECURITY_EVENT ", 1)[1]
        try:
            event = json.loads(payload, object_pairs_hook=_unique_json_object)
        except (json.JSONDecodeError, ValueError):
            fail("a source security event was not valid JSON")
        if not isinstance(event, dict):
            fail("a source security event was not a JSON object")
        canonical = json.dumps(event, sort_keys=True, separators=(",", ":"))
        if payload != canonical:
            fail("a source security event was not canonical JSON")
        records.append(
            {
                "event": event,
                "message": message,
                "stream": stream,
                "timestamp": timestamp,
            }
        )
    return records


def trusted_price_records(
    records: list[dict[str, object]], model: str
) -> list[dict[str, object]]:
    """Select fully validated price events for one portal test model."""

    trusted: list[dict[str, object]] = []
    for record in records:
        event = record["event"]
        if not isinstance(event, dict):
            fail("a parsed price record lost its event")
        if event.get("event") != "aigw.price.audit" or event.get("model") != model:
            continue
        if (
            set(event) != PRICE_AUDIT_FIELDS
            or event.get("schema_version") != 1
            or event.get("action")
            not in {"create", "backdate_preview", "backdate_confirm"}
            or event.get("outcome") != "success"
            or event.get("provider") != "anthropic"
            or event.get("usage_class")
            not in {
                "normal_input",
                "cache_creation_5m",
                "cache_creation_1h",
                "cache_read",
                "output",
            }
            or not isinstance(event.get("amount_usd"), str)
            or re.fullmatch(r"(?:0|[1-9][0-9]{0,11})(?:\.[0-9]{1,12})?", event["amount_usd"])
            is None
            or not isinstance(event.get("token_unit"), str)
            or re.fullmatch(r"[1-9][0-9]{0,11}", event["token_unit"]) is None
            or not isinstance(event.get("operation_id"), str)
            or SAFE_UUID.fullmatch(event["operation_id"]) is None
            or not isinstance(event.get("subject"), str)
            or SAFE_IDENTIFIER.fullmatch(event["subject"]) is None
            or not isinstance(event.get("source_reference"), str)
            or not 1 <= len(event["source_reference"]) <= 256
            or "://" in event["source_reference"]
            or not isinstance(event.get("effective_at"), str)
            or not event["effective_at"].endswith("Z")
            or any(
                not isinstance(event.get(name), str)
                or SAFE_HASH.fullmatch(event[name]) is None
                for name in (
                    "review_note_sha256",
                    "old_policy_sha256",
                    "candidate_sha256",
                )
            )
        ):
            fail("a trusted price event used an invalid value")
        trusted.append(record)
    return trusted


def trusted_usage_record(
    records: list[dict[str, object]],
    *,
    action: str,
    outcome: str,
    event_id: str | None = None,
    model: str | None = None,
    project: str,
    subject: str,
    completeness: str,
) -> dict[str, object]:
    """Select one exact usage record and reject ambiguous producer output."""

    selected: list[dict[str, object]] = []
    for record in records:
        event = record["event"]
        if not isinstance(event, dict) or event.get("event") != "aigw.usage.audit":
            continue
        if (
            event.get("action") == action
            and event.get("outcome") == outcome
            and event.get("project") == project
            and event.get("subject") == subject
            and event.get("completeness") == completeness
            and (event_id is None or event.get("event_id") == event_id)
            and (model is None or event.get("model") == model)
        ):
            if (
                set(event) != USAGE_AUDIT_FIELDS
                or event.get("schema_version") != 1
                or event.get("provider") != "anthropic"
                or not isinstance(event.get("event_id"), str)
                or (
                    event["event_id"] != "unattributed"
                    and SAFE_HASH.fullmatch(event["event_id"]) is None
                )
                or not isinstance(event.get("request_id"), str)
                or SAFE_IDENTIFIER.fullmatch(event["request_id"]) is None
                or not isinstance(event.get("model"), str)
                or SAFE_MODEL.fullmatch(event["model"]) is None
                or SAFE_IDENTIFIER.fullmatch(event["project"]) is None
                or SAFE_IDENTIFIER.fullmatch(event["subject"]) is None
            ):
                fail("a trusted usage event used an invalid value")
            selected.append(record)
    if len(selected) != 1:
        fail("the real producer did not emit one exact usage audit event")
    return selected[0]


def docker_log_fixture(records: list[dict[str, object]], service: str) -> str:
    """Rebuild Docker's json-file envelope around validated producer lines."""

    if service not in {"key-rotator", "litellm"}:
        fail("the natural security fixture producer is not reviewed")
    lines: list[str] = []
    for record in records:
        stream = record.get("stream")
        timestamp = record.get("timestamp")
        message = record.get("message")
        if (
            stream not in {"stdout", "stderr"}
            or not isinstance(timestamp, str)
            or not isinstance(message, str)
            or "\n" in message
            or "\r" in message
        ):
            fail("a trusted producer record cannot enter the Docker fixture")
        lines.append(
            json.dumps(
                {
                    "log": message + "\n",
                    "stream": stream,
                    "attrs": {
                        "com.docker.compose.project": PROJECT,
                        "com.docker.compose.service": service,
                    },
                    "time": timestamp,
                },
                separators=(",", ":"),
            )
        )
    content = "\n".join(lines) + "\n"
    if not lines or len(content.encode("utf-8")) > MAX_FIXTURE_BYTES:
        fail("the natural security fixture is empty or too large")
    return content


def set_security_fixture(
    preprod: Preprod,
    model: dict[str, object],
    token: str,
    content: str | None,
) -> None:
    """Create or remove one reviewed file in PreProd's owned empty volume."""

    if re.fullmatch(r"[0-9a-f]{16}", token) is None:
        fail("the natural security fixture token is invalid")
    if content is not None and len(content.encode("utf-8")) > MAX_FIXTURE_BYTES:
        fail("the natural security fixture is too large")
    volumes = model.get("volumes")
    services = model.get("services")
    if not isinstance(volumes, dict) or not isinstance(services, dict):
        fail("the preprod model has no service or volume inventory")
    volume = volumes.get(FIXTURE_VOLUME)
    volume_init = services.get("volume-init")
    if not isinstance(volume, dict) or not isinstance(volume_init, dict):
        fail("the preprod security fixture boundary is missing")
    volume_name = volume.get("name")
    image = volume_init.get("image")
    if volume_name != f"{PROJECT}_{FIXTURE_VOLUME}" or not isinstance(image, str):
        fail("the preprod security fixture boundary is invalid")
    stdout, _ = preprod.docker("volume", "inspect", volume_name)
    try:
        inspected = json.loads(stdout)[0]
    except (json.JSONDecodeError, IndexError, TypeError):
        fail("Docker returned invalid security fixture volume state")
    labels = inspected.get("Labels") or {}
    if (
        labels.get(OWNER_LABEL) != PROJECT
        or labels.get("com.docker.compose.project") != PROJECT
    ):
        fail("the security fixture volume is not owned by preprod")

    writer_name = f"{PROJECT}-natural-security-fixture-{token}"
    stdout, _ = preprod.docker(
        "container",
        "ls",
        "-a",
        "--filter",
        f"name=^{writer_name}$",
        "--format",
        "{{.ID}}",
    )
    if stdout.strip():
        fail("a stale natural security fixture writer exists")
    fixture_path = f"/fixtures/aigw-security-fixtures/natural-{token}-json.log"
    if content is None:
        script = f"rm -f {fixture_path}; sync"
        input_text = None
    else:
        script = (
            "umask 022; mkdir -p /fixtures/aigw-security-fixtures; "
            f"test ! -e {fixture_path}; cat > {fixture_path}; "
            f"chmod 0644 {fixture_path}; sync"
        )
        input_text = content
    preprod.docker(
        "run",
        "--rm",
        "-i",
        "--pull=never",
        "--name",
        writer_name,
        "--network",
        "none",
        "--read-only",
        "--user",
        "0:0",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--label",
        f"com.docker.compose.project={PROJECT}",
        "--label",
        f"{OWNER_LABEL}={PROJECT}",
        "--label",
        f"{CONFIG_LABEL}={preprod.config_digest}",
        "--mount",
        f"type=volume,src={volume_name},dst=/fixtures",
        "--entrypoint",
        "/bin/sh",
        image,
        "-ceu",
        script,
        input_text=input_text,
    )


def bridge_and_wait(
    preprod: Preprod,
    model: dict[str, object],
    records: list[dict[str, object]],
    service: str,
    since: int,
    required: tuple[str, ...],
) -> str:
    """Expose validated real lines to Alloy, wait for Cribl, then remove them."""

    token = secrets.token_hex(8)
    content = docker_log_fixture(records, service)
    created = False
    try:
        set_security_fixture(preprod, model, token, content)
        created = True
        receipt = wait_for_log_receipt(preprod, "cribl-mock", since, required)
    finally:
        if created:
            set_security_fixture(preprod, model, token, None)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-mode", choices=("seed",), default="seed")
    parser.parse_args()

    admin_password = read_admin_password()
    preprod = Preprod()
    compose_model = preprod.model()
    suffix = secrets.token_hex(6)
    portal_started_at = int(time.time()) - 2
    portal_output, _ = run(
        [
            sys.executable,
            "-I",
            str(ROOT / "scripts/test-portal-price-backdate.py"),
            "--ca",
            str(CA_FILE),
            "--suffix",
            suffix,
        ],
        input_text=admin_password + "\n",
    )
    portal_markers = (
        "PREPROD_PRICE_PORTAL_STEP_UP_PASSED",
        "PREPROD_PRICE_PORTAL_PREVIEW_PASSED",
        "PREPROD_PRICE_PORTAL_CSRF_PASSED",
        "PREPROD_PRICE_PORTAL_CONFIRM_PASSED",
        "PREPROD_PRICE_PORTAL_CLEANUP_PASSED",
        "PREPROD_PRICE_PORTAL_PASSED",
    )
    require_markers(portal_output, portal_markers)
    portal_model = "claude-portal-price-" + suffix
    review_notes = (
        "Seeded PreProd future price review.",
        "Seeded PreProd backdated price review.",
    )
    if any(
        review_note in preprod.logs_since(service, portal_started_at)
        for service in ("admin-portal", "key-rotator")
        for review_note in review_notes
    ):
        fail("a free-form price review note entered service logs")
    price_source_records = source_security_records(
        preprod, "key-rotator", portal_started_at
    )
    price_records = trusted_price_records(price_source_records, portal_model)
    if [record["event"]["action"] for record in price_records] != [
        "create",
        "backdate_preview",
        "backdate_confirm",
    ]:
        fail("the portal did not emit one natural event for each price mutation")
    expected_price_values = {
        "create": (
            "7.25",
            "1000000",
            "normal_input",
            "preprod-future-price-" + suffix,
            hashlib.sha256(review_notes[0].encode("utf-8")).hexdigest(),
        ),
        "backdate_preview": (
            "9.75",
            "1000000",
            "output",
            "preprod-backdated-price-" + suffix,
            hashlib.sha256(review_notes[1].encode("utf-8")).hexdigest(),
        ),
        "backdate_confirm": (
            "9.75",
            "1000000",
            "output",
            "preprod-backdated-price-" + suffix,
            hashlib.sha256(review_notes[1].encode("utf-8")).hexdigest(),
        ),
    }
    for record in price_records:
        event = record["event"]
        actual_values = (
            event["amount_usd"],
            event["token_unit"],
            event["usage_class"],
            event["source_reference"],
            event["review_note_sha256"],
        )
        if actual_values != expected_price_values[event["action"]]:
            fail("a backend price audit did not match its committed values")
    print("PREPROD_PRICE_AUDIT_SOURCE_PASSED")
    price_export = bridge_and_wait(
        preprod,
        compose_model,
        price_records,
        "key-rotator",
        portal_started_at,
        (
            "event=aigw.price.audit action=create",
            "action=backdate_preview",
            "action=backdate_confirm",
            portal_model,
            "review_note_sha256=",
        ),
    )
    if any(review_note in price_export for review_note in review_notes):
        fail("a free-form price review note entered the Cribl export")
    print("PREPROD_PRICE_AUDIT_EXPORT_PASSED")

    started_at = int(time.time()) - 2
    stdout, _ = preprod.compose(
        "exec",
        "-T",
        "key-rotator",
        "/opt/venv/bin/python",
        "-c",
        ACCOUNTING_HELPER,
        input_text=json.dumps(
            {
                "suffix": suffix,
                "grafana_password": preprod.values.get(
                    "PG_GRAFANA_RO_PASSWORD", ""
                ),
            },
            separators=(",", ":"),
        ),
    )
    core_markers = (
        "PREPROD_USAGE_REPLAY_GUARD_PASSED",
        "PREPROD_USAGE_UNKNOWN_PASSED",
        "PREPROD_USAGE_BACKDATE_PASSED",
        "PREPROD_USAGE_REPORTING_PASSED",
        "PREPROD_USAGE_GRAFANA_RO_PASSED",
        "PREPROD_USAGE_APPEND_ONLY_PASSED",
        "PREPROD_USAGE_REAL_REQUEST_PASSED",
        "PREPROD_USAGE_STREAM_PASSED",
        "PREPROD_USAGE_RETRY_PASSED",
        "PREPROD_USAGE_MISSING_PASSED",
        "PREPROD_USAGE_MISSING_STREAM_PASSED",
        "PREPROD_USAGE_MALFORMED_PASSED",
        "PREPROD_USAGE_MALFORMED_STREAM_PASSED",
        "PREPROD_USAGE_FAILURE_PASSED",
        "PREPROD_USAGE_ACCOUNTING_CORE_PASSED",
    )
    require_markers(stdout, core_markers)

    complete_event_id = hashlib.sha256(
        (suffix + "|complete").encode("ascii")
    ).hexdigest()
    usage_source_records = source_security_records(
        preprod, "key-rotator", started_at
    )
    usage_record = trusted_usage_record(
        usage_source_records,
        action="record",
        outcome="success",
        event_id=complete_event_id,
        model="claude-usage-" + suffix,
        project="preprod-usage-" + suffix,
        subject="preprod-synthetic-" + suffix,
        completeness="complete",
    )
    bridge_and_wait(
        preprod,
        compose_model,
        [usage_record],
        "key-rotator",
        started_at,
        ("aigw.usage.audit", complete_event_id, "preprod-synthetic-" + suffix),
    )
    print("PREPROD_USAGE_AUDIT_EXPORT_PASSED")

    key_rotator_id = preprod.container_id("key-rotator")
    gap_started_at = int(time.time()) - 2
    stopped, _ = preprod.docker("stop", "-t", "10", key_rotator_id)
    if stopped.strip() != key_rotator_id:
        fail("Docker did not stop the exact key-rotator container")
    gap_output = ""
    try:
        gap_output, _ = preprod.compose(
            "exec",
            "-T",
            "admin-portal",
            "/opt/venv/bin/python",
            "-c",
            DELIVERY_GAP_HELPER,
            input_text=json.dumps({"suffix": suffix}, separators=(",", ":")),
        )
    finally:
        started, _ = preprod.docker("start", key_rotator_id)
        if started.strip() != key_rotator_id:
            fail("Docker did not restart the exact key-rotator container")
        preprod.wait_healthy("key-rotator")
    require_markers(
        gap_output, ("PREPROD_USAGE_DELIVERY_GAP_REQUEST_PASSED",)
    )
    gap_subject = "preprod-gap-" + suffix
    wait_for_log_receipt(
        preprod,
        "litellm",
        gap_started_at,
        ('"action":"delivery_failure"', gap_subject),
    )
    delivery_source_records = source_security_records(
        preprod, "litellm", gap_started_at
    )
    delivery_record = trusted_usage_record(
        delivery_source_records,
        action="delivery_failure",
        outcome="failure",
        model="claude-sonnet-4-5",
        project=gap_subject,
        subject=gap_subject,
        completeness="complete",
    )
    bridge_and_wait(
        preprod,
        compose_model,
        [delivery_record],
        "litellm",
        gap_started_at,
        ("delivery_failure", gap_subject, "aigw.usage.audit"),
    )
    print("PREPROD_USAGE_DELIVERY_GAP_PASSED")
    print("PREPROD_USAGE_ACCOUNTING_PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
