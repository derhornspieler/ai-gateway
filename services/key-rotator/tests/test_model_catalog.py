from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from app import model_catalog
from app.model_catalog import (
    MAX_RECEIPT_BYTES,
    PROVIDER_POLICY_RECEIPT_PATH,
    CacheControlInjectionPoint,
    ModelCatalogConflict,
    ModelCatalogError,
    ModelDraftInput,
    ReceiptValidationError,
    load_provider_policy_receipt,
    parse_provider_policy_receipt,
    resolve_model_catalog,
    resolve_model_draft,
)


FIXTURE = Path(__file__).parent / "fixtures" / "provider-policy-receipt.anthropic.json"
EXPECTED_POLICY_SHA256 = (
    "8c553d83bc98edeee4e1157368b8620ec6234e557b59a8195be6390677cdada6"
)


def _canonical(value: dict[str, object]) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"


def _document() -> dict[str, object]:
    value = json.loads(FIXTURE.read_bytes())
    assert isinstance(value, dict)
    return value


def _runtime_policy(document: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": document["schema_version"],
        "selected_providers": document["selected_providers"],
        "providers": document["providers"],
        "envoy_config_sha256": document["envoy_config_sha256"],
    }


def _refresh_policy_digest(document: dict[str, object]) -> str:
    digest = hashlib.sha256(_canonical(_runtime_policy(document))).hexdigest()
    document["egress_policy_sha256"] = digest
    return digest


def _parse_document(document: dict[str, object], expected: str | None = None):
    return parse_provider_policy_receipt(
        _canonical(document),
        expected_policy_sha256=(
            str(document["egress_policy_sha256"]) if expected is None else expected
        ),
    )


def _receipt():
    return parse_provider_policy_receipt(
        FIXTURE.read_bytes(), expected_policy_sha256=EXPECTED_POLICY_SHA256
    )


def _draft(**overrides: object) -> ModelDraftInput:
    values: dict[str, object] = {
        "gateway_model_name": "claude-sonnet-4-5",
        "provider_name": "anthropic",
        "provider_model_id": "claude-sonnet-4-5",
        "visible_in_discovery": False,
    }
    values.update(overrides)
    return ModelDraftInput.model_validate(values)


def _synthetic_receipt():
    document = _document()
    provider = copy.deepcopy(document["providers"][0])  # type: ignore[index]
    assert isinstance(provider, dict)
    provider.update(
        {
            "name": "synthetic",
            "api_hostname": "api.synthetic.example",
            "route_prefix": "/synthetic/",
            "sni": "api.synthetic.example",
            "exact_sans": ["api.synthetic.example"],
            "ca_file": "synthetic-ca.pem",
        }
    )
    document["selected_providers"] = ["synthetic"]
    document["providers"] = [provider]
    expected = _refresh_policy_digest(document)
    return _parse_document(document, expected)


def test_exact_anthropic_image_receipt_is_bound_to_expected_digest() -> None:
    receipt = _receipt()

    assert receipt.schema_version == 1
    assert receipt.egress_policy_sha256 == EXPECTED_POLICY_SHA256
    assert receipt.selected_providers == ("anthropic",)
    assert receipt.providers[0].api_hostname == "api.anthropic.com"
    assert receipt.providers[0].route_prefix == "/anthropic/"
    assert receipt.providers[0].ca_file == "anthropic-ca.pem"


def test_deployment_receipt_loader_allows_only_the_fixed_path(monkeypatch) -> None:
    monkeypatch.setattr(
        model_catalog,
        "_read_bounded_regular_file",
        lambda path: FIXTURE.read_bytes(),
    )

    receipt = load_provider_policy_receipt(
        PROVIDER_POLICY_RECEIPT_PATH,
        expected_policy_sha256=EXPECTED_POLICY_SHA256,
    )
    assert receipt.selected_providers == ("anthropic",)

    with pytest.raises(ReceiptValidationError, match="approved deployment path"):
        load_provider_policy_receipt(
            "/tmp/substituted-provider-policy.json",
            expected_policy_sha256=EXPECTED_POLICY_SHA256,
        )


def test_receipt_file_reader_rejects_non_regular_and_symlink_files(tmp_path) -> None:
    directory = tmp_path / "receipt-dir"
    directory.mkdir()
    with pytest.raises(ReceiptValidationError, match="bounded regular file"):
        model_catalog._read_bounded_regular_file(str(directory))

    symlink = tmp_path / "receipt-link"
    symlink.symlink_to(FIXTURE)
    with pytest.raises(ReceiptValidationError, match="unavailable"):
        model_catalog._read_bounded_regular_file(str(symlink))


def test_receipt_file_reader_accepts_one_bounded_regular_file(tmp_path) -> None:
    receipt_file = tmp_path / "receipt.json"
    receipt_file.write_bytes(FIXTURE.read_bytes())

    assert model_catalog._read_bounded_regular_file(
        str(receipt_file)
    ) == FIXTURE.read_bytes()


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        bytearray(b"{}"),
        b"x" * (MAX_RECEIPT_BYTES + 1),
    ],
)
def test_receipt_requires_bounded_exact_bytes(raw: object) -> None:
    with pytest.raises(ReceiptValidationError):
        parse_provider_policy_receipt(  # type: ignore[arg-type]
            raw, expected_policy_sha256=EXPECTED_POLICY_SHA256
        )


def test_receipt_rejects_duplicate_json_keys() -> None:
    raw = FIXTURE.read_bytes().replace(
        b'{"schema_version":1,',
        b'{"schema_version":1,"schema_version":1,',
        1,
    )

    with pytest.raises(ReceiptValidationError, match="JSON is invalid"):
        parse_provider_policy_receipt(
            raw, expected_policy_sha256=EXPECTED_POLICY_SHA256
        )


def test_receipt_rejects_noncanonical_json() -> None:
    raw = json.dumps(_document(), indent=2).encode() + b"\n"

    with pytest.raises(ReceiptValidationError, match="not canonical"):
        parse_provider_policy_receipt(
            raw, expected_policy_sha256=EXPECTED_POLICY_SHA256
        )


@pytest.mark.parametrize(
    "expected",
    ["0" * 64, "A" * 64, "not-a-digest", 1],
)
def test_receipt_requires_separate_matching_canonical_digest(expected: object) -> None:
    with pytest.raises(ReceiptValidationError):
        parse_provider_policy_receipt(  # type: ignore[arg-type]
            FIXTURE.read_bytes(), expected_policy_sha256=expected
        )


def test_receipt_recomputes_runtime_policy_digest() -> None:
    document = _document()
    document["egress_policy_sha256"] = "0" * 64

    with pytest.raises(ReceiptValidationError, match="runtime policy"):
        _parse_document(document, "0" * 64)


@pytest.mark.parametrize(
    ("scope", "field", "value"),
    [
        ("receipt", "schema_version", 2),
        ("receipt", "schema_version", True),
        ("receipt", "envoy_config_sha256", "A" * 64),
        ("provider", "name", "Anthropic"),
        ("provider", "api_hostname", "127.0.0.1"),
        ("provider", "api_hostname", "API.ANTHROPIC.COM"),
        ("provider", "route_prefix", "/anthropic//"),
        ("provider", "route_prefix", "/anthropic"),
        ("provider", "sni", "other.anthropic.com"),
        (
            "provider",
            "exact_sans",
            ["other.anthropic.com", "api.anthropic.com"],
        ),
        ("provider", "ca_file", "certs/anthropic-ca.pem"),
        ("provider", "ca_bundle_sha256", "A" * 64),
        (
            "provider",
            "ca_sha256_fingerprints",
            [
                "1dfc1605fbad358d8bc844f76d15203fac9ca5c1a79fd4857ffaf2864fbebf96",
                "1dfc1605fbad358d8bc844f76d15203fac9ca5c1a79fd4857ffaf2864fbebf96",
            ],
        ),
        ("provider", "provenance_sha256", "f" * 63),
    ],
)
def test_receipt_rejects_malformed_policy_fields(
    scope: str, field: str, value: object
) -> None:
    document = _document()
    target = document if scope == "receipt" else document["providers"][0]  # type: ignore[index]
    assert isinstance(target, dict)
    target[field] = value

    with pytest.raises(ReceiptValidationError, match="shape is invalid"):
        _parse_document(document)


@pytest.mark.parametrize("scope", ["receipt", "provider"])
def test_receipt_rejects_unreviewed_extra_fields(scope: str) -> None:
    document = _document()
    target = document if scope == "receipt" else document["providers"][0]  # type: ignore[index]
    assert isinstance(target, dict)
    target["api_base"] = "https://unreviewed.example"

    with pytest.raises(ReceiptValidationError, match="shape is invalid"):
        _parse_document(document)


def test_receipt_rejects_provider_order_and_record_mismatch() -> None:
    document = _document()
    document["selected_providers"] = ["anthropic", "synthetic"]

    with pytest.raises(ReceiptValidationError, match="shape is invalid"):
        _parse_document(document)


def test_receipt_rejects_overlapping_provider_routes() -> None:
    document = _document()
    provider = copy.deepcopy(document["providers"][0])  # type: ignore[index]
    assert isinstance(provider, dict)
    provider.update(
        {
            "name": "synthetic",
            "api_hostname": "api.synthetic.example",
            "route_prefix": "/anthropic/v1/",
            "sni": "api.synthetic.example",
            "exact_sans": ["api.synthetic.example"],
            "ca_file": "synthetic-ca.pem",
        }
    )
    document["selected_providers"] = ["anthropic", "synthetic"]
    document["providers"] = [document["providers"][0], provider]  # type: ignore[index]

    with pytest.raises(ReceiptValidationError, match="shape is invalid"):
        _parse_document(document)


def test_model_draft_keeps_existing_gateway_name_grammar() -> None:
    draft = _draft(gateway_model_name="Vendor.Model/v1:chat_model")

    assert draft.gateway_model_name == "Vendor.Model/v1:chat_model"


@pytest.mark.parametrize(
    "gateway_model_name",
    ["-model", "model with spaces", "x" * 129, ""],
)
def test_model_draft_rejects_invalid_gateway_names(gateway_model_name: str) -> None:
    with pytest.raises(ValidationError):
        _draft(gateway_model_name=gateway_model_name)


@pytest.mark.parametrize(
    "gateway_model_name",
    ["aigw-auto", "aigw-default", "all-proxy-models"],
)
def test_model_draft_rejects_reserved_gateway_names(
    gateway_model_name: str,
) -> None:
    with pytest.raises(ValidationError, match="reserved"):
        _draft(gateway_model_name=gateway_model_name)


def test_model_draft_requires_an_explicit_strict_visibility_value() -> None:
    values = {
        "gateway_model_name": "claude-sonnet-4-5",
        "provider_name": "anthropic",
        "provider_model_id": "claude-sonnet-4-5",
    }
    with pytest.raises(ValidationError):
        ModelDraftInput.model_validate(values)

    values["visible_in_discovery"] = "false"
    with pytest.raises(ValidationError):
        ModelDraftInput.model_validate(values)


@pytest.mark.parametrize(
    "forbidden_field",
    [
        "api_base",
        "hostname",
        "route_prefix",
        "ca_file",
        "credential_name",
        "litellm_params",
    ],
)
def test_model_draft_rejects_caller_owned_runtime_fields(
    forbidden_field: str,
) -> None:
    values = _draft().model_dump()
    values[forbidden_field] = "caller-controlled"

    with pytest.raises(ValidationError):
        ModelDraftInput.model_validate(values)


@pytest.mark.parametrize(
    "provider_model_id",
    [
        "anthropic/claude-sonnet-4-5",
        "Claude-Sonnet-4-5",
        "claude_sonnet_4_5",
        "claude-sonnet-4-5-",
    ],
)
def test_anthropic_adapter_rejects_noncanonical_provider_model_ids(
    provider_model_id: str,
) -> None:
    with pytest.raises(ModelCatalogError, match="provider model ID"):
        resolve_model_draft(
            _draft(provider_model_id=provider_model_id),
            _receipt(),
        )


def test_model_provider_must_be_selected_in_deployed_receipt() -> None:
    with pytest.raises(ModelCatalogError, match="absent from the deployed policy"):
        resolve_model_draft(
            _draft(provider_name="synthetic"),
            _receipt(),
        )


def test_selected_provider_still_requires_committed_runtime_adapter() -> None:
    with pytest.raises(ModelCatalogError, match="no committed runtime adapter"):
        resolve_model_draft(
            _draft(provider_name="synthetic"),
            _synthetic_receipt(),
        )


def test_anthropic_target_is_server_owned_deterministic_and_nonsecret() -> None:
    first = resolve_model_draft(_draft(), _receipt())
    second = resolve_model_draft(_draft(), _receipt())

    assert first == second
    assert first.egress_policy_sha256 == EXPECTED_POLICY_SHA256
    assert first.visible_in_discovery is False
    assert first.target.model == "anthropic/claude-sonnet-4-5"
    assert first.target.api_base == "http://envoy-egress:8080/anthropic"
    assert first.target.litellm_credential_name == "anthropic-primary"
    assert first.target.cache_control_injection_points == (
        CacheControlInjectionPoint(location="message", role="system"),
    )
    assert "key" not in repr(first.target).lower()
    assert "secret" not in repr(first.target).lower()


def test_preprod_origin_is_server_selected_and_arbitrary_origins_are_rejected() -> None:
    preprod = resolve_model_draft(
        _draft(),
        _receipt(),
        egress_origin="http://wif-egress-mock:8080",
    )
    assert preprod.target.api_base == "http://wif-egress-mock:8080/anthropic"

    with pytest.raises(ModelCatalogError, match="egress origin"):
        resolve_model_draft(
            _draft(),
            _receipt(),
            egress_origin="https://attacker.test",
        )


def test_catalog_rejects_duplicate_gateway_names() -> None:
    with pytest.raises(ModelCatalogConflict, match="gateway model name"):
        resolve_model_catalog(
            [
                _draft(),
                _draft(provider_model_id="claude-opus-4-8"),
            ],
            _receipt(),
        )


def test_catalog_rejects_duplicate_provider_model_pairs_under_aliases() -> None:
    with pytest.raises(ModelCatalogConflict, match="provider model"):
        resolve_model_catalog(
            [
                _draft(),
                _draft(gateway_model_name="team-sonnet"),
            ],
            _receipt(),
        )


def test_catalog_resolution_has_canonical_gateway_name_order() -> None:
    resolved = resolve_model_catalog(
        [
            _draft(
                gateway_model_name="z-model",
                provider_model_id="claude-opus-4-8",
            ),
            _draft(
                gateway_model_name="a-model",
                provider_model_id="claude-haiku-4-5",
                visible_in_discovery=True,
            ),
        ],
        _receipt(),
    )

    assert [item.gateway_model_name for item in resolved] == ["a-model", "z-model"]
    assert resolved[0].visible_in_discovery is True
