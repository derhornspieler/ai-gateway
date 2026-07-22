"""Strict model-catalog inputs bound to the deployed Envoy provider policy.

This module is intentionally a small domain boundary.  It does not persist a
catalog, activate a model, probe provider entitlement, or change LiteLLM.  It
only proves that a proposed model uses a provider in the exact immutable Envoy
receipt and resolves the small set of server-owned runtime fields.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import stat
from collections.abc import Iterable
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    StrictBool,
    StrictInt,
    StrictStr,
    ValidationError,
    field_validator,
    model_validator,
)


POLICY_SCHEMA_VERSION = 1
MAX_RECEIPT_BYTES = 1 << 20
ENVOY_EGRESS_ORIGIN = "http://envoy-egress:8080"
PREPROD_EGRESS_ORIGIN = "http://wif-egress-mock:8080"
ALLOWED_EGRESS_ORIGINS = frozenset(
    {ENVOY_EGRESS_ORIGIN, PREPROD_EGRESS_ORIGIN}
)
PROVIDER_POLICY_RECEIPT_PATH = "/run/secrets/provider_policy_receipt.json"

# Keep this grammar aligned with the existing project-policy contract in
# app.identity.  A later migration can move the shared constant without
# changing names that are already valid in Keycloak project policy.
MODEL_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_./:-]{0,127}")
RESERVED_GATEWAY_MODEL_NAMES = frozenset(
    {"aigw-auto", "aigw-default", "all-proxy-models"}
)

_PROVIDER_NAME_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_ANTHROPIC_MODEL_ID_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,126}[a-z0-9])?")


class ModelCatalogError(RuntimeError):
    """A safe, non-secret model-catalog validation failure."""


class ReceiptValidationError(ModelCatalogError):
    """The deployed provider-policy receipt is malformed or inconsistent."""


class ModelCatalogConflict(ModelCatalogError):
    """Two proposed model records conflict with one another."""


def _valid_provider_name(value: str) -> bool:
    return len(value) <= 63 and _PROVIDER_NAME_RE.fullmatch(value) is not None


def _valid_hostname(value: str) -> bool:
    if not value or len(value) > 253 or value.lower() != value or value.endswith("."):
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        return False
    labels = value.split(".")
    return len(labels) >= 2 and all(_valid_provider_name(label) for label in labels)


def _valid_route_prefix(value: str) -> bool:
    if (
        len(value) < 3
        or not value.startswith("/")
        or not value.endswith("/")
        or "//" in value
    ):
        return False
    return all(_valid_provider_name(part) for part in value.strip("/").split("/"))


def _canonical_json_bytes(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


class RuntimeProvider(BaseModel):
    """One provider record copied into the immutable Envoy runtime policy."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: StrictStr
    api_hostname: StrictStr
    route_prefix: StrictStr
    sni: StrictStr
    exact_sans: tuple[StrictStr, ...]
    ca_file: StrictStr
    ca_bundle_sha256: StrictStr
    ca_sha256_fingerprints: tuple[StrictStr, ...]
    provenance_sha256: StrictStr

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if not _valid_provider_name(value):
            raise ValueError("provider name is not canonical")
        return value

    @field_validator("api_hostname", "sni")
    @classmethod
    def validate_hostname(cls, value: str) -> str:
        if not _valid_hostname(value):
            raise ValueError("provider hostname is not canonical")
        return value

    @field_validator("route_prefix")
    @classmethod
    def validate_route_prefix(cls, value: str) -> str:
        if not _valid_route_prefix(value):
            raise ValueError("provider route prefix is not canonical")
        return value

    @field_validator(
        "ca_bundle_sha256",
        "provenance_sha256",
    )
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if _SHA256_RE.fullmatch(value) is None:
            raise ValueError("provider SHA-256 is not canonical")
        return value

    @field_validator("exact_sans")
    @classmethod
    def validate_exact_sans(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if (
            not values
            or tuple(sorted(values)) != values
            or len(set(values)) != len(values)
            or any(not _valid_hostname(value) for value in values)
        ):
            raise ValueError("provider exact SANs are not canonical")
        return values

    @field_validator("ca_sha256_fingerprints")
    @classmethod
    def validate_ca_fingerprints(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if (
            not values
            or len(set(values)) != len(values)
            or any(_SHA256_RE.fullmatch(value) is None for value in values)
        ):
            raise ValueError("provider CA fingerprints are not canonical")
        return values

    @model_validator(mode="after")
    def validate_related_fields(self) -> Self:
        if self.sni not in self.exact_sans:
            raise ValueError("provider SNI is absent from its exact SANs")
        if self.ca_file != f"{self.name}-ca.pem":
            raise ValueError("provider CA filename is not canonical")
        return self

    def runtime_dict(self) -> dict[str, Any]:
        """Return fields in the exact Go RuntimeProvider serialization order."""

        return {
            "name": self.name,
            "api_hostname": self.api_hostname,
            "route_prefix": self.route_prefix,
            "sni": self.sni,
            "exact_sans": list(self.exact_sans),
            "ca_file": self.ca_file,
            "ca_bundle_sha256": self.ca_bundle_sha256,
            "ca_sha256_fingerprints": list(self.ca_sha256_fingerprints),
            "provenance_sha256": self.provenance_sha256,
        }


class ProviderPolicyReceipt(BaseModel):
    """The exact non-secret receipt baked into one Envoy image."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: StrictInt
    egress_policy_sha256: StrictStr
    envoy_config_sha256: StrictStr
    selected_providers: tuple[StrictStr, ...]
    providers: tuple[RuntimeProvider, ...]

    @field_validator("schema_version")
    @classmethod
    def validate_schema_version(cls, value: int) -> int:
        if value != POLICY_SCHEMA_VERSION:
            raise ValueError("provider-policy receipt schema is unsupported")
        return value

    @field_validator("egress_policy_sha256", "envoy_config_sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if _SHA256_RE.fullmatch(value) is None:
            raise ValueError("provider-policy SHA-256 is not canonical")
        return value

    @field_validator("selected_providers")
    @classmethod
    def validate_selected_providers(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if (
            not values
            or tuple(sorted(values)) != values
            or len(set(values)) != len(values)
            or any(not _valid_provider_name(value) for value in values)
        ):
            raise ValueError("selected providers are not canonical")
        return values

    @model_validator(mode="after")
    def validate_provider_records(self) -> Self:
        if (
            tuple(provider.name for provider in self.providers)
            != self.selected_providers
        ):
            raise ValueError("selected providers and provider records disagree")

        hostnames = [provider.api_hostname for provider in self.providers]
        routes = [provider.route_prefix for provider in self.providers]
        ca_files = [provider.ca_file for provider in self.providers]
        if (
            len(set(hostnames)) != len(hostnames)
            or len(set(routes)) != len(routes)
            or len(set(ca_files)) != len(ca_files)
        ):
            raise ValueError("runtime provider network or CA fields are duplicated")

        for left_index, left_route in enumerate(routes):
            for right_route in routes[left_index + 1 :]:
                if left_route.startswith(right_route) or right_route.startswith(
                    left_route
                ):
                    raise ValueError("runtime provider routes overlap")
        return self

    def runtime_policy_dict(self) -> dict[str, Any]:
        """Return fields in the exact Go RuntimePolicy serialization order."""

        return {
            "schema_version": self.schema_version,
            "selected_providers": list(self.selected_providers),
            "providers": [provider.runtime_dict() for provider in self.providers],
            "envoy_config_sha256": self.envoy_config_sha256,
        }

    def receipt_dict(self) -> dict[str, Any]:
        """Return fields in the exact Go Receipt serialization order."""

        return {
            "schema_version": self.schema_version,
            "egress_policy_sha256": self.egress_policy_sha256,
            "envoy_config_sha256": self.envoy_config_sha256,
            "selected_providers": list(self.selected_providers),
            "providers": [provider.runtime_dict() for provider in self.providers],
        }

    def provider(self, name: str) -> RuntimeProvider | None:
        for provider in self.providers:
            if provider.name == name:
                return provider
        return None


class _DuplicateJSONKey(ValueError):
    pass


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKey("JSON object contains a duplicate key")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError("JSON contains a non-finite number")


def parse_provider_policy_receipt(
    raw: bytes,
    *,
    expected_policy_sha256: str,
) -> ProviderPolicyReceipt:
    """Validate the exact image receipt against a separately trusted digest.

    ``expected_policy_sha256`` comes from deployment configuration, not from
    the receipt.  Requiring both prevents a substituted, internally consistent
    receipt from silently authorizing another provider policy.
    """

    if type(raw) is not bytes or not raw or len(raw) > MAX_RECEIPT_BYTES:
        raise ReceiptValidationError("provider-policy receipt size is invalid")
    if (
        type(expected_policy_sha256) is not str
        or _SHA256_RE.fullmatch(expected_policy_sha256) is None
    ):
        raise ReceiptValidationError("expected provider-policy digest is invalid")

    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateJSONKey, ValueError):
        raise ReceiptValidationError(
            "provider-policy receipt JSON is invalid"
        ) from None

    try:
        receipt = ProviderPolicyReceipt.model_validate(document)
    except ValidationError:
        # Pydantic's ValidationError includes rejected input values.  The
        # receipt should be non-secret, but keep the service error boundary
        # fixed so a future receipt field cannot leak through an exception.
        raise ReceiptValidationError(
            "provider-policy receipt shape is invalid"
        ) from None

    canonical_receipt = _canonical_json_bytes(receipt.receipt_dict())
    if not hmac.compare_digest(raw, canonical_receipt):
        raise ReceiptValidationError("provider-policy receipt is not canonical")

    if not hmac.compare_digest(receipt.egress_policy_sha256, expected_policy_sha256):
        raise ReceiptValidationError(
            "provider-policy receipt does not match the expected digest"
        )

    actual_policy_sha256 = hashlib.sha256(
        _canonical_json_bytes(receipt.runtime_policy_dict())
    ).hexdigest()
    if not hmac.compare_digest(actual_policy_sha256, receipt.egress_policy_sha256):
        raise ReceiptValidationError(
            "provider-policy receipt does not match its runtime policy"
        )
    return receipt


def _read_bounded_regular_file(path: str) -> bytes:
    """Read one already-opened regular file without following a symlink."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise ReceiptValidationError(
            "provider-policy receipt file is unavailable"
        ) from None

    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size < 1
            or metadata.st_size > MAX_RECEIPT_BYTES
        ):
            raise ReceiptValidationError(
                "provider-policy receipt file is not a bounded regular file"
            )

        chunks: list[bytes] = []
        remaining = MAX_RECEIPT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) != metadata.st_size:
            raise ReceiptValidationError(
                "provider-policy receipt file changed while being read"
            )
        return raw
    except OSError:
        raise ReceiptValidationError(
            "provider-policy receipt file could not be read"
        ) from None
    finally:
        os.close(descriptor)


def load_provider_policy_receipt(
    path: str,
    *,
    expected_policy_sha256: str,
) -> ProviderPolicyReceipt:
    """Load the only approved deployment path and bind it to manifest trust."""

    if path != PROVIDER_POLICY_RECEIPT_PATH:
        raise ReceiptValidationError(
            "provider-policy receipt path is not the approved deployment path"
        )
    return parse_provider_policy_receipt(
        _read_bounded_regular_file(path),
        expected_policy_sha256=expected_policy_sha256,
    )


class ModelDraftInput(BaseModel):
    """A structurally valid proposed model; it is not an active model."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    gateway_model_name: StrictStr
    provider_name: StrictStr
    provider_model_id: StrictStr
    visible_in_discovery: StrictBool

    @field_validator("gateway_model_name")
    @classmethod
    def validate_gateway_model_name(cls, value: str) -> str:
        if MODEL_NAME_RE.fullmatch(value) is None:
            raise ValueError("model name is invalid")
        if value in RESERVED_GATEWAY_MODEL_NAMES:
            raise ValueError("gateway model name is reserved")
        return value

    @field_validator("provider_model_id")
    @classmethod
    def validate_provider_model_id(cls, value: str) -> str:
        if MODEL_NAME_RE.fullmatch(value) is None:
            raise ValueError("model name is invalid")
        return value

    @field_validator("provider_name")
    @classmethod
    def validate_provider_name(cls, value: str) -> str:
        if not _valid_provider_name(value):
            raise ValueError("provider name is invalid")
        return value


@dataclass(frozen=True)
class CacheControlInjectionPoint:
    location: Literal["message"] = "message"
    role: Literal["system"] = "system"


@dataclass(frozen=True)
class ProviderExecutionTarget:
    """Server-owned LiteLLM target fields; contains no provider credential."""

    model: str
    api_base: str
    litellm_credential_name: str
    cache_control_injection_points: tuple[CacheControlInjectionPoint, ...]


@dataclass(frozen=True)
class ResolvedModelDraft:
    """A draft bound to one deployed provider policy and execution target."""

    gateway_model_name: str
    provider_name: str
    provider_model_id: str
    visible_in_discovery: bool
    egress_policy_sha256: str
    target: ProviderExecutionTarget


@dataclass(frozen=True)
class _ProviderAdapter:
    litellm_model_prefix: str
    credential_name: str
    provider_model_id_pattern: re.Pattern[str]
    cache_control_injection_points: tuple[CacheControlInjectionPoint, ...]


_PROVIDER_ADAPTERS = MappingProxyType(
    {
        "anthropic": _ProviderAdapter(
            litellm_model_prefix="anthropic/",
            credential_name="anthropic-primary",
            provider_model_id_pattern=_ANTHROPIC_MODEL_ID_RE,
            cache_control_injection_points=(CacheControlInjectionPoint(),),
        )
    }
)


def resolve_model_draft(
    draft: ModelDraftInput,
    receipt: ProviderPolicyReceipt,
    *,
    egress_origin: str = ENVOY_EGRESS_ORIGIN,
) -> ResolvedModelDraft:
    """Resolve one draft without activating it or probing provider entitlement."""

    if not isinstance(draft, ModelDraftInput):
        raise ModelCatalogError("model draft must be validated before resolution")
    if not isinstance(receipt, ProviderPolicyReceipt):
        raise ModelCatalogError("provider-policy receipt must be validated")
    if egress_origin not in ALLOWED_EGRESS_ORIGINS:
        raise ModelCatalogError("model egress origin is not a deployed adapter")

    provider = receipt.provider(draft.provider_name)
    if provider is None:
        raise ModelCatalogError("model provider is absent from the deployed policy")
    adapter = _PROVIDER_ADAPTERS.get(draft.provider_name)
    if adapter is None:
        raise ModelCatalogError("model provider has no committed runtime adapter")
    if adapter.provider_model_id_pattern.fullmatch(draft.provider_model_id) is None:
        raise ModelCatalogError(
            "provider model ID is invalid for the selected provider"
        )

    target = ProviderExecutionTarget(
        model=f"{adapter.litellm_model_prefix}{draft.provider_model_id}",
        api_base=f"{egress_origin}{provider.route_prefix.removesuffix('/')}",
        litellm_credential_name=adapter.credential_name,
        cache_control_injection_points=adapter.cache_control_injection_points,
    )
    return ResolvedModelDraft(
        gateway_model_name=draft.gateway_model_name,
        provider_name=draft.provider_name,
        provider_model_id=draft.provider_model_id,
        visible_in_discovery=draft.visible_in_discovery,
        egress_policy_sha256=receipt.egress_policy_sha256,
        target=target,
    )


def resolve_model_catalog(
    drafts: Iterable[ModelDraftInput],
    receipt: ProviderPolicyReceipt,
    *,
    egress_origin: str = ENVOY_EGRESS_ORIGIN,
) -> tuple[ResolvedModelDraft, ...]:
    """Resolve a complete candidate catalog and reject ambiguous duplicates.

    Version one permits only one gateway name for each provider/model pair.
    This keeps usage, pricing, and future limit records from splitting one
    upstream model across aliases.
    """

    resolved: list[ResolvedModelDraft] = []
    gateway_names: set[str] = set()
    provider_models: set[tuple[str, str]] = set()
    for draft in drafts:
        if not isinstance(draft, ModelDraftInput):
            raise ModelCatalogError("catalog contains an unvalidated model draft")
        if draft.gateway_model_name in gateway_names:
            raise ModelCatalogConflict("gateway model name is duplicated")
        provider_model = (draft.provider_name, draft.provider_model_id)
        if provider_model in provider_models:
            raise ModelCatalogConflict("provider model is duplicated")
        gateway_names.add(draft.gateway_model_name)
        provider_models.add(provider_model)
        resolved.append(
            resolve_model_draft(
                draft,
                receipt,
                egress_origin=egress_origin,
            )
        )

    return tuple(sorted(resolved, key=lambda item: item.gateway_model_name))
