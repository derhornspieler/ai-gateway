#!/usr/bin/env python3
"""Validate the three required image-security artifacts before upload."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import stat


IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_JSON_BYTES = 256 * 1024 * 1024


class EvidenceError(RuntimeError):
    """Required image evidence is missing, malformed, or contradictory."""


def read_json(path: Path) -> object:
    """Read one bounded regular JSON file and reject duplicate keys."""

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for name, value in pairs:
            if name in result:
                raise EvidenceError(f"evidence JSON repeats key {name!r}: {path.name}")
            result[name] = value
        return result

    try:
        metadata = path.lstat()
    except OSError as exc:
        raise EvidenceError(f"required evidence file is missing: {path.name}") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_size < 2
        or metadata.st_size > MAX_JSON_BYTES
    ):
        raise EvidenceError(f"required evidence file is unsafe or empty: {path.name}")
    try:
        return json.loads(path.read_bytes(), object_pairs_hook=unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"required evidence is not valid JSON: {path.name}") from exc


def validate_vulnerability_report(payload: object) -> None:
    if not isinstance(payload, dict) or not isinstance(payload.get("SchemaVersion"), int):
        raise EvidenceError("Trivy vulnerability report has an invalid schema")
    results = payload.get("Results") or []
    if not isinstance(results, list):
        raise EvidenceError("Trivy vulnerability report has invalid results")
    for result in results:
        if not isinstance(result, dict):
            raise EvidenceError("Trivy vulnerability report has an invalid result")
        vulnerabilities = result.get("Vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            raise EvidenceError("Trivy vulnerability list is invalid")
        for vulnerability in vulnerabilities:
            severity = vulnerability.get("Severity") if isinstance(vulnerability, dict) else None
            if severity in {"HIGH", "CRITICAL"}:
                raise EvidenceError(
                    "Trivy report contains a HIGH or CRITICAL vulnerability"
                )


def validate_sbom(payload: object) -> None:
    if (
        not isinstance(payload, dict)
        or payload.get("bomFormat") != "CycloneDX"
        or not isinstance(payload.get("specVersion"), str)
        or not isinstance(payload.get("metadata"), dict)
        or not isinstance(payload.get("components", []), list)
    ):
        raise EvidenceError("CycloneDX SBOM has an invalid schema")


def validate_provenance(
    payload: object, expected_platform: str, expected_image_id: str
) -> None:
    operating_system, separator, architecture = expected_platform.partition("/")
    if separator != "/" or operating_system != "linux" or not architecture:
        raise EvidenceError("expected evidence platform is invalid")
    if not isinstance(payload, dict) or payload.get("schema") != 1:
        raise EvidenceError("image provenance has an invalid schema")
    outcomes = payload.get("outcomes")
    image = payload.get("image")
    scanner = payload.get("scanner")
    if (
        not isinstance(outcomes, dict)
        or outcomes.get("pull_or_build") != "success"
        or outcomes.get("high_critical_scan") != "success"
        or outcomes.get("sbom") != "success"
        or not isinstance(scanner, dict)
        or scanner.get("waiver_file_sha256") is None
        or not isinstance(image, dict)
        or image.get("available") is not True
        or IMAGE_ID_RE.fullmatch(str(image.get("id"))) is None
        or image.get("os") != operating_system
        or image.get("architecture") != architecture
    ):
        raise EvidenceError("image provenance does not prove a complete successful scan")
    if expected_image_id:
        if IMAGE_ID_RE.fullmatch(expected_image_id) is None:
            raise EvidenceError("expected custom image ID is malformed")
        if (
            image.get("id") != expected_image_id
            or image.get("expected_build_id") != expected_image_id
            or image.get("expected_build_id_matches") is not True
        ):
            raise EvidenceError("custom image ID is not bound to its build provenance")
    elif payload.get("source_kind") == "external":
        source_reference = payload.get("source_reference")
        repo_digests = image.get("repo_digests") or []
        if (
            not isinstance(source_reference, str)
            or "@sha256:" not in source_reference
            or not isinstance(repo_digests, list)
            or not any(
                isinstance(value, str)
                and value.endswith(source_reference[source_reference.index("@sha256:") :])
                for value in repo_digests
            )
        ):
            raise EvidenceError("external provenance is not bound to its reviewed digest")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--expected-image-id", default="")
    args = parser.parse_args()
    try:
        validate_vulnerability_report(
            read_json(args.directory / "trivy-vulnerabilities.json")
        )
        validate_sbom(read_json(args.directory / "sbom.cdx.json"))
        validate_provenance(
            read_json(args.directory / "provenance.json"),
            args.platform,
            args.expected_image_id,
        )
    except EvidenceError as exc:
        raise SystemExit(str(exc)) from None


if __name__ == "__main__":
    main()
