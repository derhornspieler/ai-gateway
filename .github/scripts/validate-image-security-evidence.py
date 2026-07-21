#!/usr/bin/env python3
"""Validate every required image-security artifact before upload."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
from datetime import date


IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_JSON_BYTES = 256 * 1024 * 1024
NO_VEX_REASON = "Docker Scout reported no VEX attestation for this exact DHI image."


class EvidenceError(RuntimeError):
    """Required image evidence is missing, malformed, or contradictory."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


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
            if not isinstance(vulnerability, dict):
                raise EvidenceError("Trivy report has a malformed vulnerability")


def validate_scout_sarif(payload: object) -> None:
    """Require Docker Scout's VEX-aware blocking report to be empty."""

    if (
        not isinstance(payload, dict)
        or payload.get("version") != "2.1.0"
        or not isinstance(payload.get("runs"), list)
        or not payload["runs"]
    ):
        raise EvidenceError("Docker Scout SARIF report has an invalid schema")
    for run in payload["runs"]:
        driver = (
            run.get("tool", {}).get("driver", {})
            if isinstance(run, dict)
            else {}
        )
        results = run.get("results") if isinstance(run, dict) else None
        if (
            not isinstance(driver, dict)
            or str(driver.get("name", "")).lower() != "docker scout"
            or not isinstance(results, list)
        ):
            raise EvidenceError("Docker Scout SARIF run is malformed")
        if results:
            raise EvidenceError(
                "Docker Scout report contains a VEX-aware HIGH or CRITICAL finding"
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


def validate_vex_receipt(
    payload: object, directory: Path, expected_platform: str
) -> tuple[str, list[str], list[str], list[str], list[dict[str, object]]]:
    """Prove every selected DHI VEX file is signed-policy evidence."""

    if (
        not isinstance(payload, dict)
        or payload.get("schema") != 1
        or payload.get("platform") != expected_platform
        or payload.get("signature_verified") is not True
        or payload.get("transparency_log_verified") is not False
        or not isinstance(payload.get("transparency_log_note"), str)
        or len(str(payload.get("transparency_log_note"))) < 40
        or payload.get("docker_scout_version") != "v1.23.1"
        or IMAGE_ID_RE.fullmatch(
            "sha256:" + str(payload.get("public_key_sha256"))
        )
        is None
        or not isinstance(payload.get("records"), list)
        or not isinstance(payload.get("reviewed_records"), list)
    ):
        raise EvidenceError("selected DHI VEX receipt has an invalid schema")
    references: list[str] = []
    document_sha256s: list[str] = []
    statuses: list[str] = []
    for record in payload["records"]:
        if not isinstance(record, dict):
            raise EvidenceError("selected DHI VEX receipt has an invalid record")
        reference = record.get("reference")
        relative = record.get("file")
        digest = record.get("sha256")
        status_value = record.get("status")
        if (
            not isinstance(reference, str)
            or not reference.startswith("dhi.io/")
            or "@sha256:" not in reference
            or status_value not in {"verified", "unavailable"}
        ):
            raise EvidenceError("selected DHI VEX receipt record is malformed")
        if status_value == "verified":
            if (
                not isinstance(relative, str)
                or re.fullmatch(r"vex/[0-9a-f]{24}\.openvex\.json", relative) is None
                or IMAGE_ID_RE.fullmatch("sha256:" + str(digest)) is None
                or record.get("reason") is not None
            ):
                raise EvidenceError("verified DHI VEX receipt record is malformed")
            path = directory / relative
            try:
                metadata = path.lstat()
                actual = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError as exc:
                raise EvidenceError("selected DHI VEX document is missing") from exc
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_size < 2
                or metadata.st_size > MAX_JSON_BYTES
                or actual != digest
            ):
                raise EvidenceError(
                    "selected DHI VEX document changed after verification"
                )
            document_sha256s.append(str(digest))
        elif (
            relative is not None
            or digest is not None
            or record.get("document_id") is not None
            or record.get("statements") != 0
            or record.get("reason") != NO_VEX_REASON
        ):
            raise EvidenceError("unavailable DHI VEX receipt record is malformed")
        references.append(reference)
        statuses.append(str(status_value))
    if references != sorted(set(references)):
        raise EvidenceError("selected DHI VEX references are not canonical")
    reviewed_records: list[dict[str, object]] = []
    for record in payload["reviewed_records"]:
        if not isinstance(record, dict) or set(record) != {
            "author",
            "document_id",
            "file",
            "image",
            "package",
            "review_expires_on",
            "service",
            "sha256",
            "signature_verified",
            "status",
            "vulnerability",
        }:
            raise EvidenceError("git-reviewed VEX receipt record is malformed")
        relative = record.get("file")
        digest = record.get("sha256")
        if (
            record.get("author")
            != "AI Gateway platform security <security@aigw.internal>"
            or record.get("document_id")
            != "https://aigw.internal/security/vex/openwebui-0.10.2-aigw2-1"
            or record.get("image") != "ai-gateway/open-webui:0.10.2-aigw2"
            or record.get("package") != "pkg:pypi/chromadb@1.5.9"
            or record.get("service") != "open-webui"
            or record.get("signature_verified") is not False
            or record.get("status") != "git_reviewed_not_affected"
            or record.get("vulnerability") != "CVE-2026-45829"
            or not isinstance(relative, str)
            or re.fullmatch(r"vex/[0-9a-f]{24}\.reviewed\.openvex\.json", relative)
            is None
            or IMAGE_ID_RE.fullmatch("sha256:" + str(digest)) is None
        ):
            raise EvidenceError("git-reviewed Open WebUI VEX record drifted")
        try:
            if date.fromisoformat(str(record["review_expires_on"])) < date.today():
                raise EvidenceError("git-reviewed Open WebUI VEX record expired")
        except ValueError as exc:
            raise EvidenceError("git-reviewed Open WebUI VEX date is malformed") from exc
        document_path = directory / relative
        document = read_json(document_path)
        if (
            sha256_file(document_path) != digest
            or not isinstance(document, dict)
            or document.get("author") != record["author"]
            or document.get("@id") != record["document_id"]
            or not isinstance(document.get("statements"), list)
            or len(document["statements"]) != 1
        ):
            raise EvidenceError("git-reviewed Open WebUI VEX document changed")
        reviewed_records.append(dict(record))
    if len(reviewed_records) > 1:
        raise EvidenceError("too many git-reviewed VEX records were selected")
    receipt_path = directory / "selected-dhi-vex.json"
    return (
        hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
        references,
        document_sha256s,
        statuses,
        reviewed_records,
    )


def validate_provenance(
    payload: object,
    expected_platform: str,
    expected_image_id: str,
    vex_evidence: tuple[
        str, list[str], list[str], list[str], list[dict[str, object]]
    ],
) -> None:
    operating_system, separator, architecture = expected_platform.partition("/")
    if separator != "/" or operating_system != "linux" or not architecture:
        raise EvidenceError("expected evidence platform is invalid")
    if not isinstance(payload, dict) or payload.get("schema") != 1:
        raise EvidenceError("image provenance has an invalid schema")
    outcomes = payload.get("outcomes")
    image = payload.get("image")
    scanner = payload.get("scanner")
    vex = scanner.get("vex") if isinstance(scanner, dict) else None
    (
        vex_sha256,
        vex_references,
        vex_document_sha256s,
        vex_statuses,
        reviewed_records,
    ) = vex_evidence
    if (
        not isinstance(outcomes, dict)
        or outcomes.get("pull_or_build") != "success"
        or outcomes.get("raw_trivy_scan") != "success"
        or outcomes.get("high_critical_scan") != "success"
        or outcomes.get("sbom") != "success"
        or not isinstance(scanner, dict)
        or scanner.get("waiver_file_sha256") is None
        or not isinstance(vex, dict)
        or vex.get("receipt_file") != "selected-dhi-vex.json"
        or vex.get("receipt_sha256") != vex_sha256
        or vex.get("signature_verified") is not True
        or vex.get("transparency_log_verified") is not False
        or vex.get("references") != vex_references
        or vex.get("document_sha256s") != vex_document_sha256s
        or vex.get("statuses") != vex_statuses
        or vex.get("reviewed_records") != reviewed_records
        or not isinstance(image, dict)
        or image.get("available") is not True
        or IMAGE_ID_RE.fullmatch(str(image.get("id"))) is None
        or image.get("os") != operating_system
        or image.get("architecture") != architecture
    ):
        raise EvidenceError("image provenance does not prove a complete successful scan")
    if reviewed_records:
        reviewed = reviewed_records[0]
        if (
            payload.get("build_service") != reviewed["service"]
            or image.get("requested_reference") != reviewed["image"]
        ):
            raise EvidenceError("git-reviewed VEX is attached to another image build")
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
        validate_scout_sarif(
            read_json(args.directory / "scout-vulnerabilities.sarif")
        )
        validate_sbom(read_json(args.directory / "sbom.cdx.json"))
        vex_evidence = validate_vex_receipt(
            read_json(args.directory / "selected-dhi-vex.json"),
            args.directory,
            args.platform,
        )
        validate_provenance(
            read_json(args.directory / "provenance.json"),
            args.platform,
            args.expected_image_id,
            vex_evidence,
        )
    except EvidenceError as exc:
        raise SystemExit(str(exc)) from None


if __name__ == "__main__":
    main()
