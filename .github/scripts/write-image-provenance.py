#!/usr/bin/env python3
"""Write auditable, non-secret metadata for one CI image scan."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess


def read_vex_receipt(path: Path) -> tuple[dict[str, object], str]:
    """Read the exact signed-VEX selection used by this image scan."""

    if path.name != "selected-dhi-vex.json":
        raise SystemExit("unreviewed DHI VEX receipt name")
    try:
        raw = path.read_bytes()
        payload = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SystemExit("cannot read selected DHI VEX receipt") from exc
    records = payload.get("records") if isinstance(payload, dict) else None
    reviewed_records = (
        payload.get("reviewed_records") if isinstance(payload, dict) else None
    )
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != 1
        or payload.get("signature_verified") is not True
        or payload.get("transparency_log_verified") is not False
        or not isinstance(payload.get("transparency_log_note"), str)
        or not isinstance(records, list)
        or not isinstance(reviewed_records, list)
        or any(
            not isinstance(record, dict)
            or not isinstance(record.get("reference"), str)
            or record.get("status") not in {"verified", "unavailable"}
            or (
                record.get("status") == "verified"
                and not isinstance(record.get("sha256"), str)
            )
            for record in records
        )
        or any(
            not isinstance(record, dict)
            or record.get("service") != "open-webui"
            or record.get("signature_verified") is not False
            or record.get("status") != "git_reviewed_not_affected"
            or not isinstance(record.get("sha256"), str)
            for record in reviewed_records
        )
    ):
        raise SystemExit("selected DHI VEX receipt is malformed")
    return payload, hashlib.sha256(raw).hexdigest()


def inspect_image(reference: str) -> tuple[dict[str, object] | None, str | None]:
    """Inspect one local image without treating an earlier build failure as fatal."""

    result = subprocess.run(
        ["docker", "image", "inspect", "--", reference],
        text=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode:
        detail = result.stderr.strip().splitlines()
        return None, detail[-1][:1024] if detail else "image is unavailable"
    try:
        records = json.loads(result.stdout)
        record = records[0]
    except (IndexError, TypeError, json.JSONDecodeError):
        return None, "docker returned invalid image inspection JSON"
    if not isinstance(record, dict):
        return None, "docker returned an invalid image inspection record"
    return record, None


def trivy_version() -> str:
    """Capture scanner and database timestamps when the action leaves Trivy on PATH."""

    try:
        result = subprocess.run(
            ["trivy", "--version"],
            text=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
    except OSError:
        return "unavailable after scan action"
    return result.stdout.strip()[:4096] or "unavailable after scan action"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kind", choices=("external", "custom"), required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--source-reference", required=True)
    parser.add_argument("--scope", required=True)
    parser.add_argument("--service", default="")
    parser.add_argument("--input-digest", default="")
    parser.add_argument("--expected-image-id", default="")
    parser.add_argument("--acquisition-outcome", required=True)
    parser.add_argument("--trivy-outcome", required=True)
    parser.add_argument("--scan-outcome", required=True)
    parser.add_argument("--sbom-outcome", required=True)
    parser.add_argument("--waiver-file", required=True)
    parser.add_argument("--vex-receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    record, inspect_error = inspect_image(args.image)
    config = record.get("Config") if isinstance(record, dict) else None
    labels = config.get("Labels") if isinstance(config, dict) else None
    aigw_labels = {
        name: value
        for name, value in (labels.items() if isinstance(labels, dict) else [])
        if isinstance(name, str) and name.startswith("com.aigw.")
    }
    if args.waiver_file not in {
        ".trivyignore.yaml",
        ".github/trivyignore-images.yaml",
    }:
        raise SystemExit("unreviewed Trivy waiver file")
    waiver = Path(args.waiver_file)
    waiver_sha256 = (
        hashlib.sha256(waiver.read_bytes()).hexdigest()
        if waiver.is_file()
        else None
    )
    vex_receipt, vex_receipt_sha256 = read_vex_receipt(args.vex_receipt)
    inspected_id = record.get("Id") if isinstance(record, dict) else None
    identity_match = not args.expected_image_id or inspected_id == args.expected_image_id
    evidence = {
        "schema": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_kind": args.kind,
        "source_reference": args.source_reference,
        "release_scope": args.scope,
        "build_service": args.service or None,
        "build_input_sha256": args.input_digest or None,
        "git": {
            "repository": os.environ.get("GITHUB_REPOSITORY"),
            "commit": os.environ.get("GITHUB_SHA"),
        },
        "github_actions": {
            "workflow": os.environ.get("GITHUB_WORKFLOW"),
            "run_id": os.environ.get("GITHUB_RUN_ID"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "run_url": (
                f"{os.environ.get('GITHUB_SERVER_URL')}/"
                f"{os.environ.get('GITHUB_REPOSITORY')}/actions/runs/"
                f"{os.environ.get('GITHUB_RUN_ID')}"
            ),
        },
        "outcomes": {
            "pull_or_build": args.acquisition_outcome,
            "raw_trivy_scan": args.trivy_outcome,
            "high_critical_scan": args.scan_outcome,
            "sbom": args.sbom_outcome,
        },
        "scanner": {
            "name": "Trivy plus Docker Scout",
            "requested_version": "v0.72.0",
            "runtime_and_database_metadata": trivy_version(),
            "severities": ["HIGH", "CRITICAL"],
            "ignore_unfixed": False,
            "waiver_file": args.waiver_file,
            "waiver_file_sha256": waiver_sha256,
            "vex": {
                "receipt_file": args.vex_receipt.name,
                "receipt_sha256": vex_receipt_sha256,
                "docker_scout_version": vex_receipt["docker_scout_version"],
                "public_key_sha256": vex_receipt["public_key_sha256"],
                "signature_verified": vex_receipt["signature_verified"],
                "transparency_log_verified": vex_receipt[
                    "transparency_log_verified"
                ],
                "transparency_log_note": vex_receipt["transparency_log_note"],
                "references": [
                    record["reference"] for record in vex_receipt["records"]
                ],
                "document_sha256s": [
                    record["sha256"]
                    for record in vex_receipt["records"]
                    if record["status"] == "verified"
                ],
                "statuses": [
                    record["status"] for record in vex_receipt["records"]
                ],
                # These records are reviewed in git and deliberately marked
                # unsigned. They are never presented as Docker-signed DHI VEX.
                "reviewed_records": vex_receipt["reviewed_records"],
            },
        },
        "image": {
            "requested_reference": args.image,
            "available": record is not None,
            "inspect_error": inspect_error,
            "id": inspected_id,
            "expected_build_id": args.expected_image_id or None,
            "expected_build_id_matches": identity_match,
            "repo_digests": record.get("RepoDigests") if isinstance(record, dict) else None,
            "os": record.get("Os") if isinstance(record, dict) else None,
            "architecture": record.get("Architecture") if isinstance(record, dict) else None,
            "aigw_labels": aigw_labels,
        },
        "limitations": [
            "This record is GitHub Actions audit metadata, not signed SLSA provenance.",
            "The hosted runner did not receive or inspect the operator's local offline archive.",
            "The vulnerability database can change after this run.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if not identity_match:
        raise SystemExit("custom image identity changed after the reviewed build")


if __name__ == "__main__":
    main()
