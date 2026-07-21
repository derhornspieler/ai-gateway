#!/usr/bin/env python3
"""Attach the one reviewed Open WebUI VEX statement to its exact build."""

from __future__ import annotations

import argparse
from datetime import date
import hashlib
import json
from pathlib import Path
import re
import shutil
import stat


POLICY_PATH = Path(".github/openwebui-vex-policy.json")
MAX_JSON_BYTES = 1024 * 1024
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class ReviewedVexError(RuntimeError):
    """The local VEX statement is missing, stale, or used for another image."""


def read_json(path: Path) -> object:
    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ReviewedVexError(f"JSON repeats key {key!r}: {path.name}")
            result[key] = value
        return result

    try:
        metadata = path.lstat()
        raw = path.read_bytes()
    except OSError as exc:
        raise ReviewedVexError(f"cannot read required file: {path}") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_size < 2
        or metadata.st_size > MAX_JSON_BYTES
        or raw.startswith(b"\xef\xbb\xbf")
    ):
        raise ReviewedVexError(f"required JSON file is unsafe: {path}")
    try:
        return json.loads(raw, object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReviewedVexError(f"required file is not valid JSON: {path}") from exc


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_policy(root: Path) -> dict[str, object]:
    policy = read_json(root / POLICY_PATH)
    if not isinstance(policy, dict) or set(policy) != {
        "schema",
        "service",
        "image",
        "document",
        "document_sha256",
        "author",
        "review",
        "build_files",
    }:
        raise ReviewedVexError("reviewed VEX policy has an invalid shape")
    review = policy.get("review")
    build_files = policy.get("build_files")
    if (
        policy.get("schema") != 1
        or policy.get("service") != "open-webui"
        or policy.get("image") != "ai-gateway/open-webui:0.10.2-aigw2"
        or policy.get("document") != ".github/openwebui-vex.json"
        or HEX64_RE.fullmatch(str(policy.get("document_sha256"))) is None
        or policy.get("author")
        != "AI Gateway platform security <security@aigw.internal>"
        or not isinstance(review, dict)
        or set(review)
        != {
            "basis",
            "expires_on",
            "justification",
            "package",
            "reviewed_on",
            "vulnerability",
        }
        or review.get("vulnerability") != "CVE-2026-45829"
        or review.get("package") != "pkg:pypi/chromadb@1.5.9"
        or review.get("justification")
        != "vulnerable_code_cannot_be_controlled_by_adversary"
        or not isinstance(review.get("basis"), str)
        or len(str(review.get("basis"))) < 100
        or not isinstance(build_files, dict)
        or set(build_files)
        != {
            "compose/docker-compose.yml",
            "services/dhi-health-probe/Dockerfile.open-webui",
            "services/dhi-health-probe/patch_openwebui_chroma.py",
            "services/dhi-health-probe/verify_openwebui_chroma.py",
        }
        or any(HEX64_RE.fullmatch(str(value)) is None for value in build_files.values())
    ):
        raise ReviewedVexError("reviewed VEX policy is incomplete or unreviewed")
    try:
        reviewed_on = date.fromisoformat(str(review["reviewed_on"]))
        expires_on = date.fromisoformat(str(review["expires_on"]))
    except ValueError as exc:
        raise ReviewedVexError("reviewed VEX dates are malformed") from exc
    if expires_on < date.today() or expires_on <= reviewed_on:
        raise ReviewedVexError("reviewed Open WebUI VEX statement expired")
    for relative, expected in build_files.items():
        if sha256_file(root / relative) != expected:
            raise ReviewedVexError(f"reviewed VEX build input changed: {relative}")
    document = root / str(policy["document"])
    if sha256_file(document) != policy["document_sha256"]:
        raise ReviewedVexError("reviewed Open WebUI VEX document changed")
    return policy


def validate_document(path: Path, policy: dict[str, object]) -> dict[str, object]:
    payload = read_json(path)
    review = policy["review"]
    assert isinstance(review, dict)
    statements = payload.get("statements") if isinstance(payload, dict) else None
    if (
        not isinstance(payload, dict)
        or payload.get("@context") != "https://openvex.dev/ns/v0.2.0"
        or payload.get("@id")
        != "https://aigw.internal/security/vex/openwebui-0.10.2-aigw2-1"
        or payload.get("author") != policy["author"]
        or payload.get("role") != "Document Creator"
        or payload.get("version") != 1
        or not isinstance(statements, list)
        or len(statements) != 1
    ):
        raise ReviewedVexError("reviewed Open WebUI VEX document is malformed")
    statement = statements[0]
    products = statement.get("products") if isinstance(statement, dict) else None
    vulnerability = statement.get("vulnerability") if isinstance(statement, dict) else None
    if (
        not isinstance(statement, dict)
        or statement.get("@id") != "openwebui-chromadb-1.5.9-cve-2026-45829"
        or vulnerability != {"name": review["vulnerability"]}
        or products != [{"@id": review["package"]}]
        or statement.get("status") != "not_affected"
        or statement.get("justification") != review["justification"]
        or not isinstance(statement.get("status_notes"), str)
        or len(str(statement.get("status_notes"))) < 120
    ):
        raise ReviewedVexError("reviewed Open WebUI VEX statement drifted")
    return payload


def write_json(path: Path, payload: object) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(path)


def attach(root: Path, service: str, image: str, receipt_path: Path) -> None:
    receipt = read_json(receipt_path)
    if (
        not isinstance(receipt, dict)
        or receipt_path.name != "selected-dhi-vex.json"
        or receipt.get("schema") != 1
        or receipt.get("reviewed_records") != []
    ):
        raise ReviewedVexError("selected DHI VEX receipt is not ready for local review")
    if service != "open-webui":
        return
    policy = load_policy(root)
    if image != policy["image"]:
        raise ReviewedVexError("reviewed Open WebUI VEX was requested for another image")
    document_path = root / str(policy["document"])
    document = validate_document(document_path, policy)
    digest = sha256_file(document_path)
    vex_directory = receipt_path.parent / "vex"
    vex_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    destination = vex_directory / f"{digest[:24]}.reviewed.openvex.json"
    shutil.copyfile(document_path, destination)
    destination.chmod(0o600)
    review = policy["review"]
    assert isinstance(review, dict)
    receipt["reviewed_records"] = [
        {
            "author": policy["author"],
            "document_id": document["@id"],
            "file": f"vex/{destination.name}",
            "image": image,
            "package": review["package"],
            "review_expires_on": review["expires_on"],
            "service": service,
            "sha256": digest,
            "signature_verified": False,
            "status": "git_reviewed_not_affected",
            "vulnerability": review["vulnerability"],
        }
    ]
    write_json(receipt_path, receipt)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--service", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    try:
        attach(args.root.resolve(), args.service, args.image, args.receipt)
    except ReviewedVexError as exc:
        raise SystemExit(str(exc)) from None


if __name__ == "__main__":
    main()
