#!/usr/bin/env python3
"""Install Docker Scout and manage signed DHI VEX evidence for CI."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import urllib.request


HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
DHI_IMAGE_RE = re.compile(
    r"^dhi\.io/[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9][A-Za-z0-9._-]*"
    r"@sha256:[0-9a-f]{64}$"
)
PLATFORMS = {"linux/amd64", "linux/arm64"}
MAX_POLICY_BYTES = 64 * 1024
MAX_VEX_BYTES = 32 * 1024 * 1024
MAX_SCOUT_ARCHIVE_BYTES = 240 * 1024 * 1024
MAX_DHI_IMAGES = 32
NO_VEX_REASON = "Docker Scout reported no VEX attestation for this exact DHI image."


class VexError(RuntimeError):
    """DHI VEX input or evidence did not meet the reviewed contract."""


def read_json(path: Path, maximum: int) -> object:
    """Read a bounded regular JSON file and reject duplicate keys."""

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for name, value in pairs:
            if name in result:
                raise VexError(f"JSON repeats key {name!r}: {path.name}")
            result[name] = value
        return result

    try:
        metadata = path.lstat()
        raw = path.read_bytes()
    except OSError as exc:
        raise VexError(f"cannot read required file: {path}") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_size < 2
        or metadata.st_size > maximum
        or raw.startswith(b"\xef\xbb\xbf")
    ):
        raise VexError(f"required file is unsafe, empty, or too large: {path}")
    try:
        return json.loads(raw, object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise VexError(f"required file is not valid JSON: {path}") from exc


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_policy(path: Path) -> dict[str, object]:
    payload = read_json(path, MAX_POLICY_BYTES)
    if not isinstance(payload, dict) or set(payload) != {
        "schema",
        "docker_scout",
        "verification",
    }:
        raise VexError("DHI VEX policy has an invalid shape")
    scout = payload.get("docker_scout")
    verification = payload.get("verification")
    if (
        payload.get("schema") != 1
        or not isinstance(scout, dict)
        or set(scout) != {"version", "linux_amd64_url", "linux_amd64_sha256"}
        or not isinstance(verification, dict)
        or set(verification)
        != {
            "public_key",
            "public_key_source",
            "public_key_sha256",
            "skip_transparency_log",
            "skip_transparency_log_reason",
        }
        or scout.get("version") != "1.23.1"
        or scout.get("linux_amd64_url")
        != "https://github.com/docker/scout-cli/releases/download/v1.23.1/"
        "docker-scout_1.23.1_linux_amd64.tar.gz"
        or HEX64_RE.fullmatch(str(scout.get("linux_amd64_sha256"))) is None
        or verification.get("public_key") != ".github/docker-dhi-vex.pub"
        or verification.get("public_key_source")
        != "https://registry.scout.docker.com/keyring/dhi/latest.pub"
        or HEX64_RE.fullmatch(str(verification.get("public_key_sha256"))) is None
        or verification.get("skip_transparency_log") is not True
        or not isinstance(verification.get("skip_transparency_log_reason"), str)
        or len(str(verification.get("skip_transparency_log_reason"))) < 40
    ):
        raise VexError("DHI VEX policy is incomplete or unreviewed")
    root = path.resolve().parent.parent
    key = root / str(verification["public_key"])
    if sha256_file(key) != verification["public_key_sha256"]:
        raise VexError("committed Docker DHI VEX public key fingerprint changed")
    return payload


def canonical_references(payload: object) -> list[str]:
    if (
        not isinstance(payload, list)
        or len(payload) > MAX_DHI_IMAGES
        or any(not isinstance(value, str) for value in payload)
    ):
        raise VexError("DHI references must be a bounded JSON list of strings")
    references = list(payload)
    if references != sorted(set(references)):
        raise VexError("DHI references must be unique and in canonical order")
    if any(DHI_IMAGE_RE.fullmatch(reference) is None for reference in references):
        raise VexError("DHI references must be exact dhi.io tag-and-digest pins")
    return references


def download_scout(policy_path: Path, destination: Path) -> None:
    policy = load_policy(policy_path)
    scout = policy["docker_scout"]
    assert isinstance(scout, dict)
    request = urllib.request.Request(
        str(scout["linux_amd64_url"]),
        headers={"User-Agent": "ai-gateway-release-security/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            archive = response.read(MAX_SCOUT_ARCHIVE_BYTES + 1)
    except OSError as exc:
        raise VexError("cannot download the pinned Docker Scout release") from exc
    if len(archive) > MAX_SCOUT_ARCHIVE_BYTES:
        raise VexError("Docker Scout release archive is too large")
    if hashlib.sha256(archive).hexdigest() != scout["linux_amd64_sha256"]:
        raise VexError("Docker Scout release archive fingerprint changed")

    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    binary = destination / "docker-scout"
    with tempfile.NamedTemporaryFile(dir=destination, suffix=".tar.gz") as stream:
        stream.write(archive)
        stream.flush()
        with tarfile.open(stream.name, "r:gz") as bundle:
            members = bundle.getmembers()
            if (
                {member.name for member in members} != {"README.md", "docker-scout"}
                or any(not member.isfile() for member in members)
            ):
                raise VexError("Docker Scout archive has an unexpected file layout")
            source = bundle.extractfile("docker-scout")
            if source is None:
                raise VexError("Docker Scout archive has no executable")
            temporary = destination / ".docker-scout.tmp"
            with temporary.open("wb") as output:
                shutil.copyfileobj(source, output)
            os.chmod(temporary, 0o555)
            os.replace(temporary, binary)
    print(binary)


def validate_vex(path: Path, reference: str) -> tuple[int, str]:
    payload = read_json(path, MAX_VEX_BYTES)
    if (
        not isinstance(payload, dict)
        or payload.get("@context") != "https://openvex.dev/ns/v0.2.0"
        or payload.get("author") != "Docker Hardened Images <dhi@docker.com>"
        or payload.get("role") != "Document Creator"
        or payload.get("tooling") != "Docker Scout"
        or not isinstance(payload.get("@id"), str)
        or not str(payload["@id"]).startswith("https://scout.docker.com/public/vex-")
        or not isinstance(payload.get("statements"), list)
        or not payload["statements"]
    ):
        raise VexError(f"Docker returned malformed DHI VEX for {reference}")
    product = reference.split("@", 1)[0]
    product_ids: set[str] = set()
    for statement in payload["statements"]:
        if not isinstance(statement, dict) or not isinstance(statement.get("products"), list):
            raise VexError(f"Docker returned a malformed DHI VEX statement for {reference}")
        for item in statement["products"]:
            if isinstance(item, dict) and isinstance(item.get("@id"), str):
                product_ids.add(item["@id"])
    if product not in product_ids:
        raise VexError(f"DHI VEX does not name its requested image: {reference}")
    return len(payload["statements"]), str(payload["@id"])


def scout_version(binary: Path, expected: str) -> str:
    result = subprocess.run(
        [str(binary), "version"],
        text=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if result.returncode or f"version: v{expected}" not in result.stdout:
        raise VexError("Docker Scout executable does not match the reviewed version")
    return f"v{expected}"


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def fetch_vex(
    policy_path: Path,
    inventory_path: Path,
    scout_binary: Path,
    output_directory: Path,
) -> None:
    policy = load_policy(policy_path)
    inventory = read_json(inventory_path, MAX_POLICY_BYTES * 16)
    if not isinstance(inventory, dict):
        raise VexError("release inventory is not an object")
    platform = inventory.get("platform")
    if platform not in PLATFORMS:
        raise VexError("release inventory has an unsupported DHI VEX platform")
    references = canonical_references(inventory.get("dhi_images"))
    if not references:
        raise VexError("release inventory has no DHI images")
    expected_version = str(policy["docker_scout"]["version"])
    version = scout_version(scout_binary, expected_version)
    root = policy_path.resolve().parent.parent
    key = root / str(policy["verification"]["public_key"])
    vex_directory = output_directory / "vex"
    vex_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    records: list[dict[str, object]] = []
    for reference in references:
        name = hashlib.sha256(reference.encode("utf-8")).hexdigest()[:24]
        final = vex_directory / f"{name}.openvex.json"
        temporary = vex_directory / f".{name}.tmp"
        temporary.unlink(missing_ok=True)
        command = [
            str(scout_binary),
            "vex",
            "get",
            "--verify",
            "--skip-tlog",
            "--key",
            str(key),
            "--platform",
            platform,
            "--output",
            str(temporary),
            f"registry://{reference}",
        ]
        result = subprocess.run(
            command,
            text=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        if result.returncode:
            temporary.unlink(missing_ok=True)
            detail = result.stdout.strip().splitlines()
            diagnostic = detail[-1] if detail else "no diagnostic"
            if "no VEX attestations found for image" in diagnostic:
                records.append(
                    {
                        "document_id": None,
                        "file": None,
                        "reason": NO_VEX_REASON,
                        "reference": reference,
                        "sha256": None,
                        "statements": 0,
                        "status": "unavailable",
                    }
                )
                continue
            raise VexError(
                f"signed DHI VEX fetch failed for {reference}: "
                f"{diagnostic[:1024]}"
            )
        statements, document_id = validate_vex(temporary, reference)
        os.chmod(temporary, 0o600)
        os.replace(temporary, final)
        records.append(
            {
                "document_id": document_id,
                "file": f"vex/{final.name}",
                "reason": None,
                "reference": reference,
                "sha256": sha256_file(final),
                "statements": statements,
                "status": "verified",
            }
        )
    receipt = {
        "schema": 1,
        "platform": platform,
        "policy_sha256": sha256_file(policy_path),
        "public_key_sha256": sha256_file(key),
        "docker_scout_version": version,
        "signature_verified": True,
        "transparency_log_verified": False,
        "transparency_log_note": policy["verification"]["skip_transparency_log_reason"],
        "records": records,
    }
    write_json(output_directory / "receipt.json", receipt)


def validate_receipt(
    policy_path: Path, source_directory: Path, expected_platform: str
) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    policy = load_policy(policy_path)
    receipt = read_json(source_directory / "receipt.json", MAX_POLICY_BYTES * 16)
    if (
        not isinstance(receipt, dict)
        or set(receipt)
        != {
            "schema",
            "platform",
            "policy_sha256",
            "public_key_sha256",
            "docker_scout_version",
            "signature_verified",
            "transparency_log_verified",
            "transparency_log_note",
            "records",
        }
        or receipt.get("schema") != 1
        or receipt.get("platform") != expected_platform
        or receipt.get("policy_sha256") != sha256_file(policy_path)
        or receipt.get("public_key_sha256")
        != policy["verification"]["public_key_sha256"]
        or receipt.get("docker_scout_version")
        != f"v{policy['docker_scout']['version']}"
        or receipt.get("signature_verified") is not True
        or receipt.get("transparency_log_verified") is not False
        or receipt.get("transparency_log_note")
        != policy["verification"]["skip_transparency_log_reason"]
        or not isinstance(receipt.get("records"), list)
    ):
        raise VexError("downloaded DHI VEX receipt is malformed or from another policy")
    by_reference: dict[str, dict[str, object]] = {}
    for record in receipt["records"]:
        if not isinstance(record, dict) or set(record) != {
            "document_id",
            "file",
            "reason",
            "reference",
            "sha256",
            "statements",
            "status",
        }:
            raise VexError("downloaded DHI VEX receipt has a malformed record")
        reference = record.get("reference")
        relative = record.get("file")
        status_value = record.get("status")
        if (
            not isinstance(reference, str)
            or DHI_IMAGE_RE.fullmatch(reference) is None
            or reference in by_reference
            or not isinstance(record.get("statements"), int)
            or status_value not in {"verified", "unavailable"}
        ):
            raise VexError("downloaded DHI VEX record is invalid")
        if status_value == "verified":
            if (
                not isinstance(relative, str)
                or not re.fullmatch(r"vex/[0-9a-f]{24}\.openvex\.json", relative)
                or HEX64_RE.fullmatch(str(record.get("sha256"))) is None
                or record.get("reason") is not None
                or record["statements"] < 1
            ):
                raise VexError("verified DHI VEX record is invalid")
            path = source_directory / relative
            if sha256_file(path) != record["sha256"]:
                raise VexError(f"downloaded DHI VEX digest changed: {reference}")
            statements, document_id = validate_vex(path, reference)
            if statements != record["statements"] or document_id != record["document_id"]:
                raise VexError(f"downloaded DHI VEX content changed: {reference}")
        elif (
            relative is not None
            or record.get("document_id") is not None
            or record.get("sha256") is not None
            or record.get("statements") != 0
            or record.get("reason") != NO_VEX_REASON
        ):
            raise VexError("unavailable DHI VEX record is invalid")
        by_reference[reference] = record
    return receipt, by_reference


def select_vex(
    policy_path: Path,
    source_directory: Path,
    references_json: str,
    platform: str,
    output_directory: Path,
) -> None:
    if platform not in PLATFORMS:
        raise VexError("unsupported DHI VEX platform")
    try:
        requested_payload = json.loads(references_json)
    except json.JSONDecodeError as exc:
        raise VexError("matrix DHI references are not valid JSON") from exc
    references = canonical_references(requested_payload)
    receipt, records = validate_receipt(policy_path, source_directory, platform)
    missing = sorted(set(references) - set(records))
    if missing:
        raise VexError(f"signed DHI VEX is missing for: {', '.join(missing)}")

    output_vex = output_directory / "vex"
    output_vex.mkdir(mode=0o700, parents=True, exist_ok=True)
    selected: list[dict[str, object]] = []
    for reference in references:
        record = records[reference]
        selected_record = dict(record)
        if record["status"] == "verified":
            source = source_directory / str(record["file"])
            destination = output_vex / source.name
            shutil.copyfile(source, destination)
            os.chmod(destination, 0o600)
            selected_record["file"] = f"vex/{destination.name}"
        selected.append(selected_record)

    selected_receipt = {
        key: receipt[key]
        for key in (
            "schema",
            "platform",
            "policy_sha256",
            "public_key_sha256",
            "docker_scout_version",
            "signature_verified",
            "transparency_log_verified",
            "transparency_log_note",
        )
    }
    selected_receipt["records"] = selected
    write_json(output_directory / "selected-dhi-vex.json", selected_receipt)


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    install = subparsers.add_parser("install")
    install.add_argument("--policy", type=Path, required=True)
    install.add_argument("--directory", type=Path, required=True)

    fetch = subparsers.add_parser("fetch")
    fetch.add_argument("--policy", type=Path, required=True)
    fetch.add_argument("--inventory", type=Path, required=True)
    fetch.add_argument("--scout", type=Path, required=True)
    fetch.add_argument("--output-directory", type=Path, required=True)

    select = subparsers.add_parser("select")
    select.add_argument("--policy", type=Path, required=True)
    select.add_argument("--source-directory", type=Path, required=True)
    select.add_argument("--references-json", required=True)
    select.add_argument("--platform", required=True)
    select.add_argument("--output-directory", type=Path, required=True)

    args = parser.parse_args()
    try:
        if args.command == "install":
            download_scout(args.policy, args.directory)
        elif args.command == "fetch":
            fetch_vex(
                args.policy,
                args.inventory,
                args.scout,
                args.output_directory,
            )
        else:
            select_vex(
                args.policy,
                args.source_directory,
                args.references_json,
                args.platform,
                args.output_directory,
            )
    except VexError as exc:
        raise SystemExit(str(exc)) from None


if __name__ == "__main__":
    main()
