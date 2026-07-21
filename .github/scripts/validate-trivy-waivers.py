#!/usr/bin/env python3
"""Fail closed when a Trivy waiver lacks an owner, reason, or near expiry."""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path, PurePosixPath
import re


REPOSITORY_WAIVER = Path(".trivyignore.yaml")
IMAGE_WAIVER = Path(".github/trivyignore-images.yaml")
LEGACY_WAIVER = Path(".trivyignore")
ALLOWED_SECTIONS = {
    "licenses",
    "misconfigurations",
    "secrets",
    "vulnerabilities",
}
ALLOWED_KEYS = {"expired_at", "id", "paths", "purls", "statement"}
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$")
PURL_RE = re.compile(
    r"^pkg:[A-Za-z0-9.+-]+/[A-Za-z0-9._~%/+:-]+@"
    r"[A-Za-z0-9._~%+:-]+(?:\?[^\s#]+)?(?:#\S+)?$"
)


class WaiverError(RuntimeError):
    """The reviewed-waiver contract is incomplete or ambiguous."""


def waiver_blocks(
    text: str, allowed_sections: set[str] = ALLOWED_SECTIONS
) -> list[tuple[str, list[str]]]:
    """Split the deliberately small Trivy YAML shape into entry blocks."""

    section = ""
    blocks: list[tuple[str, list[str]]] = []
    current: list[str] = []
    seen_sections: set[str] = set()
    for line in text.splitlines():
        if line and not line.startswith(" "):
            match = re.fullmatch(r"([a-z]+):(?: \[\])?", line)
            if match is None or match.group(1) not in allowed_sections:
                raise WaiverError(f"unsupported Trivy waiver section: {line}")
            if current:
                blocks.append((section, current))
                current = []
            section = match.group(1)
            if section in seen_sections:
                raise WaiverError(f"repeated Trivy waiver section: {section}")
            seen_sections.add(section)
            continue
        if line.startswith("  - id: "):
            if not section:
                raise WaiverError("Trivy waiver entry appears before its section")
            if current:
                blocks.append((section, current))
            current = [line]
        elif current:
            current.append(line)
        elif line.strip():
            raise WaiverError("content outside a Trivy waiver entry")
    if current:
        blocks.append((section, current))
    return blocks


def validate_block(section: str, lines: list[str], today: date) -> None:
    """Validate fields that show a waiver was bounded and reviewed."""

    fields: dict[str, str] = {}
    paths: list[str] = []
    purls: list[str] = []
    statement_lines: list[str] = []
    active_multiline = ""
    for line in lines:
        entry = re.fullmatch(r"  - id: (\S+)", line)
        field = re.fullmatch(r"    ([a-z_]+):(?: (.*))?", line)
        if entry:
            if "id" in fields:
                raise WaiverError("Trivy waiver has more than one id")
            fields["id"] = entry.group(1)
            active_multiline = ""
        elif field:
            name, value = field.groups()
            if name not in ALLOWED_KEYS or name in fields:
                raise WaiverError(f"unsupported or repeated Trivy waiver key: {name}")
            fields[name] = value or ""
            active_multiline = name
        elif re.fullmatch(r"      - \S+", line) and active_multiline in {
            "paths",
            "purls",
        }:
            value = line.removeprefix("      - ")
            (paths if active_multiline == "paths" else purls).append(value)
        elif line.startswith("      ") and active_multiline == "statement":
            statement_lines.append(line.strip())
        elif line.strip():
            raise WaiverError(f"unsupported Trivy waiver content: {line.strip()}")

    required = {"id", "expired_at", "statement"}
    if not required <= set(fields) or not set(fields) <= ALLOWED_KEYS:
        raise WaiverError(f"Trivy {section} waiver is missing a required field")
    if ID_RE.fullmatch(fields["id"]) is None:
        raise WaiverError("Trivy waiver id is malformed")
    try:
        expiry = date.fromisoformat(fields["expired_at"])
    except ValueError as exc:
        raise WaiverError("Trivy waiver expiry must use YYYY-MM-DD") from exc
    if expiry <= today:
        raise WaiverError(f"Trivy waiver is expired: {fields['id']}")
    if expiry > today + timedelta(days=366):
        raise WaiverError(f"Trivy waiver exceeds the one-year review window: {fields['id']}")
    if fields["statement"] not in {">-", "|-"}:
        raise WaiverError("Trivy waiver statement must be a readable YAML block")
    statement = " ".join(statement_lines)
    if not statement.startswith("Owner: ") or len(statement) < 50:
        raise WaiverError("Trivy waiver needs an owner and a clear reason")
    if section == "vulnerabilities":
        if "paths" in fields or "purls" not in fields or not purls:
            raise WaiverError(
                "vulnerability waivers require versioned purls and forbid global paths"
            )
        for purl in purls:
            if len(purl) > 512 or PURL_RE.fullmatch(purl) is None:
                raise WaiverError(f"Trivy vulnerability purl is not version-scoped: {purl}")
    else:
        if "purls" in fields or "paths" not in fields or not paths:
            raise WaiverError("non-vulnerability waivers require repository paths")
        for raw_path in paths:
            path = PurePosixPath(raw_path)
            if path.is_absolute() or ".." in path.parts or not Path(raw_path).is_file():
                raise WaiverError(f"Trivy waiver path is unsafe or missing: {raw_path}")


def validate_file(path: Path, allowed_sections: set[str], today: date) -> None:
    text = path.read_text(encoding="utf-8")
    for section, lines in waiver_blocks(text, allowed_sections):
        validate_block(section, lines, today)


def main() -> None:
    if LEGACY_WAIVER.exists():
        raise SystemExit("legacy .trivyignore is forbidden; use reviewed YAML waivers")
    try:
        today = date.today()
        validate_file(REPOSITORY_WAIVER, ALLOWED_SECTIONS, today)
        validate_file(IMAGE_WAIVER, {"vulnerabilities"}, today)
    except (OSError, UnicodeError, WaiverError) as exc:
        raise SystemExit(str(exc)) from None


if __name__ == "__main__":
    main()
