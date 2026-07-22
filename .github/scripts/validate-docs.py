#!/usr/bin/env python3
"""Check links, bookmarks, images, fences, and Mermaid nodes in active docs.

The checker uses only Python's standard library. It deliberately skips archived,
generated, and private documentation. External links are also skipped because a
network-dependent documentation gate would be slow and unreliable.
"""

from __future__ import annotations

import argparse
import html
from html.parser import HTMLParser
from pathlib import Path
import re
import sys
import unicodedata
from typing import NamedTuple
from urllib.parse import unquote, urlsplit


DOCUMENT_SUFFIXES = {".md", ".markdown", ".html", ".htm"}
SKIPPED_DIRECTORIES = {"archive", "generated", "private", ".state"}
ACTIVE_ROOT_DOCUMENTS = (Path("README.md"), Path("CLAUDE.md"), Path("TASKS.md"))
GENERATED_HTML_MARKERS = (
    '<body for="html-export"',
    "<body for='html-export'",
    '<meta name="generator"',
    "<meta name='generator'",
)

FENCE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
ATX_HEADING_RE = re.compile(r"^ {0,3}(#{1,6})[ \t]+(.+?)\s*$")
SETEXT_RE = re.compile(r"^ {0,3}(=+|-+)\s*$")
REFERENCE_LINK_RE = re.compile(
    r"^ {0,3}\[([^]]+)\]:\s*(?:<([^>]+)>|(\S+))"
)
MERMAID_NODE_ID_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
MERMAID_DECLARATION_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_-]*)\s*@?\s*$"
)
MERMAID_SUBGRAPH_RE = re.compile(
    r"^\s*subgraph\s+([A-Za-z_][A-Za-z0-9_-]*)\b",
    re.IGNORECASE,
)
MERMAID_FLOWCHART_RE = re.compile(
    r"^\s*(?:flowchart|graph)\b",
    re.IGNORECASE,
)
MERMAID_ARROW_PATTERNS = (
    r"--\s+[^>\n]+?\s+-->",  # -- label -->
    r"-\.[^>.\n]+\.->",  # -. label .->
    r"==\s+[^>\n]+?\s+==>",  # == label ==>
    r"<-->",
    r"-->",
    r"---",
    r"-\.->",
    r"==>",
    r"--[xo]",
)
MERMAID_ARROW_RE = re.compile("|".join(MERMAID_ARROW_PATTERNS))
OWNER_NEUTRAL_WORKFLOW_RE = re.compile(
    r"^\.\./\.\./actions/workflows/"
    r"([A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml)"
    r"(?:/badge\.svg\?branch=main)?$"
)


class Issue(NamedTuple):
    path: Path
    line: int
    message: str


class Link(NamedTuple):
    line: int
    target: str
    kind: str


class ScanResult(NamedTuple):
    anchors: set[str]
    links: list[Link]
    issues: list[Issue]


def is_generated_html(path: Path) -> bool:
    """Return True for checked-in exports whose source document is validated."""

    if path.suffix.lower() not in {".html", ".htm"}:
        return False
    try:
        beginning = path.read_text(encoding="utf-8", errors="strict")[:200_000]
    except (OSError, UnicodeError):
        return False
    lowered = beginning.lower()
    return any(marker in lowered for marker in GENERATED_HTML_MARKERS)


def discover_documents(root: Path) -> list[Path]:
    """Find active documentation without walking private or archived trees."""

    documents: list[Path] = []
    for relative_path in ACTIVE_ROOT_DOCUMENTS:
        document = root / relative_path
        if document.is_file():
            documents.append(document)

    agents = root / ".claude" / "agents"
    if agents.is_dir():
        documents.extend(path for path in agents.glob("*.md") if path.is_file())

    services = root / "services"
    if services.is_dir():
        documents.extend(
            path for path in services.glob("*/README.md") if path.is_file()
        )

    docs = root / "docs"
    if not docs.is_dir():
        return documents

    for path in docs.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in DOCUMENT_SUFFIXES:
            continue
        relative_parts = path.relative_to(docs).parts[:-1]
        if any(part.lower() in SKIPPED_DIRECTORIES for part in relative_parts):
            continue
        if is_generated_html(path):
            continue
        documents.append(path)
    return sorted(documents)


def mermaid_blocks(lines: list[str]) -> list[list[tuple[int, str]]]:
    """Return the contents and source lines of closed Mermaid fences."""

    blocks: list[list[tuple[int, str]]] = []
    block: list[tuple[int, str]] = []
    open_character = ""
    open_length = 0
    is_mermaid = False

    for line_number, line in enumerate(lines, start=1):
        match = FENCE_RE.match(line)
        if not open_character:
            if not match:
                continue
            fence = match.group(1)
            language = match.group(2).strip().split(maxsplit=1)
            open_character = fence[0]
            open_length = len(fence)
            is_mermaid = bool(language and language[0].lower() == "mermaid")
            block = []
            continue

        if match:
            fence = match.group(1)
            trailing = match.group(2)
            if (
                fence[0] == open_character
                and len(fence) >= open_length
                and not trailing.strip()
            ):
                if is_mermaid:
                    blocks.append(block)
                open_character = ""
                open_length = 0
                is_mermaid = False
                block = []
                continue

        if is_mermaid:
            block.append((line_number, line))

    return blocks


def mermaid_structure(line: str) -> tuple[str, set[str]]:
    """Blank labels and return node IDs declared by shapes on one line."""

    characters = list(line)
    declared: set[str] = set()
    closing_stack: list[str] = []
    pairs = {"[": "]", "(": ")", "{": "}"}
    quote = ""
    index = 0

    while index < len(characters):
        character = characters[index]

        if quote:
            characters[index] = " "
            if character == quote and (index == 0 or line[index - 1] != "\\"):
                quote = ""
            index += 1
            continue

        if closing_stack:
            characters[index] = " "
            if character in pairs:
                closing_stack.append(pairs[character])
            elif character == closing_stack[-1]:
                closing_stack.pop()
            elif character in {'"', "'"}:
                quote = character
            index += 1
            continue

        if line.startswith("%%", index):
            for position in range(index, len(characters)):
                characters[position] = " "
            break

        if character in {'"', "'"}:
            characters[index] = " "
            quote = character
            index += 1
            continue

        if character in pairs:
            prefix = "".join(characters[:index])
            declaration = MERMAID_DECLARATION_RE.search(prefix)
            if declaration:
                declared.add(declaration.group(1))
            characters[index] = " "
            closing_stack.append(pairs[character])
            index += 1
            continue

        if character == "|":
            closing = line.find("|", index + 1)
            if closing != -1:
                for position in range(index, closing + 1):
                    characters[position] = " "
                index = closing + 1
                continue

        index += 1

    structure = "".join(characters)
    subgraph = MERMAID_SUBGRAPH_RE.match(structure)
    if subgraph:
        declared.add(subgraph.group(1))
    return structure, declared


def mermaid_flowchart_issues(path: Path, lines: list[str]) -> list[Issue]:
    """Require every node used by a flowchart edge to have a declaration.

    Mermaid silently creates a node when an edge uses a bare ID. That makes a
    typo look like a new node, so active docs require an explicit shaped node
    declaration somewhere in the same flowchart.
    """

    issues: list[Issue] = []
    for block in mermaid_blocks(lines):
        meaningful = [
            (line_number, line)
            for line_number, line in block
            if line.strip() and not line.lstrip().startswith("%%")
        ]
        if not meaningful or not MERMAID_FLOWCHART_RE.match(meaningful[0][1]):
            continue

        structures: list[tuple[int, str]] = []
        declared: set[str] = set()
        for line_number, line in meaningful[1:]:
            structure, line_declarations = mermaid_structure(line)
            structures.append((line_number, structure))
            declared.update(line_declarations)

        first_reference: dict[str, int] = {}
        for line_number, structure in structures:
            for statement in structure.split(";"):
                operands = mermaid_edge_operands(statement)
                if not operands:
                    continue
                for operand in operands:
                    operand = re.sub(
                        r":::[A-Za-z_][A-Za-z0-9_-]*", "", operand
                    )
                    for node_id in MERMAID_NODE_ID_RE.findall(operand):
                        first_reference.setdefault(node_id, line_number)

        for node_id, line_number in first_reference.items():
            if node_id not in declared:
                issues.append(
                    Issue(
                        path,
                        line_number,
                        f"Mermaid flowchart references undefined node '{node_id}'",
                    )
                )
    return issues


def mermaid_edge_operands(statement: str) -> list[str]:
    """Split one Mermaid edge statement into its node expressions."""

    arrows = list(MERMAID_ARROW_RE.finditer(statement))
    if not arrows:
        return []

    operands: list[str] = []
    start = 0
    for arrow in arrows:
        operands.append(statement[start : arrow.start()])
        start = arrow.end()
    operands.append(statement[start:])
    return operands


def visible_markdown_lines(path: Path, lines: list[str]) -> tuple[list[str], list[Issue]]:
    """Blank fenced code so examples are not mistaken for links or headings."""

    visible = list(lines)
    issues: list[Issue] = []
    open_character = ""
    open_length = 0
    open_line = 0

    for index, line in enumerate(lines, start=1):
        match = FENCE_RE.match(line)
        if not open_character:
            if match:
                fence = match.group(1)
                open_character = fence[0]
                open_length = len(fence)
                open_line = index
                visible[index - 1] = ""
            continue

        visible[index - 1] = ""
        if not match:
            continue
        fence = match.group(1)
        trailing = match.group(2)
        if (
            fence[0] == open_character
            and len(fence) >= open_length
            and not trailing.strip()
        ):
            open_character = ""
            open_length = 0
            open_line = 0

    if open_character:
        issues.append(Issue(path, open_line, "code fence is not closed"))
    return visible, issues


def strip_inline_code(line: str) -> str:
    """Replace inline code spans with spaces while keeping column positions."""

    output = list(line)
    index = 0
    while index < len(line):
        if line[index] != "`":
            index += 1
            continue
        end_of_run = index
        while end_of_run < len(line) and line[end_of_run] == "`":
            end_of_run += 1
        marker = line[index:end_of_run]
        closing = line.find(marker, end_of_run)
        if closing == -1:
            index = end_of_run
            continue
        for position in range(index, closing + len(marker)):
            output[position] = " "
        index = closing + len(marker)
    return "".join(output)


def markdown_links(lines: list[str]) -> list[Link]:
    """Read inline and reference-definition links from visible Markdown."""

    links: list[Link] = []
    for line_number, original in enumerate(lines, start=1):
        if not original:
            continue
        line = strip_inline_code(original)

        definition = REFERENCE_LINK_RE.match(line)
        if definition:
            target = definition.group(2) or definition.group(3)
            links.append(Link(line_number, target, "link"))

        index = 0
        while True:
            opening = line.find("](", index)
            if opening == -1:
                break
            target_start = opening + 2
            depth = 0
            escaped = False
            closing = -1
            for position in range(target_start, len(line)):
                character = line[position]
                if escaped:
                    escaped = False
                    continue
                if character == "\\":
                    escaped = True
                    continue
                if character == "(":
                    depth += 1
                elif character == ")":
                    if depth == 0:
                        closing = position
                        break
                    depth -= 1
            if closing == -1:
                break

            content = line[target_start:closing].strip()
            target = link_destination(content)
            if target:
                image_marker = line.rfind("![", 0, opening)
                label_marker = line.rfind("[", 0, opening)
                kind = (
                    "image"
                    if image_marker >= 0 and image_marker == label_marker - 1
                    else "link"
                )
                links.append(Link(line_number, target, kind))
            index = closing + 1
    return links


def link_destination(content: str) -> str:
    """Remove an optional Markdown link title from a destination."""

    if not content:
        return ""
    if content.startswith("<"):
        closing = content.find(">")
        return content[1:closing] if closing != -1 else content

    depth = 0
    escaped = False
    for index, character in enumerate(content):
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
        elif character == "(":
            depth += 1
        elif character == ")" and depth:
            depth -= 1
        elif character.isspace() and depth == 0:
            return content[:index]
    return content


def rendered_heading_text(value: str) -> str:
    """Remove common Markdown decoration before making a GitHub-style slug."""

    value = re.sub(r"\s+#+\s*$", "", value)
    value = re.sub(r"!\[([^]]*)\]\([^)]*\)", r"\1", value)
    value = re.sub(r"\[([^]]+)\]\([^)]*\)", r"\1", value)
    value = re.sub(r"<[^>]+>", "", value)
    value = html.unescape(value)
    value = re.sub(r"\\(.)", r"\1", value)
    return value.replace("`", "").replace("*", "").strip()


def github_slug(value: str) -> str:
    """Create the heading anchor used by GitHub-flavored Markdown."""

    slug: list[str] = []
    for character in rendered_heading_text(value).lower():
        if character.isspace():
            slug.append("-")
            continue
        if character.isascii():
            if character.isalnum() or character in {"-", "_"}:
                slug.append(character)
            continue
        category = unicodedata.category(character)
        if character in {"-", "_"} or category[0] in {"L", "M", "N", "S"}:
            slug.append(character)
    return "".join(slug)


def markdown_heading_anchors(lines: list[str]) -> set[str]:
    """Collect ATX and setext heading anchors, including duplicate suffixes."""

    anchors: set[str] = set()
    previous = ""
    for line in lines:
        heading = ATX_HEADING_RE.match(line)
        heading_text = heading.group(2) if heading else ""

        if not heading and SETEXT_RE.match(line) and previous.strip():
            heading_text = previous.strip()

        if heading_text:
            base = github_slug(heading_text)
            candidate = base
            duplicate = 1
            while candidate in anchors:
                candidate = f"{base}-{duplicate}"
                duplicate += 1
            anchors.add(candidate)

        previous = line
    return anchors


class LocalHTMLParser(HTMLParser):
    """Collect local-link candidates and explicit bookmarks from HTML."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.anchors: dict[str, int] = {}
        self.duplicate_anchors: list[tuple[str, int]] = []
        self.links: list[Link] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name.lower(): value for name, value in attrs if value is not None}
        line = self.getpos()[0]

        identifiers: list[str] = []
        if "id" in values:
            identifiers.append(values["id"])
        if tag.lower() == "a" and "name" in values:
            identifiers.append(values["name"])
        for identifier in identifiers:
            if identifier in self.anchors:
                self.duplicate_anchors.append((identifier, line))
            else:
                self.anchors[identifier] = line

        link_attribute = {
            "a": "href",
            "img": "src",
            "script": "src",
            "link": "href",
            "source": "src",
        }.get(tag.lower())
        if link_attribute and link_attribute in values:
            kind = "image" if tag.lower() in {"img", "source"} else "link"
            self.links.append(Link(line, values[link_attribute], kind))


def html_scan(path: Path, text: str) -> ScanResult:
    parser = LocalHTMLParser()
    parser.feed(text)
    issues = [
        Issue(path, line, f"duplicate HTML anchor '#{anchor}'")
        for anchor, line in parser.duplicate_anchors
    ]
    return ScanResult(set(parser.anchors), parser.links, issues)


def markdown_scan(path: Path, text: str) -> ScanResult:
    lines = text.splitlines()
    visible, issues = visible_markdown_lines(path, lines)
    issues.extend(mermaid_flowchart_issues(path, lines))
    anchors = markdown_heading_anchors(visible)
    links = markdown_links(visible)

    html_parser = LocalHTMLParser()
    html_parser.feed("\n".join(visible))
    anchors.update(html_parser.anchors)
    links.extend(html_parser.links)
    issues.extend(
        Issue(path, line, f"duplicate HTML anchor '#{anchor}'")
        for anchor, line in html_parser.duplicate_anchors
    )
    return ScanResult(anchors, links, issues)


def scan_text(path: Path, text: str) -> ScanResult:
    if path.suffix.lower() in {".md", ".markdown"}:
        return markdown_scan(path, text)
    return html_scan(path, text)


def unescape_markdown_target(target: str) -> str:
    return re.sub(r"\\([\\()<> ])", r"\1", target)


def resolved_local_target(root: Path, source: Path, target: str) -> tuple[Path, str] | None:
    """Resolve a local target, or return None when it is an external URL."""

    cleaned = unescape_markdown_target(html.unescape(target.strip()))
    if not cleaned or cleaned.startswith("//"):
        return None
    parts = urlsplit(cleaned)
    if parts.scheme or parts.netloc:
        return None

    decoded_path = unquote(parts.path)
    if decoded_path.startswith("/"):
        destination = root / decoded_path.lstrip("/")
    elif decoded_path:
        destination = source.parent / decoded_path
    else:
        destination = source
    return destination.resolve(strict=False), unquote(parts.fragment)


def is_inside(root: Path, path: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def read_document(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="strict")


def is_owner_neutral_workflow_reference(
    root: Path, source: Path, target: str
) -> bool:
    """Accept GitHub's relative badge form only for a real root workflow.

    GitHub renders ``../../actions/workflows/...`` against the current
    repository. This keeps a reusable README free of a personal account name.
    """

    if source != (root / "README.md"):
        return False
    match = OWNER_NEUTRAL_WORKFLOW_RE.fullmatch(target.strip())
    if match is None:
        return False
    return (root / ".github" / "workflows" / match.group(1)).is_file()


def validate(root: Path) -> tuple[list[Path], list[Issue]]:
    """Validate active docs and return both the file list and exact issues."""

    root = root.resolve()
    documents = discover_documents(root)
    scans: dict[Path, ScanResult] = {}
    issues: list[Issue] = []

    for path in documents:
        try:
            text = read_document(path)
        except (OSError, UnicodeError) as error:
            issues.append(Issue(path, 1, f"cannot read UTF-8 document: {error}"))
            continue
        result = scan_text(path, text)
        scans[path.resolve()] = result
        issues.extend(result.issues)

    anchor_cache: dict[Path, set[str] | None] = {
        path: result.anchors for path, result in scans.items()
    }
    for source_path, result in scans.items():
        for link in result.links:
            if is_owner_neutral_workflow_reference(
                root, source_path, link.target
            ):
                continue
            resolved = resolved_local_target(root, source_path, link.target)
            if resolved is None:
                continue
            destination, fragment = resolved
            if not is_inside(root, destination):
                issues.append(
                    Issue(
                        source_path,
                        link.line,
                        f"local {link.kind} leaves repository: {link.target}",
                    )
                )
                continue
            if not destination.exists():
                issues.append(
                    Issue(
                        source_path,
                        link.line,
                        f"local {link.kind} target does not exist: {link.target}",
                    )
                )
                continue
            if not fragment or destination.suffix.lower() not in DOCUMENT_SUFFIXES:
                continue

            if destination not in anchor_cache:
                try:
                    target_text = read_document(destination)
                    anchor_cache[destination] = scan_text(destination, target_text).anchors
                except (OSError, UnicodeError):
                    anchor_cache[destination] = None
            anchors = anchor_cache[destination]
            if anchors is None:
                issues.append(
                    Issue(source_path, link.line, f"cannot read linked document: {link.target}")
                )
            elif fragment not in anchors:
                display = destination.relative_to(root).as_posix()
                issues.append(
                    Issue(
                        source_path,
                        link.line,
                        f"anchor '#{fragment}' was not found in {display}",
                    )
                )

    issues.sort(key=lambda issue: (issue.path.as_posix(), issue.line, issue.message))
    return documents, issues


def display_path(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="repository root (defaults to this script's repository)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    documents, issues = validate(args.root)
    for issue in issues:
        print(f"{display_path(args.root, issue.path)}:{issue.line}: {issue.message}")
    if issues:
        print(f"DOCS_INVALID files={len(documents)} errors={len(issues)}")
        return 1
    print(f"DOCS_VALID files={len(documents)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
