#!/usr/bin/env python3
"""Put one offline image release on a production VM and fill in its inventory.

This is the first-install helper. It replaces the old manual routine of running
``shasum``, copying two large files by hand, and transcribing two 64-character
hashes into ``host_vars``. You point it at the folder holding the release pair
and it does the rest:

1. finds the one production archive and manifest in that folder;
2. reads their SHA-256 values for you;
3. copies both to a private root-owned directory on the VM and re-checks the
   bytes there (``ansible/stage-offline-image-seed.yml``); and
4. writes the five ``offline_image_seed_*`` values into your generated
   ``host_vars`` file.

Nothing about the security gate changes. The release is still pinned by exact
SHA-256 at every hop, and the reviewed loader on the VM still refuses anything
that does not match the manifest. The only thing that goes away is the typing.

If you hold a release hash from a separate record (a signed release note, the
project status page), pass ``--expect-manifest-sha256`` and it must match
before anything is copied.

Run from the repository root. Later image updates use
``scripts/update-images.py upgrade`` instead, which already does all of this.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import subprocess  # nosec B404 - fixed argv ansible-playbook invocation, no shell
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STAGE_PLAYBOOK = ROOT / "ansible" / "stage-offline-image-seed.yml"
REMOTE_SEED_ROOT = "/var/lib/ai-gateway/image-seeds"
HEX64 = re.compile(r"[0-9a-f]{64}")
SAFE_NAME = re.compile(r"[A-Za-z0-9._-]+")
SAFE_ALIAS = re.compile(r"[A-Za-z0-9_-]+")

# The exact keys written by scripts/bootstrap-rocky9-production.py. All five
# move together: the loader contract is fail-closed on a partial set.
SEED_KEYS = (
    "offline_image_seed_enabled",
    "offline_image_seed_remote_path",
    "offline_image_seed_sha256",
    "offline_image_seed_manifest_remote_path",
    "offline_image_seed_manifest_sha256",
)


class StagingError(Exception):
    """One operator-facing failure with a plain-language repair hint."""


def fail(message: str) -> None:
    raise StagingError(message)


def require_release_file(path: Path, suffix: str, label: str) -> Path:
    """Accept an ordinary copied release file; refuse one others can rewrite."""

    if not path.is_absolute() or not str(path).endswith(suffix):
        fail(f"{label} must be an absolute path ending in {suffix}")
    if SAFE_NAME.fullmatch(path.name) is None:
        fail(f"{label} has an unsafe filename: {path.name}")
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        fail(f"{label} does not exist: {path}")
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail(f"{label} must be a regular file, not a symlink: {path}")
    if metadata.st_uid != os.geteuid():
        fail(
            f"{label} must be owned by the user running this command"
            f' (fix: sudo chown "$(id -un)" {path})'
        )
    # Integrity comes from the SHA-256 checks below. The mode only has to stop
    # another user from rewriting the file, so a normal copied 0644 is fine.
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        fail(f"{label} must not be group- or world-writable (fix: chmod go-w {path})")
    if metadata.st_size < 1:
        fail(f"{label} is empty: {path}")
    return path


def sole_match(directory: Path, pattern: str, label: str) -> Path:
    """Return the one release file of a kind, never a preprod one."""

    found = sorted(
        candidate
        for candidate in directory.glob(pattern)
        if ".preprod." not in candidate.name
    )
    if len(found) != 1:
        names = ", ".join(item.name for item in found) or "none"
        fail(
            f"expected exactly one {label} in {directory}, found {len(found)}"
            f" ({names}). Keep one release per folder, or name the file"
            " directly with --archive and --manifest."
        )
    return found[0]


def file_sha256(path: Path, label: str) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise StagingError(f"could not read the {label}: {exc}") from exc
    return digest.hexdigest()


def require_expected(actual: str, expected: str | None, label: str) -> None:
    if expected is None:
        return
    expected = expected.strip().lower()
    if HEX64.fullmatch(expected) is None:
        fail(f"the expected {label} SHA-256 is not 64 lowercase hex characters")
    if actual != expected:
        fail(
            f"the {label} does not match the SHA-256 you supplied."
            f" Expected {expected}, the file on disk is {actual}."
            " Do not stage this file; get a clean copy of the release."
        )


def normalize_vault_id(value: str) -> str:
    """Require ALIAS@/absolute/path to a private password file."""

    alias, separator, password = value.partition("@")
    if not separator or SAFE_ALIAS.fullmatch(alias) is None:
        fail("--vault-id must look like ALIAS@/absolute/path/to/vault-password")
    path = Path(password)
    if not path.is_absolute():
        fail("--vault-id password file must be an absolute path")
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        fail(f"--vault-id password file does not exist: {path}")
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail("--vault-id password file must be a regular file, not a symlink")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        fail(f"--vault-id password file must be mode 0600 (fix: chmod 600 {path})")
    return value


def host_vars_path(inventory: Path, limit: str, override: Path | None) -> Path:
    """Find the one generated host_vars file this deploy actually reads."""

    if override is not None:
        path = override
    else:
        path = inventory.parent / "host_vars" / f"{limit}.yml"
    if not path.is_file():
        fail(
            f"could not find the host settings file: {path}."
            " Generate the inventory first with"
            " scripts/bootstrap-rocky9-production.py, or name the file with"
            " --host-vars."
        )
    return path


def seed_values(remote_archive: str, archive_sha: str, remote_manifest: str, manifest_sha: str) -> dict[str, str]:
    return {
        "offline_image_seed_enabled": "true",
        "offline_image_seed_remote_path": f'"{remote_archive}"',
        "offline_image_seed_sha256": f'"{archive_sha}"',
        "offline_image_seed_manifest_remote_path": f'"{remote_manifest}"',
        "offline_image_seed_manifest_sha256": f'"{manifest_sha}"',
    }


def write_seed_values(path: Path, values: dict[str, str]) -> None:
    """Replace exactly the five seed lines, leaving every comment in place."""

    original = path.read_text(encoding="utf-8")
    lines = original.splitlines(keepends=True)
    seen = {key: 0 for key in SEED_KEYS}
    updated: list[str] = []
    for line in lines:
        key = line.split(":", 1)[0].strip() if ":" in line else ""
        if key in seen:
            seen[key] += 1
            ending = "\n" if line.endswith("\n") else ""
            updated.append(f"{key}: {values[key]}{ending}")
        else:
            updated.append(line)
    wrong = [key for key, count in seen.items() if count != 1]
    if wrong:
        fail(
            f"{path} does not hold exactly one line for each of: "
            + ", ".join(wrong)
            + ". Add or fix those lines by hand using the block printed above,"
            " then run this again."
        )
    # Same-directory temp file plus rename, so an interrupted write can never
    # leave a half-edited inventory behind.
    handle, temporary = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write("".join(updated))
        os.chmod(temporary, stat.S_IMODE(path.stat().st_mode))  # nosec B103 - copies the existing mode
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def run_stage_playbook(
    *,
    inventory: Path,
    limit: str,
    vault_id: str,
    archive: Path,
    archive_sha: str,
    manifest: Path,
    manifest_sha: str,
    remote_directory: str,
    remote_archive: str,
    remote_manifest: str,
) -> None:
    extra = {
        "image_seed_stage_controller_archive": str(archive),
        "image_seed_stage_archive_sha256": archive_sha,
        "image_seed_stage_controller_manifest": str(manifest),
        "image_seed_stage_manifest_sha256": manifest_sha,
        "image_seed_stage_remote_directory": remote_directory,
        "image_seed_stage_remote_archive": remote_archive,
        "image_seed_stage_remote_manifest": remote_manifest,
    }
    argv = [
        "ansible-playbook",
        "-i",
        str(inventory),
        str(STAGE_PLAYBOOK),
        "--limit",
        limit,
        "--vault-id",
        vault_id,
    ]
    for key, value in extra.items():
        argv.extend(["-e", f"{key}={value}"])
    result = subprocess.run(argv, cwd=str(ROOT), check=False)  # nosec B603 - fixed argv, no shell
    if result.returncode != 0:
        fail(
            "copying the release to the VM failed. Read the Ansible error"
            " above; nothing was written to your inventory."
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Copy one production image release to a VM and fill in the five "
            "offline_image_seed_* inventory values. You never type a SHA-256."
        ),
        epilog=(
            "Use this for a first install. Later image updates use "
            "scripts/update-images.py upgrade."
        ),
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--release-dir",
        type=Path,
        help="folder holding one production .docker.tar.zst and .manifest.json",
    )
    source.add_argument("--archive", type=Path, help="absolute .docker.tar.zst path")
    parser.add_argument("--manifest", type=Path, help="absolute .manifest.json path")
    parser.add_argument("--inventory", type=Path, required=True, help="generated hosts.yml")
    parser.add_argument("--limit", required=True, help="the inventory alias for the VM")
    parser.add_argument(
        "--vault-id",
        required=True,
        help="ALIAS@/absolute/path/to/private-vault-password-file",
    )
    parser.add_argument(
        "--host-vars",
        type=Path,
        help="the host settings file to update (default: alongside --inventory)",
    )
    parser.add_argument(
        "--expect-archive-sha256",
        help="optional archive SHA-256 from a separate release record",
    )
    parser.add_argument(
        "--expect-manifest-sha256",
        help="optional manifest SHA-256 from a separate release record",
    )
    parser.add_argument(
        "--print-only",
        action="store_true",
        help="show the five values instead of writing them to the inventory",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.release_dir is not None:
        directory = args.release_dir.expanduser().resolve()
        if not directory.is_dir():
            fail(f"that release folder does not exist: {directory}")
        archive = sole_match(directory, "*.docker.tar.zst", "production archive")
        manifest = sole_match(directory, "*.manifest.json", "production manifest")
    else:
        if args.manifest is None:
            fail("--archive also needs --manifest")
        archive = args.archive.expanduser().resolve()
        manifest = args.manifest.expanduser().resolve()

    archive = require_release_file(archive, ".docker.tar.zst", "release archive")
    manifest = require_release_file(manifest, ".manifest.json", "release manifest")
    if ".preprod." in archive.name or ".preprod." in manifest.name:
        fail(
            "this is the preprod release pair. Production needs the pair"
            " without .preprod in the name."
        )

    inventory = args.inventory.expanduser().resolve()
    if not inventory.is_file():
        fail(f"that inventory file does not exist: {inventory}")
    if SAFE_ALIAS.fullmatch(args.limit) is None:
        fail("--limit must be a plain inventory alias (letters, digits, - and _)")
    vault_id = normalize_vault_id(args.vault_id)
    target = host_vars_path(inventory, args.limit, args.host_vars)

    print("Reading the release files (this takes a moment for a large archive).")
    archive_sha = file_sha256(archive, "release archive")
    manifest_sha = file_sha256(manifest, "release manifest")
    require_expected(archive_sha, args.expect_archive_sha256, "release archive")
    require_expected(manifest_sha, args.expect_manifest_sha256, "release manifest")

    remote_directory = f"{REMOTE_SEED_ROOT}/candidate-{manifest_sha[:16]}"
    remote_archive = f"{remote_directory}/{archive.name}"
    remote_manifest = f"{remote_directory}/{manifest.name}"
    values = seed_values(remote_archive, archive_sha, remote_manifest, manifest_sha)

    print(f"  archive:  {archive.name}")
    print(f"  manifest: {manifest.name}")
    print(f"\nCopying both files to {remote_directory} on {args.limit}.")
    run_stage_playbook(
        inventory=inventory,
        limit=args.limit,
        vault_id=vault_id,
        archive=archive,
        archive_sha=archive_sha,
        manifest=manifest,
        manifest_sha=manifest_sha,
        remote_directory=remote_directory,
        remote_archive=remote_archive,
        remote_manifest=remote_manifest,
    )

    block = "\n".join(f"{key}: {values[key]}" for key in SEED_KEYS)
    if args.print_only:
        print("\nPut these five lines in your host settings file:\n")
        print(block)
        return 0

    write_seed_values(target, values)
    print(f"\nSTAGED_PRODUCTION_SEED {manifest_sha}")
    print(f"Updated {target} with:\n")
    print(block)
    print("\nNext: run the preflight and then the first converge pass.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except StagingError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nERROR: stopped before finishing", file=sys.stderr)
        sys.exit(130)
