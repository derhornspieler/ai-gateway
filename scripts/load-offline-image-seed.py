#!/usr/bin/env python3
"""Verify and load one pre-staged Docker image seed exactly once.

The caller supplies an absolute archive path, its reviewed SHA-256, and a
root-only marker directory.  No archive bytes are accepted until ownership,
mode, compression integrity, and digest all match.  A marker is written only
after both sides of the zstd -> docker image load pipeline succeed.
"""

from __future__ import annotations

import hashlib
import importlib.util
import ipaddress
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from urllib.parse import urlsplit


ROOT_UID = 0
ROOT_GID = 0
SEED_MODE = 0o600
MARKER_DIR_MODE = 0o700
MARKER_MODE = 0o600
MAX_ARCHIVE_METADATA_BYTES = 1024 * 1024
MAX_ARCHIVE_MEMBERS = 100_000
MAX_CAPTURED_OCI_DOCUMENTS = 512
OCI_BLOB_PATH_RE = re.compile(r"^blobs/sha256/([0-9a-f]{64})$")
OCI_IMAGE_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
DOCKER_IMAGE_MANIFEST_MEDIA_TYPE = (
    "application/vnd.docker.distribution.manifest.v2+json"
)
MULTI_PLATFORM_IMAGE_MEDIA_TYPES = frozenset(
    {
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    }
)
OCI_EMPTY_MEDIA_TYPE = "application/vnd.oci.empty.v1+json"
SIGSTORE_BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
FIXED_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
LOCAL_CONTROLLER_PATH = (
    "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
)
LOCAL_DOCKER_HOST = "unix:///run/docker.sock"
FIXED_DOCKER_ENV = {
    "HOME": "/",
    "LC_ALL": "C",
    "PATH": FIXED_PATH,
}
REPOSITORY_COMPONENT = re.compile(r"^[a-z0-9]+(?:[._-]+[a-z0-9]+)*$")
TAG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
SERVICE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
PROVIDER_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
MUTABLE_IMAGE = re.compile(
    r"^(?:[a-z0-9]+(?:[._-]+[a-z0-9]+)*/)*"
    r"[a-z0-9]+(?:[._-]+[a-z0-9]+)*"
    r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?$"
)
MAX_BUILD_SERVICES = 256
MAX_PLAN_BYTES = 4 * 1024 * 1024
RELEASE_SCOPE_PRODUCTION = "production"
RELEASE_SCOPE_PREPROD = "preprod"
RELEASE_SCOPES = {RELEASE_SCOPE_PRODUCTION, RELEASE_SCOPE_PREPROD}
PREPROD_IMAGE_BY_SERVICE = {
    "samba-ad": "ai-gateway/samba-ad:preprod",
    "wif-provider-mock": "ai-gateway/wif-provider-mock:preprod",
}
EGRESS_IMAGE_REPOSITORY = "ai-gateway/envoy-egress"
EGRESS_POLICY_KEYS = {
    "schema_version",
    "egress_policy_sha256",
    "envoy_config_sha256",
    "selected_providers",
    "providers",
    "envoy_image_id",
}
EGRESS_PROVIDER_KEYS = {
    "name",
    "api_hostname",
    "route_prefix",
    "sni",
    "exact_sans",
    "ca_file",
    "ca_bundle_sha256",
    "ca_sha256_fingerprints",
    "provenance_sha256",
}
EGRESS_LABEL_SCHEMA = "com.aigw.egress-policy.schema"
EGRESS_LABEL_PROVIDERS = "com.aigw.egress-policy.providers"
EGRESS_LABEL_SHA256 = "com.aigw.egress-policy.sha256"
EGRESS_LABEL_SOURCE_DATE_EPOCH = "com.aigw.source-date-epoch"
REFERENCE = re.compile(
    r"^(?!ai-gateway/)(?:[a-z0-9]+(?:[._-]+[a-z0-9]+)*/)*"
    r"[a-z0-9]+(?:[._-]+[a-z0-9]+)*:"
    r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}@sha256:[0-9a-f]{64}$"
)
PIN_TOKEN = re.compile(
    r"(?<![A-Za-z0-9._/-])"
    r"((?!ai-gateway/)(?:[a-z0-9]+(?:[._-]+[a-z0-9]+)*/)*"
    r"[a-z0-9]+(?:[._-]+[a-z0-9]+)*:"
    r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}@sha256:[0-9a-f]{64})"
    r"(?![A-Za-z0-9._/-])"
)


class SeedError(RuntimeError):
    """A fail-closed seed validation or load error."""


def _mode(value: os.stat_result) -> int:
    return stat.S_IMODE(value.st_mode)


def validate_trusted_directory_lineage(directory: Path, label: str) -> None:
    """Reject a path that an unprivileged user could replace underneath root.

    Root-owned sticky boundaries such as ``/var/tmp`` are safe: the sticky bit
    prevents another user from renaming a root-owned child. Every other
    group/other-writable ancestor is rejected, as is every symlink ancestor.
    ``ROOT_UID`` is patched to the invoking UID by the unit tests; UID 0 stays
    trusted there so the simulated root path can still cross system-owned
    ancestors.
    """

    if not directory.is_absolute() or any(part == ".." for part in directory.parts):
        raise SeedError(f"{label} path must be canonical and absolute")
    trusted_uids = {0, ROOT_UID}
    cursor = directory
    while True:
        try:
            metadata = cursor.lstat()
        except OSError as exc:
            raise SeedError(f"cannot inspect {label} path ancestor: {cursor}: {exc}") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise SeedError(f"{label} path ancestor must be a real directory: {cursor}")
        if metadata.st_uid not in trusted_uids:
            raise SeedError(f"{label} path ancestor has an untrusted owner: {cursor}")
        if _mode(metadata) & 0o022 and not (
            metadata.st_mode & stat.S_ISVTX
        ):
            raise SeedError(f"{label} path ancestor is writable without sticky protection: {cursor}")
        if cursor == cursor.parent:
            return
        cursor = cursor.parent


def validate_arguments(
    archive: Path,
    archive_digest: str,
    manifest: Path,
    manifest_digest: str,
    marker_dir: Path,
) -> None:
    if not archive.is_absolute():
        raise SeedError("archive path must be absolute")
    if not str(archive).endswith(".docker.tar.zst"):
        raise SeedError("archive path must end in .docker.tar.zst")
    if not manifest.is_absolute():
        raise SeedError("manifest path must be absolute")
    if not str(manifest).endswith(".manifest.json"):
        raise SeedError("manifest path must end in .manifest.json")
    if not marker_dir.is_absolute():
        raise SeedError("marker directory must be absolute")
    for label, digest in (
        ("archive", archive_digest),
        ("manifest", manifest_digest),
    ):
        if len(digest) != 64 or any(
            character not in "0123456789abcdef" for character in digest
        ):
            raise SeedError(
                f"expected {label} SHA-256 must be exactly 64 lowercase "
                "hexadecimal characters"
            )


def validate_marker_dir(marker_dir: Path) -> None:
    validate_trusted_directory_lineage(marker_dir.parent, "marker directory")
    try:
        metadata = marker_dir.lstat()
    except FileNotFoundError:
        try:
            marker_dir.mkdir(mode=MARKER_DIR_MODE)
            os.chown(marker_dir, ROOT_UID, ROOT_GID)
            os.chmod(marker_dir, MARKER_DIR_MODE)
        except OSError as exc:
            raise SeedError(f"cannot create marker directory: {exc}") from exc
        metadata = marker_dir.lstat()

    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise SeedError("marker directory must be a real directory, not a symlink")
    if (metadata.st_uid, metadata.st_gid) != (ROOT_UID, ROOT_GID):
        raise SeedError("marker directory must be owned by root:root")
    if _mode(metadata) != MARKER_DIR_MODE:
        raise SeedError("marker directory mode must be 0700")
    validate_trusted_directory_lineage(marker_dir, "marker directory")


def marker_path(marker_dir: Path, archive_digest: str, manifest_digest: str) -> Path:
    return marker_dir / f"{archive_digest}-{manifest_digest}.loaded"


def marker_is_valid(marker: Path, archive_digest: str, manifest_digest: str) -> bool:
    try:
        metadata = marker.lstat()
    except FileNotFoundError:
        return False

    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise SeedError("existing checksum marker must be a regular file, not a symlink")
    if (metadata.st_uid, metadata.st_gid) != (ROOT_UID, ROOT_GID):
        raise SeedError("existing checksum marker must be owned by root:root")
    if _mode(metadata) != MARKER_MODE:
        raise SeedError("existing checksum marker mode must be 0600")
    try:
        content = marker.read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise SeedError(f"cannot read existing checksum marker: {exc}") from exc
    if content != f"{archive_digest} {manifest_digest}\n":
        raise SeedError("existing checksum marker content does not match its expected digest")
    return True


def validate_regular_file(path: Path, label: str) -> os.stat_result:
    validate_trusted_directory_lineage(path.parent, label)
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise SeedError(f"pre-staged {label} is missing: {path}") from exc

    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise SeedError(f"{label} must be a regular file, not a symlink")
    if (metadata.st_uid, metadata.st_gid) != (ROOT_UID, ROOT_GID):
        raise SeedError(f"{label} must be owned by root:root")
    if _mode(metadata) != SEED_MODE:
        raise SeedError(f"{label} mode must be 0600")
    if metadata.st_size <= 0:
        raise SeedError(f"{label} must not be empty")
    return metadata


def sha256_file(path: Path, label: str) -> str:
    actual = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                actual.update(block)
    except OSError as exc:
        raise SeedError(f"cannot read {label}: {exc}") from exc
    return actual.hexdigest()


def validate_archive(archive: Path, expected_digest: str) -> None:
    validate_regular_file(archive, "image seed")
    if sha256_file(archive, "image seed") != expected_digest:
        raise SeedError("image seed SHA-256 does not match the reviewed inventory value")


def validate_manifest_file(manifest: Path, expected_digest: str) -> dict[str, object]:
    metadata = validate_regular_file(manifest, "image seed manifest")
    if metadata.st_size > 1024 * 1024:
        raise SeedError("image seed manifest exceeds the 1 MiB safety bound")
    if sha256_file(manifest, "image seed manifest") != expected_digest:
        raise SeedError(
            "image seed manifest SHA-256 does not match the reviewed inventory value"
        )

    try:
        decoded = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SeedError(f"cannot decode image seed manifest: {exc}") from exc
    if not isinstance(decoded, dict):
        raise SeedError("image seed manifest root must be an object")
    return decoded


def require_executable(name: str) -> str:
    executable = shutil.which(name, path=FIXED_PATH)
    if not executable:
        raise SeedError(f"required executable is unavailable in the fixed system PATH: {name}")
    return executable


def configure_local_controller_docker(host: str) -> None:
    """Select one caller-owned local Docker socket for macOS preprod only.

    The normal loader remains root-only and fixed to ``/run/docker.sock``.
    Docker Desktop has neither that path nor a root-trusted Docker CLI, so its
    local rehearsal loads as the same non-root user that owns the selected
    desktop Docker socket and the 0600 release files.
    """

    global ROOT_UID, ROOT_GID, FIXED_PATH, LOCAL_DOCKER_HOST, FIXED_DOCKER_ENV

    if os.geteuid() == 0:
        raise SeedError("local preprod image loading must run as the desktop Docker user")
    ROOT_UID = os.geteuid()
    ROOT_GID = os.getegid()
    parsed = urlsplit(host)
    if (
        parsed.scheme != "unix"
        or parsed.netloc
        or not parsed.path.startswith("/")
        or parsed.query
        or parsed.fragment
    ):
        raise SeedError("local preprod Docker endpoint must be one absolute unix:// socket")
    socket_path = Path(parsed.path)
    if ".." in socket_path.parts:
        raise SeedError("local preprod Docker socket path must be canonical")
    validate_trusted_directory_lineage(socket_path.parent, "local Docker socket")
    try:
        metadata = socket_path.lstat()
    except OSError as exc:
        raise SeedError(f"cannot inspect local preprod Docker socket: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISSOCK(metadata.st_mode):
        raise SeedError("local preprod Docker endpoint must be a real Unix socket")
    if metadata.st_uid not in {0, os.geteuid()} or _mode(metadata) & 0o022:
        raise SeedError("local preprod Docker socket has an unsafe owner or mode")

    FIXED_PATH = LOCAL_CONTROLLER_PATH
    LOCAL_DOCKER_HOST = f"unix://{socket_path}"
    FIXED_DOCKER_ENV = {
        "HOME": "/",
        "LC_ALL": "C",
        "PATH": FIXED_PATH,
    }


def configure_local_release_reader() -> None:
    """Validate caller-owned controller files without granting Docker access."""

    global ROOT_UID, ROOT_GID, FIXED_PATH, FIXED_DOCKER_ENV

    ROOT_UID = os.geteuid()
    ROOT_GID = os.getegid()
    FIXED_PATH = LOCAL_CONTROLLER_PATH
    FIXED_DOCKER_ENV = {
        "HOME": "/",
        "LC_ALL": "C",
        "PATH": FIXED_PATH,
    }


def require_docker_ready(docker: str) -> str:
    check = subprocess.run(
        [docker, "--host", LOCAL_DOCKER_HOST, "info", "--format", "{{.Architecture}}"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=FIXED_DOCKER_ENV,
    )
    if check.returncode != 0:
        raise SeedError("Docker daemon is not ready")
    architecture = check.stdout.decode("ascii", errors="replace").strip()
    normalized = {
        "aarch64": "arm64",
        "x86_64": "amd64",
    }.get(architecture, architecture)
    if not normalized or any(
        character not in "abcdefghijklmnopqrstuvwxyz0123456789_-"
        for character in normalized
    ):
        raise SeedError("Docker returned an invalid architecture")
    return f"linux/{normalized}"


def _validate_external_images(raw_images: object) -> list[dict[str, str]]:
    if not isinstance(raw_images, list) or not raw_images:
        raise SeedError("image seed manifest must contain non-empty images data")
    images: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, raw_image in enumerate(raw_images):
        if not isinstance(raw_image, dict) or set(raw_image) != {"reference", "image_id"}:
            raise SeedError(f"image seed manifest image {index} must be an exact object")
        reference = raw_image.get("reference")
        image_id = raw_image.get("image_id")
        if not isinstance(reference, str) or not isinstance(image_id, str):
            raise SeedError(f"image seed manifest image {index} has invalid fields")
        if reference.startswith("ai-gateway/"):
            raise SeedError("external image seed entry must not contain ai-gateway outputs")
        if reference.count("@sha256:") != 1:
            raise SeedError(f"image seed reference is not digest-pinned: {reference}")
        name_and_tag, pinned_digest = reference.rsplit("@sha256:", 1)
        final_component = name_and_tag.rsplit("/", 1)[-1]
        if ":" not in final_component:
            raise SeedError(f"image seed reference is not tag-and-digest pinned: {reference}")
        repository, tag = name_and_tag.rsplit(":", 1)
        repository_components = repository.split("/")
        if (
            not repository_components
            or any(not REPOSITORY_COMPONENT.fullmatch(part) for part in repository_components)
            or not TAG.fullmatch(tag)
        ):
            raise SeedError(f"image seed reference has an unsafe name or tag: {reference}")
        if DIGEST.fullmatch(pinned_digest) is None:
            raise SeedError(f"image seed reference has an invalid digest: {reference}")
        if IMAGE_ID.fullmatch(image_id) is None:
            raise SeedError(f"image seed manifest has an invalid image ID: {reference}")
        if reference in seen:
            raise SeedError(f"image seed manifest contains a duplicate reference: {reference}")
        seen.add(reference)
        images.append({"reference": reference, "image_id": image_id})
    return images


def _validate_custom_images(
    raw_images: object, release_scope: str
) -> list[dict[str, str]]:
    if not isinstance(raw_images, list) or not raw_images:
        raise SeedError("schema-v2 image seed must contain custom images")
    images: list[dict[str, str]] = []
    seen_images: set[str] = set()
    seen_archive: set[str] = set()
    for index, raw_image in enumerate(raw_images):
        if not isinstance(raw_image, dict) or set(raw_image) != {
            "image",
            "archive_reference",
            "image_id",
            "deployment_scope",
            "target_activation",
        }:
            raise SeedError(f"custom image seed entry {index} must be an exact object")
        image = raw_image.get("image")
        archive_reference = raw_image.get("archive_reference")
        image_id = raw_image.get("image_id")
        deployment_scope = raw_image.get("deployment_scope")
        target_activation = raw_image.get("target_activation")
        if (
            not isinstance(image, str)
            or MUTABLE_IMAGE.fullmatch(image) is None
            or not isinstance(archive_reference, str)
            or MUTABLE_IMAGE.fullmatch(archive_reference) is None
            or not isinstance(image_id, str)
            or IMAGE_ID.fullmatch(image_id) is None
            or deployment_scope not in {"production", "preprod-only"}
            or target_activation not in {"active-compose", "archive-only"}
        ):
            raise SeedError(f"custom image seed entry {index} has unsafe fields")
        if (deployment_scope, target_activation) not in {
            ("production", "active-compose"),
            ("preprod-only", "archive-only"),
        }:
            raise SeedError("custom image deployment scope and activation disagree")
        repository = image.rsplit(":", 1)[0] if ":" in image.rsplit("/", 1)[-1] else image
        expected_archive = f"{repository}:aigw-seed-{image_id.removeprefix('sha256:')}"
        if archive_reference != expected_archive or archive_reference == image:
            raise SeedError("custom image transfer tag is not content-addressed")
        if image in seen_images or archive_reference in seen_archive:
            raise SeedError("custom image seed contains a duplicate image or transfer tag")
        seen_images.add(image)
        seen_archive.add(archive_reference)
        images.append(
            {
                "image": image,
                "archive_reference": archive_reference,
                "image_id": image_id,
                "deployment_scope": deployment_scope,
                "target_activation": target_activation,
            }
        )
    preprod_images = {
        image["image"]
        for image in images
        if image["deployment_scope"] == "preprod-only"
    }
    expected_preprod = set(PREPROD_IMAGE_BY_SERVICE.values())
    if release_scope == RELEASE_SCOPE_PRODUCTION:
        if preprod_images or any(
            image["target_activation"] == "archive-only" for image in images
        ):
            raise SeedError("production release contains preproduction-only image data")
        if expected_preprod.intersection({image["image"] for image in images}):
            raise SeedError("production release contains a reserved preproduction image")
    elif preprod_images != expected_preprod:
        raise SeedError(
            "preprod release must contain exactly the reviewed Samba AD and WIF extras"
        )
    return images


def _is_sorted_unique_strings(raw: object) -> bool:
    return (
        isinstance(raw, list)
        and bool(raw)
        and all(isinstance(value, str) for value in raw)
        and raw == sorted(raw)
        and len(raw) == len(set(raw))
    )


def _valid_provider_hostname(value: object) -> bool:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 253
        or value != value.lower()
        or value.endswith(".")
    ):
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        return False
    labels = value.split(".")
    return len(labels) >= 2 and all(
        PROVIDER_NAME.fullmatch(label) is not None for label in labels
    )


def _valid_route_prefix(value: object) -> bool:
    if (
        not isinstance(value, str)
        or len(value) < 3
        or not value.startswith("/")
        or not value.endswith("/")
        or "//" in value
    ):
        return False
    return all(
        PROVIDER_NAME.fullmatch(part) is not None
        for part in value.strip("/").split("/")
    )


def _image_repository(image: str) -> str:
    if ":" in image.rsplit("/", 1)[-1]:
        return image.rsplit(":", 1)[0]
    return image


def _validate_egress_policy(
    raw: object, custom_images: list[dict[str, str]]
) -> dict[str, object]:
    if not isinstance(raw, dict) or set(raw) != EGRESS_POLICY_KEYS:
        raise SeedError("schema-v2 egress policy must be an exact object")
    if type(raw.get("schema_version")) is not int or raw["schema_version"] != 1:
        raise SeedError("schema-v2 egress policy schema_version must be 1")

    policy_sha256 = raw.get("egress_policy_sha256")
    config_sha256 = raw.get("envoy_config_sha256")
    if (
        not isinstance(policy_sha256, str)
        or DIGEST.fullmatch(policy_sha256) is None
        or not isinstance(config_sha256, str)
        or DIGEST.fullmatch(config_sha256) is None
    ):
        raise SeedError("schema-v2 egress policy hashes must be canonical SHA-256 values")

    selected = raw.get("selected_providers")
    providers = raw.get("providers")
    if not _is_sorted_unique_strings(selected):
        raise SeedError("selected egress providers must be nonempty, sorted, and unique")
    assert isinstance(selected, list)
    if not isinstance(providers, list) or len(providers) != len(selected):
        raise SeedError("selected egress providers and provider records disagree")

    normalized_providers: list[dict[str, object]] = []
    hostnames: set[str] = set()
    routes: set[str] = set()
    ca_files: set[str] = set()
    for index, raw_provider in enumerate(providers):
        if not isinstance(raw_provider, dict) or set(raw_provider) != EGRESS_PROVIDER_KEYS:
            raise SeedError(f"egress provider record {index} must be an exact object")
        name = raw_provider.get("name")
        api_hostname = raw_provider.get("api_hostname")
        route_prefix = raw_provider.get("route_prefix")
        sni = raw_provider.get("sni")
        exact_sans = raw_provider.get("exact_sans")
        ca_file = raw_provider.get("ca_file")
        bundle_sha256 = raw_provider.get("ca_bundle_sha256")
        fingerprints = raw_provider.get("ca_sha256_fingerprints")
        provenance_sha256 = raw_provider.get("provenance_sha256")
        if (
            not isinstance(name, str)
            or PROVIDER_NAME.fullmatch(name) is None
            or name != selected[index]
        ):
            raise SeedError("egress provider records must follow canonical selected-provider order")
        if (
            not _valid_provider_hostname(api_hostname)
            or not _valid_route_prefix(route_prefix)
            or not _valid_provider_hostname(sni)
        ):
            raise SeedError(f"egress provider {name!r} has an invalid hostname, route, or SNI")
        if not _is_sorted_unique_strings(exact_sans) or any(
            not _valid_provider_hostname(san) for san in exact_sans
        ):
            raise SeedError(
                f"egress provider {name!r} exact SANs must be valid, sorted, and unique"
            )
        assert isinstance(sni, str)
        if sni not in exact_sans:
            raise SeedError(f"egress provider {name!r} SNI is absent from its exact SANs")
        if ca_file != f"{name}-ca.pem":
            raise SeedError(f"egress provider {name!r} has a noncanonical CA filename")
        if (
            not isinstance(bundle_sha256, str)
            or DIGEST.fullmatch(bundle_sha256) is None
            or not isinstance(provenance_sha256, str)
            or DIGEST.fullmatch(provenance_sha256) is None
        ):
            raise SeedError(f"egress provider {name!r} has an invalid reviewed hash")
        if (
            not isinstance(fingerprints, list)
            or not fingerprints
            or any(
                not isinstance(fingerprint, str)
                or DIGEST.fullmatch(fingerprint) is None
                for fingerprint in fingerprints
            )
            or len(fingerprints) != len(set(fingerprints))
        ):
            raise SeedError(f"egress provider {name!r} has invalid CA fingerprints")
        assert isinstance(api_hostname, str)
        assert isinstance(route_prefix, str)
        assert isinstance(ca_file, str)
        if api_hostname in hostnames or route_prefix in routes or ca_file in ca_files:
            raise SeedError("egress provider hostnames, routes, and CA files must be unique")
        hostnames.add(api_hostname)
        routes.add(route_prefix)
        ca_files.add(ca_file)
        normalized_providers.append(
            {
                "name": name,
                "api_hostname": api_hostname,
                "route_prefix": route_prefix,
                "sni": sni,
                "exact_sans": list(exact_sans),
                "ca_file": ca_file,
                "ca_bundle_sha256": bundle_sha256,
                "ca_sha256_fingerprints": list(fingerprints),
                "provenance_sha256": provenance_sha256,
            }
        )

    for left_index, left in enumerate(normalized_providers):
        left_route = left["route_prefix"]
        assert isinstance(left_route, str)
        for right in normalized_providers[left_index + 1 :]:
            right_route = right["route_prefix"]
            assert isinstance(right_route, str)
            if left_route.startswith(right_route) or right_route.startswith(left_route):
                raise SeedError(
                    f"egress provider routes {left_route!r} and {right_route!r} overlap"
                )

    runtime_policy = {
        "schema_version": 1,
        "selected_providers": list(selected),
        "providers": normalized_providers,
        "envoy_config_sha256": config_sha256,
    }
    canonical_policy = (
        json.dumps(
            runtime_policy,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    if hashlib.sha256(canonical_policy).hexdigest() != policy_sha256:
        raise SeedError("egress policy SHA-256 does not match its canonical receipt")

    envoy_images = [
        image
        for image in custom_images
        if _image_repository(image["image"]) == EGRESS_IMAGE_REPOSITORY
    ]
    if len(envoy_images) != 1:
        raise SeedError("schema-v2 release must contain exactly one Envoy egress image")
    envoy_image_id = raw.get("envoy_image_id")
    if (
        not isinstance(envoy_image_id, str)
        or IMAGE_ID.fullmatch(envoy_image_id) is None
        or envoy_image_id != envoy_images[0]["image_id"]
    ):
        raise SeedError("egress policy Envoy image ID does not match the custom image")

    return {
        "schema_version": 1,
        "egress_policy_sha256": policy_sha256,
        "envoy_config_sha256": config_sha256,
        "selected_providers": list(selected),
        "providers": normalized_providers,
        "envoy_image_id": envoy_image_id,
    }


def _validate_build_inputs(
    raw: object,
    custom_images: list[dict[str, str]],
    release_scope: str,
) -> dict[str, object]:
    if (
        not isinstance(raw, dict)
        or set(raw) != {"schema", "services"}
        or raw.get("schema") != 1
        or not isinstance(raw.get("services"), dict)
        or not raw["services"]
        or len(raw["services"]) > MAX_BUILD_SERVICES
    ):
        raise SeedError("schema-v2 build-input manifest is invalid")
    custom_by_image = {image["image"]: image for image in custom_images}
    normalized: dict[str, dict[str, str]] = {}
    referenced_images: set[str] = set()
    for service, record in sorted(raw["services"].items()):
        if (
            not isinstance(service, str)
            or SERVICE.fullmatch(service) is None
            or not isinstance(record, dict)
            or set(record) != {"digest", "image", "image_id"}
        ):
            raise SeedError("schema-v2 build-input service record is invalid")
        digest = record.get("digest")
        image = record.get("image")
        image_id = record.get("image_id")
        if (
            not isinstance(digest, str)
            or DIGEST.fullmatch(digest) is None
            or not isinstance(image, str)
            or image not in custom_by_image
            or not isinstance(image_id, str)
            or IMAGE_ID.fullmatch(image_id) is None
            or custom_by_image[image]["image_id"] != image_id
        ):
            raise SeedError(f"schema-v2 build-input record disagrees for service={service}")
        normalized[service] = {
            "digest": digest,
            "image": image,
            "image_id": image_id,
        }
        referenced_images.add(image)
    if referenced_images != set(custom_by_image):
        raise SeedError("schema-v2 custom images and build-input records disagree")
    preprod_services = set(PREPROD_IMAGE_BY_SERVICE).intersection(normalized)
    if release_scope == RELEASE_SCOPE_PRODUCTION and preprod_services:
        raise SeedError("production release contains preproduction build inputs")
    if release_scope == RELEASE_SCOPE_PREPROD:
        if preprod_services != set(PREPROD_IMAGE_BY_SERVICE):
            raise SeedError("preprod release omits reviewed preproduction build inputs")
        for service, image in PREPROD_IMAGE_BY_SERVICE.items():
            if normalized[service]["image"] != image:
                raise SeedError("preprod build input uses an unexpected image")
    return {"schema": 1, "services": normalized}


def validate_manifest_document(
    manifest: dict[str, object], archive: Path, platform: str
) -> dict[str, object]:
    schema_version = manifest.get("schema_version")
    if schema_version not in {1, 2}:
        raise SeedError("image seed manifest schema_version must be 1 or 2")
    if manifest.get("platform") != platform:
        raise SeedError(
            f"image seed platform {manifest.get('platform')!r} does not match {platform}"
        )
    if manifest.get("bundle") != archive.name:
        raise SeedError("image seed manifest bundle name does not match the archive")

    scope = manifest.get("scope")
    verification = manifest.get("verification")
    external_images = _validate_external_images(manifest.get("images"))
    custom_images: list[dict[str, str]] = []
    build_inputs: dict[str, object] | None = None
    egress_policy: dict[str, object] | None = None
    release_scope: str | None = None
    if schema_version == 2:
        release_scope = manifest.get("release_scope")  # type: ignore[assignment]
        if release_scope not in RELEASE_SCOPES:
            raise SeedError("schema-v2 release_scope must be production or preprod")
        custom_images = _validate_custom_images(
            manifest.get("custom_images"), release_scope
        )
        build_inputs = _validate_build_inputs(
            manifest.get("build_inputs"), custom_images, release_scope
        )
        egress_policy = _validate_egress_policy(
            manifest.get("egress_policy"), custom_images
        )
    if (
        not isinstance(scope, dict)
        or not isinstance(verification, dict)
    ):
        raise SeedError("image seed manifest must contain scope and verification data")
    if (
        schema_version == 1
        and scope.get("custom_ai_gateway_images_exported") != 0
    ):
        raise SeedError("schema-v1 manifest must not contain custom ai-gateway outputs")
    total = len(external_images) + len(custom_images)
    expected_scope = {
        "exported_images": total,
        "custom_ai_gateway_images_exported": len(custom_images),
    }
    if schema_version == 2:
        expected_scope["external_images_exported"] = len(external_images)
    if scope != expected_scope:
        raise SeedError("image seed manifest image count disagrees with its scope")
    if (
        verification
        != {"verified": total, "missing": 0, "mismatched": 0}
    ):
        raise SeedError("image seed manifest verification summary is not clean")
    expected_keys = {
        "schema_version", "platform", "bundle", "scope", "verification", "images"
    }
    if schema_version == 2:
        expected_keys.update(
            {"release_scope", "custom_images", "build_inputs", "egress_policy"}
        )
    if set(manifest) != expected_keys:
        raise SeedError("image seed manifest contains unexpected or missing fields")
    return {
        "schema_version": schema_version,
        "release_scope": release_scope,
        "platform": platform,
        "external_images": external_images,
        "custom_images": custom_images,
        "build_inputs": build_inputs,
        "egress_policy": egress_policy,
    }


def validate_manifest_schema(
    manifest: dict[str, object], archive: Path, platform: str
) -> list[dict[str, str]]:
    """Backward-compatible schema-v1 validator API used by existing callers."""

    document = validate_manifest_document(manifest, archive, platform)
    if document["schema_version"] != 1:
        raise SeedError("schema-v2 callers must use the versioned manifest document")
    return document["external_images"]  # type: ignore[return-value]


def _read_archive_metadata(archive: Path, zstd: str) -> dict[str, object]:
    """Read only OCI metadata from a verified compressed Docker export."""

    integrity = subprocess.run(
        [zstd, "--quiet", "--test", "--", str(archive)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        check=False,
        env=FIXED_DOCKER_ENV,
    )
    if integrity.returncode:
        detail = integrity.stderr.decode("utf-8", errors="replace")[-4096:].strip()
        raise SeedError(f"zstd integrity test failed: {detail or 'no diagnostic'}")

    decompressor = subprocess.Popen(
        [zstd, "--decompress", "--stdout", "--quiet", "--", str(archive)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=FIXED_DOCKER_ENV,
    )
    if decompressor.stdout is None or decompressor.stderr is None:
        decompressor.kill()
        raise SeedError("cannot establish the image-seed metadata stream")

    found: dict[str, object] = {}
    oci_documents: dict[str, dict[str, object]] = {}
    verified_small_blobs: set[str] = set()
    stream_error: SeedError | None = None
    try:
        with tarfile.open(fileobj=decompressor.stdout, mode="r|") as source:
            for count, member in enumerate(source, start=1):
                if count > MAX_ARCHIVE_MEMBERS:
                    raise SeedError("image seed archive contains too many members")
                if member.name in {"manifest.json", "index.json"}:
                    if (
                        not member.isfile()
                        or member.size < 1
                        or member.size > MAX_ARCHIVE_METADATA_BYTES
                        or member.name in found
                    ):
                        raise SeedError("image seed archive has unsafe OCI metadata")
                    member_file = source.extractfile(member)
                    if member_file is None:
                        raise SeedError("cannot read image seed OCI metadata")
                    try:
                        found[member.name] = json.loads(member_file.read().decode("utf-8"))
                    except (UnicodeError, json.JSONDecodeError) as exc:
                        raise SeedError("image seed OCI metadata is not valid JSON") from exc
                    continue

                blob_match = OCI_BLOB_PATH_RE.fullmatch(member.name)
                if (
                    blob_match is None
                    or not member.isfile()
                    or member.size < 1
                    or member.size > MAX_ARCHIVE_METADATA_BYTES
                ):
                    continue
                member_file = source.extractfile(member)
                if member_file is None:
                    raise SeedError("cannot read image seed OCI blob metadata")
                content = member_file.read()
                digest = f"sha256:{blob_match.group(1)}"
                if hashlib.sha256(content).hexdigest() != blob_match.group(1):
                    raise SeedError("image seed OCI blob digest does not match its path")
                verified_small_blobs.add(digest)
                try:
                    document = json.loads(content.decode("utf-8"))
                except (UnicodeError, json.JSONDecodeError):
                    continue
                if not isinstance(document, dict) or not (
                    isinstance(document.get("manifests"), list)
                    or document.get("artifactType") == SIGSTORE_BUNDLE_MEDIA_TYPE
                ):
                    continue
                if (
                    digest in oci_documents
                    or len(oci_documents) >= MAX_CAPTURED_OCI_DOCUMENTS
                ):
                    raise SeedError("image seed has too many or duplicate OCI documents")
                oci_documents[digest] = document
    except SeedError as exc:
        stream_error = exc
    except (OSError, tarfile.TarError) as exc:
        stream_error = SeedError(f"cannot read image seed archive metadata: {exc}")
    finally:
        decompressor.stdout.close()

    stderr = decompressor.stderr.read()
    returncode = decompressor.wait()
    if stream_error is not None:
        raise stream_error
    if returncode:
        detail = stderr.decode("utf-8", errors="replace")[-4096:].strip()
        raise SeedError(f"cannot decompress image seed metadata: {detail or 'no diagnostic'}")
    found["_oci_documents"] = oci_documents
    found["_verified_small_blobs"] = verified_small_blobs
    return found


def _normalised_oci_name(save_reference: str) -> tuple[str, str, str]:
    """Return registry, repository path, and containerd's canonical tag name."""

    repository, tag = save_reference.rsplit(":", 1)
    components = repository.split("/")
    if len(components) == 1 or not (
        "." in components[0] or ":" in components[0] or components[0] == "localhost"
    ):
        registry = "docker.io"
        image_path = "/".join(components)
        if len(components) == 1:
            image_path = f"library/{image_path}"
    else:
        registry = components[0]
        image_path = "/".join(components[1:])
    return registry, image_path, f"{registry}/{image_path}:{tag}"


def _config_matches_image_id(config: object, image_id: str) -> bool:
    if not isinstance(config, str):
        return False
    digest = image_id.removeprefix("sha256:")
    return config in {f"{digest}.json", f"blobs/sha256/{digest}"}


def _approved_external_sigstore_artifact(
    descriptor: object,
    expected_external_digests: set[str],
    oci_documents: dict[str, dict[str, object]],
    verified_small_blobs: set[str],
) -> bool:
    """Admit only a signature bundle bound to a pinned external OCI index."""

    if not isinstance(descriptor, dict):
        return False
    descriptor_digest = descriptor.get("digest")
    descriptor_size = descriptor.get("size")
    annotations = descriptor.get("annotations")
    if (
        descriptor.get("mediaType") != OCI_IMAGE_MANIFEST_MEDIA_TYPE
        or not isinstance(descriptor_digest, str)
        or IMAGE_ID.fullmatch(descriptor_digest) is None
        or not isinstance(descriptor_size, int)
        or descriptor_size < 1
        or not isinstance(annotations, dict)
        or set(annotations) != {"io.containerd.manifest.subject"}
    ):
        return False
    subject = annotations.get("io.containerd.manifest.subject")
    if not isinstance(subject, str) or IMAGE_ID.fullmatch(subject) is None:
        return False

    subject_is_approved = False
    for parent_digest in expected_external_digests:
        parent = oci_documents.get(parent_digest)
        manifests = parent.get("manifests") if isinstance(parent, dict) else None
        if not isinstance(manifests, list):
            continue
        for candidate in manifests:
            candidate_annotations = (
                candidate.get("annotations") if isinstance(candidate, dict) else None
            )
            if (
                isinstance(candidate, dict)
                and candidate.get("digest") == subject
                and isinstance(candidate_annotations, dict)
                and candidate_annotations.get("vnd.docker.reference.type")
                == "attestation-manifest"
                and isinstance(
                    candidate_annotations.get("vnd.docker.reference.digest"), str
                )
                and IMAGE_ID.fullmatch(
                    candidate_annotations["vnd.docker.reference.digest"]
                )
            ):
                subject_is_approved = True
                break
        if subject_is_approved:
            break
    if not subject_is_approved:
        return False

    artifact = oci_documents.get(descriptor_digest)
    if not isinstance(artifact, dict):
        return False
    artifact_subject = artifact.get("subject")
    config = artifact.get("config")
    layers = artifact.get("layers")
    if (
        artifact.get("schemaVersion") != 2
        or artifact.get("mediaType") != OCI_IMAGE_MANIFEST_MEDIA_TYPE
        or artifact.get("artifactType") != SIGSTORE_BUNDLE_MEDIA_TYPE
        or not isinstance(artifact_subject, dict)
        or artifact_subject.get("mediaType") != OCI_IMAGE_MANIFEST_MEDIA_TYPE
        or artifact_subject.get("digest") != subject
        or not isinstance(artifact_subject.get("size"), int)
        or artifact_subject["size"] < 1
        or not isinstance(config, dict)
        or config.get("mediaType") != OCI_EMPTY_MEDIA_TYPE
        or config.get("artifactType") != SIGSTORE_BUNDLE_MEDIA_TYPE
        or not isinstance(config.get("digest"), str)
        or config["digest"] not in verified_small_blobs
        or not isinstance(config.get("size"), int)
        or config["size"] < 1
        or not isinstance(layers, list)
        or len(layers) != 1
        or not isinstance(layers[0], dict)
        or layers[0].get("mediaType") != SIGSTORE_BUNDLE_MEDIA_TYPE
        or not isinstance(layers[0].get("digest"), str)
        or layers[0]["digest"] not in verified_small_blobs
        or not isinstance(layers[0].get("size"), int)
        or layers[0]["size"] < 1
    ):
        return False
    return descriptor_digest in verified_small_blobs


def validate_archive_document_allowlist(
    archive: Path, zstd: str, document: dict[str, object]
) -> None:
    """Prove that an archive contains only the images approved by its manifest."""

    external_images = document["external_images"]
    custom_images = document["custom_images"]
    assert isinstance(external_images, list)
    assert isinstance(custom_images, list)

    metadata = _read_archive_metadata(archive, zstd)
    archive_manifest = metadata.get("manifest.json")
    archive_index = metadata.get("index.json")
    if not isinstance(archive_manifest, list) or not isinstance(archive_index, dict):
        raise SeedError("image seed must be an OCI archive with manifest.json and index.json")

    external_by_tag = {
        image["reference"].rsplit("@sha256:", 1)[0]: image
        for image in external_images
    }
    custom_by_tag = {
        image["archive_reference"]: image for image in custom_images
    }
    expected_tags = set(external_by_tag) | set(custom_by_tag)
    seen_tags: set[str] = set()
    custom_config_matches: dict[str, bool] = {}
    for entry in archive_manifest:
        if not isinstance(entry, dict):
            raise SeedError("image seed archive manifest contains an invalid entry")
        tags = entry.get("RepoTags")
        if not isinstance(tags, list) or not tags or any(
            not isinstance(tag, str) for tag in tags
        ):
            raise SeedError("image seed archive omitted a required repository tag")
        for tag in tags:
            if tag not in expected_tags or tag in seen_tags:
                raise SeedError(
                    "image seed archive contains an unapproved or duplicate repository tag"
                )
            seen_tags.add(tag)
            custom = custom_by_tag.get(tag)
            if custom is not None:
                custom_config_matches[tag] = _config_matches_image_id(
                    entry.get("Config"), custom["image_id"]
                )
    if seen_tags != expected_tags:
        raise SeedError("image seed archive repository tags do not exactly match its manifest")
    if set(custom_config_matches) != set(custom_by_tag):
        raise SeedError("image seed archive omitted a custom image ID binding")

    descriptors = archive_index.get("manifests")
    if archive_index.get("schemaVersion") != 2 or not isinstance(descriptors, list):
        raise SeedError("image seed OCI index is invalid")

    external_descriptors: dict[tuple[str, str], dict[str, str]] = {}
    for image in external_images:
        reference = image["reference"]
        save_reference = reference.rsplit("@sha256:", 1)[0]
        registry, image_path, canonical_name = _normalised_oci_name(save_reference)
        key = (f"sha256:{reference.rsplit('@sha256:', 1)[1]}", canonical_name)
        external_descriptors[key] = {
            "reference": reference,
            "source_key": f"containerd.io/distribution.source.{registry}",
            "source_value": image_path,
        }
    custom_descriptors = {
        _normalised_oci_name(image["archive_reference"])[2]: image["archive_reference"]
        for image in custom_images
    }

    raw_oci_documents = metadata.get("_oci_documents", {})
    raw_verified_small_blobs = metadata.get("_verified_small_blobs", set())
    if not isinstance(raw_oci_documents, dict) or not isinstance(
        raw_verified_small_blobs, set
    ):
        raise SeedError("image seed OCI support metadata is invalid")
    oci_documents = {
        digest: item
        for digest, item in raw_oci_documents.items()
        if isinstance(digest, str) and isinstance(item, dict)
    }
    if len(oci_documents) != len(raw_oci_documents) or any(
        not isinstance(digest, str) for digest in raw_verified_small_blobs
    ):
        raise SeedError("image seed OCI support metadata is invalid")
    verified_small_blobs = set(raw_verified_small_blobs)
    expected_external_digests = {key[0] for key in external_descriptors}

    seen_external: set[str] = set()
    seen_custom: set[str] = set()
    seen_signature_artifacts: set[str] = set()
    for descriptor in descriptors:
        if not isinstance(descriptor, dict) or not isinstance(
            descriptor.get("annotations"), dict
        ):
            raise SeedError("image seed OCI index contains an invalid descriptor")
        digest = descriptor.get("digest")
        annotations = descriptor["annotations"]
        canonical_name = annotations.get("io.containerd.image.name")
        if not isinstance(canonical_name, str):
            if not _approved_external_sigstore_artifact(
                descriptor,
                expected_external_digests,
                oci_documents,
                verified_small_blobs,
            ):
                raise SeedError("image seed OCI descriptor lacks digest provenance")
            assert isinstance(digest, str)
            if digest in seen_signature_artifacts:
                raise SeedError("image seed archive has a duplicate signature artifact")
            seen_signature_artifacts.add(digest)
            continue
        if (
            not isinstance(digest, str)
            or IMAGE_ID.fullmatch(digest) is None
        ):
            raise SeedError("image seed OCI descriptor lacks digest provenance")

        external = external_descriptors.get((digest, canonical_name))
        if external is not None:
            reference = external["reference"]
            if (
                annotations.get(external["source_key"]) != external["source_value"]
                or reference in seen_external
            ):
                raise SeedError(
                    "image seed archive has invalid or duplicate OCI image provenance"
                )
            seen_external.add(reference)
            continue

        archive_reference = custom_descriptors.get(canonical_name)
        if archive_reference is None or archive_reference in seen_custom:
            raise SeedError("image seed archive contains an unapproved OCI image descriptor")
        custom = custom_by_tag[archive_reference]
        if (
            digest != custom["image_id"]
            and not custom_config_matches[archive_reference]
        ):
            raise SeedError(
                "custom image archive tag does not bind its immutable image ID"
            )
        seen_custom.add(archive_reference)

    expected_external = {
        image["reference"] for image in external_images
    }
    if seen_external != expected_external or seen_custom != set(custom_descriptors.values()):
        raise SeedError("image seed OCI descriptors do not exactly match its manifest")


def validate_production_release(
    archive: Path,
    archive_digest: str,
    manifest_path: Path,
    manifest_digest: str,
) -> str:
    """Prove one controller release is production-only without loading images."""

    if not archive.is_absolute() or not str(archive).endswith(".docker.tar.zst"):
        raise SeedError("archive path must be an absolute .docker.tar.zst path")
    if not manifest_path.is_absolute() or not str(manifest_path).endswith(
        ".manifest.json"
    ):
        raise SeedError("manifest path must be an absolute .manifest.json path")
    if archive.parent != manifest_path.parent:
        raise SeedError("archive and manifest must use the same release directory")
    if DIGEST.fullmatch(archive_digest) is None or DIGEST.fullmatch(
        manifest_digest
    ) is None:
        raise SeedError("release SHA-256 values must be lowercase hexadecimal")

    manifest = validate_manifest_file(manifest_path, manifest_digest)
    platform = manifest.get("platform")
    if platform not in {"linux/amd64", "linux/arm64"}:
        raise SeedError("production release platform must be linux/amd64 or linux/arm64")
    document = validate_manifest_document(manifest, archive, platform)
    if (
        document["schema_version"] != 2
        or document["release_scope"] != RELEASE_SCOPE_PRODUCTION
    ):
        raise SeedError("remote staging requires a production-scoped schema-v2 release")

    # The cheap manifest scope gate runs first. A preprod release therefore
    # cannot make the controller hash or decompress its multi-gigabyte archive.
    validate_archive(archive, archive_digest)
    zstd = require_executable("zstd")
    validate_archive_document_allowlist(archive, zstd, document)
    return f"VALIDATED_PRODUCTION_RELEASE {archive_digest} {manifest_digest}"


def validate_archive_image_allowlist(
    archive: Path, zstd: str, required_images: list[dict[str, str]]
) -> None:
    """Prove loading this archive can create only manifest-approved images.

    Docker's OCI exporter carries the tag in ``manifest.json`` and the
    repository-digest provenance in ``index.json``.  Validate both before
    ``docker image load`` touches the daemon; a checksum alone cannot express
    the manifest-to-archive allow-list boundary.
    """

    document: dict[str, object] = {
        "schema_version": 1,
        "external_images": required_images,
        "custom_images": [],
        "build_inputs": None,
    }
    validate_archive_document_allowlist(archive, zstd, document)


def _image_platform_matches(record: dict[str, object], platform: str) -> bool:
    operating_system, architecture = platform.split("/", 1)
    actual_os = record.get("Os")
    actual_architecture = record.get("Architecture")
    descriptor = record.get("Descriptor")
    if (
        (not actual_os or not actual_architecture)
        and isinstance(descriptor, dict)
        and isinstance(descriptor.get("platform"), dict)
    ):
        descriptor_platform = descriptor["platform"]
        actual_os = descriptor_platform.get("os")
        actual_architecture = descriptor_platform.get("architecture")
    actual_architecture = {
        "aarch64": "arm64",
        "x86_64": "amd64",
    }.get(actual_architecture, actual_architecture)
    return actual_os == operating_system and actual_architecture == architecture


def _local_image_has_platform(
    docker: str,
    reference: str,
    record: dict[str, object],
    expected_platform: str,
) -> bool:
    """Verify one local platform, including containerd-backed OCI indexes.

    Docker Desktop's containerd image store may load an OCI index with blank
    top-level ``Os`` and ``Architecture`` fields.  The parent index still owns
    the reviewed image ID and repository digest.  In that narrow case, ask
    Docker to resolve the requested platform from the already-loaded index and
    require an exact platform-bearing child manifest descriptor.
    """

    if _image_platform_matches(record, expected_platform):
        return True
    descriptor = record.get("Descriptor")
    if (
        not isinstance(descriptor, dict)
        or descriptor.get("mediaType") not in MULTI_PLATFORM_IMAGE_MEDIA_TYPES
        or descriptor.get("digest") != record.get("Id")
    ):
        return False
    inspection = subprocess.run(
        [
            docker,
            "--host",
            LOCAL_DOCKER_HOST,
            "image",
            "inspect",
            "--platform",
            expected_platform,
            "--",
            reference,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
        env=FIXED_DOCKER_ENV,
    )
    if inspection.returncode != 0:
        return False
    try:
        records = json.loads(inspection.stdout)
        platform_record = records[0]
        if not isinstance(platform_record, dict):
            return False
        platform_descriptor = platform_record.get("Descriptor")
    except (IndexError, KeyError, TypeError, json.JSONDecodeError):
        return False
    return _resolved_platform_record_matches(platform_record, expected_platform)


def _resolved_platform_record_matches(
    record: dict[str, object], expected_platform: str
) -> bool:
    descriptor = record.get("Descriptor")
    return (
        isinstance(descriptor, dict)
        and descriptor.get("mediaType")
        in {OCI_IMAGE_MANIFEST_MEDIA_TYPE, DOCKER_IMAGE_MANIFEST_MEDIA_TYPE}
        and isinstance(descriptor.get("digest"), str)
        and IMAGE_ID.fullmatch(descriptor["digest"]) is not None
        and _image_platform_matches(record, expected_platform)
    )


def invalid_required_images(
    docker: str,
    images: list[dict[str, str]],
    expected_platform: str | None = None,
) -> list[str]:
    invalid: list[str] = []
    for image in images:
        reference = image["reference"]
        inspection = subprocess.run(
            [docker, "--host", LOCAL_DOCKER_HOST, "image", "inspect", "--", reference],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            env=FIXED_DOCKER_ENV,
        )
        if inspection.returncode != 0:
            invalid.append(reference)
            continue
        try:
            records = json.loads(inspection.stdout)
            record = records[0]
            repo_digests = record.get("RepoDigests") or []
        except (IndexError, KeyError, TypeError, json.JSONDecodeError):
            invalid.append(reference)
            continue
        pinned_digest = reference.rsplit("@sha256:", 1)[1]
        if record.get("Id") != image["image_id"] or not any(
            isinstance(repo_digest, str)
            and repo_digest.endswith(f"@sha256:{pinned_digest}")
            for repo_digest in repo_digests
        ) or (
            expected_platform is not None
            and not _local_image_has_platform(
                docker, reference, record, expected_platform
            )
        ):
            invalid.append(reference)
    return invalid


def invalid_custom_images(
    docker: str, images: list[dict[str, str]], expected_platform: str
) -> list[str]:
    invalid: list[str] = []
    for image in images:
        archive_reference = image["archive_reference"]
        inspection = subprocess.run(
            [
                docker,
                "--host",
                LOCAL_DOCKER_HOST,
                "image",
                "inspect",
                "--",
                archive_reference,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            env=FIXED_DOCKER_ENV,
        )
        if inspection.returncode != 0:
            invalid.append(archive_reference)
            continue
        try:
            records = json.loads(inspection.stdout)
            record = records[0]
            image_id = record["Id"]
        except (IndexError, KeyError, TypeError, json.JSONDecodeError):
            invalid.append(archive_reference)
            continue
        if image_id != image["image_id"] or not _local_image_has_platform(
            docker, archive_reference, record, expected_platform
        ):
            invalid.append(archive_reference)
    return invalid


def _egress_custom_image(
    custom_images: list[dict[str, str]],
) -> dict[str, str]:
    matches = [
        image
        for image in custom_images
        if _image_repository(image["image"]) == EGRESS_IMAGE_REPOSITORY
    ]
    if len(matches) != 1:
        raise SeedError("release does not contain exactly one Envoy egress image")
    return matches[0]


def _egress_policy_labels_match(
    image_record: dict[str, object], egress_policy: dict[str, object]
) -> bool:
    config = image_record.get("Config")
    if not isinstance(config, dict):
        return False
    labels = config.get("Labels")
    if not isinstance(labels, dict):
        return False
    selected = egress_policy["selected_providers"]
    assert isinstance(selected, list)
    return (
        image_record.get("Id") == egress_policy["envoy_image_id"]
        and labels.get(EGRESS_LABEL_SCHEMA) == "1"
        and labels.get(EGRESS_LABEL_PROVIDERS) == ",".join(selected)
        and labels.get(EGRESS_LABEL_SHA256)
        == egress_policy["egress_policy_sha256"]
        and labels.get(EGRESS_LABEL_SOURCE_DATE_EPOCH) == "0"
    )


def invalid_egress_policy_image(
    docker: str,
    custom_images: list[dict[str, str]],
    egress_policy: dict[str, object],
) -> list[str]:
    """Verify immutable policy labels without executing release-controlled bytes."""

    envoy_image = _egress_custom_image(custom_images)
    reference = envoy_image["archive_reference"]
    inspection = subprocess.run(
        [docker, "--host", LOCAL_DOCKER_HOST, "image", "inspect", "--", reference],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
        env=FIXED_DOCKER_ENV,
    )
    if inspection.returncode != 0:
        return [reference]
    try:
        records = json.loads(inspection.stdout)
        record = records[0]
    except (IndexError, TypeError, json.JSONDecodeError):
        return [reference]
    if not isinstance(record, dict) or not _egress_policy_labels_match(
        record, egress_policy
    ):
        return [reference]
    return []


def invalid_document_images(docker: str, document: dict[str, object]) -> list[str]:
    external_images = document["external_images"]
    custom_images = document["custom_images"]
    expected_platform = document["platform"]
    assert isinstance(external_images, list)
    assert isinstance(custom_images, list)
    assert isinstance(expected_platform, str)
    invalid = invalid_required_images(docker, external_images, expected_platform)
    invalid.extend(invalid_custom_images(docker, custom_images, expected_platform))
    if document["schema_version"] == 2:
        egress_policy = document["egress_policy"]
        assert isinstance(egress_policy, dict)
        invalid.extend(
            invalid_egress_policy_image(docker, custom_images, egress_policy)
        )
    return invalid


def existing_seed_tag_conflicts(
    docker: str, document: dict[str, object]
) -> list[str]:
    """Return existing archive tags that a local load would overwrite.

    Docker images are daemon-global. Local preprod may add its reviewed tags,
    but it must not move a tag already used by another local project. The
    production target is a dedicated host and retains its original behavior.
    """

    expected: dict[str, str] = {}
    external_images = document.get("external_images")
    custom_images = document.get("custom_images")
    if not isinstance(external_images, list) or not isinstance(custom_images, list):
        raise SeedError("image seed document has no complete tag inventory")
    for image in external_images:
        expected[image["reference"].rsplit("@sha256:", 1)[0]] = image["image_id"]
    for image in custom_images:
        expected[image["archive_reference"]] = image["image_id"]

    conflicts: list[str] = []
    for reference, expected_id in sorted(expected.items()):
        inspection = subprocess.run(
            [
                docker,
                "--host",
                LOCAL_DOCKER_HOST,
                "image",
                "inspect",
                "--format",
                "{{.Id}}",
                "--",
                reference,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            env=FIXED_DOCKER_ENV,
        )
        if inspection.returncode == 0:
            actual_id = inspection.stdout.decode("ascii", errors="replace").strip()
            if actual_id != expected_id:
                conflicts.append(reference)
    return conflicts


def collect_current_image_reference_scopes(
    project_root: Path,
) -> dict[str, set[str]]:
    """Collect production pins and the full preprod union from deployed source."""

    if not project_root.is_absolute():
        raise SeedError("project root must be absolute")
    try:
        root = project_root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise SeedError("project root is missing or cannot be resolved") from exc
    if not root.is_dir():
        raise SeedError("project root must be a directory")
    validate_trusted_directory_lineage(root, "project root")

    compose_candidates = (
        root / "docker-compose.yml",
        root / "compose" / "docker-compose.yml",
    )
    compose_sources = [path for path in compose_candidates if path.is_file()]
    if len(compose_sources) != 1:
        raise SeedError("project root must contain exactly one reviewed Compose source")
    services_root = root / "services"
    if not services_root.is_dir():
        raise SeedError("project root does not contain reviewed service sources")
    compose_root = compose_sources[0].parent
    production_compose_sources = [
        path
        for path in (
            compose_root / "docker-compose.platform-dns.yml",
        )
        if path.is_file()
    ]
    preprod_only_paths = [
        path
        for path in (compose_root / "docker-compose.preprod.yml",)
        if path.is_file()
    ]
    production_paths = [
        compose_sources[0],
        *production_compose_sources,
    ]
    for path in sorted(services_root.glob("**/Dockerfile*")):
        relative = path.relative_to(services_root)
        if relative.parts[0] in {"samba-ad-preprod", "wif-provider-mock"}:
            preprod_only_paths.append(path)
        else:
            production_paths.append(path)
    source_paths = [*production_paths, *preprod_only_paths]
    if len(production_paths) == 1:
        raise SeedError("project root contains no reviewed Dockerfile sources")

    references_by_path: dict[Path, set[str]] = {}
    for source_path in source_paths:
        try:
            resolved = source_path.resolve(strict=True)
            resolved.relative_to(root)
            metadata = source_path.lstat()
        except (OSError, RuntimeError, ValueError) as exc:
            raise SeedError("project image source escapes the supplied root") from exc
        if (
            resolved != source_path.absolute()
            or stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
        ):
            raise SeedError("project image source must be a regular non-symlink file")
        if (metadata.st_uid, metadata.st_gid) != (ROOT_UID, ROOT_GID) or (
            _mode(metadata) & 0o022
        ):
            raise SeedError("project image source must be root-owned and non-writable")
        if metadata.st_size < 1 or metadata.st_size > MAX_ARCHIVE_METADATA_BYTES:
            raise SeedError("project image source exceeds the safety bound")
        try:
            content = resolved.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise SeedError("cannot read a project image source") from exc
        references: set[str] = set()
        for match in PIN_TOKEN.finditer(content):
            reference = match.group(1)
            if REFERENCE.fullmatch(reference) is None:
                raise SeedError("project image source contains an unsafe pin")
            references.add(reference)
        references_by_path[source_path] = references
    production = set().union(
        *(references_by_path[path] for path in production_paths)
    )
    preprod = production | set().union(
        *(references_by_path[path] for path in preprod_only_paths)
    )
    if not production or not preprod:
        raise SeedError("project image sources contain no digest-pinned external images")
    return {
        RELEASE_SCOPE_PRODUCTION: production,
        RELEASE_SCOPE_PREPROD: preprod,
    }


def collect_current_image_references(project_root: Path) -> set[str]:
    """Return the full preprod union for legacy source-parity callers."""

    return collect_current_image_reference_scopes(project_root)[
        RELEASE_SCOPE_PREPROD
    ]


def validate_build_plan(raw: object) -> dict[str, object]:
    if not isinstance(raw, dict) or set(raw) != {"manifest", "services"}:
        raise SeedError("custom-image build plan root is invalid")
    manifest = raw.get("manifest")
    planned_services = raw.get("services")
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"schema", "services"}
        or manifest.get("schema") != 1
        or not isinstance(manifest.get("services"), dict)
        or not manifest["services"]
        or len(manifest["services"]) > MAX_BUILD_SERVICES
    ):
        raise SeedError("custom-image build plan manifest is invalid")
    if (
        not isinstance(planned_services, list)
        or len(planned_services) > MAX_BUILD_SERVICES
        or planned_services != sorted(planned_services)
        or len(set(planned_services)) != len(planned_services)
    ):
        raise SeedError("custom-image planned services must be unique and sorted")

    normalized_services: dict[str, dict[str, str | None]] = {}
    for service, raw_record in sorted(manifest["services"].items()):
        if (
            not isinstance(service, str)
            or SERVICE.fullmatch(service) is None
            or not isinstance(raw_record, dict)
            or set(raw_record) != {"digest", "image", "image_id"}
        ):
            raise SeedError("custom-image build plan contains an invalid service record")
        digest = raw_record.get("digest")
        image = raw_record.get("image")
        image_id = raw_record.get("image_id")
        if (
            not isinstance(digest, str)
            or DIGEST.fullmatch(digest) is None
            or not isinstance(image, str)
            or MUTABLE_IMAGE.fullmatch(image) is None
            or image.startswith("-")
            or "@" in image
            or (
                image_id is not None
                and (not isinstance(image_id, str) or IMAGE_ID.fullmatch(image_id) is None)
            )
        ):
            raise SeedError(f"custom-image build plan is unsafe for service={service}")
        normalized_services[service] = {
            "digest": digest,
            "image": image,
            "image_id": image_id,
        }

    if any(
        not isinstance(service, str)
        or SERVICE.fullmatch(service) is None
        or service not in normalized_services
        for service in planned_services
    ):
        raise SeedError("custom-image build plan names an unknown service")
    return {
        "manifest": {"schema": 1, "services": normalized_services},
        "services": planned_services,
    }


def _current_seed_document(
    archive: Path,
    manifest_path: Path,
    manifest_digest: str,
    project_root: Path,
) -> tuple[str, dict[str, object]]:
    if not archive.is_absolute() or not str(archive).endswith(".docker.tar.zst"):
        raise SeedError("archive path must be an absolute .docker.tar.zst path")
    if not manifest_path.is_absolute() or not str(manifest_path).endswith(
        ".manifest.json"
    ):
        raise SeedError("manifest path must be an absolute .manifest.json path")
    if DIGEST.fullmatch(manifest_digest) is None:
        raise SeedError("manifest SHA-256 must be 64 lowercase hexadecimal characters")

    docker = require_executable("docker")
    platform = require_docker_ready(docker)
    manifest = validate_manifest_file(manifest_path, manifest_digest)
    document = validate_manifest_document(manifest, archive, platform)
    if document["schema_version"] == 2 and (
        document["release_scope"] != RELEASE_SCOPE_PRODUCTION
    ):
        raise SeedError("production deployment requires a production-scoped image release")

    external_images = document["external_images"]
    assert isinstance(external_images, list)
    source_scope = (
        document["release_scope"]
        if document["schema_version"] == 2
        else RELEASE_SCOPE_PREPROD
    )
    assert isinstance(source_scope, str)
    source_references = collect_current_image_reference_scopes(project_root)[
        source_scope
    ]
    manifest_references = {image["reference"] for image in external_images}
    if manifest_references != source_references:
        raise SeedError("image seed manifest does not exactly match current source pins")

    invalid_images = invalid_document_images(docker, document)
    if invalid_images:
        preview = ", ".join(invalid_images[:5])
        suffix = " ..." if len(invalid_images) > 5 else ""
        raise SeedError(
            "a current seeded image is absent or mismatched: "
            f"{preview}{suffix}"
        )
    return docker, document


def verify_current(
    archive: Path,
    manifest_path: Path,
    manifest_digest: str,
    project_root: Path,
) -> str:
    """Prove seed/source parity and exact local image presence before builds."""

    _current_seed_document(
        archive, manifest_path, manifest_digest, project_root
    )
    return f"VERIFIED {manifest_digest}"


def loaded_egress_policy_receipt(
    archive: Path,
    manifest_path: Path,
    manifest_digest: str,
) -> dict[str, object]:
    """Return the loaded schema-v2 policy without trusting project sources."""

    if not archive.is_absolute() or not str(archive).endswith(".docker.tar.zst"):
        raise SeedError("archive path must be an absolute .docker.tar.zst path")
    if not manifest_path.is_absolute() or not str(manifest_path).endswith(
        ".manifest.json"
    ):
        raise SeedError("manifest path must be an absolute .manifest.json path")
    if DIGEST.fullmatch(manifest_digest) is None:
        raise SeedError("manifest SHA-256 must be 64 lowercase hexadecimal characters")

    validate_regular_file(archive, "image seed")
    docker = require_executable("docker")
    platform = require_docker_ready(docker)
    manifest = validate_manifest_file(manifest_path, manifest_digest)
    document = validate_manifest_document(manifest, archive, platform)
    if document["schema_version"] != 2:
        raise SeedError("loaded egress policy receipt requires a schema-v2 release")
    zstd = require_executable("zstd")
    validate_archive_document_allowlist(archive, zstd, document)
    invalid_images = invalid_document_images(docker, document)
    if invalid_images:
        preview = ", ".join(invalid_images[:5])
        suffix = " ..." if len(invalid_images) > 5 else ""
        raise SeedError(
            "loaded release images or Envoy policy labels are mismatched: "
            f"{preview}{suffix}"
        )
    egress_policy = document["egress_policy"]
    assert isinstance(egress_policy, dict)
    return egress_policy


def release_receipt(
    archive: Path,
    manifest_path: Path,
    manifest_digest: str,
    project_root: Path,
) -> dict[str, object]:
    """Return exact loaded IDs only when source and build inputs still match."""

    docker, document = _current_seed_document(
        archive, manifest_path, manifest_digest, project_root
    )
    if document["schema_version"] == 2:
        builder = _load_local_builder(project_root, privileged=True)
        client = builder.DockerClient(
            docker,
            ("--host", LOCAL_DOCKER_HOST),
            dict(FIXED_DOCKER_ENV),
        )
        _verify_release_build_inputs(
            builder,
            client,
            document,
            project_root,
            privileged=True,
        )
    return format_release_receipt(
        archive, manifest_path, manifest_digest, document
    )


def format_release_receipt(
    archive: Path,
    manifest_path: Path,
    manifest_digest: str,
    document: dict[str, object],
) -> dict[str, object]:
    external_images = document["external_images"]
    custom_images = document["custom_images"]
    assert isinstance(external_images, list)
    assert isinstance(custom_images, list)

    external_receipt = {
        image["reference"]: image["image_id"] for image in external_images
    }
    custom_receipt = {
        image["image"]: {
            "image_id": image["image_id"],
            "archive_reference": image["archive_reference"],
            "deployment_scope": image["deployment_scope"],
            "target_activation": image["target_activation"],
        }
        for image in custom_images
    }
    receipt = {
        "schema_version": document["schema_version"],
        "release_scope": document["release_scope"],
        "platform": document["platform"],
        "archive": str(archive),
        "manifest": str(manifest_path),
        "manifest_sha256": manifest_digest,
        "external_images": dict(sorted(external_receipt.items())),
        "custom_images": dict(sorted(custom_receipt.items())),
    }
    if document["schema_version"] == 2:
        receipt["egress_policy"] = document["egress_policy"]
    return receipt


def _validate_local_release_file(
    path: Path, label: str, suffix: str, maximum_size: int | None = None
) -> os.stat_result:
    if not path.is_absolute() or not str(path).endswith(suffix):
        raise SeedError(f"local {label} path must be absolute and end in {suffix}")
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise SeedError(f"local {label} is missing: {path}") from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise SeedError(f"local {label} must be a regular file, not a symlink")
    if (metadata.st_uid, metadata.st_gid) != (os.geteuid(), os.getegid()):
        raise SeedError(f"local {label} must be owned by the invoking user and group")
    if _mode(metadata) != SEED_MODE:
        raise SeedError(f"local {label} mode must be 0600")
    if metadata.st_size < 1:
        raise SeedError(f"local {label} must not be empty")
    if maximum_size is not None and metadata.st_size > maximum_size:
        raise SeedError(f"local {label} exceeds its safety bound")
    return metadata


def _privileged_builder_path(project_root: Path) -> Path:
    """Return the builder only when root can trust its complete project path."""

    if not project_root.is_absolute():
        raise SeedError("release project root must be canonical and absolute")
    try:
        canonical_root = project_root.resolve(strict=True)
    except OSError as exc:
        raise SeedError("release project root is missing or cannot be resolved") from exc
    if project_root != canonical_root:
        raise SeedError("release project root must be canonical and contain no symlinks")

    validate_trusted_directory_lineage(canonical_root.parent, "release project root")
    scripts_directory = canonical_root / "scripts"
    for directory in (canonical_root, scripts_directory):
        try:
            metadata = directory.lstat()
        except OSError as exc:
            raise SeedError("release builder ancestor is missing") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise SeedError("release builder ancestors must be real directories")
        if metadata.st_uid != ROOT_UID:
            raise SeedError("release builder ancestors must be root-owned")
        if _mode(metadata) & 0o022:
            raise SeedError(
                "release builder ancestors must not be group- or world-writable"
            )

    path = scripts_directory / "rebuild-offline-image-seed.py"
    try:
        resolved_path = path.resolve(strict=True)
        resolved_path.relative_to(canonical_root)
        metadata = path.lstat()
    except (OSError, ValueError) as exc:
        raise SeedError("release builder must stay inside the canonical project root") from exc
    if resolved_path != path:
        raise SeedError("release builder must be canonical and contain no symlinks")
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise SeedError("release builder must be a regular non-symlink file")
    if (metadata.st_uid, metadata.st_gid) != (ROOT_UID, ROOT_GID):
        raise SeedError("release builder must be owned by root:root")
    if _mode(metadata) & 0o022:
        raise SeedError("release builder must not be group- or world-writable")
    return path


def _load_local_builder(
    project_root: Path | None = None, *, privileged: bool = False
):
    if project_root is None:
        path = Path(__file__).resolve().with_name("rebuild-offline-image-seed.py")
    elif privileged:
        path = _privileged_builder_path(project_root)
    else:
        path = project_root / "scripts/rebuild-offline-image-seed.py"
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise SeedError("the selected source lacks the reviewed release builder") from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise SeedError("the reviewed release builder must be a regular non-symlink file")
    spec = importlib.util.spec_from_file_location("_aigw_local_seed_builder", path)
    if spec is None or spec.loader is None:
        raise SeedError("cannot load the reviewed local release builder")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _inspect_local_release_image(
    client, reference: str, expected_platform: str | None = None
) -> dict[str, object]:
    arguments = ["image", "inspect"]
    if expected_platform is not None:
        arguments.extend(("--platform", expected_platform))
    arguments.extend(("--", reference))
    result = client.run(*arguments)
    if result.returncode != 0:
        raise SeedError(f"local release image is missing: {reference}")
    try:
        decoded = json.loads(result.stdout)
        record = decoded[0]
    except (IndexError, TypeError, json.JSONDecodeError) as exc:
        raise SeedError(f"Docker returned invalid local image data: {reference}") from exc
    if not isinstance(record, dict):
        raise SeedError(f"Docker returned invalid local image data: {reference}")
    return record


def _local_release_image_has_platform(
    client,
    reference: str,
    record: dict[str, object],
    expected_platform: str,
) -> bool:
    """Apply the same OCI-index platform proof through a selected client."""

    if _image_platform_matches(record, expected_platform):
        return True
    descriptor = record.get("Descriptor")
    if (
        not isinstance(descriptor, dict)
        or descriptor.get("mediaType") not in MULTI_PLATFORM_IMAGE_MEDIA_TYPES
        or descriptor.get("digest") != record.get("Id")
    ):
        return False
    try:
        platform_record = _inspect_local_release_image(
            client, reference, expected_platform
        )
    except SeedError:
        return False
    return _resolved_platform_record_matches(platform_record, expected_platform)


def _verify_release_build_inputs(
    builder,
    client,
    document: dict[str, object],
    project_root: Path,
    *,
    privileged: bool,
) -> None:
    """Recompute every custom build digest from the selected source tree."""

    custom_images = document["custom_images"]
    platform = document["platform"]
    assert isinstance(custom_images, list)
    assert isinstance(platform, str)
    expected_ids = {image["image"]: image["image_id"] for image in custom_images}

    def expected_image_id(image: str) -> str:
        image_id = expected_ids.get(image)
        if not isinstance(image_id, str) or IMAGE_ID.fullmatch(image_id) is None:
            raise SeedError(f"release omits a custom build image: {image}")
        return image_id

    try:
        egress_plan = builder.egress_plan_from_release_receipt(
            document["egress_policy"]
        )
        model, _, _ = builder.render_deployable_compose_model(
            client, project_root, platform, egress_plan
        )
        if document["release_scope"] == RELEASE_SCOPE_PREPROD:
            builder.add_preprod_build_services(model, project_root)
        planner = builder._load_build_planner(
            project_root,
            privileged=privileged,
        )
    except (OSError, builder.SeedBuildError) as exc:
        raise SeedError(f"cannot verify release build inputs: {exc}") from exc
    try:
        with tempfile.TemporaryDirectory(prefix="aigw-release-plan-") as temporary:
            plan = planner.plan_compose_builds(
                model,
                stack=project_root,
                state_path=Path(temporary) / "absent.json",
                project=builder.COMPOSE_PROJECT_NAME,
                image_inspector=expected_image_id,
            )
    except SeedError:
        raise
    except (OSError, builder.SeedBuildError, planner.PlanError) as exc:
        raise SeedError(f"cannot verify release build inputs: {exc}") from exc
    if plan.get("manifest") != document["build_inputs"]:
        raise SeedError("release build inputs do not match the current source tree")


def local_release_receipt(
    archive: Path,
    manifest_path: Path,
    manifest_digest: str,
    project_root: Path,
) -> dict[str, object]:
    """Verify a just-built release against local Docker Desktop or Engine."""

    _validate_local_release_file(archive, "release archive", ".docker.tar.zst")
    _validate_local_release_file(
        manifest_path,
        "release manifest",
        ".manifest.json",
        MAX_ARCHIVE_METADATA_BYTES,
    )
    if archive.parent.resolve() != manifest_path.parent.resolve():
        raise SeedError("local release archive and manifest must share one directory")
    if DIGEST.fullmatch(manifest_digest) is None:
        raise SeedError("manifest SHA-256 must be 64 lowercase hexadecimal characters")
    if sha256_file(manifest_path, "local release manifest") != manifest_digest:
        raise SeedError("local release manifest SHA-256 does not match")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SeedError("cannot decode local release manifest") from exc
    if not isinstance(manifest, dict):
        raise SeedError("local release manifest root must be an object")

    builder = _load_local_builder(project_root)
    policy = builder.OutputPolicy(os.geteuid(), os.getegid(), False)
    docker_host = os.environ.get("DOCKER_HOST")
    docker_context = None if docker_host is not None else os.environ.get("DOCKER_CONTEXT")
    config = builder._initial_docker_config(None, policy)
    client = builder.resolve_docker_client(
        policy=policy,
        docker_path=None,
        docker_config=config,
        docker_context=docker_context,
        docker_host=docker_host,
    )
    platform = builder.platform(client)
    document = validate_manifest_document(manifest, archive, platform)
    if document["schema_version"] != 2:
        raise SeedError("local preproduction requires a schema-v2 image release")
    if document["release_scope"] != RELEASE_SCOPE_PREPROD:
        raise SeedError("local preproduction requires a preprod-scoped image release")

    external_images = document["external_images"]
    custom_images = document["custom_images"]
    assert isinstance(external_images, list)
    assert isinstance(custom_images, list)
    source_references = builder.collect_project_image_reference_scopes(project_root)[
        RELEASE_SCOPE_PREPROD
    ]
    if {image["reference"] for image in external_images} != source_references:
        raise SeedError("local release manifest does not exactly match current source pins")

    for image in external_images:
        record = _inspect_local_release_image(client, image["reference"])
        repo_digests = record.get("RepoDigests") or []
        pinned_digest = image["reference"].rsplit("@sha256:", 1)[1]
        if (
            record.get("Id") != image["image_id"]
            or not isinstance(repo_digests, list)
            or not any(
                isinstance(value, str)
                and value.endswith(f"@sha256:{pinned_digest}")
                for value in repo_digests
            )
            or not _local_release_image_has_platform(
                client, image["reference"], record, platform
            )
        ):
            raise SeedError(f"local external image does not match release: {image['reference']}")
    for image in custom_images:
        record = _inspect_local_release_image(client, image["archive_reference"])
        if record.get("Id") != image["image_id"] or not (
            _local_release_image_has_platform(
                client, image["archive_reference"], record, platform
            )
        ):
            raise SeedError(f"local custom image does not match release: {image['image']}")
        if _image_repository(image["image"]) == EGRESS_IMAGE_REPOSITORY:
            egress_policy = document["egress_policy"]
            assert isinstance(egress_policy, dict)
            if not _egress_policy_labels_match(record, egress_policy):
                raise SeedError("local Envoy image labels do not match its egress policy")

    _verify_release_build_inputs(
        builder,
        client,
        document,
        project_root,
        privileged=False,
    )

    zstd = builder._find_executable("zstd", policy)
    validate_archive_document_allowlist(archive, zstd, document)
    return format_release_receipt(
        archive, manifest_path, manifest_digest, document
    )


def reconcile_build_plan(
    archive: Path,
    manifest_path: Path,
    manifest_digest: str,
    project_root: Path,
    raw_plan: object,
) -> dict[str, object]:
    """Match the target build plan to the release's reviewed build inputs."""

    plan = validate_build_plan(raw_plan)
    _, document = _current_seed_document(
        archive, manifest_path, manifest_digest, project_root
    )
    schema_version = document["schema_version"]
    if schema_version == 1:
        return {"schema_version": 1, "plan": plan}

    seed_build_inputs = document["build_inputs"]
    assert isinstance(seed_build_inputs, dict)
    seed_services = seed_build_inputs["services"]
    assert isinstance(seed_services, dict)
    current_manifest = plan["manifest"]
    assert isinstance(current_manifest, dict)
    current_services = current_manifest["services"]
    assert isinstance(current_services, dict)

    services_to_activate: list[str] = []
    for service, current_record in current_services.items():
        seed_record = seed_services.get(service)
        if not isinstance(seed_record, dict):
            raise SeedError(
                f"offline release has no build-input record for active service={service}"
            )
        assert isinstance(current_record, dict)
        if (
            current_record["digest"] != seed_record["digest"]
            or current_record["image"] != seed_record["image"]
        ):
            raise SeedError(
                f"offline release build inputs do not match active service={service}"
            )
        if current_record["image_id"] != seed_record["image_id"]:
            services_to_activate.append(service)

    return {
        "schema_version": 2,
        "plan": {
            "manifest": current_manifest,
            "services": sorted(services_to_activate),
        },
    }


def _inspect_local_image_id(
    docker: str, reference: str, *, allow_missing: bool
) -> str | None:
    result = subprocess.run(
        [docker, "--host", LOCAL_DOCKER_HOST, "image", "inspect", "--", reference],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=FIXED_DOCKER_ENV,
    )
    if result.returncode != 0:
        diagnostic = result.stderr.decode("utf-8", errors="replace").lower()
        if allow_missing and any(
            marker in diagnostic
            for marker in ("no such image", "no such object", "not found")
        ):
            return None
        raise SeedError(f"Docker cannot inspect image {reference}")
    try:
        decoded = json.loads(result.stdout)
        image_id = decoded[0]["Id"]
    except (IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise SeedError(f"Docker returned invalid image data for {reference}") from exc
    if not isinstance(image_id, str) or IMAGE_ID.fullmatch(image_id) is None:
        raise SeedError(f"Docker returned an invalid image ID for {reference}")
    return image_id


def _tag_local_image(docker: str, source: str, target: str) -> None:
    result = subprocess.run(
        [docker, "--host", LOCAL_DOCKER_HOST, "image", "tag", source, target],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        env=FIXED_DOCKER_ENV,
    )
    if result.returncode != 0:
        raise SeedError(f"Docker cannot activate tested custom image {target}")


def _remove_local_tag(docker: str, target: str) -> bool:
    result = subprocess.run(
        [docker, "--host", LOCAL_DOCKER_HOST, "image", "rm", "--", target],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        env=FIXED_DOCKER_ENV,
    )
    return result.returncode == 0


def activate_custom_images(
    archive: Path,
    manifest_path: Path,
    manifest_digest: str,
    project_root: Path,
    raw_plan: object,
) -> dict[str, object]:
    """Move reviewed custom images to Compose tags after rollback preservation."""

    reconciled = reconcile_build_plan(
        archive, manifest_path, manifest_digest, project_root, raw_plan
    )
    if reconciled["schema_version"] == 1:
        return reconciled

    docker, document = _current_seed_document(
        archive, manifest_path, manifest_digest, project_root
    )
    seed_build_inputs = document["build_inputs"]
    custom_images = document["custom_images"]
    assert isinstance(seed_build_inputs, dict)
    assert isinstance(seed_build_inputs["services"], dict)
    assert isinstance(custom_images, list)
    custom_by_image = {image["image"]: image for image in custom_images}

    plan = reconciled["plan"]
    assert isinstance(plan, dict)
    current_manifest = plan["manifest"]
    assert isinstance(current_manifest, dict)
    current_services = current_manifest["services"]
    assert isinstance(current_services, dict)

    active_seed_services: dict[str, dict[str, str]] = {}
    images_to_activate: dict[str, dict[str, str]] = {}
    for service in sorted(current_services):
        seed_record = seed_build_inputs["services"][service]
        assert isinstance(seed_record, dict)
        image = seed_record["image"]
        assert isinstance(image, str)
        custom = custom_by_image.get(image)
        if custom is None:
            raise SeedError(f"offline release has no custom image for service={service}")
        if custom["target_activation"] != "active-compose":
            raise SeedError(
                f"archive-only custom image cannot activate service={service}"
            )
        active_seed_services[service] = dict(seed_record)
        images_to_activate[image] = custom

    changed: list[tuple[str, str | None]] = []
    try:
        for image, custom in sorted(images_to_activate.items()):
            expected_id = custom["image_id"]
            archive_reference = custom["archive_reference"]
            current_id = _inspect_local_image_id(docker, image, allow_missing=True)
            if current_id == expected_id:
                continue
            _tag_local_image(docker, archive_reference, image)
            changed.append((image, current_id))
            if _inspect_local_image_id(docker, image, allow_missing=False) != expected_id:
                raise SeedError(f"custom image activation verification failed: {image}")
    except SeedError as exc:
        rollback_failed = False
        for image, previous_id in reversed(changed):
            if previous_id is None:
                if not _remove_local_tag(docker, image) or _inspect_local_image_id(
                    docker, image, allow_missing=True
                ) is not None:
                    rollback_failed = True
                continue
            try:
                _tag_local_image(docker, previous_id, image)
                if (
                    _inspect_local_image_id(docker, image, allow_missing=False)
                    != previous_id
                ):
                    rollback_failed = True
            except SeedError:
                rollback_failed = True
        if rollback_failed:
            raise SeedError(f"{exc}; custom image tag rollback also failed") from exc
        raise

    return {
        "schema_version": 2,
        "plan": {
            "manifest": {"schema": 1, "services": active_seed_services},
            "services": [],
        },
    }


def load_archive(archive: Path, zstd: str, docker: str) -> None:
    integrity = subprocess.run(
        [zstd, "--quiet", "--test", "--", str(archive)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        check=False,
        env=FIXED_DOCKER_ENV,
    )
    if integrity.returncode != 0:
        detail = integrity.stderr.decode("utf-8", errors="replace")[-4096:].strip()
        raise SeedError(f"zstd integrity test failed: {detail or 'no diagnostic'}")

    decompressor = subprocess.Popen(
        [zstd, "--decompress", "--stdout", "--quiet", "--", str(archive)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=FIXED_DOCKER_ENV,
    )
    if decompressor.stdout is None or decompressor.stderr is None:
        decompressor.kill()
        raise SeedError("cannot establish the zstd output pipe")

    try:
        loader = subprocess.Popen(
            [docker, "--host", LOCAL_DOCKER_HOST, "image", "load"],
            stdin=decompressor.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=FIXED_DOCKER_ENV,
        )
    except OSError:
        decompressor.kill()
        decompressor.wait()
        raise
    finally:
        decompressor.stdout.close()

    loader_stdout, loader_stderr = loader.communicate()
    decompressor_stderr = decompressor.stderr.read()
    decompressor_returncode = decompressor.wait()

    if decompressor_returncode != 0 or loader.returncode != 0:
        details = b"\n".join((decompressor_stderr, loader_stdout, loader_stderr))
        detail = details.decode("utf-8", errors="replace")[-4096:].strip()
        raise SeedError(
            "offline image seed load failed before its checksum marker was written: "
            f"{detail or 'no diagnostic'}"
        )


def write_marker(marker: Path, archive_digest: str, manifest_digest: str) -> None:
    descriptor = -1
    temporary_name = ""
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{archive_digest}.", suffix=".tmp", dir=marker.parent
        )
        os.fchmod(descriptor, MARKER_MODE)
        os.fchown(descriptor, ROOT_UID, ROOT_GID)
        with os.fdopen(descriptor, "w", encoding="ascii", closefd=True) as destination:
            descriptor = -1
            destination.write(f"{archive_digest} {manifest_digest}\n")
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary_name, marker)
        temporary_name = ""
        os.chown(marker, ROOT_UID, ROOT_GID)
        os.chmod(marker, MARKER_MODE)
        directory_descriptor = os.open(marker.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as exc:
        raise SeedError(f"cannot persist checksum marker: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_name:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def run(
    archive: Path,
    archive_digest: str,
    manifest_path: Path,
    manifest_digest: str,
    marker_dir: Path,
    *,
    required_release_scope: str | None = None,
) -> str:
    validate_arguments(
        archive, archive_digest, manifest_path, manifest_digest, marker_dir
    )
    docker = require_executable("docker")
    platform = require_docker_ready(docker)
    validate_marker_dir(marker_dir)
    manifest = validate_manifest_file(manifest_path, manifest_digest)
    document = validate_manifest_document(manifest, archive, platform)
    if (
        required_release_scope is not None
        and document.get("release_scope") != required_release_scope
    ):
        raise SeedError(
            f"image seed release scope must be {required_release_scope!r} for this workflow"
        )
    external_images = document["external_images"]
    assert isinstance(external_images, list)
    # Validate the reviewed archive's image allow-list even when a valid
    # marker means no load is needed.  Reset preflight relies on this proof
    # before destructive Docker-root cleanup.
    validate_archive(archive, archive_digest)
    zstd = require_executable("zstd")
    if document["schema_version"] == 1:
        validate_archive_image_allowlist(archive, zstd, external_images)
    else:
        validate_archive_document_allowlist(archive, zstd, document)

    marker = marker_path(marker_dir, archive_digest, manifest_digest)
    existing_marker = marker_is_valid(marker, archive_digest, manifest_digest)
    if document["schema_version"] == 1:
        invalid_images = invalid_required_images(docker, external_images)
    else:
        invalid_images = invalid_document_images(docker, document)
    if existing_marker and not invalid_images:
        return f"SKIPPED {archive_digest}"
    if required_release_scope is not None:
        conflicts = existing_seed_tag_conflicts(docker, document)
        if conflicts:
            preview = ", ".join(conflicts[:5])
            suffix = " ..." if len(conflicts) > 5 else ""
            raise SeedError(
                "local preprod seed load would overwrite existing Docker image tags: "
                f"{preview}{suffix}"
            )
    if existing_marker:
        try:
            marker.unlink()
        except OSError as exc:
            raise SeedError(f"cannot invalidate stale checksum marker: {exc}") from exc

    load_archive(archive, zstd, docker)
    if document["schema_version"] == 1:
        invalid_images = invalid_required_images(docker, external_images)
    else:
        invalid_images = invalid_document_images(docker, document)
    if invalid_images:
        preview = ", ".join(invalid_images[:5])
        suffix = " ..." if len(invalid_images) > 5 else ""
        raise SeedError(
            "required seeded images are missing or mismatched after load: "
            f"{preview}{suffix}"
        )
    write_marker(marker, archive_digest, manifest_digest)
    if not marker_is_valid(marker, archive_digest, manifest_digest):
        raise SeedError("checksum marker postcondition failed")
    outcome = "RELOADED" if existing_marker else "LOADED"
    return f"{outcome} {archive_digest}"


def read_build_plan() -> dict[str, object]:
    encoded = sys.stdin.buffer.read(MAX_PLAN_BYTES + 1)
    if len(encoded) > MAX_PLAN_BYTES:
        raise SeedError("custom-image build plan exceeds the 4 MiB safety bound")
    try:
        decoded = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SeedError("custom-image build plan is not valid JSON") from exc
    if not isinstance(decoded, dict):
        raise SeedError("custom-image build plan root must be an object")
    return decoded


def main(argv: list[str]) -> int:
    if len(argv) == 6 and argv[1] == "validate-production-release":
        try:
            configure_local_release_reader()
            outcome = validate_production_release(
                Path(argv[2]), argv[3], Path(argv[4]), argv[5]
            )
        except (OSError, SeedError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        print(outcome)
        return 0

    if len(argv) == 7 and argv[1] == "root-preprod-load":
        if os.geteuid() != ROOT_UID:
            print("ERROR: offline image seed loader must run as root", file=sys.stderr)
            return 1
        os.environ.clear()
        os.environ["PATH"] = FIXED_PATH
        try:
            outcome = run(
                Path(argv[2]),
                argv[3],
                Path(argv[4]),
                argv[5],
                Path(argv[6]),
                required_release_scope=RELEASE_SCOPE_PREPROD,
            )
        except (OSError, SeedError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        print(outcome)
        return 0

    if len(argv) == 8 and argv[1] == "local-preprod-load":
        if os.geteuid() == ROOT_UID:
            print(
                "ERROR: local preprod image loading must run as the desktop Docker user",
                file=sys.stderr,
            )
            return 1
        try:
            configure_local_controller_docker(argv[7])
            outcome = run(
                Path(argv[2]),
                argv[3],
                Path(argv[4]),
                argv[5],
                Path(argv[6]),
                required_release_scope=RELEASE_SCOPE_PREPROD,
            )
        except (OSError, SeedError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        print(outcome)
        return 0

    if len(argv) == 6 and argv[1] == "local-release-receipt":
        if os.geteuid() == ROOT_UID:
            print(
                "ERROR: local release receipt must run as the desktop Docker user",
                file=sys.stderr,
            )
            return 1
        try:
            outcome = local_release_receipt(
                Path(argv[2]), Path(argv[3]), argv[4], Path(argv[5])
            )
        except (OSError, SeedError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(outcome, sort_keys=True, separators=(",", ":")))
        return 0

    if len(argv) == 5 and argv[1] == "loaded-egress-policy-receipt":
        if os.geteuid() != ROOT_UID:
            print("ERROR: offline image seed loader must run as root", file=sys.stderr)
            return 1
        os.environ.clear()
        os.environ["PATH"] = FIXED_PATH
        try:
            outcome = loaded_egress_policy_receipt(
                Path(argv[2]), Path(argv[3]), argv[4]
            )
        except (OSError, SeedError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(outcome, sort_keys=True, separators=(",", ":")))
        return 0

    current_commands = {
        "verify-current",
        "release-receipt",
        "reconcile-build-plan",
        "activate-custom-images",
    }
    if len(argv) == 6 and argv[1] in current_commands:
        if os.geteuid() != ROOT_UID:
            print("ERROR: offline image seed loader must run as root", file=sys.stderr)
            return 1
        os.environ.clear()
        os.environ["PATH"] = FIXED_PATH
        try:
            if argv[1] == "verify-current":
                outcome: object = verify_current(
                    Path(argv[2]), Path(argv[3]), argv[4], Path(argv[5])
                )
            elif argv[1] == "release-receipt":
                outcome = release_receipt(
                    Path(argv[2]), Path(argv[3]), argv[4], Path(argv[5])
                )
            else:
                plan = read_build_plan()
                if argv[1] == "reconcile-build-plan":
                    outcome = reconcile_build_plan(
                        Path(argv[2]), Path(argv[3]), argv[4], Path(argv[5]), plan
                    )
                else:
                    outcome = activate_custom_images(
                        Path(argv[2]), Path(argv[3]), argv[4], Path(argv[5]), plan
                    )
        except (OSError, SeedError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        if isinstance(outcome, str):
            print(outcome)
        else:
            print(json.dumps(outcome, sort_keys=True, separators=(",", ":")))
        return 0
    if len(argv) != 6:
        print(
            "usage: load-offline-image-seed.py ARCHIVE.docker.tar.zst "
            "ARCHIVE_SHA256 MANIFEST.manifest.json MANIFEST_SHA256 "
            "MARKER_DIRECTORY\n"
            "   or: load-offline-image-seed.py validate-production-release "
            "ARCHIVE.docker.tar.zst ARCHIVE_SHA256 MANIFEST.manifest.json "
            "MANIFEST_SHA256\n"
            "   or: load-offline-image-seed.py root-preprod-load "
            "ARCHIVE.docker.tar.zst ARCHIVE_SHA256 MANIFEST.manifest.json "
            "MANIFEST_SHA256 MARKER_DIRECTORY\n"
            "   or: load-offline-image-seed.py local-preprod-load "
            "ARCHIVE.docker.tar.zst ARCHIVE_SHA256 MANIFEST.manifest.json "
            "MANIFEST_SHA256 MARKER_DIRECTORY unix:///LOCAL/DOCKER.sock\n"
            "   or: load-offline-image-seed.py verify-current "
            "ARCHIVE.docker.tar.zst MANIFEST.manifest.json "
            "MANIFEST_SHA256 PROJECT_ROOT\n"
            "   or: load-offline-image-seed.py release-receipt "
            "ARCHIVE.docker.tar.zst MANIFEST.manifest.json "
            "MANIFEST_SHA256 PROJECT_ROOT\n"
            "   or: load-offline-image-seed.py local-release-receipt "
            "ARCHIVE.docker.tar.zst MANIFEST.manifest.json "
            "MANIFEST_SHA256 PROJECT_ROOT\n"
            "   or: load-offline-image-seed.py loaded-egress-policy-receipt "
            "ARCHIVE.docker.tar.zst MANIFEST.manifest.json MANIFEST_SHA256\n"
            "   or: load-offline-image-seed.py "
            "{reconcile-build-plan|activate-custom-images} "
            "ARCHIVE.docker.tar.zst MANIFEST.manifest.json "
            "MANIFEST_SHA256 PROJECT_ROOT < BUILD_PLAN.json",
            file=sys.stderr,
        )
        return 2
    if os.geteuid() != ROOT_UID:
        print("ERROR: offline image seed loader must run as root", file=sys.stderr)
        return 1

    os.environ.clear()
    os.environ["PATH"] = FIXED_PATH
    try:
        outcome = run(
            Path(argv[1]),
            argv[2],
            Path(argv[3]),
            argv[4],
            Path(argv[5]),
            required_release_scope=RELEASE_SCOPE_PRODUCTION,
        )
    except (OSError, SeedError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(outcome)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
