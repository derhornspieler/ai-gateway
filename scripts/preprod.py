#!/usr/bin/env python3
"""Operate the local Docker preprod stack through small, explicit commands."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any
from urllib.parse import quote


REPO_ROOT = Path(__file__).resolve().parents[1]
COMPOSE_DIR = REPO_ROOT / "compose"
SECRETS_DIR = COMPOSE_DIR / "secrets"
ENV_FILE = SECRETS_DIR / "preprod.env"
REALMS_DIR = SECRETS_DIR / "preprod-realms"
EDGE_CERTS_DIR = SECRETS_DIR / "preprod-edge-certs"
VAULT_INIT_FILE = SECRETS_DIR / "preprod-vault-init.json"
SEED_RECEIPT = SECRETS_DIR / "preprod-seed-receipt.json"
SEED_OVERLAY = SECRETS_DIR / "preprod-seed-images.yml"
PREPROD_ROOT_CA_FILE = SECRETS_DIR / "preprod-root-ca.pem"

ROOT_UID = 0
ROOT_GID = 0
DARWIN_IFCONFIG = Path("/sbin/ifconfig")
DARWIN_SYSCTL = Path("/usr/sbin/sysctl")
DARWIN_LOOPBACK_INTERFACE = "lo0"
PREPROD_INTERNAL_CIDR = "127.0.2.0/24"
PREPROD_ADM_CIDR = "127.0.3.0/24"
PREPROD_LOOPBACK_ALIASES = ("127.0.2.1", "127.0.3.1")
# Release candidates built before the two host planes were corrected used
# these addresses. They are accepted only in our root-owned ownership record
# so one converge can remove aliases that this project created. We never claim
# or remove a legacy alias without that record.
LEGACY_PREPROD_LOOPBACK_ALIASES = ("127.0.0.2", "127.0.0.3")
MANAGED_PREPROD_LOOPBACK_ALIASES = (
    *PREPROD_LOOPBACK_ALIASES,
    *LEGACY_PREPROD_LOOPBACK_ALIASES,
)
DARWIN_LOOPBACK_NETMASK = "255.255.255.0"
LOOPBACK_STATE_DIR = Path("/private/var/db/aigw-preprod")
LOOPBACK_STATE_FILE = LOOPBACK_STATE_DIR / "loopback-aliases-v1.json"
LOOPBACK_STATE_MAX_BYTES = 4096

HOSTS_BEGIN = "# BEGIN AIGW PREPROD MANAGED"
HOSTS_END = "# END AIGW PREPROD MANAGED"
ALLOWED_DOMAIN = "aigw.internal"
ALLOWED_PROJECT = "aigw-preprod"
ALLOWED_PREFIX = "aigw-preprod"
ALLOWED_SUBNET_OCTET = 29
PRODUCTION_COMPOSE_PROJECT = "ai-gateway"
PRODUCTION_VENDOR_SUBNET = "172.28.7.0/24"
# Clean-room may remove the exact vendor network made by releases that used
# the separate preprod CIDR. Converge never creates or accepts this legacy
# subnet after the production-image firewall ABI became part of acceptance.
LEGACY_PREPROD_VENDOR_SUBNET = "172.29.7.0/24"
ENVOY_EGRESS_IMAGE = "ai-gateway/envoy-egress:1"
ROOT_SEED_DOCKER_SOCKET = Path("/run/docker.sock")
POSTGRES_RECONCILE_SCRIPT = "/docker-entrypoint-initdb.d/01-init-databases.sh"
POSTGRES_DIRECT_CONSUMERS = ("litellm", "keycloak", "key-rotator", "grafana")
POSTGRES_RECONCILE_RESULTS = frozenset(
    {"AIGW_POSTGRES_CHANGED", "AIGW_POSTGRES_OK"}
)
EDGE_RESPONSE_MAX_BYTES = 64 * 1024
PREPROD_USERNAMES = frozenset(
    {"preprod-admin", "preprod-developer", "preprod-user"}
)
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
CLEAN_ROOM_CONFIRMATION = "DESTROY_AIGW_PREPROD_RELEASE_IMAGES"
CLEAN_ROOM_PLAN_SCHEMA = 1
CLEAN_ROOM_RECEIPT_SCHEMA = 1
CLEAN_ROOM_MAX_GROUPS = 256
CLEAN_ROOM_MAX_RECORDS = 512
CLEAN_ROOM_MAX_ALIASES = CLEAN_ROOM_MAX_RECORDS * 3
CLEAN_ROOM_MAX_PLAN_BYTES = 512 * 1024
CLEAN_ROOM_MAX_DOCKER_OBJECTS = 4096
CUSTOM_TRANSFER_REFERENCE_RE = re.compile(
    r"^(?:[a-z0-9]+(?:[._-]+[a-z0-9]+)*/)*"
    r"[a-z0-9]+(?:[._-]+[a-z0-9]+)*:aigw-seed-[0-9a-f]{64}$"
)
EXTERNAL_IMAGE_REFERENCE_RE = re.compile(
    r"^(?!ai-gateway/)(?:[a-z0-9]+(?:[._-]+[a-z0-9]+)*/)*"
    r"[a-z0-9]+(?:[._-]+[a-z0-9]+)*:"
    r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}@sha256:[0-9a-f]{64}$"
)
CUSTOM_IMAGE_REFERENCE_RE = re.compile(
    r"^(?:[a-z0-9]+(?:[._-]+[a-z0-9]+)*/)*"
    r"[a-z0-9]+(?:[._-]+[a-z0-9]+)*"
    r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?$"
)
REPOSITORY_DIGEST_RE = re.compile(
    r"^(?:[a-z0-9]+(?:[._-]+[a-z0-9]+)*/)*"
    r"[a-z0-9]+(?:[._-]+[a-z0-9]+)*@sha256:[0-9a-f]{64}$"
)
CLEAN_ROOM_ALIAS_KINDS = frozenset(
    {
        "custom-archive-reference",
        "custom-image",
        "external-reference",
        "external-repository-digest",
        "external-tag",
    }
)
_LOCAL_DOCKER_CONTEXT = ""
_LOCAL_DOCKER_ENDPOINT = ""

NETWORKS = {
    "plane-egress": (0, False),
    "plane-adm": (1, False),
    "net-internal": (2, False),
    "net-chat": (3, True),
    "net-portal": (4, True),
    "net-admin-app": (5, True),
    "net-grafana": (6, True),
    "net-vendor": (7, True),
    "net-vault": (8, True),
    "net-db-litellm": (9, True),
    "net-db-keycloak": (10, True),
    "net-db-rotator": (11, True),
    "net-cache": (12, True),
    "net-telemetry": (13, True),
    "net-metrics": (14, True),
    "net-observability": (15, True),
    "net-identity": (17, True),
    "plane-internal": (19, False),
    "net-db-grafana": (20, True),
}

COMPOSE_FILES = (
    COMPOSE_DIR / "docker-compose.yml",
    COMPOSE_DIR / "docker-compose.preprod.yml",
)

# This is the complete bind-source inventory in the rendered preprod model.
# compose-config compares it with Docker Compose, so a new mount cannot escape
# review by accident. Most entries are immutable configuration and contribute
# to the container recreation digest. The WIF JWKS file is runtime state: the
# identity controller writes it only after Keycloak starts, so it is tracked
# here but deliberately excluded from the immutable configuration digest.
PREPROD_BIND_SOURCES = (
    "cribl-mock/config.yaml",
    "cribl-mock/config.preprod-tls.yaml",
    "grafana/provisioning",
    "litellm/aigw_default_model_hook.py",
    "loki/config.yml",
    "postgres/init",
    "prometheus/prometheus.yml",
    "prometheus/rules.yml",
    "secrets/preprod-edge-certs",
    "secrets/preprod-edge-forwarder.yaml",
    "secrets/preprod-alloy-config.alloy",
    "secrets/preprod-cribl.crt",
    "secrets/preprod-cribl.key",
    "secrets/preprod-litellm-config.yaml",
    "secrets/preprod-wif-envoy.yaml",
    "secrets/preprod-realms",
    "secrets/preprod-root-ca.pem",
    "secrets/preprod-samba-admin-password",
    "secrets/preprod-samba-bind-password",
    "secrets/preprod-samba.crt",
    "secrets/preprod-samba.key",
    "secrets/preprod-wif-jwks.json",
    "secrets/preprod-wif.crt",
    "secrets/preprod-wif.key",
    "secrets/redis_password",
    "secrets/redis_users.acl",
    "secrets/samba_user_preprod-admin_password",
    "secrets/samba_user_preprod-developer_password",
    "secrets/samba_user_preprod-user_password",
    "traefik/dynamic-adm.yml",
    "traefik/dynamic-int.yml",
    "traefik/traefik-adm.yml",
    "traefik/traefik-int.yml",
    "vault/config.hcl",
)

PREPROD_RUNTIME_BIND_SOURCES = frozenset(
    {"secrets/preprod-wif-jwks.json"}
)

ROTATOR_POLICY = """
path "kv/data/ai-gateway/anthropic-wif" { capabilities = ["create", "read", "update", "delete"] }
path "kv/metadata/ai-gateway/anthropic-wif" { capabilities = ["read", "delete"] }
path "kv/data/ai-gateway/vendors/anthropic" { capabilities = ["read"] }
path "kv/data/ai-gateway/anthropic-wif-client-key" { capabilities = ["create", "read", "update"] }
path "kv/data/ai-gateway/keycloak/identity-controller-key" { capabilities = ["create", "read", "update"] }
path "kv/data/ai-gateway/keycloak/identity-state" { capabilities = ["create", "read", "update"] }
path "kv/data/ai-gateway/keycloak/break-glass-admin" { capabilities = ["create", "read", "update"] }
path "kv/data/ai-gateway/keycloak/vault-oidc-rp" { capabilities = ["create", "read", "update"] }
""".strip()

VAULT_HTTP_HELPER = r"""
import http.client, json, sys
request = json.load(sys.stdin)
headers = {"Content-Type": "application/json"}
if request.get("token"):
    headers["X-Vault-Token"] = request["token"]
body = json.dumps(request.get("body")) if "body" in request else None
connection = http.client.HTTPConnection("vault", 8200, timeout=10)
connection.request(request["method"], request["path"], body=body, headers=headers)
response = connection.getresponse()
raw = response.read(1048577)
if len(raw) > 1048576:
    raise SystemExit("Vault response was too large")
try:
    value = json.loads(raw) if raw else {}
except Exception:
    value = {}
print(json.dumps({"status": response.status, "body": value}, separators=(",", ":")))
""".strip()

INTERNAL_HTTP_HELPER = r"""
import http.client, json, os, sys
request = json.load(sys.stdin)
headers = {"X-Internal-Auth": os.environ["ROTATOR_INTERNAL_TOKEN"]}
body = None
if "body" in request:
    body = json.dumps(request["body"], separators=(",", ":"))
    headers["Content-Type"] = "application/json"
connection = http.client.HTTPConnection("127.0.0.1", 8080, timeout=30)
connection.request(request["method"], request["path"], body=body, headers=headers)
response = connection.getresponse()
raw = response.read(1048577)
if len(raw) > 1048576:
    raise SystemExit("key-rotator response was too large")
try:
    value = json.loads(raw) if raw else {}
except Exception:
    value = {}
print(json.dumps({"status": response.status, "body": value}, separators=(",", ":")))
""".strip()


def fail(message: str) -> None:
    raise SystemExit(f"ERROR: {message}")


def validate_name(value: str, label: str) -> str:
    if re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", value) is None:
        fail(f"{label} must use only lowercase letters, digits, underscores, and hyphens")
    return value


def validate_inputs(args: argparse.Namespace) -> None:
    if args.domain != ALLOWED_DOMAIN:
        fail(f"local preprod uses the fixed test domain {ALLOWED_DOMAIN}")
    if args.project != ALLOWED_PROJECT:
        fail(f"local preprod uses the fixed Docker project {ALLOWED_PROJECT}")
    if args.prefix != ALLOWED_PREFIX:
        fail(f"local preprod uses the fixed resource prefix {ALLOWED_PREFIX}")
    if args.subnet_octet != ALLOWED_SUBNET_OCTET:
        fail(f"local preprod uses the fixed private subnet octet {ALLOWED_SUBNET_OCTET}")


def clean_environment() -> dict[str, str]:
    """Keep only process settings needed to reach the local Docker CLI."""

    allowed = (
        "DOCKER_CONFIG",
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LOGNAME",
        "PATH",
        "TMPDIR",
        "USER",
        "XDG_CONFIG_HOME",
    )
    return {name: os.environ[name] for name in allowed if name in os.environ}


def preprod_env_value(name: str) -> str:
    if not ENV_FILE.exists():
        return ""
    matches: list[str] = []
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        found_name, separator, value = line.partition("=")
        if separator and found_name == name:
            matches.append(value)
    if len(matches) > 1:
        fail(f"the preprod environment repeats {name}")
    return matches[0] if matches else ""


def run(
    command: list[str],
    *,
    input_text: str | None = None,
    capture: bool = False,
    sensitive: bool = False,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=REPO_ROOT,
        env=clean_environment(),
        input=input_text,
        text=True,
        capture_output=capture,
        check=False,
    )
    if result.returncode != 0:
        if sensitive:
            fail("a secret-bearing local preprod command failed")
        if capture:
            if result.stdout:
                print(result.stdout, end="", file=sys.stderr)
            if result.stderr:
                print(result.stderr, end="", file=sys.stderr)
        fail(f"command failed with exit code {result.returncode}: {command[0]}")
    return result


def local_docker_endpoint() -> str:
    """Resolve once, validate, and pin this process to one local Docker socket."""

    global _LOCAL_DOCKER_CONTEXT, _LOCAL_DOCKER_ENDPOINT
    if _LOCAL_DOCKER_ENDPOINT:
        return _LOCAL_DOCKER_ENDPOINT
    if shutil.which("docker") is None:
        fail("docker is not installed")
    recorded_endpoint = preprod_env_value("PREPROD_DOCKER_ENDPOINT")
    if os.geteuid() == 0:
        uid, _ = recorded_preprod_owner()
        if not recorded_endpoint:
            fail("the prepared local Docker endpoint is missing")
        context = "prepared-preprod"
        endpoint = recorded_endpoint
        allowed_socket_owners = {0, uid}
    else:
        context = run(["docker", "context", "show"], capture=True).stdout.strip()
        if (
            not context
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", context) is None
        ):
            fail("Docker returned an invalid active context name")
        raw = run(
            [
                "docker", "context", "inspect", context,
                "--format", "{{json .Endpoints.docker.Host}}",
            ],
            capture=True,
        ).stdout.strip()
        try:
            endpoint = json.loads(raw)
        except json.JSONDecodeError:
            fail("Docker returned an invalid context endpoint")
        if recorded_endpoint and endpoint != recorded_endpoint:
            fail("the active Docker endpoint differs from the prepared preprod endpoint")
        allowed_socket_owners = {0, os.geteuid()}
    if not isinstance(endpoint, str) or not endpoint.startswith("unix:///"):
        fail("preprod requires a local Unix-socket Docker context; SSH and TCP are refused")
    socket_path = Path(endpoint.removeprefix("unix://"))
    if not socket_path.is_absolute() or ".." in socket_path.parts:
        fail("Docker returned a non-canonical local socket path")
    try:
        metadata = socket_path.lstat()
    except FileNotFoundError:
        fail(f"the active local Docker socket does not exist: {socket_path}")
    if not stat.S_ISSOCK(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail("the active local Docker endpoint must be a real Unix socket")
    if metadata.st_uid not in allowed_socket_owners:
        fail("the active local Docker socket has an unexpected owner")
    _LOCAL_DOCKER_CONTEXT = context
    _LOCAL_DOCKER_ENDPOINT = endpoint
    return endpoint


def docker(*arguments: str, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return run(
        ["docker", "--host", local_docker_endpoint(), *arguments],
        capture=capture,
    )


def clean_room_docker(*arguments: str) -> subprocess.CompletedProcess[str]:
    """Run one bounded clean-room Docker operation without hiding its result."""

    return subprocess.run(
        ["docker", "--host", local_docker_endpoint(), *arguments],
        cwd=REPO_ROOT,
        env=clean_environment(),
        stdin=subprocess.DEVNULL,
        text=True,
        capture_output=True,
        check=False,
    )


def validate_local_docker_context() -> str:
    """Validate the local engine without adding output to a caller's receipt."""

    endpoint = local_docker_endpoint()
    docker("info", "--format", "{{json .ServerVersion}}", capture=True)
    return endpoint


def compose_command(args: argparse.Namespace, *arguments: str) -> list[str]:
    command = [
        "docker", "--host", local_docker_endpoint(),
        "compose", "--project-name", args.project,
    ]
    command.extend(["--env-file", str(ENV_FILE)])
    for path in COMPOSE_FILES:
        command.extend(["-f", str(path)])
    if args.image_mode == "seed":
        if not SEED_OVERLAY.is_file():
            fail("seed image mode requires the activate-seed step")
        command.extend(["-f", str(SEED_OVERLAY)])
    command.extend(["--profile", "preprod"])
    command.extend(arguments)
    return command


def compose(
    args: argparse.Namespace,
    *arguments: str,
    input_text: str | None = None,
    capture: bool = False,
    sensitive: bool = False,
) -> subprocess.CompletedProcess[str]:
    return run(
        compose_command(args, *arguments),
        input_text=input_text,
        capture=capture,
        sensitive=sensitive,
    )


def check_context(_: argparse.Namespace) -> None:
    endpoint = validate_local_docker_context()
    print(
        "PREPROD_DOCKER_CONTEXT_OK "
        f"context={_LOCAL_DOCKER_CONTEXT} endpoint={endpoint}"
    )


def check_root_seed_engine(args: argparse.Namespace) -> None:
    """Prove the root loader and operator address the same local Docker engine."""

    check_context(args)
    operator_socket = Path(local_docker_endpoint().removeprefix("unix://"))
    try:
        operator_socket.lstat()
        root_metadata = ROOT_SEED_DOCKER_SOCKET.lstat()
    except FileNotFoundError as exc:
        fail(f"the Linux root seed socket is missing: {exc.filename}")
    if (
        stat.S_ISLNK(root_metadata.st_mode)
        or not stat.S_ISSOCK(root_metadata.st_mode)
        or root_metadata.st_uid != 0
    ):
        fail("the Linux root seed endpoint must be a real root-owned Unix socket")
    try:
        same_engine = os.path.samefile(operator_socket, ROOT_SEED_DOCKER_SOCKET)
    except OSError:
        same_engine = False
    if not same_engine:
        fail("the operator and root seed loader address different Docker engines")
    print("PREPROD_ROOT_SEED_ENGINE_OK")


def load_local_preprod_seed(args: argparse.Namespace) -> None:
    """Load one preprod release as the non-root Docker Desktop operator."""

    if os.geteuid() == ROOT_UID:
        fail("local Docker Desktop seed loading must run as the recorded non-root operator")
    uid, gid = recorded_preprod_owner()
    if (os.geteuid(), os.getegid()) != (uid, gid):
        fail("local Docker Desktop seed loading must run as the recorded checkout owner")
    validate_local_docker_context()
    loader = REPO_ROOT / "scripts/load-offline-image-seed.py"
    with tempfile.TemporaryDirectory(
        prefix="preprod-seed-loader-", dir=SECRETS_DIR
    ) as marker_directory:
        result = run(
            [
                sys.executable,
                "-I",
                str(loader),
                "local-preprod-load",
                str(Path(args.archive).resolve()),
                args.archive_sha256,
                str(Path(args.manifest).resolve()),
                args.manifest_sha256,
                marker_directory,
                local_docker_endpoint(),
            ],
            capture=True,
        )
    outcome = result.stdout.strip()
    if not re.fullmatch(r"(?:LOADED|RELOADED|SKIPPED) [0-9a-f]{64}", outcome):
        fail("the local preprod seed loader returned an invalid outcome")
    print(f"PREPROD_LOCAL_SEED_{outcome}")


def _custom_image_effective_alias(value: str) -> str:
    """Return Docker's exact spelling for an omitted custom-image tag."""

    final_component = value.rsplit("/", 1)[-1]
    return value if ":" in final_component else f"{value}:latest"


def _canonical_docker_alias(value: str) -> str:
    """Normalize Docker Hub shorthand only for ownership comparisons."""

    tagged, separator, digest = value.rpartition("@")
    if not separator:
        tagged = value
        digest = ""
    final_component = tagged.rsplit("/", 1)[-1]
    if ":" in final_component:
        repository, tag = tagged.rsplit(":", 1)
        tag_suffix = f":{tag}"
    else:
        repository = tagged
        tag_suffix = "" if digest else ":latest"
    components = repository.split("/")
    first = components[0]
    if first == "index.docker.io":
        components[0] = "docker.io"
        first = "docker.io"
    if len(components) == 1:
        components = ["docker.io", "library", components[0]]
    elif first == "docker.io" and len(components) == 2:
        components.insert(1, "library")
    elif "." not in first and ":" not in first and first != "localhost":
        components.insert(0, "docker.io")
    repository = "/".join(components).lower()
    digest_suffix = f"@{digest.lower()}" if digest else ""
    return f"{repository}{tag_suffix}{digest_suffix}"


def _custom_alias_repository(kind: str, value: str) -> str:
    if kind == "custom-archive-reference":
        return value.rsplit(":", 1)[0]
    if kind != "custom-image":
        fail("cannot derive a repository from a non-custom clean-room alias")
    final_component = value.rsplit("/", 1)[-1]
    return value.rsplit(":", 1)[0] if ":" in final_component else value


def _validate_clean_room_plan(raw: object, manifest_sha256: str) -> dict[str, Any]:
    """Revalidate the loader's small canonical mutation plan."""

    expected_keys = {
        "groups",
        "manifest_sha256",
        "record_count",
        "schema_version",
        "unique_image_id_count",
    }
    if not isinstance(raw, dict) or set(raw) != expected_keys:
        fail("the clean-room purge plan has an invalid top-level shape")
    if raw.get("schema_version") != CLEAN_ROOM_PLAN_SCHEMA:
        fail("the clean-room purge plan has an unsupported schema")
    if raw.get("manifest_sha256") != manifest_sha256:
        fail("the clean-room purge plan is bound to a different manifest")
    record_count = raw.get("record_count")
    unique_count = raw.get("unique_image_id_count")
    groups = raw.get("groups")
    if (
        not isinstance(record_count, int)
        or isinstance(record_count, bool)
        or record_count < 1
        or record_count > CLEAN_ROOM_MAX_RECORDS
        or not isinstance(unique_count, int)
        or isinstance(unique_count, bool)
        or unique_count < 1
        or unique_count > CLEAN_ROOM_MAX_GROUPS
        or unique_count > record_count
        or not isinstance(groups, list)
        or len(groups) != unique_count
    ):
        fail("the clean-room purge plan counts are invalid")

    group_ids: list[str] = []
    all_alias_values: set[str] = set()
    total_aliases = 0
    counted_records = 0
    for group in groups:
        if not isinstance(group, dict) or set(group) != {"aliases", "image_id"}:
            fail("a clean-room purge group has an invalid shape")
        image_id = group.get("image_id")
        aliases = group.get("aliases")
        if not isinstance(image_id, str) or IMAGE_ID_RE.fullmatch(image_id) is None:
            fail("a clean-room purge group has an invalid image ID")
        if not isinstance(aliases, list) or not aliases:
            fail("a clean-room purge group has no aliases")
        group_ids.append(image_id)
        parsed_aliases: list[tuple[str, str]] = []
        by_kind: dict[str, set[str]] = {kind: set() for kind in CLEAN_ROOM_ALIAS_KINDS}
        for alias in aliases:
            if not isinstance(alias, dict) or set(alias) != {"kind", "value"}:
                fail("a clean-room purge alias has an invalid shape")
            kind = alias.get("kind")
            value = alias.get("value")
            if (
                not isinstance(kind, str)
                or kind not in CLEAN_ROOM_ALIAS_KINDS
                or not isinstance(value, str)
                or not value
                or len(value) > 512
                or value.startswith("-")
                or any(character.isspace() or ord(character) < 32 for character in value)
            ):
                fail("a clean-room purge alias is unsafe")
            canonical_value = _canonical_docker_alias(value)
            if canonical_value in all_alias_values:
                fail("the clean-room purge plan repeats an image alias")
            all_alias_values.add(canonical_value)
            by_kind[kind].add(value)
            parsed_aliases.append((kind, value))
        if parsed_aliases != sorted(parsed_aliases) or len(set(parsed_aliases)) != len(parsed_aliases):
            fail("clean-room purge aliases are not canonical")

        expected_custom_archives: set[str] = set()
        for value in by_kind["custom-image"]:
            if CUSTOM_IMAGE_REFERENCE_RE.fullmatch(value) is None:
                fail("a clean-room custom image alias is invalid")
            expected_custom_archives.add(
                f"{_custom_alias_repository('custom-image', value)}:"
                f"aigw-seed-{image_id.removeprefix('sha256:')}"
            )
        if (
            by_kind["custom-archive-reference"] != expected_custom_archives
            or any(
                CUSTOM_TRANSFER_REFERENCE_RE.fullmatch(value) is None
                for value in by_kind["custom-archive-reference"]
            )
        ):
            fail("clean-room custom aliases are not exact derivations")

        expected_external_tags: set[str] = set()
        expected_external_digests: set[str] = set()
        for value in by_kind["external-reference"]:
            if EXTERNAL_IMAGE_REFERENCE_RE.fullmatch(value) is None:
                fail("a clean-room external image alias is invalid")
            tagged, digest = value.rsplit("@", 1)
            expected_external_tags.add(tagged)
            expected_external_digests.add(f"{tagged.rsplit(':', 1)[0]}@{digest}")
        if (
            by_kind["external-tag"] != expected_external_tags
            or by_kind["external-repository-digest"] != expected_external_digests
            or any(
                REPOSITORY_DIGEST_RE.fullmatch(value) is None
                for value in by_kind["external-repository-digest"]
            )
        ):
            fail("clean-room external aliases are not exact derivations")
        custom_records = len(by_kind["custom-image"])
        external_records = len(by_kind["external-reference"])
        if custom_records + external_records < 1:
            fail("a clean-room purge group has no release record")
        counted_records += custom_records + external_records
        total_aliases += len(parsed_aliases)

    if group_ids != sorted(group_ids) or len(set(group_ids)) != len(group_ids):
        fail("clean-room purge groups are not canonical")
    if counted_records != record_count or total_aliases > CLEAN_ROOM_MAX_ALIASES:
        fail("clean-room purge plan record accounting is invalid")
    return raw


def clean_room_purge_plan(args: argparse.Namespace) -> dict[str, Any]:
    """Ask the read-only loader to validate and plan one exact preprod release."""

    if os.geteuid() == ROOT_UID:
        fail("clean-room seed removal must run as the non-root Docker operator")
    endpoint = validate_local_docker_context()
    loader = REPO_ROOT / "scripts/load-offline-image-seed.py"
    result = run(
        [
            sys.executable,
            "-I",
            str(loader),
            "local-preprod-purge-plan",
            str(Path(args.archive).resolve()),
            args.archive_sha256,
            str(Path(args.manifest).resolve()),
            args.manifest_sha256,
            str(REPO_ROOT.resolve()),
            endpoint,
        ],
        capture=True,
    )
    output = result.stdout
    if not output.endswith("\n") or output.count("\n") != 1 or len(output.encode()) > CLEAN_ROOM_MAX_PLAN_BYTES:
        fail("the clean-room purge planner returned an unbounded response")
    try:
        document = json.loads(output)
    except json.JSONDecodeError:
        fail("the clean-room purge planner returned invalid JSON")
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    if output != canonical:
        fail("the clean-room purge planner response is not canonical")
    return _validate_clean_room_plan(document, args.manifest_sha256)


def _clean_room_command_result(
    result: subprocess.CompletedProcess[str], operation: str
) -> str:
    if result.returncode != 0:
        fail(f"Docker failed during clean-room {operation}")
    if result.stderr:
        fail(f"Docker returned unexpected diagnostics during clean-room {operation}")
    return result.stdout


def _clean_room_list(
    kind: str, *arguments: str, deduplicate: bool = False
) -> list[str]:
    output = _clean_room_command_result(
        clean_room_docker(kind, "ls", *arguments), f"{kind} inventory"
    )
    values = output.splitlines()
    if len(values) > CLEAN_ROOM_MAX_DOCKER_OBJECTS:
        fail(f"the clean-room {kind} inventory is invalid")
    if any(not value or len(value) > 512 for value in values):
        fail(f"the clean-room {kind} inventory contains an invalid value")
    if len(values) != len(set(values)):
        if not deduplicate:
            fail(f"the clean-room {kind} inventory repeats an object")
        values = list(dict.fromkeys(values))
    return values


def _clean_room_network_inventory() -> list[tuple[str, str, dict[str, Any]]]:
    """Bind each listed network's full ID to its inspected name and settings."""

    networks: list[tuple[str, str, dict[str, Any]]] = []
    names: set[str] = set()
    for network_id in _clean_room_list("network", "--no-trunc", "--quiet"):
        if re.fullmatch(r"[0-9a-f]{64}", network_id) is None:
            fail("Docker returned an invalid full network ID")
        document = _clean_room_inspect_required("network", network_id)
        if document.get("Id") != network_id:
            fail("a clean-room network inspection changed identity")
        name = document.get("Name")
        if (
            not isinstance(name, str)
            or not name
            or len(name) > 512
            or name.startswith("-")
            or any(character.isspace() or ord(character) < 32 for character in name)
            or name in names
        ):
            fail("a clean-room network has an invalid or duplicate name")
        names.add(name)
        networks.append((network_id, name, document))
    return networks


def _clean_room_inspect_required(kind: str, value: str) -> dict[str, Any]:
    output = _clean_room_command_result(
        clean_room_docker(kind, "inspect", "--format", "{{json .}}", value),
        f"{kind} inspection",
    )
    if len(output.encode()) > 1024 * 1024 or output.count("\n") > 1:
        fail(f"the clean-room {kind} inspection was unbounded")
    try:
        document = json.loads(output)
    except json.JSONDecodeError:
        fail(f"Docker returned invalid clean-room {kind} inspection JSON")
    if not isinstance(document, dict):
        fail(f"Docker returned an invalid clean-room {kind} inspection")
    return document


def _expected_image_not_found_subject(value: str, kind: str | None) -> str:
    if kind == "custom-image":
        return _custom_image_effective_alias(value)
    return value


def _is_exact_image_not_found(
    result: subprocess.CompletedProcess[str], value: str, kind: str | None
) -> bool:
    expected = _expected_image_not_found_subject(value, kind)
    return (
        result.returncode == 1
        and result.stdout in {"", "\n"}
        and result.stderr == f"Error response from daemon: No such image: {expected}\n"
    )


def _clean_room_inspect_image_optional(
    value: str, kind: str | None = None
) -> dict[str, Any] | None:
    result = clean_room_docker(
        "image", "inspect", "--format", "{{json .}}", value
    )
    if _is_exact_image_not_found(result, value, kind):
        return None
    return _clean_room_inspect_required_result(result, "image inspection")


def _clean_room_inspect_required_result(
    result: subprocess.CompletedProcess[str], operation: str
) -> dict[str, Any]:
    output = _clean_room_command_result(result, operation)
    if len(output.encode()) > 1024 * 1024 or output.count("\n") > 1:
        fail(f"the clean-room {operation} was unbounded")
    try:
        document = json.loads(output)
    except json.JSONDecodeError:
        fail(f"Docker returned invalid clean-room {operation} JSON")
    if not isinstance(document, dict):
        fail(f"Docker returned an invalid clean-room {operation}")
    return document


def _clean_room_image_aliases(document: dict[str, Any]) -> set[str]:
    aliases: set[str] = set()
    for field in ("RepoTags", "RepoDigests"):
        values = document.get(field) or []
        if not isinstance(values, list):
            fail(f"Docker image {field} is invalid during clean-room inspection")
        for value in values:
            if (
                not isinstance(value, str)
                or not value
                or len(value) > 512
                or value.startswith("-")
                or any(character.isspace() or ord(character) < 32 for character in value)
            ):
                fail("Docker exposed an unsafe image alias during clean-room inspection")
            aliases.add(value)
    return aliases


def collect_clean_room_inventory(plan: dict[str, Any]) -> dict[str, Any]:
    """Inspect every container and image before any clean-room mutation."""

    target_groups = {group["image_id"]: group for group in plan["groups"]}
    target_ids = set(target_groups)
    container_ids = _clean_room_list(
        "container", "--all", "--no-trunc", "--quiet"
    )
    containers: dict[str, dict[str, Any]] = {}
    for container_id in container_ids:
        if re.fullmatch(r"[0-9a-f]{64}", container_id) is None:
            fail("Docker returned an invalid full container ID")
        document = _clean_room_inspect_required("container", container_id)
        if document.get("Id") != container_id:
            fail("a clean-room container inspection changed identity")
        containers[container_id] = document

    image_ids = _clean_room_list(
        "image", "--all", "--no-trunc", "--quiet", deduplicate=True
    )
    images: dict[str, dict[str, Any]] = {}
    observed_alias_owners: dict[str, str] = {}
    exposed_children: set[str] = set()
    for image_id in image_ids:
        if IMAGE_ID_RE.fullmatch(image_id) is None:
            fail("Docker returned an invalid full image ID")
        document = _clean_room_inspect_required("image", image_id)
        if document.get("Id") != image_id:
            fail("a clean-room image inspection changed identity")
        descriptor = document.get("Descriptor")
        if descriptor is not None:
            if not isinstance(descriptor, dict):
                fail("Docker exposed invalid OCI descriptor metadata")
            descriptor_digest = descriptor.get("digest")
            if descriptor_digest is not None:
                if (
                    not isinstance(descriptor_digest, str)
                    or IMAGE_ID_RE.fullmatch(descriptor_digest) is None
                ):
                    fail("Docker exposed an invalid OCI descriptor digest")
                if descriptor_digest != image_id:
                    if image_id in target_ids or descriptor_digest in target_ids:
                        fail("an OCI descriptor digest differs from a clean-room target ID")
                    exposed_children.add(descriptor_digest)
        manifests = document.get("Manifests")
        if manifests is not None:
            if not isinstance(manifests, list):
                fail("Docker exposed invalid OCI index children")
            for manifest in manifests:
                child = manifest.get("digest") if isinstance(manifest, dict) else None
                if not isinstance(child, str) or IMAGE_ID_RE.fullmatch(child) is None:
                    fail("Docker exposed an invalid OCI platform-child ID")
                if child != image_id:
                    exposed_children.add(child)
        for alias in _clean_room_image_aliases(document):
            canonical_alias = _canonical_docker_alias(alias)
            owner = observed_alias_owners.get(canonical_alias)
            if owner is not None and owner != image_id:
                fail("Docker assigned one image alias to multiple image IDs")
            observed_alias_owners[canonical_alias] = image_id
        images[image_id] = document

    approved_observed: dict[str, set[str]] = {}
    present_aliases: list[tuple[str, str, str]] = []
    generated_aliases: list[tuple[str, str, str]] = []
    for image_id, group in target_groups.items():
        approved = set()
        generated_digests = {
            f"{_custom_alias_repository(alias['kind'], alias['value'])}@{image_id}"
            for alias in group["aliases"]
            if alias["kind"] in {"custom-archive-reference", "custom-image"}
        }
        for alias in group["aliases"]:
            value = alias["value"]
            kind = alias["kind"]
            effective = (
                _custom_image_effective_alias(value)
                if kind == "custom-image"
                else value
            )
            canonical_effective = _canonical_docker_alias(effective)
            approved.add(canonical_effective)
            observed_owner = observed_alias_owners.get(canonical_effective)
            if observed_owner is not None and observed_owner != image_id:
                fail("a reviewed clean-room alias points to a foreign image ID")
            resolved = _clean_room_inspect_image_optional(value, kind)
            if resolved is not None:
                resolved_id = resolved.get("Id")
                if resolved_id != image_id:
                    fail("a reviewed clean-room alias resolves to a foreign image ID")
                present_aliases.append((image_id, kind, value))
        for value in sorted(generated_digests):
            canonical_value = _canonical_docker_alias(value)
            approved.add(canonical_value)
            observed_owner = observed_alias_owners.get(canonical_value)
            if observed_owner is not None and observed_owner != image_id:
                fail("a generated custom digest alias points to a foreign image ID")
            resolved = _clean_room_inspect_image_optional(
                value, "custom-generated-repository-digest"
            )
            if resolved is not None:
                if resolved.get("Id") != image_id:
                    fail("a generated custom digest alias resolves to a foreign image ID")
                generated_aliases.append(
                    (image_id, "custom-generated-repository-digest", value)
                )
        approved_observed[image_id] = approved

        if image_id not in images:
            resolved = _clean_room_inspect_image_optional(image_id)
            if resolved is not None:
                fail("Docker omitted a target image from its complete image inventory")

    for image_id in target_ids.intersection(images):
        if not any(
            entry[0] == image_id for entry in present_aliases + generated_aliases
        ):
            fail("a clean-room target ID exists without a reviewed alias binding")
        foreign = {
            _canonical_docker_alias(value)
            for value in _clean_room_image_aliases(images[image_id])
        } - approved_observed[image_id]
        if foreign:
            fail("a clean-room target image has an unreviewed Docker alias")

    for child in exposed_children:
        if child in target_ids:
            fail("an OCI platform child overlaps a distinct clean-room target ID")
        if child not in images:
            resolved = _clean_room_inspect_image_optional(child)
            if resolved is not None:
                fail("Docker omitted an exposed OCI platform child from image inventory")

    for document in containers.values():
        image_id = document.get("Image")
        if not isinstance(image_id, str) or IMAGE_ID_RE.fullmatch(image_id) is None:
            fail("a Docker container has an invalid image ID")
        if image_id not in target_ids:
            continue
        name = str(document.get("Name", "")).removeprefix("/")
        labels = document.get("Config", {}).get("Labels") or {}
        if (
            not isinstance(labels, dict)
            or labels.get("com.docker.compose.project") != ALLOWED_PROJECT
            or labels.get("com.aigw.preprod.project") != ALLOWED_PROJECT
            or not name.startswith(ALLOWED_PROJECT + "-")
        ):
            fail("an unrelated running or stopped container uses a clean-room target image")

    return {
        "containers": containers,
        "images": images,
        "non_target_ids": set(images) - target_ids,
        "generated_aliases": generated_aliases,
        "present_aliases": present_aliases,
        "present_target_ids": target_ids.intersection(images),
        "target_ids": target_ids,
    }


def ensure_directory(path: Path, mode: int = 0o700) -> None:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(mode)


def write_file(path: Path, content: str, mode: int, *, replace: bool = True) -> None:
    if path.exists() and not path.is_file():
        fail(f"refusing non-file path {path}")
    if path.exists() and not replace and path.read_text() != content:
        fail(f"existing static preprod file differs: {path}")
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    with temporary.open("w", encoding="utf-8") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    temporary.chmod(mode)
    temporary.replace(path)


def _validate_root_directory_lineage(directory: Path) -> None:
    """Reject a replaceable path before root reads or writes alias state."""

    if not directory.is_absolute() or ".." in directory.parts:
        fail("the loopback state directory must be canonical and absolute")
    cursor = directory
    trusted_uids = {0, ROOT_UID}
    while True:
        try:
            metadata = cursor.lstat()
        except OSError as exc:
            fail(f"cannot inspect loopback state directory ancestor: {exc}")
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            fail("the loopback state path must contain only real directories")
        if metadata.st_uid not in trusted_uids or stat.S_IMODE(metadata.st_mode) & 0o022:
            fail("the loopback state path has an untrusted owner or writable ancestor")
        if cursor == cursor.parent:
            return
        cursor = cursor.parent


def _validate_loopback_state_directory(*, create: bool) -> bool:
    try:
        metadata = LOOPBACK_STATE_DIR.lstat()
    except FileNotFoundError:
        if not create:
            return False
        _validate_root_directory_lineage(LOOPBACK_STATE_DIR.parent)
        try:
            LOOPBACK_STATE_DIR.mkdir(mode=0o700)
        except FileExistsError:
            pass
        metadata = LOOPBACK_STATE_DIR.lstat()
    _validate_root_directory_lineage(LOOPBACK_STATE_DIR.parent)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        fail("the loopback state directory must be a real directory")
    if (metadata.st_uid, metadata.st_gid) != (ROOT_UID, ROOT_GID):
        fail("the loopback state directory must be owned by root:root")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        fail("the loopback state directory must have mode 0700")
    return True


def read_loopback_state() -> set[str]:
    """Read only aliases created by this preprod installation."""

    if not _validate_loopback_state_directory(create=False):
        return set()
    try:
        metadata = LOOPBACK_STATE_FILE.lstat()
    except FileNotFoundError:
        return set()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or (metadata.st_uid, metadata.st_gid) != (ROOT_UID, ROOT_GID)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size < 1
        or metadata.st_size > LOOPBACK_STATE_MAX_BYTES
    ):
        fail("the loopback alias ownership record is unsafe")
    try:
        document = json.loads(LOOPBACK_STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        fail("the loopback alias ownership record is invalid")
    if not isinstance(document, dict) or set(document) != {
        "schema",
        "project",
        "interface",
        "boot_session",
        "owned_aliases",
    }:
        fail("the loopback alias ownership record has an invalid shape")
    aliases = document.get("owned_aliases")
    if (
        document.get("schema") != 1
        or document.get("project") != ALLOWED_PROJECT
        or document.get("interface") != DARWIN_LOOPBACK_INTERFACE
        or not isinstance(document.get("boot_session"), str)
        or re.fullmatch(
            r"[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}",
            document["boot_session"],
        )
        is None
        or not isinstance(aliases, list)
        or any(not isinstance(alias, str) for alias in aliases)
        or aliases != sorted(set(aliases))
        or any(alias not in MANAGED_PREPROD_LOOPBACK_ALIASES for alias in aliases)
    ):
        fail("the loopback alias ownership record has invalid values")
    if document["boot_session"] != darwin_boot_session():
        # Darwin loopback aliases disappear at reboot. A persistent record
        # from an earlier boot cannot prove ownership of a newly reused IP.
        LOOPBACK_STATE_FILE.unlink()
        return set()
    return set(aliases)


def write_loopback_state(owned_aliases: set[str]) -> None:
    if not owned_aliases:
        if LOOPBACK_STATE_FILE.exists():
            LOOPBACK_STATE_FILE.unlink()
        return
    if not owned_aliases.issubset(MANAGED_PREPROD_LOOPBACK_ALIASES):
        fail("refusing to record an unexpected loopback alias")
    _validate_loopback_state_directory(create=True)
    document = {
        "schema": 1,
        "project": ALLOWED_PROJECT,
        "interface": DARWIN_LOOPBACK_INTERFACE,
        "boot_session": darwin_boot_session(),
        "owned_aliases": sorted(owned_aliases),
    }
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".loopback-aliases-",
        dir=LOOPBACK_STATE_DIR,
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        os.fchown(descriptor, ROOT_UID, ROOT_GID)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            json.dump(document, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, LOOPBACK_STATE_FILE)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def darwin_loopback_addresses() -> set[str]:
    result = run(
        [str(DARWIN_IFCONFIG), DARWIN_LOOPBACK_INTERFACE],
        capture=True,
    )
    counts = {alias: 0 for alias in MANAGED_PREPROD_LOOPBACK_ALIASES}
    for line in result.stdout.splitlines():
        match = re.match(r"^\s*inet\s+([0-9.]+)\s+netmask\s+(\S+)", line)
        if match and match.group(1) in counts:
            alias, netmask = match.groups()
            if alias in PREPROD_LOOPBACK_ALIASES and netmask.lower() != "0xffffff00":
                fail(f"required preprod loopback alias {alias} is not a /24")
            counts[alias] += 1
    if any(count > 1 for count in counts.values()):
        fail("a required preprod loopback alias appears more than once")
    return {alias for alias, count in counts.items() if count == 1}


def darwin_boot_session() -> str:
    result = run(
        [str(DARWIN_SYSCTL), "-n", "kern.bootsessionuuid"],
        capture=True,
    )
    value = result.stdout.strip().upper()
    if re.fullmatch(r"[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}", value) is None:
        fail("macOS returned an invalid boot-session identifier")
    return value


def ensure_loopback_aliases(_: argparse.Namespace) -> None:
    """Add only missing Darwin aliases and record only what this run owns."""

    if sys.platform != "darwin":
        print("PREPROD_LOOPBACK_ALIASES_NOT_REQUIRED")
        return
    if os.geteuid() != ROOT_UID:
        fail("creating macOS preprod loopback aliases requires root")
    owned = read_loopback_state()
    current = darwin_loopback_addresses()
    added: list[str] = []
    migrated: list[str] = []
    for alias in reversed(LEGACY_PREPROD_LOOPBACK_ALIASES):
        if alias not in owned:
            continue
        if alias in current:
            run(
                [
                    str(DARWIN_IFCONFIG),
                    DARWIN_LOOPBACK_INTERFACE,
                    "-alias",
                    alias,
                ]
            )
            if alias in darwin_loopback_addresses():
                fail(f"macOS did not remove owned legacy loopback alias {alias}")
            current.remove(alias)
            migrated.append(alias)
        owned.remove(alias)
        write_loopback_state(owned)
    for alias in PREPROD_LOOPBACK_ALIASES:
        if alias in current:
            continue
        run(
            [
                str(DARWIN_IFCONFIG),
                DARWIN_LOOPBACK_INTERFACE,
                "alias",
                alias,
                "netmask",
                DARWIN_LOOPBACK_NETMASK,
            ]
        )
        try:
            if alias not in darwin_loopback_addresses():
                fail(f"macOS did not create required loopback alias {alias}")
            current.add(alias)
            owned.add(alias)
            write_loopback_state(owned)
            added.append(alias)
        except (OSError, SystemExit) as post_add_error:
            try:
                run(
                    [
                        str(DARWIN_IFCONFIG),
                        DARWIN_LOOPBACK_INTERFACE,
                        "-alias",
                        alias,
                    ]
                )
            except (OSError, SystemExit) as rollback_error:
                fail(
                    "post-add loopback verification failed and rollback also "
                    f"failed for {alias}: {rollback_error}"
                )
            try:
                still_present = alias in darwin_loopback_addresses()
            except (OSError, SystemExit) as rollback_check_error:
                fail(
                    "the new loopback alias was rolled back, but macOS would not "
                    f"verify its removal for {alias}: {rollback_check_error}"
                )
            if still_present:
                fail(f"the new loopback alias could not be rolled back: {alias}")
            raise post_add_error
    if added:
        print("PREPROD_LOOPBACK_ALIASES_CREATED " + " ".join(added))
    elif migrated:
        print("PREPROD_LOOPBACK_ALIASES_MIGRATED " + " ".join(migrated))
    elif owned:
        print("PREPROD_LOOPBACK_ALIASES_VERIFIED")
    else:
        print("PREPROD_LOOPBACK_ALIASES_PRESERVED")


def remove_loopback_aliases(_: argparse.Namespace) -> None:
    """Remove only Darwin aliases proven owned by the preprod state record."""

    if sys.platform != "darwin":
        print("PREPROD_LOOPBACK_ALIASES_NOT_REQUIRED")
        return
    if os.geteuid() != ROOT_UID:
        fail("removing macOS preprod loopback aliases requires root")
    owned = read_loopback_state()
    if not owned:
        print("PREPROD_LOOPBACK_ALIASES_PRESERVED")
        return
    removed: list[str] = []
    for alias in reversed(MANAGED_PREPROD_LOOPBACK_ALIASES):
        if alias not in owned:
            continue
        if alias in darwin_loopback_addresses():
            run(
                [
                    str(DARWIN_IFCONFIG),
                    DARWIN_LOOPBACK_INTERFACE,
                    "-alias",
                    alias,
                ]
            )
            if alias in darwin_loopback_addresses():
                fail(f"macOS did not remove owned loopback alias {alias}")
            removed.append(alias)
        owned.remove(alias)
        write_loopback_state(owned)
    print("PREPROD_LOOPBACK_ALIASES_REMOVED " + " ".join(removed))


def static_hex(label: str, length: int = 48) -> str:
    value = hashlib.sha256(f"aigw-preprod-only:{label}".encode()).hexdigest()
    return value[:length]


def certificate_paths() -> dict[str, Path]:
    return {
        "root_key": SECRETS_DIR / "preprod-root-ca.key",
        "root_cert": SECRETS_DIR / "preprod-root-ca.pem",
        "edge_key": EDGE_CERTS_DIR / "int.key",
        "edge_cert": EDGE_CERTS_DIR / "int.crt",
        "edge_ca": EDGE_CERTS_DIR / "ca.pem",
        "samba_key": SECRETS_DIR / "preprod-samba.key",
        "samba_cert": SECRETS_DIR / "preprod-samba.crt",
        "cribl_key": SECRETS_DIR / "preprod-cribl.key",
        "cribl_cert": SECRETS_DIR / "preprod-cribl.crt",
        "wif_key": SECRETS_DIR / "preprod-wif.key",
        "wif_cert": SECRETS_DIR / "preprod-wif.crt",
    }


def generate_root_ca(paths: dict[str, Path]) -> None:
    key_exists = paths["root_key"].exists()
    cert_exists = paths["root_cert"].exists()
    if key_exists != cert_exists:
        fail("the persistent preprod root CA is incomplete; restore its missing file")
    if key_exists:
        return
    run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:3072", "-sha256", "-nodes",
            "-days", "3650", "-subj", "/CN=AI Gateway Preprod Test Root CA",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:1",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-addext", "subjectKeyIdentifier=hash",
            "-keyout", str(paths["root_key"]), "-out", str(paths["root_cert"]),
        ]
    )
    paths["root_key"].chmod(0o600)
    paths["root_cert"].chmod(0o644)


def generate_leaf(
    paths: dict[str, Path], key_name: str, cert_name: str, common_name: str, sans: list[str]
) -> None:
    key_path = paths[key_name]
    cert_path = paths[cert_name]
    if key_path.exists() != cert_path.exists():
        fail(f"the preprod certificate for {common_name} is incomplete")
    if not key_path.exists():
        with tempfile.TemporaryDirectory(prefix="aigw-preprod-cert-") as directory:
            csr = Path(directory) / "leaf.csr"
            extensions = Path(directory) / "extensions.cnf"
            extensions.write_text(
                "basicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature,keyEncipherment\n"
                "extendedKeyUsage=serverAuth\n"
                f"subjectAltName={','.join('DNS:' + name for name in sans)}\n"
            )
            run(
                [
                    "openssl", "req", "-new", "-newkey", "rsa:2048", "-sha256", "-nodes",
                    "-subj", f"/CN={common_name}", "-keyout", str(key_path), "-out", str(csr),
                ]
            )
            run(
                [
                    "openssl", "x509", "-req", "-sha256", "-days", "825",
                    "-in", str(csr), "-CA", str(paths["root_cert"]),
                    "-CAkey", str(paths["root_key"]), "-CAcreateserial",
                    "-extfile", str(extensions), "-out", str(cert_path),
                ]
            )
        key_path.chmod(0o600)
        cert_path.chmod(0o644)
    run(
        [
            "openssl", "verify", "-CAfile", str(paths["root_cert"]),
            "-verify_hostname", sans[0], str(cert_path),
        ],
        capture=True,
    )


def prepare_certificates(domain: str) -> None:
    paths = certificate_paths()
    generate_root_ca(paths)
    generate_leaf(paths, "edge_key", "edge_cert", f"*.{domain}", [f"*.{domain}", domain])
    generate_leaf(
        paths, "samba_key", "samba_cert", f"samba-ad.{domain}", [f"samba-ad.{domain}"]
    )
    generate_leaf(paths, "cribl_key", "cribl_cert", "cribl-mock", ["cribl-mock"])
    generate_leaf(
        paths,
        "wif_key",
        "wif_cert",
        f"wif-provider-mock.{domain}",
        [f"wif-provider-mock.{domain}"],
    )
    for certificate_name in ("edge_cert", "samba_cert", "cribl_cert", "wif_cert"):
        leaf = run(
            ["openssl", "x509", "-in", str(paths[certificate_name]), "-outform", "PEM"],
            capture=True,
        ).stdout
        write_file(
            paths[certificate_name], leaf + paths["root_cert"].read_text(), 0o644
        )
    write_file(paths["edge_ca"], paths["root_cert"].read_text(), 0o644)


def render_realms(domain: str) -> None:
    aigw = json.loads((COMPOSE_DIR / "keycloak/realms/aigw-realm.json").read_text())
    wif = json.loads((COMPOSE_DIR / "keycloak/realms/anthropic-wif-realm.json").read_text())
    clients = {client["clientId"]: client for client in aigw["clients"]}
    expected_clients = {"open-webui", "dev-portal", "admin-portal", "admin-ui", "vault"}
    if set(clients) != expected_clients:
        fail("the Keycloak client set changed; update the explicit preprod realm renderer")

    clients["open-webui"]["redirectUris"] = [f"https://chat.{domain}/oauth/oidc/callback"]
    clients["open-webui"]["webOrigins"] = [f"https://chat.{domain}"]
    clients["open-webui"]["attributes"]["post.logout.redirect.uris"] = f"https://chat.{domain}/"

    clients["dev-portal"]["redirectUris"] = [f"https://portal.{domain}/auth/callback"]
    clients["dev-portal"]["webOrigins"] = [f"https://portal.{domain}"]
    clients["dev-portal"]["attributes"]["post.logout.redirect.uris"] = f"https://portal.{domain}/login"

    clients["admin-portal"]["redirectUris"] = [f"https://admin.{domain}/auth/callback"]
    clients["admin-portal"]["webOrigins"] = [f"https://admin.{domain}"]
    clients["admin-portal"]["attributes"]["post.logout.redirect.uris"] = f"https://admin.{domain}/login"

    admin_hosts = ["litellm-admin", "grafana", "prometheus", "vault"]
    clients["admin-ui"]["redirectUris"] = [
        f"https://{host}.{domain}/oauth2/callback" for host in admin_hosts
    ]
    clients["admin-ui"]["webOrigins"] = [f"https://{host}.{domain}" for host in admin_hosts]
    clients["admin-ui"]["attributes"]["post.logout.redirect.uris"] = "##".join(
        f"https://{host}.{domain}/" for host in admin_hosts
    )

    clients["vault"]["redirectUris"] = [
        f"https://vault.{domain}/ui/vault/auth/oidc/oidc/callback",
        "http://localhost:8250/oidc/callback",
    ]
    clients["vault"]["webOrigins"] = [f"https://vault.{domain}"]
    wif["attributes"]["frontendUrl"] = f"https://idp.wif.{domain}"

    rendered = json.dumps(aigw, indent=2) + "\n"
    rendered_wif = json.dumps(wif, indent=2) + "\n"
    forbidden = ("example.internal", "example.invalid")
    if any(value in rendered + rendered_wif for value in forbidden):
        fail("a rendered realm retained an example hostname")
    if f"https://idp.wif.{domain}" not in rendered_wif:
        fail("the WIF issuer was not rendered from the preprod domain")
    write_file(REALMS_DIR / "aigw-realm.json", rendered, 0o644)
    write_file(REALMS_DIR / "anthropic-wif-realm.json", rendered_wif, 0o644)


def envoy_base_image_reference() -> str:
    """Read the exact Envoy runtime pin used by the production image."""

    dockerfile = REPO_ROOT / "services/egress-proxy/Dockerfile"
    try:
        content = dockerfile.read_text(encoding="utf-8")
    except OSError as exc:
        fail(f"cannot read the Envoy Dockerfile: {exc}")
    references = re.findall(
        r"^FROM (dhi\.io/envoy:[A-Za-z0-9_.-]+@sha256:[0-9a-f]{64})$",
        content,
        flags=re.MULTILINE,
    )
    if len(references) != 1 or EXTERNAL_IMAGE_REFERENCE_RE.fullmatch(references[0]) is None:
        fail("the Envoy Dockerfile must contain one exact DHI runtime pin")
    return references[0]


def render_wif_mock_envoy(domain: str, vendor_subnet: str) -> None:
    """Render the preprod-only proxy used to exercise the local WIF mock."""

    hostname = f"wif-provider-mock.{domain}"
    configuration = f"""admin:
  address:
    socket_address: {{ address: 127.0.0.1, port_value: 9901 }}
static_resources:
  listeners:
    - name: egress_http
      address:
        socket_address: {{ address: 0.0.0.0, port_value: 8080 }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                \"@type\": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: preprod_egress
                route_config:
                  name: vendors
                  virtual_hosts:
                    - name: preprod_anthropic
                      domains: [\"*\"]
                      routes:
                        - match: {{ prefix: \"/anthropic/\" }}
                          route:
                            cluster: preprod_anthropic
                            prefix_rewrite: \"/\"
                            host_rewrite_literal: {hostname}
                            timeout: 60s
                http_filters:
                  - name: envoy.filters.http.rbac
                    typed_config:
                      \"@type\": type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBAC
                      rules:
                        action: ALLOW
                        policies:
                          vendor_network_only:
                            permissions: [{{ any: true }}]
                            principals:
                              - direct_remote_ip:
                                  address_prefix: {vendor_subnet.rsplit('.', 1)[0]}.0
                                  prefix_len: 24
                  - name: envoy.filters.http.router
                    typed_config:
                      \"@type\": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
    - name: read_only_metrics
      address:
        socket_address: {{ address: 0.0.0.0, port_value: 9902 }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                \"@type\": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: metrics
                route_config:
                  name: metrics
                  virtual_hosts:
                    - name: metrics
                      domains: [\"*\"]
                      routes:
                        - match: {{ path: \"/stats/prometheus\" }}
                          route: {{ cluster: local_admin, timeout: 5s }}
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      \"@type\": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  clusters:
    - name: local_admin
      type: STATIC
      connect_timeout: 1s
      load_assignment:
        cluster_name: local_admin
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: 127.0.0.1, port_value: 9901 }}
    - name: preprod_anthropic
      type: STRICT_DNS
      dns_lookup_family: V4_ONLY
      connect_timeout: 5s
      load_assignment:
        cluster_name: preprod_anthropic
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: {hostname}, port_value: 8443 }}
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          \"@type\": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
          sni: {hostname}
          common_tls_context:
            tls_params:
              tls_minimum_protocol_version: TLSv1_3
              tls_maximum_protocol_version: TLSv1_3
            validation_context:
              trusted_ca: {{ filename: /etc/envoy/certs/preprod-root-ca.pem }}
              match_typed_subject_alt_names:
                - san_type: DNS
                  matcher: {{ exact: {hostname} }}
"""
    write_file(SECRETS_DIR / "preprod-wif-envoy.yaml", configuration, 0o644)


def render_preprod_litellm_config() -> None:
    """Keep production models while routing test inference to the TLS mock."""

    source = COMPOSE_DIR / "litellm/config.yaml"
    try:
        configuration = source.read_text(encoding="utf-8")
    except OSError as exc:
        fail(f"cannot read the production LiteLLM config: {exc}")

    production_base = "api_base: http://envoy-egress:8080/anthropic"
    preprod_base = "api_base: http://wif-egress-mock:8080/anthropic"
    api_base_lines = [
        line.strip()
        for line in configuration.splitlines()
        if line.strip().startswith("api_base:")
    ]
    if not api_base_lines or any(line != production_base for line in api_base_lines):
        fail(
            "the production LiteLLM provider routes changed; update the explicit "
            "preprod renderer"
        )

    rendered = configuration.replace(production_base, preprod_base)
    if production_base in rendered or rendered.count(preprod_base) != len(api_base_lines):
        fail("the preprod LiteLLM provider routes were not rendered exactly")
    write_file(SECRETS_DIR / "preprod-litellm-config.yaml", rendered, 0o644)


def render_preprod_alloy_config() -> None:
    """Render the normal Alloy policy with verified TLS for the local mock."""

    source = (COMPOSE_DIR / "alloy/config.alloy").read_text(encoding="utf-8")
    begin = "    // BEGIN AIGW MANAGED CRIBL TLS"
    end = "    // END AIGW MANAGED CRIBL TLS"
    if source.count(begin) != 1 or source.count(end) != 1:
        fail("the Alloy Cribl TLS markers changed")
    before, remainder = source.split(begin, 1)
    _old_block, after = remainder.split(end, 1)
    secure_block = """
    // BEGIN AIGW MANAGED CRIBL TLS
    tls {
      insecure             = false
      ca_file              = "/etc/ssl/certs/aigw-cribl-ca.pem"
      server_name          = "cribl-mock"
      insecure_skip_verify = false
      min_version          = "1.2"
    }
    // END AIGW MANAGED CRIBL TLS"""
    rendered = before + secure_block + after
    if "insecure = true" in rendered.split(begin, 1)[1].split(end, 1)[0]:
        fail("the preprod Alloy configuration retained plaintext Cribl export")
    write_file(SECRETS_DIR / "preprod-alloy-config.alloy", rendered, 0o644)


def render_edge_forwarder() -> None:
    """Write the preprod-only TLS passthrough for Docker Desktop.

    Docker Desktop cannot publish the same IPv4 host port from two containers.
    One Envoy container owns both exact loopback publications and forwards raw
    TLS to the two unchanged Traefik edges on their separate Docker networks.
    """

    configuration = """\
static_resources:
  listeners:
    - name: internal_tls_passthrough
      address:
        socket_address: { address: 0.0.0.0, port_value: 8443 }
      filter_chains:
        - filters:
            - name: envoy.filters.network.tcp_proxy
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
                stat_prefix: internal_tls_passthrough
                cluster: traefik_internal
    - name: adm_tls_passthrough
      address:
        socket_address: { address: 0.0.0.0, port_value: 9443 }
      filter_chains:
        - filters:
            - name: envoy.filters.network.tcp_proxy
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
                stat_prefix: adm_tls_passthrough
                cluster: traefik_adm
  clusters:
    - name: traefik_internal
      type: STRICT_DNS
      dns_lookup_family: V4_ONLY
      connect_timeout: 5s
      load_assignment:
        cluster_name: traefik_internal
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: { address: traefik-int, port_value: 443 }
    - name: traefik_adm
      type: STRICT_DNS
      dns_lookup_family: V4_ONLY
      connect_timeout: 5s
      load_assignment:
        cluster_name: traefik_adm
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: { address: traefik-adm, port_value: 443 }
"""
    write_file(SECRETS_DIR / "preprod-edge-forwarder.yaml", configuration, 0o644)


def digest_inputs() -> str:
    """Hash every immutable preprod bind with the production-safe walker."""

    sources = ["docker-compose.yml", "docker-compose.preprod.yml"]
    sources.extend(
        source
        for source in PREPROD_BIND_SOURCES
        if source not in PREPROD_RUNTIME_BIND_SOURCES
    )
    manifest = json.dumps({"preprod-stack": sources}, separators=(",", ":"))
    result = run(
        [
            sys.executable,
            "-I",
            str(REPO_ROOT / "scripts/compute-bind-source-digests.py"),
            str(COMPOSE_DIR.resolve()),
            manifest,
        ],
        input_text=static_hex("bind-source-digest", 64),
        capture=True,
        sensitive=True,
    )
    try:
        document = json.loads(result.stdout)
    except json.JSONDecodeError:
        fail("the preprod bind-source digest helper returned invalid JSON")
    digest = document.get("preprod-stack") if isinstance(document, dict) else None
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        fail("the preprod bind-source digest helper returned an invalid digest")
    return digest


def current_vault_token() -> str:
    if not ENV_FILE.exists():
        return ""
    for line in ENV_FILE.read_text().splitlines():
        if line.startswith("ROTATOR_VAULT_TOKEN="):
            return line.partition("=")[2]
    return ""


def environment_values(args: argparse.Namespace) -> dict[str, str]:
    subnet = args.subnet_octet
    digest = digest_inputs()
    values = {
        "DEPLOYMENT_PROFILE": "docker-preprod",
        "PLATFORM_AUTHORITATIVE_DNS_ENABLED": "false",
        "VAULT_UI_ENABLED": "false",
        "IDENTITY_LDAP_ENABLED": "true",
        "DOMAIN": args.domain,
        "ETH1_IP": "127.0.3.1",
        "ETH2_IP": "127.0.2.1",
        "DOCKER_DATA_ROOT": "/var/lib/docker",
        "TRAEFIK_INT_CHAT_IP": f"172.{subnet}.3.2",
        "TRAEFIK_INT_PORTAL_IP": f"172.{subnet}.4.2",
        "TRAEFIK_ADM_ADMIN_IP": f"172.{subnet}.5.2",
        "OAUTH2_PROXY_LITELLM_IP": f"172.{subnet}.5.3",
        "TRAEFIK_ADM_GRAFANA_IP": f"172.{subnet}.6.2",
        "OAUTH2_PROXY_GRAFANA_IP": f"172.{subnet}.6.3",
        "ENVOY_EGRESS_IP": f"172.{subnet}.0.2",
        "AIGW_EGRESS_SOURCE_DATE_EPOCH": "0",
        "AIGW_EGRESS_PROVIDERS": "anthropic",
        "AIGW_EGRESS_POLICY_SHA256": "8c553d83bc98edeee4e1157368b8620ec6234e557b59a8195be6390677cdada6",
        "ALLOY_INTERNAL_IP": f"172.{subnet}.2.2",
        "ALLOY_TELEMETRY_IP": f"172.{subnet}.13.2",
        "ALLOY_OBSERVABILITY_IP": f"172.{subnet}.15.2",
        "PROMETHEUS_OBSERVABILITY_IP": f"172.{subnet}.15.3",
        "PORTAL_KEY_DEFAULT_MAX_BUDGET": "none",
        "PORTAL_KEY_DEFAULT_TPM_LIMIT": "none",
        "PORTAL_KEY_DEFAULT_RPM_LIMIT": "none",
        "PORTAL_KEY_DEFAULT_DURATION": "none",
        "PORTAL_KEY_PROJECT_LIMITS": "{}",
        "PG_SUPER_PASSWORD": static_hex("pg-super"),
        "PG_LITELLM_PASSWORD": static_hex("pg-litellm"),
        "PG_KEYCLOAK_PASSWORD": static_hex("pg-keycloak"),
        "PG_ROTATOR_PASSWORD": static_hex("pg-rotator"),
        "PG_GRAFANA_RO_PASSWORD": static_hex("pg-grafana"),
        "KC_ADMIN_PASSWORD": "OnlyForTesting1!Keycloak",
        "KC_BOOTSTRAP_ADMIN_CLIENT_SECRET": static_hex("keycloak-bootstrap"),
        "LITELLM_MASTER_KEY": "sk-" + static_hex("litellm-master"),
        "LITELLM_SALT_KEY": static_hex("litellm-salt"),
        "LITELLM_UI_BREAKGLASS_PASSWORD": "OnlyForTesting1!LiteLLM",
        "REDIS_PASSWORD": static_hex("redis"),
        "WEBUI_LITELLM_KEY": "sk-" + static_hex("webui-litellm"),
        "WEBUI_SECRET_KEY": static_hex("webui-session"),
        "WEBUI_OIDC_CLIENT_SECRET": static_hex("webui-oidc"),
        "PORTAL_OIDC_CLIENT_SECRET": static_hex("portal-oidc"),
        "ADMIN_PORTAL_OIDC_CLIENT_SECRET": static_hex("admin-portal-oidc"),
        "OAUTH2_PROXY_CLIENT_SECRET": static_hex("oauth-client"),
        "VAULT_OIDC_CLIENT_SECRET": static_hex("vault-oidc"),
        "OAUTH2_PROXY_LITELLM_COOKIE_SECRET": static_hex("cookie-litellm", 32),
        "OAUTH2_PROXY_GRAFANA_COOKIE_SECRET": static_hex("cookie-grafana", 32),
        "OAUTH2_PROXY_PROMETHEUS_COOKIE_SECRET": static_hex("cookie-prometheus", 32),
        "OAUTH2_PROXY_VAULT_COOKIE_SECRET": static_hex("cookie-vault", 32),
        "PORTAL_SESSION_SECRET": static_hex("portal-session"),
        "ADMIN_PORTAL_SESSION_SECRET": static_hex("admin-session"),
        "ROTATOR_INTERNAL_TOKEN": static_hex("rotator-internal"),
        "PORTAL_IDENTITY_TOKEN": static_hex("portal-identity"),
        "ROTATOR_VAULT_TOKEN": current_vault_token(),
        "KC_CLIENT_ASSERTION_KEY_VAULT_PATH": "ai-gateway/anthropic-wif-client-key",
        "IDENTITY_CONTROLLER_KEY_VAULT_PATH": "ai-gateway/keycloak/identity-controller-key",
        "IDENTITY_STATE_VAULT_PATH": "ai-gateway/keycloak/identity-state",
        "BREAK_GLASS_ADMIN_ENABLED": "true",
        "BREAK_GLASS_ADMIN_VAULT_PATH": "ai-gateway/keycloak/break-glass-admin",
        "VAULT_OIDC_RP_VAULT_PATH": "ai-gateway/keycloak/vault-oidc-rp",
        "GRAFANA_ADMIN_PASSWORD": "OnlyForTesting1!Grafana",
        "CRIBL_OTLP_ENDPOINT": "cribl-mock:4317",
        "CRIBL_OTLP_INSECURE": "false",
        "CRIBL_OTLP_CA_FILE": "/etc/ssl/certs/aigw-cribl-ca.pem",
        "CRIBL_OTLP_SERVER_NAME": "cribl-mock",
        "PREPROD_PROJECT": args.project,
        "PREPROD_PREFIX": args.prefix,
        "PG_DATA_VOLUME_NAME": f"{args.project}_pg18_data",
        "PREPROD_HOST_UID": str(os.getuid()),
        "PREPROD_HOST_GID": str(os.getgid()),
        "PREPROD_DOCKER_ENDPOINT": local_docker_endpoint(),
        "PREPROD_WIF_ENVOY_IMAGE": envoy_base_image_reference(),
        "AIGW_PREPROD_CONFIG_DIGEST": digest,
    }
    for name in (
        "TRAEFIK_INT", "TRAEFIK_ADM", "LITELLM", "OPEN_WEBUI", "KEYCLOAK",
        "VAULT", "POSTGRES", "REDIS", "ALLOY", "PROMETHEUS", "LOKI",
        "GRAFANA", "CRIBL_MOCK", "SAMBA_AD", "KEY_ROTATOR_LDAP",
    ):
        values[f"AIGW_BIND_DIGEST_{name}"] = digest
    return values


def render_environment(args: argparse.Namespace) -> None:
    values = environment_values(args)
    content = "# Generated by ansible/preprod.yml. Test credentials only.\n"
    content += "".join(f"{name}={value}\n" for name, value in values.items())
    write_file(ENV_FILE, content, 0o600)


def prepare(args: argparse.Namespace) -> None:
    check_context(args)
    if shutil.which("openssl") is None:
        fail("openssl is required to create the local test CA")
    ensure_directory(SECRETS_DIR)
    ensure_directory(REALMS_DIR, 0o755)
    ensure_directory(EDGE_CERTS_DIR)
    prepare_certificates(args.domain)
    render_realms(args.domain)
    vendor_subnet = desired_networks(args)[f"{args.prefix}-net-vendor"][0]
    render_wif_mock_envoy(args.domain, vendor_subnet)
    render_preprod_litellm_config()
    render_preprod_alloy_config()
    render_edge_forwarder()
    write_file(SECRETS_DIR / "preprod-samba-admin-password", "OnlyForTesting1!DomainAdmin\n", 0o600, replace=False)
    write_file(SECRETS_DIR / "preprod-samba-bind-password", "OnlyForTesting1!LdapBind\n", 0o600, replace=False)
    write_file(SECRETS_DIR / "samba_user_preprod-admin_password", "OnlyForTesting1!PreprodAdmin\n", 0o600, replace=False)
    write_file(SECRETS_DIR / "samba_user_preprod-developer_password", "OnlyForTesting1!PreprodDeveloper\n", 0o600, replace=False)
    write_file(SECRETS_DIR / "samba_user_preprod-user_password", "OnlyForTesting1!PreprodUser\n", 0o600, replace=False)
    redis_password = static_hex("redis")
    redis_password_hash = hashlib.sha256(redis_password.encode()).hexdigest()
    # These values are fixed, local test credentials. Local preprod runs Redis
    # as the recorded checkout owner, so Docker Desktop can bind these files
    # without making the password readable by other users.
    write_file(SECRETS_DIR / "redis_password", redis_password + "\n", 0o600)
    write_file(
        SECRETS_DIR / "redis_users.acl",
        f"user default reset on #{redis_password_hash} ~* &* +@all\n",
        0o600,
    )
    jwks_path = SECRETS_DIR / "preprod-wif-jwks.json"
    if not jwks_path.exists():
        write_file(jwks_path, '{"keys":[]}\n', 0o600)
    render_environment(args)
    print("PREPROD_PREPARED")


def base_compose_model(args: argparse.Namespace) -> dict[str, Any]:
    command = [
        "docker", "--host", local_docker_endpoint(),
        "compose", "--project-name", args.project,
        "--env-file", str(ENV_FILE),
        "-f", str(COMPOSE_FILES[0]),
        "--profile", "*", "config", "--format", "json",
    ]
    result = run(command, capture=True)
    try:
        model = json.loads(result.stdout)
    except json.JSONDecodeError:
        fail("Docker Compose returned an invalid base model")
    if not isinstance(model, dict) or not isinstance(model.get("services"), dict):
        fail("Docker Compose returned an incomplete base model")
    return model


def canonical_seed_image(service_name: str, service: dict[str, Any]) -> str:
    """Return the canonical release tag used by the production build planner."""

    image = service.get("image")
    if image is None:
        return f"{PRODUCTION_COMPOSE_PROJECT}-{service_name}"
    if not isinstance(image, str) or not image:
        fail(f"the production image name for {service_name} is invalid")
    return image


def seed_egress_policy(receipt: dict[str, Any]) -> dict[str, Any]:
    """Return the loader-verified policy after checking its release binding."""

    policy = receipt.get("egress_policy")
    custom_images = receipt.get("custom_images")
    if not isinstance(policy, dict) or not isinstance(custom_images, dict):
        fail("the offline seed receipt has no immutable Envoy policy")
    required = {
        "schema_version",
        "egress_policy_sha256",
        "envoy_config_sha256",
        "selected_providers",
        "providers",
        "envoy_image_id",
    }
    selected = policy.get("selected_providers")
    providers = policy.get("providers")
    envoy = custom_images.get(ENVOY_EGRESS_IMAGE)
    if (
        set(policy) != required
        or policy.get("schema_version") != 1
        or not isinstance(selected, list)
        or not selected
        or selected != sorted(set(selected))
        or any(
            not isinstance(name, str)
            or re.fullmatch(r"[a-z][a-z0-9-]{0,31}", name) is None
            for name in selected
        )
        or not isinstance(providers, list)
        or len(providers) != len(selected)
        or any(not isinstance(record, dict) for record in providers)
        or [record.get("name") for record in providers if isinstance(record, dict)]
        != selected
        or not isinstance(envoy, dict)
        or policy.get("envoy_image_id") != envoy.get("image_id")
        or not isinstance(policy.get("egress_policy_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", policy["egress_policy_sha256"]) is None
    ):
        fail("the offline seed Envoy policy is malformed or not bound to its image")
    return policy


def seed_service_images(
    model: dict[str, Any], receipt: dict[str, Any]
) -> dict[str, str]:
    """Map every preprod service to one image already verified by the loader."""

    services = model.get("services")
    custom_images = receipt.get("custom_images")
    external_images = receipt.get("external_images")
    if not isinstance(services, dict) or not services:
        fail("the production Compose model has no services")
    if not isinstance(custom_images, dict) or not isinstance(external_images, dict):
        fail("the offline seed receipt has no complete image inventory")

    service_images: dict[str, str] = {}
    for service_name, service in services.items():
        if not isinstance(service_name, str) or not isinstance(service, dict):
            fail("the production Compose model has an invalid service")
        if "build" in service:
            canonical_image = canonical_seed_image(service_name, service)
            record = custom_images.get(canonical_image)
            if not isinstance(record, dict):
                fail(f"the offline seed has no custom image for service {service_name}")
            archive_reference = record.get("archive_reference")
            if record.get("target_activation") != "active-compose":
                fail(f"service {service_name} is not an active Compose seed image")
            if not isinstance(archive_reference, str) or not (
                CUSTOM_TRANSFER_REFERENCE_RE.fullmatch(archive_reference)
            ):
                fail(f"the seed transfer reference for {service_name} is invalid")
            service_images[service_name] = archive_reference
            continue

        reference = service.get("image")
        if not isinstance(reference, str) or not (
            EXTERNAL_IMAGE_REFERENCE_RE.fullmatch(reference)
        ):
            fail(f"service {service_name} has no exact external image pin")
        expected_id = external_images.get(reference)
        if not isinstance(expected_id, str) or not IMAGE_ID_RE.fullmatch(expected_id):
            fail(f"the offline seed has no external image for service {service_name}")
        service_images[service_name] = reference

    if set(service_images) != set(services):
        fail("the seed image overlay does not cover every production service")

    preprod_only_images = {
        "samba-ad": "ai-gateway/samba-ad:preprod",
        "wif-provider-mock": "ai-gateway/wif-provider-mock:preprod",
    }
    for service_name, canonical_tag in preprod_only_images.items():
        if service_name in service_images:
            fail(f"the preprod-only service name collides with {service_name}")
        record = custom_images.get(canonical_tag)
        if not isinstance(record, dict):
            fail(f"the offline seed has no preprod image for {service_name}")
        archive_reference = record.get("archive_reference")
        if (
            record.get("deployment_scope") != "preprod-only"
            or record.get("target_activation") != "archive-only"
        ):
            fail(f"the {service_name} image has an unsafe deployment scope")
        if not isinstance(archive_reference, str) or not (
            CUSTOM_TRANSFER_REFERENCE_RE.fullmatch(archive_reference)
        ):
            fail(f"the seed transfer reference for {service_name} is invalid")
        service_images[service_name] = archive_reference

    wif_envoy_image = preprod_env_value("PREPROD_WIF_ENVOY_IMAGE")
    expected_wif_envoy_id = external_images.get(wif_envoy_image)
    if (
        EXTERNAL_IMAGE_REFERENCE_RE.fullmatch(wif_envoy_image) is None
        or not isinstance(expected_wif_envoy_id, str)
        or IMAGE_ID_RE.fullmatch(expected_wif_envoy_id) is None
    ):
        fail("the offline seed has no exact Envoy base image for the WIF mock proxy")
    for service_name in ("preprod-edge-forwarder", "wif-egress-mock"):
        if service_name in service_images:
            fail(f"the preprod Envoy service collides with {service_name}")
        service_images[service_name] = wif_envoy_image
    return service_images


def rendered_compose_model(args: argparse.Namespace) -> dict[str, Any]:
    result = compose(args, "config", "--format", "json", capture=True)
    try:
        model = json.loads(result.stdout)
    except json.JSONDecodeError:
        fail("Docker Compose returned an invalid preprod model")
    if not isinstance(model, dict) or not isinstance(model.get("services"), dict):
        fail("Docker Compose returned an incomplete preprod model")
    return model


def verify_rendered_resource_ownership(
    args: argparse.Namespace, model: dict[str, Any]
) -> set[str]:
    """Require the rendered model to keep every mutable resource in preprod."""

    services = model.get("services")
    networks = model.get("networks")
    volumes = model.get("volumes")
    if not isinstance(services, dict) or not isinstance(networks, dict):
        fail("the rendered preprod model has no complete resource inventory")
    if not isinstance(volumes, dict) or not volumes:
        fail("the rendered preprod model has no volume inventory")

    expected_config_digest = preprod_env_value("AIGW_PREPROD_CONFIG_DIGEST")
    if re.fullmatch(r"[0-9a-f]{64}", expected_config_digest) is None:
        fail("the preprod environment has no valid complete configuration digest")
    for service_name, definition in services.items():
        labels = definition.get("labels") if isinstance(definition, dict) else None
        if (
            not isinstance(labels, dict)
            or labels.get("com.aigw.preprod.project") != args.project
        ):
            fail(f"preprod service {service_name} has no exact ownership label")
        if labels.get("com.aigw.preprod.config-digest") != expected_config_digest:
            fail(f"preprod service {service_name} has no exact configuration digest")

    alloy_mounts = services.get("alloy", {}).get("volumes") or []
    alloy_security = services.get("alloy", {}).get("security_opt") or []
    if "label=disable" in alloy_security:
        fail("preprod Alloy must keep SELinux process isolation enabled")
    alloy_log_mounts = [
        mount
        for mount in alloy_mounts
        if isinstance(mount, dict)
        and mount.get("target") == "/var/lib/docker/containers"
    ]
    if len(alloy_log_mounts) != 1 or (
        alloy_log_mounts[0].get("type") != "volume"
        or alloy_log_mounts[0].get("source") != "preprod_empty_docker_logs"
        or alloy_log_mounts[0].get("read_only") is not True
    ):
        fail("preprod Alloy must use only its owned security-fixture log volume")
    node_mounts = services.get("node-exporter", {}).get("volumes") or []
    if any(
        isinstance(mount, dict) and mount.get("target") == "/host"
        for mount in node_mounts
    ):
        fail("preprod node-exporter must not mount the local host root")

    bind_consumers: dict[str, set[str]] = {}
    bind_mounts: list[tuple[str, dict[str, Any]]] = []
    for service_name, definition in services.items():
        service_volumes = definition.get("volumes") if isinstance(definition, dict) else []
        for mount in service_volumes or []:
            if not isinstance(mount, dict) or mount.get("type") != "bind":
                continue
            source = mount.get("source")
            if not isinstance(source, str) or not Path(source).is_absolute():
                fail(f"preprod service {service_name} has a noncanonical bind source")
            if mount.get("read_only") is not True:
                fail(f"preprod service {service_name} has a writable bind source")
            bind_consumers.setdefault(source, set()).add(service_name)
            bind_mounts.append((service_name, mount))

    expected_bind_sources = {
        str((COMPOSE_DIR / relative).resolve(strict=True))
        for relative in PREPROD_BIND_SOURCES
    }
    if set(bind_consumers) != expected_bind_sources:
        fail("the rendered bind sources differ from the complete preprod digest inventory")
    for service_name, mount in bind_mounts:
        source = mount["source"]
        expected_selinux = "z" if len(bind_consumers[source]) > 1 else "Z"
        bind_options = mount.get("bind")
        actual_selinux = bind_options.get("selinux") if isinstance(bind_options, dict) else None
        if actual_selinux != expected_selinux:
            fail(
                f"preprod service {service_name} bind source has the wrong SELinux relabel"
            )

    expected_network_names = set(desired_networks(args))
    rendered_network_names = {
        definition.get("name")
        for definition in networks.values()
        if isinstance(definition, dict)
    }
    if rendered_network_names != expected_network_names:
        fail("the rendered preprod network names escaped the fixed resource prefix")

    expected_volume_names: set[str] = set()
    for volume_name, definition in volumes.items():
        if not isinstance(definition, dict):
            fail(f"preprod volume {volume_name} has an invalid definition")
        rendered_name = definition.get("name")
        labels = definition.get("labels")
        if volume_name == "pg_data":
            expected_name = f"{args.project}_pg18_data"
            if preprod_env_value("PG_DATA_VOLUME_NAME") != expected_name:
                fail("the preprod PostgreSQL volume selector escaped its fixed project")
        else:
            expected_name = f"{args.project}_{volume_name}"
        if rendered_name != expected_name:
            fail(f"preprod volume {volume_name} escaped the fixed Docker project")
        if (
            not isinstance(labels, dict)
            or labels.get("com.aigw.preprod.project") != args.project
        ):
            fail(f"preprod volume {volume_name} has no exact ownership label")
        expected_volume_names.add(expected_name)
    return expected_volume_names


def source_build_targets(
    args: argparse.Namespace, model: dict[str, Any]
) -> set[str]:
    """Return source-build tags after checking their reserved namespace labels."""

    services = model.get("services")
    if not isinstance(services, dict):
        fail("the rendered preprod model has no service inventory")
    expected_owner = args.project
    expected_pattern = re.compile(
        rf"^{re.escape(args.project)}/[a-z0-9][a-z0-9_.-]*:local$"
    )
    targets: set[str] = set()
    for service_name, definition in services.items():
        if not isinstance(definition, dict) or "build" not in definition:
            continue
        build_config = definition.get("build")
        image = definition.get("image")
        if not isinstance(build_config, dict) or not isinstance(image, str):
            fail(f"preprod service {service_name} has an invalid source build")
        labels = build_config.get("labels")
        if (
            not isinstance(labels, dict)
            or labels.get("com.aigw.preprod.image-owner") != expected_owner
        ):
            fail(f"preprod service {service_name} has no source-image owner label")
        if expected_pattern.fullmatch(image) is None:
            fail(f"preprod service {service_name} escaped the source-image namespace")
        targets.add(image)
    if not targets:
        fail("the rendered preprod model has no source-build images")
    return targets


def verify_source_image_boundary(
    args: argparse.Namespace,
    model: dict[str, Any],
    *,
    require_all: bool,
) -> None:
    """Refuse to overwrite or run an image not owned by this preprod project."""

    targets = source_build_targets(args, model)
    listed = set(
        docker(
            "image", "ls", "--format", "{{.Repository}}:{{.Tag}}", capture=True
        ).stdout.splitlines()
    )
    for reference in sorted(targets):
        if reference not in listed:
            if require_all:
                fail(f"the owned preprod source image is missing: {reference}")
            continue
        raw_labels = docker(
            "image", "inspect", reference,
            "--format", "{{json .Config.Labels}}",
            capture=True,
        ).stdout.strip()
        try:
            labels = json.loads(raw_labels)
        except json.JSONDecodeError:
            fail(f"the preprod source image has invalid labels: {reference}")
        if (
            not isinstance(labels, dict)
            or labels.get("com.aigw.preprod.image-owner") != args.project
        ):
            fail(f"refusing an unowned image in the preprod namespace: {reference}")


def verify_existing_project_boundary(
    args: argparse.Namespace, expected_volume_names: set[str]
) -> None:
    """Refuse to mutate an existing container or volume we do not own."""

    container_ids = docker(
        "ps", "-a", "--format", "{{.ID}}", capture=True
    ).stdout.splitlines()
    for container_id in container_ids:
        documents = json.loads(docker("inspect", container_id, capture=True).stdout)
        document = documents[0]
        name = str(document.get("Name", "")).removeprefix("/")
        labels = document.get("Config", {}).get("Labels") or {}
        compose_project = labels.get("com.docker.compose.project")
        owner = labels.get("com.aigw.preprod.project")
        belongs = (
            compose_project == args.project
            or owner == args.project
            or name.startswith(args.project + "-")
        )
        if belongs and (compose_project != args.project or owner != args.project):
            fail(f"refusing unowned container in the preprod namespace: {name}")

    volume_names = docker(
        "volume", "ls", "--format", "{{.Name}}", capture=True
    ).stdout.splitlines()
    for volume_name in volume_names:
        documents = json.loads(
            docker("volume", "inspect", volume_name, capture=True).stdout
        )
        document = documents[0]
        labels = document.get("Labels") or {}
        compose_project = labels.get("com.docker.compose.project")
        owner = labels.get("com.aigw.preprod.project")
        belongs = (
            volume_name in expected_volume_names
            or compose_project == args.project
            or owner == args.project
            or volume_name.startswith(args.project + "_")
        )
        if belongs and (compose_project != args.project or owner != args.project):
            fail(f"refusing unowned volume in the preprod namespace: {volume_name}")


def _activate_seed(args: argparse.Namespace) -> None:
    check_context(args)
    loader = REPO_ROOT / "scripts/load-offline-image-seed.py"
    command = [
        sys.executable,
        "-I",
        str(loader),
        "local-release-receipt",
        str(Path(args.archive).resolve()),
        str(Path(args.manifest).resolve()),
        args.manifest_sha256,
        str(REPO_ROOT),
    ]
    result = run(command, capture=True)
    try:
        receipt = json.loads(result.stdout)
    except json.JSONDecodeError:
        fail("the offline seed loader returned an invalid release receipt")
    if receipt.get("schema_version") != 2:
        fail("preprod seed mode requires a schema-v2 release receipt")
    policy = seed_egress_policy(receipt)

    values = environment_values(args)
    values["AIGW_EGRESS_SOURCE_DATE_EPOCH"] = "0"
    values["AIGW_EGRESS_PROVIDERS"] = ",".join(policy["selected_providers"])
    values["AIGW_EGRESS_POLICY_SHA256"] = policy["egress_policy_sha256"]
    content = "# Generated by ansible/preprod.yml. Test credentials only.\n"
    content += "".join(f"{name}={value}\n" for name, value in values.items())
    write_file(ENV_FILE, content, 0o600)

    model = base_compose_model(args)
    service_images = seed_service_images(model, receipt)
    build_services = {
        service_name
        for service_name, service in model["services"].items()
        if isinstance(service, dict) and "build" in service
    }
    build_services.update({"samba-ad", "wif-provider-mock"})

    lines = ["# Generated from a verified offline-seed release receipt.", "services:"]
    for service_name, image in sorted(service_images.items()):
        lines.extend(
            [
                f"  {service_name}:",
                f"    image: {image}",
                "    pull_policy: never",
            ]
        )
        if service_name in build_services:
            lines.append("    build: !reset null")
    write_file(SEED_RECEIPT, json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n", 0o644)
    write_file(SEED_OVERLAY, "\n".join(lines) + "\n", 0o644)
    verify_seed_images(args)
    print("PREPROD_SEED_ACTIVATED")


def recorded_preprod_owner() -> tuple[int, int]:
    """Return the non-root owner recorded when preprod was prepared."""

    try:
        repo_metadata = REPO_ROOT.lstat()
        env_metadata = ENV_FILE.lstat()
    except FileNotFoundError as exc:
        fail(f"preprod ownership metadata is missing: {exc.filename}")
    if not stat.S_ISDIR(repo_metadata.st_mode) or stat.S_ISLNK(repo_metadata.st_mode):
        fail("the preprod source checkout must be a real directory")
    if not stat.S_ISREG(env_metadata.st_mode) or stat.S_ISLNK(env_metadata.st_mode):
        fail("the preprod environment must be a regular file, not a symlink")
    if env_metadata.st_nlink != 1 or stat.S_IMODE(env_metadata.st_mode) != 0o600:
        fail("the preprod environment must have one link and mode 0600")

    values: dict[str, str] = {}
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        name, separator, value = line.partition("=")
        if separator and name in {"PREPROD_HOST_UID", "PREPROD_HOST_GID"}:
            if name in values:
                fail(f"the preprod environment repeats {name}")
            values[name] = value
    uid_text = values.get("PREPROD_HOST_UID", "")
    gid_text = values.get("PREPROD_HOST_GID", "")
    if re.fullmatch(r"[1-9][0-9]{0,9}", uid_text) is None:
        fail("PREPROD_HOST_UID must be one non-root decimal user ID")
    if re.fullmatch(r"[0-9]{1,10}", gid_text) is None:
        fail("PREPROD_HOST_GID must be one decimal group ID")
    uid = int(uid_text)
    gid = int(gid_text)
    if uid > 2_147_483_647 or gid > 2_147_483_647:
        fail("the recorded preprod user or group ID is outside the supported range")
    if (env_metadata.st_uid, env_metadata.st_gid) != (uid, gid):
        fail("the preprod environment owner differs from its recorded owner")
    if (repo_metadata.st_uid, repo_metadata.st_gid) != (uid, gid):
        fail("the source checkout owner differs from the recorded preprod owner")
    return uid, gid


def seed_output_files() -> tuple[Path, Path]:
    return SEED_RECEIPT, SEED_OVERLAY


def activate_seed(args: argparse.Namespace) -> None:
    if os.geteuid() == 0:
        fail("preprod seed activation must run as the recorded non-root operator")
    uid, gid = recorded_preprod_owner()
    if (os.geteuid(), os.getegid()) != (uid, gid):
        fail("preprod seed activation must run as the recorded checkout owner")
    _activate_seed(args)


def verify_seed_images(args: argparse.Namespace) -> None:
    if not SEED_RECEIPT.is_file() or not SEED_OVERLAY.is_file():
        fail("the preprod seed receipt or image overlay is missing")
    try:
        receipt = json.loads(SEED_RECEIPT.read_text())
    except json.JSONDecodeError:
        fail("the preprod seed receipt is invalid")
    custom_images = receipt.get("custom_images")
    external_images = receipt.get("external_images")
    if not isinstance(custom_images, dict) or not custom_images:
        fail("the preprod seed receipt has no custom images")
    if not isinstance(external_images, dict) or not external_images:
        fail("the preprod seed receipt has no external images")
    policy = seed_egress_policy(receipt)
    if (
        preprod_env_value("AIGW_EGRESS_SOURCE_DATE_EPOCH") != "0"
        or preprod_env_value("AIGW_EGRESS_PROVIDERS")
        != ",".join(policy["selected_providers"])
        or preprod_env_value("AIGW_EGRESS_POLICY_SHA256")
        != policy["egress_policy_sha256"]
    ):
        fail("the preprod environment does not match the seed Envoy policy")
    for canonical, record in sorted(custom_images.items()):
        if not isinstance(record, dict):
            fail(f"the seed record for {canonical} is invalid")
        reference = record.get("archive_reference")
        expected_id = record.get("image_id")
        if not isinstance(reference, str) or not isinstance(expected_id, str):
            fail(f"the seed record for {canonical} is incomplete")
        result = docker("image", "inspect", reference, "--format", "{{.Id}}", capture=True)
        if result.stdout.strip() != expected_id:
            fail(f"the loaded image ID does not match the release receipt: {canonical}")

    envoy = custom_images[ENVOY_EGRESS_IMAGE]
    runtime = docker(
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--user",
        "65532:65532",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        envoy["archive_reference"],
        "receipt",
        capture=True,
    )
    try:
        live_policy = json.loads(runtime.stdout)
    except json.JSONDecodeError:
        fail("the seeded Envoy image returned an invalid policy receipt")
    expected_policy = dict(policy)
    del expected_policy["envoy_image_id"]
    if live_policy != expected_policy:
        fail("the seeded Envoy image policy differs from the release receipt")
    for reference, expected_id in sorted(external_images.items()):
        if not isinstance(reference, str) or not isinstance(expected_id, str):
            fail("the seed external-image receipt is invalid")
        result = docker("image", "inspect", reference, "--format", "{{.Id}}", capture=True)
        if result.stdout.strip() != expected_id:
            fail(f"the loaded external image ID does not match the release receipt: {reference}")


def desired_networks(args: argparse.Namespace) -> dict[str, tuple[str, bool]]:
    result = {}
    for suffix, (index, internal) in NETWORKS.items():
        # The exact production Envoy image admits only the reviewed production
        # vendor CIDR. Preprod uses that one CIDR so it tests the immutable
        # image and its firewall ABI; every other namespaced network stays on
        # the separate 172.29 test range.
        subnet = (
            PRODUCTION_VENDOR_SUBNET
            if suffix == "net-vendor"
            else f"172.{args.subnet_octet}.{index}.0/24"
        )
        result[f"{args.prefix}-{suffix}"] = (subnet, internal)
    return result


def existing_networks() -> dict[str, dict[str, Any]]:
    names = docker("network", "ls", "--format", "{{.Name}}", capture=True).stdout.splitlines()
    result: dict[str, dict[str, Any]] = {}
    for name in names:
        raw = docker("network", "inspect", name, capture=True).stdout
        result[name] = json.loads(raw)[0]
    return result


def network_subnets(document: dict[str, Any]) -> list[str]:
    configuration = document.get("IPAM", {}).get("Config") or []
    return [item["Subnet"] for item in configuration if item.get("Subnet")]


def network_ip_ranges(document: dict[str, Any]) -> list[str]:
    configuration = document.get("IPAM", {}).get("Config") or []
    return [item["IPRange"] for item in configuration if item.get("IPRange")]


def dynamic_ip_range(subnet: str) -> str:
    """Keep automatic addresses away from reviewed low fixed addresses."""

    network = ipaddress.ip_network(subnet)
    if network.prefixlen != 24:
        fail("preprod Docker networks must use /24 subnets")
    return str(list(network.subnets(new_prefix=25))[1])


def create_networks(args: argparse.Namespace) -> None:
    check_context(args)
    existing = existing_networks()
    desired = desired_networks(args)
    for name, (subnet, internal) in desired.items():
        if name in existing:
            document = existing[name]
            subnets = network_subnets(document)
            ip_ranges = network_ip_ranges(document)
            labels = document.get("Labels") or {}
            if (
                subnets != [subnet]
                or ip_ranges != [dynamic_ip_range(subnet)]
                or bool(document.get("Internal")) is not internal
                or labels.get("com.aigw.preprod.project") != args.project
                or document.get("Driver") != "bridge"
                or document.get("Scope") != "local"
            ):
                fail(f"existing preprod network {name} has the wrong ownership or settings")
            for container_id in (document.get("Containers") or {}):
                containers = json.loads(
                    docker("inspect", container_id, capture=True).stdout
                )
                container_labels = containers[0].get("Config", {}).get("Labels") or {}
                if (
                    container_labels.get("com.docker.compose.project") != args.project
                    or container_labels.get("com.aigw.preprod.project") != args.project
                ):
                    fail(f"existing preprod network {name} has an unowned endpoint")
            continue
        requested = ipaddress.ip_network(subnet)
        for other_name, document in existing.items():
            other_subnets = network_subnets(document)
            for other_subnet in other_subnets:
                if requested.overlaps(ipaddress.ip_network(other_subnet)):
                    fail(f"subnet {subnet} overlaps existing Docker network {other_name}")
        command = [
            "network", "create", "--driver", "bridge", "--subnet", subnet,
            "--ip-range", dynamic_ip_range(subnet),
            "--label", f"com.aigw.preprod.project={args.project}",
        ]
        if internal:
            command.append("--internal")
        command.append(name)
        docker(*command)
        existing[name] = json.loads(
            docker("network", "inspect", name, capture=True).stdout
        )[0]
    print("PREPROD_NETWORKS_READY")


def compose_config(args: argparse.Namespace) -> None:
    check_context(args)
    if not ENV_FILE.exists():
        fail("run the prepare step first")
    if args.image_mode == "seed":
        verify_seed_images(args)
    model = rendered_compose_model(args)
    verify_rendered_resource_ownership(args, model)
    if args.image_mode == "source":
        source_build_targets(args, model)
    compose(args, "config", "--quiet")
    print("PREPROD_COMPOSE_VALID")


def build(args: argparse.Namespace) -> None:
    check_context(args)
    if args.image_mode == "seed":
        fail("seed image mode never rebuilds images")
    model = rendered_compose_model(args)
    verify_source_image_boundary(args, model, require_all=False)
    command = ["build"]
    if args.pull:
        command.append("--pull")
    compose(args, *command)
    verify_source_image_boundary(args, model, require_all=True)
    print("PREPROD_IMAGES_BUILT")


def pull(args: argparse.Namespace) -> None:
    check_context(args)
    if args.image_mode == "seed":
        fail("seed image mode never pulls images")
    compose(args, "pull", "--ignore-buildable")
    print("PREPROD_IMAGES_PULLED")


def reconcile_postgres(args: argparse.Namespace, phase: str) -> None:
    """Run the reviewed idempotent database reconciler and validate its receipt."""

    result = compose(
        args,
        "exec", "-T", "postgres", POSTGRES_RECONCILE_SCRIPT,
        capture=True,
        sensitive=True,
    )
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    receipts = [line for line in lines if line in POSTGRES_RECONCILE_RESULTS]
    if len(receipts) != 1 or not lines or lines[-1] != receipts[0]:
        fail("the PostgreSQL reconciler returned an invalid receipt")
    print(f"PREPROD_POSTGRES_RECONCILED phase={phase} result={receipts[0]}")


def stage_postgres_before_consumers(args: argparse.Namespace) -> None:
    """Create/reconcile the databases before any direct DB consumer starts."""

    # The DHI entrypoint initializes PGDATA but does not promise compatibility
    # with the Docker Hub image's /docker-entrypoint-initdb.d hook contract.
    # Stop only this Compose project's direct consumers, start PostgreSQL with
    # its volume-init dependency, then explicitly execute the same idempotent
    # reconciler used by the production Ansible converge.
    compose(args, "stop", "--timeout", "30", *POSTGRES_DIRECT_CONSUMERS)
    compose(args, "up", "-d", "postgres")
    wait_for_container(args, "postgres", "healthy", 300)
    reconcile_postgres(args, "before-consumers")


def start(args: argparse.Namespace) -> None:
    check_context(args)
    if args.image_mode == "seed":
        verify_seed_images(args)
    model = rendered_compose_model(args)
    if args.image_mode == "source":
        verify_source_image_boundary(args, model, require_all=True)
    expected_volume_names = verify_rendered_resource_ownership(args, model)
    verify_existing_project_boundary(args, expected_volume_names)
    stage_postgres_before_consumers(args)
    compose(args, "up", "-d", "--remove-orphans")
    verify_existing_project_boundary(args, expected_volume_names)
    wait_for_container(args, "traefik-int", "healthy", 300)
    wait_for_container(args, "traefik-adm", "healthy", 300)
    # Docker Desktop can leave the passthrough proxy with unusable upstream
    # sockets even though its configuration-only healthcheck is green. Restart
    # it after both Traefik edges are ready, then prove both real TLS routes.
    compose(
        args,
        "restart",
        "--no-deps",
        "--timeout",
        "30",
        "preprod-edge-forwarder",
    )
    wait_for_container(args, "preprod-edge-forwarder", "healthy", 120)
    wait_for_container(args, "samba-ad", "healthy", 300)
    wait_for_container(args, "litellm", "healthy", 600)
    wait_for_container(args, "keycloak", "healthy", 600)
    verify_edge_routes(args)
    wait_for_container(args, "key-rotator", "running", 300)
    # LiteLLM creates its reporting tables during startup. A second idempotent
    # pass installs the reviewed column-only Grafana grants on a clean stack.
    reconcile_postgres(args, "after-litellm-migrations")
    print("PREPROD_STACK_STARTED")


def container_state(args: argparse.Namespace, service: str) -> tuple[str, str]:
    identifier = compose(args, "ps", "-q", service, capture=True).stdout.strip()
    if not identifier:
        return "missing", ""
    raw = docker("inspect", identifier, capture=True).stdout
    state = json.loads(raw)[0]["State"]
    return state.get("Status", ""), state.get("Health", {}).get("Status", "")


def verify_volume_init(args: argparse.Namespace) -> None:
    identifiers = compose(
        args, "ps", "-a", "-q", "volume-init", capture=True
    ).stdout.splitlines()
    if len(identifiers) != 1 or not identifiers[0].strip():
        fail("preprod volume-init does not have one completed container")
    try:
        documents = json.loads(
            docker("inspect", identifiers[0].strip(), capture=True).stdout
        )
        state = documents[0]["State"]
    except (json.JSONDecodeError, IndexError, KeyError, TypeError):
        fail("Docker returned invalid volume-init state")
    if state.get("Status") != "exited" or state.get("ExitCode") != 0:
        fail("preprod volume-init did not exit successfully")


def wait_for_container(args: argparse.Namespace, service: str, wanted: str, timeout: int) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status, health = container_state(args, service)
        if wanted == "running" and status == "running":
            return
        if wanted == "healthy" and health == "healthy":
            return
        if status in {"dead", "exited", "removing"} or health == "unhealthy":
            fail(f"preprod service {service} entered state status={status} health={health}")
        time.sleep(3)
    fail(f"timed out waiting for preprod service {service} to become {wanted}")


def edge_json(hostname: str, address: str, path: str) -> object:
    """Read one fixed preprod TLS route without using local curl settings."""

    approved = {
        ("api.aigw.internal", "127.0.2.1", "/health/liveliness"),
        (
            "auth.aigw.internal",
            "127.0.3.1",
            "/realms/aigw/.well-known/openid-configuration",
        ),
    }
    if (hostname, address, path) not in approved:
        fail("the preprod edge verifier received an unapproved route")
    result = run(
        [
            "curl",
            "--disable",
            "--silent",
            "--show-error",
            "--fail-with-body",
            "--http1.1",
            "--connect-timeout",
            "5",
            "--max-time",
            "15",
            "--max-filesize",
            str(EDGE_RESPONSE_MAX_BYTES),
            "--noproxy",
            "*",
            "--proto",
            "=https",
            "--cacert",
            str(PREPROD_ROOT_CA_FILE),
            "--resolve",
            f"{hostname}:443:{address}",
            f"https://{hostname}{path}",
        ],
        capture=True,
    )
    response_size = len(result.stdout.encode("utf-8"))
    if not result.stdout or response_size > EDGE_RESPONSE_MAX_BYTES:
        fail(f"{hostname}{path} returned an invalid response size")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        fail(f"{hostname}{path} returned invalid JSON")


def verify_edge_routes(_: argparse.Namespace) -> None:
    """Prove that both loopback planes reach the intended TLS services."""

    api_health = edge_json(
        "api.aigw.internal", "127.0.2.1", "/health/liveliness"
    )
    if api_health != "I'm alive!":
        fail("the preprod API edge returned the wrong health response")
    discovery = edge_json(
        "auth.aigw.internal",
        "127.0.3.1",
        "/realms/aigw/.well-known/openid-configuration",
    )
    if not isinstance(discovery, dict) or discovery.get("issuer") != (
        "https://auth.aigw.internal/realms/aigw"
    ):
        fail("the preprod identity edge returned the wrong issuer")
    print("PREPROD_EDGE_ROUTES_VERIFIED")


def vault_call(
    args: argparse.Namespace,
    method: str,
    path: str,
    *,
    body: Any | None = None,
    token: str = "",
) -> tuple[int, Any]:
    request: dict[str, Any] = {"method": method, "path": path}
    if body is not None:
        request["body"] = body
    if token:
        request["token"] = token
    result = compose(
        args,
        # Compose v5.3 no longer forwards piped stdin to `compose run`, even
        # with --interactive. The stack start gate already proves this
        # container is running, so exec keeps the secret-bearing request on
        # stdin without creating a second container.
        "exec", "-T", "key-rotator", "/opt/venv/bin/python", "-c",
        VAULT_HTTP_HELPER,
        input_text=json.dumps(request, separators=(",", ":")),
        capture=True,
        sensitive=True,
    )
    try:
        response = json.loads(result.stdout)
        return int(response["status"]), response["body"]
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        fail("the local Vault helper returned an invalid response")


def wait_for_vault(args: argparse.Namespace) -> dict[str, Any]:
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            status, body = vault_call(args, "GET", "/v1/sys/health")
        except SystemExit:
            time.sleep(3)
            continue
        if status in {200, 429, 472, 473, 501, 503} and isinstance(body, dict):
            return body
        time.sleep(3)
    fail("Vault did not answer its local health endpoint")


def load_vault_init() -> dict[str, Any]:
    if not VAULT_INIT_FILE.exists():
        fail("Vault is initialized but its local preprod recovery file is missing")
    mode = stat.S_IMODE(VAULT_INIT_FILE.stat().st_mode)
    if mode != 0o600:
        fail("the local preprod Vault recovery file must have mode 0600")
    document = json.loads(VAULT_INIT_FILE.read_text())
    if not document.get("root_token") or len(document.get("keys_base64", [])) != 1:
        fail("the local preprod Vault recovery file is invalid")
    return document


def bootstrap_vault(args: argparse.Namespace) -> None:
    check_context(args)
    if args.image_mode == "seed":
        verify_seed_images(args)
    health = wait_for_vault(args)
    if health.get("initialized") is False:
        if VAULT_INIT_FILE.exists():
            fail("Vault is fresh but an old recovery file exists; run preprod-destroy.yml")
        status, document = vault_call(
            args,
            "PUT",
            "/v1/sys/init",
            body={"secret_shares": 1, "secret_threshold": 1},
        )
        if status != 200 or not isinstance(document, dict):
            fail("Vault initialization failed")
        write_file(VAULT_INIT_FILE, json.dumps(document, separators=(",", ":")) + "\n", 0o600)
    document = load_vault_init()
    health = wait_for_vault(args)
    if health.get("sealed") is True:
        status, body = vault_call(
            args,
            "PUT",
            "/v1/sys/unseal",
            body={"key": document["keys_base64"][0]},
        )
        if status != 200 or body.get("sealed") is not False:
            fail("Vault did not accept the local preprod unseal share")

    root_token = document["root_token"]
    desired_audit = {
        "file_path": "/vault/logs/audit.log",
        "format": "json",
        "hmac_accessor": "true",
        "log_raw": "false",
        "mode": "0640",
    }
    status, audit_devices = vault_call(
        args, "GET", "/v1/sys/audit", token=root_token
    )
    if status != 200 or not isinstance(audit_devices, dict):
        fail("Vault audit-device inspection failed")
    file_audit = audit_devices.get("file/")
    if file_audit is None:
        status, _ = vault_call(
            args,
            "PUT",
            "/v1/sys/audit/file",
            body={"type": "file", "options": desired_audit},
            token=root_token,
        )
        if status not in {200, 204}:
            fail("Vault file audit-device setup failed")
    status, audit_devices = vault_call(
        args, "GET", "/v1/sys/audit", token=root_token
    )
    file_audit = audit_devices.get("file/") if isinstance(audit_devices, dict) else None
    options = file_audit.get("options") if isinstance(file_audit, dict) else None
    if (
        status != 200
        or not isinstance(file_audit, dict)
        or file_audit.get("type") != "file"
        or not isinstance(options, dict)
        or any(
            str(options.get(key, "")).lower() != value
            for key, value in desired_audit.items()
        )
    ):
        fail("Vault file audit-device configuration did not verify")
    status, mounts = vault_call(args, "GET", "/v1/sys/mounts", token=root_token)
    if status != 200:
        fail("Vault mount inspection failed")
    if "kv/" not in mounts:
        status, _ = vault_call(
            args,
            "POST",
            "/v1/sys/mounts/kv",
            body={"type": "kv", "options": {"version": "2"}},
            token=root_token,
        )
        if status not in {200, 204}:
            fail("Vault KV v2 setup failed")
    status, _ = vault_call(
        args,
        "PUT",
        "/v1/sys/policies/acl/rotator",
        body={"policy": ROTATOR_POLICY},
        token=root_token,
    )
    if status not in {200, 204}:
        fail("Vault rotator policy setup failed")
    status, _ = vault_call(
        args,
        "POST",
        "/v1/kv/metadata/ai-gateway/keycloak/break-glass-admin",
        body={"max_versions": 100},
        token=root_token,
    )
    if status not in {200, 204}:
        fail("Vault break-glass history setup failed")

    token = current_vault_token()
    token_valid = False
    if token:
        status, _ = vault_call(args, "GET", "/v1/auth/token/lookup-self", token=token)
        token_valid = status == 200
    if not token_valid:
        status, token_response = vault_call(
            args,
            "POST",
            "/v1/auth/token/create-orphan",
            body={"policies": ["rotator"], "period": "768h", "renewable": True},
            token=root_token,
        )
        if status != 200:
            fail("Vault rotator token creation failed")
        token = token_response.get("auth", {}).get("client_token", "")
        if not token:
            fail("Vault returned no rotator token")
        values = environment_values(args)
        values["ROTATOR_VAULT_TOKEN"] = token
        content = "# Generated by ansible/preprod.yml. Test credentials only.\n"
        content += "".join(f"{name}={value}\n" for name, value in values.items())
        write_file(ENV_FILE, content, 0o600)
    model = rendered_compose_model(args)
    expected_volume_names = verify_rendered_resource_ownership(args, model)
    verify_existing_project_boundary(args, expected_volume_names)
    compose(args, "up", "-d", "--no-deps", "--force-recreate", "key-rotator")
    verify_existing_project_boundary(args, expected_volume_names)
    wait_for_container(args, "key-rotator", "healthy", 240)
    print("PREPROD_VAULT_READY")


def auto_initialize_identity(args: argparse.Namespace) -> None:
    result = compose(
        args,
        "exec", "-T", "key-rotator", "/opt/venv/bin/python", "-m",
        "app.auto_bootstrap_identity", "--confirm", "AUTO_BOOTSTRAP_IDENTITY",
        capture=True,
        sensitive=True,
    )
    marker = result.stdout.strip()
    if marker not in {"IDENTITY_AUTO_BOOTSTRAP_APPLIED", "IDENTITY_AUTO_BOOTSTRAP_VERIFIED"}:
        fail("identity auto-initialization did not verify LDAP and durable controller state")
    print(marker)


def configure_preprod_users(args: argparse.Namespace) -> None:
    desired = {
        "preprod-admins": ("preprod-admin", ["aigw-admins", "aigw-chat"]),
        "preprod-developers": ("preprod-developer", ["aigw-chat", "aigw-developers"]),
        "preprod-users": ("preprod-user", ["aigw-chat"]),
    }
    status_code, groups = internal_call(args, "GET", "/identity/groups")
    if status_code != 200 or not isinstance(groups, list):
        fail("the managed preprod groups could not be listed")
    groups_by_name = {
        group.get("name"): group for group in groups if isinstance(group, dict)
    }
    for group_name, (_, capabilities) in desired.items():
        group = groups_by_name.get(group_name)
        if group is None:
            status_code, group = internal_call(
                args,
                "POST",
                "/identity/groups",
                {"name": group_name, "capabilities": capabilities},
            )
            if status_code != 201 or not isinstance(group, dict):
                fail(f"the managed group {group_name} could not be created")
            groups_by_name[group_name] = group
        if sorted(group.get("capabilities", [])) != sorted(capabilities):
            fail(f"the managed group {group_name} has unexpected capabilities")

    for group_name, (username, _) in desired.items():
        status_code, users = internal_call(
            args, "GET", f"/identity/users?search={quote(username, safe='')}"
        )
        matching = [
            user
            for user in users
            if isinstance(user, dict) and user.get("username") == username
        ] if isinstance(users, list) else []
        if status_code != 200 or len(matching) != 1 or matching[0].get("enabled") is not True:
            fail(f"the static LDAPS user {username} was not uniquely available")
        group_id = groups_by_name[group_name].get("id")
        user_id = matching[0].get("id")
        status_code, _ = internal_call(
            args, "PUT", f"/identity/groups/{group_id}/members/{user_id}"
        )
        if status_code != 204:
            fail(f"the static LDAPS user {username} could not join {group_name}")

    for group_name, (username, _) in desired.items():
        group_id = groups_by_name[group_name]["id"]
        status_code, members = internal_call(
            args, "GET", f"/identity/groups/{group_id}/members"
        )
        usernames = {
            member.get("username") for member in members if isinstance(member, dict)
        } if isinstance(members, list) else set()
        if status_code != 200 or username not in usernames:
            fail(f"the static LDAPS membership for {username} did not verify")
    print("PREPROD_USERS_CONFIGURED")


def unlock_preprod_user(args: argparse.Namespace) -> None:
    """Unlock one of the three fixed disposable directory users."""

    if args.username not in PREPROD_USERNAMES:
        fail("only a fixed preprod username can be unlocked")
    check_context(args)
    model = rendered_compose_model(args)
    expected_volume_names = verify_rendered_resource_ownership(args, model)
    verify_existing_project_boundary(args, expected_volume_names)
    compose(
        args,
        "exec",
        "-T",
        "samba-ad",
        "samba-tool",
        "user",
        "unlock",
        args.username,
    )
    print(f"PREPROD_USER_UNLOCKED username={args.username}")


def internal_call(
    args: argparse.Namespace,
    method: str,
    path: str,
    body: Any | None = None,
) -> tuple[int, Any]:
    request: dict[str, Any] = {"method": method, "path": path}
    if body is not None:
        request["body"] = body
    result = compose(
        args,
        "exec", "-T", "key-rotator", "/opt/venv/bin/python", "-c",
        INTERNAL_HTTP_HELPER,
        input_text=json.dumps(request, separators=(",", ":")),
        capture=True,
        sensitive=True,
    )
    try:
        response = json.loads(result.stdout)
        return int(response["status"]), response["body"]
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        fail("the key-rotator helper returned an invalid response")


def configure_wif(args: argparse.Namespace) -> None:
    status_code, provider = internal_call(args, "GET", "/providers/anthropic")
    if status_code != 200 or not isinstance(provider, dict):
        fail("the Anthropic WIF setup bundle is unavailable")
    bundle = provider.get("setup_bundle")
    jwks = bundle.get("jwks") if isinstance(bundle, dict) else None
    jwks_sha = provider.get("current_jwks_sha256")
    if not isinstance(jwks, dict) or not isinstance(jwks_sha, str) or len(jwks_sha) != 64:
        fail("the Anthropic WIF setup bundle is incomplete")
    jwks_path = SECRETS_DIR / "preprod-wif-jwks.json"
    # Keep the inode stable because Docker bind-mounted this file at start.
    with jwks_path.open("w", encoding="utf-8") as handle:
        json.dump(jwks, handle, separators=(",", ":"))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    jwks_path.chmod(0o600)

    wanted_ids = {
        "organization_id": "preprod-org",
        "service_account_id": "preprod-service-account",
        "federation_rule_id": "preprod-federation-rule",
        "workspace_id": "preprod-workspace",
    }
    if provider.get("configured") is True:
        if provider.get("nonsecret_ids") != wanted_ids:
            fail("the existing preprod WIF enrollment uses unexpected identifiers")
    else:
        enrollment = {
            **wanted_ids,
            "federation_jwks_sha256": jwks_sha,
            "enrollment_confirmation": "ENROLLED",
        }
        status_code, provider = internal_call(args, "PUT", "/providers/anthropic", enrollment)
        if status_code != 200 or provider.get("state") != "configured":
            fail("the preprod WIF enrollment failed")

    status_code, history = internal_call(args, "GET", "/history?limit=50")
    if status_code != 200 or not isinstance(history, list):
        fail("the preprod WIF history boundary could not be read")
    history_ids: list[int] = []
    for row in history:
        if (
            not isinstance(row, dict)
            or type(row.get("id")) is not int
            or row["id"] < 1
        ):
            fail("the preprod WIF history boundary is invalid")
        history_ids.append(row["id"])
    history_boundary = max(history_ids, default=0)

    status_code, response = internal_call(args, "POST", "/rotate/anthropic")
    if status_code == 202:
        if not isinstance(response, dict) or response.get("accepted") is not True:
            fail("the preprod WIF rotation returned an invalid acceptance response")
    elif status_code == 409:
        detail = response.get("detail") if isinstance(response, dict) else ""
        if detail != "rotation already in progress for vendor 'anthropic'":
            fail(f"the preprod WIF rotation was refused: {detail}")
    else:
        fail("the preprod WIF rotation could not start")
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        status_code, history = internal_call(args, "GET", "/history?limit=50")
        if status_code == 200 and isinstance(history, list):
            completed = [
                row
                for row in history
                if isinstance(row, dict)
                and type(row.get("id")) is int
                and row["id"] > history_boundary
                and row.get("vendor") == "anthropic"
                and row.get("action") == "rotate"
            ]
            if completed:
                newest = max(completed, key=lambda row: row["id"])
                if newest.get("status") != "success":
                    fail(
                        "the new preprod WIF rotation completed unsuccessfully: "
                        f"{newest.get('status', 'unknown')}"
                    )
                print("PREPROD_WIF_CONFIGURED")
                return
        time.sleep(3)
    fail("the preprod WIF token exchange did not complete successfully")


def verify(args: argparse.Namespace) -> None:
    services = rendered_compose_model(args)["services"]
    if "volume-init" not in services:
        fail("the rendered preprod model has no volume-init service")
    long_running: list[str] = []
    for name, definition in sorted(services.items()):
        if name == "volume-init":
            continue
        if (
            not isinstance(name, str)
            or validate_name(name, "Compose service") != name
            or not isinstance(definition, dict)
            or not isinstance(definition.get("healthcheck"), dict)
        ):
            fail(f"preprod service {name} has no rendered healthcheck")
        long_running.append(name)
    if not long_running:
        fail("the rendered preprod model has no long-running services")

    verify_volume_init(args)
    for service in long_running:
        wait_for_container(args, service, "healthy", 120)
    for service in long_running:
        status, health = container_state(args, service)
        if status != "running" or health != "healthy":
            fail(
                f"preprod service {service} is not running and healthy: "
                f"status={status} health={health}"
            )
    verify_edge_routes(args)
    status_code, identity = internal_call(args, "GET", "/identity/status")
    identity_fields = {
        "configured": True,
        "controller_usable": True,
        "bootstrap_available": False,
        "bootstrap_cleanup_required": False,
        "ldap_configured": True,
        "break_glass_escrow_readable": True,
        "break_glass_escrowed": True,
        "vault_oidc_rp_escrow_readable": True,
        "vault_oidc_rp_escrowed": True,
    }
    if status_code != 200 or any(identity.get(name) is not value for name, value in identity_fields.items()):
        fail("identity verification did not prove LDAP, OIDC, controller, and escrow state")
    status_code, provider = internal_call(args, "GET", "/providers/anthropic")
    if status_code != 200 or provider.get("state") != "configured" or provider.get("enabled") is not True:
        fail("WIF provider verification failed")
    print("PREPROD_VERIFIED")


def hosts_fragment(_: argparse.Namespace) -> str:
    return "\n".join(
        [
            HOSTS_BEGIN,
            "127.0.2.1 api.aigw.internal portal.aigw.internal",
            "127.0.3.1 auth.aigw.internal chat.aigw.internal admin.aigw.internal litellm-admin.aigw.internal grafana.aigw.internal prometheus.aigw.internal vault.aigw.internal",
            HOSTS_END,
        ]
    ) + "\n"


def replace_hosts_block(install: bool) -> None:
    path = Path("/etc/hosts")
    if os.geteuid() != 0:
        fail("installing or removing the hosts fragment requires root")
    if path.is_symlink() or not path.is_file():
        fail("/etc/hosts must be a regular file")
    original = path.read_text()
    if original.count(HOSTS_BEGIN) != original.count(HOSTS_END) or original.count(HOSTS_BEGIN) > 1:
        fail("the managed preprod hosts markers are incomplete or duplicated")
    expected = hosts_fragment(argparse.Namespace())
    if HOSTS_BEGIN in original:
        start = original.index(HOSTS_BEGIN)
        end = original.index(HOSTS_END, start) + len(HOSTS_END)
        existing = original[start:end] + ("\n" if original[end:end + 1] == "\n" else "")
        if existing != expected:
            fail("the managed preprod hosts block was edited; refusing to overwrite it")
        updated = original[:start] + original[end + (1 if original[end:end + 1] == "\n" else 0):]
        if install:
            print("PREPROD_HOSTS_VERIFIED")
            return
    else:
        updated = original
        if not install:
            print("PREPROD_HOSTS_ABSENT")
            return
    if install:
        if updated and not updated.endswith("\n"):
            updated += "\n"
        updated += expected
    metadata = path.stat()
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(updated)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, stat.S_IMODE(metadata.st_mode))
    os.chown(temporary, metadata.st_uid, metadata.st_gid)
    os.replace(temporary, path)
    print("PREPROD_HOSTS_INSTALLED" if install else "PREPROD_HOSTS_REMOVED")


def _clean_room_source_args(args: argparse.Namespace) -> argparse.Namespace:
    values = vars(args).copy()
    values["image_mode"] = "source"
    return argparse.Namespace(**values)


def _validate_clean_room_generated_state() -> int:
    """Validate every generated seed-state file before another mutation begins."""

    allowed_owners = {(0, 0), (os.geteuid(), os.getegid())}
    count = 0
    for path, expected_mode in (
        (SEED_RECEIPT, 0o644),
        (SEED_OVERLAY, 0o644),
        (VAULT_INIT_FILE, 0o600),
    ):
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            continue
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != expected_mode
            or (metadata.st_uid, metadata.st_gid) not in allowed_owners
        ):
            fail(f"refusing unsafe generated clean-room state file {path}")
        count += 1
    return count


def preflight_clean_room_resources(
    args: argparse.Namespace, inventory: dict[str, Any]
) -> dict[str, Any]:
    """Validate the complete project resource boundary before compose mutates it."""

    source_args = _clean_room_source_args(args)
    expected_volumes: set[str] = set()
    if ENV_FILE.exists():
        model = rendered_compose_model(source_args)
        expected_volumes = verify_rendered_resource_ownership(source_args, model)
        verify_existing_project_boundary(source_args, expected_volumes)

    owned_container_ids: set[str] = set()
    for container_id, document in inventory["containers"].items():
        name = str(document.get("Name", "")).removeprefix("/")
        labels = document.get("Config", {}).get("Labels") or {}
        if not isinstance(labels, dict):
            fail("a clean-room container has invalid labels")
        compose_project = labels.get("com.docker.compose.project")
        owner = labels.get("com.aigw.preprod.project")
        belongs = (
            compose_project == args.project
            or owner == args.project
            or name.startswith(args.project + "-")
        )
        if not belongs:
            continue
        if (
            compose_project != args.project
            or owner != args.project
            or not name.startswith(args.project + "-")
            or not ENV_FILE.exists()
        ):
            fail("refusing a container outside the exact clean-room project boundary")
        owned_container_ids.add(container_id)

    owned_volumes: set[str] = set()
    for volume_name in _clean_room_list("volume", "--format", "{{.Name}}"):
        document = _clean_room_inspect_required("volume", volume_name)
        if document.get("Name") != volume_name:
            fail("a clean-room volume inspection changed identity")
        labels = document.get("Labels") or {}
        if not isinstance(labels, dict):
            fail("a clean-room volume has invalid labels")
        compose_project = labels.get("com.docker.compose.project")
        owner = labels.get("com.aigw.preprod.project")
        belongs = (
            volume_name in expected_volumes
            or compose_project == args.project
            or owner == args.project
            or volume_name.startswith(args.project + "_")
        )
        if not belongs:
            continue
        if (
            volume_name not in expected_volumes
            or compose_project != args.project
            or owner != args.project
            or document.get("Driver") != "local"
            or document.get("Scope") != "local"
        ):
            fail("refusing a volume outside the exact clean-room project boundary")
        owned_volumes.add(volume_name)

    desired = desired_networks(source_args)
    owned_networks: set[str] = set()
    for _network_id, network_name, document in _clean_room_network_inventory():
        labels = document.get("Labels") or {}
        if not isinstance(labels, dict):
            fail("a clean-room network has invalid labels")
        owner = labels.get("com.aigw.preprod.project")
        belongs = (
            network_name in desired
            or owner == args.project
            or network_name.startswith(args.prefix + "-")
        )
        endpoints = document.get("Containers") or {}
        if not isinstance(endpoints, dict):
            fail("a clean-room network has invalid endpoint metadata")
        if not belongs:
            if set(endpoints).intersection(owned_container_ids):
                fail("a preprod container is attached to an unrelated Docker network")
            continue
        if network_name not in desired or owner != args.project:
            fail("refusing a network outside the exact clean-room project boundary")
        subnet, internal = desired[network_name]
        actual_subnets = network_subnets(document)
        allowed_subnets = {subnet}
        if network_name == f"{args.prefix}-net-vendor":
            allowed_subnets.add(LEGACY_PREPROD_VENDOR_SUBNET)
        actual_subnet = actual_subnets[0] if len(actual_subnets) == 1 else ""
        if (
            document.get("Driver") != "bridge"
            or document.get("Scope") != "local"
            or bool(document.get("Internal")) is not internal
            or actual_subnet not in allowed_subnets
            or network_ip_ranges(document) != [dynamic_ip_range(actual_subnet)]
        ):
            fail("refusing a clean-room network with unexpected settings")
        if not set(endpoints).issubset(owned_container_ids):
            fail("a clean-room network has an unrelated container endpoint")
        owned_networks.add(network_name)

    return {
        "containers": owned_container_ids,
        "volumes": owned_volumes,
        "networks": owned_networks,
        "generated_state_files": _validate_clean_room_generated_state(),
        "source_args": source_args,
    }


def prove_clean_room_resource_absence(args: argparse.Namespace) -> None:
    """Prove no container, volume, network, or seed activation state remains."""

    for container_id in _clean_room_list(
        "container", "--all", "--no-trunc", "--quiet"
    ):
        document = _clean_room_inspect_required("container", container_id)
        name = str(document.get("Name", "")).removeprefix("/")
        labels = document.get("Config", {}).get("Labels") or {}
        if (
            isinstance(labels, dict)
            and (
                labels.get("com.docker.compose.project") == args.project
                or labels.get("com.aigw.preprod.project") == args.project
            )
        ) or name.startswith(args.project + "-"):
            fail("a preprod container remains after clean-room resource removal")
    for value in _clean_room_list("volume", "--format", "{{.Name}}"):
        document = _clean_room_inspect_required("volume", value)
        labels = document.get("Labels") or {}
        if (
            isinstance(labels, dict)
            and (
                labels.get("com.docker.compose.project") == args.project
                or labels.get("com.aigw.preprod.project") == args.project
            )
        ) or value.startswith(args.project + "_"):
            fail("a preprod volume remains after clean-room resource removal")
    for _network_id, value, document in _clean_room_network_inventory():
        labels = document.get("Labels") or {}
        if (
            isinstance(labels, dict)
            and (
                labels.get("com.docker.compose.project") == args.project
                or labels.get("com.aigw.preprod.project") == args.project
            )
        ) or value.startswith(args.project + "-"):
            fail("a preprod network remains after clean-room resource removal")
    for path in (SEED_RECEIPT, SEED_OVERLAY, VAULT_INIT_FILE):
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        fail(f"generated preprod state remains after clean-room removal: {path}")


def prove_clean_room_target_images_unused(target_ids: set[str]) -> None:
    """Close the post-destroy container race before the first alias removal."""

    for container_id in _clean_room_list(
        "container", "--all", "--no-trunc", "--quiet"
    ):
        if re.fullmatch(r"[0-9a-f]{64}", container_id) is None:
            fail("Docker returned an invalid post-destroy container ID")
        document = _clean_room_inspect_required("container", container_id)
        image_id = document.get("Image")
        if not isinstance(image_id, str) or IMAGE_ID_RE.fullmatch(image_id) is None:
            fail("a post-destroy Docker container has an invalid image ID")
        if image_id in target_ids:
            fail("a container appeared using a clean-room target image after destroy")


def remove_seed_output_files() -> None:
    """Remove only generated seed files after proving their exact boundaries."""

    existing: list[tuple[Path, os.stat_result]] = []
    for path in seed_output_files():
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            continue
        existing.append((path, metadata))
    if not existing:
        return

    uid, gid = recorded_preprod_owner()
    if os.geteuid() not in {0, uid}:
        fail("only root or the recorded preprod owner may remove generated seed files")
    for path, metadata in existing:
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o644
        ):
            fail(f"refusing unsafe generated seed file {path}")
        if (metadata.st_uid, metadata.st_gid) not in {(0, 0), (uid, gid)}:
            fail(f"generated seed file has an unexpected owner: {path}")

    for path, _ in existing:
        path.unlink()
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        fail(f"generated seed file still exists after cleanup: {path}")


def _destroy_project_resources(
    args: argparse.Namespace, *, emit_context: bool, emit_receipt: bool
) -> None:
    quiet = not emit_context and not emit_receipt
    if emit_context:
        check_context(args)
    else:
        validate_local_docker_context()
    if ENV_FILE.exists():
        model = rendered_compose_model(args)
        expected_volume_names = verify_rendered_resource_ownership(args, model)
        verify_existing_project_boundary(args, expected_volume_names)
        compose(
            args,
            "down",
            "--volumes",
            "--remove-orphans",
            "--timeout",
            "30",
            capture=quiet,
        )
    existing_names = set(
        docker("network", "ls", "--format", "{{.Name}}", capture=True).stdout.splitlines()
    )
    for name in reversed(list(desired_networks(args))):
        if name not in existing_names:
            continue
        inspect = docker("network", "inspect", name, capture=True)
        document = json.loads(inspect.stdout)[0]
        labels = document.get("Labels") or {}
        if labels.get("com.aigw.preprod.project") != args.project:
            fail(f"refusing to remove network {name} because its ownership label differs")
        docker("network", "rm", name, capture=quiet)
    remove_seed_output_files()
    for path in (VAULT_INIT_FILE,):
        if path.exists():
            path.unlink()
    if emit_receipt:
        print("PREPROD_DESTROYED_CA_PRESERVED")


def destroy(args: argparse.Namespace) -> None:
    _destroy_project_resources(args, emit_context=True, emit_receipt=True)


def _remove_clean_room_image_reference(value: str, kind: str | None) -> bool:
    """Remove one exact alias or ID, allowing only its exact not-found result."""

    result = clean_room_docker("image", "rm", "--no-prune", value)
    if result.returncode == 0:
        if result.stderr:
            fail("Docker returned diagnostics while removing a clean-room image")
        return True
    if _is_exact_image_not_found(result, value, kind):
        return False
    fail("Docker failed while removing an exact clean-room image reference")


def remove_clean_room_images(
    plan: dict[str, Any], inventory: dict[str, Any]
) -> dict[str, int]:
    """Remove approved aliases first, then only their alias-proven image IDs."""

    alias_bound_ids = {
        entry[0]
        for entry in inventory["present_aliases"] + inventory["generated_aliases"]
    }
    removed_aliases = 0
    for group in plan["groups"]:
        image_id = group["image_id"]
        for alias in group["aliases"]:
            kind = alias["kind"]
            value = alias["value"]
            resolved = _clean_room_inspect_image_optional(value, kind)
            if resolved is None:
                continue
            if resolved.get("Id") != image_id:
                fail("a clean-room alias changed image ID before removal")
            _remove_clean_room_image_reference(value, kind)
            removed_aliases += 1

    for image_id, kind, value in sorted(inventory["generated_aliases"]):
        resolved = _clean_room_inspect_image_optional(value, kind)
        if resolved is None:
            continue
        if resolved.get("Id") != image_id:
            fail("a generated custom digest alias changed image ID before removal")
        _remove_clean_room_image_reference(value, kind)
        removed_aliases += 1

    removed_ids = len(inventory["present_target_ids"])
    for image_id in sorted(inventory["present_target_ids"]):
        if image_id not in alias_bound_ids:
            fail("refusing to remove a clean-room image ID without an alias proof")
        resolved = _clean_room_inspect_image_optional(image_id)
        if resolved is None:
            continue
        if resolved.get("Id") != image_id:
            fail("a clean-room target image changed identity before removal")
        if _clean_room_image_aliases(resolved):
            fail("a clean-room target image gained an unreviewed alias before ID removal")
        _remove_clean_room_image_reference(image_id, None)
    return {"aliases": removed_aliases, "image_ids": removed_ids}


def prove_clean_room_image_absence(
    plan: dict[str, Any], inventory: dict[str, Any]
) -> None:
    """Prove every target is absent and every snapshotted non-target survives."""

    for group in plan["groups"]:
        for alias in group["aliases"]:
            if _clean_room_inspect_image_optional(
                alias["value"], alias["kind"]
            ) is not None:
                fail("a reviewed clean-room image alias remains after removal")
        if _clean_room_inspect_image_optional(group["image_id"]) is not None:
            fail("a clean-room target image ID remains after removal")
    for _image_id, kind, value in inventory["generated_aliases"]:
        if _clean_room_inspect_image_optional(value, kind) is not None:
            fail("a generated custom digest alias remains after removal")
    for image_id in sorted(inventory["non_target_ids"]):
        document = _clean_room_inspect_image_optional(image_id)
        if document is None or document.get("Id") != image_id:
            fail("a non-target image ID did not survive clean-room removal")


def clean_room_seed(args: argparse.Namespace) -> None:
    """Destroy one exact preprod deployment and only its planned release images."""

    if args.confirm != CLEAN_ROOM_CONFIRMATION:
        fail(f"clean-room seed removal requires {CLEAN_ROOM_CONFIRMATION}")
    plan = clean_room_purge_plan(args)
    inventory = collect_clean_room_inventory(plan)
    resources = preflight_clean_room_resources(args, inventory)

    _destroy_project_resources(
        resources["source_args"], emit_context=False, emit_receipt=False
    )
    prove_clean_room_resource_absence(args)
    prove_clean_room_target_images_unused(inventory["target_ids"])
    removed = remove_clean_room_images(plan, inventory)
    prove_clean_room_image_absence(plan, inventory)

    receipt = {
        "manifest_sha256": args.manifest_sha256,
        "preserved_image_ids": len(inventory["non_target_ids"]),
        "project": args.project,
        "removed_aliases": removed["aliases"],
        "removed_containers": len(resources["containers"]),
        "removed_generated_state_files": resources["generated_state_files"],
        "removed_image_ids": removed["image_ids"],
        "removed_networks": len(resources["networks"]),
        "removed_volumes": len(resources["volumes"]),
        "schema_version": CLEAN_ROOM_RECEIPT_SCHEMA,
    }
    output = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
    if len(output.encode()) > 1024:
        fail("the clean-room receipt exceeded its output bound")
    print(f"PREPROD_CLEAN_ROOM_OK {output}")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--domain", default=ALLOWED_DOMAIN)
    result.add_argument("--project", default="aigw-preprod")
    result.add_argument("--prefix", default="aigw-preprod")
    result.add_argument("--subnet-octet", type=int, default=29)
    result.add_argument("--image-mode", choices=("source", "seed"), default="source")
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("check-context")
    commands.add_parser("check-root-seed-engine")
    commands.add_parser("prepare")
    local_seed_parser = commands.add_parser("load-local-preprod-seed")
    local_seed_parser.add_argument("archive")
    local_seed_parser.add_argument("archive_sha256")
    local_seed_parser.add_argument("manifest")
    local_seed_parser.add_argument("manifest_sha256")
    activate_parser = commands.add_parser("activate-seed")
    activate_parser.add_argument("archive")
    activate_parser.add_argument("manifest")
    activate_parser.add_argument("manifest_sha256")
    commands.add_parser("create-networks")
    commands.add_parser("compose-config")
    build_parser = commands.add_parser("build")
    build_parser.add_argument("--pull", action="store_true")
    commands.add_parser("pull")
    commands.add_parser("start")
    commands.add_parser("bootstrap-vault")
    commands.add_parser("auto-initialize-identity")
    commands.add_parser("configure-users")
    unlock_parser = commands.add_parser("unlock-user")
    unlock_parser.add_argument("username")
    commands.add_parser("configure-wif")
    commands.add_parser("verify")
    commands.add_parser("hosts-fragment")
    commands.add_parser("install-hosts")
    commands.add_parser("remove-hosts")
    commands.add_parser("ensure-loopback-aliases")
    commands.add_parser("remove-loopback-aliases")
    clean_room_parser = commands.add_parser("clean-room-seed")
    clean_room_parser.add_argument("--archive", required=True)
    clean_room_parser.add_argument("--archive-sha256", required=True)
    clean_room_parser.add_argument("--manifest", required=True)
    clean_room_parser.add_argument("--manifest-sha256", required=True)
    clean_room_parser.add_argument("--confirm", required=True)
    commands.add_parser("destroy")
    return result


def main() -> int:
    args = parser().parse_args()
    validate_inputs(args)
    actions = {
        "check-context": check_context,
        "check-root-seed-engine": check_root_seed_engine,
        "prepare": prepare,
        "load-local-preprod-seed": load_local_preprod_seed,
        "activate-seed": activate_seed,
        "create-networks": create_networks,
        "compose-config": compose_config,
        "build": build,
        "pull": pull,
        "start": start,
        "bootstrap-vault": bootstrap_vault,
        "auto-initialize-identity": auto_initialize_identity,
        "configure-users": configure_preprod_users,
        "unlock-user": unlock_preprod_user,
        "configure-wif": configure_wif,
        "verify": verify,
        "hosts-fragment": lambda parsed: print(hosts_fragment(parsed), end=""),
        "install-hosts": lambda _: replace_hosts_block(True),
        "remove-hosts": lambda _: replace_hosts_block(False),
        "ensure-loopback-aliases": ensure_loopback_aliases,
        "remove-loopback-aliases": remove_loopback_aliases,
        "clean-room-seed": clean_room_seed,
        "destroy": destroy,
    }
    actions[args.command](args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
