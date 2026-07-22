#!/usr/bin/env python3
"""Move AI Gateway data from PostgreSQL 16 to PostgreSQL 18.

The workflow never mounts the PostgreSQL 16 data directory in PostgreSQL 18.
It restores the logical dumps from an authenticated state backup into a new
volume.  The old volume stays unchanged until the operator retires it later.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
import uuid


POSTGRES_IMAGE = (
    "dhi.io/postgres:18.4@sha256:"
    "a807e832c1fc9ded731956abcb53dc98ed003fd82e27275eaef8dcf52fb90236"
)
POSTGRES_IMAGE_DIGEST = (
    "sha256:a807e832c1fc9ded731956abcb53dc98ed003fd82e27275eaef8dcf52fb90236"
)
POSTGRES_DATA_PATH = "/var/lib/postgresql/18/data"
SOURCE_DATA_PATH = "/var/lib/postgresql/16/data"
POSTGRES_IMAGE_USER = "70"
SOURCE_MAJOR = "16"
TARGET_MAJOR = "18"
RECEIPT_FORMAT = "aigw-postgres-major-migration-v1"
BACKUP_QUIESCE_FORMAT = "aigw-postgres-major-migration-quiesce-v1"
BACKUP_WRITE_BARRIER = "forced-checkpoint-after-logical-dumps-v1"
EXPECTED_ROLES = frozenset({"postgres", "litellm", "keycloak", "rotator", "grafana_ro"})
EXPECTED_DATABASES = ("litellm", "keycloak", "rotator")
SECRET_KEYS = (
    "PG_SUPER_PASSWORD",
    "PG_LITELLM_PASSWORD",
    "PG_KEYCLOAK_PASSWORD",
    "PG_ROTATOR_PASSWORD",
    "PG_GRAFANA_RO_PASSWORD",
)
VOLUME_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$")
ABSOLUTE_PATH = re.compile(
    r"^/(?:[A-Za-z0-9][A-Za-z0-9._-]{0,127})(?:/[A-Za-z0-9][A-Za-z0-9._-]{0,127}){0,15}$"
)
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")
IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
DIGEST_PINNED_IMAGE = re.compile(r"^[^\s@]+:[^\s@]+@sha256:[0-9a-f]{64}$")
NEXT_XID = re.compile(r"^[0-9]+:[0-9]+$")
ROLE_LINE = re.compile(
    r'^(?:CREATE|ALTER) ROLE (?:"((?:[^"]|"")+)"|([a-zA-Z_][a-zA-Z0-9_$]*))(?:[ ;])'
)


class MigrationError(RuntimeError):
    """The migration contract was not met."""


def run(
    argv: list[str],
    *,
    input_bytes: bytes | None = None,
    capture: bool = True,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    """Run one command without a shell or inherited stdin."""
    result = subprocess.run(
        argv,
        input=input_bytes,
        stdin=subprocess.DEVNULL if input_bytes is None else None,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        check=False,
    )
    if check and result.returncode:
        detail = (result.stderr or b"").decode("utf-8", "replace").strip()
        raise MigrationError(f"command failed ({argv[0]}): {detail or result.returncode}")
    return result


def docker(*args: str, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
    return run(["docker", "--host", "unix:///run/docker.sock", *args], **kwargs)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_json(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(path)


def read_receipt(path: Path) -> dict[str, object]:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise MigrationError("migration receipt must be one regular file")
        if metadata.st_uid != 0 or metadata.st_gid != 0 or metadata.st_mode & 0o077:
            raise MigrationError("migration receipt must be root-owned mode 0600")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MigrationError("migration receipt is missing or malformed") from exc
    if not isinstance(value, dict) or value.get("format") != RECEIPT_FORMAT:
        raise MigrationError("unsupported migration receipt")
    return value


def parse_env(path: Path) -> dict[str, str]:
    """Read only the five PostgreSQL secrets; never source shell text."""
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise MigrationError("deployed .env is missing") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or metadata.st_mode & 0o077
    ):
        raise MigrationError("deployed .env must be one root-owned private regular file")
    wanted: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in SECRET_KEYS:
            if key in wanted or not value or "\x00" in value or "\n" in value:
                raise MigrationError(f"invalid {key} in deployed .env")
            wanted[key] = value
    if set(wanted) != set(SECRET_KEYS):
        raise MigrationError("deployed .env is missing a PostgreSQL secret")
    return wanted


def parse_globals_roles(text: str) -> frozenset[str]:
    """Validate role inventory without executing globals.sql."""
    roles: set[str] = set()
    for line in text.splitlines():
        match = ROLE_LINE.match(line)
        if match:
            roles.add((match.group(1) or match.group(2)).replace('""', '"'))
        if re.match(r"^(?:GRANT|REVOKE) .+ (?:TO|FROM) ", line):
            raise MigrationError("globals.sql contains role memberships")
        if line.startswith(("CREATE TABLESPACE ", "ALTER TABLESPACE ")):
            raise MigrationError("globals.sql contains a tablespace definition")
    if roles != EXPECTED_ROLES:
        raise MigrationError(
            "globals.sql role inventory is not exact: " + ",".join(sorted(roles))
        )
    return frozenset(roles)


def private_state_directory(stack_dir: str) -> Path:
    if ABSOLUTE_PATH.fullmatch(stack_dir) is None:
        raise MigrationError("stack directory must be one canonical absolute path")
    stack = Path(stack_dir)
    try:
        stack_metadata = stack.lstat()
    except OSError as exc:
        raise MigrationError("deployed stack directory is missing") from exc
    if (
        not stat.S_ISDIR(stack_metadata.st_mode)
        or stat.S_ISLNK(stack_metadata.st_mode)
        or stack_metadata.st_uid != 0
        or stack_metadata.st_gid != 0
        or stack_metadata.st_mode & 0o022
    ):
        raise MigrationError("deployed stack directory has an unsafe ownership boundary")
    state_dir = stack / ".state"
    try:
        state_dir.mkdir(mode=0o700)
    except FileExistsError:
        pass
    metadata = state_dir.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise MigrationError("migration state directory must be root-owned mode 0700")
    return state_dir


def host_platform() -> str:
    architecture = docker("info", "--format", "{{.Architecture}}").stdout.decode().strip()
    platforms = {
        "amd64": "linux/amd64",
        "x86_64": "linux/amd64",
        "arm64": "linux/arm64",
        "aarch64": "linux/arm64",
    }
    try:
        return platforms[architecture]
    except KeyError as exc:
        raise MigrationError(f"unsupported Docker host architecture: {architecture}") from exc


def image_contract() -> tuple[str, str]:
    platform = host_platform()
    result = docker("image", "inspect", "--platform", platform, POSTGRES_IMAGE)
    try:
        image = json.loads(result.stdout)[0]
        config = image["Config"]
    except (json.JSONDecodeError, IndexError, KeyError, TypeError) as exc:
        raise MigrationError("cannot inspect the exact PostgreSQL 18 image") from exc
    env = set(config.get("Env") or [])
    repo_digests = set(image.get("RepoDigests") or [])
    if (
        config.get("User") != POSTGRES_IMAGE_USER
        or config.get("Entrypoint") != ["/usr/local/bin/docker-entrypoint.sh"]
        or config.get("Volumes") not in (None, {})
        or f"PGDATA={POSTGRES_DATA_PATH}" not in env
        or "PG_MAJOR=18" not in env
        or "PG_MINOR=4" not in env
        or not any(item.endswith("@" + POSTGRES_IMAGE_DIGEST) for item in repo_digests)
    ):
        raise MigrationError("PostgreSQL 18 image metadata differs from the reviewed contract")
    image_id = image.get("Id")
    if not isinstance(image_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise MigrationError("PostgreSQL 18 image ID is malformed")
    return image_id, platform


def volume_info(name: str) -> dict[str, object] | None:
    result = docker("volume", "inspect", name, check=False)
    if result.returncode:
        return None
    try:
        value = json.loads(result.stdout)
        return value[0]
    except (json.JSONDecodeError, IndexError, TypeError) as exc:
        raise MigrationError(f"cannot inspect Docker volume {name}") from exc


def project_containers(project: str) -> list[dict[str, object]]:
    result = docker("ps", "-aq", "--no-trunc", "--filter", f"label=com.docker.compose.project={project}")
    ids = result.stdout.decode().split()
    if not ids:
        return []
    try:
        value = json.loads(docker("inspect", *ids).stdout)
    except json.JSONDecodeError as exc:
        raise MigrationError("cannot inspect project containers") from exc
    if not isinstance(value, list):
        raise MigrationError("project container inventory is malformed")
    return value


def exact_container_ids(
    value: object, label: str, *, allow_empty: bool = False
) -> tuple[str, ...]:
    """Return one sorted, duplicate-free list of full Docker container IDs."""

    if not isinstance(value, list) or (not value and not allow_empty):
        raise MigrationError(f"{label} is missing")
    if any(
        not isinstance(item, str) or CONTAINER_ID.fullmatch(item) is None
        for item in value
    ):
        raise MigrationError(f"{label} contains a malformed container ID")
    if value != sorted(value) or len(value) != len(set(value)):
        raise MigrationError(f"{label} is not a canonical container inventory")
    return tuple(value)


def exact_project_inventory(
    containers: list[dict[str, object]], project: str
) -> dict[str, dict[str, object]]:
    """Index an exact Compose project inventory and reject ambiguous records."""

    inventory: dict[str, dict[str, object]] = {}
    for container in containers:
        if not isinstance(container, dict):
            raise MigrationError("project container inventory is malformed")
        container_id = container.get("Id")
        if (
            not isinstance(container_id, str)
            or CONTAINER_ID.fullmatch(container_id) is None
        ):
            raise MigrationError("project container inventory has a malformed ID")
        if container_id in inventory:
            raise MigrationError("project container inventory contains a duplicate ID")
        labels = (container.get("Config") or {}).get("Labels") or {}
        if labels.get("com.docker.compose.project") != project:
            raise MigrationError(
                "project container inventory has an unexpected project label"
            )
        inventory[container_id] = container
    return inventory


def backup_quiesce_contract(
    manifest: dict[str, object], *, source_volume: str
) -> dict[str, object]:
    """Validate the authenticated PG16 quiesce record from the backup."""

    value = manifest.get("postgres_major_migration_quiesce")
    if not isinstance(value, dict) or set(value) != {
        "format",
        "project_container_ids",
        "prior_running_container_ids",
        "writer_container_ids",
        "stopped_container_states",
        "source",
    }:
        raise MigrationError("backup lacks the major-migration quiesce record")
    if value.get("format") != BACKUP_QUIESCE_FORMAT:
        raise MigrationError("backup has an unsupported major-migration quiesce record")

    project_ids = exact_container_ids(
        value.get("project_container_ids"), "backup project container inventory"
    )
    prior_running_ids = exact_container_ids(
        value.get("prior_running_container_ids"), "backup running container inventory"
    )
    writer_ids = exact_container_ids(
        value.get("writer_container_ids"),
        "backup writer container inventory",
        allow_empty=True,
    )
    source = value.get("source")
    if not isinstance(source, dict) or set(source) != {
        "container_id",
        "image",
        "image_id",
        "volume",
        "data_path",
    }:
        raise MigrationError("backup PostgreSQL 16 source identity is malformed")
    source_id = source.get("container_id")
    source_image = source.get("image")
    source_image_id = source.get("image_id")
    if not isinstance(source_id, str) or CONTAINER_ID.fullmatch(source_id) is None:
        raise MigrationError("backup PostgreSQL 16 source container ID is malformed")
    if (
        not isinstance(source_image, str)
        or DIGEST_PINNED_IMAGE.fullmatch(source_image) is None
    ):
        raise MigrationError("backup PostgreSQL 16 source image is not digest-pinned")
    if not isinstance(source_image_id, str) or IMAGE_ID.fullmatch(source_image_id) is None:
        raise MigrationError("backup PostgreSQL 16 source image ID is malformed")
    if (
        source.get("volume") != source_volume
        or source.get("data_path") != SOURCE_DATA_PATH
    ):
        raise MigrationError("backup PostgreSQL 16 source volume identity changed")

    project_set = set(project_ids)
    prior_set = set(prior_running_ids)
    if source_id not in project_set or source_id not in prior_set:
        raise MigrationError("backup PostgreSQL 16 source is absent from its inventory")
    if not prior_set.issubset(project_set):
        raise MigrationError("backup running containers are absent from the project inventory")
    if set(writer_ids) != prior_set - {source_id}:
        raise MigrationError("backup writer inventory does not match the prior running graph")
    stopped_states = value.get("stopped_container_states")
    if (
        not isinstance(stopped_states, dict)
        or set(stopped_states) != project_set - {source_id}
    ):
        raise MigrationError("backup stopped-container state inventory is incomplete")
    for container_id, state in stopped_states.items():
        if (
            not isinstance(container_id, str)
            or CONTAINER_ID.fullmatch(container_id) is None
            or not isinstance(state, dict)
            or set(state) != {"started_at", "finished_at", "restart_count"}
            or not isinstance(state.get("started_at"), str)
            or not isinstance(state.get("finished_at"), str)
            or type(state.get("restart_count")) is not int
            or state["restart_count"] < 0
        ):
            raise MigrationError("backup stopped-container state inventory is malformed")

    # Keep the normalized record easy to compare and safe to put in a receipt.
    return {
        "format": BACKUP_QUIESCE_FORMAT,
        "project_container_ids": list(project_ids),
        "prior_running_container_ids": list(prior_running_ids),
        "writer_container_ids": list(writer_ids),
        "stopped_container_states": dict(sorted(stopped_states.items())),
        "source": dict(source),
    }


def quiesce_contract_from_receipt(receipt: dict[str, object]) -> dict[str, object]:
    """Rebuild and validate the quiesce record stored in a migration receipt."""

    manifest = {
        "postgres_major_migration_quiesce": {
            "format": receipt.get("source_quiesce_format"),
            "project_container_ids": receipt.get("source_project_container_ids"),
            "prior_running_container_ids": receipt.get("source_running_container_ids"),
            "writer_container_ids": receipt.get("source_writer_container_ids"),
            "stopped_container_states": receipt.get("source_stopped_container_states"),
            "source": {
                "container_id": receipt.get("source_container_id"),
                "image": receipt.get("source_image"),
                "image_id": receipt.get("source_image_id"),
                "volume": receipt.get("source_volume"),
                "data_path": receipt.get("source_data_path"),
            },
        }
    }
    return backup_quiesce_contract(
        manifest,
        source_volume=str(receipt.get("source_volume", "")),
    )


def verify_quiesced_source(
    containers: list[dict[str, object]],
    postgres: dict[str, object],
    quiesce: dict[str, object],
    *,
    project: str,
) -> None:
    """Prove the same PG16 source is running and every other container is stopped."""

    inventory = exact_project_inventory(containers, project)
    expected_ids = set(
        exact_container_ids(
            quiesce.get("project_container_ids"),
            "quiesced project container inventory",
        )
    )
    if set(inventory) != expected_ids:
        raise MigrationError("project containers changed after the major-migration backup")

    live_source = verify_recorded_source(inventory, quiesce)
    if postgres is not live_source:
        raise MigrationError("PostgreSQL 16 source container changed after backup")

    stopped_states = quiesce.get("stopped_container_states")
    if not isinstance(stopped_states, dict):
        raise MigrationError("quiesced stopped-container state inventory is malformed")
    for container_id, expected in stopped_states.items():
        container = inventory[container_id]
        state = container.get("State") or {}
        actual = {
            "started_at": state.get("StartedAt"),
            "finished_at": state.get("FinishedAt"),
            "restart_count": container.get("RestartCount"),
        }
        if state.get("Running") is not False or actual != expected:
            raise MigrationError(
                "an application container restarted after the major-migration backup"
            )

    source = quiesce["source"]
    source_id = str(source["container_id"])
    running_ids = {
        container_id
        for container_id, container in inventory.items()
        if (container.get("State") or {}).get("Running") is True
    }
    if running_ids != {source_id}:
        raise MigrationError(
            "major migration requires the exact PostgreSQL 16 source to be the only running project container"
        )


def verify_recorded_source(
    inventory: dict[str, dict[str, object]], quiesce: dict[str, object]
) -> dict[str, object]:
    """Find the exact recorded PG16 container without requiring it to run."""

    source = quiesce.get("source")
    if not isinstance(source, dict):
        raise MigrationError("quiesced PostgreSQL 16 source identity is malformed")
    source_id = str(source.get("container_id", ""))
    postgres = inventory.get(source_id)
    if postgres is None:
        raise MigrationError("PostgreSQL 16 source container changed after backup")
    config = postgres.get("Config") or {}
    labels = config.get("Labels") or {}
    if labels.get("com.docker.compose.service") != "postgres":
        raise MigrationError("PostgreSQL 16 source service label changed after backup")
    if (
        config.get("Image") != source.get("image")
        or postgres.get("Image") != source.get("image_id")
    ):
        raise MigrationError("PostgreSQL 16 source image changed after backup")
    matching_mounts = [
        mount
        for mount in postgres.get("Mounts") or []
        if isinstance(mount, dict)
        and mount.get("Type") == "volume"
        and mount.get("Name") == source.get("volume")
        and mount.get("Destination") == source.get("data_path")
    ]
    if len(matching_mounts) != 1:
        raise MigrationError("PostgreSQL 16 source mount changed after backup")
    return postgres


def source_postgres(containers: list[dict[str, object]], source_volume: str) -> dict[str, object]:
    matches = []
    for container in containers:
        labels = (container.get("Config") or {}).get("Labels") or {}
        if labels.get("com.docker.compose.service") == "postgres":
            matches.append(container)
    if len(matches) != 1:
        raise MigrationError("exactly one PostgreSQL 16 Compose container is required")
    container = matches[0]
    mounts = container.get("Mounts") or []
    if not any(
        mount.get("Type") == "volume"
        and mount.get("Name") == source_volume
        and mount.get("Destination") == SOURCE_DATA_PATH
        for mount in mounts
        if isinstance(mount, dict)
    ):
        raise MigrationError("source PostgreSQL container does not mount the reviewed PG16 volume")
    state = container.get("State") or {}
    if not state.get("Running"):
        raise MigrationError("source PostgreSQL 16 container must be running for plan")
    return container


def postgres_scalar(container_id: str, sql: str) -> str:
    result = docker(
        "exec",
        container_id,
        "psql",
        "--username",
        "postgres",
        "--dbname",
        "postgres",
        "--tuples-only",
        "--no-align",
        "--command",
        sql,
    )
    return result.stdout.decode("utf-8", "strict").strip()


def force_checkpoint(container_id: str) -> None:
    """Flush accepted source writes into pg_control before the final proof."""

    docker(
        "exec",
        container_id,
        "psql",
        "--username",
        "postgres",
        "--dbname",
        "postgres",
        "--set",
        "ON_ERROR_STOP=1",
        "--command",
        "CHECKPOINT;",
    )


def require_backup_write_barrier(manifest: dict[str, object]) -> None:
    """Reject backups made before the post-dump checkpoint contract."""

    if manifest.get("postgres_write_barrier") != BACKUP_WRITE_BARRIER:
        raise MigrationError(
            "backup lacks the forced post-dump PostgreSQL checkpoint barrier"
        )


def validate_backup_inputs(args: argparse.Namespace, staging: Path) -> tuple[dict[str, object], Path]:
    backup = Path(args.input)
    identity = Path(args.identity)
    if identity.parent != Path("/run/ai-gateway-postgres18"):
        raise MigrationError("age identity must stay in /run/ai-gateway-postgres18")
    metadata_by_label: dict[str, os.stat_result] = {}
    for path, label in ((backup, "backup"), (identity, "age identity")):
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise MigrationError(f"{label} is missing") from exc
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise MigrationError(f"{label} must be one regular file")
        metadata_by_label[label] = metadata
    identity_metadata = metadata_by_label["age identity"]
    if (
        identity_metadata.st_uid != 0
        or identity_metadata.st_gid != 0
        or identity_metadata.st_mode & 0o077
    ):
        raise MigrationError("age identity must be root-owned and not group/other accessible")
    if not HEX_SHA256.fullmatch(args.sha256) or sha256_file(backup) != args.sha256:
        raise MigrationError("encrypted backup SHA-256 does not match")

    decrypted = staging / "backup.tar.gz"
    with decrypted.open("wb") as output:
        result = subprocess.run(
            ["age", "--decrypt", "-i", str(identity), str(backup)],
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.PIPE,
            check=False,
        )
    if result.returncode:
        raise MigrationError("age could not authenticate and decrypt the backup")

    docker_root_result = docker("info", "--format", "{{.DockerRootDir}}")
    docker_root = docker_root_result.stdout.decode().strip()
    if not docker_root.startswith("/") or not Path(docker_root).is_dir():
        raise MigrationError("DockerRootDir is not a usable absolute directory")
    extracted = staging / "extracted"
    config = staging / "stack-config"
    run(
        [
            sys.executable,
            "-I",
            str(Path(args.stack_dir) / "scripts" / "restore_archive.py"),
            "--archive",
            str(decrypted),
            "--extracted-root",
            str(extracted),
            "--config-root",
            str(config),
            "--project",
            args.project,
            "--profile",
            args.deployment_profile,
            "--volume-target",
            docker_root,
        ]
    )
    decrypted.unlink()
    try:
        manifest = json.loads((extracted / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MigrationError("validated backup manifest cannot be read") from exc
    return manifest, extracted


def validate_plan_inputs(args: argparse.Namespace) -> tuple[dict[str, object], dict[str, object]]:
    if os.geteuid() != 0:
        raise MigrationError("PostgreSQL major migration must run as root")
    if not VOLUME_NAME.fullmatch(args.source_volume) or not VOLUME_NAME.fullmatch(args.target_volume):
        raise MigrationError("source and target volume names must be canonical")
    if args.source_volume == args.target_volume:
        raise MigrationError("PostgreSQL 18 requires a fresh volume name")
    source = volume_info(args.source_volume)
    if source is None:
        raise MigrationError("source PostgreSQL 16 volume is missing")
    source_labels = source.get("Labels") or {}
    if (
        source_labels.get("com.docker.compose.project") != args.project
        or source_labels.get("com.docker.compose.volume") != "pg_data"
    ):
        raise MigrationError("source PostgreSQL 16 volume has the wrong ownership labels")
    if volume_info(args.target_volume) is not None:
        raise MigrationError("target PostgreSQL 18 volume already exists")
    image_id, platform = image_contract()
    containers = project_containers(args.project)
    postgres = source_postgres(containers, args.source_volume)
    container_id = str(postgres["Id"])
    live_version = postgres_scalar(container_id, "SHOW server_version;")
    live_next_xid = postgres_scalar(container_id, "SELECT next_xid FROM pg_control_checkpoint();")
    if not live_version.startswith(SOURCE_MAJOR + ".") or not NEXT_XID.fullmatch(live_next_xid):
        raise MigrationError("live source is not a valid PostgreSQL 16 cluster")

    state_dir = private_state_directory(args.stack_dir)
    if Path(args.receipt) != state_dir / "postgres-major-migration-v1.json":
        raise MigrationError("migration receipt must use the fixed stack state path")
    with tempfile.TemporaryDirectory(prefix="postgres18-plan.", dir=state_dir) as temporary:
        manifest, extracted = validate_backup_inputs(args, Path(temporary))
        quiesce = backup_quiesce_contract(
            manifest, source_volume=args.source_volume
        )
        verify_quiesced_source(
            containers, postgres, quiesce, project=args.project
        )
        backup_version = str(manifest.get("postgres_version", ""))
        backup_next_xid = str(manifest.get("postgres_next_xid", ""))
        require_backup_write_barrier(manifest)
        if not backup_version.startswith(SOURCE_MAJOR + "."):
            raise MigrationError("backup was not created by PostgreSQL 16")
        if backup_version != live_version:
            raise MigrationError("backup and live PostgreSQL versions differ")
        if not NEXT_XID.fullmatch(backup_next_xid) or backup_next_xid != live_next_xid:
            raise MigrationError(
                "PostgreSQL changed after the backup; take a new backup and keep writers stopped"
            )
        try:
            created = dt.datetime.fromisoformat(str(manifest["created_at"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise MigrationError("backup creation time is missing or malformed") from exc
        if created.tzinfo is None:
            raise MigrationError("backup creation time lacks a timezone")
        age = dt.datetime.now(dt.timezone.utc) - created.astimezone(dt.timezone.utc)
        if age < dt.timedelta(0) or age > dt.timedelta(minutes=args.max_backup_age_minutes):
            raise MigrationError("backup is too old for a major migration")

        postgres_dir = extracted / "postgres"
        parse_globals_roles((postgres_dir / "globals.sql").read_text(encoding="utf-8"))
        dumps: dict[str, dict[str, object]] = {}
        for database in EXPECTED_DATABASES:
            dump = postgres_dir / f"{database}.dump"
            listing = docker(
                "run",
                "--rm",
                "-i",
                "--network",
                "none",
                "--read-only",
                "--security-opt",
                "no-new-privileges:true",
                "--cap-drop",
                "ALL",
                "--entrypoint",
                "pg_restore",
                POSTGRES_IMAGE,
                "--list",
                input_bytes=dump.read_bytes(),
            ).stdout.decode("utf-8", "strict")
            entries = sum(
                1 for line in listing.splitlines() if line and not line.startswith(";")
            )
            if entries == 0:
                raise MigrationError(f"{database} dump has no restore entries")
            dumps[database] = {
                "sha256": sha256_file(dump),
                "bytes": dump.stat().st_size,
                "restore_entries": entries,
            }
        plan = {
            "format": RECEIPT_FORMAT,
            "migration_id": str(uuid.uuid4()),
            "phase": "planned",
            "planned_at": utc_now(),
            "project": args.project,
            "deployment_profile": args.deployment_profile,
            "source_major": SOURCE_MAJOR,
            "source_version": live_version,
            "source_next_xid": live_next_xid,
            "source_volume": args.source_volume,
            "source_quiesce_format": quiesce["format"],
            "source_project_container_ids": quiesce["project_container_ids"],
            "source_running_container_ids": quiesce["prior_running_container_ids"],
            "source_writer_container_ids": quiesce["writer_container_ids"],
            "source_stopped_container_states": quiesce["stopped_container_states"],
            "source_container_id": quiesce["source"]["container_id"],
            "source_image": quiesce["source"]["image"],
            "source_image_id": quiesce["source"]["image_id"],
            "source_data_path": quiesce["source"]["data_path"],
            "target_major": TARGET_MAJOR,
            "target_version": "18.4",
            "target_volume": args.target_volume,
            "postgres_image": POSTGRES_IMAGE,
            "postgres_image_id": image_id,
            "platform": platform,
            "backup_sha256": args.sha256,
            "backup_id": manifest.get("backup_id"),
            "backup_created_at": manifest.get("created_at"),
            "dumps": dumps,
        }
        details = {
            "containers": containers,
            "extracted": extracted,
            "manifest": manifest,
            "quiesce": quiesce,
        }
        # ``extracted`` is valid only until this function returns, so callers
        # that migrate validate and extract the backup again after stopping.
        return plan, details


def command_plan(args: argparse.Namespace) -> None:
    plan, _ = validate_plan_inputs(args)
    atomic_json(Path(args.receipt), plan)
    print(f"POSTGRES_MIGRATION_PLANNED {plan['migration_id']}")


def write_secret_env(path: Path, secrets: dict[str, str]) -> None:
    mapping = {
        "POSTGRES_PASSWORD": secrets["PG_SUPER_PASSWORD"],
        "PG_LITELLM_PASSWORD": secrets["PG_LITELLM_PASSWORD"],
        "PG_KEYCLOAK_PASSWORD": secrets["PG_KEYCLOAK_PASSWORD"],
        "PG_ROTATOR_PASSWORD": secrets["PG_ROTATOR_PASSWORD"],
        "PG_GRAFANA_RO_PASSWORD": secrets["PG_GRAFANA_RO_PASSWORD"],
        "POSTGRES_INITDB_ARGS": "--auth-host=scram-sha-256",
    }
    path.write_text("".join(f"{key}={value}\n" for key, value in mapping.items()), encoding="utf-8")
    path.chmod(0o600)


def wait_for_postgres(container: str) -> None:
    for _ in range(120):
        result = docker(
            "exec",
            container,
            "pg_isready",
            "--username",
            "postgres",
            "--dbname",
            "postgres",
            check=False,
        )
        if result.returncode == 0:
            return
        time.sleep(1)
    raise MigrationError("PostgreSQL 18 did not become ready")


def reconcile_database_contract(container: str) -> None:
    """Create or repair the reviewed roles, databases, passwords, and ACLs."""
    docker(
        "exec",
        container,
        "/docker-entrypoint-initdb.d/01-init-databases.sh",
    )


ROLE_MATRIX_SQL = """
SELECT role_name || '|' || db_name || '|' ||
       CASE WHEN has_database_privilege(role_name, db_name, 'CONNECT')
            THEN 'true' ELSE 'false' END
  FROM unnest(ARRAY['grafana_ro','keycloak','litellm','rotator']) AS role_name
 CROSS JOIN unnest(ARRAY['keycloak','litellm','rotator','postgres']) AS db_name
 ORDER BY role_name, db_name;
SELECT 'postgres|postgres|' ||
       CASE WHEN has_database_privilege('postgres', 'postgres', 'CONNECT')
            THEN 'true' ELSE 'false' END;
SELECT 'owner|' || datname || '|' || pg_get_userbyid(datdba)
  FROM pg_database WHERE datname IN ('keycloak','litellm','rotator') ORDER BY datname;
SELECT 'membership|' || count(*)
  FROM pg_auth_members membership
  JOIN pg_roles granted_role ON granted_role.oid = membership.roleid
  JOIN pg_roles member_role ON member_role.oid = membership.member
 WHERE granted_role.rolname IN ('grafana_ro','keycloak','litellm','rotator')
    OR member_role.rolname IN ('grafana_ro','keycloak','litellm','rotator');
SELECT 'role|' || rolname || '|' ||
       CASE WHEN rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND
                 NOT rolcreaterole AND NOT rolinherit AND NOT rolreplication AND
                 NOT rolbypassrls AND rolconnlimit = -1 AND rolconfig IS NULL AND
                 (rolvaliduntil IS NULL OR rolvaliduntil = 'infinity'::timestamptz)
            THEN 'true' ELSE 'false' END
  FROM pg_roles
 WHERE rolname IN ('grafana_ro','keycloak','litellm','rotator') ORDER BY rolname;
"""


EXPECTED_ROLE_MATRIX = sorted(
    [
        "grafana_ro|keycloak|false",
        "grafana_ro|litellm|true",
        "grafana_ro|postgres|false",
        "grafana_ro|rotator|false",
        "keycloak|keycloak|true",
        "keycloak|litellm|false",
        "keycloak|postgres|false",
        "keycloak|rotator|false",
        "litellm|keycloak|false",
        "litellm|litellm|true",
        "litellm|postgres|false",
        "litellm|rotator|false",
        "postgres|postgres|true",
        "rotator|keycloak|false",
        "rotator|litellm|false",
        "rotator|postgres|false",
        "rotator|rotator|true",
        "owner|keycloak|keycloak",
        "owner|litellm|litellm",
        "owner|rotator|rotator",
        "membership|0",
        "role|grafana_ro|true",
        "role|keycloak|true",
        "role|litellm|true",
        "role|rotator|true",
    ]
)


def validate_database(container: str) -> dict[str, dict[str, int]]:
    version = postgres_scalar(container, "SHOW server_version;")
    if version != "18.4":
        raise MigrationError(f"restored server is {version}, expected 18.4")
    matrix = postgres_scalar(container, ROLE_MATRIX_SQL).splitlines()
    if sorted(matrix) != EXPECTED_ROLE_MATRIX:
        raise MigrationError("restored role/database security matrix differs")
    metrics: dict[str, dict[str, int]] = {}
    for database in EXPECTED_DATABASES:
        result = docker(
            "exec",
            container,
            "psql",
            "--username",
            "postgres",
            "--dbname",
            database,
            "--tuples-only",
            "--no-align",
            "--field-separator",
            "|",
            "--command",
            "SELECT count(*), pg_database_size(current_database()) "
            "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE c.relkind IN ('r','p','v','m','S','f') "
            "AND n.nspname NOT IN ('pg_catalog','information_schema') "
            "AND n.nspname NOT LIKE 'pg_toast%';",
        )
        fields = result.stdout.decode().strip().split("|")
        if len(fields) != 2 or not all(field.isdigit() for field in fields):
            raise MigrationError(f"cannot read restored {database} metrics")
        object_count, size_bytes = (int(field) for field in fields)
        if object_count < 1 or size_bytes < 1:
            raise MigrationError(f"restored {database} appears empty")
        metrics[database] = {"objects": object_count, "bytes": size_bytes}
    return metrics


def command_migrate(args: argparse.Namespace) -> None:
    if args.confirm != "MIGRATE_POSTGRES_16_TO_18":
        raise MigrationError("migration confirmation is missing")
    receipt_path = Path(args.receipt)
    existing = read_receipt(receipt_path)
    if existing.get("phase") != "planned":
        raise MigrationError("migration receipt is not in planned phase")
    plan, details = validate_plan_inputs(args)
    for key in (
        "project",
        "source_volume",
        "target_volume",
        "postgres_image",
        "postgres_image_id",
        "platform",
        "backup_sha256",
        "source_version",
        "source_next_xid",
        "source_quiesce_format",
        "source_project_container_ids",
        "source_running_container_ids",
        "source_writer_container_ids",
        "source_stopped_container_states",
        "source_container_id",
        "source_image",
        "source_image_id",
        "source_data_path",
        "dumps",
    ):
        if existing.get(key) != plan.get(key):
            raise MigrationError(f"planned migration input changed: {key}")
    plan = existing
    containers = details["containers"]
    quiesce = details["quiesce"]
    postgres = source_postgres(containers, args.source_volume)
    verify_quiesced_source(containers, postgres, quiesce, project=args.project)
    plan["phase"] = "source_stopping"
    plan["source_stopping_at"] = utc_now()
    atomic_json(receipt_path, plan)

    # The backup deliberately left every application writer stopped. Prove the
    # exact container inventory again immediately before the last checkpoint;
    # this command never tries to create quiescence itself.
    containers = project_containers(args.project)
    postgres = source_postgres(containers, args.source_volume)
    verify_quiesced_source(containers, postgres, quiesce, project=args.project)
    postgres_id = str(postgres["Id"])
    stopped_source_version = postgres_scalar(postgres_id, "SHOW server_version;")
    force_checkpoint(postgres_id)
    stopped_source_next_xid = postgres_scalar(
        postgres_id, "SELECT next_xid FROM pg_control_checkpoint();"
    )
    if (
        stopped_source_version != plan["source_version"]
        or stopped_source_next_xid != plan["source_next_xid"]
    ):
        plan["phase"] = "failed"
        plan["failed_at"] = utc_now()
        atomic_json(receipt_path, plan)
        raise MigrationError(
            "PostgreSQL changed after the backup; take a new backup and keep writers stopped"
        )
    containers = project_containers(args.project)
    postgres = source_postgres(containers, args.source_volume)
    verify_quiesced_source(containers, postgres, quiesce, project=args.project)
    docker("stop", "--time", "60", postgres_id)

    # Revalidate the backup after quiescing. This creates a new private
    # extraction so no bytes from the read-only plan phase are reused.
    state_dir = Path(args.stack_dir) / ".state"
    with tempfile.TemporaryDirectory(prefix="postgres18-migrate.", dir=state_dir) as temporary:
        temporary_path = Path(temporary)
        _, extracted = validate_backup_inputs(args, temporary_path)
        postgres_dir = extracted / "postgres"
        parse_globals_roles((postgres_dir / "globals.sql").read_text(encoding="utf-8"))
        secrets = parse_env(Path(args.stack_dir) / ".env")
        secret_env = temporary_path / "postgres.env"
        write_secret_env(secret_env, secrets)

        labels = {
            "com.docker.compose.project": args.project,
            "com.docker.compose.volume": "pg_data",
            "com.aigw.postgres.major": TARGET_MAJOR,
            "com.aigw.postgres.migration-id": str(plan["migration_id"]),
        }
        create_args = ["volume", "create"]
        for key, value in labels.items():
            create_args.extend(["--label", f"{key}={value}"])
        create_args.append(args.target_volume)
        docker(*create_args)

        container = f"aigw-postgres18-migration-{str(plan['migration_id'])[:8]}"
        docker(
            "run",
            "--detach",
            "--name",
            container,
            "--network",
            "none",
            "--read-only",
            "--security-opt",
            "no-new-privileges:true",
            "--cap-drop",
            "ALL",
            "--pids-limit",
            "1024",
            "--memory",
            "2g",
            "--cpus",
            "2",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev",
            "--tmpfs",
            "/run/postgresql:rw,noexec,nosuid,nodev",
            "--env-file",
            str(secret_env),
            "--volume",
            f"{args.target_volume}:{POSTGRES_DATA_PATH}",
            "--volume",
            f"{Path(args.stack_dir) / 'postgres' / 'init'}:/docker-entrypoint-initdb.d:ro,Z",
            "--label",
            f"com.aigw.postgres.migration-id={plan['migration_id']}",
            POSTGRES_IMAGE,
        )
        try:
            wait_for_postgres(container)
            # DHI initializes PGDATA but does not run files from
            # /docker-entrypoint-initdb.d. Create the reviewed target roles
            # and databases before pg_restore tries to use them.
            reconcile_database_contract(container)
            for database in EXPECTED_DATABASES:
                dump = postgres_dir / f"{database}.dump"
                if sha256_file(dump) != plan["dumps"][database]["sha256"]:
                    raise MigrationError(f"{database} dump changed after plan")
                docker(
                    "exec",
                    "-i",
                    container,
                    "pg_restore",
                    "--username",
                    "postgres",
                    "--dbname",
                    database,
                    "--single-transaction",
                    "--exit-on-error",
                    "--clean",
                    "--if-exists",
                    input_bytes=dump.read_bytes(),
                )
            # Restore may bring old ownership or grants with it. Re-run the
            # same idempotent contract before validating the restored data.
            reconcile_database_contract(container)
            metrics = validate_database(container)
        except Exception:
            plan["phase"] = "failed"
            plan["failed_at"] = utc_now()
            atomic_json(receipt_path, plan)
            raise
        finally:
            docker("rm", "--force", container, check=False)

    plan["phase"] = "migrated"
    plan["migrated_at"] = utc_now()
    plan["restored_metrics"] = metrics
    atomic_json(receipt_path, plan)
    print(f"POSTGRES_MIGRATION_RESTORED {plan['migration_id']}")


def check_volume_receipt(receipt: dict[str, object]) -> None:
    target = str(receipt.get("target_volume", ""))
    source = str(receipt.get("source_volume", ""))
    if not VOLUME_NAME.fullmatch(target) or not VOLUME_NAME.fullmatch(source) or target == source:
        raise MigrationError("migration receipt volume names are invalid")
    target_info = volume_info(target)
    source_info = volume_info(source)
    if target_info is None or source_info is None:
        raise MigrationError("source or target migration volume is missing")
    project = receipt.get("project")
    labels = target_info.get("Labels") or {}
    source_labels = source_info.get("Labels") or {}
    if (
        labels.get("com.docker.compose.project") != project
        or labels.get("com.aigw.postgres.major") != TARGET_MAJOR
        or labels.get("com.aigw.postgres.migration-id") != receipt.get("migration_id")
        or labels.get("com.docker.compose.volume") != "pg_data"
        or source_labels.get("com.docker.compose.project") != project
        or source_labels.get("com.docker.compose.volume") != "pg_data"
    ):
        raise MigrationError("PostgreSQL migration volume labels do not match the receipt")


def command_check_ready(args: argparse.Namespace) -> None:
    receipt = read_receipt(Path(args.receipt))
    if receipt.get("phase") not in {"migrated", "writes_opened", "validated"}:
        raise MigrationError("PostgreSQL 18 migration is not ready for deployment")
    if receipt.get("target_volume") != args.target_volume or receipt.get("project") != args.project:
        raise MigrationError("migration receipt does not match this deployment")
    if receipt.get("postgres_image") != POSTGRES_IMAGE:
        raise MigrationError("migration receipt has the wrong PostgreSQL image")
    check_volume_receipt(receipt)
    print(f"POSTGRES_MIGRATION_READY {receipt['migration_id']}")


def command_mark_writes_opened(args: argparse.Namespace) -> None:
    path = Path(args.receipt)
    receipt = read_receipt(path)
    if receipt.get("phase") == "migrated":
        check_volume_receipt(receipt)
        receipt["phase"] = "writes_opened"
        receipt["writes_opened_at"] = utc_now()
        atomic_json(path, receipt)
    elif receipt.get("phase") not in {"writes_opened", "validated"}:
        raise MigrationError("cannot open writes from this migration phase")
    print(f"POSTGRES_MIGRATION_WRITES_OPENED {receipt['migration_id']}")


def command_validate(args: argparse.Namespace) -> None:
    path = Path(args.receipt)
    receipt = read_receipt(path)
    if receipt.get("phase") not in {"writes_opened", "validated"}:
        raise MigrationError("deployment validation requires the writes-opened phase")
    command_check_ready(args)
    containers = project_containers(args.project)
    matches = [
        container
        for container in containers
        if ((container.get("Config") or {}).get("Labels") or {}).get(
            "com.docker.compose.service"
        )
        == "postgres"
    ]
    if len(matches) != 1 or not (matches[0].get("State") or {}).get("Running"):
        raise MigrationError("deployed PostgreSQL 18 container is not running")
    container = matches[0]
    if container.get("Image") != receipt.get("postgres_image_id"):
        raise MigrationError("deployed PostgreSQL image ID differs from the receipt")
    if not any(
        mount.get("Type") == "volume"
        and mount.get("Name") == receipt.get("target_volume")
        and mount.get("Destination") == POSTGRES_DATA_PATH
        for mount in container.get("Mounts") or []
        if isinstance(mount, dict)
    ):
        raise MigrationError("deployed PostgreSQL does not mount the migrated volume")
    metrics = validate_database(str(container["Id"]))
    restored = receipt.get("restored_metrics")
    if not isinstance(restored, dict):
        raise MigrationError("migration receipt lacks restored database metrics")
    for database in EXPECTED_DATABASES:
        if metrics[database]["objects"] < restored[database]["objects"]:
            raise MigrationError(f"deployed {database} has fewer objects than the restored copy")
    receipt["phase"] = "validated"
    receipt["validated_at"] = utc_now()
    receipt["deployed_metrics"] = metrics
    atomic_json(path, receipt)
    print(f"POSTGRES_MIGRATION_VALIDATED {receipt['migration_id']}")


def command_rollback(args: argparse.Namespace) -> None:
    if args.confirm != "ROLLBACK_POSTGRES_18_TO_16":
        raise MigrationError("rollback confirmation is missing")
    path = Path(args.receipt)
    receipt = read_receipt(path)
    phase = receipt.get("phase")
    if phase not in {
        "planned",
        "source_stopping",
        "failed",
        "migrated",
        "rollback_in_progress",
        "rolled_back",
    }:
        raise MigrationError(
            "rollback refused after writes reopened; keep PostgreSQL 18 and fix forward"
        )

    if (
        receipt.get("project") != args.project
        or receipt.get("target_volume") != args.target_volume
    ):
        raise MigrationError("migration receipt does not match this rollback request")
    quiesce = quiesce_contract_from_receipt(receipt)
    project_ids = set(
        exact_container_ids(
            quiesce["project_container_ids"], "receipt project container inventory"
        )
    )
    prior_running_ids = exact_container_ids(
        quiesce["prior_running_container_ids"], "receipt running container inventory"
    )

    source = str(receipt.get("source_volume", ""))
    source_info = volume_info(source) if VOLUME_NAME.fullmatch(source) else None
    source_labels = (source_info or {}).get("Labels") or {}
    if (
        source_info is None
        or source_labels.get("com.docker.compose.project") != args.project
        or source_labels.get("com.docker.compose.volume") != "pg_data"
    ):
        raise MigrationError("source PostgreSQL 16 volume is missing")

    target = str(receipt.get("target_volume", ""))
    target_info = volume_info(target)
    target_exists = target_info is not None
    if target_exists:
        labels = target_info.get("Labels") or {}
        if (
            labels.get("com.docker.compose.project") != args.project
            or labels.get("com.docker.compose.volume") != "pg_data"
            or labels.get("com.aigw.postgres.major") != TARGET_MAJOR
            or labels.get("com.aigw.postgres.migration-id") != receipt.get("migration_id")
        ):
            raise MigrationError("PostgreSQL 18 volume labels do not match the receipt")
    elif phase == "migrated":
        raise MigrationError("migrated PostgreSQL 18 volume is missing")

    containers = project_containers(args.project)
    inventory = exact_project_inventory(containers, args.project)
    if set(inventory) != project_ids:
        raise MigrationError("rollback refused because project containers changed")
    verify_recorded_source(inventory, quiesce)
    running_ids = sorted(
        container_id
        for container_id, container in inventory.items()
        if (container.get("State") or {}).get("Running") is True
    )

    # A completed rollback is a no-op when the exact old graph is already
    # running and the verified PG18 target is gone.
    if (
        phase == "rolled_back"
        and not target_exists
        and running_ids == list(prior_running_ids)
    ):
        print(f"POSTGRES_MIGRATION_ROLLED_BACK {receipt['migration_id']}")
        return

    temporary = docker(
        "ps",
        "-aq",
        "--no-trunc",
        "--filter",
        f"label=com.aigw.postgres.migration-id={receipt['migration_id']}",
    ).stdout.decode().split()
    if any(CONTAINER_ID.fullmatch(container_id) is None for container_id in temporary):
        raise MigrationError("temporary migration container inventory is malformed")
    if temporary:
        if len(temporary) != 1:
            raise MigrationError("temporary migration container inventory is not exact")
        try:
            inspected_temporary = json.loads(docker("inspect", temporary[0]).stdout)
        except (json.JSONDecodeError, TypeError) as exc:
            raise MigrationError("temporary migration container cannot be inspected") from exc
        if (
            not isinstance(inspected_temporary, list)
            or len(inspected_temporary) != 1
            or not isinstance(inspected_temporary[0], dict)
        ):
            raise MigrationError("temporary migration container cannot be inspected")
        temporary_container = inspected_temporary[0]
        temporary_config = temporary_container.get("Config") or {}
        temporary_labels = temporary_config.get("Labels") or {}
        expected_name = f"/aigw-postgres18-migration-{str(receipt['migration_id'])[:8]}"
        if (
            temporary_container.get("Id") != temporary[0]
            or temporary_container.get("Name") != expected_name
            or temporary_config.get("Image") != POSTGRES_IMAGE
            or temporary_container.get("Image") != receipt.get("postgres_image_id")
            or temporary_labels.get("com.aigw.postgres.migration-id")
            != receipt.get("migration_id")
            or "com.docker.compose.project" in temporary_labels
        ):
            raise MigrationError("temporary migration container does not match the receipt")

    # Write the resumable phase before the first stop/remove operation. A
    # retry can safely finish after an interrupted partial stop or removal.
    if phase != "rollback_in_progress":
        receipt["phase"] = "rollback_in_progress"
        receipt["rollback_started_at"] = utc_now()
        receipt["rollback_target_existed"] = target_exists
        atomic_json(path, receipt)
    if running_ids:
        docker("stop", "--time", "60", *running_ids)

    stopped_containers = project_containers(args.project)
    stopped_inventory = exact_project_inventory(stopped_containers, args.project)
    if set(stopped_inventory) != project_ids:
        raise MigrationError("rollback refused because project containers changed while stopping")
    verify_recorded_source(stopped_inventory, quiesce)
    if any(
        (container.get("State") or {}).get("Running") is True
        for container in stopped_inventory.values()
    ):
        raise MigrationError("rollback could not stop the exact project container inventory")

    if temporary:
        docker("rm", "--force", *temporary)
    if target_exists:
        docker("volume", "rm", target)
    docker("start", *prior_running_ids)

    restored_containers = project_containers(args.project)
    restored_inventory = exact_project_inventory(restored_containers, args.project)
    if set(restored_inventory) != project_ids:
        raise MigrationError("rollback refused because project containers changed while starting")
    verify_recorded_source(restored_inventory, quiesce)
    restored_running_ids = sorted(
        container_id
        for container_id, container in restored_inventory.items()
        if (container.get("State") or {}).get("Running") is True
    )
    if restored_running_ids != list(prior_running_ids):
        raise MigrationError("rollback did not restore the exact prior running graph")

    receipt["target_volume_removed"] = bool(
        target_exists or receipt.get("rollback_target_existed")
    )
    receipt["phase"] = "rolled_back"
    receipt["rolled_back_at"] = utc_now()
    atomic_json(path, receipt)
    print(f"POSTGRES_MIGRATION_ROLLED_BACK {receipt['migration_id']}")


def common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--project", default="ai-gateway")
    parser.add_argument("--target-volume", required=True)


def backup_arguments(parser: argparse.ArgumentParser) -> None:
    common_arguments(parser)
    parser.add_argument("--input", required=True)
    parser.add_argument("--identity", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--source-volume", required=True)
    parser.add_argument("--stack-dir", default="/opt/ai-gateway")
    parser.add_argument("--deployment-profile", required=True)
    parser.add_argument("--max-backup-age-minutes", type=int, default=30)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    plan = subparsers.add_parser("plan", help="validate inputs and write a read-only plan")
    backup_arguments(plan)
    plan.set_defaults(handler=command_plan)
    migrate = subparsers.add_parser("migrate", help="restore logical dumps into a new PG18 volume")
    backup_arguments(migrate)
    migrate.add_argument("--confirm", required=True)
    migrate.set_defaults(handler=command_migrate)
    ready = subparsers.add_parser("check-ready", help="verify the migration receipt and both volumes")
    common_arguments(ready)
    ready.set_defaults(handler=command_check_ready)
    opened = subparsers.add_parser(
        "mark-writes-opened", help="close the PostgreSQL 16 rollback window"
    )
    common_arguments(opened)
    opened.set_defaults(handler=command_mark_writes_opened)
    validate = subparsers.add_parser("validate", help="validate the deployed PostgreSQL 18 database")
    common_arguments(validate)
    validate.set_defaults(handler=command_validate)
    rollback = subparsers.add_parser("rollback", help="restart exact PG16 containers before cutover")
    common_arguments(rollback)
    rollback.add_argument("--confirm", required=True)
    rollback.set_defaults(handler=command_rollback)
    args = parser.parse_args(argv)
    if hasattr(args, "max_backup_age_minutes") and not 1 <= args.max_backup_age_minutes <= 60:
        parser.error("--max-backup-age-minutes must be between 1 and 60")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        args.handler(args)
    except (MigrationError, OSError, UnicodeError, KeyError, TypeError) as exc:
        print(f"postgres migration refused: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
