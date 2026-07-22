#!/usr/bin/env python3
"""Rehearse the fixed PostgreSQL 16 to 18 move in local seeded PreProd.

This program has no deployment, image, host, volume, or path switches.  It can
touch only the ``aigw-preprod`` Docker project created from the verified local
schema-v2 seed receipt.  Run it through
``ansible/preprod-postgres18-rehearsal.yml``; do not run it against production.
"""

from __future__ import annotations

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
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
COMPOSE_DIR = ROOT / "compose"
SECRETS_DIR = COMPOSE_DIR / "secrets"
ENV_FILE = SECRETS_DIR / "preprod.env"
SEED_RECEIPT = SECRETS_DIR / "preprod-seed-receipt.json"
SEED_OVERLAY = SECRETS_DIR / "preprod-seed-images.yml"
RECEIPT_FILE = SECRETS_DIR / "preprod-postgres18-rehearsal-receipt.json"
PREPROD = ROOT / "scripts/preprod.py"
E2E = ROOT / "scripts/test-e2e-preprod.py"
CRIBL_E2E = ROOT / "scripts/test-preprod-cribl-security.py"

PROJECT = "aigw-preprod"
PREFIX = "aigw-preprod"
DOMAIN = "aigw.internal"
SUBNET_OCTET = "29"
SOURCE_VOLUME = "aigw-preprod_pg16_data"
TARGET_VOLUME = "aigw-preprod_pg18_data"
RESTORE_CONTAINER = "aigw-preprod-postgres18-physical-restore"
POSTGRES_SERVICE = "postgres"
POSTGRES16_DATA = "/var/lib/postgresql/16/data"
POSTGRES18_DATA = "/var/lib/postgresql/18/data"
POSTGRES_RECONCILE = "/docker-entrypoint-initdb.d/01-init-databases.sh"
RECEIPT_FORMAT = "aigw-preprod-postgres18-rehearsal-v1"
IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
LOCAL_DOCKER = re.compile(r"^unix:///[A-Za-z0-9_./-]+$")

POSTGRES16_IMAGE = (
    "dhi.io/postgres:16.14@sha256:"
    "47a12e559e8c418ed54e27da521efcbf4c00fc1c26e86eb58d82845afd7c57c7"
)
POSTGRES18_IMAGE = (
    "dhi.io/postgres:18.4@sha256:"
    "a807e832c1fc9ded731956abcb53dc98ed003fd82e27275eaef8dcf52fb90236"
)

# This is a bounded production-size floor for the prototype: at least 384 MiB
# across all three application databases. Every row comes from fixed text.
FIXTURE_PROFILE: dict[str, dict[str, int]] = {
    "keycloak": {"rows": 512_000, "minimum_bytes": 128 * 1024 * 1024},
    "litellm": {"rows": 512_000, "minimum_bytes": 128 * 1024 * 1024},
    "rotator": {"rows": 512_000, "minimum_bytes": 128 * 1024 * 1024},
}


class RehearsalError(RuntimeError):
    """The bounded local rehearsal failed closed."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def fail(message: str) -> None:
    raise RehearsalError(message)


def run(
    command: list[str],
    *,
    capture: bool = False,
    input_bytes: bytes | None = None,
    label: str,
) -> subprocess.CompletedProcess[bytes]:
    """Run one argv-only command with no inherited stdin."""

    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            input=input_bytes,
            stdin=subprocess.DEVNULL if input_bytes is None else None,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            check=False,
        )
    except OSError as exc:
        raise RehearsalError(f"{label} could not start: {exc}") from exc
    if result.returncode:
        detail = (result.stderr or b"").decode("utf-8", "replace").strip().splitlines()
        suffix = f": {detail[-1][:400]}" if detail else ""
        raise RehearsalError(
            f"{label} failed with exit code {result.returncode}{suffix}"
        )
    return result


def read_env() -> dict[str, str]:
    try:
        metadata = ENV_FILE.lstat()
    except FileNotFoundError as exc:
        raise RehearsalError("the activated PreProd environment is missing") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != os.geteuid()
    ):
        fail("the activated PreProd environment is not a private caller-owned file")
    values: dict[str, str] = {}
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        name, separator, value = line.partition("=")
        if not separator:
            continue
        if name in values:
            fail(f"the PreProd environment repeats {name}")
        values[name] = value
    endpoint = values.get("PREPROD_DOCKER_ENDPOINT", "")
    if LOCAL_DOCKER.fullmatch(endpoint) is None or ".." in Path(endpoint[7:]).parts:
        fail("the rehearsal requires the recorded local Unix-socket Docker engine")
    if values.get("PREPROD_PROJECT") != PROJECT:
        fail("the rehearsal environment escaped the fixed PreProd project")
    return values


def read_seed_receipt() -> dict[str, Any]:
    try:
        metadata = SEED_RECEIPT.lstat()
        value = json.loads(SEED_RECEIPT.read_text(encoding="utf-8"))
    except (FileNotFoundError, UnicodeError, json.JSONDecodeError) as exc:
        raise RehearsalError("the verified schema-v2 seed receipt is missing") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o644
        or not isinstance(value, dict)
        or value.get("schema_version") != 2
        or value.get("release_scope") != "preprod"
        or not isinstance(value.get("manifest_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", value["manifest_sha256"]) is None
    ):
        fail("the local seed receipt is not one safe preprod schema-v2 receipt")
    images = value.get("external_images")
    if not isinstance(images, dict):
        fail("the local seed receipt has no external image inventory")
    expected = {
        POSTGRES16_IMAGE: "sha256:" + POSTGRES16_IMAGE.rsplit("@sha256:", 1)[1],
        POSTGRES18_IMAGE: "sha256:" + POSTGRES18_IMAGE.rsplit("@sha256:", 1)[1],
    }
    for reference, image_id in expected.items():
        if images.get(reference) != image_id or IMAGE_ID.fullmatch(image_id) is None:
            fail(f"the exact seeded image is missing: {reference.split('@', 1)[0]}")
    return value


def docker(endpoint: str, *arguments: str, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
    return run(
        ["docker", "--host", endpoint, *arguments],
        label="Docker " + " ".join(arguments[:2]),
        **kwargs,
    )


def compose_command(endpoint: str, major: str, *arguments: str) -> list[str]:
    command = [
        "docker",
        "--host",
        endpoint,
        "compose",
        "--project-name",
        PROJECT,
        "--env-file",
        str(ENV_FILE),
        "-f",
        str(COMPOSE_DIR / "docker-compose.yml"),
        "-f",
        str(COMPOSE_DIR / "docker-compose.preprod.yml"),
        "-f",
        str(SEED_OVERLAY),
    ]
    if major == "16":
        command.extend(
            ["-f", str(COMPOSE_DIR / "docker-compose.preprod-postgres16.yml")]
        )
    command.extend(["--profile", "preprod", *arguments])
    return command


def compose(
    endpoint: str,
    major: str,
    *arguments: str,
    capture: bool = False,
    input_bytes: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    return run(
        compose_command(endpoint, major, *arguments),
        capture=capture,
        input_bytes=input_bytes,
        label=f"PostgreSQL {major} PreProd Compose",
    )


def preprod_command(major: str, action: str) -> list[str]:
    command = [
        sys.executable,
        "-I",
        str(PREPROD),
        "--domain",
        DOMAIN,
        "--project",
        PROJECT,
        "--prefix",
        PREFIX,
        "--subnet-octet",
        SUBNET_OCTET,
        "--image-mode",
        "seed",
        "--postgres-major",
        major,
    ]
    if major == "16":
        command.append("--confirm-postgres16-rehearsal")
    command.append(action)
    return command


def preprod(major: str, action: str) -> None:
    command = preprod_command(major, action)
    run(command, label=f"PreProd PostgreSQL {major} {action}")


def full_acceptance(major: str) -> None:
    """Run the same application and edge checks as the PreProd Ansible role."""

    for action in ("prepare", "create-networks", "compose-config", "start"):
        preprod(major, action)
    for action in (
        "reconcile-openwebui-key",
        "bootstrap-vault",
        "auto-initialize-identity",
        "configure-users",
        "configure-wif",
        "verify",
    ):
        preprod(major, action)
    acceptance_arguments = [
        "--image-mode",
        "seed",
        "--postgres-major",
        major,
    ]
    if major == "16":
        acceptance_arguments.append("--confirm-postgres16-rehearsal")
    run(
        [sys.executable, "-I", str(E2E), *acceptance_arguments],
        label=f"PostgreSQL {major} full PreProd acceptance",
    )
    run(
        [sys.executable, "-I", str(CRIBL_E2E), *acceptance_arguments],
        label=f"PostgreSQL {major} Cribl acceptance",
    )


def postgres_container(endpoint: str, *, running: bool | None = None) -> dict[str, Any]:
    result = docker(
        endpoint,
        "ps",
        "--all",
        "--no-trunc",
        "--quiet",
        "--filter",
        f"label=com.docker.compose.project={PROJECT}",
        "--filter",
        f"label=com.docker.compose.service={POSTGRES_SERVICE}",
        capture=True,
    )
    ids = result.stdout.decode("utf-8", "strict").splitlines()
    if len(ids) != 1 or re.fullmatch(r"[0-9a-f]{64}", ids[0]) is None:
        fail("the rehearsal requires exactly one owned PostgreSQL container")
    document = json.loads(
        docker(endpoint, "inspect", ids[0], capture=True).stdout.decode("utf-8")
    )
    if not isinstance(document, list) or len(document) != 1:
        fail("Docker returned an invalid PostgreSQL inspection")
    item = document[0]
    state = item.get("State") if isinstance(item, dict) else None
    is_running = state.get("Running") if isinstance(state, dict) else None
    if running is not None and is_running is not running:
        fail("the owned PostgreSQL container has the wrong running state")
    return item


def postgres_exec(
    endpoint: str,
    *arguments: str,
    capture: bool = False,
    input_bytes: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    container = postgres_container(endpoint, running=True)
    command = ["exec"]
    if input_bytes is not None:
        command.append("-i")
    command.extend([str(container["Id"]), *arguments])
    return docker(
        endpoint,
        *command,
        capture=capture,
        input_bytes=input_bytes,
    )


def psql(endpoint: str, database: str, sql: str) -> str:
    result = postgres_exec(
        endpoint,
        "psql",
        "--username",
        "postgres",
        "--dbname",
        database,
        "--no-align",
        "--tuples-only",
        "--set",
        "ON_ERROR_STOP=1",
        "--command",
        sql,
        capture=True,
    )
    return result.stdout.decode("utf-8", "strict").strip()


def fixture_sql(database: str, rows: int) -> str:
    literals = " || ".join(
        f"encode(sha256(convert_to('{database}:' || value || ':{salt}','UTF8')),'hex')"
        for salt in range(4)
    )
    return (
        "CREATE TABLE IF NOT EXISTS public.aigw_preprod_migration_fixture ("
        "id bigint PRIMARY KEY, payload text NOT NULL);"
        "TRUNCATE public.aigw_preprod_migration_fixture;"
        "INSERT INTO public.aigw_preprod_migration_fixture(id,payload) "
        f"SELECT value, {literals} FROM generate_series(1,{rows}) AS value;"
    )


def fixture_metrics(endpoint: str, database: str) -> dict[str, object]:
    profile = FIXTURE_PROFILE[database]
    fields = psql(
        endpoint,
        database,
        "SELECT count(*), pg_total_relation_size("
        "'public.aigw_preprod_migration_fixture'::regclass) "
        "FROM public.aigw_preprod_migration_fixture;",
    ).split("|")
    if len(fields) != 2 or not all(field.isdigit() for field in fields):
        fail(f"cannot read the {database} fixture size")
    rows, size_bytes = (int(field) for field in fields)
    if rows != profile["rows"] or size_bytes < profile["minimum_bytes"]:
        fail(f"the deterministic {database} fixture is incomplete")
    output = postgres_exec(
        endpoint,
        "psql",
        "--username",
        "postgres",
        "--dbname",
        database,
        "--set",
        "ON_ERROR_STOP=1",
        "--command",
        "COPY (SELECT id,payload FROM public.aigw_preprod_migration_fixture "
        "ORDER BY id) TO STDOUT WITH (FORMAT csv);",
        capture=True,
    ).stdout
    return {
        "rows": rows,
        "bytes": size_bytes,
        "content_sha256": hashlib.sha256(output).hexdigest(),
    }


def create_fixtures(endpoint: str) -> dict[str, dict[str, object]]:
    for database, profile in FIXTURE_PROFILE.items():
        psql(endpoint, database, fixture_sql(database, profile["rows"]))
    return {database: fixture_metrics(endpoint, database) for database in FIXTURE_PROFILE}


def verify_fixtures(
    endpoint: str, expected: dict[str, dict[str, object]]
) -> dict[str, dict[str, object]]:
    actual = {database: fixture_metrics(endpoint, database) for database in FIXTURE_PROFILE}
    for database in FIXTURE_PROFILE:
        if (
            actual[database]["rows"] != expected[database]["rows"]
            or actual[database]["content_sha256"]
            != expected[database]["content_sha256"]
        ):
            fail(f"the {database} fixture changed during migration")
    return actual


def logical_dumps(endpoint: str, directory: Path) -> dict[str, dict[str, object]]:
    records: dict[str, dict[str, object]] = {}
    for database in FIXTURE_PROFILE:
        data = postgres_exec(
            endpoint,
            "pg_dump",
            "--username",
            "postgres",
            "--dbname",
            database,
            "--format",
            "custom",
            "--no-owner",
            "--no-privileges",
            capture=True,
        ).stdout
        if len(data) < 1024:
            fail(f"the {database} logical dump is unexpectedly small")
        path = directory / f"{database}.dump"
        path.write_bytes(data)
        path.chmod(0o600)
        records[database] = {
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    return records


def volume_document(endpoint: str, name: str) -> dict[str, Any] | None:
    result = run(
        ["docker", "--host", endpoint, "volume", "inspect", name],
        capture=True,
        label=f"Docker volume inspection for {name}",
    )
    try:
        document = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RehearsalError("Docker returned invalid volume JSON") from exc
    if not isinstance(document, list) or len(document) != 1:
        fail(f"the fixed volume is missing: {name}")
    item = document[0]
    labels = item.get("Labels") if isinstance(item, dict) else None
    if not isinstance(labels, dict) or labels.get("com.aigw.preprod.project") != PROJECT:
        fail(f"the fixed volume is not owned by local PreProd: {name}")
    return item


def create_owned_volume(endpoint: str, name: str) -> None:
    docker(
        endpoint,
        "volume",
        "create",
        "--label",
        f"com.aigw.preprod.project={PROJECT}",
        "--label",
        f"com.docker.compose.project={PROJECT}",
        "--label",
        "com.docker.compose.volume=pg_data",
        name,
    )
    volume_document(endpoint, name)


def remove_owned_volume(endpoint: str, name: str) -> None:
    volume_document(endpoint, name)
    docker(endpoint, "volume", "rm", name)


def stop_project(endpoint: str, major: str) -> None:
    compose(endpoint, major, "stop", "--timeout", "60")


def stop_application_writers(endpoint: str) -> None:
    """Stop every running project container except the source database."""

    ids = docker(
        endpoint,
        "ps",
        "--no-trunc",
        "--quiet",
        "--filter",
        f"label=com.docker.compose.project={PROJECT}",
        capture=True,
    ).stdout.decode("utf-8", "strict").splitlines()
    if not ids or any(re.fullmatch(r"[0-9a-f]{64}", item) is None for item in ids):
        fail("Docker returned an invalid running PreProd container inventory")
    documents = json.loads(
        docker(endpoint, "inspect", *ids, capture=True).stdout.decode("utf-8")
    )
    if not isinstance(documents, list) or len(documents) != len(ids):
        fail("Docker returned an incomplete PreProd writer inventory")
    postgres_ids: list[str] = []
    writer_ids: list[str] = []
    for document in documents:
        labels = (document.get("Config") or {}).get("Labels") or {}
        if (
            labels.get("com.docker.compose.project") != PROJECT
            or labels.get("com.aigw.preprod.project") != PROJECT
        ):
            fail("the PreProd writer inventory contains an unowned container")
        if labels.get("com.docker.compose.service") == POSTGRES_SERVICE:
            postgres_ids.append(str(document.get("Id")))
        else:
            writer_ids.append(str(document.get("Id")))
    if len(postgres_ids) != 1 or not writer_ids:
        fail("the full PreProd writer graph is incomplete")
    docker(endpoint, "stop", "--time", "60", *sorted(writer_ids))
    psql(endpoint, "postgres", "CHECKPOINT;")


def start_postgres18_for_restore(endpoint: str, expected_image_id: str) -> None:
    preprod("18", "prepare")
    preprod("18", "compose-config")
    compose(endpoint, "18", "up", "-d", "postgres")
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        item = postgres_container(endpoint)
        health = (item.get("State") or {}).get("Health") or {}
        if item.get("Image") == expected_image_id and health.get("Status") == "healthy":
            break
        time.sleep(2)
    else:
        fail("the exact PostgreSQL 18 seed image did not become healthy")
    postgres_exec(endpoint, POSTGRES_RECONCILE)
    version = psql(endpoint, "postgres", "SHOW server_version;")
    if version != "18.4":
        fail(f"the target server is {version}, expected 18.4")


def restore_logical_dumps(endpoint: str, directory: Path) -> None:
    for database in FIXTURE_PROFILE:
        data = (directory / f"{database}.dump").read_bytes()
        postgres_exec(
            endpoint,
            "pg_restore",
            "--username",
            "postgres",
            "--dbname",
            database,
            "--single-transaction",
            "--exit-on-error",
            "--clean",
            "--if-exists",
            "--no-owner",
            "--no-privileges",
            input_bytes=data,
        )
    postgres_exec(endpoint, POSTGRES_RECONCILE)


def stable_runtime_fingerprint(endpoint: str) -> str:
    container = postgres_container(endpoint, running=True)
    volume = volume_document(endpoint, TARGET_VOLUME)
    stable = {
        "container": {
            "id": container.get("Id"),
            "image": container.get("Image"),
            "labels": (container.get("Config") or {}).get("Labels"),
            "mounts": container.get("Mounts"),
        },
        "volume": {
            "name": volume.get("Name") if volume else None,
            "driver": volume.get("Driver") if volume else None,
            "labels": volume.get("Labels") if volume else None,
            "options": volume.get("Options") if volume else None,
            "scope": volume.get("Scope") if volume else None,
        },
    }
    canonical = json.dumps(stable, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def prove_downgrade_refusal(
    endpoint: str,
    fixtures: dict[str, dict[str, object]],
    seed: dict[str, Any],
) -> dict[str, object]:
    atomic_receipt(
        {
            "format": RECEIPT_FORMAT,
            "status": "running",
            "phase": "writes_opened",
            "project": PROJECT,
            "manifest_sha256": seed["manifest_sha256"],
            "target_image_id": seed["external_images"][POSTGRES18_IMAGE],
            "target_volume": TARGET_VOLUME,
        }
    )
    before_runtime = stable_runtime_fingerprint(endpoint)
    before_fixtures = verify_fixtures(endpoint, fixtures)
    try:
        run(
            preprod_command("16", "compose-config"),
            capture=True,
            label="real post-write PostgreSQL 16 downgrade request",
        )
    except RehearsalError as exc:
        reason = str(exc)
        if "downgrade refused after PostgreSQL 18 writes opened" not in reason:
            fail("the real PostgreSQL 16 command failed for the wrong reason")
    else:  # pragma: no cover - the command must be rejected by preprod.py
        fail("the post-write downgrade request was not refused")
    after_runtime = stable_runtime_fingerprint(endpoint)
    after_fixtures = verify_fixtures(endpoint, fixtures)
    if before_runtime != after_runtime or before_fixtures != after_fixtures:
        fail("the refused downgrade mutated the PostgreSQL 18 release")
    return {
        "refused": True,
        "reason": reason,
        "runtime_sha256_before": before_runtime,
        "runtime_sha256_after": after_runtime,
        "fixtures_unchanged": True,
    }


def write_physical_backup(endpoint: str, container_id: str, path: Path) -> dict[str, object]:
    command = [
        "docker",
        "--host",
        endpoint,
        "cp",
        "--archive",
        f"{container_id}:{POSTGRES18_DATA}/.",
        "-",
    ]
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        pass
    else:
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            fail("the fixed physical-backup scratch file is unsafe")
        path.unlink()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        result = subprocess.run(
            command,
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.PIPE,
            check=False,
        )
    path.chmod(0o600)
    if result.returncode:
        fail("Docker could not create the PostgreSQL 18 physical backup")
    size = path.stat().st_size
    if size < 1024 * 1024:
        fail("the PostgreSQL 18 physical backup is unexpectedly small")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return {"bytes": size, "sha256": digest.hexdigest()}


def restore_physical_backup(
    endpoint: str, path: Path, postgres_image: str, expected_image_id: str
) -> None:
    compose(endpoint, "18", "down", "--remove-orphans", "--timeout", "60")
    remove_owned_volume(endpoint, TARGET_VOLUME)
    create_owned_volume(endpoint, TARGET_VOLUME)
    docker(
        endpoint,
        "create",
        "--name",
        RESTORE_CONTAINER,
        "--network",
        "none",
        "--pull",
        "never",
        "--label",
        f"com.aigw.preprod.project={PROJECT}",
        "--label",
        f"com.docker.compose.project={PROJECT}",
        "--volume",
        f"{TARGET_VOLUME}:{POSTGRES18_DATA}",
        postgres_image,
    )
    helper = json.loads(
        docker(endpoint, "inspect", RESTORE_CONTAINER, capture=True).stdout.decode()
    )[0]
    if helper.get("Image") != expected_image_id:
        fail("the physical restore helper does not use the exact PostgreSQL 18 image")
    try:
        with path.open("rb") as source:
            result = subprocess.run(
                [
                    "docker",
                    "--host",
                    endpoint,
                    "cp",
                    "--archive",
                    "-",
                    f"{RESTORE_CONTAINER}:{POSTGRES18_DATA}",
                ],
                cwd=ROOT,
                stdin=source,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                check=False,
            )
        if result.returncode:
            fail("Docker could not restore the PostgreSQL 18 physical backup")
    finally:
        docker(endpoint, "rm", "--force", RESTORE_CONTAINER)


def atomic_receipt(document: dict[str, object]) -> None:
    SECRETS_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(
        prefix=".preprod-postgres18-rehearsal.", suffix=".tmp", dir=SECRETS_DIR
    )
    temporary = Path(name)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(document, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(RECEIPT_FILE)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def run_rehearsal() -> dict[str, object]:
    if os.geteuid() == 0:
        fail("the local PostgreSQL rehearsal must run as the Docker Desktop operator")
    seed = read_seed_receipt()
    environment = read_env()
    endpoint = environment["PREPROD_DOCKER_ENDPOINT"]
    expected_pg16 = seed["external_images"][POSTGRES16_IMAGE]
    expected_pg18 = seed["external_images"][POSTGRES18_IMAGE]
    started_at = utc_now()

    full_acceptance("16")
    source = postgres_container(endpoint, running=True)
    if source.get("Image") != expected_pg16:
        fail("the PostgreSQL 16 graph does not use the exact seeded image")
    if not psql(endpoint, "postgres", "SHOW server_version;").startswith("16.14"):
        fail("the source graph is not PostgreSQL 16.14")
    source_volume = volume_document(endpoint, SOURCE_VOLUME)
    fixtures = create_fixtures(endpoint)

    with tempfile.TemporaryDirectory(
        prefix="preprod-postgres18-logical.", dir=SECRETS_DIR
    ) as directory_name:
        directory = Path(directory_name)
        directory.chmod(0o700)
        stop_application_writers(endpoint)
        fault_dumps = logical_dumps(endpoint, directory)
        stop_project(endpoint, "16")

        # Inject a failure before cutover.  The target is removed and the exact
        # source graph is restarted before any PostgreSQL 18 writes can occur.
        create_owned_volume(endpoint, TARGET_VOLUME)
        remove_owned_volume(endpoint, TARGET_VOLUME)
        full_acceptance("16")
        rollback_fixtures = verify_fixtures(endpoint, fixtures)
        rollback_volume = volume_document(endpoint, SOURCE_VOLUME)
        if rollback_volume.get("Name") != source_volume.get("Name"):
            fail("the pre-cutover rollback did not preserve the source volume")
        stop_application_writers(endpoint)
        dumps = logical_dumps(endpoint, directory)
        stop_project(endpoint, "16")

        start_postgres18_for_restore(endpoint, expected_pg18)
        restore_logical_dumps(endpoint, directory)
        logical_fixtures = verify_fixtures(endpoint, fixtures)

    full_acceptance("18")
    writes_opened_fixtures = verify_fixtures(endpoint, fixtures)
    downgrade = prove_downgrade_refusal(endpoint, fixtures, seed)

    backup_path = SECRETS_DIR / ".preprod-postgres18-physical-backup.tar"
    stop_project(endpoint, "18")
    stopped = postgres_container(endpoint, running=False)
    physical = write_physical_backup(endpoint, str(stopped["Id"]), backup_path)
    try:
        restore_physical_backup(endpoint, backup_path, POSTGRES18_IMAGE, expected_pg18)
    finally:
        try:
            backup_path.unlink()
        except FileNotFoundError:
            pass

    full_acceptance("18")
    restored_fixtures = verify_fixtures(endpoint, fixtures)
    final_postgres = postgres_container(endpoint, running=True)
    if final_postgres.get("Image") != expected_pg18:
        fail("the restored graph does not use the exact PostgreSQL 18 seed image")

    # The old major is retained through every rollback proof, then retired so
    # the ordinary exact-manifest clean-room command can remove the rehearsal.
    remove_owned_volume(endpoint, SOURCE_VOLUME)
    document: dict[str, object] = {
        "format": RECEIPT_FORMAT,
        "status": "passed",
        "started_at": started_at,
        "completed_at": utc_now(),
        "manifest_sha256": seed["manifest_sha256"],
        "platform": seed["platform"],
        "project": PROJECT,
        "source": {
            "major": 16,
            "image": POSTGRES16_IMAGE,
            "image_id": expected_pg16,
            "volume": SOURCE_VOLUME,
            "full_application_acceptance": True,
        },
        "target": {
            "major": 18,
            "version": "18.4",
            "image": POSTGRES18_IMAGE,
            "image_id": expected_pg18,
            "volume": TARGET_VOLUME,
            "full_application_acceptance": True,
        },
        "fixture_profile": FIXTURE_PROFILE,
        "fixtures": fixtures,
        "pre_cutover_fault": {
            "injected": True,
            "target_removed": True,
            "source_restarted": True,
            "source_volume_preserved": True,
            "backup_before_fault": fault_dumps,
            "fixtures": rollback_fixtures,
        },
        "logical_migration": {
            "dumps": dumps,
            "fixtures_after_restore": logical_fixtures,
        },
        "writes_opened": {
            "recorded": True,
            "fixtures": writes_opened_fixtures,
        },
        "downgrade_refusal": downgrade,
        "physical_restore": {
            **physical,
            "same_major": True,
            "fixtures": restored_fixtures,
        },
        "source_retired_after_acceptance": True,
    }
    atomic_receipt(document)
    return document


def main() -> int:
    try:
        document = run_rehearsal()
    except (OSError, UnicodeError, ValueError, RehearsalError) as exc:
        print(f"POSTGRES18_PREPROD_REHEARSAL_REFUSED {exc}", file=sys.stderr)
        return 1
    print(
        "POSTGRES18_PREPROD_REHEARSAL_PASSED "
        + json.dumps(document, sort_keys=True, separators=(",", ":"))
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
