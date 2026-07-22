#!/usr/bin/env bash
# Quiesced, age-encrypted state backup for the single-VM AI Gateway.
set -euo pipefail
umask 077

usage() {
  cat >&2 <<EOF
usage: sudo $0 --recipient age1... --output /independent/mount/aigw-STATE.tar.gz.age
       sudo $0 --recipient age1... --output /independent/mount/aigw-PG16.tar.gz.age \\
         --major-migration-quiesce --confirm QUIESCE_POSTGRES_16_FOR_MAJOR_MIGRATION
EOF
  exit 2
}

[[ $(id -u) -eq 0 ]] || { echo "state backup must run as root" >&2; exit 1; }
STACK_DIR="${STACK_DIR:-/opt/ai-gateway}"
PROJECT="${COMPOSE_PROJECT_NAME:-ai-gateway}"
HELPER_IMAGE="dhi.io/busybox:1.38.0-alpine@sha256:69a25015bda2c7dfac5d3a88990b56bc0f38539b313c448b171edef1497193ad"
# Preserve registry credentials in DOCKER_CONFIG when a future helper needs
# them, but never inherit a controller-selected daemon/context from root's
# environment. All maintenance Docker operations target the local socket.
unset DOCKER_CONTEXT DOCKER_HOST DOCKER_TLS DOCKER_TLS_VERIFY DOCKER_CERT_PATH DOCKER_API_VERSION
docker_cmd=(docker --host unix:///run/docker.sock)
recipient=""
output=""
major_migration_quiesce=false
confirmation=""
while (($#)); do
  case "$1" in
    --recipient) [[ $# -ge 2 ]] || usage; recipient="$2"; shift 2 ;;
    --output) [[ $# -ge 2 ]] || usage; output="$2"; shift 2 ;;
    --major-migration-quiesce) major_migration_quiesce=true; shift ;;
    --confirm) [[ $# -ge 2 ]] || usage; confirmation="$2"; shift 2 ;;
    *) usage ;;
  esac
done
if [[ "$major_migration_quiesce" == true ]]; then
  [[ "$confirmation" == QUIESCE_POSTGRES_16_FOR_MAJOR_MIGRATION ]] || usage
else
  [[ -z "$confirmation" ]] || usage
fi
[[ "$recipient" =~ ^age1[0-9a-z]{58}$ ]] || { echo "only an age X25519 recipient is accepted" >&2; exit 2; }
[[ "$output" = /* && "$output" == *.age ]] || { echo "--output must be an absolute .age path" >&2; exit 2; }
[[ -d "$STACK_DIR" && -f "$STACK_DIR/docker-compose.yml" && -f "$STACK_DIR/docker-compose.dns.yml" && -f "$STACK_DIR/docker-compose.platform-dns.yml" ]] || { echo "stack directory is not deployed" >&2; exit 1; }
[[ -d "$(dirname "$output")" && ! -e "$output" && ! -L "$output" ]] || { echo "backup output must be new in an existing directory" >&2; exit 1; }
for command in age age-inspect docker findmnt sha256sum tar python3; do
  command -v "$command" >/dev/null || { echo "required command missing: $command" >&2; exit 1; }
done

# A copy on the same block filesystem is not disaster recovery. The explicit
# override exists only for a deliberate, non-production restore rehearsal.
stack_device="$(findmnt -n -o MAJ:MIN -T "$STACK_DIR")"
output_device="$(findmnt -n -o MAJ:MIN -T "$(dirname "$output")")"
if [[ "$stack_device" == "$output_device" ]] &&
   [[ "${AIGW_ALLOW_SAME_DEVICE_BACKUP:-}" != "I_UNDERSTAND_THIS_IS_NOT_DR" ]]; then
  echo "backup destination shares the stack filesystem; use independent encrypted/off-host storage" >&2
  exit 1
fi

cd "$STACK_DIR"
compose=("$STACK_DIR/scripts/aigw-compose.sh")
deployment_profile="$(grep -E '^DEPLOYMENT_PROFILE=' .env | tail -n 1 | cut -d= -f2- || true)"
mkdir -p .state
chmod 0700 .state
staging="$(mktemp -d "$STACK_DIR/.state-backup.XXXXXX")"
partial="${output}.partial.$$"
running_file="$staging/running-services.txt"
restarted=false

mapfile -t running < <("${compose[@]}" ps --services --filter status=running | LC_ALL=C sort -u)
printf '%s\n' "${running[@]}" > "$running_file"
running_containers=()
for service in "${running[@]}"; do
  mapfile -t service_containers < <("${compose[@]}" ps -q "$service")
  ((${#service_containers[@]} > 0)) || {
    echo "running service has no concrete container: $service" >&2
    exit 1
  }
  running_containers+=("${service_containers[@]}")
done
if ((${#running_containers[@]} > 0)); then
  mapfile -t running_containers < <(
    printf '%s\n' "${running_containers[@]}" | LC_ALL=C sort -u
  )
fi

restart_original() {
  local rc=$?
  if [[ "$restarted" != true && ${#running_containers[@]} -gt 0 ]]; then
    # Start only the exact containers that were running before quiesce.
    # `docker compose start` traverses dependencies and can incorrectly rerun
    # the successful exited volume-init one-shot.
    "${docker_cmd[@]}" start "${running_containers[@]}" >/dev/null 2>&1 || {
      echo "WARNING: backup completed/failed but one or more original containers did not restart" >&2
      rc=1
    }
    restarted=true
  fi
  rm -rf "$staging"
  rm -f "$partial"
  exit "$rc"
}
trap restart_original EXIT INT TERM

postgres_cid="$("${compose[@]}" ps -q postgres)"
[[ -n "$postgres_cid" ]] || { echo "PostgreSQL must be running" >&2; exit 1; }

project_container_ids=()
writer_container_ids=()
postgres_source_json=""
stopped_container_states_json=""

prove_major_migration_quiesce() {
  local -a current_running=()
  mapfile -t current_running < <(
    "${docker_cmd[@]}" ps -q --no-trunc \
      --filter "label=com.docker.compose.project=$PROJECT" | LC_ALL=C sort -u
  )
  if ((${#current_running[@]} != 1)) || [[ "${current_running[0]:-}" != "$postgres_cid" ]]; then
    echo "major migration requires PostgreSQL to be the only running project container" >&2
    return 1
  fi
}

if [[ "$major_migration_quiesce" == true ]]; then
  mapfile -t project_container_ids < <(
    "${docker_cmd[@]}" ps -aq --no-trunc \
      --filter "label=com.docker.compose.project=$PROJECT" | LC_ALL=C sort -u
  )
  mapfile -t docker_running_containers < <(
    "${docker_cmd[@]}" ps -q --no-trunc \
      --filter "label=com.docker.compose.project=$PROJECT" | LC_ALL=C sort -u
  )
  ((${#project_container_ids[@]} > 0)) || {
    echo "major migration found no project container inventory" >&2
    exit 1
  }
  for container_id in "${project_container_ids[@]}" "${running_containers[@]}"; do
    [[ "$container_id" =~ ^[0-9a-f]{64}$ ]] || {
      echo "major migration found a malformed project container ID" >&2
      exit 1
    }
  done
  [[ "$(printf '%s\n' "${docker_running_containers[@]}")" == \
      "$(printf '%s\n' "${running_containers[@]}")" ]] || {
    echo "Compose and Docker disagree about the exact running project containers" >&2
    exit 1
  }
  [[ " ${project_container_ids[*]} " == *" $postgres_cid "* ]] || {
    echo "PostgreSQL is missing from the exact project container inventory" >&2
    exit 1
  }
  for container_id in "${running_containers[@]}"; do
    [[ "$container_id" == "$postgres_cid" ]] || writer_container_ids+=("$container_id")
  done

  postgres_inspect="$staging/.postgres-source-inspect.json"
  "${docker_cmd[@]}" inspect "$postgres_cid" > "$postgres_inspect"
  postgres_source_json="$(
    python3 - "$postgres_inspect" "$PROJECT" "$postgres_cid" <<'PY'
import json, re, sys

documents = json.load(open(sys.argv[1], encoding="utf-8"))
if not isinstance(documents, list) or len(documents) != 1:
    raise SystemExit("PostgreSQL source inspection is not exact")
container = documents[0]
config = container.get("Config") or {}
labels = config.get("Labels") or {}
container_id = container.get("Id")
image_id = container.get("Image")
image = config.get("Image")
if container_id != sys.argv[3] or re.fullmatch(r"[0-9a-f]{64}", str(container_id)) is None:
    raise SystemExit("PostgreSQL source container ID is malformed")
if labels.get("com.docker.compose.project") != sys.argv[2] or labels.get("com.docker.compose.service") != "postgres":
    raise SystemExit("PostgreSQL source labels are not exact")
if re.fullmatch(r"sha256:[0-9a-f]{64}", str(image_id)) is None:
    raise SystemExit("PostgreSQL source image ID is malformed")
if re.fullmatch(r"[^\s@]+:[^\s@]+@sha256:[0-9a-f]{64}", str(image)) is None:
    raise SystemExit("PostgreSQL source image reference is not digest-pinned")
mounts = [
    mount for mount in container.get("Mounts") or []
    if isinstance(mount, dict) and mount.get("Destination") == "/var/lib/postgresql/16/data"
]
if len(mounts) != 1 or mounts[0].get("Type") != "volume" or re.fullmatch(
    r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", str(mounts[0].get("Name", ""))
) is None:
    raise SystemExit("PostgreSQL 16 source volume identity is not exact")
print(json.dumps({
    "container_id": container_id,
    "image": image,
    "image_id": image_id,
    "volume": mounts[0]["Name"],
    "data_path": "/var/lib/postgresql/16/data",
}, sort_keys=True, separators=(",", ":")))
PY
  )"
  rm -f "$postgres_inspect"
fi

# Refuse a backup in the middle of an external credential transition.
if "${compose[@]}" ps -q key-rotator | grep -q .; then
  "${compose[@]}" exec -T key-rotator python3 - <<'PY'
import json, os, urllib.request
token = os.environ.get("ROTATOR_INTERNAL_TOKEN", "")
request = urllib.request.Request(
    "http://127.0.0.1:8080/status", headers={"X-Internal-Auth": token}
)
try:
    rows = json.load(urllib.request.urlopen(request, timeout=5))
except Exception:
    raise SystemExit("key-rotator status unavailable; refusing an unverifiable backup")
active = [row.get("vendor", "unknown") for row in rows if row.get("rotation_in_progress")]
if active:
    raise SystemExit("credential rotation in progress: " + ", ".join(active))
PY
fi

# Stop every writer except PostgreSQL, take portable logical dumps, then stop
# PostgreSQL too before exact volume archives are read.
writers=()
for service in "${running[@]}"; do
  [[ "$service" == postgres ]] || writers+=("$service")
done
if ((${#writers[@]})); then
  "${compose[@]}" stop -t 60 "${writers[@]}" >/dev/null
fi
if [[ "$major_migration_quiesce" == true ]]; then
  prove_major_migration_quiesce
  project_inspect="$staging/.quiesced-project-inspect.json"
  "${docker_cmd[@]}" inspect "${project_container_ids[@]}" > "$project_inspect"
  stopped_container_states_json="$(
    python3 - "$project_inspect" "$postgres_cid" "${project_container_ids[@]}" <<'PY'
import json, re, sys

documents = json.load(open(sys.argv[1], encoding="utf-8"))
source_id = sys.argv[2]
expected_ids = set(sys.argv[3:])
if not isinstance(documents, list) or len(documents) != len(expected_ids):
    raise SystemExit("quiesced project inspection is not exact")
states = {}
for container in documents:
    container_id = container.get("Id")
    if container_id not in expected_ids or container_id in states:
        raise SystemExit("quiesced project container identity changed")
    if container_id == source_id:
        continue
    state = container.get("State") or {}
    restart_count = container.get("RestartCount")
    if state.get("Running") is not False:
        raise SystemExit("a non-PostgreSQL project container is still running")
    if (
        re.fullmatch(r"[0-9a-f]{64}", str(container_id)) is None
        or not isinstance(state.get("StartedAt"), str)
        or not isinstance(state.get("FinishedAt"), str)
        or not isinstance(restart_count, int)
        or restart_count < 0
    ):
        raise SystemExit("quiesced project container state is malformed")
    states[container_id] = {
        "started_at": state["StartedAt"],
        "finished_at": state["FinishedAt"],
        "restart_count": restart_count,
    }
if set(states) != expected_ids - {source_id}:
    raise SystemExit("quiesced stopped-container inventory is incomplete")
print(json.dumps(states, sort_keys=True, separators=(",", ":")))
PY
  )"
  rm -f "$project_inspect"
fi

mkdir -p "$staging/postgres" "$staging/volumes"
"${compose[@]}" exec -T postgres psql -v ON_ERROR_STOP=1 -U postgres -d postgres -c CHECKPOINT >/dev/null
"${compose[@]}" exec -T postgres pg_dumpall -U postgres --globals-only > "$staging/postgres/globals.sql"
for database in litellm keycloak rotator; do
  "${compose[@]}" exec -T postgres pg_dump -U postgres -d "$database" --format=custom \
    > "$staging/postgres/${database}.dump"
  "${compose[@]}" exec -T postgres pg_restore --list \
    < "$staging/postgres/${database}.dump" >/dev/null
done
# Flush the post-dump transaction state into pg_control before recording the
# migration barrier. Without this checkpoint, a later comparison can read the
# same old checkpoint even when PostgreSQL accepted writes after the backup.
"${compose[@]}" exec -T postgres psql -v ON_ERROR_STOP=1 -U postgres -d postgres -c CHECKPOINT >/dev/null
pg_version="$("${compose[@]}" exec -T postgres psql -U postgres -d postgres -Atqc 'show server_version')"
# This value does not reveal application data. The PostgreSQL 18 migration
# compares it after stopping writers. A mismatch means the source changed
# after this backup, so the migration refuses a stale logical snapshot.
pg_next_xid="$("${compose[@]}" exec -T postgres psql -U postgres -d postgres -Atqc \
  'SELECT next_xid FROM pg_control_checkpoint()')"
[[ "$pg_next_xid" =~ ^[0-9]+:[0-9]+$ ]] || {
  echo "PostgreSQL returned a malformed next_xid checkpoint value" >&2
  exit 1
}
"${compose[@]}" stop -t 60 postgres >/dev/null

allowed_volumes=(
  pg_data openwebui_data vault_data vault_audit alloy_data prom_data
  alertmanager_data loki_data grafana_data
)
archived_volumes=()
for logical in "${allowed_volumes[@]}"; do
  mapfile -t matches < <("${docker_cmd[@]}" volume ls -q \
    --filter "label=com.docker.compose.project=$PROJECT" \
    --filter "label=com.docker.compose.volume=$logical")
  ((${#matches[@]} <= 1)) || { echo "multiple volumes found for $logical" >&2; exit 1; }
  ((${#matches[@]} == 1)) || continue
  volume_tar_args=(--numeric-owner -czf - -C /source)
  if [[ "$logical" == openwebui_data ]]; then
    # Hugging Face embedding downloads create symlinks beneath this
    # regenerable model cache. The restore format deliberately rejects every
    # link before mutation, so omit the exact cache root while retaining the
    # durable Open WebUI database and application data.
    volume_tar_args=(--numeric-owner --exclude ./cache -czf - -C /source)
  fi
  "${docker_cmd[@]}" run --rm --network none --read-only --security-opt no-new-privileges:true \
    --cap-drop ALL --cap-add DAC_READ_SEARCH --user 0:0 \
    -v "${matches[0]}:/source:ro" --entrypoint /bin/tar "$HELPER_IMAGE" \
    "${volume_tar_args[@]}" . > "$staging/volumes/${logical}.tar.gz"
  tar -tzf "$staging/volumes/${logical}.tar.gz" >/dev/null
  archived_volumes+=("$logical")
done

# Recovery needs the exact reviewed configuration and rendered secrets, but a
# Vault init response must remain separately split/offline from Vault storage.
[[ ! -e secrets/vault-init.json ]] || {
  echo "move/delete secrets/vault-init.json before backup; do not co-locate unseal material with Vault state" >&2
  exit 1
}
config_items=(docker-compose.yml docker-compose.dns.yml docker-compose.platform-dns.yml bind-source-digest-inputs.json .env alertmanager alloy cribl-mock grafana keycloak litellm loki postgres prometheus traefik services scripts certs)
[[ ! -d secrets ]] || config_items+=(secrets)
tar --numeric-owner --exclude='.state' --exclude='.state-backup.*' \
  -czf "$staging/stack-config.tar.gz" "${config_items[@]}"
tar -tzf "$staging/stack-config.tar.gz" >/dev/null

export AIGW_BACKUP_STAGING="$staging" AIGW_BACKUP_PROJECT="$PROJECT"
export AIGW_BACKUP_PG_VERSION="$pg_version"
export AIGW_BACKUP_PG_NEXT_XID="$pg_next_xid"
export AIGW_BACKUP_PG_WRITE_BARRIER="forced-checkpoint-after-logical-dumps-v1"
AIGW_BACKUP_MAJOR_MIGRATION_QUIESCE="$major_migration_quiesce"
AIGW_BACKUP_PROJECT_CONTAINER_IDS="$(printf '%s\n' "${project_container_ids[@]}")"
AIGW_BACKUP_PRIOR_RUNNING_CONTAINER_IDS="$(printf '%s\n' "${running_containers[@]}")"
AIGW_BACKUP_WRITER_CONTAINER_IDS="$(printf '%s\n' "${writer_container_ids[@]}")"
export AIGW_BACKUP_MAJOR_MIGRATION_QUIESCE AIGW_BACKUP_PROJECT_CONTAINER_IDS
export AIGW_BACKUP_PRIOR_RUNNING_CONTAINER_IDS AIGW_BACKUP_WRITER_CONTAINER_IDS
export AIGW_BACKUP_POSTGRES_SOURCE_JSON="$postgres_source_json"
export AIGW_BACKUP_STOPPED_CONTAINER_STATES_JSON="$stopped_container_states_json"
AIGW_BACKUP_VOLUMES="$(printf '%s\n' "${archived_volumes[@]}")"
export AIGW_BACKUP_VOLUMES
export AIGW_BACKUP_DEPLOYMENT_PROFILE="$deployment_profile"
export AIGW_BACKUP_COMPOSE_WRAPPER="$STACK_DIR/scripts/aigw-compose.sh"
python3 - <<'PY'
import datetime, hashlib, json, os, pathlib, re, subprocess, uuid
root = pathlib.Path(os.environ["AIGW_BACKUP_STAGING"])
files = sorted(p for p in root.rglob("*") if p.is_file() and p.name != "manifest.json")
manifest = {
    "format": "aigw-state-backup-v1",
    "backup_id": str(uuid.uuid4()),
    "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "project": os.environ["AIGW_BACKUP_PROJECT"],
    "deployment_profile": os.environ["AIGW_BACKUP_DEPLOYMENT_PROFILE"],
    "postgres_version": os.environ["AIGW_BACKUP_PG_VERSION"],
    "postgres_next_xid": os.environ["AIGW_BACKUP_PG_NEXT_XID"],
    "postgres_write_barrier": os.environ["AIGW_BACKUP_PG_WRITE_BARRIER"],
    "volumes": [v for v in os.environ.get("AIGW_BACKUP_VOLUMES", "").splitlines() if v],
    "running_services": (root / "running-services.txt").read_text().splitlines(),
    "images": subprocess.run(
        [os.environ["AIGW_BACKUP_COMPOSE_WRAPPER"], "config", "--images"], check=True, text=True,
        capture_output=True,
    ).stdout.splitlines(),
    "sha256": {
        str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files
    },
}
if os.environ["AIGW_BACKUP_MAJOR_MIGRATION_QUIESCE"] == "true":
    def container_ids(name, *, allow_empty=False):
        values = [value for value in os.environ[name].splitlines() if value]
        if (not allow_empty and not values) or len(values) != len(set(values)) or any(
            not re.fullmatch(r"[0-9a-f]{64}", value) for value in values
        ):
            raise SystemExit(f"invalid {name} inventory")
        return sorted(values)

    project_ids = container_ids("AIGW_BACKUP_PROJECT_CONTAINER_IDS")
    prior_running_ids = container_ids("AIGW_BACKUP_PRIOR_RUNNING_CONTAINER_IDS")
    writer_ids = container_ids("AIGW_BACKUP_WRITER_CONTAINER_IDS", allow_empty=True)
    source = json.loads(os.environ["AIGW_BACKUP_POSTGRES_SOURCE_JSON"])
    stopped_states = json.loads(os.environ["AIGW_BACKUP_STOPPED_CONTAINER_STATES_JSON"])
    source_id = source.get("container_id")
    if (
        source_id not in project_ids
        or source_id not in prior_running_ids
        or not set(prior_running_ids).issubset(project_ids)
        or set(writer_ids) != set(prior_running_ids) - {source_id}
        or set(stopped_states) != set(project_ids) - {source_id}
    ):
        raise SystemExit("major-migration quiesce inventory is inconsistent")
    manifest["postgres_major_migration_quiesce"] = {
        "format": "aigw-postgres-major-migration-quiesce-v1",
        "project_container_ids": project_ids,
        "prior_running_container_ids": prior_running_ids,
        "writer_container_ids": writer_ids,
        "stopped_container_states": stopped_states,
        "source": source,
    }
(root / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
PY

tar -C "$staging" --numeric-owner -czf - . | age --encrypt -r "$recipient" -o "$partial"
[[ -s "$partial" ]] || { echo "age produced an empty backup" >&2; exit 1; }
age-inspect "$partial" >/dev/null
chmod 0600 "$partial"
mv "$partial" "$output"
backup_sha="$(sha256sum "$output" | awk '{print $1}')"

# Ordinary backup restores the exact prior graph. Major-migration mode keeps
# every application writer stopped and starts only PostgreSQL for the reviewed
# plan/migrate checks. Any earlier failure still reaches the EXIT trap, which
# restores the full prior graph because the quiesce did not complete.
if [[ "$major_migration_quiesce" == true ]]; then
  "${docker_cmd[@]}" start "$postgres_cid" >/dev/null
  prove_major_migration_quiesce
elif ((${#running_containers[@]})); then
  "${docker_cmd[@]}" start "${running_containers[@]}" >/dev/null
fi
restarted=true

export AIGW_BACKUP_OUTPUT="$output" AIGW_BACKUP_SHA="$backup_sha"
python3 - <<'PY'
import datetime, json, os, pathlib
receipt = {
    "format": "aigw-state-backup-receipt-v1",
    "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "path": os.environ["AIGW_BACKUP_OUTPUT"],
    "sha256": os.environ["AIGW_BACKUP_SHA"],
    "major_migration_quiesced": os.environ["AIGW_BACKUP_MAJOR_MIGRATION_QUIESCE"] == "true",
}
path = pathlib.Path(".state/last-backup.json")
tmp = path.with_suffix(".tmp")
tmp.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
tmp.chmod(0o600)
tmp.replace(path)
PY

rm -rf "$staging"
trap - EXIT INT TERM
printf 'backup=%s\nsha256=%s\n' "$output" "$backup_sha"
if [[ "$major_migration_quiesce" == true ]]; then
  echo "Major-migration backup complete. PostgreSQL 16 is running; every recorded application writer remains stopped." >&2
else
  echo "Backup complete. Vault restarted sealed; perform the normal manual unseal before full readiness." >&2
fi
