#!/usr/bin/env bash
# Quiesced, age-encrypted state backup for the single-VM AI Gateway.
set -euo pipefail
umask 077

usage() {
  echo "usage: sudo $0 --recipient age1... --output /independent/mount/aigw-STATE.tar.gz.age" >&2
  exit 2
}

[[ $(id -u) -eq 0 ]] || { echo "state backup must run as root" >&2; exit 1; }
STACK_DIR="${STACK_DIR:-/opt/ai-gateway}"
PROJECT="${COMPOSE_PROJECT_NAME:-ai-gateway}"
HELPER_IMAGE="dhi.io/busybox:1.38.0-alpine@sha256:69a25015bda2c7dfac5d3a88990b56bc0f38539b313c448b171edef1497193ad"
recipient=""
output=""
while (($#)); do
  case "$1" in
    --recipient) [[ $# -ge 2 ]] || usage; recipient="$2"; shift 2 ;;
    --output) [[ $# -ge 2 ]] || usage; output="$2"; shift 2 ;;
    *) usage ;;
  esac
done
[[ "$recipient" =~ ^age1[0-9a-z]{58}$ ]] || { echo "only an age X25519 recipient is accepted" >&2; exit 2; }
[[ "$output" = /* && "$output" == *.age ]] || { echo "--output must be an absolute .age path" >&2; exit 2; }
[[ -d "$STACK_DIR" && -f "$STACK_DIR/docker-compose.yml" ]] || { echo "stack directory is not deployed" >&2; exit 1; }
[[ -d "$(dirname "$output")" && ! -e "$output" && ! -L "$output" ]] || { echo "backup output must be new in an existing directory" >&2; exit 1; }
for command in age age-inspect docker findmnt sha256sum tar python3; do
  command -v "$command" >/dev/null || { echo "required command missing: $command" >&2; exit 1; }
done

# A copy on the same block filesystem is not disaster recovery. The explicit
# override exists only for disposable lab validation.
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

restart_original() {
  local rc=$?
  if [[ "$restarted" != true && ${#running_containers[@]} -gt 0 ]]; then
    # Start only the exact containers that were running before quiesce.
    # `docker compose start` traverses dependencies and can incorrectly rerun
    # the successful exited volume-init one-shot.
    docker start "${running_containers[@]}" >/dev/null 2>&1 || {
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

mkdir -p "$staging/postgres" "$staging/volumes"
"${compose[@]}" exec -T postgres psql -v ON_ERROR_STOP=1 -U postgres -d postgres -c CHECKPOINT >/dev/null
"${compose[@]}" exec -T postgres pg_dumpall -U postgres --globals-only > "$staging/postgres/globals.sql"
for database in litellm keycloak rotator; do
  "${compose[@]}" exec -T postgres pg_dump -U postgres -d "$database" --format=custom \
    > "$staging/postgres/${database}.dump"
  "${compose[@]}" exec -T postgres pg_restore --list \
    < "$staging/postgres/${database}.dump" >/dev/null
done
pg_version="$("${compose[@]}" exec -T postgres psql -U postgres -d postgres -Atqc 'show server_version')"
"${compose[@]}" stop -t 60 postgres >/dev/null

allowed_volumes=(
  pg_data openwebui_data vault_data vault_audit alloy_data prom_data
  loki_data tempo_data grafana_data samba_ad_config samba_ad_state samba_ad_public
)
archived_volumes=()
for logical in "${allowed_volumes[@]}"; do
  mapfile -t matches < <(docker volume ls -q \
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
  docker run --rm --network none --read-only --security-opt no-new-privileges:true \
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
config_items=(docker-compose.yml bind-source-digest-inputs.json .env alloy cribl-mock grafana keycloak litellm loki postgres prometheus tempo traefik services scripts certs)
[[ ! -f docker-compose.lab.yml ]] || config_items+=(docker-compose.lab.yml)
[[ ! -d secrets ]] || config_items+=(secrets)
tar --numeric-owner --exclude='.state' --exclude='.state-backup.*' \
  -czf "$staging/stack-config.tar.gz" "${config_items[@]}"
tar -tzf "$staging/stack-config.tar.gz" >/dev/null

export AIGW_BACKUP_STAGING="$staging" AIGW_BACKUP_PROJECT="$PROJECT"
export AIGW_BACKUP_PG_VERSION="$pg_version"
AIGW_BACKUP_VOLUMES="$(printf '%s\n' "${archived_volumes[@]}")"
export AIGW_BACKUP_VOLUMES
export AIGW_BACKUP_DEPLOYMENT_PROFILE="$deployment_profile"
export AIGW_BACKUP_COMPOSE_WRAPPER="$STACK_DIR/scripts/aigw-compose.sh"
python3 - <<'PY'
import datetime, hashlib, json, os, pathlib, subprocess, uuid
root = pathlib.Path(os.environ["AIGW_BACKUP_STAGING"])
files = sorted(p for p in root.rglob("*") if p.is_file() and p.name != "manifest.json")
manifest = {
    "format": "aigw-state-backup-v1",
    "backup_id": str(uuid.uuid4()),
    "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "project": os.environ["AIGW_BACKUP_PROJECT"],
    "deployment_profile": os.environ["AIGW_BACKUP_DEPLOYMENT_PROFILE"],
    "postgres_version": os.environ["AIGW_BACKUP_PG_VERSION"],
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
(root / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
PY

tar -C "$staging" --numeric-owner -czf - . | age --encrypt -r "$recipient" -o "$partial"
[[ -s "$partial" ]] || { echo "age produced an empty backup" >&2; exit 1; }
age-inspect "$partial" >/dev/null
chmod 0600 "$partial"
mv "$partial" "$output"
backup_sha="$(sha256sum "$output" | awk '{print $1}')"

# Restore exactly the concrete containers that were running before
# maintenance. Do not use Compose dependency traversal: volume-init is a
# successful exited one-shot and must stay exited. Vault's file backend seals
# on process restart, so post-backup full readiness still requires unseal.
if ((${#running_containers[@]})); then
  docker start "${running_containers[@]}" >/dev/null
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
echo "Backup complete. Vault restarted sealed; perform the normal manual unseal before full readiness." >&2
