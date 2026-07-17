#!/usr/bin/env bash
# Fail closed before a stateful direct-image or custom-build change unless a
# recent encrypted backup still matches its independently stored receipt.
set -euo pipefail
umask 077
[[ $(id -u) -eq 0 ]] || { echo "pre-upgrade check must run as root" >&2; exit 1; }
STACK_DIR="${STACK_DIR:-/opt/ai-gateway}"
PROJECT="${COMPOSE_PROJECT_NAME:-ai-gateway}"
MAX_AGE="${BACKUP_MAX_AGE_SECONDS:-86400}"
unset DOCKER_CONTEXT DOCKER_HOST DOCKER_TLS DOCKER_TLS_VERIFY DOCKER_CERT_PATH DOCKER_API_VERSION
docker_cmd=(docker --host unix:///run/docker.sock)
cd "$STACK_DIR"
compose=("$STACK_DIR/scripts/aigw-compose.sh")
[[ ! -e .state/restore-required-unseal ]] || {
  echo "restore verification marker exists; refusing an upgrade" >&2; exit 1;
}

stateful=(
  postgres keycloak litellm open-webui vault alloy prometheus loki grafana
  samba-ad
)
existing_stateful=()
changed=()

add_changed() {
  local service="$1"
  local existing
  if ((${#changed[@]})); then
    for existing in "${changed[@]}"; do
      [[ "$existing" == "$service" ]] && return 0
    done
  fi
  changed+=("$service")
}

has_existing_state() {
  local service="$1"
  local existing
  if ((${#existing_stateful[@]})); then
    for existing in "${existing_stateful[@]}"; do
      [[ "$existing" == "$service" ]] && return 0
    done
  fi
  return 1
}

# Preserve the direct-image reference check for pulled/pinned services. Inspect
# every existing container for the service rather than an arbitrary first row.
for service in "${stateful[@]}"; do
  cid_text="$("${docker_cmd[@]}" ps -a -q \
    --filter "label=com.docker.compose.project=$PROJECT" \
    --filter "label=com.docker.compose.service=$service")"
  cids=()
  while IFS= read -r cid; do
    [[ -n "$cid" ]] && cids+=("$cid")
  done <<< "$cid_text"
  ((${#cids[@]})) || continue
  existing_stateful+=("$service")
  desired="$("${compose[@]}" config --format json | python3 -I -c '
import json, sys
service = sys.argv[1]
print((json.load(sys.stdin).get("services", {}).get(service, {}) or {}).get("image", ""))
' "$service")"
  for cid in "${cids[@]}"; do
    current="$("${docker_cmd[@]}" inspect --format '{{.Config.Image}}' "$cid")"
    [[ -z "$desired" || "$current" == "$desired" ]] || add_changed "$service"
  done
done

# A stable local image tag does not identify the binary that a later Compose up
# will run. Use the exact same content/image-ID planner as Ansible's build step,
# then gate only planned stateful services that already have a container. On a
# first deployment every custom image may be planned, but there is no state to
# protect and therefore no receipt requirement.
build_plan="$("${compose[@]}" config --format json |
  python3 -I "$STACK_DIR/scripts/plan-compose-builds.py" \
    "$STACK_DIR" "$STACK_DIR/.state/compose-build-inputs.json" "$PROJECT")"
planned_text="$(python3 -I -c '
import json, re, sys
payload = json.load(sys.stdin)
services = payload.get("services")
if not isinstance(services, list) or any(
    not isinstance(service, str)
    or re.fullmatch(r"[a-z0-9][a-z0-9-]*", service) is None
    for service in services
):
    raise SystemExit("invalid custom-image build plan")
print("\n".join(services))
' <<< "$build_plan")"
while IFS= read -r service; do
  [[ -n "$service" ]] || continue
  if has_existing_state "$service"; then
    add_changed "$service"
  fi
done <<< "$planned_text"

((${#changed[@]})) || { echo "no stateful image change detected" >&2; exit 0; }
[[ -f .state/last-backup.json && ! -L .state/last-backup.json ]] || {
  echo "stateful image change (${changed[*]}) requires scripts/state-backup.sh first" >&2; exit 1;
}
python3 -I - "$MAX_AGE" <<'PY'
import datetime, hashlib, json, pathlib, sys
max_age = int(sys.argv[1])
if max_age <= 0:
    raise SystemExit("backup maximum age must be positive")
receipt = json.loads(pathlib.Path(".state/last-backup.json").read_text())
if receipt.get("format") != "aigw-state-backup-receipt-v1":
    raise SystemExit("invalid backup receipt")
created = datetime.datetime.fromisoformat(receipt["created_at"])
if created.tzinfo is None or created.utcoffset() is None:
    raise SystemExit("backup receipt timestamp must include a timezone")
age = (datetime.datetime.now(datetime.timezone.utc) - created).total_seconds()
if age < 0 or age > max_age:
    raise SystemExit(f"backup receipt is stale ({int(age)} seconds old)")
path = pathlib.Path(receipt["path"])
if not path.is_absolute() or not path.is_file() or path.is_symlink():
    raise SystemExit("encrypted backup from receipt is not mounted/available")
digest = hashlib.sha256()
with path.open("rb") as source:
    for chunk in iter(lambda: source.read(1024 * 1024), b""):
        digest.update(chunk)
actual = digest.hexdigest()
if actual != receipt.get("sha256"):
    raise SystemExit("encrypted backup no longer matches its receipt")
PY
echo "recent encrypted backup verified for stateful image change: ${changed[*]}" >&2
