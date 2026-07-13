#!/usr/bin/env bash
# Bound Vault's raw file audit device without exposing Docker's data-root to a
# host logrotate domain. Rotation happens through a locked, networkless helper
# mounting only vault_audit; Vault receives HUP before the old inode is
# compressed, as required by Vault's audit-log guidance.
set -euo pipefail
umask 077

PROJECT="${COMPOSE_PROJECT_NAME:-ai-gateway}"
MAX_BYTES="${VAULT_AUDIT_MAX_BYTES:-104857600}"
KEEP_FILES="${VAULT_AUDIT_KEEP_FILES:-14}"
HELPER_IMAGE="dhi.io/busybox:1.38.0-alpine@sha256:69a25015bda2c7dfac5d3a88990b56bc0f38539b313c448b171edef1497193ad"

if [[ ! "$MAX_BYTES" =~ ^[0-9]+$ ]] || (( MAX_BYTES < 1048576 )); then
  echo "invalid VAULT_AUDIT_MAX_BYTES" >&2
  exit 2
fi
if [[ ! "$KEEP_FILES" =~ ^[0-9]+$ ]] || (( KEEP_FILES < 2 || KEEP_FILES > 100 )); then
  echo "invalid VAULT_AUDIT_KEEP_FILES" >&2
  exit 2
fi

lock_file="${AIGW_AUDIT_LOCK_FILE:-/run/lock/aigw-vault-audit-rotate.lock}"
mkdir -p "$(dirname "$lock_file")"
lock_dir="${lock_file}.d"
if ! mkdir "$lock_dir" 2>/dev/null; then
  owner="$(cat "$lock_dir/pid" 2>/dev/null || true)"
  if [[ "$owner" =~ ^[0-9]+$ ]] && kill -0 "$owner" 2>/dev/null; then
    exit 0
  fi
  rm -rf "$lock_dir"
  mkdir "$lock_dir"
fi
printf '%s\n' "$$" > "$lock_dir/pid"
release_lock() { rm -rf "$lock_dir"; }
trap release_lock EXIT INT TERM

container_for() {
  docker ps -q \
    --filter "label=com.docker.compose.project=$PROJECT" \
    --filter "label=com.docker.compose.service=$1" | head -n 1
}

vault_cid="$(container_for vault)"
[[ -n "$vault_cid" ]] || {
  echo "Vault container unavailable; audit rotation deferred" >&2
  exit 0
}

read -r audit_volume < <(
  docker inspect "$vault_cid" | python3 -c '
import json, sys
mounts = json.load(sys.stdin)[0].get("Mounts", [])
matches = [m.get("Name", "") for m in mounts if m.get("Destination") == "/vault/logs"]
if len(matches) != 1 or not matches[0]:
    raise SystemExit("Vault /vault/logs is not exactly one named volume")
print(matches[0])
'
)
helper() {
  docker run --rm --network none --read-only \
    --security-opt no-new-privileges:true --cap-drop ALL \
    --user 1000:473 --entrypoint /bin/sh \
    -v "$audit_volume:/audit" "$HELPER_IMAGE" "$@"
}

rotated="$(helper -ec '
f=/audit/audit.log
[ -f "$f" ] || exit 0
size=$(wc -c < "$f")
[ "$size" -ge "$1" ] || exit 0
name="audit.log.$(date -u +%Y%m%dT%H%M%SZ)"
mv "$f" "/audit/$name"
: > "$f"
chmod 0600 "$f"
printf "%s\n" "$name"
' sh "$MAX_BYTES")"

[[ -n "$rotated" ]] || exit 0
[[ "$rotated" =~ ^audit\.log\.[0-9]{8}T[0-9]{6}Z$ ]] || {
  echo "unsafe rotated audit filename" >&2; exit 1;
}

committed=false
rollback() {
  if [[ "$committed" != true ]]; then
    helper -ec '
      rm -f /audit/audit.log
      [ ! -f "/audit/$1" ] || mv "/audit/$1" /audit/audit.log
    ' sh "$rotated" >/dev/null 2>&1 || true
  fi
}
trap 'rollback; release_lock' EXIT INT TERM

if ! docker kill --signal HUP "$vault_cid" >/dev/null; then
  echo "Vault HUP failed; rolling audit file back" >&2
  exit 1
fi
committed=true
sleep 1

helper -ec '
gzip -f "/audit/$1"
keep="$2"
count=0
for file in $(ls -1t /audit/audit.log.*.gz 2>/dev/null || true); do
  count=$((count + 1))
  [ "$count" -le "$keep" ] || rm -f "$file"
done
' sh "$rotated" "$KEEP_FILES" >/dev/null

trap - EXIT INT TERM
release_lock
echo "Vault audit log rotated and HUP-reopened" >&2
