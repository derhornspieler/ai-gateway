#!/usr/bin/env bash
# Destructive exact-volume restore for an authenticated AI Gateway backup.
set -euo pipefail
umask 077

usage() {
  echo "usage: sudo $0 --input BACKUP.age --identity AGE-KEY --sha256 HEX --confirm RESTORE_AI_GATEWAY_STATE" >&2
  exit 2
}

[[ $(id -u) -eq 0 ]] || { echo "state restore must run as root" >&2; exit 1; }
STACK_DIR="${STACK_DIR:-/opt/ai-gateway}"
PROJECT="${COMPOSE_PROJECT_NAME:-ai-gateway}"
HELPER_IMAGE="dhi.io/busybox:1.38.0-alpine@sha256:69a25015bda2c7dfac5d3a88990b56bc0f38539b313c448b171edef1497193ad"
input="" identity="" expected_sha="" confirmation=""
while (($#)); do
  case "$1" in
    --input) [[ $# -ge 2 ]] || usage; input="$2"; shift 2 ;;
    --identity) [[ $# -ge 2 ]] || usage; identity="$2"; shift 2 ;;
    --sha256) [[ $# -ge 2 ]] || usage; expected_sha="$2"; shift 2 ;;
    --confirm) [[ $# -ge 2 ]] || usage; confirmation="$2"; shift 2 ;;
    *) usage ;;
  esac
done
[[ "$confirmation" == RESTORE_AI_GATEWAY_STATE ]] || usage
[[ -f "$input" && ! -L "$input" && -f "$identity" && ! -L "$identity" ]] || { echo "backup/identity must be regular files" >&2; exit 1; }
[[ "$expected_sha" =~ ^[0-9a-f]{64}$ ]] || { echo "--sha256 is required from an authenticated out-of-band receipt" >&2; exit 2; }
[[ "$(sha256sum "$input" | awk '{print $1}')" == "$expected_sha" ]] || { echo "encrypted backup checksum mismatch" >&2; exit 1; }
identity_mode="$(stat -c '%a' "$identity")"
(( (8#$identity_mode & 8#077) == 0 )) || { echo "age identity must not be group/other accessible" >&2; exit 1; }
[[ -d "$STACK_DIR" && ! -L "$STACK_DIR" && -f "$STACK_DIR/docker-compose.yml" ]] || {
  echo "stack directory must be a real deployed directory" >&2; exit 1;
}
for command in age cp docker install sha256sum python3 stat; do
  command -v "$command" >/dev/null || { echo "required command missing: $command" >&2; exit 1; }
done

cd "$STACK_DIR"
compose=("$STACK_DIR/scripts/aigw-compose.sh")
deployment_profile="$(grep -E '^DEPLOYMENT_PROFILE=' .env | tail -n 1 | cut -d= -f2- || true)"
staging="$(mktemp -d "$STACK_DIR/.state-restore.XXXXXX")"
cleanup() { rm -rf "$staging"; }
trap cleanup EXIT INT TERM

require_project_stopped() {
  local -a running_project=()
  mapfile -t running_project < <(
    docker ps -q --filter "label=com.docker.compose.project=$PROJECT"
  )
  ((${#running_project[@]} == 0)) || {
    echo "restore requires zero running $PROJECT project containers; found ${#running_project[@]}" >&2
    return 1
  }
}

age --decrypt -i "$identity" "$input" > "$staging/outer.tar.gz"
docker_root="$(docker info --format '{{.DockerRootDir}}')"
[[ "$docker_root" = /* && -d "$docker_root" && ! -L "$docker_root" ]] || {
  echo "DockerRootDir must be an existing real absolute directory" >&2; exit 1;
}
# Validate the complete decrypted envelope, manifest/checksum bijection, exact
# profile volume set, every nested volume tar, and the stack-config member
# graph before the first destructive operation. Declared volume bytes must fit
# beneath fixed per-volume/total ceilings and in DockerRootDir while retaining
# the restore reserve; sparse maps are forbidden. The helper extracts only
# ordinary files/directories into new root-owned staging directories; links,
# devices, traversal, duplicates, unexpected roots, and extra/missing members
# fail here while the live stack remains untouched.
python3 "$STACK_DIR/scripts/restore_archive.py" \
  --archive "$staging/outer.tar.gz" \
  --extracted-root "$staging/extracted" \
  --config-root "$staging/stack-config" \
  --project "$PROJECT" \
  --profile "$deployment_profile" \
  --volume-target "$docker_root"
rm -f "$staging/outer.tar.gz"

echo "Stopping the current stack for destructive restore..." >&2
"${compose[@]}" stop -t 60 >/dev/null
require_project_stopped

mapfile -t volumes < <(python3 - "$staging/extracted/manifest.json" <<'PY'
import json, sys
print("\n".join(json.load(open(sys.argv[1]))["volumes"]))
PY
)
for logical in "${volumes[@]}"; do
  [[ "$logical" =~ ^[a-z0-9_]+$ ]] || { echo "unsafe logical volume name" >&2; exit 1; }
  mapfile -t matches < <(docker volume ls -q \
    --filter "label=com.docker.compose.project=$PROJECT" \
    --filter "label=com.docker.compose.volume=$logical")
  ((${#matches[@]} <= 1)) || { echo "multiple target volumes for $logical" >&2; exit 1; }
  if ((${#matches[@]} == 0)); then
    volume_name="${PROJECT}_${logical}"
    docker volume create \
      --label "com.docker.compose.project=$PROJECT" \
      --label "com.docker.compose.volume=$logical" "$volume_name" >/dev/null
  else
    volume_name="${matches[0]}"
  fi
  docker run --rm --network none --read-only --security-opt no-new-privileges:true \
    --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add FOWNER --user 0:0 \
    -v "$volume_name:/destination" --entrypoint /bin/sh "$HELPER_IMAGE" -ec \
    'find /destination -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +'
  docker run --rm -i --network none --read-only --security-opt no-new-privileges:true \
    --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add FOWNER --cap-add CHOWN --user 0:0 \
    -v "$volume_name:/destination" --entrypoint /bin/tar "$HELPER_IMAGE" \
    --numeric-owner -xzf - -C /destination < "$staging/extracted/volumes/${logical}.tar.gz"
done

# The configuration archive was safely extracted into a new staging tree
# before containers were stopped. Remove only the fixed reviewed top-level
# roots, so a pre-existing symlink cannot redirect a privileged copy outside
# STACK_DIR, then install the root-owned staged tree without interpreting tar.
config_roots=(
  docker-compose.yml docker-compose.lab.yml bind-source-digest-inputs.json .env alloy cribl-mock grafana
  keycloak litellm loki postgres prometheus tempo traefik services scripts
  certs secrets
)
for root in "${config_roots[@]}"; do
  rm -rf -- "$STACK_DIR/$root"
done
cp -a "$staging/stack-config/." "$STACK_DIR/"
# `.state` is deliberately excluded from the authenticated configuration
# archive. Retire the local bind-digest key as a restore epoch: even when the
# restored bytes equal the pre-restore bytes, every bind consumer must be
# recreated because its old bind mount still references a deleted inode.
if [[ -e .state || -L .state ]]; then
  [[ -d .state && ! -L .state && "$(stat -c '%u:%g:%a' .state)" == 0:0:700 ]] || {
    echo "unsafe .state boundary after restore" >&2
    exit 1
  }
else
  install -d -o root -g root -m 0700 .state
fi
rm -f -- .state/bind-digest.key
printf '%s\n' "$expected_sha" > .state/restore-required-unseal
chmod 0600 .state/restore-required-unseal
require_project_stopped

# Keep the captured graph stopped. The hostile-archive extractor deliberately
# installs the authenticated configuration as root-owned regular files rather
# than trusting archived ownership metadata. Starting that older graph here
# can both execute superseded deployment code and make a non-root service loop
# on a root-only bind mount before current Ansible reconciles its exact owner
# and mode. The designated current source must converge first; restored Vault
# then starts sealed and can be unsealed with separately held custody material.
rm -rf "$staging"
trap - EXIT INT TERM
cat >&2 <<'EOF'
Restore complete; the captured graph is intentionally stopped.
1. Run the full current-source Ansible converge while ingress stays closed.
2. Unseal restored Vault with the separately held threshold shares.
3. Run: scripts/aigw-runtime-up.sh -d --wait --wait-timeout 300
4. Verify applications/data, then remove .state/restore-required-unseal.
EOF
