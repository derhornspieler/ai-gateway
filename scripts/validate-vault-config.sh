#!/usr/bin/env bash
# Vault has no server -verify-only flag. `operator diagnose` does parse
# the full server config, but returns non-zero for unrelated OSS/telemetry
# diagnostics. Accept only an explicit successful Parse Configuration child.
set -eu
unset DOCKER_CONTEXT DOCKER_HOST DOCKER_TLS DOCKER_TLS_VERIFY DOCKER_CERT_PATH DOCKER_API_VERSION
docker_cmd=(docker --host unix:///run/docker.sock)

STACK_DIR="${STACK_DIR:-/opt/ai-gateway}"
IMAGE='dhi.io/vault:2.0.3@sha256:743791e1bf99025aae045b3155fecf0542e7fd1bde7bbfbaf76eb4b9ff2555a6'
source_config="$STACK_DIR/vault/config.hcl"
if [ ! -f "$source_config" ] || [ -L "$source_config" ] ||
   [ "$(stat -c '%u:%g:%a:%h' -- "$source_config")" != "0:0:644:1" ]; then
  echo "deployed Vault config must be a root:root 0644 single-link regular file" >&2
  exit 1
fi

# A private `Z` bind gives the transient validator its own MCS category. Never
# apply it to the deployed config path: doing so would steal that path from an
# unchanged running Vault container. Validate an exact private staged copy and
# remove it after the container exits.
validation_dir="$(mktemp -d "/tmp/aigw-vault-validate.XXXXXXXX")"
cleanup() {
  rm -rf -- "$validation_dir"
}
trap cleanup EXIT HUP INT TERM
install -m 0444 -- "$source_config" "$validation_dir/config.hcl"

"${docker_cmd[@]}" run --rm \
  --network none \
  --cap-drop ALL \
  --cap-add IPC_LOCK \
  --security-opt no-new-privileges:true \
  --read-only \
  --tmpfs /vault/data:uid=1000,gid=1000,mode=0700 \
  --tmpfs /vault/logs:uid=1000,gid=1000,mode=0700 \
  --entrypoint vault \
  --volume "$validation_dir/config.hcl:/vault/config/aigw.hcl:ro,Z" \
  "$IMAGE" operator diagnose -config=/vault/config/aigw.hcl -format=json 2>/dev/null |
python3 -c '
import json, sys

report = json.load(sys.stdin)
parse = next(
    (child for child in report.get("children", []) if child.get("name") == "Parse Configuration"),
    None,
)
if not parse or parse.get("status") != "ok":
    raise SystemExit("Vault configuration parse did not report status=ok")
'

echo "Static Vault configuration parses successfully in the pinned image."
