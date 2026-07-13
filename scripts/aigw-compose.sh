#!/usr/bin/env bash
# One authoritative Compose selector for every deployed operator script.
set -euo pipefail
# Keep DOCKER_CONFIG: root's reviewed registry-auth config may carry the DHI
# pull credential. Endpoint selection is pinned independently; only inherited
# context/host/TLS selectors are discarded.
unset DOCKER_CONTEXT DOCKER_HOST DOCKER_TLS DOCKER_TLS_VERIFY DOCKER_CERT_PATH DOCKER_API_VERSION
STACK_DIR="${STACK_DIR:-/opt/ai-gateway}"
PROJECT="${COMPOSE_PROJECT_NAME:-ai-gateway}"
[[ "$PROJECT" =~ ^[a-z0-9][a-z0-9_-]{0,62}$ ]] || { echo "unsafe Compose project name" >&2; exit 2; }
[[ -f "$STACK_DIR/.env" && -f "$STACK_DIR/docker-compose.yml" ]] || { echo "deployed Compose files are missing" >&2; exit 1; }
profile="$(grep -E '^DEPLOYMENT_PROFILE=' "$STACK_DIR/.env" | tail -n 1 | cut -d= -f2- || true)"
compose=(docker --host unix:///run/docker.sock compose --project-name "$PROJECT" --env-file "$STACK_DIR/.env" -f "$STACK_DIR/docker-compose.yml")
if [[ "$profile" == rocky9-lab ]]; then
  [[ -f "$STACK_DIR/docker-compose.lab.yml" ]] || { echo "lab profile is missing docker-compose.lab.yml" >&2; exit 1; }
  compose+=(-f "$STACK_DIR/docker-compose.lab.yml" --profile lab-ad)
fi
exec "${compose[@]}" "$@"
