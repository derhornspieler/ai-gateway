#!/usr/bin/env bash
# Start/wait the long-running Compose graph without ever restarting the
# versioned volume-init one-shot through depends_on.
set -euo pipefail

STACK_DIR="${STACK_DIR:-/opt/ai-gateway}"
compose=("$STACK_DIR/scripts/aigw-compose.sh")

args=()
while (($#)); do
  case "$1" in
    -d|--detach|--wait)
      args+=("$1")
      shift
      ;;
    --wait-timeout)
      [[ $# -ge 2 && "$2" =~ ^[0-9]+$ ]] && ((10#$2 > 0)) || {
        echo "--wait-timeout requires a positive integer" >&2
        exit 2
      }
      args+=("$1" "$2")
      shift 2
      ;;
    --wait-timeout=*)
      wait_timeout="${1#*=}"
      [[ "$wait_timeout" =~ ^[0-9]+$ ]] && ((10#$wait_timeout > 0)) || {
        echo "--wait-timeout requires a positive integer" >&2
        exit 2
      }
      args+=("$1")
      shift
      ;;
    *)
      echo "unsupported runtime-up option: $1" >&2
      exit 2
      ;;
  esac
done

mapfile -t effective_services < <("${compose[@]}" config --services)
runtime_services=()
initializer_count=0
for service in "${effective_services[@]}"; do
  if [[ "$service" == volume-init ]]; then
    ((initializer_count += 1))
  elif [[ "$service" =~ ^[a-z0-9][a-z0-9-]*$ ]]; then
    runtime_services+=("$service")
  else
    echo "unsafe effective Compose service name: $service" >&2
    exit 1
  fi
done

[[ "$initializer_count" -eq 1 && "${#runtime_services[@]}" -gt 0 ]] || {
  echo "effective Compose model must contain exactly one volume-init plus runtime services" >&2
  exit 1
}

"${compose[@]}" up --no-deps --no-build "${args[@]}" "${runtime_services[@]}"
