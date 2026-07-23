#!/usr/bin/env bash
# Run the render-only Compose validation (scripts/validate-compose.sh) on a
# remote Rocky 9 target's Docker instead of a local Docker Desktop.
#
# Why: validate-compose.sh needs a Docker daemon to render `docker compose
# config`. Running it on the deployment target validates against that target's
# exact Compose version (the version-skew class of bug only reproduces on the
# real engine), and keeps a heavy local Docker Desktop out of the dev loop. The
# target's Docker socket is root-only by the hardening contract, so this syncs
# the working tree over and runs the validator there via sudo.
#
# Usage:
#   scripts/validate-compose-on-vm.sh                 # default target below
#   AIGW_VALIDATE_VM=user@host scripts/validate-compose-on-vm.sh
set -euo pipefail

VM="${AIGW_VALIDATE_VM:-ansible@10.8.10.10}"
REMOTE="${AIGW_VALIDATE_REMOTE_DIR:-/var/tmp/aigw-validate}"

root="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
cd "$root"

# COPYFILE_DISABLE + discarding tar stderr silences macOS AppleDouble/xattr
# noise; the working tree (minus VCS, local assistant state, and runtime
# state) is streamed straight into a fresh remote directory.
COPYFILE_DISABLE=1 tar czf - \
  --exclude='./.git' --exclude='./.claude' --exclude='./.codex' \
  --exclude='./AGENTS.md' --exclude='./CLAUDE.md' --exclude='./TASKS.md' \
  --exclude='./.state' . 2>/dev/null \
  | ssh -o BatchMode=yes "$VM" \
      "rm -rf ${REMOTE} && mkdir -p ${REMOTE} && tar xzf - -C ${REMOTE} 2>/dev/null"

ssh -o BatchMode=yes "$VM" "cd ${REMOTE} && sudo bash scripts/validate-compose.sh"
