#!/usr/bin/env bash
# Single source of truth for which shell this repository lints and with what.
#
# The repo previously had no shellcheck at all — `bash -n scripts/*.sh` plus
# contract tests were the only shell gate, and `bash -n` proves nothing beyond
# parseability. These scripts run as root on the customer VM, handle Vault
# unseal material on stdin, and `rm -rf` a restore path, so semantic shell
# defects are a security concern rather than a style one.
#
# ShellCheck is pinned by tag AND digest, like every other image in this repo:
# an unpinned linter silently changes the gate under the maintainers.
#
# Usage: run-shellcheck.sh <severity>   (error | warning | info | style)
set -euo pipefail

SEVERITY="${1:?usage: run-shellcheck.sh <error|warning|info|style>}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SHELLCHECK_IMAGE="koalaman/shellcheck:v0.11.0@sha256:61862eba1fcf09a484ebcc6feea46f1782532571a34ed51fedf90dd25f925a8d"

# Every shell artefact that ships to the VM or runs in an image. Extensionless
# entrypoints and the operator-facing .example scripts are listed explicitly
# because they carry no .sh suffix; the Python-shebanged samba-ad-secret-tool is
# deliberately absent. scripts/tests/test_ci_health_checks.py fails if a tracked
# shell file is neither listed here nor explicitly excluded there, so a new
# script cannot quietly escape the linter.
#
# NOT linted: ansible/**/templates/*.j2. ShellCheck cannot parse Jinja — `{{ }}`
# is a syntax error to it — so the rendered root-run firewall and policy-routing
# scripts stay outside this gate. That is a real, accepted coverage gap; they are
# covered instead by the exact-string contract tests in scripts/tests.
TARGETS=(
  .github/scripts/run-shellcheck.sh
  ansible/inventory/examples/production-rocky9.first-init.sh.example
  ansible/inventory/examples/rocky9-lab.first-init.sh.example
  ansible/inventory/examples/rocky9-lab.stage-customer-intermediate.sh.example
  ansible/roles/network_routing/files/90-aigw-policy-routing
  compose/postgres/init/01-init-databases.sh
  scripts/aigw-compose.sh
  scripts/aigw-runtime-up.sh
  scripts/e2e-fresh-vm-check.sh
  scripts/pre-upgrade-check.sh
  scripts/rotate-vault-audit.sh
  scripts/state-backup.sh
  scripts/state-restore.sh
  scripts/sign-vault-intermediate.sh
  scripts/validate-compose.sh
  scripts/validate-compose-on-vm.sh
  scripts/validate-vault-config.sh
  scripts/vault-bootstrap.sh
  scripts/vault-pki-intermediate.sh
  scripts/vault-unseal.sh
  services/egress-proxy/generate-pins.sh
  services/samba-ad-lab/policy-rc.d
  services/samba-ad-lab/samba-ad-entrypoint
  services/samba-ad-lab/samba-ad-healthcheck
  services/samba-ad-lab/tests/test-lockout-policy.sh
  services/samba-ad-lab/tests/test-secret-argv.sh
)

# Fail closed when a listed target is renamed or deleted: a linter that silently
# stops covering a file is worse than no linter.
missing=()
for target in "${TARGETS[@]}"; do
  [[ -f "$ROOT/$target" ]] || missing+=("$target")
done
if ((${#missing[@]} > 0)); then
  printf '::error title=ShellCheck target missing::%s is listed in .github/scripts/run-shellcheck.sh but does not exist\n' "${missing[@]}"
  exit 2
fi

exec docker run --rm \
  --network=none \
  --volume "$ROOT:/mnt:ro" \
  --workdir /mnt \
  "$SHELLCHECK_IMAGE" \
  --severity="$SEVERITY" \
  --format=gcc \
  "${TARGETS[@]}"
