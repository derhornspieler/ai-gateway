#!/usr/bin/env bash
# One command to take local preprod down. It never asks you to type a SHA-256.
#
# Ordinary cleanup after testing (keeps the local test CA so your browser does
# not have to trust a new one next time):
#   scripts/preprod-down.sh
#
# Release teardown, when you need the exact-manifest receipt. Point it at the
# folder holding the release files you tested. It reads their hashes for you:
#   scripts/preprod-down.sh --seed /path/to/release-folder
#
# It asks for your sudo password once (it removes the /etc/hosts block and the
# macOS loopback aliases). Pass --become-password-file /path to skip the prompt.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SEED_DIR=""
BECOME_FILE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --seed)
      SEED_DIR="${2:-}"
      [[ -n "$SEED_DIR" ]] || { echo "ERROR: --seed needs a folder path" >&2; exit 2; }
      shift 2
      ;;
    --become-password-file)
      BECOME_FILE="${2:-}"
      [[ -n "$BECOME_FILE" ]] || { echo "ERROR: --become-password-file needs a path" >&2; exit 2; }
      shift 2
      ;;
    -h|--help)
      # Print the leading comment block (lines after the shebang that start
      # with '#'), with the '# ' prefix stripped.
      awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *)
      echo "ERROR: unknown option: $1 (try --help)" >&2
      exit 2
      ;;
  esac
done

say() { printf '\n== %s\n' "$1"; }
die() { printf '\nSTOP: %s\n' "$1" >&2; exit 1; }

BECOME_ARGS=()
if [[ -n "$BECOME_FILE" ]]; then
  [[ -f "$BECOME_FILE" ]] || die "The become password file does not exist: $BECOME_FILE"
  BECOME_ARGS=(--become-password-file "$BECOME_FILE")
else
  BECOME_ARGS=(--ask-become-pass)
fi

if [[ -z "$SEED_DIR" ]]; then
  say "Removing the preprod stack (ordinary cleanup)"
  ansible-playbook -i ansible/inventory/preprod.yml ansible/preprod-destroy.yml \
    -e preprod_destroy_confirmation=DESTROY_AIGW_PREPROD \
    "${BECOME_ARGS[@]}"
  cat <<'EOF'

Done. Only resources named aigw-preprod were removed. The local test Root CA
was kept, so a new run does not need a fresh browser trust step.

This is development cleanup. It is NOT the release receipt. For that, run:
  scripts/preprod-down.sh --seed /path/to/release-folder
EOF
  exit 0
fi

say "Step 1 of 2: reading the release files you tested"
[[ -d "$SEED_DIR" ]] || die "That seed folder does not exist: $SEED_DIR"
shopt -s nullglob
archives=("$SEED_DIR"/*.preprod.docker.tar.zst)
manifests=("$SEED_DIR"/*.preprod.manifest.json)
shopt -u nullglob
[[ ${#archives[@]} -eq 1 ]] \
  || die "Expected exactly one *.preprod.docker.tar.zst in $SEED_DIR, found ${#archives[@]}."
[[ ${#manifests[@]} -eq 1 ]] \
  || die "Expected exactly one *.preprod.manifest.json in $SEED_DIR, found ${#manifests[@]}."
archive="$(cd "$(dirname "${archives[0]}")" && pwd)/$(basename "${archives[0]}")"
manifest="$(cd "$(dirname "${manifests[0]}")" && pwd)/$(basename "${manifests[0]}")"
# Compute the hashes for the operator. No SHA-256 is ever typed by hand.
archive_sha="$(shasum -a 256 "$archive" | cut -d' ' -f1)"
manifest_sha="$(shasum -a 256 "$manifest" | cut -d' ' -f1)"
echo "OK: found the release pair and read its hashes."
echo "     archive:  $(basename "$archive")"
echo "     manifest: $(basename "$manifest")"

say "Step 2 of 2: proving every release resource and image is gone"
ansible-playbook -i ansible/inventory/preprod.yml ansible/preprod-clean-room.yml \
  -e preprod_seed_archive="$archive" \
  -e preprod_seed_archive_sha256="$archive_sha" \
  -e preprod_seed_manifest="$manifest" \
  -e preprod_seed_manifest_sha256="$manifest_sha" \
  -e preprod_clean_room_confirmation=DESTROY_AIGW_PREPROD_RELEASE_IMAGES \
  "${BECOME_ARGS[@]}"

cat <<'EOF'

Done. Save the one-line PREPROD_CLEAN_ROOM_OK receipt printed above. It is the
release evidence: every owned container, image, volume, network, hosts entry,
and loopback alias is gone, and unrelated images were left alone.
EOF
