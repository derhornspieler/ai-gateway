#!/usr/bin/env bash
# One command to bring up local preprod. It checks each thing you need,
# tells you the exact fix when something is missing, then runs the deploy.
#
# Plain path (build from source; needs a dhi.io login):
#   scripts/preprod-up.sh
#
# Offline seed path (no dhi.io needed; images come from the release files).
# Point it at the folder that holds the .preprod.docker.tar.zst and its
# .preprod.manifest.json. This script reads the hashes for you; you never
# type a SHA-256:
#   scripts/preprod-up.sh --seed /path/to/release-folder
#
# It asks for your sudo password once (macOS loopback aliases + the bounded
# /etc/hosts block). Pass --become-password-file /path to skip the prompt.
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

say "Step 1 of 5: is Docker running?"
command -v docker >/dev/null 2>&1 \
  || die "Docker is not installed. Install Docker Desktop, start it, then run this again."
docker info >/dev/null 2>&1 \
  || die "Docker is installed but not running. Open Docker Desktop, wait for it to say Running, then run this again."
echo "OK: Docker is running."

say "Step 2 of 5: is Ansible installed?"
command -v ansible-playbook >/dev/null 2>&1 \
  || die "Ansible is missing. Install it with:  pip3 install ansible-core  (then run this again)."
command -v ansible-galaxy >/dev/null 2>&1 \
  || die "ansible-galaxy is missing. Reinstall with:  pip3 install ansible-core"
echo "OK: Ansible is installed."

say "Step 3 of 5: installing the Ansible add-ons this deploy needs"
# Idempotent: re-running just confirms they are present.
ansible-galaxy collection install -r ansible/requirements.yml >/dev/null \
  || die "Could not install the Ansible collections. Check your internet connection and try again."
echo "OK: Ansible collections are ready."

# Sudo method: a password file if given, otherwise prompt once.
BECOME_ARGS=()
if [[ -n "$BECOME_FILE" ]]; then
  [[ -f "$BECOME_FILE" ]] || die "The become password file does not exist: $BECOME_FILE"
  BECOME_ARGS=(--become-password-file "$BECOME_FILE")
else
  BECOME_ARGS=(--ask-become-pass)
fi

LOG_DIR="$REPO_ROOT/.state"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/preprod-up.log"

if [[ -n "$SEED_DIR" ]]; then
  say "Step 4 of 5: reading the release files (no dhi.io login needed)"
  [[ -d "$SEED_DIR" ]] || die "That seed folder does not exist: $SEED_DIR"
  # Find exactly one preprod archive and one preprod manifest in the folder.
  shopt -s nullglob
  archives=("$SEED_DIR"/*.preprod.docker.tar.zst)
  manifests=("$SEED_DIR"/*.preprod.manifest.json)
  shopt -u nullglob
  [[ ${#archives[@]} -eq 1 ]] \
    || die "Expected exactly one *.preprod.docker.tar.zst in $SEED_DIR, found ${#archives[@]}."
  [[ ${#manifests[@]} -eq 1 ]] \
    || die "Expected exactly one *.preprod.manifest.json in $SEED_DIR, found ${#manifests[@]}."
  archive="${archives[0]}"
  manifest="${manifests[0]}"
  # Compute the hashes for the operator. No SHA-256 is ever typed by hand.
  archive_sha="$(shasum -a 256 "$archive" | cut -d' ' -f1)"
  manifest_sha="$(shasum -a 256 "$manifest" | cut -d' ' -f1)"
  echo "OK: found the release pair and read its hashes."
  echo "     archive:  $(basename "$archive")"
  echo "     manifest: $(basename "$manifest")"

  say "Step 5 of 5: loading the images and deploying (this can take a while)"
  echo "Full output is being saved to: $LOG_FILE"
  python3 -I scripts/update-images.py test-preprod \
    --archive "$archive" \
    --manifest "$manifest" \
    --load-archive \
    "${BECOME_ARGS[@]}" 2>&1 | tee "$LOG_FILE"
else
  say "Step 4 of 5: checking your dhi.io login (needed to pull images)"
  # A source build pulls the pinned base images from dhi.io. Warn clearly if
  # the login looks absent; the pull step will give the final word.
  if ! grep -q 'dhi.io' "${HOME}/.docker/config.json" 2>/dev/null; then
    echo "WARNING: no dhi.io login found in ~/.docker/config.json."
    echo "         If the build fails to pull images, run:  docker login dhi.io"
    echo "         Or use the offline seed path:  scripts/preprod-up.sh --seed /path/to/release-folder"
  else
    echo "OK: a dhi.io login is present."
  fi

  say "Step 5 of 5: building from source and deploying (this can take a while)"
  echo "Full output is being saved to: $LOG_FILE"
  ansible-playbook -i ansible/inventory/preprod.yml ansible/preprod.yml \
    "${BECOME_ARGS[@]}" 2>&1 | tee "$LOG_FILE"
fi

say "Done"
cat <<'EOF'
Preprod is up. Open these in a browser:
  https://chat.aigw.internal        (chat)
  https://admin.aigw.internal       (admin console)
  https://grafana.aigw.internal     (dashboards)

Every test login is written to one private file:
  compose/secrets/preprod-test-logins.md

To take it all down later:
  ansible-playbook -i ansible/inventory/preprod.yml ansible/preprod-destroy.yml \
    -e preprod_destroy_confirmation=DESTROY_AIGW_PREPROD --ask-become-pass
EOF
