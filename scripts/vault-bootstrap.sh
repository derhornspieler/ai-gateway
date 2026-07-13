#!/usr/bin/env bash
# vault-bootstrap.sh — one-time Vault init for the AI Gateway VM (TEST MODE).
#
# Run ON THE VM from the stack directory (default /opt/ai-gateway) AFTER
# `docker compose up -d vault`. Production differences are flagged inline:
# single unseal key share (prod: 5/3 shares to separate custodians), and a
# self-generated PKI root (prod: intermediate CSR signed by customer root,
# per docs/anthropic-wif-bootstrap.md + solution-map §9.5).
#
# What it does:
#   1. vault operator init (1 share) -> secrets/vault-init.json (0600)
#      [MOVE TO A PASSWORD MANAGER AND DELETE — see warning at the end]
#   2. unseal + root login (secrets passed via stdin/env, never as argv)
#   3. enable kv-v2 at kv/, pki root + pki_int intermediate
#   4. issue wildcard+apex cert for *.${DOMAIN}/${DOMAIN} -> ./certs/{int.crt,int.key}, CA -> ./certs/ca.pem
#   5. create rotator policy + token  (written into .env ROTATOR_VAULT_TOKEN)
#   6. optionally seed vendor keys from $ANTHROPIC_API_KEY / $OPENAI_API_KEY
#   7. restart cert/CA consumers
set -euo pipefail

# Any file we create that may hold secret material must never be readable by
# other users, not even between creation and a later chmod.
umask 077

STACK_DIR="${STACK_DIR:-/opt/ai-gateway}"
cd "$STACK_DIR"
compose=("$STACK_DIR/scripts/aigw-compose.sh")
DEPLOYMENT_PROFILE="$(grep -E '^DEPLOYMENT_PROFILE=' .env | cut -d= -f2- || true)"
if [[ "$DEPLOYMENT_PROFILE" != "rocky9-lab" ]] &&
   [[ "${AIGW_ALLOW_INSECURE_VAULT_BOOTSTRAP:-}" != "I_UNDERSTAND_THIS_IS_LAB_ONLY" ]]; then
  cat >&2 <<'EOF'
FATAL: vault-bootstrap.sh is deliberately a lab/test bootstrap (1-of-1
unseal, generated test root, plaintext isolated listener). It is not the
customer Vault initialization path. Use the reviewed production ceremony, or
set AIGW_ALLOW_INSECURE_VAULT_BOOTSTRAP=I_UNDERSTAND_THIS_IS_LAB_ONLY only for
an explicitly disposable, non-production test VM.
EOF
  exit 1
fi
DOMAIN="$(grep -E '^DOMAIN=' .env | cut -d= -f2)"
DOMAIN="${DOMAIN:-aigw.example.internal}"
KC_CLIENT_ASSERTION_KEY_VAULT_PATH="$(grep -E '^KC_CLIENT_ASSERTION_KEY_VAULT_PATH=' .env | cut -d= -f2-)"
KC_CLIENT_ASSERTION_KEY_VAULT_PATH="${KC_CLIENT_ASSERTION_KEY_VAULT_PATH:-ai-gateway/anthropic-wif-client-key}"
IDENTITY_CONTROLLER_KEY_VAULT_PATH="$(grep -E '^IDENTITY_CONTROLLER_KEY_VAULT_PATH=' .env | cut -d= -f2-)"
IDENTITY_CONTROLLER_KEY_VAULT_PATH="${IDENTITY_CONTROLLER_KEY_VAULT_PATH:-ai-gateway/keycloak/identity-controller-key}"
IDENTITY_STATE_VAULT_PATH="$(grep -E '^IDENTITY_STATE_VAULT_PATH=' .env | cut -d= -f2-)"
IDENTITY_STATE_VAULT_PATH="${IDENTITY_STATE_VAULT_PATH:-ai-gateway/keycloak/identity-state}"

validate_vault_path() {
  local label="$1" value="$2"
  case "$value" in
    ai-gateway/*) ;;
    *) echo "FATAL: $label must stay under ai-gateway/" >&2; exit 1 ;;
  esac
  if [[ "$value" == *..* ]] ||
     [[ ! "$value" =~ ^[A-Za-z0-9/_.-]+$ ]]; then
    echo "FATAL: unsafe $label" >&2
    exit 1
  fi
}
validate_vault_path KC_CLIENT_ASSERTION_KEY_VAULT_PATH "$KC_CLIENT_ASSERTION_KEY_VAULT_PATH"
validate_vault_path IDENTITY_CONTROLLER_KEY_VAULT_PATH "$IDENTITY_CONTROLLER_KEY_VAULT_PATH"
validate_vault_path IDENTITY_STATE_VAULT_PATH "$IDENTITY_STATE_VAULT_PATH"
mkdir -p secrets certs

# VAULT_TOKEN is forwarded by NAME only (`-e VAULT_TOKEN`): docker takes the
# value from our environment, so the token never appears on the `docker
# compose exec` command line (visible in `ps`).
vlt() {
  if [ -n "${VAULT_TOKEN:-}" ]; then
    "${compose[@]}" exec -T -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN vault vault "$@"
  else
    "${compose[@]}" exec -T -e VAULT_ADDR=http://127.0.0.1:8200 vault vault "$@"
  fi
}

echo ">> waiting for vault..."
for _ in $(seq 1 30); do
  # The shellless DHI image deliberately has no curl/wget. During a fresh
  # bootstrap Vault reports 501 (uninitialized), after a reboot it may report
  # 503 (sealed), and an already-unsealed rerun reports 200. Any of those
  # proves the local listener is ready for the init/unseal ceremony.
  for status in 200 501 503; do
    if "${compose[@]}" exec -T vault \
      /usr/local/bin/aigw-health-probe http \
      --url 'http://127.0.0.1:8200/v1/sys/health?standbyok=true' \
      --status "$status" >/dev/null 2>&1; then
      vault_listener_ready=true
      break
    fi
  done
  [ "${vault_listener_ready:-false}" = true ] && break
  sleep 2
done
[ "${vault_listener_ready:-false}" = true ] \
  || { echo "FATAL: Vault listener did not become reachable" >&2; exit 1; }

# ── 1+2: init & unseal ───────────────────────────────────────────────────
if [ ! -f secrets/vault-init.json ]; then
  echo ">> initializing vault (TEST: 1 key share — use 5/3 in production)"
  vlt operator init -key-shares=1 -key-threshold=1 -format=json > secrets/vault-init.json
fi
chmod 600 secrets/vault-init.json
UNSEAL_KEY="$(python3 -c 'import json;print(json.load(open("secrets/vault-init.json"))["unseal_keys_b64"][0])')"
ROOT_TOKEN="$(python3 -c 'import json;print(json.load(open("secrets/vault-init.json"))["root_token"])')"
# vault-unseal.sh is the reusable reboot/restore path. It uses a disposable,
# capability-free DHI client and keeps the share exclusively on stdin.
printf '%s\n' "$UNSEAL_KEY" | "$STACK_DIR/scripts/vault-unseal.sh"
export VAULT_TOKEN="$ROOT_TOKEN"
unset UNSEAL_KEY ROOT_TOKEN
echo ">> unsealed."

# Enable a named, idempotent Vault audit device before any secrets/PKI work.
# Vault HMAC-redacts sensitive values in these JSON records. /vault/logs is a
# dedicated named volume shared read-only with Alloy; it is never stdout and
# never placed in the general Docker log stream.
if ! vlt audit list -format=json | grep -q '"aigw_file/"'; then
  # The setgid audit volume is owned 1000:473. Mode 0640 lets only the
  # dedicated uid/gid-473 Alloy collector read the HMAC-redacted stream.
  vlt audit enable -path=aigw_file file \
      file_path=/vault/logs/audit.log mode=0640 >/dev/null
fi
# Vault refuses requests when every enabled audit device is unavailable. A
# second device backed by Docker's bounded json-file logger prevents a stale
# file handle or rotation fault from making the secret store unavailable. The
# two streams have independent audit HMAC keys and are deduplicated by request
# id downstream.
if ! vlt audit list -format=json | grep -q '"aigw_stdout/"'; then
  vlt audit enable -path=aigw_stdout file \
      file_path=stdout mode=0600 >/dev/null
fi

# ── 3: engines ───────────────────────────────────────────────────────────
vlt secrets list -format=json | grep -q '"kv/"'      || vlt secrets enable -path=kv kv-v2
vlt secrets list -format=json | grep -q '"pki/"'     || vlt secrets enable -path=pki pki
vlt secrets list -format=json | grep -q '"pki_int/"' || vlt secrets enable -path=pki_int pki
vlt secrets tune -max-lease-ttl=87600h pki
vlt secrets tune -max-lease-ttl=43800h pki_int

# ── root CA (TEST). PRODUCTION: generate CSR on pki_int, have the CUSTOMER
#    ROOT sign it, and skip the self-signed root entirely (§9.5):
#      vlt write -format=json pki_int/intermediate/generate/internal common_name="AIGW Intermediate CA" > csr.json
if ! vlt read pki/cert/ca >/dev/null 2>&1; then
  echo ">> generating TEST root CA (prod: customer-root-signed intermediate)"
  vlt write -field=certificate pki/root/generate/internal \
      common_name="AIGW Test Root CA" ttl=87600h > /dev/null
  # intermediate
  CSR=$(vlt write -field=csr pki_int/intermediate/generate/internal \
      common_name="AIGW Intermediate CA" ttl=43800h)
  SIGNED=$(echo "$CSR" | vlt write -field=certificate pki/root/sign-intermediate \
      csr=- format=pem_bundle ttl=43800h)
  echo "$SIGNED" | vlt write pki_int/intermediate/set-signed certificate=- >/dev/null
fi

vlt write pki_int/roles/aigw \
    allowed_domains="$DOMAIN" allow_subdomains=true allow_bare_domains=true \
    max_ttl=2160h >/dev/null

# ── 4: issue wildcard + bare-domain cert for the traefik edges ───────────
# Stream the issue response straight into python — the private key goes only
# to certs/int.key (created privately, then narrowed to the Traefik runtime
# group); no JSON copy of it is left on disk.
echo ">> issuing *.$DOMAIN and $DOMAIN"
vlt write -format=json pki_int/issue/aigw \
    common_name="*.$DOMAIN" alt_names="$DOMAIN" ttl=2160h \
| python3 -c '
import json, sys
d = json.load(sys.stdin)["data"]
open("certs/int.crt","w").write(d["certificate"] + "\n" + "\n".join(d.get("ca_chain", [])) + "\n")
open("certs/int.key","w").write(d["private_key"] + "\n")
open("certs/ca.pem","w").write("\n".join(d.get("ca_chain", [])) + "\n")
'
# Certificates are public; the key is group-readable only by non-root Traefik.
chown root:root certs/int.crt certs/ca.pem
chmod 644 certs/int.crt certs/ca.pem
# Traefik's DHI runtime is uid/gid 65532. Keep the host directory private and
# grant only its runtime group read access to the key; the two exact read-only
# bind mounts are the only containers that receive this directory.
chown root:65532 certs certs/int.key
chmod 750 certs
chmod 640 certs/int.key
rm -f secrets/edge-cert.json  # plaintext key copy written by older versions

# ── 5: rotator policy + token ────────────────────────────────────────────
vlt policy write rotator - <<HCL
# Read-only inputs.
path "kv/data/ai-gateway/anthropic-wif" { capabilities = ["read"] }
path "kv/data/ai-gateway/openai-admin" { capabilities = ["read"] }
path "kv/data/ai-gateway/vendors/anthropic" { capabilities = ["read"] }

# The identity setup controller writes only its three exact, prevalidated
# records. It cannot enumerate or mutate any neighboring Vault subtree.
path "kv/data/${KC_CLIENT_ASSERTION_KEY_VAULT_PATH}" { capabilities = ["create", "read", "update"] }
path "kv/data/${IDENTITY_CONTROLLER_KEY_VAULT_PATH}" { capabilities = ["create", "read", "update"] }
path "kv/data/${IDENTITY_STATE_VAULT_PATH}" { capabilities = ["create", "read", "update"] }

# OpenAI's driver rotates these two exact records.
path "kv/data/ai-gateway/vendors/openai" { capabilities = ["create", "read", "update"] }
path "kv/data/ai-gateway/openai-state" { capabilities = ["create", "read", "update"] }
HCL
ROTATOR_TOKEN="$(vlt token create -policy=rotator -period=768h -field=token)"

# ── 6: optional vendor key seeding (static_seed driver picks these up) ──
# `api_key=-` makes the vault CLI read the value from stdin, keeping the
# vendor keys out of the docker/vault command lines.
if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
  printf '%s' "$ANTHROPIC_API_KEY" | vlt kv put kv/ai-gateway/vendors/anthropic api_key=- >/dev/null
  echo ">> seeded anthropic key"
fi
if [ -n "${OPENAI_API_KEY:-}" ]; then
  printf '%s' "$OPENAI_API_KEY" | vlt kv put kv/ai-gateway/vendors/openai api_key=- >/dev/null
  echo ">> seeded openai key"
fi

# ── 7: apply ─────────────────────────────────────────────────────────────
# .env update is done with shell builtins / python-reading-env so the token
# never appears on a command line (sed's argv is visible in `ps`).
export ROTATOR_TOKEN
python3 -c '
import os, re
tok = os.environ["ROTATOR_TOKEN"]
with open(".env") as f:
    s = f.read()
line = "ROTATOR_VAULT_TOKEN=" + tok
if re.search(r"^ROTATOR_VAULT_TOKEN=", s, flags=re.M):
    s = re.sub(r"^ROTATOR_VAULT_TOKEN=.*$", lambda m: line, s, flags=re.M)
else:
    s += ("" if s.endswith("\n") or not s else "\n") + line + "\n"
with open(".env", "w") as f:
    f.write(s)
'
unset ROTATOR_TOKEN
chmod 600 .env
"${compose[@]}" up -d --no-deps --force-recreate traefik-int traefik-adm open-webui key-rotator
# This is phase two of deployment. Unlike the first Ansible converge, Vault is
# now initialized/unsealed and the rotator token has been installed, so every
# strict healthcheck must pass before bootstrap is reported complete.
"$STACK_DIR/scripts/aigw-runtime-up.sh" -d --wait --wait-timeout 300

cat <<EOF

DONE.

  !!! SECURITY: $STACK_DIR/secrets/vault-init.json contains the Vault
  !!! UNSEAL KEY and ROOT TOKEN in plaintext (mode 0600). Copy both into
  !!! your password manager / offline vault NOW, then delete the file:
  !!!     shred -u $STACK_DIR/secrets/vault-init.json   # or: rm -P / rm
  !!! Anyone who reads that file owns this Vault.

  edge certs    : $STACK_DIR/certs/  (int.crt / int.key / ca.pem)
  rotator token : written to .env (ROTATOR_VAULT_TOKEN)

After every VM reboot Vault is SEALED (manual-unseal posture, §9.6).
Use a hidden shell read, then the hardened stdin-only helper (the share is
never an argument, environment variable, container setting, or Docker log):
  read -rsp 'Vault unseal share: ' AIGW_UNSEAL_SHARE; printf '\n'
  printf '%s\n' "\$AIGW_UNSEAL_SHARE" | sudo scripts/vault-unseal.sh
  unset AIGW_UNSEAL_SHARE
EOF
