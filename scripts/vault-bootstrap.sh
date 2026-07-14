#!/usr/bin/env bash
# vault-bootstrap.sh — one-time Vault init for the AI Gateway VM (TEST MODE).
#
# Run ON THE VM from the stack directory (default /opt/ai-gateway) AFTER
# `docker compose up -d vault`. Production differences are flagged inline:
# single unseal key share (prod: 5/3 shares to separate custodians).
#
# EDGE PKI depends on the deployed aigw_edge_tls_mode:
#   vault-intermediate -- steps 3a/4 are SKIPPED. Vault's intermediate CSR is
#                         signed by the CUSTOMER's CA and imported by
#                         scripts/vault-pki-intermediate.sh. No test root is
#                         created. This is what the committed lab now uses.
#   lab                -- steps 3a/4 mint a self-signed TEST root and issue the
#                         edge certificate from it. Disposable labs only; no
#                         browser or customer trusts that root.
#
# What it does:
#   1. vault operator init (1 share) -> secrets/vault-init.json (0600)
#      [MOVE TO A PASSWORD MANAGER AND DELETE — see warning at the end]
#   2. unseal + root login (secrets passed via stdin/env, never as argv)
#   3. enable kv-v2 at kv/ and the pki_int intermediate mount
#   3a. (mode 'lab' only) self-signed TEST root at pki/
#   4. (mode 'lab' only) issue wildcard+apex cert for *.${DOMAIN}/${DOMAIN}
#      -> ./certs/{int.crt,int.key}, CA -> ./certs/ca.pem
#   5. create rotator policy + token  (written into .env ROTATOR_VAULT_TOKEN)
#   6. optionally seed vendor keys from $ANTHROPIC_API_KEY / $OPENAI_API_KEY
#   7. restart cert/CA consumers
set -euo pipefail

# Any file we create that may hold secret material must never be readable by
# other users, not even between creation and a later chmod.
umask 077

EMIT_UNSEAL_KEY=false
case "${1:-}" in
  "") ;;
  --emit-unseal-key)
    EMIT_UNSEAL_KEY=true
    shift
    ;;
  -h|--help)
    cat <<'EOF'
Usage: vault-bootstrap.sh [--emit-unseal-key]

  --emit-unseal-key  Reserve stdout exclusively for the generated 1-of-1
                     unseal share. Stdout must be a pipe, never a terminal.
                     The root-owned 0600 init response remains on the Vault
                     host until controller-side encrypted custody is verified.
EOF
    exit 0
    ;;
  *)
    echo "FATAL: unsupported argument: $1" >&2
    exit 2
    ;;
esac
if [[ "$#" -ne 0 ]]; then
  echo "FATAL: vault-bootstrap.sh accepts only one optional argument" >&2
  exit 2
fi
if [[ "$EMIT_UNSEAL_KEY" == true ]]; then
  if [[ -t 1 ]]; then
    echo "FATAL: --emit-unseal-key requires captured stdout; refusing to print an unseal share to a terminal" >&2
    exit 2
  fi
  # Preserve the caller's captured stdout as the single-purpose custody
  # channel. Everything else from this script and its children goes to stderr,
  # so status output can never be confused with or appended to the share.
  exec 3>&1
  exec 1>&2
fi

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
# Edge PKI ownership is decided by the deployed inventory, not by this script.
#   lab                -- this script mints the self-signed TEST root below.
#   vault-intermediate -- the REAL customer CA signs Vault's intermediate CSR.
#                         This script must NOT create a competing test root or
#                         issue an edge certificate; scripts/vault-pki-intermediate.sh
#                         owns the edge in that mode. Everything else here (init,
#                         unseal, audit, kv, rotator token, vendor seeding) still runs.
AIGW_EDGE_TLS_MODE="$(grep -E '^AIGW_EDGE_TLS_MODE=' .env | cut -d= -f2- || true)"
AIGW_EDGE_TLS_MODE="${AIGW_EDGE_TLS_MODE:-lab}"
case "$AIGW_EDGE_TLS_MODE" in
  lab|vault-intermediate|customer-intermediate) ;;
  *) echo "FATAL: vault-bootstrap.sh cannot run with aigw_edge_tls_mode=$AIGW_EDGE_TLS_MODE" >&2; exit 1 ;;
esac
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
# `vault status` exits 2 for both an uninitialized Vault and an initialized,
# sealed Vault.  Its JSON body is the authoritative distinction.  Refuse every
# initialized state here: this script is only the first-initialization ceremony;
# an existing Vault must use the separately held unseal shares instead.
if vault_status_json="$(vlt status -format=json)"; then
  vault_status_rc=0
else
  vault_status_rc=$?
fi
if [[ "$vault_status_rc" -ne 0 && "$vault_status_rc" -ne 2 ]]; then
  echo "FATAL: could not read Vault initialization status; refusing bootstrap" >&2
  exit 1
fi
if ! vault_status_state="$(printf '%s' "$vault_status_json" | python3 -c '
import json
import sys

try:
    status = json.load(sys.stdin)
except (TypeError, ValueError):
    raise SystemExit("Vault status was not valid JSON") from None
initialized = status.get("initialized") if isinstance(status, dict) else None
sealed = status.get("sealed") if isinstance(status, dict) else None
if type(initialized) is not bool or type(sealed) is not bool:
    raise SystemExit("Vault status omitted initialized/sealed booleans")
print(f"{str(initialized).lower()} {str(sealed).lower()}")
')"; then
  echo "FATAL: Vault returned an invalid initialization status; refusing bootstrap" >&2
  exit 1
fi
read -r vault_initialized vault_sealed <<<"$vault_status_state"
case "$vault_initialized:$vault_sealed" in
  false:true)
    ;;
  true:*)
    echo "FATAL: Vault is already initialized; do not run vault-bootstrap.sh. Use scripts/vault-unseal.sh with the separately held existing unseal share." >&2
    exit 1
    ;;
  *)
    echo "FATAL: Vault reported an impossible initialization/seal state; refusing bootstrap" >&2
    exit 1
    ;;
esac

# A previously interrupted or manually supplied init response must never be
# trusted to drive a new ceremony. The response below is written only to a
# private same-directory temporary file and atomically renamed after validation.
if [[ -e secrets/vault-init.json || -L secrets/vault-init.json ]]; then
  echo "FATAL: Vault is uninitialized but secrets/vault-init.json already exists; preserve it for review and resolve the inconsistency before bootstrap." >&2
  exit 1
fi
vault_init_tmp=""
cleanup_vault_init_tmp() {
  if [[ -n "${vault_init_tmp:-}" ]]; then
    rm -f -- "$vault_init_tmp" || true
  fi
}
abort_vault_init_tmp() {
  cleanup_vault_init_tmp
  exit 1
}
trap cleanup_vault_init_tmp EXIT
trap abort_vault_init_tmp HUP INT TERM
vault_init_tmp="$(mktemp "secrets/.vault-init.json.XXXXXX")"
chmod 600 "$vault_init_tmp"
echo ">> initializing vault (TEST: 1 key share — use 5/3 in production)"
if ! vlt operator init -key-shares=1 -key-threshold=1 -format=json > "$vault_init_tmp"; then
  echo "FATAL: Vault initialization failed; no init response was retained" >&2
  exit 1
fi
if ! python3 - "$vault_init_tmp" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as source:
        response = json.load(source)
except (OSError, TypeError, ValueError):
    raise SystemExit("Vault init response was not valid JSON") from None

keys = response.get("unseal_keys_b64") if isinstance(response, dict) else None
root_token = response.get("root_token") if isinstance(response, dict) else None
if (
    not isinstance(keys, list)
    or len(keys) != 1
    or not isinstance(keys[0], str)
    or not keys[0]
    or not isinstance(root_token, str)
    or not root_token
):
    raise SystemExit("Vault init response was incomplete")
PY
then
  echo "FATAL: Vault initialization returned an incomplete response; no init response was retained" >&2
  exit 1
fi
# Recheck immediately before the same-directory rename. The stack directory is
# root-owned, and this prevents silently overwriting any response that appeared
# while the init command was running.
if [[ -e secrets/vault-init.json || -L secrets/vault-init.json ]]; then
  echo "FATAL: secrets/vault-init.json appeared during initialization; refusing to overwrite it" >&2
  exit 1
fi
if ! mv -f -- "$vault_init_tmp" secrets/vault-init.json; then
  echo "FATAL: could not atomically commit the Vault init response" >&2
  exit 1
fi
vault_init_tmp=""
chmod 600 secrets/vault-init.json
UNSEAL_KEY="$(python3 -c 'import json;print(json.load(open("secrets/vault-init.json"))["unseal_keys_b64"][0])')"
ROOT_TOKEN="$(python3 -c 'import json;print(json.load(open("secrets/vault-init.json"))["root_token"])')"
# vault-unseal.sh is the reusable reboot/restore path. It uses a disposable,
# capability-free DHI client and keeps the share exclusively on stdin.
printf '%s\n' "$UNSEAL_KEY" | "$STACK_DIR/scripts/vault-unseal.sh"
export VAULT_TOKEN="$ROOT_TOKEN"
unset ROOT_TOKEN
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
vlt secrets list -format=json | grep -q '"pki_int/"' || vlt secrets enable -path=pki_int pki
vlt secrets tune -max-lease-ttl=43800h pki_int

if [[ "$AIGW_EDGE_TLS_MODE" == "lab" ]]; then
# ── 3a+4 (mode 'lab' ONLY): self-signed TEST root and edge certificate ───
# This is the disposable-lab fallback. It produces a root that no browser and
# no customer trusts. The real path -- and the one the committed lab inventory
# selects -- is aigw_edge_tls_mode=vault-intermediate, where the CUSTOMER's CA
# signs Vault's intermediate CSR and this block never runs.
vlt secrets list -format=json | grep -q '"pki/"'     || vlt secrets enable -path=pki pki
vlt secrets tune -max-lease-ttl=87600h pki

if ! vlt read pki/cert/ca >/dev/null 2>&1; then
  echo ">> generating TEST root CA (real CA path: aigw_edge_tls_mode=vault-intermediate)"
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
else
# ── modes vault-intermediate / customer-intermediate: the edge belongs to the
#    customer CA ──────────────────────────────────────────────────────────────
# Deliberately no root mount, no test root, and no edge certificate here. The
# bootstrap placeholder keeps Traefik serving until the operator ceremony
# completes. pki_int is already enabled above; the ceremony promotes the
# customer issuer into it.
echo ">> edge PKI deferred to the customer CA (aigw_edge_tls_mode=$AIGW_EDGE_TLS_MODE)"
if [[ "$AIGW_EDGE_TLS_MODE" == "customer-intermediate" ]]; then
  echo ">>   next: sudo scripts/vault-pki-intermediate.sh import-intermediate \\"
  echo ">>           --intermediate secrets/aigw-intermediate-import.pem \\"
  echo ">>           --intermediate-key secrets/aigw-intermediate-import.key \\"
  echo ">>           --chain secrets/aigw-intermediate-import-chain.pem"
else
  echo ">>   next: sudo scripts/vault-pki-intermediate.sh csr"
fi
fi

# ── 5: rotator policy + token ────────────────────────────────────────────
vlt policy write rotator - <<HCL
# The typed provider-auth adapter owns this exact enrollment document. It can
# neither choose a Vault path nor enumerate neighboring secrets. Metadata
# deletion is separate in KV v2 and is required only after the adapter proves
# that refresh is disabled and the last short-lived token has expired.
path "kv/data/ai-gateway/anthropic-wif" { capabilities = ["create", "read", "update", "delete"] }
path "kv/metadata/ai-gateway/anthropic-wif" { capabilities = ["read", "delete"] }

# Read-only inputs.
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
# Open WebUI's conservative migration/readiness budget is 450 seconds; retain
# a scheduling margin so this final bootstrap gate does not preempt it.
"$STACK_DIR/scripts/aigw-runtime-up.sh" -d --wait --wait-timeout 600

if [[ "$EMIT_UNSEAL_KEY" == true ]]; then
  # Emit only after Vault accepted the share and the complete post-bootstrap
  # runtime gate passed. The durable 0600 init response remains the recovery
  # copy until the controller helper has atomically stored and independently
  # decrypted-verified the inline Ansible Vault value.
  if ! printf '%s\n' "$UNSEAL_KEY" >&3; then
    echo "FATAL: controller custody channel rejected the unseal share; retaining secrets/vault-init.json" >&2
    exit 1
  fi
  exec 3>&-
fi
unset UNSEAL_KEY

cat <<EOF

DONE.

  !!! SECURITY: $STACK_DIR/secrets/vault-init.json contains the Vault
  !!! UNSEAL KEY and ROOT TOKEN in plaintext (mode 0600). Copy both into
  !!! your password manager / offline vault NOW, then delete the file:
  !!!     shred -u $STACK_DIR/secrets/vault-init.json   # or: rm -P / rm
  !!! Anyone who reads that file owns this Vault.

  edge TLS mode : $AIGW_EDGE_TLS_MODE
  edge certs    : $STACK_DIR/certs/  (int.crt / int.key / ca.pem)
  rotator token : written to .env (ROTATOR_VAULT_TOKEN)

$(if [[ "$AIGW_EDGE_TLS_MODE" == "vault-intermediate" ]]; then cat <<'NEXT'
  !!! The edge is still serving the SELF-SIGNED BOOTSTRAP PLACEHOLDER.
  !!! Complete the customer-CA ceremony before anyone uses this deployment:
  !!!     sudo scripts/vault-pki-intermediate.sh csr        # emits the CSR
  !!!     (customer CA signs it offline — the root key never comes here)
  !!!     sudo scripts/vault-pki-intermediate.sh install-signed ...
NEXT
elif [[ "$AIGW_EDGE_TLS_MODE" == "customer-intermediate" ]]; then cat <<'NEXT'
  !!! The edge is still serving the SELF-SIGNED BOOTSTRAP PLACEHOLDER.
  !!! Complete the customer-intermediate import ceremony before anyone uses this
  !!! deployment (the staged intermediate key is validated, imported, shredded):
  !!!     sudo scripts/vault-pki-intermediate.sh import-intermediate \
  !!!         --intermediate secrets/aigw-intermediate-import.pem \
  !!!         --intermediate-key secrets/aigw-intermediate-import.key \
  !!!         --chain secrets/aigw-intermediate-import-chain.pem
NEXT
fi)

After every VM reboot Vault is SEALED unless the deployment controller has an
inline-encrypted vault_unseal_key. Use a hidden shell read, then the hardened
stdin-only helper when manual recovery is required (the share is never an
argument, environment variable, container setting, or Docker log):
  read -rsp 'Vault unseal share: ' AIGW_UNSEAL_SHARE; printf '\n'
  printf '%s\n' "\$AIGW_UNSEAL_SHARE" | sudo scripts/vault-unseal.sh
  unset AIGW_UNSEAL_SHARE
EOF
