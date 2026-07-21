#!/usr/bin/env bash
# vault-oidc-setup.sh — root-token ceremony wiring Vault's OIDC auth method to
# the deployment's Keycloak, retiring routine root-token logins.
#
# Run ON THE VM from the stack directory (default /opt/ai-gateway) as root,
# AFTER the normal Ansible converge has automatically deployed identity control
# and escrowed the `vault` relying-party client secret.
# Idempotent and re-runnable; every write is read back and verified.
#
# What it does:
#   1. reads the rotator-escrowed `vault` OIDC client secret from Vault
#      (kv/<VAULT_OIDC_RP_VAULT_PATH>) — root-side, never from argv/env/files
#   2. enables auth/oidc and configures discovery against the PUBLIC issuer
#      https://auth.<domain>/realms/aigw, pinned to the deployment CA bundle
#      (certs/ca.pem). Discovery must use the public issuer: OIDC libraries
#      require the discovery document's `iss` to equal the discovery URL, and
#      Keycloak (hostname-pinned) advertises the public issuer even on its
#      internal listener. The vault container reaches that hostname through
#      the reviewed edge alias on net-vault, mirroring Open WebUI on net-chat.
#   3. writes the scoped `vault-admins` policy (kv data plane + edge PKI;
#      deliberately NO auth/policy/identity/audit/seal/mount-creation
#      authority and NO access to the credential escrows — those remain
#      root-token ceremonies; see docs/identity-operations.md)
#   4. writes role `aigw` (user_claim preferred_username, groups_claim roles,
#      bound to aud=vault and roles∋aigw-admins) with the UI callback and the
#      CLI loopback callback on its redirect allow-list
#   5. maps the external identity group `aigw-admins` (plus its OIDC mount
#      alias) onto the vault-admins policy
#   6. proves the wiring end-to-end by requesting a real auth URL for the role
#
# The Vault root token is read from stdin only — never argv, never an
# environment variable on a command line, never a log.
set -euo pipefail
umask 077

case "${1:-}" in
  "") ;;
  -h|--help)
    cat <<'EOF'
Usage: read -rsp 'Vault root token: ' TOK; printf '\n'
       printf '%s\n' "$TOK" | sudo scripts/vault-oidc-setup.sh
       unset TOK
EOF
    exit 0
    ;;
  *)
    echo "FATAL: vault-oidc-setup.sh accepts no arguments" >&2
    exit 2
    ;;
esac

STACK_DIR="${STACK_DIR:-/opt/ai-gateway}"
cd "$STACK_DIR"
compose=("$STACK_DIR/scripts/aigw-compose.sh")

die() { echo "FATAL: $*" >&2; exit 1; }

env_value() {
  grep -E "^$1=" .env | cut -d= -f2- || true
}

DOMAIN="$(env_value DOMAIN)"
[[ -n "$DOMAIN" ]] || die "DOMAIN is not set in .env"
VAULT_OIDC_RP_VAULT_PATH="$(env_value VAULT_OIDC_RP_VAULT_PATH)"
VAULT_OIDC_RP_VAULT_PATH="${VAULT_OIDC_RP_VAULT_PATH:-ai-gateway/keycloak/vault-oidc-rp}"
BREAK_GLASS_ADMIN_VAULT_PATH="$(env_value BREAK_GLASS_ADMIN_VAULT_PATH)"
BREAK_GLASS_ADMIN_VAULT_PATH="${BREAK_GLASS_ADMIN_VAULT_PATH:-ai-gateway/keycloak/break-glass-admin}"
IDENTITY_CONTROLLER_KEY_VAULT_PATH="$(env_value IDENTITY_CONTROLLER_KEY_VAULT_PATH)"
IDENTITY_CONTROLLER_KEY_VAULT_PATH="${IDENTITY_CONTROLLER_KEY_VAULT_PATH:-ai-gateway/keycloak/identity-controller-key}"
KC_CLIENT_ASSERTION_KEY_VAULT_PATH="$(env_value KC_CLIENT_ASSERTION_KEY_VAULT_PATH)"
KC_CLIENT_ASSERTION_KEY_VAULT_PATH="${KC_CLIENT_ASSERTION_KEY_VAULT_PATH:-ai-gateway/anthropic-wif-client-key}"

validate_vault_path() {
  local label="$1" value="$2"
  case "$value" in
    ai-gateway/*) ;;
    *) die "$label must stay under ai-gateway/" ;;
  esac
  if [[ "$value" == *..* ]] ||
     [[ ! "$value" =~ ^[A-Za-z0-9/_.-]+$ ]]; then
    die "unsafe $label"
  fi
}
validate_vault_path VAULT_OIDC_RP_VAULT_PATH "$VAULT_OIDC_RP_VAULT_PATH"
validate_vault_path BREAK_GLASS_ADMIN_VAULT_PATH "$BREAK_GLASS_ADMIN_VAULT_PATH"
validate_vault_path IDENTITY_CONTROLLER_KEY_VAULT_PATH "$IDENTITY_CONTROLLER_KEY_VAULT_PATH"
validate_vault_path KC_CLIENT_ASSERTION_KEY_VAULT_PATH "$KC_CLIENT_ASSERTION_KEY_VAULT_PATH"

CA_BUNDLE="$STACK_DIR/certs/ca.pem"
[[ -s "$CA_BUNDLE" ]] || die "missing edge CA bundle $CA_BUNDLE"
grep -q 'BEGIN CERTIFICATE' "$CA_BUNDLE" || die "$CA_BUNDLE holds no PEM certificate"

# ── token on stdin only ─────────────────────────────────────────────────────
if [[ -t 0 ]]; then
  cat >&2 <<'EOF'
FATAL: the Vault root token must arrive on stdin, never as an argument.

  read -rsp 'Vault root token: ' TOK; printf '\n'
  printf '%s\n' "$TOK" | sudo scripts/vault-oidc-setup.sh
  unset TOK
EOF
  exit 2
fi
IFS= read -r VAULT_TOKEN || die "no Vault token on stdin"
[[ -n "$VAULT_TOKEN" ]] || die "the Vault token on stdin was empty"
export VAULT_TOKEN

# VAULT_TOKEN is forwarded by NAME only (`-e VAULT_TOKEN`): docker takes the
# value from our environment, so it never appears on the exec command line.
vlt() {
  "${compose[@]}" exec -T -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN vault vault "$@"
}

# ── Vault must be initialized and unsealed ──────────────────────────────────
for _ in $(seq 1 30); do
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
[ "${vault_listener_ready:-false}" = true ] || die "Vault listener did not become reachable"

vault_status_json="$(vlt status -format=json || true)"
vault_state="$(printf '%s' "$vault_status_json" | python3 -I -c '
import json, sys
try:
    status = json.load(sys.stdin)
except (TypeError, ValueError):
    raise SystemExit("Vault status was not valid JSON") from None
initialized = status.get("initialized") if isinstance(status, dict) else None
sealed = status.get("sealed") if isinstance(status, dict) else None
if type(initialized) is not bool or type(sealed) is not bool:
    raise SystemExit("Vault status omitted initialized/sealed booleans")
print(f"{str(initialized).lower()} {str(sealed).lower()}")
')" || die "could not read Vault status"
read -r vault_initialized vault_sealed <<<"$vault_state"
if [[ "$vault_initialized" != true ]]; then
  die "Vault is not initialized. Run the production operator init ceremony, then scripts/store-vault-unseal-key.py on the controller."
fi
if [[ "$vault_sealed" != false ]]; then
  die "Vault is sealed. Unseal it first: printf '%s\\n' \"\$SHARE\" | sudo scripts/vault-unseal.sh"
fi

# ── 1: read the rotator-escrowed relying-party client secret ────────────────
echo ">> reading the escrowed vault OIDC client secret"
if ! escrow_json="$(vlt kv get -format=json "kv/$VAULT_OIDC_RP_VAULT_PATH")"; then
  cat >&2 <<EOF
FATAL: no readable escrow at kv/$VAULT_OIDC_RP_VAULT_PATH.

The key-rotator escrows the 'vault' relying-party client secret during the
automatic Ansible identity setup. Run the normal playbook first. On a host
bootstrapped before this feature, first re-write the rotator policy from
the documented Vault policy ceremony, restore the
temporary bootstrap service if needed, and re-run Ansible. See
docs/identity-operations.md.
EOF
  exit 1
fi
# Only the secret crosses back into the shell; the schema is validated where
# the JSON is parsed, and nothing from the escrow document is ever printed.
CLIENT_SECRET="$(printf '%s' "$escrow_json" | python3 -I -c '
import json, sys
try:
    doc = json.load(sys.stdin)["data"]["data"]
except (KeyError, TypeError, ValueError):
    raise SystemExit("Vault OIDC RP escrow was not valid KV JSON") from None
if not isinstance(doc, dict) or doc.get("schema_version") != 1:
    raise SystemExit("Vault OIDC RP escrow has an unsupported schema")
if doc.get("client_id") != "vault":
    raise SystemExit("Vault OIDC RP escrow is for an unexpected client")
secret = doc.get("client_secret")
if not isinstance(secret, str) or len(secret) < 32:
    raise SystemExit("Vault OIDC RP escrow holds no usable client secret")
sys.stdout.write(secret)
')" || die "the escrow at kv/$VAULT_OIDC_RP_VAULT_PATH is invalid"

# ── 2: enable and configure the OIDC auth method ────────────────────────────
if ! vlt auth list -format=json | grep -q '"oidc/"'; then
  echo ">> enabling auth/oidc"
  vlt auth enable oidc >/dev/null
fi
OIDC_ACCESSOR="$(vlt auth list -format=json | python3 -I -c '
import json, sys
mounts = json.load(sys.stdin)
accessor = mounts.get("oidc/", {}).get("accessor") if isinstance(mounts, dict) else None
if not isinstance(accessor, str) or not accessor.startswith("auth_oidc_"):
    raise SystemExit("auth/oidc accessor was not found")
print(accessor)
')" || die "could not resolve the auth/oidc mount accessor"

# The config write makes Vault perform discovery immediately, so it proves
# the issuer URL, the net-vault edge alias, and the CA pinning in one step.
# JSON on stdin keeps the client secret off every command line.
echo ">> configuring auth/oidc against https://auth.$DOMAIN/realms/aigw"
printf '%s' "$CLIENT_SECRET" | python3 -I -c '
import json, sys
secret = sys.stdin.read()
with open(sys.argv[1], encoding="ascii") as handle:
    ca_pem = handle.read()
print(json.dumps({
    "oidc_discovery_url": f"https://auth.{sys.argv[2]}/realms/aigw",
    "oidc_discovery_ca_pem": ca_pem,
    "oidc_client_id": "vault",
    "oidc_client_secret": secret,
    "default_role": "aigw",
}))
' "$CA_BUNDLE" "$DOMAIN" | vlt write auth/oidc/config - >/dev/null \
  || die "Vault refused the OIDC configuration (is the current converge deployed? Vault reaches auth.$DOMAIN only through the net-vault edge alias)"
unset CLIENT_SECRET

# ── 3: the scoped vault-admins policy ───────────────────────────────────────
# Day-to-day platform-secret administration, deliberately NOT a root
# replacement. Holders can manage the application KV data plane and the edge
# issuing CA; they cannot touch auth methods, policies, identity, audit
# devices, seal state, mount creation, or the credential escrows.
echo ">> writing the vault-admins policy"
vlt policy write vault-admins - <<HCL
# Application secrets: full KV v2 data-plane control on the kv/ mount,
# including version soft-delete/undelete/destroy and metadata management.
path "kv/data/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "kv/metadata/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "kv/delete/*" { capabilities = ["update"] }
path "kv/undelete/*" { capabilities = ["update"] }
path "kv/destroy/*" { capabilities = ["update"] }

# The credential escrows and the two Keycloak client private keys stay
# root-ceremony-only, and "untouchable" must cover EVERY KV v2 sub-API, not
# just reads. Vault matches one most-specific rule per exact request path, and
# KV v2 serves read/write (kv/data), metadata + permanent delete-all
# (kv/metadata), per-version soft-delete (kv/delete), undelete (kv/undelete),
# permanent per-version destroy (kv/destroy), and subkey-structure reads
# (kv/subkeys) at SEPARATE paths. A deny on only kv/data/X + kv/metadata/X
# would leave \`vault kv delete -versions=N\` and \`vault kv destroy -versions=N\`
# falling through to the wildcard grants above and irreversibly wiping the
# break-glass recovery credential (or a rotator private key). So each protected
# record is denied on all six sub-APIs. (kv/subkeys has no matching grant above
# and is therefore already default-denied; it is pinned here as defense in
# depth so a future kv/subkeys/* grant cannot silently expose these records.)
# deny always wins over the globs.
path "kv/data/${BREAK_GLASS_ADMIN_VAULT_PATH}" { capabilities = ["deny"] }
path "kv/metadata/${BREAK_GLASS_ADMIN_VAULT_PATH}" { capabilities = ["deny"] }
path "kv/delete/${BREAK_GLASS_ADMIN_VAULT_PATH}" { capabilities = ["deny"] }
path "kv/undelete/${BREAK_GLASS_ADMIN_VAULT_PATH}" { capabilities = ["deny"] }
path "kv/destroy/${BREAK_GLASS_ADMIN_VAULT_PATH}" { capabilities = ["deny"] }
path "kv/subkeys/${BREAK_GLASS_ADMIN_VAULT_PATH}" { capabilities = ["deny"] }
path "kv/data/${VAULT_OIDC_RP_VAULT_PATH}" { capabilities = ["deny"] }
path "kv/metadata/${VAULT_OIDC_RP_VAULT_PATH}" { capabilities = ["deny"] }
path "kv/delete/${VAULT_OIDC_RP_VAULT_PATH}" { capabilities = ["deny"] }
path "kv/undelete/${VAULT_OIDC_RP_VAULT_PATH}" { capabilities = ["deny"] }
path "kv/destroy/${VAULT_OIDC_RP_VAULT_PATH}" { capabilities = ["deny"] }
path "kv/subkeys/${VAULT_OIDC_RP_VAULT_PATH}" { capabilities = ["deny"] }
path "kv/data/${IDENTITY_CONTROLLER_KEY_VAULT_PATH}" { capabilities = ["deny"] }
path "kv/metadata/${IDENTITY_CONTROLLER_KEY_VAULT_PATH}" { capabilities = ["deny"] }
path "kv/delete/${IDENTITY_CONTROLLER_KEY_VAULT_PATH}" { capabilities = ["deny"] }
path "kv/undelete/${IDENTITY_CONTROLLER_KEY_VAULT_PATH}" { capabilities = ["deny"] }
path "kv/destroy/${IDENTITY_CONTROLLER_KEY_VAULT_PATH}" { capabilities = ["deny"] }
path "kv/subkeys/${IDENTITY_CONTROLLER_KEY_VAULT_PATH}" { capabilities = ["deny"] }
path "kv/data/${KC_CLIENT_ASSERTION_KEY_VAULT_PATH}" { capabilities = ["deny"] }
path "kv/metadata/${KC_CLIENT_ASSERTION_KEY_VAULT_PATH}" { capabilities = ["deny"] }
path "kv/delete/${KC_CLIENT_ASSERTION_KEY_VAULT_PATH}" { capabilities = ["deny"] }
path "kv/undelete/${KC_CLIENT_ASSERTION_KEY_VAULT_PATH}" { capabilities = ["deny"] }
path "kv/destroy/${KC_CLIENT_ASSERTION_KEY_VAULT_PATH}" { capabilities = ["deny"] }
path "kv/subkeys/${KC_CLIENT_ASSERTION_KEY_VAULT_PATH}" { capabilities = ["deny"] }

# Edge PKI: operate the pki_int issuing mount (roles, issuance, revocation,
# CRL). No authority over any root CA mount and no mount create/delete.
path "pki_int/*" { capabilities = ["create", "read", "update", "delete", "list"] }

# Introspection and bounded mount tuning of the two mounts above.
path "sys/mounts" { capabilities = ["read"] }
path "sys/mounts/kv/tune" { capabilities = ["read", "update"] }
path "sys/mounts/pki_int/tune" { capabilities = ["read", "update"] }
path "sys/health" { capabilities = ["read"] }
path "sys/seal-status" { capabilities = ["read"] }
HCL

# ── 4: the aigw login role ──────────────────────────────────────────────────
# bound_claims requires the aigw-admins realm role in the roles claim, so a
# non-admin who reaches the listener (for example over an SSH tunnel) cannot
# log in at all — matching the outer oauth2-proxy gate. The loopback callback
# serves `vault login -method=oidc` through a deliberate operator SSH tunnel.
echo ">> writing the aigw OIDC role"
python3 -I -c '
import json, sys
print(json.dumps({
    "role_type": "oidc",
    "user_claim": "preferred_username",
    "groups_claim": "roles",
    "bound_audiences": ["vault"],
    "bound_claims": {"roles": ["aigw-admins"]},
    "oidc_scopes": ["openid", "profile"],
    "allowed_redirect_uris": [
        f"https://vault.{sys.argv[1]}/ui/vault/auth/oidc/oidc/callback",
        "http://localhost:8250/oidc/callback",
    ],
    "token_policies": ["default"],
    "token_ttl": "1h",
    "token_max_ttl": "8h",
}))
' "$DOMAIN" | vlt write auth/oidc/role/aigw - >/dev/null

# ── 5: external group aigw-admins -> vault-admins ───────────────────────────
echo ">> mapping external group aigw-admins to vault-admins"
if group_json="$(vlt read -format=json identity/group/name/aigw-admins 2>/dev/null)"; then
  GROUP_ID="$(printf '%s' "$group_json" | python3 -I -c '
import json, sys
data = json.load(sys.stdin).get("data", {})
if data.get("type") != "external":
    raise SystemExit("identity group aigw-admins exists but is not external; refusing to adopt it")
print(data["id"])
')" || die "identity group aigw-admins is not adoptable"
  vlt write identity/group name=aigw-admins type=external policies=vault-admins >/dev/null
else
  vlt write identity/group name=aigw-admins type=external policies=vault-admins >/dev/null
  GROUP_ID="$(vlt read -format=json identity/group/name/aigw-admins | python3 -I -c '
import json, sys
print(json.load(sys.stdin)["data"]["id"])
')" || die "could not read back the aigw-admins identity group"
fi

alias_lookup="$(vlt write -format=json identity/lookup/group \
  alias_name=aigw-admins "alias_mount_accessor=$OIDC_ACCESSOR" 2>/dev/null || true)"
existing_alias_group="$(printf '%s' "$alias_lookup" | python3 -I -c '
import json, sys
raw = sys.stdin.read().strip()
if not raw:
    print("")
    raise SystemExit(0)
data = json.loads(raw).get("data") or {}
print(data.get("id", ""))
' || true)"
if [[ -z "$existing_alias_group" ]]; then
  vlt write identity/group-alias name=aigw-admins \
    "mount_accessor=$OIDC_ACCESSOR" "canonical_id=$GROUP_ID" >/dev/null
elif [[ "$existing_alias_group" != "$GROUP_ID" ]]; then
  die "an aigw-admins alias on auth/oidc already maps to a different identity group; resolve it manually"
fi

# ── 6: verify the ceremony's own work ───────────────────────────────────────
echo ">> verifying"
vlt read -format=json auth/oidc/config | python3 -I -c '
import json, sys
data = json.load(sys.stdin).get("data", {})
expected_issuer = f"https://auth.{sys.argv[1]}/realms/aigw"
if data.get("oidc_discovery_url") != expected_issuer:
    raise SystemExit("auth/oidc discovery URL did not verify")
if data.get("oidc_client_id") != "vault":
    raise SystemExit("auth/oidc client id did not verify")
if data.get("default_role") != "aigw":
    raise SystemExit("auth/oidc default role did not verify")
if "BEGIN CERTIFICATE" not in (data.get("oidc_discovery_ca_pem") or ""):
    raise SystemExit("auth/oidc discovery CA pinning did not verify")
' "$DOMAIN" || die "auth/oidc configuration did not verify"

vlt read -format=json auth/oidc/role/aigw | python3 -I -c '
import json, sys
data = json.load(sys.stdin).get("data", {})
ui_callback = f"https://vault.{sys.argv[1]}/ui/vault/auth/oidc/oidc/callback"
checks = (
    data.get("user_claim") == "preferred_username",
    data.get("groups_claim") == "roles",
    data.get("bound_audiences") == ["vault"],
    (data.get("bound_claims") or {}).get("roles") == ["aigw-admins"],
    sorted(data.get("allowed_redirect_uris") or []) == sorted(
        [ui_callback, "http://localhost:8250/oidc/callback"]
    ),
    data.get("token_policies") == ["default"],
)
if not all(checks):
    raise SystemExit("auth/oidc role aigw did not verify")
' "$DOMAIN" || die "auth/oidc role did not verify"

vault_admins_policy="$(vlt policy read vault-admins)"
printf '%s' "$vault_admins_policy" | grep -q 'pki_int/\*' \
  || die "vault-admins policy did not verify"
# Prove the version-sub-API denies actually landed, not just the reads: the
# break-glass escrow is the irreversible worst case, so require its
# soft-delete and permanent-destroy denies explicitly.
for protected_sub_api in delete destroy; do
  printf '%s' "$vault_admins_policy" \
    | grep -q "kv/${protected_sub_api}/${BREAK_GLASS_ADMIN_VAULT_PATH}" \
    || die "vault-admins escrow ${protected_sub_api}-deny did not verify"
done

group_verify_json="$(vlt read -format=json identity/group/name/aigw-admins)"
printf '%s' "$group_verify_json" | python3 -I -c '
import json, sys
data = json.load(sys.stdin).get("data", {})
if data.get("type") != "external" or data.get("policies") != ["vault-admins"]:
    raise SystemExit("identity group aigw-admins did not verify")
' || die "identity group mapping did not verify"

# A real auth URL proves discovery, role, and redirect allow-list end to end
# without any interactive login. Only the URL prefix is checked; nothing
# secret is contained in or printed from it.
auth_url_json="$(vlt write -format=json auth/oidc/oidc/auth_url \
  role=aigw "redirect_uri=https://vault.$DOMAIN/ui/vault/auth/oidc/oidc/callback")" \
  || die "Vault could not produce an OIDC auth URL for role aigw"
printf '%s' "$auth_url_json" | python3 -I -c '
import json, sys
url = json.load(sys.stdin).get("data", {}).get("auth_url", "")
prefix = f"https://auth.{sys.argv[1]}/realms/aigw/protocol/openid-connect/auth"
if not url.startswith(prefix):
    raise SystemExit("the generated auth URL does not target the aigw realm")
' "$DOMAIN" || die "the OIDC auth URL did not verify"

cat <<EOF

DONE. Vault OIDC login is wired to Keycloak realm aigw.

  UI : https://vault.$DOMAIN -> Sign in with OIDC Provider (role aigw)
  CLI: via a deliberate operator SSH tunnel to the Vault listener:
         vault login -method=oidc role=aigw
  Who: aigw realm users whose token carries the aigw-admins role
  Policy: vault-admins (kv data plane + pki_int; NO auth/policy/identity/
          audit/seal/mount authority, NO credential-escrow access)

Routine root-token logins are now retired; the root token remains reserved
for ceremonies (this script, PKI, policy amendments, break-glass retrieval).
EOF
