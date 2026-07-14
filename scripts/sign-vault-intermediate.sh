#!/usr/bin/env bash
# sign-vault-intermediate.sh — offline CA side of the mode-2 PKI ceremony.
#
# Signs the CSR that Vault emitted for its INTERNALLY GENERATED intermediate key
# and returns the signed intermediate plus the complete chain.
#
#   Vault holds the intermediate private key and never exports it.
#   This script holds nothing: it reads the customer root key by path, signs,
#   and exits. The root private key is NEVER copied into this repository, never
#   placed on the gateway VM, and never transported anywhere.
#
# This script is deliberately NOT in the operational-script manifest, so Ansible
# never deploys it to the gateway. It runs on the operator's CA workstation --
# the only machine that legitimately holds the root signing key.
#
# Usage:
#   scripts/sign-vault-intermediate.sh \
#     --csr        /path/to/aigw-intermediate.csr \
#     --root-cert  /path/to/root-ca.pem \
#     --root-key   /path/to/root-ca-key.pem \
#     --out-dir    /path/to/output
#
# Emits into --out-dir:
#   intermediate.pem  the signed intermediate CA certificate
#   chain.pem         intermediate + root, in that order (what Vault imports)
set -euo pipefail
umask 077

DAYS=1825          # 5 years; must not outlive the root (checked below)
CSR=""
ROOT_CERT=""
ROOT_KEY=""
OUT_DIR=""
FORCE=false

die() { echo "FATAL: $*" >&2; exit 1; }

usage() {
  sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --csr)       CSR="${2:-}"; shift 2 ;;
    --root-cert) ROOT_CERT="${2:-}"; shift 2 ;;
    --root-key)  ROOT_KEY="${2:-}"; shift 2 ;;
    --out-dir)   OUT_DIR="${2:-}"; shift 2 ;;
    --days)      DAYS="${2:-}"; shift 2 ;;
    --force)     FORCE=true; shift ;;
    -h|--help)   usage 0 ;;
    *)           die "unsupported argument: $1" ;;
  esac
done

[[ -n "$CSR"       ]] || die "--csr is required"
[[ -n "$ROOT_CERT" ]] || die "--root-cert is required"
[[ -n "$ROOT_KEY"  ]] || die "--root-key is required"
[[ -n "$OUT_DIR"   ]] || die "--out-dir is required"

# ── OpenSSL 3 is required ───────────────────────────────────────────────────
# macOS ships LibreSSL at /usr/bin/openssl, whose x509/req extension handling
# diverges. Resolve a real OpenSSL 3 and refuse anything else rather than emit a
# subtly wrong intermediate.
OPENSSL="${AIGW_OPENSSL:-openssl}"
command -v "$OPENSSL" >/dev/null 2>&1 || die "openssl not found (set AIGW_OPENSSL)"
OPENSSL_VERSION="$("$OPENSSL" version)"
case "$OPENSSL_VERSION" in
  "OpenSSL 3."*) ;;
  *) die "OpenSSL 3 is required for this ceremony; found '$OPENSSL_VERSION'. On macOS install it (brew install openssl@3) and re-run with AIGW_OPENSSL=/opt/homebrew/opt/openssl@3/bin/openssl" ;;
esac

# ── fail-closed input validation, BEFORE any mutation ───────────────────────
require_safe_input() {
  local path="$1" label="$2"
  [[ "$path" = /* ]] || die "$label must be an absolute path: $path"
  [[ ! -L "$path" ]]  || die "$label is a symlink; supply the real file: $path"
  [[ -f "$path" ]]    || die "$label is not a regular file: $path"
  [[ -r "$path" ]]    || die "$label is not readable: $path"
  local links
  links="$(python3 -I -c 'import os,sys; print(os.lstat(sys.argv[1]).st_nlink)' "$path")"
  [[ "$links" -eq 1 ]] || die "$label has $links hard links; expected exactly 1: $path"
}

require_safe_input "$CSR"       "--csr"
require_safe_input "$ROOT_CERT" "--root-cert"
require_safe_input "$ROOT_KEY"  "--root-key"

# The CSR is the ONLY thing that should ever leave the gateway. If a private key
# turns up in it, someone exported key material that must never have moved.
if grep -q "PRIVATE KEY" "$CSR"; then
  die "certificate input contains private key material; the customer CA signing key must never be supplied"
fi
grep -q "BEGIN CERTIFICATE REQUEST" "$CSR" || die "--csr is not a PEM certificate request: $CSR"

# The root key must not be readable by anyone else on this workstation.
ROOT_KEY_MODE="$(python3 -I -c 'import os,stat,sys; print(oct(stat.S_IMODE(os.lstat(sys.argv[1]).st_mode))[2:].zfill(4))' "$ROOT_KEY")"
case "$ROOT_KEY_MODE" in
  0600|0400) ;;
  *) die "--root-key mode is $ROOT_KEY_MODE; the CA signing key must be 0600 or 0400 (chmod 600 '$ROOT_KEY')" ;;
esac

[[ -d "$OUT_DIR" ]] || die "--out-dir is not a directory: $OUT_DIR"

INTERMEDIATE="$OUT_DIR/intermediate.pem"
CHAIN="$OUT_DIR/chain.pem"
if [[ "$FORCE" != true ]]; then
  for existing in "$INTERMEDIATE" "$CHAIN"; do
    [[ ! -e "$existing" ]] || die "refusing to overwrite $existing (pass --force to replace)"
  done
fi

# The CSR must be internally consistent: its signature proves the requester holds
# the matching private key (Vault does, and never released it).
"$OPENSSL" req -in "$CSR" -noout -verify >/dev/null 2>&1 \
  || die "--csr signature does not verify: $CSR"

# The root must actually be a self-signed CA, and the supplied key must be its key.
ROOT_SUBJECT="$("$OPENSSL" x509 -in "$ROOT_CERT" -noout -subject)"
ROOT_ISSUER="$("$OPENSSL" x509 -in "$ROOT_CERT" -noout -issuer)"
[[ "${ROOT_SUBJECT#subject=}" == "${ROOT_ISSUER#issuer=}" ]] \
  || die "--root-cert is not self-signed; supply the root CA, not an intermediate"
"$OPENSSL" x509 -in "$ROOT_CERT" -noout -text | grep -q "CA:TRUE" \
  || die "--root-cert is not a CA certificate (CA:TRUE absent)"
ROOT_CERT_PUB="$("$OPENSSL" x509 -in "$ROOT_CERT" -noout -pubkey)"
ROOT_KEY_PUB="$("$OPENSSL" pkey -in "$ROOT_KEY" -pubout)"
[[ "$ROOT_CERT_PUB" == "$ROOT_KEY_PUB" ]] \
  || die "--root-key does not match --root-cert"

# The intermediate must not outlive the root that signed it.
if ! "$OPENSSL" x509 -in "$ROOT_CERT" -noout -checkend "$(( DAYS * 86400 ))" >/dev/null; then
  die "the root CA expires within $DAYS days; choose a shorter --days or renew the root"
fi

# ── sign ────────────────────────────────────────────────────────────────────
# Exactly the extensions an issuing intermediate needs and nothing more.
# pathlen:0 stops this intermediate from minting further CAs.
WORK="$(mktemp -d)"
cleanup() { rm -rf -- "$WORK"; }
trap cleanup EXIT HUP INT TERM

cat > "$WORK/intermediate.ext" <<'EXT'
basicConstraints = critical,CA:true,pathlen:0
keyUsage = critical,digitalSignature,cRLSign,keyCertSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EXT

"$OPENSSL" x509 -req \
  -in "$CSR" \
  -CA "$ROOT_CERT" \
  -CAkey "$ROOT_KEY" \
  -CAcreateserial -CAserial "$WORK/ca.srl" \
  -days "$DAYS" \
  -sha256 \
  -extfile "$WORK/intermediate.ext" \
  -out "$WORK/intermediate.pem" >/dev/null 2>&1 \
  || die "the root CA refused to sign the CSR"

cat "$WORK/intermediate.pem" "$ROOT_CERT" > "$WORK/chain.pem"

# ── prove the result before handing it back ─────────────────────────────────
"$OPENSSL" verify -CAfile "$ROOT_CERT" "$WORK/intermediate.pem" >/dev/null \
  || die "the signed intermediate does not verify against the root"

INTERMEDIATE_TEXT="$("$OPENSSL" x509 -in "$WORK/intermediate.pem" -noout -text)"
grep -q "CA:TRUE, pathlen:0" <<<"$INTERMEDIATE_TEXT" \
  || die "the signed intermediate lacks basicConstraints CA:TRUE, pathlen:0"
grep -q "Certificate Sign" <<<"$INTERMEDIATE_TEXT" \
  || die "the signed intermediate lacks the Certificate Sign key usage"

install -m 0644 "$WORK/intermediate.pem" "$INTERMEDIATE"
install -m 0644 "$WORK/chain.pem" "$CHAIN"

cat >&2 <<EOF

Signed intermediate ready.

  intermediate : $INTERMEDIATE
  chain        : $CHAIN   (intermediate + root)

The root private key was read in place and never copied. Nothing in $OUT_DIR
contains private key material.

Next: copy ONLY these two files to the gateway and import them into Vault:

  scp $INTERMEDIATE $CHAIN <gateway>:/tmp/
  ssh <gateway>
  cd /opt/ai-gateway
  read -rsp 'Vault root token: ' TOK; printf '\n'
  printf '%s\n' "\$TOK" | sudo scripts/vault-pki-intermediate.sh install-signed \\
      --signed-intermediate /tmp/intermediate.pem --chain /tmp/chain.pem
  unset TOK
EOF
