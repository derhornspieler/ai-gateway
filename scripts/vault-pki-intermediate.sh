#!/usr/bin/env bash
# vault-pki-intermediate.sh — gateway side of the mode-2 PKI ceremony.
#
# Run ON THE VM from the stack directory (default /opt/ai-gateway) as root.
#
# The trust model, which every gate below exists to preserve:
#
#   * Vault GENERATES the intermediate private key INTERNALLY and never exports
#     it. This script cannot extract it and does not try.
#   * The CUSTOMER's root/issuing private key stays wherever the customer keeps
#     it. It is never requested, transported, or stored here. What crosses the
#     boundary is a CSR going out and a signed certificate coming back.
#   * Consequently this script never enables or writes a Vault ROOT PKI mount.
#     A contract test asserts that no root-generation or root-signing Vault path
#     appears anywhere in this file -- including in comments, which is why none
#     is spelled out here.
#
# Ceremony:
#   1.  vault-pki-intermediate.sh csr            (here)   -> secrets/aigw-intermediate.csr
#   2.  sign-vault-intermediate.sh               (CA host) -> intermediate.pem + chain.pem
#   3.  vault-pki-intermediate.sh install-signed (here)   -> live edge certificates
#
# The Vault token is read from stdin only -- never argv, never an environment
# variable on a command line, never a log.
set -euo pipefail
umask 077

STACK_DIR="${STACK_DIR:-/opt/ai-gateway}"
cd "$STACK_DIR"
compose=("$STACK_DIR/scripts/aigw-compose.sh")

die() { echo "FATAL: $*" >&2; exit 1; }

env_value() {
  grep -E "^$1=" .env | cut -d= -f2- || true
}

SUBCOMMAND="${1:-}"
shift || true

SIGNED_INTERMEDIATE=""
CHAIN=""
REGENERATE=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --signed-intermediate) SIGNED_INTERMEDIATE="${2:-}"; shift 2 ;;
    --chain)               CHAIN="${2:-}"; shift 2 ;;
    --regenerate)          REGENERATE=true; shift ;;
    *) die "unsupported argument: $1" ;;
  esac
done

# ── mode gate ───────────────────────────────────────────────────────────────
# This ceremony is meaningless on a deployment that did not select it, and on a
# customer-supplied deployment it would silently replace operator-owned material.
AIGW_EDGE_TLS_MODE="$(env_value AIGW_EDGE_TLS_MODE)"
if [[ "$AIGW_EDGE_TLS_MODE" != "vault-intermediate" ]]; then
  die "vault-pki-intermediate.sh requires aigw_edge_tls_mode=vault-intermediate in the deployed inventory"
fi

DOMAIN="$(env_value DOMAIN)"
[[ -n "$DOMAIN" ]] || die "DOMAIN is not set in .env"
MIN_DAYS="$(env_value AIGW_EDGE_TLS_MIN_DAYS_REMAINING)"
MIN_DAYS="${MIN_DAYS:-30}"

MARKER="$STACK_DIR/.state/edge-tls-issued"

# ── token on stdin only ─────────────────────────────────────────────────────
if [[ -t 0 ]]; then
  cat >&2 <<'EOF'
FATAL: the Vault token must arrive on stdin, never as an argument.

  read -rsp 'Vault token: ' TOK; printf '\n'
  printf '%s\n' "$TOK" | sudo scripts/vault-pki-intermediate.sh <subcommand>
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
  die "Vault is not initialized. Run the Vault init ceremony first (lab: scripts/vault-bootstrap.sh; production: the operator init ceremony + scripts/store-vault-unseal-key.py on the controller)."
fi
if [[ "$vault_sealed" != false ]]; then
  die "Vault is sealed. Unseal it first: printf '%s\\n' \"\$SHARE\" | sudo scripts/vault-unseal.sh"
fi

require_safe_input() {
  local path="$1" label="$2"
  [[ -n "$path" ]]   || die "$label is required"
  [[ ! -L "$path" ]] || die "$label is a symlink; supply the real file: $path"
  [[ -f "$path" ]]   || die "$label is not a regular file: $path"
  if grep -q "PRIVATE KEY" "$path"; then
    die "certificate input contains private key material; the customer CA signing key must never be supplied"
  fi
}

issue_and_install_leaf() {
  # Stream the issue response straight into python. The leaf private key lands
  # only in the private staging file and then in certs/int.key; no JSON copy of
  # it is retained anywhere.
  local staging
  staging="$(mktemp -d "$STACK_DIR/.state/edge-tls-staging.XXXXXX")"
  chmod 700 "$staging"
  # shellcheck disable=SC2064
  trap "rm -rf -- '$staging'" EXIT HUP INT TERM

  echo ">> issuing *.$DOMAIN and $DOMAIN from the customer-CA-signed intermediate"
  vlt write -format=json pki_int/issue/aigw \
      common_name="*.$DOMAIN" alt_names="$DOMAIN" ttl=2160h \
  | STAGING="$staging" python3 -I -c '
import json, os, sys
staging = os.environ["STAGING"]
data = json.load(sys.stdin)["data"]
leaf = os.open(os.path.join(staging, "leaf.pem"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
os.write(leaf, (data["certificate"] + "\n").encode())
os.close(leaf)
key = os.open(os.path.join(staging, "leaf.key"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
os.write(key, (data["private_key"] + "\n").encode())
os.close(key)
'

  # The chain we install is the reviewed one: the customer-signed intermediate
  # plus the customer root. edge-tls.py refuses it if it does not anchor on a
  # self-signed root, so a leaf+intermediate bundle cannot slip through.
  cp -- "$STACK_DIR/secrets/aigw-edge-chain.pem" "$staging/chain.pem"

  # Validation happens BEFORE certs/ is touched. On failure the live edge keeps
  # serving whatever it was serving.
  python3 -I "$STACK_DIR/scripts/edge-tls.py" install \
    --leaf "$staging/leaf.pem" \
    --key "$staging/leaf.key" \
    --chain "$staging/chain.pem" \
    --certs-dir "$STACK_DIR/certs" \
    --domain "$DOMAIN" \
    --min-days-remaining "$MIN_DAYS"

  rm -rf -- "$staging"
  trap - EXIT HUP INT TERM
}

restart_edge_consumers() {
  "${compose[@]}" up -d --no-deps --force-recreate traefik-int traefik-adm open-webui
  "$STACK_DIR/scripts/aigw-runtime-up.sh" -d --wait --wait-timeout 600
}

# Issue the lab Samba AD LDAPS leaf from the SAME customer-CA-signed
# intermediate that signs the edge certificates, then deliver it to the lab DC
# as root-owned files and recreate the container so it serves it. This makes
# Keycloak exercise the real production trust path (Aegis chain in certs/ca.pem)
# instead of trusting a self-signed lab certificate.
#
# The certificate's ONLY SAN is the FQDN samba-ad.$DOMAIN. A bare-hostname SAN
# (`samba-ad`) is deliberately NOT requested: the Aegis root CA carries critical
# name constraints (permitted DNS aegisgroup.ch/cluster.local), so a bare host
# label would poison the leaf -> `openssl verify` error 47 (permitted subtree
# violation). Vault's `aigw` role is allowed_domains=$DOMAIN allow_subdomains,
# so samba-ad.$DOMAIN is issuable and constraint-clean.
issue_and_install_samba_leaf() {
  local profile
  profile="$(env_value DEPLOYMENT_PROFILE)"
  [[ "$profile" == rocky9-lab ]] \
    || die "samba-tls is a lab-only ceremony (DEPLOYMENT_PROFILE must be rocky9-lab)"

  local staging
  staging="$(mktemp -d "$STACK_DIR/.state/samba-tls-staging.XXXXXX")"
  chmod 700 "$staging"
  # shellcheck disable=SC2064
  trap "rm -rf -- '$staging'" EXIT HUP INT TERM

  # The reviewed edge chain (intermediate + self-signed customer root), written
  # by install-signed, is the ONLY complete chain: Vault's ca_chain returns the
  # intermediate but omits the external root it does not hold. The DC publishes
  # this bundle as its trust anchor (samba-public/ca.pem), so it must reach the
  # root or a client cannot complete the path.
  [[ -s "$STACK_DIR/secrets/aigw-edge-chain.pem" ]] \
    || die "samba-tls requires the customer-CA edge chain; run install-signed first"

  echo ">> issuing samba-ad.$DOMAIN from the customer-CA-signed intermediate"
  vlt write -format=json pki_int/issue/aigw \
      common_name="samba-ad.$DOMAIN" ttl=2160h \
  | STAGING="$staging" EDGE_CHAIN="$STACK_DIR/secrets/aigw-edge-chain.pem" python3 -I -c '
import json, os, sys
staging = os.environ["STAGING"]
data = json.load(sys.stdin)["data"]
# Leaf, then the complete issuing chain (intermediate + self-signed root) taken
# from the reviewed edge chain so the published trust anchor reaches a root.
ca = open(os.environ["EDGE_CHAIN"], encoding="ascii").read().rstrip("\n") + "\n"
bundle = data["certificate"].rstrip("\n") + "\n" + ca
cert_fd = os.open(os.path.join(staging, "tls.crt"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
os.write(cert_fd, bundle.encode())
os.close(cert_fd)
key_fd = os.open(os.path.join(staging, "tls.key"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
os.write(key_fd, (data["private_key"].rstrip("\n") + "\n").encode())
os.close(key_fd)
'
  # Prove the leaf certifies exactly the FQDN before it is installed, so a wrong
  # or truncated response never displaces the working (self-signed) material.
  openssl x509 -in "$staging/tls.crt" -noout -checkhost "samba-ad.$DOMAIN" >/dev/null \
    || die "issued leaf does not certify samba-ad.$DOMAIN"
  openssl pkey -in "$staging/tls.key" -noout >/dev/null 2>&1 \
    || die "issued private key is unreadable"

  # Atomic, root-owned install. Key is 0600 root:root: Samba's CVE-2013-4476
  # guard rejects any group/other bit on the LDAPS private key.
  install -m 0644 -- "$staging/tls.crt" "$STACK_DIR/secrets/samba_ad_tls_cert"
  install -m 0600 -- "$staging/tls.key" "$STACK_DIR/secrets/samba_ad_tls_key"

  rm -rf -- "$staging"
  trap - EXIT HUP INT TERM

  # Recreate the DC so its entrypoint adopts the CA-issued material now. A later
  # converge re-digests the new bytes and reconciles the same recreation.
  "${compose[@]}" up -d --no-deps --force-recreate samba-ad
}

case "$SUBCOMMAND" in
  csr)
    if [[ -e "$MARKER" && "$REGENERATE" != true ]]; then
      die "this deployment already has customer-CA-signed edge material ($MARKER). Regenerating the intermediate key invalidates the currently installed chain and any pending CSR; pass --regenerate only if you intend to repeat the whole ceremony."
    fi
    if ! vlt secrets list -format=json | grep -q '"pki_int/"'; then
      vlt secrets enable -path=pki_int pki
    fi
    vlt secrets tune -max-lease-ttl=43800h pki_int

    mkdir -p secrets
    csr_tmp="$(mktemp "secrets/.aigw-intermediate.csr.XXXXXX")"
    chmod 600 "$csr_tmp"
    # shellcheck disable=SC2064
    trap "rm -f -- '$csr_tmp'" EXIT HUP INT TERM
    vlt write -field=csr pki_int/intermediate/generate/internal \
        common_name="AIGW Intermediate CA" ttl=43800h > "$csr_tmp"
    grep -q "BEGIN CERTIFICATE REQUEST" "$csr_tmp" || die "Vault did not return a CSR"
    mv -f -- "$csr_tmp" secrets/aigw-intermediate.csr
    chmod 600 secrets/aigw-intermediate.csr
    trap - EXIT HUP INT TERM

    cat >&2 <<EOF

CSR ready: $STACK_DIR/secrets/aigw-intermediate.csr

Vault generated the intermediate private key internally and will not release it.
The CSR is the only artifact that leaves this host.

Have the CUSTOMER CA sign it OFFLINE with exactly:

    basicConstraints = critical,CA:true,pathlen:0
    keyUsage         = critical,digitalSignature,cRLSign,keyCertSign

scripts/sign-vault-intermediate.sh does this. Return the signed intermediate
plus the COMPLETE chain, including the self-signed root.

NEVER provide, request, copy, or store the customer root or issuing private key.

Then:
    printf '%s\n' "\$TOK" | sudo scripts/vault-pki-intermediate.sh install-signed \\
        --signed-intermediate /tmp/intermediate.pem --chain /tmp/chain.pem
EOF
    ;;

  install-signed)
    require_safe_input "$SIGNED_INTERMEDIATE" "--signed-intermediate"
    require_safe_input "$CHAIN" "--chain"

    # Pre-validate the signed intermediate before importing it into Vault.
    openssl x509 -in "$SIGNED_INTERMEDIATE" -noout -text | grep -q "CA:TRUE" \
      || die "--signed-intermediate is not a CA certificate (CA:TRUE absent)"
    openssl x509 -in "$SIGNED_INTERMEDIATE" -noout -text | grep -q "Certificate Sign" \
      || die "--signed-intermediate lacks the Certificate Sign key usage"
    openssl x509 -in "$SIGNED_INTERMEDIATE" -noout -checkend "$(( MIN_DAYS * 86400 ))" >/dev/null \
      || die "--signed-intermediate expires within the ${MIN_DAYS}-day safety window"
    openssl verify -CAfile "$CHAIN" -untrusted "$CHAIN" "$SIGNED_INTERMEDIATE" >/dev/null \
      || die "--signed-intermediate does not verify against --chain; the chain must contain the complete path including the self-signed root"

    # Vault itself enforces that this certificate matches the intermediate key it
    # generated internally. A certificate for any other key is rejected here.
    #
    # set-signed IMPORTS an issuer; it does not make it the one that signs. A
    # mount that was previously bootstrapped with the self-signed TEST root (the
    # brownfield case: an existing deployment migrating onto the customer CA)
    # already holds issuers, and Vault's default_follows_latest_issuer is false,
    # so the mount keeps issuing from the OLD test intermediate. Every leaf would
    # then chain to the test root and fail edge-tls.py's verification -- with the
    # customer-signed issuer sitting unused in the mount. Promote the imported
    # issuer explicitly, and prove the promotion took.
    imported="$(vlt write -format=json pki_int/intermediate/set-signed \
        certificate=- < "$SIGNED_INTERMEDIATE" \
        | python3 -I -c 'import json,sys; ids=(json.load(sys.stdin)["data"] or {}).get("imported_issuers") or []; print(ids[0] if ids else "")')"

    supplied_fp="$(openssl x509 -in "$SIGNED_INTERMEDIATE" -noout -fingerprint -sha256)"

    # set-signed is idempotent: re-running the ceremony with a certificate Vault
    # already holds imports nothing and returns an empty list. The ceremony must
    # stay re-runnable, so resolve the issuer by certificate identity rather than
    # by "was it new" -- then promotion below is correct on both paths.
    if [[ -z "$imported" ]]; then
      for candidate in $(vlt list -format=json pki_int/issuers \
          | python3 -I -c 'import json,sys; [print(i) for i in json.load(sys.stdin)]'); do
        if [[ "$(vlt read -field=certificate "pki_int/issuer/$candidate" \
                 | openssl x509 -noout -fingerprint -sha256)" == "$supplied_fp" ]]; then
          imported="$candidate"
          break
        fi
      done
    fi
    [[ -n "$imported" ]] \
      || die "Vault holds no issuer matching --signed-intermediate; refusing to leave the mount issuing from a stale CA"

    vlt write pki_int/config/issuers \
        default="$imported" default_follows_latest_issuer=false >/dev/null

    # Fail closed if the mount would still sign with anything but the certificate
    # the customer CA just signed.
    promoted_fp="$(vlt read -field=certificate "pki_int/issuer/$imported" \
      | openssl x509 -noout -fingerprint -sha256)"
    [[ "$promoted_fp" == "$supplied_fp" ]] \
      || die "the promoted Vault issuer is not the customer-signed intermediate"

    # Pin the role to the promoted issuer so a later default change cannot
    # silently move leaf issuance back onto a stale CA.
    vlt write pki_int/roles/aigw \
        issuer_ref="$imported" \
        allowed_domains="$DOMAIN" allow_subdomains=true allow_bare_domains=true \
        max_ttl=2160h >/dev/null

    # Retain the reviewed chain so renew-leaf can rebuild the edge bundle without
    # the operator re-supplying it. This is public certificate material only --
    # edge-tls.py has already refused it if it contained any private key.
    install -m 0644 -- "$CHAIN" "$STACK_DIR/secrets/aigw-edge-chain.pem"

    mkdir -p "$STACK_DIR/.state"
    issue_and_install_leaf

    printf 'vault-intermediate %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$MARKER"
    chmod 600 "$MARKER"

    restart_edge_consumers
    echo ">> edge now serves a certificate chaining to the customer root CA."
    ;;

  renew-leaf)
    [[ -e "$MARKER" ]] || die "no customer-CA-signed intermediate is installed; run the csr + install-signed ceremony first"
    issue_and_install_leaf
    restart_edge_consumers
    echo ">> edge leaf renewed."
    ;;

  samba-tls)
    [[ -e "$MARKER" ]] || die "no customer-CA-signed intermediate is installed; run the csr + install-signed ceremony first"
    issue_and_install_samba_leaf
    echo ">> lab Samba AD now serves ldaps://samba-ad.$DOMAIN:636 with a customer-CA-signed certificate."
    ;;

  *)
    die "usage: vault-pki-intermediate.sh {csr|install-signed --signed-intermediate FILE --chain FILE|renew-leaf|samba-tls}"
    ;;
esac
