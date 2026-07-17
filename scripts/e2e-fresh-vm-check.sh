#!/usr/bin/env bash
# e2e-fresh-vm-check.sh — READ-ONLY post-deploy acceptance verification for an
# AI Gateway VM (lab Parallels aigw01 or production). It starts nothing, changes
# nothing, and prints no secret material. It proves, from a controller/jump host
# that can reach BOTH published edges on tcp/443, that:
#
#   A. every published FQDN presents a certificate that verifies to the customer
#      root CA WITH hostname verification (openssl s_client -verify_hostname and
#      curl's ssl_verify_result — the browser green-lock, headless);
#   B. every ADMIN-plane FQDN answers on the ADM edge and 404s on the internal
#      edge (curl --resolve against both plane IPs);
#   C. every USER/internal-plane FQDN answers on the internal edge and 404s on
#      the ADM edge; the dual-homed auth. and chat. hosts answer on both;
#   D. the Keycloak authorization endpoint returns 200 (login page) for every
#      OIDC client's registered redirect_uri (SSO is wired);
#   E. (optional, --ssh) the live DOCKER-USER + nft aigw_guard prove Envoy
#      (172.28.0.2) is the ONLY workload allowed out to vendors on tcp/443 and
#      every container bridge is default-drop — i.e. internal-plane containers
#      cannot reach the Internet. This is the same evidence the converge's
#      verify role asserts, read back over SSH with iptables/nft (read-only).
#   F. Samba LDAPS testLDAPConnection is reported as a token-gated manual step
#      (it needs a Keycloak admin token this read-only script must not custody).
#
# Interactive OIDC login (typing credentials, landing on an authenticated page)
# and any real browser "green lock" screenshot require a human Chrome click and
# are NOT performed here; see docs/acceptance-e2e-fresh-vm.md Phase 5.
#
# Exit status: 0 only if every executed check passed; non-zero on any failure.
#
# Usage:
#   scripts/e2e-fresh-vm-check.sh \
#       --domain aigw.aegisgroup.ch \
#       --adm-ip 10.8.10.10 --internal-ip 10.20.0.10 \
#       --root-ca ansible/inventory/local-pki/ca-chain.pem \
#       [--vault-ui] [--system-trust] [--ssh ansible@10.8.10.10] [--timeout 8]
#
# Every flag also has an environment fallback: AIGW_DOMAIN, AIGW_ADM_IP,
# AIGW_INTERNAL_IP, AIGW_ROOT_CA, AIGW_VAULT_UI (true/false), AIGW_SYSTEM_TRUST,
# AIGW_SSH_TARGET, AIGW_TIMEOUT.
set -euo pipefail

DOMAIN="${AIGW_DOMAIN:-}"
ADM_IP="${AIGW_ADM_IP:-}"
INTERNAL_IP="${AIGW_INTERNAL_IP:-}"
ROOT_CA="${AIGW_ROOT_CA:-}"
VAULT_UI="${AIGW_VAULT_UI:-false}"
SYSTEM_TRUST="${AIGW_SYSTEM_TRUST:-false}"
SSH_TARGET="${AIGW_SSH_TARGET:-}"
TIMEOUT="${AIGW_TIMEOUT:-8}"
# Fixed workload address from ansible/group_vars/all.yml (envoy_egress_ip). It is
# part of the host-firewall ABI and never derived per-deployment.
ENVOY_IP="${AIGW_ENVOY_IP:-172.28.0.2}"

usage() {
  sed -n '2,40p' "$0"
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain)       DOMAIN="${2:-}"; shift 2 ;;
    --adm-ip)       ADM_IP="${2:-}"; shift 2 ;;
    --internal-ip)  INTERNAL_IP="${2:-}"; shift 2 ;;
    --root-ca)      ROOT_CA="${2:-}"; shift 2 ;;
    --vault-ui)     VAULT_UI=true; shift ;;
    --system-trust) SYSTEM_TRUST=true; shift ;;
    --ssh)          SSH_TARGET="${2:-}"; shift 2 ;;
    --timeout)      TIMEOUT="${2:-}"; shift 2 ;;
    -h|--help)      usage 0 ;;
    *) printf 'FATAL: unknown argument: %s\n' "$1" >&2; usage 2 ;;
  esac
done

fatal() { printf 'FATAL: %s\n' "$1" >&2; exit 2; }

[[ -n "$DOMAIN" ]]      || fatal "--domain (or AIGW_DOMAIN) is required"
[[ -n "$ADM_IP" ]]      || fatal "--adm-ip (or AIGW_ADM_IP) is required"
[[ -n "$INTERNAL_IP" ]] || fatal "--internal-ip (or AIGW_INTERNAL_IP) is required"
[[ -n "$ROOT_CA" ]]     || fatal "--root-ca (or AIGW_ROOT_CA) is required"
[[ -f "$ROOT_CA" ]]     || fatal "root CA file does not exist: $ROOT_CA"
[[ "$TIMEOUT" =~ ^[0-9]+$ ]] || fatal "--timeout must be an integer"
command -v curl >/dev/null    || fatal "curl is required"
command -v openssl >/dev/null || fatal "openssl is required"

# FQDN-to-plane map. Source of truth: compose/traefik/dynamic-adm.yml (ADM edge,
# published on ETH1_IP) and compose/traefik/dynamic-int.yml (internal edge,
# published on ETH2_IP). auth. is served on BOTH edges (full admin console on
# ADM; the browser OIDC subset on internal). chat. is likewise dual-homed
# (owner decision): the source-restricted ADM/VPN listener stays, and LAN
# users reach the same Open WebUI — same OIDC client, same aigw-chat gate —
# on the internal edge.
ADMIN_LABELS=(admin litellm-admin grafana prometheus)
if [[ "$VAULT_UI" == "true" ]]; then
  ADMIN_LABELS+=(vault)
fi
USER_LABELS=(api portal)

# Keycloak OIDC clients from compose/keycloak/realms/aigw-realm.json. Each
# redirect_uri is derived from the deployment domain (label + fixed callback
# path) exactly as the rendered realm registers it.
OIDC_CLIENTS=(
  "open-webui|https://chat.${DOMAIN}/oauth/oidc/callback"
  "dev-portal|https://portal.${DOMAIN}/auth/callback"
  "admin-portal|https://admin.${DOMAIN}/auth/callback"
  "admin-ui|https://litellm-admin.${DOMAIN}/oauth2/callback"
)

PASS=0
FAIL=0
SKIP=0
pass() { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
skip() { printf '  SKIP  %s\n' "$1"; SKIP=$((SKIP + 1)); }
section() { printf '\n== %s ==\n' "$1"; }

# probe_http <fqdn> <ip> <path> -> sets HTTP_CODE and SSL_VERIFY (globals). TLS
# is always verified against the customer root; ssl_verify_result==0 is the
# green-lock. A connection failure yields code 000.
probe_http() {
  local fqdn="$1" ip="$2" path="$3" resp
  resp="$(curl -sS -o /dev/null -m "$TIMEOUT" \
    -w '%{http_code}:%{ssl_verify_result}' \
    --resolve "${fqdn}:443:${ip}" --cacert "$ROOT_CA" \
    "https://${fqdn}${path}" 2>/dev/null || true)"
  HTTP_CODE="${resp%%:*}"
  SSL_VERIFY="${resp##*:}"
  [[ -n "$HTTP_CODE" ]] || HTTP_CODE="000"
  [[ -n "$SSL_VERIFY" && "$resp" == *:* ]] || SSL_VERIFY="unknown"
}

# openssl_hostname_verify <fqdn> <ip> -> 0 when the presented chain verifies to
# the customer root AND the SAN matches the requested hostname.
openssl_hostname_verify() {
  local fqdn="$1" ip="$2" out
  out="$(printf '' | openssl s_client -connect "${ip}:443" \
    -servername "$fqdn" -verify_hostname "$fqdn" \
    -CAfile "$ROOT_CA" -verify_return_error 2>/dev/null || true)"
  printf '%s' "$out" | grep -q 'Verify return code: 0 (ok)'
}

# ── A. Certificate chain + hostname verification on the serving edge ─────────
section "A. TLS chain verifies to the customer root (hostname-checked)"
verify_cert_on_edge() {
  local label="$1" ip="$2" plane="$3" fqdn="${1}.${DOMAIN}"
  if openssl_hostname_verify "$fqdn" "$ip"; then
    pass "openssl -verify_hostname ${fqdn} on ${plane} edge (${ip})"
  else
    fail "openssl -verify_hostname ${fqdn} on ${plane} edge (${ip})"
  fi
  probe_http "$fqdn" "$ip" "/"
  if [[ "$SSL_VERIFY" == "0" ]]; then
    pass "curl --cacert ssl_verify_result=0 for ${fqdn} on ${plane} edge"
  else
    fail "curl --cacert ssl_verify_result=${SSL_VERIFY} for ${fqdn} on ${plane} edge"
  fi
  if [[ "$SYSTEM_TRUST" == "true" ]]; then
    local sresp scode
    sresp="$(curl -sS -o /dev/null -m "$TIMEOUT" -w '%{ssl_verify_result}' \
      --resolve "${fqdn}:443:${ip}" "https://${fqdn}/" 2>/dev/null || true)"
    scode="${sresp:-unknown}"
    if [[ "$scode" == "0" ]]; then
      pass "curl system-trust ssl_verify_result=0 for ${fqdn} (customer root is in OS store)"
    else
      fail "curl system-trust ssl_verify_result=${scode} for ${fqdn} (add customer root to OS store)"
    fi
  fi
}
for label in "${ADMIN_LABELS[@]}"; do verify_cert_on_edge "$label" "$ADM_IP" "ADM"; done
for label in "${USER_LABELS[@]}"; do verify_cert_on_edge "$label" "$INTERNAL_IP" "internal"; done
verify_cert_on_edge "auth" "$ADM_IP" "ADM"
verify_cert_on_edge "auth" "$INTERNAL_IP" "internal"
verify_cert_on_edge "chat" "$ADM_IP" "ADM"
verify_cert_on_edge "chat" "$INTERNAL_IP" "internal"

# ── B. Admin FQDNs: answer on ADM, 404 on internal ──────────────────────────
section "B. Admin FQDNs answer on the ADM edge and 404 on the internal edge"
for label in "${ADMIN_LABELS[@]}"; do
  fqdn="${label}.${DOMAIN}"
  probe_http "$fqdn" "$ADM_IP" "/"
  if [[ "$HTTP_CODE" != "000" && "$HTTP_CODE" != "404" ]]; then
    pass "${fqdn} answers on ADM edge (HTTP ${HTTP_CODE})"
  else
    fail "${fqdn} did not answer on ADM edge (HTTP ${HTTP_CODE})"
  fi
  probe_http "$fqdn" "$INTERNAL_IP" "/"
  if [[ "$HTTP_CODE" == "404" ]]; then
    pass "${fqdn} correctly 404s on internal edge (plane isolation)"
  else
    fail "${fqdn} leaked onto internal edge (HTTP ${HTTP_CODE}, expected 404)"
  fi
done

# ── C. User FQDNs: answer on internal, 404 on ADM ───────────────────────────
section "C. User FQDNs answer on the internal edge and 404 on the ADM edge"
declare -A USER_PATH=( [api]="/health/readiness" [portal]="/healthz" )
for label in "${USER_LABELS[@]}"; do
  fqdn="${label}.${DOMAIN}"
  path="${USER_PATH[$label]:-/}"
  probe_http "$fqdn" "$INTERNAL_IP" "$path"
  if [[ "$HTTP_CODE" != "000" && "$HTTP_CODE" != "404" ]]; then
    pass "${fqdn}${path} answers on internal edge (HTTP ${HTTP_CODE})"
  else
    fail "${fqdn}${path} did not answer on internal edge (HTTP ${HTTP_CODE})"
  fi
  probe_http "$fqdn" "$ADM_IP" "$path"
  if [[ "$HTTP_CODE" == "404" ]]; then
    pass "${fqdn} correctly 404s on ADM edge (plane isolation)"
  else
    fail "${fqdn} leaked onto ADM edge (HTTP ${HTTP_CODE}, expected 404)"
  fi
done
# auth. is dual-homed: OIDC discovery on internal, admin console on ADM.
probe_http "auth.${DOMAIN}" "$INTERNAL_IP" "/realms/aigw/.well-known/openid-configuration"
if [[ "$HTTP_CODE" == "200" ]]; then
  pass "auth.${DOMAIN} serves OIDC discovery on the internal edge (HTTP 200)"
else
  fail "auth.${DOMAIN} OIDC discovery on internal edge returned HTTP ${HTTP_CODE}"
fi
probe_http "auth.${DOMAIN}" "$ADM_IP" "/admin/"
if [[ "$HTTP_CODE" != "000" && "$HTTP_CODE" != "404" ]]; then
  pass "auth.${DOMAIN} serves the admin console on the ADM edge (HTTP ${HTTP_CODE})"
else
  fail "auth.${DOMAIN} admin console on ADM edge returned HTTP ${HTTP_CODE}"
fi
# chat. is dual-homed (owner decision): Open WebUI answers on BOTH edges. The
# internal path is reachability only — unauthenticated entry must still hand
# off to the Keycloak OIDC gate (3xx redirect), and role authorization
# (aigw-chat; wrong-role 403) is enforced by the application after the code
# exchange, proven by the build-time OAuth harness and the converge's verify
# role — this read-only script never holds credentials to exercise it.
probe_http "chat.${DOMAIN}" "$ADM_IP" "/health"
if [[ "$HTTP_CODE" == "200" ]]; then
  pass "chat.${DOMAIN} answers on the ADM edge (HTTP 200 /health)"
else
  fail "chat.${DOMAIN} /health on ADM edge returned HTTP ${HTTP_CODE}"
fi
probe_http "chat.${DOMAIN}" "$INTERNAL_IP" "/health"
if [[ "$HTTP_CODE" == "200" ]]; then
  pass "chat.${DOMAIN} answers on the internal edge (HTTP 200 /health)"
else
  fail "chat.${DOMAIN} /health on internal edge returned HTTP ${HTTP_CODE}"
fi
probe_http "chat.${DOMAIN}" "$INTERNAL_IP" "/oauth/oidc/login"
if [[ "$HTTP_CODE" =~ ^30[0-9]$ ]]; then
  pass "chat.${DOMAIN} unauthenticated login on internal edge redirects into OIDC (HTTP ${HTTP_CODE})"
else
  fail "chat.${DOMAIN} internal-edge login did not redirect into OIDC (HTTP ${HTTP_CODE})"
fi

# ── D. OIDC authorization endpoint renders the login page per client ─────────
section "D. Keycloak authorization endpoint returns 200 for each client redirect_uri"
authz="https://auth.${DOMAIN}/realms/aigw/protocol/openid-connect/auth"
for entry in "${OIDC_CLIENTS[@]}"; do
  cid="${entry%%|*}"
  ruri="${entry##*|}"
  code="$(curl -sS -G -o /dev/null -m "$TIMEOUT" -w '%{http_code}' \
    --resolve "auth.${DOMAIN}:443:${INTERNAL_IP}" --cacert "$ROOT_CA" \
    --data-urlencode "client_id=${cid}" \
    --data-urlencode "redirect_uri=${ruri}" \
    --data-urlencode "response_type=code" \
    --data-urlencode "scope=openid" \
    "$authz" 2>/dev/null || true)"
  code="${code:-000}"
  if [[ "$code" == "200" ]]; then
    pass "authz login page renders for client ${cid} (HTTP 200)"
  else
    fail "authz for client ${cid} returned HTTP ${code} (bad/unregistered redirect_uri?)"
  fi
done

# ── E. No-egress / Envoy-only egress (optional, needs --ssh, read-only) ──────
section "E. Plane isolation / no-egress (Envoy 172.28.0.2 is the only vendor path)"
if [[ -z "$SSH_TARGET" ]]; then
  skip "no --ssh target; the converge's verify role already asserts this. To"
  skip "  re-prove here read-only: --ssh <user@ADM_IP> (runs iptables/nft only)"
else
  du=""; guard=""
  du="$(ssh -o BatchMode=yes "$SSH_TARGET" 'sudo iptables -S DOCKER-USER' 2>/dev/null || true)"
  guard="$(ssh -o BatchMode=yes "$SSH_TARGET" 'sudo nft list table inet aigw_guard' 2>/dev/null || true)"
  if [[ -z "$du" || -z "$guard" ]]; then
    fail "could not read DOCKER-USER / aigw_guard over SSH (need sudo, BatchMode key)"
  else
    if grep -q -- "-s ${ENVOY_IP}/32" <<<"$du" && grep -q -- '--dport 443 -j RETURN' <<<"$du"; then
      pass "DOCKER-USER allows tcp/443 egress ONLY from Envoy ${ENVOY_IP}/32"
    else
      fail "DOCKER-USER does not pin tcp/443 egress to Envoy ${ENVOY_IP}/32"
    fi
    if grep -q -- '-i br+ ! -o br+ -j DROP' <<<"$du"; then
      pass "DOCKER-USER drops all other bridge-originated egress (internal cannot reach Internet)"
    else
      fail "DOCKER-USER lacks the all-bridge original-direction egress drop"
    fi
    if grep -q "ip saddr ${ENVOY_IP}" <<<"$guard"; then
      pass "independent nft aigw_guard is present and Envoy-pinned"
    else
      fail "independent nft aigw_guard did not show the Envoy identity pin"
    fi
  fi
fi

# ── F. Samba LDAPS testLDAPConnection (token-gated manual step) ──────────────
section "F. Samba/directory LDAPS testLDAPConnection (manual — needs admin token)"
skip "Keycloak's POST /admin/realms/aigw/testLDAPConnection needs a realm-admin"
skip "  bearer token this read-only script must not custody. Run it by hand per"
skip "  docs/acceptance-e2e-fresh-vm.md Phase 5F; expect HTTP 204 for both"
skip "  testConnection and testAuthentication over ldaps://samba-ad.${DOMAIN}:636."

# ── Summary ─────────────────────────────────────────────────────────────────
printf '\n== SUMMARY ==\n  passed=%d failed=%d skipped=%d\n' "$PASS" "$FAIL" "$SKIP"
if [[ "$FAIL" -gt 0 ]]; then
  printf 'RESULT: FAIL (%d check(s) failed)\n' "$FAIL" >&2
  exit 1
fi
printf 'RESULT: PASS\n'
