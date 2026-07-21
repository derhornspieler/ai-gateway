#!/usr/bin/env bash
# generate-pins.sh — capture candidate pinning material for review.
#
# The immutable Envoy image uses reviewed CA bundles from the provider catalog.
# This helper fetches and emits one point-in-time issuing-CA chain as PEM. Its
# output is a candidate, not an approved release input. Review its provenance,
# fingerprints, validity, CA constraints, and official CA source separately.
#
# It also prints the leaf SPKI hash as review evidence. The current provider
# catalog and generated policy do not enable leaf SPKI pinning. Adding that
# control would require a reviewed schema, generator, test, and release change.
# Do not paste a leaf hash into a live config. Leaf keys rotate often, and
# Envoy matches `verify_certificate_spki` against the leaf only.
#
# This script does not update the catalog, provenance record, release manifest,
# image, or deployment. Follow docs/sop/provider-ca-maintenance.md. A rotation
# needs review, a new immutable release, offline-seed preprod testing, and
# release approval.
#
# Run on a NETWORKED host you trust. A second network vantage point is useful,
# but it does not prove provenance by itself. Certs that fail TLS chain
# verification are REFUSED (never emitted) — see -verify_return_error below.
#
# Usage: ./generate-pins.sh [host ...]
#        (defaults to api.anthropic.com)
#   env: CONNECT_TIMEOUT (seconds, default 15)
#        CERTS_DIR (default: <script dir>/certs)

set -uo pipefail   # NOTE: deliberately NOT `-e`; we handle failures per-host
                   # so a single failed s_client prints a friendly error and
                   # moves on instead of killing the script silently.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${CERTS_DIR:-${SCRIPT_DIR}/certs}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-15}"

HOSTS=("$@")
if [ "${#HOSTS[@]}" -eq 0 ]; then
    HOSTS=(api.anthropic.com)
fi

for tool in openssl base64 awk; do
    command -v "${tool}" >/dev/null 2>&1 || { echo "ERROR: '${tool}' not found" >&2; exit 1; }
done

# Wrap openssl in a timeout if one is available (coreutils `timeout`/`gtimeout`).
TIMEOUT_CMD=()
if command -v timeout >/dev/null 2>&1; then
    TIMEOUT_CMD=(timeout "${CONNECT_TIMEOUT}")
elif command -v gtimeout >/dev/null 2>&1; then
    TIMEOUT_CMD=(gtimeout "${CONNECT_TIMEOUT}")
else
    echo "WARNING: no 'timeout' command found; s_client runs without a connect timeout." >&2
fi

vendor_of() {  # api.anthropic.com -> anthropic ; foo.example.org -> example
    printf '%s' "$1" | sed -E 's/^api\.//; s/\.[^.]+$//; s/.*\.//'
}

spki_pin() {   # stdin: one PEM cert -> stdout: base64 SPKI SHA-256 pin
    openssl x509 -pubkey -noout \
        | openssl pkey -pubin -outform der \
        | openssl dgst -sha256 -binary \
        | base64
}

FAIL=0

for host in "${HOSTS[@]}"; do
    vendor="$(vendor_of "${host}")"
    echo "== ${host}  (vendor: ${vendor}) =="

    # Fetch the presented chain WITH verification enforced. -verify_return_error
    # makes s_client exit non-zero if the chain does not validate against the
    # host's trust store, so we never emit pins for a TOFU/MITM cert.
    if out="$(${TIMEOUT_CMD[@]+"${TIMEOUT_CMD[@]}"} openssl s_client -connect "${host}:443" \
                 -servername "${host}" -showcerts -verify_return_error \
                 </dev/null 2>&1)"; then
        connect_rc=0
    else
        connect_rc=$?
    fi

    if [ "${connect_rc}" -ne 0 ]; then
        echo "  ERROR: TLS connect/verify failed for ${host} (openssl exit ${connect_rc})." >&2
        echo "  Not emitting pins or CA bundle. Relevant output:" >&2
        printf '%s\n' "${out}" | grep -Ei 'verify return code|error|refused|timed out|handshake failure|unable to' >&2 \
            || printf '%s\n' "${out}" | tail -n 3 >&2
        FAIL=1
        echo
        continue
    fi

    # Belt and suspenders: require an explicit "Verify return code: 0 (ok)".
    if ! printf '%s' "${out}" | grep -q 'Verify return code: 0 (ok)'; then
        echo "  ERROR: chain did not verify (Verify return code != 0). Refusing" >&2
        echo "  to emit — possible MITM or missing trust anchor." >&2
        printf '%s\n' "${out}" | grep -i 'verify return code' >&2 || true
        FAIL=1
        echo
        continue
    fi

    chain="$(printf '%s\n' "${out}" | awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/')"
    if [ -z "${chain}" ]; then
        echo "  ERROR: no certificates parsed from ${host} output." >&2
        FAIL=1
        echo
        continue
    fi

    # Split the chain; report each cert, and collect the CA certs (index >= 1,
    # i.e. everything except the leaf) into the narrowed trusted_ca bundle.
    ca_bundle=""
    idx=0
    cert=""
    while IFS= read -r line; do
        cert+="${line}"$'\n'
        if [ "${line}" = "-----END CERTIFICATE-----" ]; then
            subject="$(printf '%s' "${cert}" | openssl x509 -noout -subject 2>/dev/null)"
            pin="$(printf '%s' "${cert}" | spki_pin 2>/dev/null)"
            case "${idx}" in
                0) role="leaf   (SPKI hash is review evidence only)" ;;
                1) role="intermediate CA  -> goes in trusted_ca bundle" ;;
                *) role="CA[${idx}]         -> goes in trusted_ca bundle" ;;
            esac
            echo "  [${idx}] ${role}"
            echo "        ${subject}"
            echo "        leaf/SPKI pin: \"${pin}\""
            if [ "${idx}" -ge 1 ]; then
                ca_bundle+="${cert}"
            fi
            cert=""
            idx=$((idx + 1))
        fi
    done <<< "${chain}"

    if [ -z "${ca_bundle}" ]; then
        echo "  WARNING: only a leaf was presented (no intermediate/root sent by" >&2
        echo "  ${host}). You must obtain the issuing CA(s) out of band to build" >&2
        echo "  the trusted_ca bundle." >&2
        FAIL=1
        echo
        continue
    fi

    # Emit the issuing-CA chain PEM and write the per-vendor bundle.
    out_file="${CERTS_DIR}/${vendor}-ca.pem"
    echo "  --- issuing-CA bundle (PEM) for ${vendor} -> ${out_file} ---"
    printf '%s' "${ca_bundle}"
    if mkdir -p "${CERTS_DIR}" 2>/dev/null && printf '%s' "${ca_bundle}" > "${out_file}" 2>/dev/null; then
        echo "  WROTE ${out_file} ($(grep -c 'BEGIN CERTIFICATE' "${out_file}") cert(s))."
    else
        echo "  NOTE: could not write ${out_file}; copy the PEM above into it manually." >&2
        FAIL=1
        echo
        continue
    fi

    # Self-test the written bundle exactly as Envoy's trusted_ca will use it:
    # default verification (NO -partial_chain), so the bundle must contain a
    # self-signed trust anchor. A server frequently presents a CROSS-signed root
    # (e.g. GTS Root R4 signed by GlobalSign) rather than its self-signed form;
    # embedding that yields "unable to get issuer certificate" and Envoy would
    # fail closed at startup. Catch it here instead of at deploy time.
    verify_rc="$(${TIMEOUT_CMD[@]+"${TIMEOUT_CMD[@]}"} openssl s_client -connect "${host}:443" \
                     -servername "${host}" -CAfile "${out_file}" </dev/null 2>&1 \
                     | grep -i 'verify return code' | head -1)"
    if printf '%s' "${verify_rc}" | grep -q 'code: 0'; then
        echo "  SELF-TEST ok: leaf chains to the bundle under default verification."
    else
        echo "  ERROR: bundle self-test FAILED (${verify_rc:-no result})." >&2
        echo "  The presented top CA is likely CROSS-signed, not a self-signed anchor." >&2
        echo "  Fix: replace the top cert in ${out_file} with the vendor CA's" >&2
        echo "  SELF-SIGNED root (subject == issuer). For Google Trust Services:" >&2
        echo "    curl -s https://pki.goog/repo/certs/gtsr4.pem   (GTS Root R4, self-signed)" >&2
        echo "  Keep the intermediate(s), swap only the root. Removing broken bundle." >&2
        rm -f "${out_file}"
        FAIL=1
        echo
        continue
    fi
    echo
done

cat <<'EOF'
Next steps:
  1. Treat every written PEM as a candidate, not an approved CA bundle.
  2. Follow docs/sop/provider-ca-maintenance.md. Verify each certificate
     against an official CA source, record provenance and limitations, and
     obtain an independent review.
  3. Update the reviewed bundle, provenance record, and provider catalog in
     one code review. Do not mount this file into a running container.
  4. Build a new immutable offline release, load its exact preprod seed, and
     pass validation before deployment.
EOF

if [ "${FAIL}" -ne 0 ]; then
    echo "One or more hosts failed; see errors above." >&2
    exit 1
fi
