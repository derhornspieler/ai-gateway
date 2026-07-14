# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# The source image is HashiCorp's official multi-architecture Vault 2.0.3
# release, pinned to its manifest-list digest. Its /bin/vault is the exact
# release binary (the arm64 variant was byte-compared with the archive covered
# by HashiCorp's signed SHA256SUMS). It is parsed as data, never executed, and
# never crosses into the runtime stage. Keeping this source as an OCI image
# lets the existing verified offline-image seed carry every build input.
FROM hashicorp/vault:2.0.3@sha256:a296a888b118615dc01d5f1a6846e6d4a7277946caaed5b447008fff5fe06b54 AS upstream-vault-ui

# Both build tools are stdlib-only and compile in the already-reviewed DHI Go
# toolchain. GOTOOLCHAIN=local prevents an implicit toolchain download.
FROM dhi.io/golang:1.25.12-alpine-dev@sha256:4411028e8461d5a111cdbf0aa172db17342557590f7727a4dd4649440bb411c2 AS builder
ARG TARGETARCH
ENV GOTOOLCHAIN=local
WORKDIR /src
COPY go.mod ./
COPY main.go main_test.go ./
COPY upstream-provenance.json ./
COPY cmd ./cmd
RUN --network=none go test ./... \
    && mkdir -p /out \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -buildid=" \
         -o /out/vault-ui-proxy . \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -buildid=" \
         -o /out/extract-vault-ui ./cmd/extract-ui

# The copied source is architecture-native but the embedded UI output must be
# identical. Lock both supported release binaries as well as every extracted
# entry, compiler content hash, byte count, and the complete asset manifest.
COPY --from=upstream-vault-ui /bin/vault /release/vault
COPY --from=upstream-vault-ui /usr/share/doc/vault/LICENSE.txt /release/LICENSE.txt

RUN --network=none set -eu; \
    echo '513f764041bd2882551f0fc5b5e3274b13f60f9e35b3e23719e90edf75e8464c  upstream-provenance.json' | sha256sum -c -; \
    test "$(wc -c < /release/LICENSE.txt | tr -d ' ')" = 4919; \
    case "$TARGETARCH" in \
      arm64) expected_binary='8495a9215c20030c0f054699d52f6c1cf09dd3a663068bce57939adc193f564b' ;; \
      amd64) expected_binary='7e8731db316124619ff2e64aee6957df6d54b824dfdc3494466193cb7bde0ac4' ;; \
      *) echo "unsupported target architecture" >&2; exit 1 ;; \
    esac; \
    echo "$expected_binary  /release/vault" | sha256sum -c -; \
    result="$(/out/extract-vault-ui /release/vault /vault-ui)"; \
    expected="$(printf '%s\n' \
      'symbol=github.com/hashicorp/vault/http.content.files' \
      'entries=132' \
      'directories=27' \
      'files=105' \
      'bytes=20549720' \
      'hashes_verified=105')"; \
    test "$result" = "$expected"; \
    echo '7902aff69dccdea5096e05b7b6bdcfa218113ae6314f7574f955e417e9c34198  /vault-ui.MANIFEST.sha256' | sha256sum -c -; \
    /out/vault-ui-proxy sanitize-index /vault-ui/index.html; \
    /out/vault-ui-proxy write-manifest /vault-ui /out/vault-ui.sha256.json; \
    /out/vault-ui-proxy verify-assets /vault-ui /out/vault-ui.sha256.json

# DHI-only runtime. Reuse the already-required, deployment-verified Vault base
# instead of introducing a new DHI entitlement. Its UI-less Vault binary stays
# intact but the direct proxy entrypoint and startup process assertion prove it
# is dormant. The upstream extraction binary, extractor, source-image layers,
# build shell, and package tools do not cross this stage.
FROM dhi.io/vault:2.0.3@sha256:743791e1bf99025aae045b3155fecf0542e7fd1bde7bbfbaf76eb4b9ff2555a6

COPY --from=builder --chown=0:0 --chmod=0555 /out/vault-ui-proxy /usr/local/bin/vault-ui-proxy
COPY --from=builder --chown=0:0 /vault-ui /opt/vault-ui
COPY --from=builder --chown=0:0 --chmod=0444 /out/vault-ui.sha256.json /opt/vault-ui.sha256.json
COPY --from=builder --chown=0:0 --chmod=0444 /release/LICENSE.txt /licenses/vault/LICENSE.txt
COPY --from=builder --chown=0:0 --chmod=0444 /src/upstream-provenance.json /licenses/vault/UPSTREAM-PROVENANCE.json

USER 1000:1000
RUN ["/usr/local/bin/vault-ui-proxy", "verify-assets", "/opt/vault-ui", "/opt/vault-ui.sha256.json"]

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/vault-ui-proxy"]
CMD []
