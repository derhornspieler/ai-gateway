# Keep Traefik's shellless, non-root DHI runtime while Docker's Traefik DHI
# trails the upstream security release.  The copied artifact is the exact
# patched upstream v3.7.7 binary; both source images are immutable OCI pins.
ARG BASE_IMAGE=dhi.io/traefik:3.7.6@sha256:790392e8d8dc7c572afacd6d598cabab103034c79ad04a4c3c84116dbc12f2f4
ARG PATCH_IMAGE=traefik:v3.7.8@sha256:4299bbed850421258fc5448c2e0e6ad350981d4d335a68de11b92448aedbefe5

FROM ${PATCH_IMAGE} AS patched

FROM ${BASE_IMAGE}
COPY --from=patched --chown=0:0 --chmod=0755 /usr/local/bin/traefik /usr/bin/traefik
LABEL org.opencontainers.image.title="AI Gateway hardened Traefik" \
      org.opencontainers.image.version="3.7.8" \
      org.opencontainers.image.description="Traefik 3.7.7 security binary on the non-root Docker Hardened Image runtime"
