# syntax=docker/dockerfile:1.25.0@sha256:0adf442eae370b6087e08edc7c50b552d80ddf261576f4ebd6421006b2461f12

# BuildKit uses this value for reproducible image metadata.
ARG SOURCE_DATE_EPOCH

# The Go module has no external dependencies. Tests, policy generation, and
# compilation all run with networking disabled.
FROM dhi.io/golang:1.26.5-alpine-dev@sha256:711ea0b8f09f549c50f2f550dc26859d3e6441ca11d5640caecf69c29a862f0c AS gate-builder
WORKDIR /src
COPY go.mod entrypoint.go entrypoint_test.go envoy.yaml envoy.yaml.tmpl ./
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY providers/ ./providers/
COPY certs/ ./certs/
RUN --network=none go test ./...
RUN --network=none CGO_ENABLED=0 go build -trimpath -buildvcs=false \
    -ldflags="-s -w -buildid=" -o /out/aigw-egress-policy ./cmd/policygen

# Release scripts may build this target once and run it with --network=none.
# It is the one canonical parser for provider arguments and catalog data.
FROM gate-builder AS policy-planner
ENTRYPOINT ["/out/aigw-egress-policy"]
CMD ["plan"]

FROM gate-builder AS image-builder
ARG SOURCE_DATE_EPOCH
ARG AIGW_EGRESS_PROVIDERS
ARG AIGW_EGRESS_POLICY_SHA256
RUN --network=none test -n "$SOURCE_DATE_EPOCH" \
    && test -n "$AIGW_EGRESS_PROVIDERS" \
    && test -n "$AIGW_EGRESS_POLICY_SHA256" \
    && /out/aigw-egress-policy generate \
      --providers-csv "$AIGW_EGRESS_PROVIDERS" \
      --expect-policy-sha256 "$AIGW_EGRESS_POLICY_SHA256" \
      --output /out/image
RUN --network=none CGO_ENABLED=0 go build -trimpath -buildvcs=false \
    -ldflags="-s -w -buildid= -X=main.expectedPolicySHA256=$AIGW_EGRESS_POLICY_SHA256" \
    -o /out/image/usr/local/bin/aigw-envoy-entrypoint ./ \
    && /out/aigw-egress-policy normalize \
      --output /out/image --source-date-epoch "$SOURCE_DATE_EPOCH"

# DHI Envoy is shellless and runs as uid/gid 65532. Only generated config,
# selected CA files, immutable policy metadata, and the gate enter this stage.
FROM dhi.io/envoy:1.39.0@sha256:25060ec6f5bd9ac708a7426f076829178e426ca9dfef688bdca27c50fa8ad15e
ARG SOURCE_DATE_EPOCH
ARG AIGW_EGRESS_PROVIDERS
ARG AIGW_EGRESS_POLICY_SHA256
LABEL com.aigw.egress-policy.schema="1" \
      com.aigw.egress-policy.providers="$AIGW_EGRESS_PROVIDERS" \
      com.aigw.egress-policy.sha256="$AIGW_EGRESS_POLICY_SHA256" \
      com.aigw.source-date-epoch="$SOURCE_DATE_EPOCH"
COPY --from=image-builder --chown=0:0 /out/image/etc/envoy/ /etc/envoy/
COPY --from=image-builder --chown=0:0 --chmod=0555 \
    /out/image/usr/local/bin/aigw-envoy-entrypoint /usr/local/bin/aigw-envoy-entrypoint

USER 65532:65532

RUN --network=none ["/usr/local/bin/aigw-envoy-entrypoint", "validate"]
RUN --network=none ["/usr/local/bin/envoy", "--mode", "validate", "-c", "/etc/envoy/envoy.yaml"]

ENTRYPOINT ["/usr/local/bin/aigw-envoy-entrypoint"]
CMD ["--log-level", "info"]
