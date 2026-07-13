# syntax=docker/dockerfile:1.7

# Build a static fail-closed launcher and health probe. There are no module
# dependencies, and the build step has no network access.
FROM dhi.io/golang:1.25.12-alpine-dev@sha256:4411028e8461d5a111cdbf0aa172db17342557590f7727a4dd4649440bb411c2 AS gate-builder
WORKDIR /src
COPY go.mod entrypoint.go entrypoint_test.go ./
RUN --network=none go test ./... \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/aigw-envoy-entrypoint ./

# DHI Envoy is shellless and runs as uid/gid 65532. The compiled launcher
# replaces the former Bash gate without adding a shell or package manager.
FROM dhi.io/envoy:1.38.3@sha256:b63b5a9d9b7deefdc6cc85f32b03dee31c2add6d21862f7750f3983646b4e990
COPY --chown=0:0 envoy.yaml /etc/envoy/envoy.yaml
COPY --chown=0:0 certs/ /etc/envoy/certs/
COPY --from=gate-builder --chown=0:0 --chmod=0555 /out/aigw-envoy-entrypoint /usr/local/bin/aigw-envoy-entrypoint

USER 65532:65532

# Validate both the narrowed-CA policy and Envoy's configuration schema in the
# final runtime image. Exec-form RUN is required because the image is shellless.
RUN ["/usr/local/bin/aigw-envoy-entrypoint", "validate"]
RUN ["/usr/local/bin/envoy", "--mode", "validate", "-c", "/etc/envoy/envoy.yaml"]

ENTRYPOINT ["/usr/local/bin/aigw-envoy-entrypoint"]
CMD ["--log-level", "info"]
