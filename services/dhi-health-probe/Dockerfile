# syntax=docker/dockerfile:1.7

ARG BASE_IMAGE

# The dev image is build-only. The final stage is the exact service DHI passed
# by BASE_IMAGE and retains that image's entrypoint, command, and non-root user.
FROM dhi.io/golang:1.25.12-alpine-dev@sha256:4411028e8461d5a111cdbf0aa172db17342557590f7727a4dd4649440bb411c2 AS probe-builder
WORKDIR /src
COPY go.mod main.go main_test.go ./
RUN --network=none go test ./... \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/aigw-health-probe ./

FROM ${BASE_IMAGE}
COPY --from=probe-builder --chmod=0555 /out/aigw-health-probe /usr/local/bin/aigw-health-probe
