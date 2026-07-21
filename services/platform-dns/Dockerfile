# syntax=docker/dockerfile:1.25.0@sha256:0adf442eae370b6087e08edc7c50b552d80ddf261576f4ebd6421006b2461f12

# Build a single-purpose health probe. The DHI dev stage is discarded; the
# runtime contains only DHI CoreDNS plus this static binary. The build has no
# module dependencies and Compose disables its build network.
FROM dhi.io/golang:1.26.5-alpine-dev@sha256:711ea0b8f09f549c50f2f550dc26859d3e6441ca11d5640caecf69c29a862f0c AS health-builder
WORKDIR /src
COPY healthcheck.go .
RUN --network=none CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/dns-healthcheck ./healthcheck.go

# DHI CoreDNS is shellless and runs as uid/gid 65532 (nonroot).
FROM dhi.io/coredns:1.14.6@sha256:2a3969483a757474e70ae7fc4f4a5d0af61e112a4e23e9c5ad3ddfad5979f716
COPY --from=health-builder --chmod=0555 /out/dns-healthcheck /dns-healthcheck
USER 65532:65532
