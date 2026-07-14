# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# Build a single-purpose health probe. The DHI dev stage is discarded; the
# runtime contains only DHI CoreDNS plus this static binary. The build has no
# module dependencies and Compose disables its build network.
FROM dhi.io/golang:1.25.12-alpine-dev@sha256:4411028e8461d5a111cdbf0aa172db17342557590f7727a4dd4649440bb411c2 AS health-builder
WORKDIR /src
COPY healthcheck.go .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/dns-healthcheck ./healthcheck.go

# DHI CoreDNS is shellless and runs as uid/gid 65532 (nonroot).
FROM dhi.io/coredns:1.14.4@sha256:d9983439aa6ff935a715f9f2cd11a043e42b40be4d526b187041acfb5c0a4e7c
COPY --from=health-builder --chmod=0555 /out/dns-healthcheck /dns-healthcheck
USER 65532:65532
