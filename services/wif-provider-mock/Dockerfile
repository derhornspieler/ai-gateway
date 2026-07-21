# syntax=docker/dockerfile:1.25.0@sha256:0adf442eae370b6087e08edc7c50b552d80ddf261576f4ebd6421006b2461f12

FROM dhi.io/golang:1.26.5-alpine-dev@sha256:711ea0b8f09f549c50f2f550dc26859d3e6441ca11d5640caecf69c29a862f0c AS builder
WORKDIR /src
COPY go.mod main.go main_test.go ./
RUN --network=none go test ./... \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/wif-provider-mock ./

FROM scratch
COPY --from=builder --chown=0:0 --chmod=0555 /out/wif-provider-mock /wif-provider-mock
USER 65532:65532
ENTRYPOINT ["/wif-provider-mock"]
CMD ["serve"]
