# egress-proxy

`egress-proxy` is the only workload allowed to reach approved AI provider
APIs. LiteLLM and key-rotator send plain HTTP to Envoy on `net-vendor`.
Envoy then starts TLS to each selected provider.

The provider policy is immutable. It is generated while the offline release
is built. It is not downloaded, mounted, or changed during deployment.

## Select providers for a release

Run the release command from the repository root. Repeat `--provider` for each
provider that the release may reach:

```bash
python3 -I scripts/update-images.py prepare \
  --provider anthropic \
  --platform linux/amd64 \
  --archive /release/aigw.docker.tar.zst \
  --manifest /release/aigw.manifest.json
```

Provider names come from [`providers/catalog.json`](providers/catalog.json).
The command does not accept a hostname or CA file. Unknown names and an empty
selection fail. Anthropic is the only provider approved today. Repeated names
are removed, and the final list is sorted. Future providers require a reviewed
catalog change before the command accepts them.

The build runs with networking disabled. It checks the catalog, CA files,
certificate fingerprints, provenance records, route prefixes, SNI names, and
exact SAN names. The final image contains only the selected routes, clusters,
CA bundles, and policy files. A different provider selection produces a
different policy digest and image ID.

See [Provider onboarding](../../docs/provider-onboarding.md) for the full
catalog contract and [Provider CA maintenance](../../docs/sop/provider-ca-maintenance.md)
for CA review and rotation.

## Runtime request path

This component is an originating TLS reverse proxy. It is not an HTTPS
`CONNECT` proxy.

For a selected provider, the generated policy does all of the following:

- maps its reviewed route prefix, such as `/anthropic/`, to one cluster;
- removes that prefix before sending the request;
- writes the reviewed API hostname into the HTTP `Host` header;
- uses the reviewed SNI name for TLS;
- requires an exact reviewed DNS SAN; and
- validates the chain with that provider's reviewed CA bundle.

There is no default provider route. An unselected or unknown route returns
404. The host firewall also blocks every workload except Envoy from direct
external DNS and TCP/443 access.

## What enters the image

The policy generator creates these files for the selected providers:

```text
/etc/envoy/envoy.yaml
/etc/envoy/provider-policy.json
/etc/envoy/provider-policy.sha256
/etc/envoy/provider-policy-receipt.json
/etc/envoy/certs/<selected-provider>-ca.pem
```

The final DHI Envoy stage receives no unselected CA file. The image labels
record the policy schema, canonical provider list, and policy SHA-256 digest.
The schema-v2 offline manifest binds that digest and provider evidence to the
same immutable Envoy image ID.

Do not add a CA volume to `envoy-egress`. Do not set `ENVOY_CONFIG`, pass
`-c` or another `--config-*` option, or override the image entrypoint. These
changes would weaken the reviewed image boundary, so the startup gate rejects
the config overrides.

## Fail-closed startup gate

The static `aigw-envoy-entrypoint` validates the image before it starts Envoy.
It exits nonzero when it finds any of these problems:

- the policy digest does not match the digest compiled into the gate;
- the policy JSON, Envoy config, or policy receipt is missing or changed;
- a selected CA file is missing, empty, malformed, or not a regular file;
- an unexpected CA file is present;
- a CA bundle or certificate fingerprint differs from the catalog;
- a CA certificate is expired, not active yet, or cannot act as a CA;
- SNI is absent from the provider's exact SAN list; or
- a caller tries to select another Envoy config.

The gate does not fall back to the operating system trust store. The final
container is shellless and runs as UID/GID 65532.

The Envoy admin listener stays on `127.0.0.1:9901`. The health command checks
that loopback listener without using proxy environment variables or redirects.
Prometheus can reach only the exact read-only `/stats/prometheus` route on
port 9902. Other admin paths are not routed.

## CA capture is not CA approval

[`generate-pins.sh`](generate-pins.sh) can capture a point-in-time TLS chain
on a trusted, networked maintenance system. Its output is only a candidate.
It must go through the separate CA review process before anyone changes the
catalog or builds a release.

A matching SHA-256 fingerprint proves that certificate bytes match. It does
not prove who captured them or which network path was used. A certificate
subject that includes `C=US` does not prove that the endpoint is in the United
States or that provider data stays there. See the
[CA maintenance SOP](../../docs/sop/provider-ca-maintenance.md) for these trust
limits and the approval steps.

## Test this component

Run the unit and policy tests from this directory:

```bash
go test -race ./...
go vet ./...
```

With DHI credentials, the Go security workflow also builds the fixed
`anthropic` image twice, compares the complete Docker archive bytes,
loads one archive, and checks its live receipt. If that CI step is skipped, it
is not deterministic-build evidence.

The release test is stronger than a local unit test. It builds the exact image,
loads it through the offline seed, starts local preprod with `pull_policy:
never`, and runs the end-to-end checks. Follow the
[image update workflow](../../docs/image-update-workflow.md).

## Important files

- `providers/catalog.json` — reviewed provider names and trust requirements.
- `providers/provenance/*.json` — reviewed CA evidence and its limits.
- `certs/*.pem` — reviewed source CA bundles. Only selected bundles enter an
  image.
- `envoy.yaml.tmpl` — generated route and cluster template.
- `internal/egresspolicy/` — catalog validation and deterministic generation.
- `entrypoint.go` — runtime validation, launch, and health gate.
- `Dockerfile` — network-disabled planner, generator, tests, and final image.
- `generate-pins.sh` — candidate capture helper; it does not approve trust.
