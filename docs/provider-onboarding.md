# Provider onboarding

This guide explains how to add an AI provider to the reviewed Envoy catalog.
Adding a provider is a code and release change. It is never a deployment-time
setting.

For routine release selection, skip to [Select providers](#select-providers).
For CA changes, use the [provider CA maintenance SOP](sop/provider-ca-maintenance.md).
The [security model](security-model.md#provider-egress-is-selected-at-release-time)
explains why this is a release boundary.

Four diagrams show the full path:

- [Provider selection and immutable build](architecture-diagrams.md#11-provider-selection-and-immutable-envoy-build).
- [Runtime request routing](architecture-diagrams.md#12-runtime-request-path-for-selected-providers).
- [CA capture, review, and rotation](architecture-diagrams.md#13-ca-capture-review-rotation-and-approval).
- [Offline validation and rollback](architecture-diagrams.md#14-offline-seed-validation-deployment-and-rollback).

## Safety rule

The release command accepts provider names only. It does not accept a hostname
or CA path:

```bash
python3 -I scripts/update-images.py prepare \
  --provider anthropic \
  --platform linux/amd64 \
  --archive /release/aigw.docker.tar.zst \
  --manifest /release/aigw.manifest.json
```

Each name must already exist in the committed catalog. This blocks an operator
from sending traffic to an unreviewed hostname or adding an unreviewed CA file
while building a release.

## Select providers

Repeat `--provider` for every approved provider that this release needs. At
least one is required. Anthropic is the only approved provider today.

The planner removes exact duplicates and sorts the names. With today's
catalog, these two selections create the same provider policy:

```text
--provider anthropic
--provider anthropic --provider anthropic
```

An unknown name, blank selection, leading or trailing space, hostname, or file
path fails before the Envoy image is built.

The final image contains only the selected provider routes and CA bundles. If
the selection changes, the generated policy digest and final image ID change.
The schema-v2 manifest records both values.

Provider selection grants only a reviewed network and TLS path. It does not
create provider credentials or teach LiteLLM how to call a new API. A new
provider may also need a reviewed LiteLLM configuration and a key-rotator
driver. Keep that authentication work separate from the egress trust record,
then test both together in the exact offline release.

## Catalog files

The reviewed source files are under `services/egress-proxy`:

- `providers/catalog.json` lists approved providers.
- `certs/<name>-ca.pem` holds the reviewed CA chain.
- `providers/provenance/<name>.json` records how that chain was checked.
- `envoy.yaml.tmpl` turns selected catalog records into Envoy routes and TLS
  clusters.

The catalog is sorted by provider name. Each provider record must contain:

| Field | Meaning |
|---|---|
| `name` | Lowercase provider name used by `--provider`. |
| `api_hostname` | Exact lowercase DNS name that Envoy connects to. |
| `route_prefix` | Unique internal path, such as `/example/`. It must start and end with `/`. |
| `sni` | Exact DNS name sent in the TLS handshake. |
| `exact_sans` | Sorted, unique DNS SAN names accepted from the endpoint certificate. This list must include `sni`. |
| `ca_bundle` | Safe path to the reviewed PEM file inside the component source. |
| `ca_bundle_sha256` | SHA-256 of the complete PEM file bytes. |
| `ca_sha256_fingerprints` | SHA-256 of each CA certificate's DER bytes, in PEM order. |
| `provenance_file` | Safe path to the provider's reviewed provenance JSON. |
| `provenance_sha256` | SHA-256 of the complete provenance file bytes. |

Provider names, API hostnames, route prefixes, and provenance files must be
unique. Route prefixes may not overlap. The catalog rejects unknown JSON fields
and duplicate JSON keys.

## Add a provider

Use this process for every new provider.

1. Confirm the provider's official API hostname and TLS requirements from an
   approved source.
2. Capture candidate CA material on a trusted maintenance system. Follow the
   [CA maintenance SOP](sop/provider-ca-maintenance.md).
3. Have another reviewer check the source, certificate chain, SNI, exact SANs,
   validity dates, CA constraints, and fingerprints.
4. Add the reviewed PEM file under `services/egress-proxy/certs/`.
5. Add a provenance JSON file under
   `services/egress-proxy/providers/provenance/`.
6. Add the provider to `providers/catalog.json` and keep the array sorted.
7. Add or update tests for the catalog record, selected-only image contents,
   generated route, exact SAN, SNI, CA failure cases, and manifest receipt.
8. Update the caller configuration if LiteLLM or key-rotator needs the new
   internal route prefix. Add a reviewed credential driver when the provider's
   authentication method is not already supported.
9. Build a new offline release with the new provider selected.
10. Load that exact seed into local preprod and run the full end-to-end test.
11. Review the diff and test evidence. Approve a release only after all gates
    pass.

Use a catalog record shaped like this. Replace every example value with
reviewed evidence:

```json
{
  "name": "example",
  "api_hostname": "api.example.com",
  "route_prefix": "/example/",
  "sni": "api.example.com",
  "exact_sans": [
    "api.example.com"
  ],
  "ca_bundle": "certs/example-ca.pem",
  "ca_bundle_sha256": "<64-lowercase-hex-characters>",
  "ca_sha256_fingerprints": [
    "<one-64-character-fingerprint-per-certificate>"
  ],
  "provenance_file": "providers/provenance/example.json",
  "provenance_sha256": "<64-lowercase-hex-characters>"
}
```

Do not copy example hashes into a real record.

## Provenance record

The provenance file is part of the reviewed input. It must record:

- Schema version `1`.
- Provider name and API hostname.
- Status `current-chain-verified`.
- The review date and what was checked.
- The bundle SHA-256 and ordered certificate fingerprints.
- At least one clear verification statement.
- At least one clear limitation statement.

The bundle hash and fingerprint list must exactly match the catalog. The
catalog also pins the hash of the provenance file itself.

## Verify the change

Run the component tests first:

```bash
cd services/egress-proxy
go test -race ./...
go vet ./...
cd ../..
```

Then run the release and documentation contracts:

```bash
python3 -I -m unittest discover -v -s scripts/tests \
  -p 'test_rebuild_offline_image_seed.py'
python3 -I -m unittest discover -v -s scripts/tests \
  -p 'test_load_offline_image_seed.py'
python3 -I .github/scripts/validate-docs.py
```

When DHI credentials are available, the Go security workflow builds the
reviewed `anthropic` Envoy image twice from clean, network-disabled
builds. It compares the complete Docker archive bytes, loads the first archive,
and compares the running image receipt with the planner receipt. Treat this as
deterministic-build evidence only when the workflow summary says `COMPLETE`.
`SKIPPED` is not a pass, and the fixed CI selection does not replace testing
the operator's selected provider list in its offline release.

Finally, build and test a real release. Use the command in the
[image update workflow](image-update-workflow.md#1-build-the-offline-release).
The test must use the generated preprod seed. A direct local image build is not
release evidence.

## What the release proves

The schema-v2 manifest records the selected provider names, hostnames, route
and TLS rules, bundle hashes, certificate fingerprints, provenance hashes,
generated Envoy config digest, egress-policy digest, and final Envoy image ID.

The loader recalculates the policy digest and checks the Envoy image labels.
It refuses a manifest whose provider policy and Envoy image do not match. An
upgrade and rollback therefore move the Envoy image and its provider policy as
one release unit.

## Know what certificate evidence means

These facts are different:

- **Certificate integrity:** a fingerprint proves the reviewed certificate
  bytes did not change.
- **Trust provenance:** review evidence explains where the certificate came
  from and how it was checked. A hash alone does not prove this.
- **CA organization country:** a certificate subject may contain a country,
  such as `C=US`. That describes the certificate organization record.
- **Endpoint geography:** the server IP used for one connection may be in a
  country or region. CDN routing can change it later.
- **Data residency:** provider policy and contracts decide where data is
  stored or processed. A certificate or endpoint IP does not prove residency.

Do not use a matching hash, `C=US`, or one network trace as proof of United
States data residency.
