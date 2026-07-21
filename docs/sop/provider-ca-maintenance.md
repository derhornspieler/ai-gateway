# SOP: Review and rotate provider CA bundles

Use this SOP when an approved AI provider changes its issuing CA, a reviewed
CA nears expiration, or a new provider is added.

This is a trusted release-maintenance task. It is separate from deployment.
Ansible never discovers or downloads CA files.

## Goal

Produce reviewed CA bytes and provenance records, then bake them into a new
immutable Envoy image. The live container must never receive an unreviewed CA
mount or a downloaded CA file.

## Before you start

You need:

- an approved provider API hostname;
- a trusted, patched maintenance system with network access;
- the provider's or CA operator's official certificate repository;
- a second reviewer who did not perform the capture;
- a private directory for candidate files; and
- enough time to build and test a full offline release before a cutover.

Keep the previous approved release archive, manifest, source commit, and
rollback backup available.

## 1. Confirm the approved endpoint

Read the current provider record:

```bash
python3 -m json.tool services/egress-proxy/providers/catalog.json
```

Confirm the provider name, API hostname, route prefix, SNI, and exact SAN list.
Do not change the hostname because a certificate appeared on an unapproved
endpoint. A new endpoint requires a reviewed catalog change.

## 2. Capture a candidate chain

Create a private temporary directory. Point the helper at that directory so it
does not overwrite reviewed source files:

```bash
candidate_dir="$(mktemp -d)"
chmod 0700 "$candidate_dir"
CERTS_DIR="$candidate_dir" \
  services/egress-proxy/generate-pins.sh api.example.com
```

Replace `api.example.com` with the already approved catalog hostname. The
helper requires normal TLS chain verification and refuses a failed chain. It
writes candidate CA certificates only. It does not approve them.

Record the capture date, system, network path, command, and complete output in
the maintenance evidence. A second network path can help detect a local
intercept proxy, but two matching captures still do not prove original trust
provenance.

## 3. Check the candidate against an official source

Use the provider's documented PKI source or the CA operator's official
certificate repository. Do not trust a certificate only because the live
endpoint sent it.

For every certificate in the candidate bundle, check:

- subject and issuer;
- `notBefore` and `notAfter` dates;
- `CA:TRUE` basic constraint;
- certificate-signing key usage;
- SHA-256 fingerprint; and
- its place and order in the endpoint chain.

Inspect one certificate with:

```bash
openssl x509 -in candidate-ca-01.pem -noout \
  -subject -issuer -dates -text -fingerprint -sha256
```

If the bundle has more than one certificate, split it into one temporary PEM
file per certificate and inspect each file in bundle order. Store catalog
fingerprints as 64 lowercase hexadecimal characters with no colons.

Hash the complete candidate bundle:

```bash
shasum -a 256 "$candidate_dir/example-ca.pem"
```

The complete-file hash detects any change to PEM bytes or order. The
certificate fingerprints identify each DER certificate. Both checks are
required.

Reject the candidate if any certificate is unexpected, expired, not active
yet, malformed, unable to sign certificates, or absent from the reviewed
official source.

## 4. Write the provenance record

Create or update
`services/egress-proxy/providers/provenance/<provider>.json`. Record what was
checked and what the evidence cannot prove.

The record must contain:

- `schema_version` set to `1`;
- exact provider name and API hostname;
- `verification_status` set to `current-chain-verified`;
- review date and scope;
- the bundle SHA-256;
- ordered certificate SHA-256 fingerprints;
- verification statements naming the official source; and
- limitations of the evidence.

At a minimum, the limitations must say that a live check is a point-in-time
observation, a matching hash does not prove the original capture path, and a
certificate country does not prove endpoint geography or data residency.

Hash the completed provenance file:

```bash
shasum -a 256 \
  services/egress-proxy/providers/provenance/example.json
```

## 5. Update reviewed source

Only after independent review:

1. Copy the approved bundle to
   `services/egress-proxy/certs/<provider>-ca.pem`.
2. Update the provider's bundle hash and ordered fingerprints in
   `services/egress-proxy/providers/catalog.json`.
3. Update its provenance path and provenance hash.
4. Keep catalog providers and exact SAN values sorted.
5. Commit the CA, provenance, catalog, and tests in one reviewed change.

Do not add a deployment variable, CLI CA path, URL download, runtime volume,
or Ansible trust-discovery task.

## 6. Test the policy before release

Run the component tests:

```bash
cd services/egress-proxy
go test -race ./...
go vet ./...
cd ../..
```

The tests must cover changed fingerprints, expiry, not-yet-valid dates, CA
constraints, SNI, exact SANs, missing files, malformed files, and unexpected
files. The startup gate must fail closed for every bad case.

## 7. Build and test the exact release

Build a new release with the affected provider selected:

```bash
python3 -I scripts/update-images.py prepare \
  --provider example \
  --platform linux/amd64 \
  --archive /release/aigw-ca-rotation.docker.tar.zst \
  --manifest /release/aigw-ca-rotation.manifest.json \
  --test-preprod
```

Use the real approved provider list and target platform. On macOS, add
`--ask-become-pass`.

The command also creates the sibling preprod release. Local preprod loads that
archive and starts the exact Envoy image with `pull_policy: never`. Do not use
a separate hand-built image as acceptance evidence.

Review the schema-v2 manifest. Confirm that it records the selected providers,
hostnames, CA fingerprints, policy digest, and final Envoy image ID. Confirm
that the image contains no unselected CA file or route.

## 8. Approve and deploy

Approve the release only when:

- the independent CA review is complete;
- component and contract tests pass;
- the exact seed passes local preprod;
- real approved-provider TLS and inference checks pass where policy allows;
- the previous release and state backup are ready; and
- the rotation window keeps rollback safe.

Use the remote `upgrade` command in the
[image update workflow](../image-update-workflow.md#4-upgrade-the-remote-host).
The manifest binds the Envoy image and policy. Deployment cannot replace one
without the other.

## Rotation with an overlap window

If the CA operator provides an overlap window, use two reviewed releases:

1. Build a transition release whose provider bundle contains the approved old
   and new CA certificates in reviewed order.
2. Test and deploy it before the provider changes its chain.
3. Confirm traffic after the provider cutover.
4. Build another release that removes the retired CA.
5. Test and deploy the smaller final bundle.

Every bundle change changes the policy digest and Envoy image ID.

Do not assume the old release remains a safe rollback after the provider stops
using the old chain. Plan the overlap so the previous known-good release still
trusts the active chain, or keep ingress closed while the release team decides
the recovery path.

## Rollback

The normal automatic rollback restores the previous state, source, seed, and
validation result. It does not edit a CA file in place. The previous manifest's
provider policy and Envoy image move together.

If rollback fails because the provider has already removed the old chain, keep
ingress closed. Do not mount the new CA into the old image. Build and approve a
new immutable release through this SOP.

## What this evidence does and does not prove

- A **certificate fingerprint** proves the certificate bytes match the
  reviewed bytes.
- **Provenance** records where those bytes came from and how people checked
  them. The fingerprint alone does not prove provenance.
- A CA subject country, including `C=US`, describes the CA organization entry.
  It does not prove the server's physical location.
- A server IP location is only endpoint geography for that connection. CDN
  routing can change it.
- **Data residency** concerns where provider data is processed or stored. It
  needs provider policy, contract, and audit evidence. A certificate does not
  prove it.

Keep these statements in the release evidence. Do not turn certificate
integrity into a data-residency claim.
