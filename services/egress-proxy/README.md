# egress-proxy — CA-pinned originating TLS proxy (custom component)

Envoy on `net-egress`, the **only** container with a path out eth0 (enforced
in DOCKER-USER). All LLM vendor API traffic leaves through it.

## Architecture

This is **not** an `HTTPS_PROXY`/CONNECT forward proxy (an earlier design,
now abandoned). With CONNECT, the client does TLS end-to-end and the proxy
only sees an opaque tunnel — pinning would be unenforceable without MITM.

Instead, Envoy is an **originating TLS reverse proxy**:

- Clients (LiteLLM, key-rotator) speak plain HTTP to Envoy on the backend
  network: `http://envoy-egress:8080/<vendor>/...`
  (e.g. `POST /anthropic/v1/messages`).
- Path-prefix routing maps each vendor prefix to a dedicated upstream
  cluster (`/anthropic/` → `anthropic`, `/openai/` → `openai`) with
  `prefix_rewrite`, `host_rewrite_literal`, and per-cluster SNI.
- Envoy **originates the vendor TLS itself**, so it validates and pins the
  vendor's certificate. A compromised gateway container cannot bypass
  pinning — it has no direct route out.
- **No default route**: any path not on the vendor allow-list returns 404.
  Adding a vendor requires both a route and a cluster in `envoy.yaml`.

## Pinning posture

Each upstream cluster's `validation_context` enforces, on top of normal TLS
chain validation:

- **CA pinning via a narrowed `trusted_ca`** — the PRIMARY enforcement.
  `trusted_ca` is **not** the full public root bundle; it is a curated
  per-vendor file (`certs/anthropic-ca.pem`, `certs/openai-ca.pem`) that holds
  **only the issuing CA(s) that vendor actually uses** (its intermediate +
  root). Envoy builds the chain against this store, so a technically-valid
  public-CA certificate for the vendor hostname issued by *any other CA* is
  rejected. This is the real, rotation-stable pin: roots/intermediates change
  on a multi-year cadence.
  - As of the last capture, both `api.anthropic.com` and `api.openai.com`
    chain via **Google Trust Services** (intermediate `WE1` → root
    `GTS Root R4`); narrowing `trusted_ca` to those constrains egress to that
    CA. Re-verify with `generate-pins.sh` — do not trust this doc blindly.
- **Optional leaf SPKI pinning** (`verify_certificate_spki`) — commented out by
  default, defense-in-depth only. It is base64 SHA-256 of the DER
  SubjectPublicKeyInfo and — per Envoy's implementation — matches the **LEAF
  certificate ONLY** (it does **not** walk the chain; pinning an intermediate
  here does nothing). It is strict but **rotation-fragile**: vendor CDN leaf
  certs rotate roughly every **90 days**, so an active leaf pin must be
  refreshed on that cadence or egress breaks. This is why leaf SPKI is *not*
  the primary enforcement. If you enable it, keep 2 slots (current + incoming).
- **Strict SAN matching** (`match_typed_subject_alt_names`, exact DNS per
  vendor).

> Earlier revisions of this component made leaf/chain SPKI the sole enforcement
> and kept `trusted_ca` as the full system bundle. That was wrong:
> `verify_certificate_spki` is leaf-only, so pinning an intermediate never took
> effect, and leaf-only pins brick egress on every ~90-day vendor rotation. The
> narrowed `trusted_ca` above is the fix.

### Generating / rotating pins

```sh
# On a trusted networked host (verify from two vantage points if possible):
./generate-pins.sh                    # defaults to the pinned vendors
./generate-pins.sh api.anthropic.com  # or specific hosts
```

The script connects with `openssl s_client -showcerts -verify_return_error`,
**refuses** any cert whose chain does not validate (Verify return code != 0),
and then:

- writes each vendor's **issuing-CA chain** (intermediate + root) to
  `certs/<vendor>-ca.pem` — this is the trusted_ca bundle; and
- prints the **leaf SPKI pin** for the optional `verify_certificate_spki`
  layer.

**Rotation runbook:**

- *CA bundle (primary, stable):* re-run only when a vendor changes issuing CA
  (rare). To rotate without an outage, **append** the incoming CA cert to
  `certs/<vendor>-ca.pem` (keep the old) *before* the vendor cuts over, deploy,
  then prune the retired CA.
- *Leaf SPKI (optional, ~90 days):* if enabled, add the incoming leaf pin to
  the second slot before the vendor rotates, deploy, then drop the old pin.

## Fail-closed startup

The compiled, static `aigw-envoy-entrypoint` (built from `entrypoint.go` and
wired as the image ENTRYPOINT) asserts that the narrowed-CA enforcement is
actually **present and populated** before starting Envoy. It keeps the final
DHI image shellless and exits non-zero (fail closed) if, for any vendor TLS
context:

- a `trusted_ca` file is missing from the config (block deleted), or
- `trusted_ca` points at a system/public root bundle (pinning voided), or
- the referenced bundle is missing, empty, still a `REPLACE_WITH_*`
  placeholder, or contains no certificate.

It also rejects any active (uncommented) `REPLACE_WITH_SPKI` placeholder. This
closes the earlier gap where a config with the pin block simply **deleted**
would start on public-PKI-only validation.

### Entrypoint is a trust boundary

The entrypoint also **refuses caller-supplied `--config-yaml` / `--config-path`
/ `-c` flags**: it chooses the config path itself, and a compose
`command: ["--config-yaml", ...]` would otherwise merge unvetted config *after*
the gate validated the file. To point at a different config, set the
`ENVOY_CONFIG` env var (still gated) rather than passing a flag.

Note that **overriding the container `entrypoint:` in compose bypasses this
gate entirely** — that is an inherent trust boundary. Do not override
`entrypoint:` for `envoy-egress`; if you must, replicate the compiled launcher's
checks and acceptance tests.

## Admin interface

The Envoy admin listener is bound to `127.0.0.1:9901` (it is unauthenticated
and exposes `/quitquitquit`, `/runtime_modify`, etc.). It is not reachable
from other containers. The healthcheck execs
`/usr/local/bin/aigw-envoy-entrypoint health` inside the shellless container;
the compiled probe disables proxies and redirects and requires a loopback HTTP
200 response containing `LIVE`. A separate listener on `:9902` routes only an
exact `GET /stats/prometheus` to loopback admin for Prometheus; there is no
catch-all route, so mutation/shutdown endpoints remain unreachable.

## Observability

Structured JSON access logs to stdout (method, path, upstream cluster,
status, response flags, duration, bytes) — every egress request is
auditable.

## Deployment (compose)

The narrowed CA bundles must reach the container at the paths in `envoy.yaml`
(`/etc/envoy/certs/<vendor>-ca.pem`). The image bakes in `certs/` as fail-closed
placeholders; mount the real, verified bundles over them, e.g.:

```yaml
    volumes:
      - ./services/egress-proxy/certs/anthropic-ca.pem:/etc/envoy/certs/anthropic-ca.pem:ro
      - ./services/egress-proxy/certs/openai-ca.pem:/etc/envoy/certs/openai-ca.pem:ro
```

Do not set a `command:` with `--config-yaml/--config-path/-c` (the entrypoint
rejects them) and do not override `entrypoint:` (bypasses the gate).

## Files

- `envoy.yaml` — listener, vendor routes/clusters, narrowed-CA validation
  contexts (optional leaf SPKI commented out)
- `certs/` — per-vendor narrowed `trusted_ca` bundles (issuing CA(s) only);
  shipped as fail-closed placeholders
- `generate-pins.sh` — issuing-CA bundle + leaf-SPKI generation/rotation helper
- `entrypoint.go`, `entrypoint_test.go` — compiled fail-closed startup gate and
  loopback readiness probe; the gate asserts CA pinning and refuses
  config-override flags
- `Dockerfile` — DHI Envoy runtime and DHI Go build source pinned by digest,
  offline gate tests/build, and compiled entrypoint wiring
