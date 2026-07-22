# Image and dependency version review

This is the dated version review for the 2026-07-22 ARM64 release. A version
is “current” here only as of that date. Run the checks again before the next
release.

A pin is a fixed version and SHA-256 digest. It prevents a registry tag from
changing after review.

The final 2026-07-22 check found newer registry digests for the same Grafana
`13.1.0`, Python `3.14.6`, and Vault `2.0.3` DHI tags. The source pins now use
those newer digests. The committed digest still cannot move after release.
The next release must repeat this check before it accepts a rebuilt tag.

The same check found that the Alloy pin used the `1.18.0` digest but called it
`1.17.1`. The image bytes were current, but the label was wrong. The source now
uses the truthful `1.18.0` tag with that same fixed digest.

## Result

The current source selects the newest stable and compatible version available
from each reviewed source. Version selection is complete. Runtime acceptance
is not: the current source now renders 26 long-running services in normal
PreProd and still needs a new exact-seed test.

The last accepted seed ran 25 long-running services. It passed the full
Ansible test, the PostgreSQL 16-to-18 move, rollback, downgrade refusal,
physical restore, and final cleanup. That result is historical evidence, not a
pass for the new image digests and feature changes.

One project published a newer upstream release after its matching Docker
Hardened Image (DHI):

- Grafana upstream is `13.1.1`; DHI offers `13.1.0`.

Do not swap that image to another registry without a new review. Its selected
DHI version is the newest DHI tag. The current exact-seed gate must test it
with the rest of this source candidate.

## DHI release images

The `docker dhi catalog get NAME --json` command checked each DHI repository.
Every selected tag below is the newest matching stable DHI tag for its major
version and image variant.

| Component | Selected DHI tag | Decision |
| --- | --- | --- |
| Alertmanager | `0.33.1` | Current stable release; open DHI security finding below |
| Alloy | `1.18.0` | Current |
| BusyBox | `1.38.0-alpine` | Current |
| CoreDNS | `1.14.6` | Current |
| Envoy | `1.39.0` | Current |
| Go build image | `1.26.5-alpine-dev` | Current |
| Grafana | `13.1.0` | Newest DHI; upstream `13.1.1` is not in DHI yet |
| Keycloak | `26.7.0` | Current |
| Loki | `3.7.3` | Current |
| Node Exporter | `1.12.1` | Current |
| OAuth2 Proxy | `7.15.3` | Current |
| OpenTelemetry Collector | `0.156.0-contrib` | Current |
| PostgreSQL rehearsal source | `16.14` | Latest PostgreSQL 16 maintenance release |
| PostgreSQL runtime | `18.4` | Latest stable PostgreSQL 18 maintenance release |
| Prometheus | `3.13.1` | Current |
| Python build image | `3.14.6-dev` | Current |
| Python runtime image | `3.14.6` | Current |
| Redis | `8.8.0` | Current |
| Traefik runtime base | `3.7.6` | Newest DHI; final image carries reviewed Traefik `3.7.8` |
| Vault runtime | `2.0.3` | Current |

The catalog did not contain DHI tags for Grafana `13.1.1` or Traefik `3.7.8`
at review time. The Traefik Dockerfile copies the current signed `3.7.8`
binary into the newest DHI Traefik runtime. Contract tests check the binary
version and both digests.

## Other release images

| Component | Selected tag | Decision |
| --- | --- | --- |
| Debian build base | `13.6-slim` | Current Debian stable point release |
| Dockerfile frontend | `1.25.0` | Current published frontend tag |
| LiteLLM base | `v1.93.0` | Current upstream release; final image is the reviewed `1.93.0-aigw2` derivative |
| Open WebUI base | `v0.10.2` | Current upstream release; final image is the reviewed `0.10.2-aigw2` derivative |
| Traefik binary source | `v3.7.8` | Current upstream release |
| Vault UI binary source | `2.0.3` | Matches the current reviewed Vault release |

Each release reference is pinned by tag and digest in source. The schema-v2
manifest records the exact image ID used by the archive.

## Language and library versions

The services use Python `3.14.6`. The four Go modules use Go `1.26` source
mode and the exact Go `1.26.5` build image. The Go modules use only the standard
library, so they have no third-party Go module versions to update.

The PyPI project record was checked for every direct Python pin. Every pin
matched the current published version on 2026-07-22:

| Group | Exact direct pins |
| --- | --- |
| Portal runtime | `fastapi 0.139.2`, `uvicorn 0.51.0`, `httpx 0.28.1`, `authlib 1.7.2`, `itsdangerous 2.2.0`, `jinja2 3.1.6`, `pydantic-settings 2.14.2`, `python-multipart 0.0.32`, `PyYAML 6.0.3` |
| Rotator runtime | `fastapi 0.139.2`, `uvicorn 0.51.0`, `httpx 0.28.1`, `APScheduler 3.11.3`, `hvac 2.4.0`, `requests 2.34.2`, `pydantic-settings 2.14.2`, `psycopg 3.3.4`, `PyJWT 2.13.0`, `cryptography 49.0.0` |
| Rotator telemetry | `opentelemetry-api 1.44.0`, `opentelemetry-sdk 1.44.0`, `opentelemetry-exporter-otlp-proto-http 1.44.0`, `opentelemetry-instrumentation-fastapi 0.65b0` |
| Test tools | `bandit 1.9.4`, `pip-audit 2.10.1`, `pytest 9.1.1`, `pytest-asyncio 1.4.0`, `ruff 0.15.22` |

The hash-locked transitive packages passed `pip-audit`. A future direct pin
change must regenerate the matching lock file and rebuild the release.

The LiteLLM derivative keeps the exact `v1.93.0` application base. Its
network-disabled build replaces `pyasn1` `0.6.3` with the reviewed `0.6.4`
wheel. It also applies one exact usage-validation patch. That patch lets the
prompt-free accounting callback record unknown usage when Anthropic omits or
malforms token counts in normal or streaming responses. The build stops if the
pinned LiteLLM version, reviewed source fragment, or patched Python syntax
changes. The Open WebUI derivative installs reviewed
`pyasn1` `0.6.4` and `GitPython` `3.1.54` wheels along with its existing
runtime updates. The repository stores each wheel and its SHA-256 hash. Both
AMD64 and ARM64 builds passed read-only package checks. The current exact-seed
and GitHub scan gates still must pass before release.

## Production host tools

The production inventory pins this compatible set:

| Tool | Selected version | Decision |
| --- | --- | --- |
| Docker Engine | `29.6.2` | Current stable security release |
| Docker Compose plugin | `5.3.1` | Current stable release |
| containerd.io | `2.2.6` | The version packaged with Docker Engine `29.6.2` |

Upstream containerd has a newer `2.3` line. Do not mix it into this Docker
Engine package set. Docker Engine `29.6.2` release notes name containerd
`2.2.6` as its packaging update. This is a compatibility choice, not a missed
update.

## Security gate

Version review does not replace a security scan. The protected GitHub
environment now has `DHI_USERNAME` and `DHI_PASSWORD`. A local DHI login must
not be copied into GitHub. Push the exact tested commit, run every source and
image scan, and save the SBOM and provenance for each final image. The separate
security audit is not complete until the blocking jobs pass and a person
reviews every finding and waiver.

The 2026-07-22 DHI reports found `GHSA-hrxh-6v49-42gf` in the gRPC `1.82.0`
library inside Alertmanager `0.33.1` on both AMD64 and ARM64. gRPC `1.82.1`
contains the fix. DHI had no rebuilt Alertmanager image and no signed VEX
statement for this finding. Older DHI tags and the Alpine `0.33.1` image were
not safer. Keep the newest Debian pin, keep the scan blocking, and recheck DHI.
Do not create a local waiver. The durable acceptance steps are in
[TASKS.md](../TASKS.md#recheck-and-clear-the-dhi-alertmanager-security-finding).

## Sources and next review

Use these primary sources during the next review:

- [DHI catalog CLI](https://docs.docker.com/dhi/how-to/cli/)
- [Prometheus and Alertmanager downloads](https://prometheus.io/download/)
- [Debian releases](https://www.debian.org/releases/)
- [Docker Engine 29 release notes](https://docs.docker.com/engine/release-notes/29/)
- [Go downloads](https://go.dev/dl/)
- [PostgreSQL release notes](https://www.postgresql.org/docs/release/)
- [Python releases](https://www.python.org/downloads/)
- each project’s official release page; and
- the package’s official PyPI project record.

Then follow the [image update workflow](image-update-workflow.md). Change the
reviewed source pin first. Never edit a generated seed manifest by hand.
