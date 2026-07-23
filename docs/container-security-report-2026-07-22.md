# Container security scan report — 2026-07-22

This is the dated record of the release container security scan for the
2026-07-22 Anthropic-only `linux/arm64` release candidate (runtime commit
`ada03be`, scanned at repository commit `2395b51`).

- Workflow: **Repository and release container security**
- GitHub Actions run: `29971773431` (completed 2026-07-23 UTC)
- Jobs: **48 total — 20 passed, 28 failed.**
- Of the 28 failed jobs, **27 failed on real unpatched upstream findings**
  and **1 failed on a scanner download error**, not a vulnerability.

The gate is working as designed. It stays red until each upstream publisher
ships a fixed image. We do not hide findings and we do not add broad waivers.
The acceptance steps for clearing each finding are in the
[engineering backlog](backlog.md#recheck-current-upstream-container-findings).

## How the scan works

Each release image gets one job. The job pulls or builds the exact pinned
image, runs Trivy, and runs the Docker Scout gate for HIGH and CRITICAL
findings. The Scout gate honors signed VEX statements, so a finding a vendor
has formally marked "not affected" does not fail the job. Any other HIGH or
CRITICAL finding, or a failed scan, fails the job.

## Good news first

- **The shipped custom Open WebUI image passed clean.** The raw upstream
  `ghcr.io/open-webui/open-webui:v0.10.2` reference image failed with 50
  HIGH/CRITICAL findings across 25 packages, but our hardened rebuild
  remediates every finding Scout flags in the shipped image.
- **The shipped custom Vault image passed clean.** Only the scan of its
  upstream reference image hit the scanner error below.
- All repository-source scans (code, workflows, configs) passed.

## Real findings (accepted, unpatched upstream)

The dominant finding is one gRPC library advisory repeated across the Go-based
images. Every finding below is in an upstream image or package we cannot patch
without forking. Each keeps its newest reviewed pin until the publisher ships
a fix.

| Images | Package (version) | Advisory | Severity | Fixed version |
| --- | --- | --- | --- | --- |
| 17 Go-based images (alertmanager, loki, oauth2-proxy, otel-collector, prometheus, traefik, platform-dns, and their upstream counterparts) | google.golang.org/grpc (1.81.0–1.82.0) | GHSA-hrxh-6v49-42gf | HIGH | 1.82.1 |
| keycloak (custom + upstream) | jackson-core (2.21.1) | GHSA-r7wm-3cxj-wff9 | HIGH | 2.21.4 |
| keycloak (custom + upstream) | org.postgresql/postgresql (42.7.11) | CVE-2026-54291 | HIGH | 42.7.12 |
| grafana (custom + upstream) | grafana/tempo | CVE-2026-28377, CVE-2026-21728 | HIGH | 2.10.3 / 2.8.4 |
| prometheus (custom + upstream) | immutable (5.1.5, npm) | CVE-2026-59880, CVE-2026-59879 | HIGH | 5.1.8 |
| alloy (custom + upstream) | docker/docker (28.5.2) | CVE-2026-42306, CVE-2026-41567 | HIGH | none (vendor VEX: "not affected" / "under investigation") |
| samba-ad | cryptography (43.0.0) | GHSA-537c-gmf6-5ccf, CVE-2026-26007 | HIGH | 48.0.1 / 46.0.5 |
| litellm + open-webui upstream bases | pyasn1 (0.6.3) | CVE-2026-59886, -59885, -59884 | HIGH | 0.6.4 (already applied in our shipped derivatives) |
| debian:13.6-slim, open-webui upstream | perl | CVE-2026-12087 | CRITICAL | none published |
| docker/dockerfile:1.25.0 | moby/buildkit, containerd/v2 | CVE-2024-23651/23652/23653, CVE-2026-33747/33748, CVE-2026-53488/53489/53492 | CRITICAL/HIGH | buildkit 0.12.5+/0.28.1, containerd 2.2.5 |
| traefik upstream binary source | docker/cli (29.4.0) | CVE-2025-15558 | HIGH | none published |
| open-webui upstream base only | ~20 further packages (pillow, gitpython, torch, mariadb, and others) | various | HIGH (1 CRITICAL) | mixed |

The full per-advisory detail (every image, package, and advisory ID from the
run) is preserved in the run's artifacts and logs under run `29971773431`.

## Scanner failure (not a vulnerability)

One job failed before any scan ran:

| Job | Error | Meaning |
| --- | --- | --- |
| External `dhi.io/vault:2.0.3` | HTTP 403 downloading the Docker Scout binary | Infrastructure error on GitHub's side. No scan output was produced, so the job correctly failed closed. Trivy passed this image in the same run. The rerun covers it. |

## What happens next

Follow the durable steps in the
[engineering backlog](backlog.md#recheck-current-upstream-container-findings):
keep each pin at the newest reviewed release, watch for a fixed tag, rebuilt
digest, or signed VEX, then update the pin, rebuild the schema-v2 seed, rerun
full local PreProd, and require a green GitHub scan for the new image ID.

A rerun of the same workflow on repository commit `9264090`
(run `29973600720`, completed 2026-07-23 UTC) confirmed this record:
21 jobs passed and 27 failed. The scanner failure did not repeat — the
external Vault image scan passed on the rerun, which confirms the HTTP 403
was a temporary infrastructure error. Every remaining failed job is one of
the real upstream findings above. No image pin changed between the runs.
