# Container Platform Security

This document describes how AI Gateway hardens the Docker platform itself:
daemon configuration, the image supply chain, per-container runtime
restrictions, secrets handling, volume and bind-mount integrity, and port
publication. Host-level controls are in
[OS security](os-security.md); packet-level controls in
[network security](network-security.md).

## 1. Daemon configuration

`/etc/docker/daemon.json` is an exact, validated contract — six keys, no
more — checked with `dockerd --validate` before installation and re-checked
by preflight on every run:

```json
{
  "data-root": "<docker_data_root>",
  "log-driver": "json-file",
  "log-opts": { "max-size": "50m", "max-file": "5" },
  "live-restore": true,
  "firewall-backend": "iptables",
  "selinux-enabled": true
}
```

`firewall-backend: iptables` is deliberate: Docker 29's experimental
nftables backend removes the `DOCKER-USER` chain this design enforces
against. SELinux integration is mandatory — the daemon must report
`name=selinux` — and the daemon is never started until the host packet
policy is live. A drifted `daemon.json` on a provisioned host is a refused
condition, not an auto-repair.

## 2. Image supply chain

**Every image is pinned by tag and immutable digest.** No floating tags, no
`latest`, and Compose runs with implicit builds disabled — an unchanged
converge can never rebuild or retag an image.

**Docker Hardened Images (DHI) by default.** Catalog-supported components
run directly on `dhi.io` images (Postgres 16.14, BusyBox) or on
reviewed single-layer derivatives that add only a static health-probe binary
to an otherwise shellless DHI runtime (Keycloak 26.6.4, Vault 2.0.3, Redis
7.4.9, the four OAuth2 Proxy 7.15.3 gates, Alloy, Prometheus, Loki, Grafana,
node-exporter, the OTel collector). Traefik is a reviewed two-stage build
that places the patched 3.7.7 binary on the non-root DHI runtime. The
portals, key-rotator, and Envoy entrypoint build from DHI Python/Go bases
with `--network=none`.

**Documented exceptions.** Three upstream images remain, each pinned past a
known-vulnerable release with the rationale recorded inline: LiteLLM
v1.92.0, Open WebUI 0.10.2, and the lab-only Debian Samba build.

**Extracted, never executed.** The optional Vault browser UI
(`vault-ui-proxy`) is a stdlib-only Go proxy whose UI assets are extracted
from the official `hashicorp/vault:2.0.3` image *as data* — the upstream
binary is never run — with the exact embedded file set pinned in
`upstream-provenance.json`, analytics force-disabled, a strict no-external
CSP, and a startup proof that the proxy is PID 1 with no other process in
the container.

**Deterministic builds and rollback.** A build planner digests each
service's effective build definition and complete build context
(length-framed, collision-resistant) into a root-only manifest
(`.state/compose-build-inputs.json`); only changed or missing images are
built. Before any tag moves, the exact running image is preserved under a
content-addressed rollback reference. The portal image installs its complete
transitive dependency set from a SHA-256-hashed lock file with pip
`--require-hashes`; installing from an unhashed requirements list is
forbidden.

## 3. Runtime hardening

A shared hardening anchor applies to every long-running service:
`no-new-privileges`, `cap_drop: ALL`, explicit per-plane container resolvers
(rendered into `docker-compose.dns.yml`; only Envoy receives Internet DNS),
bounded JSON logging (20 MiB × 5), a PID limit, and `restart:
unless-stopped`. On top of that baseline:

- **Non-root everywhere.** Application services run as uid 65532 (or a
  service-specific non-root uid such as Vault's 1000 and Alloy's 473). The
  only root container is the one-shot volume initializer — networkless,
  read-only, PID-limited, and exiting before any stateful service starts.
- **Minimal capabilities.** Almost every service runs with zero
  capabilities. The exceptions are explicit and narrow: `NET_BIND_SERVICE`
  for the two Traefik edges (and lab DNS), `IPC_LOCK` for Vault (with
  unlimited memlock so key material never swaps), `CHOWN/FOWNER/FSETID` for
  the volume initializer, and the lab-only Samba set.
- **Read-only root filesystems** with per-purpose `tmpfs` mounts, except
  three documented writable-rootfs exceptions whose upstreams require it
  (LiteLLM, Open WebUI, Keycloak) — each justified inline in the Compose
  file.
- **Resource ceilings** on every service (memory, CPU, PIDs), from 64 MiB
  for lab DNS to 4 GiB for LiteLLM.
- **Shellless health checks.** DHI runtimes carry no shell, so health checks
  use a static, purpose-built probe binary (`aigw-health-probe`) or the
  component's own native health command — never `curl | sh` patterns.
- **SELinux confinement** with per-container MCS categories on process and
  mount labels. Exactly two services run `label=disable`, each bounded and
  justified: Alloy (must read Docker's runtime-owned logs, which must never
  be relabeled) and node-exporter (read-only host-root metrics view). Both
  remain non-root, capability-dropped, read-only, and unpublished.
- **No privileged containers** anywhere, including the lab overlay.

## 4. Secrets handling

- **Fail-closed variable contract.** Every required Compose variable uses
  `${VAR:?}`; a missing secret stops the stack rather than starting it
  half-configured. Secret values are validated for length and character
  class before rendering, and related secrets are asserted mutually
  distinct.
- **No secret in a command line or environment where a file will do.**
  Redis receives only a SHA-256 ACL verifier via file; its health probe
  reads a separate password file; neither value appears in the container's
  command or environment metadata. Lab Samba passwords are file-backed
  Docker secrets read with `O_NOFOLLOW` and driven through the Samba API —
  never a child-process argument.
- **Verified absence.** The converge proves the Open WebUI workload key's
  plaintext appears in no project container log, and stores only its hash in
  the gateway database. Provider credentials live in Vault and are brokered
  at runtime ([WIF flow](anthropic-wif-bootstrap.md)); no long-lived vendor
  key sits in configuration.

## 5. Volume and bind-mount integrity

- **State-volume ownership contracts.** The versioned one-shot initializer
  owns exactly eight volume-root contracts (owner, group, mode — including
  the SGID audit volume) and re-runs only when absent, failed, redefined, or
  drifted; Ansible verifies the exact metadata afterward.
- **Read-only, relabeled binds.** Every configuration bind is read-only with
  exactly one SELinux relabel flag: private (`Z`) for per-service files,
  shared (`z`) only where two reviewed consumers share a source. Docker's
  own runtime tree is never relabeled.
- **Keyed content digests force safe recreation.** Bind mounts pin the file
  inode at container creation, so an atomically replaced config could
  otherwise leave a running service reading stale bytes. A per-service
  HMAC-SHA256 digest over each service's complete bind-source inventory
  (path, type, owner, mode, size, content — links and special files
  rejected) is stamped into service metadata; a source change recreates
  exactly the affected consumers. The 32-byte key is root-only, single-link,
  accepted on stdin only, and excluded from backups.

## 6. No Docker socket exposure

No container mounts the Docker socket. Traefik uses a reviewed file provider
— not Docker-label discovery — with its dashboard disabled. The log
collector reads container logs through a read-only filesystem bind bounded
by host ACLs (uid 473, current project only), not through the API. The only
socket consumers are the host-side automation itself and a sandboxed
systemd ACL reconciler with a read-only socket bind.

## 7. Port publication

Exactly two services publish host ports in the base stack, each bound to one
exact address: `traefik-int` on `ETH2_IP:443` and `traefik-adm` on
`ETH1_IP:443` (the optional platform-DNS overlay adds authoritative DNS on
port 53, bound to the same two addresses).
The converge asserts the live publication set equals that expectation,
rejects any binding on `0.0.0.0`, `::`, or the egress address, and verifies
the corresponding NAT rules — Envoy's admin endpoint and every telemetry
listener remain unpublished on fixed internal bridge addresses.
