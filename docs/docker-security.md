# Container security

This page explains how AI Gateway locks down Docker, images, containers,
mounts, and ports. See [host security](os-security.md) and
[network security](network-security.md) for the other layers.

The main rules are:

- Every image has a reviewed tag and digest.
- Normal services run as non-root with small permissions.
- No container gets the Docker socket.
- Config mounts are read-only and tied to content digests.
- Only the two Traefik edges publish application ports.
- Provider routes and CA files are built into one immutable Envoy image.

## Docker daemon

Ansible owns one exact `/etc/docker/daemon.json` file:

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

There are six keys. Ansible checks the file with `dockerd --validate` and
reads it again on later deploys. Drift on a marked production host stops the
deploy instead of changing a live daemon without review.

The iptables backend is required. Docker's nftables backend does not provide
the `DOCKER-USER` chain used by this design. SELinux must also be active in the
daemon.

Docker starts only after the host packet rules are ready.

## Image supply chain

Every source image uses both a tag and an OCI digest. The project does not use
`latest`. Normal Compose starts disable hidden builds and pulls.

DHI is the first choice when it is current, compatible, and at least as secure
as the reviewed option. Some DHI runtimes are shellless, so local builds add a
small static health probe.

Current DHI-based services include PostgreSQL 18.4, BusyBox, Keycloak, Vault,
Redis, OAuth2 Proxy, Alloy, Prometheus, Loki, Grafana, node-exporter, the OTel
collector, Envoy, portals, key-rotator, and optional platform DNS. Traefik uses
a reviewed patched binary on a DHI runtime.

Three reviewed upstream exceptions remain:

| Image | Reason |
| --- | --- |
| LiteLLM `v1.93.0` | The reviewed upstream image was safer and compatible |
| Open WebUI `0.10.2-aigw2` | No matching application DHI image was available |
| Samba AD test image | Local preprod only; never a production directory |

An exception does not allow a floating tag or skipped scan.

### Open WebUI chat-only image

The `0.10.2-aigw2` derivative is smaller than the upstream general-purpose
image and has fewer runtime paths:

- Its root filesystem is read-only.
- Its named data volume holds required application state.
- A bounded `/tmp` `tmpfs` holds temporary files and generated static files.
- The build removes unused local ML packages and document-conversion tools.
- `BYPASS_EMBEDDING_AND_RETRIEVAL=true` stops local vector indexing, and
  `RAG_EMBEDDING_MODEL` is empty.
- An exact source patch removes remote Chroma settings and the `HttpClient`
  path. Only the embedded `PersistentClient` code remains, and retrieval is
  bypassed for this chat-only deployment.

The offline build also installs reviewed wheels for cryptography 48.0.1,
Pillow 12.3.0, MCP 1.28.1, and python-multipart 0.0.30. Compiled wheels are
committed for both AMD64 and ARM64. Their hashes are checked before install,
and the Docker build has no network.

Open WebUI has no DHI VEX statement. The repository therefore carries one
local OpenVEX review for `CVE-2026-45829`. It is tied to the exact `aigw2`
build inputs and expires on 2026-10-19. The document is unsigned and reviewed
through Git. It must not be described as Docker-signed evidence. A reviewed
local Scout comparison found one raw finding and zero VEX-aware findings.
The protected GitHub release scan still needs to run before release approval.

### Release image scan evidence

GitHub saves raw Trivy `HIGH` and `CRITICAL` JSON for each release image. That
record is not VEX-filtered. Docker Scout 1.23.1 applies the blocking VEX-aware
gate.

For DHI bases, CI fetches VEX only for the exact tag and digest. It verifies
the signature with the committed Docker public key, then selects the statement
only when that exact DHI base is part of the final image. A missing DHI VEX
statement means no DHI suppression.

Docker's current DHI statements have no public transparency-log entries. The
fetch therefore uses `--verify --skip-tlog`. The pinned-key signature is still
checked, and the evidence receipt records that public-log inclusion was not
proved. This limitation is different from Open WebUI's unsigned, Git-reviewed
local VEX statement.

The optional Vault UI proxy extracts static UI files from the pinned official
Vault image. It does not run the upstream Vault binary. A provenance file lists
the exact embedded files. The proxy blocks analytics and outside web content.

Custom Dockerfiles build with networking disabled. Python production images
install a full hash-locked dependency file. Go images test during their
network-disabled build.

Before a tag moves, the release flow saves the exact current image under a
content-based rollback name. Stateful image changes also need a recent,
verified backup.

## Immutable Envoy provider policy

The release operator selects provider names from a committed catalog. The CLI
does not accept arbitrary hostnames or CA paths.

For each selected provider, the build checks:

- API hostname and route prefix;
- SNI and exact SAN names;
- reviewed CA bundle and certificate fingerprints;
- CA dates and signing rules; and
- provenance evidence and hashes.

The final shellless image contains only the selected routes and CA files.
Changing the provider set or CA evidence changes the policy digest and image
ID.

The schema-v2 seed manifest records the provider evidence, policy digest, and
final Envoy image ID. The offline loader checks the matching image labels.
Ansible never finds or downloads CA trust during a deploy.

At startup, the compiled gate rejects:

- changed policy or config bytes;
- missing, extra, broken, expired, or wrong-fingerprint CA files;
- unsafe SNI or SAN rules;
- `ENVOY_CONFIG`; and
- caller-supplied config flags.

There is no system trust fallback. Do not mount CA files over the image or
replace its entrypoint.

See [provider onboarding](provider-onboarding.md), the
[CA maintenance SOP](sop/provider-ca-maintenance.md), and
[offline image releases](offline-image-seed.md#envoy-image-and-policy-binding).

## Runtime limits

Every long-running service gets this base policy:

- `no-new-privileges`;
- all Linux capabilities dropped first;
- an explicit DNS path;
- bounded JSON logs;
- CPU, memory, and PID limits; and
- a reviewed restart policy.

Application services run as UID 65532 or their own non-root UID. The one-shot
volume initializer is the only production root container. It has no network,
a read-only root, a small PID limit, and exits before stateful services start.

Most services keep zero capabilities. The approved additions are:

| Service | Capability | Reason |
| --- | --- | --- |
| Traefik and optional platform DNS | `NET_BIND_SERVICE` | Bind low ports |
| Vault | `IPC_LOCK` | Keep key material out of swap |
| Volume initializer | `CHOWN`, `FOWNER`, `FSETID` | Set state-volume owners and modes |

The local Samba test container has a separate reviewed capability set. It is
not part of production.

Most root filesystems are read-only, with small `tmpfs` paths for writes.
LiteLLM and Keycloak keep documented writable-root exceptions because their
upstream images need them. Open WebUI no longer has that exception.

Health checks use a static project probe or the service's own command. They do
not depend on a shell or download a tool at runtime.

Normal containers use SELinux MCS separation. Alloy and node-exporter are the
only `label=disable` cases. They remain non-root, capability-dropped,
read-only, and unpublished.

No production or preprod container is privileged.

## Secrets

Required Compose values use `${VAR:?}` so a missing value stops rendering.
Ansible checks secret length, allowed characters, and required differences
before it writes runtime files.

Use a mounted file when command or environment metadata would expose a secret.
Examples:

- Redis reads a SHA-256 password verifier file.
- Redis clients read a separate password file.
- The production LDAPS bind password is a root-owned file.
- Preprod Samba reads test passwords from protected files.

Provider credentials live in Vault and reach LiteLLM through the reviewed
broker path. No long-lived provider key is stored in normal config.

Verification checks that the Open WebUI workload key does not appear in any
project container log. The database stores its hash, not its plaintext.

## Volumes and config mounts

The one-shot initializer owns eight state-volume root contracts. It runs only
when it is missing, failed, changed, or the required owner or mode drifted.
Ansible checks the state again after it exits.

Every config bind is read-only. Private files use `Z`; files shared by reviewed
containers use `z`. Docker's own runtime tree is never relabeled.

Docker binds an inode when it creates a container. An atomic file replacement
could leave a running service on old bytes. The project prevents that with a
per-service HMAC-SHA256 bind-source digest.

The digest covers path, type, owner, mode, size, and content. Unsafe links,
special files, and read races fail. A changed digest recreates only the service
that uses those files. The digest key is root-only, arrives on stdin, and is
not backed up.

## No Docker socket in containers

No container mounts `/var/run/docker.sock`.

Traefik reads Ansible-made files instead of Docker labels. Alloy reads only
approved Docker JSON log files through a read-only host path and narrow ACLs.
It does not call the Docker API.

Only host automation and the locked log-ACL systemd job use the socket. The
systemd job receives a read-only socket bind and a small file-permission set.

## Published ports

The base production stack publishes application traffic through two services:

| Service | Bind |
| --- | --- |
| `traefik-int` | `ETH2_IP:443` |
| `traefik-adm` | `ETH1_IP:443` |

Optional platform DNS also binds TCP and UDP 53 on those two exact addresses.

Verification rejects `0.0.0.0`, `::`, and the egress address. It also checks
the matching NAT rules. Envoy admin, databases, cache, Vault, and telemetry
listeners stay on private Docker networks.

Alloy may make one outbound TLS connection to the approved Cribl address and
port. Only the curated SOC log set can use it. Metrics, alerts, raw traces, and
normal service logs stay local. See the [Cribl handoff](cribl-soc-handoff.md).
