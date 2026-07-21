# Local preprod

Local preprod runs the AI Gateway from this checkout on one local Docker
engine. Ansible is the operator entry point. It does not run the Rocky Linux
host roles, change firewalls, or touch another Compose project.
The role requires the committed `localhost` inventory and Ansible's `local`
connection. It refuses an inventory that redirects the play to another host.

The preprod project name and every Docker resource start with `aigw-preprod`.
Three Docker networks model the host-facing planes:

| Plane | Docker network | Host bind |
| --- | --- | --- |
| Egress | `aigw-preprod-plane-egress` | none |
| ADM | `aigw-preprod-plane-adm` | `127.0.3.1:443` |
| Internal | `aigw-preprod-plane-internal` | `127.0.2.1:443` |

The namespace and reviewed private `172.29.x.0/24` subnet set are fixed. They
are not operator overrides. The preflight refuses an overlap, a non-local or
non-bridge network, or a network endpoint that is not owned by this preprod
project.

The service-to-service networks remain separate. Preprod never removes a
network unless its exact name and `com.aigw.preprod.project` ownership label
both match. Containers and volumes carry the same ownership label, and the
operator refuses an existing resource in that namespace without it.

Docker Desktop cannot publish the same IPv4 host port from two different
containers, even when their host IPs differ. A preprod-only Envoy forwarder
therefore owns both exact loopback bindings in one container. It passes raw
TLS to `traefik-int` or `traefik-adm` on the matching plane. TLS still ends at
the two separate Traefik containers. The forwarder cannot use `0.0.0.0`, is
part of the `aigw-preprod` Compose project, and is removed by the destroy play.
Production does not use this forwarder.

Local observability is deliberately smaller than production. Alloy receives
an empty preprod-owned Docker-log volume instead of the local Docker data root,
and node-exporter sees only its own container namespace. Preprod never mounts
the workstation root or reads logs from another local Compose project.
It still tests local Loki, 30-day-configured Prometheus, Grafana, and the
log-only Cribl allow-list against `cribl-mock`. Local Alertmanager lifecycle
handling remains backlog work. The mock does
not prove production TLS, firewall, or 24-hour Cribl retention.

## Requirements

- macOS or Linux
- a local Unix-socket Docker context; SSH and TCP contexts are refused
- Docker Compose 2.24.4 or newer
- Ansible Core
- OpenSSL
- enough memory for the full stack
- access to the pinned DHI images, or a verified offline image seed

On macOS, add `--ask-become-pass` to the start and destroy playbook commands.
The Internal plane is `127.0.2.0/24`, and the ADM plane is `127.0.3.0/24`.
Their usable host listeners are `127.0.2.1` and `127.0.3.1`. Docker Desktop
cannot publish them until they exist as `/24` aliases on `lo0`. Ansible uses
sudo only for that bounded host step. Linux skips it and does not need sudo for
normal source-mode preprod. Do not put a become password in this repository.

## Start from source

From the repository root:

```bash
ansible-playbook -i ansible/inventory/preprod.yml ansible/preprod.yml
```

On macOS:

```bash
ansible-playbook -i ansible/inventory/preprod.yml ansible/preprod.yml \
  --ask-become-pass
```

This command creates the test CA and leaf certificates, builds the custom
images, starts the stack, initializes the test Vault, initializes identity,
configures the static users, enrolls WIF, rotates the test credential, and
checks the result.

To ask Docker to refresh every pinned base image before the build:

```bash
ansible-playbook -i ansible/inventory/preprod.yml ansible/preprod.yml \
  -e preprod_pull_images=true
```

This is the normal candidate-image test before an offline seed is transferred.
It does not weaken or remove any image pin.

## Local names

The play prints the exact `/etc/hosts` fragment without changing the file. To
let Ansible install that marker-bounded fragment:

```bash
ansible-playbook -i ansible/inventory/preprod.yml ansible/preprod.yml \
  -e preprod_manage_hosts=true --ask-become-pass
```

The fragment is:

```text
# BEGIN AIGW PREPROD MANAGED
127.0.2.1 api.aigw.internal portal.aigw.internal
127.0.3.1 auth.aigw.internal chat.aigw.internal admin.aigw.internal litellm-admin.aigw.internal grafana.aigw.internal prometheus.aigw.internal vault.aigw.internal
# END AIGW PREPROD MANAGED
```

Docker bridge addresses never go into `/etc/hosts`. Docker Desktop does not
route those addresses from the host. On macOS, Ansible creates only a missing
`127.0.2.1` or `127.0.3.1` alias. It records only aliases it created in the
root-only `/private/var/db/aigw-preprod/loopback-aliases-v1.json` file. Destroy
removes only those recorded aliases. An alias that existed before preprod is
never claimed or removed. The record is tied to the current macOS boot, so a
stale record cannot claim an address reused after a reboot. Linux already
supports these loopback binds and is left unchanged.

The generated test root is
`compose/secrets/preprod-root-ca.pem`. The play does not silently trust it at
the operating-system level. Import that certificate into a test browser or
test trust store when browser testing is needed. Remove it from the trust store
when preprod testing is complete.

## Static test users

These values are public test credentials. Never use them outside local
preprod.

| Username | Password | Access |
| --- | --- | --- |
| `preprod-admin` | `OnlyForTesting1!PreprodAdmin` | admin and chat |
| `preprod-developer` | `OnlyForTesting1!PreprodDeveloper` | developer portal and chat |
| `preprod-user` | `OnlyForTesting1!PreprodUser` | chat |

Samba serves only hostname-verified LDAPS at
`samba-ad.aigw.internal:636`. Its certificate and the edge and WIF mock
certificates are signed by the persistent ignored test root.

## Run the end-to-end check

The Ansible play runs the full end-to-end check after its internal health and
identity checks. A successful play prints `PREPROD_E2E_PASSED`.

To rerun only that check without another converge:

```bash
python3 -I scripts/test-e2e-preprod.py
```

The automated check does not require `/etc/hosts`: its preprod-only resolver
maps only the reviewed public FQDNs to `127.0.2.1` and `127.0.3.1` while
preserving the hostname for TLS, cookies, and Host routing. The optional hosts
fragment remains useful for manual browser testing.

The check proves:

- every expected long-running preprod service is running and healthy, while
  the `volume-init` one-shot is successfully exited;
- LDAP federation and the durable identity controller are ready;
- temporary bootstrap authority is gone;
- break-glass and Vault OIDC credentials are escrowed;
- Keycloak advertises `https://auth.aigw.internal/realms/aigw`;
- all three static users authenticate through LDAPS; the administrator reaches
  both portals, the developer reaches only the developer portal, and the
  ordinary user is denied both application surfaces after authentication;
- all three users complete Open WebUI's real OIDC callback and retain an
  authenticated chat session;
- the administrator completes the LiteLLM Admin, Grafana, and Prometheus
  oauth2-proxy callbacks, while both non-admin users authenticate at Keycloak
  and are denied at each callback boundary without receiving a session;
- every portal session completes the Keycloak logout chain and is cleared;
- the WIF provider is configured and enabled; and
- an HTTPS request through `127.0.2.1` reaches LiteLLM, exchanges a real
  Keycloak RS256 JWT at the TLS WIF mock, and returns `pong` from the mocked
  `/v1/messages` endpoint.

The WIF mock rejects a token unless its signature verifies against the live
Keycloak JWKS and its issuer, subject, audience, and lifetime match exactly.

## Test an offline seed

Seed mode uses the immutable transfer tags from the seed manifest. It removes
all Compose build sections, sets `pull_policy: never`, and compares every local
image ID with the loader's release receipt before startup. The `build` and
`pull` commands refuse to run in seed mode.

Immediately after `prepare`, you may test the transfer tags that are already in
the same Docker engine. This is a quick development check and does not unpack
the archive again:

```bash
python3 -I scripts/update-images.py test-preprod \
  --archive /absolute/path/ai-gateway-images.preprod.docker.tar.zst \
  --manifest /absolute/path/ai-gateway-images.preprod.manifest.json
```

Use the preprod-scoped pair created by `prepare`. A production-scoped manifest
is rejected because it does not contain the Samba AD and WIF mock images.

The final clean release test must add `--load-archive`. This proves the exact
archive can be loaded before Ansible starts seed mode:

```bash
python3 -I scripts/update-images.py test-preprod \
  --archive /absolute/path/ai-gateway-images.preprod.docker.tar.zst \
  --manifest /absolute/path/ai-gateway-images.preprod.manifest.json \
  --load-archive
```

On macOS, the normal Docker Desktop user verifies and loads the caller-owned
private release files. Also add `--ask-become-pass` so Ansible can create only
the missing owned loopback aliases.

On a rootful Linux controller, the updater
stages caller-owned files into a private root-owned boundary before invoking
the loader. Root loads only those staged copies. The normal operator then
verifies the release receipt against the caller-owned source tree and original
release files before preprod starts. Calling the Ansible play directly with
caller-owned files as root is unsupported because the root loader correctly
rejects their ownership.

On Linux, transferred-load mode requires a rootful Docker Engine. Before
loading, the updater proves that the operator's Docker context and
`/run/docker.sock` point to the same Unix socket. Rootless Docker and a
different local engine fail before the loader changes any images.

## Remove preprod

```bash
ansible-playbook -i ansible/inventory/preprod.yml ansible/preprod-destroy.yml \
  -e preprod_destroy_confirmation=DESTROY_AIGW_PREPROD
```

On macOS, append `--ask-become-pass`; Ansible removes only loopback aliases
listed in its root-only ownership record. Also add
`-e preprod_manage_hosts=true` if Ansible installed the hosts fragment.
Removal deletes only the named preprod containers, volumes, networks, owned
loopback aliases, and disposable Vault recovery record. It preserves the
generated test root and leaf certificates so browsers and clients do not see a
new CA on every run. The generated files live below ignored
`compose/secrets/` and are never committed.

The disposable directory implementation is maintained once under
`services/samba-ad-preprod`; no retired lab Compose file or profile is part of
the preproduction runtime.
