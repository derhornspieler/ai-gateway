# Service FQDN Inventory and DNS Design

This is the authoritative list of every fully-qualified domain name AI
Gateway exposes, what each one serves, and how name resolution is designed.
Hostnames are shown against the deployment's base domain (`<domain>`, e.g.
`aigw.example.com`); deliberately, **no IP addresses appear here** — the
addresses belong to each deployment's inventory and change per install. The
routing behind each name is defined in the Traefik file-provider
configuration and verified by the `verify` role on every converge.

## External FQDNs

| FQDN | Purpose | Leg | Notes |
|---|---|---|---|
| `<domain>` (apex) | DNS zone apex | — | NS/A records only; no HTTPS router answers on the apex |
| `dns.<domain>` | Authoritative, non-recursive platform DNS (TCP/UDP 53) | ADM + internal | Exists only when the platform-DNS overlay is enabled (`platform_authoritative_dns_enabled`) |
| `api.<domain>` | LiteLLM inference API (OpenAI/Anthropic-compatible) | Internal | Only the allow-listed inference/model/health paths; every other path on this host is an explicit 403 |
| `portal.<domain>` | Developer self-service portal (gateway keys, tool snippets) | Internal | |
| `auth.<domain>` | Keycloak | Internal + ADM | Internal edge serves only the scoped `aigw`-realm login paths; the full console and master realm are reachable only through the ADM edge |
| `chat.<domain>` | Open WebUI browser chat | Internal + ADM | The same OIDC client serves both source-restricted edges |
| `admin.<domain>` | Platform administration portal | ADM | |
| `litellm-admin.<domain>` | Native LiteLLM administration UI | ADM | Behind its oauth2-proxy gate; `/openapi.json`, `/docs`, `/redoc` are denied |
| `grafana.<domain>` | Grafana dashboards | ADM | Behind its oauth2-proxy gate |
| `prometheus.<domain>` | Prometheus UI | ADM | Behind its oauth2-proxy gate |
| `vault.<domain>` | Vault browser UI and `/v1` API proxy | ADM | Exists only when the optional Vault UI profile is enabled (`aigw_vault_ui_enabled`); router and backend are omitted otherwise |

Two non-entries worth stating explicitly: the VM's own hostname needs no
platform DNS record, and `keycloak.<domain>` is a stale historical name that
was never implemented — use `auth.<domain>`.

**Everything else has no external FQDN.** This includes PostgreSQL, Redis,
Vault's internal API, Envoy, key-rotator, the oauth2-proxy gates, Alloy, Loki,
node-exporter, cribl-mock, Samba AD, and the Traefik edges. They use private
Docker DNS names on isolated bridges and cannot be reached from a physical
network.

## DNS resolution design

Name resolution is split into two non-overlapping planes; the firewall
enforces the split, not just configuration.

**Internal plane — the customer's DNS.** Internal services, users, and
administrators resolve `<domain>` names through `internal_dns_servers`. Put
the records in corporate DNS, or point approved clients at `dns.<domain>` when
the optional platform DNS is enabled. Platform DNS uses separate views and
never sends a query to another DNS server. The internal view shows only user
records. The ADM view also shows administration records, so user-network DNS
does not reveal the admin surface. Every container except Envoy uses this
internal DNS plane.

**Egress plane — internet DNS, Envoy only.** Envoy resolves vendor APIs through
the internet servers in `egress_dns_servers`. For this deployment, they are
`1.1.1.1` and `9.9.9.9`. Queries leave only through the egress interface. Both
packet filters allow only Envoy's fixed address. No other container or host
process may use an internet resolver. The internal and egress resolver lists
cannot overlap. Preflight also rejects loopback, link-local, and multicast
addresses.

**Expected resolution per audience:**

| Who | Resolves via | Should resolve |
|---|---|---|
| Internal users | corporate DNS (or `dns.<domain>` internal view) | `chat`, `portal`, `api`, `auth` → internal leg address |
| Administrators (VPN) | corporate DNS (or `dns.<domain>` ADM view) | `auth`, `chat`, `admin`, `litellm-admin`, `grafana`, `prometheus`, and optional `vault` → ADM leg address; `api` and `portal` → internal leg address |
| Gateway containers | per-plane resolvers rendered by Ansible | internal names via internal plane; Envoy alone via internet plane |

The `verify` role resolves and probes each name after every converge, so a
missing or wrong record fails the deployment rather than surfacing as a
user-reported outage.

## The certificate that covers all of them

Every published name above is a **one-level subdomain of the base domain**, so a
single edge certificate with

```
SAN = DNS:*.<domain>, DNS:<domain>
```

covers every FQDN on **both** edges. `scripts/edge-tls.py` enforces exactly this
shape: it refuses edge material whose SAN is missing either the wildcard or the
apex, so a certificate that would leave one vhost unservable cannot reach the
live store. The apex entry is not decorative — a `*.<domain>` wildcard does not
match the bare `<domain>`.

Both Traefik edges read the same store (`certs/int.crt` + `certs/int.key`).
HTTPS terminates there and nowhere else; traffic behind the edges is plain HTTP
on segmented internal bridges. See [operations](operations.md) §"Production edge
TLS" for the three supported certificate modes and their ceremony commands.

> If the signing CA carries `nameConstraints`, `<domain>` must fall within a
> permitted DNS subtree or the chain will not verify. Pick the base domain to
> satisfy the CA before deploying, not after.
