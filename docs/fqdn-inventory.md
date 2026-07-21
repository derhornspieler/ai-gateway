# Service names and DNS

This page lists every full DNS name, or FQDN, that AI Gateway publishes. It
also says what each name does. `<domain>` means the base domain for one
install, such as `aigw.example.com`.

IP addresses are not listed here. They belong in that install's Ansible
inventory. Traefik routes each name to the right service. Ansible checks every
route after each deploy.

## External FQDNs

| FQDN | Purpose | Leg | Notes |
|---|---|---|---|
| `<domain>` (apex) | Base of the DNS zone | — | DNS records only. No HTTPS route uses this name. |
| `dns.<domain>` | Platform DNS on TCP/UDP 53 | ADM + internal | Exists only when `platform_authoritative_dns_enabled` is on. It answers from its own records and does not forward queries. |
| `api.<domain>` | LiteLLM inference API (OpenAI/Anthropic-compatible) | Internal | Only approved inference, model, and health paths work. Every other path returns 403. |
| `portal.<domain>` | Developer self-service portal (gateway keys, tool snippets) | Internal | |
| `auth.<domain>` | Keycloak | Internal + ADM | The internal edge serves only `aigw` realm login paths. The full console and master realm are ADM-only. |
| `chat.<domain>` | Open WebUI browser chat | Internal + ADM | The same OIDC client serves both source-restricted edges |
| `admin.<domain>` | Platform administration portal | ADM | |
| `litellm-admin.<domain>` | Native LiteLLM administration UI | ADM | Behind its oauth2-proxy gate; `/openapi.json`, `/docs`, `/redoc` are denied |
| `grafana.<domain>` | Grafana dashboards | ADM | Behind its oauth2-proxy gate |
| `prometheus.<domain>` | Prometheus UI | ADM | Behind its oauth2-proxy gate |
| `vault.<domain>` | Vault browser UI and `/v1` API proxy | ADM | Exists only when `aigw_vault_ui_enabled` is on. The route and service do not exist when it is off. |

The VM hostname does not need a platform DNS record. Do not use
`keycloak.<domain>`. That old name was never active. Use `auth.<domain>`.

Every other service stays private. This includes PostgreSQL, Redis, Vault's
internal API, Envoy, key-rotator, the OAuth2 Proxy gates, Alloy, Loki,
node-exporter, the Cribl mock, Samba AD, and both Traefik edges. They use
private Docker names on isolated networks. A physical network cannot reach
them directly.

## DNS resolution design

DNS uses two separate paths. The firewall enforces this split.

**Internal path: customer DNS.** Internal services, users, and admins resolve
`<domain>` through `internal_dns_servers`. Put the records in corporate DNS.
You may instead point approved clients at `dns.<domain>` when platform DNS is
on. Platform DNS has separate internal and ADM views. The internal view shows
only user names. The ADM view also shows admin names. Platform DNS never sends
a query to another DNS server. Every container except Envoy uses this path.

**Egress path: internet DNS for Envoy only.** Envoy resolves provider API names
through `egress_dns_servers`. The current values are `1.1.1.1` and `9.9.9.9`.
Queries leave only through the egress interface. Both packet filters allow
only Envoy's fixed address. No other container or host process may use these
resolvers. The internal and egress DNS lists cannot overlap. Preflight also
rejects loopback, link-local, and multicast addresses.

**Expected resolution per audience:**

| Who | Resolves via | Should resolve |
|---|---|---|
| Internal users | corporate DNS (or `dns.<domain>` internal view) | `chat`, `portal`, `api`, `auth` → internal leg address |
| Administrators (VPN) | corporate DNS (or `dns.<domain>` ADM view) | `auth`, `chat`, `admin`, `litellm-admin`, `grafana`, `prometheus`, and optional `vault` → ADM leg address; `api` and `portal` → internal leg address |
| Gateway containers | per-plane resolvers rendered by Ansible | internal names via internal plane; Envoy alone via internet plane |

The `verify` role checks each name after every deploy. A missing or wrong DNS
record stops the deploy.

## The certificate that covers all of them

Every published service name is one level below the base domain. One edge
certificate can therefore cover all names when it has these values:

```
SAN = DNS:*.<domain>, DNS:<domain>
```

`scripts/edge-tls.py` requires both values. It rejects a certificate that is
missing either one. The base-domain entry matters because `*.<domain>` does
not match the bare `<domain>`.

Both Traefik edges read `certs/int.crt` and `certs/int.key`. They end the HTTPS
connection. Traffic behind them uses plain HTTP only on isolated Docker
networks. See [operations](operations.md#production-edge-tls) for the three
certificate modes and their commands.

> If the signing CA has `nameConstraints`, `<domain>` must be in an allowed DNS
> tree. Check this before you deploy. Otherwise, certificate checks will fail.
