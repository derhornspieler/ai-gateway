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
| `chat.<domain>` | Open WebUI browser chat | **ADM** | Routed on the ADM edge in the current implementation; the internal DNS view carries no `chat` record |
| `admin.<domain>` | Platform administration portal | ADM | |
| `admin-portal.<domain>` | Legacy alias | ADM | Permanent redirect to `admin.<domain>` |
| `litellm-admin.<domain>` | Native LiteLLM administration UI | ADM | Behind its oauth2-proxy gate; `/openapi.json`, `/docs`, `/redoc` are denied |
| `grafana.<domain>` | Grafana dashboards | ADM | Behind its oauth2-proxy gate |
| `prometheus.<domain>` | Prometheus UI | ADM | Behind its oauth2-proxy gate |
| `vault.<domain>` | Vault browser UI and `/v1` API proxy | ADM | Exists only when the optional Vault UI profile is enabled (`aigw_vault_ui_enabled`); router and backend are omitted otherwise |

Two non-entries worth stating explicitly: the VM's own hostname needs no
platform DNS record, and `keycloak.<domain>` is a stale historical name that
was never implemented — use `auth.<domain>`.

**Everything else has no external FQDN.** PostgreSQL, Redis, Vault's internal
API, Envoy, key-rotator, the oauth2-proxy gates, Alloy, Loki, Tempo,
node-exporter, cribl-mock, Samba AD, and the Traefik edges themselves are
addressed only by private Docker DNS names on their isolated bridges and are
unreachable from any physical network.

## DNS resolution design

Name resolution is split into two non-overlapping planes; the firewall
enforces the split, not just configuration.

**Internal plane — the customer's DNS.** Internal services and every user
and administrator resolve `<domain>` names through the internal/corporate
DNS (`internal_dns_servers`). The records above live there — either entered
directly in the corporate DNS, or by pointing clients and resolvers at the
platform's own authoritative server (`dns.<domain>`) when the platform-DNS
overlay is enabled. The platform DNS is split-view and non-recursive: clients
arriving on the internal leg see only the user-facing records, while clients
on the ADM leg additionally see the administrative records — so the admin
surface is not even discoverable from the user network. Every container
plane except Envoy resolves exclusively against this internal plane.

**Egress plane — internet DNS, Envoy only.** The gateway's sole outbound
identity, Envoy, resolves AI vendor APIs through the internet resolvers
configured in `egress_dns_servers` — for this deployment, `1.1.1.1` and
`9.9.9.9` — over the egress interface only. Both packet-filter planes pin
this allowance to Envoy's exact fixed address; no other container, and no
host process, may reach an internet resolver. The two resolver lists may not
overlap, and loopback/link-local/multicast values are rejected at preflight.

**Expected resolution per audience:**

| Who | Resolves via | Should resolve |
|---|---|---|
| Internal users | corporate DNS (or `dns.<domain>` internal view) | `chat`* , `portal`, `api`, `auth` → internal leg address |
| Administrators (VPN) | corporate DNS (or `dns.<domain>` ADM view) | all of the above plus `admin`, `admin-portal`, `litellm-admin`, `grafana`, `prometheus`, `vault`, `chat` → ADM leg address |
| Gateway containers | per-plane resolvers rendered by Ansible | internal names via internal plane; Envoy alone via internet plane |

\* `chat.<domain>` currently resolves and routes only on the ADM leg — see
the inventory note above.

The `verify` role resolves and probes each name after every converge, so a
missing or wrong record fails the deployment rather than surfacing as a
user-reported outage. TLS certificates must cover each name on its
respective edge; see the [deployment guide](deploy-guide.md) §"DNS and
certificates".
