# Platform authoritative DNS

This is the optional authoritative, non-recursive CoreDNS service for the
configured AI Gateway domain. Ansible renders its two zone views from
`aigw_domain`, `eth1_ip`, and `eth2_ip`; the files in this source directory are
validation fixtures only. It is loaded only when
`platform_authoritative_dns_enabled=true`.

The service binds TCP and UDP port 53 only on the target's exact ADM and
internal addresses, never the egress address, and has no forwarding plugin.
The host firewall accepts those listeners only from the corresponding source
CIDRs. Its dedicated no-peer bridge plus the DOCKER-USER and independent
nftables policies deny all container-originated egress.

Records intentionally split the two Traefik edges:

| Name | Answer | Plane |
| --- | --- | --- |
| `admin.<domain>` | `eth1_ip` | ADM |
| `grafana.<domain>` | `eth1_ip` | ADM |
| `litellm-admin.<domain>` | `eth1_ip` | ADM |
| `prometheus.<domain>` | `eth1_ip` | ADM |
| `vault.<domain>` | `eth1_ip` when the Vault UI is enabled | ADM |
| `api.<domain>` | `eth2_ip` | internal |
| `auth.<domain>` | `eth1_ip` or `eth2_ip`, based on the DNS view | ADM full console; internal user-realm routes only |
| `chat.<domain>` | `eth1_ip` or `eth2_ip`, based on the DNS view | ADM and internal |
| `portal.<domain>` | `eth2_ip` | internal |

`auth.<domain>` is the only public Keycloak name. The internal edge serves only
the browser routes needed for the `aigw` realm. The ADM edge serves the full
console, master realm, and administration API. There is no public
`keycloak.<domain>` record. Vault is reachable only through the ADM `vault`
route, which applies an `aigw-admins` OIDC gate before Vault's own login. The
Anthropic WIF fabricated issuer remains deliberately non-resolvable and is not
part of this zone.

Verify both views against the target addresses declared in inventory:

```sh
scutil --dns | grep -A5 '<domain>'
dig @<ADM-IP> admin.<domain> A +short
dig @<ADM-IP> auth.<domain> A +short
dig @<INTERNAL-IP> auth.<domain> A +short
dig @<INTERNAL-IP> portal.<domain> A +short
dig @<ADM-IP> example.com A +noall +comments
```

The last query must return `NXDOMAIN`; the platform DNS service must never
recurse. Clients may use the service directly or through a domain-scoped
resolver configured by the customer's DNS administrators.
