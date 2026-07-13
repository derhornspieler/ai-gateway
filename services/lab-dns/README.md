# Lab DNS

This is an authoritative, non-recursive CoreDNS configuration for the local
`aigw.internal` test domain. It is loaded only by the lab Compose
overlay. The service binds TCP and UDP port 53 only on the VM's exact ADM and
internal addresses, never the egress address, and has no forwarding plugin.
The host firewall accepts those listeners only from the corresponding
ADM/internal source CIDRs. Its dedicated bridge has no application peers, and
the host's DOCKER-USER plus independent nftables guard deny all
container-originated egress.

Records intentionally split the two Traefik edges:

| Name | Lab address | Plane |
| --- | --- | --- |
| `admin.aigw.internal` | `10.8.10.10` | ADM |
| `admin-portal.aigw.internal` | `10.8.10.10` | ADM |
| `grafana.aigw.internal` | `10.8.10.10` | ADM |
| `keycloak.aigw.internal` | `10.8.10.10` | ADM |
| `prometheus.aigw.internal` | `10.8.10.10` | ADM |
| `vault.aigw.internal` | `10.8.10.10` | ADM |
| `api.aigw.internal` | `10.20.0.10` | internal |
| `auth.aigw.internal` | `10.20.0.10` | internal user-realm issuer only |
| `chat.aigw.internal` | `10.20.0.10` | internal |
| `portal.aigw.internal` | `10.20.0.10` | internal |

`auth` and `keycloak` are intentionally different hostnames. The internal edge
serves only the `aigw` realm and static Keycloak resources through `auth`; the
master realm, administration console, and API are available only through the
ADM `keycloak` name. Vault is reachable only through the ADM `vault` route,
which applies an `aigw-admins` OIDC gate before Vault's own login. The
Anthropic WIF fabricated issuer remains deliberately non-resolvable and is not
part of this zone.

## macOS scoped resolver

After the VM DNS service is healthy, install a domain-scoped resolver on the
Mac. This does not replace the Mac's normal DNS servers:

```sh
sudo install -d -m 755 /etc/resolver
printf 'nameserver 10.8.10.10\nport 53\ntimeout 2\n' | \
  sudo tee /etc/resolver/aigw.internal >/dev/null
sudo chmod 644 /etc/resolver/aigw.internal
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder
```

Verify the scoped resolver and both address planes:

```sh
scutil --dns | grep -A5 'aigw.internal'
dig +short admin.aigw.internal
dig +short admin-portal.aigw.internal
dig +short auth.aigw.internal
dig +short keycloak.aigw.internal
dig +short portal.aigw.internal
dig @10.8.10.10 example.com A +noall +comments
```

The last query must return `NXDOMAIN`; it must never recurse.

Trust the lab root CA from `/opt/ai-gateway/certs/ca.pem` only after comparing
its SHA-256 fingerprint with the VM copy. Install it into a disposable test
keychain, not a customer or production trust store.
