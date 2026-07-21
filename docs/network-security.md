# Production network security

This page explains the production network rules. Local preprod uses Docker
networks only. It does not test Rocky Linux routing or firewall rules. See
[local preprod](preprod.md).

The main rules are:

- no service listens on the egress connection;
- admins enter through ADM from the approved VPN range;
- users enter through the internal connection from the approved source range;
- services can talk only when they share an approved Docker network;
- only Envoy can use internet DNS and provider TCP port 443; and
- Keycloak gets one exact path to the customer LDAPS server; and
- Alloy gets one optional path to the Cribl endpoint.

Both `DOCKER-USER` and the `aigw_guard` nftables table enforce container packet
rules. Both must be active. See the [network diagrams](architecture-diagrams.md)
and [security model](security-model.md) for related controls.

## Exact allow rules

Each allow rule names an exact source range, host address, bridge, or container
address. There are no open firewall zones, wildcard listeners, or whole-subnet
shortcuts. Everything else is denied.

## 1. Host connections and firewall zones

The VM has three customer-owned network connections:

| Zone | Connection | Default action | Allowed inbound traffic |
| --- | --- | --- | --- |
| `aigw-egress` | egress NIC | `DROP` | None |
| `aigw-adm` | ADM NIC at `ETH1_IP` | `REJECT` | From `vpn_client_cidr`: management SSH and TCP 443. Optional platform DNS uses TCP and UDP 53. |
| `aigw-internal` | internal NIC at `ETH2_IP` | `REJECT` | From `internal_cidr`: TCP 443. Optional platform DNS uses TCP and UDP 53. |

All allows include an IPv4 source range. A plain open port, unknown service,
masquerade rule, or zone-forward rule fails verification. Denied packets are
logged with `--set-log-denied=unicast`.

NetworkManager stores each connection's firewall zone. A blank saved zone can
move a connection back to the default zone after a firewall reload. Ansible
therefore finds the one live connection UUID for each NIC and sets only
`connection.zone` when it is wrong. It does not change addresses or restart a
connection. A dispatcher script restores the zone after link events. Ansible
checks the same mapping in NetworkManager and in live and saved firewalld data.

## 2. Reply routing

The main route table has one default route on the egress NIC. Replies from ADM
and internal addresses must leave through the same NIC that received them.
Two extra route tables do this:

| Table | ID | Rule priority | Used for |
| --- | --- | --- | --- |
| `adm` | 101 | 10101 | replies from `ETH1_IP` |
| `internal` | 102 | 10102 | replies from `ETH2_IP` |

`/usr/local/sbin/aigw-policy-routing` first proves that the NIC owns the source
address and can reach its gateway. Each table must have one default route. The
script copies only that NIC's connected routes. It does not change the main
table or a NetworkManager profile.

A systemd unit applies the routes after NetworkManager is online. A dispatcher
hook restores them after link events. After the change, Ansible opens a new
key-only SSH session through ADM before it continues.

## 3. Docker networks

Ansible creates 20 fixed `/24` bridges in the `172.28.0.0/24` through
`172.28.20.0/24` range. `172.28.16.0/24` stays unused and reserved. Each active
network has a short, fixed bridge name such as `br-egress` or `br-vault`.

IPv6 is off. Fifteen networks use Docker's `internal` flag, so they have no NAT
path. The lower `.0/25` half of each subnet is reserved for fixed addresses.
Docker cannot give Envoy's fixed `172.28.0.2` address to another service.

Two non-internal bridges exist only so Docker can publish approved ports:
`net-int-edge` and the optional `net-platform-dns`. They have no app peers.
Both packet filters still block bridge egress.

Before any change, Ansible checks the Docker data root, foreign resources,
subnet overlap, drivers, bridge names, internal flags, subnets, and IP ranges.

## 4. Container packet filters

### `DOCKER-USER`

Ansible replaces the whole chain in one `iptables-restore` action. It never
updates rules one at a time. Rules run in this order:

1. Allow traffic on the same bridge.
2. Drop traffic between bridges, including `docker0`.
3. Allow established replies only in the reply direction.
4. Allow published traffic only for exact source, host IP, port, and DNAT
   matches. Drop all other physical-NIC traffic into Docker.
5. Allow only Envoy at `172.28.0.2` to use approved DNS and provider TCP 443 on
   egress. Allow only the exact Keycloak-to-LDAPS tuple on internal. If Cribl
   export is enabled, allow only the exact Alloy-to-Cribl tuple on internal.
6. Drop every other bridge-to-physical-network packet.

The IPv6 chain has no allow rules.

### `aigw_guard`

The separate `inet aigw_guard` nftables table stays active during a firewalld
reload. It has two hooks:

- `container_input` blocks containers from starting new connections to host
  services. Host-started replies may return.
- `container_forward` repeats the same-plane, cross-plane, published-port, and
  Envoy egress rules from `DOCKER-USER`.

Both policy units start before Docker. A watcher reapplies host rules and
`DOCKER-USER` after a firewalld reload. Ansible also proves that Docker's
`FORWARD` chain jumps to `DOCKER-USER` before it creates a network.

## 5. DNS paths

Ansible gives containers one of two DNS lists:

- `internal_dns_servers` is customer DNS on the ADM and internal paths.
- `egress_dns_servers` is internet DNS. Only Envoy can reach it through egress.

Every container gets an explicit resolver. This keeps DNS packets inside the
paths checked by both packet filters. Preflight rejects loopback, link-local,
and multicast DNS addresses. The two lists cannot overlap.

When `platform_authoritative_dns_enabled` is on, CoreDNS publishes TCP and UDP
53 only on the exact ADM and internal host addresses. See the
[service name list](fqdn-inventory.md).

## 6. Kernel settings

`/etc/sysctl.d/90-ai-gateway.conf` sets:

```text
net.ipv4.ip_forward=1
rp_filter=2
```

IP forwarding is needed for Docker bridges. Loose reverse-path checks are
needed for the reply routes above. Strict mode would drop valid replies.
Envoy egress is still safe because the TCP 443 rule also requires the
`br-egress` input bridge. A forged source address from another bridge does not
match.

## 7. Checks after every deploy

The `verify` role requires:

- one default route through egress;
- both source rules and both one-default route tables;
- the same zone owner in NetworkManager and live and saved firewalld data;
- the exact `DOCKER-USER` and `aigw_guard` rules;
- no physical allow based only on source and port;
- the exact settings for every Docker network; and
- only approved Traefik and optional DNS host ports, with no wildcard or
  egress listener.

Any mismatch fails the deployment.
