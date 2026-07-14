# Network Architecture and Enforcement

This document describes how AI Gateway's routing, host interfaces, firewalld
zones, iptables (`DOCKER-USER`), and native nftables policy connect into one
layered, fail-closed network design. It is a customer-facing reference for
the implemented configuration in `ansible/roles/network_routing`,
`ansible/roles/firewalld_zones`, and `ansible/roles/docker_networks`.
Companion visuals are in [technical diagrams](architecture-diagrams.md);
component detail is in the [solution map](solution-map.md).

## Design principle

Every allow rule is pinned to an exact identity — a source CIDR, a specific
host address, a specific bridge, or a specific container IP. There are no
zone-wide port openings, no wildcard binds, and no "allow the subnet"
shortcuts. Two independent enforcement planes (iptables `DOCKER-USER` and a
native nftables table) carry the same policy, so a transient failure or
reload of one cannot open the other.

## 1. Host interfaces and firewalld zones

The VM's three customer-owned interfaces map to three dedicated zones. The
zones are deliberately named with an `aigw-` prefix so no firewalld built-in
zone template is silently activated.

| Zone | Interface | Target | Permitted inbound |
|---|---|---|---|
| `aigw-egress` | egress NIC | `DROP` | nothing — no listener exists on this leg |
| `aigw-adm` | ADM NIC (`ETH1_IP`) | `REJECT` | source `vpn_client_cidr` only: management SSH port/tcp and 443/tcp (lab profile adds 53 tcp+udp) |
| `aigw-internal` | internal NIC (`ETH2_IP`) | `REJECT` | source `internal_cidr` only: 443/tcp (lab profile adds 53 tcp+udp) |

All permissions are IPv4 source-scoped rich rules; verification fails if any
zone carries a plain port opening, an unexpected service, masquerade, or
intra-zone forwarding. Denied packets are logged (`--set-log-denied=unicast`).

**Zone persistence is anchored in NetworkManager, not firewalld alone.** On
Rocky 9, NetworkManager is authoritative for an active interface's zone: a
profile whose saved `connection.zone` is blank re-advertises its interface
into the default zone after a firewalld reload. Ansible therefore resolves
the one active connection UUID per interface, verifies all three UUIDs are
valid and distinct, and persists only a drifted `connection.zone` — it never
cycles, reactivates, or readdresses a connection. A NetworkManager dispatcher
script (`91-aigw-firewalld-zones`) reasserts runtime zone ownership after
link events. Verification requires the same interface-to-zone mapping in the
saved profile, firewalld runtime, and firewalld permanent configuration.

## 2. Source-policy routing

The main routing table keeps exactly one default route, through the egress
interface. So that ADM and internal replies leave on the leg they arrived
on, Ansible installs two additive policy tables:

| Table | ID | Rule priority | Scope |
|---|---|---|---|
| `adm` | 101 | 10101 | replies sourced from `ETH1_IP` |
| `internal` | 102 | 10102 | replies sourced from `ETH2_IP` |

The applicator (`/usr/local/sbin/aigw-policy-routing`) refuses to act unless
the interface actually owns the source address and the gateway resolves on
that interface; each table must contain exactly one default route. It copies
only the interface's connected routes into the policy table and never touches
the main table or any NetworkManager profile. Persistence is a oneshot
systemd unit ordered after `NetworkManager-wait-online.service` plus a
dispatcher hook for interface events. If Rocky's `/etc/iproute2/rt_tables`
override is absent, Ansible seeds it from the vendor registry rather than
shadowing standard table names. After applying routing, the play proves a
fresh key-only SSH connection over the ADM leg from inside `vpn_client_cidr`
before continuing.

## 3. Container network planes

Ansible pre-creates 20 fixed bridges (`172.28.0.0/24` through
`172.28.19.0/24`), each pinned to a stable, short Linux bridge name
(`br-egress`, `br-chat`, `br-vault`, …) so firewall rules can reference
bridges as a stable ABI. IPv6 is disabled on every bridge. Fifteen planes are
Docker-`internal` (no NAT path); the lower half of every subnet (`.0/25`) is
reserved for fixed workload addresses so Compose cannot allocate a firewall-
pinned address (such as Envoy's `172.28.0.2`) to an ordinary service.

Two ordinary (non-internal) bridges exist solely so Docker will render
published-port DNAT — Docker omits publication when every attached network is
`internal` — and carry no application peers: `net-int-edge` (traefik-int)
and the lab-only `net-lab-dns`. Their bridge-originated egress is still
denied by both packet-filter planes.

A read-only preflight audits the live daemon before any change: correct data
root, no foreign containers or networks, no subnet overlap with the default
bridge or address pools, and exact per-network contracts (driver, internal
flag, bridge name, subnet, IP range).

## 4. Packet filtering — two independent planes

### 4.1 iptables `DOCKER-USER` (forward path)

The complete chain is replaced in a single atomic
`iptables-restore --wait --noflush` transaction — never rule-by-rule, so no
fail-open interval exists during updates. Rule groups, in order:

1. Same-bridge traffic returns (a plane may talk to itself).
2. Cross-bridge traffic is dropped in both directions, including to and from
   `docker0`.
3. Established/related traffic is accepted **only in the reply direction** —
   a deliberate narrowing so a flow opened during a reload gap cannot remain
   authorized.
4. Inbound publication is accepted only as an exact DNAT tuple: ADM-sourced
   (`vpn_client_cidr`) TCP/443 whose original destination is exactly
   `ETH1_IP:443`, and internal-sourced TCP/443 to exactly `ETH2_IP:443`
   (plus lab DNS equivalents). All other physical-interface ingress into the
   bridge fabric is dropped.
5. Container egress is accepted only for Envoy's exact address
   (`172.28.0.2/32` on `br-egress`): DNS to the one approved resolver, and
   TCP/443 out the egress NIC. The subnet is deliberately not allowed —
   only the pinned /32. An optional, exactly-tupled Alloy-to-Cribl export on
   the internal NIC is the only other egress allowance.
6. Default deny: any bridge-to-non-bridge traffic is dropped.

The IPv6 chain is the fail-closed subset — no allow rules at all.

### 4.2 Native nftables guard (`inet aigw_guard`)

`DOCKER-USER` protects only the forward path and can be transiently flushed
by a firewalld reload. The independent `aigw_guard` table closes both gaps,
rebuilt atomically per run:

- `container_input` (input hook, priority −5): containers may never initiate
  new connections to host listeners; only host-initiated replies return.
  This covers all managed bridges, `docker0`, and any future `br-*`.
- `container_forward` (forward hook, priority −5): a native mirror of the
  `DOCKER-USER` policy — same-plane accept, cross-plane deny, exact DNAT
  tuples, Envoy-pinned egress — that stays live even while firewalld's
  reload momentarily removes `DOCKER-USER`.

### 4.3 Ordering and reload defense

Both policy units are ordered `Before=docker.service`, so the packet policy
is live before Docker can publish a port. A watch service subscribes to
firewalld's D-Bus `Reloaded` signal and immediately reapplies the host-input
rules and `DOCKER-USER` after every reload. The `docker_networks` role
additionally asserts that Docker's `FORWARD` chain actually jumps to
`DOCKER-USER` before creating any network.

## 5. Container DNS enforcement

DNS is split into two non-overlapping resolver planes, rendered by Ansible
into a dedicated `docker-compose.dns.yml` overlay (the legacy shared
`CONTAINER_DNS_SERVER` variable is gone): `internal_dns_servers` (the
corporate/ADM resolver plane, reachable only via the ADM and internal legs)
and `egress_dns_servers` (the Internet resolver plane, reachable only by
Envoy over the egress leg). Explicit per-container resolvers matter on
Docker 29: an inherited host resolver is dialed by `dockerd` from the host
namespace and would bypass the forward path entirely, whereas explicit
per-plane resolvers keep queries inside the container namespace where
`DOCKER-USER` and `aigw_guard` enforce them. Loopback, link-local, and
multicast values are rejected at preflight, the two lists may not overlap,
and only Envoy's pinned address may reach an Internet resolver. When the
platform runs its own authoritative DNS
(`platform_authoritative_dns_enabled`, default on only for the lab profile),
the `docker-compose.platform-dns.yml` overlay adds the CoreDNS service,
which then publishes port 53 on the exact ADM and internal host addresses.
The complete hostname inventory and per-audience resolution design are in the
[FQDN inventory](fqdn-inventory.md).

## 6. Kernel settings

`/etc/sysctl.d/90-ai-gateway.conf` sets `net.ipv4.ip_forward=1` (required
for bridges) and **loose** reverse-path filtering (`rp_filter=2`) on the ADM
and internal interfaces. Loose mode is deliberate: strict mode would drop the
asymmetric replies that source-policy routing produces. Egress anti-spoofing
does not depend on rp_filter — the TCP/443 egress allowance is pinned to the
`br-egress` ingress interface, so a container on another plane forging an
egress-subnet source address still matches no allow rule.

## 7. What verification asserts

The `verify` role re-derives the contract from the live host after every
converge: exactly one default route on the egress NIC; both policy rules and
their single-default tables; every zone's runtime, saved, and permanent
interface ownership; the presence of the identity-pinned `DOCKER-USER` and
`aigw_guard` rules (and the absence of any source/port-only physical
accept); per-network driver, internal, bridge-name, subnet, and IP-range
contracts; and published ports limited to exactly the two Traefik binds
(plus lab DNS), never a wildcard or the egress address.
