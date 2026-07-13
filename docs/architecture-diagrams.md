# AI Gateway — Technical Diagrams

This document is the visual companion to the
[solution map](solution-map.md). Each diagram reflects the implemented
configuration in `compose/`, `ansible/`, and `services/`; where a diagram
simplifies, the solution map's tables remain authoritative. Diagrams render
natively on GitHub/GitLab (Mermaid).

## 1. Network topology and trust zones

Three customer-owned interfaces map to three firewalld zones with distinct
inbound policy. Nothing publishes a listener on the egress leg; only the two
Traefik edges publish container ports, each bound to its exact host address.

```mermaid
flowchart TB
  INET[Internet — AI vendor APIs]
  VPN[Administrators via VPN<br/>vpn_client_cidr]
  USERS[Internal users and AI tools<br/>internal_cidr]

  subgraph vm [Rocky Linux 9 VM]
    subgraph zegress [zone aigw-egress]
      NIC0[egress NIC<br/>target DROP, no listener<br/>only default route]
    end
    subgraph zadm [zone aigw-adm]
      NIC1[ADM NIC — ETH1_IP<br/>TCP/22 + TCP/443<br/>from VPN CIDR only]
    end
    subgraph zint [zone aigw-internal]
      NIC2[internal NIC — ETH2_IP<br/>TCP/443<br/>from internal CIDR only]
    end
    EV[Envoy egress 172.28.0.2<br/>sole workload allowed external DNS + TCP/443]
    TA[traefik-adm :443]
    TI[traefik-int :443]
  end

  EV -->|pinned TLS, exact SANs,<br/>narrowed per-vendor CAs| NIC0 --> INET
  VPN -->|SSH + admin HTTPS| NIC1 --> TA
  USERS -->|user HTTPS| NIC2 --> TI
```

Reply traffic for the ADM and internal legs uses source-policy routing
(tables 101/102) so responses leave through the interface they arrived on.

## 2. Segmented container planes

The stack pre-creates 20 Docker bridges and uses 18 in the base profile;
services join only the planes they need, and both an atomic `DOCKER-USER`
chain and an independent native nftables guard (`aigw_guard`) deny
cross-plane, container-to-host, and unapproved egress traffic. The full
per-bridge membership table is in the solution map.

```mermaid
flowchart LR
  subgraph edge [Edge planes]
    E1[net-internal / net-int-edge<br/>traefik-int + user apps]
    E2[net-adm / net-admin-app / net-grafana<br/>traefik-adm + admin gates]
  end
  subgraph app [Application planes]
    A1[net-chat / net-portal<br/>Open WebUI, portals, LiteLLM, Keycloak]
    A2[net-vendor<br/>LiteLLM, key-rotator → Envoy]
  end
  subgraph data [Data planes]
    D1[net-db-litellm / net-db-keycloak / net-db-rotator<br/>three isolated paths to Postgres]
    D2[net-cache — Redis]
    D3[net-vault — Vault + key-rotator + Vault gate]
  end
  subgraph obs [Telemetry planes]
    O1[net-telemetry / net-traces / net-observability / net-metrics<br/>Alloy, Tempo, Loki, Prometheus, Grafana, node-exporter]
  end
  E1 --- A1
  E2 --- A1
  A1 --- D1
  A1 --- D2
  A2 --- G[net-egress<br/>Envoy only]
  A1 -.OTLP.-> O1
  D3 --- A1
```

## 3. Software flow — user, developer, and administrator paths

```mermaid
flowchart LR
  U[User browser] -->|chat.DOMAIN| TI[traefik-int]
  T[AI tool with gateway key] -->|api.DOMAIN /v1| TI
  D[Developer browser] -->|portal.DOMAIN| TI
  A[Administrator browser] -->|admin hosts on ADM leg| TA[traefik-adm]

  TI --> OW[Open WebUI] --> LL[LiteLLM]
  TI -->|inference allow-list| LL
  TI --> DP[dev-portal]
  TI -->|aigw realm only| KC[Keycloak]

  TA --> AP[admin-portal]
  TA --> O2[oauth2-proxy gates ×4] -->|aigw-admins| ADM_UIS[LiteLLM Admin / Grafana / Prometheus / Vault UIs]
  TA -->|auth.DOMAIN full console| KC

  DP -->|key lifecycle| KR[key-rotator]
  AP -->|identity + rotation control| KR
  LL -->|vendor path| EV[Envoy egress] --> V[Anthropic / OpenAI]
  KR --> EV
  LL & KC & KR --> PG[(Postgres)]
  LL --> RD[(Redis)]
  KR --> VT[(Vault)]
```

## 4. Authentication flow — browser OIDC and admin gates

All human access authenticates against Keycloak realm `aigw`, which emits
the three realm roles (`aigw-users`, `aigw-developers`, `aigw-admins`) in a
`roles` claim. Admin UIs sit behind dedicated oauth2-proxy instances.

```mermaid
sequenceDiagram
  autonumber
  participant B as Browser
  participant T as Traefik edge
  participant P as oauth2-proxy (admin UIs only)
  participant K as Keycloak (realm aigw)
  participant S as Upstream service

  B->>T: HTTPS request
  T->>P: route (ADM admin UIs) / direct OIDC app (chat, portals)
  P->>B: redirect to Keycloak authorization endpoint
  B->>K: authenticate (directory-federated user)
  K-->>B: authorization code
  B->>P: callback with code
  P->>K: exchange code, validate roles claim
  alt roles include required role
    P->>S: proxy request (encrypted session cookie)
    S-->>B: application response
  else missing role
    P-->>B: access denied
  end
```

Admin-portal mutations additionally require a CSRF token and a fresh
Keycloak step-up (`prompt=login`, `max_age=0`) within a five-minute window,
and every page read re-checks the caller's live composite roles — a revoked
administrator fails closed even with a valid session cookie.

## 5. Logic flow — developer key lifecycle

Group membership in Keycloak is the authorization source; LiteLLM virtual
keys are always derived from it and revoked with it.

```mermaid
flowchart TD
  S([Developer opens dev-portal]) --> AUTHZ{Token carries<br/>aigw-developers?}
  AUTHZ -- no --> DENY([Denied])
  AUTHZ -- yes --> PROJ{Live member of a managed<br/>project group? — verified via key-rotator}
  PROJ -- no --> DENY
  PROJ -- yes --> MINT[key-rotator mints scoped LiteLLM virtual key<br/>project ID = group name in key metadata]
  MINT --> SHOW[One-time plaintext key shown once<br/>never stored or logged]
  SHOW --> USE[AI tool calls api.DOMAIN /v1 with key]
  REM([Admin removes member from group]) --> KILL[key-rotator logs user out of Keycloak<br/>and deactivates that subject's project keys<br/>before and after the membership change]
```

## 6. Security flow — provider credential rotation (Anthropic WIF)

No long-lived vendor API key sits in application configuration. key-rotator
brokers a short-lived Anthropic token through Keycloak's isolated
`anthropic-wif` realm using `private_key_jwt`; the private key exists only
in Vault (or a mounted PEM) and every vendor call leaves through Envoy.

```mermaid
sequenceDiagram
  autonumber
  participant KR as key-rotator
  participant VT as Vault (KV-v2)
  participant KC as Keycloak (realm anthropic-wif)
  participant EV as Envoy egress
  participant AN as Anthropic API

  KR->>VT: read client private key<br/>(ai-gateway/anthropic-wif-client-key)
  KR->>KC: token request as anthropic-token-broker<br/>client assertion: private_key_jwt (RS256, 3072-bit)
  KC-->>KR: workload identity JWT<br/>sub=service-account-anthropic-token-broker<br/>aud contains https://api.anthropic.com (600 s lifespan)
  KR->>EV: POST /v1/oauth/token (WIF exchange)
  EV->>AN: pinned TLS, exact SAN, narrowed CA
  AN-->>KR: short-lived sk-ant-oat01 access token
  KR->>KR: install token as LiteLLM provider credential<br/>(anthropic-primary), schedule refresh
```

## 7. Security design — layered enforcement

Each layer fails closed independently; compromising one does not disable the
others.

```mermaid
flowchart TB
  L1[Host ingress — firewalld zones:<br/>exact source CIDRs, SSH key-only on ADM,<br/>no egress-leg listener]
  L2[Packet policy — atomic DOCKER-USER +<br/>independent nftables aigw_guard:<br/>deny cross-plane, container-to-host,<br/>unapproved bridge egress]
  L3[Network segmentation — 18 per-function bridges;<br/>services join only required planes;<br/>fixed IPs for firewall-addressed workloads]
  L4[Identity — Keycloak OIDC everywhere;<br/>three realm roles; per-UI oauth2-proxy gates;<br/>step-up + live-role re-checks for admin mutations]
  L5["Secrets — Vault-backed provider credentials;<br/>file-backed Docker secrets; no secret in argv/env;<br/>fail-closed blank-variable Compose contract"]
  L6[Runtime — SELinux enforcing with per-container MCS;<br/>non-root DHI images, digest-pinned;<br/>read-only binds with keyed HMAC digests;<br/>no Docker socket exposure]
  L7[Egress — Envoy as the only external identity:<br/>exact routes, exact SANs, per-vendor CA bundles]
  L1 --> L2 --> L3 --> L4 --> L5 --> L6 --> L7
```

## 8. Telemetry flow

Prompts and completions are sensitive: they travel as Tempo trace attributes
(and optionally to Cribl), never as ordinary Loki log records. Retention and
redaction rules are in
[observability operations](observability-operations.md).

```mermaid
flowchart LR
  LL[LiteLLM<br/>full AI spans] -->|OTLP| AL[Alloy]
  DP[Portals] -->|OTLP/logs| AL
  KR[key-rotator] -->|OTLP/logs| AL
  DL[Docker JSON logs<br/>uid-473 ACL tail] --> AL
  VA[Vault audit device tail] --> AL

  AL -->|traces| TP[(Tempo — 30 d<br/>prompt-bearing spans)]
  AL -->|logs| LK[(Loki — 30 d)]
  AL -->|remote write + spanmetrics| PR[(Prometheus — 15 d)]
  NE[node-exporter] --> PR
  AL -.optional OTLP over internal NIC.-> CR[Cribl export]
  GF[Grafana — ADM leg,<br/>behind oauth2-proxy] --> TP & LK & PR
```

## 9. Deployment logic — Ansible converge order

The converge is a gated pipeline: each stage validates its contract and the
run stops at the first failure, before later stages can mutate the host.

```mermaid
flowchart TD
  R1[host_preflight<br/>topology, SELinux enforcing,<br/>encrypted-state backing] --> R2[selinux_baseline<br/>container-selinux, MCS contract]
  R2 --> R3[network_routing<br/>additive tables 101/102]
  R3 --> R4[firewalld_zones<br/>zone ownership by live UUID;<br/>nftables + DOCKER-USER live]
  R4 --> R5[os_baseline<br/>Docker CE behind packet policy;<br/>sshd hardening with proven re-login]
  R5 --> R6[docker_networks<br/>20 pinned bridges]
  R6 --> R7[docker_stack<br/>render .env + secrets, bind digests,<br/>DB contracts, volume-init, pinned builds,<br/>Compose up — no implicit builds]
  R7 --> R8[verify<br/>routing, firewall, listeners, DNS,<br/>SELinux/MCS, zero AVCs]
  R8 --> GATE{Vault initialized<br/>and unsealed?}
  GATE -- no — first converge --> WAIT[Reduced wait + explicit Vault gate<br/>→ initialize Vault, re-run]
  GATE -- yes --> FULL[Full service-graph wait — done]
```
