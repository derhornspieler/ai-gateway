# AI Gateway technical diagrams

These pictures match the current code in `compose/`, `ansible/`, and
`services/`. The [solution map](solution-map.md) has the exact service tables.
The [security model](security-model.md) explains the controls in plain words.

GitHub renders these Mermaid diagrams. Provider details are in
[provider onboarding](provider-onboarding.md) and the
[CA maintenance SOP](sop/provider-ca-maintenance.md).

## Diagram index

- Foundations: [production network](#1-network-topology-and-trust-zones),
  [local preprod](#2-local-preprod-topology), and
  [container planes](#3-segmented-container-planes).
- Application flows: [user and admin paths](#4-software-flow--user-developer-and-administrator-paths),
  [browser OIDC](#5-authentication-flow--browser-oidc-and-admin-gates),
  [developer keys](#6-logic-flow--developer-key-lifecycle), and
  [Anthropic WIF](#7-security-flow--provider-credential-rotation-anthropic-wif).
- Security and telemetry: [layered enforcement](#8-security-design--layered-enforcement)
  and [local versus SOC telemetry](#9-telemetry-and-soc-log-flow).
- Release path: [Ansible order](#10-deployment-logic--ansible-converge-order),
  [provider selection](#11-provider-selection-and-immutable-envoy-build),
  [provider runtime](#12-runtime-request-path-for-selected-providers),
  [CA review and rotation](#13-ca-capture-review-rotation-and-approval), and
  [seed validation and rollback](#14-offline-seed-validation-deployment-and-rollback).

## 1. Network topology and trust zones

Production has three customer-owned connections. Each has its own firewalld
zone. Egress has no listener. The two Traefik edges bind only to the exact ADM
and internal addresses.

```mermaid
flowchart TB
  INET[Internet — selected AI provider APIs]
  VPN[Administrators via VPN<br/>vpn_client_cidr]
  USERS[Internal users and AI tools<br/>internal_cidr]

  subgraph vm [Rocky Linux 9 VM]
    subgraph zegress [zone aigw-egress]
      NIC0[egress NIC<br/>target DROP, no listener<br/>only default route]
    end
    subgraph zadm [zone aigw-adm]
      NIC1[ADM NIC — ETH1_IP<br/>management SSH + TCP/443<br/>from VPN CIDR only]
    end
    subgraph zint [zone aigw-internal]
      NIC2[internal NIC — ETH2_IP<br/>TCP/443<br/>from internal CIDR only]
    end
    EV[Envoy egress 172.28.0.2<br/>sole workload allowed external DNS + TCP/443]
    TA[traefik-adm :443]
    TI[traefik-int :443]
  end

  EV -->|selected-provider TLS, exact SANs,<br/>reviewed CA bundles| NIC0 --> INET
  VPN -->|SSH + admin HTTPS| NIC1 --> TA
  USERS -->|user HTTPS| NIC2 --> TI
```

Route tables 101 and 102 send ADM and internal replies back through the same
connection.

## 2. Local preprod topology

Local preprod runs on one Docker engine. Three Docker planes stand in for the
host connections. Only `127.0.2.1:443` and `127.0.3.1:443` are published.

The exact production Envoy image comes from the seed and must pass its policy
gate. A separate test Envoy handles mock WIF. Test CA trust never enters the
production image.

Docker Desktop needs one test-only TCP forwarder to own both port 443 binds.
It passes TLS to the two Traefik edges. Production does not use this helper.

```mermaid
flowchart LR
  SEED[(Schema-v2 preprod<br/>offline seed)]
  ANS[Ansible preprod<br/>pull never, no build]
  CLIENT[Local browser and API tests]

  subgraph engine [Local Docker engine — project aigw-preprod]
    PNI[plane-internal<br/>127.0.2.1:443]
    PNA[plane-adm<br/>127.0.3.1:443]
    PNE[plane-egress<br/>no host bind]
    TI[traefik-int]
    TA[traefik-adm]
    APPS[Portals, chat, LiteLLM,<br/>Vault, and telemetry]
    KC[Keycloak]
    AD[Samba AD<br/>hostname-verified LDAPS]
    KR[key-rotator]
    WEV[Separate test Envoy<br/>trusts preprod Root CA]
    WIF[WIF provider mock<br/>TLS + JWT checks]
    EV[Exact production Envoy image<br/>selected policy checked]
    CA[Preprod Root CA<br/>generated locally]
  end

  SEED --> ANS --> APPS
  CLIENT -->|user names| PNI --> TI --> APPS
  CLIENT -->|admin names| PNA --> TA --> APPS
  KC -->|LDAPS| AD
  KC --> APPS
  KR --> WEV --> WIF
  EV --- PNE
  CA -.signs edge, LDAPS,<br/>and mock certificates.-> TI
  CA -.-> TA
  CA -.-> AD
  CA -.-> WIF
```

See [local preprod](preprod.md) for names, addresses, users, and destroy steps.

## 3. Segmented container planes

Ansible creates 20 Docker bridges. The base stack uses 18. Services join only
the planes they need. `DOCKER-USER` and `aigw_guard` deny cross-plane,
container-to-host, and unsafe outbound traffic.

```mermaid
flowchart LR
  subgraph edge [Edge planes]
    E1[net-int-edge: traefik-int<br/>net-internal: exact external paths]
    E2[net-adm: traefik-adm<br/>net-admin-app / net-grafana: admin apps]
  end
  subgraph app [Application planes]
    A1[net-chat / net-portal<br/>Open WebUI, portals, LiteLLM, Keycloak]
    A2[net-vendor<br/>LiteLLM, key-rotator → Envoy]
  end
  subgraph data [Data planes]
    D1[net-db-litellm / net-db-keycloak / net-db-rotator / net-db-grafana<br/>four isolated paths to Postgres]
    D2[net-cache — Redis]
    D3[net-vault — Vault + key-rotator + Vault gate]
  end
  subgraph obs [Telemetry planes]
    O1[net-telemetry / net-observability / net-metrics<br/>Alloy, Loki, Prometheus, Grafana, node-exporter]
  end
  E1 --- A1
  E2 --- A1
  A1 --- D1
  A1 --- D2
  A2 --- G[net-egress<br/>Envoy only]
  A1 -.OTLP.-> O1
  D3 --- A1
```

## 4. Software flow — user, developer, and administrator paths

```mermaid
flowchart LR
  U[User browser] -->|chat.DOMAIN, ADM leg| TA
  U -->|chat.DOMAIN, internal leg| TI
  T[AI tool with gateway key] -->|api.DOMAIN /v1| TI[traefik-int]
  D[Developer browser] -->|portal.DOMAIN| TI
  A[Administrator browser] -->|admin hosts on ADM leg| TA[traefik-adm]

  TA --> OW[Open WebUI] --> LL[LiteLLM]
  TI --> OW
  TI -->|inference allow-list| LL
  TI --> DP[dev-portal]
  TI -->|aigw realm only| KC[Keycloak]

  TA --> AP[admin-portal]
  TA --> O2[up to 4 oauth2-proxy gates] -->|aigw-admins| ADM_UIS[LiteLLM Admin / Grafana / Prometheus / optional Vault UIs]
  TA -->|auth.DOMAIN full console| KC

  DP -->|live project checks| KR[key-rotator]
  DP -->|create and manage own keys| LL
  AP -->|identity + rotation control| KR
  AP -->|admin key controls| LL
  LL -->|selected provider path| EV[Envoy egress] --> V[Selected provider APIs]
  KR --> EV
  LL & KC & KR --> PG[(Postgres)]
  LL --> RD[(Redis)]
  KR --> VT[(Vault)]
```

## 5. Authentication flow — browser OIDC and admin gates

All people sign in through Keycloak realm `aigw`. It sends four roles in the
`roles` claim: `aigw-chat`, old `aigw-users`, `aigw-developers`, and
`aigw-admins`. Each proxied admin UI has its own OAuth2 Proxy. Chat and both
portals use OIDC in the app.

```mermaid
sequenceDiagram
  autonumber
  participant B as Browser
  participant T as Traefik edge
  participant P as oauth2-proxy (admin UIs only)
  participant K as Keycloak (realm aigw)
  participant S as App or admin UI

  B->>T: HTTPS request
  alt Proxied admin UI
    T->>P: route to its dedicated gate
    P-->>B: redirect to Keycloak
    B->>K: authenticate
    K-->>B: authorization code
    B->>P: callback with code
    P->>K: exchange code and check admin role
    alt admin role present
      P->>S: send approved request
      S-->>B: response
    else admin role missing
      P-->>B: access denied
    end
  else Chat or portal app
    T->>S: route to app
    S-->>B: redirect to Keycloak
    B->>K: authenticate
    K-->>B: authorization code
    B->>S: callback with code
    S->>K: exchange code and check required role
    S-->>B: app response or access denied
  end
```

Admin portal writes also need a CSRF token and a fresh Keycloak login. The
step-up uses `prompt=login` and `max_age=0` and lasts five minutes. Each page
checks the live admin role again.

## 6. Logic flow — developer key lifecycle

Keycloak group membership grants project access. Portal keys follow that live
membership.

```mermaid
flowchart TD
  S([Developer opens dev-portal]) --> AUTHZ{Token carries<br/>aigw-developers?}
  AUTHZ -- no --> DENY([Denied])
  AUTHZ -- yes --> PROJ{Live member of a managed<br/>project group? — verified via key-rotator}
  PROJ -- no --> DENY
  PROJ -- yes --> MINT[dev-portal calls LiteLLM to mint a scoped key<br/>project ID = group name in key metadata]
  MINT --> SHOW[One-time plaintext key shown once<br/>never stored or logged]
  SHOW --> USE[AI tool calls api.DOMAIN /v1 with key]
  REM([Admin removes member from group]) --> KILL[key-rotator logs user out of Keycloak<br/>and deactivates that subject's project keys<br/>before and after the membership change]
```

## 7. Security flow — provider credential rotation (Anthropic WIF)

No long-lived Anthropic key sits in app config. key-rotator gets a short-lived
token through the separate `anthropic-wif` realm. Production keeps the
`private_key_jwt` key in Vault. A reviewed test can use a mounted PEM instead.

The signing key is not a provider CA. Provider CA files are built into the
immutable Envoy image. Every provider call goes through Envoy.

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
  KC-->>KR: workload identity JWT<br/>sub=service-account-anthropic-token-broker<br/>aud=https://api.anthropic.com (600 s lifespan)
  KR->>EV: POST /v1/oauth/token (WIF exchange)
  EV->>AN: pinned TLS, exact SAN, narrowed CA
  AN-->>EV: short-lived sk-ant-oat01 access token
  EV-->>KR: return token
  KR->>KR: install token as LiteLLM provider credential<br/>(anthropic-primary), schedule refresh
```

## 8. Security design — layered enforcement

Each layer fails closed on its own. One failed layer does not switch off the
rest.

```mermaid
flowchart TB
  L1[Host ingress — firewalld zones:<br/>exact source CIDRs, SSH key-only on ADM,<br/>no egress-leg listener]
  L2[Packet policy — atomic DOCKER-USER +<br/>independent nftables aigw_guard:<br/>deny cross-plane, container-to-host,<br/>unapproved bridge egress]
  L3[Network segmentation — 20 isolated bridges;<br/>the base stack joins 18 as needed;<br/>fixed IPs for firewall-addressed workloads]
  L4[Identity — Keycloak OIDC for people;<br/>gateway keys for API tools; per-UI oauth2-proxy gates;<br/>step-up + live-role re-checks for admin mutations]
  L5["Secrets — Vault-backed provider credentials;<br/>file-backed where the service supports it;<br/>no secret in command arguments;<br/>fail-closed required-variable contract"]
  L6[Runtime — SELinux enforcing with per-container MCS;<br/>non-root DHI images, digest-pinned;<br/>read-only binds with keyed HMAC digests;<br/>no Docker socket exposure]
  L7[Egress — Envoy as the only external identity:<br/>selected routes, exact SANs, reviewed CA bundles]
  L1 --> L2 --> L3 --> L4 --> L5 --> L6 --> L7
```

## 9. Telemetry and SOC log flow

Prompts and replies are sensitive. Alloy turns the reviewed `litellm_request`
span into a log. The raw span never leaves the gateway. The log stays in Loki
and may enter the narrow Cribl SOC feed.

Metrics, raw traces, normal service logs, and alert data never enter Cribl.
See [observability operations](observability-operations.md) and the
[Cribl SOC handoff](cribl-soc-handoff.md).

```mermaid
flowchart LR
  LL[LiteLLM<br/>AI spans and runtime logs] --> AL[Alloy]
  KC[Keycloak<br/>auth events] --> AL
  SE[Reviewed trust and<br/>security-control events] --> AL
  DL[Other Docker JSON logs<br/>uid-473 ACL tail] --> AL
  VA[Vault raw audit tail] --> AL

  AL -->|local logs + request audit| LK[(Loki — 7 days)]
  AL -->|local metrics + spanmetrics| PR[(Prometheus<br/>30 days or 5 GB, first limit wins)]
  NE[node-exporter] --> PR
  PR -.approved backlog.-> AM[Future Alertmanager<br/>local only]
  AL -.curated OTLP logs over TLS only.-> CR[Cribl SOC destination<br/>24-hour retention]
  GF[Grafana — ADM leg,<br/>behind oauth2-proxy] --> LK & PR
```

## 10. Deployment logic — Ansible converge order

The run stops at the first failed gate. `ansible/os-prep.yml` runs R1 through
R6 and starts no containers. `ansible/deploy-stack-only.yml` runs R7 through
R9. `ansible/site.yml` runs both files in that order.

```mermaid
flowchart TD
  R1[host_preflight<br/>topology, dedicated-host adoption,<br/>encrypted-state warning] --> R1b[firewall_preflight<br/>existing firewall-state audit]
  R1b --> R1c[time_sync<br/>proven synchronized clock<br/>before signed installs]
  R1c --> R2[selinux_baseline<br/>container-selinux, MCS contract,<br/>enforcing required]
  R2 --> R3[network_routing<br/>additive tables 101/102]
  R3 --> R4[firewalld_zones<br/>zone ownership by live UUID;<br/>nftables + DOCKER-USER live]
  R4 --> R5[os_baseline<br/>Docker CE behind packet policy;<br/>sshd hardening with proven re-login]
  R5 --> R6[docker_networks<br/>20 pinned bridges]
  R6 --> R7[docker_stack<br/>render .env + secrets, bind digests,<br/>DB contracts, volume-init, pinned builds,<br/>Compose up — no implicit builds]
  R7 --> R8[verify<br/>routing, firewall, listeners, DNS,<br/>SELinux/MCS, zero AVCs]
  R8 --> R9[host_finalize<br/>promote dedicated-host marker]
  R9 --> GATE{Vault initialized<br/>and unsealed?}
  GATE -- no — first converge --> WAIT[Reduced wait + explicit Vault gate<br/>→ initialize Vault, re-run]
  GATE -- yes --> FULL[Full service-graph wait — done]
```

## 11. Provider selection and immutable Envoy build

Operators select reviewed names. They cannot pass a hostname or CA path. One
sorted policy drives the image and both seed files.

```mermaid
flowchart LR
  OP[Operator repeats<br/>--provider NAME] --> PLAN[Network-disabled policy planner]
  CAT[Committed provider catalog] --> PLAN
  CA[Reviewed CA bundles] --> PLAN
  PROV[Reviewed provenance records] --> PLAN
  PLAN --> CHECK{Names, routes, SNI, SANs,<br/>hashes, fingerprints, dates valid?}
  CHECK -- no --> STOP[Stop: no image or release]
  CHECK -- yes --> CANON[Canonical sorted provider list<br/>and egress-policy digest]
  CANON --> BUILD[Network-disabled reproducible<br/>Envoy image build]
  CAT --> BUILD
  CA --> BUILD
  PROV --> BUILD
  BUILD --> ONLY[Final image contains only selected<br/>routes, policy, and CA bundles]
  ONLY --> ID[Immutable Envoy image ID]
  CANON --> MAN[Matching schema-v2 manifest<br/>egress-policy receipts]
  ID --> MAN
  MAN --> PROD[Production offline seed<br/>no preprod-only images]
  MAN --> PRE[Preprod offline seed<br/>production plus Samba AD, WIF mock,<br/>and their extra Debian base]
```

The catalog is not copied into the image. Only selected records enter the
policy. A different selection creates a different policy and image ID.

## 12. Runtime request path for selected providers

The host firewall lets only Envoy reach a provider. Envoy has no catch-all
provider route and no system trust fallback.

```mermaid
flowchart LR
  LL[LiteLLM] -->|HTTP on net-vendor| EV[Envoy egress]
  KR[key-rotator] -->|HTTP on net-vendor| EV
  EV --> ROUTE{Path matches a selected<br/>provider prefix?}
  ROUTE -- no --> DENY[Return 404<br/>no upstream request]
  ROUTE -- yes --> TLS[Rewrite path and Host<br/>start TLS with reviewed SNI]
  TLS --> VERIFY{Exact SAN and reviewed<br/>CA bundle valid?}
  VERIFY -- no --> FAIL[Fail closed]
  VERIFY -- yes --> API[Selected provider API]
  LL -.direct TCP/443 blocked.-> FW[Host egress firewall]
  KR -.direct TCP/443 blocked.-> FW
  UNS[Unselected provider] -.no generated route.-> DENY
```

## 13. CA capture, review, rotation, and approval

A live capture is only evidence. A separate review and release approval must
pass before the CA can reach runtime.

```mermaid
flowchart LR
  NOTICE[Provider or CA change notice] --> CAP
  ENDPOINT[Approved provider endpoint] --> CAP
  OFFICIAL[Official provider or CA repository] --> REVIEW

  subgraph TRUST [Trusted release-maintenance boundary]
    CAP[Capture candidate chain<br/>on trusted networked system] --> REVIEW[Independent review:<br/>source, chain, dates, CA use,<br/>hashes, provenance limits]
    REVIEW --> DECIDE{All evidence approved?}
    DECIDE -- no --> REJECT[Reject candidate]
    DECIDE -- yes --> SOURCE[Update reviewed PEM,<br/>provenance, catalog, and tests]
    SOURCE --> GATES[Unit, contract, deterministic,<br/>and selected-only tests]
    GATES --> APPROVE{Release approval}
  end

  APPROVE -- no --> REJECT
  APPROVE -- yes --> RELEASE[Build new immutable Envoy image<br/>and offline seeds]
  RELEASE --> TRANSITION[Optional transition release<br/>contains approved old and new CAs]
  TRANSITION --> CUTOVER[Provider chain cutover]
  CUTOVER --> FINAL[New reviewed release<br/>removes retired CA]
```

Ansible does not enter this flow. It receives the built release and never
downloads trust files.

The fingerprint proves the certificate bytes. The provenance record explains
the capture and review. Neither proves CA country, endpoint location, or data
residency. Those need separate proof.

## 14. Offline-seed validation, deployment, and rollback

One build makes separate production and preprod files. Local preprod must pass
with its exact seed before anyone transfers the production pair.

```mermaid
flowchart TD
  BUILD[One reviewed release build] --> PRESEED[Preprod archive and manifest]
  BUILD --> PRODSEED[Production archive and manifest]
  PRESEED --> LLOAD[Local loader checks archive allow-list,<br/>source hashes, policy, labels, and image IDs]
  LLOAD --> PE2E[Ansible local preprod<br/>pull never, no build]
  PE2E --> PGATE{Full end-to-end test passed?}
  PGATE -- no --> FIX[Reject release and fix source]
  PGATE -- yes --> XFER[Transfer production pair<br/>and independent hashes]
  PRODSEED --> XFER
  XFER --> RLOAD[Remote loader checks production scope,<br/>policy, labels, and exact image IDs]
  RLOAD --> BACKUP[Authenticate encrypted state backup]
  BACKUP --> DEPLOY[Ansible deploys candidate<br/>Envoy image and policy as one unit]
  DEPLOY --> VALIDATE{Readiness and external<br/>validation passed?}
  VALIDATE -- yes --> ACCEPT[Accept candidate release]
  VALIDATE -- no --> ROLLBACK[Restore prior state and use<br/>previous clean source plus seed]
  ROLLBACK --> OLDTEST{Previous release validates?}
  OLDTEST -- yes --> RESTORED[Rollback complete]
  OLDTEST -- no --> CLOSED[Keep ingress closed<br/>manual recovery required]
```

See the [image update workflow](image-update-workflow.md) for commands and
[offline image releases](offline-image-seed.md) for the manifest and loader
contracts.
