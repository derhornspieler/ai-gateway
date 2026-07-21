# AI Gateway — Technical Diagrams

This document is the visual companion to the
[solution map](solution-map.md). Each diagram reflects the implemented
configuration in `compose/`, `ansible/`, and `services/`; where a diagram
simplifies, the solution map's tables remain authoritative. Diagrams render
natively on GitHub/GitLab (Mermaid). Provider catalog and CA review details
are in [Provider onboarding](provider-onboarding.md) and the
[Provider CA maintenance SOP](sop/provider-ca-maintenance.md).

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

  EV -->|selected-provider TLS, exact SANs,<br/>reviewed CA bundles| NIC0 --> INET
  VPN -->|SSH + admin HTTPS| NIC1 --> TA
  USERS -->|user HTTPS| NIC2 --> TI
```

Reply traffic for the ADM and internal legs uses source-policy routing
(tables 101/102) so responses leave through the interface they arrived on.

## 2. Local preprod topology

Local preprod runs on one local Docker engine. It keeps the production service
networks but replaces physical host interfaces with three labeled Docker
planes. Only the two loopback HTTPS addresses are published. The exact
production Envoy image starts from the offline seed and its policy is checked.
The mock WIF request path stays separate, so test trust can never enter that
production Envoy image.

Docker Desktop requires one preprod-only Envoy TCP forwarder to own both IPv4
port 443 publications. It passes TLS through unchanged to the separate
Internal and ADM Traefik containers. This workaround is not in production.

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
    CA[Test Root CA<br/>generated locally]
  end

  SEED --> ANS --> APPS
  CLIENT -->|user names| PNI --> TI --> APPS
  CLIENT -->|admin names| PNA --> TA --> APPS
  AD -->|LDAPS| KC --> APPS
  KR --> WEV --> WIF
  EV --- PNE
  CA -.signs edge, LDAPS,<br/>and mock certificates.-> TI
  CA -.-> TA
  CA -.-> AD
  CA -.-> WIF
```

See [Local preprod](preprod.md) for the exact names, addresses, static users,
and bounded destroy command.

## 3. Segmented container planes

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
  T[AI tool with gateway key] -->|api.DOMAIN /v1| TI[traefik-int]
  D[Developer browser] -->|portal.DOMAIN| TI
  A[Administrator browser] -->|admin hosts on ADM leg| TA[traefik-adm]

  TA --> OW[Open WebUI] --> LL[LiteLLM]
  TI -->|inference allow-list| LL
  TI --> DP[dev-portal]
  TI -->|aigw realm only| KC[Keycloak]

  TA --> AP[admin-portal]
  TA --> O2[up to 4 oauth2-proxy gates] -->|aigw-admins| ADM_UIS[LiteLLM Admin / Grafana / Prometheus / optional Vault UIs]
  TA -->|auth.DOMAIN full console| KC

  DP -->|key lifecycle| KR[key-rotator]
  AP -->|identity + rotation control| KR
  LL -->|selected provider path| EV[Envoy egress] --> V[Selected provider APIs]
  KR --> EV
  LL & KC & KR --> PG[(Postgres)]
  LL --> RD[(Redis)]
  KR --> VT[(Vault)]
```

## 5. Authentication flow — browser OIDC and admin gates

All human access authenticates against Keycloak realm `aigw`, which emits
the four realm roles (`aigw-chat`, `aigw-users` (deprecated for chat),
`aigw-developers`, `aigw-admins`) in a
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

## 6. Logic flow — developer key lifecycle

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

## 7. Security flow — provider credential rotation (Anthropic WIF)

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

## 8. Security design — layered enforcement

Each layer fails closed independently; compromising one does not disable the
others.

```mermaid
flowchart TB
  L1[Host ingress — firewalld zones:<br/>exact source CIDRs, SSH key-only on ADM,<br/>no egress-leg listener]
  L2[Packet policy — atomic DOCKER-USER +<br/>independent nftables aigw_guard:<br/>deny cross-plane, container-to-host,<br/>unapproved bridge egress]
  L3[Network segmentation — 18 per-function bridges;<br/>services join only required planes;<br/>fixed IPs for firewall-addressed workloads]
  L4[Identity — Keycloak OIDC everywhere;<br/>role-based access; per-UI oauth2-proxy gates;<br/>step-up + live-role re-checks for admin mutations]
  L5["Secrets — Vault-backed provider credentials;<br/>file-backed Docker secrets; no secret in argv/env;<br/>fail-closed blank-variable Compose contract"]
  L6[Runtime — SELinux enforcing with per-container MCS;<br/>non-root DHI images, digest-pinned;<br/>read-only binds with keyed HMAC digests;<br/>no Docker socket exposure]
  L7[Egress — Envoy as the only external identity:<br/>selected routes, exact SANs, reviewed CA bundles]
  L1 --> L2 --> L3 --> L4 --> L5 --> L6 --> L7
```

## 9. Telemetry and SOC log flow

Prompts and completions are sensitive. Alloy converts the reviewed
`litellm_request` span into a log record. The raw span never leaves the gateway.
The log stays locally in Loki and may enter the narrow Cribl SOC feed.

Metrics, raw traces, ordinary service logs, and alert payloads never enter
Cribl. Detailed routes and redaction rules are in
[observability operations](observability-operations.md). The logging-team
contract is in [Cribl SOC logging handoff](cribl-soc-handoff.md).

```mermaid
flowchart LR
  LL[LiteLLM<br/>AI spans and runtime logs] --> AL[Alloy]
  KC[Keycloak<br/>auth events] --> AL
  SE[Reviewed trust and<br/>security-control events] --> AL
  DL[Other Docker JSON logs<br/>uid-473 ACL tail] --> AL
  VA[Vault raw audit tail] --> AL

  AL -->|local logs + request audit| LK[(Loki — 7 days)]
  AL -->|local metrics + spanmetrics| PR[(Prometheus — 30 days)]
  NE[node-exporter] --> PR
  PR -.approved backlog.-> AM[Future Alertmanager<br/>local only]
  AL -.curated OTLP logs over TLS only.-> CR[Cribl SOC — 24 hours]
  GF[Grafana — ADM leg,<br/>behind oauth2-proxy] --> LK & PR
```

## 10. Deployment logic — Ansible converge order

The converge is a gated pipeline: each stage validates its contract and the
run stops at the first failure, before later stages can mutate the host.
Stages R1–R6 are `ansible/os-prep.yml` (host preparation, runs standalone and
starts no containers); R7–R9 are `ansible/deploy-stack-only.yml` (stack
phase); `ansible/site.yml` composes the two in this exact order.

```mermaid
flowchart TD
  R1[host_preflight<br/>topology, dedicated-host adoption,<br/>encrypted-state backing] --> R1b[firewall_preflight<br/>existing firewall-state audit]
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

Operators select reviewed names. They cannot pass a hostname or CA path. The
same canonical policy is used to build the image and write both release
projections.

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
  CANON --> MAN[Schema-v2 manifest egress policy]
  ID --> MAN
  MAN --> PROD[Production offline seed<br/>no preprod-only images]
  MAN --> PRE[Preprod offline seed<br/>production plus Samba AD and WIF mock]
```

The catalog itself is not copied into the final image. The generated policy
contains only the selected records. Changing the selection changes the policy
and image identity.

## 12. Runtime request path for selected providers

The host firewall leaves Envoy as the only external workload identity. Envoy
has no catch-all provider route and no system-trust fallback.

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

Live capture is evidence, not approval. The reviewed source and a new release
must cross the release approval boundary before any CA reaches runtime.

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

Ansible does not enter this flow. It receives the already-built release and
never downloads trust material.

## 14. Offline-seed validation, deployment, and rollback

The production and preprod files are separate projections from one build.
Local preprod must pass using its exact seed before the production pair is
transferred.

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
