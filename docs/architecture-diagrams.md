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
  and [local versus SOC telemetry](#9-telemetry-and-soc-export-flow).
- Release path: [Ansible order](#10-deployment-logic--ansible-converge-order),
  [provider selection](#11-provider-selection-and-immutable-envoy-build),
  [provider runtime](#12-runtime-request-path-for-selected-providers),
  [CA review and rotation](#13-ca-capture-review-rotation-and-approval), and
  [seed validation and rollback](#14-offline-seed-validation-deployment-and-rollback).
- Managed control: [identity change and drift recovery](#15-managed-identity-change-and-recovery),
  [model lifecycle and discovery](#16-governed-model-lifecycle-and-discovery), and
  [usage and reviewed pricing](#17-usage-and-reviewed-pricing).

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

  TA --> OW[Open WebUI] -->|scoped service key +<br/>signed subject and name| LL[LiteLLM]
  TI --> OW
  TI -->|inference allow-list| LL
  TI --> DP[dev-portal]
  TI -->|aigw realm only| KC[Keycloak]

  TA --> AP[admin-portal]
  TA --> O2[up to 4 oauth2-proxy gates] -->|aigw-admins| ADM_UIS[LiteLLM Admin / Grafana / Prometheus / optional Vault UIs]
  TA -->|auth.DOMAIN full console| KC

  DP -->|live project checks| KR[key-rotator]
  DP -->|create and manage own keys| LL
  AP -->|identity, rotation, model,<br/>and price control| KR
  AP -->|admin key controls| LL
  LL -->|prompt-free usage callback| KR
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

For chat, Open WebUI signs a short-lived assertion for the logged-in directory
user. LiteLLM checks that assertion and the exact Open WebUI workload-key
markers before provider dispatch. Missing, duplicate, changed, or expired
assertions stop the request. The signed subject is the stable per-user audit
ID. The signed username or e-mail is the readable audit name and may contain
`@`. The Keycloak role and shared workload key remain the access checks.

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
  SHOW --> LEAVE[User changes portal tab or page]
  LEAVE --> ERASE[Browser clears the plaintext and replaces<br/>the secret-bearing history entry]
  ERASE --> BACK[Back or Forward cannot show the key again]
  REM([Admin removes member from group]) --> KILL[key-rotator logs user out of Keycloak<br/>and deactivates that subject's project keys<br/>before and after the membership change]
```

The key panel starts hidden until its exit guards are active. The response is
not cacheable. The browser removes the whole panel before normal navigation,
page hiding, form submission, or portal tab changes. A browser-history restore
must pass the same consumed-state check and cannot reveal the key again.

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

## 9. Telemetry and SOC export flow

Alloy is the only collection and export choke point. It sends every admitted
log, metric, and trace to Cribl after redaction. Logs and metrics also keep
their local paths. This release has no local trace store.

Prompts and replies are sensitive. Alloy accepts LiteLLM request traces on a
separate authenticated receiver, removes secrets, and turns each reviewed
`litellm_request` span into a local request-audit log. The sanitized source
trace and log may enter Cribl. See
[observability operations](observability-operations.md) and the
[Cribl telemetry handoff](cribl-soc-handoff.md).

```mermaid
flowchart LR
  LL[LiteLLM<br/>AI audit spans] -->|bearer-auth OTLP/HTTP<br/>port 4319| AL[Alloy]
  OT[Other internal telemetry] -->|ordinary OTLP<br/>ports 4317 and 4318| AL
  KC[Keycloak<br/>auth events] --> AL
  SE[Reviewed trust and<br/>security-control events] --> AL
  CT[/Target lifecycle files<br/>upgrade and rollback/] -->|read-only| AL
  DL[Docker JSON logs<br/>uid-473 ACL tail] --> AL
  VA[Vault raw audit tail] --> AL
  MS[Approved metric endpoints<br/>including node-exporter] -->|scrape| AL

  AL -->|admitted local logs| LK[(Loki — 7 days)]
  AL -->|admitted local metrics| PR[(Prometheus<br/>up to 30 days or configured size cap<br/>first limit wins)]
  PR -->|firing and resolved state| AM[Alertmanager<br/>private, no FQDN]
  PR -->|ALERTS and ALERTS_FOR_STATE only<br/>private mutual TLS| AL
  AL --> RED[Secret removal + fixed fields<br/>for sensitive event classes]
  RED --> COMMON[Common gate:<br/>server-owned environment,<br/>source and recent UTC time]
  COMMON -->|logs, metrics, and traces<br/>OTLP/gRPC with TLS| CR[Cribl destination<br/>24-hour retention]
  GF[Grafana — ADM leg,<br/>behind oauth2-proxy] --> LK & PR & AM
```

Alloy adds the trusted LiteLLM source marker only after port 4319 checks the
private token. The ordinary OTLP path removes a caller-supplied marker and
rejects a caller that claims to be LiteLLM.

Open WebUI chat records get a stable user ID and readable name only from the
valid signed assertion. LiteLLM denies the exact Open WebUI service key when
the assertion is missing or bad, so an unaudited chat request cannot reach a
provider. The shared key remains service authorization evidence.

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
  MAN --> PRE[Preprod offline seed<br/>production plus Samba AD, WIF mock,<br/>their Debian base, and the PostgreSQL 16<br/>migration-test source]
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
  PE2E --> PGATE{Full end-to-end, Vault restart,<br/>and browser tests passed?}
  PGATE --> CLEAN[Run exact-manifest clean-room teardown]
  CLEAN --> ABSENT{Owned resources and images absent?<br/>Unrelated images preserved?}
  ABSENT -- no --> FIX[Reject release and fix source]
  ABSENT -- yes --> RESULT{All release tests passed?}
  RESULT -- no --> FIX
  RESULT -- yes --> XFER[Transfer production pair<br/>and independent hashes]
  PRODSEED --> XFER
  XFER --> RLOAD[Remote loader checks production scope,<br/>policy, labels, and exact image IDs]
  RLOAD --> BACKUP[Authenticate encrypted state backup]
  BACKUP --> USTART[Target audit:<br/>upgrade started]
  USTART --> DEPLOY[Ansible deploys candidate<br/>Envoy image and policy as one unit]
  DEPLOY --> VALIDATE{Readiness and external<br/>validation passed?}
  VALIDATE -- yes --> USUCCESS[Target audit:<br/>upgrade success] --> ACCEPT[Accept candidate release]
  VALIDATE -- no --> UFAIL[Target audit:<br/>upgrade failed + rollback started]
  UFAIL --> ROLLBACK[Restore prior state and use<br/>previous clean source plus seed]
  ROLLBACK --> OLDTEST{Previous release validates?}
  OLDTEST -- yes --> RSUCCESS[Target audit:<br/>rollback success] --> RESTORED[Rollback complete]
  OLDTEST -- no --> RFAIL[Target audit:<br/>rollback failed] --> CLOSED[Keep ingress closed<br/>manual recovery required]
```

See the [image update workflow](image-update-workflow.md) for commands and
[offline image releases](offline-image-seed.md) for the manifest and loader
contracts.

The target lifecycle source is not Ansible stdout. A fixed root-only writer
uses only `lifecycle.jsonl` and `lifecycle.jsonl.1`. Alloy reads those files
through a read-only mount and sends only the fixed fields through the common
Cribl gate. One operation UUID joins the upgrade and any rollback.

## 15. Managed identity change and recovery

The controller records the lifecycle before it changes live Keycloak or LDAP
state. The pending Vault record survives a failed run.

```mermaid
flowchart TD
  START[Ansible asks key-rotator<br/>to converge identity] --> READ[Read verified Vault policy<br/>and pending state]
  READ --> SAFE{Pending record valid and<br/>desired digest unchanged?}
  SAFE -- no --> STOP[Stop before live mutation]
  SAFE -- yes --> KIND{Why is change needed?}
  KIND -- reviewed input changed --> PLAN[Write pending UUID<br/>planned_change]
  KIND -- unexpected live drift --> DRIFT[Write pending UUID<br/>security_drift]
  PLAN --> PEVENT[Audit change planned]
  DRIFT --> DEVENT[Audit drift detected]
  PEVENT --> REPAIR[Repair managed clients, broker,<br/>events, LDAP, and escrow]
  DEVENT --> REPAIR
  REPAIR --> VERIFY{Live and durable state pass?}
  VERIFY -- no --> FAIL[Audit terminal failure<br/>keep same pending UUID]
  FAIL --> START
  VERIFY -- yes --> TERMINAL[Audit applied or recovery success]
  TERMINAL --> CLEAR[Clear pending record only<br/>after terminal audit passes]
```

A managed LDAP provider rename needs a reviewed migration. A legacy blank name
is adopted only when its saved provider ID matches the same live provider.

## 16. Governed model lifecycle and discovery

PostgreSQL is the model source of truth. LiteLLM holds only the checked runtime
copy. A draft or retired model cannot remain in that copy. An unexpected or
changed LiteLLM row makes the controller unready instead of widening access.

```mermaid
flowchart TD
  ADM[Admin with recent Keycloak login] --> PORTAL[Admin portal Models page]
  RECEIPT[Loaded Envoy provider-policy receipt<br/>Anthropic selected] --> CONTROL[key-rotator model controller]
  PORTAL -->|create draft, activate,<br/>show, hide, or retire| CONTROL
  CONTROL --> POLICY[(Append-only model policy<br/>and lifecycle events)]
  POLICY --> STATE{Saved model state}
  STATE -- draft or retired --> ABSENT[LiteLLM deployment must be absent]
  STATE -- active --> PROJECT[Check exact Keycloak<br/>project assignments]
  PROJECT --> PROJECTION[Create or verify exact<br/>managed LiteLLM projection]
  ABSENT --> VERIFY{Full bounded inventory exact?}
  PROJECTION --> VERIFY
  VERIFY -->|no: unmanaged, duplicate,<br/>changed, or malformed| NOTREADY[Fail readiness closed]
  VERIFY -- yes --> READY[Controller ready]
  READY --> FILTER[Dev portal discovery filter]
  CALLER[Caller model list] --> FILTER
  FULL[Full LiteLLM inventory] --> FILTER
  POLICY --> FILTER
  FILTER --> PUBLIC[Return only active, visible,<br/>caller-allowed models]
  POLICY --> EXACT[Hidden active model:<br/>callable only by assigned exact name]
  PROJECT --> RETIRE{Any live assignment remains?}
  RETIRE -- yes --> BLOCK[Block retirement]
  RETIRE -- no --> ABSENT
```

Native LiteLLM model and configuration mutations are blocked at the ADM edge.
Use the [model lifecycle SOP](sop/model-lifecycle.md) for operator steps and
the [model control plan](model-governance-plan.md) for the remaining work.

## 17. Usage and reviewed pricing

The usage callback contains no prompt, reply, API key, or request header. A
separate private token lets it call only the usage endpoint. Each accepted
event and each price version is append-only.

```mermaid
flowchart LR
  REQ[User or tool request] --> LL[LiteLLM 1.93.0]
  LL -->|selected route| EV[Envoy] --> AN[Anthropic]
  LL -->|prompt-free result<br/>private usage token| API[key-rotator usage endpoint]
  API --> CHECK{Shape, identity,<br/>token classes, event ID valid?}
  CHECK -- no --> REJECT[Reject malformed or<br/>conflicting event]
  CHECK -- yes --> LEDGER[(Append-only usage ledger)]
  ADMIN[Admin with login<br/>from last 5 minutes] --> PRICE[Admin portal price form]
  PRICE --> WHEN{Future or backdated?}
  WHEN -->|future| PRICES[(Append-only price versions)]
  WHEN -->|past or current| PREVIEW[Store affected window,<br/>all row hashes, and exact delta]
  PREVIEW --> REVIEW[Show totals and up to<br/>100 row details]
  REVIEW -->|fresh login plus<br/>exact phrase| CONFIRM[Recheck policy, usage,<br/>adjustments, and digests]
  CONFIRM --> PRICES
  CONFIRM --> ADJUST[(Append-only cost adjustments)]
  PRICES --> COST[Bind exact price IDs<br/>and component costs]
  LEDGER --> COST
  ADJUST --> VIEW
  COST --> VIEW[Reviewed read-only views]
  VIEW --> GF[Grafana Model Usage and Cost]
  API --> AUDIT[Bounded stored, replay,<br/>conflict, or write-failure audit]
  REJECT --> AUDIT
  LL -. endpoint unavailable .-> GAP[Prompt-free delivery-failure audit]
  GAP --> AL
  AUDIT --> AL[Alloy redaction and policy gate]
  AL --> LK[(Loki)]
  AL --> CR[Cribl over OTLP/gRPC TLS]
```

Exact callback replays return the saved receipt. The same event ID with
different data is a conflict. Missing usage or price stays unknown, never
zero. Backdating is implemented with immutable preview evidence and
append-only adjustments. It is not production-accepted until the exact-seed
PreProd and rollback tests pass. See
[usage and cost accounting](usage-and-cost-accounting.md).
