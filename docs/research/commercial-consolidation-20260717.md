# Commercial consolidation study — what paid tiers could absorb, per component

Date: 2026-07-17. Owner question: "How much could we collapse into LiteLLM if we
paid for it? Is LiteLLM Kubernetes capable?" — expanded to the whole stack, with
an Envoy AI Gateway comparison for a Kubernetes-shaped future and license-cost
estimates for planning.

**Status of numbers:** feature claims verified against the repo and vendor docs
where marked; prices are list where public, otherwise labeled *reported* or
*quote-only*. Confirm every number with the vendor before budgeting — this doc
is for shortlisting, not procurement.

---

## 1. Current stack inventory and its license posture

Everything deployed today is free/OSS. The table maps each component to the role
it plays and the commercial tier that exists for it.

| Component | Role in this stack | License today | Paid option |
|---|---|---|---|
| LiteLLM (proxy) | OpenAI/Anthropic-compatible API, virtual keys, model catalog | MIT (OSS features) | LiteLLM Enterprise (self-hosted license) |
| Open WebUI | End-user chat | Open WebUI license (branding clause) | Open WebUI Enterprise (per-seat) |
| Keycloak | OIDC IdP, LDAP/AD federation, roles | Apache-2.0 | Red Hat build of Keycloak (subscription) |
| Vault | Provider-credential store, break-glass escrow, PKI | BSL 1.1 (Community) | Vault Enterprise / HCP Vault Dedicated |
| Traefik ×2 | TLS edge, host routing, NIC-pinned publish | MIT (Proxy OSS) | Traefik Enterprise / Hub API Gateway |
| Envoy (egress) | Pinned egress, per-vendor CA narrowing, TLS origination | Apache-2.0 | n/a (commercial support via vendors) |
| oauth2-proxy ×4 | OIDC gate for admin UIs | MIT | none (would be *replaced*, not licensed) |
| dev-portal / admin-portal | Self-service keys, group model policy, identity ops | ours | n/a (candidate for *collapse*) |
| key-rotator | Provider+virtual key rotation, Keycloak identity controller | ours | n/a (candidate for *partial collapse*) |
| Grafana/Prometheus/Loki/Tempo/Alloy | Dashboards, metrics, logs, traces | AGPL/Apache | Grafana Enterprise stack / Grafana Cloud |
| PostgreSQL, Redis-less design | State | PostgreSQL license | n/a |

---

## 2. What LiteLLM Enterprise would absorb (verified against repo behavior)

The enterprise license is the single highest-leverage purchase because it
attacks the custom Python surface we maintain, not just a feature checkbox.

**Collapses (high confidence):**

- **oauth2-proxy in front of litellm-admin + the `litellm-breakglass` inner
  login** → enterprise SSO (generic OIDC against Keycloak) on the Admin UI.
  One login instead of today's double gate.
- **dev-portal key issuance** → SSO users self-serve keys under teams with
  budgets/rate limits. Our portal's core loop (login → mint scoped key → show
  config snippets) is native, minus the curated snippet/tooling pages.
- **admin-portal model policy (`allowed_models` lever)** → teams + model
  access groups, plus per-team budgets we do not have today. The
  `aigw-no-models` sentinel becomes unnecessary on this path (a team with no
  model groups sees nothing).
- **Virtual-key rotation half of key-rotator** → scheduled key rotations
  (enterprise) + audit logs (enterprise).
- **Prometheus `/metrics`** → enterprise-gated endpoint becomes available;
  today's workaround (OTel callback → Alloy → Tempo spans; edge metrics from
  Traefik/Envoy; no `litellm` scrape job in `compose/prometheus/prometheus.yml`)
  stops being the only source of request metrics.
- **JWT auth** (enterprise) → API callers could present Keycloak-issued JWTs
  instead of static `sk-` keys — a posture upgrade nothing in the current
  stack offers.
- **SCIM** → IdP-driven user/team provisioning replacing part of the identity
  controller's group sync.

**Does NOT collapse:**

- **Open WebUI** — LiteLLM has no end-user chat surface.
- **Keycloak** — LiteLLM consumes OIDC; the realm, LDAP federation,
  brute-force protection, and role model stay.
- **Envoy pinned egress / firewall ABI / Traefik edge** — LiteLLM is an
  outbound HTTP client; the egress trust boundary and NIC-pinned publish are
  ours by design.
- **Keycloak-side identity controller** — managed-group topology, last-admin
  protection, `aigw-chat` gating, break-glass escrow: org policy with no
  LiteLLM equivalent.
- **Provider-credential rotation** — LiteLLM can *read* credentials from
  Vault (enterprise secret-manager integration) but does not rotate vendor
  keys; that half of key-rotator stays.

**Net effect:** roughly 30–40% of the custom Python surface (dev-portal
issuance flow, admin model-policy page, virtual-key rotation engine, one
oauth2-proxy instance) retires, in exchange for accepting LiteLLM's UI and
policy model where ours is more opinionated (identity-linked project groups,
deny-all sentinel, curated developer experience).

**Follow-on facts verified for the owner's side questions:**

- *"If we enable OpenAI through LiteLLM, do the portals pick it up?"* — Yes,
  automatically. Both portals enumerate models live from LiteLLM `/v1/models`
  (`services/dev-portal/app/litellm_client.py`); nothing is hardcoded. Add the
  OpenAI model block + credential and converge; gpt models appear as admin
  checkboxes and in developer tables with no portal change.
- *"We pull logs via OTel because Prometheus export is enterprise, right?"* —
  Correct in substance: LiteLLM's `/metrics` is enterprise-gated, so the
  free-tier design uses the OTel callback (spans → Alloy → Tempo, with
  key/project attribution) and container logs → Loki. Request metrics today
  come from the Traefik/Envoy edges, not from LiteLLM itself.

---

## 3. Per-component commercial options (beyond LiteLLM)

### Vault → Vault Enterprise or HCP Vault Dedicated
What paid adds: HSM auto-unseal + seal-wrap, performance/DR replication,
namespaces, enterprise support. What we'd actually use: **auto-unseal against a
cloud KMS/HSM** (removes the manual unseal ceremony and the controller-held
share), DR replication if the platform ever becomes HA. What we would not use:
namespaces, performance replication at this scale.
Verdict: nice-to-have; the pain it removes (unseal ceremony) is real but
already automated by the converge. Community BSL remains legal for this
self-hosted commercial use (BSL restricts *competing hosted offerings*, not
internal use). Priority: low until HA or compliance demands HSM custody.

### Traefik → Traefik Hub API Gateway (Traefik Enterprise is folded into Hub)
What paid adds: clustered HA control plane, OIDC middleware *at the edge*,
native WAF, distributed rate limiting, air-gapped mode, support. The OIDC
middleware is the interesting one: it could replace all four oauth2-proxy
instances with edge authentication — one fewer moving part per admin app.
Verdict: only compelling if we also want edge HA or contractually need
support; oauth2-proxy is working and free. Priority: low.

### Keycloak → Red Hat build of Keycloak
Sold as part of Red Hat subscriptions (Application Foundations / per-core),
value = supported lifecycle, CVE SLAs, certified LDAP integrations. No feature
delta that matters to us — upstream Keycloak already does everything we use.
Verdict: purely a support/compliance purchase for customers that require a
vendor throat to choke. Priority: customer-driven.

### Open WebUI → Enterprise
The current "Open WebUI License" (v0.6.6+) is BSD-3 **plus a branding clause**:
deployments exceeding 50 users in a rolling 30-day window may not remove or
alter Open WebUI branding without an enterprise license. Use, modification,
and self-hosting stay free at any scale — the cap gates *rebranding*, not
use. Enterprise (seat-based, quote-only) buys white-labeling, support, and
priority features.
Verdict: if the customer is fine with visible Open WebUI branding, no license
is required at any seat count; budget it only if white-labeling is a
requirement. Priority: a branding decision, not an engineering one.

### Grafana stack → Grafana Enterprise / Cloud
What paid adds: enterprise datasources, RBAC/reporting, support; Cloud removes
self-hosting. We lose nothing staying OSS — AGPL is fine for internal use.
Verdict: no. Priority: none.

### Envoy (egress) — stays OSS
The pinned-egress entrypoint gate is ours; commercial Envoy support (Tetrate
et al.) only matters if we adopt their distribution wholesale.

---

## 4. Kubernetes design: LiteLLM vs Envoy AI Gateway

Both are Kubernetes-capable; they solve different layers and could even
coexist (Envoy AI Gateway as data plane, LiteLLM as key/budget control plane).

### LiteLLM on Kubernetes
- Official Helm chart; stateless proxy pods scale horizontally behind
  Postgres (keys/config) + Redis (distributed rate limits, budget state,
  router health). Migration job + HPA are documented production posture.
- Multi-replica is supported — the single-replica constraints in *our* stack
  are our own process-local locks (dev-portal dedupe, key-rotator last-admin),
  not LiteLLM limits.
- Carries the whole control plane with it: virtual keys, teams, budgets,
  spend logs, admin UI. Nothing else in the cluster has to know about AI.
- It remains a Python data plane: per-pod throughput is modest and latency
  under load is the known weak spot; you scale it wide.

### Envoy AI Gateway
- Apache-2.0 CNCF project on top of Envoy Gateway (Kubernetes Gateway API),
  co-created by Tetrate + Bloomberg. **v1.0 went GA 2026-06-23** — the first
  release with a committed-stable control-plane API. AI-specific CRDs
  (`AIGatewayRoute`, `AIServiceBackend`, `BackendSecurityPolicy`, `MCPRoute`)
  route OpenAI-format traffic to 16+ providers, handle upstream auth, and do
  token-aware rate limiting; supports the Gateway API Inference Extension
  (InferencePool + endpoint picker) for in-cluster model servers.
- **Kubernetes-only**: it programs Envoy via Envoy Gateway and the Gateway
  API — there is no Docker Compose deployment mode, so it is not an option
  for the current stack shape at all, only for a k8s future.
- Fully OSS, no paid feature gates. Tetrate's commercial layer is a *hosted*
  router (Agent Router Service, model cost + 5% routing fee) and a
  quote-only Enterprise with spend attribution/SSO/on-prem — optional, not
  required.
- C++ Envoy data plane: much higher per-pod throughput, native Gateway API
  integration, and it *is* the same technology family as our egress trust
  boundary — one mental model for edge, egress, and AI routing.
- What it does NOT have: virtual-key issuance/lifecycle, per-team budgets and
  spend tracking, an admin UI, model-access groups. That control plane is
  exactly the part of LiteLLM our portals depend on (`/key/generate`,
  `/v1/models`, per-key `allowed_models`). Adopting it alone would mean
  rebuilding key management ourselves — the opposite of consolidation.

### Recommendation shape
- **Compose stack (today, this prototype):** stay LiteLLM OSS; buy Enterprise
  only when SSO-on-admin-UI, native metrics, and self-serve keys justify
  retiring portal code.
- **Kubernetes future, consolidation goal:** LiteLLM (Helm, HPA, Redis) keeps
  the most functionality per component. Envoy AI Gateway becomes attractive
  when raw throughput/latency or Gateway-API-native platform standards
  dominate — and then it *fronts* providers while something (LiteLLM or our
  portals) still owns keys and budgets.
- **Not recommended:** Envoy AI Gateway as a lone replacement for LiteLLM —
  it removes the control plane the portals are built on.

---

## 5. License cost estimates (researched 2026-07-17)

Labels: **list** = publicly published price; **reported** = credible
third-party/vendor-adjacent figure; **quote** = contact-sales only. All annual
figures are planning ballparks — get real quotes before budgeting.

| Product | Paid tier | Price signal | Label | What it buys us |
|---|---|---|---|---|
| LiteLLM | Enterprise (self-hosted, `LITELLM_LICENSE` key) | Basic ~$250/mo (~$3k/yr); Premium ~$30k/yr | reported (vendor-adjacent for the floor) | SSO on admin UI, SCIM, JWT auth, audit logs, key-rotation automation, guardrails, Prometheus `/metrics`, SLA |
| Open WebUI | Enterprise (seat-based) | quote-only; free tier fully usable at any scale if branding stays | quote | White-labeling above 50 users, support |
| Vault | Enterprise (self-managed) | low-to-mid six figures/yr reported; HCP Dedicated ~$1.58–$9.41/cluster-hr (~$14k–$83k/yr) + per-client fees | reported | HSM auto-unseal, DR/perf replication, namespaces, support |
| Traefik | Hub API Gateway / API Management | quote-only (marketplace private offers) | quote | Edge OIDC middleware, WAF, distributed rate limiting, HA control plane, support |
| Keycloak | Red Hat build of Keycloak | not sold standalone — bundled into Red Hat Application Foundations/OpenShift core subscriptions; expect five figures/yr small-footprint | reported (imprecise) | Support/SLA, hardened lifecycle — no feature delta |
| Grafana stack | Grafana Enterprise (self-managed) / Cloud Pro | Cloud Pro $19/mo + usage (list); Enterprise ~$25k floor, typically $40k–$150k/yr | list / reported | Enterprise datasources, RBAC/reporting, support — nothing we need |
| Envoy AI Gateway | (fully OSS) | $0; Tetrate hosted router = model cost + 5% fee; Tetrate Enterprise quote-only | list/quote | n/a — no feature gates |
| NGINX Plus (edge alt.) | per-instance subscription | ~$2.5k–$5k/instance/yr (+~$2k WAF) | reported | Edge alternative only; not planned |
| HAProxy Enterprise (edge alt.) | per-instance subscription | quote-only | quote | Edge alternative only; not planned |

**Scenario totals (annual, planning-grade):**

- **Minimum meaningful spend** — LiteLLM Enterprise Basic only: **~$3k/yr.**
  Un-gates SSO-on-admin-UI, `/metrics`, audit logs; retires the litellm
  oauth2-proxy and inner break-glass login. Portal-collapse features (SCIM
  depth, full RBAC) may require Premium — confirm tier split in the trial.
- **Consolidation scenario** — LiteLLM Premium: **~$30k/yr.** The full §2
  collapse (self-serve keys, teams/budgets, scheduled rotation, JWT auth),
  retiring 30–40% of the custom Python surface.
- **White-label chat add-on** — Open WebUI Enterprise: quote, seat-based;
  only if the customer requires de-branding above 50 users.
- **Compliance-driven ceiling** — adding Vault Enterprise + RH Keycloak +
  Traefik Hub + Grafana Enterprise: realistically **$150k–$400k+/yr**, none
  of it buying functionality the gateway lacks today. Recommend against
  unless the customer's support/HSM/SLA posture demands it.

---

## 6. Bottom line

1. **Highest-leverage purchase:** LiteLLM Enterprise — retires real custom
   code (portal issuance, model policy, virtual-key rotation, one oauth2-proxy)
   and un-gates `/metrics`, SSO, JWT auth, SCIM.
2. **Open WebUI:** free at any scale if its branding stays visible; the
   enterprise license is only needed for white-labeling above 50 users — a
   customer branding decision, not an engineering one.
3. **Customer-compliance purchases, not engineering ones:** Red Hat Keycloak,
   Vault Enterprise, Traefik Enterprise, Grafana Enterprise — buy if the
   customer's support/HSM/SLA posture demands, not for features we lack.
4. **Kubernetes:** LiteLLM is fully k8s-capable (Helm/HPA/Redis) and preserves
   consolidation; Envoy AI Gateway is the performance-first alternative that
   solves routing but reopens the key-management problem.
