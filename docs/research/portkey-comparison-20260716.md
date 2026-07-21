# Portkey vs. AI Gateway — an apples-to-oranges comparison

Research note, 2026-07-16. Sources: github.com/Portkey-AI (org + gateway README),
portkey.ai/pricing (fetched today). Owner request: compare the two designs and
flag, feature by feature, what sits behind a paywall — in Portkey *and* in the
components this stack is built from.

## Why apples-to-oranges

The two products answer different questions.

- **Portkey** is a hosted **control panel for LLM traffic**. Its open-source
  core (`Portkey-AI/gateway`, MIT, ~12.4k stars, TypeScript) is a fast routing
  data plane: one OpenAI-compatible API over 1,600+ models, retries,
  fallbacks, load balancing, 40+ pre-built guardrail checks. Nearly everything
  an enterprise needs *around* that data plane — durable observability,
  prompt management, semantic caching, SSO, RBAC at org scope, audit logs,
  private deployment — lives in their hosted platform on a paid tier.
- **This AI Gateway** is a **sovereignty stack**: the same platform
  capabilities composed from self-hosted OSS (LiteLLM, Keycloak, Vault,
  key-rotator, Envoy, Grafana/Prometheus/Loki/Tempo, Open WebUI) on one
  hardened customer-owned VM. The design center is the security boundary —
  pinned egress, three-NIC segmentation, Vault-held short-lived credentials —
  and *no third party in the request path*, which is precisely the property
  Portkey's hosted tiers cannot offer and its Enterprise tier charges for.

## Portkey's pricing tiers (as fetched 2026-07-16)

| Tier | Price | What it adds | What stays locked |
|---|---|---|---|
| Open Source (self-hosted) | Free (MIT) | Universal API, retries/timeouts, routing, fallbacks, load balancing, guardrail checks, basic dashboard | Observability logs, virtual keys, prompt mgmt, caching, SSO/SAML, RBAC, audit logs, compliance certs |
| Developer (hosted) | Free | Key management, 3 prompt templates, **10k logged requests/mo**, 3-day log retention, basic traces | Guardrails, caching, SSO/SAML, RBAC, audit logs, private deployment |
| Production (hosted) | $49/mo | **100k logs/mo** (then $9 per extra 100k, cap 3M), 30/90-day retention, alerts, LLM+partner guardrails, unlimited prompts, simple + semantic caching, RBAC, service-account keys | SSO/SAML, full audit logs, private deployment, advanced compliance, custom guardrails |
| Enterprise | Custom | 10M+ logs/mo, custom retention, custom guardrail hooks, SSO, granular budgets/rate limits, org-wide audit logs, **private cloud/VPC deployment**, data isolation, SOC2/GDPR/HIPAA, BAAs | — |

The pattern to notice: the features a security-focused customer is required to
have — SSO, audit logs, private deployment, data isolation — are exactly the
ones stacked at the top ("custom pricing") tier.

## Feature-by-feature, with paywall flags on both sides

| Capability | Portkey | Paywall (Portkey) | AI Gateway (this design) | Paywall (our components) |
|---|---|---|---|---|
| Multi-provider routing, retries, fallbacks | OSS gateway | Free | LiteLLM proxy | Free (MIT) |
| OpenAI/Anthropic-compatible API | OSS gateway | Free | LiteLLM (`/v1/chat/completions`, `/v1/messages`) | Free |
| Provider-credential vaulting ("virtual keys") | Hosted platform | **Paid** (absent from OSS tier) | Vault + key-rotator; WIF-minted 600 s tokens, restart-safe reconcile | Free (Vault under BSL 1.1 — free to run, source-available, not OSI-open) |
| Automated key rotation | Managed | Paid tiers | Anthropic WIF; other provider drivers are dormant until reviewed and released | Free (built here) |
| SSO / OIDC / SAML | Hosted platform | **Enterprise only** | Keycloak, first-class across every app | Free (Apache-2.0). **LiteLLM's own admin-UI SSO is an enterprise feature — routed around with oauth2-proxy + Keycloak** |
| RBAC / teams / workspaces | Hosted | **Production tier and up**; org-granular at Enterprise | Keycloak realm roles (`aigw-admins/-developers/-chat`) + admin portal | Free |
| Observability: logs, traces, metrics | Hosted; 10k logs/mo free, 100k at $49, 10M+ Enterprise; retention capped by tier | **Metered + paid** | Grafana/Prometheus/Loki/Tempo — unlimited, local, retention is a disk decision | Free (AGPL/Apache). Note: some LiteLLM telemetry callbacks are enterprise-gated upstream; our dashboards use self-owned pipelines |
| Audit logs | Hosted | **Enterprise only** (org-wide) | Keycloak event log + Loki pipeline; break-glass logins flagged incident-grade | Free |
| Guardrails | 40+ checks in OSS; LLM/partner guardrails Production; custom hooks Enterprise | **Mixed** | Not implemented (LiteLLM hooks available if wanted) | n/a today |
| Simple caching | Hosted | **Production tier** | Not implemented (LiteLLM supports Redis caching if wanted) | Free if adopted |
| Semantic caching | Hosted | **Production tier** | Not implemented | n/a |
| Prompt management / playground | Hosted (3 templates free) | **Metered, then paid** | Not a goal; Open WebUI holds user-level prompts | n/a |
| Budgets & rate limits per key/team | Hosted | Production/Enterprise (granular) | LiteLLM OSS budgets + admin-portal key policy | Free |
| Private / air-gapped deployment | Enterprise private-cloud/VPC | **Enterprise only** | The entire architecture; egress pinned through Envoy to two vendor CIDRs | Free by design |
| Data isolation / residency | Enterprise ("data isolation") | **Enterprise only** | Nothing leaves the customer VM except model calls | Free by design |
| Compliance certs (SOC2/GDPR/HIPAA, BAA) | Vendor-carried | **Enterprise** | Customer-carried (self-hosted trade-off: you inherit the audit burden) | n/a |
| End-user chat UI | None | n/a | Open WebUI | Free; **branding clause in Open WebUI ≥0.6 license: >50-user deployments must keep branding unless an enterprise license is bought** |
| Hardened container base images | n/a (their concern) | n/a | Docker Hardened Images (dhi.io) | **Paid Docker subscription — a real recurring cost in this design** |
| Identity provider itself | External (bring your IdP at Enterprise) | — | Keycloak in-stack; lab AD via Samba | Free |
| HA / managed operations | Their pager, their SLA | Included in paid tiers | Single-VM by design; Blue/Green two-VM path is a recorded planning exercise | Labor, not license |

## Honest counterpoints

1. **Our stack has its own shadow paywalls.** LiteLLM gates admin-UI SSO (and
   some telemetry/audit conveniences) behind its enterprise license — this
   design routes around it with oauth2-proxy + Keycloak rather than paying.
   Open WebUI's license carries a >50-user branding clause. Vault is BSL, not
   OSI-open. DHI base images are a paid Docker feature the CI depends on.
   None of these block the design today, but all four are license surfaces to
   watch on upgrades.
2. **Portkey's paywall buys real labor.** The credential-persistence bug, the
   logout-redirect fix, and the upgrade-durability audit of the past two days
   are the operational cost of owning the platform. With Portkey those are
   someone else's pager — at the price of their cloud sitting in the request
   path (until Enterprise).
3. **Scale claims differ in kind.** Portkey advertises 400B+ tokens/day across
   200+ enterprises; this stack is one customer VM. If multi-tenant scale ever
   becomes the requirement, the comparison changes shape.

## Bottom line

For this customer profile — a hard requirement that no prompt, credential, or
log leaves customer-owned hardware — Portkey's free and $49 tiers are
disqualified on architecture, not features: their hosted control plane sits in
the data path, and the fixes (private deployment, SSO, audit logs, data
isolation) are exactly the Enterprise-tier items. The MIT gateway alone is a
router, not a platform — it would still need Keycloak, Vault, and the
observability stack built around it, i.e. most of what this repo already is.
What Portkey offers that this design deliberately lacks: managed prompt
tooling, semantic caching, polished usage analytics, and somebody else's
on-call rotation.
