# Automatic model routing decision record

Status: Proposed

Date: 2026-07-22

## Summary

Automatic model routing is not active today.

The name `aigw-auto` is reserved for possible future use. The gateway denies
that name for every key type. It also denies every request from a key whose
project default is set to `aigw-auto`. This is intentional. It stops an
unfinished routing feature from becoming active by mistake.

This record keeps routing disabled until the model catalog, prices, limits,
privacy rules, tests, and rollback process are complete. A later decision must
approve activation. This proposed record does not approve activation.

## Problem

People may want the gateway to choose a model for a request. A router could
pick a smaller model for simple work and a larger model for hard work. That
may lower cost or improve speed. A bad choice could also lower answer quality,
break a project limit, reveal a prompt to another service, or use a model the
caller is not allowed to use.

The gateway needs one clear rule while this feature is unfinished. It also
needs safety rules for any future design.

## Decision

We choose **no automatic routing for now**.

The current rules are:

1. Reserve the exact model name `aigw-auto`.
2. Return the existing HTTP 400 policy error when a request uses that name.
3. Apply the denial to portal, operator, service, unrestricted, wildcard, and
   Open WebUI keys.
4. Treat `aigw-auto` as an invalid project default. Deny every request from
   that key until the project policy is fixed.
5. Do not send a prompt to a second model, classifier, embedding service, or
   provider to decide where the prompt should go.
6. Keep an explicit normal model request working as it does today, unless the
   key contains an invalid routing policy.
7. Fail closed when routing policy or required data is missing, invalid, or
   out of date.

A future release may activate routing only after a new review approves the
design and all gates in this record pass.

## Options considered

| Option | Privacy | Extra cost | Latency | Quality | Audit and operations |
| --- | --- | --- | --- | --- | --- |
| No routing | The prompt goes only to the model the caller chose. | No routing cost. | No routing delay. | The caller owns the model choice. There is no automatic correction for a poor choice. | Simple to explain, test, and roll back. This is the current choice. |
| Local deterministic rule router | Rules run inside the gateway. The prompt must not leave the gateway for classification. | Small local CPU cost. There is no second provider charge. | Usually a small local delay. | Easy to predict, but simple rules may choose the wrong model for unusual prompts. | Clear reason codes and repeatable choices. Rules must be reviewed, versioned, and tied to the offline seed. This is the leading future candidate. |
| LiteLLM Auto Router v2 | Acceptable only when the exact shipped version proves that the approved mode runs locally and makes no second prompt disclosure. | Depends on the exact mode and release. Any mode with a paid classifier is not allowed by this decision. | Depends on the exact mode and release. It must be measured in PreProd. | It may classify request difficulty better than simple rules, but behavior may change between versions. | It may reduce custom code, but the exact API, defaults, logs, failure behavior, and upgrade path must be pinned and tested. It remains an evaluation option. |

An external LLM classifier and an external embedding service are not approved
options. A prompt must not be copied to one provider so that another provider
can answer it.

## Why this decision is safe

The reserved name gives clients and future code one stable name without
turning on an unfinished feature. Denying it by default is safer than guessing
a model. It also gives tests a clear result: routing is either approved and
fully ready, or the request fails with HTTP 400.

A local deterministic router is the easiest future design to review. The same
input and policy should produce the same result. LiteLLM Auto Router v2 may be
useful, but only after the exact image proves what it does. Upstream defaults
or documentation are not enough.

## Gates before any future activation

Every gate below is required. A missing gate means routing stays disabled.

### Caller and model eligibility

The router may choose only from the intersection of:

- active models in the reviewed model catalog;
- models assigned to the caller's project;
- models in the caller's exact key allowlist;
- providers included in the loaded immutable Envoy policy;
- models with complete price data;
- models with complete limit policy; and
- models with healthy limit counters and enough remaining capacity.

Wildcard or empty model access is not enough. The caller must have an exact
eligible model list. Operator keys, service keys, and the shared Open WebUI key
must remain unable to use `aigw-auto` unless a later decision names and tests a
safe use for each key type.

The gateway must check eligibility before selection and check the selected
model again before provider dispatch. If the checks disagree, the request is
denied.

### Catalog, price, and limit completeness

Every routing target must have:

- one active catalog entry with a stable gateway model name;
- one provider that exists in the exact offline release;
- complete prices for every token class that provider may bill;
- a clear price version and effective time;
- all required request, rate, token, and money limits; and
- healthy storage needed to reserve those limits.

Unknown does not mean zero. A missing price, missing limit, failed counter,
stale policy digest, or failed reservation removes that model from the
eligible set. If no model remains, the gateway denies the request.

### Immutable policy

Routing profiles must be committed and reviewed release data. A profile must
have a canonical digest and must name its exact target models, rules, default
behavior, and reason codes. The offline-seed manifest must bind that digest to
the LiteLLM image and provider policy in the same release.

The admin portal may enable a reviewed profile for a project in a future
release. It must not accept arbitrary models, rules, weights, provider URLs,
classifier URLs, or fallback targets.

### Privacy

The selected provider may receive the prompt once for the requested
inference. The routing step must not send the prompt to a separate provider,
classifier model, embedding endpoint, traffic mirror, or analytics service.

A local router may read only the request fields it needs. It must not save or
log the prompt, reply, credentials, or headers. Tests must prove that normal
logs, error logs, traces, and routing audit records do not contain them.

### Cost and latency

The router must not create a second provider charge. Local CPU and memory use
must be measured. PreProd tests must report routing time separately from
provider time. The release review must set a routing latency limit before
activation.

Price-based choices may use only complete, versioned price data. The audit
record must show the price-policy revision used. The router must not describe
a configured estimate as a provider invoice.

### Quality

Tests need a committed set of safe sample requests with expected route reason
codes. They must cover short, long, simple, complex, malformed, and ambiguous
requests. Test prompts must contain no real user or production data.

Quality tests must compare each routed result with the approved baseline. A
route that is cheaper or faster is not acceptable when it breaks the required
task. The release owner must approve the quality limits and the test set.

## Request behavior

Routing may run only when all of these statements are true:

1. The caller requests the exact reserved name `aigw-auto`.
2. The caller's project has enabled one reviewed routing profile.
3. The profile digest matches the loaded release.
4. The full eligible-model set passes every gate.
5. The routing engine returns one valid model and one known reason code.
6. The selected model passes access, price, and limit checks again.

Any other result is an HTTP 400 policy denial. The gateway must not guess,
silently widen access, or send the request to an unreviewed default.

An explicit normal model request is an override of automatic selection. It
still must pass the normal key, project, provider, price, and limit checks. A
caller cannot override a deny, add a route target, change rule weights, or
select a fallback through request fields.

## Audit requirements

Each routing attempt must record:

- time and request correlation ID;
- trusted user and project IDs;
- routing profile revision and digest;
- offline release and provider-policy digests;
- eligible model IDs before selection;
- selected model, or denial reason;
- stable route reason code;
- price and limit policy revisions;
- whether the project default was considered;
- retry or fallback result; and
- final policy result.

The record must not contain the prompt, reply, key, token, authorization
header, cookie, or raw classifier input. Audit delivery failure must follow
the approved security-log back-pressure rule. It must not silently discard a
routing decision.

## Fallback and retry

The first routing release must not use cross-model fallback. It may use only
the current bounded retry behavior for the one selected model.

When no rule matches, the profile may name the project's normal default only
if that default is still in the exact eligible set. Otherwise the request is
denied. This default choice must have its own reason code.

A later cross-model fallback needs a separate review. Every fallback target
must pass the same caller, catalog, provider, price, and limit checks as the
first target. A failed target must never cause a wider or cheaper access rule
to be used automatically.

## Exact-seed PreProd acceptance

Source-tree tests are not enough. The exact release candidate must pass this
flow before routing can be approved:

1. Build the candidate images and routing policy.
2. Record their IDs and digests in one offline-seed manifest.
3. Destroy the local PreProd deployment, its test volumes, and its test
   images so stale state cannot hide a problem.
4. Load only the generated offline seed.
5. Deploy local PreProd with the Ansible playbook and with outside image pulls
   disabled.
6. Prove the running LiteLLM image, routing profile, provider policy, and
   catalog match the manifest.
7. Run the eligibility, privacy, price, limit, latency, quality, audit,
   override, retry, fallback, and fail-closed tests.
8. Test malformed, missing, stale, and mismatched policy data.
9. Test the current deny-by-default release and the proposed enabled release.
10. Roll back to the prior exact seed and rerun the full health and request
    tests.
11. Tear down PreProd after the final result.

The enabled release fails acceptance if it pulls an image, policy, model,
price, or classifier at deployment or request time.

## Rollback

The router code, reviewed profile, catalog projection, LiteLLM image, Envoy
provider policy, and offline manifest form one release unit. They must move
forward and backward together.

The first safety action is to disable the project routing profile. Requests to
`aigw-auto` must then return HTTP 400 again. An image rollback must load the
prior exact offline seed, restore its matching policy digests, validate every
service, and confirm that ordinary explicit model requests still work.

A rollback must never map `aigw-auto` to a guessed model. If the old release
cannot prove a complete matching policy, it must keep the alias denied.

## Consequences

The gateway gains no automatic model choice now. Clients must name an allowed
model or omit the model only where the existing project-default rule applies.

This delays possible cost and speed gains, but it prevents an unfinished
router from weakening access rules or creating a second prompt disclosure. It
also gives a future implementation a clear test, audit, and rollback contract.

## Questions required for the activation decision

Before activation, the later review must answer:

- Which exact router implementation and image version passed PreProd?
- Which local request fields does it inspect?
- What is the measured latency and local resource cost?
- What quality test set and limits did the release owner approve?
- Which projects and key types may enable routing?
- What committed profiles and reason codes exist?
- How are price and limit completeness proved at runtime?
- How does audit back-pressure fail safely?
- What exact seed is the tested rollback target?

Until every answer is reviewed and tested, `aigw-auto` remains reserved and
denied.
