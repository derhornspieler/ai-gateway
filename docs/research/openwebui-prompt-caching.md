# Prompt Caching for the Open WebUI → LiteLLM → Anthropic Path

This note explains why Anthropic prompt caching was off for chat traffic, how
it is turned on entirely inside LiteLLM without touching Open WebUI, what it
costs and saves, and the caveats that matter in this stack. It documents the
conservative first cut that ships alongside it: caching the system message
only. The surrounding LiteLLM design is in
[litellm-scaling.md](../litellm-scaling.md) and
[solution-map.md](../solution-map.md) §1, §1.7; the spend/telemetry boundary is
in [observability-operations.md](../observability-operations.md).

Upstream syntax below was confirmed against the LiteLLM docs
(`/websites/litellm_ai`, tutorials/prompt_caching and the
"save Claude Code costs with LiteLLM" blog) for the pinned image
`ghcr.io/berriai/litellm:v1.91.3`. Recheck it whenever that pin moves.

## 1. Baseline: caching was not enabled

Before this change, no request on the chat path carried a `cache_control`
marker, so Anthropic billed every input token at the full rate on every turn.

- **Open WebUI is a plain OpenAI client.** It talks to LiteLLM over
  `OPENAI_API_BASE_URL: http://litellm:4000/v1`
  (`compose/docker-compose.yml:553`) and sends OpenAI-format chat completions.
  The OpenAI wire format has no field for Anthropic cache breakpoints, and
  Open WebUI never adds one. Nothing on the client can request caching.
- **LiteLLM's config declared no caching.** In `compose/litellm/config.yaml`
  the two Anthropic models (`claude-sonnet` → `anthropic/claude-sonnet-4-5`,
  `claude-haiku` → `anthropic/claude-haiku-4-5`) carried only `model`,
  `api_base`, and `litellm_credential_name`; `litellm_settings` and
  `router_settings` held no cache directives. With no injection point and no
  client-supplied `cache_control`, every call was a full-price read.

So the gap was purely a LiteLLM configuration gap, not an Open WebUI or Envoy
limitation.

## 2. How caching reaches Anthropic through an OpenAI-format path

LiteLLM has an **Auto-Inject Prompt Caching** feature that stamps the Anthropic
`cache_control` marker at the proxy, after it has received the OpenAI-format
request and before it transforms the call into Anthropic's `/v1/messages`
shape. Two settings turn it on:

- Per model, under `litellm_params`:
  `cache_control_injection_points: [{location: message, role: system}]`. This
  tells LiteLLM to attach a cache breakpoint to the system message of every
  request routed to that model.
- Globally, in `router_settings`:
  `optional_pre_call_checks: ["prompt_caching"]`. This activates LiteLLM's
  `PromptCachingDeploymentCheck`, without which the per-model injection points
  are a no-op.

Because the injection happens **inside LiteLLM**, it is client-agnostic. Open
WebUI, the dev-portal, the admin-portal, and Claude Code all benefit with no
code or config change on their side — they keep sending ordinary OpenAI
requests, and LiteLLM adds the Anthropic-specific marker on the way out. This
is the key property: the fix lives in one reviewed config file and covers every
caller of the two Claude models at once.

The shipped first cut declares the injection point on `claude-sonnet` and
`claude-haiku` only. The `gpt` (OpenAI) model is deliberately left untouched —
`prompt_caching` there would be inert, and there is no reason to change it.

## 3. Cost and benefit

Anthropic prices the three token classes very differently:

- A **cache read** costs roughly **10%** of a normal input token.
- A **cache write** costs roughly **25% more** than a normal input token, paid
  once when the cached prefix is first stored.
- The cached prefix lives for a **5-minute** sliding TTL by default (a 1-hour
  option exists at a higher write premium).

The arithmetic: the first request pays the ~1.25× write premium; every later
request that reuses the same prefix within the TTL pays ~0.1× instead of 1.0×,
saving ~0.9× each time. The one-time write premium is recovered almost
immediately, so **roughly two uses of the same prefix inside the 5-minute
window already come out ahead**, and the margin widens with every additional
reuse.

That is exactly the shape of multi-turn chat. Each new user message re-sends
the entire prior conversation plus the system prompt, and the turns arrive
seconds apart — well inside the 5-minute TTL. A long, stable prefix (system
prompt today; growing history once the second injection point is added) is
therefore re-read on every turn, turning most of each request's input tokens
from full price into cache reads.

Where it is weak: one- or two-turn conversations with tiny prompts. There the
prefix is never reused enough to clear the write premium, and Anthropic will
not cache a prefix below its minimum cacheable length at all, so the feature is
simply a no-op rather than a loss.

Model note: **`claude-sonnet` gains the most in absolute terms** because its
per-token price is higher, so the ~0.9× saving per cached token is worth more
money. **`claude-haiku` gains proportionally** — the same multipliers apply to
a lower base rate, so the percentage saving is similar even though the absolute
dollars are smaller.

## 4. Caveats

- **This is a converge, not a runtime toggle.** `compose/litellm/config.yaml`
  is a bind-mounted, read-only config
  (`./litellm/config.yaml:/app/config.yaml:ro,Z`,
  `compose/docker-compose.yml:502`) whose content feeds the bind-source-digest
  contract (see §5). Editing it requires an Ansible re-converge; a manual
  `docker compose up` fails closed. You cannot flip caching on or off on a live
  host without going through the deploy path.
- **Credential rotation versus the cache.** `key-rotator` hot-swaps the
  `anthropic-primary` credential without restarting LiteLLM. Anthropic's cache
  is workspace-scoped and content-addressed — keyed by the prompt prefix
  content within the workspace, not by the individual API credential — so a
  rotation does not invalidate a live cache entry. At the 5-minute default TTL
  this is safe by a wide margin, because rotation cadence is far longer than
  the cache window. Before relying on the **1-hour** cache option, verify
  empirically that reads still land after a rotation by watching
  `cache_read_input_tokens` in the usage counters; do not assume it.
- **Observability changes shape.** Once caching is active, Anthropic splits the
  input token count into three fields — plain input, `cache_creation_input_tokens`
  (writes), and `cache_read_input_tokens` (reads) — and LiteLLM surfaces them
  in usage and in `LiteLLM_SpendLogs`. Any cost dashboard that assumes a single
  input-token number will now understate or misattribute cost. The Grafana cost
  work should read the three-way split so a cache read is not billed as a full
  input token. This is purely a token-accounting change:
  `store_prompts_in_spend_logs` stays `false`
  (`compose/litellm/config.yaml`), so no prompt content moves into the spend
  index — caching touches counters, not the content-storage boundary described
  in [observability-operations.md](../observability-operations.md).

## 5. Repo-discipline notes

- **`config.yaml` is already a digest input.**
  `compose/bind-source-digest-inputs.json` lists `"litellm":
  ["litellm/config.yaml"]`, so changing the file's **content** recomputes the
  LiteLLM bind-source digest (`AIGW_BIND_DIGEST_LITELLM`) automatically at
  converge. This is a content edit, not a bind-mount add or remove, so the
  five-place bind-mount sync described in `CLAUDE.md` is **not** triggered.
- **No exact-string contract test pins this file's body.** No test under
  `scripts/tests/` reads `litellm/config.yaml` or asserts its `model_list`,
  `litellm_settings`, or `router_settings` text, and `validate-compose.sh`
  computes the LiteLLM digest from content (it does not hardcode a value), so a
  content edit renders and validates without a paired test change.
- **`drop_params: true` does not strip the marker.** `drop_params` only removes
  top-level OpenAI parameters a provider's transformer does not support.
  `cache_control` is not a client-passed top-level param here — LiteLLM injects
  it inside message content as part of the native Anthropic transformation,
  which is the supported path for prompt caching. It is not a candidate for
  dropping, so a reviewer need not worry that `drop_params` defeats the
  feature.

## 6. Recommendation and rollout

1. **Enable the system-message injection point first** (the shipped first cut).
   The system prompt is the most stable, most-reused prefix and the lowest-risk
   place to start.
2. **Measure the cache-hit ratio in spend logs.** Compute
   `cache_read_input_tokens / (input_tokens + cache_read_input_tokens)` over
   real chat traffic to confirm reads are landing and to size the actual
   saving.
3. **Add the conversation-turn injection point only if justified.** A second
   point, `cache_control_injection_points: [{location: message, index: -2}]`,
   caches up to the second-to-last message so each turn's cache write becomes
   the next turn's cache read — the standard incremental-caching pattern for
   growing history. It is deferred here on purpose: it is worth adding once the
   measured hit ratio shows the extra breakpoint will pay for its write
   premium, and not before. Both points can coexist (Anthropic allows up to
   four cache blocks per request, and LiteLLM caps injection at that limit).
