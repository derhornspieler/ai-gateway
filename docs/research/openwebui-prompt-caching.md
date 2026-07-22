# Prompt caching in the Open WebUI path

This note explains the prompt-caching path used by the current release:

```text
Open WebUI -> LiteLLM -> Envoy -> Anthropic
```

The current LiteLLM image is `v1.93.0`. Anthropic is the only configured
provider. The exact model list lives in
[`compose/litellm/config.yaml`](../../compose/litellm/config.yaml).

For the larger system design, see the [solution map](../solution-map.md),
[LiteLLM scaling guide](../litellm-scaling.md), and
[observability guide](../observability-operations.md).

## What the client sends

Open WebUI sends an OpenAI-compatible chat request to LiteLLM. It does not add
Anthropic cache markers. This is expected. Open WebUI should not need provider
rules.

LiteLLM adds the Anthropic `cache_control` marker before it changes the request
into Anthropic's message format. Every current model entry has this setting:

```yaml
cache_control_injection_points: [{location: message, role: system}]
```

The router also has this required check:

```yaml
optional_pre_call_checks: ["prompt_caching"]
```

Both settings are needed. The first one selects the system message. The second
one turns on LiteLLM's prompt-caching check.

No OpenAI provider or model is configured. Adding another provider would need
its own reviewed catalog, model, credential, and release changes. See
[provider onboarding](../provider-onboarding.md).

## Why the system message is cached first

The system message is usually the most stable part of a chat. Many turns reuse
it without changes. A cache read costs less than sending the same input again,
while the first cache write costs more. Reuse is what makes caching useful.

Provider prices, minimum cache sizes, and cache life can change. Check the
current Anthropic pricing and prompt-caching documentation before you estimate
savings. Do not copy old prices into a budget or release decision.

This release does not add a second cache point for the growing conversation.
That may improve long chats, but it also creates more cache writes. Add it only
after real measurements show that it helps.

## What caching does not change

Prompt caching does not change these security rules:

- Open WebUI still signs its short-lived user assertion.
- LiteLLM still checks the exact Open WebUI workload key and signed assertion.
- Gateway keys still control projects and allowed models.
- Envoy remains the only provider network path.
- The selected provider route and CA bundle stay fixed in the Envoy image.
- `store_prompts_in_spend_logs` stays `false`.

Caching changes provider request content and token counters. It does not make a
new provider route or a new prompt store.

## Metrics and cost records

Anthropic responses may split input use into normal input, cache creation, and
cache read counters. A cost report must handle all three. A report that reads
only the normal input count can show the wrong cost.

Prompt and reply content uses the protected request-audit path. It must not be
copied into LiteLLM spend logs just to measure caching. Use approved counters
and synthetic prompts for a test when possible.

Measure at least:

- cache-read input tokens;
- cache-creation input tokens;
- normal input tokens;
- request count and latency; and
- provider cost for the same test period.

Compare a stable test before and after the change. A successful request alone
does not prove that a cache read occurred.

## Safe change and test flow

`compose/litellm/config.yaml` is a read-only bind mount and a bind-digest
input. A content change makes Ansible recreate LiteLLM with the new digest.
Do not edit the deployed file and do not run `docker compose up` by hand.

Some contract tests read this config directly. After a caching change, run the
normal release checks from the repository root:

```bash
bash scripts/validate-compose.sh
python3 -I -m unittest discover -v -s scripts/tests -p 'test_*.py'
```

Then build a new schema-v2 offline seed and run the clean-room local PreProd
test. Follow the [image update workflow](../image-update-workflow.md) and
[acceptance test runbook](../test-runbook.md). Local PreProd uses the fixed
domain `aigw.internal`; no test VM is needed.

Accept the change only when request identity, model rules, prompt redaction,
telemetry, and mock inference still pass with the exact seed.
