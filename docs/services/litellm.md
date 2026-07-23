# litellm

## What it does

LiteLLM is the AI Gateway's single door to an AI model. Every chat message,
developer API call, and admin test request goes through this one proxy, which
holds the live model catalog, mints and checks gateway keys, enforces each
project's per-request and per-minute output caps, and is the only service
allowed to ask Envoy to reach a real AI provider.

## Who talks to it

- Open WebUI sends chat requests here over `net-chat`, authenticated with a
  scoped LiteLLM key (`OPENAI_API_KEY: ${WEBUI_LITELLM_KEY}`), never the
  master key.
- dev-portal and admin-portal both call LiteLLM's management API with the
  shared `LITELLM_MASTER_KEY` (`LITELLM_URL: http://litellm:4000`) to create
  keys and read model/price state; dev-portal's `/v1/models` filter also calls
  this API (`services/dev-portal/app/model_discovery.py`).
- key-rotator manages LiteLLM's provider credential objects over the OSS
  `/credentials` API (`services/key-rotator/app/litellm_client.py`) so
  provider secrets are never baked into `config.yaml` or an env var.
- LiteLLM calls Envoy for every provider request
  (`api_base: http://envoy-egress:8080/anthropic`) and posts prompt-free usage
  events to key-rotator (`http://key-rotator:8080/usage/events`, from
  `compose/litellm/aigw_usage_callback.py`).
- Traefik-int's `api` router on `api.<domain>` forwards only an exact list of
  inference and health paths here; anything else 403s before it arrives
  (`compose/traefik/dynamic-int.yml`).

## The load-bearing config

One model entry from `compose/litellm/config.yaml`:

```yaml
- model_name: claude-sonnet-4-5
  litellm_params:
    model: anthropic/claude-sonnet-4-5
    api_base: http://envoy-egress:8080/anthropic
    litellm_credential_name: anthropic-primary
    cache_control_injection_points: [{location: message, role: system}]
```

`model_name` is what a caller asks for; `api_base` always points at Envoy,
never a public Anthropic hostname, so no model entry can route around the
pinned egress path. `cache_control_injection_points` auto-stamps Anthropic's
prompt-caching header at the system message for every client, with no
client-side change needed.

## How you know it is healthy

The compose healthcheck calls `/health/readiness`, which LiteLLM turns to 503
specifically when its configured PostgreSQL connection is down — a plain
liveness check would miss that (`compose/docker-compose.yml`). For real
traffic health, watch `AIGatewayServiceLatencyHigh`/`Critical` and
`AIGatewayServiceErrorRateHigh`/`Critical` for the `litellm` service label in
Grafana; those come from real Traefik request data, not process liveness.

## Learn more

See [LiteLLM capacity and scaling](../litellm-scaling.md).
