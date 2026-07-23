# dev-portal

## What it does

dev-portal is the self-service developer portal — where a logged-in developer
creates their own gateway API key for an assigned project, sees a live model
list, and copies a getting-started example. It shows a newly created key's
plaintext exactly once, in the response that creates it, and never stores that
plaintext for later display.

## Who talks to it

- Developers reach it as a browser at `portal.<domain>` on the internal edge
  (`compose/traefik/dynamic-int.yml`); the same host's `api.<domain>` model
  discovery paths (`/v1/models`, `/models`) are also routed here, filtered by
  `services/dev-portal/app/model_discovery.py` rather than served by LiteLLM
  directly.
- dev-portal calls LiteLLM's management API with the shared master key
  (`LITELLM_URL: http://litellm:4000`, `LITELLM_MASTER_KEY`) to create and
  list keys.
- dev-portal calls key-rotator with a least-privilege token
  (`ROTATOR_INTERNAL_TOKEN: ${PORTAL_IDENTITY_TOKEN}`) that is only accepted
  for a read of the logged-in user's live project membership — never for any
  admin or rotation mutation.
- It logs users in through Keycloak (`OIDC_ISSUER`) using its own `dev-portal`
  OIDC client, distinct from admin-portal's client.

## The load-bearing config

The image's default command, from `services/dev-portal/Dockerfile`:

```
CMD ["/opt/venv/bin/python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1", "--no-server-header", "--no-access-log"]
```

`--workers 1` is not a resource-saving default — it's load-bearing. The portal
serializes its list/generate/deactivate checks for a given owner+project pair
with an in-process `asyncio.Lock` (`_project_lock` in
`services/dev-portal/app/main.py`), so a second worker process would let two
requests race past that lock and could mint two active keys for the same
project.

## How you know it is healthy

The compose healthcheck calls `/healthz`, which only proves the process is up
and responding — it does not check LiteLLM, key-rotator, or Keycloak
(`services/dev-portal/app/main.py`, `compose/docker-compose.yml`). For real
user-facing health, watch `AIGatewayServiceLatencyHigh`/`Critical` and
`AIGatewayServiceErrorRateHigh`/`Critical` for the `dev-portal` Traefik
service label.

## Learn more

See [Security model — Developer keys are shown once](../security-model.md#developer-keys-are-shown-once).
