# admin-portal

## What it does

admin-portal is the first-party platform console for operators: user,
project, provider, model, and price control. It shares its image with
dev-portal but runs a distinct ASGI app, OIDC client, session cookie, and
container, and it is reachable only from the VPN admin edge. Every write
requires the `aigw-admins` role plus a login within the last
`ADMIN_STEP_UP_SECONDS` (300 seconds) — an old session cannot make a change.

## Who talks to it

- VPN admins reach it as a browser at `admin.<domain>` on the ADM edge only
  (`compose/traefik/dynamic-adm.yml`); it is not reachable from the internal
  edge at all.
- admin-portal calls LiteLLM's management API with the shared master key
  (`LITELLM_URL: http://litellm:4000`) — this is the governed path for model
  and price changes, since the ADM edge separately blocks LiteLLM's own native
  UI from serving its model-mutation API directly.
- admin-portal calls key-rotator with the full internal token
  (`ROTATOR_INTERNAL_TOKEN`, not dev-portal's read-only project-membership
  token) for user, project, provider, model, and price operations. It only
  requires key-rotator to have started, not be healthy — a fresh or sealed
  Vault keeps key-rotator's readiness at 503 until the unseal ceremony runs,
  and requiring health here would deadlock the first converge.
- It logs admins in through Keycloak using its own `admin-portal` OIDC client.

## The load-bearing config

The container's explicit command, from `compose/docker-compose.yml`:

```yaml
command:
  - /opt/venv/bin/python
  - -m
  - uvicorn
  - app.main:admin_app
  - --host
  - 0.0.0.0
  - --port
  - "8080"
  - --workers
  - "1"
```

Unlike dev-portal's default image command, admin-portal overrides it to load
`app.main:admin_app` — the same image, a different ASGI app. `--workers 1`
still matters here for its own reason: an in-process lock
(`_admin_key_policy_lock` in `services/dev-portal/app/main.py`) serializes
policy cutovers against manual key edits inside this one process; a second
worker would let the two race.

## How you know it is healthy

The compose healthcheck calls `/healthz`, which only proves the process is up
— it does not check LiteLLM, key-rotator, or Keycloak
(`services/dev-portal/app/main.py`, `compose/docker-compose.yml`). For real
user-facing health, watch `AIGatewayServiceLatencyHigh`/`Critical` and
`AIGatewayServiceErrorRateHigh`/`Critical` for the `admin-portal` Traefik
service label.

## Learn more

See [Security model — Model and price policy is append-only](../security-model.md#model-and-price-policy-is-append-only).
