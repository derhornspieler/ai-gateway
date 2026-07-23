# open-webui

## What it does

Open WebUI is the gateway's browser chat application — the only place a
regular user types a prompt and reads a reply. In this deployment it is
deliberately chat-only: no local file retrieval, no code execution, no
alternate model connections, and no local user accounts. It logs a user in
through Keycloak, then forwards every chat request to LiteLLM as the sole
model backend.

## Who talks to it

- People reach it as a browser: internal users at `chat.<domain>` on the
  internal edge, and VPN admins at the same `chat.<domain>` on the ADM edge as
  a second, source-restricted path (`compose/traefik/dynamic-int.yml` and
  `dynamic-adm.yml`) — both are the same application and OIDC client, just two
  network paths in.
- Open WebUI's only model backend is LiteLLM
  (`OPENAI_API_BASE_URL: http://litellm:4000/v1`), authenticated with a scoped
  key, never Open WebUI's own disabled API-key feature.
- It performs OIDC discovery, login, and logout against Keycloak's public
  `auth.<domain>` name, which resolves to the private Keycloak container over
  the shared `net-chat` bridge.
- On every chat request it sends LiteLLM one short-lived signed identity
  assertion (`FORWARD_USER_INFO_HEADER_JWT`) so LiteLLM's audit trail can
  trust who really sent the prompt.

## The load-bearing config

From `compose/docker-compose.yml`:

```yaml
ENABLE_PERSISTENT_CONFIG: "false"
OAUTH_ALLOWED_ROLES: "aigw-chat"
```

Open WebUI normally persists most settings in its own database after first
boot and ignores the environment from then on; pinning `ENABLE_PERSISTENT_CONFIG`
false forces every hardening setting below it to re-apply on every restart
instead of silently drifting. `OAUTH_ALLOWED_ROLES` is the actual chat gate —
a Keycloak login without the dedicated `aigw-chat` role, including a plain
developer or admin role, does not get into chat.

## How you know it is healthy

The compose healthcheck runs `aigw-health-probe http --url http://127.0.0.1:8080/health`,
an unauthenticated call that also proves basic database connectivity, with a
90-second start period to cover startup migrations
(`compose/docker-compose.yml`). For real user-facing health, watch
`AIGatewayServiceLatencyHigh`/`Critical` and
`AIGatewayServiceErrorRateHigh`/`Critical` for the `open-webui` Traefik
service label.

## Learn more

See [Container security — Open WebUI chat-only image](../docker-security.md#open-webui-chat-only-image).
