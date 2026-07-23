# vault-ui-proxy

## What it does

vault-ui-proxy is an optional, minimal Go reverse proxy that serves Vault's
static browser UI assets and forwards only `/v1` API calls to the real Vault
backend. It exists so operators can get a browser UI without running
HashiCorp's upstream UI-enabled Vault binary. It runs only when the
`vault-ui` Compose profile is turned on (`profiles: [vault-ui]` in
`compose/docker-compose.yml`).

## Who talks to it

- `oauth2-proxy-vault` is its only client. Every UI or API request is gated
  behind Keycloak OIDC login and the `aigw-admins` group first
  (`OAUTH2_PROXY_UPSTREAMS: http://vault-ui-proxy:8080`, and it will not
  start until this proxy reports healthy).
- Traefik's ADM edge routes `vault.<domain>` to `oauth2-proxy-vault`, not
  directly to this proxy (`compose/traefik/dynamic-adm.yml`).
- This proxy is, in turn, the only thing that talks onward to Vault: its
  upstream is fixed at build time (see below), over the private `net-vault`
  network — its sole network.
- It depends on `vault: { condition: service_started }`, the same
  first-converge reasoning as `key-rotator`: a freshly installed Vault can be
  running but still sealed and uninitialized.

## The load-bearing config

From `services/vault-ui-proxy/main.go`:

```go
vaultUpstream = "http://vault:8200"
```

The upstream is a compile-time constant, not a config file or environment
variable. The compose file's comment on this service states it directly: "No
environment variable or request field can select another upstream." A
compromised caller cannot redirect this proxy to a second Vault backend.

## How you know it is healthy

The compose healthcheck runs the binary's own `check` subcommand
(`test: [CMD, /usr/local/bin/vault-ui-proxy, check]`). It deliberately treats
Vault's sealed (503) and not-yet-initialized (501) responses as healthy,
alongside 200, 429, 472, and 473
(`acceptedVaultHealthStatuses` in `services/vault-ui-proxy/main.go`) —
those are legitimate operator states for the proxy to be up in front of, not
failures of the proxy itself.

## Learn more

See [AI Gateway solution map — Running services](../solution-map.md#running-services).
