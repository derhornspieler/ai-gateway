# key-rotator — upstream vendor API-key rotation (custom component)

> **IMPLEMENTED:** see `Dockerfile`, `requirements.txt`, and `app/` in this
> directory for the running service (FastAPI + APScheduler + hvac + psycopg,
> OTel-instrumented). Drivers: `app/drivers/anthropic_wif.py` (WIF from
> Keycloak) and `app/drivers/static_seed.py` (Anthropic static-key bootstrap
> for local/dev testing).
> The design docs below remain the source of truth for *why*; the code
> implements the v5 design from `docs/solution-map.md` §1.7 and
> `docs/anthropic-wif-bootstrap.md`.

## Configuration notes (current implementation)

- `ROTATOR_INTERNAL_TOKEN` is **required** (min 16 chars, no placeholders):
  the service refuses to start without it, and all routes except `/healthz`
  require a matching `X-Internal-Auth` header (constant-time compared).
- Keycloak client auth for the Anthropic WIF exchange is `private_key_jwt`
  (RFC 7523) — key from `KC_CLIENT_ASSERTION_KEY_FILE` (mounted PEM) or
  Vault KV v2 at `KC_CLIENT_ASSERTION_KEY_VAULT_PATH`
  (default `ai-gateway/anthropic-wif-client-key`, fields `private_key_pem`
  + optional `kid`). Static `kc_client_secret` fallback exists only behind
  `ANTHROPIC_WIF_ALLOW_INSECURE_CLIENT_SECRET=true` (dev only, logs ERROR).
- `JWKS_WATCH_INTERVAL_SECONDS` (default 300): Keycloak realm JWKS drift
  watcher. It persists and alerts on a candidate full JWKS/hash but never
  mutates the Anthropic issuer: that operation requires an interactive
  `org:admin` token which the inference broker must not receive. After the
  human update, record the exact approved hash as
  `federation_jwks_sha256` in the `ai-gateway/anthropic-wif` Vault doc.
The service also exposes the authenticated identity-administration controller
used by the admin portal. It bootstraps a least-privilege Keycloak controller,
manages the `aigw-managed` group tree, assigns existing Keycloak/federated
users to capability groups, invalidates affected sessions, and protects the
last managed administrator. When external LDAP is enabled, it also configures
the bounded read-only directory provider; deployments with LDAP disabled leave
that integration absent.

## Rotation cycle (per vendor, on schedule + on-demand)

1. Authenticate through the configured implemented driver:
   - **Anthropic**: Keycloak `private_key_jwt` exchange for short-lived WIF
     tokens; JWKS drift is detected and requires explicit operator approval.
   - **Static Anthropic seed**: explicit local/bootstrap path only.
2. Canary-verify new key **through envoy-egress** (pinned path).
3. Update LiteLLM credential (credentials API / DB) — hot reload, no restart.
4. Grace window, then revoke/deactivate old key.
5. Emit local OTel evidence plus a sanitized, structured rotation security
   event. Only that reviewed event may enter the Cribl SOC log feed; the raw
   span and ordinary service logs stay local.

## Non-goals

The service does not rotate LiteLLM virtual keys (the developer portal owns
that lifecycle), invent unsupported vendor APIs, or provide a generic
SOPS/OpenBao adapter. Vault CE KV v2, Anthropic WIF, and the static Anthropic
bootstrap driver are the supported scope. OpenAI is not a registered provider.
