# key-rotator — upstream vendor API-key rotation (custom component)

> **IMPLEMENTED:** see `Dockerfile`, `requirements.txt`, and `app/` in this
> directory for the running service (FastAPI + APScheduler + hvac + psycopg,
> OTel-instrumented). Drivers: `app/drivers/anthropic_wif.py` (WIF from
> Keycloak), `app/drivers/openai_svcacct.py` (blue/green service accounts),
> `app/drivers/static_seed.py` (static-key bootstrap for local/dev testing).
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
- `OPENAI_ORPHAN_CLEANUP_INTERVAL_SECONDS` (default 3600): retries
  delete/revocation-verification of service accounts orphaned by a
  partially-failed rotation.

The service also exposes the authenticated identity-administration controller
used by the admin portal. It bootstraps a least-privilege Keycloak controller,
manages the `aigw-managed` group tree, assigns existing Keycloak/federated
users to capability groups, invalidates affected sessions, and protects the
last managed administrator. In the explicit Parallels lab profile it also
configures the bounded Samba AD LDAP provider; generic deployments leave that
lab integration disabled.

## Rotation cycle (per vendor, on schedule + on-demand)

1. Authenticate through the configured implemented driver:
   - **Anthropic**: Keycloak `private_key_jwt` exchange for short-lived WIF
     tokens; JWKS drift is detected and requires explicit operator approval.
   - **OpenAI**: project service-account blue/green rotation using the
     organization admin credential stored in Vault, with durable recovery of
     ambiguous/partial promotion and revocation state.
   - **Static seed drivers**: explicit local/bootstrap path only.
2. Canary-verify new key **through envoy-egress** (pinned path).
3. Update LiteLLM credential (credentials API / DB) — hot reload, no restart.
4. Grace window, then revoke/deactivate old key.
5. Emit OTel span + audit event per rotation (→ Cribl).

## Non-goals

The service does not rotate LiteLLM virtual keys (the developer portal owns
that lifecycle), invent unsupported vendor APIs, or provide a generic
SOPS/OpenBao adapter. Vault CE KV v2 and the implemented Anthropic, OpenAI,
and static bootstrap drivers are the supported scope.
