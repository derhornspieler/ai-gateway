# Key rotator and identity controller

This Python service manages Anthropic credentials and the Keycloak identity
state used by AI Gateway. The running code is in `app/`. The image build and
locked dependencies are in `Dockerfile`, `requirements.txt`, and
`requirements.lock`.

Read the [solution map](../../docs/solution-map.md) for the full system and the
[Anthropic WIF guide](../../docs/anthropic-wif-bootstrap.md) for the provider
flow.

## API protection

`ROTATOR_INTERNAL_TOKEN` is required. It must have at least 16 characters and
cannot be a placeholder. Every route except `/healthz` requires the same value
in `X-Internal-Auth`. The comparison is constant-time.

The service runs one process. Do not add workers or replicas. Its safety locks
are local to that process.

## Anthropic WIF

Production uses Keycloak `private_key_jwt`. The private key comes from one of
these reviewed sources:

- `KC_CLIENT_ASSERTION_KEY_FILE`, for a mounted test key; or
- Vault KV v2 at `KC_CLIENT_ASSERTION_KEY_VAULT_PATH`, which defaults to
  `ai-gateway/anthropic-wif-client-key`.

The Vault record contains `private_key_pem` and may contain `kid`.

There is no production shared-secret fallback. The development-only fallback
requires `ANTHROPIC_WIF_ALLOW_INSECURE_CLIENT_SECRET=true` and logs an error.
Never enable it in production.

`JWKS_WATCH_INTERVAL_SECONDS` defaults to 300 seconds. The watcher records a
changed Keycloak public-key set and raises an alert. It does not update the
Anthropic issuer. A human Anthropic organization administrator must approve
that change with a fresh `org:admin` session.

## Credential rotation

Each planned or manual Anthropic rotation follows this order:

1. Use Keycloak WIF to get a short-lived provider token.
2. Check the new token through Envoy, the only provider path.
3. Update the `anthropic-primary` LiteLLM credential without a restart.
4. Wait for the reviewed grace period.
5. Revoke or stop using the old token.
6. Write bounded local history and a structured security event with no secret.

The static Anthropic seed driver exists only for an explicit local or bootstrap
path. OpenAI is not a registered provider.

This service does not rotate LiteLLM virtual keys. The developer portal owns
those keys.

## Identity control

The admin portal uses this service for the managed Keycloak state. It:

- creates the least-privilege `aigw` identity controller;
- manages the `aigw-managed` group tree;
- assigns existing Keycloak or federated users to capability groups;
- closes affected sessions after membership changes;
- prevents removal of the last managed administrator; and
- sets up the bounded, read-only LDAPS provider when LDAPS is enabled.

Ansible starts this work automatically after Vault and LDAPS inputs are ready.
The admin portal has no platform-initialization step. For exact redirects and
the operator flow, see [identity operations](../../docs/identity-operations.md).

## Logs and history

Raw service logs and traces stay local. The service emits a small set of
reviewed security events for rotation and identity changes. Those records use
fixed fields and remove secret details before Alloy may send them to Cribl.
See the [Cribl SOC handoff](../../docs/cribl-soc-handoff.md).

## Test this service

Run the service checks from this directory:

```bash
PYTHONPATH=. pytest -q
ruff check app tests
bandit -q -r app --severity-level medium --confidence-level medium
```

The full release gate also loads the exact offline seed into local Docker
PreProd at `aigw.internal`. Follow the
[acceptance test runbook](../../docs/test-runbook.md). No rehearsal VM is
needed.
