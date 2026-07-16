# Anthropic Workload Identity Federation

For the step-by-step operator procedure, start with the
[Anthropic WIF setup SOP](sop/anthropic-wif-jwt-setup.md); this document is
the authoritative reference behind it.

This runbook describes the implemented Keycloak-to-Anthropic WIF path, which has
two deliberately separate authority domains. AI Gateway automatically creates
and proves the Keycloak broker's `private_key_jwt` key, mints short-lived
workload assertions, exchanges them through pinned Envoy egress, and refreshes
LiteLLM. A human Anthropic organization administrator creates the initial issuer,
service account, and federation rule, and manually approves every inline-JWKS
change.

The inference broker never receives `org:admin`. Anthropic issuer mutation
requires an `org:admin` OAuth bearer, and granting that authority to the
inference path would turn a model-credential compromise into organization-wide
administration; the recurring watcher therefore detects and records drift but
makes no Anthropic administration call. The external product behavior here was
checked against the official Anthropic WIF documentation on 2026-07-12 — recheck
the linked API contract at deployment time, because it is outside this
repository's version control. The identity controller that performs the Keycloak
side of this flow is documented in
[identity-operations.md](identity-operations.md); see
[solution-map.md](solution-map.md) for the egress trust boundary and
[project-status.md](project-status.md) for overall posture.

## Current lab execution status

The 2026-07-13 replacement-VM recovery did **not** configure the customer-side
Anthropic issuer, rule, service account, workspace, or approved inline JWKS.
Consequently real WIF exchange, Anthropic Envoy traversal, LiteLLM inference, and
inference-derived telemetry are **NOT EXECUTED**. A portal lifecycle canary
received a LiteLLM HTTP 401 before Envoy and was safely cleaned up; the zero
Envoy delta is evidence that no provider request occurred, not a network or
inference pass. A separate synthetic collector test passed the in-stack Alloy
transform and export path with fabricated non-sensitive spans; it does not
exercise Keycloak token minting, Anthropic exchange, LiteLLM, Envoy, provider
billing or workspace attribution, or model output. Complete every external
ceremony and the real canary below before changing the Anthropic/WIF
disposition. This matches the honest posture recorded in
[test-runbook.md](test-runbook.md) and [project-status.md](project-status.md):
customer prototype, Vault in lab/test mode, Anthropic inference not executed.

## Implemented Keycloak contract

The `anthropic-wif` realm is separate from the user-authentication `aigw` realm
and advertises a distinct fabricated frontend URL,
`https://idp.wif-a.example.invalid`. Its broker client `anthropic-token-broker`
is imported disabled with service accounts enabled, `client-jwt`
(`private_key_jwt`) authentication, RS256, no shared-secret fallback, a
600-second access-token lifetime, and audience `https://api.anthropic.com`.

During portal **Initialize identity control**, key-rotator keeps the broker
disabled while changing credentials, asks Keycloak to generate a 3072-bit
PKCS#12 keypair under a one-use random archive password, extracts the private
key in memory and stores it only at the Vault KV-v2 path
`ai-gateway/anthropic-wif-client-key` under the `kv/` mount (configured by
`KC_CLIENT_ASSERTION_KEY_VAULT_PATH`; a mounted PEM at
`KC_CLIENT_ASSERTION_KEY_FILE` is an alternative source), registers the public
certificate on the Keycloak client, reconciles one deterministic hardcoded
access-token subject mapper, enables the broker, proves `private_key_jwt` works,
and decodes the returned token locally. It fails closed unless these exact claims
are present:

```text
sub = service-account-anthropic-token-broker
aud contains https://api.anthropic.com
```

The mapper is necessary because Keycloak's native service-account `sub` is an
internal user UUID that changes across realm recreation or restore.
Initialization rejects a competing `sub` mapper, and the broker stays disabled
whenever key generation, the Vault write, the client proof, or the claim proof
fails. This mapper and client-credentials behavior was runtime-verified against
the repository-pinned DHI Keycloak 26.6.4 image: `sub` was the stable value
above, `aud` contained the Anthropic audience, and `azp`/`client_id` identified
`anthropic-token-broker`. Treat the runtime claim validator, not assumptions
about Keycloak defaults, as the release gate after any image upgrade. No operator
should import a private key through Keycloak or the portal; the portal displays
only a SHA-256 certificate fingerprint.

## Prerequisites

Complete the full three-interface deployment and Vault bootstrap and unseal,
complete portal identity initialization, and record a ready WIF broker plus its
certificate fingerprint. Confirm time synchronization on the host and on the
Anthropic administrator's workstation, and identify the approved Anthropic
organization and workspace. The one-time Console ceremony requires an Anthropic
Admin, Owner, or Primary Owner; an Admin API key is not accepted for WIF
administration. Decide the narrowest rule scope: `workspace:inference` is
preferred for this gateway's Messages and Models calls, and `workspace:developer`
is used only if an approved workload also needs non-inference workspace APIs.

## One-time external bootstrap

### 1. Export the public JWKS and canonical hash

Run from `/opt/ai-gateway` on the target. This prints public keys only; it never
mints or prints a bearer token, and its canonicalization matches the watcher's
exactly (keys sorted by `kid` then `alg`, compact separators):

```bash
scripts/aigw-compose.sh exec -T key-rotator python3 - <<'PY'
import hashlib
import json
import urllib.request

url = (
    "http://keycloak:8080/realms/anthropic-wif/"
    "protocol/openid-connect/certs"
)
discovery_url = (
    "http://keycloak:8080/realms/anthropic-wif/"
    ".well-known/openid-configuration"
)
with urllib.request.urlopen(url, timeout=10) as response:
    keys = json.load(response)["keys"]
with urllib.request.urlopen(discovery_url, timeout=10) as response:
    issuer = json.load(response)["issuer"]
ordered = sorted(
    keys,
    key=lambda key: (str(key.get("kid", "")), str(key.get("alg", ""))),
)
canonical = json.dumps(ordered, sort_keys=True, separators=(",", ":"))
print(json.dumps({"type": "inline", "keys": keys}, indent=2))
print("issuer_url=" + issuer)
print("federation_jwks_sha256=" + hashlib.sha256(canonical.encode()).hexdigest())
PY
```

Record the hash in the controlled deployment evidence and copy the complete
`keys` array — never a private key. If the command returns no keys or the broker
is not ready, stop rather than creating an unverified federation.

### 2. Create the Anthropic resources

In Claude Console, open **Settings → Workload identity → Connect workload** and
choose **Custom OIDC**. Create an inline federation issuer whose issuer URL is
exactly `https://idp.wif-a.example.invalid/realms/anthropic-wif` for the
committed realm profile — or the exact `issuer_url` printed by the helper for a
reviewed environment — with JWKS type `inline` carrying the full `keys` array
from step 1, replay/JTI checking enabled, and a maximum assertion lifetime
compatible with the 600-second Keycloak token lifetime. Create a developer-role
service account named for AI Gateway and add it to the target workspace. Then
create a federation rule that pins the exact subject
`service-account-anthropic-token-broker` with no wildcard, the exact audience
`https://api.anthropic.com`, the new service account as target, only the approved
workspace, `workspace:inference` unless broader developer APIs are explicitly
required, and a short access-token lifetime, normally 600 seconds.

An audience-only rule is invalid and unsafe; the exact subject is the workload
identity boundary. Do not use a trailing `*`, do not match the Keycloak-native
UUID, and do not create an `org:admin` rule for this broker. Record the returned
issuer (`fdis_...`), rule (`fdrl_...`), service-account (`svac_...`),
organization UUID, and workspace (`wrkspc_...`) identifiers; they are
configuration identifiers rather than bearer credentials, but still belong in the
controlled Vault record rather than browser storage.

### 3. Create the rotator bootstrap record

Establish a Vault operator token through the approved process. The example passes
it as an ephemeral exec environment variable, not an argument, and supplies the
recorded identifiers without angle brackets:

```bash
cd /opt/ai-gateway
read -rsp 'Vault operator token: ' VAULT_TOKEN; printf '\n'
export VAULT_TOKEN
scripts/aigw-compose.sh exec -T -e VAULT_TOKEN vault vault kv put \
  kv/ai-gateway/anthropic-wif \
  kc_token_url=http://keycloak:8080/realms/anthropic-wif/protocol/openid-connect/token \
  kc_client_id=anthropic-token-broker \
  federation_issuer_id=fdis_... \
  federation_rule_id=fdrl_... \
  organization_id=00000000-0000-0000-0000-000000000000 \
  service_account_id=svac_... \
  workspace_id=wrkspc_... \
  federation_jwks_sha256=<64-character-hash-from-step-1>
unset VAULT_TOKEN
```

The driver requires `kc_token_url`, `kc_client_id`, `federation_rule_id`,
`organization_id`, and `service_account_id`; it validates `kc_token_url` against
the configured `KEYCLOAK_URL` origin and the canonical
`/realms/<realm>/protocol/openid-connect/token` path. `workspace_id` is required
only when the rule covers multiple workspaces and is kept here even for a single
workspace to make the billing and rate-limit boundary explicit.
`federation_jwks_sha256` is required for the watcher to accept its first
baseline. `federation_issuer_id` is retained for operator evidence only; the
watcher does not use it to mutate Anthropic.

### 4. Prove exchange and promotion

In the admin portal, enable the Anthropic WIF rotation row with the reviewed
interval and grace values and trigger **Rotate now**. It passes only if Keycloak
`private_key_jwt` authentication succeeds, the local stable-subject and audience
validation succeeds, `POST /v1/oauth/token` traverses `envoy-egress` and returns
a short-lived `sk-ant-oat01-...` token, the LiteLLM credential
`anthropic-primary` is updated, an inference canary succeeds through
`api.<domain>`, and the `anthropic.token_exchange` and `anthropic.jwks` health
flags are healthy without printing the assertion or access token. The first
successful JWKS watcher pass accepts a baseline only when the live canonical hash
equals `federation_jwks_sha256`; a matching hash is an operator attestation that
the Console's inline keys were updated, not proof by itself, so the token
exchange remains mandatory.

## Recurring automated token flow

For every scheduled or manual rotation, key-rotator signs a unique 60-second RFC
7523 client assertion with the Vault-held broker key, where `iss` and `sub` are
both `anthropic-token-broker` and the audience is the WIF realm's canonical
frontend token endpoint
(`https://idp.wif-a.example.invalid/realms/anthropic-wif/protocol/openid-connect/token`).
That audience is deliberately the public/frontend URL, which Keycloak validates,
even though the POST itself stays on the internal `keycloak:8080` origin and is
never routed through egress. key-rotator then obtains a 600-second Keycloak
service-account access token and verifies the stable `sub` and Anthropic audience
locally, exchanges that JWT at Anthropic's `/v1/oauth/token` through Envoy using
the recorded rule, organization, service-account, and workspace identifiers,
promotes the returned short-lived bearer into the LiteLLM `anthropic-primary`
credential, and schedules the next refresh at roughly 80% of the reported
lifetime.

Failures use bounded exponential backoff with jitter, capped so a persistent
failure never idles past the normal refresh cadence. If the active token is past
90% of its lifetime while refresh keeps failing, the rotator raises an explicit
inference-at-risk alert. The driver never silently falls back to a static client
secret: `ANTHROPIC_WIF_ALLOW_INSECURE_CLIENT_SECRET` is a development escape
hatch that must remain false in production and logs an error on every use.

## Manual inline-JWKS rotation

Inline JWKS has no remote discovery, so rotate Keycloak signing keys without an
exchange outage. Add the new Keycloak realm signing provider at a lower priority
so its public key is published while the old key still signs. Wait for
`anthropic.jwks` to report the candidate canonical SHA-256 and independently
export the full old-plus-new JWKS with the helper above. Using a fresh
interactive Anthropic `org:admin` Console session, replace the issuer's entire
inline `keys` array — do not give that token to key-rotator or store it in Vault.
Then patch only the approved hash in the existing Vault document:

```bash
read -rsp 'Vault operator token: ' VAULT_TOKEN; printf '\n'
export VAULT_TOKEN
scripts/aigw-compose.sh exec -T -e VAULT_TOKEN vault vault kv patch \
  kv/ai-gateway/anthropic-wif \
  federation_jwks_sha256=<new-64-character-canonical-hash>
unset VAULT_TOKEN
```

Wait for watcher history `manual_update_confirmed` and a healthy
`anthropic.jwks`, then make the new Keycloak key active and prove a fresh token
exchange and inference. After every old assertion has expired, retire the old
Keycloak key and repeat the full-array Console update and approved-hash patch for
the resulting key-removal drift.

The watcher persists the pending public JWKS and hash and emits one history row
per newly observed candidate without five-minute log spam. It never assumes a
first observation is correct after database loss or restore. Do not clear an
alert by writing the candidate hash before the Anthropic Console update; that
records a false operator attestation and the next token exchange can still fail.

## Troubleshooting and recovery

| Symptom | Check |
|---|---|
| Keycloak client authentication fails | broker fingerprint, Vault key path, client enabled state, `client-jwt` authenticator, canonical frontend token audience |
| "unstable subject claim" | identity initialization completed, one hardcoded `sub` mapper exists, no competing subject mapper |
| missing Anthropic audience | `anthropic-audience` mapper and exact `https://api.anthropic.com` value |
| Anthropic `invalid_grant` | exact issuer, subject, audience, expiry/clock, rule and workspace IDs, service-account membership, and current inline JWKS in Console history |
| `baseline_unconfirmed` | export live JWKS, update the Console with an interactive org admin, then record the exact canonical hash in Vault |
| `drift_detected` | complete the manual old-plus-new or key-removal ceremony; do not activate or retire signing keys first |
| token minted but LiteLLM promotion fails | LiteLLM health and credential API, and rotator database persistence — a token exchange alone is not a healthy rotation |

Anthropic returns an opaque HTTP 400 `invalid_grant` for every exchange failure,
including a signature mismatch against a stale inline JWKS, so the driver raises a
loud `anthropic.token_exchange` alert on 400/401 responses from `/oauth/token`.
After a restore, compare the recorded broker fingerprint, the Keycloak public
certificate, the Vault private key, the stable subject mapper, and the approved
JWKS hash. Use [identity recovery](identity-operations.md) if the broker key
proof fails, and never copy the private key into a ticket or browser or replace
`private_key_jwt` with a long-lived client secret to recover quickly.

## Residual operational boundary

External Anthropic resources and every inline-JWKS approval remain a human
`org:admin` ceremony by design. The portal does not collect the external WIF
identifiers; an operator writes the complete Vault record. No Anthropic
organization-admin token is stored, so there is no automatic issuer update or
emergency rollback. This repository cannot prove the customer's Anthropic
organization, workspace membership, billing attribution, or Console audit
retention in local unit tests, so the acceptance runbook in
[test-runbook.md](test-runbook.md) requires a real external canary before the WIF
disposition changes.

Official references:

- [Anthropic Workload Identity Federation](https://platform.claude.com/docs/en/manage-claude/workload-identity-federation)
- [Anthropic WIF reference](https://platform.claude.com/docs/en/manage-claude/wif-reference)
- [Manage WIF with the Admin API](https://platform.claude.com/docs/en/manage-claude/wif-admin-api)

## Enrollment control plane

Enrollment, disable, and delete now run through bounded key-rotator routes
(`GET/PUT/DELETE /providers/anthropic`, `POST /providers/anthropic/disable`)
surfaced in the admin portal. The enrollment payload carries only non-secret
identifiers (organization, service account, federation rule, optional
workspace, and the approved federation JWKS SHA-256 fingerprint) plus the
literal confirmation `ENROLLED`; it is rejected unless identity bootstrap has
already generated the `private_key_jwt` key in Vault, and any drift between
the live Keycloak JWKS and the approved fingerprint is surfaced as a
`jwks_drift` state rather than silently accepted. Disable stops refresh and
lets the active short-lived credential expire; delete requires the literal
`DELETE anthropic` and succeeds only with durable proof that the last
short-lived credential was never issued or has already expired.

