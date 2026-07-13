# Anthropic Workload Identity Federation

This runbook describes the implemented Keycloak-to-Anthropic WIF path. It has
two deliberately separate authority domains:

- AI Gateway automatically creates and proves the Keycloak broker's
  `private_key_jwt` key, mints short-lived workload assertions, exchanges them
  through pinned Envoy egress, and refreshes LiteLLM.
- A human Anthropic organization administrator creates the initial issuer,
  service account, and rule, and manually approves every inline-JWKS change.

The inference broker never receives `org:admin`. Anthropic issuer mutation
requires an `org:admin` OAuth bearer; granting that authority to the inference
path would turn a model credential compromise into organization-wide
administration. The recurring watcher therefore detects and records drift but
makes no Anthropic administration call.

The external product behavior in this guide was checked against the official
Anthropic WIF documentation on 2026-07-12. Recheck the linked API contract at
deployment time because it is outside this repository's version control.

## Current lab execution status

The 2026-07-13 replacement-VM recovery did **not** configure the customer-side
Anthropic issuer, rule, service account, workspace, or approved inline JWKS.
Consequently real WIF exchange, Anthropic Envoy traversal, LiteLLM inference,
and inference-derived telemetry are **NOT EXECUTED**. A portal lifecycle canary
received LiteLLM HTTP 401 before Envoy and was safely cleaned up; zero Envoy
delta is evidence that no provider request occurred, not a network or inference
pass.

The separate synthetic collector test passed the in-stack Alloy
transform/export path with fabricated non-sensitive spans. It does not exercise
Keycloak token minting, Anthropic exchange, LiteLLM, Envoy, provider billing/
workspace attribution, or model output. Complete every external ceremony and
the real canary in this runbook before changing the Anthropic/WIF disposition.

## Implemented Keycloak contract

The `anthropic-wif` realm is separate from the user-authentication `aigw`
realm. Its broker client is imported disabled with service accounts enabled,
`private_key_jwt`, RS256 client authentication, no shared-secret fallback, a
600-second access-token lifetime, and audience
`https://api.anthropic.com`.

During portal **Initialize identity control**, key-rotator:

1. keeps the broker disabled while changing credentials;
2. asks Keycloak to generate a 3072-bit PKCS#12 keypair with a one-use random
   archive password;
3. extracts the private key in memory and stores it only at Vault path
   `kv/ai-gateway/anthropic-wif-client-key`;
4. registers the public certificate on the Keycloak client;
5. installs one deterministic hardcoded access-token subject mapper;
6. enables the broker and proves `private_key_jwt` works; and
7. decodes the returned token locally and fails closed unless these exact
   claims are present:

```text
sub = service-account-anthropic-token-broker
aud contains https://api.anthropic.com
```

The mapper is necessary because Keycloak's native service-account `sub` is an
internal user UUID that changes across realm recreation/restore. Initialization
rejects a competing `sub` mapper. The broker remains disabled when key
generation, the Vault write, client proof, or claim proof fails.

This exact mapper/client-credentials behavior was runtime-verified against the
repository-pinned DHI Keycloak 26.6.4 ARM64 image: `sub` was the stable value above,
`aud` contained the Anthropic audience, `azp`/`client_id` identified
`anthropic-token-broker`, and the fabricated issuer matched exactly. Treat the
runtime claim validator—not assumptions about Keycloak defaults—as the release
gate after any image upgrade.

No operator should import a private key through Keycloak or the portal. The
portal displays only a SHA-256 certificate fingerprint.

## Prerequisites

- Complete the full three-interface deployment and Vault bootstrap/unseal.
- Complete portal identity initialization and record a ready WIF broker plus
  its certificate fingerprint.
- Confirm time synchronization on the host and the Anthropic administrator's
  workstation.
- Identify the approved Anthropic organization and workspace.
- Use an Anthropic Admin, Owner, or Primary Owner for the one-time Console
  ceremony. An Admin API key is not accepted for WIF administration.
- Decide the narrowest rule scope. `workspace:inference` is preferred for this
  gateway's Messages/Models calls; use `workspace:developer` only if an
  approved workload also needs non-inference workspace APIs.

## One-time external bootstrap

### 1. Export the public JWKS and canonical hash

Run from `/opt/ai-gateway` on the target. This prints public keys only; it does
not mint or print a bearer token:

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

Record the hash in the controlled deployment evidence. Copy the complete
`keys` array, never a private key. If the command returns no keys or the broker
status is not ready, stop rather than creating an unverified federation.

### 2. Create the Anthropic resources

In Claude Console, open **Settings → Workload identity → Connect workload**
and choose **Custom OIDC**. Create:

1. An inline federation issuer:
   - issuer URL exactly
     `https://idp.wif-a.example.invalid/realms/anthropic-wif` for the committed
     realm profile, or the exact `issuer_url` printed by the helper for the
     reviewed environment;
   - JWKS type `inline`, with the full `keys` array from step 1;
   - replay/JTI checking enabled;
   - maximum assertion lifetime compatible with the reviewed 600-second
     Keycloak token lifetime.
2. A developer-role service account named for AI Gateway and membership in
   the target workspace.
3. A federation rule with all of these constraints:
   - exact subject, with no wildcard:
     `service-account-anthropic-token-broker`;
   - exact audience `https://api.anthropic.com`;
   - target set to the new service account;
   - only the approved workspace;
   - `workspace:inference` unless broader developer APIs are explicitly
     required; and
   - a short access-token lifetime, normally 600 seconds.

An audience-only rule is invalid and unsafe; the exact subject is the workload
identity boundary. Do not use a trailing `*`, do not match the Keycloak-native
UUID, and do not create an `org:admin` rule for this broker.

Record the returned issuer (`fdis_...`), rule (`fdrl_...`), service-account
(`svac_...`), organization UUID, and workspace (`wrkspc_...`) identifiers.
They are configuration identifiers rather than bearer credentials, but still
belong in the controlled Vault record rather than browser storage.

### 3. Create the rotator bootstrap record

Establish a Vault operator token using the approved process. The example below
passes it as an ephemeral exec environment variable, not an argument. Supply
the recorded identifiers without angle brackets:

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

`kc_token_url`, `kc_client_id`, `federation_rule_id`, `organization_id`, and
`service_account_id` are required by the driver. `workspace_id` is required
when the rule covers multiple workspaces and is retained here even for a
single-workspace rule to make the intended billing/rate-limit boundary
explicit. `federation_jwks_sha256` is required for the watcher to accept its
first baseline. `federation_issuer_id` is retained for operator evidence; the
watcher does not use it to mutate Anthropic.

### 4. Prove exchange and promotion

In the portal admin page, enable the Anthropic WIF rotation row, use the
reviewed interval/grace values, and trigger **Rotate now**. Pass only if:

- Keycloak `private_key_jwt` authentication succeeds;
- local stable-subject/audience validation succeeds;
- `POST /v1/oauth/token` traverses `envoy-egress` and returns a short-lived
  `sk-ant-oat01-...` token;
- LiteLLM credential `anthropic-primary` is updated;
- an inference canary succeeds through `api.<domain>`; and
- `anthropic.token_exchange` and `anthropic.jwks` are healthy without printing
  the assertion or access token.

The first successful JWKS watcher pass accepts a baseline only when the live
canonical hash equals `federation_jwks_sha256`. A matching hash is an operator
attestation that the Console's inline keys were updated; it is not proof by
itself, so the token exchange remains mandatory.

## Recurring automated token flow

For every scheduled or manual rotation, key-rotator:

1. signs a unique, 60-second RFC 7523 client assertion with the Vault-held
   broker key (`iss=sub=anthropic-token-broker`, audience equal to the exact
   internal Keycloak token endpoint);
2. obtains a 600-second Keycloak service-account access token and verifies the
   stable `sub` and Anthropic audience locally;
3. exchanges that JWT at Anthropic's `/v1/oauth/token` through Envoy using the
   recorded rule/organization/service-account/workspace identifiers;
4. promotes the returned short-lived bearer into LiteLLM; and
5. schedules refresh at roughly 80% of its reported lifetime.

Failures use bounded exponential backoff with jitter. If the current token is
past 90% of its lifetime while refresh fails, the rotator raises an explicit
inference-at-risk alert. The driver does not silently fall back to a static
client secret. `ANTHROPIC_WIF_ALLOW_INSECURE_CLIENT_SECRET` is a development
escape hatch and must remain false in production.

## Manual inline-JWKS rotation

Inline JWKS has no remote discovery. Rotate without an exchange outage:

1. Add the new Keycloak realm signing provider at a lower priority so its
   public key is published while the old key still signs.
2. Wait for `anthropic.jwks` to report the candidate canonical SHA-256, and
   independently export the full old-plus-new JWKS using the helper above.
3. Using a fresh interactive Anthropic `org:admin` Console session, replace
   the issuer's entire inline `keys` array. Do not give that token to
   key-rotator and do not store it in Vault.
4. Patch only the approved hash in the existing Vault document:

```bash
read -rsp 'Vault operator token: ' VAULT_TOKEN; printf '\n'
export VAULT_TOKEN
scripts/aigw-compose.sh exec -T -e VAULT_TOKEN vault vault kv patch \
  kv/ai-gateway/anthropic-wif \
  federation_jwks_sha256=<new-64-character-canonical-hash>
unset VAULT_TOKEN
```

5. Wait for watcher history `manual_update_confirmed` and a healthy
   `anthropic.jwks`, then make the new Keycloak key active and prove a fresh
   token exchange/inference.
6. After every old assertion has expired, retire the old Keycloak key. Repeat
   the full-array Console update and approved-hash patch for the resulting
   key-removal drift.

The watcher persists the pending public JWKS/hash and emits one history row
per newly observed candidate without five-minute log spam. It never assumes a
first observation is correct after database loss or restore. Do not clear an
alert by writing the candidate hash before the Anthropic Console update; doing
so records a false operator attestation and the next token exchange can still
fail.

## Troubleshooting and recovery

| Symptom | Check |
|---|---|
| Keycloak client authentication fails | broker fingerprint, Vault key path, client enabled state, `client-jwt` authenticator, exact internal token URL |
| “unstable subject claim” | identity initialization completed, one hardcoded `sub` mapper exists, no competing subject mapper |
| missing Anthropic audience | `anthropic-audience` mapper and exact `https://api.anthropic.com` value |
| Anthropic `invalid_grant` | exact issuer, subject, audience, expiry/clock, rule/workspace IDs, service-account membership, and current inline JWKS in Console history |
| `baseline_unconfirmed` | export live JWKS, update Console with an interactive org admin, then record the exact canonical hash in Vault |
| `drift_detected` | complete the manual old-plus-new or key-removal ceremony; do not activate/retire signing keys first |
| token minted but LiteLLM promotion fails | LiteLLM health/credential API and rotator database persistence; token exchange alone is not a healthy rotation |

After a restore, compare the recorded broker fingerprint, Keycloak public
certificate, Vault private key, stable subject mapper, and approved JWKS hash.
Use [identity recovery](identity-operations.md) if the broker key proof fails.
Never copy the private key into a ticket/browser or replace
`private_key_jwt` with a long-lived client secret to recover quickly.

## Residual operational boundary

- External Anthropic resources and every inline-JWKS approval remain a human
  `org:admin` ceremony by design.
- The portal does not collect the external WIF identifiers; an operator writes
  the complete Vault record.
- No Anthropic organization-admin token is stored, so there is no automatic
  issuer update or emergency rollback.
- This repository cannot prove the customer's Anthropic organization,
  workspace membership, billing attribution, or Console audit retention in
  local unit tests; the acceptance runbook requires a real external canary.

Official references:

- [Anthropic Workload Identity Federation](https://platform.claude.com/docs/en/manage-claude/workload-identity-federation)
- [Anthropic WIF reference](https://platform.claude.com/docs/en/manage-claude/wif-reference)
- [Manage WIF with the Admin API](https://platform.claude.com/docs/en/manage-claude/wif-admin-api)
