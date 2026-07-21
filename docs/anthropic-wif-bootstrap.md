# Anthropic workload identity federation

This page explains the Anthropic WIF design. Use the
[WIF setup SOP](sop/anthropic-wif-jwt-setup.md) for the exact operator steps.

WIF lets the gateway use short-lived provider tokens. It removes the need for
a long-lived Anthropic API key in LiteLLM. Keycloak proves the gateway's
identity with a signed JWT. Anthropic exchanges that JWT for a short-lived
access token.

## The two authority areas

Two owners take part:

| Owner | What it controls |
| --- | --- |
| AI Gateway | Keycloak signing key, JWT creation, token exchange, refresh, and LiteLLM update |
| Human Anthropic org admin | Anthropic issuer, service account, rule, workspace, and inline public keys |

The gateway never gets `org:admin`. A stolen inference credential must not
become an Anthropic organization admin credential.

The gateway can detect an Anthropic public-key mismatch. It cannot approve a
new key set in Anthropic. A human must do that with a fresh admin session.

## What local preprod proves

Local preprod tests this full shape against local TLS mocks:

- Keycloak creates and signs the token.
- The token has the required subject and audience.
- Envoy carries the exchange request.
- key-rotator updates LiteLLM.
- LiteLLM sends a mock inference request.

This does not prove a real Anthropic organization, workspace, bill, policy, or
model response. Each production deployment still needs its own Anthropic
enrollment and real inference canary. See [project status](project-status.md).

## Automatic Keycloak setup

Ansible performs the Keycloak setup. The admin portal has no initialization
button.

The WIF realm is separate from the user login realm:

```text
User login realm:  aigw
WIF realm:         anthropic-wif
Public WIF issuer: https://idp.wif.<domain>/realms/anthropic-wif
Broker client:     anthropic-token-broker
```

`<domain>` comes from the Ansible inventory. A domain change also changes the
WIF issuer. Anthropic must receive that issuer change in the same maintenance
window.

The broker uses these fixed rules:

- `private_key_jwt` client authentication;
- RS256 signing;
- a 3072-bit key pair;
- no shared client secret;
- a 600-second Keycloak token;
- no inherited client scopes; and
- only the audience `https://api.anthropic.com`.

During setup, key-rotator:

1. Keeps the broker disabled.
2. Asks Keycloak to make the key pair.
3. moves the private key into Vault.
4. Registers the public certificate in Keycloak.
5. Adds the fixed subject mapper.
6. Enables the broker and proves `private_key_jwt` works.
7. Checks the returned claims before it marks setup ready.

The private key normally lives at:

```text
kv/ai-gateway/anthropic-wif-client-key
```

The supported file option is `KC_CLIENT_ASSERTION_KEY_FILE`. Do not import a
private key through Keycloak or the portal. The portal shows only the public
certificate SHA-256 fingerprint.

The release gate requires these exact claims:

```text
sub = service-account-anthropic-token-broker
aud = https://api.anthropic.com
```

Keycloak's normal service-account subject is an internal UUID. That UUID can
change after a restore. The fixed mapper above keeps the Anthropic rule stable.
Setup fails if another subject mapper competes with it.

## One-time Anthropic enrollment

Complete these steps only after the full deploy passes and Vault is unsealed.
The [WIF setup SOP](sop/anthropic-wif-jwt-setup.md) gives the commands and
expected output.

### 1. Export public keys

Run the SOP export on the target VM. It prints:

- the public JWKS;
- the exact issuer URL; and
- a canonical SHA-256 hash of the public key set.

It prints no private key, assertion, or provider token. Stop if the export has
no keys or the broker is not ready.

### 2. Create the Anthropic objects

Use a human Anthropic Admin, Owner, or Primary Owner session. An Admin API key
is not enough for this task.

Create these objects:

- one Custom OIDC issuer with inline JWKS;
- one developer-role service account;
- membership in the approved workspace; and
- one federation rule.

The rule must use these exact limits:

| Field | Required value |
| --- | --- |
| Issuer | The exact URL printed by the export |
| Subject | `service-account-anthropic-token-broker` |
| Audience | `https://api.anthropic.com` |
| Target | The new service account |
| Workspace | Only the approved workspace |
| Scope | `workspace:inference`, unless broader access was approved |
| Token life | Normally 600 seconds |

Do not use a subject wildcard. Do not use the Keycloak UUID. Do not give this
broker `org:admin`.

The controller helper can perform the reviewed Anthropic Admin API actions.
It reads the short-lived `org:admin` token on stdin and does not store it:

```bash
python3 -I scripts/anthropic-wif-enroll.py --help
```

Using the helper does not remove the human approval boundary.

### 3. Save the non-secret IDs

Record these values in the admin portal enrollment form or the approved Vault
record:

```text
federation_issuer_id
federation_rule_id
organization_id
service_account_id
workspace_id
federation_jwks_sha256
```

These are IDs and a public-key hash, not bearer tokens. They still belong in a
controlled record. The portal requires the literal confirmation `ENROLLED`.
It refuses enrollment if the live Keycloak key hash differs from the approved
hash.

### 4. Prove the first exchange

Select **Rotate now** in the admin portal. A pass requires all of these checks:

- Keycloak `private_key_jwt` authentication;
- exact local subject and audience checks;
- `POST /v1/oauth/token` through Envoy;
- a short-lived Anthropic token;
- an update to the LiteLLM credential `anthropic-primary`;
- healthy `anthropic.token_exchange` and `anthropic.jwks` flags; and
- a real inference canary through `api.<domain>`.

No test may print the assertion or access token. An HTTP 401 before Envoy is
not a provider or network pass.

## Normal token refresh

For each refresh, key-rotator creates a unique 60-second client assertion. Its
`iss` and `sub` both name `anthropic-token-broker`. The assertion audience is
the public Keycloak token URL:

```text
https://idp.wif.<domain>/realms/anthropic-wif/protocol/openid-connect/token
```

The request itself stays on the private Keycloak network. Keycloak then issues
a 600-second service token. key-rotator checks its claims and exchanges it at
Anthropic through Envoy.

The returned token replaces `anthropic-primary` in LiteLLM. Refresh is planned
at about 80% of the token life. Failures use bounded backoff. At 90%, a
continued refresh failure raises an inference-at-risk alert.

There is no production fallback to a static client secret.

## Public-key rotation

Anthropic uses inline JWKS for this design. It does not fetch new keys from
Keycloak. Rotate keys in this order:

1. Add the new Keycloak signing key at lower priority. Keep the old key active.
2. Export the full old-plus-new public key set and its hash.
3. In a fresh Anthropic org-admin session, replace the whole inline key set.
4. Record the new approved hash in the portal or Vault.
5. Wait for `manual_update_confirmed` and healthy JWKS status.
6. Make the new Keycloak key active.
7. Run a fresh exchange and inference canary.
8. After old assertions expire, remove the old key and repeat the approval
   steps for the final key set.

Never approve the new hash before Anthropic receives the new public keys. That
would create false evidence while the next exchange could still fail.

The watcher stores the pending public candidate and hash. It does not call the
Anthropic admin API and does not assume the first value after a restore is
correct.

## Disable and delete

The bounded key-rotator API and admin portal can enroll, disable, or delete the
Anthropic record. The enrollment payload contains no private key.

Disable stops refresh and lets the short-lived token expire. Delete requires
the literal confirmation `DELETE anthropic`. Delete is blocked while a valid
short-lived token may still exist.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Keycloak client auth fails | Broker enabled state, Vault key path, public fingerprint, `client-jwt`, and public token URL |
| `unstable subject claim` | Automatic identity setup and the one fixed subject mapper |
| Missing audience | Exact `https://api.anthropic.com` audience mapper |
| Anthropic `invalid_grant` | Clock, issuer, subject, audience, rule IDs, workspace, service account, and current inline keys |
| `baseline_unconfirmed` | Export keys, update Anthropic, then approve the exact hash |
| `drift_detected` | Complete the overlap or key-removal ceremony |
| Token exchange passes but LiteLLM update fails | LiteLLM health, credential API, and rotator database |

Anthropic may return the same HTTP 400 `invalid_grant` for several causes,
including an old inline key set. Check each field instead of guessing.

After a restore, compare the broker fingerprint, Keycloak certificate, Vault
private key, fixed subject mapper, and approved JWKS hash. Never copy the
private key into a ticket or replace WIF with a long-lived secret as a quick
fix.

## What remains human-owned

Anthropic objects and each inline-key approval remain human-owned. The gateway
stores no Anthropic organization-admin token. Local tests cannot prove the
customer's organization, workspace, bill, or Console audit history.

The external contract was last checked against Anthropic's official pages on
2026-07-12. Recheck it before a production enrollment because Anthropic owns
that API.

Official references:

- [Anthropic Workload Identity Federation](https://platform.claude.com/docs/en/manage-claude/workload-identity-federation)
- [Anthropic WIF reference](https://platform.claude.com/docs/en/manage-claude/wif-reference)
- [Anthropic WIF Admin API](https://platform.claude.com/docs/en/manage-claude/wif-admin-api)
