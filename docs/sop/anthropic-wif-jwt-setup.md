# SOP: Set up Anthropic Workload Identity Federation (JWT path)

**Goal:** make the gateway authenticate to Anthropic with short-lived,
Keycloak-signed JWT tokens instead of a long-lived API key.

**Audience:** an on-call operator. Follow the steps top-to-bottom. One action per
step; run the command shown, confirm the "Expect" line, move on.

**Authoritative reference:** [anthropic-wif-bootstrap.md](../anthropic-wif-bootstrap.md).
This SOP is the checklist version of that runbook — it invents no steps the
runbook does not support. When something goes wrong, that runbook and the
[troubleshooting table](#8-troubleshooting) are the source of truth.

> **Why this works (in plain terms).** WIF means the gateway *proves who it is*
> to Anthropic with a short-lived JWT that your own Keycloak signs — no shared
> API key ever leaves your network. You paste your Keycloak public keys into the
> Anthropic Console once ("inline JWKS"), so Anthropic verifies each token
> **offline** and never calls back to your Keycloak. The gateway mints, exchanges,
> and refreshes these tokens automatically; a human Anthropic org-admin only does
> the one-time Console setup and re-approves the keys whenever Keycloak rotates.

> **This is a two-authority-domain flow.** A **human Anthropic org-admin** creates
> the issuer, service account, and federation rule in the Console (Steps 3–4).
> The **gateway** (key-rotator) does everything else — signing assertions,
> exchanging them through Envoy, refreshing LiteLLM — with no operator action per
> token. The inference path is never given `org:admin`, so it can never mutate
> your Anthropic org.

---

## 1. Before you start (prerequisites checklist)

Verify every box before touching the Console. If any fails, stop and fix it
first — a half-ready broker produces an unverifiable federation.

- [ ] **Stack is fully deployed and Vault is unsealed.** The three-interface
  converge completed and the `verify` role passed (this is what makes Envoy
  egress — the gateway's only path to `api.anthropic.com` — reachable).
- [ ] **Identity controller was reconciled automatically by Ansible.** Operators
  do not initialize it in a portal; verify that the admin portal's **Keycloak
  controller** card shows **`ready`** after the converge.
- [ ] **Broker `private_key_jwt` key is ready.** The same **Identity and
  authorization** section shows an **Anthropic broker certificate SHA-256**, and
  the **Anthropic Workload Identity Federation** card shows
  **Server-generated private_key_jwt: `ready`**. (Never a key you import — the
  portal only ever shows the fingerprint.)
- [ ] **Host and admin workstation clocks are in sync.** Assertions live 60 s and
  tokens 600 s; clock skew shows up later as an opaque `invalid_grant`.
- [ ] **You have a human Anthropic org-admin.** WIF administration requires an
  Anthropic **Admin, Owner, or Primary Owner**. An **Admin API key is not
  accepted.**
- [ ] **You picked the rule scope.** Use **`workspace:inference`** (correct for
  this gateway's Messages/Models calls). Use `workspace:developer` only if an
  approved workload also needs non-inference workspace APIs.

---

## 2. Export the gateway's public keys and their hash

Do this on the target VM.

1. Change into the deploy directory:
   ```bash
   cd /opt/ai-gateway
   ```

2. Export the public JWKS, issuer URL, and canonical hash (public keys only —
   this never mints or prints a token):
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
   **Expect:** a JSON block with a `keys` array, an `issuer_url=` line, and a
   64-hex-character `federation_jwks_sha256=` line. **If it prints no keys, STOP** —
   the broker is not ready; do not create a federation.

   > **The array normally holds two keys, and that is correct.** The realm's
   > default key providers publish an RS256 **signing** key (`use:"sig"`) and an
   > RSA-OAEP **encryption** key (`use:"enc"`). Paste the **entire** array — both
   > keys. Inline verification uses only the signing key; the encryption key is
   > harmless and expected, and `federation_jwks_sha256` is computed over both, so
   > the pasted set matches the recorded hash. (If the admin portal's *Broker
   > private_key_jwt* readiness ever disagrees with this export — export prints
   > keys but the panel says "not ready" — trust this §2 export; that is the
   > authoritative readiness check.)

3. Copy the whole `keys` array and record the `federation_jwks_sha256` value in
   your controlled deployment evidence.

   > These are public keys and non-secret hashes. There is **no private key** in
   > this output — the private key stays in Vault and is never exported.

---

## 3. Create the Anthropic resources (org-admin, in the Console)

Do this once, in an interactive Anthropic org-admin Console session. Use the
**exact** values below.

**The values the gateway expects** (committed realm profile — or the exact
`issuer_url` from Step 2 for a reviewed environment; both are also shown in the
portal's *Nonsecret external enrollment bundle*):

| Field | Exact value |
|---|---|
| Issuer URL | `https://idp.wif.<domain>/realms/anthropic-wif` (copy the exact `issuer_url` from Step 2) |
| Subject | `service-account-anthropic-token-broker` |
| Audience | `https://api.anthropic.com` |

> The WIF hostname is derived from the deployment's `aigw_domain`. Because JWKS
> is inline, **Anthropic never contacts Keycloak**, but the issuer still has to
> match the tokens exactly. A domain change therefore requires updating this
> Anthropic Console setting in the same maintenance window.

1. Open **Settings → Workload identity → Connect workload** and choose
   **Custom OIDC**.

2. Create the federation issuer:
   - Issuer URL: the exact value from the table above.
   - **JWKS type: `INLINE`.** Paste the full `keys` array from Step 2.
   - Enable **replay / JTI checking**.
   - Set **maximum assertion lifetime** so it is **compatible with the 600 s
     Keycloak token lifetime** (i.e. not shorter than the token you exchange).
   **Expect:** an issuer ID beginning `fdis_`.

3. Create a **developer-role service account** named for AI Gateway, and add it
   to the **target workspace**.
   **Expect:** a service-account ID beginning `svac_`.

4. Create the federation rule, pinning **all** of:
   - Subject: `service-account-anthropic-token-broker` — **exact, no `*` wildcard.**
   - Audience: `https://api.anthropic.com` — exact.
   - Target: the service account from step 3.
   - Workspace: **only** the one approved workspace.
   - Scope: `workspace:inference` (unless developer APIs were explicitly approved).
   - Access-token lifetime: short — normally **600 s**.
   **Expect:** a rule ID beginning `fdrl_`.

   > **Do not** create an audience-only rule (unsafe — the exact subject *is* the
   > identity boundary), **do not** use a trailing `*`, **do not** match the
   > Keycloak-native UUID, and **do not** create an `org:admin` rule for this broker.

---

## 4. Record the IDs and enroll in the admin portal

1. From the Console, write down all five identifiers:
   - `federation_issuer_id` — `fdis_…` (evidence only)
   - `federation_rule_id` — `fdrl_…`
   - `service_account_id` — `svac_…`
   - `organization_id` — the org UUID
   - `workspace_id` — `wrkspc_…`

   > These are configuration IDs, not bearer credentials. Keep them in your
   > controlled record, not in browser storage.

2. In the admin portal, if it prompts, click **Reauthenticate with Keycloak** —
   identity changes stay unlocked for 5 minutes.
   **Expect:** the enrollment form below is now visible.

3. Go to the **Anthropic Workload Identity Federation** card. Confirm the
   **Current Keycloak JWKS SHA-256** shown matches the hash you pasted into the
   Console in Step 3. (The portal binds this exact live hash to your enrollment
   automatically — you never re-type it.)

4. Fill the enrollment form:
   - **Anthropic organization ID** → `organization_id`
   - **Anthropic service-account ID** → `service_account_id`
   - **Anthropic federation-rule ID** → `federation_rule_id`
   - **Anthropic workspace ID (optional)** → `workspace_id`
   - **Type `ENROLLED`** exactly in the confirmation field.

5. Click **Save verified enrollment**.
   **Expect:** the flash message *"Anthropic WIF enrollment saved. No private key
   material was returned."*

   > The driver **refetches the live Keycloak JWKS and compares it** to the hash
   > bound to your `ENROLLED` confirmation. If the live keys no longer match the
   > approved hash, enrollment lands in the **`jwks_drift`** state instead of being
   > silently accepted — see [troubleshooting](#8-troubleshooting).

---

## 5. Trigger the first exchange and verify success

1. In the **Vendors → anthropic** card, set the reviewed **Interval** and **Grace
   / soak** seconds, then **Save**.
   **Expect:** settings saved. (For anthropic, enable/disable is driven only by
   the WIF lifecycle controls above — there is no separate enable checkbox.)

2. Click **Rotate now** on the anthropic card.
   **Expect:** a new **Rotation history** row with vendor `anthropic`, action
   `rotate`, status `success`. The detail shows a **masked** token
   (`sk-ant-oat01…***`) — never the full token.

3. Confirm the provider is active. On the WIF card:
   **Expect:** state badge **`configured`** and **Refresh: `enabled`**, with
   **Current** and **Operator-approved** JWKS SHA-256 equal (no `jwks_drift`).

4. Confirm both health flags are healthy. They surface on key-rotator's
   `/healthz` (snapshot) and `/status` (per vendor), and in the portal's **Rotator
   status** card.
   **Expect:** `anthropic.token_exchange` and `anthropic.jwks` both show
   **`ok: true`** with an **empty detail** and no `pending` — meaning the assertion
   was signed, `POST /v1/oauth/token` traversed Envoy, LiteLLM's `anthropic-primary`
   credential was hot-swapped, and the live JWKS matches the approved hash. No
   token or assertion is ever printed to reach this state.

5. Run a **real inference canary** — use the acceptance-runbook canary in
   [test-runbook.md §9](../test-runbook.md), **not** an invented one. It calls
   `claude-haiku` through `https://api.$AIGW_DOMAIN` with a **disposable virtual
   key read on stdin** (never the LiteLLM master key):
   ```bash
   read -rsp 'Disposable LiteLLM virtual key: ' AIGW_TEST_KEY; printf '\n'
   curl --fail --silent --show-error --cacert "$AIGW_CA" \
     --resolve "api.$AIGW_DOMAIN:443:$AIGW_INTERNAL_IP" \
     "https://api.$AIGW_DOMAIN/v1/chat/completions" \
     -H "Authorization: Bearer $AIGW_TEST_KEY" \
     -H 'Content-Type: application/json' \
     --data '{"model":"claude-haiku","messages":[{"role":"user","content":"acceptance canary"}],"max_tokens":16}' \
     >/dev/null
   unset AIGW_TEST_KEY
   ```
   **Expect:** HTTP success and a completion, with the request provably traversing
   **LiteLLM and Envoy** and the provider seeing the expected workspace/credential.
   A **401 with no Envoy delta means the call never reached Anthropic** — that is
   *not* a pass; see [troubleshooting](#8-troubleshooting).

WIF is live once Steps 3–5 all pass. From here the gateway refreshes tokens on
its own at roughly 80% of each token's lifetime.

---

## 6. Rotation and maintenance (when Keycloak signing keys rotate)

**Inline JWKS has no remote discovery.** Anthropic never re-fetches your keys, so
when Keycloak rotates its realm signing keys you **must hand the new public keys
to the Anthropic Console yourself** — otherwise every exchange fails with an
opaque `invalid_grant`. Do this with **zero exchange outage** by overlapping keys:

1. In Keycloak, add the **new** realm signing provider at a **lower priority** so
   its public key is published while the **old key still signs**.
   **Expect:** the WIF card's **Current Keycloak JWKS SHA-256** changes to a new
   candidate; `anthropic.jwks` reports the candidate canonical hash.

2. Re-run the [Step 2 export](#2-export-the-gateways-public-keys-and-their-hash)
   to get the **full old-plus-new** `keys` array and its new hash.

3. In a **fresh interactive Anthropic org-admin Console session**, replace the
   issuer's **entire** inline `keys` array with the old-plus-new array.
   **Do not** give that org-admin token to key-rotator or store it in Vault.

4. Approve the new hash so the watcher accepts it. Either:
   - **Portal (matches this SOP):** re-open the WIF enrollment form and **Save**
     again — the portal binds the now-current live hash to your `ENROLLED`
     confirmation; **or**
   - **Vault patch (runbook procedure):** patch **only** the hash, token read on
     stdin:
     ```bash
     read -rsp 'Vault operator token: ' VAULT_TOKEN; printf '\n'
     export VAULT_TOKEN
     scripts/aigw-compose.sh exec -T -e VAULT_TOKEN vault vault kv patch \
       kv/ai-gateway/anthropic-wif \
       federation_jwks_sha256=<new-64-character-canonical-hash>
     unset VAULT_TOKEN
     ```
   **Expect:** watcher history row `manual_update_confirmed` and a healthy
   `anthropic.jwks`.

   > **Never approve the hash before the Console update.** Writing the candidate
   > hash first records a false attestation and the next exchange can still fail.

5. Make the new Keycloak key **active**, then prove a fresh token exchange and a
   fresh inference canary (repeat [Step 5](#5-trigger-the-first-exchange-and-verify-success)).

6. Once **every old assertion has expired**, retire the old Keycloak key and
   repeat steps 2–5 (full-array Console update + hash approval) for the resulting
   key-removal change.

> **A note if you have read Anthropic's WIF docs:** the "JWKS is cached ~5 minutes"
> and "publish new keys ~15 minutes early" guidance applies to **discovery-mode**
> issuers only, where Anthropic fetches your JWKS endpoint. This gateway uses
> **inline** JWKS — Anthropic never fetches anything — so that timing guidance
> **does not apply**. Overlapping keys as above is the whole story.

---

## 7. Ground rules (do not violate)

- **Public keys and hashes only** ever leave the gateway. The `private_key_jwt`
  key stays in Vault; the portal shows only a fingerprint.
- **Secrets travel on stdin only** — never in a command argument, env assignment
  on the command line, or a log. The `read -rsp … ; export` idiom above is the
  pattern.
- **Never print, diff, or commit** an assertion, an access token, or a decrypted
  Vault value. A masked prefix in history is the most detail you should ever see.
- The broker is **never** given `org:admin`, and the gateway **never** falls back
  to a static client secret to "recover quickly."

---

## 8. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Portal shows **`jwks_drift`**; watcher `baseline_unconfirmed` / `drift_detected` | Live Keycloak JWKS no longer matches the hash approved in the Console | Re-export ([Step 2](#2-export-the-gateways-public-keys-and-their-hash)), update the Console inline keys with an **org-admin**, then re-approve the new hash ([Step 6.4](#6-rotation-and-maintenance-when-keycloak-signing-keys-rotate)). Never write the hash before the Console update. |
| Canary returns **401 at LiteLLM, no Envoy delta** | No provider request happened — `anthropic-primary` holds no valid token yet (rotation never ran or failed), or the wrong bearer was used | Check **Rotation history** for a `rotate`/`success`; click **Rotate now**; confirm `anthropic.token_exchange` is `ok`. Use a **disposable virtual key**, not the master key. |
| Anthropic **`invalid_grant`** / `anthropic.token_exchange` alert on `/oauth/token` (400/401) | Clock skew or expiry, Console **max assertion lifetime too short**, replay/JTI rejection, or **stale inline JWKS** signature mismatch | Verify time sync; confirm the Console max assertion lifetime ≥ token lifetime and replay window; confirm the inline JWKS is current in **Console → Workload identity → History**; re-check exact issuer/subject/audience and the rule/workspace/service-account IDs. |
| **"unstable subject claim"** locally | Identity init incomplete or a competing `sub` mapper exists | Confirm identity initialization completed and exactly one hardcoded `sub` mapper (`service-account-anthropic-token-broker`) exists — no competing subject mapper. |
| **Keycloak client authentication fails** (before any exchange) | Broker disabled, wrong Vault key path, or missing `client-jwt` auth | Check the broker fingerprint, the Vault key path, that the client is enabled with the `client-jwt` authenticator, and the canonical frontend token audience. |
| Token minted but **LiteLLM promotion fails** | Exchange succeeded but the credential hot-swap or state write failed | A token exchange alone is not a healthy rotation — check LiteLLM health / the credentials API and rotator DB persistence, then **Rotate now**. |

---

## 9. References

- [anthropic-wif-bootstrap.md](../anthropic-wif-bootstrap.md) — the implemented
  runbook this SOP condenses (authoritative for edge cases).
- [test-runbook.md §9](../test-runbook.md) — the real acceptance canary.
- [identity-operations.md](../identity-operations.md) — Keycloak controller and
  identity recovery.
- Anthropic: [Workload Identity Federation](https://platform.claude.com/docs/en/manage-claude/workload-identity-federation)
  · [WIF reference](https://platform.claude.com/docs/en/manage-claude/wif-reference)
  · [Manage WIF with the Admin API](https://platform.claude.com/docs/en/manage-claude/wif-admin-api)
