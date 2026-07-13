# Codex prompt: fix AI Gateway SSO auth errors

Paste everything below the line into codex.

---

I ran all 7 `*.aigw.internal` hostnames through a browser and found two real authentication bugs and two non-bugs (documented below so you don't "fix" things that are working as designed). Confirm each against the live containers before changing anything, then patch.

## Bug 1 — `admin.aigw.internal` and `grafana.aigw.internal`: Keycloak rejects login with `invalid_scope`

Clicking "Sign in with OpenID Connect" on both sites redirects to Keycloak and immediately bounces back to a 403 at:

```
https://admin.aigw.internal/oauth2/callback?error=invalid_scope&error_description=Invalid+scopes%3A+openid+email+profile+groups&...
https://grafana.aigw.internal/oauth2/callback?error=invalid_scope&error_description=Invalid+scopes%3A+openid+email+profile+groups&...
```

Root cause: in `compose/docker-compose.yml`, both the `oauth2-proxy` (lines ~223-247) and `oauth2-proxy-grafana` (lines ~274-299) services set `OAUTH2_PROXY_ALLOWED_GROUPS: "aigw-admins"` and `OAUTH2_PROXY_OIDC_GROUPS_CLAIM: "roles"`, but never set `OAUTH2_PROXY_SCOPE` explicitly. oauth2-proxy's default OIDC scope is `openid email profile`, and it auto-appends `groups` whenever `OAUTH2_PROXY_ALLOWED_GROUPS` is set — hence the requested scope `openid email profile groups`. The Keycloak realm template (`ansible/roles/docker_stack/templates/keycloak-realms/aigw-realm.json.j2`) never defines a `groups` client scope anywhere in the `aigw` realm, so Keycloak's authorization endpoint rejects the request outright, before the login form even renders.

Fix: explicitly set `OAUTH2_PROXY_SCOPE: "openid email profile"` on both the `oauth2-proxy` and `oauth2-proxy-grafana` services in `compose/docker-compose.yml`, so `groups` is never requested. This is safe — the `roles` claim these proxies actually check (`OAUTH2_PROXY_OIDC_GROUPS_CLAIM: "roles"`) comes from the `realm-roles-to-roles-claim` protocol mapper defined directly on the `admin-ui` Keycloak client (same template file, lines ~128-142), which is a client-level mapper Keycloak includes in every issued token regardless of requested scope — it does not depend on a `groups` scope being granted. So dropping `groups` from the request has no effect on role/group enforcement.

Alternative fix (don't do both): add a `groups` client scope to the `aigw` realm and assign it as an optional/default scope on the `admin-ui` client. This is more moving parts for no benefit since `OAUTH2_PROXY_OIDC_GROUPS_CLAIM` is already pointed at `roles`, not `groups` — prefer the scope-string fix above.

After the fix, redeploy and confirm both `https://admin.aigw.internal` and `https://grafana.aigw.internal` reach the real Keycloak login form (not an immediate 403) and that a successful login lands back on the admin/Grafana UI.

## Bug 2 — `chat.aigw.internal` (Open WebUI): 500 on `/oauth/oidc/login`

Clicking "Continue with AIGW SSO" hits `GET https://chat.aigw.internal/oauth/oidc/login` and gets a plain `Internal Server Error` (HTTP 500) before ever reaching Keycloak — no redirect happens at all.

Likely cause: Open WebUI's OIDC client is built on Authlib, which performs OIDC discovery/token exchange over `httpx`, not Python's `requests` library. The compose config (`compose/docker-compose.yml`, open-webui service, ~line 398) sets `REQUESTS_CA_BUNDLE: /etc/ssl/certs/aigw-ca.pem` and mounts the CA at that path — but `REQUESTS_CA_BUNDLE` is only honored by the `requests` library. If Open WebUI's OIDC codepath uses `httpx`/Authlib under the hood, that env var does nothing for it, and the outbound HTTPS call to `https://auth.aigw.internal/realms/aigw/.well-known/openid-configuration` (a self-signed cert, since these are internal lab certs) fails certificate verification inside the container, throwing an unhandled exception that Open WebUI surfaces as a bare 500.

Steps to confirm and fix:
1. Pull the actual traceback: `docker compose -f compose/docker-compose.yml logs open-webui --since 10m | grep -i -A 20 'oauth\|ssl\|certificate'` (or equivalent for however this stack is orchestrated) right after reproducing the 500. Confirm whether it's an `SSLCertVerificationError` / `httpx.ConnectError` or something unrelated (e.g. a missing/invalid `OAUTH_CLIENT_SECRET`, bad `OPENID_PROVIDER_URL` value, or an Authlib config error) before changing anything.
2. If it is a CA trust issue: add `SSL_CERT_FILE=/etc/ssl/certs/aigw-ca.pem` (and/or `SSL_CERT_DIR=/etc/ssl/certs`) alongside the existing `REQUESTS_CA_BUNDLE` in the `open-webui` service environment in `compose/docker-compose.yml`. The more robust fix is to install the CA into the container's system trust store (e.g. `update-ca-certificates` in the image build/entrypoint using the already-mounted `./certs/ca.pem`) so every HTTP client inside the container — `requests`, `httpx`, `aiohttp`, whatever — trusts it uniformly, instead of chasing per-library env vars one at a time.
3. Re-test the full flow end to end: "Get started" → "Continue with AIGW SSO" should redirect to the same Keycloak login form `dev-portal` reaches successfully (see below), not 500.

## Working correctly — do not change

- **`portal.aigw.internal`**: "Sign in with Keycloak" correctly redirects to a working Keycloak login form (`client_id=dev-portal`, scope `openid profile email` — notably it does *not* request `groups`, which is why it doesn't hit Bug 1). Use this as the reference/working case when validating the other fixes.
- **`api.aigw.internal`**: hitting `/` returns a bare `403 Forbidden`. This is intentional — `compose/traefik/dynamic-int.yml` explicitly allow-lists only inference paths (`/v1/*`, `/chat/completions`, `/completions`, `/embeddings`, `/models`, `/health/*`) via the `api` router (priority 100) and denies everything else via the `api-deny` catch-all router (priority 1, `deny-all` ipAllowList middleware). There is no browsable root on this host by design — test it with a real inference path and a Bearer API key instead, not a bare GET `/`.
- **`auth.aigw.internal`** root page ("Welcome to Keycloak — Local access required to create the administrative user"): this is Keycloak's own bootstrap-admin restriction, not a routing bug. `auth.aigw.internal` reaches `traefik-adm`'s `keycloak-admin` router (`compose/traefik/dynamic-adm.yml`), which intentionally exposes the full Keycloak admin console on the VPN-restricted ADM plane (see comment in that file — internal users only get `/realms/aigw` + static assets via `traefik-int`, admin console is ADM-only). The message is Keycloak telling you no bootstrap admin has been created yet; per `ansible/inventory/host_vars/lab-aigw01.yml`, this lab seeds a `lab-admin` identity for exactly this purpose. This does not need a code fix — it's an operational step (create the bootstrap admin locally/via `bootstrap-admin` command, or confirm `lab-admin` already covers it) rather than a bug.

## Priority

Fix Bug 1 first — it's a one-line config change per proxy with a fully-confirmed root cause and no ambiguity. Then investigate Bug 2 by reading the actual open-webui logs before patching, since the CA-trust theory is the most likely explanation but should be confirmed against the real traceback rather than assumed.
