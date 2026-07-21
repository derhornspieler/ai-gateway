# Archived: retired Rocky/Parallels lab UX checklist

> Historical evidence only. Use `docs/preprod.md` and
> `scripts/test-e2e-preprod.py` for current acceptance.

The companion to `scripts/test-e2e-lab.py`. That harness proves the backend and
logout **mechanics** headlessly (HTTP + subprocess); this checklist proves the
**human experience** — the parts only a real browser exercises: rendered login,
the model picker, streamed tokens, and the visual return to a login page on
sign-out. Run it after any converge or image bump that touches the chat, edge,
or identity planes. The one step no automation can perform is typing a
password; that stays with the operator.

Lab base domain: `aigw.internal`. Disposable lab users: `lab-admin`,
`lab-developer`, `lab-user` (passwords in the VM's
`/opt/ai-gateway/secrets/samba_user_<user>_password`, operator-retrieved).

## A. Chat sign-in and inference (run once per role)

| # | Action | Expected screen / result |
|---|---|---|
| 1 | Open `https://chat.aigw.internal/` | Open WebUI "Sign in to Open WebUI" with a single **Continue with AIGW SSO** button — no local email/password form |
| 2 | Click **Continue with AIGW SSO** | Redirects to Keycloak "AI GATEWAY — Sign in to your account" (username + password) |
| 3 | Enter the role's username + password, submit | Returns to Open WebUI, logged in, chat composer visible |
| 4 | Open the model picker (top-left model dropdown) | The full catalog is listed (claude-opus-4-8, claude-opus-4-7, claude-sonnet-5, claude-sonnet-4-5, claude-haiku-4-5, claude-fable-5, gpt) — **not** just one or two |
| 5 | Pick `claude-haiku-4-5`, send "ping" | A streamed reply appears token-by-token (not a spinner then a block); reply is coherent |
| 6 | Confirm no Ollama UI | Settings → Connections shows no Ollama section; no "manage Ollama models" anywhere |

Repeat A for `lab-admin`, `lab-developer`, `lab-user`. All three must reach
chat (the dedicated `aigw-chat` role gates access, not admin status).

## B. Sign-out returns to a login page (the regression this guards)

| # | Action | Expected screen / result |
|---|---|---|
| 1 | While signed in to chat, click the user menu → **Sign Out** | Browser ends on the Keycloak **or** Open WebUI **sign-in** page — never a bare "You are logged out" Keycloak page, and never a Keycloak "Invalid redirect uri" error |
| 2 | Press browser Back, then reload | Still signed out — the chat composer is not reachable without re-authenticating |

### Admin apps (Grafana has a real sign-out button; the others use the URL)

| # | Action | Expected screen / result |
|---|---|---|
| 3 | Sign in to `https://grafana.aigw.internal/` via SSO, then use Grafana's **Sign out** | Lands on the Keycloak login for `grafana.` — cookie-less, so it prompts to log in again |
| 4 | For LiteLLM-admin / Prometheus / Vault (no native button), visit `https://<host>.aigw.internal/oauth2/sign_out` | Redirects through Keycloak and back to that host's login |

## What "pass" means

Every row lands on its expected screen with no error page, no missing models,
and no lingering authenticated session after sign-out. If any row fails, the
matching headless check in `test-e2e-lab.py` (`logout:*`, `chat:*`) will usually
also fail and localizes it; a row that fails **only** in the browser points at a
rendering/JS/session-cookie issue the HTTP checks cannot see (this is exactly
how the stale model-picker, the broken key scope, and the PersistentConfig
no-ops were caught on 2026-07-16).

## Driving it under automation

Claude can drive steps A1–A5 and B1 via the Chrome browser tools (it cannot
type the password — hand it off at the Keycloak form, or pre-establish the
session). Capture a GIF of the login → chat → sign-out loop for the record when
demonstrating the flow.
