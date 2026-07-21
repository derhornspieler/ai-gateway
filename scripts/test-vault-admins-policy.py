#!/usr/bin/env python3
"""Acquire a real vault-admins Vault token via Keycloak OIDC and prove its
policy boundary live, end to end, through the public edge.

This exercises the exact operator path documented in
docs/identity-operations.md ("Vault OIDC login for the aigw-admins
operators"): oauth2-proxy-vault fronts vault.<domain> with the same
aigw-admins gate as the other ADM UIs, and Vault's own auth/oidc role `aigw`
(configured by scripts/vault-oidc-setup.sh) issues a client token scoped to
the `vault-admins` policy for any aigw realm user whose token carries
aigw-admins.

Flow, entirely headless:

  1. Log in through oauth2-proxy-vault as preprod-admin exactly like
     test-oidc-callbacks.py's "vault" target -- this both proves the edge
     gate and leaves a live Keycloak SSO session in the same cookie jar.
  2. POST /v1/auth/oidc/oidc/auth_url for role=aigw with the CLI loopback
     redirect_uri (http://localhost:8250/oidc/callback) -- the same
     redirect_uri `vault login -method=oidc` uses, and the one already on
     the role's reviewed redirect allow-list.
  3. GET that auth_url with the same cookie jar. Because the Keycloak SSO
     session from step 1 is still live, Keycloak silently reissues an
     authorization code for the separate `vault` OIDC client and redirects
     to the loopback callback -- exactly what a real browser would do
     without a second login prompt. This harness never contacts
     localhost:8250; it captures the redirect's query string directly from
     the HTTP response instead of following it.
  4. GET /v1/auth/oidc/oidc/callback with that code+state to complete the
     exchange and receive a real, short-lived Vault client token.
  5. Assert the token's live policy boundary directly against Vault's HTTP
     API (kv/, sys/policies/acl, sys/auth) -- not by re-reading the written
     policy text, which was already reviewed; this proves live enforcement.
  6. Best-effort self-revoke the acquired token so no acceptance-run
     artifact is left live longer than necessary.

The static preprod-admin password is accepted only on stdin and is never
logged, persisted, placed in argv, or included in an exception message. No
Vault root or unseal material is ever touched by this script.
"""

from __future__ import annotations

import argparse
import http.cookiejar
import importlib.util
import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


OIDC_PATH = Path(__file__).with_name("test-oidc-callbacks.py")
_OIDC_SPEC = importlib.util.spec_from_file_location("aigw_oidc_callbacks", OIDC_PATH)
if _OIDC_SPEC is None or _OIDC_SPEC.loader is None:
    raise RuntimeError("could not load the reviewed OIDC callback targets")
oidc = importlib.util.module_from_spec(_OIDC_SPEC)
# Register before exec: oidc.py's @dataclass(frozen=True) target definitions
# resolve their own module via sys.modules during class creation on newer
# Python, which requires the module to already be registered there.
sys.modules[_OIDC_SPEC.name] = oidc
_OIDC_SPEC.loader.exec_module(oidc)


HOST = "vault.aigw.internal"
ORIGIN = f"https://{HOST}"
ALLOWED_HOSTS = frozenset({HOST, oidc.AUTH_HOST})
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
LOCALHOST_CALLBACK = "http://localhost:8250/oidc/callback"
# Only an aigw-admins identity can reach Vault's `aigw` OIDC role at all; a
# non-admin cannot even pass the oauth2-proxy edge gate in front of it (that
# denial is covered by test-admin-denial.py's "vault" target).
ACCEPTANCE_USERNAME = "preprod-admin"
# A name that unambiguously marks this as a bounded, never-mounted acceptance
# probe. The assertion is that Vault denies the request before it ever
# performs the mount -- a 403 proves no auth backend was enabled.
AUTH_ENABLE_PROBE_PATH = "aigw-acceptance-probe-never-mounted"


class PolicyAssertionError(RuntimeError):
    """A deliberately non-sensitive live vault-admins policy check failure."""


class CaptureLocalhostRedirect(urllib.request.HTTPRedirectHandler):
    """Follow only the reviewed Keycloak/vault hosts; capture (never dial)
    the terminal redirect to the CLI loopback callback."""

    def __init__(self) -> None:
        super().__init__()
        self.captured: str | None = None

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if parsed.hostname == "localhost":
            if self.captured is not None:
                raise PolicyAssertionError("more than one localhost callback redirect was observed")
            self.captured = newurl
            return None
        if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
            raise PolicyAssertionError("vault OIDC redirect left the reviewed Keycloak/vault hosts")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def read_password() -> str:
    if sys.stdin.isatty():
        raise SystemExit("pipe the static preprod-admin password on stdin")
    raw = sys.stdin.buffer.read(513)
    if not raw or len(raw) > 512:
        raise SystemExit("invalid preprod password length")
    try:
        password = raw.strip().decode("utf-8")
    except UnicodeDecodeError:
        raise SystemExit("preprod password is not UTF-8") from None
    if not password:
        raise SystemExit("invalid preprod password")
    return password


def _decode(body: bytes) -> str:
    if len(body) > MAX_RESPONSE_BYTES:
        raise PolicyAssertionError("vault API response exceeded the acceptance limit")
    try:
        return body.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise PolicyAssertionError("vault API response was not valid UTF-8") from exc


def acquire_vault_admins_token(
    context: ssl.SSLContext, cookies: http.cookiejar.CookieJar, password: str
) -> tuple[str, urllib.request.OpenerDirector]:
    """Log in as preprod-admin and complete Vault's OIDC role=aigw exchange."""

    target = oidc.TARGET_BY_NAME["vault"]
    edge_redirects = oidc.RestrictedRedirects(target)
    edge_opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        urllib.request.HTTPCookieProcessor(cookies),
        edge_redirects,
    )
    login_url, login_html = oidc.read_response(edge_opener, oidc.start_url(target))
    login_parts = oidc.reviewed_https_url(login_url, target.allowed_hosts)
    if login_parts.hostname != oidc.AUTH_HOST:
        raise PolicyAssertionError("vault edge OIDC start did not reach the Keycloak password form")
    form = oidc.find_keycloak_login_form(login_html)
    final_url, final_html = oidc.post_keycloak_login(
        edge_opener,
        login_url,
        form,
        target=target,
        username=ACCEPTANCE_USERNAME,
        password=password,
    )
    oidc.verify_callback_completion(target, edge_redirects.redirects, final_url, final_html)
    oidc.require_session_cookie(cookies, target)

    # A second opener sharing the same authenticated cookie jar but with its
    # own bounded redirect handler for the Vault-role OIDC dance.
    capture = CaptureLocalhostRedirect()
    api_opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        urllib.request.HTTPCookieProcessor(cookies),
        capture,
    )

    auth_url_request = urllib.request.Request(
        f"{ORIGIN}/v1/auth/oidc/oidc/auth_url",
        data=json.dumps({"role": "aigw", "redirect_uri": LOCALHOST_CALLBACK}).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "aigw-acceptance/1"},
        method="POST",
    )
    try:
        with api_opener.open(auth_url_request, timeout=20) as response:
            if response.getcode() != 200:
                raise PolicyAssertionError("vault OIDC auth_url request did not return 200")
            payload = json.loads(_decode(response.read(MAX_RESPONSE_BYTES + 1)))
    except urllib.error.HTTPError as exc:
        raise PolicyAssertionError("vault OIDC auth_url request was rejected") from exc
    except (OSError, ssl.SSLError, urllib.error.URLError) as exc:
        raise PolicyAssertionError("vault OIDC auth_url request could not be completed") from exc

    auth_url = payload.get("data", {}).get("auth_url")
    if not isinstance(auth_url, str):
        raise PolicyAssertionError("vault OIDC auth_url response had no usable auth_url")
    auth_url_parts = urllib.parse.urlsplit(auth_url)
    if auth_url_parts.scheme != "https" or auth_url_parts.hostname != oidc.AUTH_HOST:
        raise PolicyAssertionError("vault OIDC auth_url did not point at the reviewed Keycloak issuer")

    try:
        with api_opener.open(
            urllib.request.Request(auth_url, headers={"User-Agent": "aigw-acceptance/1"}),
            timeout=20,
        ):
            pass
    except urllib.error.HTTPError:
        pass  # Expected: the redirect handler above stops the chain with a 3xx.
    except (OSError, ssl.SSLError, urllib.error.URLError) as exc:
        raise PolicyAssertionError("vault OIDC auth_url could not be followed to Keycloak") from exc

    if capture.captured is None:
        raise PolicyAssertionError(
            "Keycloak did not silently complete SSO back to the CLI loopback callback "
            "-- the pre-established edge session did not carry over to the vault client"
        )
    callback_parts = urllib.parse.urlsplit(capture.captured)
    if (
        callback_parts.scheme != "http"
        or callback_parts.hostname != "localhost"
        or callback_parts.port != 8250
        or callback_parts.path != "/oidc/callback"
    ):
        raise PolicyAssertionError("vault OIDC callback redirect did not match the reviewed CLI loopback")
    query = dict(urllib.parse.parse_qsl(callback_parts.query))
    if "error" in query or "code" not in query or "state" not in query:
        raise PolicyAssertionError(
            "vault OIDC callback redirect did not carry a real authorization code "
            "-- this would prove a broken login, not a live token"
        )

    callback_request = urllib.request.Request(
        f"{ORIGIN}/v1/auth/oidc/oidc/callback?" + urllib.parse.urlencode(query),
        headers={"User-Agent": "aigw-acceptance/1"},
    )
    try:
        with api_opener.open(callback_request, timeout=20) as response:
            if response.getcode() != 200:
                raise PolicyAssertionError("vault OIDC callback exchange did not return 200")
            payload = json.loads(_decode(response.read(MAX_RESPONSE_BYTES + 1)))
    except urllib.error.HTTPError as exc:
        raise PolicyAssertionError("vault OIDC callback exchange was rejected") from exc
    except (OSError, ssl.SSLError, urllib.error.URLError) as exc:
        raise PolicyAssertionError("vault OIDC callback exchange could not be completed") from exc

    auth = payload.get("auth") or {}
    token = auth.get("client_token")
    policies = auth.get("policies")
    if not isinstance(token, str) or len(token) < 10:
        raise PolicyAssertionError("vault OIDC callback did not return a usable client token")
    if not isinstance(policies, list) or "vault-admins" not in policies:
        raise PolicyAssertionError("issued vault token did not carry the vault-admins policy")
    if "root" in policies:
        raise PolicyAssertionError("issued vault token unexpectedly carried the root policy")
    return token, api_opener


def vault_api(
    opener: urllib.request.OpenerDirector,
    token: str,
    method: str,
    path: str,
    body: dict[str, object] | None = None,
) -> tuple[int, str]:
    data = None
    headers = {"X-Vault-Token": token, "User-Agent": "aigw-acceptance/1"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(f"{ORIGIN}/v1/{path}", data=data, headers=headers, method=method)
    try:
        with opener.open(request, timeout=20) as response:
            return response.getcode(), _decode(response.read(MAX_RESPONSE_BYTES + 1))
    except urllib.error.HTTPError as exc:
        return exc.code, _decode(exc.read(MAX_RESPONSE_BYTES + 1))
    except (OSError, ssl.SSLError, urllib.error.URLError) as exc:
        raise PolicyAssertionError(f"vault API call to {path} could not be completed") from exc


def assert_allowed_kv_list(opener: urllib.request.OpenerDirector, token: str) -> None:
    status, body = vault_api(opener, token, "LIST", "kv/metadata/ai-gateway")
    if status != 200:
        raise PolicyAssertionError(f"vault-admins could not list kv/ai-gateway (status {status})")
    payload = json.loads(body)
    if "keys" not in payload.get("data", {}):
        raise PolicyAssertionError("vault-admins list of kv/ai-gateway returned no keys field")


def assert_denied(
    opener: urllib.request.OpenerDirector,
    token: str,
    method: str,
    path: str,
    body: dict[str, object] | None,
    *,
    label: str,
) -> None:
    status, resp_body = vault_api(opener, token, method, path, body)
    if status != 403:
        raise PolicyAssertionError(f"{label} was not denied by the vault-admins policy (status {status})")
    if "permission denied" not in resp_body.lower():
        raise PolicyAssertionError(f"{label} denial did not report permission denied")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ca", required=True)
    args = parser.parse_args()
    password = read_password()
    oidc.install_preprod_resolution()
    try:
        context = ssl.create_default_context(cafile=args.ca)
    except (OSError, ssl.SSLError) as exc:
        raise SystemExit("could not load the reviewed CA file") from exc

    cookies = http.cookiejar.CookieJar()
    token: str | None = None
    opener: urllib.request.OpenerDirector | None = None
    try:
        try:
            token, opener = acquire_vault_admins_token(context, cookies, password)
        except Exception:
            print("VAULT_OIDC_TOKEN_ACQUIRED_FAIL", file=sys.stderr)
            raise
        print(f"VAULT_OIDC_TOKEN_ACQUIRED_PASS role=aigw username={ACCEPTANCE_USERNAME}")

        checks = (
            ("VAULT_ADMINS_KV_LIST_ALLOWED", lambda: assert_allowed_kv_list(opener, token)),
            (
                "VAULT_ADMINS_BREAK_GLASS_READ_DENIED",
                lambda: assert_denied(
                    opener,
                    token,
                    "GET",
                    "kv/data/ai-gateway/keycloak/break-glass-admin",
                    None,
                    label="break-glass-admin escrow read",
                ),
            ),
            (
                "VAULT_ADMINS_OIDC_RP_READ_DENIED",
                lambda: assert_denied(
                    opener,
                    token,
                    "GET",
                    "kv/data/ai-gateway/keycloak/vault-oidc-rp",
                    None,
                    label="vault-oidc-rp escrow read",
                ),
            ),
            (
                "VAULT_ADMINS_POLICY_LIST_DENIED",
                lambda: assert_denied(
                    opener, token, "LIST", "sys/policies/acl", None, label="sys/policies/acl listing"
                ),
            ),
            (
                "VAULT_ADMINS_AUTH_ENABLE_DENIED",
                lambda: assert_denied(
                    opener,
                    token,
                    "POST",
                    f"sys/auth/{AUTH_ENABLE_PROBE_PATH}",
                    {"type": "approle"},
                    label="auth-method enable",
                ),
            ),
        )
        for name, check in checks:
            try:
                check()
            except Exception:
                print(f"{name}_FAIL", file=sys.stderr)
                return 1
            print(f"{name}_PASS")
        print("VAULT_ADMINS_POLICY_ALL_PASS")
        return 0
    finally:
        if token is not None and opener is not None:
            # Best-effort hygiene: revoke the ephemeral token this run
            # acquired so no acceptance-run artifact stays live. Never
            # fails the check -- this is cleanup, not an assertion.
            try:
                vault_api(opener, token, "POST", "auth/token/revoke-self", {})
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
