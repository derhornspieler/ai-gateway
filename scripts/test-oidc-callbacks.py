#!/usr/bin/env python3
"""Exercise browserless OIDC callbacks against the local preprod edges.

This is intentionally a preprod acceptance harness rather than a general-purpose
HTTP client. It accepts the static test-directory password only on stdin and
has no host, callback, redirect, or return-URL command-line options.  Every
network transition is restricted to one hard-coded relying-party hostname and
the Keycloak issuer over HTTPS. Those names resolve directly to the reviewed
loopback listeners without relying on workstation DNS or /etc/hosts; their URL
hostnames remain intact for TLS SNI, certificate validation, cookies, and Host
routing.
"""

from __future__ import annotations

import argparse
import http.cookiejar
import importlib.util
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path


FLOW_PATH = Path(__file__).with_name("test-portal-identity-flow.py")
SPEC = importlib.util.spec_from_file_location("aigw_portal_flow", FLOW_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load portal acceptance form parser")
flow = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(flow)


AUTH_HOST = "auth.aigw.internal"
AUTH_LOGIN_ACTION_PREFIX = "/realms/aigw/login-actions/authenticate"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
ACCEPTANCE_USERNAMES = frozenset(
    {"preprod-admin", "preprod-developer", "preprod-user"}
)

PREPROD_HOST_ADDRESSES = {
    "admin.aigw.internal": "127.0.3.1",
    "auth.aigw.internal": "127.0.3.1",
    "chat.aigw.internal": "127.0.3.1",
    "grafana.aigw.internal": "127.0.3.1",
    "litellm-admin.aigw.internal": "127.0.3.1",
    "prometheus.aigw.internal": "127.0.3.1",
    "vault.aigw.internal": "127.0.3.1",
}
_SYSTEM_GETADDRINFO = socket.getaddrinfo


def preprod_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    if not isinstance(host, str) or host not in PREPROD_HOST_ADDRESSES:
        raise socket.gaierror(
            socket.EAI_NONAME,
            "hostname is outside the reviewed preprod OIDC boundary",
        )
    return _SYSTEM_GETADDRINFO(
        PREPROD_HOST_ADDRESSES[host], port, family, type, proto, flags
    )


def install_preprod_resolution() -> None:
    if socket.getaddrinfo is not _SYSTEM_GETADDRINFO:
        raise RuntimeError("socket name resolution was already replaced")
    socket.getaddrinfo = preprod_getaddrinfo


class AcceptanceError(RuntimeError):
    """A deliberately non-sensitive live-acceptance failure."""


@dataclass(frozen=True)
class OidcTarget:
    name: str
    host: str
    start_path: str
    callback_path: str
    requested_path: str
    final_paths: frozenset[str]
    probe_path: str
    probe_statuses: frozenset[int]
    session_cookie: str
    denied_paths: tuple[str, ...] = ()

    @property
    def origin(self) -> str:
        return f"https://{self.host}"

    @property
    def allowed_hosts(self) -> frozenset[str]:
        return frozenset({AUTH_HOST, self.host})


# This closed allow-list is deliberately duplicated from the reviewed
# Keycloak redirect URI contract.  Do not turn any of these values into CLI
# options: a browserless password flow must never follow an arbitrary IdP,
# callback, or return URL.
TARGETS = (
    OidcTarget(
        name="litellm-admin",
        host="litellm-admin.aigw.internal",
        start_path="/oauth2/start",
        callback_path="/oauth2/callback",
        requested_path="/ui",
        final_paths=frozenset({"/ui", "/ui/"}),
        probe_path="/oauth2/auth",
        probe_statuses=frozenset({202}),
        session_cookie="_aigw_litellm_admin_oauth",
        denied_paths=(
            "/openapi.json",
            "/openapi.json/",
            "/docs",
            "/docs/",
            "/redoc",
            "/redoc/",
        ),
    ),
    OidcTarget(
        name="grafana",
        host="grafana.aigw.internal",
        start_path="/oauth2/start",
        callback_path="/oauth2/callback",
        requested_path="/",
        final_paths=frozenset({"/"}),
        probe_path="/oauth2/auth",
        probe_statuses=frozenset({202}),
        session_cookie="_aigw_grafana_oauth",
    ),
    OidcTarget(
        name="prometheus",
        host="prometheus.aigw.internal",
        start_path="/oauth2/start",
        callback_path="/oauth2/callback",
        requested_path="/",
        # Prometheus' reviewed UI has used both /graph and /query as the
        # canonical root landing page across supported releases.
        final_paths=frozenset({"/", "/graph", "/query"}),
        probe_path="/oauth2/auth",
        probe_statuses=frozenset({202}),
        session_cookie="_aigw_prometheus_oauth",
    ),
    OidcTarget(
        name="vault",
        host="vault.aigw.internal",
        start_path="/oauth2/start",
        callback_path="/oauth2/callback",
        requested_path="/ui/",
        final_paths=frozenset({"/ui/"}),
        probe_path="/oauth2/auth",
        probe_statuses=frozenset({202}),
        session_cookie="_aigw_vault_oauth",
    ),
    OidcTarget(
        name="chat",
        host="chat.aigw.internal",
        start_path="/oauth/oidc/login",
        callback_path="/oauth/oidc/callback",
        requested_path="/auth",
        final_paths=frozenset({"/auth"}),
        probe_path="/api/v1/auths/",
        probe_statuses=frozenset({200}),
        session_cookie="token",
    ),
)
TARGET_BY_NAME = {target.name: target for target in TARGETS}


def require_reviewed_target(target: OidcTarget) -> None:
    """Reject a caller-supplied target rather than broadening the boundary."""

    if TARGET_BY_NAME.get(target.name) is not target:
        raise ValueError("OIDC target is not part of the reviewed allow-list")


def reviewed_https_url(url: str, allowed_hosts: frozenset[str]):
    """Parse one strictly reviewed HTTPS URL without retaining its query."""

    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise AcceptanceError("OIDC URL was malformed") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname not in allowed_hosts
        or port not in (None, 443)
        or parsed.username is not None
        or parsed.password is not None
        or not parsed.path.startswith("/")
    ):
        raise AcceptanceError("OIDC redirect left reviewed HTTPS hosts")
    return parsed


class RestrictedRedirects(urllib.request.HTTPRedirectHandler):
    """Follow only Keycloak <-> one reviewed relying-party redirects."""

    def __init__(self, target: OidcTarget) -> None:
        super().__init__()
        require_reviewed_target(target)
        self.target = target
        self.redirects: list[tuple[str, str]] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = reviewed_https_url(newurl, self.target.allowed_hosts)
        # Keep only origin/path evidence. Authorization codes, state, and
        # error descriptions are never retained or printed by this harness.
        self.redirects.append((parsed.hostname, parsed.path))
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """Expose a probe's first status instead of silently re-authenticating."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def read_response(opener, url: str) -> tuple[str, str]:
    """Read a bounded successful response and return its final URL/body."""

    request = urllib.request.Request(url, headers={"User-Agent": "aigw-acceptance/1"})
    try:
        with opener.open(request, timeout=30) as response:
            final_url = response.geturl()
            body = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise AcceptanceError("OIDC request returned an unexpected HTTP status") from exc
    except (OSError, ssl.SSLError, urllib.error.URLError) as exc:
        raise AcceptanceError("OIDC request could not be completed") from exc
    if len(body) > MAX_RESPONSE_BYTES:
        raise AcceptanceError("OIDC response exceeded the acceptance limit")
    try:
        return final_url, body.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise AcceptanceError("OIDC response was not valid UTF-8") from exc


def find_keycloak_login_form(html: str) -> dict[str, object]:
    forms = [
        form
        for form in flow.parse_forms(html)
        if AUTH_LOGIN_ACTION_PREFIX in str(form["action"])
    ]
    if len(forms) != 1 or str(forms[0]["method"]).lower() != "post":
        raise AcceptanceError("Keycloak password form was not unique")
    return forms[0]


def reviewed_login_action(
    base_url: str,
    form: dict[str, object],
    target: OidcTarget,
) -> str:
    """Resolve and validate the only endpoint permitted to receive a password."""

    require_reviewed_target(target)
    action = urllib.parse.urljoin(base_url, str(form["action"]))
    parsed = reviewed_https_url(action, target.allowed_hosts)
    if parsed.hostname != AUTH_HOST or not parsed.path.startswith(AUTH_LOGIN_ACTION_PREFIX):
        raise AcceptanceError("password form action was outside the Keycloak boundary")
    return action


def post_keycloak_login(
    opener,
    base_url: str,
    form: dict[str, object],
    *,
    target: OidcTarget,
    username: str,
    password: str,
) -> tuple[str, str]:
    """Submit credentials only to the reviewed Keycloak form action."""

    action = reviewed_login_action(base_url, form, target)
    values = dict(form["inputs"])
    values.update({"username": username, "password": password})
    request = urllib.request.Request(
        action,
        data=urllib.parse.urlencode(values).encode("utf-8"),
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "aigw-acceptance/1",
        },
        method="POST",
    )
    try:
        with opener.open(request, timeout=45) as response:
            final_url = response.geturl()
            body = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise AcceptanceError("OIDC callback returned an unexpected HTTP status") from exc
    except (OSError, ssl.SSLError, urllib.error.URLError) as exc:
        raise AcceptanceError("OIDC callback could not be completed") from exc
    if len(body) > MAX_RESPONSE_BYTES:
        raise AcceptanceError("OIDC callback response exceeded the acceptance limit")
    try:
        return final_url, body.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise AcceptanceError("OIDC callback response was not valid UTF-8") from exc


def verify_callback_completion(
    target: OidcTarget,
    redirects: list[tuple[str, str]],
    final_url: str,
    html: str,
) -> None:
    """Require a clean return through the target's exact registered callback."""

    require_reviewed_target(target)
    if (target.host, target.callback_path) not in redirects:
        raise AcceptanceError("OIDC flow did not reach its registered callback")
    parsed = reviewed_https_url(final_url, frozenset({target.host}))
    if parsed.path not in target.final_paths:
        raise AcceptanceError("OIDC callback returned to an unexpected application path")
    query_names = {name for name, _ in urllib.parse.parse_qsl(parsed.query)}
    if query_names & {"error", "error_description", "error_message"}:
        raise AcceptanceError("OIDC callback completed with an application error")
    if query_names & {"code", "state", "session_state", "token", "access_token", "id_token"}:
        raise AcceptanceError("OIDC callback leaked sensitive material into its return URL")
    lowered = html.lower()
    if "invalid_scope" in lowered or "internal server error" in lowered:
        raise AcceptanceError("OIDC callback returned a known authentication failure")


def require_session_cookie(cookies: http.cookiejar.CookieJar, target: OidcTarget) -> None:
    """Require the target's secure session cookie without ever reading its value."""

    require_reviewed_target(target)
    matching = [
        cookie
        for cookie in cookies
        if (
            cookie.name == target.session_cookie
            and cookie.domain.lstrip(".") == target.host
            and cookie.secure
        )
    ]
    if len(matching) != 1:
        raise AcceptanceError("OIDC callback did not establish the expected secure session")


def probe_status(
    context: ssl.SSLContext,
    cookies: http.cookiejar.CookieJar,
    target: OidcTarget,
    path: str | None = None,
) -> int:
    """Make one no-redirect session probe so an auth loop cannot pass."""

    require_reviewed_target(target)
    if path is None:
        path = target.probe_path
    elif path not in target.denied_paths:
        raise ValueError("probe path is not part of the reviewed target contract")
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        urllib.request.HTTPCookieProcessor(cookies),
        RefuseRedirects(),
    )
    request = urllib.request.Request(
        target.origin + path,
        headers={"User-Agent": "aigw-acceptance/1"},
    )
    try:
        with opener.open(request, timeout=30) as response:
            return response.getcode()
    except urllib.error.HTTPError as exc:
        return exc.code
    except (OSError, ssl.SSLError, urllib.error.URLError) as exc:
        raise AcceptanceError("authenticated session probe could not be completed") from exc


def start_url(target: OidcTarget) -> str:
    """Build a reviewed local return path; no remote return URL is accepted."""

    require_reviewed_target(target)
    if target.start_path == "/oauth2/start":
        return (
            target.origin
            + target.start_path
            + "?rd="
            + urllib.parse.quote(target.requested_path, safe="/")
        )
    return target.origin + target.start_path


def run_target(context: ssl.SSLContext, target: OidcTarget, username: str, password: str) -> None:
    """Run one independent full authorization-code callback flow."""

    require_reviewed_target(target)
    cookies = http.cookiejar.CookieJar()
    redirects = RestrictedRedirects(target)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        urllib.request.HTTPCookieProcessor(cookies),
        redirects,
    )
    login_url, login_html = read_response(opener, start_url(target))
    login_url_parts = reviewed_https_url(login_url, target.allowed_hosts)
    if login_url_parts.hostname != AUTH_HOST:
        raise AcceptanceError("OIDC start did not reach the Keycloak password form")
    form = find_keycloak_login_form(login_html)
    final_url, final_html = post_keycloak_login(
        opener,
        login_url,
        form,
        target=target,
        username=username,
        password=password,
    )
    verify_callback_completion(target, redirects.redirects, final_url, final_html)
    require_session_cookie(cookies, target)
    if probe_status(context, cookies, target) not in target.probe_statuses:
        raise AcceptanceError("OIDC session did not survive the authenticated probe")
    for denied_path in target.denied_paths:
        if probe_status(context, cookies, target, denied_path) != 403:
            raise AcceptanceError("authenticated session reached a denied endpoint")


def read_password() -> str:
    if sys.stdin.isatty():
        raise SystemExit("pipe the static preprod password on stdin")
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ca", required=True)
    parser.add_argument(
        "--target",
        choices=("all", *TARGET_BY_NAME),
        default="all",
        help="one reviewed relying party, or all reviewed relying parties",
    )
    parser.add_argument(
        "--username",
        choices=tuple(sorted(ACCEPTANCE_USERNAMES)),
        default="preprod-admin",
    )
    args = parser.parse_args()
    if args.username != "preprod-admin" and args.target != "chat":
        raise SystemExit(
            "non-admin preprod identities may exercise only the chat target here"
        )
    password = read_password()
    try:
        context = ssl.create_default_context(cafile=args.ca)
    except (OSError, ssl.SSLError) as exc:
        raise SystemExit("could not load the reviewed CA file") from exc
    install_preprod_resolution()
    selected = TARGETS if args.target == "all" else (TARGET_BY_NAME[args.target],)
    for target in selected:
        try:
            run_target(context, target, args.username, password)
        except Exception:
            # Keep query strings, cookies, forms, and password-derived details
            # out of CI and terminal output.
            print(f"OIDC_CALLBACK_FAIL target={target.name}", file=sys.stderr)
            return 1
        print(f"OIDC_CALLBACK_PASS target={target.name} username={args.username}")
    print(f"OIDC_CALLBACK_ALL_PASS count={len(selected)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
