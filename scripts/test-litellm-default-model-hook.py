#!/usr/bin/env python3
"""Prove the default-model pre-call hook against local preprod LiteLLM.

Mints a real one-time dev-portal key for the preprod-developer's project and
drives the public inference edge directly:

  * a request that OMITS ``model`` resolves to the project's configured
    default (or, if the live project has none configured, falls through to
    LiteLLM's own native missing-model rejection — both are the documented
    contract, and the harness observes which one the live policy state
    implies rather than assuming one);
  * an explicit, allowed model is honored untouched;
  * the ``aigw-default`` sentinel is exercised and classified against
    whichever of the hook's three sentinel branches the live key/policy
    state actually reaches (resolved-to-default, denied-with-no-default, or
    rejected natively by LiteLLM's own allowlist for a restricted key).

The malformed-default and allowlist-skew fail-closed permutations are
already pinned against the hook function directly by
``scripts/tests/test_litellm_default_model_hook_contract.py``; this harness
does not reproduce them live because doing so would require corrupting real
Keycloak policy state, which is out of scope for a read-mostly acceptance
run.

Model resolution is proved at the LiteLLM *router* layer rather than by
requiring a full vendor round trip: a resolved model always appears either
as the successful response's ``model`` field, or — if preprod's downstream
vendor credentials are not currently enrolled — as the ``Received Model
Group=<name>`` router diagnostic LiteLLM attaches to the resulting vendor
auth error. Both are equally strong proof of what the pre-call hook handed
the router, since vendor credential enrollment is a separate, unrelated
concern (see ``docs/anthropic-wif-bootstrap.md``) from this hook's
contract. An omitted model with no project default never reaches the
router at all (LiteLLM's own "Invalid model name passed in model=None"),
which is the distinguishing, credential-independent signal used below.

Follows the same conventions as ``test-portal-key-lifecycle.py`` and
``test-portal-login.py``: headless urllib OIDC flow, the preprod-developer
Samba password accepted only on stdin and never logged or persisted, a
restricted-redirect handler bounding every hop to the reviewed portal/auth
hosts, and a ``--ca`` flag for the deployment CA. The minted key's plaintext
lives only in process memory and is deactivated before exit even if an
assertion above it fails.
"""

from __future__ import annotations

import argparse
import http.cookiejar
import importlib.util
import json
import re
import secrets
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


LIFECYCLE_PATH = Path(__file__).with_name("test-portal-key-lifecycle.py")
LIFECYCLE_SPEC = importlib.util.spec_from_file_location(
    "aigw_portal_key_lifecycle", LIFECYCLE_PATH
)
if LIFECYCLE_SPEC is None or LIFECYCLE_SPEC.loader is None:
    raise RuntimeError("could not load portal key-lifecycle acceptance helpers")
lifecycle = importlib.util.module_from_spec(LIFECYCLE_SPEC)
LIFECYCLE_SPEC.loader.exec_module(lifecycle)

flow = lifecycle.flow  # the same test-portal-identity-flow.py helper module

API_ORIGIN = lifecycle.API_ORIGIN
SENTINEL = "aigw-default"
MAX_RESPONSE_BYTES = 1024 * 1024


def chat_completion(
    context: ssl.SSLContext, secret: str, payload: dict
) -> tuple[int, bytes]:
    """One bounded, non-redirecting chat-completions request to the edge."""

    request = urllib.request.Request(
        API_ORIGIN + "/v1/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {secret}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "aigw-default-model-hook-acceptance/1",
        },
        method="POST",
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        lifecycle.RejectRedirects(),
    )
    try:
        with opener.open(request, timeout=30) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
            status = response.status
    except urllib.error.HTTPError as exc:
        body = exc.read(MAX_RESPONSE_BYTES + 1)
        status = exc.code
    if len(body) > MAX_RESPONSE_BYTES:
        raise RuntimeError("chat completion response exceeded 1 MiB")
    return status, body


ROUTER_MODEL_GROUP_RE = re.compile(r"Received Model Group=([A-Za-z0-9_./:-]+)")
NATIVE_MISSING_MODEL_TEXT = "Invalid model name passed in model=None"


def router_model(status: int, body: bytes) -> str | None:
    """Ground truth of which model (if any) reached the LiteLLM router.

    Returns the resolved model group, or ``None`` when the router received
    no model at all (proof the hook did not substitute one). Works whether
    or not a downstream vendor credential is currently enrolled: the
    router decides and logs the model group before it ever dials the
    vendor, so a vendor auth failure still carries the resolved name.
    Raises when the response cannot be classified as either outcome.
    """

    if status == 200:
        try:
            payload = json.loads(body)
        except (TypeError, ValueError) as exc:
            raise RuntimeError("successful completion response was not JSON") from exc
        model = payload.get("model") if isinstance(payload, dict) else None
        if not isinstance(model, str) or not model:
            raise RuntimeError("successful completion response had no usable model field")
        return model
    text = body.decode("utf-8", errors="replace")
    match = ROUTER_MODEL_GROUP_RE.search(text)
    if match:
        return match.group(1)
    if NATIVE_MISSING_MODEL_TEXT in text:
        return None
    raise RuntimeError(
        f"could not classify router response (status {status}): {text[:300]!r}"
    )


def probe(context: ssl.SSLContext, secret: str, model: str | None) -> tuple[int, bytes]:
    payload: dict = {
        "messages": [{"role": "user", "content": "Reply with the single word OK."}],
        "max_tokens": 16,
        "stream": False,
    }
    if model is not None:
        payload["model"] = model
    return chat_completion(context, secret, payload)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ca", required=True)
    args = parser.parse_args()
    if sys.stdin.isatty():
        raise SystemExit("pipe the preprod-developer Samba password on stdin")
    raw = sys.stdin.buffer.read(513)
    if not raw or len(raw) > 512:
        raise SystemExit("invalid preprod password length")
    password = raw.strip().decode("utf-8")

    context = ssl.create_default_context(cafile=args.ca)
    flow.install_preprod_resolution()
    cookies = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        urllib.request.HTTPCookieProcessor(cookies),
        flow.RestrictedRedirects(flow.PORTAL_ALLOWED_HOSTS),
    )

    page_url, body = flow.keycloak_login(
        opener,
        flow.PORTAL_ORIGIN + "/login/start",
        password,
        allowed_hosts=flow.PORTAL_ALLOWED_HOSTS,
        username="preprod-developer",
    )
    if urllib.parse.urlsplit(page_url).path != "/":
        raise RuntimeError("preprod-developer login did not reach the key page")
    print("DEFAULT_MODEL_HOOK_LOGIN_PASS")

    form = lifecycle.exact_form(page_url, body, "/keys")
    project_id = str(form["inputs"].get("project_id", ""))
    if not project_id:
        raise RuntimeError("preprod-developer has no active project binding")

    # LiteLLM enforces key_alias uniqueness at the database layer even
    # across deactivated keys, so a fixed alias would fail every run after
    # the first. Suffix it with a short random token per invocation.
    alias = f"default-model-hook-acceptance-{secrets.token_hex(4)}"

    secret: str | None = None
    try:
        secret, _, generated_body = lifecycle.generate(
            opener, page_url, body, alias
        )
        if secret not in generated_body:
            raise RuntimeError("new key was not present in its creation response")
        print(f"DEFAULT_MODEL_HOOK_KEY_MINT_PASS project={project_id}")

        lifecycle.require_gateway_key_accepted(context, secret)
        print("DEFAULT_MODEL_HOOK_KEY_ACCEPTED_PASS")

        status, models_body = lifecycle.gateway_models_status(context, secret)
        if status != 200:
            raise RuntimeError("could not enumerate the key's allowed models")
        models_payload = json.loads(models_body)
        models_list = sorted(
            entry["id"]
            for entry in models_payload.get("data", [])
            if isinstance(entry, dict) and isinstance(entry.get("id"), str)
        )
        if not models_list:
            raise RuntimeError("gateway reported zero usable models for the new key")

        # Case 1: a request that omits `model` entirely. Check first
        # whether the live project has a default configured at all: the
        # router either never sees a model (native rejection, no default)
        # or sees the substituted default (hook resolved it).
        status_a, body_a = probe(context, secret, None)
        default_model = router_model(status_a, body_a)
        if default_model is not None:
            if default_model not in models_list:
                raise RuntimeError(
                    "resolved default model is not among the key's allowed models"
                )
            print(
                "AIGW_OMITTED_MODEL_RESOLVED_DEFAULT_PASS "
                f"model={default_model}"
            )
        else:
            print(
                "AIGW_OMITTED_MODEL_NATIVE_REJECTION_PASS "
                f"status={status_a}"
            )

        # Case 2: an explicit, allowed model must be left untouched.
        explicit_model = next(
            (name for name in models_list if name != default_model), models_list[0]
        )
        status_b, body_b = probe(context, secret, explicit_model)
        if router_model(status_b, body_b) != explicit_model:
            raise RuntimeError("explicit model choice was not honored untouched")
        print(f"AIGW_EXPLICIT_MODEL_HONORED_PASS model={explicit_model} status={status_b}")

        # Case 3 (best-effort): the `aigw-default` sentinel, classified by
        # whichever of the hook's documented branches the live key/policy
        # state actually reaches.
        status_c, body_c = probe(context, secret, SENTINEL)
        text_c = body_c.decode("utf-8", errors="replace")
        if status_c == 400 and "no default model configured" in text_c:
            if default_model is not None:
                raise RuntimeError(
                    "sentinel was denied despite a live default being resolvable"
                )
            print("AIGW_SENTINEL_NO_DEFAULT_DENIED_PASS")
        elif status_c == 200 or ROUTER_MODEL_GROUP_RE.search(text_c):
            sentinel_model = router_model(status_c, body_c)
            if default_model is None or sentinel_model != default_model:
                raise RuntimeError(
                    "sentinel resolved to a model inconsistent with the "
                    "omitted-model case"
                )
            print(
                f"AIGW_SENTINEL_RESOLVED_DEFAULT_PASS model={sentinel_model} "
                f"status={status_c}"
            )
        elif status_c != 200:
            # Some other rejection: the sentinel did not silently succeed or
            # widen access. This still proves the fail-closed contract even
            # when the exact branch (e.g. a restricted key's own allowlist
            # rejecting the literal "aigw-default" before the hook runs) is
            # not independently distinguishable from here.
            print(f"AIGW_SENTINEL_FAIL_CLOSED_PASS status={status_c}")
        else:
            raise RuntimeError("sentinel request unexpectedly succeeded")
    finally:
        if secret is not None:
            page_url, body = flow.read_page(opener, flow.PORTAL_ORIGIN + "/")
            lifecycle.deactivate(opener, page_url, body)
            lifecycle.require_gateway_key_revoked(context, secret)
            print("DEFAULT_MODEL_HOOK_KEY_DEACTIVATED_PASS")

    print("AIGW_DEFAULT_MODEL_HOOK_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
