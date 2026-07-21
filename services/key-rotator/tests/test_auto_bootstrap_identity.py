from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request

import pytest

from app import auto_bootstrap_identity


TOKEN = "0123456789abcdef0123456789abcdef"


class Response:
    def __init__(self, payload: bytes, *, status: int = 200) -> None:
        self.payload = payload
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _size: int) -> bytes:
        return self.payload


class Opener:
    def __init__(self, response: Response | Exception) -> None:
        self.response = response
        self.calls: list[tuple[urllib.request.Request, int]] = []

    def open(self, request: urllib.request.Request, *, timeout: int):
        self.calls.append((request, timeout))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def install_response(monkeypatch, payload: bytes, *, status: int = 200) -> Opener:
    opener = Opener(Response(payload, status=status))
    monkeypatch.setenv("ROTATOR_INTERNAL_TOKEN", TOKEN)
    monkeypatch.setattr(
        auto_bootstrap_identity.urllib.request,
        "build_opener",
        lambda *_handlers: opener,
    )
    return opener


@pytest.mark.parametrize(
    ("result", "marker"),
    [
        ("applied", auto_bootstrap_identity.APPLIED_MARKER),
        ("verified", auto_bootstrap_identity.VERIFIED_MARKER),
    ],
)
def test_loopback_route_returns_only_fixed_success_markers(
    monkeypatch, result: str, marker: str
) -> None:
    opener = install_response(
        monkeypatch,
        json.dumps({"result": result}).encode("ascii"),
    )

    assert auto_bootstrap_identity.converge() == marker

    assert len(opener.calls) == 1
    request, timeout = opener.calls[0]
    assert request.full_url == auto_bootstrap_identity.DEPLOYMENT_URL
    assert request.get_method() == "POST"
    assert request.data == b'{"confirmation":"AUTO_BOOTSTRAP_IDENTITY"}'
    assert request.get_header("Content-type") == "application/json"
    assert request.get_header("X-internal-auth") == TOKEN
    assert timeout == 300


def test_loopback_transport_disables_proxies_and_redirects(monkeypatch) -> None:
    handlers: list[object] = []
    opener = Opener(Response(b'{"result":"verified"}'))

    def build_opener(*received):
        handlers.extend(received)
        return opener

    monkeypatch.setenv("ROTATOR_INTERNAL_TOKEN", TOKEN)
    monkeypatch.setattr(
        auto_bootstrap_identity.urllib.request, "build_opener", build_opener
    )

    assert (
        auto_bootstrap_identity.converge()
        == auto_bootstrap_identity.VERIFIED_MARKER
    )
    assert len(handlers) == 2
    assert isinstance(handlers[0], urllib.request.ProxyHandler)
    assert handlers[0].proxies == {}
    assert isinstance(handlers[1], auto_bootstrap_identity.NoRedirects)


@pytest.mark.parametrize(
    "payload",
    [
        b"not-json",
        b"[]",
        b'{"result":"verified","extra":true}',
        b'{"result":"skipped"}',
        b"x" * (auto_bootstrap_identity.MAX_RESPONSE_BYTES + 1),
    ],
)
def test_invalid_or_oversized_response_fails_closed(monkeypatch, payload: bytes) -> None:
    install_response(monkeypatch, payload)

    with pytest.raises(RuntimeError, match="identity deployment response"):
        auto_bootstrap_identity.converge()


def test_non_success_response_fails_closed(monkeypatch) -> None:
    install_response(monkeypatch, b"secret directory diagnostic", status=503)

    with pytest.raises(RuntimeError, match="did not succeed"):
        auto_bootstrap_identity.converge()


def test_transport_failure_does_not_include_upstream_detail(monkeypatch) -> None:
    secret = "directory-password-from-upstream"
    failure = urllib.error.URLError(secret)
    opener = Opener(failure)
    monkeypatch.setenv("ROTATOR_INTERNAL_TOKEN", TOKEN)
    monkeypatch.setattr(
        auto_bootstrap_identity.urllib.request,
        "build_opener",
        lambda *_handlers: opener,
    )

    with pytest.raises(RuntimeError) as raised:
        auto_bootstrap_identity.converge()
    assert secret not in str(raised.value)


@pytest.mark.parametrize("token", ["", "short\ncontrol", "x" * 4097])
def test_missing_or_unsafe_inherited_token_is_rejected(monkeypatch, token: str) -> None:
    monkeypatch.setenv("ROTATOR_INTERNAL_TOKEN", token)

    with pytest.raises(RuntimeError, match="authentication is unavailable"):
        auto_bootstrap_identity.converge()


def test_command_prints_only_the_success_marker(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        auto_bootstrap_identity,
        "converge",
        lambda: auto_bootstrap_identity.APPLIED_MARKER,
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "auto_bootstrap_identity.py",
            "--confirm",
            auto_bootstrap_identity.CONFIRMATION,
        ],
    )

    assert auto_bootstrap_identity.main() == 0
    captured = capsys.readouterr()
    assert captured.out == f"{auto_bootstrap_identity.APPLIED_MARKER}\n"
    assert captured.err == ""


def test_command_redacts_failures(monkeypatch, capsys) -> None:
    secret = "secret directory password"

    def fail() -> str:
        raise RuntimeError(secret)

    monkeypatch.setattr(auto_bootstrap_identity, "converge", fail)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "auto_bootstrap_identity.py",
            "--confirm",
            auto_bootstrap_identity.CONFIRMATION,
        ],
    )

    assert auto_bootstrap_identity.main() == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == f"{auto_bootstrap_identity.FAILED_MARKER}\n"
    assert secret not in captured.err
