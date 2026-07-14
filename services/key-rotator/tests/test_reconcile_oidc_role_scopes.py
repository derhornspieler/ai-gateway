from __future__ import annotations

import sys

from app import reconcile_oidc_role_scopes


def test_unexpected_failure_has_only_a_fixed_redacted_marker(
    monkeypatch, capsys
) -> None:
    async def unexpected_failure() -> bool:
        raise RuntimeError("sensitive topology and bootstrap credential detail")

    monkeypatch.setattr(reconcile_oidc_role_scopes, "reconcile", unexpected_failure)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "reconcile_oidc_role_scopes.py",
            "--confirm",
            reconcile_oidc_role_scopes.CONFIRMATION,
        ],
    )

    assert reconcile_oidc_role_scopes.main() == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "OIDC_ROLE_SCOPE_PREBOOTSTRAP_RECONCILIATION_FAILED\n"
    assert "RuntimeError" not in captured.err
    assert "sensitive topology" not in captured.err
