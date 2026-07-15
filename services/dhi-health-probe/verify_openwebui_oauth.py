#!/usr/bin/env python3
"""Behaviorally verify the patched Open WebUI OAuth role method.

The verifier executes only the reviewed method from the built image's parsed
source with inert standard-library stubs. It deliberately avoids importing
Open WebUI, initializing a database, or contacting an identity provider.
"""

from __future__ import annotations

import ast
import asyncio
from pathlib import Path
import sys
from types import SimpleNamespace


class ReviewedHttpException(Exception):
    def __init__(self, status_code: int, *, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class InertLog:
    def debug(self, *args: object, **kwargs: object) -> None:
        pass

    def warning(self, *args: object, **kwargs: object) -> None:
        pass


RUNTIME_CONFIG = SimpleNamespace(
    ENABLE_OAUTH_ROLE_MANAGEMENT=True,
    OAUTH_ROLES_CLAIM="roles",
    # Chat access is the dedicated aigw-chat capability only; the legacy
    # aigw-users role and the developer role no longer admit a session.
    OAUTH_ALLOWED_ROLES=["aigw-chat"],
    OAUTH_ADMIN_ROLES=["aigw-admins"],
    DEFAULT_USER_ROLE="user",
)


async def reviewed_runtime_config() -> SimpleNamespace:
    return RUNTIME_CONFIG


def load_reviewed_method(source_path: Path):
    tree = ast.parse(source_path.read_bytes(), filename=str(source_path))
    oauth_manager = next(
        (
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "OAuthManager"
        ),
        None,
    )
    if oauth_manager is None:
        raise ValueError("OAuthManager class is missing")
    methods = [
        node
        for node in oauth_manager.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "get_user_role"
    ]
    if len(methods) != 1:
        raise ValueError("get_user_role must exist exactly once")

    skeleton = ast.parse("class ReviewedOAuthManager:\n    pass\n")
    reviewed_class = skeleton.body[0]
    if not isinstance(reviewed_class, ast.ClassDef):
        raise AssertionError("invalid verifier skeleton")
    reviewed_class.body = methods
    ast.fix_missing_locations(skeleton)

    namespace = {
        "ERROR_MESSAGES": SimpleNamespace(ACCESS_PROHIBITED="access prohibited"),
        "HTTPException": ReviewedHttpException,
        "OAUTH_ROLES_SEPARATOR": ",",
        "get_oauth_runtime_config": reviewed_runtime_config,
        "log": InertLog(),
        "status": SimpleNamespace(HTTP_403_FORBIDDEN=403),
    }
    exec(compile(skeleton, str(source_path), "exec"), namespace)
    return namespace["ReviewedOAuthManager"].get_user_role


async def verify(source_path: Path) -> None:
    get_user_role = load_reviewed_method(source_path)
    manager = object()

    rejected_claims = (
        {},
        {"roles": []},
        {"roles": ["unapproved"]},
        # The pre-aigw-chat roles must no longer admit a chat session.
        {"roles": ["aigw-users"]},
        {"roles": ["aigw-developers"]},
        {"roles": ["aigw-users", "aigw-developers"]},
    )
    for claims in rejected_claims:
        try:
            await get_user_role(manager, None, claims)
        except ReviewedHttpException as exc:
            if exc.status_code != 403:
                raise AssertionError("role rejection did not return HTTP 403") from exc
        else:
            raise AssertionError(f"unapproved role claim was accepted: {claims!r}")

    first_non_admin = await get_user_role(manager, None, {"roles": ["aigw-chat"]})
    if first_non_admin != "user":
        raise AssertionError("first allowed non-admin identity was promoted")

    genuine_admin = await get_user_role(manager, None, {"roles": ["aigw-admins"]})
    if genuine_admin != "admin":
        raise AssertionError("approved admin identity did not map to local admin")


def main() -> int:
    if len(sys.argv) != 2:
        return 2
    asyncio.run(verify(Path(sys.argv[1])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
