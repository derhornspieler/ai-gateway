#!/usr/bin/env python3
"""Remove Open WebUI's role-bypassing first-user OAuth promotion.

This is intentionally an exact, version-locked transform for the immutable
Open WebUI v0.10.2 image used by Compose. It must fail rather than make a broad
or fuzzy edit when upstream bytes change.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import sys


EXPECTED_SOURCE_SHA256 = (
    "8c8b04f4e032ab309daff93b19b07d178d005cfcfcfc3fc4b56fcd65b2b2c8b4"
)
# Filled with the exact digest of the reviewed transform below. Keeping the
# output digest pinned catches an accidental edit to any replacement too.
EXPECTED_PATCHED_SHA256 = (
    "e4405033f827241d110d4591e58d54d820428dccc8ccc08ecc15ddb1125ba535"
)
MAX_SOURCE_BYTES = 512 * 1024

FIRST_USER_ROLE_BYPASS = """\
        user_count = await Users.get_num_users()
        if user and user_count == 1:
            # If the user is the only user, assign the role "admin" - actually repairs role for single user on login
            log.debug('Assigning the only user the admin role')
            return 'admin'
        if not user and user_count == 0:
            # First-user bootstrap: skip role management gating so the
            # instance can be initialized.  We intentionally return the
            # default role here (not 'admin') — admin promotion happens
            # race-safely *after* insert via get_num_users() == 1.
            log.debug('First user bootstrap: using default role (admin promotion deferred to post-insert)')
            return auth_config.DEFAULT_USER_ROLE

""".encode("utf-8")

POST_INSERT_ADMIN_PROMOTION = """\
                    # Atomically check if this is the only user *after* the
                    # insert to avoid TOCTOU race on first-user registration.
                    # Matches signup_handler pattern.
                    if await Users.get_num_users(db=db) == 1:
                        await Users.update_user_role_by_id(user.id, 'admin', db=db)
                        user = await Users.get_user_by_id(user.id, db=db)

""".encode("utf-8")

ROLE_GATE_ANCHOR = """\
            # If roles are present in the token, they must match; otherwise deny access
            if oauth_roles:
""".encode("utf-8")

ROLE_GATE_REPLACEMENT = """\
            # Role management is enabled, so an absent or empty roles claim
            # must not fall through to the default local role.
            if not oauth_roles:
                log.warning(
                    'OAuth role management enabled but the roles claim is absent or empty.'
                )
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN,
                    detail=ERROR_MESSAGES.ACCESS_PROHIBITED,
                )

            # If roles are present in the token, they must match; otherwise deny access
            if oauth_roles:
""".encode("utf-8")


def transform(source: bytes) -> bytes:
    if len(source) > MAX_SOURCE_BYTES:
        raise ValueError("Open WebUI OAuth source exceeds the reviewed bound")
    if hashlib.sha256(source).hexdigest() != EXPECTED_SOURCE_SHA256:
        raise ValueError("Open WebUI OAuth source digest drifted")
    if source.count(FIRST_USER_ROLE_BYPASS) != 1:
        raise ValueError("first-user role bypass snippet drifted")
    if source.count(POST_INSERT_ADMIN_PROMOTION) != 1:
        raise ValueError("post-insert admin promotion snippet drifted")
    if source.count(ROLE_GATE_ANCHOR) != 1:
        raise ValueError("OAuth role gate anchor drifted")

    patched = source.replace(FIRST_USER_ROLE_BYPASS, b"", 1).replace(
        POST_INSERT_ADMIN_PROMOTION, b"", 1
    )
    patched = patched.replace(ROLE_GATE_ANCHOR, ROLE_GATE_REPLACEMENT, 1)
    if FIRST_USER_ROLE_BYPASS in patched or POST_INSERT_ADMIN_PROMOTION in patched:
        raise ValueError("Open WebUI OAuth promotion removal was incomplete")
    if patched.count(ROLE_GATE_REPLACEMENT) != 1:
        raise ValueError("Open WebUI fail-closed role gate was not installed exactly once")
    if b"if auth_config.ENABLE_OAUTH_ROLE_MANAGEMENT:" not in patched:
        raise ValueError("Open WebUI OAuth role management disappeared")
    if b"for admin_role in oauth_admin_roles:" not in patched:
        raise ValueError("Open WebUI OAuth admin-role mapping disappeared")
    if b"if admin_role in oauth_roles:" not in patched:
        raise ValueError("Open WebUI OAuth admin-role membership check disappeared")
    if hashlib.sha256(patched).hexdigest() != EXPECTED_PATCHED_SHA256:
        raise ValueError("patched Open WebUI OAuth source digest drifted")
    compile(patched, "oauth.py", "exec")
    return patched


def patch_file(path: Path) -> None:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != 0
    ):
        raise ValueError("Open WebUI OAuth source has an unsafe file boundary")
    with path.open("rb") as source_file:
        source = source_file.read(MAX_SOURCE_BYTES + 1)
    patched = transform(source)
    with path.open("wb") as destination:
        destination.write(patched)
        destination.flush()
        os.fsync(destination.fileno())


def main() -> int:
    if len(sys.argv) != 2:
        return 2
    try:
        patch_file(Path(sys.argv[1]))
    except Exception as exc:  # build-only diagnostic; source contains no secrets
        print(f"Open WebUI OAuth hardening failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
