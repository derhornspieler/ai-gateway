"""Shared durable provider-credential lifecycle markers.

These values live in ``rotator_settings.config``.  A provider enrollment may
be deleted only when that durable document proves either that no credential
was ever promoted or that the most recently promoted credential has expired.
"""

from __future__ import annotations

CREDENTIAL_LIFECYCLE_FIELD = "_credential_lifecycle"
CREDENTIAL_NEVER_ISSUED = "never_issued"
CREDENTIAL_PROMOTION_PENDING = "promotion_pending"
CREDENTIAL_ISSUED = "issued"

CREDENTIAL_LIFECYCLE_STATES = frozenset(
    {
        CREDENTIAL_NEVER_ISSUED,
        CREDENTIAL_PROMOTION_PENDING,
        CREDENTIAL_ISSUED,
    }
)
