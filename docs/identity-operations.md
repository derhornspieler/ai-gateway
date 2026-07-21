# Identity Operations

Production identity comes from one inventory-owned external directory over
LDAPS. The directory hostname, fixed internal address, users DN, bind DN,
attribute mapping, user filter, and public CA bundle are validated before any
stack mutation. The bind credential is stored in a dedicated encrypted Ansible
overlay and reaches key-rotator only through a root-owned read-only file.

The durable identity controller reconciles Keycloak groups, role mappings,
OIDC relying parties, redirect URIs, logout URIs, and directory federation. A
live Keycloak directory probe proves the CA chain, hostname, and bind on every
reconcile; stored component configuration alone is not treated as readiness.

## Production workflow

1. Set `identity_ldap_enabled: true` and complete the external-directory fields
   in the generated production host variables.
2. Store the bind password through
   `scripts/store-identity-ldap-bind-password.py` using stdin.
3. Run the controller preflight, then the normal production converge.
4. Confirm a named directory administrator can complete both developer-portal
   and admin-portal OIDC callbacks, and that logout ends the Keycloak session.

Do not edit imported realm JSON to update an existing realm; Keycloak imports
realm templates only into an empty database. Runtime identity changes belong
to the controller/reconciliation path.

## Migrating an existing realm to `aigw-chat`

An existing realm created before the dedicated chat capability must be
migrated with the reviewed break-glass master administrator. Create the
`aigw-chat` realm role, assign it to every group that should retain chat
access, and add its scope mapping to each first-party relying party. Complete
and verify this one-time migration **BEFORE the converge**: the verify role
fails closed if the role, group mappings, or relying-party scopes are absent.

## Local preprod

The localhost-only preprod overlay supplies a disposable Samba AD over LDAPS
with static `preprod-*` identities. It exercises the same production
`IDENTITY_LDAP_*` configuration and live bind proof. Run its acceptance through
`scripts/update-images.py test-preprod`; see [preprod.md](preprod.md).
