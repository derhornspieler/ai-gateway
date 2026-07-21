# Identity operations

Ansible sets up Keycloak. The user does not initialize identity in the admin
portal.

Production connects to one customer directory over LDAPS. Preprod connects to
its own Samba AD test container. Both paths use the same Keycloak setup code.

## What Ansible does

After Vault is ready and the LDAPS bind password is mounted, each full
converge does this work:

1. Proves the directory certificate, hostname, and bind account.
2. Creates or checks the Keycloak directory provider.
3. Creates or checks the managed groups and realm roles.
4. Creates or checks each first-party OIDC client.
5. Builds redirect, origin, and logout URLs from `aigw_domain`.
6. Stores the long-term identity controller data in Vault.
7. Removes the short-term bootstrap account and client.
8. Checks the final state.

The setup is safe to run again. If a live setting does not match the inventory,
the controller repairs the managed setting or stops with an error.

The admin portal no longer has an identity initialization step. Its identity
pages are for normal access work after deployment. They are not a deployment
gate.

## Domain-based Keycloak URLs

Set the base domain once with `aigw_domain`. Ansible uses it for every managed
Keycloak URL.

| Client | Redirect URL pattern |
| --- | --- |
| Open WebUI | `https://chat.<domain>/oauth/oidc/callback` |
| Developer portal | `https://portal.<domain>/auth/callback` |
| Admin portal | `https://admin.<domain>/auth/callback` |
| Admin UI proxy | `https://litellm-admin.<domain>/oauth2/callback`, `https://grafana.<domain>/oauth2/callback`, `https://prometheus.<domain>/oauth2/callback`, and `https://vault.<domain>/oauth2/callback` |
| Vault OIDC | `https://vault.<domain>/ui/vault/auth/oidc/oidc/callback` and the approved local CLI callback |

Web origins and logout URLs use the same domain. Do not enter a second domain
in Keycloak by hand.

If you change `aigw_domain`, update DNS and edge certificates first. Then run
the full production converge. Ansible checks the managed clients against the
new domain. It fails if it cannot make the live realm match.

## Production workflow

1. Set `identity_ldap_enabled: true` in the generated host variables.
2. Fill in every `identity_ldap_*` field. Use an `ldaps://` URL and a CA file
   with an absolute path.
3. Store the bind password with the stdin-only helper:

   ```bash
   read -rsp 'Directory bind password: ' AIGW_LDAP_BIND; printf '\n'
   printf '%s\n' "$AIGW_LDAP_BIND" | \
     python3 -I scripts/store-identity-ldap-bind-password.py \
       --vault-file ansible/inventory/generated/<alias>/group_vars/production_rocky9/identity-ldap.yml \
       --vault-id <vault-id> \
       --vault-password-file </absolute/private/password-file>
   unset AIGW_LDAP_BIND
   ```

4. Run the controller preflight.
5. Run the normal two-pass production converge in the
   [deployment runbook](deploy-runbook.md).
6. Assign one named directory user to the approved admin group. This is an
   access grant, not platform initialization.
7. Test login and logout at the developer portal and admin portal.

Never put the bind password in host variables, command options, shell history,
or a ticket.

## Migrating an existing realm to `aigw-chat`

This section is only for a realm created before the separate chat role existed.

Use the reviewed break-glass master administrator. Create the `aigw-chat`
realm role. Give it to each group that should use chat. Add the role scope to
each first-party OIDC client.

Finish and test this change **BEFORE the converge**. The verify role stops if
the role, group links, or client scopes are missing.

Do not edit imported realm JSON to repair a live realm. Keycloak reads realm
imports only when its database is empty.

## Local preprod

Preprod uses static test users and Samba AD over LDAPS. Ansible performs the
same automatic Keycloak setup and domain-based redirect checks. A successful
run prints `PREPROD_E2E_PASSED`.

See [Local preprod](preprod.md) and the
[acceptance test runbook](test-runbook.md).
