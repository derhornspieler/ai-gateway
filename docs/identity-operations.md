# Identity, Directory Federation, and Group Operations

This guide keeps three ownership domains distinct, because blurring them is how
directory operations go wrong. AD or LDAP owns usernames, passwords, account
enablement, and password policy; the Parallels lab uses a disposable Samba AD
domain, while a customer deployment uses the customer's own directory through a
separately reviewed integration. Keycloak (realm `aigw`) imports or federates
those directory users, authenticates them, emits realm-role claims, and stores
the AI Gateway authorization groups. The portals create and delete only managed
Keycloak groups and assign already-imported directory users to them; they never
create a directory account, change a password, or write a directory group.

The user-facing self-service portal (`dev-portal`) runs on the internal leg and
the administrative portal (`admin-portal`) runs on the ADM leg. Both are the
same image `ai-gateway/portal:1`. The `key-rotator` service is the Keycloak
identity controller behind the admin portal: the browser and either portal never
receive a Keycloak administration credential or a private key. See
[solution-map.md](solution-map.md) for the trust boundaries and
[deploy-guide.md](deploy-guide.md) for how the stack is brought up.

## Current deployment contract

The base Compose stack runs both portals and the rotator identity controller.
The Parallels profile additionally merges `compose/docker-compose.lab.yml` under
the explicit `lab-ad` Compose profile, which starts `samba-ad` (the lab domain
controller) and `lab-dns`, attaches Samba and Keycloak to the isolated,
internal `net-identity` bridge, publishes no Samba host ports, mounts the
domain-admin password, the read-only bind password, and three per-user
passwords as file-backed Docker secrets rather than environment variables,
persists `/etc/samba`, `/var/lib/samba`, and the public LDAPS certificate in
three named volumes, mounts only that public certificate into Keycloak
(`KC_TRUSTSTORE_PATHS=/var/lib/samba-public/ca.pem`), and enables the lab LDAP
setup path in key-rotator through `LAB_SAMBA_LDAP_ENABLED`. The bind password is
the only secret shared between Samba and key-rotator.

Samba runs unprivileged in the Docker sense (`privileged: false`) with
`no-new-privileges`, a read-only root filesystem, all Linux capabilities dropped
and only those Samba AD requires added back. Its healthcheck validates the
domain database, the Samba control plane, domain policy, and hostname-verified
LDAPS on port 636 rather than merely checking that a process is alive.
Provisioning and seed passwords stay inside the container: a small helper reads
bounded Docker-secret files with `O_NOFOLLOW` and drives the Samba Python API
directly, so no password is passed as a child-process argument, an environment
variable, or a generated shell command.

The lab directory is fixed:

| Item | Value |
|---|---|
| realm/forest | `LAB.AIGW.INTERNAL` |
| NetBIOS domain | `AIGWLAB` |
| DC hostname | `samba-ad` |
| Keycloak bind account | `svc-keycloak-ldap` (non-admin, no expiry, under `CN=Users`) |
| human-user search root | `OU=AIGWUsers,DC=lab,DC=aigw,DC=internal` |
| seeded users | `lab-admin`, `lab-developer`, `lab-user` |

All of those passwords come from the encrypted lab overlay. Existing Samba users
are never silently reset on container restart; the entrypoint reconciles domain
policy on every start, but changing an Ansible variable alone does not change a
password already stored in the domain.

A generic customer deployment does not start Samba and does not create a
customer LDAP component automatically. `samba-ad` is a lab-only fixture and must
never be treated as a customer directory. Configure the customer's LDAPS
provider through a separately reviewed Keycloak procedure or overlay using the
same principles the lab uses: verified TLS, a least-privilege bind identity,
`READ_ONLY` edit mode, imported users, and no portal access to the bind
credential.

## Authorization model

The `aigw` realm defines exactly three realm roles, and these are the only
capabilities the portals honor:

| Realm role | Capability |
|---|---|
| `aigw-users` | Open WebUI chat |
| `aigw-developers` | dev-portal self-service LiteLLM keys and coding-tool snippets |
| `aigw-admins` | developer functions plus rotation, identity administration, the LiteLLM Admin UI, and Grafana edge access |

Authorization is carried as a realm-role claim, not a group claim: each of the
four first-party OIDC clients (`open-webui`, `dev-portal`, `admin-portal`,
`admin-ui`) maps realm roles into a `roles` claim. Membership in an
`aigw-admins`-capable managed group is how a directory user acquires the
`aigw-admins` role.

The controller creates only direct children of the protected `/aigw-managed`
root group, each mapped to one or more of the three allow-listed realm roles.
Group names must match `[a-z0-9][a-z0-9_.-]{0,63}` — lowercase, at most 64
characters — because the group name is the canonical project ID copied into
LiteLLM key metadata and audit records. Only a user whose `federationLink`
matches the configured LDAP provider can be added to a group. A group must be
empty before deletion, the managed root itself cannot be modified, and the last
managed administrator cannot be removed.

Every managed-group create, delete, member-add, and member-remove runs through
one process-local topology lock, and the last-admin decision and its mutation
run inside the same lock, so concurrent operations cannot briefly manufacture a
recovery administrator that another removal then relies on. This holds only for
the single deployed key-rotator process and worker; it is not a cross-process
lock, which is why the stack must keep one key-rotator worker and replica (see
[litellm-scaling.md](litellm-scaling.md) and
[high-availability.md](high-availability.md) for the scaling posture).

Every admin-portal page read and every mutation asks the controller to
re-evaluate the caller's live Keycloak composite realm roles rather than
trusting only the signed browser-session snapshot. If live `aigw-admins`
authority has been revoked, the portal clears its session and rejects the
request; if the controller cannot verify authority, the request fails closed.
Mutations additionally require a valid CSRF token and a fresh Keycloak step-up
(`prompt=login`, `max_age=0`) within a five-minute window. Removing a member
also logs the affected directory user out of Keycloak and deactivates that
subject's project keys in LiteLLM before and after the membership change, so an
old session cannot immediately mint or keep using a role-bearing token. The
controller bounds pagination and rejects unknown IDs, groups outside its tree,
users from another federation, roles outside the three capabilities, and
redirects returned by Keycloak; administrative errors surfaced to the portal
exclude Keycloak bodies that might contain DNs or credential configuration.

## One-time identity-controller bootstrap

### Prerequisites

The full stack — and the lab overlay, if applicable — must be running, and Vault
must be initialized and unsealed with `vault-bootstrap.sh` having created the
rotator policy and token. That policy grants create/read/update only to the
three identity records the controller uses, whose logical paths are configured
by environment variable (defaults shown):

- `ai-gateway/keycloak/identity-controller-key` (`IDENTITY_CONTROLLER_KEY_VAULT_PATH`)
- `ai-gateway/keycloak/identity-state` (`IDENTITY_STATE_VAULT_PATH`)
- `ai-gateway/anthropic-wif-client-key` (`KC_CLIENT_ASSERTION_KEY_VAULT_PATH`)

These are logical paths under the KV-v2 `kv/` mount; the configured default
strings themselves carry no `kv/` prefix.

Keycloak's temporary master-realm bootstrap service client
(`aigw-bootstrap-controller`, `KC_BOOTSTRAP_ADMIN_CLIENT_ID`) must be available.
Its secret exists only in the encrypted deployment overlay and the Keycloak and
rotator container environments; it never reaches a portal or a browser. Vault
today is a lab/test bootstrap (1-of-1 unseal, local file backend); production
needs the controls in [deploy-guide.md](deploy-guide.md) and
[operations.md](operations.md).

Finally, an existing `aigw` realm user whose token already carries `aigw-admins`
must be able to sign in to `admin-portal.<domain>`. The portal cannot create or
authorize its own first administrator. A generic deployment must establish this
user through a controlled Keycloak or customer-IdP process. Only the Parallels
inventory seeds disposable Keycloak-local users for this first entry — and only
when `aigw_seed_test_users` is explicitly enabled — because lab LDAP is not
configured yet: `testadmin` (all three roles) is the first-entry administrator
and `testuser` (developer and user roles) is a non-admin fixture. Both are
removed after the Samba `lab-admin` handoff.

### Portal procedure

Open `https://admin-portal.<domain>` as the initial administrator and choose
**Reauthenticate with Keycloak**. The portal sends `prompt=login` and
`max_age=0`, requires the same immutable subject and a current admin role, and
grants a five-minute mutation window; ordinary page access is not sufficient for
an identity change. In **Initialize identity control**, type `INITIALIZE`
exactly and submit.

The rotator then performs one ordered transaction, consuming the temporary
bootstrap service client and establishing durable controls:

1. obtain a short-lived token from the temporary master-realm service client;
2. reconcile and verify the four first-party OIDC clients (`open-webui`,
   `dev-portal`, `admin-portal`, `admin-ui`) — their callbacks, web origins, and
   secrets are read back and compared, because Keycloak's `--import-realm`
   deliberately skips an already-existing realm, so a restored database needs
   this repair rather than a fresh import;
3. create or repair the disabled `aigw-identity-controller` client (`client-jwt`,
   RS256), ask Keycloak to generate a 3072-bit PKCS#12 keypair under a one-use
   random archive password, extract it in memory, and verify the unencrypted
   private-key write to Vault;
4. grant the controller service account only `manage-users`, `query-groups`,
   `query-users`, `view-realm`, and `view-users` from `realm-management`
   (`view-realm` is the read-only permission Keycloak needs to resolve the three
   capability roles before mapping them; it cannot create or delete realm roles
   or clients), enable the controller, and prove a 60-second `private_key_jwt`
   client-credentials exchange works;
5. create and mark the protected `/aigw-managed` root group;
6. in the lab, configure the `lab-samba-ad` LDAP provider over LDAPS with
   `READ_ONLY`, user import enabled, registration sync disabled, automatic and
   changed-user sync periods disabled, no LDAP group mapper, and a search filter
   that excludes the `svc-keycloak-ldap` bind account from import, then trigger a
   single full sync (a failed first sync deletes the incomplete component so a
   retry cannot inherit partial configuration);
7. generate, store, enable, and prove the separate `anthropic-token-broker`
   `private_key_jwt` key in the isolated `anthropic-wif` realm, reconciling the
   single hardcoded stable-subject mapper and failing closed unless a real
   issued token carries `sub=service-account-anthropic-token-broker` plus the
   Anthropic audience (see [anthropic-wif-bootstrap.md](anthropic-wif-bootstrap.md));
8. write verified identity state plus controller and broker certificate SHA-256
   fingerprints to Vault; and
9. only after every prior proof succeeds, delete the temporary bootstrap
   principals. The broad temporary service client is always deleted; the
   password-backed temporary admin user is deleted too, unless
   `RETAIN_BOOTSTRAP_ADMIN_USER` is set (Parallels lab only), in which case it is
   converted into a marked ADM-console recovery operator. Customer profiles keep
   that flag false and rely on their own reviewed break-glass process.

The portal receives readiness booleans and the two SHA-256 certificate
fingerprints, never a bootstrap secret, access token, PKCS#12 archive, or
private key. Record the displayed fingerprints in the deployment evidence and
compare them after a restore. If any of the controller or broker key generation,
the Vault write, the `private_key_jwt` proof, or the lab full sync fails, the
whole initialization fails closed and the affected durable client stays
disabled; the operation is idempotent, so reauthenticating and running
**Initialize identity control** again reuses proven state and retries.

## Creating groups and assigning users

Every mutation below requires a still-valid five-minute step-up and a valid CSRF
token, and prefers separate single-purpose groups over one group holding every
role.

Create a group under **Identity and authorization** and select one or more
capabilities. Open **Manage members**, search for an imported directory user,
and assign that user. Because roles are captured at login, have the user perform
a fresh Keycloak login before expecting new capabilities; controller-driven
removal logs the affected user out, and the portal rechecks live authority on
every admin read and mutation. To remove a group, remove every member first,
then delete the empty group. Removing the current portal user clears that
browser session, and the controller refuses any operation that would remove the
final managed administrator — so establish at least two independently controlled
administrator identities before normal operations begin.

Samba's automatic and changed-user synchronization periods are disabled, and the
initial bootstrap performs one full sync because all three lab users already
exist under the dedicated `AIGWUsers` OU. Existing disposable lab domains are
migrated idempotently by moving the seeded human users into that OU; privileged
built-ins and the bind account remain under `CN=Users`, outside Keycloak's
search root. If a lab user is added later, create it under `AIGWUsers` and then
run **User federation → lab-samba-ad → Synchronize all users** in the ADM
Keycloak console before the portal can find the account.

## Lab password and user operations

Use Samba tooling, not the portal, and prompt interactively so a new password
never lands in shell history or process arguments:

```bash
cd /opt/ai-gateway
docker compose -f docker-compose.yml -f docker-compose.lab.yml \
  --profile lab-ad exec samba-ad samba-tool user setpassword lab-user
```

Creating or deleting a lab identity is likewise an explicit Samba operation
followed by a Keycloak sync, and the Keycloak LDAP bind user must never be
granted domain-administrator rights. The Samba domain is provisioned once and
partial state fails closed. A disposable lab reset must stop the merged project
and remove `samba_ad_config`, `samba_ad_state`, and `samba_ad_public` together;
removing only one volume produces an intentionally rejected inconsistent state.
Never run that reset against a customer directory. See
[lab-dr-rehearsal.md](lab-dr-rehearsal.md) for the destructive rebuild register.

## Recovery

### Vault sealed or rotator unavailable

Unseal Vault first and let key-rotator reconnect. Do not create a new Keycloak
controller merely because Vault is sealed. Recheck the identity status once Vault
and Postgres are healthy.

### Temporary bootstrap client was consumed, or the database predates it

If the Vault controller key is missing or mismatched, identity state is
incomplete, and no temporary service client remains, create a new temporary
Keycloak bootstrap service while the normal Keycloak instance is stopped
(Keycloak requires all normal nodes stopped for this command):

```bash
cd /opt/ai-gateway
docker compose stop keycloak
docker compose run --rm --no-deps keycloak \
  bootstrap-admin service \
  --client-id aigw-bootstrap-controller \
  --client-secret:env=KC_BOOTSTRAP_ADMIN_CLIENT_SECRET \
  --no-prompt
scripts/aigw-compose.sh up -d --no-deps --no-build keycloak
```

`--no-deps` prevents the dependency graph from restarting the successful
`volume-init` one-shot; this assumes Keycloak's Postgres dependency is already
healthy. In the Parallels lab, add `-f docker-compose.yml -f
docker-compose.lab.yml --profile lab-ad` to each Compose command. Then
reauthenticate in the admin portal and run **Initialize identity control**
again; the bootstrap reuses and proves valid state, repairs mismatched keys
while clients are disabled, and deletes the temporary client only after verified
completion. If status reports `bootstrap_cleanup_required`, the durable
controller is usable but a marked temporary principal still exists —
reauthenticate and re-run the idempotent initialization to retry the bounded
cleanup. Do not delete an unmarked client because its name looks similar, and
never leave a bootstrap service in place as a permanent administrator or fall
back to a shared secret for the durable controller or WIF broker.

### Administrator lockout

The portal protects the last managed administrator, but an out-of-band Keycloak
change can still cause lockout. Use Keycloak's offline `bootstrap-admin user` or
the temporary-service recovery above while normal Keycloak is stopped, restore a
known administrator role or group, verify login, and remove the temporary
principal. Record the incident and review Keycloak admin events.

### Remove disposable lab-local users

After `lab-admin` has authenticated with its Samba password, can reach the admin
portal, and belongs to a retained managed `aigw-admins` group, remove the two
Keycloak-local seed users. The bounded operator tool authenticates with the
durable Vault-backed controller — it accepts no credential on argv, stdin, or
the environment — preflights both exact usernames and their
`<user>@<domain>` emails, and refuses any federated user:

```bash
cd /opt/ai-gateway
docker compose -f docker-compose.yml -f docker-compose.lab.yml --profile lab-ad \
  run --rm --no-deps \
  -v ./scripts/remove-lab-local-keycloak-users.py:/tmp/remove-local-users.py:ro \
  key-rotator python3 /tmp/remove-local-users.py \
  --confirm REMOVE_LOCAL_TEST_USERS
```

It prints `LOCAL_KEYCLOAK_TEST_USERS_REMOVED_PASS` on success. Then prove both
old passwords are denied through the public OIDC login path. Do not run this
before the retained directory administrator and the last-admin protection have
both been verified.

### Brute-force lockout, in two independent layers

Both imported realms enable Keycloak 26.6.4 brute-force detection with an
identical policy: five failures, `MULTIPLE` backoff in 60-second increments, a
60-second minimum penalty for attempts less than one second apart, a 15-minute
maximum wait, and a 12-hour failure-counter reset, with permanent lockout and
promotion after repeated temporary lockouts both disabled. This bounds
attacker-induced denial of a known account to 15 minutes while materially
slowing password spraying. `scripts/validate-identity-policy.py` statically
asserts these exact values in every realm source and template.

Keycloak's startup realm import does not overwrite an existing realm. On an
upgraded database, apply these values through the ADM console at **Realm
settings → Security defenses → Brute force detection** for both realms, then
re-open the page or export the realm to confirm persistence; fresh databases
receive them from the reviewed realm imports automatically. For a Keycloak-local
lock, wait for the temporary lock to expire or clear the user's brute-force
failures from a separate authorized ADM session; if every administrator is
unavailable, use the stopped-Keycloak bootstrap recovery above rather than
weakening the realm policy or exposing the admin API on the internal edge.

The Parallels Samba domain independently locks an AD account after five failed
passwords for 15 minutes and resets its bad-attempt count after 15 minutes. The
entrypoint reconciles this policy on every restart and the health probe verifies
it. Inspect or recover a lab account locally with no password in the process
arguments:

```bash
docker compose -f docker-compose.yml -f docker-compose.lab.yml \
  --profile lab-ad exec -T samba-ad samba-tool domain passwordsettings show
docker compose -f docker-compose.yml -f docker-compose.lab.yml \
  --profile lab-ad exec -T samba-ad samba-tool user unlock lab-user
```

Keycloak and Samba track failures separately; clearing one layer does not clear
the other, so inspect both before escalating to offline recovery, and unlock
only a validated username.

### LDAP or LDAPS failure

Check state and recent logs, in order:

```bash
docker compose -f docker-compose.yml -f docker-compose.lab.yml \
  --profile lab-ad ps samba-ad keycloak
docker compose -f docker-compose.yml -f docker-compose.lab.yml \
  --profile lab-ad logs --since=15m samba-ad keycloak
```

Confirm `samba_ad_public` holds the current public certificate, Keycloak mounts
it read-only, `KC_TRUSTSTORE_PATHS` points at it, the certificate SAN matches
`samba-ad`, and Samba health is green. A regenerated Samba CA requires a Keycloak
restart because Keycloak trusts that exact certificate. Never bypass hostname or
certificate verification.

### Restore consistency

Keycloak/Postgres, the Vault identity keys and state, and the Samba domain
volumes form one logical identity backup set; restore them to a consistent
point. A restored Keycloak public key paired with a different Vault private key
will correctly fail `private_key_jwt` — use the temporary-service recovery flow
rather than copying keys through a browser. Proactive controller and broker key
rotation and a fully automated identity restore drill remain production blockers
to implement and test.

The 2026-07-13 replacement-VM G6 identity lane passed the retained-realm,
LDAP-provider, managed-group, federated-user, service-account, Samba-object,
immutable GUID/SID, hostname-verified-LDAPS, live directory-login, portal-role,
and corrected logout-redirect checks; its protected evidence is indexed in
[the destructive rehearsal](lab-dr-rehearsal.md#g6-evidence-and-disposition).
Not every persistent-session count change is identity loss: in that rehearsal
the backup held 9 rows in each of `offline_client_session` and
`offline_user_session`, but authenticated inspection proved all 18 had
`offline_flag=0` — persistent online sessions whose timestamps exceeded the
realm's 1,800-second SSO idle timeout before restored Keycloak started, so their
deterministic expiry was the secure expected result. Evidence quality stays
separate from live consistency: the pre-destroy marker did not retain
controller/broker fingerprints as independent fields, so although the current
Vault-backed fingerprints match the live Keycloak client certificates and
controller authentication works, no exact historical fingerprint comparison can
be claimed. Use authenticated dump hashes with a documented canonicalizer rather
than guessing at opaque historical values.

### Lab LDAP bind-password rotation

Changing only the Ansible secret source does not update the password already
stored in Samba, and changing only Samba breaks Keycloak federation. Treat the
bind password as one coordinated maintenance transaction: set the new
`svc-keycloak-ldap` password in Samba with an interactive prompt, update the
encrypted Ansible value, reconverge so the Docker secret changes, update the
Keycloak LDAP credential through the ADM console, restart or reload the affected
services, and prove an LDAP sync and a fresh user login. Keep a rollback value
under the customer's secret-handling policy until the proof succeeds.
Portal-driven atomic bind-password rotation is not implemented.

## Bootstrap completion sequence

After the first successful initialization in the Parallels lab, create an
administrator-capability group below `/aigw-managed`, assign the imported
`lab-admin` user to it, sign out, and prove `lab-admin` can authenticate with the
Samba-owned password and reach the expected admin functions. Only then remove
the disposable Keycloak-local users' managed access and finally the users
themselves, and only once at least two durable administrator identities exist.
Do not remove the disposable users before the Samba login and role claim have
both been proved.

The verified retained lab topology is three managed groups, each with exactly
one federated member: `lab-admins` (capability `aigw-admins`, member `lab-admin`),
`lab-developers` (`aigw-developers`, `lab-developer`), and `lab-users`
(`aigw-users`, `lab-user`). `scripts/verify-live-lab-identity.py` asserts that
exact state — three federated users, three groups, `configured=true`,
`controller_usable=true`, `bootstrap_available=false`, and
`bootstrap_cleanup_required=false`.

## Auditing and acceptance

Identity bootstrap, group create/delete, and membership changes write bounded
metadata to rotator history, portal actions emit structured subject-based audit
logs, and Vault audit records cover key and state writes. None of these replaces
Keycloak administrative event logging, which should be enabled and retained under
the customer's identity policy. The controller's `manage-users` service-account
role is broader than the portal's group-only workflow: the implementation
constrains paths, roles, federation links, and response bodies, but compromise
of the durable controller still carries high Keycloak impact, so treat the single
key-rotator worker and the process-local topology lock as an accepted limitation
until a database-backed or distributed fenced lock replaces it.

The acceptance runbook in [test-runbook.md](test-runbook.md) drives the portal
tests — `test-portal-login.py` (a real directory password through the OIDC
callback), `test-portal-identity-flow.py` (OIDC step-up and the INITIALIZE
form), `test-portal-group-flow.py` (create/assign/remove/delete under real
step-up), and `test-portal-key-lifecycle.py` (the one-time-key lifecycle) — and
must prove that LDAP password validation works over hostname-verified LDAPS; the
bind account is neither imported nor able to administer the domain; portal search
returns only federated users; an unprivileged user cannot view the admin page; an
admin without fresh step-up cannot mutate identity; arbitrary roles, groups, and
out-of-tree or foreign-federation users are rejected; the last-admin and
non-empty-group guards hold; concurrent group delete, member add, and last-admin
removal cannot interleave into a zero-administrator state; a role change takes
effect only after the expected token or session refresh; revoking the acting
administrator makes the next admin read or mutation fail its live composite-role
check and clears the portal session; and the controller and broker fingerprints
match the recorded deployment evidence.

Keycloak logout does not erase an already-issued oauth2-proxy cookie
immediately. Both ADM proxies refresh and revalidate cookies every five minutes
and cap them at eight hours; the portal's live composite-role check closes the
stale-cookie path immediately for admin reads and mutations, while the LiteLLM
Admin UI and Grafana can retain their edge session until the next proxy refresh.
Acceptance must prove revocation is enforced within that five-minute bound after
Keycloak logout and that no cookie survives the eight-hour maximum. See
[project-status.md](project-status.md) for the overall prototype posture: this is
a customer prototype, not a turnkey, highly available appliance, and recovery
acceptance does not confer HA.
