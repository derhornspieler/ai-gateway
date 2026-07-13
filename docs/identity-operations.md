# Identity, Directory Federation, and Group Operations

This guide separates three different ownership domains that must not be
blurred:

- **AD/LDAP** owns usernames, passwords, account enablement, and password
  policy. The Parallels lab uses disposable Samba AD; a customer deployment
  uses the customer's directory.
- **Keycloak** imports/federates directory users, authenticates them, emits
  realm-role claims, and stores AI Gateway authorization groups.
- **The AI Gateway admin portal** creates/deletes only managed Keycloak groups
  and assigns imported directory users to them. It never creates an AD user,
  changes a password, or writes an AD group.

## Current deployment contract

The base stack includes the portal and rotator identity-controller APIs. The
Parallels profile additionally merges `compose/docker-compose.lab.yml`, which:

- starts `samba-ad` only under Compose profile `lab-ad`;
- attaches Samba and Keycloak to isolated, internal `net-identity`;
- publishes no Samba host ports;
- mounts the domain-admin, read-only bind, and three user passwords as Docker
  secret files rather than environment variables;
- persists `/etc/samba`, `/var/lib/samba`, and the public LDAPS certificate in
  three named volumes;
- mounts only the public certificate into Keycloak and enables the lab LDAP
  setup path in key-rotator.

Samba runs unprivileged in the Docker sense (`privileged: false`) with
`no-new-privileges`, a read-only root filesystem, all capabilities dropped,
and only the capabilities required by Samba AD added. Its healthcheck validates
the domain database, Samba control plane, domain metadata, and
hostname-verified LDAPS on port 636.

Provisioning/seed password handling stays inside the container process: a
small Samba helper reads bounded Docker-secret files with `O_NOFOLLOW` and uses
the Samba Python API directly. Passwords are not forwarded to a child-process
argument, environment variable, or generated shell command.

The lab directory is:

| Item | Value |
|---|---|
| realm/forest | `LAB.AIGW.INTERNAL` |
| NetBIOS domain | `AIGWLAB` |
| DC hostname | `samba-ad` |
| Keycloak bind account | `svc-keycloak-ldap` (non-admin, no expiry) |
| human-user search root | `OU=AIGWUsers,DC=lab,DC=aigw,DC=internal` |
| seeded users | `lab-admin`, `lab-developer`, `lab-user` |

All corresponding passwords come from the encrypted lab overlay. Existing
Samba users are never silently reset on container restart; changing an Ansible
variable alone does not change a password already stored in the domain.

Generic customer deployment does not start Samba and does not currently create
a customer LDAP component automatically. Configure the customer's LDAPS
provider through a separately reviewed Keycloak procedure/overlay using the
same principles: verified TLS, least-privilege bind identity, read-only edit
mode, imported users, and no portal access to the bind credential.

## Authorization model

The `aigw` realm defines three capabilities:

| Realm role | Capability |
|---|---|
| `aigw-users` | Open WebUI chat |
| `aigw-developers` | self-service LiteLLM keys and coding-tool snippets |
| `aigw-admins` | developer functions plus rotation, identity administration, LiteLLM Admin UI, and Grafana edge access |

The portal creates direct children of the protected `/aigw-managed` root. Each
child group is mapped to one or more of the three allow-listed realm roles.
Only users whose `federationLink` matches the configured LDAP provider can be
added. A group must be empty before deletion; the root cannot be modified; and
the last managed administrator cannot be removed.

The controller serializes every managed-group create, delete, member-add, and
member-remove operation through one process-local topology lock. The
last-admin decision and its mutation run inside the same lock, so a concurrent
group deletion/addition cannot briefly manufacture a recovery administrator
that another removal relies on. This contract is valid only for the deployed
single key-rotator process and worker; it is not a cross-process lock.

Every portal administrative page read and mutation asks the controller to
re-evaluate the caller's live Keycloak composite roles rather than trusting
only the signed browser-session snapshot. If live admin authority has been
revoked, the portal clears its session and rejects the request. Mutations also
require CSRF and a fresh Keycloak step-up. Member removal triggers Keycloak
logout for the affected user so an old Keycloak session cannot immediately
mint a new role-bearing token.

Group names are limited to 64 characters and a conservative character set.
The controller bounds pagination and rejects unknown IDs, groups outside its
tree, users from another federation, arbitrary roles, and redirects from
Keycloak. Administrative errors returned to the portal exclude Keycloak
bodies that might contain DNs or credential configuration.

## One-time identity-controller bootstrap

### Prerequisites

1. The full stack and lab overlay, if applicable, are running.
2. Vault has been initialized/unsealed and `vault-bootstrap.sh` has created the
   rotator policy/token. That policy grants create/read/update only to these
   three identity records:

   - `kv/ai-gateway/keycloak/identity-controller-key`
   - `kv/ai-gateway/keycloak/identity-state`
   - `kv/ai-gateway/anthropic-wif-client-key`

3. Keycloak's temporary master-realm bootstrap service client is available.
   Its secret exists only in the encrypted deployment overlay and the Keycloak
   and rotator container environments; it never reaches the portal/browser.
4. An existing `aigw` realm user whose token already carries `aigw-admins` can
   log in to `portal.<domain>/admin`. The portal cannot create or authorize its
   own first administrator. A generic deployment must establish this user via
   a controlled Keycloak/customer-IdP process. Only the Parallels inventory
   seeds disposable Keycloak-local `testadmin` for this first entry because
   lab LDAP is not configured yet.

### Portal procedure

1. Open `https://portal.<domain>/admin` as the initial administrator.
2. Select **Reauthenticate with Keycloak**. The portal sends `prompt=login` and
   `max_age=0`, requires the same immutable subject and a current admin role,
   and grants a five-minute mutation window. Ordinary page access is not
   sufficient for an identity change.
3. In **Initialize identity control**, type `INITIALIZE` exactly and submit.

The rotator then performs this ordered transaction:

1. obtains a short-lived token from the temporary master service client;
2. creates or repairs disabled `aigw-identity-controller` in the `aigw` realm;
3. asks Keycloak to generate a 3072-bit PKCS#12 keypair with a one-use random
   archive password, extracts it in memory, and verifies the unencrypted
   private-key write to Vault;
4. grants only `manage-users`, `query-groups`, `query-users`, `view-realm`, and
   `view-users`; `view-realm` is the read-only permission Keycloak requires to
   resolve the three allow-listed capability roles before group mapping,
   enables the controller, and proves 60-second `private_key_jwt` client
   credentials work;
5. creates and marks the protected `/aigw-managed` root;
6. in the lab, configures `lab-samba-ad` over LDAPS with `READ_ONLY`, user
   import enabled, registration sync disabled, no LDAP group mapper, and a
   full user sync. The service bind account is excluded from import;
7. generates, stores, enables, and proves the separate
   `anthropic-token-broker` `private_key_jwt` key in the isolated
   `anthropic-wif` realm; it reconciles a single hardcoded stable
   `sub=service-account-anthropic-token-broker` mapper and fails closed unless
   a real issued token contains that exact subject plus the exact Anthropic
   audience;
8. writes verified identity state/fingerprints to Vault; and
9. only after every prior proof succeeds, deletes Keycloak-marked temporary
   bootstrap principals.

The portal receives readiness booleans and SHA-256 certificate fingerprints,
never a bootstrap secret, access token, PKCS#12 archive, or private key. Record
the displayed fingerprints in the deployment evidence and compare them after
a restore.

## Creating groups and assigning users

Every mutation requires a still-valid five-minute step-up and a valid CSRF
token.

1. Create a group under **Identity and authorization**.
2. Select one or more capabilities. Prefer separate groups such as chat users,
   developers, and administrators rather than giving every group all roles.
3. Open **Manage members**, search for an imported directory user, and assign
   the user.
4. Have that user perform a new Keycloak login. Existing OIDC/session cookies
   can otherwise carry old role claims; controller-driven removal logs the
   affected user out, and the portal rechecks live authority on every admin
   page read and mutation.
5. To remove a group, remove every member first, then delete the empty group.

Removing the current portal user clears that browser session. The controller
also refuses an operation that would remove the final managed administrator.
Keep at least two independently controlled administrator identities before
normal operations begin.

Samba's automatic and changed-user synchronization periods are disabled. The
initial bootstrap performs one full sync because all three lab users already
exist under the dedicated `AIGWUsers` OU. Existing disposable lab domains are
migrated idempotently by moving the seeded human users into that OU; privileged
built-ins and the bind account remain under `CN=Users` and outside Keycloak's
search root. If a lab user is added later, create it under `AIGWUsers`, then
use the Keycloak ADM console at **User federation → lab-samba-ad → Synchronize
all users** before the portal can find the account.

## Lab password and user operations

Use Samba tooling, not the AI Gateway portal. For example, prompt
interactively so a new password is not placed in shell history or process
arguments:

```bash
cd /opt/ai-gateway
docker compose -f docker-compose.yml -f docker-compose.lab.yml \
  --profile lab-ad exec samba-ad samba-tool user setpassword lab-user
```

Creating/deleting lab identities is likewise an explicit Samba operation and
requires a subsequent Keycloak sync. Do not grant the Keycloak LDAP bind user
domain-administrator privileges.

The Samba domain is provisioned once. Partial state fails closed. A disposable
lab reset must stop the merged project and remove `samba_ad_config`,
`samba_ad_state`, and `samba_ad_public` together; deleting only one produces an
intentionally rejected inconsistent state. Never use that reset against a
customer directory.

## Recovery

### Vault sealed or rotator unavailable

Unseal Vault first and let key-rotator restart/reconnect. Do not create a new
Keycloak controller merely because Vault is sealed. Check the identity status
again after Vault and Postgres are healthy.

### Temporary bootstrap client was consumed or an old Keycloak DB predates it

If the Vault controller key is missing/mismatched, the identity state is
incomplete, and no temporary service client remains, create a new **temporary**
Keycloak bootstrap service while the normal Keycloak instance is stopped.
Keycloak requires all normal nodes stopped for this command.

Base stack:

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

This recovery assumes Keycloak's Postgres dependency is already healthy. The
explicit `--no-deps` prevents recovery from restarting the successful
`volume-init` one-shot through the dependency graph.

Parallels lab: add `-f docker-compose.yml -f docker-compose.lab.yml --profile
lab-ad` to each Compose command. Then reauthenticate in the portal and run
**Initialize identity control** again. The bootstrap is designed to reuse and
prove valid state, repair mismatched keys while clients are disabled, and
delete the temporary client only after verified completion.

If status reports `bootstrap_cleanup_required`, the durable controller is
usable but a Keycloak-marked temporary bootstrap principal still exists.
Reauthenticate and run **Initialize identity control** again; the operation is
idempotent and retries the bounded cleanup. Do not delete an unmarked client
merely because its name looks similar.

Never expose the bootstrap service on a browser route, leave it in place as a
permanent administrator, or fall back to a shared secret for the durable
controller/WIF broker.

### Administrator lockout

The portal protects the last managed administrator, but an out-of-band
Keycloak change can still cause lockout. Use Keycloak's offline
`bootstrap-admin user` or temporary service recovery while normal Keycloak is
stopped, restore a known administrator role/group, verify login, and remove the
temporary principal. Record the incident and review Keycloak admin events.

### Remove disposable lab-local users

After `lab-admin` has authenticated with its Samba password, can reach
`/admin`, and belongs to a retained managed `aigw-admins` group, remove the
two Keycloak-local seed users. The bounded operator tool authenticates with
the durable Vault-backed controller, preflights both exact usernames and
emails, and refuses federated users:

```bash
cd /opt/ai-gateway
docker compose -f docker-compose.yml -f docker-compose.lab.yml --profile lab-ad \
  run --rm --no-deps \
  -v ./scripts/remove-lab-local-keycloak-users.py:/tmp/remove-local-users.py:ro \
  key-rotator python3 /tmp/remove-local-users.py \
  --confirm REMOVE_LOCAL_TEST_USERS
```

Then prove both old passwords are denied through the public OIDC login path.
Do not run this tool before the retained directory administrator and
last-admin protection have both been verified.

Both imported realms enable Keycloak 26.6.4 brute-force detection. The policy is
five failures, `MULTIPLE` backoff in 60-second increments, a 60-second minimum
penalty for attempts less than one second apart, a 15-minute maximum wait, and
a 12-hour failure-counter reset. Permanent lockout and promotion after repeated
temporary lockouts are disabled. This bounds attacker-induced denial of a
known account to 15 minutes while materially slowing password spraying.

Keycloak's startup realm import does not overwrite an already-existing realm.
For an upgraded database, use the ADM-only console's **Realm settings →
Security defenses → Brute force detection** page to apply these exact values
to both realms during the upgrade, then export/inspect the realm or re-open the
page to verify persistence. Fresh databases receive them from the reviewed
realm imports automatically.

For a Keycloak-local lock, wait for the temporary lock to expire or use a
separate authorized administrator session on the ADM-only Keycloak console to
clear the user's brute-force failures. If all administrators are unavailable,
use the stopped-Keycloak bootstrap recovery above; do not weaken the realm
policy or expose the admin API on the internal edge.

The Parallels Samba domain independently locks an AD account after five failed
passwords for 15 minutes and resets its bad-attempt count after 15 minutes.
The entrypoint reconciles this policy on every restart and the container health
probe verifies it. Inspect or recover a lab user locally with no password in
the process arguments:

```bash
docker compose -f docker-compose.yml -f docker-compose.lab.yml \
  --profile lab-ad exec -T samba-ad samba-tool domain passwordsettings show
docker compose -f docker-compose.yml -f docker-compose.lab.yml \
  --profile lab-ad exec -T samba-ad samba-tool user unlock lab-user
```

Keycloak and Samba track failures separately. Clearing one layer does not
clear the other, so inspect both before escalating to offline recovery. Unlock
only a validated username and retain the administrative event/incident record.

### LDAP or LDAPS failure

Check, in order:

```bash
docker compose -f docker-compose.yml -f docker-compose.lab.yml \
  --profile lab-ad ps samba-ad keycloak
docker compose -f docker-compose.yml -f docker-compose.lab.yml \
  --profile lab-ad logs --since=15m samba-ad keycloak
```

Confirm `samba_ad_public` contains the current public certificate, Keycloak
mounts it read-only, `KC_TRUSTSTORE_PATHS` points at it, the certificate SAN
matches `samba-ad`, and Samba health is green. A regenerated Samba CA requires
a Keycloak restart. Do not bypass hostname or certificate verification.

### Restore consistency

Keycloak/Postgres, Vault identity keys/state, and Samba domain volumes form one
logical identity backup set. Restore them to a consistent point. A restored
Keycloak public key with a different Vault private key will correctly fail
`private_key_jwt`; use the temporary-service recovery flow rather than copying
keys through the browser. Proactive controller/broker key rotation and a fully
automated identity restore drill remain production blockers to implement and
test.

The 2026-07-13 replacement-VM G6 identity lane passed the retained realm,
LDAP-provider, managed-group, federated-user, service-account, Samba object,
immutable GUID/SID, hostname-verified LDAPS, live directory-login, portal-role,
and corrected logout-redirect checks. Its protected evidence is indexed in
[the destructive rehearsal](lab-dr-rehearsal.md#g6-evidence-and-disposition).

Do not treat every persistent-session count change as identity loss. In that
rehearsal the backup contained 9 rows in each table named
`offline_client_session` and `offline_user_session`, but authenticated row
inspection proved all 18 had `offline_flag=0`. They were persistent online
sessions whose timestamps exceeded the realm's exact 1,800-second SSO idle
timeout before restored Keycloak started. Their deterministic expiry is the
secure expected result; offline sessions and durable identity objects were not
lost.

Evidence quality remains separate from live consistency. The pre-destroy
marker did not retain controller/broker certificate fingerprints as independent
fields. The current Vault-backed fingerprints exactly match the public
certificates on the corresponding Keycloak clients and controller
authentication works, but no exact historical fingerprint comparison can be
claimed. Likewise, opaque historical row-count hashes without their retained
canonicalizer/provenance are an evidence gap; use authenticated dump hashes and
an explicitly documented supplemental canonicalizer rather than guessing or
redefining the old value.

### Lab LDAP bind-password rotation

Changing only the Ansible secret source does not update the password already
stored in Samba, and changing only Samba breaks Keycloak federation. Treat the
bind password as one coordinated maintenance transaction: set the new
`svc-keycloak-ldap` password in Samba using an interactive prompt, update the
encrypted Ansible value, reconverge so the Docker secret changes, update the
Keycloak LDAP credential through the ADM console, restart or reload the
affected services, and prove an LDAP sync and a fresh user login. Keep a
rollback value under the customer's secret-handling policy until the proof
succeeds. Portal-driven atomic bind-password rotation is not implemented.

## Bootstrap completion sequence

After the first successful initialization in the Parallels lab:

1. create an administrator-capability group below `/aigw-managed`;
2. assign imported user `lab-admin` to it;
3. sign out and prove `lab-admin` can authenticate with the Samba-owned
   password and reach the expected admin functions; and
4. remove the disposable Keycloak-local bootstrap user's managed access, then
   remove that user once at least two durable administrator identities exist.

Do not remove the disposable user before the Samba login and role claim have
been proved. If controller or broker key generation, the Vault write, the
`private_key_jwt` proof, or the lab full sync fails, initialization fails
closed: the affected durable client remains disabled. A failed initial LDAP
full sync removes the incomplete LDAP component so a retry cannot silently
inherit partial configuration.

## Auditing and acceptance

Identity bootstrap, group creation/deletion, and membership changes write
bounded metadata to rotator history; portal actions also emit structured
subject-based audit logs. Vault audit records cover key/state writes. These do
not replace Keycloak administrative event logging, which should be enabled and
retained under the customer's identity policy.

Acceptance must prove:

- LDAP password validation works over hostname-verified LDAPS;
- the service bind account is not imported and cannot administer the domain;
- portal search returns only users from the configured federation;
- an unprivileged user cannot view the admin page;
- an admin without fresh step-up cannot mutate identity;
- arbitrary roles/groups/out-of-tree users are rejected;
- the last-admin and non-empty-group guards work;
- concurrent group delete, member add, and last-admin removal cannot interleave
  into a zero-administrator state;
- a role change takes effect only after expected token/session refresh;
- revoking the acting administrator causes the next admin page read or
  mutation to fail its live composite-role check and clears the portal
  session;
- controller and broker fingerprints match the recorded deployment evidence.

The controller's `manage-users` service-account role is broader than the
portal's intended group-only workflow. The implementation constrains paths,
roles, federation links, and response bodies, but compromise of the durable
controller still has high Keycloak impact. In addition, the shared topology
lock for managed groups is safe only within one key-rotator Uvicorn process.
Keep one key-rotator worker and replica until the check-and-mutate transaction
is serialized with a database-backed or distributed fenced lock, then retest
all four group mutations adversarially across writers.

Keycloak logout does not erase an already-issued oauth2-proxy cookie
immediately. Both ADM proxies explicitly refresh/revalidate cookies every five
minutes and cap them at eight hours. The portal's live composite-role check
closes the stale-cookie path immediately for admin reads and mutations;
LiteLLM Admin and Grafana can retain their edge session until the next proxy
refresh. Acceptance
must prove revocation is enforced within that five-minute bound after Keycloak
logout and that no cookie survives the eight-hour maximum.
