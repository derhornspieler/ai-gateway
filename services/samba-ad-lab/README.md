# Samba AD lab image

This image exists only to exercise Keycloak's Microsoft Active Directory LDAP
provider in the `parallels-rocky9-lab` deployment profile. It is not a customer
directory and must never be enabled by the default/production Compose profile.

It is built from the official multi-architecture Debian 13 base and Debian's
security-maintained Samba 4.22 packages. It supports both `linux/amd64` and
`linux/arm64`; no emulation is required.

Runtime contract:

- run as root, `privileged: false`, with every capability dropped and only
  `CHOWN`, `DAC_OVERRIDE`, `NET_BIND_SERVICE`, `SETGID`, `SETUID`, and
  `SYS_ADMIN` added;
- set `security_opt: [no-new-privileges:true]`;
- use named volumes for `/etc/samba` and `/var/lib/samba` (the latter must
  support `security.NTACL` extended attributes), plus a public-only volume at
  `/var/lib/samba-public` that Keycloak mounts read-only as a trust anchor;
- use tmpfs mounts for `/run`, `/tmp`, `/var/cache/samba`, and
  `/var/log/samba`;
- attach only to a dedicated internal identity network; publish no ports;
- provide the domain administrator and Keycloak LDAP bind passwords as Docker
  secret files, never environment variables;
- optionally set comma-separated `SAMBA_SEED_USERS`; each named lab identity
  requires `/run/secrets/samba_user_<username>_password` and is created only
  when absent;
- set a stable container hostname matching `SAMBA_HOSTNAME`.

The entrypoint provisions exactly once and fails closed on partial state. It
creates a non-admin `svc-keycloak-ldap` account for Keycloak. Keycloak must use
`Import Users=ON`, `Edit Mode=READ_ONLY`, and `Sync Registrations=OFF`; lab
authorization groups remain Keycloak-local. The healthcheck verifies the DC,
its control plane, hostname-validated LDAPS on port 636, and the fixed domain
lockout policy. Five failed passwords lock an account for 15 minutes; the bad
attempt count resets after 15 minutes. The entrypoint reconciles those values
on every restart, so persisted domain-policy drift fails closed or is repaired.

This temporary policy trades a bounded per-user denial-of-service risk for
password-spray resistance. It never permanently locks an account. An operator
can wait 15 minutes or unlock a lab identity locally without passing a secret:

```bash
docker compose -f docker-compose.yml -f docker-compose.lab.yml \
  --profile lab-ad exec -T samba-ad samba-tool user unlock lab-user
```

Always validate the username and record an emergency unlock. Do not treat this
disposable policy as a substitute for the customer's AD lockout standard.
