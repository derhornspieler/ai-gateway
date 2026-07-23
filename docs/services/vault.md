# vault

## What it does

Vault is the gateway's dedicated secrets store. It holds provider
credentials, the Keycloak identity-controller key, the break-glass admin
password, PKI-related material, and its own audit log. No other service
keeps long-lived secrets itself — they read them from Vault, and only
`key-rotator` does that read/write.

## Who talks to it

- `key-rotator` is Vault's only real API client
  (`VAULT_ADDR: http://vault:8200` in `compose/docker-compose.yml`, over the
  private `net-vault` network) — it is the sole writer and reader of every
  Vault path the stack uses.
- `vault-ui-proxy` (only when the optional `vault-ui` profile is enabled)
  forwards `/v1` API requests to `http://vault:8200` — a compile-time Go
  constant, not a request field or environment variable
  (`services/vault-ui-proxy/main.go`).
- `oauth2-proxy-vault` sits in front of `vault-ui-proxy`, not Vault directly,
  gating that optional browser UI to the `aigw-admins` group.
- `volume-init` must finish first (`service_completed_successfully`); it owns
  the `vault_data` and `vault_audit` volumes Vault mounts.

## The load-bearing config

From `compose/vault/config.hcl`:

```hcl
storage "file" {
  path = "/vault/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}
```

Vault uses local file storage, so the `vault_data` volume is the only copy of
the secrets store. The listener is deliberately plaintext HTTP; that is only
safe because `net-vault` is a private bridge reaching just Vault,
`key-rotator`, and `vault-ui-proxy`, and it is never published. TLS is still
required before a production rollout.

## How you know it is healthy

The compose healthcheck GETs `/v1/sys/health?standbyok=true`. That endpoint
returns HTTP 503 while Vault is sealed, and Vault seals itself on every
restart — `docs/test-runbook.md` confirms this directly: "The health probe
must fail with HTTP 503" after a Vault restart, before Ansible unseals it
again. A sealed Vault after a reboot is expected, not an outage; follow
[Unseal Vault after a production VM reboot](../sop/vault-unseal-after-reboot.md)
rather than re-initializing it.

## Learn more

See [Acceptance test runbook — Prove Vault restart recovery](../test-runbook.md#3-prove-vault-restart-recovery).
