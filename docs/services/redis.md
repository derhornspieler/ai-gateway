# redis

## What it does

redis is the gateway's private, non-persistent cache. Snapshotting is
disabled (`--save ""`) and its `/data` directory sits on tmpfs, so nothing
survives a container recreation — that is deliberate, not an oversight.
LiteLLM is its only user, for ordinary response caching and for the atomic
per-project, per-minute output-token reservation that the pre-call rate
limiter checks before every provider dispatch.

## Who talks to it

- `litellm` is the only service on the private `net-cache` network
  (`REDIS_HOST: redis`), and the only client with the password.
- `litellm`'s `depends_on` requires `redis: { condition: service_healthy }`
  before it starts — a strict health gate, not just "started."
- `volume-init` has no role here: redis keeps no named volume, so it starts
  independently of the one-shot initializer.

## The load-bearing config

The ACL Ansible renders for redis to load, from
`ansible/roles/docker_stack/tasks/main.yml`:

```yaml
- filename: redis_users.acl
  content: "user default reset on #{{ redis_password | hash('sha256') }} ~* &* +@all"
```

This resets the built-in `default` user off, then re-enables it with a SHA-256
verifier of the one generated `redis_password` — never the plaintext — and
grants it every key and command (`~* &* +@all`). redis loads that file with
`--aclfile /run/secrets/redis_users.acl`; the plaintext password only ever
reaches the separate `redis_password` file, read by clients and the health
probe.

## How you know it is healthy

The compose healthcheck runs `aigw-health-probe redis --password-file
/run/secrets/redis_password` every 5s (12 retries, 5s start period). The probe
does a real `AUTH` with that password and then `PING`, requiring `+PONG` —
proving authentication actually works, not just that the TCP port answers.
There is no Prometheus target for redis either; the best other signal is
LiteLLM's own structured log line: when Redis can't satisfy a reservation,
`compose/litellm/aigw_model_limits.py` logs `security_event="aigw.model.limit"`
with `security_action="fail_closed"` and `security_reason="redis_unavailable"`
— a combination Alloy's schema allow-list keeps intact — visible in Loki and
Cribl.

## Learn more

See [Security model — Model and price policy is append-only](../security-model.md#model-and-price-policy-is-append-only).
