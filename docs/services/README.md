# Service reference

One page per service in the stack. Every page follows the same pattern:
what the service does in plain words, who talks to it, the exact config
that does the enforcing, and how an operator knows it is healthy. The
pattern comes from the
[egress CA-pin section](../security-model.md#how-the-ca-pin-is-enforced-checked-and-watched)
of the security model.

## Edge and access

- [traefik-int](traefik-int.md) — internal-plane HTTPS edge
- [traefik-adm](traefik-adm.md) — admin-plane HTTPS edge
- [oauth2-proxy](oauth2-proxy.md) — login gate for the LiteLLM admin UI
- [oauth2-proxy-grafana](oauth2-proxy-grafana.md) — login gate for Grafana
- [oauth2-proxy-prometheus](oauth2-proxy-prometheus.md) — login gate for Prometheus
- [oauth2-proxy-vault](oauth2-proxy-vault.md) — login gate for the optional Vault UI

## AI request path

- [open-webui](open-webui.md) — the chat application
- [dev-portal](dev-portal.md) — developer self-service portal and API front door
- [admin-portal](admin-portal.md) — operator console
- [litellm](litellm.md) — the model gateway and virtual-key enforcement point
- [envoy-egress](envoy-egress.md) — the only path to the provider, with the pinned CA

## Identity and secrets

- [keycloak](keycloak.md) — login and roles
- [key-rotator](key-rotator.md) — key lifecycle and identity control
- [vault](vault.md) — secret storage; sealed after every restart by design
- [vault-ui-proxy](vault-ui-proxy.md) — optional read-path proxy for the Vault UI

## Data and support

- [postgres](postgres.md) — the database
- [redis](redis.md) — atomic counters for per-minute model limits
- [volume-init](volume-init.md) — one-shot volume ownership setup
- [cribl-mock](cribl-mock.md) — receipt test endpoint for the SOC feed

## Observability

- [alloy](alloy.md) — the one outbound telemetry choke point
- [prometheus](prometheus.md) — metric store and the only alert evaluator
- [alertmanager](alertmanager.md) — alert grouping and lifecycle
- [grafana](grafana.md) — the operator UI for dashboards and alerts
- [loki](loki.md) — log store
- [node-exporter](node-exporter.md) — host metrics
