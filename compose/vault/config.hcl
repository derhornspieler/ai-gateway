# Static, reviewed Vault server configuration. Runtime generation through
# VAULT_LOCAL_CONFIG is intentionally avoided: the hardened container drops
# DAC_OVERRIDE and must never need to mutate its image-owned config directory.
storage "file" {
  path = "/vault/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

telemetry {
  prometheus_retention_time = "5m"
  disable_hostname          = true
}

api_addr = "http://vault:8200"
ui       = true
