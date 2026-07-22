# Preprod WIF provider mock

This service replaces Anthropic only in local preprod. It serves HTTPS on
port 8443 and has two useful routes:

- `POST /v1/oauth/token` verifies the real Keycloak RS256 signature and the
  exact issuer, subject, audience, expiry, and preprod enrollment IDs. It then
  creates a random test token that expires after ten minutes. A new exchange
  invalidates the previous token.
- `POST /v1/messages` accepts only the current, unexpired test token and
  returns `pong` in an Anthropic-shaped response.

Tokens exist only in this process memory. No token is built into the image or
written to disk. The service reads Keycloak's public JWKS and its test TLS
certificate from read-only mounts. It has no vendor credentials and makes no
outbound request. Its scratch image has no shell or package manager.
