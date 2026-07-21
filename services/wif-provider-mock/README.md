# Preprod WIF provider mock

This service replaces Anthropic only in local preprod. It serves HTTPS on
port 8443 and has two useful routes:

- `POST /v1/oauth/token` verifies the real Keycloak RS256 signature and the
  exact issuer, subject, audience, expiry, and preprod enrollment IDs. It then
  returns a short-lived test token.
- `POST /v1/messages` accepts only that test token and returns `pong` in an
  Anthropic-shaped response.

The service reads Keycloak's public JWKS and its test TLS certificate from
read-only mounts. It has no vendor credentials and makes no outbound request.
Its scratch image has no shell or package manager.
