# TokenDock — Fake OAuth 2.0 Authorization Server for CI

## Context

Teams testing applications in CI often can't reach their real authorization server, so JWT-protected flows go untested or get stubbed out. TokenDock is a purpose-built fake OAuth 2.0 Authorization Server: it issues signed JWTs from configurable credentials and exposes JWKS + OIDC discovery, so the app under test validates tokens with its normal JWT middleware — no test-specific code changes. Prior art (navikt/mock-oauth2-server ~200MB JVM image, oauth2-mock-server npm lib) exists; TokenDock differentiates on a ~10MB instantly-starting image, dead-simple declarative config, and a first-class GitHub Action wrapper.

**Decisions made with the user (ideation phase):**
- Client credentials flow only (no auth code, ROPC, or token exchange)
- Layered config: zero-config defaults → YAML file → env vars
- Endpoints: token, OIDC discovery, JWKS, health (no introspection/userinfo)
- Per-client custom claims in config (audience, subject, lifetime, arbitrary claims)
- Stack: Go, stdlib `net/http` + `golang-jwt`, static binary on scratch/distroless
- Distribution: Docker image (GHCR, multi-arch) first; thin composite GitHub Action wrapper second

## Design

### Configuration (defaults → file → env, later layers override)

Zero-config startup ships a demo client (`tokendock` / `tokendock-secret`), logged loudly at startup. YAML config file at `/etc/tokendock/config.yaml` (path overridable via flag/env):

```yaml
issuer: http://tokendock:8080   # must match how the app under test reaches the server
port: 8080
signing_key: /keys/private.pem  # optional; ephemeral RSA-2048 generated at startup if absent
clients:
  - client_id: my-service
    client_secret: ci-secret
    scopes: [read, write]
    audience: my-api
    subject: my-service          # defaults to client_id
    token_lifetime: 3600
    claims:
      roles: [admin]
```

Env vars for the single-client no-file case: `TOKENDOCK_ISSUER`, `TOKENDOCK_CLIENT_ID`, `TOKENDOCK_CLIENT_SECRET`, `TOKENDOCK_SCOPES`, `TOKENDOCK_AUDIENCE`, `TOKENDOCK_PORT`.

Docs must call out the issuer-URL subtlety: `iss` is compared strictly by validators, so it must match the hostname the app under test uses (`http://tokendock:8080` on a Docker network vs `http://localhost:8080` from the runner).

### Endpoints

- `POST /token` — client_credentials grant; client auth via HTTP Basic **or** form body. Validates client/secret/scopes; returns `{access_token, token_type: "Bearer", expires_in, scope}`.
- `GET /.well-known/openid-configuration` — issuer, token endpoint, jwks_uri, grant types, algs.
- `GET /.well-known/jwks.json` — public key(s) with `kid`.
- `GET /health` — readiness for Docker health checks / action wait-loop.

Errors per RFC 6749: `401 {"error":"invalid_client"}`, `400 {"error":"invalid_scope"|"unsupported_grant_type"|"invalid_request"}`.

### Tokens & keys

RS256 JWTs, `kid` header. Claims: `iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `scope` (space-delimited), merged with per-client custom claims. Default signing key: ephemeral RSA-2048 generated at startup; optional mounted PEM for reproducibility.

### Repo layout

```
cmd/tokendock/main.go        # flag parsing, wiring, serve
internal/config/             # load + merge defaults/file/env, validation
internal/keys/               # keypair generation, PEM loading, JWKS encoding
internal/server/             # HTTP handlers (token, discovery, jwks, health)
Dockerfile                   # multi-stage: build → scratch/distroless, multi-arch
action/                      # composite GitHub Action wrapper
docs/design/      # committed design spec (this design)
```

### GitHub Action wrapper

Composite action in `action/`: inputs mirror env vars plus optional config-file path; runs the container, polls `/health`, and exposes outputs `issuer`, `token-endpoint`, `jwks-uri`.

## Implementation steps

1. `git init`, Go module init, commit the design spec to `docs/design/2026-07-08-tokendock-design.md`.
2. `internal/config`: types, YAML loading (`gopkg.in/yaml.v3`), env overlay, defaults, validation — with unit tests (TDD throughout).
3. `internal/keys`: ephemeral RSA generation, PEM loading, JWKS JSON encoding, `kid` derivation — unit tests.
4. `internal/server`: handlers for `/token` (both client-auth styles, scope validation, RFC 6749 errors), discovery, JWKS, health — handler unit tests using `httptest`.
5. `cmd/tokendock`: wire config + keys + server; startup logging (issuer, clients, demo-client warning).
6. Integration test: start server, request token with `golang-jwt` client, validate signature/claims against the JWKS endpoint end-to-end.
7. Dockerfile (multi-stage, static binary, distroless, HEALTHCHECK) + GitHub Actions workflow to build/push multi-arch to GHCR.
8. `action/action.yml` composite action + a dogfooding CI workflow that uses the action and validates a token.
9. README: quickstart (zero-config), GitHub Actions `services:` example, action example, config reference, issuer-URL gotcha.

## Verification

- `go test ./...` — unit + integration tests pass.
- `docker build` then `docker run -p 8080:8080` with no config: fetch a token via `curl -u tokendock:tokendock-secret -d grant_type=client_credentials http://localhost:8080/token`, then verify it against `/.well-known/jwks.json` (integration test automates the same check in-process).
- Confirm `/.well-known/openid-configuration` returns a document a standard OIDC client accepts.
- Dogfooding workflow: GitHub Actions job spins up the image via the composite action, requests a token, validates it — proving the primary use case end-to-end.
