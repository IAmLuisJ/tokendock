# TokenDock

A fake OAuth 2.0 Authorization Server for CI. TokenDock issues RS256-signed JWTs
via the client credentials grant and serves the JWKS + OIDC discovery endpoints
your application already uses to validate tokens — so JWT-protected flows work
in CI without reaching your real authorization server, and without any
test-specific code in your app.

- **Tiny and instant**: single static Go binary in a distroless image (~10MB, starts in milliseconds)
- **Zero-config**: starts with a built-in demo client; add real clients via env vars or YAML
- **Standards-shaped**: `/token`, `/.well-known/openid-configuration`, `/.well-known/jwks.json`, RFC 6749 errors

> ⚠️ TokenDock is a **test double**. It signs whatever your config says with an
> ephemeral key. Never expose it outside CI or local development.

## Quickstart

```sh
docker run -p 8080:8080 ghcr.io/luisjuarez/tokendock:latest
```

Fetch a token with the built-in demo client:

```sh
curl -u tokendock:tokendock-secret -d grant_type=client_credentials http://localhost:8080/token
```

Point your app's JWT validation at `http://localhost:8080` as the issuer and it
will discover the keys and validate the token like any real identity provider.

## GitHub Actions

### As a service container

```yaml
jobs:
  test:
    runs-on: ubuntu-latest
    services:
      tokendock:
        image: ghcr.io/luisjuarez/tokendock:latest
        ports: ["8080:8080"]
        env:
          TOKENDOCK_ISSUER: http://localhost:8080
          TOKENDOCK_CLIENT_ID: my-service
          TOKENDOCK_CLIENT_SECRET: ci-secret
          TOKENDOCK_SCOPES: read,write
          TOKENDOCK_AUDIENCE: my-api
    steps:
      - run: |
          curl -u my-service:ci-secret \
            -d grant_type=client_credentials -d 'scope=read write' \
            http://localhost:8080/token
```

### As an action

```yaml
steps:
  - uses: luisjuarez/tokendock/action@v1
    id: tokendock
    with:
      client-id: my-service
      client-secret: ci-secret
      scopes: read,write
      audience: my-api

  - run: |
      curl -u my-service:ci-secret -d grant_type=client_credentials \
        "${{ steps.tokendock.outputs.token-endpoint }}"
```

The action starts the container, waits for it to be healthy, and exposes
`issuer`, `token-endpoint`, and `jwks-uri` outputs.

## Configuration

Three layers, later wins: **defaults → YAML file → environment variables**.

### Environment variables (single client)

| Variable | Meaning |
|---|---|
| `TOKENDOCK_ISSUER` | Issuer URL embedded in tokens (default `http://localhost:<port>`) |
| `TOKENDOCK_PORT` | Listen port (default `8080`) |
| `TOKENDOCK_CLIENT_ID` / `TOKENDOCK_CLIENT_SECRET` | Define a client |
| `TOKENDOCK_SCOPES` | Comma-separated scopes the client may request |
| `TOKENDOCK_AUDIENCE` | `aud` claim for issued tokens |
| `TOKENDOCK_SIGNING_KEY` | Path to an RSA private key PEM (default: ephemeral key per start) |
| `TOKENDOCK_CONFIG` | Path to the YAML config file |

### YAML file (multiple clients, custom claims)

Mounted at `/etc/tokendock/config.yaml` (or set `TOKENDOCK_CONFIG` / `-config`):

```yaml
issuer: http://tokendock:8080
port: 8080
# signing_key: /keys/private.pem   # optional; ephemeral if omitted
clients:
  - client_id: my-service
    client_secret: ci-secret
    scopes: [read, write]      # empty/omitted = any scope allowed
    audience: my-api
    subject: my-service        # defaults to client_id
    token_lifetime: 3600       # seconds, default 3600
    claims:                    # arbitrary extra claims for authz testing
      roles: [admin]
      tenant: acme
```

If no clients are configured anywhere, TokenDock starts with the demo client
`tokendock` / `tokendock-secret` (any scope allowed) and logs a loud warning.

### ⚠️ The issuer URL must match

JWT validators compare the token's `iss` claim **strictly** against their
configured issuer, and OIDC discovery URLs are derived from it. Set
`TOKENDOCK_ISSUER` to the URL **as the app under test sees it**:

- App in a container on the same Docker network: `http://tokendock:8080`
- App on the runner host (services with mapped ports): `http://localhost:8080`

## Endpoints

| Endpoint | Purpose |
|---|---|
| `POST /token` | Client credentials grant. Client auth via HTTP Basic or form body (`client_id`/`client_secret`). |
| `GET /.well-known/openid-configuration` | OIDC discovery document |
| `GET /.well-known/jwks.json` | Public signing keys |
| `GET /health` | Readiness probe (also `tokendock -healthcheck` for Docker HEALTHCHECK) |

Issued tokens are RS256 JWTs with `iss`, `sub`, `aud`, `exp`, `iat`, `jti`,
`scope`, and any custom claims from the client's config. Errors follow RFC 6749
(`invalid_client`, `invalid_scope`, `unsupported_grant_type`, `invalid_request`).

## Development

```sh
go test ./...          # unit + end-to-end integration tests
go run ./cmd/tokendock # run locally with zero config
docker build -t tokendock .
```

## License

MIT
