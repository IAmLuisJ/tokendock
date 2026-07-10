# TokenDock

A fake OAuth 2.0 Authorization Server for CI. TokenDock issues RS256-signed JWTs
via the client credentials grant and serves the JWKS + OIDC discovery endpoints
your application already uses to validate tokens — so JWT-protected flows work
in CI without reaching your real authorization server, and without any
test-specific code in your app.

- **Tiny and instant**: single static Go binary in a distroless image (~4MB, starts in milliseconds)
- **Zero-config**: starts with a built-in demo client; add real clients via env vars or YAML
- **Standards-shaped**: `/token`, `/.well-known/openid-configuration`, `/.well-known/jwks.json`, RFC 6749 errors

> ⚠️ TokenDock is a **test double**. It signs whatever your config says with an
> ephemeral key. Never expose it outside CI or local development.

## Quickstart

```sh
docker run -p 8080:8080 ghcr.io/iamluisj/tokendock:latest
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
        image: ghcr.io/iamluisj/tokendock:latest
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
  - uses: IAmLuisJ/tokendock/action@v1
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

## Docker Compose

Add TokenDock as a sibling service in your existing `docker-compose.yml`. The
image's built-in HEALTHCHECK means `depends_on: condition: service_healthy`
just works — your app won't start until tokens are available:

```yaml
services:
  tokendock:
    image: ghcr.io/iamluisj/tokendock:latest
    environment:
      # Other containers reach it by service name, so the issuer must match:
      TOKENDOCK_ISSUER: http://tokendock:8080
      TOKENDOCK_CLIENT_ID: my-service
      # no TOKENDOCK_CLIENT_SECRET -> any secret is accepted
      TOKENDOCK_AUDIENCE: my-api
    ports: ["8080:8080"]   # optional: only if the host also needs tokens

  my-app:
    build: .
    depends_on:
      tokendock:
        condition: service_healthy
    environment:
      # Point your app's normal JWT/OIDC validation at TokenDock:
      OIDC_ISSUER: http://tokendock:8080
```

For multiple clients or custom claims, mount a config file instead of the
environment variables:

```yaml
  tokendock:
    image: ghcr.io/iamluisj/tokendock:latest
    volumes:
      - ./tokendock.yaml:/etc/tokendock/config.yaml:ro
```

## Configuration

Three layers, later wins: **defaults → YAML file → environment variables**.

### Environment variables (single client)

| Variable | Meaning |
|---|---|
| `TOKENDOCK_ISSUER` | Issuer URL embedded in tokens (default `http://localhost:<port>`) |
| `TOKENDOCK_PORT` | Listen port (default `8080`) |
| `TOKENDOCK_CLIENT_ID` / `TOKENDOCK_CLIENT_SECRET` | Define a client (omit the secret to accept **any** secret for that client ID) |
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
    client_secret: ci-secret  # omit to accept ANY secret — CI never needs the real one
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

**Secretless clients**: a client configured with only a `client_id` accepts any
secret (including none). Your app keeps sending whatever credential it normally
sends — TokenDock issues the token either way, and your real secret never
enters CI. The startup log flags these clients loudly.

### ⚠️ The issuer URL must match

JWT validators compare the token's `iss` claim **strictly** against their
configured issuer, and OIDC discovery URLs are derived from it. Set
`TOKENDOCK_ISSUER` to the URL **as the app under test sees it**:

- App in a container on the same Docker network: `http://tokendock:8080`
- App on the runner host (services with mapped ports): `http://localhost:8080`

## Endpoints

| Endpoint | Purpose |
|---|---|
| `POST /token` | Client credentials and token exchange (RFC 8693) grants. Client auth via HTTP Basic or form body (`client_id`/`client_secret`). |
| `GET /.well-known/openid-configuration` | OIDC discovery document |
| `GET /.well-known/jwks.json` | Public signing keys |
| `GET /health` | Readiness probe (also `tokendock -healthcheck` for Docker HEALTHCHECK) |
| `GET /heartbeat` | Alias of `/health`, for tooling that expects a heartbeat path |

Issued tokens are RS256 JWTs with `iss`, `sub`, `aud`, `exp`, `iat`, `jti`,
`scope`, and any custom claims from the client's config. Errors follow RFC 6749
(`invalid_client`, `invalid_scope`, `unsupported_grant_type`, `invalid_request`,
`invalid_grant`).

### Token exchange (RFC 8693)

Exchange an existing token for a new one — for testing service-to-service
delegation:

```sh
curl -u my-service:ci-secret \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token="$USER_TOKEN" \
  -d actor_token="$SERVICE_TOKEN" \
  -d audience=downstream-api \
  http://localhost:8080/token
```

Test-double leniency, applied deliberately: `subject_token` (and the optional
`actor_token`) must be **well-formed** JWTs containing `sub`, but signatures
and expiry are not verified — exchange TokenDock-issued, third-party, or
hand-crafted tokens freely. The issued token carries the subject's `sub` and
custom claims (subject wins over client-configured claims on conflict), takes
audience/scopes/lifetime from the requesting client (request `audience` and
`scope` params override), and gets `act: {"sub": …}` when an `actor_token` is
supplied. Any configured client may use either grant.

## TokenDock vs. mock-oauth2-server

[navikt/mock-oauth2-server](https://github.com/navikt/mock-oauth2-server) is the
established tool in this space — mature, capable, and the right choice for
plenty of teams. An honest comparison:

| | TokenDock | mock-oauth2-server |
|---|---|---|
| Runtime & image | ~4 MB static Go binary | ~200 MB JVM image (Kotlin) |
| Cold start | Milliseconds | Seconds (JVM startup) |
| Grant types | Client credentials + token exchange (RFC 8693) | Authorization code, token exchange, JWT bearer, refresh & more |
| Interactive login page | None | Yes — for browser-driven E2E tests |
| Embed in test code | Container only | JVM library, JUnit-friendly |
| Issuers | One per container | Multiple per instance |
| Configuration | Zero-config default, then env vars or YAML | JSON or programmatic API |
| CI wrapper | Composite GitHub Action with health-wait and outputs | — |

**Choose TokenDock when** you're testing machine-to-machine bearer tokens,
want a service container that's ready before your app finishes booting, aren't
on the JVM, or would rather declare clients in a few env vars than maintain
config code.

**Choose mock-oauth2-server when** your E2E tests drive a browser through a
real login redirect, you need authorization code flow or refresh tokens, you
want the server embedded in your JUnit lifecycle, or you need several issuers
from one instance.

## Development

```sh
go test ./...          # unit + end-to-end integration tests
go run ./cmd/tokendock # run locally with zero config
docker build -t tokendock .
```

## License

MIT
