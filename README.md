# TokenDock

A fake OAuth 2.0 Authorization Server for CI. TokenDock issues RS256-signed JWTs
via the client credentials, authorization code, and token exchange grants, and
serves the JWKS + OIDC discovery endpoints your application already uses to
validate tokens — so JWT-protected flows, browser logins included, work in CI
without reaching your real authorization server, and without any test-specific
code in your app.

- **Tiny and instant**: single static Go binary in a distroless image (~4MB, starts in milliseconds)
- **Zero-config**: starts with a built-in demo client; add real clients via env vars or YAML
- **Standards-shaped**: `/token`, `/authorize`, `/.well-known/openid-configuration`, `/.well-known/jwks.json`, PKCE, OIDC ID tokens, RFC 9068 `at+jwt` access tokens, RFC 8693 token exchange, RFC 6749 errors

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
`issuer`, `token-endpoint`, `authorization-endpoint`, and `jwks-uri` outputs.

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
Zero config gets you the demo client (`tokendock` / `tokendock-secret`).

**One client** — env vars are enough:

```yaml
env:
  TOKENDOCK_ISSUER: http://localhost:8080
  TOKENDOCK_CLIENT_ID: my-service     # omit TOKENDOCK_CLIENT_SECRET to accept ANY secret
  TOKENDOCK_SCOPES: read,write
  TOKENDOCK_AUDIENCE: my-api
```

**Multiple clients** — either mount a YAML file at
`/etc/tokendock/config.yaml`, or put an inline list in `TOKENDOCK_CLIENTS`
(no file needed — ideal for GitHub Actions `services:` blocks, which can't
mount repo files):

```yaml
env:
  TOKENDOCK_CLIENTS: |
    - client_id: frontend-service
      scopes: [read]
    - client_id: batch-worker
      client_secret: worker-secret
      scopes: [read, write]
      claims:
        roles: [batch]
```

Two rules worth knowing before anything else: a client without a
`client_secret` accepts **any** secret (your real one never enters CI), and
the **issuer must match the URL as the app under test sees it** —
`http://tokendock:8080` from inside a Docker network is not
`http://localhost:8080` from the host.

📖 **[Full configuration reference →](docs/configuration.md)** — every
variable and per-client field, defaults, JSON forms, and the issuer gotcha
explained.

🔌 **[Pointing your app at TokenDock →](docs/system-under-test.md)** —
framework-specific setup for the system under test: Spring Boot property
files and env overrides, Node.js (jose), ASP.NET Core, and a troubleshooting
checklist.

## Endpoints

| Endpoint | Purpose |
|---|---|
| `POST /token` | Client credentials, authorization code, and token exchange (RFC 8693) grants. Client auth via HTTP Basic or form body (`client_id`/`client_secret`). |
| `GET`/`POST /authorize` | Authorization code flow: redirects straight back with a code, or shows a login page with `TOKENDOCK_INTERACTIVE_LOGIN=true`. |
| `GET /.well-known/openid-configuration` | OIDC discovery document |
| `GET /.well-known/jwks.json` | Public signing keys |
| `GET /health` | Readiness probe (also `tokendock -healthcheck` for Docker HEALTHCHECK) |
| `GET /heartbeat` | Alias of `/health`, for tooling that expects a heartbeat path |

Issued tokens are RS256 JWTs with the RFC 9068 `typ: at+jwt` header, `kid`, and
`iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `scope`, plus any custom claims from
the client's config. Authorization code requests with the `openid` scope also
get an OIDC `id_token`. Errors follow RFC 6749
(`invalid_client`, `invalid_scope`, `unsupported_grant_type`, `invalid_request`,
`invalid_grant`).

Set `TOKENDOCK_RFC9068=false` to issue `typ: JWT` instead — needed for
validators that reject `at+jwt`, notably Spring Security 7 / Spring Boot 4 out
of the box. See [RFC 9068 and the `typ` header](docs/configuration.md#rfc-9068-and-the-typ-header).

### Authorization code (browser login)

For apps that sign users in through a browser redirect: OIDC login in a web
app, or a SPA using PKCE. Point the app's OIDC settings at TokenDock and it
discovers `/authorize` like any other provider. TokenDock **approves every
valid request immediately** and redirects straight back with a code, so a
browser test has nothing to click:

```sh
# The browser's leg: /authorize answers with a redirect carrying the code.
curl -s -o /dev/null -w '%{redirect_url}\n' \
  'http://localhost:8080/authorize?response_type=code&client_id=tokendock&redirect_uri=http://localhost:3000/callback&scope=openid&state=xyz&login_hint=alice'
# http://localhost:3000/callback?code=…&state=xyz

# The app's leg: redeem the code at /token.
curl -u tokendock:tokendock-secret -d grant_type=authorization_code \
  -d code=… -d redirect_uri=http://localhost:3000/callback \
  http://localhost:8080/token
```

- **Who signs in:** the `login_hint` the app sends (most OIDC client libraries
  can pass one), else the client's configured `subject`. Tokens carry the
  client's `audience`, `token_lifetime`, and custom `claims`.
- **`openid` scope:** the response adds an `id_token` for the client (`aud` is
  the client ID; `nonce` and `auth_time` included), signed with `typ: JWT` so
  it can never pass for an RFC 9068 access token.
- **PKCE** (`S256` or `plain`) is verified whenever the app sent a
  `code_challenge`. SPAs and native apps are secretless clients that send
  `client_id` alone; CORS is open so SPAs can call `/token` directly.
- **Redirect URIs:** any absolute `redirect_uri` works unless the client lists
  `redirect_uris`, which are then matched exactly.
- **Login page:** `TOKENDOCK_INTERACTIVE_LOGIN=true` makes `/authorize` show a
  one-field form where the test types the subject — for browser tests that
  switch between users.

The browser has to reach the issuer URL too. See
[Authorization code and browser login](docs/configuration.md#authorization-code-and-browser-login)
for that and every parameter rule, and
[Pointing your app at TokenDock](docs/system-under-test.md#browser-login-authorization-code)
for Spring Boot `oauth2Login` and Playwright examples.

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
| Grant types | Client credentials, authorization code (PKCE, OIDC ID tokens), token exchange (RFC 8693) | Authorization code, token exchange, JWT bearer, refresh & more |
| Interactive login page | Opt-in — by default `/authorize` approves instantly | Yes — for browser-driven E2E tests |
| Embed in test code | Container only | JVM library, JUnit-friendly |
| Issuers | One per container | Multiple per instance |
| Configuration | Zero-config default, then env vars or YAML | JSON or programmatic API |
| CI wrapper | Composite GitHub Action with health-wait and outputs | — |

**Choose TokenDock when** you're testing machine-to-machine bearer tokens or
browser logins that only need to get through the redirect, want a service
container that's ready before your app finishes booting, aren't on the JVM, or
would rather declare clients in a few env vars than maintain config code.

**Choose mock-oauth2-server when** you need refresh tokens, a userinfo
endpoint, or the JWT bearer grant, you want the server embedded in your JUnit
lifecycle, or you need several issuers from one instance.

## Development

```sh
go test ./...          # unit + end-to-end integration tests
go run ./cmd/tokendock # run locally with zero config
docker build -t tokendock .
```

## License

MIT
