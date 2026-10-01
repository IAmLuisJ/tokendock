# Configuration reference

TokenDock merges configuration from three layers. Later layers override or
extend earlier ones:

1. **Built-in defaults** — port `8080`, issuer `http://localhost:<port>`, and
   (only when no clients are configured anywhere) the demo client.
2. **YAML config file** — `/etc/tokendock/config.yaml`, or wherever
   `TOKENDOCK_CONFIG` / the `-config` flag points.
3. **Environment variables** — scalar values (issuer, port, signing key)
   override the file; client definitions are **appended** to the file's list.

## Environment variables

| Variable | Meaning |
|---|---|
| `TOKENDOCK_ISSUER` | Issuer URL embedded in tokens. Default `http://localhost:<port>`. Must match how the app under test reaches the server — see [The issuer URL must match](#the-issuer-url-must-match). |
| `TOKENDOCK_PORT` | Listen port. Default `8080`. |
| `TOKENDOCK_SIGNING_KEY` | Path to an RSA private key PEM. Default: a fresh ephemeral RSA-2048 key per start. |
| `TOKENDOCK_CONFIG` | Path to the YAML config file. |
| `TOKENDOCK_CLIENT_ID` | Defines a single client. |
| `TOKENDOCK_CLIENT_SECRET` | Secret for that client. **Omit to accept any secret** (see [Secretless clients](#secretless-clients)). |
| `TOKENDOCK_SCOPES` | Comma-separated scopes that client may request. Empty = any scope allowed. |
| `TOKENDOCK_AUDIENCE` | `aud` claim for that client's tokens. |
| `TOKENDOCK_RFC9068` | `true` (default) issues access tokens with the RFC 9068 `typ: at+jwt` header; `false` issues `typ: JWT`. See [RFC 9068 and the `typ` header](#rfc-9068-and-the-typ-header). |
| `TOKENDOCK_INTERACTIVE_LOGIN` | `true` makes `/authorize` show a login page where the tester types the subject; `false` (default) approves every valid request immediately. See [Authorization code and browser login](#authorization-code-and-browser-login). |
| `TOKENDOCK_CLIENTS` | **Multiple clients, no file needed**: an inline YAML or JSON list of client objects (same schema as the config file's `clients:` entries). |

### Multiple clients via `TOKENDOCK_CLIENTS`

The single-client variables (`TOKENDOCK_CLIENT_ID` etc.) define exactly one
client. For more than one without mounting a file, put the whole list in
`TOKENDOCK_CLIENTS`:

```yaml
# docker-compose.yml
services:
  tokendock:
    image: ghcr.io/iamluisj/tokendock:latest
    environment:
      TOKENDOCK_ISSUER: http://tokendock:8080
      TOKENDOCK_CLIENTS: |
        - client_id: frontend-service
          scopes: [read]
          audience: my-api
        - client_id: batch-worker
          client_secret: worker-secret
          scopes: [read, write]
          audience: my-api
          claims:
            roles: [batch]
```

JSON works too (handy for single-line env definitions):

```sh
docker run -p 8080:8080 \
  -e TOKENDOCK_CLIENTS='[{"client_id":"frontend"},{"client_id":"worker"}]' \
  ghcr.io/iamluisj/tokendock:latest
```

This is the recommended path for GitHub Actions `services:` blocks, which
start before checkout and therefore can't mount files from your repository:

```yaml
services:
  tokendock:
    image: ghcr.io/iamluisj/tokendock:latest
    ports: ["8080:8080"]
    env:
      TOKENDOCK_CLIENTS: '[{"client_id":"frontend","scopes":["read"]},{"client_id":"worker","scopes":["read","write"]}]'
```

The composite action exposes the same thing as a `clients` input.

All client sources combine: file `clients:` first, then `TOKENDOCK_CLIENTS`
entries, then the single `TOKENDOCK_CLIENT_ID` client.

## YAML config file

```yaml
issuer: http://tokendock:8080   # must match how the app under test reaches the server
port: 8080
signing_key: /keys/private.pem  # optional; ephemeral RSA-2048 per start if omitted
rfc9068: true                   # optional; false issues typ: JWT instead of at+jwt
interactive_login: false        # optional; true shows a login page at /authorize
clients:
  - client_id: my-service       # required
    client_secret: ci-secret    # omit to accept ANY secret
    scopes: [read, write]       # empty/omitted = any scope allowed
    audience: my-api            # aud claim; omitted if empty
    subject: my-service         # sub claim; defaults to client_id
    token_lifetime: 3600        # seconds; default 3600
    redirect_uris:              # authorization code only; omit to accept any
      - http://localhost:3000/callback
    claims:                     # arbitrary extra claims for authz testing
      roles: [admin]
      tenant: acme
```

### Per-client fields

| Field | Default | Notes |
|---|---|---|
| `client_id` | — | Required. |
| `client_secret` | *(none)* | Omit for a secretless client. |
| `scopes` | any scope | Requested scopes must be a subset; no scopes configured means anything goes. The OpenID Connect scopes (`openid`, `profile`, `email`, `address`, `phone`, `offline_access`) are always allowed. |
| `audience` | *(omitted)* | Becomes the `aud` claim. Token exchange requests may override per-request. |
| `subject` | `client_id` | Becomes the `sub` claim for client_credentials tokens, and for authorization code tokens when the app sends no `login_hint`. |
| `token_lifetime` | `3600` | Seconds until `exp`, for access and ID tokens alike. |
| `redirect_uris` | any | Authorization code redirect URIs, matched exactly. Omitted = any absolute URI; with exactly one, apps may leave `redirect_uri` out. |
| `claims` | `{}` | Merged into every token this client obtains, ID tokens included. |

## RFC 9068 and the `typ` header

By default TokenDock stamps issued access tokens with the
[RFC 9068](https://datatracker.ietf.org/doc/rfc9068/) media type in the JWS
header:

```json
{ "alg": "RS256", "kid": "…", "typ": "at+jwt" }
```

That is what a real RFC 9068 authorization server emits, and it lets the app
under test exercise its strict `typ` checking in CI.

**Turn it off when your validator rejects `at+jwt`.** Either layer works:

```yaml
# config.yaml
rfc9068: false
```

```yaml
# docker-compose.yml
environment:
  TOKENDOCK_RFC9068: "false"
```

```yaml
# GitHub Actions, via the composite action
- uses: IAmLuisJ/tokendock@v1
  with:
    rfc9068: "false"
```

With it disabled, tokens carry `typ: JWT` and everything else is unchanged.
The startup log always states which one is in effect.

### Which validators care

| Stack | Default behavior with `at+jwt` |
|---|---|
| Spring Security 7 / Spring Boot 4 | **Rejects** — `JwtTypeValidator` accepts only `JWT` unless you configure otherwise |
| Spring Boot 3.x | Accepts |
| Node `jose` | Accepts — `typ` is only checked when you pass the `typ` option |
| ASP.NET Core `JwtBearer` | Accepts — `typ` is only checked when you set `TokenValidationParameters.ValidTypes` |

The fastest fix for a Spring Boot 4 app under test is `TOKENDOCK_RFC9068=false`.
To keep RFC 9068 on and adjust the app instead, see
[Pointing your app at TokenDock](system-under-test.md#spring-boot-4--spring-security-7-rejects-atjwt).

## Authorization code and browser login

The authorization code grant lets the app under test run its real browser
login against TokenDock. The app sends the browser to `/authorize` (found
through OIDC discovery), gets a code back on its redirect URI, and redeems the
code at `/token` with its normal client authentication.

### Who signs in

By default `/authorize` **approves every valid request immediately** — no
page, nothing to click. The subject (`sub` claim) is:

1. the request's `login_hint`, when the app sends one — most OIDC client
   libraries let you pass it per login, which is how a test picks a user;
2. otherwise the client's configured `subject` (default: the `client_id`).

Tokens take `audience`, `token_lifetime`, and custom `claims` from the client,
as with client credentials. Claims are per client, not per user: every subject
signed in through one client gets the same custom claims.

### Interactive login page

For browser tests that should pick the user on a login screen, turn the page
on:

```yaml
# config.yaml
interactive_login: true
```

```yaml
# docker-compose.yml / GitHub Actions services
environment:
  TOKENDOCK_INTERACTIVE_LOGIN: "true"
```

The composite action takes `interactive-login: "true"`.

`/authorize` then shows a one-field form: **Subject** (prefilled from
`login_hint`, else the client's `subject`) and a **Sign in** button. A
Playwright test drives it like this:

```ts
await page.getByLabel("Subject").fill("alice");
await page.getByRole("button", { name: "Sign in" }).click();
```

The form posts to `POST /login`. Tests without a browser can post there
directly — the authorization parameters plus `login_hint` — to skip the page.
`prompt=none` (silent re-authentication) returns `error=login_required` in
this mode, because TokenDock keeps no login session.

### Request rules

| Parameter | Rule |
|---|---|
| `response_type` | Must be `code`. |
| `client_id` | Any configured client. |
| `redirect_uri` | Any absolute URI without a fragment, unless the client lists `redirect_uris` — then an exact match, optional when exactly one is listed. |
| `scope` | Same rules as every grant; see [per-client fields](#per-client-fields). |
| `state` | Echoed back unchanged. |
| `nonce` | Copied into the ID token. |
| `code_challenge`, `code_challenge_method` | PKCE: `S256` or `plain` (the default method). |
| `login_hint` | The subject to sign in. |
| `prompt` | Ignored, except that `prompt=none` fails with the login page on. |

Anything else (`response_mode`, `max_age`, …) is accepted and ignored; the
response always comes back in the redirect's query string. `/authorize`
accepts GET and POST.

A missing or unknown `client_id`, or a bad `redirect_uri`, gets a `400` JSON
error and **no redirect**, as RFC 6749 requires — the redirect target can't be
trusted. Every other problem redirects back with `error`, `error_description`,
and `state`: `invalid_request`, `unsupported_response_type`, `invalid_scope`,
or `login_required`.

### Redeeming the code

```sh
curl -u web-app:anything \
  -d grant_type=authorization_code \
  -d code="$CODE" \
  -d redirect_uri=http://localhost:3000/callback \
  -d code_verifier="$VERIFIER" \
  http://localhost:8080/token
```

- Codes are single use and expire after 10 minutes. They live in memory, so a
  restart invalidates outstanding ones.
- `redirect_uri` must repeat the one sent to `/authorize`, if one was sent.
- `code_verifier` is required when the app sent a `code_challenge`, and
  rejected when it didn't (RFC 9700's PKCE downgrade protection).
- SPAs and native apps are **public clients**: configure them without a
  `client_secret` and they authenticate with `client_id` alone. CORS is open
  on every endpoint, so a SPA can call `/token` from its own origin.
- Failures return `invalid_grant`.

With the `openid` scope the response includes an `id_token`: `iss`, `sub`,
`aud` (the client ID), `iat`, `exp`, `auth_time`, `nonce` when the app sent
one, and the client's custom claims. It is always signed with `typ: JWT`,
never `at+jwt`, whatever `rfc9068` says — RFC 9068 reserves `at+jwt` for
access tokens so an ID token can't be replayed as one. There is no userinfo
endpoint and no refresh token; apps read the user from the ID token and sign
in again when the access token expires.

### The browser must reach the issuer too

The **browser** visits `/authorize`; the **app** calls `/token` and the JWKS.
Discovery derives every URL from the issuer, so the issuer's host has to
resolve for both:

- **App and browser on the runner** (TokenDock as a service container with a
  mapped port): `http://localhost:8080` works for both. Simplest.
- **App in a container:** either run the browser in the same Docker network
  (for example the Playwright image as a compose service) so
  `http://tokendock:8080` resolves for it as well, or keep the internal issuer
  and override only the app's browser-facing authorization URL — see
  [Pointing your app at TokenDock](system-under-test.md#browser-login-authorization-code).

## Secretless clients

A client configured with only a `client_id` accepts **any** secret, including
none. Your app keeps sending whatever credential it normally sends — TokenDock
issues the token either way, and the real secret never enters CI. Unknown
client IDs are still rejected, and clients that do configure a secret still
enforce it. The startup log flags every secretless client loudly.

Secretless clients are also how public clients — SPAs and native apps using
the authorization code flow — work: they send `client_id` alone and prove
possession of the code with PKCE.

## The issuer URL must match

JWT validators compare the token's `iss` claim **strictly** against their
configured issuer, and OIDC discovery URLs are derived from it. Set the issuer
to the URL **as the app under test sees it**:

- App in a container on the same Docker network: `http://tokendock:8080`
- App on the runner host (services with mapped ports): `http://localhost:8080`

Getting this wrong is the most common setup mistake — the symptom is a
signature-valid token rejected with an issuer mismatch.

## Demo client

When no clients are configured by any layer, TokenDock starts with
`tokendock` / `tokendock-secret` (any scope and any redirect URI allowed) and
logs a warning. The
demo client disappears as soon as you configure any real client.
