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
clients:
  - client_id: my-service       # required
    client_secret: ci-secret    # omit to accept ANY secret
    scopes: [read, write]       # empty/omitted = any scope allowed
    audience: my-api            # aud claim; omitted if empty
    subject: my-service         # sub claim; defaults to client_id
    token_lifetime: 3600        # seconds; default 3600
    claims:                     # arbitrary extra claims for authz testing
      roles: [admin]
      tenant: acme
```

### Per-client fields

| Field | Default | Notes |
|---|---|---|
| `client_id` | — | Required. |
| `client_secret` | *(none)* | Omit for a secretless client. |
| `scopes` | any scope | Requested scopes must be a subset; no scopes configured means anything goes. |
| `audience` | *(omitted)* | Becomes the `aud` claim. Token exchange requests may override per-request. |
| `subject` | `client_id` | Becomes the `sub` claim for client_credentials tokens. |
| `token_lifetime` | `3600` | Seconds until `exp`. |
| `claims` | `{}` | Merged into every token this client obtains. |

## Secretless clients

A client configured with only a `client_id` accepts **any** secret, including
none. Your app keeps sending whatever credential it normally sends — TokenDock
issues the token either way, and the real secret never enters CI. Unknown
client IDs are still rejected, and clients that do configure a secret still
enforce it. The startup log flags every secretless client loudly.

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
`tokendock` / `tokendock-secret` (any scope allowed) and logs a warning. The
demo client disappears as soon as you configure any real client.
