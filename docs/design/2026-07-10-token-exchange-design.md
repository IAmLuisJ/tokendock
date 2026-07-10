# Token Exchange (RFC 8693) — Design

## Context

Teams testing service-to-service delegation need the token exchange grant:
service A holds a token for a subject and exchanges it for a new token to call
service B, optionally recording that A is acting on the subject's behalf.
TokenDock currently supports only client_credentials; this adds the second
grant type real delegation tests need, with test-double leniency.

Decisions made with the user:

- **Subject token leniency:** `subject_token` must be a well-formed JWT, but
  signature and expiry are deliberately not verified — its claims are trusted.
  Tests may exchange TokenDock-issued, third-party, or hand-crafted tokens.
- **Issued token content:** identity from the subject, authorization context
  from the requesting client (see merge rules below).
- **Delegation:** `actor_token` supported; issued token gets `act: {"sub": …}`.
- **Gating:** none — every configured client may use either grant type.

## Request

`POST /token` with client authentication as today (HTTP Basic or form body;
secretless clients participate normally).

| Parameter | Handling |
|---|---|
| `grant_type` | `urn:ietf:params:oauth:grant-type:token-exchange` |
| `subject_token` | Required. Any well-formed JWT; must contain `sub`. |
| `subject_token_type` | Accepted and ignored (lenient). |
| `actor_token` | Optional. Well-formed JWT with `sub`; produces `act` claim. |
| `actor_token_type` | Accepted and ignored. |
| `audience` | Optional. Overrides the client's configured `audience`. |
| `scope` | Optional. Validated against client scopes (same rules as client_credentials). |
| `requested_token_type` | Accepted and ignored; we always issue an access token. |

## Issued token

- `sub`: copied from `subject_token`.
- Custom claims: requesting client's configured `claims`, overlaid with the
  subject token's non-registered claims (subject wins on conflict). Registered
  claims (`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`, `scope`, `act`) are
  never copied from the subject token wholesale; they are stamped last by the
  server.
- `aud`: request `audience` param, else client config, else omitted.
- `scope`: requested scopes, else client's configured scopes, omitted if none.
- `exp`/`iat`: now + client `token_lifetime`.
- `act`: `{"sub": <actor sub>}` when `actor_token` present.
- Signed RS256 with the server key, `kid` header as today.

## Response

```json
{
  "access_token": "…",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read write"
}
```

`scope` omitted when empty, matching the client_credentials response.

## Errors (RFC 6749/8693 shapes)

- Missing `subject_token` → `400 invalid_request`
- Unparseable subject/actor JWT, or one lacking `sub` → `400 invalid_grant`
- Disallowed scope → `400 invalid_scope`
- Unknown/failed client auth → `401 invalid_client` (unchanged)
- Other grant types → `400 unsupported_grant_type` (unchanged)

## Code shape

- `internal/server/exchange.go`: `handleTokenExchange` + subject/actor JWT
  parsing (`jwt.Parser.ParseUnverified`).
- `internal/server/token.go`: `handleToken` dispatches on `grant_type`;
  `mintToken` generalized to take subject, scopes, audience, and extra claims.
- Discovery document adds the exchange URN to `grant_types_supported`.

## Testing

- Handler tests: happy path (sub carried, claim merge order, client aud/
  lifetime), audience override, scope validation and default, `act` claim,
  each error path, response `issued_token_type`.
- Integration test: client_credentials → exchange → validate issued token via
  the JWKS endpoint only.
- Existing suites must stay green (client_credentials behavior unchanged).

## Docs

README grant documentation + comparison table row ("client credentials only,
deliberately" becomes "client credentials + token exchange"); landing page
comparison table and copy updated to match.
