# JWT Bearer (RFC 7523) — Design

## Context

TokenDock covers client credentials, authorization code, and token exchange.
The README and landing page still send teams to mock-oauth2-server when they
need the JWT bearer grant. This adds both halves of RFC 7523:

- **§2.1 authorization grant:** `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`
  with an `assertion` JWT — what Spring's `JwtBearerOAuth2AuthorizedClientProvider`
  and Azure-style on-behalf-of flows send.
- **§2.2 client authentication:** `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
  plus a `client_assertion` JWT (OIDC `private_key_jwt` / `client_secret_jwt`),
  accepted on every grant, so apps that authenticate with a key or certificate
  instead of a secret run unchanged.

Decisions made with the user:

- **Client auth for the grant:** required, as for every grant. Secretless
  clients send `client_id` alone. Self-issued assertions with no client
  credentials (Google service-account style) are out of scope.
- **Assertion leniency:** the assertion must be a well-formed JWT containing
  `sub`; signature, `exp`, `iss`, and `aud` are deliberately not verified —
  the token exchange stance.
- **Claims:** the requesting client's configured claims, overlaid with the
  assertion's non-registered claims (assertion wins) — the token exchange merge.
- **Scope:** the grant and client assertions together.

## Grant: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`

`POST /token` with client authentication as for every grant.

| Parameter | Handling |
|---|---|
| `assertion` | Required. Any well-formed JWT; must contain `sub`. |
| `scope` | Optional. Same rules as every grant (allowlist; OIDC scopes always allowed). |
| anything else (`requested_token_use`, …) | Accepted and ignored. |

### Issued token

- `sub`: copied from the assertion.
- Custom claims: the client's configured `claims`, overlaid with the
  assertion's non-registered claims. Registered claims (`iss`, `sub`, `aud`,
  `exp`, `iat`, `nbf`, `jti`, `scope`, `act`) are never copied; the server
  stamps them.
- `aud`, lifetime, default scopes: from the client. RFC 7523 defines no
  `audience` parameter, so there is no per-request override.
- `typ`: `at+jwt`, or `JWT` with `rfc9068: false`.

Response: the standard token response (`access_token`, `token_type`,
`expires_in`, `scope` when non-empty). No `issued_token_type` — RFC 7523
doesn't define one.

### Errors

- Missing `assertion` → `400 invalid_request`
- Unparseable assertion, or one lacking `sub` → `400 invalid_grant` (RFC 7523 §3.1)
- Disallowed scope → `400 invalid_scope`

## Client authentication with a JWT assertion (every grant)

Applies when the form carries `client_assertion` or `client_assertion_type`:

1. A Basic `Authorization` header or a `client_secret` form value alongside it
   → `400 invalid_request`: RFC 6749 §2.3 allows one authentication method per
   request.
2. `client_assertion_type` other than the jwt-bearer URN → `401 invalid_client`.
3. `client_assertion` missing, malformed, or lacking `sub` → `401 invalid_client`
   (RFC 7521 §4.2.1).
4. `client_id`, when sent, must equal the assertion's `sub` → else
   `401 invalid_client` (RFC 7521 §4.2).
5. The client is the configured client whose `client_id` equals `sub`; none →
   `401 invalid_client`.

The assertion's signature isn't verified, so a client's configured
`client_secret` is not checked on this path: a well-formed assertion naming a
configured client authenticates it. Same test-double leniency as unverified
subject tokens; the docs say so.

Requests without assertion parameters authenticate exactly as before.

## Discovery

- `grant_types_supported` adds `urn:ietf:params:oauth:grant-type:jwt-bearer`.
- `token_endpoint_auth_methods_supported` adds `private_key_jwt` and
  `client_secret_jwt`.
- New `token_endpoint_auth_signing_alg_values_supported`: every algorithm the
  assertion parser recognizes except `none` — `RS256`/`384`/`512`,
  `PS256`/`384`/`512`, `ES256`/`384`/`512`, `EdDSA`, `HS256`/`384`/`512`.
  Client libraries such as openid-client read it to pick an assertion
  algorithm.

No new configuration, environment variables, or action inputs.

## Code shape

- `internal/server/jwtbearer.go`: the grant and client-assertion constants,
  `handleJWTBearer`, and `authenticateAssertion` (steps 1–5, writing its own
  error like `parseAuthRequest`).
- `internal/server/token.go`: `authenticateClient` split out of `handleToken`,
  delegating to `authenticateAssertion` when assertion parameters are present;
  the grant dispatch case.
- `internal/server/exchange.go`: `overlayClaims` extracted from the token
  exchange handler and shared with the JWT bearer grant.
- `internal/server/server.go`: discovery fields.

## Testing

- Handler tests: grant happy path (sub, iss, client aud/lifetime/scopes, claim
  merge, registered claims not copied), scope subset and disallowed scope,
  each error, client auth still required, no `issued_token_type`.
- Client assertion tests: authenticates on `client_credentials` with and
  without a configured secret, `client_id` match/mismatch, unknown `sub`,
  malformed, wrong or missing type/assertion, combined with Basic or
  `client_secret`, combined with the JWT bearer grant (on-behalf-of).
- Discovery fields.
- Integration: a demo-client token presented as the JWT bearer `assertion`,
  authenticated by a hand-built client assertion; result validated through
  JWKS only.
- CI dogfood: both assertions hand-crafted in bash against the built image.

## Docs

README (intro, endpoints, a JWT bearer section, comparison table and "choose"
lists), `docs/configuration.md` (request rules; client assertions vs. secrets),
action description, landing page copy and comparison.

## Out of scope

Grant requests without client authentication (client identified by the
assertion's `iss`), signature or claim verification of either assertion, an
`audience` parameter, and `scope` read from inside the assertion.
