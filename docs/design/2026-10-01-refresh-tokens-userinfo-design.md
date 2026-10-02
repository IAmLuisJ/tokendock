# Refresh Token Grant (RFC 6749 §6) and UserInfo Endpoint — Design

## Context

The authorization code release (v1.6.0) left refresh tokens and a userinfo
endpoint out of scope. Without them, apps that keep a session alive
(`offline_access`) or read the profile from `/userinfo` (Spring's
`OidcUserService` when `profile`/`email` are in scope, plain OAuth2 login)
can't run their full login flow in CI. The README sent those users to
mock-oauth2-server. This adds both, keeping the test-double stance: no new
configuration, behaviour shaped like real providers.

Decisions made with the user:

- **Issuance:** a refresh token is returned from the authorization code grant
  only when `offline_access` is granted, as OIDC Core §11 describes and real
  providers do. Client credentials and token exchange never return one.
- **Rotation:** every use returns a new refresh token and spends the old one,
  so CI can exercise rotation-aware clients.
- **Userinfo content:** `sub` always; the token's custom claims only when the
  token carries the `openid` scope.

## Refresh token grant: `POST /token`, `grant_type=refresh_token`

| Parameter | Handling |
|---|---|
| `refresh_token` | Required (`invalid_request` if missing). Unknown, spent, or expired → `invalid_grant`. |
| `scope` | Optional. Must be a subset of the original grant (`invalid_scope` otherwise); omitted means the original scope. |

Client authentication is unchanged (Basic or form body; secretless clients
send `client_id` alone). A token issued to another client is `invalid_grant`.

The response mirrors the authorization code response: an access token minted
from the stored grant (subject, scope) and the client's audience, lifetime,
and claims; an `id_token` when the requested scope includes `openid`; and a
new `refresh_token`.

- **Rotated token scope:** the new refresh token always carries the original
  scope, even when the request narrowed the access token (RFC 6749 §6).
- **Refreshed ID token:** OIDC Core §12.2. It keeps `iss`, `sub`, `aud` and
  the original `auth_time`, gets a new `iat`, and has no `nonce` because
  there is no new authentication request for it to bind to.
- **Consumed on any attempt:** every redemption attempt spends the token,
  including failed ones (wrong client, bad scope). This matches the
  authorization code store and gives one simple rule to document. Replay
  does not revoke the newer token in the chain; a test double has no stolen
  tokens to contain.

### Storage

Refresh tokens reuse the authorization code store (`codeStore`), which now
takes its lifetime as a parameter: 10 minutes for codes, 24 hours for refresh
tokens. A stored refresh grant is an `authCode` that keeps the client ID,
scope, subject and `auth_time`, and drops the nonce, redirect URI and PKCE
challenge. Tokens are `rand.Text()` strings (opaque, not JWTs), held in
memory and swept on issue, so a restart invalidates them. Because each use
rotates the token, the 24-hour lifetime limits idle sessions, not active
ones.

## UserInfo endpoint: `GET|POST /userinfo`

OIDC Core §5.3 allows both methods. The access token arrives as
`Authorization: Bearer` (RFC 6750 §2.1). The form-body and query-string
methods are not supported.

- **Verification:** RS256 against the server key, `iss` must equal the
  issuer, and `exp` is required and checked. This is the one place TokenDock
  verifies its own tokens. Token exchange stays lenient because it accepts
  third-party tokens; userinfo only makes sense for tokens TokenDock issued.
- **No token:** `401` with `WWW-Authenticate: Bearer realm="tokendock"` and no
  error code (RFC 6750 §3.1).
- **Invalid token:** `401`, `WWW-Authenticate: Bearer realm="tokendock",
  error="invalid_token"`, and a JSON error body for debugging.
- **Response:** `{"sub": …}`, plus every non-registered claim in the token
  when its `scope` contains `openid`. The registered claims excluded are
  `iss`, `aud`, `exp`, `iat`, `nbf`, `jti`, `scope` and `act`.

Claims come from the verified access token, not from a client lookup. The
token already carries the client's configured claims, so the result is the
same, and tokens need no new `client_id` claim. Exchanged tokens report the
subject's claims they carry.

## Discovery, action, docs

- **Discovery:** the discovery document adds `userinfo_endpoint`, and
  `refresh_token` joins `grant_types_supported`.
- **Action:** the composite action gains a `userinfo-endpoint` output. The
  CI `dogfood-action` job runs authorize, redeem, refresh, a rejected reuse,
  and a userinfo call.
- **Docs:** the README, configuration reference, system-under-test guide and
  landing page drop "no refresh tokens / no userinfo". The mock-oauth2-server
  comparison now names only the JWT bearer grant, embedding and multiple
  issuers.

## Out of scope

- Token revocation (RFC 7009) and introspection (RFC 7662).
- Refresh tokens for client credentials or token exchange.
- Per-client switches for rotation or refresh-token lifetime. Add them if a
  user needs them.
- Userinfo claims filtered by the `profile`, `email`, `address` or `phone`
  scopes. The configured claims are returned whenever `openid` is present.
