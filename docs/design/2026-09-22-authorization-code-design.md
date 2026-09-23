# Authorization Code Grant (RFC 6749 §4.1) — Design

## Context

TokenDock covers machine-to-machine flows (client credentials, token
exchange). Apps with a browser login — server-rendered apps using OIDC login
(Spring `oauth2Login`, ASP.NET `AddOpenIdConnect`, Auth.js) and SPAs using
PKCE — still can't run their login flow in CI against TokenDock. This adds the
authorization code grant, with PKCE and OpenID Connect ID tokens, keeping the
test-double stance: nothing to click by default, lenient unless configured.

Decisions made with the user:

- **Login UX:** `/authorize` auto-approves by default — it redirects straight
  back with a code. An opt-in `interactive_login` renders a minimal login page
  where the tester types the subject, for browser tests that switch users.
- **Who logs in:** `sub` is the `login_hint` parameter when the app sends one
  (on the login page: the typed value), else the client's configured
  `subject`. Audience, lifetime, and custom claims come from the client, as
  with client credentials.
- **Scope of this change:** authorization code + PKCE + ID token + CORS. No
  refresh tokens and no userinfo endpoint — OIDC apps read identity from the
  ID token.

## Authorization endpoint: `GET|POST /authorize`

OIDC Core §3.1.2.1 requires both methods; parameters are read from the query
string or form body alike.

| Parameter | Handling |
|---|---|
| `response_type` | Required; must be `code`. |
| `client_id` | Required; must be a configured client. No secret here — the client authenticates at `/token`. |
| `redirect_uri` | See [redirect URI rules](#redirect-uri-rules). |
| `scope` | Optional; validated like every grant (see [scope rule](#scope-rule-change-all-grants)). |
| `state` | Optional; echoed back verbatim on success and error. |
| `nonce` | Optional; copied into the ID token. |
| `code_challenge`, `code_challenge_method` | Optional PKCE (RFC 7636): `S256` or `plain`; method defaults to `plain` when omitted (§4.3). |
| `login_hint` | Optional; becomes the token subject. |
| `prompt` | Ignored when auto-approving. With interactive login, `prompt=none` returns `login_required`. |
| anything else (`response_mode`, `max_age`, `ui_locales`, …) | Accepted and ignored; responses always use the query string. |

### Redirect URI rules

New optional per-client `redirect_uris`:

- **Not configured:** any absolute URI without a fragment is accepted, and
  `redirect_uri` is then required. Same leniency as secretless and scope-less
  clients.
- **Configured:** `redirect_uri` must exactly match an entry. It may be
  omitted when exactly one is configured (RFC 6749 §3.1.2.3).
- Config loading rejects configured entries that are not absolute URIs or
  that contain a fragment (§3.1.2).
- A query component in the redirect URI is kept when the response parameters
  are added (§3.1.2).

### Responses

- **Success:** `302` to the redirect URI with `code` and `state` (when sent).
- **Errors (RFC 6749 §4.1.2.1):** a missing or unknown `client_id`, or a
  missing, invalid, or unregistered `redirect_uri`, gets a `400` JSON
  `invalid_request` and is **never redirected**. Everything else redirects
  back with `error`, `error_description`, and `state`:
  - missing `response_type` → `invalid_request`
  - any other `response_type` → `unsupported_response_type`
  - disallowed scope → `invalid_scope`
  - unknown `code_challenge_method` → `invalid_request`
  - `prompt=none` with interactive login on → `login_required`

### Interactive login

With `interactive_login: true` (`TOKENDOCK_INTERACTIVE_LOGIN=true`), a valid
authorization request renders an HTML page instead of redirecting. It shows
the client, requested scopes, and redirect URI, plus a **Subject** field
(`name="login_hint"`, prefilled with the request's `login_hint` or the
client's `subject`) and a **Sign in** button.

The form posts every original parameter back as hidden fields to
`POST /login`, which validates the request exactly like `/authorize` and
approves it with the typed subject (blank falls back to the client's
`subject`). Headless tests can POST to `/login` directly to skip the page.

Every reflected parameter is escaped with `html.EscapeString` — values only
land in element text and quoted attributes — rather than `html/template`,
which measured at +1.9 MB on the static binary (+0.7 MB gzipped) against
+0.1 MB for this approach. The page is sent with `Cache-Control: no-store`
and a CSP that blocks scripts, and fetches no external assets, so it works on
an offline runner.

`prompt=none` forbids showing UI (OIDC Core §3.1.2.1) and TokenDock keeps no
login session, so it returns `login_required` when interactive login is on.

## Code storage

In memory, per process. A random 128-bit code maps to the client ID, the
`redirect_uri` as sent (empty when omitted), granted scopes, subject, nonce,
PKCE challenge and method, and `auth_time`.

- Codes live 10 minutes (the maximum RFC 6749 §4.1.2 recommends).
- Single use: redeeming removes the code whether or not the token request
  then succeeds.
- Expired codes are swept whenever a new code is issued.
- A restart invalidates outstanding codes.

## Token endpoint: `grant_type=authorization_code`

Client authentication is unchanged. Public clients (SPAs, native apps) are
secretless clients that send only `client_id`.

| Parameter | Handling |
|---|---|
| `code` | Required. |
| `redirect_uri` | Required and identical when it was sent to `/authorize` (RFC 6749 §4.1.3); ignored otherwise. |
| `code_verifier` | Required when the code carries a challenge. Rejected when it doesn't (RFC 9700 §4.8.2, PKCE downgrade). |

Errors:

- Missing `code` → `400 invalid_request`
- Unknown, expired, or already-used code; code issued to another client;
  `redirect_uri` mismatch; PKCE failure → `400 invalid_grant`
- Failed client authentication → `401 invalid_client` (unchanged)

## Issued tokens

**Access token** — same shape as client credentials:

- `sub`: the subject chosen at `/authorize`.
- `aud`, lifetime, custom claims: from the client.
- `scope`: the scopes granted at `/authorize`.
- `typ`: `at+jwt`, or `JWT` with `rfc9068: false`.

**ID token** — issued when `openid` is among the granted scopes (OIDC Core
§3.1.3.3):

- `iss`, `sub`, `aud` (the client ID), `iat`, `exp` (client lifetime),
  `auth_time` (when `/authorize` approved), `nonce` (when sent).
- The client's custom claims, so apps reading `name`, `email`, or `roles`
  from the ID token see them. The registered claims above always win.
- JWS header `typ: JWT` regardless of `rfc9068`: RFC 9068 (§2.1, §5) uses
  `at+jwt` precisely so validators can tell access tokens from ID tokens.
- No `at_hash` — optional in the code flow (OIDC Core §3.1.3.6).

Response:

```json
{
  "access_token": "…",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile",
  "id_token": "…"
}
```

## Scope rule change (all grants)

The OpenID Connect scopes — `openid`, `profile`, `email`, `address`, `phone`,
`offline_access` — are always allowed, even for clients with a scope
allowlist. Real identity providers accept them from any OIDC client and every
OIDC library requests some of them by default, so a client restricted to
`scopes: [read]` would otherwise reject every login. The other rules are
unchanged. Behavior change: requests that got `invalid_scope` for these
scopes now succeed; nothing that succeeded before changes.

## CORS

Every response carries `Access-Control-Allow-Origin: *`, and preflight
`OPTIONS` requests get a `204` allowing `GET` and `POST` with whatever request
headers the browser asked for.
SPAs fetch discovery, JWKS, and `/token` cross-origin; none of it relies on
cookies, so the wildcard origin suffices.

## Discovery

Adds `authorization_endpoint`, `authorization_code` in
`grant_types_supported`, `response_modes_supported: ["query"]`,
`subject_types_supported: ["public"]` (required by OIDC Discovery 1.0 §3),
`code_challenge_methods_supported: ["S256", "plain"]` (RFC 9700 §2.1.1), and
`none` in `token_endpoint_auth_methods_supported`.

Fixes `response_types_supported`, which advertised `["token"]` — the implicit
flow TokenDock never supported — to `["code"]`.

## Configuration

- Per-client `redirect_uris` (YAML list; works in `TOKENDOCK_CLIENTS` too). No
  single-client env var, like `subject` and `claims`.
- Global `interactive_login` (default `false`), `TOKENDOCK_INTERACTIVE_LOGIN`,
  and an `interactive-login` action input.
- New action output `authorization-endpoint`.
- The startup log states the authorization endpoint and the login mode.

## Code shape

- `internal/server/authorize.go`: `/authorize` and `/login` handlers, the
  shared request validation, redirect helpers, login page rendering.
- `internal/server/login.html`: the embedded login page, with placeholders
  filled in one `strings.Replacer` pass.
- `internal/server/authcode.go`: the `authorization_code` grant, PKCE
  verification, ID token minting.
- `internal/server/codes.go`: in-memory code store with an injectable clock.
- `internal/server/cors.go`: CORS middleware.
- `internal/server/token.go`: grant dispatch; a `sign` helper split out of
  `mintToken` so ID tokens can use a fixed `typ`; the OIDC scope rule.
- `internal/server/server.go`: routes and discovery fields.
- `internal/config/config.go`: `RedirectURIs`, `InteractiveLogin`, validation.
- `cmd/tokendock/main.go`: startup log lines.

## Testing

- Handler tests: `/authorize` success (code, state, preserved query), each
  non-redirected error, each redirected error, registered-URI rules, POST;
  token grant happy path (sub, aud, scope, claims), `login_hint`, ID token
  (`typ: JWT` with RFC 9068 on, aud, nonce, auth_time, claims), single use,
  wrong client, `redirect_uri` mismatch, PKCE S256/plain/wrong/missing/
  downgrade, public client with only `client_id`; login page render (prefill,
  hidden parameters, escaping), `/login` with a typed subject, `prompt=none`;
  CORS headers and preflight; discovery fields; OIDC scope rule.
- Code store tests with a fake clock: single use, expiry, sweep.
- Config tests: `redirect_uris` parsing and validation, `interactive_login`
  from file, env, and invalid env.
- Integration: PKCE + `openid` flow with the zero-config demo client; access
  and ID tokens validated through the JWKS endpoint only.
- CI dogfood: the same flow driven by `curl` against the built image through
  the composite action.

## Docs

README (intro, endpoints, authorization code section, comparison table and
"choose" lists), `docs/configuration.md` (new fields and env var, authorization
code reference including interactive login and browser-reachable issuers),
`docs/system-under-test.md` (Spring Boot `oauth2Login`, Playwright on the
login page), landing page comparison and copy, action description.

## Out of scope

Refresh tokens, userinfo, `form_post`/fragment response modes, per-user claim
sets, a deny button on the login page, the RFC 9207 `iss` response parameter,
pushed authorization requests, and a `client_id` claim in access tokens.
