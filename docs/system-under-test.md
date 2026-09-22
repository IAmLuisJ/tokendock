# Pointing your app at TokenDock

TokenDock's whole premise is that the **system under test keeps its normal JWT
validation code** — you only point its issuer configuration at TokenDock for
the test run. This guide shows how, per framework.

The pattern is always the same:

1. Your app already validates JWTs against an issuer (it fetches
   `/.well-known/openid-configuration` or a JWKS URL from it).
2. In CI, override *only* the issuer/JWKS URL via environment variables —
   production config stays untouched.
3. The issuer value must be the URL **as your app's container sees it**
   (`http://tokendock:8080` on a compose network, `http://localhost:8080` on
   the host) and must match `TOKENDOCK_ISSUER` exactly.

One exception to "no code changes": apps that validate the JWS `typ` header
strictly may reject TokenDock's default RFC 9068 `at+jwt` tokens. Spring Boot 4
is the common case — set `TOKENDOCK_RFC9068=false` or see
[the Spring Boot 4 section](#spring-boot-4--spring-security-7-rejects-atjwt).

---

## Java Spring Boot (Spring Security)

Spring Security's OAuth2 Resource Server validates bearer JWTs. Your
production `application.yml` points at the real identity provider:

```yaml
# src/main/resources/application.yml — unchanged for tests
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: https://auth.mycompany.com/realms/prod
```

(or the `application.properties` form:)

```properties
spring.security.oauth2.resourceserver.jwt.issuer-uri=https://auth.mycompany.com/realms/prod
```

With `issuer-uri`, Spring fetches `<issuer>/.well-known/openid-configuration`
**at startup**, discovers the JWKS URL, and rejects tokens whose `iss` claim
doesn't match. That's exactly what TokenDock serves — no code changes needed.

### Overriding via environment variables in Docker Compose

Spring Boot's relaxed binding maps `SPRING_SECURITY_OAUTH2_RESOURCESERVER_JWT_ISSUERURI`
onto the property above, so the CI compose file just injects it:

```yaml
# docker-compose.test.yml
services:
  tokendock:
    image: ghcr.io/iamluisj/tokendock:latest
    environment:
      TOKENDOCK_ISSUER: http://tokendock:8080     # how my-app reaches it
      TOKENDOCK_CLIENT_ID: my-service             # secretless: any secret accepted
      TOKENDOCK_AUDIENCE: my-api

  my-app:
    build: .
    depends_on:
      tokendock:
        condition: service_healthy   # issuer-uri is fetched at startup — order matters
    environment:
      SPRING_SECURITY_OAUTH2_RESOURCESERVER_JWT_ISSUERURI: http://tokendock:8080
    ports: ["8081:8080"]
```

Two Spring-specific gotchas:

- **Startup order matters.** Because `issuer-uri` triggers discovery at boot,
  the app must start after TokenDock is healthy. TokenDock's built-in
  HEALTHCHECK makes `condition: service_healthy` work out of the box.
- **Audience validation** is off by default in Spring. If you enable it
  (`spring.security.oauth2.resourceserver.jwt.audiences=my-api`, Boot 3.1+),
  set `TOKENDOCK_AUDIENCE` to the same value.
- **Spring Boot 4 rejects TokenDock's default `typ`** — see the next section.
  Boot 3.x is unaffected.

### Spring Boot 4 / Spring Security 7 rejects `at+jwt`

TokenDock issues RFC 9068 access tokens (`typ: at+jwt`) by default. Spring
Security 7, which Spring Boot 4 ships with, moved `typ` checking into
`JwtTypeValidator` and added it to every default validator chain. That
validator accepts only `JWT`, so a Boot 4 app rejects the token:

```
the given typ value needs to be one of [JWT]
```

**Quickest fix — tell TokenDock to emit `typ: JWT`:**

```yaml
  tokendock:
    environment:
      TOKENDOCK_RFC9068: "false"
```

Nothing else about the token changes, and Boot 3.x apps keep working either
way.

**Or keep RFC 9068 on and teach the app to accept it.** Useful when the app
must accept `at+jwt` in production too. Configuring this is fiddlier than it
looks: a standalone `JwtTypeValidator` bean gets wrapped by Boot and ignored,
and `JwtValidators.createAtJwtValidator()` refuses to start without a
`clientId`. Build the decoder yourself:

```java
@Bean
JwtDecoder jwtDecoder(
        @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuer) {
    var decoder = NimbusJwtDecoder.withIssuerLocation(issuer)
            .validateType(false)   // singular; stop Nimbus pre-checking typ
            .build();
    decoder.setJwtValidator(JwtValidators.createDefaultWithValidators(
            new JwtIssuerValidator(issuer),
            new JwtTypeValidator(List.of("JWT", "at+jwt"))));
    return decoder;
}
```

Declaring that bean replaces Boot's auto-configured decoder, so the default
`typ` validator no longer applies.

### Variant: JWKS URL only (no startup discovery)

If you'd rather not depend on startup-time discovery, point directly at the
JWKS endpoint:

```properties
spring.security.oauth2.resourceserver.jwt.jwk-set-uri=http://tokendock:8080/.well-known/jwks.json
```

(env form: `SPRING_SECURITY_OAUTH2_RESOURCESERVER_JWT_JWKSETURI=…`)

Trade-off: with only `jwk-set-uri`, Spring validates the signature but **not**
the `iss` claim — fine for most CI tests, just know what you're skipping.

### Exercising a protected endpoint in a test

```java
// Any HTTP client works; the test fetches a token like a real service would.
var token = restClient.post()
    .uri("http://tokendock:8080/token")
    .header("Authorization", basic("my-service", "anything")) // secretless
    .body("grant_type=client_credentials&scope=read")
    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
    .retrieve().body(TokenResponse.class);

mockMvc.perform(get("/api/orders")
        .header("Authorization", "Bearer " + token.accessToken()))
    .andExpect(status().isOk());
```

---

## Node.js (jose)

```js
import { createRemoteJWKSet, jwtVerify } from "jose";

const issuer = process.env.OIDC_ISSUER ?? "https://auth.mycompany.com";
const jwks = createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks.json`));

export async function verify(token) {
  const { payload } = await jwtVerify(token, jwks, {
    issuer,
    audience: "my-api",
  });
  return payload;
}
```

`jose` ignores the `typ` header unless you ask for it, so TokenDock's
`at+jwt` tokens verify as-is. To assert RFC 9068 compliance in the test,
add the `typ` option — it then requires the header to be present and match:

```js
const { payload } = await jwtVerify(token, jwks, {
  issuer,
  audience: "my-api",
  typ: "at+jwt",   // fails closed if the token is not an RFC 9068 access token
});
```

Compose override — nothing framework-specific, it's your own env var:

```yaml
  my-app:
    environment:
      OIDC_ISSUER: http://tokendock:8080
```

---

## ASP.NET Core

```csharp
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = builder.Configuration["Oidc:Issuer"];
        options.TokenValidationParameters.ValidAudience = "my-api";
        // TokenDock serves plain HTTP inside the test network. Only an explicit
        // opt-in turns HTTPS metadata off; every other environment keeps it.
        options.RequireHttpsMetadata =
            !builder.Configuration.GetValue<bool>("Oidc:AllowHttpMetadata");
    });
```

Compose override (double underscore maps to the `:` separator):

```yaml
  my-app:
    environment:
      Oidc__Issuer: http://tokendock:8080
      Oidc__AllowHttpMetadata: "true"
```

Avoid `RequireHttpsMetadata = builder.Environment.IsProduction()`: it also
turns HTTPS metadata off in Staging and any other non-Production environment,
where an attacker on the network could swap the signing keys your app
downloads.

`JwtBearer` does not check the `typ` header unless you list the types you
accept, so TokenDock's tokens work unchanged. To require RFC 9068 access
tokens — and reject ID tokens presented as bearer tokens — set `ValidTypes`:

```csharp
options.TokenValidationParameters.ValidTypes = ["at+jwt"];
```

---

## Checklist when it doesn't work

- **`iss` mismatch** — the most common failure. The app's configured issuer,
  the token's `iss` claim, and `TOKENDOCK_ISSUER` must all be the same string.
- **App started before TokenDock** — frameworks that discover at startup
  (Spring's `issuer-uri`) need `depends_on: condition: service_healthy`.
- **Audience rejected** — if your app validates `aud`, set
  `TOKENDOCK_AUDIENCE` (or per-client `audience`) to match.
- **`typ` rejected** (`the given typ value needs to be one of [JWT]`) — the
  app validates the JWS type header and does not accept RFC 9068's `at+jwt`.
  Spring Boot 4 does this by default. Set `TOKENDOCK_RFC9068=false`, or
  [configure the app to accept it](#spring-boot-4--spring-security-7-rejects-atjwt).
- **HTTPS required** — some stacks refuse plain-HTTP issuers outside dev
  profiles (ASP.NET's `RequireHttpsMetadata`); relax that for the test
  environment only.
