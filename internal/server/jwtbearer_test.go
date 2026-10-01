package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

const jwtBearerGrant = "urn:ietf:params:oauth:grant-type:jwt-bearer"

func TestJWTBearerCarriesSubjectAndMergesClaims(t *testing.T) {
	ts, key, cfg := testServer(t)
	assertion := makeJWT(t, jwt.MapClaims{
		"iss":    "https://external-idp.example",
		"sub":    "alice",
		"aud":    "somewhere-else",
		"exp":    9999999999,
		"roles":  []string{"user"},
		"tenant": "acme",
	})
	form := url.Values{
		"grant_type": {jwtBearerGrant},
		"assertion":  {assertion},
	}
	resp, body := requestToken(t, ts, form, [2]string{"my-service", "ci-secret"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %+v", resp.StatusCode, body)
	}
	if body.ExpiresIn != 600 {
		t.Errorf("expires_in = %d, want client lifetime 600", body.ExpiresIn)
	}
	if body.Scope != "read write" {
		t.Errorf("scope = %q, want client scopes", body.Scope)
	}

	claims := parseToken(t, body.AccessToken, key)
	if claims["sub"] != "alice" {
		t.Errorf("sub = %v, want alice (carried from assertion)", claims["sub"])
	}
	if claims["iss"] != cfg.Issuer {
		t.Errorf("iss = %v, want %v (never copied from assertion)", claims["iss"], cfg.Issuer)
	}
	if claims["aud"] != "my-api" {
		t.Errorf("aud = %v, want client-configured audience", claims["aud"])
	}
	// The assertion's custom claims win over the client's configured claims.
	roles, _ := claims["roles"].([]any)
	if len(roles) != 1 || roles[0] != "user" {
		t.Errorf("roles = %v, want [user] (assertion wins over client's [admin])", claims["roles"])
	}
	if claims["tenant"] != "acme" {
		t.Errorf("tenant = %v, want acme (from assertion)", claims["tenant"])
	}
	exp, iat := int64(claims["exp"].(float64)), int64(claims["iat"].(float64))
	if exp-iat != 600 {
		t.Errorf("exp-iat = %d, want client lifetime 600 (never copied from assertion)", exp-iat)
	}
	if _, present := claims["act"]; present {
		t.Error("act claim present on a JWT bearer token")
	}
}

func TestJWTBearerResponseHasNoIssuedTokenType(t *testing.T) {
	ts, _, _ := testServer(t)
	form := url.Values{
		"grant_type":    {jwtBearerGrant},
		"assertion":     {makeJWT(t, jwt.MapClaims{"sub": "alice"})},
		"client_id":     {"my-service"},
		"client_secret": {"ci-secret"},
	}
	resp, err := http.PostForm(ts.URL+"/token", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var full map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&full); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %v", resp.StatusCode, full)
	}
	if _, present := full["issued_token_type"]; present {
		t.Errorf("issued_token_type = %v, want absent (token exchange only)", full["issued_token_type"])
	}
	if full["token_type"] != "Bearer" {
		t.Errorf("token_type = %v", full["token_type"])
	}
}

func TestJWTBearerScopeRequestedSubset(t *testing.T) {
	ts, key, _ := testServer(t)
	form := url.Values{
		"grant_type": {jwtBearerGrant},
		"assertion":  {makeJWT(t, jwt.MapClaims{"sub": "alice"})},
		"scope":      {"read"},
	}
	resp, body := requestToken(t, ts, form, [2]string{"my-service", "ci-secret"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %+v", resp.StatusCode, body)
	}
	if body.Scope != "read" {
		t.Errorf("scope = %q, want read", body.Scope)
	}
	claims := parseToken(t, body.AccessToken, key)
	if claims["scope"] != "read" {
		t.Errorf("scope claim = %v", claims["scope"])
	}
}

func TestJWTBearerDisallowedScopeIsInvalidScope(t *testing.T) {
	ts, _, _ := testServer(t)
	form := url.Values{
		"grant_type": {jwtBearerGrant},
		"assertion":  {makeJWT(t, jwt.MapClaims{"sub": "alice"})},
		"scope":      {"admin"},
	}
	resp, body := requestToken(t, ts, form, [2]string{"my-service", "ci-secret"})
	if resp.StatusCode != http.StatusBadRequest || body.Error != "invalid_scope" {
		t.Errorf("status = %d, error = %q", resp.StatusCode, body.Error)
	}
}

func TestJWTBearerMissingAssertionIsInvalidRequest(t *testing.T) {
	ts, _, _ := testServer(t)
	form := url.Values{"grant_type": {jwtBearerGrant}}
	resp, body := requestToken(t, ts, form, [2]string{"my-service", "ci-secret"})
	if resp.StatusCode != http.StatusBadRequest || body.Error != "invalid_request" {
		t.Errorf("status = %d, error = %q", resp.StatusCode, body.Error)
	}
}

func TestJWTBearerMalformedAssertionIsInvalidGrant(t *testing.T) {
	ts, _, _ := testServer(t)
	form := url.Values{
		"grant_type": {jwtBearerGrant},
		"assertion":  {"not-a-jwt-at-all"},
	}
	resp, body := requestToken(t, ts, form, [2]string{"my-service", "ci-secret"})
	if resp.StatusCode != http.StatusBadRequest || body.Error != "invalid_grant" {
		t.Errorf("status = %d, error = %q", resp.StatusCode, body.Error)
	}
}

func TestJWTBearerAssertionWithoutSubIsInvalidGrant(t *testing.T) {
	ts, _, _ := testServer(t)
	form := url.Values{
		"grant_type": {jwtBearerGrant},
		"assertion":  {makeJWT(t, jwt.MapClaims{"tenant": "acme"})},
	}
	resp, body := requestToken(t, ts, form, [2]string{"my-service", "ci-secret"})
	if resp.StatusCode != http.StatusBadRequest || body.Error != "invalid_grant" {
		t.Errorf("status = %d, error = %q", resp.StatusCode, body.Error)
	}
}

func TestJWTBearerStillRequiresClientAuth(t *testing.T) {
	ts, _, _ := testServer(t)
	form := url.Values{
		"grant_type": {jwtBearerGrant},
		"assertion":  {makeJWT(t, jwt.MapClaims{"sub": "alice"})},
	}
	resp, body := requestToken(t, ts, form, [2]string{"my-service", "wrong-secret"})
	if resp.StatusCode != http.StatusUnauthorized || body.Error != "invalid_client" {
		t.Errorf("status = %d, error = %q", resp.StatusCode, body.Error)
	}
}

const clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// clientAssertionForm is a client_credentials request authenticated only by a
// JWT client assertion naming my-service, as private_key_jwt clients send it.
func clientAssertionForm(t *testing.T) url.Values {
	t.Helper()
	return url.Values{
		"grant_type":            {"client_credentials"},
		"client_assertion_type": {clientAssertionType},
		"client_assertion": {makeJWT(t, jwt.MapClaims{
			"iss": "my-service",
			"sub": "my-service",
			"aud": "http://tokendock.test/token",
			"exp": 9999999999,
		})},
	}
}

func TestClientAssertionAuthenticatesWithoutCheckingSecret(t *testing.T) {
	ts, key, _ := testServer(t)
	// my-service has a client_secret configured; the assertion alone suffices.
	resp, body := requestToken(t, ts, clientAssertionForm(t), [2]string{})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %+v", resp.StatusCode, body)
	}
	claims := parseToken(t, body.AccessToken, key)
	if claims["sub"] != "my-service" || claims["aud"] != "my-api" {
		t.Errorf("sub = %v, aud = %v, want my-service's subject and audience", claims["sub"], claims["aud"])
	}
}

func TestClientAssertionWithMatchingClientID(t *testing.T) {
	ts, _, _ := testServer(t)
	form := clientAssertionForm(t)
	form.Set("client_id", "my-service")
	resp, body := requestToken(t, ts, form, [2]string{})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, body = %+v", resp.StatusCode, body)
	}
}

func TestClientAssertionRejectedAsInvalidClient(t *testing.T) {
	cases := map[string]func(url.Values){
		"unknown sub": func(f url.Values) {
			f.Set("client_assertion", makeJWT(t, jwt.MapClaims{"sub": "nobody"}))
		},
		"malformed assertion": func(f url.Values) { f.Set("client_assertion", "garbage") },
		"assertion without sub": func(f url.Values) {
			f.Set("client_assertion", makeJWT(t, jwt.MapClaims{"iss": "my-service"}))
		},
		"missing assertion":        func(f url.Values) { f.Del("client_assertion") },
		"wrong assertion type":     func(f url.Values) { f.Set("client_assertion_type", "urn:example:saml") },
		"missing assertion type":   func(f url.Values) { f.Del("client_assertion_type") },
		"mismatched client_id":     func(f url.Values) { f.Set("client_id", "open-client") },
		"assertion for secretless": func(f url.Values) { f.Set("client_id", "secretless") },
	}
	ts, _, _ := testServer(t)
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			form := clientAssertionForm(t)
			mutate(form)
			resp, body := requestToken(t, ts, form, [2]string{})
			if resp.StatusCode != http.StatusUnauthorized || body.Error != "invalid_client" {
				t.Errorf("status = %d, error = %q, want 401 invalid_client", resp.StatusCode, body.Error)
			}
		})
	}
}

func TestClientAssertionWithAnotherAuthMethodIsInvalidRequest(t *testing.T) {
	ts, _, _ := testServer(t)
	t.Run("basic auth", func(t *testing.T) {
		resp, body := requestToken(t, ts, clientAssertionForm(t), [2]string{"my-service", "ci-secret"})
		if resp.StatusCode != http.StatusBadRequest || body.Error != "invalid_request" {
			t.Errorf("status = %d, error = %q, want 400 invalid_request", resp.StatusCode, body.Error)
		}
	})
	t.Run("client_secret", func(t *testing.T) {
		form := clientAssertionForm(t)
		form.Set("client_secret", "ci-secret")
		resp, body := requestToken(t, ts, form, [2]string{})
		if resp.StatusCode != http.StatusBadRequest || body.Error != "invalid_request" {
			t.Errorf("status = %d, error = %q, want 400 invalid_request", resp.StatusCode, body.Error)
		}
	})
}

// TestJWTBearerWithClientAssertion is the on-behalf-of shape: the user's token
// is the grant's assertion and the client authenticates with its own JWT.
func TestJWTBearerWithClientAssertion(t *testing.T) {
	ts, key, _ := testServer(t)
	form := clientAssertionForm(t)
	form.Set("grant_type", jwtBearerGrant)
	form.Set("assertion", makeJWT(t, jwt.MapClaims{"sub": "alice"}))
	resp, body := requestToken(t, ts, form, [2]string{})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %+v", resp.StatusCode, body)
	}
	claims := parseToken(t, body.AccessToken, key)
	if claims["sub"] != "alice" || claims["aud"] != "my-api" {
		t.Errorf("sub = %v, aud = %v, want alice for my-api", claims["sub"], claims["aud"])
	}
}
