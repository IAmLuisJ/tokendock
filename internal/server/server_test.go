package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/luisjuarez/tokendock/internal/config"
	"github.com/luisjuarez/tokendock/internal/keys"
)

func testServer(t *testing.T) (*httptest.Server, *keys.Key, *config.Config) {
	t.Helper()
	key, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Issuer: "http://tokendock.test",
		Clients: []config.Client{
			{
				ClientID:      "my-service",
				ClientSecret:  "ci-secret",
				Scopes:        []string{"read", "write"},
				Audience:      "my-api",
				Subject:       "my-service",
				TokenLifetime: 600,
				Claims:        map[string]any{"roles": []any{"admin"}},
			},
			{
				ClientID:      "open-client",
				ClientSecret:  "open-secret",
				Subject:       "open-client",
				TokenLifetime: 3600,
			},
		},
	}
	ts := httptest.NewServer(New(cfg, key))
	t.Cleanup(ts.Close)
	return ts, key, cfg
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	Error       string `json:"error"`
}

func requestToken(t *testing.T, ts *httptest.Server, form url.Values, basicAuth [2]string) (*http.Response, tokenResponse) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicAuth[0] != "" {
		req.SetBasicAuth(basicAuth[0], basicAuth[1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	return resp, body
}

func parseToken(t *testing.T, raw string, key *keys.Key) jwt.MapClaims {
	t.Helper()
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(raw, claims, func(tok *jwt.Token) (any, error) {
		if tok.Method.Alg() != "RS256" {
			t.Errorf("alg = %s, want RS256", tok.Method.Alg())
		}
		if kid := tok.Header["kid"]; kid != key.KID {
			t.Errorf("kid = %v, want %s", kid, key.KID)
		}
		return &key.Private.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("token does not verify: %v", err)
	}
	return claims
}

func TestTokenWithBasicAuth(t *testing.T) {
	ts, key, _ := testServer(t)
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"read write"}}
	resp, body := requestToken(t, ts, form, [2]string{"my-service", "ci-secret"})

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %+v", resp.StatusCode, body)
	}
	if body.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", body.TokenType)
	}
	if body.ExpiresIn != 600 {
		t.Errorf("expires_in = %d, want 600", body.ExpiresIn)
	}
	if body.Scope != "read write" {
		t.Errorf("scope = %q, want %q", body.Scope, "read write")
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}

	claims := parseToken(t, body.AccessToken, key)
	if claims["iss"] != "http://tokendock.test" {
		t.Errorf("iss = %v", claims["iss"])
	}
	if claims["sub"] != "my-service" {
		t.Errorf("sub = %v", claims["sub"])
	}
	if claims["aud"] != "my-api" {
		t.Errorf("aud = %v", claims["aud"])
	}
	if claims["scope"] != "read write" {
		t.Errorf("scope claim = %v", claims["scope"])
	}
	if claims["jti"] == nil || claims["jti"] == "" {
		t.Error("jti missing")
	}
	roles, ok := claims["roles"].([]any)
	if !ok || len(roles) != 1 || roles[0] != "admin" {
		t.Errorf("custom claim roles = %v", claims["roles"])
	}
	exp, iat := int64(claims["exp"].(float64)), int64(claims["iat"].(float64))
	if exp-iat != 600 {
		t.Errorf("exp-iat = %d, want 600", exp-iat)
	}
}

func TestTokenWithFormBodyAuth(t *testing.T) {
	ts, _, _ := testServer(t)
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"my-service"},
		"client_secret": {"ci-secret"},
	}
	resp, body := requestToken(t, ts, form, [2]string{})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %+v", resp.StatusCode, body)
	}
	if body.AccessToken == "" {
		t.Error("access_token empty")
	}
}

func TestNoScopeRequestedGrantsConfiguredScopes(t *testing.T) {
	ts, key, _ := testServer(t)
	form := url.Values{"grant_type": {"client_credentials"}}
	resp, body := requestToken(t, ts, form, [2]string{"my-service", "ci-secret"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %+v", resp.StatusCode, body)
	}
	if body.Scope != "read write" {
		t.Errorf("scope = %q, want configured scopes %q", body.Scope, "read write")
	}
	claims := parseToken(t, body.AccessToken, key)
	if claims["scope"] != "read write" {
		t.Errorf("scope claim = %v", claims["scope"])
	}
}

func TestClientWithNoScopesAllowsAnyScope(t *testing.T) {
	ts, _, _ := testServer(t)
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"anything at-all"}}
	resp, body := requestToken(t, ts, form, [2]string{"open-client", "open-secret"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %+v", resp.StatusCode, body)
	}
	if body.Scope != "anything at-all" {
		t.Errorf("scope = %q", body.Scope)
	}
}

func TestNoScopesAtAllOmitsScopeEntirely(t *testing.T) {
	ts, key, _ := testServer(t)
	form := url.Values{"grant_type": {"client_credentials"}}
	resp, body := requestToken(t, ts, form, [2]string{"open-client", "open-secret"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %+v", resp.StatusCode, body)
	}
	if body.Scope != "" {
		t.Errorf("scope = %q, want omitted", body.Scope)
	}
	claims := parseToken(t, body.AccessToken, key)
	if _, present := claims["scope"]; present {
		t.Errorf("scope claim = %v, want absent", claims["scope"])
	}
}

func TestWrongSecretIsInvalidClient(t *testing.T) {
	ts, _, _ := testServer(t)
	form := url.Values{"grant_type": {"client_credentials"}}
	resp, body := requestToken(t, ts, form, [2]string{"my-service", "wrong"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	if body.Error != "invalid_client" {
		t.Errorf("error = %q, want invalid_client", body.Error)
	}
	if resp.Header.Get("WWW-Authenticate") == "" {
		t.Error("WWW-Authenticate header missing on 401")
	}
}

func TestUnknownClientIsInvalidClient(t *testing.T) {
	ts, _, _ := testServer(t)
	form := url.Values{"grant_type": {"client_credentials"}}
	resp, body := requestToken(t, ts, form, [2]string{"nobody", "nothing"})
	if resp.StatusCode != http.StatusUnauthorized || body.Error != "invalid_client" {
		t.Errorf("status = %d, error = %q", resp.StatusCode, body.Error)
	}
}

func TestMissingCredentialsIsInvalidClient(t *testing.T) {
	ts, _, _ := testServer(t)
	form := url.Values{"grant_type": {"client_credentials"}}
	resp, body := requestToken(t, ts, form, [2]string{})
	if resp.StatusCode != http.StatusUnauthorized || body.Error != "invalid_client" {
		t.Errorf("status = %d, error = %q", resp.StatusCode, body.Error)
	}
}

func TestWrongGrantTypeIsUnsupported(t *testing.T) {
	ts, _, _ := testServer(t)
	form := url.Values{"grant_type": {"password"}}
	resp, body := requestToken(t, ts, form, [2]string{"my-service", "ci-secret"})
	if resp.StatusCode != http.StatusBadRequest || body.Error != "unsupported_grant_type" {
		t.Errorf("status = %d, error = %q", resp.StatusCode, body.Error)
	}
}

func TestMissingGrantTypeIsInvalidRequest(t *testing.T) {
	ts, _, _ := testServer(t)
	resp, body := requestToken(t, ts, url.Values{}, [2]string{"my-service", "ci-secret"})
	if resp.StatusCode != http.StatusBadRequest || body.Error != "invalid_request" {
		t.Errorf("status = %d, error = %q", resp.StatusCode, body.Error)
	}
}

func TestUnauthorizedScopeIsInvalidScope(t *testing.T) {
	ts, _, _ := testServer(t)
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"read admin"}}
	resp, body := requestToken(t, ts, form, [2]string{"my-service", "ci-secret"})
	if resp.StatusCode != http.StatusBadRequest || body.Error != "invalid_scope" {
		t.Errorf("status = %d, error = %q", resp.StatusCode, body.Error)
	}
}

func TestTokenEndpointRejectsGET(t *testing.T) {
	ts, _, _ := testServer(t)
	resp, err := http.Get(ts.URL + "/token")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

func TestOpenIDConfiguration(t *testing.T) {
	ts, _, _ := testServer(t)
	resp, err := http.Get(ts.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if doc["issuer"] != "http://tokendock.test" {
		t.Errorf("issuer = %v", doc["issuer"])
	}
	if doc["token_endpoint"] != "http://tokendock.test/token" {
		t.Errorf("token_endpoint = %v", doc["token_endpoint"])
	}
	if doc["jwks_uri"] != "http://tokendock.test/.well-known/jwks.json" {
		t.Errorf("jwks_uri = %v", doc["jwks_uri"])
	}
	grants, _ := doc["grant_types_supported"].([]any)
	if len(grants) != 1 || grants[0] != "client_credentials" {
		t.Errorf("grant_types_supported = %v", doc["grant_types_supported"])
	}
}

func TestJWKSEndpoint(t *testing.T) {
	ts, key, _ := testServer(t)
	resp, err := http.Get(ts.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q", ct)
	}
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Keys) != 1 || doc.Keys[0]["kid"] != key.KID {
		t.Errorf("jwks = %+v", doc)
	}
}

func TestHealth(t *testing.T) {
	ts, _, _ := testServer(t)
	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}
