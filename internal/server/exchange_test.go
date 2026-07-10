package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

const exchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange"

// makeJWT builds a well-formed JWT for use as a subject/actor token. The
// signature is irrelevant — TokenDock deliberately does not verify it.
func makeJWT(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("irrelevant"))
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestExchangeCarriesSubjectAndMergesClaims(t *testing.T) {
	ts, key, cfg := testServer(t)
	subject := makeJWT(t, jwt.MapClaims{
		"iss":    "https://external-idp.example",
		"sub":    "alice",
		"exp":    9999999999,
		"roles":  []string{"user"},
		"tenant": "acme",
	})
	form := url.Values{
		"grant_type":    {exchangeGrant},
		"subject_token": {subject},
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
		t.Errorf("sub = %v, want alice (carried from subject_token)", claims["sub"])
	}
	if claims["iss"] != cfg.Issuer {
		t.Errorf("iss = %v, want %v (never copied from subject)", claims["iss"], cfg.Issuer)
	}
	if claims["aud"] != "my-api" {
		t.Errorf("aud = %v, want client-configured audience", claims["aud"])
	}
	// Subject's custom claims win over the client's configured claims.
	roles, _ := claims["roles"].([]any)
	if len(roles) != 1 || roles[0] != "user" {
		t.Errorf("roles = %v, want [user] (subject wins over client's [admin])", claims["roles"])
	}
	if claims["tenant"] != "acme" {
		t.Errorf("tenant = %v, want acme (from subject)", claims["tenant"])
	}
	exp, iat := int64(claims["exp"].(float64)), int64(claims["iat"].(float64))
	if exp-iat != 600 {
		t.Errorf("exp-iat = %d, want client lifetime 600 (never copied from subject)", exp-iat)
	}
	if _, present := claims["act"]; present {
		t.Error("act claim present without actor_token")
	}
}

func TestExchangeResponseIssuedTokenType(t *testing.T) {
	ts, _, _ := testServer(t)
	form := url.Values{
		"grant_type":    {exchangeGrant},
		"subject_token": {makeJWT(t, jwt.MapClaims{"sub": "alice"})},
		"client_id":     {"my-service"},
		"client_secret": {"ci-secret"},
	}
	respRaw, err := http.PostForm(ts.URL+"/token", form)
	if err != nil {
		t.Fatal(err)
	}
	defer respRaw.Body.Close()
	var full map[string]any
	if err := json.NewDecoder(respRaw.Body).Decode(&full); err != nil {
		t.Fatal(err)
	}
	if full["issued_token_type"] != "urn:ietf:params:oauth:token-type:access_token" {
		t.Errorf("issued_token_type = %v", full["issued_token_type"])
	}
	if full["token_type"] != "Bearer" {
		t.Errorf("token_type = %v", full["token_type"])
	}
}

func TestExchangeAudienceOverride(t *testing.T) {
	ts, key, _ := testServer(t)
	form := url.Values{
		"grant_type":    {exchangeGrant},
		"subject_token": {makeJWT(t, jwt.MapClaims{"sub": "alice"})},
		"audience":      {"other-api"},
	}
	resp, body := requestToken(t, ts, form, [2]string{"my-service", "ci-secret"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %+v", resp.StatusCode, body)
	}
	claims := parseToken(t, body.AccessToken, key)
	if claims["aud"] != "other-api" {
		t.Errorf("aud = %v, want other-api (request param overrides config)", claims["aud"])
	}
}

func TestExchangeScopeRequestedSubset(t *testing.T) {
	ts, key, _ := testServer(t)
	form := url.Values{
		"grant_type":    {exchangeGrant},
		"subject_token": {makeJWT(t, jwt.MapClaims{"sub": "alice"})},
		"scope":         {"read"},
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

func TestExchangeDisallowedScopeIsInvalidScope(t *testing.T) {
	ts, _, _ := testServer(t)
	form := url.Values{
		"grant_type":    {exchangeGrant},
		"subject_token": {makeJWT(t, jwt.MapClaims{"sub": "alice"})},
		"scope":         {"admin"},
	}
	resp, body := requestToken(t, ts, form, [2]string{"my-service", "ci-secret"})
	if resp.StatusCode != http.StatusBadRequest || body.Error != "invalid_scope" {
		t.Errorf("status = %d, error = %q", resp.StatusCode, body.Error)
	}
}

func TestExchangeActorProducesActClaim(t *testing.T) {
	ts, key, _ := testServer(t)
	form := url.Values{
		"grant_type":    {exchangeGrant},
		"subject_token": {makeJWT(t, jwt.MapClaims{"sub": "alice"})},
		"actor_token":   {makeJWT(t, jwt.MapClaims{"sub": "service-a"})},
	}
	resp, body := requestToken(t, ts, form, [2]string{"my-service", "ci-secret"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %+v", resp.StatusCode, body)
	}
	claims := parseToken(t, body.AccessToken, key)
	act, ok := claims["act"].(map[string]any)
	if !ok || act["sub"] != "service-a" {
		t.Errorf("act = %v, want {sub: service-a}", claims["act"])
	}
}

func TestExchangeMissingSubjectTokenIsInvalidRequest(t *testing.T) {
	ts, _, _ := testServer(t)
	form := url.Values{"grant_type": {exchangeGrant}}
	resp, body := requestToken(t, ts, form, [2]string{"my-service", "ci-secret"})
	if resp.StatusCode != http.StatusBadRequest || body.Error != "invalid_request" {
		t.Errorf("status = %d, error = %q", resp.StatusCode, body.Error)
	}
}

func TestExchangeMalformedSubjectTokenIsInvalidGrant(t *testing.T) {
	ts, _, _ := testServer(t)
	form := url.Values{
		"grant_type":    {exchangeGrant},
		"subject_token": {"not-a-jwt-at-all"},
	}
	resp, body := requestToken(t, ts, form, [2]string{"my-service", "ci-secret"})
	if resp.StatusCode != http.StatusBadRequest || body.Error != "invalid_grant" {
		t.Errorf("status = %d, error = %q", resp.StatusCode, body.Error)
	}
}

func TestExchangeSubjectWithoutSubIsInvalidGrant(t *testing.T) {
	ts, _, _ := testServer(t)
	form := url.Values{
		"grant_type":    {exchangeGrant},
		"subject_token": {makeJWT(t, jwt.MapClaims{"tenant": "acme"})},
	}
	resp, body := requestToken(t, ts, form, [2]string{"my-service", "ci-secret"})
	if resp.StatusCode != http.StatusBadRequest || body.Error != "invalid_grant" {
		t.Errorf("status = %d, error = %q", resp.StatusCode, body.Error)
	}
}

func TestExchangeMalformedActorTokenIsInvalidGrant(t *testing.T) {
	ts, _, _ := testServer(t)
	form := url.Values{
		"grant_type":    {exchangeGrant},
		"subject_token": {makeJWT(t, jwt.MapClaims{"sub": "alice"})},
		"actor_token":   {"garbage"},
	}
	resp, body := requestToken(t, ts, form, [2]string{"my-service", "ci-secret"})
	if resp.StatusCode != http.StatusBadRequest || body.Error != "invalid_grant" {
		t.Errorf("status = %d, error = %q", resp.StatusCode, body.Error)
	}
}

func TestExchangeStillRequiresClientAuth(t *testing.T) {
	ts, _, _ := testServer(t)
	form := url.Values{
		"grant_type":    {exchangeGrant},
		"subject_token": {makeJWT(t, jwt.MapClaims{"sub": "alice"})},
	}
	resp, body := requestToken(t, ts, form, [2]string{"my-service", "wrong-secret"})
	if resp.StatusCode != http.StatusUnauthorized || body.Error != "invalid_client" {
		t.Errorf("status = %d, error = %q", resp.StatusCode, body.Error)
	}
}
