package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/IAmLuisJ/tokendock/internal/keys"
)

// userinfo calls /userinfo with method, sending token as a Bearer credential
// unless it is empty.
func userinfo(t *testing.T, ts *httptest.Server, method, token string) (*http.Response, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, ts.URL+"/userinfo", nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil && err != io.EOF {
		t.Fatalf("decoding response: %v", err)
	}
	return resp, body
}

// accessTokenFor runs the authorization code flow for my-service as alice
// with scope and returns the access token.
func accessTokenFor(t *testing.T, ts *httptest.Server, scope string) string {
	t.Helper()
	p := authParams()
	p.Set("scope", scope)
	p.Set("login_hint", "alice")
	resp, body := requestToken(t, ts, codeForm(codeFor(t, ts, p)), myService)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %+v", resp.StatusCode, body)
	}
	return body.AccessToken
}

func TestUserinfoReturnsSubAndClaimsWithOpenID(t *testing.T) {
	ts, _, _ := testServer(t)
	resp, body := userinfo(t, ts, http.MethodGet, accessTokenFor(t, ts, "openid read"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %v", resp.StatusCode, body)
	}
	if body["sub"] != "alice" {
		t.Errorf("sub = %v, want alice", body["sub"])
	}
	roles, _ := body["roles"].([]any)
	if len(roles) != 1 || roles[0] != "admin" {
		t.Errorf("roles = %v, want the client's claims", body["roles"])
	}
	for _, claim := range []string{"iss", "aud", "exp", "iat", "jti", "scope"} {
		if _, ok := body[claim]; ok {
			t.Errorf("%s = %v, want token-only claims left out", claim, body[claim])
		}
	}
}

func TestUserinfoWithoutOpenIDReturnsOnlySub(t *testing.T) {
	ts, _, _ := testServer(t)
	resp, body := userinfo(t, ts, http.MethodGet, accessTokenFor(t, ts, "read"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %v", resp.StatusCode, body)
	}
	if len(body) != 1 || body["sub"] != "alice" {
		t.Errorf("body = %v, want only sub", body)
	}
}

func TestUserinfoAcceptsPOST(t *testing.T) {
	ts, _, _ := testServer(t)
	resp, body := userinfo(t, ts, http.MethodPost, accessTokenFor(t, ts, "openid"))
	if resp.StatusCode != http.StatusOK || body["sub"] != "alice" {
		t.Errorf("status = %d, body = %v", resp.StatusCode, body)
	}
}

func TestUserinfoAcceptsClientCredentialsToken(t *testing.T) {
	ts, _, _ := testServer(t)
	_, tok := requestToken(t, ts, url.Values{"grant_type": {"client_credentials"}}, myService)
	resp, body := userinfo(t, ts, http.MethodGet, tok.AccessToken)
	if resp.StatusCode != http.StatusOK || body["sub"] != "my-service" {
		t.Errorf("status = %d, body = %v", resp.StatusCode, body)
	}
}

func TestUserinfoWithoutTokenIsUnauthorized(t *testing.T) {
	ts, _, _ := testServer(t)
	resp, _ := userinfo(t, ts, http.MethodGet, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	// RFC 6750 §3.1: no error code when the request had no credentials.
	if got := resp.Header.Get("WWW-Authenticate"); got != `Bearer realm="tokendock"` {
		t.Errorf("WWW-Authenticate = %q", got)
	}
}

func TestUserinfoRejectsInvalidTokens(t *testing.T) {
	ts, key, cfg := testServer(t)
	other, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	valid := func() jwt.MapClaims {
		return jwt.MapClaims{"iss": cfg.Issuer, "sub": "alice", "exp": time.Now().Add(time.Hour).Unix()}
	}
	sign := func(k *keys.Key, claims jwt.MapClaims) string {
		tok, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(k.Private)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	expired, wrongIssuer, noExp := valid(), valid(), valid()
	expired["exp"] = time.Now().Add(-time.Minute).Unix()
	wrongIssuer["iss"] = "https://elsewhere.example"
	delete(noExp, "exp")

	cases := map[string]string{
		"not a JWT":             "garbage",
		"signed by another key": sign(other, valid()),
		"HMAC signed":           makeJWT(t, valid()),
		"expired":               sign(key, expired),
		"wrong issuer":          sign(key, wrongIssuer),
		"no expiry":             sign(key, noExp),
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			resp, body := userinfo(t, ts, http.MethodGet, token)
			if resp.StatusCode != http.StatusUnauthorized || body["error"] != "invalid_token" {
				t.Errorf("status = %d, body = %v, want 401 invalid_token", resp.StatusCode, body)
			}
			if got := resp.Header.Get("WWW-Authenticate"); !strings.HasPrefix(got, `Bearer realm="tokendock", error="invalid_token"`) {
				t.Errorf("WWW-Authenticate = %q", got)
			}
		})
	}
}
