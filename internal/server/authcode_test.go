package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// RFC 7636 Appendix B test vector.
const (
	pkceVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	pkceChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

var myService = [2]string{"my-service", "ci-secret"}

// codeForm redeems code with the redirect_uri authParams sends.
func codeForm(code string) url.Values {
	return url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {"https://app.example/callback"},
	}
}

func TestAuthorizationCodeIssuesAccessToken(t *testing.T) {
	ts, key, cfg := testServer(t)
	resp, body := requestToken(t, ts, codeForm(codeFor(t, ts, authParams())), myService)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %+v", resp.StatusCode, body)
	}
	if body.ExpiresIn != 600 {
		t.Errorf("expires_in = %d, want client lifetime 600", body.ExpiresIn)
	}
	if body.Scope != "read write" {
		t.Errorf("scope = %q, want the client's configured scopes", body.Scope)
	}
	if body.IDToken != "" {
		t.Error("id_token issued without the openid scope")
	}
	claims := parseToken(t, body.AccessToken, key)
	if claims["sub"] != "my-service" {
		t.Errorf("sub = %v, want the client's subject", claims["sub"])
	}
	if claims["iss"] != cfg.Issuer || claims["aud"] != "my-api" {
		t.Errorf("iss = %v, aud = %v", claims["iss"], claims["aud"])
	}
	roles, _ := claims["roles"].([]any)
	if len(roles) != 1 || roles[0] != "admin" {
		t.Errorf("roles = %v, want the client's claims", claims["roles"])
	}
}

func TestAuthorizationCodeLoginHintSetsSubject(t *testing.T) {
	ts, key, _ := testServer(t)
	p := authParams()
	p.Set("login_hint", "alice@example.com")
	resp, body := requestToken(t, ts, codeForm(codeFor(t, ts, p)), myService)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %+v", resp.StatusCode, body)
	}
	if claims := parseToken(t, body.AccessToken, key); claims["sub"] != "alice@example.com" {
		t.Errorf("sub = %v, want the login_hint", claims["sub"])
	}
}

func TestAuthorizationCodeOpenIDScopeIssuesIDToken(t *testing.T) {
	ts, key, cfg := testServer(t)
	p := authParams()
	p.Set("scope", "openid profile read") // my-service allows only read/write: OIDC scopes bypass that
	p.Set("nonce", "n-0S6_WzA2Mj")
	p.Set("login_hint", "alice")
	before := time.Now().Unix()
	resp, body := requestToken(t, ts, codeForm(codeFor(t, ts, p)), myService)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %+v", resp.StatusCode, body)
	}
	if body.Scope != "openid profile read" {
		t.Errorf("scope = %q", body.Scope)
	}
	if body.IDToken == "" {
		t.Fatal("id_token missing with the openid scope")
	}

	// RFC 9068 is on, yet the ID token must not claim to be an access token.
	id := parseTokenTyp(t, body.IDToken, key, "JWT")
	if id["iss"] != cfg.Issuer || id["sub"] != "alice" {
		t.Errorf("iss = %v, sub = %v", id["iss"], id["sub"])
	}
	if id["aud"] != "my-service" {
		t.Errorf("aud = %v, want the client ID", id["aud"])
	}
	if id["nonce"] != "n-0S6_WzA2Mj" {
		t.Errorf("nonce = %v", id["nonce"])
	}
	if authTime, _ := id["auth_time"].(float64); int64(authTime) < before {
		t.Errorf("auth_time = %v, want the time of authorization", id["auth_time"])
	}
	roles, _ := id["roles"].([]any)
	if len(roles) != 1 || roles[0] != "admin" {
		t.Errorf("roles = %v, want the client's claims in the ID token", id["roles"])
	}
	if exp, iat := int64(id["exp"].(float64)), int64(id["iat"].(float64)); exp-iat != 600 {
		t.Errorf("exp-iat = %d, want client lifetime 600", exp-iat)
	}
	if access := parseToken(t, body.AccessToken, key); access["sub"] != "alice" {
		t.Errorf("access token sub = %v, want alice", access["sub"])
	}
}

func TestAuthorizationCodeIsSingleUse(t *testing.T) {
	ts, _, _ := testServer(t)
	form := codeForm(codeFor(t, ts, authParams()))
	if resp, body := requestToken(t, ts, form, myService); resp.StatusCode != http.StatusOK {
		t.Fatalf("first redemption: status = %d, body = %+v", resp.StatusCode, body)
	}
	resp, body := requestToken(t, ts, form, myService)
	if resp.StatusCode != http.StatusBadRequest || body.Error != "invalid_grant" {
		t.Errorf("second redemption: status = %d, error = %q, want invalid_grant", resp.StatusCode, body.Error)
	}
}

func TestAuthorizationCodeRejectedRedemptions(t *testing.T) {
	cases := []struct {
		name      string
		form      func(code string) url.Values
		auth      [2]string
		wantError string
	}{
		{"unknown code", func(string) url.Values { return codeForm("not-a-code") }, myService, "invalid_grant"},
		{"missing code", func(string) url.Values {
			f := codeForm("")
			f.Del("code")
			return f
		}, myService, "invalid_request"},
		{"code issued to another client", codeForm, [2]string{"open-client", "open-secret"}, "invalid_grant"},
		{"redirect_uri mismatch", func(code string) url.Values {
			f := codeForm(code)
			f.Set("redirect_uri", "https://app.example/other")
			return f
		}, myService, "invalid_grant"},
		{"redirect_uri missing", func(code string) url.Values {
			f := codeForm(code)
			f.Del("redirect_uri")
			return f
		}, myService, "invalid_grant"},
		{"verifier without challenge", func(code string) url.Values {
			f := codeForm(code)
			f.Set("code_verifier", pkceVerifier)
			return f
		}, myService, "invalid_grant"},
	}
	ts, _, _ := testServer(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := requestToken(t, ts, tc.form(codeFor(t, ts, authParams())), tc.auth)
			if resp.StatusCode != http.StatusBadRequest || body.Error != tc.wantError {
				t.Errorf("status = %d, error = %q, want 400 %s", resp.StatusCode, body.Error, tc.wantError)
			}
		})
	}
}

func TestAuthorizationCodeStillRequiresClientAuth(t *testing.T) {
	ts, _, _ := testServer(t)
	resp, body := requestToken(t, ts, codeForm(codeFor(t, ts, authParams())), [2]string{"my-service", "wrong"})
	if resp.StatusCode != http.StatusUnauthorized || body.Error != "invalid_client" {
		t.Errorf("status = %d, error = %q", resp.StatusCode, body.Error)
	}
}

func TestAuthorizationCodePKCES256PublicClient(t *testing.T) {
	ts, key, _ := testServer(t)
	p := authParams()
	p.Set("client_id", "spa")
	p.Del("redirect_uri") // sole registered URI
	p.Set("code_challenge", pkceChallenge)
	p.Set("code_challenge_method", "S256")
	// A public client authenticates with client_id alone, and needn't repeat
	// a redirect_uri it never sent.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {codeFor(t, ts, p)},
		"client_id":     {"spa"},
		"code_verifier": {pkceVerifier},
	}
	resp, body := requestToken(t, ts, form, [2]string{})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %+v", resp.StatusCode, body)
	}
	if claims := parseToken(t, body.AccessToken, key); claims["sub"] != "spa" {
		t.Errorf("sub = %v", claims["sub"])
	}
}

func TestAuthorizationCodePKCEPlain(t *testing.T) {
	ts, _, _ := testServer(t)
	verifier := strings.Repeat("plain-verifier-", 4)
	p := authParams()
	p.Set("code_challenge", verifier) // no method: plain
	form := codeForm(codeFor(t, ts, p))
	form.Set("code_verifier", verifier)
	if resp, body := requestToken(t, ts, form, myService); resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, body = %+v", resp.StatusCode, body)
	}
}

func TestAuthorizationCodePKCEFailures(t *testing.T) {
	for name, verifier := range map[string]string{
		"wrong verifier":   strings.Repeat("wrong-verifier-", 4),
		"missing verifier": "",
	} {
		t.Run(name, func(t *testing.T) {
			ts, _, _ := testServer(t)
			p := authParams()
			p.Set("code_challenge", pkceChallenge)
			p.Set("code_challenge_method", "S256")
			form := codeForm(codeFor(t, ts, p))
			if verifier != "" {
				form.Set("code_verifier", verifier)
			}
			resp, body := requestToken(t, ts, form, myService)
			if resp.StatusCode != http.StatusBadRequest || body.Error != "invalid_grant" {
				t.Errorf("status = %d, error = %q, want invalid_grant", resp.StatusCode, body.Error)
			}
		})
	}
}
