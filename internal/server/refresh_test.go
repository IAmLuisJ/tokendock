package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func refreshForm(refreshToken string) url.Values {
	return url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}
}

// offlineTokens runs the authorization code flow for my-service as alice with
// scope and returns the token response, which must carry a refresh token.
func offlineTokens(t *testing.T, ts *httptest.Server, scope string) tokenResponse {
	t.Helper()
	p := authParams()
	p.Set("scope", scope)
	p.Set("login_hint", "alice")
	p.Set("nonce", "n-0S6_WzA2Mj")
	resp, body := requestToken(t, ts, codeForm(codeFor(t, ts, p)), myService)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %+v", resp.StatusCode, body)
	}
	if body.RefreshToken == "" {
		t.Fatalf("no refresh_token for scope %q", scope)
	}
	return body
}

func TestAuthorizationCodeWithoutOfflineAccessOmitsRefreshToken(t *testing.T) {
	ts, _, _ := testServer(t)
	p := authParams()
	p.Set("scope", "openid read")
	resp, body := requestToken(t, ts, codeForm(codeFor(t, ts, p)), myService)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %+v", resp.StatusCode, body)
	}
	if body.RefreshToken != "" {
		t.Error("refresh_token issued without the offline_access scope")
	}
}

func TestRefreshTokenGrantIssuesNewTokens(t *testing.T) {
	ts, key, cfg := testServer(t)
	first := offlineTokens(t, ts, "read write offline_access")

	resp, body := requestToken(t, ts, refreshForm(first.RefreshToken), myService)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %+v", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if body.Scope != "read write offline_access" {
		t.Errorf("scope = %q, want the original scope", body.Scope)
	}
	if body.ExpiresIn != 600 {
		t.Errorf("expires_in = %d, want client lifetime 600", body.ExpiresIn)
	}
	if body.IDToken != "" {
		t.Error("id_token issued without the openid scope")
	}
	if body.RefreshToken == "" || body.RefreshToken == first.RefreshToken {
		t.Errorf("refresh_token = %q, want a new rotated token", body.RefreshToken)
	}
	claims := parseToken(t, body.AccessToken, key)
	if claims["sub"] != "alice" || claims["iss"] != cfg.Issuer || claims["aud"] != "my-api" {
		t.Errorf("sub = %v, iss = %v, aud = %v", claims["sub"], claims["iss"], claims["aud"])
	}
	roles, _ := claims["roles"].([]any)
	if len(roles) != 1 || roles[0] != "admin" {
		t.Errorf("roles = %v, want the client's claims", claims["roles"])
	}
}

func TestRefreshTokenRotatesOnEveryUse(t *testing.T) {
	ts, _, _ := testServer(t)
	first := offlineTokens(t, ts, "read offline_access")

	resp, second := requestToken(t, ts, refreshForm(first.RefreshToken), myService)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first refresh: status = %d, body = %+v", resp.StatusCode, second)
	}
	resp, body := requestToken(t, ts, refreshForm(first.RefreshToken), myService)
	if resp.StatusCode != http.StatusBadRequest || body.Error != "invalid_grant" {
		t.Errorf("reused refresh token: status = %d, error = %q, want invalid_grant", resp.StatusCode, body.Error)
	}
	if resp, body := requestToken(t, ts, refreshForm(second.RefreshToken), myService); resp.StatusCode != http.StatusOK {
		t.Errorf("rotated refresh token: status = %d, body = %+v", resp.StatusCode, body)
	}
}

func TestRefreshTokenWithOpenIDIssuesIDToken(t *testing.T) {
	ts, key, _ := testServer(t)
	first := offlineTokens(t, ts, "openid offline_access")
	original := parseTokenTyp(t, first.IDToken, key, "JWT")

	resp, body := requestToken(t, ts, refreshForm(first.RefreshToken), myService)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %+v", resp.StatusCode, body)
	}
	if body.IDToken == "" {
		t.Fatal("id_token missing on refresh with the openid scope")
	}
	// OpenID Connect Core §12.2: same iss, sub, aud and auth_time as the
	// original ID token.
	id := parseTokenTyp(t, body.IDToken, key, "JWT")
	for _, claim := range []string{"iss", "sub", "aud", "auth_time"} {
		if id[claim] != original[claim] {
			t.Errorf("%s = %v, want %v from the original ID token", claim, id[claim], original[claim])
		}
	}
	if _, ok := id["nonce"]; ok {
		t.Errorf("nonce = %v, want none on a refreshed ID token", id["nonce"])
	}
}

func TestRefreshTokenNarrowsScope(t *testing.T) {
	ts, key, _ := testServer(t)
	first := offlineTokens(t, ts, "openid read write offline_access")

	form := refreshForm(first.RefreshToken)
	form.Set("scope", "read")
	resp, narrowed := requestToken(t, ts, form, myService)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %+v", resp.StatusCode, narrowed)
	}
	if narrowed.Scope != "read" {
		t.Errorf("scope = %q, want the requested subset", narrowed.Scope)
	}
	if claims := parseToken(t, narrowed.AccessToken, key); claims["scope"] != "read" {
		t.Errorf("access token scope = %v, want read", claims["scope"])
	}
	if narrowed.IDToken != "" {
		t.Error("id_token issued although openid was not requested")
	}

	// RFC 6749 §6: the rotated refresh token keeps the original scope.
	resp, full := requestToken(t, ts, refreshForm(narrowed.RefreshToken), myService)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("second refresh: status = %d, body = %+v", resp.StatusCode, full)
	}
	if full.Scope != "openid read write offline_access" {
		t.Errorf("scope = %q, want the original scope back", full.Scope)
	}
}

func TestRefreshTokenRejectedRequests(t *testing.T) {
	cases := []struct {
		name       string
		form       func(refreshToken string) url.Values
		auth       [2]string
		wantStatus int
		wantError  string
	}{
		{"unknown refresh token", func(string) url.Values { return refreshForm("not-a-token") }, myService, http.StatusBadRequest, "invalid_grant"},
		{"missing refresh token", func(string) url.Values {
			return url.Values{"grant_type": {"refresh_token"}}
		}, myService, http.StatusBadRequest, "invalid_request"},
		{"issued to another client", refreshForm, [2]string{"open-client", "open-secret"}, http.StatusBadRequest, "invalid_grant"},
		{"scope beyond the original", func(rt string) url.Values {
			f := refreshForm(rt)
			f.Set("scope", "read write")
			return f
		}, myService, http.StatusBadRequest, "invalid_scope"},
		{"wrong client secret", refreshForm, [2]string{"my-service", "wrong"}, http.StatusUnauthorized, "invalid_client"},
	}
	ts, _, _ := testServer(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first := offlineTokens(t, ts, "read offline_access")
			resp, body := requestToken(t, ts, tc.form(first.RefreshToken), tc.auth)
			if resp.StatusCode != tc.wantStatus || body.Error != tc.wantError {
				t.Errorf("status = %d, error = %q, want %d %s", resp.StatusCode, body.Error, tc.wantStatus, tc.wantError)
			}
		})
	}
}
