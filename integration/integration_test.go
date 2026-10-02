// Integration test proving TokenDock's core promise: an application can
// fetch a token from /token and validate it using only the public material
// served at /.well-known/jwks.json — exactly what a JWT middleware does.
package integration_test

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/IAmLuisJ/tokendock/internal/config"
	"github.com/IAmLuisJ/tokendock/internal/keys"
	"github.com/IAmLuisJ/tokendock/internal/server"
)

func TestEndToEndTokenValidationViaJWKS(t *testing.T) {
	cfg, err := config.Load("", func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	key, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(server.New(cfg, key))
	defer ts.Close()

	// Step 1: fetch a token like a CI job would, using the zero-config demo client.
	form := url.Values{"grant_type": {"client_credentials"}}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(config.DemoClientID, config.DemoClientSecret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token request status = %d", resp.StatusCode)
	}
	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		t.Fatal(err)
	}

	// Step 2: validate the token using only the JWKS endpoint, like an app's
	// JWT middleware would.
	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(tokenResp.AccessToken, claims, func(tok *jwt.Token) (any, error) {
		kid, _ := tok.Header["kid"].(string)
		return fetchJWKSKey(ts.URL+"/.well-known/jwks.json", kid)
	})
	if err != nil {
		t.Fatalf("token failed validation against JWKS endpoint: %v", err)
	}
	if claims["iss"] != cfg.Issuer {
		t.Errorf("iss = %v, want %v", claims["iss"], cfg.Issuer)
	}
	if claims["sub"] != config.DemoClientID {
		t.Errorf("sub = %v, want %v", claims["sub"], config.DemoClientID)
	}
}

// TestEndToEndTokenExchange proves the delegation flow: obtain a token via
// client_credentials, exchange it (RFC 8693) for a new token with an actor,
// and validate the result using only the JWKS endpoint.
func TestEndToEndTokenExchange(t *testing.T) {
	cfg, err := config.Load("", func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	key, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(server.New(cfg, key))
	defer ts.Close()

	fetchToken := func(form url.Values) string {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(config.DemoClientID, config.DemoClientSecret)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("token request status = %d", resp.StatusCode)
		}
		var tr struct {
			AccessToken string `json:"access_token"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
			t.Fatal(err)
		}
		return tr.AccessToken
	}

	subject := fetchToken(url.Values{"grant_type": {"client_credentials"}})
	exchanged := fetchToken(url.Values{
		"grant_type":    {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token": {subject},
		"actor_token":   {subject},
	})

	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(exchanged, claims, func(tok *jwt.Token) (any, error) {
		kid, _ := tok.Header["kid"].(string)
		return fetchJWKSKey(ts.URL+"/.well-known/jwks.json", kid)
	})
	if err != nil {
		t.Fatalf("exchanged token failed validation against JWKS: %v", err)
	}
	if claims["sub"] != config.DemoClientID {
		t.Errorf("sub = %v, want %v (carried from subject token)", claims["sub"], config.DemoClientID)
	}
	act, ok := claims["act"].(map[string]any)
	if !ok || act["sub"] != config.DemoClientID {
		t.Errorf("act = %v, want {sub: %v}", claims["act"], config.DemoClientID)
	}
}

// TestEndToEndAuthorizationCodeWithPKCE proves the browser-login flow with the
// zero-config demo client: /authorize redirects straight back with a code,
// /token redeems it with the PKCE verifier, and both the access token and the
// ID token validate using only the JWKS endpoint.
func TestEndToEndAuthorizationCodeWithPKCE(t *testing.T) {
	cfg, err := config.Load("", func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	key, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(server.New(cfg, key))
	defer ts.Close()

	// RFC 7636 Appendix B test vector.
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	const redirectURI = "http://localhost:3000/callback"

	// Step 1: the browser visits /authorize and is sent straight back.
	browser := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := browser.Get(ts.URL + "/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {config.DemoClientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid profile"},
		"state":                 {"af0ifjsldkj"},
		"nonce":                 {"n-0S6_WzA2Mj"},
		"login_hint":            {"alice"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize: status = %d, Location = %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if got := loc.Query().Get("state"); got != "af0ifjsldkj" {
		t.Errorf("state = %q", got)
	}

	// Step 2: the app's backend redeems the code with its PKCE verifier.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {loc.Query().Get("code")},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(config.DemoClientID, config.DemoClientSecret)
	tokenResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer tokenResp.Body.Close()
	if tokenResp.StatusCode != http.StatusOK {
		t.Fatalf("token request status = %d", tokenResp.StatusCode)
	}
	var tokens struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokens); err != nil {
		t.Fatal(err)
	}

	// Step 3: validate both tokens like the app would, via the JWKS endpoint.
	keyFunc := func(tok *jwt.Token) (any, error) {
		kid, _ := tok.Header["kid"].(string)
		return fetchJWKSKey(ts.URL+"/.well-known/jwks.json", kid)
	}
	idClaims := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(tokens.IDToken, idClaims, keyFunc,
		jwt.WithIssuer(cfg.Issuer), jwt.WithAudience(config.DemoClientID)); err != nil {
		t.Fatalf("ID token failed validation against JWKS: %v", err)
	}
	if idClaims["sub"] != "alice" || idClaims["nonce"] != "n-0S6_WzA2Mj" {
		t.Errorf("ID token sub = %v, nonce = %v", idClaims["sub"], idClaims["nonce"])
	}
	accessClaims := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(tokens.AccessToken, accessClaims, keyFunc, jwt.WithIssuer(cfg.Issuer)); err != nil {
		t.Fatalf("access token failed validation against JWKS: %v", err)
	}
	if accessClaims["sub"] != "alice" || accessClaims["scope"] != "openid profile" {
		t.Errorf("access token sub = %v, scope = %v", accessClaims["sub"], accessClaims["scope"])
	}
}

// TestEndToEndRefreshAndUserinfo proves the session-keeping half of a browser
// login with the zero-config demo client: offline_access yields a refresh
// token, refreshing rotates it, and the refreshed access token reads the
// user's profile from the userinfo endpoint advertised by discovery.
func TestEndToEndRefreshAndUserinfo(t *testing.T) {
	cfg, err := config.Load("", func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	key, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(server.New(cfg, key))
	defer ts.Close()

	var discovery struct {
		UserinfoEndpoint string `json:"userinfo_endpoint"`
	}
	getJSON(t, ts.URL+"/.well-known/openid-configuration", &discovery)
	if discovery.UserinfoEndpoint != cfg.Issuer+"/userinfo" {
		t.Fatalf("userinfo_endpoint = %q", discovery.UserinfoEndpoint)
	}

	const redirectURI = "http://localhost:3000/callback"
	browser := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := browser.Get(ts.URL + "/authorize?" + url.Values{
		"response_type": {"code"},
		"client_id":     {config.DemoClientID},
		"redirect_uri":  {redirectURI},
		"scope":         {"openid profile offline_access"},
		"login_hint":    {"alice"},
	}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize: status = %d, Location = %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	type tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		Error        string `json:"error"`
	}
	postToken := func(form url.Values) (int, tokens) {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(config.DemoClientID, config.DemoClientSecret)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var body tokens
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, body
	}

	status, login := postToken(url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {loc.Query().Get("code")},
		"redirect_uri": {redirectURI},
	})
	if status != http.StatusOK || login.RefreshToken == "" {
		t.Fatalf("code redemption: status = %d, body = %+v", status, login)
	}

	refreshForm := func(rt string) url.Values {
		return url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}
	}
	status, refreshed := postToken(refreshForm(login.RefreshToken))
	if status != http.StatusOK || refreshed.RefreshToken == "" || refreshed.RefreshToken == login.RefreshToken {
		t.Fatalf("refresh: status = %d, body = %+v", status, refreshed)
	}
	if status, body := postToken(refreshForm(login.RefreshToken)); status != http.StatusBadRequest || body.Error != "invalid_grant" {
		t.Errorf("reused refresh token: status = %d, error = %q, want invalid_grant", status, body.Error)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+refreshed.AccessToken)
	userResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer userResp.Body.Close()
	var profile map[string]any
	if err := json.NewDecoder(userResp.Body).Decode(&profile); err != nil {
		t.Fatal(err)
	}
	if userResp.StatusCode != http.StatusOK || profile["sub"] != "alice" {
		t.Errorf("userinfo: status = %d, body = %v", userResp.StatusCode, profile)
	}
}

func getJSON(t *testing.T, target string, into any) {
	t.Helper()
	resp, err := http.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
		t.Fatal(err)
	}
}

// TestEndToEndJWTBearerWithClientAssertion proves the RFC 7523 on-behalf-of
// shape with the zero-config demo client: a user's token from another issuer
// is the grant's assertion, the client authenticates with its own JWT instead
// of a secret, and the issued token validates using only the JWKS endpoint.
func TestEndToEndJWTBearerWithClientAssertion(t *testing.T) {
	cfg, err := config.Load("", func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	key, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(server.New(cfg, key))
	defer ts.Close()

	// Neither assertion is signed with anything TokenDock knows.
	sign := func(claims jwt.MapClaims) string {
		tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("not-shared-with-tokendock"))
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion": {sign(jwt.MapClaims{
			"iss": "https://upstream-idp.example", "sub": "alice", "roles": []string{"reader"},
		})},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion": {sign(jwt.MapClaims{
			"iss": config.DemoClientID, "sub": config.DemoClientID, "aud": cfg.Issuer + "/token",
		})},
	}
	resp, err := http.PostForm(ts.URL+"/token", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token request status = %d", resp.StatusCode)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		t.Fatal(err)
	}

	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(tr.AccessToken, claims, func(tok *jwt.Token) (any, error) {
		kid, _ := tok.Header["kid"].(string)
		return fetchJWKSKey(ts.URL+"/.well-known/jwks.json", kid)
	}, jwt.WithIssuer(cfg.Issuer))
	if err != nil {
		t.Fatalf("issued token failed validation against JWKS: %v", err)
	}
	if claims["sub"] != "alice" {
		t.Errorf("sub = %v, want alice (carried from assertion)", claims["sub"])
	}
	if roles, _ := claims["roles"].([]any); len(roles) != 1 || roles[0] != "reader" {
		t.Errorf("roles = %v, want [reader] (carried from assertion)", claims["roles"])
	}
}

// fetchJWKSKey resolves a public key by kid from a live JWKS endpoint,
// independent of the keys package's own encoding.
func fetchJWKSKey(jwksURL, kid string) (*rsa.PublicKey, error) {
	resp, err := http.Get(jwksURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}
	for _, k := range doc.Keys {
		if k.Kid != kid {
			continue
		}
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, err
		}
		e, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, err
		}
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Int64()),
		}, nil
	}
	return nil, fmt.Errorf("kid %q not found in JWKS", kid)
}
