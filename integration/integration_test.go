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

	"github.com/luisjuarez/tokendock/internal/config"
	"github.com/luisjuarez/tokendock/internal/keys"
	"github.com/luisjuarez/tokendock/internal/server"
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
