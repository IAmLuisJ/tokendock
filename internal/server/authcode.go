package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/IAmLuisJ/tokendock/internal/config"
)

// handleAuthorizationCode redeems a code from /authorize (RFC 6749 §4.1.3)
// for an access token, plus an OpenID Connect ID token when the openid scope
// was granted.
func (s *server) handleAuthorizationCode(w http.ResponseWriter, r *http.Request, client *config.Client) {
	code := r.PostFormValue("code")
	if code == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code is required")
		return
	}
	grant, ok := s.codes.redeem(code)
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid, expired, or already used")
		return
	}
	if grant.clientID != client.ClientID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code was issued to another client")
		return
	}
	if grant.redirectURI != "" && r.PostFormValue("redirect_uri") != grant.redirectURI {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match the authorization request")
		return
	}
	if err := verifyPKCE(grant, r.PostFormValue("code_verifier")); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		return
	}

	token, err := s.mintToken(tokenSpec{
		subject:  grant.subject,
		audience: client.Audience,
		lifetime: client.TokenLifetime,
		scopes:   grant.scopes,
		claims:   client.Claims,
	})
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to sign token")
		return
	}
	var extra map[string]any
	if slices.Contains(grant.scopes, "openid") {
		idToken, err := s.mintIDToken(grant, client)
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to sign ID token")
			return
		}
		extra = map[string]any{"id_token": idToken}
	}
	writeTokenResponse(w, token, client.TokenLifetime, grant.scopes, extra)
}

// verifyPKCE checks the RFC 7636 code_verifier against the challenge stored
// with the code. A verifier for a code issued without a challenge is rejected
// too, as RFC 9700 §4.8.2 requires against PKCE downgrade.
func verifyPKCE(grant *authCode, verifier string) error {
	if grant.challenge == "" {
		if verifier != "" {
			return errors.New("code_verifier sent but the authorization request had no code_challenge")
		}
		return nil
	}
	if verifier == "" {
		return errors.New("code_verifier is required")
	}
	computed := verifier
	if grant.challengeMethod == "S256" {
		sum := sha256.Sum256([]byte(verifier))
		computed = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	if subtle.ConstantTimeCompare([]byte(computed), []byte(grant.challenge)) != 1 {
		return errors.New("code_verifier does not match code_challenge")
	}
	return nil
}

// mintIDToken issues the OpenID Connect ID token for a redeemed code. Its typ
// is always "JWT": RFC 9068 (§2.1, §5) reserves at+jwt for access tokens so
// validators can refuse an ID token presented as a bearer token.
func (s *server) mintIDToken(grant *authCode, client *config.Client) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{}
	for k, v := range client.Claims {
		claims[k] = v
	}
	claims["iss"] = s.cfg.Issuer
	claims["sub"] = grant.subject
	claims["aud"] = client.ClientID
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(time.Duration(client.TokenLifetime) * time.Second).Unix()
	claims["auth_time"] = grant.authTime.Unix()
	if grant.nonce != "" {
		claims["nonce"] = grant.nonce
	}
	return s.sign(claims, "JWT")
}
