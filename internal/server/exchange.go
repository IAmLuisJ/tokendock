package server

import (
	"net/http"

	"github.com/golang-jwt/jwt/v5"

	"github.com/IAmLuisJ/tokendock/internal/config"
)

const grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"

// registeredClaims are stamped by the server and never copied from a
// subject token into the issued token.
var registeredClaims = map[string]bool{
	"iss": true, "sub": true, "aud": true, "exp": true,
	"iat": true, "nbf": true, "jti": true, "scope": true, "act": true,
}

// handleTokenExchange implements RFC 8693 with test-double leniency: the
// subject and actor tokens must be well-formed JWTs, but their signatures
// and expiry are deliberately not verified.
func (s *server) handleTokenExchange(w http.ResponseWriter, r *http.Request, client *config.Client) {
	subjectRaw := r.PostFormValue("subject_token")
	if subjectRaw == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "subject_token is required")
		return
	}
	subjectClaims, subjectSub, err := parseUnverified(subjectRaw)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "subject_token: "+err.Error())
		return
	}

	var act map[string]any
	if actorRaw := r.PostFormValue("actor_token"); actorRaw != "" {
		_, actorSub, err := parseUnverified(actorRaw)
		if err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "actor_token: "+err.Error())
			return
		}
		act = map[string]any{"sub": actorSub}
	}

	scopes, ok := grantScopes(client, r.PostFormValue("scope"))
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "requested scope not allowed for this client")
		return
	}

	audience := r.PostFormValue("audience")
	if audience == "" {
		audience = client.Audience
	}

	// Client's configured claims first, subject's custom claims win.
	merged := map[string]any{}
	for k, v := range client.Claims {
		merged[k] = v
	}
	for k, v := range subjectClaims {
		if !registeredClaims[k] {
			merged[k] = v
		}
	}

	token, err := s.mintToken(tokenSpec{
		subject:  subjectSub,
		audience: audience,
		lifetime: client.TokenLifetime,
		scopes:   scopes,
		claims:   merged,
		act:      act,
	})
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to sign token")
		return
	}
	writeTokenResponse(w, token, client.TokenLifetime, scopes, map[string]any{
		"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
	})
}

// parseUnverified decodes a JWT without checking its signature and returns
// its claims and required sub.
func parseUnverified(raw string) (jwt.MapClaims, string, error) {
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(raw, claims); err != nil {
		return nil, "", err
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, "", jwt.ErrTokenRequiredClaimMissing
	}
	return claims, sub, nil
}
