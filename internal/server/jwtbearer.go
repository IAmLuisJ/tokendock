package server

import (
	"net/http"

	"github.com/IAmLuisJ/tokendock/internal/config"
)

const grantTypeJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer"

// handleJWTBearer implements the RFC 7523 §2.1 authorization grant with the
// same leniency as token exchange: the assertion must be a well-formed JWT
// with a sub, but its signature and claims are deliberately not verified.
func (s *server) handleJWTBearer(w http.ResponseWriter, r *http.Request, client *config.Client) {
	assertion := r.PostFormValue("assertion")
	if assertion == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "assertion is required")
		return
	}
	assertionClaims, sub, err := parseUnverified(assertion)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "assertion: "+err.Error())
		return
	}

	scopes, ok := grantScopes(client, r.PostFormValue("scope"))
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "requested scope not allowed for this client")
		return
	}

	token, err := s.mintToken(tokenSpec{
		subject:  sub,
		audience: client.Audience,
		lifetime: client.TokenLifetime,
		scopes:   scopes,
		claims:   overlayClaims(client.Claims, assertionClaims),
	})
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to sign token")
		return
	}
	writeTokenResponse(w, token, client.TokenLifetime, scopes, nil)
}
