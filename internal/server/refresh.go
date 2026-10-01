package server

import (
	"net/http"
	"slices"
	"strings"

	"github.com/IAmLuisJ/tokendock/internal/config"
)

// issueRefreshToken stores grant as a new refresh token. The nonce and PKCE
// challenge belonged to the original authorization request, so they are not
// carried forward.
func (s *server) issueRefreshToken(grant *authCode) string {
	return s.refreshTokens.issue(&authCode{
		clientID: grant.clientID,
		scopes:   grant.scopes,
		subject:  grant.subject,
		authTime: grant.authTime,
	})
}

// handleRefreshToken implements RFC 6749 §6. Refresh tokens rotate: every
// redemption attempt consumes the token, and a successful one returns a new
// refresh token with the original scope.
func (s *server) handleRefreshToken(w http.ResponseWriter, r *http.Request, client *config.Client) {
	refreshToken := r.PostFormValue("refresh_token")
	if refreshToken == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}
	grant, ok := s.refreshTokens.redeem(refreshToken)
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token is invalid, expired, or already used")
		return
	}
	if grant.clientID != client.ClientID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token was issued to another client")
		return
	}

	// The access token may narrow the scope; the rotated refresh token keeps
	// the original one.
	scopes := grant.scopes
	if requested := r.PostFormValue("scope"); requested != "" {
		scopes = strings.Fields(requested)
		for _, scope := range scopes {
			if !slices.Contains(grant.scopes, scope) {
				writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "requested scope exceeds the scope originally granted")
				return
			}
		}
	}

	token, err := s.mintToken(tokenSpec{
		subject:  grant.subject,
		audience: client.Audience,
		lifetime: client.TokenLifetime,
		scopes:   scopes,
		claims:   client.Claims,
	})
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to sign token")
		return
	}
	extra := map[string]any{"refresh_token": s.issueRefreshToken(grant)}
	if slices.Contains(scopes, "openid") {
		idToken, err := s.mintIDToken(grant, client)
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to sign ID token")
			return
		}
		extra["id_token"] = idToken
	}
	writeTokenResponse(w, token, client.TokenLifetime, scopes, extra)
}
