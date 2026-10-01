package server

import (
	"net/http"
	"slices"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// handleUserinfo implements the OpenID Connect UserInfo endpoint (Core §5.3).
// The bearer token must be one TokenDock signed. The response always carries
// sub; the token's custom claims — the client's configured claims, or those
// carried over by token exchange — are added when the token has the openid
// scope.
func (s *server) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || raw == "" {
		// RFC 6750 §3.1: no error code when the request had no credentials.
		w.Header().Set("WWW-Authenticate", `Bearer realm="tokendock"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(raw, claims,
		func(*jwt.Token) (any, error) { return &s.key.Private.PublicKey, nil },
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(s.cfg.Issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="tokendock", error="invalid_token"`)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", err.Error())
		return
	}

	body := map[string]any{"sub": claims["sub"]}
	scope, _ := claims["scope"].(string)
	if slices.Contains(strings.Fields(scope), "openid") {
		for k, v := range claims {
			if !registeredClaims[k] {
				body[k] = v
			}
		}
	}
	writeJSON(w, http.StatusOK, body)
}
