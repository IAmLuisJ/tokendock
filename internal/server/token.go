package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/IAmLuisJ/tokendock/internal/config"
)

func (s *server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}

	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.PostFormValue("client_id")
		clientSecret = r.PostFormValue("client_secret")
	}
	client := s.authenticate(clientID, clientSecret)
	if client == nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="tokendock"`)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}

	switch grantType := r.PostFormValue("grant_type"); grantType {
	case "client_credentials":
	case "":
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "grant_type is required")
		return
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "only client_credentials is supported")
		return
	}

	scopes, ok := grantScopes(client, r.PostFormValue("scope"))
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "requested scope not allowed for this client")
		return
	}

	token, err := s.mintToken(client, scopes)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to sign token")
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	body := map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   client.TokenLifetime,
	}
	if len(scopes) > 0 {
		body["scope"] = strings.Join(scopes, " ")
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *server) authenticate(clientID, clientSecret string) *config.Client {
	for i := range s.cfg.Clients {
		c := &s.cfg.Clients[i]
		idMatch := subtle.ConstantTimeCompare([]byte(c.ClientID), []byte(clientID)) == 1
		// A client configured without a secret accepts any secret, so tests
		// never need the real credential.
		secretMatch := c.ClientSecret == "" ||
			subtle.ConstantTimeCompare([]byte(c.ClientSecret), []byte(clientSecret)) == 1
		if idMatch && secretMatch {
			return c
		}
	}
	return nil
}

// grantScopes resolves the scopes for a token request: no requested scope
// grants the client's configured scopes; a client with no configured scopes
// allows any request; otherwise every requested scope must be configured.
func grantScopes(client *config.Client, requested string) ([]string, bool) {
	if requested == "" {
		return client.Scopes, true
	}
	scopes := strings.Fields(requested)
	if len(client.Scopes) == 0 {
		return scopes, true
	}
	for _, s := range scopes {
		if !slices.Contains(client.Scopes, s) {
			return nil, false
		}
	}
	return scopes, true
}

func (s *server) mintToken(client *config.Client, scopes []string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{}
	for k, v := range client.Claims {
		claims[k] = v
	}
	claims["iss"] = s.cfg.Issuer
	claims["sub"] = client.Subject
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(time.Duration(client.TokenLifetime) * time.Second).Unix()
	claims["jti"] = newJTI()
	if len(scopes) > 0 {
		claims["scope"] = strings.Join(scopes, " ")
	}
	if client.Audience != "" {
		claims["aud"] = client.Audience
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.key.KID
	return token.SignedString(s.key.Private)
}

func newJTI() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{
		"error":             code,
		"error_description": description,
	})
}
