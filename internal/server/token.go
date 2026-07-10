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
		s.handleClientCredentials(w, r, client)
	case grantTypeTokenExchange:
		s.handleTokenExchange(w, r, client)
	case "":
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "grant_type is required")
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "supported: client_credentials, "+grantTypeTokenExchange)
	}
}

func (s *server) handleClientCredentials(w http.ResponseWriter, r *http.Request, client *config.Client) {
	scopes, ok := grantScopes(client, r.PostFormValue("scope"))
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "requested scope not allowed for this client")
		return
	}

	token, err := s.mintToken(tokenSpec{
		subject:  client.Subject,
		audience: client.Audience,
		lifetime: client.TokenLifetime,
		scopes:   scopes,
		claims:   client.Claims,
	})
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to sign token")
		return
	}
	writeTokenResponse(w, token, client.TokenLifetime, scopes, nil)
}

func writeTokenResponse(w http.ResponseWriter, token string, lifetime int, scopes []string, extra map[string]any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	body := map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   lifetime,
	}
	if len(scopes) > 0 {
		body["scope"] = strings.Join(scopes, " ")
	}
	for k, v := range extra {
		body[k] = v
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

// tokenSpec is everything mintToken needs; grant handlers assemble it.
type tokenSpec struct {
	subject  string
	audience string
	lifetime int // seconds
	scopes   []string
	claims   map[string]any // custom claims, already merged by the caller
	act      map[string]any // RFC 8693 actor, nil when not delegating
}

func (s *server) mintToken(spec tokenSpec) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{}
	for k, v := range spec.claims {
		claims[k] = v
	}
	claims["iss"] = s.cfg.Issuer
	claims["sub"] = spec.subject
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(time.Duration(spec.lifetime) * time.Second).Unix()
	claims["jti"] = newJTI()
	if len(spec.scopes) > 0 {
		claims["scope"] = strings.Join(spec.scopes, " ")
	}
	if spec.audience != "" {
		claims["aud"] = spec.audience
	}
	if spec.act != nil {
		claims["act"] = spec.act
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
