package server

import (
	"net/http"

	"github.com/IAmLuisJ/tokendock/internal/config"
)

const (
	grantTypeJWTBearer           = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	clientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

// authenticateAssertion implements RFC 7523 §2.2 client authentication
// (private_key_jwt and client_secret_jwt) with test-double leniency: the
// assertion's sub names a configured client, and neither its signature nor
// that client's secret is checked. On failure it writes the error response
// and returns false.
func (s *server) authenticateAssertion(w http.ResponseWriter, r *http.Request) (*config.Client, bool) {
	if _, _, basic := r.BasicAuth(); basic || r.PostFormValue("client_secret") != "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "use only one client authentication method")
		return nil, false
	}
	if r.PostFormValue("client_assertion_type") != clientAssertionTypeJWTBearer {
		writeInvalidClient(w, "client_assertion_type must be "+clientAssertionTypeJWTBearer)
		return nil, false
	}
	_, sub, err := parseUnverified(r.PostFormValue("client_assertion"))
	if err != nil {
		writeInvalidClient(w, "client_assertion: "+err.Error())
		return nil, false
	}
	if id := r.PostFormValue("client_id"); id != "" && id != sub {
		writeInvalidClient(w, "client_id does not match the client_assertion sub")
		return nil, false
	}
	client := s.findClient(sub)
	if client == nil {
		writeInvalidClient(w, "client_assertion sub is not a configured client")
		return nil, false
	}
	return client, true
}

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
