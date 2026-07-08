// Package server implements TokenDock's HTTP endpoints: the client
// credentials token endpoint, OIDC discovery, JWKS, and health.
package server

import (
	"encoding/json"
	"net/http"

	"github.com/luisjuarez/tokendock/internal/config"
	"github.com/luisjuarez/tokendock/internal/keys"
)

type server struct {
	cfg *config.Config
	key *keys.Key
}

// New returns the handler serving all TokenDock endpoints.
func New(cfg *config.Config, key *keys.Key) http.Handler {
	s := &server{cfg: cfg, key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", s.handleToken)
	mux.HandleFunc("GET /.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("GET /.well-known/jwks.json", s.handleJWKS)
	mux.HandleFunc("GET /health", s.handleHealth)
	return mux
}

func (s *server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                s.cfg.Issuer,
		"token_endpoint":                        s.cfg.Issuer + "/token",
		"jwks_uri":                              s.cfg.Issuer + "/.well-known/jwks.json",
		"grant_types_supported":                 []string{"client_credentials"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"token"},
	})
}

func (s *server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	data, err := s.key.JWKS()
	if err != nil {
		http.Error(w, "failed to encode JWKS", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}
