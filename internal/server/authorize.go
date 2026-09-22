package server

import (
	_ "embed"
	"errors"
	"fmt"
	"html"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/IAmLuisJ/tokendock/internal/config"
)

// loginHTML is the interactive login page; renderLogin fills its
// {{placeholders}}.
//
//go:embed login.html
var loginHTML string

// authRequest is a validated RFC 6749 §4.1.1 authorization request.
type authRequest struct {
	client          *config.Client
	redirectURI     string // where the response goes
	sentRedirectURI string // redirect_uri as sent; empty when omitted
	state           string
	scopes          []string
	nonce           string
	loginHint       string
	challenge       string
	challengeMethod string
}

// subject is who the issued tokens are about: the login_hint the client sent
// (or the tester typed), else the client's configured subject.
func (req *authRequest) subject() string {
	if req.loginHint != "" {
		return req.loginHint
	}
	return req.client.Subject
}

// handleAuthorize is the authorization endpoint. By default it approves every
// valid request on the spot, so browser tests have nothing to click; with
// interactive_login it shows a login page instead.
func (s *server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	req, ok := s.parseAuthRequest(w, r)
	if !ok {
		return
	}
	if !s.cfg.InteractiveLogin {
		s.approve(w, r, req)
		return
	}
	// prompt=none forbids showing UI (OIDC Core §3.1.2.1), and TokenDock
	// keeps no login session to satisfy it with.
	if slices.Contains(strings.Fields(r.Form.Get("prompt")), "none") {
		redirectError(w, r, req, "login_required", "interactive login is enabled, so prompt=none cannot succeed")
		return
	}
	renderLogin(w, r, req)
}

// handleLogin receives the login page's form: the original authorization
// request plus the typed subject as login_hint. Headless tests can post here
// directly to skip the page.
func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	req, ok := s.parseAuthRequest(w, r)
	if !ok {
		return
	}
	s.approve(w, r, req)
}

// renderLogin shows the interactive login page. Its form posts the original
// request back to /login as hidden fields, with the subject as login_hint.
// Values only land in element text and quoted attributes, so
// html.EscapeString is all the escaping needed — html/template would add
// ~2 MB to a binary whose selling point is being small.
func renderLogin(w http.ResponseWriter, r *http.Request, req *authRequest) {
	var hidden strings.Builder
	for _, name := range slices.Sorted(maps.Keys(r.Form)) {
		if name == "login_hint" {
			continue
		}
		for _, value := range r.Form[name] {
			fmt.Fprintf(&hidden, "\n    <input type=\"hidden\" name=\"%s\" value=\"%s\">",
				html.EscapeString(name), html.EscapeString(value))
		}
	}
	scopes := strings.Join(req.scopes, " ")
	if scopes == "" {
		scopes = "(none)"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	// One pass over the page: substituted values are never rescanned, so a
	// parameter can't smuggle in a placeholder.
	strings.NewReplacer(
		"{{client_id}}", html.EscapeString(req.client.ClientID),
		"{{hidden_fields}}", hidden.String(),
		"{{subject}}", html.EscapeString(req.subject()),
		"{{scopes}}", html.EscapeString(scopes),
		"{{redirect_uri}}", html.EscapeString(req.redirectURI),
	).WriteString(w, loginHTML)
}

// parseAuthRequest validates an authorization request. When it fails it has
// already responded: to the user agent directly if the client or
// redirect_uri can't be trusted (RFC 6749 §4.1.2.1), otherwise with an error
// redirect back to the client.
func (s *server) parseAuthRequest(w http.ResponseWriter, r *http.Request) (*authRequest, bool) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "malformed request")
		return nil, false
	}
	clientID := r.Form.Get("client_id")
	if clientID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "client_id is required")
		return nil, false
	}
	client := s.findClient(clientID)
	if client == nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "unknown client_id")
		return nil, false
	}
	sent := r.Form.Get("redirect_uri")
	target, err := resolveRedirectURI(client, sent)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return nil, false
	}

	req := &authRequest{
		client:          client,
		redirectURI:     target,
		sentRedirectURI: sent,
		state:           r.Form.Get("state"),
		nonce:           r.Form.Get("nonce"),
		loginHint:       strings.TrimSpace(r.Form.Get("login_hint")),
		challenge:       r.Form.Get("code_challenge"),
		challengeMethod: r.Form.Get("code_challenge_method"),
	}

	// The redirect URI is trusted from here on, so errors go back to it.
	switch r.Form.Get("response_type") {
	case "code":
	case "":
		redirectError(w, r, req, "invalid_request", "response_type is required")
		return nil, false
	default:
		redirectError(w, r, req, "unsupported_response_type", "only response_type=code is supported")
		return nil, false
	}
	scopes, ok := grantScopes(client, r.Form.Get("scope"))
	if !ok {
		redirectError(w, r, req, "invalid_scope", "requested scope not allowed for this client")
		return nil, false
	}
	req.scopes = scopes
	if req.challenge != "" {
		switch req.challengeMethod {
		case "":
			req.challengeMethod = "plain" // RFC 7636 §4.3
		case "plain", "S256":
		default:
			redirectError(w, r, req, "invalid_request", "code_challenge_method must be S256 or plain")
			return nil, false
		}
	}
	return req, true
}

// findClient looks a client up by ID alone: clients don't authenticate at the
// authorization endpoint.
func (s *server) findClient(clientID string) *config.Client {
	for i := range s.cfg.Clients {
		if s.cfg.Clients[i].ClientID == clientID {
			return &s.cfg.Clients[i]
		}
	}
	return nil
}

// resolveRedirectURI picks where the authorization response goes. A client
// without registered redirect_uris accepts any absolute URI; a registered list
// is matched exactly, and a sole entry may be omitted (RFC 6749 §3.1.2.3).
func resolveRedirectURI(client *config.Client, sent string) (string, error) {
	registered := client.RedirectURIs
	if sent == "" {
		if len(registered) == 1 {
			return registered[0], nil
		}
		return "", errors.New("redirect_uri is required")
	}
	if len(registered) > 0 {
		if !slices.Contains(registered, sent) {
			return "", errors.New("redirect_uri is not registered for this client")
		}
		return sent, nil
	}
	if err := config.ValidateRedirectURI(sent); err != nil {
		return "", fmt.Errorf("redirect_uri: %w", err)
	}
	return sent, nil
}

// approve issues an authorization code for req and redirects back with it.
func (s *server) approve(w http.ResponseWriter, r *http.Request, req *authRequest) {
	code := s.codes.issue(&authCode{
		clientID:        req.client.ClientID,
		redirectURI:     req.sentRedirectURI,
		scopes:          req.scopes,
		subject:         req.subject(),
		nonce:           req.nonce,
		challenge:       req.challenge,
		challengeMethod: req.challengeMethod,
		authTime:        time.Now(),
	})
	redirect(w, r, req, url.Values{"code": {code}})
}

// redirectError sends an RFC 6749 §4.1.2.1 error response to the client.
func redirectError(w http.ResponseWriter, r *http.Request, req *authRequest, code, description string) {
	redirect(w, r, req, url.Values{"error": {code}, "error_description": {description}})
}

// redirect sends the user agent back to the client with params and the
// request's state, keeping any query the redirect URI already has.
func redirect(w http.ResponseWriter, r *http.Request, req *authRequest, params url.Values) {
	u, _ := url.Parse(req.redirectURI) // validated by resolveRedirectURI
	q := u.Query()
	for k, v := range params {
		q[k] = v
	}
	if req.state != "" {
		q.Set("state", req.state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}
