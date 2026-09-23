package server

import (
	"crypto/rand"
	"sync"
	"time"
)

// codeLifetime is how long an authorization code stays redeemable: the
// maximum RFC 6749 §4.1.2 recommends.
const codeLifetime = 10 * time.Minute

// authCode is everything /authorize decided, held until the client redeems
// the code at /token.
type authCode struct {
	clientID        string
	redirectURI     string // as sent to /authorize; empty when omitted
	scopes          []string
	subject         string
	nonce           string
	challenge       string // PKCE code_challenge; empty when none was sent
	challengeMethod string // "S256" or "plain"
	authTime        time.Time
	expiresAt       time.Time
}

// codeStore holds issued authorization codes in memory. Codes are single use
// and short-lived, so a restart simply invalidates outstanding ones.
type codeStore struct {
	mu    sync.Mutex
	codes map[string]*authCode
	now   func() time.Time
}

func newCodeStore() *codeStore {
	return &codeStore{codes: map[string]*authCode{}, now: time.Now}
}

// issue stores grant under a fresh random code and returns the code. Expired
// codes are swept first so unredeemed ones can't pile up.
func (cs *codeStore) issue(grant *authCode) string {
	code := rand.Text()
	cs.mu.Lock()
	defer cs.mu.Unlock()
	now := cs.now()
	for c, g := range cs.codes {
		if now.After(g.expiresAt) {
			delete(cs.codes, c)
		}
	}
	grant.expiresAt = now.Add(codeLifetime)
	cs.codes[code] = grant
	return code
}

// redeem returns the grant for code and deletes it, so every redemption
// attempt consumes the code whether or not the token request succeeds.
func (cs *codeStore) redeem(code string) (*authCode, bool) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	grant, ok := cs.codes[code]
	if !ok {
		return nil, false
	}
	delete(cs.codes, code)
	if cs.now().After(grant.expiresAt) {
		return nil, false
	}
	return grant, true
}
