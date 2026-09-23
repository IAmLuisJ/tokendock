package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// noRedirects returns redirects instead of following them, so tests can
// inspect authorization responses.
var noRedirects = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// authParams is a valid authorization request for my-service, which has no
// registered redirect URIs.
func authParams() url.Values {
	return url.Values{
		"response_type": {"code"},
		"client_id":     {"my-service"},
		"redirect_uri":  {"https://app.example/callback"},
		"state":         {"xyz"},
	}
}

func authorize(t *testing.T, ts *httptest.Server, params url.Values) *http.Response {
	t.Helper()
	resp, err := noRedirects.Get(ts.URL + "/authorize?" + params.Encode())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// redirectParams asserts resp is a 302 to wantTarget and returns the query
// parameters it carries.
func redirectParams(t *testing.T, resp *http.Response, wantTarget string) url.Values {
	t.Helper()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	params := loc.Query()
	loc.RawQuery = ""
	if loc.String() != wantTarget {
		t.Errorf("redirected to %s, want %s", loc, wantTarget)
	}
	return params
}

// codeFor runs a successful authorization request and returns its code.
func codeFor(t *testing.T, ts *httptest.Server, params url.Values) string {
	t.Helper()
	resp := authorize(t, ts, params)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d, want 302", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect %s", loc)
	}
	return code
}

// assertNotRedirected checks an authorization error went to the user agent
// as JSON rather than to an untrusted redirect URI.
func assertNotRedirected(t *testing.T, resp *http.Response, wantError string) {
	t.Helper()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		t.Errorf("Location = %q, want no redirect", loc)
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decoding error body: %v", err)
	}
	if body.Error != wantError {
		t.Errorf("error = %q, want %q", body.Error, wantError)
	}
}

func TestAuthorizeRedirectsWithCodeAndState(t *testing.T) {
	ts, _, _ := testServer(t)
	p := authParams()
	p.Set("redirect_uri", "https://app.example/callback?tenant=acme")
	q := redirectParams(t, authorize(t, ts, p), "https://app.example/callback")
	if q.Get("code") == "" {
		t.Error("code missing from redirect")
	}
	if q.Get("state") != "xyz" {
		t.Errorf("state = %q, want xyz", q.Get("state"))
	}
	if q.Get("tenant") != "acme" {
		t.Errorf("tenant = %q, want the redirect URI's own query kept", q.Get("tenant"))
	}
}

func TestAuthorizeWithoutStateOmitsIt(t *testing.T) {
	ts, _, _ := testServer(t)
	p := authParams()
	p.Del("state")
	q := redirectParams(t, authorize(t, ts, p), "https://app.example/callback")
	if _, present := q["state"]; present {
		t.Errorf("state = %q, want omitted", q.Get("state"))
	}
}

func TestAuthorizeAcceptsPOST(t *testing.T) {
	ts, _, _ := testServer(t)
	resp, err := noRedirects.PostForm(ts.URL+"/authorize", authParams())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if q := redirectParams(t, resp, "https://app.example/callback"); q.Get("code") == "" {
		t.Error("code missing from redirect")
	}
}

func TestAuthorizePromptNoneAutoApproves(t *testing.T) {
	ts, _, _ := testServer(t)
	p := authParams()
	p.Set("prompt", "none")
	if q := redirectParams(t, authorize(t, ts, p), "https://app.example/callback"); q.Get("code") == "" {
		t.Error("prompt=none should still auto-approve when interactive login is off")
	}
}

func TestAuthorizeRegisteredRedirectURI(t *testing.T) {
	ts, _, _ := testServer(t)
	p := authParams()
	p.Set("client_id", "web-app")
	p.Set("redirect_uri", "https://app.test/alt")
	if q := redirectParams(t, authorize(t, ts, p), "https://app.test/alt"); q.Get("code") == "" {
		t.Error("code missing from redirect")
	}
}

func TestAuthorizeSoleRegisteredRedirectURIMayBeOmitted(t *testing.T) {
	ts, _, _ := testServer(t)
	p := authParams()
	p.Set("client_id", "spa")
	p.Del("redirect_uri")
	if q := redirectParams(t, authorize(t, ts, p), "https://spa.test/cb"); q.Get("code") == "" {
		t.Error("code missing from redirect")
	}
}

func TestAuthorizeRejectsUntrustedRequestsWithoutRedirecting(t *testing.T) {
	cases := map[string]func(url.Values){
		"missing client_id":          func(p url.Values) { p.Del("client_id") },
		"unknown client_id":          func(p url.Values) { p.Set("client_id", "nobody") },
		"missing redirect_uri":       func(p url.Values) { p.Del("redirect_uri") },
		"relative redirect_uri":      func(p url.Values) { p.Set("redirect_uri", "/callback") },
		"redirect_uri with fragment": func(p url.Values) { p.Set("redirect_uri", "https://app.example/cb#x") },
		"unregistered redirect_uri": func(p url.Values) {
			p.Set("client_id", "web-app")
			p.Set("redirect_uri", "https://evil.example/cb")
		},
		"omitted redirect_uri with several registered": func(p url.Values) {
			p.Set("client_id", "web-app")
			p.Del("redirect_uri")
		},
	}
	ts, _, _ := testServer(t)
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := authParams()
			mutate(p)
			assertNotRedirected(t, authorize(t, ts, p), "invalid_request")
		})
	}
}

func TestAuthorizeErrorsRedirectBackToClient(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(url.Values)
		wantError string
	}{
		{"missing response_type", func(p url.Values) { p.Del("response_type") }, "invalid_request"},
		{"implicit response_type", func(p url.Values) { p.Set("response_type", "token") }, "unsupported_response_type"},
		{"disallowed scope", func(p url.Values) { p.Set("scope", "read admin") }, "invalid_scope"},
		{"unknown PKCE method", func(p url.Values) {
			p.Set("code_challenge", "abc")
			p.Set("code_challenge_method", "S512")
		}, "invalid_request"},
	}
	ts, _, _ := testServer(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := authParams()
			tc.mutate(p)
			q := redirectParams(t, authorize(t, ts, p), "https://app.example/callback")
			if q.Get("error") != tc.wantError {
				t.Errorf("error = %q, want %q", q.Get("error"), tc.wantError)
			}
			if q.Get("state") != "xyz" {
				t.Errorf("state = %q, want xyz echoed with the error", q.Get("state"))
			}
			if q.Get("code") != "" {
				t.Error("code issued alongside an error")
			}
		})
	}
}
