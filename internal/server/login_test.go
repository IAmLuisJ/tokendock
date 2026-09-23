package server

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/IAmLuisJ/tokendock/internal/config"
)

func interactive(cfg *config.Config) { cfg.InteractiveLogin = true }

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestInteractiveLoginRendersPage(t *testing.T) {
	ts, _, _ := testServerWith(t, interactive)
	p := authParams()
	p.Set("scope", "openid read")
	p.Set("nonce", "n-123")
	resp := authorize(t, ts, p)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want the 200 login page", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	page := readBody(t, resp)
	for _, want := range []string{
		`<form method="post" action="login">`,
		`name="login_hint" value="my-service"`, // prefilled with the client's subject
		`<input type="hidden" name="state" value="xyz">`,
		`<input type="hidden" name="nonce" value="n-123">`,
		`<input type="hidden" name="scope" value="openid read">`,
		`<input type="hidden" name="client_id" value="my-service">`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("page missing %s", want)
		}
	}
}

func TestInteractiveLoginPrefillsLoginHint(t *testing.T) {
	ts, _, _ := testServerWith(t, interactive)
	p := authParams()
	p.Set("login_hint", "alice")
	page := readBody(t, authorize(t, ts, p))
	if !strings.Contains(page, `name="login_hint" value="alice"`) {
		t.Error("subject field not prefilled from login_hint")
	}
	if strings.Contains(page, `type="hidden" name="login_hint"`) {
		t.Error("login_hint duplicated as a hidden field")
	}
}

func TestInteractiveLoginEscapesReflectedParameters(t *testing.T) {
	ts, _, _ := testServerWith(t, interactive)
	p := authParams()
	p.Set("state", `"><script>alert(1)</script>`)
	page := readBody(t, authorize(t, ts, p))
	if !strings.Contains(page, `name="state"`) {
		t.Fatal("state not carried on the login page at all")
	}
	if strings.Contains(page, "<script>") {
		t.Error("state reflected into the login page unescaped")
	}
}

func TestInteractiveLoginSubmitIssuesCodeForTypedSubject(t *testing.T) {
	ts, key, _ := testServerWith(t, interactive)
	// What the browser posts: the hidden fields plus the typed subject.
	form := authParams()
	form.Set("login_hint", "bob")
	resp, err := noRedirects.PostForm(ts.URL+"/login", form)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	q := redirectParams(t, resp, "https://app.example/callback")
	if q.Get("state") != "xyz" {
		t.Errorf("state = %q, want xyz", q.Get("state"))
	}
	_, body := requestToken(t, ts, codeForm(q.Get("code")), myService)
	if claims := parseToken(t, body.AccessToken, key); claims["sub"] != "bob" {
		t.Errorf("sub = %v, want the typed subject bob", claims["sub"])
	}
}

func TestInteractiveLoginPromptNoneIsLoginRequired(t *testing.T) {
	ts, _, _ := testServerWith(t, interactive)
	p := authParams()
	p.Set("prompt", "none")
	q := redirectParams(t, authorize(t, ts, p), "https://app.example/callback")
	if q.Get("error") != "login_required" {
		t.Errorf("error = %q, want login_required", q.Get("error"))
	}
	if q.Get("state") != "xyz" {
		t.Errorf("state = %q, want xyz", q.Get("state"))
	}
}

func TestInteractiveLoginStillRejectsUnknownClient(t *testing.T) {
	ts, _, _ := testServerWith(t, interactive)
	p := authParams()
	p.Set("client_id", "nobody")
	assertNotRedirected(t, authorize(t, ts, p), "invalid_request")
}
