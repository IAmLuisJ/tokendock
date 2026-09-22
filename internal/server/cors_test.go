package server

import (
	"net/http"
	"net/url"
	"testing"
)

func TestCORSAllowsAnyOrigin(t *testing.T) {
	ts, _, _ := testServer(t)
	for _, path := range []string{"/.well-known/openid-configuration", "/.well-known/jwks.json"} {
		req, err := http.NewRequest(http.MethodGet, ts.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Origin", "http://localhost:3000")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
			t.Errorf("%s: Access-Control-Allow-Origin = %q, want *", path, got)
		}
	}
	resp, _ := requestToken(t, ts, url.Values{"grant_type": {"client_credentials"}}, [2]string{"my-service", "ci-secret"})
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("/token: Access-Control-Allow-Origin = %q, want *", got)
	}
}

func TestCORSPreflight(t *testing.T) {
	ts, _, _ := testServer(t)
	req, err := http.NewRequest(http.MethodOptions, ts.URL+"/token", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "authorization, content-type")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	for header, want := range map[string]string{
		"Access-Control-Allow-Origin":  "*",
		"Access-Control-Allow-Methods": "GET, POST",
		"Access-Control-Allow-Headers": "authorization, content-type",
	} {
		if got := resp.Header.Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
}
