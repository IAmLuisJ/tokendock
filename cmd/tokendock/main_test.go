package main

import (
	"testing"

	"github.com/IAmLuisJ/tokendock/internal/config"
)

// A slow or stalled client must not hold a connection open forever, so the
// server is built with header/read/write deadlines rather than using the
// zero-value http.Server defaults.
func TestHTTPServerHasTimeouts(t *testing.T) {
	srv := newHTTPServer(&config.Config{Port: 8080}, nil)

	if srv.Addr != ":8080" {
		t.Errorf("Addr = %q, want :8080", srv.Addr)
	}
	if srv.ReadHeaderTimeout == 0 {
		t.Error("ReadHeaderTimeout is unset: slow-header clients can hold connections open")
	}
	if srv.ReadTimeout == 0 {
		t.Error("ReadTimeout is unset")
	}
	if srv.WriteTimeout == 0 {
		t.Error("WriteTimeout is unset")
	}
	if srv.IdleTimeout == 0 {
		t.Error("IdleTimeout is unset")
	}
}
