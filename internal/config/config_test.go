package config

import (
	"os"
	"path/filepath"
	"testing"
)

func noEnv(string) (string, bool) { return "", false }

func envFrom(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

func writeTempConfig(t *testing.T, yaml string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestZeroConfigDefaults(t *testing.T) {
	cfg, err := Load("", noEnv)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 8080 {
		t.Errorf("Port = %d, want 8080", cfg.Port)
	}
	if cfg.Issuer != "http://localhost:8080" {
		t.Errorf("Issuer = %q, want http://localhost:8080", cfg.Issuer)
	}
	if !cfg.DemoClient {
		t.Error("DemoClient = false, want true")
	}
	if len(cfg.Clients) != 1 {
		t.Fatalf("len(Clients) = %d, want 1", len(cfg.Clients))
	}
	c := cfg.Clients[0]
	if c.ClientID != "tokendock" || c.ClientSecret != "tokendock-secret" {
		t.Errorf("demo client = %q/%q, want tokendock/tokendock-secret", c.ClientID, c.ClientSecret)
	}
	if c.Subject != "tokendock" {
		t.Errorf("Subject = %q, want tokendock (defaults to client_id)", c.Subject)
	}
	if c.TokenLifetime != 3600 {
		t.Errorf("TokenLifetime = %d, want 3600", c.TokenLifetime)
	}
}

func TestLoadYAMLFile(t *testing.T) {
	path := writeTempConfig(t, `
issuer: http://tokendock:9000
port: 9000
clients:
  - client_id: my-service
    client_secret: ci-secret
    scopes: [read, write]
    audience: my-api
    claims:
      roles: [admin]
`)
	cfg, err := Load(path, noEnv)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Issuer != "http://tokendock:9000" {
		t.Errorf("Issuer = %q", cfg.Issuer)
	}
	if cfg.Port != 9000 {
		t.Errorf("Port = %d", cfg.Port)
	}
	if cfg.DemoClient {
		t.Error("DemoClient = true, want false when clients are configured")
	}
	if len(cfg.Clients) != 1 {
		t.Fatalf("len(Clients) = %d, want 1", len(cfg.Clients))
	}
	c := cfg.Clients[0]
	if c.ClientID != "my-service" || c.Audience != "my-api" {
		t.Errorf("client = %+v", c)
	}
	if c.Subject != "my-service" {
		t.Errorf("Subject = %q, want my-service (defaults to client_id)", c.Subject)
	}
	if c.TokenLifetime != 3600 {
		t.Errorf("TokenLifetime = %d, want default 3600", c.TokenLifetime)
	}
	if got := c.Scopes; len(got) != 2 || got[0] != "read" || got[1] != "write" {
		t.Errorf("Scopes = %v", got)
	}
	roles, ok := c.Claims["roles"].([]any)
	if !ok || len(roles) != 1 || roles[0] != "admin" {
		t.Errorf("Claims[roles] = %v", c.Claims["roles"])
	}
}

func TestEnvOverridesFile(t *testing.T) {
	path := writeTempConfig(t, `
issuer: http://from-file:8080
port: 8081
`)
	cfg, err := Load(path, envFrom(map[string]string{
		"TOKENDOCK_ISSUER": "http://from-env:9999",
		"TOKENDOCK_PORT":   "9999",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Issuer != "http://from-env:9999" {
		t.Errorf("Issuer = %q, want env value", cfg.Issuer)
	}
	if cfg.Port != 9999 {
		t.Errorf("Port = %d, want 9999", cfg.Port)
	}
}

func TestEnvOnlyClient(t *testing.T) {
	cfg, err := Load("", envFrom(map[string]string{
		"TOKENDOCK_CLIENT_ID":     "env-client",
		"TOKENDOCK_CLIENT_SECRET": "env-secret",
		"TOKENDOCK_SCOPES":        "read,write",
		"TOKENDOCK_AUDIENCE":      "env-api",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DemoClient {
		t.Error("DemoClient = true, want false when env client is set")
	}
	if len(cfg.Clients) != 1 {
		t.Fatalf("len(Clients) = %d, want 1", len(cfg.Clients))
	}
	c := cfg.Clients[0]
	if c.ClientID != "env-client" || c.ClientSecret != "env-secret" || c.Audience != "env-api" {
		t.Errorf("client = %+v", c)
	}
	if len(c.Scopes) != 2 || c.Scopes[0] != "read" || c.Scopes[1] != "write" {
		t.Errorf("Scopes = %v", c.Scopes)
	}
}

func TestEnvClientAppendsToFileClients(t *testing.T) {
	path := writeTempConfig(t, `
clients:
  - client_id: file-client
    client_secret: file-secret
`)
	cfg, err := Load(path, envFrom(map[string]string{
		"TOKENDOCK_CLIENT_ID":     "env-client",
		"TOKENDOCK_CLIENT_SECRET": "env-secret",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Clients) != 2 {
		t.Fatalf("len(Clients) = %d, want 2", len(cfg.Clients))
	}
}

func TestIssuerDefaultDerivedFromPort(t *testing.T) {
	path := writeTempConfig(t, `
port: 9000
`)
	cfg, err := Load(path, noEnv)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Issuer != "http://localhost:9000" {
		t.Errorf("Issuer = %q, want http://localhost:9000", cfg.Issuer)
	}
}

func TestClientWithoutSecretIsSecretless(t *testing.T) {
	path := writeTempConfig(t, `
clients:
  - client_id: trusting
`)
	cfg, err := Load(path, noEnv)
	if err != nil {
		t.Fatalf("client without secret should load, got error: %v", err)
	}
	c := cfg.Clients[0]
	if c.ClientSecret != "" {
		t.Errorf("ClientSecret = %q, want empty (secretless)", c.ClientSecret)
	}
	if c.Subject != "trusting" || c.TokenLifetime != 3600 {
		t.Errorf("defaults not applied to secretless client: %+v", c)
	}
}

func TestEnvClientWithoutSecretIsSecretless(t *testing.T) {
	cfg, err := Load("", envFrom(map[string]string{
		"TOKENDOCK_CLIENT_ID": "env-trusting",
	}))
	if err != nil {
		t.Fatalf("env client without secret should load, got error: %v", err)
	}
	if len(cfg.Clients) != 1 || cfg.Clients[0].ClientID != "env-trusting" {
		t.Fatalf("clients = %+v", cfg.Clients)
	}
	if cfg.DemoClient {
		t.Error("DemoClient = true, want false")
	}
}

func TestMissingFileIsError(t *testing.T) {
	if _, err := Load("/nonexistent/config.yaml", noEnv); err == nil {
		t.Error("want error for missing config file, got nil")
	}
}

func TestMalformedYAMLIsError(t *testing.T) {
	path := writeTempConfig(t, "clients: [not: valid: yaml")
	if _, err := Load(path, noEnv); err == nil {
		t.Error("want error for malformed YAML, got nil")
	}
}

func TestInvalidEnvPortIsError(t *testing.T) {
	if _, err := Load("", envFrom(map[string]string{"TOKENDOCK_PORT": "not-a-number"})); err == nil {
		t.Error("want error for non-numeric TOKENDOCK_PORT, got nil")
	}
}
