// Package config loads TokenDock configuration from three layers:
// built-in defaults, an optional YAML file, and TOKENDOCK_* environment
// variables. Later layers override earlier ones.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	DefaultPort          = 8080
	DefaultTokenLifetime = 3600

	DemoClientID     = "tokendock"
	DemoClientSecret = "tokendock-secret"
)

// Client is one OAuth client allowed to request tokens.
type Client struct {
	ClientID      string         `yaml:"client_id"`
	ClientSecret  string         `yaml:"client_secret"`
	Scopes        []string       `yaml:"scopes"`
	Audience      string         `yaml:"audience"`
	Subject       string         `yaml:"subject"`
	TokenLifetime int            `yaml:"token_lifetime"`
	Claims        map[string]any `yaml:"claims"`
}

// Config is the full server configuration after merging all layers.
type Config struct {
	Issuer     string   `yaml:"issuer"`
	Port       int      `yaml:"port"`
	SigningKey string   `yaml:"signing_key"`
	Clients    []Client `yaml:"clients"`

	// DemoClient is true when no clients were configured and the built-in
	// demo client was injected; main logs a loud warning in that case.
	DemoClient bool `yaml:"-"`
}

// EnvLookup matches os.LookupEnv so tests can inject environment values.
type EnvLookup func(key string) (string, bool)

// Load merges defaults, the YAML file at path (skipped when path is empty),
// and environment variables. It validates the result and applies per-client
// defaults (subject, token lifetime).
func Load(path string, env EnvLookup) (*Config, error) {
	cfg := &Config{}

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parsing config file %s: %w", path, err)
		}
	}

	if err := applyEnv(cfg, env); err != nil {
		return nil, err
	}

	if cfg.Port == 0 {
		cfg.Port = DefaultPort
	}
	if cfg.Issuer == "" {
		cfg.Issuer = fmt.Sprintf("http://localhost:%d", cfg.Port)
	}
	if len(cfg.Clients) == 0 {
		cfg.Clients = []Client{{ClientID: DemoClientID, ClientSecret: DemoClientSecret}}
		cfg.DemoClient = true
	}

	for i := range cfg.Clients {
		c := &cfg.Clients[i]
		if c.ClientID == "" {
			return nil, fmt.Errorf("client %d: client_id is required", i)
		}
		// An empty ClientSecret is allowed: that client accepts any secret,
		// so CI never needs the real one. The server logs this at startup.
		if c.Subject == "" {
			c.Subject = c.ClientID
		}
		if c.TokenLifetime == 0 {
			c.TokenLifetime = DefaultTokenLifetime
		}
	}

	return cfg, nil
}

func applyEnv(cfg *Config, env EnvLookup) error {
	if v, ok := env("TOKENDOCK_ISSUER"); ok {
		cfg.Issuer = v
	}
	if v, ok := env("TOKENDOCK_PORT"); ok {
		port, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("TOKENDOCK_PORT %q is not a number: %w", v, err)
		}
		cfg.Port = port
	}
	if v, ok := env("TOKENDOCK_SIGNING_KEY"); ok {
		cfg.SigningKey = v
	}

	// TOKENDOCK_CLIENTS holds an inline YAML/JSON list of clients — the
	// multi-client escape hatch for environments where mounting a config
	// file is awkward (e.g. GitHub Actions service containers).
	if v, ok := env("TOKENDOCK_CLIENTS"); ok {
		var clients []Client
		if err := yaml.Unmarshal([]byte(v), &clients); err != nil {
			return fmt.Errorf("parsing TOKENDOCK_CLIENTS: %w", err)
		}
		cfg.Clients = append(cfg.Clients, clients...)
	}

	id, ok := env("TOKENDOCK_CLIENT_ID")
	if !ok {
		return nil
	}
	client := Client{ClientID: id}
	if v, ok := env("TOKENDOCK_CLIENT_SECRET"); ok {
		client.ClientSecret = v
	}
	if v, ok := env("TOKENDOCK_SCOPES"); ok {
		for _, s := range strings.Split(v, ",") {
			if s = strings.TrimSpace(s); s != "" {
				client.Scopes = append(client.Scopes, s)
			}
		}
	}
	if v, ok := env("TOKENDOCK_AUDIENCE"); ok {
		client.Audience = v
	}
	cfg.Clients = append(cfg.Clients, client)
	return nil
}
