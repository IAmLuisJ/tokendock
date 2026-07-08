// TokenDock is a fake OAuth 2.0 Authorization Server for CI: it issues
// RS256-signed JWTs via the client credentials grant and serves the JWKS
// and OIDC discovery documents apps need to validate them.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/IAmLuisJ/tokendock/internal/config"
	"github.com/IAmLuisJ/tokendock/internal/keys"
	"github.com/IAmLuisJ/tokendock/internal/server"
)

func main() {
	configPath := flag.String("config", defaultConfigPath(), "path to YAML config file (empty for zero-config defaults)")
	healthcheck := flag.Bool("healthcheck", false, "probe the running server's /health endpoint and exit (for Docker HEALTHCHECK)")
	flag.Parse()

	cfg, err := config.Load(*configPath, os.LookupEnv)
	if err != nil {
		log.Fatalf("tokendock: %v", err)
	}

	if *healthcheck {
		resp, err := http.Get(fmt.Sprintf("http://localhost:%d/health", cfg.Port))
		if err != nil || resp.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		return
	}

	key, err := loadKey(cfg)
	if err != nil {
		log.Fatalf("tokendock: %v", err)
	}

	logStartup(cfg, key)
	addr := fmt.Sprintf(":%d", cfg.Port)
	if err := http.ListenAndServe(addr, server.New(cfg, key)); err != nil {
		log.Fatalf("tokendock: %v", err)
	}
}

// defaultConfigPath returns TOKENDOCK_CONFIG if set, else the conventional
// mount point if a file exists there, else empty (zero-config).
func defaultConfigPath() string {
	if v, ok := os.LookupEnv("TOKENDOCK_CONFIG"); ok {
		return v
	}
	const conventional = "/etc/tokendock/config.yaml"
	if _, err := os.Stat(conventional); err == nil {
		return conventional
	}
	return ""
}

func loadKey(cfg *config.Config) (*keys.Key, error) {
	if cfg.SigningKey != "" {
		return keys.LoadPEM(cfg.SigningKey)
	}
	return keys.Generate()
}

func logStartup(cfg *config.Config, key *keys.Key) {
	log.Printf("issuer: %s", cfg.Issuer)
	log.Printf("token endpoint: %s/token", cfg.Issuer)
	log.Printf("jwks: %s/.well-known/jwks.json", cfg.Issuer)
	if cfg.SigningKey != "" {
		log.Printf("signing key: %s (kid %s)", cfg.SigningKey, key.KID)
	} else {
		log.Printf("signing key: ephemeral RSA-2048 (kid %s)", key.KID)
	}
	for _, c := range cfg.Clients {
		scopes := "any scope"
		if len(c.Scopes) > 0 {
			scopes = strings.Join(c.Scopes, " ")
		}
		log.Printf("client %q (scopes: %s)", c.ClientID, scopes)
	}
	if cfg.DemoClient {
		log.Printf("WARNING: no clients configured — using built-in demo client %q / %q. "+
			"This is for testing only; never expose TokenDock outside CI.",
			config.DemoClientID, config.DemoClientSecret)
	}
	log.Printf("listening on :%d", cfg.Port)
}
