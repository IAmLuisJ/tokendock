// Package keys manages the server's RSA signing key: ephemeral generation,
// loading from PEM, and JWKS encoding of the public half.
package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
)

// Key is the server signing key with its JWKS key ID.
type Key struct {
	Private *rsa.PrivateKey
	KID     string
}

// Generate creates an ephemeral RSA-2048 signing key.
func Generate() (*Key, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generating RSA key: %w", err)
	}
	return FromPrivateKey(priv)
}

// FromPrivateKey wraps an existing private key, deriving its KID as the
// RFC 7638 JWK thumbprint (SHA-256, base64url).
func FromPrivateKey(priv *rsa.PrivateKey) (*Key, error) {
	thumbprintInput, err := json.Marshal(map[string]string{
		"e":   base64URLUint(big.NewInt(int64(priv.PublicKey.E))),
		"kty": "RSA",
		"n":   base64URLUint(priv.PublicKey.N),
	})
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(thumbprintInput)
	return &Key{
		Private: priv,
		KID:     base64.RawURLEncoding.EncodeToString(sum[:]),
	}, nil
}

// LoadPEM reads an RSA private key from a PEM file (PKCS#1 or PKCS#8).
func LoadPEM(path string) (*Key, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading signing key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("signing key %s: no PEM block found", path)
	}

	var priv *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		priv, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("signing key %s: %w", path, err)
		}
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("signing key %s: %w", path, err)
		}
		var ok bool
		if priv, ok = parsed.(*rsa.PrivateKey); !ok {
			return nil, fmt.Errorf("signing key %s: not an RSA key (got %T)", path, parsed)
		}
	default:
		return nil, fmt.Errorf("signing key %s: unsupported PEM block type %q", path, block.Type)
	}

	return FromPrivateKey(priv)
}

// JWKS returns the RFC 7517 JSON Web Key Set for the public key.
func (k *Key) JWKS() ([]byte, error) {
	return json.Marshal(map[string]any{
		"keys": []map[string]string{{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": k.KID,
			"n":   base64URLUint(k.Private.PublicKey.N),
			"e":   base64URLUint(big.NewInt(int64(k.Private.PublicKey.E))),
		}},
	})
}

// base64URLUint encodes a big integer per RFC 7518 (unpadded base64url of
// the big-endian bytes).
func base64URLUint(n *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(n.Bytes())
}
