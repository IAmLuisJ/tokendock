package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerate(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if k.Private.N.BitLen() != 2048 {
		t.Errorf("key size = %d bits, want 2048", k.Private.N.BitLen())
	}
	if k.KID == "" {
		t.Error("KID is empty")
	}
}

func TestKIDIsDeterministicPerKey(t *testing.T) {
	k1, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	k2, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if k1.KID == k2.KID {
		t.Error("two different keys produced the same KID")
	}
	again, err := FromPrivateKey(k1.Private)
	if err != nil {
		t.Fatal(err)
	}
	if again.KID != k1.KID {
		t.Errorf("KID not deterministic: %q vs %q", again.KID, k1.KID)
	}
}

func TestJWKSRoundTrip(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	data, err := k.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Use string `json:"use"`
			Alg string `json:"alg"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("JWKS is not valid JSON: %v", err)
	}
	if len(doc.Keys) != 1 {
		t.Fatalf("len(keys) = %d, want 1", len(doc.Keys))
	}
	jwk := doc.Keys[0]
	if jwk.Kty != "RSA" || jwk.Use != "sig" || jwk.Alg != "RS256" {
		t.Errorf("jwk header fields = %+v", jwk)
	}
	if jwk.Kid != k.KID {
		t.Errorf("kid = %q, want %q", jwk.Kid, k.KID)
	}

	// Reconstruct the public key from n/e and compare with the original.
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		t.Fatalf("n is not base64url: %v", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		t.Fatalf("e is not base64url: %v", err)
	}
	pub := rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}
	if !pub.Equal(&k.Private.PublicKey) {
		t.Error("public key reconstructed from JWKS does not match original")
	}
}

func writePEM(t *testing.T, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key.pem")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadPEMPKCS1(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	path := writePEM(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(priv))
	k, err := LoadPEM(path)
	if err != nil {
		t.Fatal(err)
	}
	if !k.Private.Equal(priv) {
		t.Error("loaded key does not match written key")
	}
}

func TestLoadPEMPKCS8(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	path := writePEM(t, "PRIVATE KEY", der)
	k, err := LoadPEM(path)
	if err != nil {
		t.Fatal(err)
	}
	if !k.Private.Equal(priv) {
		t.Error("loaded key does not match written key")
	}
}

func TestLoadPEMMissingFileIsError(t *testing.T) {
	if _, err := LoadPEM("/nonexistent/key.pem"); err == nil {
		t.Error("want error for missing file, got nil")
	}
}

func TestLoadPEMGarbageIsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPEM(path); err == nil {
		t.Error("want error for invalid PEM, got nil")
	}
}
