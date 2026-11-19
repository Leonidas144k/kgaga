package passport

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
)

type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	Use string `json:"use"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

// GetJWKS reads the public key and formats it as a standard JSON Web Key Set.
func GetJWKS(pubPath string) (*JWKS, error) {
	raw, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("invalid PEM public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pubKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("not an Ed25519 public key")
	}

	return JWKSForKey(pubKey)
}

// JWKSForKey publishes the same key used by the verifier.
func JWKSForKey(pubKey ed25519.PublicKey) (*JWKS, error) {
	if len(pubKey) != ed25519.PublicKeySize {
		return nil, errors.New("invalid Ed25519 public key length")
	}
	// Ed25519 public keys are raw 32-byte arrays in JWK 'x' parameter (base64url encoded without padding)
	xEncoded := base64.RawURLEncoding.EncodeToString(pubKey)

	return &JWKS{
		Keys: []JWK{
			{
				Kty: "OKP",
				Crv: "Ed25519",
				Kid: "pangolin-root-1",
				X:   xEncoded,
				Use: "sig",
			},
		},
	}, nil
}
