package passport

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type AgentClaims struct {
	AgentID string   `json:"agent_id"`
	Owner   string   `json:"owner"`
	Scopes  []string `json:"scopes"`
	jwt.RegisteredClaims
}

func GenerateKeyPair(privPath, pubPath string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
		return err
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	return os.WriteFile(pubPath, pubPEM, 0644)
}

func loadPrivateKey(privPath string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(privPath)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("invalid PEM private key")
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	privKey, ok := parsedKey.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("key is not Ed25519")
	}

	return privKey, nil
}

func Mint(privPath, agentID, owner string, scopes []string, ttl time.Duration) (string, error) {
	privKey, err := loadPrivateKey(privPath)
	if err != nil {
		return "", err
	}

	now := time.Now()
	claims := AgentClaims{
		AgentID: agentID,
		Owner:   owner,
		Scopes:  scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "pangolin-ca",
			Subject:   agentID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	return token.SignedString(privKey)
}

func LoadPublicKey(pubPath string) (ed25519.PublicKey, error) {
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
		return nil, errors.New("public key is not Ed25519")
	}
	return pubKey, nil
}

func Verify(tokenStr string, pubKey ed25519.PublicKey) (*AgentClaims, error) {
	if len(pubKey) != ed25519.PublicKeySize {
		return nil, errors.New("invalid Ed25519 public key length")
	}
	claims := &AgentClaims{}
	token, err := jwt.ParseWithClaims(
		tokenStr,
		claims,
		func(t *jwt.Token) (any, error) { return pubKey, nil },
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithIssuer("pangolin-ca"),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("invalid agent passport: %w", err)
	}
	if token == nil || !token.Valid {
		return nil, errors.New("invalid agent passport")
	}
	return claims, nil
}
