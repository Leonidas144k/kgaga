package passport

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const IssuerV2 = "kgaga-ca"
const PassportTypeV2 = "kgaga-passport+jwt"
const MaxTTL = time.Hour
const maxTokenSize = 16 << 10

// KeyID is the RFC 7638 SHA-256 thumbprint of an Ed25519 OKP public JWK.
func KeyID(key ed25519.PublicKey) (string, error) {
	if len(key) != ed25519.PublicKeySize {
		return "", errors.New("invalid Ed25519 public key length")
	}
	canonical := fmt.Sprintf(`{"crv":"Ed25519","kty":"OKP","x":"%s"}`, base64.RawURLEncoding.EncodeToString(key))
	digest := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

// safeValue restricts identity values to nonempty visible ASCII without spaces.
// Identity values may be propagated in HTTP headers.
func safeValue(s string, max int) bool {
	if len(s) == 0 || len(s) > max {
		return false
	}
	for _, c := range []byte(s) {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}

func ValidateAudience(audience string) error {
	if !safeValue(audience, 512) {
		return errors.New("audience must be a nonempty explicit service identifier")
	}
	return nil
}

// ValidateIdentity validates identity and scope claim syntax.
func ValidateIdentity(agent, owner string, scopes []string) error {
	if !safeValue(agent, 256) || !safeValue(owner, 256) {
		return errors.New("invalid agent or owner identifier")
	}
	if len(scopes) == 0 || len(scopes) > 64 {
		return errors.New("expected 1 to 64 permission scopes")
	}
	seen := make(map[string]bool, len(scopes))
	for _, scope := range scopes {
		if !safeValue(scope, 128) || seen[scope] {
			return errors.New("invalid or duplicate scope")
		}
		seen[scope] = true
	}
	return nil
}

// MintV2 issues an audience-bound passport, with no fallback to the legacy issuer.
func MintV2(privPath, agent, owner string, scopes []string, audience string, ttl time.Duration) (string, error) {
	return mintV2(privPath,agent,owner,scopes,audience,ttl,nil)
}

// MintBoundV2 binds a passport to an independently held Ed25519 key.
func MintBoundV2(privPath, agent, owner string, scopes []string, audience string, ttl time.Duration, holder ed25519.PublicKey) (string,error) {
	id,err:=KeyID(holder)
	if err!=nil { return "",err }
	return mintV2(privPath,agent,owner,scopes,audience,ttl,&Confirmation{Thumbprint:id})
}

func mintV2(privPath, agent, owner string, scopes []string, audience string, ttl time.Duration, confirmation *Confirmation) (string,error) {
	if err := ValidateAudience(audience); err != nil {
		return "", err
	}
	if err := ValidateIdentity(agent, owner, scopes); err != nil {
		return "", err
	}
	if ttl < time.Second || ttl > MaxTTL {
		return "", errors.New("passport TTL must be between 1 second and 1 hour")
	}
	key, err := loadPrivateKey(privPath)
	if err != nil {
		return "", err
	}
	kid, err := KeyID(key.Public().(ed25519.PublicKey))
	if err != nil {
		return "", err
	}
	if confirmation!=nil && confirmation.Thumbprint==kid { return "",errors.New("holder and issuer keys must differ") }
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return "", err
	}
	now := time.Now().UTC().Truncate(time.Second)
	claims := AgentClaims{
		Confirmation:confirmation,
		AgentID: agent, Owner: owner, Scopes: append([]string(nil), scopes...),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: IssuerV2, Subject: agent, Audience: jwt.ClaimStrings{audience},
			ID: hex.EncodeToString(id), IssuedAt: jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	t.Header["kid"] = kid
	t.Header["typ"] = PassportTypeV2
	signed, err := t.SignedString(key)
	if err == nil && len(signed) > maxTokenSize {
		return "", errors.New("passport exceeds size limit")
	}
	return signed, err
}

// VerifyV2 requires the exact configured audience, signing key and credential type.
// A valid passport is still a bearer credential; jti alone does not prevent replay.
func VerifyV2(raw string, key ed25519.PublicKey, audience string) (*AgentClaims, error) {
	if err := ValidateAudience(audience); err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > maxTokenSize {
		return nil, errors.New("invalid passport size")
	}
	kid, err := KeyID(key)
	if err != nil {
		return nil, err
	}
	c := &AgentClaims{}
	t, err := jwt.ParseWithClaims(raw, c, func(t *jwt.Token) (any, error) {
		if t.Header["kid"] != kid || t.Header["typ"] != PassportTypeV2 {
			return nil, errors.New("passport key ID or type mismatch")
		}
		if _, critical := t.Header["crit"]; critical {
			return nil, errors.New("unsupported critical header")
		}
		return key, nil
	}, jwt.WithValidMethods([]string{"EdDSA"}), jwt.WithIssuer(IssuerV2),
		jwt.WithAudience(audience), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithStrictDecoding())
	if err != nil {
		return nil, fmt.Errorf("passport verification failed: %w", err)
	}
	if t == nil || !t.Valid {
		return nil, errors.New("invalid passport signature")
	}
	if len(c.Audience) != 1 || c.Audience[0] != audience {
		return nil, errors.New("passport must have exactly one matching audience")
	}
	if c.Subject != c.AgentID || c.IssuedAt == nil || c.NotBefore == nil || c.ExpiresAt == nil {
		return nil, errors.New("missing or inconsistent mandatory claims")
	}
	if !c.NotBefore.Time.Equal(c.IssuedAt.Time) || !c.ExpiresAt.Time.After(c.IssuedAt.Time) || c.ExpiresAt.Time.Sub(c.IssuedAt.Time) > MaxTTL {
		return nil, errors.New("invalid credential validity interval")
	}
	id, err := hex.DecodeString(c.ID)
	if err != nil || len(id) != 16 || strings.ToLower(c.ID) != c.ID {
		return nil, errors.New("invalid passport identifier")
	}
	if err := ValidateIdentity(c.AgentID, c.Owner, c.Scopes); err != nil {
		return nil, err
	}
	if c.Confirmation!=nil {
		b,err:=base64.RawURLEncoding.Strict().DecodeString(c.Confirmation.Thumbprint)
		if err!=nil || len(b)!=32 || c.Confirmation.Thumbprint==kid { return nil,errors.New("invalid holder confirmation") }
	}
	return c, nil
}
