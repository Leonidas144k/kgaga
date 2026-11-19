package passport

import (
	"crypto/ed25519"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestV2Issuance(t *testing.T) {
	dir := t.TempDir()
	priv, pub := filepath.Join(dir, "test.key"), filepath.Join(dir, "test.pub")
	if err := GenerateKeyPair(priv, pub); err != nil {
		t.Fatal(err)
	}
	key, err := LoadPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	mint := func() string {
		t.Helper()
		raw, err := MintV2(priv, "agent-1", "ops@example.com", []string{"db:read"}, "service-a", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	first, second := mint(), mint()
	c, err := VerifyV2(first, key, "service-a")
	if err != nil {
		t.Fatal(err)
	}
	d, err := VerifyV2(second, key, "service-a")
	if err != nil {
		t.Fatal(err)
	}
	if c.ID == d.ID || c.AgentID != "agent-1" || c.Owner != "ops@example.com" || c.Subject != c.AgentID ||
		c.Issuer != IssuerV2 || len(c.Scopes) != 1 || c.Scopes[0] != "db:read" || c.ExpiresAt.Time.Sub(c.IssuedAt.Time) != time.Minute {
		t.Fatal("unexpected signed claims")
	}
	if _, err := VerifyV2(first, key, "service-b"); err == nil {
		t.Fatal("accepted wrong audience")
	}
	other, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyV2(first, other, "service-a"); err == nil {
		t.Fatal("accepted wrong key")
	}
	if _, err := VerifyV2(first, nil, "service-a"); err == nil {
		t.Fatal("accepted invalid key")
	}
	parts := strings.Split(first, ".")
	ch := "A"
	if strings.HasPrefix(parts[2], ch) {
		ch = "B"
	}
	parts[2] = ch + parts[2][1:]
	if _, err := VerifyV2(strings.Join(parts, "."), key, "service-a"); err == nil {
		t.Fatal("accepted tampered signature")
	}
	legacy, err := Mint(priv, "agent-1", "ops@example.com", []string{"db:read"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyV2(legacy, key, "service-a"); err == nil {
		t.Fatal("accepted legacy passport")
	}
	kid, err := KeyID(key)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := JWKSForKeyV2(key)
	if err != nil || len(jwks.Keys) != 1 || jwks.Keys[0].Kid != kid {
		t.Fatal("JWKS key ID mismatch")
	}
	parsed, _, err := jwt.NewParser().ParseUnverified(first, &AgentClaims{})
	if err != nil || parsed.Header["kid"] != kid || parsed.Header["typ"] != PassportTypeV2 {
		t.Fatal("unexpected JWT header")
	}
}

func TestV2RejectInvalidClaims(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	kid, err := KeyID(pub)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	for _, tc := range []struct {
		name string
		change func(*AgentClaims, *jwt.Token)
	}{
		{"issuer", func(c *AgentClaims, _ *jwt.Token) { c.Issuer = "other" }},
		{"subject", func(c *AgentClaims, _ *jwt.Token) { c.Subject = "other" }},
		{"missing audience", func(c *AgentClaims, _ *jwt.Token) { c.Audience = nil }},
		{"multiple audiences", func(c *AgentClaims, _ *jwt.Token) { c.Audience = []string{"service-a", "service-b"} }},
		{"missing jti", func(c *AgentClaims, _ *jwt.Token) { c.ID = "" }},
		{"missing iat", func(c *AgentClaims, _ *jwt.Token) { c.IssuedAt = nil }},
		{"missing nbf", func(c *AgentClaims, _ *jwt.Token) { c.NotBefore = nil }},
		{"missing exp", func(c *AgentClaims, _ *jwt.Token) { c.ExpiresAt = nil }},
		{"expired", func(c *AgentClaims, _ *jwt.Token) { c.IssuedAt = jwt.NewNumericDate(now.Add(-2*time.Minute)); c.NotBefore = c.IssuedAt; c.ExpiresAt = jwt.NewNumericDate(now.Add(-time.Minute)) }},
		{"future", func(c *AgentClaims, _ *jwt.Token) { c.IssuedAt = jwt.NewNumericDate(now.Add(time.Minute)); c.NotBefore = c.IssuedAt; c.ExpiresAt = jwt.NewNumericDate(now.Add(2*time.Minute)) }},
		{"overlong TTL", func(c *AgentClaims, _ *jwt.Token) { c.ExpiresAt = jwt.NewNumericDate(now.Add(2*time.Hour)) }},
		{"no scopes", func(c *AgentClaims, _ *jwt.Token) { c.Scopes = nil }},
		{"duplicate scopes", func(c *AgentClaims, _ *jwt.Token) { c.Scopes = []string{"db:read","db:read"} }},
		{"header injection", func(c *AgentClaims, _ *jwt.Token) { c.Owner = "a\r\nb" }},
		{"wrong kid", func(_ *AgentClaims, tok *jwt.Token) { tok.Header["kid"] = "wrong" }},
		{"wrong type", func(_ *AgentClaims, tok *jwt.Token) { tok.Header["typ"] = "JWT" }},
		{"critical header", func(_ *AgentClaims, tok *jwt.Token) { tok.Header["crit"] = []string{"custom"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &AgentClaims{AgentID:"agent", Owner:"owner", Scopes:[]string{"db:read"}, RegisteredClaims:jwt.RegisteredClaims{
				Issuer:IssuerV2, Subject:"agent", Audience:jwt.ClaimStrings{"service-a"}, ID:strings.Repeat("a",32),
				IssuedAt:jwt.NewNumericDate(now), NotBefore:jwt.NewNumericDate(now), ExpiresAt:jwt.NewNumericDate(now.Add(time.Minute)),
			}}
			token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, c)
			token.Header["kid"], token.Header["typ"] = kid, PassportTypeV2
			tc.change(c, token)
			raw, err := token.SignedString(priv)
			if err != nil { t.Fatal(err) }
			if _, err := VerifyV2(raw, pub, "service-a"); err == nil { t.Fatalf("accepted %s", tc.name) }
		})
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"iss":IssuerV2})
	raw, err := token.SignedString([]byte(pub))
	if err != nil { t.Fatal(err) }
	if _, err := VerifyV2(raw, pub, "service-a"); err == nil { t.Fatal("accepted HMAC algorithm") }
}

func TestV2MintRejectInvalidInputs(t *testing.T) {
	dir := t.TempDir()
	priv := filepath.Join(dir, "test.key")
	if err := GenerateKeyPair(priv, filepath.Join(dir, "test.pub")); err != nil { t.Fatal(err) }
	for _, tc := range []struct{ agent, owner, aud string; scopes []string; ttl time.Duration }{
		{"","owner","svc",[]string{"read"},time.Minute},
		{"agent","","svc",[]string{"read"},time.Minute},
		{"agent","owner","",[]string{"read"},time.Minute},
		{"agent","owner","svc",nil,time.Minute},
		{"agent","owner","svc",[]string{"read","read"},time.Minute},
		{"agent","owner","svc",[]string{"read"},0},
		{"agent","owner","svc",[]string{"read"},2*time.Hour},
	} {
		if _, err := MintV2(priv, tc.agent, tc.owner, tc.scopes, tc.aud, tc.ttl); err == nil { t.Fatal("accepted invalid issuance inputs") }
	}
}
