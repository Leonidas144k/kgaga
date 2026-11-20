package proxy

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Leonidas144k/kgaga/internal/passport"
	"github.com/Leonidas144k/kgaga/internal/policy"
)

func TestGatewaySecurity(t *testing.T) {
	dir := t.TempDir()
	priv, pub := filepath.Join(dir, "test.key"), filepath.Join(dir, "test.pub")
	if err := passport.GenerateKeyPair(priv, pub); err != nil { t.Fatal(err) }
	key, err := passport.LoadPublicKey(pub)
	if err != nil { t.Fatal(err) }
	mint := func(scopes []string, ttl time.Duration) string {
		t.Helper()
		token, err := passport.Mint(priv, "test-agent", "test-owner", scopes, ttl)
		if err != nil { t.Fatal(err) }
		return token
	}
	valid := mint([]string{"mcp:tool:search", "db:read"}, time.Minute)
	expired := mint([]string{"db:read"}, -time.Minute)
	var forwarded atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		if r.Header.Get("X-Pangolin-Verified-Agent") != "test-agent" { t.Error("missing verified identity") }
		w.WriteHeader(http.StatusNoContent)
	}))
	defer up.Close()
	cfg := &policy.Config{
		MCP: policy.MCPPolicy{AllowedTools: []string{"search"}, DeniedTools: []string{"drop_table"}},
		Rules: []policy.Rule{{PathPrefix: "/api/db", AllowedScopes: []string{"db:read"}, AllowedMethods: []string{"GET","HEAD"}, DenyMethods: []string{"DELETE"}}},
	}
	h, err := NewHandler(up.URL, key, cfg)
	if err != nil { t.Fatal(err) }
	for _, tc := range []struct{name, method, path, token, body, mcpMethod string; want int}{
		{"missing token", "GET", "/api/db", "", "", "", 401},
		{"invalid token", "GET", "/api/db", "invalid", "", "", 403},
		{"expired token", "GET", "/api/db", expired, "", "", 403},
		{"default deny", "GET", "/unknown", valid, "", "", 403},
		{"denied method", "DELETE", "/api/db", valid, "", "", 403},
		{"oversize", "POST", "/api/db", valid, strings.Repeat("x", maxRequestBytes+1), "", 413},
		{"malformed MCP", "POST", "/mcp", valid, "{", "", 400},
		{"MCP mismatch", "POST", "/mcp", valid, "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"search\"}}", "tools/list", 400},
		{"denied tool", "POST", "/mcp", valid, "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"drop_table\"}}", "", 403},
		{"missing scope", "POST", "/mcp", mint([]string{"db:read"}, time.Minute), "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"search\"}}", "", 403},
		{"valid HTTP", "GET", "/api/db", valid, "", "", 204},
		{"valid MCP", "POST", "/mcp", valid, "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"search\"}}", "", 204},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := forwarded.Load()
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.Header.Set("X-Agent-Passport", tc.token)
			req.Header.Set("Mcp-Method", tc.mcpMethod)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != tc.want { t.Fatalf("status %d, want %d: %s", w.Code, tc.want, w.Body.String()) }
			if tc.want >= 400 && forwarded.Load() != before { t.Fatal("blocked request reached upstream") }
		})
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/.well-known/jwks.json", nil))
	var jwks passport.JWKS
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &jwks) != nil || len(jwks.Keys) != 1 || jwks.Keys[0].X != base64.RawURLEncoding.EncodeToString(key) {
		t.Fatal("JWKS does not match verifier key")
	}
	if forwarded.Load() != 2 { t.Fatalf("expected 2 forwarded requests, got %d", forwarded.Load()) }
}

func TestInvalidGatewayConfiguration(t *testing.T) {
	key, _, err := ed25519.GenerateKey(nil)
	if err != nil { t.Fatal(err) }
	for _, target := range []string{"relative", "ftp://example.com", "http://user:pass@example.com", "http://"} {
		if _, err := NewHandler(target, key, &policy.Config{}); err == nil { t.Fatalf("accepted %q", target) }
	}
	if _, err := NewHandler("http://localhost", nil, &policy.Config{}); err == nil { t.Fatal("accepted invalid key") }
	if _, err := NewHandler("http://localhost", key, nil); err == nil { t.Fatal("accepted nil policy") }
}
