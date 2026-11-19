package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Leonidas144k/kgaga/internal/passport"
	"github.com/Leonidas144k/kgaga/internal/policy"
)

func TestAudienceGateway(t *testing.T) {
	dir := t.TempDir()
	priv, pub := filepath.Join(dir, "key"), filepath.Join(dir, "pub")
	if err := passport.GenerateKeyPair(priv,pub); err != nil { t.Fatal(err) }
	key, err := passport.LoadPublicKey(pub)
	if err != nil { t.Fatal(err) }
	mint := func(aud string) string {
		t.Helper()
		raw, err := passport.MintV2(priv,"agent","owner",[]string{"db:read"},aud,time.Minute)
		if err != nil { t.Fatal(err) }
		return raw
	}
	legacy, err := passport.Mint(priv,"agent","owner",[]string{"db:read"},time.Minute)
	if err != nil { t.Fatal(err) }
	var calls atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		calls.Add(1)
		if r.Header.Get("X-Agent-Passport") != "" || r.Header.Get("X-Kgaga-Passport") != "" { t.Error("credential leaked upstream") }
		if r.Header.Get("X-Kgaga-Verified-Agent") != "agent" || r.Header.Get("X-Pangolin-Verified-Agent") != "agent" ||
			r.Header.Get("X-Kgaga-Agent-Owner") != "owner" || r.Header.Get("X-Pangolin-Agent-Owner") != "owner" { t.Error("verified identity missing or spoofed") }
		w.WriteHeader(http.StatusNoContent)
	}))
	defer up.Close()
	cfg := &policy.Config{Rules:[]policy.Rule{{PathPrefix:"/api/db",AllowedScopes:[]string{"db:read"}}}}
	if _,err := NewHandlerForAudience(up.URL,key,cfg,""); err == nil { t.Fatal("accepted empty audience") }
	h,err := NewHandlerForAudience(up.URL,key,cfg,"service-a")
	if err != nil { t.Fatal(err) }
	for _,tc := range []struct{ name, token string; duplicate bool; want int }{
		{"wrong audience",mint("service-b"),false,403},
		{"legacy",legacy,false,403},
		{"duplicate",mint("service-a"),true,400},
		{"valid",mint("service-a"),false,204},
	} {
		t.Run(tc.name,func(t *testing.T){
			r:=httptest.NewRequest("GET","/api/db",nil)
			r.Header.Set("X-Agent-Passport",tc.token)
			if tc.duplicate { r.Header.Add("X-Agent-Passport",tc.token) }
			r.Header.Set("X-Kgaga-Passport","untrusted")
			r.Header.Set("X-Kgaga-Verified-Agent","spoofed")
			r.Header.Set("X-Pangolin-Agent-Owner","spoofed")
			r.Header.Set("Connection","X-Kgaga-Verified-Agent, X-Pangolin-Agent-Owner")
			w:=httptest.NewRecorder()
			h.ServeHTTP(w,r)
			if w.Code != tc.want { t.Fatalf("status %d want %d",w.Code,tc.want) }
		})
	}
	if calls.Load()!=1 { t.Fatalf("upstream calls %d want 1",calls.Load()) }
	w:=httptest.NewRecorder()
	h.ServeHTTP(w,httptest.NewRequest("GET","/.well-known/jwks.json",nil))
	var jwks passport.JWKS
	kid, err := passport.KeyID(key)
	if err != nil || w.Code != 200 || json.Unmarshal(w.Body.Bytes(),&jwks)!=nil || len(jwks.Keys)!=1 || jwks.Keys[0].Kid!=kid { t.Fatal("gateway published wrong key ID") }
}
