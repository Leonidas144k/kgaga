package proxy

import (
	"encoding/json"
	"net/http"
	"os"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Leonidas144k/kgaga/internal/passport"
	"github.com/Leonidas144k/kgaga/internal/policy"
	"github.com/Leonidas144k/kgaga/internal/revocation"
	"github.com/Leonidas144k/kgaga/internal/registry"
	"github.com/Leonidas144k/kgaga/internal/keyring"
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
	storePath:=filepath.Join(dir,"revocations")
	if err:=revocation.Init(storePath); err!=nil { t.Fatal(err) }
	store,err:=revocation.Open(storePath)
	if err!=nil { t.Fatal(err) }
	regPath:=filepath.Join(dir,"agents")
	if err:=registry.Init(regPath); err!=nil { t.Fatal(err) }
	reg,err:=registry.Open(regPath)
	if err!=nil { t.Fatal(err) }
	if err:=reg.Register(registry.Agent{ID:"agent",Owner:"owner",Scopes:[]string{"db:read"},Audiences:[]string{"service-a"}}); err!=nil { t.Fatal(err) }
	trustPath:=filepath.Join(dir,"trust")
	if err:=keyring.Init(trustPath); err!=nil { t.Fatal(err) }
	trust,err:=keyring.Open(trustPath)
	if err!=nil { t.Fatal(err) }
	oldID,err:=trust.Trust(key)
	if err!=nil { t.Fatal(err) }
	if _,err:=NewHandlerForAudience(up.URL,nil,cfg,"service-a",store,reg); err==nil { t.Fatal("accepted absent trust store") }
	if _,err:=NewHandlerForAudience(up.URL,trust,cfg,"service-a",store,nil); err==nil { t.Fatal("accepted absent registry") }
	if _,err := NewHandlerForAudience(up.URL,trust,cfg,"service-a",nil,reg); err==nil { t.Fatal("accepted missing revocation store") }
	if _,err := NewHandlerForAudience(up.URL,trust,cfg,"",store,reg); err == nil { t.Fatal("accepted empty audience") }
	h,err := NewHandlerForAudience(up.URL,trust,cfg,"service-a",store,reg)
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
	// A previously accepted passport is rejected immediately after revocation.
	raw:=mint("service-a")
	claims,err:=passport.VerifyV2(raw,key,"service-a")
	if err!=nil { t.Fatal(err) }
	check:=func(token string,want int){
		t.Helper()
		r:=httptest.NewRequest("GET","/api/db",nil)
		r.Header.Set("X-Agent-Passport",token)
		w:=httptest.NewRecorder()
		h.ServeHTTP(w,r)
		if w.Code!=want { t.Fatalf("status %d want %d",w.Code,want) }
	}
	check(raw,204)
	if err:=store.Revoke(claims.ID); err!=nil { t.Fatal(err) }
	check(raw,403)
	for _,a:=range []struct{id,owner,scope string}{{"unknown","owner","db:read"},{"agent","other","db:read"},{"agent","owner","db:write"}} {
		raw,err:=passport.MintV2(priv,a.id,a.owner,[]string{a.scope},"service-a",time.Minute)
		if err!=nil { t.Fatal(err) }
		check(raw,403)
	}
	newPriv,newPub:=filepath.Join(dir,"new.key"),filepath.Join(dir,"new.pub")
	if err:=passport.GenerateKeyPair(newPriv,newPub); err!=nil { t.Fatal(err) }
	newKey,err:=passport.LoadPublicKey(newPub)
	if err!=nil { t.Fatal(err) }
	newID,err:=trust.Trust(newKey)
	if err!=nil { t.Fatal(err) }
	fresh,err:=passport.MintV2(newPriv,"agent","owner",[]string{"db:read"},"service-a",time.Minute)
	if err!=nil { t.Fatal(err) }
	check(fresh,204)
	old:=mint("service-a")
	check(old,204)
	if err:=trust.Retire(oldID); err!=nil { t.Fatal(err) }
	check(old,403)
	check(fresh,204)
	if err:=reg.Suspend("agent"); err!=nil { t.Fatal(err) }
	check(fresh,403)
	if err:=os.Rename(regPath,regPath+"-backup"); err!=nil { t.Fatal(err) }
	check(fresh,503)
	if err:=os.Rename(storePath,storePath+"-backup"); err!=nil { t.Fatal(err) }
	check(fresh,503)
	if calls.Load()!=5 { t.Fatalf("upstream calls %d want 5",calls.Load()) }
	w:=httptest.NewRecorder()
	h.ServeHTTP(w,httptest.NewRequest("GET","/.well-known/jwks.json",nil))
	var jwks passport.JWKS
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(),&jwks)!=nil || len(jwks.Keys)!=1 || jwks.Keys[0].Kid!=newID { t.Fatal("gateway published wrong key ID") }
}
