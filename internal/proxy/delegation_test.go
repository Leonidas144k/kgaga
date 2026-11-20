package proxy

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Leonidas144k/kgaga/internal/delegation"
	"github.com/Leonidas144k/kgaga/internal/keyring"
	"github.com/Leonidas144k/kgaga/internal/passport"
	"github.com/Leonidas144k/kgaga/internal/policy"
	"github.com/Leonidas144k/kgaga/internal/registry"
	"github.com/Leonidas144k/kgaga/internal/revocation"
)

func TestDelegatedGatewayParentLifecycle(t *testing.T) {
	dir := t.TempDir()
	keys := func(name string) (string, string) {
		t.Helper()
		priv, pub := filepath.Join(dir, name+".key"), filepath.Join(dir, name+".pub")
		if err := passport.GenerateKeyPair(priv, pub); err != nil { t.Fatal(err) }
		return priv, pub
	}
	issuer, issuerPub := keys("issuer")
	parentPriv, parentPub := keys("parent")
	childPriv, childPub := keys("child")
	td, rd, vd, pd := filepath.Join(dir,"trust"), filepath.Join(dir,"registry"), filepath.Join(dir,"rev"), filepath.Join(dir,"replay")
	if err:=keyring.Init(td); err!=nil { t.Fatal(err) }
	if err:=registry.Init(rd); err!=nil { t.Fatal(err) }
	if err:=revocation.Init(vd); err!=nil { t.Fatal(err) }
	if err:=revocation.Init(pd); err!=nil { t.Fatal(err) }
	trust,err:=keyring.Open(td); if err!=nil { t.Fatal(err) }
	reg,err:=registry.Open(rd); if err!=nil { t.Fatal(err) }
	rev,err:=revocation.Open(vd); if err!=nil { t.Fatal(err) }
	replay,err:=revocation.Open(pd); if err!=nil { t.Fatal(err) }
	issuerKey,err:=passport.LoadPublicKey(issuerPub); if err!=nil { t.Fatal(err) }
	if _,err:=trust.Trust(issuerKey); err!=nil { t.Fatal(err) }
	parentKey,err:=passport.LoadPublicKey(parentPub); if err!=nil { t.Fatal(err) }
	childKey,err:=passport.LoadPublicKey(childPub); if err!=nil { t.Fatal(err) }
	parentEncoded,err:=registry.EncodeHolder(parentKey); if err!=nil { t.Fatal(err) }
	childEncoded,err:=registry.EncodeHolder(childKey); if err!=nil { t.Fatal(err) }
	if err:=reg.Register(registry.Agent{ID:"parent",Owner:"owner",Scopes:[]string{"read",passport.DelegateScope},Audiences:[]string{"api"},HolderKey:parentEncoded}); err!=nil { t.Fatal(err) }
	if err:=reg.Register(registry.Agent{ID:"child",Owner:"owner",Scopes:[]string{"read"},Audiences:[]string{"api"},HolderKey:childEncoded}); err!=nil { t.Fatal(err) }
	parent,err:=passport.MintBoundV2(issuer,"parent","owner",[]string{"read",passport.DelegateScope},"api",5*time.Minute,parentKey); if err!=nil { t.Fatal(err) }
	p,err:=trust.Verify(parent,"api"); if err!=nil { t.Fatal(err) }
	kid,err:=passport.KeyID(childKey); if err!=nil { t.Fatal(err) }
	exp:=time.Now().Add(2*time.Minute).Unix()
	sig,err:=passport.SignGrant(parentPriv,parent,"child","owner",[]string{"read"},"api",kid,exp); if err!=nil { t.Fatal(err) }
	child,err:=delegation.Issue(issuer,"child","owner",[]string{"read"},"api",passport.Delegation{Parent:parent,Signature:sig,Expires:exp},trust,reg,rev); if err!=nil { t.Fatal(err) }
	var calls atomic.Int32
	up:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		calls.Add(1)
		if r.Header.Get("X-Kgaga-Verified-Agent")!="child" { t.Error("incorrect child identity") }
		if r.Header.Get("X-Agent-Passport")!="" || r.Header.Get(passport.ProofHeader)!="" { t.Error("credential forwarded") }
		w.WriteHeader(204)
	}))
	defer up.Close()
	h,err:=NewHandlerForAudience(up.URL,trust,&policy.Config{Version:"2",Rules:[]policy.Rule{{PathPrefix:"/api/db",AllowedScopes:[]string{"read"},AllowedMethods:[]string{"GET"}}}},"api",rev,reg,replay,UpstreamTLSOptions{AllowLoopbackHTTP:true}); if err!=nil { t.Fatal(err) }
	check:=func(signer string,want int){
		t.Helper()
		r:=httptest.NewRequest("GET","/api/db",nil)
		proof,err:=passport.SignRequest(signer,child,passport.RequestBinding{Method:"GET",Target:"/api/db"},time.Now()); if err!=nil { t.Fatal(err) }
		r.Header.Set("X-Agent-Passport",child)
		r.Header.Set(passport.ProofHeader,proof)
		w:=httptest.NewRecorder()
		h.ServeHTTP(w,r)
		if w.Code!=want { t.Fatalf("status %d want %d",w.Code,want) }
	}
	check(parentPriv,403)
	check(childPriv,204)
	if err:=rev.Revoke(p.ID); err!=nil { t.Fatal(err) }
	check(childPriv,403)
	if calls.Load()!=1 { t.Fatalf("upstream calls %d want 1",calls.Load()) }
}
