package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Leonidas144k/kgaga/internal/keyring"
	"github.com/Leonidas144k/kgaga/internal/passport"
	"github.com/Leonidas144k/kgaga/internal/policy"
	"github.com/Leonidas144k/kgaga/internal/registry"
	"github.com/Leonidas144k/kgaga/internal/revocation"
)

type admissionReader struct {
	io.Reader
	once sync.Once
	before func()
}

func (r *admissionReader) Read(p []byte)(int,error) {
	r.once.Do(r.before)
	return r.Reader.Read(p)
}

func TestAdversarialAdmission(t *testing.T) {
	dir:=t.TempDir()
	issuer,ipub:=filepath.Join(dir,"issuer.key"),filepath.Join(dir,"issuer.pub")
	holder,hpub:=filepath.Join(dir,"holder.key"),filepath.Join(dir,"holder.pub")
	for _,pair:=range [][2]string{{issuer,ipub},{holder,hpub}} { if err:=passport.GenerateKeyPair(pair[0],pair[1]); err!=nil { t.Fatal(err) } }
	ik,err:=passport.LoadPublicKey(ipub); if err!=nil { t.Fatal(err) }
	hk,err:=passport.LoadPublicKey(hpub); if err!=nil { t.Fatal(err) }
	encoded,err:=registry.EncodeHolder(hk); if err!=nil { t.Fatal(err) }
	td,rd,vd,pd:=filepath.Join(dir,"trust"),filepath.Join(dir,"registry"),filepath.Join(dir,"rev"),filepath.Join(dir,"replay")
	if err:=keyring.Init(td); err!=nil { t.Fatal(err) }
	if err:=registry.Init(rd); err!=nil { t.Fatal(err) }
	if err:=revocation.Init(vd); err!=nil { t.Fatal(err) }
	if err:=revocation.Init(pd); err!=nil { t.Fatal(err) }
	trust,err:=keyring.Open(td); if err!=nil { t.Fatal(err) }
	if _,err:=trust.Trust(ik); err!=nil { t.Fatal(err) }
	reg,err:=registry.Open(rd); if err!=nil { t.Fatal(err) }
	if err:=reg.Register(registry.Agent{ID:"agent",Owner:"owner",Scopes:[]string{"read"},Audiences:[]string{"api"},HolderKey:encoded}); err!=nil { t.Fatal(err) }
	rev,err:=revocation.Open(vd); if err!=nil { t.Fatal(err) }
	replay,err:=revocation.Open(pd); if err!=nil { t.Fatal(err) }
	var calls atomic.Int32
	var revokeOnUpstream atomic.Value
	revokeOnUpstream.Store("")
	up:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		calls.Add(1)
		if id:=revokeOnUpstream.Load().(string); id!="" {
			if err:=rev.Revoke(id); err!=nil { t.Error(err) }
		}
		w.Header().Set("Content-Type","text/plain")
		_,_=io.WriteString(w,"protected response")
	}))
	defer up.Close()
	cfg:=&policy.Config{Version:"2",Rules:[]policy.Rule{{PathPrefix:"/api",AllowedScopes:[]string{"read"},AllowedMethods:[]string{"POST"}}}}
	h,err:=NewHandlerForAudience(up.URL,trust,cfg,"api",rev,reg,replay,UpstreamTLSOptions{AllowLoopbackHTTP:true}); if err!=nil { t.Fatal(err) }
	mint:=func()(string,string){
		t.Helper()
		raw,err:=passport.MintBoundV2(issuer,"agent","owner",[]string{"read"},"api",5*time.Minute,hk); if err!=nil { t.Fatal(err) }
		c,err:=trust.Verify(raw,"api"); if err!=nil { t.Fatal(err) }
		return raw,c.ID
	}
	body:="test"
	prove:=func(token string)string{
		t.Helper()
		p,err:=passport.SignRequest(holder,token,passport.RequestBinding{Method:"POST",Target:"/api",ContentType:"text/plain",Body:[]byte(body)},time.Now())
		if err!=nil { t.Fatal(err) }
		return p
	}
	request:=func(token,p string,b io.Reader)*http.Request{
		r:=httptest.NewRequest("POST","/api",b)
		r.Header.Set("X-Agent-Passport",token)
		r.Header.Set(passport.ProofHeader,p)
		r.Header.Set("Content-Type","text/plain")
		return r
	}
	token,_:=mint()
	p:=prove(token)
	// Concurrent delivery of the exact same signed request must cause
	// at most one upstream dispatch, even if storage contention denies
	// some of the other requests with a transient 503.
	var wg sync.WaitGroup
	var allowed atomic.Int32
	for i:=0;i<8;i++ {
		wg.Add(1)
		go func(){
			defer wg.Done()
			w:=httptest.NewRecorder()
			h.ServeHTTP(w,request(token,p,strings.NewReader(body)))
			switch w.Code { case 200: allowed.Add(1); case 403,503: default: t.Errorf("unexpected replay status %d",w.Code) }
		}()
	}
	wg.Wait()
	if allowed.Load()!=1 || calls.Load()!=1 { t.Fatalf("duplicate dispatch: accepted %d upstream %d",allowed.Load(),calls.Load()) }
	// Revoke while the body is being read (after initial credential checks).
	token,id:=mint()
	p=prove(token)
	w:=httptest.NewRecorder()
	reader:=&admissionReader{Reader:strings.NewReader(body),before:func(){ if err:=rev.Revoke(id); err!=nil { t.Error(err) } }}
	h.ServeHTTP(w,request(token,p,reader))
	if w.Code!=403 || calls.Load()!=1 { t.Fatal("revoked in-flight credential reached upstream") }
	// An upstream may finish an action after revocation; its protected
	// response must not be released to the revoked agent.
	token,id=mint()
	revokeOnUpstream.Store(id)
	w=httptest.NewRecorder()
	h.ServeHTTP(w,request(token,prove(token),strings.NewReader(body)))
	if w.Code!=403 || calls.Load()!=2 || strings.Contains(w.Body.String(),"protected response") { t.Fatal("revoked response released") }
}
