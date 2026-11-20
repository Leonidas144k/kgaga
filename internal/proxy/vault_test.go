package proxy

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Leonidas144k/kgaga/internal/audit"
	"github.com/Leonidas144k/kgaga/internal/keyring"
	"github.com/Leonidas144k/kgaga/internal/passport"
	"github.com/Leonidas144k/kgaga/internal/policy"
	"github.com/Leonidas144k/kgaga/internal/registry"
	"github.com/Leonidas144k/kgaga/internal/revocation"
	"github.com/Leonidas144k/kgaga/internal/vault"
)

type auditFixture struct {
	buf bytes.Buffer
	fail string
}
func (a *auditFixture) Write(p []byte)(int,error) {
	if a.fail!="" && bytes.Contains(p,[]byte(`"phase":"`+a.fail+`"`)) { return 0,errors.New("synthetic audit sink failure") }
	return a.buf.Write(p)
}

func TestVaultCredentialInjection(t *testing.T) {
	dir:=t.TempDir()
	const secret="synthetic-vault-token-0123456789"
	var calls atomic.Int32
	var mode atomic.Int32
	var revokeActive func() error
	up:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		calls.Add(1)
		expected:=secret
		if mode.Load()==7 { expected="different-version-not-selected" }
		if r.TLS==nil || r.Header.Get("Authorization")!="Bearer "+expected || r.Header.Get("X-Kgaga-Verified-Agent")!="agent" ||
			r.Header.Get("X-Agent-Passport")!="" || r.Header.Get(passport.ProofHeader)!="" || r.Header.Get("X-Injected")!="" { t.Error("incorrect guarded upstream request") }
		switch mode.Load() {
		case 1: w.Header().Set("Content-Type","text/plain"); _,_=w.Write([]byte(secret))
		case 2: w.Header().Set("Content-Type","application/json"); _,_=w.Write([]byte(`{"value":"\u0073ynthetic-vault-token-0123456789"}`))
		case 3: w.Header().Set("Location","https://elsewhere.example"); w.WriteHeader(302)
		case 4: w.Header().Set("Content-Type","application/json"); _,_=w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
		case 5: w.Header().Set("Content-Type","application/json"); w.Header().Set("MCP-Protocol-Version",secret); _,_=w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
		case 6:
			if err:=revokeActive(); err!=nil { t.Error("in-flight revocation failed") }
			w.Header().Set("Content-Type","text/plain"); _,_=w.Write([]byte("protected response"))
		default: w.Header().Set("X-Private",secret); w.WriteHeader(204)
		}
	}))
	defer up.Close()
	ca:=filepath.Join(dir,"ca.pem")
	if err:=os.WriteFile(ca,pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:up.Certificate().Raw}),0600); err!=nil { t.Fatal(err) }
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
	scopes:=[]string{"read","vault:use","mcp:tool:search"}
	for _,id:=range []string{"agent","other"} {
		if err:=reg.Register(registry.Agent{ID:id,Owner:"owner",Scopes:scopes,Audiences:[]string{"api"},HolderKey:encoded}); err!=nil { t.Fatal(err) }
	}
	rev,err:=revocation.Open(vd); if err!=nil { t.Fatal(err) }
	replay,err:=revocation.Open(pd); if err!=nil { t.Fatal(err) }
	vid,err:=vault.GenerateID(); if err!=nil { t.Fatal(err) }
	kid,err:=vault.GenerateID(); if err!=nil { t.Fatal(err) }
	vdir:=filepath.Join(dir,"vault")
	keyDir:=filepath.Join(dir,"keys")
	if err:=os.Mkdir(keyDir,0700); err!=nil { t.Fatal(err) }
	keyPath:=filepath.Join(keyDir,"master")
	if err:=vault.Init(vdir,vid); err!=nil { t.Fatal(err) }
	s,err:=vault.Open(vdir,vid); if err!=nil { t.Fatal(err) }
	if err:=s.CreateMasterKey(keyPath,kid); err!=nil { t.Fatal(err) }
	m,err:=s.OpenManaged(keyPath,kid); if err!=nil { t.Fatal(err) }
	now:=time.Now().Unix()
	if err:=m.PutBearer("token",1,[]byte(secret),now-10,now+600); err!=nil { t.Fatal(err) }
	if err:=m.PutBearer("token",2,[]byte("different-version-not-selected"),now-10,now+600); err!=nil { t.Fatal(err) }
	if err:=m.PutBearer("token",3,[]byte(secret),now+600,now+1200); err!=nil { t.Fatal(err) }
	if err:=m.Put("token",4,[]byte(secret)); err!=nil { t.Fatal(err) }
	revokeActive=func()error{return m.RevokeVersion("token",1)}
	grant:=func(path,method,mcp,tool,scope string,version int)string{
		return fmt.Sprintf(`  - agent_id: "agent"
    owner: "owner"
    audience: "api"
    origin: "%s"
    method: "%s"
    target: "%s"
    mcp_method: "%s"
    tool: "%s"
    required_scopes: ["%s", "vault:use"]
    secret_name: "token"
    secret_version: %d
`,up.URL,method,path,mcp,tool,scope,version)
	}
	policyPath:=filepath.Join(dir,"vault.yaml")
	id:=hex.EncodeToString(vid[:])
	raw:=fmt.Sprintf("version: \"1\"\nvault_id: \"%s\"\ngrants:\n",id)+grant("/api","GET","","","read",1)+grant("/api/rotated","GET","","","read",2)+grant("/api/missing","GET","","","read",9)+grant("/api/future","GET","","","read",3)+grant("/api/legacy","GET","","","read",4)+grant("/mcp","POST","tools/call","search","mcp:tool:search",1)
	if err:=os.WriteFile(policyPath,[]byte(raw),0600); err!=nil { t.Fatal(err) }
	broker,err:=OpenVaultGateway(policyPath,vdir,id,keyPath,hex.EncodeToString(kid[:])); if err!=nil { t.Fatal(err) }
	sink:=&auditFixture{}
	broker.audit=audit.NewRecorder(sink)
	cfg:=&policy.Config{Version:"2",RedactSecrets:true,MCP:policy.MCPPolicy{AllowedTools:[]string{"search","read_file"}},Rules:[]policy.Rule{{PathPrefix:"/api",AllowedScopes:[]string{"read"},AllowedMethods:[]string{"GET"}}}}
	opt:=UpstreamTLSOptions{CAFile:ca}
	h,err:=NewHandlerWithVault(up.URL,trust,cfg,"api",rev,reg,replay,broker,opt); if err!=nil { t.Fatal(err) }
	if _,err:=NewHandlerWithVault(up.URL,trust,cfg,"api",rev,reg,replay,nil,opt); err==nil { t.Fatal("nil broker accepted") }
	if _,err:=NewHandlerWithVault(up.URL,trust,cfg,"other",rev,reg,replay,broker,opt); err==nil { t.Fatal("wrong audience binding accepted") }
	if _,err:=NewHandlerWithVault("http://127.0.0.1:3000",trust,cfg,"api",rev,reg,replay,broker,UpstreamTLSOptions{AllowLoopbackHTTP:true}); err==nil { t.Fatal("plaintext vault accepted") }
	noInspect:=*cfg; noInspect.RedactSecrets=false
	if _,err:=NewHandlerWithVault(up.URL,trust,&noInspect,"api",rev,reg,replay,broker,opt); err==nil { t.Fatal("disabled inspection accepted") }
	run:=func(handler http.Handler,agent,target,method,body string,grantedScopes []string,session bool,want int,dispatch bool){
		t.Helper()
		token,err:=passport.MintBoundV2(issuer,agent,"owner",grantedScopes,"api",5*time.Minute,hk); if err!=nil { t.Fatal(err) }
		r:=httptest.NewRequest(method,target,strings.NewReader(body))
		ct:=""; if body!="" { ct="application/json"; r.Header.Set("Content-Type",ct) }
		sid:=""; if session { sid="session"; r.Header.Set("Mcp-Session-Id",sid) }
		proof,err:=passport.SignRequest(holder,token,passport.RequestBinding{Method:method,Target:target,ContentType:ct,MCPSession:sid,Body:[]byte(body)},time.Now()); if err!=nil { t.Fatal(err) }
		r.Header.Set("X-Agent-Passport",token); r.Header.Set(passport.ProofHeader,proof)
		r.Header.Set("Authorization","Bearer attacker-supplied")
		r.Header.Set("X-Injected","spoof")
		before:=calls.Load()
		w:=httptest.NewRecorder(); handler.ServeHTTP(w,r)
		if w.Code!=want || (calls.Load()!=before)!=dispatch || bytes.Contains(w.Body.Bytes(),[]byte(secret)) || (want==403 && strings.Contains(w.Body.String(),"protected response")) || w.Header().Get("Location")!="" || w.Header().Get("X-Private")!="" { t.Fatalf("unexpected result: status=%d want=%d dispatched=%v",w.Code,want,calls.Load()!=before) }
		for _,values:=range w.Header() { for _,value:=range values { if strings.Contains(value,secret) { t.Fatal("credential in response header") } } }
	}
	run(h,"agent","/api","GET","",scopes,false,403,false)
	if err:=m.Activate("token",1); err!=nil { t.Fatal(err) }
	run(h,"agent","/api","GET","",scopes,false,204,true)
	run(h,"other","/api","GET","",scopes,false,403,false)
	run(h,"agent","/api","GET","",[]string{"read"},false,403,false)
	run(h,"agent","/api?x=1","GET","",scopes,false,403,false)
	run(h,"agent","/api/ungranted","GET","",scopes,false,403,false)
	run(h,"agent","/api/missing","GET","",scopes,false,403,false)
	run(h,"agent","/api/future","GET","",scopes,false,403,false)
	run(h,"agent","/api/legacy","GET","",scopes,false,403,false)
	for _,v:=range []int32{1,2,3} { mode.Store(v); run(h,"agent","/api","GET","",scopes,false,502,true) }
	body:=`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search"}}`
	mode.Store(4)
	run(h,"agent","/mcp","POST",body,scopes,false,200,true)
	run(h,"agent","/mcp","POST",body,scopes,true,403,false)
	mode.Store(5)
	run(h,"agent","/mcp","POST",body,scopes,false,502,true)
	// Revocation during upstream execution must withhold the response.
	mode.Store(6)
	run(h,"agent","/api","GET","",scopes,false,403,true)
	run(h,"agent","/api","GET","",scopes,false,403,false)
	if err:=m.Activate("token",2); err!=nil { t.Fatal(err) }
	mode.Store(7)
	run(h,"agent","/api","GET","",scopes,false,403,false)
	run(h,"agent","/api/rotated","GET","",scopes,false,204,true)
	sink.fail="dispatch_intent"
	run(h,"agent","/api/rotated","GET","",scopes,false,503,false)
	sink.fail="response_release_intent"
	run(h,"agent","/api/rotated","GET","",scopes,false,503,true)
	// Deliberately do not log the supplied client auth, proof, request
	// body, query or the selected bearer, even when an upstream echoes it.
	rawAudit:=sink.buf.String()
	for _,s:=range []string{secret,"different-version-not-selected","attacker-supplied","protected response","?x=1","X-Kgaga-Proof"} {
		if strings.Contains(rawAudit,s) { t.Fatal("sensitive input in structured audit") }
	}
	phases:=map[string]int{}
	attempts:=map[string]bool{}
	for _,line:=range strings.Split(strings.TrimSuffix(rawAudit,"\n"),"\n") {
		var e audit.Event
		if err:=json.Unmarshal([]byte(line),&e); err!=nil || e.Schema!="kgaga.vault.audit.v1" || e.VaultID!=id || e.Actor!="agent" || e.AgentID=="" || e.PassportID=="" || e.Audience!="api" { t.Fatal("invalid usage audit metadata") }
		if e.Phase=="attempt" { if attempts[e.AttemptID] { t.Fatal("duplicate attempt") }; attempts[e.AttemptID]=true } else if !attempts[e.AttemptID] { t.Fatal("uncorrelated audit event") }
		if e.Phase=="dispatch_intent" && (e.Name!="token" || e.Version==0 || e.Origin!=up.URL || e.Target=="") { t.Fatal("missing selected credential metadata") }
		phases[e.Phase]++
	}
	for _,phase:=range []string{"attempt","denied","dispatch_intent","exchange_failed_or_rejected","response_withheld","response_release_intent"} {
		if phases[phase]==0 { t.Fatalf("missing phase %s",phase) }
	}
}
