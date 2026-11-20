package proxy

import (
	"encoding/json"
	"net/http"
	"os"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"strings"
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
	holderPriv,holderPub:=filepath.Join(dir,"holder.key"),filepath.Join(dir,"holder.pub")
	if err:=passport.GenerateKeyPair(holderPriv,holderPub); err!=nil { t.Fatal(err) }
	holder,err:=passport.LoadPublicKey(holderPub)
	if err!=nil { t.Fatal(err) }
	encoded,err:=registry.EncodeHolder(holder)
	if err!=nil { t.Fatal(err) }
	sign:=func(r *http.Request,token string) string {
		t.Helper()
		p,err:=passport.SignRequest(holderPriv,token,passport.RequestBinding{Method:r.Method,Target:r.URL.RequestURI()},time.Now())
		if err!=nil { t.Fatal(err) }
		r.Header.Set(passport.ProofHeader,p)
		return p
	}
	mint := func(aud string) string {
		t.Helper()
		raw, err := passport.MintBoundV2(priv,"agent","owner",[]string{"db:read"},aud,time.Minute,holder)
		if err != nil { t.Fatal(err) }
		return raw
	}
	legacy, err := passport.Mint(priv,"agent","owner",[]string{"db:read"},time.Minute)
	if err != nil { t.Fatal(err) }
	var calls atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		calls.Add(1)
		if r.Header.Get("Mcp-Name")!="" { t.Error("redundant MCP tool header forwarded") }
		if r.Header.Get("X-Agent-Passport") != "" || r.Header.Get("X-Kgaga-Passport") != "" || r.Header.Get(passport.ProofHeader)!="" { t.Error("credential leaked upstream") }
		if r.Header.Get("X-Kgaga-Verified-Agent") != "agent" || r.Header.Get("X-Pangolin-Verified-Agent") != "agent" ||
			r.Header.Get("X-Kgaga-Agent-Owner") != "owner" || r.Header.Get("X-Pangolin-Agent-Owner") != "owner" { t.Error("verified identity missing or spoofed") }
		if r.URL.Path=="/mcp" {
			var req map[string]any
			if err:=json.NewDecoder(r.Body).Decode(&req); err!=nil { t.Error("invalid forwarded request") }
			w.Header().Set("Content-Type","application/json")
			switch req["id"] {
			case float64(2): _,_=w.Write([]byte(`{"jsonrpc":"2.0","id":999,"result":{}}`))
			case float64(3): _,_=w.Write([]byte(`{"jsonrpc":"2.0","id":3,"result":{"value":"\u0073k-abcdefghijklmnopqrstuvwxyz"}}`))
			default: _,_=w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
			}
			return
		}
		if r.Header.Get("Authorization")!="" || r.Header.Get("Cookie")!="" || r.Header.Get("X-Unknown")!="" { t.Error("unapproved request header forwarded") }
		switch r.URL.Query().Get("response") {
		case "redirect": w.Header().Set("Location","/api/db"); w.WriteHeader(302)
		case "large": w.Header().Set("Content-Type","text/plain"); _,_=w.Write([]byte(strings.Repeat("a",maxResponseBytes+1)))
		case "encoded": w.Header().Set("Content-Encoding","gzip"); _,_=w.Write([]byte("encoded"))
		case "secret": w.Header().Set("Content-Type","application/json"); _,_=w.Write([]byte(`{"value":"\u0073k-abcdefghijklmnopqrstuvwxyz"}`))
		case "clean": w.Header().Set("Content-Type","application/json"); w.Header().Set("Set-Cookie","session=secret"); w.Header().Set("X-Secret","do not forward"); _,_=w.Write([]byte(`{"ok":true}`))
		default: w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer up.Close()
	cfg := &policy.Config{Version:"2",RedactSecrets:true,MCP:policy.MCPPolicy{AllowedTools:[]string{"search"},DeniedTools:[]string{"drop_table"}},Rules:[]policy.Rule{{PathPrefix:"/api/db",AllowedScopes:[]string{"db:read"},AllowedMethods:[]string{"GET"}}}}
	storePath:=filepath.Join(dir,"revocations")
	if err:=revocation.Init(storePath); err!=nil { t.Fatal(err) }
	store,err:=revocation.Open(storePath)
	if err!=nil { t.Fatal(err) }
	regPath:=filepath.Join(dir,"agents")
	if err:=registry.Init(regPath); err!=nil { t.Fatal(err) }
	reg,err:=registry.Open(regPath)
	if err!=nil { t.Fatal(err) }
	if err:=reg.Register(registry.Agent{ID:"agent",Owner:"owner",Scopes:[]string{"db:read","mcp:tool:search"},Audiences:[]string{"service-a"},HolderKey:encoded}); err!=nil { t.Fatal(err) }
	trustPath:=filepath.Join(dir,"trust")
	if err:=keyring.Init(trustPath); err!=nil { t.Fatal(err) }
	trust,err:=keyring.Open(trustPath)
	if err!=nil { t.Fatal(err) }
	oldID,err:=trust.Trust(key)
	if err!=nil { t.Fatal(err) }
	replayPath:=filepath.Join(dir,"replay")
	if err:=revocation.Init(replayPath); err!=nil { t.Fatal(err) }
	replay,err:=revocation.Open(replayPath)
	if err!=nil { t.Fatal(err) }
	if _,err:=NewHandlerForAudience(up.URL,trust,cfg,"service-a",store,reg,nil,UpstreamTLSOptions{AllowLoopbackHTTP:true}); err==nil { t.Fatal("accepted missing replay store") }
	if _,err:=NewHandlerForAudience(up.URL,nil,cfg,"service-a",store,reg,replay,UpstreamTLSOptions{AllowLoopbackHTTP:true}); err==nil { t.Fatal("accepted absent trust store") }
	if _,err:=NewHandlerForAudience(up.URL,trust,cfg,"service-a",store,nil,replay,UpstreamTLSOptions{AllowLoopbackHTTP:true}); err==nil { t.Fatal("accepted absent registry") }
	if _,err := NewHandlerForAudience(up.URL,trust,cfg,"service-a",nil,reg,replay,UpstreamTLSOptions{AllowLoopbackHTTP:true}); err==nil { t.Fatal("accepted missing revocation store") }
	if _,err := NewHandlerForAudience(up.URL,trust,cfg,"",store,reg,replay,UpstreamTLSOptions{AllowLoopbackHTTP:true}); err == nil { t.Fatal("accepted empty audience") }
	h,err := NewHandlerForAudience(up.URL,trust,cfg,"service-a",store,reg,replay,UpstreamTLSOptions{AllowLoopbackHTTP:true})
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
			sign(r,tc.token)
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
	// Exercise the real holder-bound gateway, not just the legacy verifier.
	mcpToken,err:=passport.MintBoundV2(priv,"agent","owner",[]string{"mcp:tool:search"},"service-a",time.Minute,holder)
	if err!=nil { t.Fatal(err) }
	for _,tc:=range []struct{body,name string; want int}{
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search"}}`,"search",200},
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","name":"drop_table"}}`,"",400},
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search"}}`,"other",400},
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"drop_table"}}`,"",403},
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":{"value":"sk-abcdefghijklmnopqrstuvwxyz"}}}`,"",403},
	} {
		r:=httptest.NewRequest("POST","/mcp",strings.NewReader(tc.body))
		r.Header.Set("X-Agent-Passport",mcpToken)
		r.Header.Set("Content-Type","application/json")
		if tc.name!="" { r.Header.Set("Mcp-Name",tc.name) }
		p,err:=passport.SignRequest(holderPriv,mcpToken,passport.RequestBinding{Method:"POST",Target:"/mcp",ContentType:"application/json",Body:[]byte(tc.body)},time.Now())
		if err!=nil { t.Fatal(err) }
		r.Header.Set(passport.ProofHeader,p)
		before:=calls.Load()
		w:=httptest.NewRecorder()
		h.ServeHTTP(w,r)
		if w.Code!=tc.want || (tc.want>=400 && calls.Load()!=before) { t.Fatalf("MCP status %d want %d",w.Code,tc.want) }
		if tc.want>=400 && !json.Valid(w.Body.Bytes()) { t.Fatal("invalid MCP error response") }
	}
	// Response inspection happens after admission and does not leak rejected bytes.
	for _,id:=range []string{"2","3"} {
		body:=`{"jsonrpc":"2.0","id":`+id+`,"method":"tools/call","params":{"name":"search"}}`
		r:=httptest.NewRequest("POST","/mcp",strings.NewReader(body))
		r.Header.Set("X-Agent-Passport",mcpToken)
		r.Header.Set("Content-Type","application/json")
		p,err:=passport.SignRequest(holderPriv,mcpToken,passport.RequestBinding{Method:"POST",Target:"/mcp",ContentType:"application/json",Body:[]byte(body)},time.Now())
		if err!=nil { t.Fatal(err) }
		r.Header.Set(passport.ProofHeader,p)
		w:=httptest.NewRecorder()
		h.ServeHTTP(w,r)
		if w.Code!=502 || !json.Valid(w.Body.Bytes()) || strings.Contains(w.Body.String(),"abcdefghijklmnopqrstuvwxyz") { t.Fatal("unsafe MCP response released") }
	}
	for _,tc:=range []struct{query string; want int; forwarded bool}{
		{"response=redirect",502,true},{"response=large",502,true},{"response=encoded",502,true},{"response=secret",502,true},{"response=clean",200,true},{"value=%73k-abcdefghijklmnopqrstuvwxyz",403,false},
	} {
		r:=httptest.NewRequest("GET","/api/db?"+tc.query,nil)
		token:=mint("service-a")
		r.Header.Set("X-Agent-Passport",token)
		r.Header.Set("Authorization","Bearer not-forwarded")
		r.Header.Set("Cookie","session=not-forwarded")
		r.Header.Set("X-Unknown","not-forwarded")
		sign(r,token)
		before:=calls.Load()
		w:=httptest.NewRecorder()
		h.ServeHTTP(w,r)
		if w.Code!=tc.want || (calls.Load()!=before)!=tc.forwarded { t.Fatalf("response %s: got %d want %d",tc.query,w.Code,tc.want) }
		if w.Header().Get("Location")!="" || w.Header().Get("Set-Cookie")!="" || w.Header().Get("X-Secret")!="" || strings.Contains(w.Body.String(),"abcdefghijklmnopqrstuvwxyz") { t.Fatal("unsafe response metadata or body released") }
	}
	// Possession of a valid passport and proof must not bypass route policy.
	for _,tc:=range []struct{method,target,header,value string; want int}{
		{"POST","/api/db","","",403},
		{"DELETE","/api/db","","",403},
		{"HEAD","/api/db","","",403},
		{"GET","/api/db-extra","","",403},
		{"GET","/api/db/../other","","",400},
		{"GET","/api/db%2fother","","",400},
		{"GET","/api/db//other","","",400},
		{"GET","/api/db;other","","",400},
		{"GET","/api/db","X-HTTP-Method-Override","DELETE",400},
		{"GET","/api/db","Mcp-Method","tools/call",400},
		{"GET","/api/db","X-Rewrite-URL","/other",400},
	} {
		r:=httptest.NewRequest(tc.method,tc.target,nil)
		raw:=mint("service-a")
		r.Header.Set("X-Agent-Passport",raw)
		if tc.header!="" { r.Header.Set(tc.header,tc.value) }
		sign(r,raw)
		w:=httptest.NewRecorder()
		before:=calls.Load()
		h.ServeHTTP(w,r)
		if w.Code!=tc.want || calls.Load()!=before { t.Fatalf("route %s %s: status %d want %d, forwarded=%v",tc.method,tc.target,w.Code,tc.want,calls.Load()!=before) }
	}
	// A separate handler with a one-token burst proves enforcement on the
	// authenticated path, including replacement passports and route changes.
	limited:=*cfg
	limited.RateLimit=&policy.RateLimitConfig{RequestsPerMinute:1,Burst:1,MaxAgents:2}
	lh,err:=NewHandlerForAudience(up.URL,trust,&limited,"service-a",store,reg,replay,UpstreamTLSOptions{AllowLoopbackHTTP:true})
	if err!=nil { t.Fatal(err) }
	limitedRequest:=func(token,target string,want int,signed bool) {
		t.Helper()
		r:=httptest.NewRequest("GET",target,nil)
		r.Header.Set("X-Agent-Passport",token)
		if signed { sign(r,token) }
		before:=calls.Load()
		w:=httptest.NewRecorder()
		lh.ServeHTTP(w,r)
		if w.Code!=want || (calls.Load()!=before)!=(want==204) { t.Fatalf("rate limit: got %d want %d",w.Code,want) }
		if want==429 && w.Header().Get("Retry-After")!="60" { t.Fatal("missing retry-after") }
	}
	limitedRequest(mint("service-a"),"/api/db",403,false)
	limitedRequest(mint("service-a"),"/api/db",204,true)
	limitedRequest(mint("service-a"),"/api/db/items",429,true)
	// A second registered identity has an independent bucket. The test
	// upstream expects "agent", so use a separate upstream for this check.
	var otherCalls atomic.Int32
	otherUp:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		otherCalls.Add(1)
		w.WriteHeader(204)
	}))
	defer otherUp.Close()
	if err:=reg.Register(registry.Agent{ID:"second-agent",Owner:"owner",Scopes:[]string{"db:read"},Audiences:[]string{"service-a"},HolderKey:encoded}); err!=nil { t.Fatal(err) }
	other,err:=passport.MintBoundV2(priv,"second-agent","owner",[]string{"db:read"},"service-a",time.Minute,holder)
	if err!=nil { t.Fatal(err) }
	isolated,err:=NewHandlerForAudience(otherUp.URL,trust,&limited,"service-a",store,reg,replay,UpstreamTLSOptions{AllowLoopbackHTTP:true})
	if err!=nil { t.Fatal(err) }
	for _,tc:=range []struct{token string;want int}{{mint("service-a"),204},{mint("service-a"),429},{other,204},{other,429}} {
		r:=httptest.NewRequest("GET","/api/db",nil)
		r.Header.Set("X-Agent-Passport",tc.token)
		sign(r,tc.token)
		w:=httptest.NewRecorder()
		isolated.ServeHTTP(w,r)
		if w.Code!=tc.want { t.Fatalf("agent isolation: got %d want %d",w.Code,tc.want) }
	}
	if otherCalls.Load()!=2 { t.Fatal("quota denial reached upstream") }
	// A previously accepted passport is rejected immediately after revocation.
	raw:=mint("service-a")
	claims,err:=passport.VerifyV2(raw,key,"service-a")
	if err!=nil { t.Fatal(err) }
	check:=func(token string,want int){
		t.Helper()
		r:=httptest.NewRequest("GET","/api/db",nil)
		r.Header.Set("X-Agent-Passport",token)
		sign(r,token)
		w:=httptest.NewRecorder()
		h.ServeHTTP(w,r)
		if w.Code!=want { t.Fatalf("status %d want %d",w.Code,want) }
	}
	check(raw,204)
	if err:=store.Revoke(claims.ID); err!=nil { t.Fatal(err) }
	check(raw,403)
	for _,a:=range []struct{id,owner,scope string}{{"unknown","owner","db:read"},{"agent","other","db:read"},{"agent","owner","db:write"}} {
		raw,err:=passport.MintBoundV2(priv,a.id,a.owner,[]string{a.scope},"service-a",time.Minute,holder)
		if err!=nil { t.Fatal(err) }
		check(raw,403)
	}
	newPriv,newPub:=filepath.Join(dir,"new.key"),filepath.Join(dir,"new.pub")
	if err:=passport.GenerateKeyPair(newPriv,newPub); err!=nil { t.Fatal(err) }
	newKey,err:=passport.LoadPublicKey(newPub)
	if err!=nil { t.Fatal(err) }
	newID,err:=trust.Trust(newKey)
	if err!=nil { t.Fatal(err) }
	fresh,err:=passport.MintBoundV2(newPriv,"agent","owner",[]string{"db:read"},"service-a",time.Minute,holder)
	if err!=nil { t.Fatal(err) }
	check(fresh,204)
	old:=mint("service-a")
	check(old,204)
	if err:=trust.Retire(oldID); err!=nil { t.Fatal(err) }
	check(old,403)
	check(fresh,204)
	r:=httptest.NewRequest("GET","/api/db",nil)
	r.Header.Set("X-Agent-Passport",fresh)
	w0:=httptest.NewRecorder()
	h.ServeHTTP(w0,r)
	if w0.Code!=403 { t.Fatal("accepted missing proof") }
	p:=sign(r,fresh)
	request:=func(target string,proof string,want int) {
		t.Helper()
		r:=httptest.NewRequest("GET",target,nil)
		r.Header.Set("X-Agent-Passport",fresh)
		r.Header.Set(passport.ProofHeader,proof)
		w:=httptest.NewRecorder()
		h.ServeHTTP(w,r)
		if w.Code!=want { t.Fatalf("proof status %d want %d",w.Code,want) }
	}
	request("/api/db?changed=1",p,403)
	request("/api/db",p,204)
	request("/api/db",p,403)
	if err:=os.Rename(replayPath,replayPath+"-backup"); err!=nil { t.Fatal(err) }
	check(fresh,503)
	if err:=reg.Suspend("agent"); err!=nil { t.Fatal(err) }
	check(fresh,403)
	if err:=os.Rename(regPath,regPath+"-backup"); err!=nil { t.Fatal(err) }
	check(fresh,503)
	if err:=os.Rename(storePath,storePath+"-backup"); err!=nil { t.Fatal(err) }
	check(fresh,503)
	if calls.Load()!=15 { t.Fatalf("upstream calls %d want 15",calls.Load()) }
	w:=httptest.NewRecorder()
	h.ServeHTTP(w,httptest.NewRequest("GET","/.well-known/jwks.json",nil))
	var jwks passport.JWKS
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(),&jwks)!=nil || len(jwks.Keys)!=1 || jwks.Keys[0].Kid!=newID { t.Fatal("gateway published wrong key ID") }
}
