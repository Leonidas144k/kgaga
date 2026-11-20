package proxy

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Leonidas144k/kgaga/internal/keyring"
	"github.com/Leonidas144k/kgaga/internal/passport"
	"github.com/Leonidas144k/kgaga/internal/policy"
	"github.com/Leonidas144k/kgaga/internal/registry"
	"github.com/Leonidas144k/kgaga/internal/revocation"
)

func TestStdioFrameAuthentication(t *testing.T) {
	dir:=t.TempDir()
	priv,pub:=filepath.Join(dir,"issuer.key"),filepath.Join(dir,"issuer.pub")
	hpriv,hpub:=filepath.Join(dir,"holder.key"),filepath.Join(dir,"holder.pub")
	if err:=passport.GenerateKeyPair(priv,pub); err!=nil { t.Fatal(err) }
	if err:=passport.GenerateKeyPair(hpriv,hpub); err!=nil { t.Fatal(err) }
	issuer,err:=passport.LoadPublicKey(pub); if err!=nil { t.Fatal(err) }
	holder,err:=passport.LoadPublicKey(hpub); if err!=nil { t.Fatal(err) }
	encoded,err:=registry.EncodeHolder(holder); if err!=nil { t.Fatal(err) }
	td,rd,vd,pd:=filepath.Join(dir,"trust"),filepath.Join(dir,"reg"),filepath.Join(dir,"rev"),filepath.Join(dir,"replay")
	if err:=keyring.Init(td); err!=nil { t.Fatal(err) }
	if err:=registry.Init(rd); err!=nil { t.Fatal(err) }
	if err:=revocation.Init(vd); err!=nil { t.Fatal(err) }
	if err:=revocation.Init(pd); err!=nil { t.Fatal(err) }
	trust,err:=keyring.Open(td); if err!=nil { t.Fatal(err) }
	if _,err:=trust.Trust(issuer); err!=nil { t.Fatal(err) }
	reg,err:=registry.Open(rd); if err!=nil { t.Fatal(err) }
	if err:=reg.Register(registry.Agent{ID:"agent",Owner:"owner",Scopes:[]string{"mcp:tool:search"},Audiences:[]string{"stdio-api"},HolderKey:encoded}); err!=nil { t.Fatal(err) }
	rev,err:=revocation.Open(vd); if err!=nil { t.Fatal(err) }
	replay,err:=revocation.Open(pd); if err!=nil { t.Fatal(err) }
	token,err:=passport.MintBoundV2(priv,"agent","owner",[]string{"mcp:tool:search"},"stdio-api",time.Minute,holder); if err!=nil { t.Fatal(err) }
	cfg:=&policy.Config{Version:"2",MCP:policy.MCPPolicy{AllowedTools:[]string{"search"}}}
	body:=[]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search"}}`)
	frame,err:=SignStdioFrame(hpriv,token,body); if err!=nil { t.Fatal(err) }
	_,proof,decoded,err:=parseFrame(frame); if err!=nil || !bytes.Equal(decoded,body) { t.Fatal("frame roundtrip failed") }
	if _,err:=passport.VerifyRequest(proof,token,holder,passport.RequestBinding{Method:"POST",Target:"/mcp",ContentType:"application/json",Body:body},time.Now()); err==nil { t.Fatal("stdio proof accepted as HTTP") }
	bad,err:=SignStdioFrame(priv,token,body); if err!=nil { t.Fatal(err) }
	denied,err:=SignStdioFrame(hpriv,token,[]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"other"}}`)); if err!=nil { t.Fatal(err) }
	run:=func(line string)error {
		var out bytes.Buffer
		err:=RunStdioProxy(filepath.Join(dir,"must-not-start"),nil,cfg,"stdio-api",trust,reg,rev,replay,strings.NewReader(line+"\n"),&out)
		if out.Len()!=0 { t.Fatal("rejected frame returned output") }
		return err
	}
	for _,tc:=range []struct{line,want string}{{string(body),"invalid signed stdio frame"},{bad,"stdio proof rejected"},{denied,"stdio policy denied"}} {
		if err:=run(tc.line); err==nil || err.Error()!=tc.want { t.Fatalf("want %s, got %v",tc.want,err) }
	}
	// A valid proof reaches the execution boundary, where the nonexistent
	// child fails. Its nonce remains consumed even when launching fails.
	if err:=run(frame); err==nil || !strings.Contains(err.Error(),"must-not-start") { t.Fatalf("expected launch failure, got %v",err) }
	if err:=run(frame); err==nil || err.Error()!="stdio replay check rejected" { t.Fatalf("replay: %v",err) }
	claims,err:=trust.Verify(token,"stdio-api"); if err!=nil { t.Fatal(err) }
	if err:=rev.Revoke(claims.ID); err!=nil { t.Fatal(err) }
	fresh,err:=SignStdioFrame(hpriv,token,body); if err!=nil { t.Fatal(err) }
	if err:=run(fresh); err==nil || err.Error()!="stdio revocation check rejected" { t.Fatalf("revocation: %v",err) }
}
