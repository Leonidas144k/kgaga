package passport

import (
	"path/filepath"
	"testing"
	"time"
)

func TestRequestProof(t *testing.T) {
	dir:=t.TempDir()
	priv,pub:=filepath.Join(dir,"holder.key"),filepath.Join(dir,"holder.pub")
	if err:=GenerateKeyPair(priv,pub); err!=nil { t.Fatal(err) }
	key,err:=LoadPublicKey(pub)
	if err!=nil { t.Fatal(err) }
	now:=time.Now()
	r:=RequestBinding{Method:"POST",Target:"/mcp?x=1",ContentType:"application/json",MCPMethod:"tools/call",Body:[]byte("abc")}
	p,err:=SignRequest(priv,"token",r,now)
	if err!=nil { t.Fatal(err) }
	if _,err:=VerifyRequest(p,"token",key,r,now); err!=nil { t.Fatal(err) }
	for _,mutate:=range []func(*RequestBinding){
		func(b *RequestBinding){ b.Method="GET" },
		func(b *RequestBinding){ b.Target="/mcp?x=2" },
		func(b *RequestBinding){ b.Body=[]byte("xyz") },
		func(b *RequestBinding){ b.ContentType="text/plain" },
		func(b *RequestBinding){ b.MCPMethod="tools/list" },
		func(b *RequestBinding){ b.MCPSession="new" },
	} {
		b:=r; mutate(&b)
		if _,err:=VerifyRequest(p,"token",key,b,now); err==nil { t.Fatal("accepted changed request") }
	}
	if _,err:=VerifyRequest(p,"different",key,r,now); err==nil { t.Fatal("accepted different passport") }
	if _,err:=VerifyRequest(p,"token",key,r,now.Add(31*time.Second)); err==nil { t.Fatal("accepted expired proof") }
	if _,err:=VerifyRequest(p,"token",key,r,now.Add(-6*time.Second)); err==nil { t.Fatal("accepted future proof") }
	otherPriv,otherPub:=filepath.Join(dir,"other.key"),filepath.Join(dir,"other.pub")
	if err:=GenerateKeyPair(otherPriv,otherPub); err!=nil { t.Fatal(err) }
	other,err:=LoadPublicKey(otherPub)
	if err!=nil { t.Fatal(err) }
	if _,err:=VerifyRequest(p,"token",other,r,now); err==nil { t.Fatal("accepted wrong holder") }
}
