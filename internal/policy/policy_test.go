package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStrictHTTPPolicy(t *testing.T) {
	c:=Config{Rules:[]Rule{
		{PathPrefix:"/api",AllowedMethods:[]string{"GET"},AllowedScopes:[]string{"read"}},
		{PathPrefix:"/api/private",AllowedMethods:[]string{"GET","DELETE"},AllowedScopes:[]string{"admin"},DenyMethods:[]string{"DELETE"}},
	}}
	for _,tc:=range []struct{method,path,scope string; allow bool}{
		{"GET","/api","read",true},
		{"GET","/api/items","read",true},
		{"GET","/apix","read",false},
		{"GET","/api/private","read",false},
		{"GET","/api/private/items","admin",true},
		{"GET","/api/private-x","read",true},
		{"POST","/api","read",false},
		{"HEAD","/api","read",false},
		{"DELETE","/api/private","admin",false},
		{"get","/api","read",false},
		{"CONNECT","/api","read",false},
		{"GET","/api/../private","read",false},
		{"GET","/api//items","read",false},
		{"GET","/api/items/","read",false},
		{"GET","/api/%2f","read",false},
		{"GET","/api/items;other","read",false},
		{"GET","/api/items","admin",false},
	} {
		ok,_:=c.Authorize(tc.method,tc.path,[]string{tc.scope})
		if ok!=tc.allow { t.Errorf("%s %s %s: got %t want %t",tc.method,tc.path,tc.scope,ok,tc.allow) }
	}
	c.Rules=append(c.Rules,c.Rules[1])
	if ok,_:=c.Authorize("GET","/api/private",[]string{"admin"}); ok { t.Fatal("duplicate prefix accepted") }
	if ok,_:=(&Config{Rules:[]Rule{{PathPrefix:"/",AllowedScopes:[]string{"read"}}}}).Authorize("GET","/x",[]string{"read"}); ok { t.Fatal("missing method allowlist accepted") }
}

func TestPolicyVersionMigration(t *testing.T) {
	p:=filepath.Join(t.TempDir(),"policy.yaml")
	if err:=os.WriteFile(p,[]byte("version: \"1\"\n"),0600); err!=nil { t.Fatal(err) }
	if _,err:=Load(p); err==nil { t.Fatal("old policy silently accepted") }
	if err:=os.WriteFile(p,[]byte(DefaultConfigYAML),0600); err!=nil { t.Fatal(err) }
	c,err:=Load(p)
	if err!=nil { t.Fatal(err) }
	if ok,_:=c.Authorize("GET","/api/db",[]string{"db:read"}); !ok { t.Fatal("default read denied") }
	if ok,_:=c.Authorize("POST","/api/db",[]string{"db:read"}); ok { t.Fatal("default read permits write") }
}
