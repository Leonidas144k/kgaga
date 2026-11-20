package policy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Leonidas144k/kgaga/internal/passport"
	"github.com/golang-jwt/jwt/v5"
)

const vaultHeader = "version: \"1\"\nvault_id: \"1234567890abcdef1234567890abcdef\"\ngrants:\n"
const vaultGrantYAML = `  - agent_id: "agent-a"
    owner: "owner-a"
    audience: "backend"
    origin: "https://backend.example"
    method: "POST"
    target: "/api/payments"
    mcp_method: ""
    tool: ""
    required_scopes: ["payments:write", "vault:use"]
    secret_name: "service-token"
    secret_version: 2
`

func vaultClaims() *passport.AgentClaims {
	now:=time.Now().Truncate(time.Second)
	return &passport.AgentClaims{AgentID:"agent-a",Owner:"owner-a",Scopes:[]string{"payments:write","vault:use"},
		Confirmation:&passport.Confirmation{Thumbprint:"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		RegisteredClaims:jwt.RegisteredClaims{Issuer:passport.IssuerV2,Subject:"agent-a",Audience:jwt.ClaimStrings{"backend"},
			IssuedAt:jwt.NewNumericDate(now),NotBefore:jwt.NewNumericDate(now),ExpiresAt:jwt.NewNumericDate(now.Add(time.Minute))}}
}
func vaultOp() VaultOperation { return VaultOperation{Origin:"https://backend.example",Method:"POST",Target:"/api/payments"} }

func TestVaultPolicyExactAuthorization(t *testing.T) {
	p,err:=ParseVaultPolicy([]byte(vaultHeader+vaultGrantYAML))
	if err!=nil { t.Fatal(err) }
	c:=vaultClaims()
	want:=VaultSelection{VaultID:"1234567890abcdef1234567890abcdef",SecretName:"service-token",Version:2}
	got,err:=p.Authorize(c,"backend",vaultOp())
	if err!=nil || got!=want { t.Fatal("valid exact grant denied") }
	// Returned metadata cannot modify the immutable policy.
	got.SecretName="changed"
	if got,err:=p.Authorize(c,"backend",vaultOp()); err!=nil || got!=want { t.Fatal("policy mutated") }
	for _,mutate:=range []func(*passport.AgentClaims){
		func(c *passport.AgentClaims){c.AgentID="agent-b";c.Subject="agent-b"},
		func(c *passport.AgentClaims){c.Owner="owner-b"},
		func(c *passport.AgentClaims){c.Scopes=[]string{"payments:write"}},
		func(c *passport.AgentClaims){c.Scopes=[]string{"admin","vault:*"}},
		func(c *passport.AgentClaims){c.Audience=jwt.ClaimStrings{"backend","other"}},
		func(c *passport.AgentClaims){c.Confirmation=nil},
		func(c *passport.AgentClaims){c.Confirmation.Thumbprint="invalid"},
		func(c *passport.AgentClaims){c.Delegation=&passport.Delegation{}},
		func(c *passport.AgentClaims){c.ExpiresAt=jwt.NewNumericDate(time.Now().Add(-time.Second))},
		func(c *passport.AgentClaims){c.Issuer="other"},
	} {
		bad:=vaultClaims(); mutate(bad)
		if sel,err:=p.Authorize(bad,"backend",vaultOp()); !errors.Is(err,ErrVaultDenied)||sel!=(VaultSelection{}) { t.Fatal("incorrect identity or scope accepted") }
	}
	for _,op:=range []VaultOperation{
		{Origin:"https://other.example",Method:"POST",Target:"/api/payments"},
		{Origin:"http://backend.example",Method:"POST",Target:"/api/payments"},
		{Origin:"https://backend.example:443",Method:"POST",Target:"/api/payments"},
		{Origin:"https://backend.example",Method:"GET",Target:"/api/payments"},
		{Origin:"https://backend.example",Method:"POST",Target:"/api/payments/child"},
		{Origin:"https://backend.example",Method:"POST",Target:"/api/payments?"},
		{Origin:"https://backend.example",Method:"POST",Target:"/api/payments?mode=other"},
		{Origin:"https://backend.example",Method:"POST",Target:"/api/%70ayments"},
		{Origin:"https://backend.example",Method:"POST",Target:"/api/payments",Tool:"search"},
	} {
		if _,err:=p.Authorize(c,"backend",op); !errors.Is(err,ErrVaultDenied) { t.Fatal("incorrect operation accepted") }
	}
	if _,err:=p.Authorize(c,"other",vaultOp()); !errors.Is(err,ErrVaultDenied) { t.Fatal("wrong audience accepted") }
	var nilPolicy *VaultPolicy
	if _,err:=nilPolicy.Authorize(c,"backend",vaultOp()); !errors.Is(err,ErrVaultDenied) { t.Fatal("nil policy allowed") }
	empty,err:=ParseVaultPolicy([]byte(strings.TrimSuffix(vaultHeader,"\n")+" []\n"))
	if err!=nil { t.Fatal(err) }
	if _,err:=empty.Authorize(c,"backend",vaultOp()); !errors.Is(err,ErrVaultDenied) { t.Fatal("empty policy allowed") }
}

func TestVaultPolicyMCPExactTool(t *testing.T) {
	grant:=strings.NewReplacer("/api/payments","/mcp",`mcp_method: ""`,`mcp_method: "tools/call"`,`tool: ""`,`tool: "search"`,"payments:write","mcp:tool:search").Replace(vaultGrantYAML)
	p,err:=ParseVaultPolicy([]byte(vaultHeader+grant))
	if err!=nil { t.Fatal(err) }
	c:=vaultClaims(); c.Scopes=[]string{"mcp:tool:search","vault:use"}
	op:=VaultOperation{Origin:"https://backend.example",Method:"POST",Target:"/mcp",MCPMethod:"tools/call",Tool:"search"}
	if _,err:=p.Authorize(c,"backend",op); err!=nil { t.Fatal(err) }
	bad:=op; bad.Tool="read_file"
	if _,err:=p.Authorize(c,"backend",bad); !errors.Is(err,ErrVaultDenied) { t.Fatal("wrong tool accepted") }
	bad=op; bad.MCPMethod="tools/list"
	if _,err:=p.Authorize(c,"backend",bad); !errors.Is(err,ErrVaultDenied) { t.Fatal("wrong RPC method accepted") }
	if _,err:=ParseVaultPolicy([]byte(vaultHeader+strings.Replace(grant,"mcp:tool:search","admin",1))); err==nil { t.Fatal("missing tool scope accepted") }
}

func TestVaultPolicyStrictParser(t *testing.T) {
	valid:=vaultHeader+vaultGrantYAML
	for _,raw:=range []string{
		valid+"---\n"+valid,
		valid+vaultGrantYAML,
		strings.Replace(valid,`version: "1"`,"version: 1",1),
		strings.Replace(valid,`version: "1"`,"version: &v \"1\"",1),
		strings.Replace(valid,`version: "1"`,"version: !!str 1",1),
		strings.Replace(valid,`owner: "owner-a"`,`owner: "*"`,1),
		strings.Replace(valid,`owner: "owner-a"`,"owner: owner-a\n    owner: other",1),
		strings.Replace(valid,`origin: "https://backend.example"`,`origin: "https://user@backend.example"`,1),
		strings.Replace(valid,"https://backend.example","http://backend.example",1),
		strings.Replace(valid,"https://backend.example","https://backend.example/",1),
		strings.Replace(valid,"https://backend.example","https://backend.example:0443",1),
		strings.Replace(valid,"https://backend.example","https://backend.example:0",1),
		strings.Replace(valid,"/api/payments","/api/../payments",1),
		strings.Replace(valid,"/api/payments","/.well-known/jwks.json",1),
		strings.Replace(valid,"service-token","../service-token",1),
		strings.Replace(valid,"secret_version: 2","secret_version: 0",1),
		strings.Replace(valid,"secret_version: 2","secret_version: 0x2",1),
		strings.Replace(valid,"secret_version: 2","secret_version: \"2\"",1),
		strings.Replace(valid,"secret_version: 2","secret_version: 2\n    header: Authorization",1),
		strings.Replace(valid,`["payments:write", "vault:use"]`,"[]",1),
		strings.Replace(valid,`["payments:write", "vault:use"]`,`["vault:*"]`,1),
		strings.Replace(valid,`["payments:write", "vault:use"]`,`["vault:use","vault:use"]`,1),
		strings.Replace(valid,`    tool: ""`+"\n","",1),
		strings.Replace(valid,"1234567890abcdef1234567890abcdef",strings.Repeat("0",32),1),
		strings.Repeat("a",MaxConfigBytes+1),
	} {
		if p,err:=ParseVaultPolicy([]byte(raw)); err==nil || p!=nil { t.Fatal("invalid policy accepted") }
	}
}

func TestVaultPolicyLoad(t *testing.T) {
	dir:=t.TempDir(); path:=filepath.Join(dir,"policy.yaml")
	if err:=os.WriteFile(path,[]byte(vaultHeader+vaultGrantYAML),0600); err!=nil { t.Fatal(err) }
	if _,err:=LoadVaultPolicy(path); err!=nil { t.Fatal(err) }
	if err:=os.Symlink(path,path+".link"); err!=nil { t.Fatal(err) }
	if _,err:=LoadVaultPolicy(path+".link"); err==nil { t.Fatal("symlink policy accepted") }
	if _,err:=LoadVaultPolicy(dir); err==nil { t.Fatal("directory policy accepted") }
}
