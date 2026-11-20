package policy

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Leonidas144k/kgaga/internal/passport"
	"gopkg.in/yaml.v3"
)

const MaxVaultGrants = 256

var ErrVaultDenied = errors.New("vault access denied")
var ErrVaultPolicy = errors.New("invalid vault policy")

// VaultOperation must be constructed by trusted gateway code using its
// configured upstream origin, the verified exact request target and the
// inspected MCP message, never from untrusted routing headers.
type VaultOperation struct {
	Origin string
	Method string
	Target string
	MCPMethod string
	Tool string
}

type vaultSelector struct {
	agent, owner, audience string
	op VaultOperation
}

type vaultGrant struct {
	scopes []string
	selection VaultSelection
}

// VaultSelection contains operator-selected metadata only. It is not a
// bearer capability and does not grant direct access to the secret store.
type VaultSelection struct {
	VaultID string
	SecretName string
	Version uint64
}

// VaultPolicy is immutable after successful parsing. An empty policy or
// missing exact grant denies access. Injection is not implemented here.
type VaultPolicy struct {
	grants map[vaultSelector]vaultGrant
}

func vaultName(s string) bool {
	if len(s)==0 || len(s)>64 { return false }
	for _,b:=range []byte(s) {
		if !(b>='a'&&b<='z' || b>='0'&&b<='9' || b=='_' || b=='-') { return false }
	}
	return true
}

func vaultID(s string) bool {
	b,err:=hex.DecodeString(s)
	return err==nil && len(b)==16 && s==hex.EncodeToString(b) && s!=strings.Repeat("0",32)
}

// exactHTTPSOrigin avoids normalization surprises. Port presence is
// significant; no wildcard, userinfo, trailing slash, query or fragment.
func exactHTTPSOrigin(raw string) bool {
	if len(raw)==0 || len(raw)>512 { return false }
	u,err:=url.Parse(raw)
	if err!=nil || u.Scheme!="https" || u.User!=nil || u.Path!="" || u.RawPath!="" ||
		u.RawQuery!="" || u.ForceQuery || u.Fragment!="" || u.Opaque!="" || u.String()!=raw { return false }
	host:=u.Hostname()
	if host=="" { return false }
	expectedHost:=host
	if ip,err:=netip.ParseAddr(host); err==nil {
		if ip.Zone()!="" || ip.String()!=host { return false }
		if ip.Is6() { expectedHost="["+host+"]" }
	} else {
		if len(host)>253 || strings.ToLower(host)!=host { return false }
		for _,part:=range strings.Split(host,".") {
			if len(part)==0 || len(part)>63 || part[0]=='-' || part[len(part)-1]=='-' { return false }
			for _,b:=range []byte(part) {
				if !(b>='a'&&b<='z' || b>='0'&&b<='9' || b=='-') { return false }
			}
		}
	}
	if p:=u.Port(); p!="" {
		n,err:=strconv.Atoi(p)
		if err!=nil || n<1 || n>65535 || strconv.Itoa(n)!=p { return false }
		expectedHost+=":"+p
	}
	return u.Host==expectedHost
}

func vaultTool(s string) bool {
	if len(s)==0 || len(s)>119 { return false }
	for _,b:=range []byte(s) {
		if !(b>='a'&&b<='z' || b>='A'&&b<='Z' || b>='0'&&b<='9' || b=='-' || b=='_' || b=='.') { return false }
	}
	return true
}

func (op VaultOperation) valid() bool {
	if !exactHTTPSOrigin(op.Origin) || !StandardMethod(op.Method) || !CanonicalPath(op.Target) || op.Target=="/.well-known/jwks.json" { return false }
	if op.Target=="/mcp" { return op.Method=="POST" && op.MCPMethod=="tools/call" && vaultTool(op.Tool) }
	return !strings.HasPrefix(op.Target,"/mcp/") && op.MCPMethod=="" && op.Tool==""
}

// LoadVaultPolicy accepts only a bounded regular file. The policy file
// and its parent hierarchy must be trusted and operator-controlled.
func LoadVaultPolicy(path string)(*VaultPolicy,error) {
	before,err:=os.Lstat(path)
	if err!=nil || !before.Mode().IsRegular() || before.Size()<1 || before.Size()>MaxConfigBytes { return nil,ErrVaultPolicy }
	f,err:=os.Open(path)
	if err!=nil { return nil,ErrVaultPolicy }
	defer f.Close()
	info,err:=f.Stat()
	if err!=nil || !info.Mode().IsRegular() || !os.SameFile(before,info) { return nil,ErrVaultPolicy }
	raw,err:=io.ReadAll(io.LimitReader(f,MaxConfigBytes+1))
	if err!=nil { return nil,ErrVaultPolicy }
	return ParseVaultPolicy(raw)
}

// ParseVaultPolicy uses the same strict YAML node checks as gateway policy.
// No aliases, unknown fields, duplicate keys, scalar coercion or multiple
// documents. Duplicate selectors are errors even when scopes differ.
func ParseVaultPolicy(raw []byte)(*VaultPolicy,error) {
	if len(raw)==0 || len(raw)>MaxConfigBytes { return nil,ErrVaultPolicy }
	d:=yaml.NewDecoder(bytes.NewReader(raw))
	var doc,extra yaml.Node
	if err:=d.Decode(&doc); err!=nil { return nil,ErrVaultPolicy }
	if err:=d.Decode(&extra); err!=io.EOF || doc.Kind!=yaml.DocumentNode || len(doc.Content)!=1 { return nil,ErrVaultPolicy }
	top,err:=mapping(doc.Content[0],"vault policy","version","vault_id","grants")
	if err!=nil { return nil,ErrVaultPolicy }
	for _,k:=range []string{"version","vault_id"} {
		if nodeType(top[k],yaml.ScalarNode,"!!str",k)!=nil { return nil,ErrVaultPolicy }
	}
	id:=top["vault_id"].Value
	if top["version"].Value!="1" || !vaultID(id) { return nil,ErrVaultPolicy }
	list:=top["grants"]
	if nodeType(list,yaml.SequenceNode,"!!seq","grants")!=nil || len(list.Content)>MaxVaultGrants { return nil,ErrVaultPolicy }
	out:=&VaultPolicy{grants:make(map[vaultSelector]vaultGrant,len(list.Content))}
	for _,node:=range list.Content {
		keys:=[]string{"agent_id","owner","audience","origin","method","target","mcp_method","tool","secret_name"}
		required:=append(slices.Clone(keys),"required_scopes","secret_version")
		g,err:=mapping(node,"grant",required...)
		if err!=nil { return nil,ErrVaultPolicy }
		for _,k:=range keys {
			if nodeType(g[k],yaml.ScalarNode,"!!str",k)!=nil { return nil,ErrVaultPolicy }
		}
		if stringList(g["required_scopes"],"required_scopes",64)!=nil ||
			nodeType(g["secret_version"],yaml.ScalarNode,"!!int","secret_version")!=nil { return nil,ErrVaultPolicy }
		scopes:=make([]string,0,len(g["required_scopes"].Content))
		for _,n:=range g["required_scopes"].Content {
			if strings.Contains(n.Value,"*") { return nil,ErrVaultPolicy }
			scopes=append(scopes,n.Value)
		}
		v,err:=strconv.ParseUint(g["secret_version"].Value,10,64)
		if err!=nil || v==0 || strconv.FormatUint(v,10)!=g["secret_version"].Value { return nil,ErrVaultPolicy }
		s:=vaultSelector{agent:g["agent_id"].Value,owner:g["owner"].Value,audience:g["audience"].Value,
			op:VaultOperation{Origin:g["origin"].Value,Method:g["method"].Value,Target:g["target"].Value,MCPMethod:g["mcp_method"].Value,Tool:g["tool"].Value}}
		if passport.ValidateIdentity(s.agent,s.owner,scopes)!=nil || passport.ValidateAudience(s.audience)!=nil ||
			strings.Contains(s.agent+s.owner+s.audience,"*") || !s.op.valid() || !vaultName(g["secret_name"].Value) { return nil,ErrVaultPolicy }
		if s.op.Tool!="" && !slices.Contains(scopes,"mcp:tool:"+s.op.Tool) { return nil,ErrVaultPolicy }
		if _,ok:=out.grants[s]; ok { return nil,ErrVaultPolicy }
		out.grants[s]=vaultGrant{scopes:scopes,selection:VaultSelection{VaultID:id,SecretName:g["secret_name"].Value,Version:v}}
	}
	return out,nil
}

// Authorize is an ADDITIONAL decision after the trusted caller has verified
// the passport, holder proof, replay, live registry/trust/revocation and
// ordinary gateway policy. Claims alone do not prove authentication.
// No secret is read; delegated passports are intentionally unsupported.
// All required scopes must be present literally: no implicit admin or
// wildcard permission, no prefix/path fallback or agent-selected secret.
func (p *VaultPolicy) Authorize(c *passport.AgentClaims,audience string,op VaultOperation)(VaultSelection,error) {
	if p==nil || c==nil || c.Delegation!=nil || c.Confirmation==nil ||
		c.Issuer!=passport.IssuerV2 || c.Subject!=c.AgentID ||
		len(c.Audience)!=1 || c.Audience[0]!=audience || !op.valid() ||
		passport.ValidateIdentity(c.AgentID,c.Owner,c.Scopes)!=nil { return VaultSelection{},ErrVaultDenied }
	thumb:=c.Confirmation.Thumbprint
	b,err:=base64.RawURLEncoding.Strict().DecodeString(thumb)
	if err!=nil || len(b)!=32 || base64.RawURLEncoding.EncodeToString(b)!=thumb { return VaultSelection{},ErrVaultDenied }
	now:=time.Now()
	if c.IssuedAt==nil || c.NotBefore==nil || c.ExpiresAt==nil ||
		!c.NotBefore.Time.Equal(c.IssuedAt.Time) || now.Before(c.NotBefore.Time) ||
		!now.Before(c.ExpiresAt.Time) || c.ExpiresAt.Time.Sub(c.IssuedAt.Time)>passport.MaxTTL { return VaultSelection{},ErrVaultDenied }
	g,ok:=p.grants[vaultSelector{agent:c.AgentID,owner:c.Owner,audience:audience,op:op}]
	if !ok { return VaultSelection{},ErrVaultDenied }
	for _,scope:=range g.scopes { if !slices.Contains(c.Scopes,scope) { return VaultSelection{},ErrVaultDenied } }
	return g.selection,nil
}
