package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"

	"gopkg.in/yaml.v3"
)

const MaxConfigBytes = 128 << 10
const maxRules = 256

// Load accepts a bounded, single-document policy with an explicit schema.
// No aliases, anchors, merge keys, custom tags or scalar coercion.
func Load(path string) (*Config,error) {
	f,err:=os.Open(path)
	if err!=nil { return nil,err }
	defer f.Close()
	info,err:=f.Stat()
	if err!=nil { return nil,err }
	if !info.Mode().IsRegular() { return nil,errors.New("policy must be a regular file") }
	data,err:=io.ReadAll(io.LimitReader(f,MaxConfigBytes+1))
	if err!=nil { return nil,err }
	return Parse(data)
}

// Parse validates YAML node types and exact field names before decoding.
func Parse(data []byte) (*Config,error) {
	if len(data)==0 || len(data)>MaxConfigBytes { return nil,errors.New("policy size invalid") }
	d:=yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err:=d.Decode(&doc); err!=nil { return nil,fmt.Errorf("invalid policy YAML: %w",err) }
	var extra yaml.Node
	if err:=d.Decode(&extra); err!=io.EOF { return nil,errors.New("policy must contain exactly one YAML document") }
	if doc.Kind!=yaml.DocumentNode || len(doc.Content)!=1 { return nil,errors.New("invalid policy document") }
	root:=doc.Content[0]
	fields,err:=mappingOptional(root,"policy",[]string{"version","redact_secrets","mcp","rules"},"rate_limit")
	if err!=nil { return nil,err }
	if err:=nodeType(fields["version"],yaml.ScalarNode,"!!str","version"); err!=nil { return nil,err }
	if err:=nodeType(fields["redact_secrets"],yaml.ScalarNode,"!!bool","redact_secrets"); err!=nil { return nil,err }
	if v:=fields["redact_secrets"].Value; v!="true" && v!="false" { return nil,errors.New("redact_secrets must be true or false") }
	if node,ok:=fields["rate_limit"]; ok {
		r,err:=mapping(node,"rate_limit","requests_per_minute","burst","max_agents")
		if err!=nil { return nil,err }
		for _,name:=range []string{"requests_per_minute","burst","max_agents"} {
			n:=r[name]
			if err:=nodeType(n,yaml.ScalarNode,"!!int","rate_limit."+name); err!=nil { return nil,err }
			v,err:=strconv.Atoi(n.Value)
			if err!=nil || strconv.Itoa(v)!=n.Value { return nil,fmt.Errorf("rate_limit.%s: expected decimal integer",name) }
		}
	}
	mcp,err:=mapping(fields["mcp"],"mcp","allowed_tools","denied_tools")
	if err!=nil { return nil,err }
	for _,name:=range []string{"allowed_tools","denied_tools"} {
		if err:=stringList(mcp[name],"mcp."+name,256); err!=nil { return nil,err }
	}
	rules:=fields["rules"]
	if err:=nodeType(rules,yaml.SequenceNode,"!!seq","rules"); err!=nil { return nil,err }
	if len(rules.Content)>maxRules { return nil,errors.New("too many policy rules") }
	for i,n:=range rules.Content {
		label:=fmt.Sprintf("rules[%d]",i)
		r,err:=mapping(n,label,"path_prefix","allowed_scopes","allowed_methods","deny_methods")
		if err!=nil { return nil,err }
		if err:=nodeType(r["path_prefix"],yaml.ScalarNode,"!!str",label+".path_prefix"); err!=nil { return nil,err }
		for _,name:=range []string{"allowed_scopes","allowed_methods","deny_methods"} {
			if err:=stringList(r[name],label+"."+name,64); err!=nil { return nil,err }
		}
	}
	var cfg Config
	if err:=root.Decode(&cfg); err!=nil { return nil,err }
	if err:=cfg.Validate(); err!=nil { return nil,err }
	return &cfg,nil
}

func nodeType(n *yaml.Node,kind yaml.Kind,tag,label string) error {
	if n==nil || n.Kind!=kind || n.Tag!=tag || n.Anchor!="" || n.Alias!=nil || n.Style&yaml.TaggedStyle!=0 {
		return fmt.Errorf("%s: invalid YAML type, alias, anchor or tag",label)
	}
	return nil
}

func mapping(n *yaml.Node,label string,required ...string)(map[string]*yaml.Node,error) {
	return mappingOptional(n,label,required)
}

func mappingOptional(n *yaml.Node,label string,required []string,optional ...string)(map[string]*yaml.Node,error) {
	if err:=nodeType(n,yaml.MappingNode,"!!map",label); err!=nil { return nil,err }
	out:=make(map[string]*yaml.Node,len(required))
	for i:=0;i<len(n.Content);i+=2 {
		key:=n.Content[i]
		if err:=nodeType(key,yaml.ScalarNode,"!!str",label+" key"); err!=nil { return nil,err }
		if !slices.Contains(required,key.Value) && !slices.Contains(optional,key.Value) { return nil,fmt.Errorf("%s: unknown field %q",label,key.Value) }
		if _,exists:=out[key.Value]; exists { return nil,fmt.Errorf("%s: duplicate field %q",label,key.Value) }
		out[key.Value]=n.Content[i+1]
	}
	for _,key:=range required {
		if _,exists:=out[key]; !exists { return nil,fmt.Errorf("%s: missing required field %q",label,key) }
	}
	return out,nil
}

func stringList(n *yaml.Node,label string,max int) error {
	if err:=nodeType(n,yaml.SequenceNode,"!!seq",label); err!=nil { return err }
	if len(n.Content)>max { return fmt.Errorf("%s: too many values",label) }
	for _,v:=range n.Content {
		if err:=nodeType(v,yaml.ScalarNode,"!!str",label+" value"); err!=nil { return err }
	}
	return nil
}

func visible(s string,max int) bool {
	if len(s)==0 || len(s)>max { return false }
	for _,c:=range []byte(s) { if c<33 || c>126 { return false } }
	return true
}

func unique(values []string,max int,label string,valid func(string)bool) error {
	if len(values)>max { return fmt.Errorf("%s: too many values",label) }
	seen:=map[string]bool{}
	for _,v:=range values {
		if !valid(v) || seen[v] { return fmt.Errorf("%s: invalid or duplicate value",label) }
		seen[v]=true
	}
	return nil
}

// Validate also protects programmatic gateway construction. An empty rules
// list denies all HTTP requests. An empty MCP tool allowlist denies tools.
func (c *Config) Validate() error {
	if c==nil { return errors.New("policy configuration required") }
	if c.Version!="2" { return errors.New("policy version unsupported: use version 2") }
	if c.RateLimit!=nil { if err:=c.RateLimit.Validate(); err!=nil { return err } }
	if len(c.Rules)>maxRules { return errors.New("too many policy rules") }
	if err:=unique(c.MCP.AllowedTools,256,"mcp.allowed_tools",func(v string)bool{return visible(v,128)}); err!=nil { return err }
	if err:=unique(c.MCP.DeniedTools,256,"mcp.denied_tools",func(v string)bool{return visible(v,128)&&v!="*"}); err!=nil { return err }
	if slices.Contains(c.MCP.AllowedTools,"*") && len(c.MCP.AllowedTools)!=1 { return errors.New("mcp.allowed_tools: wildcard must be the only entry") }
	prefixes:=map[string]bool{}
	for i,r:=range c.Rules {
		label:=fmt.Sprintf("rules[%d]",i)
		if !CanonicalPath(r.PathPrefix) || prefixes[r.PathPrefix] { return fmt.Errorf("%s: invalid or duplicate path_prefix",label) }
		prefixes[r.PathPrefix]=true
		if len(r.AllowedScopes)==0 || len(r.AllowedMethods)==0 { return fmt.Errorf("%s: allowed_scopes and allowed_methods must be nonempty",label) }
		if err:=unique(r.AllowedScopes,64,label+".allowed_scopes",func(v string)bool{return visible(v,128)}); err!=nil { return err }
		if err:=unique(r.AllowedMethods,7,label+".allowed_methods",StandardMethod); err!=nil { return err }
		if err:=unique(r.DenyMethods,7,label+".deny_methods",StandardMethod); err!=nil { return err }
	}
	return nil
}

// Snapshot validates and copies all slices so a caller cannot later
// mutate a running gateway's policy. Reload requires a new handler.
func (c *Config) Snapshot() (*Config,error) {
	if err:=c.Validate(); err!=nil { return nil,err }
	out:=*c
	rate:=DefaultRateLimit()
	if c.RateLimit!=nil { rate=*c.RateLimit }
	out.RateLimit=&rate
	out.MCP.AllowedTools=slices.Clone(c.MCP.AllowedTools)
	out.MCP.DeniedTools=slices.Clone(c.MCP.DeniedTools)
	out.Rules=slices.Clone(c.Rules)
	for i:=range out.Rules {
		out.Rules[i].AllowedScopes=slices.Clone(c.Rules[i].AllowedScopes)
		out.Rules[i].AllowedMethods=slices.Clone(c.Rules[i].AllowedMethods)
		out.Rules[i].DenyMethods=slices.Clone(c.Rules[i].DenyMethods)
	}
	return &out,nil
}
