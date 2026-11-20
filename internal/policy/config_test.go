package policy

import (
	"strings"
	"testing"
)

func TestStrictConfig(t *testing.T) {
	good:=DefaultConfigYAML
	for _,tc:=range []struct{name,raw string}{
		{"unknown root",good+"unexpected: true\n"},
		{"unknown rule",strings.Replace(good,"deny_methods: [\"DELETE\"]","deny_method: [\"DELETE\"]",1)},
		{"duplicate key",good+"version: \"2\"\n"},
		{"multiple docs",good+"\n---\n"+good},
		{"version integer",strings.Replace(good,"version: \"2\"","version: 2",1)},
		{"boolean string",strings.Replace(good,"redact_secrets: true","redact_secrets: \"true\"",1)},
		{"missing redaction",strings.Replace(good,"redact_secrets: true\n","",1)},
		{"missing mcp list",strings.Replace(good,"  denied_tools: [\"execute_shell\", \"drop_table\"]\n","",1)},
		{"anchor",strings.Replace(good,"[\"GET\", \"HEAD\"]","&methods [\"GET\", \"HEAD\"]",1)},
		{"alias",strings.Replace(good,"[\"GET\", \"HEAD\"]","*methods",1)},
		{"tag",strings.Replace(good,"version: \"2\"","version: !!str 2",1)},
		{"merge",strings.Replace(good,"mcp:\n","mcp:\n  <<: {}\n",1)},
		{"null list",strings.Replace(good,"[\"GET\", \"HEAD\"]","null",1)},
		{"nonstring scope",strings.Replace(good,"[\"db:read\", \"admin\"]","[42]",1)},
		{"unknown method",strings.Replace(good,"\"HEAD\"","\"CONNECT\"",1)},
		{"lowercase method",strings.Replace(good,"\"HEAD\"","\"head\"",1)},
		{"duplicate method",strings.Replace(good,"\"HEAD\"","\"GET\"",1)},
		{"missing allowlist",strings.Replace(good,"    allowed_methods: [\"GET\", \"HEAD\"]\n","",1)},
		{"empty method list",strings.Replace(good,"[\"GET\", \"HEAD\"]","[]",1)},
		{"empty scope",strings.Replace(good,"[\"db:read\", \"admin\"]","[]",1)},
		{"duplicate route",strings.Replace(good,"/api/payments","/api/db",1)},
		{"bad route",strings.Replace(good,"/api/db","/api//db",1)},
		{"mixed wildcard",strings.Replace(good,"\"search\", \"read_file\"","\"*\", \"read_file\"",1)},
		{"oversize",strings.Repeat(" ",MaxConfigBytes+1)},
	} {
		t.Run(tc.name,func(t *testing.T){ if _,err:=Parse([]byte(tc.raw)); err==nil { t.Fatal("invalid policy accepted") } })
	}
	c,err:=Parse([]byte(good))
	if err!=nil { t.Fatal(err) }
	snapshot,err:=c.Snapshot()
	if err!=nil { t.Fatal(err) }
	c.Rules[0].AllowedMethods[0]="POST"
	c.MCP.AllowedTools[0]="other"
	if ok,_:=snapshot.Authorize("GET","/api/db",[]string{"db:read"}); !ok { t.Fatal("snapshot mutated") }
	if ok,_:=snapshot.AuthorizeMCP("tools/call","search","mcp:tool:search",[]string{"mcp:tool:search"}); !ok { t.Fatal("snapshot tool list mutated") }
}

func TestExplicitEmptyToolAllowlist(t *testing.T) {
	c,err:=Parse([]byte("version: \"2\"\nredact_secrets: false\nmcp: {allowed_tools: [], denied_tools: []}\nrules: []\n"))
	if err!=nil { t.Fatal(err) }
	if ok,_:=c.Authorize("GET","/",[]string{"admin"}); ok { t.Fatal("empty rules permitted HTTP") }
	if ok,_:=c.AuthorizeMCP("tools/call","search","mcp:tool:search",[]string{"admin"}); ok { t.Fatal("empty allowlist permitted tool") }
}

func TestRateLimitConfig(t *testing.T) {
	base:=strings.Replace(DefaultConfigYAML,"rate_limit:\n  requests_per_minute: 120\n  burst: 40\n  max_agents: 4096\n\n","",1)
	c,err:=Parse([]byte(base))
	if err!=nil { t.Fatal(err) }
	s,err:=c.Snapshot()
	if err!=nil || s.RateLimit==nil || *s.RateLimit!=DefaultRateLimit() { t.Fatal("missing mandatory default") }
	for _,block:=range []string{
		"rate_limit: null",
		"rate_limit: {requests_per_minute: 0, burst: 2, max_agents: 1}",
		"rate_limit: {requests_per_minute: 6001, burst: 2, max_agents: 1}",
		"rate_limit: {requests_per_minute: 10, burst: 0, max_agents: 1}",
		"rate_limit: {requests_per_minute: 10, burst: 2, max_agents: 16385}",
		"rate_limit: {requests_per_minute: 10, burst: 2}",
		"rate_limit: {requests_per_minute: 10, burst: 2, max_agents: 1, enabled: false}",
		"rate_limit: {requests_per_minute: \"10\", burst: 2, max_agents: 1}",
		"rate_limit: {requests_per_minute: 0x10, burst: 2, max_agents: 1}",
		"rate_limit: {requests_per_minute: 10, burst: 2, burst: 3, max_agents: 1}",
	} { if _,err:=Parse([]byte(base+"\n"+block+"\n")); err==nil { t.Fatalf("invalid rate config accepted: %s",block) } }
	c,err=Parse([]byte(base+"\nrate_limit: {requests_per_minute: 10, burst: 2, max_agents: 1}\n"))
	if err!=nil { t.Fatal(err) }
	s,err=c.Snapshot()
	if err!=nil { t.Fatal(err) }
	c.RateLimit.Burst=99
	if s.RateLimit.Burst!=2 { t.Fatal("rate snapshot mutated") }
}
