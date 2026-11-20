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
