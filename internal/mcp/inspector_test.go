package mcp

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStrictInspection(t *testing.T) {
	good:=`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":{"query":"hello"}}}`
	for _,tc:=range []struct{name,body string}{
		{"batch","["+good+"]"},
		{"trailing",good+" {}"},
		{"duplicate method",strings.Replace(good,`"method":"tools/call"`,`"method":"tools/call","method":"tools/list"`,1)},
		{"case alias",strings.Replace(good,`"method":"tools/call"`,`"Method":"tools/call"`,1)},
		{"duplicate escaped key",strings.Replace(good,`"name":"search"`,`"name":"search","\u006eame":"other"`,1)},
		{"nested duplicate",strings.Replace(good,`"query":"hello"`,`"query":"hello","Query":"other"`,1)},
		{"unknown field",strings.Replace(good,`"id":1`,`"id":1,"result":{}`,1)},
		{"null ID",strings.Replace(good,`"id":1`,`"id":null`,1)},
		{"fractional ID",strings.Replace(good,`"id":1`,`"id":1.0`,1)},
		{"large ID",strings.Replace(good,`"id":1`,`"id":9007199254740992`,1)},
		{"missing ID",strings.Replace(good,`"id":1,`,"",1)},
		{"unknown method",strings.Replace(good,"tools/call","unknown/method",1)},
		{"invalid tool",strings.Replace(good,`"search"`,`"*"`,1)},
		{"invalid arguments",strings.Replace(good,`{"query":"hello"}`,"[]",1)},
		{"invalid params",`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":null}`},
		{"invalid surrogate",strings.Replace(good,"hello",`\ud800`,1)},
		{"invalid UTF8",strings.Replace(good,"hello",string([]byte{0xff}),1)},
		{"too deep",strings.Replace(good,`"hello"`,strings.Repeat("[",40)+"0"+strings.Repeat("]",40),1)},
		{"too many tokens",strings.Replace(good,`"hello"`,"["+strings.Repeat("0,",65536)+"0]",1)},
	} {
		t.Run(tc.name,func(t *testing.T){
			r:=httptest.NewRequest("POST","/mcp",nil)
			r.Header.Set("Content-Type","application/json")
			if _,err:=Inspect(r,[]byte(tc.body)); err==nil { t.Fatal("accepted invalid message") }
		})
	}
	r:=httptest.NewRequest("POST","/mcp",nil)
	r.Header.Set("Content-Type","application/json; charset=utf-8")
	r.Header.Set("Mcp-Method","tools/call")
	r.Header.Set("Mcp-Name","search")
	got,err:=Inspect(r,[]byte(good))
	if err!=nil || got.RequiredScope!="mcp:tool:search" { t.Fatalf("valid request rejected: %v",err) }
	r.Header.Add("Mcp-Name","search")
	if _,err:=Inspect(r,[]byte(good)); err==nil { t.Fatal("duplicate header accepted") }
	r.Header.Set("Mcp-Name","other")
	if _,err:=Inspect(r,[]byte(good)); err==nil { t.Fatal("mismatch accepted") }
	r.Header.Set("Mcp-Name","search")
	r.Header.Set("Connection","Mcp-Method")
	if _,err:=Inspect(r,[]byte(good)); err==nil { t.Fatal("unsafe connection option accepted") }
	r.Header.Del("Connection")
	r.Header.Set("Content-Type","text/plain")
	if _,err:=Inspect(r,[]byte(good)); err==nil { t.Fatal("invalid media type accepted") }
}

func TestSupportedMethods(t *testing.T) {
	for _,body:=range []string{
		`{"jsonrpc":"2.0","id":"1","method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":1,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
	} {
		r:=httptest.NewRequest("POST","/mcp",nil)
		r.Header.Set("Content-Type","application/json")
		if _,err:=Inspect(r,[]byte(body)); err!=nil { t.Fatal(err) }
	}
}
