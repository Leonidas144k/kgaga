package mcp

import "testing"

func TestStdioResponseBinding(t *testing.T) {
	req,err:=InspectStdio([]byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	if err!=nil { t.Fatal(err) }
	if err:=ValidateStdioResponse([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`),req.ID); err!=nil { t.Fatal(err) }
	if err:=ValidateStdioResponse([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"test"}}`),req.ID); err!=nil { t.Fatal(err) }
	for _,body:=range []string{
		`{"jsonrpc":"2.0","id":2,"result":{}}`,
		`{"jsonrpc":"2.0","id":"1","result":{}}`,
		`{"jsonrpc":"2.0","id":1,"id":2,"result":{}}`,
		`{"jsonrpc":"2.0","id":1,"result":{},"error":{}}`,
		`{"jsonrpc":"2.0","id":1,"method":"ping"}`,
		`{"jsonrpc":"2.0","method":"notifications/message"}`,
		`{"jsonrpc":"2.0","id":1,"result":{"x":1,"X":2}}`,
	} { if err:=ValidateStdioResponse([]byte(body),req.ID); err==nil { t.Fatal("invalid response accepted") } }
}
