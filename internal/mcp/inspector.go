package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"
)

const MaxPayload = 1 << 20
const maxDepth = 32
const maxTokens = 65536

// RPCRequest describes a JSON-RPC request. Security decisions use the strict decoder below.
type RPCRequest struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      any            `json:"id,omitempty"`
	Method  string         `json:"method"`
	Params  map[string]any `json:"params,omitempty"`
}

type InspectionResult struct {
	ID any
	Notification bool
	Method string
	ToolName string
	RequiredScope string
}

var invalid = errors.New("invalid or ambiguous JSON-RPC message")

// decodeValue walks every value once, preserving numbers and rejecting
// duplicate and case-folded duplicate keys at every object depth.
func decodeValue(d *json.Decoder,depth int,budget *int) (any,error) {
	if depth>maxDepth || *budget<=0 { return nil,invalid }
	*budget--
	t,err:=d.Token()
	if err!=nil { return nil,invalid }
	switch v:=t.(type) {
	case json.Delim:
		switch v {
		case '{':
			out:=map[string]any{}
			seen:=map[string]bool{}
			for d.More() {
				if *budget<=0 { return nil,invalid }
				*budget--
				k,err:=d.Token()
				if err!=nil { return nil,invalid }
				key,ok:=k.(string)
				if !ok || strings.ContainsRune(key,utf8.RuneError) { return nil,invalid }
				fold:=strings.ToLower(key)
				if seen[fold] { return nil,invalid }
				seen[fold]=true
				item,err:=decodeValue(d,depth+1,budget)
				if err!=nil { return nil,err }
				out[key]=item
			}
			close,err:=d.Token()
			if err!=nil || close!=json.Delim('}') { return nil,invalid }
			return out,nil
		case '[':
			out:=[]any{}
			for d.More() {
				item,err:=decodeValue(d,depth+1,budget)
				if err!=nil { return nil,err }
				out=append(out,item)
			}
			close,err:=d.Token()
			if err!=nil || close!=json.Delim(']') { return nil,invalid }
			return out,nil
		default:
			return nil,invalid
		}
	case string:
		// Go replaces invalid surrogate escapes with U+FFFD. Reject any
		// replacement character rather than rely on parser-specific behavior.
		if strings.ContainsRune(v,utf8.RuneError) { return nil,invalid }
		return v,nil
	case nil,bool,json.Number:
		return v,nil
	default:
		return nil,invalid
	}
}

func decode(body []byte) (map[string]any,error) {
	if len(body)==0 || len(body)>MaxPayload || !utf8.Valid(body) { return nil,invalid }
	d:=json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	budget:=maxTokens
	v,err:=decodeValue(d,0,&budget)
	if err!=nil { return nil,err }
	if _,err:=d.Token(); err!=io.EOF { return nil,invalid }
	obj,ok:=v.(map[string]any)
	if !ok { return nil,invalid }
	return obj,nil
}

func validID(v any) bool {
	switch id:=v.(type) {
	case string:
		return len(id)>0 && len(id)<=256
	case json.Number:
		n,err:=strconv.ParseInt(string(id),10,64)
		return err==nil && strconv.FormatInt(n,10)==string(id) && n>=-9007199254740991 && n<=9007199254740991
	}
	return false
}

func toolName(s string) bool {
	// Passport scopes are limited to 128 bytes including the prefix.
	if len(s)==0 || len(s)>119 { return false }
	for _,c:=range []byte(s) {
		if !(c>='a'&&c<='z'||c>='A'&&c<='Z'||c>='0'&&c<='9'||c=='_'||c=='-'||c=='.') { return false }
	}
	return true
}

// Inspect validates a deliberately limited HTTP MCP request subset, not
// full MCP schemas, session negotiation, streaming or server responses.
func Inspect(r *http.Request,body []byte) (*InspectionResult,error) {
	if r==nil || r.Method!="POST" || r.URL==nil || r.URL.Path!="/mcp" || r.URL.RawQuery!="" || r.URL.ForceQuery { return nil,errors.New("unsupported MCP transport") }
	for _,name:=range []string{"Content-Type","Content-Encoding","Mcp-Method","Mcp-Name","Mcp-Session-Id","MCP-Protocol-Version"} {
		if len(r.Header.Values(name))>1 { return nil,errors.New("ambiguous MCP header") }
	}
	if r.Header.Get("Content-Encoding")!="" || len(r.Trailer)>0 { return nil,errors.New("unsupported MCP encoding") }
	for _,value:=range r.Header.Values("Connection") {
		for _,part:=range strings.Split(value,",") {
			switch strings.ToLower(strings.TrimSpace(part)) {
			case "close","keep-alive":
			default: return nil,errors.New("unsupported MCP connection option")
			}
		}
	}
	media,params,err:=mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err!=nil || media!="application/json" { return nil,errors.New("MCP requires application/json") }
	for k,v:=range params {
		if k!="charset" || !strings.EqualFold(v,"utf-8") { return nil,errors.New("unsupported MCP content type parameter") }
	}
	return inspectMessage(body,r.Header.Get("Mcp-Method"),r.Header.Get("Mcp-Name"),len(r.Header.Values("Mcp-Name"))>0)
}

// InspectStdio uses the same strict request grammar without HTTP headers.
func InspectStdio(body []byte) (*InspectionResult,error) {
	if bytes.ContainsAny(body,"\r\n") { return nil,invalid }
	return inspectMessage(body,"","",false)
}

func inspectMessage(body []byte,methodHeader,nameHeader string,hasNameHeader bool) (*InspectionResult,error) {
	obj,err:=decode(body)
	if err!=nil { return nil,err }
	for key:=range obj {
		switch key { case "jsonrpc","id","method","params": default: return nil,invalid }
	}
	version,ok:=obj["jsonrpc"].(string)
	if !ok || version!="2.0" { return nil,invalid }
	method,ok:=obj["method"].(string)
	if !ok { return nil,invalid }
	switch method {
	case "initialize","ping","tools/list","tools/call","notifications/initialized":
	default: return nil,errors.New("unsupported MCP method")
	}
	id,present:=obj["id"]
	if method=="notifications/initialized" {
		if present { return nil,invalid }
	} else if !present || !validID(id) { return nil,invalid }
	var p map[string]any
	if raw,exists:=obj["params"]; exists {
		p,ok=raw.(map[string]any)
		if !ok { return nil,invalid }
	}
	if h:=methodHeader; h!="" && h!=method { return nil,errors.New("MCP method header mismatch") }
	res:=&InspectionResult{ID:id,Notification:!present,Method:method,RequiredScope:"mcp:method:"+method}
	if method=="tools/call" {
		// Disallow alternative spellings of the structural fields and
		// unknown tool-call fields. Arguments remain application data.
		for k:=range p {
			switch k { case "name","arguments","_meta": default: return nil,invalid }
		}
		name,ok:=p["name"].(string)
		if !ok || !toolName(name) { return nil,errors.New("invalid MCP tool name") }
		for _,k:=range []string{"arguments","_meta"} {
			if raw,exists:=p[k]; exists {
				if _,ok:=raw.(map[string]any); !ok { return nil,invalid }
			}
		}
		if h:=nameHeader; h!="" && h!=name { return nil,errors.New("MCP tool header mismatch") }
		res.ToolName=name
		res.RequiredScope="mcp:tool:"+name
	} else if hasNameHeader {
		return nil,errors.New("unexpected MCP tool header")
	}
	return res,nil
}

// ValidateStdioResponse accepts only a single result or error for the
// outstanding request. Server-initiated requests and notifications are not
// supported by the lockstep development transport.
func ValidateStdioResponse(body []byte,id any) error {
	if bytes.ContainsAny(body,"\r\n") { return invalid }
	return ValidateResponse(body,id)
}

// ValidateResponse checks the strict JSON-RPC result/error and exact ID.
func ValidateResponse(body []byte,id any) error {
	if !validID(id) { return invalid }
	obj,err:=decode(body)
	if err!=nil { return err }
	for k:=range obj { switch k { case "jsonrpc","id","result","error": default: return invalid } }
	v,ok:=obj["jsonrpc"].(string)
	if !ok || v!="2.0" || !validID(obj["id"]) || obj["id"]!=id { return invalid }
	result,hasResult:=obj["result"]
	rpcErr,hasError:=obj["error"]
	if hasResult==hasError { return invalid }
	if hasResult {
		if _,ok:=result.(map[string]any); !ok { return invalid }
		return nil
	}
	e,ok:=rpcErr.(map[string]any)
	if !ok { return invalid }
	for k:=range e { switch k { case "code","message","data": default: return invalid } }
	code,ok:=e["code"].(json.Number)
	if !ok || !validID(code) { return invalid }
	if _,ok:=e["message"].(string); !ok { return invalid }
	return nil
}
