package passport

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

var errEnvelope = errors.New("invalid or ambiguous passport envelope")

// exactObject recognizes only the supplied keys. Decode each value as raw
// JSON so duplicate keys are never merged by a map or struct decoder.
func exactObject(raw []byte,required,optional []string)(map[string]json.RawMessage,error) {
	if !utf8.Valid(raw) { return nil,errEnvelope }
	d:=json.NewDecoder(bytes.NewReader(raw))
	t,err:=d.Token()
	if err!=nil || t!=json.Delim('{') { return nil,errEnvelope }
	allowed:=map[string]bool{}
	for _,k:=range required { allowed[k]=true }
	for _,k:=range optional { allowed[k]=true }
	fields:=map[string]json.RawMessage{}
	for d.More() {
		key,err:=d.Token()
		k,ok:=key.(string)
		if err!=nil || !ok || !allowed[k] || fields[k]!=nil { return nil,errEnvelope }
		var value json.RawMessage
		if err:=d.Decode(&value); err!=nil { return nil,errEnvelope }
		fields[k]=value
	}
	t,err=d.Token()
	if err!=nil || t!=json.Delim('}') { return nil,errEnvelope }
	if _,err:=d.Token(); err!=io.EOF { return nil,errEnvelope }
	for _,k:=range required { if fields[k]==nil { return nil,errEnvelope } }
	return fields,nil
}

func exactString(raw json.RawMessage) bool {
	var s string
	return len(raw)>0 && raw[0]=='"' && json.Unmarshal(raw,&s)==nil && !strings.ContainsRune(s,utf8.RuneError)
}

func exactStrings(raw json.RawMessage) bool {
	var values []json.RawMessage
	if len(raw)==0 || raw[0]!='[' || json.Unmarshal(raw,&values)!=nil || len(values)==0 { return false }
	for _,v:=range values { if !exactString(v) { return false } }
	return true
}

func exactInteger(raw json.RawMessage) bool {
	n,err:=strconv.ParseInt(string(raw),10,64)
	return err==nil && n>0 && n<=9007199254740991 && strconv.FormatInt(n,10)==string(raw)
}

// validateEnvelope specifies the closed v2 wire schema minted by Kgaga.
// Signature and semantic checks remain mandatory after this preflight.
func validateEnvelope(raw string) error {
	if len(raw)==0 || len(raw)>maxTokenSize { return errEnvelope }
	parts:=strings.Split(raw,".")
	if len(parts)!=3 { return errEnvelope }
	decoded:=make([][]byte,3)
	for i,p:=range parts {
		b,err:=base64.RawURLEncoding.Strict().DecodeString(p)
		if err!=nil || base64.RawURLEncoding.EncodeToString(b)!=p { return errEnvelope }
		decoded[i]=b
	}
	if len(decoded[2])!=64 { return errEnvelope }
	header,err:=exactObject(decoded[0],[]string{"alg","kid","typ"},nil)
	if err!=nil { return err }
	for _,v:=range header { if !exactString(v) { return errEnvelope } }
	body,err:=exactObject(decoded[1],[]string{"agent_id","owner","scopes","iss","sub","aud","jti","iat","nbf","exp"},[]string{"cnf","delegation"})
	if err!=nil { return err }
	for _,k:=range []string{"agent_id","owner","iss","sub","jti"} { if !exactString(body[k]) { return errEnvelope } }
	for _,k:=range []string{"iat","nbf","exp"} { if !exactInteger(body[k]) { return errEnvelope } }
	if !exactStrings(body["aud"]) || !exactStrings(body["scopes"]) { return errEnvelope }
	if raw,ok:=body["cnf"]; ok {
		m,err:=exactObject(raw,[]string{"jkt"},nil)
		if err!=nil || !exactString(m["jkt"]) { return errEnvelope }
	}
	if raw,ok:=body["delegation"]; ok {
		m,err:=exactObject(raw,[]string{"parent","signature","expires"},nil)
		if err!=nil || !exactString(m["parent"]) || !exactString(m["signature"]) || !exactInteger(m["expires"]) { return errEnvelope }
	}
	return nil
}
