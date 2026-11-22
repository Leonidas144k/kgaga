package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

// InspectText returns true when a recognized secret pattern occurs.
func InspectText(text string) bool {
	for _,re:=range secretPatterns {
		if re.MatchString(text) { return true }
	}
	return false
}

// InspectPayload validates text/JSON and scans both raw bytes and decoded
// JSON strings (including keys). It is bounded, not comprehensive DLP.
// It does not rewrite signed content.
func InspectPayload(body []byte,jsonBody,inspectSecrets bool) error {
	return InspectPayloadWithSecret(body,jsonBody,inspectSecrets,"")
}

// InspectPayloadWithSecret also blocks an exact injected token, including
// decoded JSON strings. It is not a general information-flow guarantee.
func InspectPayloadWithSecret(body []byte,jsonBody,inspectSecrets bool,secret string) error {
	if len(body)>1<<20 || !utf8.Valid(body) { return errors.New("invalid or oversized text payload") }
	if secret!="" && bytes.Contains(body,[]byte(secret)) { return errors.New("protected credential in response") }
	if inspectSecrets && InspectText(string(body)) { return errors.New("recognized secret pattern") }
	if !jsonBody { return nil }
	if !json.Valid(body) { return errors.New("invalid JSON payload") }
	d:=json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	depth,count:=0,0
	for {
		t,err:=d.Token()
		if err==io.EOF { break }
		if err!=nil { return errors.New("invalid JSON payload") }
		count++
		if count>65536 { return errors.New("JSON token limit exceeded") }
		switch v:=t.(type) {
		case json.Delim:
			switch v { case '{','[': depth++; case '}',']': depth-- }
			if depth>32 || depth<0 { return errors.New("JSON depth limit exceeded") }
		case string:
			if strings.ContainsRune(v,utf8.RuneError) { return errors.New("invalid JSON string") }
			if secret!="" && strings.Contains(v,secret) { return errors.New("protected credential in response") }
			if inspectSecrets && InspectText(v) { return errors.New("recognized secret pattern") }
		}
	}
	return nil
}
