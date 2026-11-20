package policy

import (
	"strings"
	"testing"
)

func TestInspectPayload(t *testing.T) {
	for _,tc:=range []struct{body string; json,enabled,deny bool}{
		{`{"ok":true}`,true,true,false},
		{`{"value":"\u0073k-abcdefghijklmnopqrstuvwxyz"}`,true,true,true},
		{`{"\u0073k-abcdefghijklmnopqrstuvwxyz":true}`,true,true,true},
		{"AKIAABCDEFGHIJKLMNOP",false,true,true},
		{`{"value":"sk-abcdefghijklmnopqrstuvwxyz"}`,true,false,false},
		{`{"value":`,true,false,true},
		{strings.Repeat("[",33)+"0"+strings.Repeat("]",33),true,false,true},
		{string([]byte{0xff}),false,false,true},
	} {
		if err:=InspectPayload([]byte(tc.body),tc.json,tc.enabled); (err!=nil)!=tc.deny { t.Fatalf("inspection mismatch: %v",err) }
	}
}
