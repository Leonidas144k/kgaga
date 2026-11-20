package vault

import (
	"strings"
	"testing"
)

func TestBearerValidation(t *testing.T) {
	for _,s:=range []string{"synthetic-token-12345","abc123ABC-._~+/abc==",strings.Repeat("a",4096)} { if ValidateBearer([]byte(s))!=nil { t.Fatal("valid token rejected") } }
	for _,s:=range []string{"", "short", "synthetic-token\r\n", "synthetic-token 123", "synthetic-token=abc", strings.Repeat("=",32),strings.Repeat("a",4097)} { if ValidateBearer([]byte(s))==nil { t.Fatal("invalid token accepted") } }
}
