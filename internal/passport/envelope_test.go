package passport

import (
	"crypto/ed25519"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSignedAmbiguousPassportEnvelopes(t *testing.T) {
	dir:=t.TempDir()
	priv,pub:=filepath.Join(dir,"issuer.key"),filepath.Join(dir,"issuer.pub")
	if err:=GenerateKeyPair(priv,pub); err!=nil { t.Fatal(err) }
	key,err:=LoadPublicKey(pub); if err!=nil { t.Fatal(err) }
	signer,err:=loadPrivateKey(priv); if err!=nil { t.Fatal(err) }
	holder,_,err:=ed25519.GenerateKey(nil); if err!=nil { t.Fatal(err) }
	raw,err:=MintBoundV2(priv,"agent","owner",[]string{"read"},"api",time.Minute,holder); if err!=nil { t.Fatal(err) }
	parts:=strings.Split(raw,".")
	enc:=base64.RawURLEncoding
	h,err:=enc.DecodeString(parts[0]); if err!=nil { t.Fatal(err) }
	b,err:=enc.DecodeString(parts[1]); if err!=nil { t.Fatal(err) }
	header,body:=string(h),string(b)
	signed:=func(h,b string)string{
		message:=enc.EncodeToString([]byte(h))+"."+enc.EncodeToString([]byte(b))
		return message+"."+enc.EncodeToString(ed25519.Sign(signer,[]byte(message)))
	}
	if _,err:=VerifyV2(raw,key,"api"); err!=nil { t.Fatal(err) }
	for _,tc:=range []struct{name,h,b string}{
		{"duplicate alg",strings.Replace(header,"{",`{"alg":"EdDSA",`,1),body},
		{"unknown header",strings.Replace(header,"{",`{"extra":true,`,1),body},
		{"case alias",header,strings.Replace(body,"{",`{"OWNER":"other",`,1)},
		{"duplicate owner",header,strings.Replace(body,"{",`{"owner":"other",`,1)},
		{"escaped duplicate",header,strings.Replace(body,"{",`{"\u006fwner":"other",`,1)},
		{"unknown claim",header,strings.Replace(body,"{",`{"extra":true,`,1)},
		{"trailing document",header,body+" {}"},
		{"scalar audience",header,strings.Replace(body,`"aud":["api"]`,`"aud":"api"`,1)},
		{"null confirmation",header,strings.Replace(body,`"cnf":{`,`"cnf":null,"other":{`,1)},
		{"nested duplicate",header,strings.Replace(body,`"cnf":{`,`"cnf":{"jkt":"other",`,1)},
		{"null scope",header,strings.Replace(body,`["read"]`,`[null]`,1)},
	} {
		t.Run(tc.name,func(t *testing.T){
			if tc.h==header && tc.b==body { t.Fatal("mutation did not modify fixture") }
			if _,err:=VerifyV2(signed(tc.h,tc.b),key,"api"); err==nil { t.Fatal("accepted ambiguous signed passport") }
		})
	}
	// A signature segment containing a newline decodes to the same bytes
	// in Go's base64 decoder. Its noncanonical wire representation is denied.
	if _,err:=VerifyV2(parts[0]+"."+parts[1]+"."+parts[2][:20]+"\n"+parts[2][20:],key,"api"); err==nil { t.Fatal("accepted noncanonical signature") }
}

func FuzzPassportEnvelope(f *testing.F) {
	f.Add("a.b.c")
	f.Add("")
	f.Add("e30.e30.AA")
	f.Fuzz(func(t *testing.T,raw string){ _=validateEnvelope(raw) })
}
