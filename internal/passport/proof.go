package passport

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

const ProofHeader = "X-Kgaga-Proof"
const ReplayDir = "kgaga-replay"

// RequestBinding describes the exact inbound request before proxy rewriting
// and redaction. The audience is bound through the digest of the passport.
type RequestBinding struct {
	Method string
	Target string
	ContentType string
	MCPVersion string
	MCPMethod string
	MCPSession string
	Body []byte
}

func digest(b []byte) string {
	sum:=sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func proofMessage(token,stamp,nonce string,r RequestBinding) ([]byte,error) {
	if len(token)==0 || len(token)>maxTokenSize || !safeValue(r.Method,32) || !safeValue(r.Target,8192) || !strings.HasPrefix(r.Target,"/") || strings.HasPrefix(r.Target,"//") || len(r.Body)>1<<20 {
		return nil,errors.New("invalid request binding")
	}
	for _,v:=range []string{r.ContentType,r.MCPVersion,r.MCPMethod,r.MCPSession} {
		if len(v)>1024 || strings.ContainsAny(v,"\r\n") { return nil,errors.New("invalid bound header") }
	}
	return json.Marshal([]string{"kgaga-request-proof-v1",stamp,nonce,digest([]byte(token)),r.Method,r.Target,r.ContentType,r.MCPVersion,r.MCPMethod,r.MCPSession,digest(r.Body)})
}

// SignRequest signs a short-lived request proof using the agent's private key.
func SignRequest(privatePath,token string,r RequestBinding,now time.Time) (string,error) {
	key,err:=loadPrivateKey(privatePath)
	if err!=nil { return "",err }
	nonce:=make([]byte,16)
	if _,err:=rand.Read(nonce); err!=nil { return "",err }
	id:=hex.EncodeToString(nonce)
	stamp:=strconv.FormatInt(now.Unix(),10)
	msg,err:=proofMessage(token,stamp,id,r)
	if err!=nil { return "",err }
	sig:=ed25519.Sign(key,msg)
	return "v1."+stamp+"."+id+"."+base64.RawURLEncoding.EncodeToString(sig),nil
}

// VerifyRequest verifies exact request binding and a 30-second freshness
// window (5 seconds future skew). The caller MUST atomically consume the
// returned nonce before admitting the request.
func VerifyRequest(proof,token string,key ed25519.PublicKey,r RequestBinding,now time.Time) (string,error) {
	invalid:=errors.New("invalid request proof")
	if len(proof)>256 || len(key)!=ed25519.PublicKeySize { return "",invalid }
	p:=strings.Split(proof,".")
	if len(p)!=4 || p[0]!="v1" || len(p[2])!=32 || strings.ToLower(p[2])!=p[2] { return "",invalid }
	if _,err:=hex.DecodeString(p[2]); err!=nil { return "",invalid }
	stamp,err:=strconv.ParseInt(p[1],10,64)
	if err!=nil || strconv.FormatInt(stamp,10)!=p[1] || stamp<now.Unix()-30 || stamp>now.Unix()+5 { return "",invalid }
	sig,err:=base64.RawURLEncoding.Strict().DecodeString(p[3])
	if err!=nil || len(sig)!=ed25519.SignatureSize { return "",invalid }
	msg,err:=proofMessage(token,p[1],p[2],r)
	if err!=nil || !ed25519.Verify(key,msg,sig) { return "",invalid }
	return p[2],nil
}
