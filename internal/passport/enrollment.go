package passport

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

// ValidateEnrollmentChallenge accepts only a canonical 256-bit random challenge.
func ValidateEnrollmentChallenge(challenge string) error {
	if len(challenge)!=64 || strings.ToLower(challenge)!=challenge { return errors.New("invalid enrolment challenge") }
	if _,err:=hex.DecodeString(challenge); err!=nil { return errors.New("invalid enrolment challenge") }
	return nil
}

// The signed statement binds the complete proposed registration, including
// the exact scope and audience ordering. The domain is not a request proof.
func enrollmentMessage(challenge,agent,owner string,scopes,audiences []string,key ed25519.PublicKey) ([]byte,error) {
	if err:=ValidateEnrollmentChallenge(challenge); err!=nil { return nil,err }
	if err:=ValidateIdentity(agent,owner,scopes); err!=nil { return nil,err }
	if len(audiences)==0 || len(audiences)>64 { return nil,errors.New("invalid audiences") }
	seen:=map[string]bool{}
	for _,aud:=range audiences {
		if err:=ValidateAudience(aud); err!=nil { return nil,err }
		if seen[aud] { return nil,errors.New("duplicate audience") }
		seen[aud]=true
	}
	kid,err:=KeyID(key)
	if err!=nil { return nil,err }
	return json.Marshal([]any{"kgaga-enrolment-v1",challenge,agent,owner,scopes,audiences,kid})
}

// SignEnrollment is performed by the prospective holder, not the issuer.
func SignEnrollment(privatePath,challenge,agent,owner string,scopes,audiences []string) (string,error) {
	key,err:=loadPrivateKey(privatePath)
	if err!=nil { return "",err }
	msg,err:=enrollmentMessage(challenge,agent,owner,scopes,audiences,key.Public().(ed25519.PublicKey))
	if err!=nil { return "",err }
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(key,msg)),nil
}

// VerifyEnrollment proves possession of the supplied holder key for a
// particular statement. The registry separately enforces challenge freshness
// and one-time use. It does not attest runtime or software integrity.
func VerifyEnrollment(signature,challenge,agent,owner string,scopes,audiences []string,key ed25519.PublicKey) error {
	if len(signature)!=86 { return errors.New("invalid enrolment signature") }
	sig,err:=base64.RawURLEncoding.Strict().DecodeString(signature)
	if err!=nil || len(sig)!=ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(sig)!=signature { return errors.New("invalid enrolment signature") }
	msg,err:=enrollmentMessage(challenge,agent,owner,scopes,audiences,key)
	if err!=nil { return err }
	if !ed25519.Verify(key,msg,sig) { return errors.New("invalid enrolment signature") }
	return nil
}
