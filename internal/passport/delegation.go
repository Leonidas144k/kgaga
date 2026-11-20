package passport

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

const DelegateScope = "kgaga:delegate"

// GrantMessage signs precisely one proposed child authorization and its
// parent passport. It intentionally does not authorize nested delegation.
func grantMessage(parent,child,owner string,scopes []string,audience,holderID string,expires int64) ([]byte,error) {
	if len(parent)==0 || len(parent)>maxTokenSize || expires<=0 { return nil,errors.New("invalid delegation grant") }
	if err:=ValidateIdentity(child,owner,scopes); err!=nil { return nil,err }
	if err:=ValidateAudience(audience); err!=nil { return nil,err }
	raw,err:=base64.RawURLEncoding.Strict().DecodeString(holderID)
	if err!=nil || len(raw)!=32 || base64.RawURLEncoding.EncodeToString(raw)!=holderID { return nil,errors.New("invalid child holder thumbprint") }
	return json.Marshal([]any{"kgaga-delegation-v1",digest([]byte(parent)),child,owner,scopes,audience,holderID,expires})
}

func SignGrant(privatePath,parent,child,owner string,scopes []string,audience,holderID string,expires int64) (string,error) {
	key,err:=loadPrivateKey(privatePath)
	if err!=nil { return "",err }
	msg,err:=grantMessage(parent,child,owner,scopes,audience,holderID,expires)
	if err!=nil { return "",err }
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(key,msg)),nil
}

func VerifyGrant(c,p *AgentClaims,holder ed25519.PublicKey,audience string,now time.Time) error {
	denied:=errors.New("invalid delegation grant")
	if c==nil || p==nil || c.Delegation==nil || c.Confirmation==nil || p.Confirmation==nil || p.Delegation!=nil ||
		c.ExpiresAt==nil || p.ExpiresAt==nil || c.IssuedAt==nil || p.IssuedAt==nil ||
		c.AgentID==p.AgentID || c.Owner!=p.Owner || c.Confirmation.Thumbprint==p.Confirmation.Thumbprint ||
		len(c.Audience)!=1 || c.Audience[0]!=audience || len(p.Audience)!=1 || p.Audience[0]!=audience ||
		c.ExpiresAt.Unix()!=c.Delegation.Expires || c.ExpiresAt.Time.After(p.ExpiresAt.Time) ||
		c.IssuedAt.Time.Before(p.IssuedAt.Time) || !c.ExpiresAt.Time.After(now) {
		return denied
	}
	kid,err:=KeyID(holder)
	if err!=nil || kid!=p.Confirmation.Thumbprint { return denied }
	scopes:=map[string]bool{}
	for _,scope:=range p.Scopes { scopes[scope]=true }
	if !scopes[DelegateScope] { return denied }
	for _,scope:=range c.Scopes {
		if !scopes[scope] || scope==DelegateScope { return denied }
	}
	msg,err:=grantMessage(c.Delegation.Parent,c.AgentID,c.Owner,c.Scopes,audience,c.Confirmation.Thumbprint,c.Delegation.Expires)
	if err!=nil { return denied }
	if len(c.Delegation.Signature)!=86 { return denied }
	sig,err:=base64.RawURLEncoding.Strict().DecodeString(c.Delegation.Signature)
	if err!=nil || len(sig)!=ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(sig)!=c.Delegation.Signature || !ed25519.Verify(holder,msg,sig) { return denied }
	return nil
}
