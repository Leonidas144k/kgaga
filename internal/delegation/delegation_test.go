package delegation

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Leonidas144k/kgaga/internal/keyring"
	"github.com/Leonidas144k/kgaga/internal/passport"
	"github.com/Leonidas144k/kgaga/internal/registry"
	"github.com/Leonidas144k/kgaga/internal/revocation"
)

func TestDelegationLifecycle(t *testing.T) {
	dir:=t.TempDir()
	keys:=func(name string) (string,string) {
		t.Helper()
		priv,pub:=filepath.Join(dir,name+".key"),filepath.Join(dir,name+".pub")
		if err:=passport.GenerateKeyPair(priv,pub); err!=nil { t.Fatal(err) }
		return priv,pub
	}
	issuer,issuerPub:=keys("issuer")
	parentKey,parentPub:=keys("parent")
	_,childPub:=keys("child")
	trustDir,regDir,revDir:=filepath.Join(dir,"trust"),filepath.Join(dir,"reg"),filepath.Join(dir,"rev")
	if err:=keyring.Init(trustDir); err!=nil { t.Fatal(err) }
	if err:=registry.Init(regDir); err!=nil { t.Fatal(err) }
	if err:=revocation.Init(revDir); err!=nil { t.Fatal(err) }
	trust,err:=keyring.Open(trustDir); if err!=nil { t.Fatal(err) }
	reg,err:=registry.Open(regDir); if err!=nil { t.Fatal(err) }
	rev,err:=revocation.Open(revDir); if err!=nil { t.Fatal(err) }
	pub,err:=passport.LoadPublicKey(issuerPub); if err!=nil { t.Fatal(err) }
	if _,err:=trust.Trust(pub); err!=nil { t.Fatal(err) }
	register:=func(id,path string,scopes []string) {
		t.Helper()
		key,err:=passport.LoadPublicKey(path); if err!=nil { t.Fatal(err) }
		encoded,err:=registry.EncodeHolder(key); if err!=nil { t.Fatal(err) }
		if err:=reg.Register(registry.Agent{ID:id,Owner:"owner",Scopes:scopes,Audiences:[]string{"api"},HolderKey:encoded}); err!=nil { t.Fatal(err) }
	}
	register("parent",parentPub,[]string{"read",passport.DelegateScope})
	register("child",childPub,[]string{"read","write",passport.DelegateScope})
	pkey,err:=passport.LoadPublicKey(parentPub); if err!=nil { t.Fatal(err) }
	ckey,err:=passport.LoadPublicKey(childPub); if err!=nil { t.Fatal(err) }
	kid,err:=passport.KeyID(ckey); if err!=nil { t.Fatal(err) }
	parent,err:=passport.MintBoundV2(issuer,"parent","owner",[]string{"read",passport.DelegateScope},"api",5*time.Minute,pkey)
	if err!=nil { t.Fatal(err) }
	p,err:=trust.Verify(parent,"api"); if err!=nil { t.Fatal(err) }
	exp:=time.Now().Add(2*time.Minute).Unix()
	grant:=func(raw string,scopes []string,expiry int64) passport.Delegation {
		t.Helper()
		sig,err:=passport.SignGrant(parentKey,raw,"child","owner",scopes,"api",kid,expiry)
		if err!=nil { t.Fatal(err) }
		return passport.Delegation{Parent:raw,Signature:sig,Expires:expiry}
	}
	issue:=func(scopes []string,d passport.Delegation)(string,error){
		return Issue(issuer,"child","owner",scopes,"api",d,trust,reg,rev)
	}
	d:=grant(parent,[]string{"read"},exp)
	for _,tc:=range []struct{scopes []string; d passport.Delegation}{
		{[]string{"write"},grant(parent,[]string{"write"},exp)},
		{[]string{passport.DelegateScope},grant(parent,[]string{passport.DelegateScope},exp)},
		{[]string{"read"},grant(parent,[]string{"read"},p.ExpiresAt.Unix()+1)},
		{[]string{"write"},d},
	} {
		if _,err:=issue(tc.scopes,tc.d); err==nil { t.Fatal("invalid grant accepted") }
	}
	child,err:=issue([]string{"read"},d); if err!=nil { t.Fatal(err) }
	c,err:=trust.Verify(child,"api"); if err!=nil { t.Fatal(err) }
	if c.ExpiresAt.Unix()!=exp { t.Fatal("wrong delegated expiration") }
	if err:=Check(c,"api",trust,reg,rev); err!=nil { t.Fatal(err) }
	if err:=rev.Revoke(p.ID); err!=nil { t.Fatal(err) }
	if err:=Check(c,"api",trust,reg,rev); !errors.Is(err,ErrDenied) { t.Fatal("revoked parent accepted") }
	if _,err:=issue([]string{"read"},d); err==nil { t.Fatal("issued from revoked parent") }
}
