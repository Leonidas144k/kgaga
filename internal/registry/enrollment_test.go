package registry

import (
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Leonidas144k/kgaga/internal/passport"
)

func TestAttestedEnrollment(t *testing.T) {
	dir:=t.TempDir()
	path:=filepath.Join(dir,"registry")
	if err:=Init(path); err!=nil { t.Fatal(err) }
	s,err:=Open(path)
	if err!=nil { t.Fatal(err) }
	priv,pub:=filepath.Join(dir,"holder.key"),filepath.Join(dir,"holder.pub")
	if err:=passport.GenerateKeyPair(priv,pub); err!=nil { t.Fatal(err) }
	key,err:=passport.LoadPublicKey(pub)
	if err!=nil { t.Fatal(err) }
	encoded,err:=EncodeHolder(key)
	if err!=nil { t.Fatal(err) }
	a:=Agent{ID:"agent",Owner:"owner",Scopes:[]string{"read"},Audiences:[]string{"api"},HolderKey:encoded}
	now:=time.Now()
	challenge,err:=s.newChallengeAt(a.ID,now)
	if err!=nil { t.Fatal(err) }
	sig,err:=passport.SignEnrollment(priv,challenge,a.ID,a.Owner,a.Scopes,a.Audiences)
	if err!=nil { t.Fatal(err) }
	for _,mutate:=range []func(*Agent){
		func(x *Agent){ x.ID="other" },
		func(x *Agent){ x.Owner="other" },
		func(x *Agent){ x.Scopes=[]string{"admin"} },
		func(x *Agent){ x.Audiences=[]string{"other"} },
	} {
		b:=a; mutate(&b)
		if err:=s.registerAttestedAt(b,challenge,sig,now); err==nil { t.Fatal("accepted changed enrollment") }
	}
	if err:=s.registerAttestedAt(a,challenge,sig,now.Add(EnrollmentTTL+time.Second)); err==nil { t.Fatal("accepted expired challenge") }
	otherPriv,otherPub:=filepath.Join(dir,"other.key"),filepath.Join(dir,"other.pub")
	if err:=passport.GenerateKeyPair(otherPriv,otherPub); err!=nil { t.Fatal(err) }
	wrong,err:=passport.SignEnrollment(otherPriv,challenge,a.ID,a.Owner,a.Scopes,a.Audiences)
	if err!=nil { t.Fatal(err) }
	if err:=s.registerAttestedAt(a,challenge,wrong,now); err==nil { t.Fatal("accepted wrong holder") }
	if err:=s.registerAttestedAt(a,challenge,"",now); err==nil { t.Fatal("accepted missing proof") }
	var wg sync.WaitGroup
	var successes atomic.Int32
	for i:=0;i<8;i++ {
		wg.Add(1)
		go func(){ defer wg.Done(); if s.registerAttestedAt(a,challenge,sig,now)==nil { successes.Add(1) } }()
	}
	wg.Wait()
	if successes.Load()!=1 { t.Fatalf("expected a single enrolment, got %d",successes.Load()) }
	reopened,err:=Open(path)
	if err!=nil { t.Fatal(err) }
	if err:=reopened.registerAttestedAt(a,challenge,sig,now); err==nil || err.Error()!="enrolment challenge already consumed" { t.Fatalf("challenge reuse: %v",err) }
	if _,err:=reopened.AuthorizedHolder(a.ID,a.Owner,a.Scopes,"api"); err!=nil { t.Fatal(err) }
}
