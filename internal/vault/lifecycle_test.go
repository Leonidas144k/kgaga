package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCredentialLifecycle(t *testing.T) {
	m,s,kid,keyPath:=managedFixture(t)
	now:=time.Now().Unix()
	token:=[]byte("synthetic-lifecycle-token-01234")
	for _,v:=range []uint64{1,2,3,4} {
		if err:=m.PutBearer("service",v,token,now-5,now+600); err!=nil { t.Fatal(err) }
	}
	if err:=m.PutBearer("service",5,token,now+600,now+1200); err!=nil { t.Fatal(err) }
	if err:=m.Put("service",6,token); err!=nil { t.Fatal(err) }
	if err:=m.Activate("service",5); !errors.Is(err,ErrCredentialValidity) { t.Fatal("future credential activated") }
	if err:=m.Activate("service",6); !errors.Is(err,ErrCredentialFormat) { t.Fatal("untimed credential activated") }
	if err:=m.Activate("service",99); !errors.Is(err,ErrRecordNotFound) { t.Fatal("missing record activated") }
	if err:=m.CheckActive("service",1); !errors.Is(err,ErrInactiveVersion) { t.Fatal("staged token active") }
	if err:=m.Activate("service",1); err!=nil { t.Fatal(err) }
	p,_,err:=m.GetActiveBearer("service",1)
	if err!=nil || !bytes.Equal(p,token) { t.Fatal("active token unavailable") }
	clear(p)
	// Revoke a future version without interrupting the active version.
	if err:=m.RevokeVersion("service",3); err!=nil { t.Fatal(err) }
	if err:=m.CheckActive("service",1); err!=nil { t.Fatal(err) }
	if err:=m.Activate("service",3); !errors.Is(err,ErrInactiveVersion) { t.Fatal("revoked future activated") }
	if err:=m.Activate("service",2); err!=nil { t.Fatal(err) }
	if err:=m.CheckActive("service",1); !errors.Is(err,ErrInactiveVersion) { t.Fatal("retired token active") }
	if err:=m.Activate("service",1); !errors.Is(err,ErrInactiveVersion) { t.Fatal("rollback accepted") }
	if err:=m.RevokeVersion("service",2); err!=nil { t.Fatal(err) }
	if err:=m.RevokeVersion("service",2); err!=nil { t.Fatal(err) }
	if p,_,err:=m.GetActiveBearer("service",2); p!=nil || !errors.Is(err,ErrInactiveVersion) { t.Fatal("revoked token returned") }
	reopened,err:=Open(s.dir,s.id); if err!=nil { t.Fatal(err) }
	n,err:=reopened.OpenManaged(keyPath,kid); if err!=nil { t.Fatal(err) }
	for _,v:=range []uint64{1,2,3} {
		if err:=n.Activate("service",v); !errors.Is(err,ErrInactiveVersion) { t.Fatal("retired or revoked version reactivated after restart") }
	}
	if err:=n.Activate("service",4); err!=nil { t.Fatal(err) }
	if err:=m.CheckActive("service",4); err!=nil { t.Fatal("existing store did not observe rotation") }
	if err:=m.CheckActive("service",2); !errors.Is(err,ErrInactiveVersion) { t.Fatal("fallback accepted") }
}

func TestLifecycleIntegrity(t *testing.T) {
	m,s,_,_:=managedFixture(t)
	now:=time.Now().Unix()
	if err:=m.PutBearer("service",1,[]byte("synthetic-lifecycle-token"),now-5,now+600); err!=nil { t.Fatal(err) }
	if err:=m.Activate("service",1); err!=nil { t.Fatal(err) }
	path,err:=m.lifecyclePath("service"); if err!=nil { t.Fatal(err) }
	raw,err:=os.ReadFile(path); if err!=nil { t.Fatal(err) }
	for i:=range raw {
		bad:=bytes.Clone(raw); bad[i]^=1
		if _,err:=m.decodeLifecycle("service",bad); !errors.Is(err,ErrLifecycleState) { t.Fatal("tampered lifecycle accepted") }
	}
	if _,err:=m.decodeLifecycle("other",raw); !errors.Is(err,ErrLifecycleState) { t.Fatal("cross-name lifecycle accepted") }
	other:=*m
	other.kek[0]^=1
	if _,err:=other.decodeLifecycle("service",raw); !errors.Is(err,ErrLifecycleState) { t.Fatal("wrong key accepted") }
	if err:=os.WriteFile(filepath.Join(s.dir,".lifecycle-other"),raw,0600); err!=nil { t.Fatal(err) }
	if err:=m.CheckActive("other",1); !errors.Is(err,ErrLifecycleState) { t.Fatal("substituted lifecycle accepted") }
	bad:=bytes.Clone(raw); bad[len(bad)-1]^=1
	if err:=os.WriteFile(path,bad,0600); err!=nil { t.Fatal(err) }
	if err:=m.CheckActive("service",1); !errors.Is(err,ErrLifecycleState) { t.Fatal("corrupt state allowed") }
	if err:=m.RevokeVersion("service",1); !errors.Is(err,ErrLifecycleState) { t.Fatal("corrupt state silently replaced") }
	after,err:=os.ReadFile(path)
	if err!=nil || !bytes.Equal(after,bad) { t.Fatal("invalid state overwritten") }
	if err:=os.Remove(path); err!=nil { t.Fatal(err) }
	if err:=m.CheckActive("service",1); !errors.Is(err,ErrInactiveVersion) { t.Fatal("missing state allowed") }
}

func TestLifecycleConcurrentActivation(t *testing.T) {
	m,s,kid,keyPath:=managedFixture(t)
	n,err:=s.OpenManaged(keyPath,kid); if err!=nil { t.Fatal(err) }
	now:=time.Now().Unix()
	if err:=m.PutBearer("service",1,[]byte("synthetic-lifecycle-token"),now-5,now+600); err!=nil { t.Fatal(err) }
	var wg sync.WaitGroup
	var success atomic.Int32
	for _,store:=range []*ManagedStore{m,n} {
		wg.Add(1)
		go func(store *ManagedStore){
			defer wg.Done()
			err:=store.Activate("service",1)
			if err==nil { success.Add(1) } else if !errors.Is(err,ErrLifecycleBusy) && !errors.Is(err,ErrInactiveVersion) { t.Errorf("unexpected activation error: %v",err) }
		}(store)
	}
	wg.Wait()
	if success.Load()!=1 { t.Fatal("multiple activations succeeded") }
	if err:=m.CheckActive("service",1); err!=nil { t.Fatal(err) }
	path,err:=m.lifecyclePath("service"); if err!=nil { t.Fatal(err) }
	if err:=os.Mkdir(path+".lock",0700); err!=nil { t.Fatal(err) }
	if err:=n.RevokeVersion("service",1); !errors.Is(err,ErrLifecycleBusy) { t.Fatal("contended update admitted") }
	if err:=os.Remove(path+".lock"); err!=nil { t.Fatal(err) }
	if err:=n.RevokeVersion("service",1); err!=nil { t.Fatal(err) }
	if err:=m.CheckActive("service",1); !errors.Is(err,ErrInactiveVersion) { t.Fatal("live revocation not observed") }
}

func TestLifecycleBounds(t *testing.T) {
	m,_,_,_:=managedFixture(t)
	// Exercise the canonical bounded decoder without hundreds of disk syncs.
	s:=lifecycleState{high:1}
	for i:=0;i<maxFutureRevocations;i++ { s.future=append(s.future,uint64(i+2)) }
	raw:=m.encodeLifecycle("service",s)
	if len(raw)!=maxLifecycleBytes { t.Fatal("incorrect maximum size") }
	got,err:=m.decodeLifecycle("service",raw)
	if err!=nil || len(got.future)!=maxFutureRevocations { t.Fatal("valid bounded state rejected") }
	s.future=append(s.future,uint64(maxFutureRevocations+2))
	if _,err:=m.decodeLifecycle("service",m.encodeLifecycle("service",s)); err==nil { t.Fatal("oversized list accepted") }
	s.future=[]uint64{3,2}
	if _,err:=m.decodeLifecycle("service",m.encodeLifecycle("service",s)); err==nil { t.Fatal("unordered future revocations accepted") }
}
