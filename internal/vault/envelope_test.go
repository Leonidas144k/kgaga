package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

func managedFixture(t *testing.T)(*ManagedStore,*Store,ID,string) {
	t.Helper()
	s,_,_,_:=newStore(t)
	id,err:=GenerateID()
	if err!=nil { t.Fatal(err) }
	dir:=filepath.Join(t.TempDir(),"keys")
	if err:=os.Mkdir(dir,0700); err!=nil { t.Fatal(err) }
	path:=filepath.Join(dir,"master")
	if err:=s.CreateMasterKey(path,id); err!=nil { t.Fatal(err) }
	m,err:=s.OpenManaged(path,id)
	if err!=nil { t.Fatal(err) }
	return m,s,id,path
}

func TestManagedRestart(t *testing.T) {
	m,s,id,path:=managedFixture(t)
	secret:=[]byte("synthetic-backend-credential")
	if err:=m.Put("service",1,secret); err!=nil { t.Fatal(err) }
	if err:=m.Put("service",2,secret); err!=nil { t.Fatal(err) }
	if err:=m.Put("service",1,[]byte("other")); !errors.Is(err,ErrRecordExists) { t.Fatal("overwrite accepted") }
	reopened,err:=Open(s.dir,s.id)
	if err!=nil { t.Fatal(err) }
	n,err:=reopened.OpenManaged(path,id)
	if err!=nil { t.Fatal(err) }
	var records [][]byte
	for _,v:=range []uint64{1,2} {
		p,err:=n.Get("service",v)
		if err!=nil || !bytes.Equal(p,secret) { t.Fatal("restart retrieval failed") }
		ctx,slot,err:=n.slot("service",v)
		if err!=nil { t.Fatal(err) }
		raw,err:=os.ReadFile(slot)
		if err!=nil { t.Fatal(err) }
		if bytes.Contains(raw,secret) || bytes.Contains(raw,n.kek[:]) { t.Fatal("raw secret or KEK persisted") }
		copy(ctx.KeyID[:],raw[20:36])
		aad,err:=wrapAAD(ctx,id)
		if err!=nil { t.Fatal(err) }
		aead,err:=recordAEAD(n.kek)
		if err!=nil { t.Fatal(err) }
		dek,err:=aead.Open(nil,raw[36:48],raw[48:envelopeHeader],aad)
		if err!=nil || len(dek)!=32 || bytes.Contains(raw,dek) { t.Fatal("raw DEK persisted or invalid wrap") }
		records=append(records,raw)
	}
	if bytes.Equal(records[0][20:36],records[1][20:36]) || bytes.Equal(records[0][36:48],records[1][36:48]) { t.Fatal("reused key identifier or wrapping nonce") }
	if p,err:=n.Get("missing",1); p!=nil || !errors.Is(err,ErrRecordNotFound) { t.Fatal("missing slot accepted") }
}

func TestManagedAuthentication(t *testing.T) {
	m,_,_,_:=managedFixture(t)
	secret:=[]byte("synthetic")
	if err:=m.Put("service",1,secret); err!=nil { t.Fatal(err) }
	ctx,path,err:=m.slot("service",1)
	if err!=nil { t.Fatal(err) }
	raw,err:=os.ReadFile(path)
	if err!=nil { t.Fatal(err) }
	reject:=func(key Key,id ID,c RecordContext,b []byte){
		t.Helper()
		p,err:=openEnvelope(key,id,c,b)
		if p!=nil || !errors.Is(err,ErrAuthentication) { t.Fatal("invalid envelope accepted") }
	}
	for i:=range raw {
		bad:=bytes.Clone(raw)
		bad[i]^=1
		reject(m.kek,m.kekID,ctx,bad)
	}
	for i:=0;i<len(raw);i++ { reject(m.kek,m.kekID,ctx,raw[:i]) }
	reject(m.kek,m.kekID,ctx,append(bytes.Clone(raw),0))
	other,err:=GenerateKey()
	if err!=nil { t.Fatal(err) }
	reject(other,m.kekID,ctx,raw)
	for _,mutate:=range []func(*RecordContext){func(c *RecordContext){c.Name="other"},func(c *RecordContext){c.Version++},func(c *RecordContext){c.VaultID[0]^=1}} {
		bad:=ctx; mutate(&bad)
		reject(m.kek,m.kekID,bad,raw)
	}
	// Mix a valid header/wrapped key with a different valid ciphertext
	// generated for this same context: the distinct data key denies it.
	otherRaw,err:=sealEnvelope(m.kek,m.kekID,ctx,secret)
	if err!=nil { t.Fatal(err) }
	mixed:=append(bytes.Clone(raw[:envelopeHeader]),otherRaw[envelopeHeader:]...)
	reject(m.kek,m.kekID,ctx,mixed)
	if err:=os.WriteFile(path,mixed,0600); err!=nil { t.Fatal(err) }
	if p,err:=m.Get("service",1); p!=nil || !errors.Is(err,ErrAuthentication) { t.Fatal("tampered disk envelope accepted") }
}

func TestMasterKeyCustody(t *testing.T) {
	_,s,id,path:=managedFixture(t)
	before,err:=os.ReadFile(path)
	if err!=nil { t.Fatal(err) }
	if err:=s.CreateMasterKey(path,id); err==nil { t.Fatal("master key overwritten") }
	after,err:=os.ReadFile(path)
	if err!=nil || !bytes.Equal(before,after) { t.Fatal("master key changed") }
	wrong:=id; wrong[0]^=1
	if _,err:=s.OpenManaged(path,wrong); err==nil { t.Fatal("wrong key ID accepted") }
	if err:=s.CreateMasterKey(filepath.Join(s.dir,"master"),id); err==nil { t.Fatal("master key stored alongside records") }
	if err:=os.Chmod(path,0644); err!=nil { t.Fatal(err) }
	if _,err:=s.OpenManaged(path,id); err==nil { t.Fatal("unsafe key permission accepted") }
	if err:=os.Chmod(path,0600); err!=nil { t.Fatal(err) }
	link:=path+".link"
	if err:=os.Symlink(path,link); err!=nil { t.Fatal(err) }
	if _,err:=s.OpenManaged(link,id); err==nil { t.Fatal("symlink key accepted") }
	other,_,_,_:=newStore(t)
	if _,err:=other.OpenManaged(path,id); err==nil { t.Fatal("cross-vault key accepted") }
	if _,err:=s.OpenManaged(path+".missing",id); err==nil { t.Fatal("missing key accepted") }
	if err:=os.WriteFile(path,before[:len(before)-1],0600); err!=nil { t.Fatal(err) }
	if _,err:=s.OpenManaged(path,id); err==nil { t.Fatal("truncated key accepted") }
}

func TestManagedConcurrentPublicationAndRawIsolation(t *testing.T) {
	m,s,id,path:=managedFixture(t)
	n,err:=s.OpenManaged(path,id)
	if err!=nil { t.Fatal(err) }
	var wg sync.WaitGroup
	var accepted,winner atomic.Int32
	for i:=1;i<=4;i++ {
		wg.Add(1)
		go func(i int){
			defer wg.Done()
			target:=m
			if i%2==0 { target=n }
			if err:=target.Put("service",1,[]byte{byte(i)}); err==nil { winner.Store(int32(i)); accepted.Add(1) } else if !errors.Is(err,ErrRecordExists) { t.Errorf("publication error: %v",err) }
		}(i)
	}
	wg.Wait()
	if accepted.Load()!=1 { t.Fatal("multiple writes admitted") }
	p,err:=n.Get("service",1)
	if err!=nil || !bytes.Equal(p,[]byte{byte(winner.Load())}) { t.Fatal("winning record changed") }
	key,ctx:=fixture(t)
	ctx.VaultID=s.id
	ctx.Name="service"
	if err:=s.Put(key,ctx,[]byte("raw")); !errors.Is(err,ErrRecordExists) { t.Fatal("raw API overwrote managed record") }
	ctx.Version=2
	if err:=s.Put(key,ctx,[]byte("raw")); err!=nil { t.Fatal(err) }
	if p,err:=m.Get("service",2); p!=nil || !errors.Is(err,ErrAuthentication) { t.Fatal("managed API accepted raw record") }
	if err:=m.Put("service",2,[]byte("managed")); !errors.Is(err,ErrRecordExists) { t.Fatal("managed API overwrote raw record") }
}
