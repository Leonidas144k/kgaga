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

func newStore(t *testing.T)(*Store,Key,RecordContext,string) {
	t.Helper()
	key,ctx:=fixture(t)
	dir:=filepath.Join(t.TempDir(),"vault")
	if err:=Init(dir,ctx.VaultID); err!=nil { t.Fatal(err) }
	s,err:=Open(dir,ctx.VaultID)
	if err!=nil { t.Fatal(err) }
	return s,key,ctx,dir
}

func TestStoreRestartAndImmutability(t *testing.T) {
	s,key,ctx,dir:=newStore(t)
	secret:=[]byte("synthetic-credential-never-plaintext-on-disk")
	if p,err:=s.Get(key,ctx); p!=nil || !errors.Is(err,ErrRecordNotFound) { t.Fatal("missing record not denied") }
	if err:=s.Put(key,ctx,secret); err!=nil { t.Fatal(err) }
	path,err:=s.recordPath(ctx)
	if err!=nil { t.Fatal(err) }
	before,err:=os.ReadFile(path)
	if err!=nil { t.Fatal(err) }
	if err:=s.Put(key,ctx,[]byte("replacement")); !errors.Is(err,ErrRecordExists) { t.Fatal("overwrite accepted") }
	after,err:=os.ReadFile(path)
	if err!=nil || !bytes.Equal(before,after) { t.Fatal("record changed") }
	if err:=Init(dir,ctx.VaultID); err==nil { t.Fatal("reinitialization succeeded") }
	reopened,err:=Open(dir,ctx.VaultID)
	if err!=nil { t.Fatal(err) }
	p,err:=reopened.Get(key,ctx)
	if err!=nil || !bytes.Equal(p,secret) { t.Fatal("restart read failed") }
	files,err:=os.ReadDir(dir)
	if err!=nil || len(files)!=2 { t.Fatal("unexpected persisted files") }
	for _,entry:=range files {
		raw,err:=os.ReadFile(filepath.Join(dir,entry.Name()))
		if err!=nil { t.Fatal(err) }
		if bytes.Contains(raw,secret) || bytes.Contains(raw,key[:]) { t.Fatal("plaintext secret or DEK persisted") }
		info,err:=entry.Info()
		if err!=nil || info.Mode().Perm()!=0600 { t.Fatal("unsafe file mode") }
	}
}

func TestStoreAuthentication(t *testing.T) {
	s,key,ctx,_:=newStore(t)
	if err:=s.Put(key,ctx,[]byte("synthetic-token")); err!=nil { t.Fatal(err) }
	other,err:=GenerateKey()
	if err!=nil { t.Fatal(err) }
	if p,err:=s.Get(other,ctx); p!=nil || !errors.Is(err,ErrAuthentication) { t.Fatal("wrong key accepted") }
	bad:=ctx
	bad.KeyID[0]^=1
	if p,err:=s.Get(key,bad); p!=nil || !errors.Is(err,ErrAuthentication) { t.Fatal("wrong key identifier accepted") }
	bad=ctx
	bad.VaultID[0]^=1
	if p,err:=s.Get(key,bad); p!=nil || !errors.Is(err,ErrInvalidContext) { t.Fatal("wrong vault accepted") }
	path,err:=s.recordPath(ctx)
	if err!=nil { t.Fatal(err) }
	raw,err:=os.ReadFile(path)
	if err!=nil { t.Fatal(err) }
	// Copy a valid version into another name/version slot.
	for _,mutate:=range []func(*RecordContext){
		func(c *RecordContext){c.Name="other-token"},
		func(c *RecordContext){c.Version++},
	} {
		bad=ctx
		mutate(&bad)
		target,err:=s.recordPath(bad)
		if err!=nil { t.Fatal(err) }
		if err:=os.WriteFile(target,raw,0600); err!=nil { t.Fatal(err) }
		if p,err:=s.Get(key,bad); p!=nil || !errors.Is(err,ErrAuthentication) { t.Fatal("substitution accepted") }
	}
	raw[len(raw)-1]^=1
	if err:=os.WriteFile(path,raw,0600); err!=nil { t.Fatal(err) }
	if p,err:=s.Get(key,ctx); p!=nil || !errors.Is(err,ErrAuthentication) { t.Fatal("tampered record accepted") }
	if err:=os.WriteFile(path,make([]byte,maxRecordBytes+1),0600); err!=nil { t.Fatal(err) }
	if p,err:=s.Get(key,ctx); p!=nil || err==nil { t.Fatal("oversized record accepted") }
}

func TestStoreConcurrentPublication(t *testing.T) {
	a,key,ctx,dir:=newStore(t)
	b,err:=Open(dir,ctx.VaultID)
	if err!=nil { t.Fatal(err) }
	var wg sync.WaitGroup
	var accepted atomic.Int32
	var winner atomic.Int32
	for i:=1;i<=8;i++ {
		wg.Add(1)
		go func(i int){
			defer wg.Done()
			s:=a
			if i%2==0 { s=b }
			// Synthetic contention fixture uses one test key.
			err:=s.Put(key,ctx,[]byte{byte(i)})
			if err==nil { winner.Store(int32(i)); accepted.Add(1) } else if !errors.Is(err,ErrRecordExists) { t.Errorf("unexpected publication error: %v",err) }
		}(i)
	}
	wg.Wait()
	if accepted.Load()!=1 { t.Fatalf("published %d versions",accepted.Load()) }
	p,err:=b.Get(key,ctx)
	if err!=nil || !bytes.Equal(p,[]byte{byte(winner.Load())}) { t.Fatal("winning version changed") }
	entries,err:=os.ReadDir(dir)
	if err!=nil || len(entries)!=2 { t.Fatal("temporary record cleanup failed") }
}

func TestStoreUnsafeState(t *testing.T) {
	s,key,ctx,dir:=newStore(t)
	if err:=s.Put(key,ctx,[]byte("synthetic-token")); err!=nil { t.Fatal(err) }
	path,err:=s.recordPath(ctx)
	if err!=nil { t.Fatal(err) }
	wrong:=ctx.VaultID
	wrong[0]^=1
	if _,err:=Open(dir,wrong); err==nil { t.Fatal("wrong vault ID accepted") }
	if _,err:=Open(filepath.Join(dir,"missing"),ctx.VaultID); err==nil { t.Fatal("missing vault opened") }
	if err:=os.Chmod(dir,0755); err!=nil { t.Fatal(err) }
	if err:=s.Ready(); err==nil { t.Fatal("public directory accepted") }
	if err:=os.Chmod(dir,0700); err!=nil { t.Fatal(err) }
	if err:=os.Chmod(path,0644); err!=nil { t.Fatal(err) }
	if p,err:=s.Get(key,ctx); p!=nil || err==nil { t.Fatal("public file accepted") }
	if err:=os.Chmod(path,0600); err!=nil { t.Fatal(err) }
	// A symlink is rejected even if it leads to a valid encrypted record.
	backup:=path+".backup"
	if err:=os.Rename(path,backup); err!=nil { t.Fatal(err) }
	if err:=os.Symlink(backup,path); err!=nil { t.Fatal(err) }
	if p,err:=s.Get(key,ctx); p!=nil || err==nil { t.Fatal("symlink accepted") }
	if err:=s.Put(key,ctx,[]byte("test")); !errors.Is(err,ErrRecordExists) { t.Fatal("symlink overwritten") }
	if err:=os.Rename(dir,dir+"-old"); err!=nil { t.Fatal(err) }
	if err:=Init(dir,ctx.VaultID); err!=nil { t.Fatal(err) }
	if p,err:=s.Get(key,ctx); p!=nil || !errors.Is(err,ErrStoreUnavailable) { t.Fatal("replaced directory accepted") }
}

func TestManifestReplacement(t *testing.T) {
	s,_,ctx,dir:=newStore(t)
	path:=filepath.Join(dir,manifestName)
	if err:=os.Rename(path,path+".old"); err!=nil { t.Fatal(err) }
	if err:=os.WriteFile(path,append([]byte(manifestMagic),ctx.VaultID[:]...),0600); err!=nil { t.Fatal(err) }
	if err:=s.Ready(); !errors.Is(err,ErrStoreUnavailable) { t.Fatal("replaced manifest accepted") }
}
