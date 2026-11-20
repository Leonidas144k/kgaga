package registry

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

func TestAgentLifecycle(t *testing.T) {
	path:=filepath.Join(t.TempDir(),"registry")
	if _,err:=Open(path); err==nil { t.Fatal("opened absent registry") }
	if err:=Init(path); err!=nil { t.Fatal(err) }
	s,err:=Open(path)
	if err!=nil { t.Fatal(err) }
	a:=Agent{ID:"agent",Owner:"owner",Scopes:[]string{"read","write"},Audiences:[]string{"api"}}
	if err:=s.Authorize(a.ID,a.Owner,[]string{"read"},"api"); !errors.Is(err,ErrDenied) { t.Fatal("unknown agent allowed") }
	if err:=s.Register(a); err!=nil { t.Fatal(err) }
	if err:=s.Register(a); err==nil { t.Fatal("overwrote agent") }
	if err:=s.Authorize(a.ID,a.Owner,[]string{"read"},"api"); err!=nil { t.Fatal(err) }
	for _,tc:=range []struct{owner,scope,aud string}{{"other","read","api"},{"owner","admin","api"},{"owner","read","other"}} {
		if err:=s.Authorize(a.ID,tc.owner,[]string{tc.scope},tc.aud); !errors.Is(err,ErrDenied) { t.Fatal("unauthorized claims accepted") }
	}
	if err:=s.Suspend(a.ID); err!=nil { t.Fatal(err) }
	if err:=s.Suspend(a.ID); err!=nil { t.Fatal(err) }
	reopened,err:=Open(path)
	if err!=nil { t.Fatal(err) }
	if _,suspended,err:=reopened.Get(a.ID); err!=nil || !suspended { t.Fatal("suspension lost") }
	if err:=reopened.Authorize(a.ID,a.Owner,[]string{"read"},"api"); !errors.Is(err,ErrDenied) { t.Fatal("suspended agent allowed") }
	if err:=os.Rename(path,path+"-backup"); err!=nil { t.Fatal(err) }
	if err:=Init(path); err!=nil { t.Fatal(err) }
	if err:=s.Ready(); err==nil { t.Fatal("replacement registry accepted") }
}

func TestConcurrentRegistration(t *testing.T) {
	path:=filepath.Join(t.TempDir(),"registry")
	if err:=Init(path); err!=nil { t.Fatal(err) }
	s,err:=Open(path)
	if err!=nil { t.Fatal(err) }
	a:=Agent{ID:"same",Owner:"owner",Scopes:[]string{"read"},Audiences:[]string{"api"}}
	var wg sync.WaitGroup
	var count atomic.Int32
	for i:=0;i<8;i++ {
		wg.Add(1)
		go func(){ defer wg.Done(); if s.Register(a)==nil { count.Add(1) } }()
	}
	wg.Wait()
	if count.Load()!=1 { t.Fatalf("registrations: %d",count.Load()) }
	if err:=s.Authorize(a.ID,a.Owner,a.Scopes,"api"); err!=nil { t.Fatal(err) }
	base,err:=s.base(a.ID)
	if err!=nil { t.Fatal(err) }
	if err:=os.WriteFile(base+".json",[]byte("{"),0600); err!=nil { t.Fatal(err) }
	if err:=s.Authorize(a.ID,a.Owner,a.Scopes,"api"); err==nil { t.Fatal("corrupt record accepted") }
}
