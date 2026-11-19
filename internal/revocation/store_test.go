package revocation

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestPersistentRevocations(t *testing.T) {
	path:=filepath.Join(t.TempDir(),"revocations")
	id:=strings.Repeat("a",32)
	if _,err:=Open(path); err==nil { t.Fatal("opened missing store") }
	if err:=Init(path); err!=nil { t.Fatal(err) }
	s,err:=Open(path)
	if err!=nil { t.Fatal(err) }
	if err:=s.Check(id); err!=nil { t.Fatal(err) }
	if err:=s.Revoke(id); err!=nil { t.Fatal(err) }
	if err:=s.Revoke(id); err!=nil { t.Fatal(err) }
	if err:=Init(path); err==nil { t.Fatal("overwrote existing store") }
	reopened,err:=Open(path)
	if err!=nil { t.Fatal(err) }
	if !errors.Is(reopened.Check(id),ErrRevoked) { t.Fatal("revocation lost after restart") }
	if err:=reopened.Check(strings.Repeat("b",32)); err!=nil { t.Fatal(err) }
	for _,bad:=range []string{"","../escape","A"+id[1:],strings.Repeat("z",32),id+"x"} {
		if err:=s.Check(bad); err==nil { t.Fatalf("accepted invalid ID %q",bad) }
		if err:=s.Revoke(bad); err==nil { t.Fatalf("revoked invalid ID %q",bad) }
	}
	if err:=os.Rename(path,path+"-backup"); err!=nil { t.Fatal(err) }
	if err:=s.Check(id); err==nil { t.Fatal("accepted missing store") }
	if err:=Init(path); err!=nil { t.Fatal(err) }
	if err:=s.Check(id); err==nil { t.Fatal("accepted replaced store") }
}

func TestConcurrentRevocations(t *testing.T) {
	path:=filepath.Join(t.TempDir(),"revocations")
	if err:=Init(path); err!=nil { t.Fatal(err) }
	s,err:=Open(path)
	if err!=nil { t.Fatal(err) }
	var wg sync.WaitGroup
	for i:=0;i<16;i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id:=fmt.Sprintf("%032x",i)
			if err:=s.Revoke(id); err!=nil { t.Error(err) }
			if err:=s.Revoke(id); err!=nil { t.Error(err) }
		}(i)
	}
	wg.Wait()
	for i:=0;i<16;i++ {
		if !errors.Is(s.Check(fmt.Sprintf("%032x",i)),ErrRevoked) { t.Fatalf("lost revocation %d",i) }
	}
}
