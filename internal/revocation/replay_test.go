package revocation

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

func TestReplayQuotaPersists(t *testing.T) {
	dir:=filepath.Join(t.TempDir(),"replay")
	if err:=Init(dir); err!=nil { t.Fatal(err) }
	s,err:=Open(dir)
	if err!=nil { t.Fatal(err) }
	id:=func(n int)string{return fmt.Sprintf("%032x",n)}
	// Simulate old format before the quota upgrade.
	if err:=s.createReplayMarker(id(1)); err!=nil { t.Fatal(err) }
	if err:=s.consumeBounded(id(2),3); err!=nil { t.Fatal(err) }
	if err:=s.consumeBounded(id(2),3); !errors.Is(err,ErrRevoked) { t.Fatalf("replay: %v",err) }
	other,err:=Open(dir)
	if err!=nil { t.Fatal(err) }
	if err:=other.consumeBounded(id(3),3); err!=nil { t.Fatal(err) }
	if err:=s.consumeBounded(id(4),3); !errors.Is(err,ErrReplayCapacity) { t.Fatalf("quota: %v",err) }
	if err:=other.consumeBounded(id(1),3); !errors.Is(err,ErrRevoked) { t.Fatal("old replay lost") }
	if err:=other.Check(id(4)); err!=nil { t.Fatal("rejected nonce recorded") }
	if err:=os.WriteFile(filepath.Join(dir,countName),[]byte("invalid"),0600); err!=nil { t.Fatal(err) }
	if err:=other.consumeBounded(id(5),3); err==nil { t.Fatal("accepted corrupt counter") }
}

func TestReplayQuotaConcurrent(t *testing.T) {
	dir:=filepath.Join(t.TempDir(),"replay")
	if err:=Init(dir); err!=nil { t.Fatal(err) }
	a,err:=Open(dir); if err!=nil { t.Fatal(err) }
	b,err:=Open(dir); if err!=nil { t.Fatal(err) }
	var wg sync.WaitGroup
	var passed atomic.Int32
	for i:=0;i<12;i++ {
		wg.Add(1)
		go func(i int){
			defer wg.Done()
			s:=a
			if i%2==0 { s=b }
			if err:=s.consumeBounded(fmt.Sprintf("%032x",i),4); err==nil { passed.Add(1) } else if !errors.Is(err,ErrReplayCapacity) { t.Errorf("unexpected error: %v",err) }
		}(i)
	}
	wg.Wait()
	if passed.Load()!=4 { t.Fatalf("accepted %d want 4",passed.Load()) }
}

func TestReplayLockFailsClosed(t *testing.T) {
	dir:=filepath.Join(t.TempDir(),"replay")
	if err:=Init(dir); err!=nil { t.Fatal(err) }
	s,err:=Open(dir); if err!=nil { t.Fatal(err) }
	if err:=os.Mkdir(filepath.Join(dir,lockName),0700); err!=nil { t.Fatal(err) }
	if err:=s.consumeBounded(fmt.Sprintf("%032x",1),4); err==nil { t.Fatal("accepted locked store") }
}
