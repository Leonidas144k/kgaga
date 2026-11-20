package revocation

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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
			id:=fmt.Sprintf("%032x",i)
			// Busy is an intentional fail-closed outcome, not a quota
			// violation. Retry only that pre-reservation error within a
			// test deadline; never retry ambiguous storage failures.
			deadline:=time.Now().Add(20*time.Second)
			for {
				err:=s.consumeWithWait(id,4,250*time.Millisecond)
				if err==nil { passed.Add(1); return }
				if errors.Is(err,ErrReplayCapacity) { return }
				if !errors.Is(err,ErrReplayBusy) || !time.Now().Before(deadline) {
					t.Errorf("unexpected or persistent error: %v",err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
	if passed.Load()!=4 { t.Fatalf("accepted %d want 4",passed.Load()) }
	recorded:=0
	for i:=0;i<12;i++ {
		err:=a.Check(fmt.Sprintf("%032x",i))
		if errors.Is(err,ErrRevoked) { recorded++ } else if err!=nil { t.Fatal(err) }
	}
	if recorded!=4 { t.Fatalf("recorded %d want 4",recorded) }
	raw,err:=os.ReadFile(filepath.Join(dir,countName))
	if err!=nil || string(raw)!="4" { t.Fatalf("incorrect persistent reservation count: %q, %v",raw,err) }
}

func TestReplayLockFailsClosed(t *testing.T) {
	dir:=filepath.Join(t.TempDir(),"replay")
	if err:=Init(dir); err!=nil { t.Fatal(err) }
	s,err:=Open(dir); if err!=nil { t.Fatal(err) }
	if err:=os.Mkdir(filepath.Join(dir,lockName),0700); err!=nil { t.Fatal(err) }
	id:=fmt.Sprintf("%032x",1)
	if err:=s.consumeWithWait(id,4,30*time.Millisecond); !errors.Is(err,ErrReplayBusy) { t.Fatalf("locked store: %v",err) }
	if err:=s.Check(id); err!=nil { t.Fatal("busy attempt recorded nonce") }
	if _,err:=os.Stat(filepath.Join(dir,countName)); !os.IsNotExist(err) { t.Fatal("busy attempt reserved capacity") }
	if _,err:=os.Stat(filepath.Join(dir,lockName)); err!=nil { t.Fatal("busy attempt removed lock") }
}

func TestReplayWaitsForSlowWriter(t *testing.T) {
	dir:=filepath.Join(t.TempDir(),"replay")
	if err:=Init(dir); err!=nil { t.Fatal(err) }
	s,err:=Open(dir); if err!=nil { t.Fatal(err) }
	lock:=filepath.Join(dir,lockName)
	if err:=os.Mkdir(lock,0700); err!=nil { t.Fatal(err) }
	id:=fmt.Sprintf("%032x",1)
	done:=make(chan error,1)
	go func(){ done<-s.consumeBounded(id,4) }()
	// The previous 100 ms timeout would reject legitimate contention.
	select {
	case err:=<-done: t.Fatalf("finished while lock held: %v",err)
	case <-time.After(200*time.Millisecond):
	}
	if err:=os.Remove(lock); err!=nil { t.Fatal(err) }
	select {
	case err:=<-done: if err!=nil { t.Fatal(err) }
	case <-time.After(5*time.Second): t.Fatal("writer did not finish")
	}
	if !errors.Is(s.Check(id),ErrRevoked) { t.Fatal("nonce not recorded") }
}

func TestReplayDuplicateConcurrent(t *testing.T) {
	dir:=filepath.Join(t.TempDir(),"replay")
	if err:=Init(dir); err!=nil { t.Fatal(err) }
	a,err:=Open(dir); if err!=nil { t.Fatal(err) }
	b,err:=Open(dir); if err!=nil { t.Fatal(err) }
	id:=fmt.Sprintf("%032x",1)
	var wg sync.WaitGroup
	var passed atomic.Int32
	for _,s:=range []*Store{a,b} {
		wg.Add(1)
		go func(s *Store){
			defer wg.Done()
			deadline:=time.Now().Add(20*time.Second)
			for {
				err:=s.consumeWithWait(id,4,250*time.Millisecond)
				if err==nil { passed.Add(1); return }
				if errors.Is(err,ErrRevoked) { return }
				if !errors.Is(err,ErrReplayBusy) || !time.Now().Before(deadline) { t.Errorf("duplicate contention: %v",err); return }
			}
		}(s)
	}
	wg.Wait()
	if passed.Load()!=1 { t.Fatalf("duplicate acceptance: %d",passed.Load()) }
	raw,err:=os.ReadFile(filepath.Join(dir,countName))
	if err!=nil || string(raw)!="1" { t.Fatalf("duplicate reserved capacity: %q, %v",raw,err) }
}
