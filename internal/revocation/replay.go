package revocation

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const MaxReplayMarkers = 1000000

var ErrReplayCapacity = errors.New("replay store quota exhausted")

const countName = ".replay-count"
const lockName = ".replay-lock"

// Consume reserves capacity persistently before creating the exclusive nonce
// marker. Cooperating updated processes share a quota. No marker is pruned,
// including on restart. Older writers must be stopped before upgrading.
// A crash leaving the lock behind denies admission until offline recovery.
func (s *Store) Consume(id string) error {
	return s.consumeBounded(id,MaxReplayMarkers)
}

func (s *Store) consumeBounded(id string,limit int) (result error) {
	if limit<1 || limit>MaxReplayMarkers { return errors.New("invalid replay quota") }
	if _,err:=s.marker(id); err!=nil { return err }
	s.replayMu.Lock()
	defer s.replayMu.Unlock()
	if err:=s.ready(); err!=nil { return err }
	lock:=filepath.Join(s.dir,lockName)
	deadline:=time.Now().Add(100*time.Millisecond)
	for {
		err:=os.Mkdir(lock,0700)
		if err==nil { break }
		if !os.IsExist(err) { return err }
		if !time.Now().Before(deadline) { return errors.New("replay quota lock unavailable") }
		time.Sleep(5*time.Millisecond)
	}
	defer func(){
		if err:=s.ready(); err!=nil { result=err; return }
		if err:=os.Remove(lock); err!=nil { result=fmt.Errorf("release replay quota lock: %w",err) }
	}()
	if err:=s.Check(id); err!=nil { return err }
	n,err:=s.replayCount(limit)
	if err!=nil { return err }
	if n>=limit { return ErrReplayCapacity }
	// A failed marker write burns its reserved slot, never increases the
	// quota. Atomic publication is a normal-restart guarantee, not a
	// power-loss guarantee. Protected operator state is assumed.
	if err:=s.writeReplayCount(n+1); err!=nil { return err }
	return s.createReplayMarker(id)
}

func (s *Store) replayCount(limit int) (int,error) {
	path:=filepath.Join(s.dir,countName)
	info,err:=os.Lstat(path)
	if err==nil {
		if !info.Mode().IsRegular() || info.Size()<1 || info.Size()>16 { return 0,errors.New("invalid replay count record") }
		f,err:=os.Open(path)
		if err!=nil { return 0,err }
		defer f.Close()
		raw,err:=io.ReadAll(io.LimitReader(f,17))
		if err!=nil || len(raw)>16 { return 0,errors.New("invalid replay count record") }
		n,err:=strconv.Atoi(string(raw))
		if err!=nil || n<0 || n>MaxReplayMarkers || strconv.Itoa(n)!=string(raw) { return 0,errors.New("invalid replay count record") }
		return n,nil
	}
	if !os.IsNotExist(err) { return 0,err }
	// First upgrade: count legacy markers without loading the whole directory
	// into memory. Unknown entries are errors, not silently ignored.
	f,err:=os.Open(s.dir)
	if err!=nil { return 0,err }
	defer f.Close()
	count:=0
	for {
		entries,err:=f.ReadDir(256)
		for _,entry:=range entries {
			if entry.Name()==lockName { continue }
			name:=entry.Name()
			if len(name)!=32 || strings.ToLower(name)!=name { return 0,errors.New("unexpected replay directory entry") }
			for _,c:=range name { if !(c>='0'&&c<='9'||c>='a'&&c<='f') { return 0,errors.New("invalid replay marker") } }
			if !entry.Type().IsRegular() { return 0,errors.New("invalid replay marker type") }
			count++
			if count>=limit { return 0,ErrReplayCapacity }
		}
		if err==io.EOF { break }
		if err!=nil { return 0,err }
	}
	return count,s.ready()
}

func (s *Store) writeReplayCount(n int) error {
	if err:=s.ready(); err!=nil { return err }
	f,err:=os.CreateTemp(s.dir,".replay-reserve-")
	if err!=nil { return err }
	defer os.Remove(f.Name())
	if _,err:=f.WriteString(strconv.Itoa(n)); err!=nil { _=f.Close(); return err }
	if err:=f.Sync(); err!=nil { _=f.Close(); return err }
	if err:=f.Close(); err!=nil { return err }
	if err:=s.ready(); err!=nil { return err }
	if err:=os.Rename(f.Name(),filepath.Join(s.dir,countName)); err!=nil { return err }
	return s.ready()
}
