package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
)

type shortWriter struct{}
func (shortWriter) Write(p []byte)(int,error) { return len(p)-1,nil }
type badWriter struct{}
func (badWriter) Write(p []byte)(int,error) { return 0,errors.New("private writer error") }

func TestAuditConcurrentJSON(t *testing.T) {
	var b bytes.Buffer
	r:=NewRecorder(&b)
	var wg sync.WaitGroup
	for i:=0;i<32;i++ {
		wg.Add(1)
		go func(){
			defer wg.Done()
			id,err:=NewID(); if err!=nil { t.Error(err); return }
			if err:=r.Record(Event{AttemptID:id,Action:"credential_use",Phase:"attempt",Actor:"agent",VaultID:"fixture",AgentID:"agent\nname"}); err!=nil { t.Error(err) }
		}()
	}
	wg.Wait()
	lines:=strings.Split(strings.TrimSuffix(b.String(),"\n"),"\n")
	if len(lines)!=32 { t.Fatal("audit lines interleaved") }
	seen:=map[string]bool{}
	for _,line:=range lines {
		var e Event
		if err:=json.Unmarshal([]byte(line),&e); err!=nil || e.Schema!="kgaga.vault.audit.v1" || e.Timestamp=="" || e.AgentID!="agent\nname" { t.Fatal("invalid audit event") }
		if seen[e.AttemptID] { t.Fatal("duplicate correlation id") }
		seen[e.AttemptID]=true
	}
}

func TestAuditErrors(t *testing.T) {
	id,err:=NewID(); if err!=nil { t.Fatal(err) }
	e:=Event{AttemptID:id,Action:"credential_use",Phase:"attempt",Actor:"agent",VaultID:"fixture"}
	for _,r:=range []*Recorder{nil,NewRecorder(nil),NewRecorder(shortWriter{}),NewRecorder(badWriter{})} {
		if err:=r.Record(e); !errors.Is(err,ErrUnavailable) { t.Fatal("audit failure not propagated") }
	}
	var b bytes.Buffer
	e.Target=strings.Repeat("x",maxEventBytes)
	if err:=NewRecorder(&b).Record(e); !errors.Is(err,ErrUnavailable) || b.Len()!=0 { t.Fatal("oversized event accepted") }
}

type recoverableWriter struct {
	buf bytes.Buffer
	calls int
	fail bool
}
func (w *recoverableWriter) Write(p []byte)(int,error) {
	w.calls++
	if w.fail { return w.buf.Write(p[:len(p)/2]) }
	return w.buf.Write(p)
}

func TestAuditFailureLatched(t *testing.T) {
	id,err:=NewID(); if err!=nil { t.Fatal(err) }
	e:=Event{AttemptID:id,Action:"credential_use",Phase:"attempt",Actor:"agent",VaultID:"fixture"}
	w:=&recoverableWriter{fail:true}
	r:=NewRecorder(w)
	if !errors.Is(r.Record(e),ErrUnavailable) { t.Fatal("short write accepted") }
	w.fail=false
	before:=w.buf.Len()
	var wg sync.WaitGroup
	for i:=0;i<16;i++ {
		wg.Add(1)
		go func(){ defer wg.Done(); if !errors.Is(r.Record(e),ErrUnavailable) { t.Error("failed recorder resumed") } }()
	}
	wg.Wait()
	if w.calls!=1 || w.buf.Len()!=before { t.Fatal("wrote additional bytes after stream failure") }
	// A deliberately new recorder on a repaired/new stream can operate.
	var repaired bytes.Buffer
	if err:=NewRecorder(&repaired).Record(e); err!=nil { t.Fatal("new recorder failed") }
}
