package ledger

import (
 "bytes"
 "encoding/json"
 "errors"
 "io"
 "sync"

 "github.com/Leonidas144k/kgaga/internal/audit"
)

var ErrAuditBridge=errors.New("ledger audit bridge unavailable")

// AuditBridge implements io.Writer for audit.NewRecorder. It accepts one
// canonical kgaga.vault.audit.v1 JSONL record per call and appends it to a
// journal plus checkpoint before acknowledging the write. It never logs
// or falls back to stderr on a failed append.
type AuditBridge struct {
 mu sync.Mutex
 journal *AnchoredJournal
 failed bool
}

// NewAuditBridge is an explicit operator-programmatic opt-in. It never
// initializes or repairs journal state and requires an already-open,
// checkpoint-verified AnchoredJournal.
func NewAuditBridge(j *AnchoredJournal)(*AuditBridge,error){
 if j==nil {return nil,ErrAuditBridge}
 if _,err:=j.Head();err!=nil{return nil,ErrAuditBridge}
 return &AuditBridge{journal:j},nil
}

// Write is designed for audit.Recorder, which supplies complete canonical
// event lines. Invalid or ambiguous input fails closed. Any sink failure
// latches this bridge; a partial append must never be retried blindly.
func(b *AuditBridge)Write(p []byte)(int,error){
 if b==nil{return 0,ErrAuditBridge}
 b.mu.Lock()
 defer b.mu.Unlock()
 if b.failed{return 0,ErrAuditBridge}
 fail:=func()(int,error){b.failed=true;return 0,ErrAuditBridge}
 if len(p)<2 || len(p)>maxEventBytes+1 || p[len(p)-1]!='\n' ||
  bytes.IndexByte(p[:len(p)-1],'\n')>=0{return fail()}
 var ev audit.Event
 if err:=json.Unmarshal(p[:len(p)-1],&ev);err!=nil{return fail()}
 canonical,err:=marshalEvent(ev)
 if err!=nil || !bytes.Equal(canonical,p[:len(p)-1]){return fail()}
 if _,err:=b.journal.Append(ev);err!=nil{return fail()}
 return len(p),nil
}

var _ io.Writer=(*AuditBridge)(nil)
