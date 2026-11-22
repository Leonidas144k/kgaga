package ledger

import (
 "bytes"
 "encoding/json"
 "io"

 "github.com/Leonidas144k/kgaga/internal/audit"
)

// SentinelHistory returns incident and delivery transitions in the exact
// verified Ledger order. The journal must already have been opened against
// an independently trusted Head. This method verifies the ENTIRE observed
// journal, not just the chosen events. It enforces a bounded replay window.
// It does not anchor checkpoints or offer crash-lock recovery.
func (a *AnchoredJournal) SentinelHistory(limit int) ([]audit.Event,Head,error) {
 if a==nil || limit<1 || limit>maxIncidentReplayEvents {
  return nil,Head{},ErrInvalid
 }
 a.mu.Lock()
 defer a.mu.Unlock()
 if a.failed || a.closed || a.journal==nil || a.checkpoint==nil {
  return nil,Head{},ErrAnchor
 }
 fail:=func()([]audit.Event,Head,error){
  a.failed=true
  return nil,Head{},ErrCorrupt
 }
 h,err:=a.journal.Head()
 if err!=nil{return fail()}
 witness,err:=a.checkpoint.Head()
 if err!=nil || witness!=h {return fail()}
 file:=a.journal.file
 if _,err:=file.Seek(0,io.SeekStart);err!=nil{return fail()}
 raw,err:=io.ReadAll(io.LimitReader(file,maxIncidentReplayBytes+1))
 _,seekErr:=file.Seek(0,io.SeekEnd)
 if err!=nil || seekErr!=nil || len(raw)>maxIncidentReplayBytes{return fail()}
 observed,err:=Verify(bytes.NewReader(raw),a.journal.chain.key,a.journal.chain.id)
 if err!=nil || observed!=h{return fail()}
 var result []audit.Event
 for _,line:=range bytes.Split(raw,[]byte{'\n'}){
  if len(line)==0{continue}
  var record record
  if json.Unmarshal(line,&record)!=nil{return fail()}
  switch record.Event.Action {
  case "sentinel_incident","sentinel_delivery":
   if len(result)>=limit{return fail()}
   result=append(result,record.Event)
  }
 }
 again,err:=a.journal.Head()
 if err!=nil || again!=h{return fail()}
 witnessed,err:=a.checkpoint.Head()
 if err!=nil || witnessed!=h{return fail()}
 return result,h,nil
}
