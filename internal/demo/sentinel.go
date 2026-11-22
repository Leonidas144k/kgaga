// Package demo implements an isolated, synthetic-only integration exercise.
// It deliberately does not start a Gateway, access real Vault secrets or
// configure any external transport. No state survives the process.
package demo

import (
 "encoding/json"
 "errors"
 "io"
 "os"
 "path/filepath"
 "time"

 "github.com/Leonidas144k/kgaga/internal/audit"
 "github.com/Leonidas144k/kgaga/internal/ledger"
 "github.com/Leonidas144k/kgaga/internal/sentinel"
)

var ErrDemo=errors.New("synthetic sentinel demonstration failed")

type Summary struct {
 Mode string `json:"mode"`
 AdvisorySignals int `json:"advisory_signals"`
 IncidentTransitions int `json:"incident_transitions"`
 VerifiedLedgerRecords uint64 `json:"verified_ledger_records"`
 RecoveredState string `json:"recovered_state"`
 NotificationsSent int `json:"notifications_sent"`
 ProductionConfigured bool `json:"production_configured"`
}

// RunSentinel performs a short-lived synthetic event -> verified Ledger ->
// advisory Sentinel -> incident -> verified restart lifecycle. Keys and files
// are generated under an exclusively created temporary directory and removed
// on exit. The expected Head is retained only in this process: this does not
// demonstrate external checkpoint anchoring or production restart recovery.
func RunSentinel(out io.Writer) error {
 if out==nil{return ErrDemo}
 root,err:=os.MkdirTemp("","kgaga-synthetic-")
 if err!=nil{return ErrDemo}
 defer os.RemoveAll(root)
 private:=filepath.Join(root,"private")
 if err:=os.Mkdir(private,0700);err!=nil{return ErrDemo}
 chainKey,err:=ledger.GenerateKey();if err!=nil{return ErrDemo}
 defer clear(chainKey[:])
 witnessKey,err:=ledger.GenerateKey();if err!=nil{return ErrDemo}
 defer clear(witnessKey[:])
 stream,err:=ledger.GenerateStreamID();if err!=nil{return ErrDemo}
 journalDir:=filepath.Join(private,"journal")
 checkpointDir:=filepath.Join(private,"checkpoint")
 anchor,err:=ledger.InitAnchoredJournal(journalDir,checkpointDir,chainKey,witnessKey,stream)
 if err!=nil{return ErrDemo}
 bridge,err:=ledger.NewAuditBridge(anchor)
 if err!=nil{return ErrDemo}
 recorder:=audit.NewRecorder(bridge)
 now:=time.Now().UTC()
 clock:=func()time.Time{return now}
 engine,err:=sentinel.NewEngine(sentinel.DefaultConfig(),clock)
 if err!=nil{return ErrDemo}
 manager,err:=sentinel.NewIncidentManager(anchor,12,clock)
 if err!=nil{return ErrDemo}
 var caseID string
 signals:=0
 for i:=0;i<5;i++ {
  attempt,err:=audit.NewID()
  if err!=nil{return ErrDemo}
  event:=audit.Event{
   Schema:"kgaga.vault.audit.v1",Timestamp:now.Format(time.RFC3339Nano),
   AttemptID:attempt,Action:"credential_use",
   Phase:"denied_before_dispatch",Actor:"agent",
   VaultID:"synthetic-vault",AgentID:"synthetic-agent",
   Owner:"synthetic-owner",Audience:"synthetic-api",
  }
  if err:=recorder.Record(event);err!=nil{return ErrDemo}
  alert,err:=engine.Observe(event)
  if err!=nil{return ErrDemo}
  if alert!=nil{
   signals++
   opened,err:=manager.Open(*alert)
   if err!=nil{return ErrDemo}
   caseID=opened.ID
  }
 }
 if signals!=1||caseID=="" {return ErrDemo}
 ack,err:=manager.Acknowledge(caseID,"synthetic-reviewer",1)
 if err!=nil||ack.Revision!=2{return ErrDemo}
 resolved,err:=manager.Resolve(caseID,"synthetic-reviewer",2,sentinel.ResolutionInconclusive)
 if err!=nil||resolved.Revision!=3{return ErrDemo}
 expected,err:=anchor.Head()
 if err!=nil||expected.Sequence!=8{return ErrDemo}
 if err:=anchor.Close();err!=nil{return ErrDemo}
 reopened,err:=ledger.OpenAnchoredJournal(journalDir,checkpointDir,chainKey,witnessKey,stream,expected)
 if err!=nil{return ErrDemo}
 restored,err:=sentinel.RestoreIncidentManager(reopened,12,clock)
 if err!=nil{return ErrDemo}
 recovered,err:=restored.Get(caseID)
 if err!=nil||recovered.State!=sentinel.IncidentResolved||
   recovered.Revision!=3||recovered.Resolution!=sentinel.ResolutionInconclusive{return ErrDemo}
 after,err:=reopened.Head()
 if err!=nil||after!=expected{return ErrDemo}
 if err:=reopened.Close();err!=nil{return ErrDemo}
 return json.NewEncoder(out).Encode(Summary{
  Mode:"synthetic",AdvisorySignals:signals,
  IncidentTransitions:3,VerifiedLedgerRecords:expected.Sequence,
  RecoveredState:recovered.State,NotificationsSent:0,
  ProductionConfigured:false,
 })
}
