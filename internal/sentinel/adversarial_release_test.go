package sentinel

import (
 "context"
 "errors"
 "os"
 "path/filepath"
 "testing"
 "time"

 "github.com/Leonidas144k/kgaga/internal/audit"
 "github.com/Leonidas144k/kgaga/internal/ledger"
)

// A delivery ID is a transport idempotency key, not merely a per-incident
// label. A crafted but HMAC-authenticated Ledger history must not reuse it.
func TestAdversarialRejectCrossIncidentDeliveryIDReuse(t *testing.T){
 j,jdir,cdir,key,witness,id,now:=recoveryFixture(t)
 clock:=func()time.Time{return now}
 m,err:=NewIncidentManager(j,10,clock)
 if err!=nil{t.Fatal(err)}
 a:=incidentAlert(now)
 first,err:=m.Open(a)
 if err!=nil{t.Fatal(err)}
 a.AgentID="second-agent"
 second,err:=m.Open(a)
 if err!=nil{t.Fatal(err)}
 sharedID,err:=audit.NewID()
 if err!=nil{t.Fatal(err)}
 d,err:=NewDispatcher(m,j,&fakeDeliveryTransport{},DefaultDeliveryConfig(),clock)
 if err!=nil{t.Fatal(err)}
 for _,in:=range []Incident{first,second}{
  queued:=Delivery{ID:sharedID,IncidentID:in.ID,IncidentRevision:in.Revision,Status:DeliveryQueued}
  if err:=d.persist(in,queued,"queued",now);err!=nil{t.Fatal(err)}
 }
 expected,err:=j.Head()
 if err!=nil{t.Fatal(err)}
 if err:=j.Close();err!=nil{t.Fatal(err)}
 reopened,err:=ledger.OpenAnchoredJournal(jdir,cdir,key,witness,id,expected)
 if err!=nil{t.Fatal(err)}
 transport:=&fakeDeliveryTransport{}
 if _,_,err:=RestoreDispatcher(reopened,10,transport,DefaultDeliveryConfig(),clock);!errors.Is(err,ErrDeliveryStorage){
  t.Fatal("reused idempotency key accepted",err)
 }
 if transport.count()!=0{t.Fatal("recovery triggered transport")}
 if err:=reopened.Close();err!=nil{t.Fatal(err)}
}

// A privileged local edit to a record cannot be repaired or accepted by
// recovery, even if it preserves the same byte count or journal inode.
func TestAdversarialRejectModifiedJournalBeforeRecovery(t *testing.T){
 j,jdir,cdir,key,witness,id,now:=recoveryFixture(t)
 m,err:=NewIncidentManager(j,10,func()time.Time{return now})
 if err!=nil{t.Fatal(err)}
 in,err:=m.Open(incidentAlert(now))
 if err!=nil{t.Fatal(err)}
 transport:=&fakeDeliveryTransport{}
 d,err:=NewDispatcher(m,j,transport,DefaultDeliveryConfig(),func()time.Time{return now})
 if err!=nil{t.Fatal(err)}
 if _,err:=d.Notify(context.Background(),in.ID);err!=nil{t.Fatal(err)}
 expected,err:=j.Head()
 if err!=nil{t.Fatal(err)}
 if err:=j.Close();err!=nil{t.Fatal(err)}
 path:=filepath.Join(jdir,"ledger.jsonl")
 raw,err:=os.ReadFile(path)
 if err!=nil{t.Fatal(err)}
 changed:=false
 for i:=0;i<len(raw);i++{
  if raw[i]=='q'{
   raw[i]='x'
   changed=true
   break
  }
 }
 if !changed{t.Fatal("no journal byte available for mutation")}
 if err:=os.WriteFile(path,raw,0600);err!=nil{t.Fatal(err)}
 if _,err:=ledger.OpenAnchoredJournal(jdir,cdir,key,witness,id,expected);err==nil{
  t.Fatal("modified journal accepted against independently expected checkpoint")
 }
 if transport.count()!=1{t.Fatal("recovery dispatched another notification")}
}

// Even when transport acceptance is valid, a replayed terminal record
// must never be able to advance an incident or trigger another send.
func TestAdversarialRejectRepeatedDeliveryTerminal(t *testing.T){
 j,jdir,cdir,key,witness,id,now:=recoveryFixture(t)
 m,err:=NewIncidentManager(j,10,func()time.Time{return now})
 if err!=nil{t.Fatal(err)}
 in,err:=m.Open(incidentAlert(now));if err!=nil{t.Fatal(err)}
 d,err:=NewDispatcher(m,j,&fakeDeliveryTransport{},DefaultDeliveryConfig(),func()time.Time{return now})
 if err!=nil{t.Fatal(err)}
 accepted,err:=d.Notify(context.Background(),in.ID)
 if err!=nil{t.Fatal(err)}
 ev:=audit.Event{
  Schema:"kgaga.vault.audit.v1",Timestamp:now.UTC().Format(time.RFC3339Nano),
  Action:"sentinel_delivery",Actor:"sentinel",Phase:"accepted",
  VaultID:in.Alert.VaultID,AgentID:in.Alert.AgentID,
  Owner:in.Alert.Owner,Audience:in.Alert.Audience,
  IncidentID:in.ID,IncidentRevision:in.Revision,IncidentSignal:in.Alert.Signal,
  IncidentState:in.State,DeliveryID:accepted.ID,DeliveryPhase:"accepted",
  DeliveryAttempt:accepted.Attempts,DeliveryChannel:DeliveryChannel,
 }
 ev.AttemptID,err=audit.NewID()
 if err!=nil{t.Fatal(err)}
 if _,err:=j.Append(ev);err!=nil{t.Fatal(err)}
 head,err:=j.Head();if err!=nil{t.Fatal(err)}
 if err:=j.Close();err!=nil{t.Fatal(err)}
 reopened,err:=ledger.OpenAnchoredJournal(jdir,cdir,key,witness,id,head)
 if err!=nil{t.Fatal(err)}
 transport:=&fakeDeliveryTransport{}
 if _,_,err:=RestoreDispatcher(reopened,10,transport,DefaultDeliveryConfig(),func()time.Time{return now});!errors.Is(err,ErrDeliveryStorage){
  t.Fatal("repeated terminal event admitted",err)
 }
 if transport.count()!=0{t.Fatal("unverified recovery dispatched transport")}
 if err:=reopened.Close();err!=nil{t.Fatal(err)}
}
