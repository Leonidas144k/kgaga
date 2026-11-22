package sentinel

import (
 "context"
 "errors"
 "testing"
 "time"

 "github.com/Leonidas144k/kgaga/internal/audit"
 "github.com/Leonidas144k/kgaga/internal/ledger"
)

func restoreDeliveryFixture(t *testing.T,fail bool)(*ledger.AnchoredJournal,string,string,ledger.Key,ledger.Key,ledger.StreamID,*time.Time,string,*fakeDeliveryTransport){
 t.Helper()
 j,jdir,cdir,key,witness,id,clock:=recoveryFixture(t)
 m,err:=NewIncidentManager(j,10,func()time.Time{return clock})
 if err!=nil{t.Fatal(err)}
 opened,err:=m.Open(incidentAlert(clock))
 if err!=nil{t.Fatal(err)}
 transport:=&fakeDeliveryTransport{fail:fail}
 d,err:=NewDispatcher(m,j,transport,DefaultDeliveryConfig(),func()time.Time{return clock})
 if err!=nil{t.Fatal(err)}
 _=d
 return j,jdir,cdir,key,witness,id,&clock,opened.ID,transport
}

func reopenForDelivery(t *testing.T,j *ledger.AnchoredJournal,jdir,cdir string,key,witness ledger.Key,id ledger.StreamID)*ledger.AnchoredJournal{
 t.Helper()
 head,err:=j.Head()
 if err!=nil{t.Fatal(err)}
 if err:=j.Close();err!=nil{t.Fatal(err)}
 reopened,err:=ledger.OpenAnchoredJournal(jdir,cdir,key,witness,id,head)
 if err!=nil{t.Fatal(err)}
 return reopened
}

func TestRestoreAcceptedDeliveryPreventsResend(t *testing.T){
 j,jdir,cdir,key,witness,id,now,incidentID,transport:=restoreDeliveryFixture(t,false)
 m,err:=RestoreIncidentManager(j,10,func()time.Time{return *now})
 if err!=nil{t.Fatal(err)}
 // Fresh construction is allowed while there is no delivery history.
 d,err:=NewDispatcher(m,j,transport,DefaultDeliveryConfig(),func()time.Time{return *now})
 if err!=nil{t.Fatal(err)}
 sent,err:=d.Notify(context.Background(),incidentID)
 if err!=nil||sent.Status!=DeliveryAccepted||transport.count()!=1{t.Fatal("initial notification failed",err)}
 reopened:=reopenForDelivery(t,j,jdir,cdir,key,witness,id)
 if _,err:=NewDispatcher(m,reopened,transport,DefaultDeliveryConfig(),func()time.Time{return *now});!errors.Is(err,ErrDeliveryStorage) {
  t.Fatal("fresh dispatcher reset persisted delivery history",err)
 }
 recoveredManager,recovered,err:=RestoreDispatcher(reopened,10,transport,DefaultDeliveryConfig(),func()time.Time{return *now})
 if err!=nil{t.Fatal(err)}
 if _,err:=recoveredManager.Get(incidentID);err!=nil{t.Fatal(err)}
 got,err:=recovered.Get(incidentID)
 if err!=nil||got!=sent{t.Fatal("accepted delivery state lost",err)}
 again,err:=recovered.Notify(context.Background(),incidentID)
 if err!=nil||again!=sent||transport.count()!=1{t.Fatal("accepted message resent",err)}
 if err:=reopened.Close();err!=nil{t.Fatal(err)}
}

func TestRestoreFailedDeliveryKeepsBudgetAndStableID(t *testing.T){
 j,jdir,cdir,key,witness,id,now,incidentID,transport:=restoreDeliveryFixture(t,true)
 manager,err:=RestoreIncidentManager(j,10,func()time.Time{return *now})
 if err!=nil{t.Fatal(err)}
 d,err:=NewDispatcher(manager,j,transport,DefaultDeliveryConfig(),func()time.Time{return *now})
 if err!=nil{t.Fatal(err)}
 failed,err:=d.Notify(context.Background(),incidentID)
 if !errors.Is(err,ErrDeliveryTransport)||failed.Status!=DeliveryFailed||failed.Attempts!=1{t.Fatal("first failure not stored",err)}
 reopened:=reopenForDelivery(t,j,jdir,cdir,key,witness,id)
 _,restored,err:=RestoreDispatcher(reopened,10,transport,DefaultDeliveryConfig(),func()time.Time{return *now})
 if err!=nil{t.Fatal(err)}
 if _,err:=restored.Notify(context.Background(),incidentID);!errors.Is(err,ErrDeliveryRetry) {t.Fatal("retry cooldown lost",err)}
 *now=now.Add(2*time.Second)
 transport.mu.Lock();transport.fail=false;transport.mu.Unlock()
 accepted,err:=restored.Notify(context.Background(),incidentID)
 if err!=nil||accepted.Status!=DeliveryAccepted||accepted.Attempts!=2||
 accepted.ID!=failed.ID||transport.count()!=2{t.Fatal("recovered retry not bounded/idempotent",err)}
 if err:=reopened.Close();err!=nil{t.Fatal(err)}
}

func TestRestoreUncertainAttemptNeverResends(t *testing.T){
 j,jdir,cdir,key,witness,id,now,incidentID,transport:=restoreDeliveryFixture(t,false)
 manager,err:=RestoreIncidentManager(j,10,func()time.Time{return *now})
 if err!=nil{t.Fatal(err)}
 d,err:=NewDispatcher(manager,j,transport,DefaultDeliveryConfig(),func()time.Time{return *now})
 if err!=nil{t.Fatal(err)}
 incident,err:=manager.Get(incidentID)
 if err!=nil{t.Fatal(err)}
 deliveryID,err:=audit.NewID()
 if err!=nil{t.Fatal(err)}
 queued:=Delivery{ID:deliveryID,IncidentID:incidentID,IncidentRevision:incident.Revision,Status:DeliveryQueued}
 if err:=d.persist(incident,queued,"queued",*now);err!=nil{t.Fatal(err)}
 attempted:=queued
 attempted.Attempts=1
 attempted.LastAttemptAt=now.Format(time.RFC3339Nano)
 // Crash between recorded dispatch intent and terminal result.
 if err:=d.persist(incident,attempted,"attempted",*now);err!=nil{t.Fatal(err)}
 reopened:=reopenForDelivery(t,j,jdir,cdir,key,witness,id)
 _,restored,err:=RestoreDispatcher(reopened,10,transport,DefaultDeliveryConfig(),func()time.Time{return *now})
 if err!=nil{t.Fatal(err)}
 state,err:=restored.Get(incidentID)
 if err!=nil||state.Status!=DeliveryUncertain||state.Attempts!=1||state.ID!=deliveryID{
  t.Fatal("uncertain attempt forgotten",err)
 }
 if _,err:=restored.Notify(context.Background(),incidentID);!errors.Is(err,ErrDeliveryUncertain){t.Fatal("uncertain send retried",err)}
 if transport.count()!=0{t.Fatal("transport invoked during recovery")}
 if err:=reopened.Close();err!=nil{t.Fatal(err)}
}

func TestRestoreRejectsTamperedDeliveryStateMachine(t *testing.T){
 for _,mutation:=range []struct{
  name string
  phase string
  attempts int
  extra func(*audit.Event)
 }{
  {"outcome_without_queue","accepted",1,nil},
  {"attempt_without_queue","attempted",1,nil},
  {"unsafe_extra_metadata","queued",0,func(e *audit.Event){e.Name="unwanted-name"}},
  {"wrong_channel","queued",0,func(e *audit.Event){e.DeliveryChannel="unknown"}},
  {"invalid_attempt","queued",1,nil},
 } {
  t.Run(mutation.name,func(t *testing.T){
   j,jdir,cdir,key,witness,id,now,incidentID,transport:=restoreDeliveryFixture(t,false)
   m,err:=RestoreIncidentManager(j,10,func()time.Time{return *now})
   if err!=nil{t.Fatal(err)}
   in,err:=m.Get(incidentID)
   if err!=nil{t.Fatal(err)}
   deliveryID,err:=audit.NewID()
   if err!=nil{t.Fatal(err)}
   attemptID,err:=audit.NewID()
   if err!=nil{t.Fatal(err)}
   ev:=audit.Event{
    Schema:"kgaga.vault.audit.v1",Timestamp:now.Format(time.RFC3339Nano),
    AttemptID:attemptID,Action:"sentinel_delivery",Actor:"sentinel",
    Phase:mutation.phase,VaultID:in.Alert.VaultID,
    AgentID:in.Alert.AgentID,Owner:in.Alert.Owner,Audience:in.Alert.Audience,
    IncidentID:in.ID,IncidentRevision:in.Revision,IncidentSignal:in.Alert.Signal,
    IncidentState:in.State,DeliveryID:deliveryID,DeliveryPhase:mutation.phase,
    DeliveryAttempt:mutation.attempts,DeliveryChannel:DeliveryChannel,
   }
   if mutation.extra!=nil{mutation.extra(&ev)}
   if _,err:=j.Append(ev);err!=nil{t.Fatal(err)}
   reopened:=reopenForDelivery(t,j,jdir,cdir,key,witness,id)
   if _,_,err:=RestoreDispatcher(reopened,10,transport,DefaultDeliveryConfig(),func()time.Time{return *now});!errors.Is(err,ErrDeliveryStorage){
    t.Fatal("malformed authenticated history accepted",err)
   }
   // Recovery failure does not emit a transport request.
   if transport.count()!=0{t.Fatal("transport invoked on corrupted history")}
  })
 }
}

func TestRestoreDeliveryPolicyRejectsUnsupportedConfig(t *testing.T){
 j,_,_,_,_,_,clock,_,transport:=restoreDeliveryFixture(t,false)
 cfg:=DefaultDeliveryConfig()
 cfg.MaxAttempts=0
 if _,_,err:=RestoreDispatcher(j,10,transport,cfg,func()time.Time{return *clock});!errors.Is(err,ErrDeliveryConfig){t.Fatal("unsafe retry policy accepted")}
}
