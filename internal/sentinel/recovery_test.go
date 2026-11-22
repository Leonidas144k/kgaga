package sentinel

import (
 "errors"
 "os"
 "path/filepath"
 "testing"
 "time"

 "github.com/Leonidas144k/kgaga/internal/audit"
 "github.com/Leonidas144k/kgaga/internal/ledger"
)

func recoveryFixture(t *testing.T) (*ledger.AnchoredJournal,string,string,ledger.Key,ledger.Key,ledger.StreamID,time.Time){
 t.Helper()
 root:=t.TempDir()
 if err:=os.Chmod(root,0700);err!=nil{t.Fatal(err)}
 private:=filepath.Join(root,"private")
 if err:=os.Mkdir(private,0700);err!=nil{t.Fatal(err)}
 key,err:=ledger.GenerateKey();if err!=nil{t.Fatal(err)}
 witness,err:=ledger.GenerateKey();if err!=nil{t.Fatal(err)}
 id,err:=ledger.GenerateStreamID();if err!=nil{t.Fatal(err)}
 jdir,cdir:=filepath.Join(private,"journal"),filepath.Join(private,"checkpoint")
 j,err:=ledger.InitAnchoredJournal(jdir,cdir,key,witness,id)
 if err!=nil{t.Fatal(err)}
 return j,jdir,cdir,key,witness,id,time.Now().UTC().Truncate(time.Second)
}

func TestRestoreIncidentManagerAfterVerifiedRestart(t *testing.T){
 j,jdir,cdir,key,witness,id,now:=recoveryFixture(t)
 manager,err:=NewIncidentManager(j,10,func()time.Time{return now})
 if err!=nil{t.Fatal(err)}
 opened,err:=manager.Open(incidentAlert(now));if err!=nil{t.Fatal(err)}
 now=now.Add(3*time.Hour)
 ack,err:=manager.Acknowledge(opened.ID,"trusted-operator",1)
 if err!=nil||ack.Revision!=2{t.Fatal("late acknowledgement failed",err)}
 expected,err:=j.Head();if err!=nil{t.Fatal(err)}
 if err:=j.Close();err!=nil{t.Fatal(err)}
 reopened,err:=ledger.OpenAnchoredJournal(jdir,cdir,key,witness,id,expected)
 if err!=nil{t.Fatal(err)}
 recovered,err:=RestoreIncidentManager(reopened,10,func()time.Time{return now})
 if err!=nil{t.Fatal("verified restoration failed",err)}
 got,err:=recovered.Get(opened.ID)
 if err!=nil||got.Revision!=2||got.State!=IncidentAcknowledged||got.AcknowledgedBy!="trusted-operator"{
  t.Fatal("incident state or ownership lost",err)
 }
 again,err:=recovered.Open(incidentAlert(now))
 if err!=nil||again.ID!=opened.ID{t.Fatal("duplicate case after restart",err)}
 resolved,err:=recovered.Resolve(opened.ID,"reviewer-two",2,ResolutionInconclusive)
 if err!=nil||resolved.Revision!=3{t.Fatal("resolution after restart failed",err)}
 if err:=reopened.Close();err!=nil{t.Fatal(err)}
}

func TestRestoreRejectsAuthenticatedButInvalidTransitions(t *testing.T){
 for _,mutation:=range []struct{name string; edit func(*audit.Event)}{
  {"orphan_acknowledgement",func(e *audit.Event){e.Phase="acknowledged";e.Actor="local_operator";e.OperatorID="trusted";e.IncidentState=IncidentAcknowledged;e.IncidentRevision=2}},
  {"unknown_resolution",func(e *audit.Event){e.Phase="resolved";e.Actor="local_operator";e.OperatorID="trusted";e.IncidentState=IncidentResolved;e.IncidentRevision=3;e.IncidentResolution=ResolutionConfirmed}},
  {"duplicate_open",func(e *audit.Event){e.IncidentRevision=1}},
  {"bad_revision",func(e *audit.Event){e.IncidentRevision=5}},
  {"untrusted_operator",func(e *audit.Event){e.Phase="acknowledged";e.Actor="local_operator";e.OperatorID="bad\nname";e.IncidentState=IncidentAcknowledged;e.IncidentRevision=2}},
 }{
  t.Run(mutation.name,func(t *testing.T){
   j,_,_,_,_,_,now:=recoveryFixture(t)
   m,err:=NewIncidentManager(j,10,func()time.Time{return now});if err!=nil{t.Fatal(err)}
   opened,err:=m.Open(incidentAlert(now));if err!=nil{t.Fatal(err)}
   e:=audit.Event{Schema:"kgaga.vault.audit.v1",Timestamp:now.Format(time.RFC3339Nano),
    AttemptID:"0123456789abcdef0123456789abcdef",Action:"sentinel_incident",
    Phase:"opened",Actor:"sentinel",VaultID:opened.Alert.VaultID,
    AgentID:opened.Alert.AgentID,Owner:opened.Alert.Owner,
    Audience:opened.Alert.Audience,IncidentID:opened.ID,IncidentSignal:opened.Alert.Signal,
    IncidentState:IncidentOpen,IncidentRevision:1,
    IncidentCount:opened.Alert.Count,IncidentWindowSeconds:opened.Alert.WindowSeconds,
    IncidentObservedAt:opened.Alert.ObservedAt}
   mutation.edit(&e)
   if _,err:=j.Append(e);err!=nil{t.Fatal("synthetic event append",err)}
   if _,err:=RestoreIncidentManager(j,10,func()time.Time{return now});!errors.Is(err,ErrIncidentHistory){
    t.Fatal("invalid authenticated transition accepted",err)
   }
  })
 }
}

func TestRestoreRejectsDuplicateOpenSameSignalAndForeignFields(t *testing.T){
 for _,bad:=range []string{"duplicate","foreign"}{
  t.Run(bad,func(t *testing.T){
   j,_,_,_,_,_,now:=recoveryFixture(t)
   manager,err:=NewIncidentManager(j,10,func()time.Time{return now});if err!=nil{t.Fatal(err)}
   opened,err:=manager.Open(incidentAlert(now));if err!=nil{t.Fatal(err)}
   anotherID,err:=audit.NewID();if err!=nil{t.Fatal(err)}
   e:=audit.Event{Schema:"kgaga.vault.audit.v1",Timestamp:now.Format(time.RFC3339Nano),
    AttemptID:"0123456789abcdef0123456789abcdef",Action:"sentinel_incident",
    Phase:"opened",Actor:"sentinel",VaultID:opened.Alert.VaultID,
    AgentID:opened.Alert.AgentID,Owner:opened.Alert.Owner,
    Audience:opened.Alert.Audience,IncidentID:anotherID,IncidentSignal:opened.Alert.Signal,
    IncidentState:IncidentOpen,IncidentRevision:1,
    IncidentCount:opened.Alert.Count,IncidentWindowSeconds:opened.Alert.WindowSeconds,
    IncidentObservedAt:opened.Alert.ObservedAt}
   if bad=="foreign"{e.AgentID="another-agent";e.Name="unnecessary-secret-name"}
   if _,err:=j.Append(e);err!=nil{t.Fatal(err)}
   if _,err:=RestoreIncidentManager(j,10,func()time.Time{return now});!errors.Is(err,ErrIncidentHistory){
    t.Fatal("invalid history accepted",err)
   }
  })
 }
}

func TestRestoreIncidentManagerBoundedHistory(t *testing.T){
 j,_,_,_,_,_,now:=recoveryFixture(t)
 manager,err:=NewIncidentManager(j,10,func()time.Time{return now});if err!=nil{t.Fatal(err)}
 alert:=incidentAlert(now)
 opened,err:=manager.Open(alert);if err!=nil{t.Fatal(err)}
 _,err=manager.Acknowledge(opened.ID,"operator-a",1);if err!=nil{t.Fatal(err)}
 _,err=manager.Resolve(opened.ID,"operator-b",2,ResolutionBenign);if err!=nil{t.Fatal(err)}
 // Three historical transitions exceed the limit for zero effective
 // capacity only; a real max=1 permits three transitions for one case.
 if _,err:=RestoreIncidentManager(j,1,func()time.Time{return now});err!=nil{t.Fatal(err)}
 if _,err:=RestoreIncidentManager(j,0,func()time.Time{return now});!errors.Is(err,ErrIncident){t.Fatal("unbounded replay admitted")}
}
