package sentinel

import(
 "errors"
 "os"
 "path/filepath"
 "strings"
 "sync"
 "sync/atomic"
 "testing"
 "time"

 "github.com/Leonidas144k/kgaga/internal/audit"
 "github.com/Leonidas144k/kgaga/internal/ledger"
)

type incidentSink struct{
 mu sync.Mutex
 entries []audit.Event
 fail bool
}
func(s *incidentSink)Append(e audit.Event)(ledger.Head,error){
 s.mu.Lock();defer s.mu.Unlock()
 if s.fail{return ledger.Head{},errors.New("synthetic write failure")}
 s.entries=append(s.entries,e)
 return ledger.Head{Sequence:uint64(len(s.entries))},nil
}
func(s *incidentSink)Head()(ledger.Head,error){return ledger.Head{},nil}
func incidentAlert(now time.Time)Alert{
 return Alert{
  Schema:AlertSchema,ObservedAt:now.UTC().Format(time.RFC3339Nano),
  Signal:DenialBurst,Severity:"warning",VaultID:"test-vault",
  AgentID:"agent-1",Owner:"ops@example.com",Audience:"api",
  Count:5,WindowSeconds:300,Advisory:true,
 }
}
func TestIncidentLifecycleAndRevision(t *testing.T){
 now:=time.Date(2026,11,22,12,0,0,0,time.UTC)
 s:=&incidentSink{}
 manager,err:=NewIncidentManager(s,10,func()time.Time{return now})
 if err!=nil{t.Fatal(err)}
 alert:=incidentAlert(now)
 opened,err:=manager.Open(alert)
 if err!=nil || opened.State!=IncidentOpen || opened.Revision!=1{t.Fatal("opening failed",err)}
 same,err:=manager.Open(alert)
 if err!=nil || same.ID!=opened.ID {t.Fatal("duplicate active incident created",err)}
 if _,err:=manager.Resolve(opened.ID,"operator-1",1,ResolutionBenign);!errors.Is(err,ErrIncidentConflict){t.Fatal("direct resolution accepted")}
 if _,err:=manager.Acknowledge(opened.ID,"",1);!errors.Is(err,ErrIncident){t.Fatal("unauthenticated id accepted")}
 ack,err:=manager.Acknowledge(opened.ID,"operator-1",1)
 if err!=nil||ack.State!=IncidentAcknowledged||ack.Revision!=2||ack.AcknowledgedBy!="operator-1"{t.Fatal("ack failed",err)}
 if _,err:=manager.Acknowledge(opened.ID,"operator-1",1);!errors.Is(err,ErrIncidentConflict){t.Fatal("stale revision accepted")}
 if _,err:=manager.Resolve(opened.ID,"operator-2",2,"other");!errors.Is(err,ErrIncidentConflict){t.Fatal("unapproved resolution accepted")}
 res,err:=manager.Resolve(opened.ID,"operator-2",2,ResolutionConfirmed)
 if err!=nil||res.State!=IncidentResolved||res.Revision!=3||res.ResolvedBy!="operator-2"{t.Fatal("resolution failed",err)}
 if _,err:=manager.Resolve(opened.ID,"operator-2",3,ResolutionConfirmed);!errors.Is(err,ErrIncidentConflict){t.Fatal("double resolution accepted")}
 reopened,err:=manager.Open(alert)
 if err!=nil||reopened.ID==opened.ID{t.Fatal("resolved incident blocked future case",err)}
 if len(s.entries)!=4 {t.Fatal("unexpected transition count",len(s.entries))}
 for i,e:=range s.entries {
  if e.Schema!="kgaga.vault.audit.v1" || e.Action!="sentinel_incident" || e.IncidentID=="" || e.IncidentRevision==0 ||
   e.VaultID!="test-vault" || e.IncidentSignal!=DenialBurst || len(e.AttemptID)!=32{
    t.Fatalf("bad ledger event %d",i)
  }
 }
 for _,phase:=range []string{"opened","acknowledged","resolved","opened"}{
  matched:=false
  for _,event:=range s.entries{if event.Phase==phase{matched=true}}
  if !matched{t.Fatalf("missing %s event",phase)}
 }
}

func TestIncidentFailureLatchedWithoutStateMutation(t *testing.T){
 now:=time.Date(2026,11,22,12,0,0,0,time.UTC)
 sink:=&incidentSink{}
 m,err:=NewIncidentManager(sink,5,func()time.Time{return now})
 if err!=nil{t.Fatal(err)}
 a:=incidentAlert(now)
 opened,err:=m.Open(a);if err!=nil{t.Fatal(err)}
 sink.fail=true
 if _,err:=m.Acknowledge(opened.ID,"trusted-operator",1);!errors.Is(err,ErrIncidentStorage){t.Fatal("failed sink allowed ack")}
 sink.fail=false
 if _,err:=m.Get(opened.ID);!errors.Is(err,ErrIncidentStorage){t.Fatal("failed manager resumed")}
 if _,err:=m.Open(a);!errors.Is(err,ErrIncidentStorage){t.Fatal("failed manager admitted new incident")}
 if len(sink.entries)!=1 || sink.entries[0].IncidentState!=IncidentOpen{t.Fatal("state advanced despite failure")}
}

func TestIncidentBoundsAndOperatorValidation(t *testing.T){
 now:=time.Date(2026,11,22,12,0,0,0,time.UTC)
 sink:=&incidentSink{}
 m,err:=NewIncidentManager(sink,1,func()time.Time{return now});if err!=nil{t.Fatal(err)}
 alert:=incidentAlert(now)
 if _,err:=m.Open(Alert{});!errors.Is(err,ErrIncident){t.Fatal("untrusted alert accepted")}
 opened,err:=m.Open(alert);if err!=nil{t.Fatal(err)}
 other:=alert;other.AgentID="other-agent"
 if _,err:=m.Open(other);!errors.Is(err,ErrCapacity){t.Fatal("capacity not enforced")}
 if _,err:=m.Acknowledge(opened.ID,"bad\noperator",1);!errors.Is(err,ErrIncident){t.Fatal("unsafe operator identifier accepted")}
 if _,err:=m.Acknowledge("missing","operator",1);!errors.Is(err,ErrIncidentNotFound){t.Fatal("missing incident accepted")}
 if _,err:=m.Acknowledge(opened.ID,strings.Repeat("x",129),1);!errors.Is(err,ErrIncident){t.Fatal("oversized operator accepted")}
 now=now.Add(-time.Second)
 if _,err:=m.Acknowledge(opened.ID,"operator",1);!errors.Is(err,ErrClock){t.Fatal("clock rollback accepted")}
 if _,err:=NewIncidentManager(nil,1,nil);!errors.Is(err,ErrIncident){t.Fatal("nil sink accepted")}
}

func TestIncidentConcurrentRevisionLock(t *testing.T){
 now:=time.Date(2026,11,22,12,0,0,0,time.UTC)
 m,err:=NewIncidentManager(&incidentSink{},10,func()time.Time{return now});if err!=nil{t.Fatal(err)}
 opened,err:=m.Open(incidentAlert(now));if err!=nil{t.Fatal(err)}
 var success atomic.Int32
 var wg sync.WaitGroup
 for i:=0;i<20;i++{
  wg.Add(1)
  go func(){defer wg.Done()
   _,e:=m.Acknowledge(opened.ID,"reviewer",1)
   if e==nil{success.Add(1)}else if !errors.Is(e,ErrIncidentConflict){t.Error(e)}
  }()
 }
 wg.Wait()
 if success.Load()!=1{t.Fatal("concurrent duplicate acknowledgement")}
}

func TestIncidentWithRealAnchoredLedger(t *testing.T){
 now:=time.Now().UTC().Truncate(time.Second)
 root:=t.TempDir()
 if err:=os.Chmod(root,0700);err!=nil{t.Fatal(err)}
 parent:=filepath.Join(root,"private")
 if err:=os.Mkdir(parent,0700);err!=nil{t.Fatal(err)}
 key,err:=ledger.GenerateKey();if err!=nil{t.Fatal(err)}
 witness,err:=ledger.GenerateKey();if err!=nil{t.Fatal(err)}
 id,err:=ledger.GenerateStreamID();if err!=nil{t.Fatal(err)}
 jdir,wdir:=filepath.Join(parent,"journal"),filepath.Join(parent,"checkpoint")
 anchored,err:=ledger.InitAnchoredJournal(jdir,wdir,key,witness,id)
 if err!=nil{t.Fatal(err)}
 m,err:=NewIncidentManager(anchored,10,func()time.Time{return now})
 if err!=nil{t.Fatal(err)}
 opened,err:=m.Open(incidentAlert(now))
 if err!=nil{t.Fatal(err)}
 ack,err:=m.Acknowledge(opened.ID,"operator-a",1)
 if err!=nil||ack.Revision!=2{t.Fatal("ack not persisted",err)}
 resolved,err:=m.Resolve(opened.ID,"operator-b",2,ResolutionInconclusive)
 if err!=nil||resolved.Revision!=3{t.Fatal("resolve not persisted",err)}
 expected,err:=anchored.Head()
 if err!=nil||expected.Sequence!=3{t.Fatal("missing checkpoint evidence",err)}
 if err:=anchored.Close();err!=nil{t.Fatal(err)}
 again,err:=ledger.OpenAnchoredJournal(jdir,wdir,key,witness,id,expected)
 if err!=nil{t.Fatal("checkpoint rejected incident records",err)}
 if err:=again.Close();err!=nil{t.Fatal(err)}
}
