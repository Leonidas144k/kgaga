package sentinel

import(
 "encoding/json"
 "errors"
 "fmt"
 "strings"
 "sync"
 "sync/atomic"
 "testing"
 "time"

 "github.com/Leonidas144k/kgaga/internal/audit"
)

func testEvent(t time.Time,n int,phase string)audit.Event{
 return audit.Event{
  Schema:"kgaga.vault.audit.v1",Timestamp:t.UTC().Format(time.RFC3339Nano),
  AttemptID:fmt.Sprintf("%032x",n),Action:"credential_use",Phase:phase,
  Actor:"agent",AgentID:"agent-one",Owner:"operator@example.com",
  Audience:"api",VaultID:"synthetic-vault",
 }
}
func testEngine(t *testing.T,at *time.Time,cfg Config)*Engine{
 t.Helper()
 e,err:=NewEngine(cfg,func()time.Time{return *at})
 if err!=nil{t.Fatal(err)}
 return e
}

func TestDenialBurstSuppressionAndRearming(t *testing.T){
 now:=time.Date(2026,11,22,12,0,0,0,time.UTC)
 e:=testEngine(t,&now,DefaultConfig())
 for i:=1;i<=6;i++{
  alert,err:=e.Observe(testEvent(now,i,"denied"))
  if err!=nil{t.Fatal(err)}
  if (i==5)!=(alert!=nil){t.Fatalf("alert at wrong threshold %d",i)}
  if alert!=nil && (alert.Signal!=DenialBurst || !alert.Advisory || alert.Count!=5 || alert.WindowSeconds!=300){t.Fatal("bad alert")}
 }
 now=now.Add(5*time.Minute)
 for i:=10;i<=14;i++{
  alert,err:=e.Observe(testEvent(now,i,"denied_before_dispatch"))
  if err!=nil{t.Fatal(err)}
  if (i==14)!=(alert!=nil){t.Fatal("did not rearm after window expiry")}
 }
}

func TestDeduplicateAndIndependentSignals(t *testing.T){
 now:=time.Date(2026,11,22,12,0,0,0,time.UTC)
 cfg:=DefaultConfig();cfg.DenialThreshold=2;cfg.ExchangeFailureThreshold=2;cfg.WithheldThreshold=2
 e:=testEngine(t,&now,cfg)
 first:=testEvent(now,1,"denied")
 for _,phase:=range []string{"attempt","denied","denied_before_dispatch","response_withheld","denied"}{
  v:=first;v.Phase=phase
  if alert,err:=e.Observe(v);err!=nil||alert!=nil{t.Fatal("attempt counted repeatedly",err)}
 }
 if a,err:=e.Observe(testEvent(now,2,"denied"));err!=nil||a==nil||a.Signal!=DenialBurst{t.Fatal("dedup suppressed legitimate denial threshold",err)}
 if a,err:=e.Observe(testEvent(now,3,"credential_unavailable"));err!=nil||a!=nil{t.Fatal(err)}
 if a,err:=e.Observe(testEvent(now,4,"exchange_failed_or_rejected"));err!=nil||a==nil||a.Signal!=ExchangeFailureBurst{t.Fatal("missing exchange alert",err)}
 if a,err:=e.Observe(testEvent(now,5,"response_withheld"));err!=nil||a!=nil{t.Fatal(err)}
 if a,err:=e.Observe(testEvent(now,6,"response_withheld"));err!=nil||a==nil||a.Signal!=ResponseWithheldBurst||a.Severity!="notice"{t.Fatal("missing advisory withholding alert",err)}
}

func TestIsolationAndCapacity(t *testing.T){
 now:=time.Date(2026,11,22,12,0,0,0,time.UTC)
 cfg:=DefaultConfig();cfg.Window=time.Minute;cfg.MaxIdentities=1;cfg.MaxFailuresPerIdentity=2
 cfg.DenialThreshold=2;cfg.ExchangeFailureThreshold=2;cfg.WithheldThreshold=2
 e:=testEngine(t,&now,cfg)
 if _,err:=e.Observe(testEvent(now,1,"denied"));err!=nil{t.Fatal(err)}
 other:=testEvent(now,2,"denied");other.Owner="another@example.com"
 if _,err:=e.Observe(other);!errors.Is(err,ErrCapacity){t.Fatal("cross-owner identity incorrectly merged")}
 if a,err:=e.Observe(testEvent(now,3,"denied"));err!=nil||a==nil{t.Fatal("wrong capacity behavior",err)}
 if _,err:=e.Observe(testEvent(now,4,"denied"));!errors.Is(err,ErrCapacity){t.Fatal("per-identity capacity not enforced")}
 now=now.Add(time.Minute)
 other.Timestamp=now.Format(time.RFC3339Nano)
 if a,err:=e.Observe(other);err!=nil||a!=nil{t.Fatal("expired identity not reclaimed",err)}
}

func TestEventValidationAndClock(t *testing.T){
 now:=time.Date(2026,11,22,12,0,0,0,time.UTC)
 e:=testEngine(t,&now,DefaultConfig())
 valid:=testEvent(now,1,"denied")
 for _,mutate:=range []func(*audit.Event){
  func(e *audit.Event){e.Schema="bad"},
  func(e *audit.Event){e.AttemptID="not-hex"},
  func(e *audit.Event){e.Timestamp=now.Add(-2*time.Minute).Format(time.RFC3339Nano)},
  func(e *audit.Event){e.Timestamp=now.Add(2*time.Minute).Format(time.RFC3339Nano)},
  func(e *audit.Event){e.Timestamp=now.In(time.FixedZone("other",3600)).Format(time.RFC3339Nano)},
  func(e *audit.Event){e.Phase="replay_blocked"},
  func(e *audit.Event){e.Owner=""},
  func(e *audit.Event){e.AgentID="bad\nname"},
  func(e *audit.Event){e.Actor="untrusted"},
 }{
  bad:=valid;mutate(&bad)
  if a,err:=e.Observe(bad);a!=nil||!errors.Is(err,ErrEvent){t.Fatal("malformed event accepted",err)}
 }
 op:=valid;op.Actor="local_operator";op.Action="vault-activate"
 if a,err:=e.Observe(op);err!=nil||a!=nil{t.Fatal("operator action treated as attack",err)}
 if _,err:=e.Observe(valid);err!=nil{t.Fatal(err)}
 now=now.Add(-time.Second)
 valid.Timestamp=now.Format(time.RFC3339Nano)
 if _,err:=e.Observe(valid);!errors.Is(err,ErrClock){t.Fatal("clock rollback accepted")}
 if _,err:=NewEngine(Config{},nil);!errors.Is(err,ErrConfig){t.Fatal("zero policy accepted")}
 cfg:=DefaultConfig();cfg.DenialThreshold=cfg.MaxFailuresPerIdentity+1
 if _,err:=NewEngine(cfg,nil);!errors.Is(err,ErrConfig){t.Fatal("unreachable threshold accepted")}
}

func TestAlertsExcludeCredentialDetails(t *testing.T){
 now:=time.Date(2026,11,22,12,0,0,0,time.UTC)
 cfg:=DefaultConfig();cfg.DenialThreshold=2
 e:=testEngine(t,&now,cfg)
 for i:=1;i<=2;i++{
  ev:=testEvent(now,i,"denied")
  ev.Name="private-secret-marker"
  ev.PassportID="private-passport-marker"
  ev.Origin="https://private.example"
  ev.Target="/secret"
  ev.Tool="private-tool"
  alert,err:=e.Observe(ev)
  if err!=nil{t.Fatal(err)}
  if alert!=nil{
   b,err:=json.Marshal(alert);if err!=nil{t.Fatal(err)}
   for _,secret:=range []string{"private-secret-marker","private-passport-marker","private.example","private-tool","/secret"} {
    if strings.Contains(string(b),secret){t.Fatal("unnecessary sensitive field in alert")}
   }
  }
 }
}

func TestConcurrentDistinctFailures(t *testing.T){
 now:=time.Date(2026,11,22,12,0,0,0,time.UTC)
 cfg:=DefaultConfig();cfg.MaxFailuresPerIdentity=128;cfg.DenialThreshold=5
 e:=testEngine(t,&now,cfg)
 var alerts atomic.Int32
 var wg sync.WaitGroup
 for i:=1;i<=64;i++{
  wg.Add(1)
  go func(n int){
   defer wg.Done()
   a,err:=e.Observe(testEvent(now,n,"denied"))
   if err!=nil{t.Error(err);return}
   if a!=nil{alerts.Add(1)}
  }(i)
 }
 wg.Wait()
 if alerts.Load()!=1{t.Fatalf("multiple threshold crossings without decay: %d",alerts.Load())}
}
