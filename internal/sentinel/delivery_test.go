package sentinel

import (
 "context"
 "errors"
 "sync"
 "sync/atomic"
 "testing"
 "time"

 "github.com/Leonidas144k/kgaga/internal/audit"
 "github.com/Leonidas144k/kgaga/internal/ledger"
)

type fakeDeliveryTransport struct{
 mu sync.Mutex
 calls []Notice
 fail bool
 block bool
}
func(t *fakeDeliveryTransport)Send(ctx context.Context,n Notice)error{
 t.mu.Lock()
 t.calls=append(t.calls,n)
 fail,block:=t.fail,t.block
 t.mu.Unlock()
 if block{<-ctx.Done();return ctx.Err()}
 if fail{return errors.New("synthetic transport failure: must not be logged")}
 return nil
}
func(t *fakeDeliveryTransport)count()int{
 t.mu.Lock();defer t.mu.Unlock()
 return len(t.calls)
}
type failDeliverySink struct{
 mu sync.Mutex
 fail bool
 events []audit.Event
}
func(s *failDeliverySink)Append(e audit.Event)(ledger.Head,error){
 s.mu.Lock();defer s.mu.Unlock()
 if s.fail{return ledger.Head{},errors.New("synthetic persistence failure")}
 s.events=append(s.events,e)
 return ledger.Head{Sequence:uint64(len(s.events))},nil
}
func(s *failDeliverySink)Head()(ledger.Head,error){return ledger.Head{},nil}
func(s *failDeliverySink)list()[]audit.Event {
 s.mu.Lock();defer s.mu.Unlock()
 return append([]audit.Event(nil),s.events...)
}
func newDeliveryFixture(t *testing.T)(*Dispatcher,*IncidentManager,*fakeDeliveryTransport,*failDeliverySink,*time.Time,string){
 t.Helper()
 now:=time.Date(2026,11,22,12,0,0,0,time.UTC)
 sink:=&failDeliverySink{}
 manager,err:=NewIncidentManager(sink,10,func()time.Time{return now})
 if err!=nil{t.Fatal(err)}
 opened,err:=manager.Open(incidentAlert(now))
 if err!=nil{t.Fatal(err)}
 transport:=&fakeDeliveryTransport{}
 d,err:=NewDispatcher(manager,sink,transport,DefaultDeliveryConfig(),func()time.Time{return now})
 if err!=nil{t.Fatal(err)}
 return d,manager,transport,sink,&now,opened.ID
}

func TestDeliveryAcceptedOnceAndSanitized(t *testing.T){
 d,_,transport,sink,_,id:=newDeliveryFixture(t)
 got,err:=d.Notify(context.Background(),id)
 if err!=nil||got.Status!=DeliveryAccepted||got.Attempts!=1||transport.count()!=1{t.Fatal("delivery not accepted",err)}
 again,err:=d.Notify(context.Background(),id)
 if err!=nil||again!=got||transport.count()!=1{t.Fatal("accepted delivery resent",err)}
 events:=sink.list()
 if len(events)!=4{t.Fatalf("expected incident open, queue, attempt and outcome: got %d",len(events))}
 for _,e:=range events[1:]{
  if e.Action!="sentinel_delivery"||e.DeliveryID!=got.ID||
   e.DeliveryChannel!=DeliveryChannel||e.Name!=""||e.PassportID!=""||e.Target!=""||e.Provider!=""||
   e.DeliveryAttempt<0{t.Fatal("unsafe delivery metadata")}
 }
 transport.mu.Lock()
 note:=transport.calls[0]
 transport.mu.Unlock()
 if note.Schema!=DeliverySchema||note.DeliveryID!=got.ID||!note.Advisory||note.AgentID!="agent-1" {t.Fatal("invalid sanitized notice")}
}

func TestDeliveryRetryCooldownAndBound(t *testing.T){
 d,_,transport,_,now,id:=newDeliveryFixture(t)
 transport.fail=true
 for attempt:=1;attempt<=3;attempt++{
  got,err:=d.Notify(context.Background(),id)
  if !errors.Is(err,ErrDeliveryTransport)||got.Status!=DeliveryFailed||got.Attempts!=attempt{t.Fatal("retry state",err)}
  if _,err:=d.Notify(context.Background(),id);!errors.Is(err,ErrDeliveryRetry)&&attempt<3{t.Fatal("cooldown not enforced",err)}
  *now=now.Add(time.Second)
 }
 if _,err:=d.Notify(context.Background(),id);!errors.Is(err,ErrDeliveryLimit){t.Fatal("retry limit bypassed",err)}
 if transport.count()!=3{t.Fatal("wrong number of sends")}
 transport.mu.Lock()
 first:=transport.calls[0].DeliveryID
 for _,n:=range transport.calls{if n.DeliveryID!=first{t.Fatal("unstable deduplication identifier")}}
 transport.mu.Unlock()
}

func TestDeliveryStorageFailureLatchesWithoutTransport(t *testing.T){
 d,_,transport,sink,_,id:=newDeliveryFixture(t)
 sink.mu.Lock();sink.fail=true;sink.mu.Unlock()
 if _,err:=d.Notify(context.Background(),id);!errors.Is(err,ErrDeliveryStorage){t.Fatal("failed sink admitted dispatch",err)}
 sink.mu.Lock();sink.fail=false;sink.mu.Unlock()
 if _,err:=d.Notify(context.Background(),id);!errors.Is(err,ErrDeliveryStorage){t.Fatal("dispatcher resumed")}
 if transport.count()!=0{t.Fatal("sent without durable intent")}
}

func TestDeliveryOutcomeFailureLatches(t *testing.T){
 d,_,transport,sink,_,id:=newDeliveryFixture(t)
 transport.mu.Lock();transport.fail=true;transport.mu.Unlock()
 // This intentionally tests a failed transport with durable outcome:
 // it permits a bounded retry, but no automatic background sending.
 if _,err:=d.Notify(context.Background(),id);!errors.Is(err,ErrDeliveryTransport){t.Fatal(err)}
 sink.mu.Lock();sink.fail=true;sink.mu.Unlock()
 // Move clock through the operator-configured cooldown.
 d.clock=func()time.Time{return time.Date(2026,11,22,12,0,2,0,time.UTC)}
 if _,err:=d.Notify(context.Background(),id);!errors.Is(err,ErrDeliveryStorage){t.Fatal("ambiguous subsequent write allowed",err)}
 if transport.count()!=1{t.Fatal("sent without recorded retry intent")}
}

func TestDeliveryCancellationAndIncidentResolution(t *testing.T){
 d,m,transport,_,_,id:=newDeliveryFixture(t)
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 if _,err:=d.Notify(ctx,id);!errors.Is(err,context.Canceled){t.Fatal("canceled delivery accepted")}
 if transport.count()!=0{t.Fatal("canceled request sent")}
 ack,err:=m.Acknowledge(id,"reviewer",1);if err!=nil{t.Fatal(err)}
 if _,err:=m.Resolve(id,"reviewer",ack.Revision,ResolutionBenign);err!=nil{t.Fatal(err)}
 if _,err:=d.Notify(context.Background(),id);!errors.Is(err,ErrDeliveryIncident){t.Fatal("resolved incident sent")}
}

func TestDeliveryDeadlineAndConcurrentAttempt(t *testing.T){
 d,_,transport,_,now,id:=newDeliveryFixture(t)
 transport.block=true
 d.cfg.SendTimeout=time.Second
 var got atomic.Int32
 var wg sync.WaitGroup
 for i:=0;i<10;i++{
  wg.Add(1)
  go func(){
   defer wg.Done()
   _,err:=d.Notify(context.Background(),id)
   if errors.Is(err,ErrDeliveryTransport){got.Add(1)}else if !errors.Is(err,ErrDeliveryRetry){t.Errorf("unexpected concurrent outcome: %v",err)}
  }()
 }
 wg.Wait()
 if transport.count()!=1||got.Load()!=1{t.Fatal("concurrent duplicate transport send")}
 *now=now.Add(time.Second)
}

func TestDeliveryRejectsUnsafeConfig(t *testing.T){
 d,m,transport,sink,_,_:=newDeliveryFixture(t)
 _=d
 cfg:=DefaultDeliveryConfig()
 cfg.MaxAttempts=0
 if _,err:=NewDispatcher(m,sink,transport,cfg,nil);!errors.Is(err,ErrDeliveryConfig){t.Fatal("unbounded retry config accepted")}
 if _,err:=NewDispatcher(m,sink,nil,DefaultDeliveryConfig(),nil);!errors.Is(err,ErrDeliveryConfig){t.Fatal("missing transport accepted")}
}
