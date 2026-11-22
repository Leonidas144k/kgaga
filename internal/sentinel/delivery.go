package sentinel

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/Leonidas144k/kgaga/internal/audit"
)

const DeliverySchema = "kgaga.sentinel.delivery.v1"
const DeliveryChannel = "operator-configured"

const (
	DeliveryQueued = "queued"
	DeliveryFailed = "failed"
	DeliveryAccepted = "accepted"
)

var (
	ErrDeliveryConfig = errors.New("sentinel delivery configuration invalid")
	ErrDeliveryStorage = errors.New("sentinel delivery journal unavailable")
	ErrDeliveryTransport = errors.New("sentinel notification transport did not confirm acceptance")
	ErrDeliveryLimit = errors.New("sentinel delivery retry limit reached")
	ErrDeliveryRetry = errors.New("sentinel delivery retry not yet permitted")
	ErrDeliveryIncident = errors.New("sentinel incident is not eligible for delivery")
)

type DeliveryConfig struct {
	MaxAttempts int
	RetryInterval time.Duration
	SendTimeout time.Duration
	MaxPending int
}
func DefaultDeliveryConfig()DeliveryConfig{
	return DeliveryConfig{MaxAttempts:3,RetryInterval:time.Second,SendTimeout:5*time.Second,MaxPending:256}
}

// Notice is an intentionally narrow, advisory-only transport envelope.
// A stable delivery_id lets an operator-controlled adapter ask its provider
// to deduplicate ambiguous retries. Kgaga does not enforce remote idempotency.
type Notice struct {
	Schema string `json:"schema"`
	DeliveryID string `json:"delivery_id"`
	IncidentID string `json:"incident_id"`
	IncidentRevision uint64 `json:"incident_revision"`
	Signal string `json:"signal"`
	Severity string `json:"severity"`
	VaultID string `json:"vault_id"`
	AgentID string `json:"agent_id"`
	Audience string `json:"audience"`
	Count int `json:"count"`
	Advisory bool `json:"advisory"`
}

// Transport is supplied by trusted operator code. Success means the adapter
// reports acceptance only; NOT successful human acknowledgement or delivery.
// Adapters must respect the context deadline and idempotency key.
type Transport interface{ Send(context.Context,Notice)error }

type Delivery struct{
	ID string
	IncidentID string
	IncidentRevision uint64
	Status string
	Attempts int
	LastAttemptAt string
	NextRetryAt string
}

// Dispatcher writes intent before calling the adapter and a sanitized result
// after it returns. It only supports explicit/manual synchronous attempts.
// It does not persist its queue across restart or run a background worker.
type Dispatcher struct{
	mu sync.Mutex
	incidents *IncidentManager
	sink IncidentLedger
	transport Transport
	cfg DeliveryConfig
	clock func()time.Time
	last time.Time
	deliveries map[string]*Delivery
	failed bool
}

func NewDispatcher(incidents *IncidentManager,sink IncidentLedger,transport Transport,cfg DeliveryConfig,clock func()time.Time)(*Dispatcher,error){
	if incidents==nil || sink==nil || transport==nil ||
		cfg.MaxAttempts<1 || cfg.MaxAttempts>5 ||
		cfg.RetryInterval<time.Second || cfg.RetryInterval>time.Hour ||
		cfg.SendTimeout<time.Second || cfg.SendTimeout>10*time.Second ||
		cfg.MaxPending<1 || cfg.MaxPending>4096{return nil,ErrDeliveryConfig}
	if _,err:=sink.Head();err!=nil{return nil,ErrDeliveryStorage}
	if clock==nil{clock=time.Now}
	return &Dispatcher{incidents:incidents,sink:sink,transport:transport,cfg:cfg,clock:clock,deliveries:make(map[string]*Delivery)},nil
}

func(d *Dispatcher)persist(in Incident, delivery Delivery, phase string, now time.Time)error{
	attempt,err:=audit.NewID()
	if err!=nil {d.failed=true;return ErrDeliveryStorage}
	e:=audit.Event{
		Schema:"kgaga.vault.audit.v1",
		Timestamp:now.Format(time.RFC3339Nano),
		AttemptID:attempt,Action:"sentinel_delivery",Phase:phase,
		Actor:"sentinel",VaultID:in.Alert.VaultID,
		AgentID:in.Alert.AgentID,Owner:in.Alert.Owner,Audience:in.Alert.Audience,
		IncidentID:in.ID,IncidentRevision:delivery.IncidentRevision,
		IncidentSignal:in.Alert.Signal,IncidentState:in.State,
		DeliveryID:delivery.ID,DeliveryPhase:phase,
		DeliveryAttempt:delivery.Attempts,DeliveryChannel:DeliveryChannel,
	}
	if _,err:=d.sink.Append(e);err!=nil{d.failed=true;return ErrDeliveryStorage}
	return nil
}

// Notify returns the existing result if transport accepted previously.
// Failures permit a new manual attempt after RetryInterval (at most
// MaxAttempts). A ledger error latches the dispatcher and forbids retries.
// The original alert and transport errors never appear in journal entries.
func(d *Dispatcher)Notify(ctx context.Context,incidentID string)(Delivery,error){
	if d==nil || ctx==nil{return Delivery{},ErrDeliveryConfig}
	if err:=ctx.Err();err!=nil{return Delivery{},err}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failed{return Delivery{},ErrDeliveryStorage}
	now:=d.clock().UTC()
	if err:=incidentClock(now,d.last);err!=nil{return Delivery{},err}
	in,err:=d.incidents.Get(incidentID)
	if err!=nil{return Delivery{},err}
	if in.State==IncidentResolved{return Delivery{},ErrDeliveryIncident}
	item:=d.deliveries[incidentID]
	if item==nil{
		if len(d.deliveries)>=d.cfg.MaxPending{return Delivery{},ErrCapacity}
		id,e:=audit.NewID()
		if e!=nil{d.failed=true;return Delivery{},ErrDeliveryStorage}
		pending:=Delivery{ID:id,IncidentID:incidentID,IncidentRevision:in.Revision,Status:DeliveryQueued}
		if err:=d.persist(in,pending,"queued",now);err!=nil{return Delivery{},err}
		item=&pending
		d.deliveries[incidentID]=item
	}
	if item.Status==DeliveryAccepted{return *item,nil}
	if item.Attempts>=d.cfg.MaxAttempts{return *item,ErrDeliveryLimit}
	if item.NextRetryAt!="" {
		until,e:=time.Parse(time.RFC3339Nano,item.NextRetryAt)
		if e!=nil{d.failed=true;return Delivery{},ErrDeliveryStorage}
		if now.Before(until){return *item,ErrDeliveryRetry}
	}
	// Even if the transport later reports success, an aborted or ambiguous
	// ledger result will stop the dispatcher; no blind retry can occur.
	if err:=ctx.Err();err!=nil{return *item,err}
	next:=*item
	next.Attempts++
	next.LastAttemptAt=now.Format(time.RFC3339Nano)
	if err:=d.persist(in,next,"attempted",now);err!=nil{return Delivery{},err}
	*item=next
	note:=Notice{
		Schema:DeliverySchema,DeliveryID:item.ID,IncidentID:item.IncidentID,
		IncidentRevision:item.IncidentRevision,
		Signal:in.Alert.Signal,Severity:in.Alert.Severity,
		VaultID:in.Alert.VaultID,AgentID:in.Alert.AgentID,
		Audience:in.Alert.Audience,Count:in.Alert.Count,Advisory:true,
	}
	deadlineCtx,cancel:=context.WithTimeout(ctx,d.cfg.SendTimeout)
	sendErr:=d.transport.Send(deadlineCtx,note)
	if deadlineCtx.Err()!=nil{sendErr=deadlineCtx.Err()}
	cancel()
	outcome:=*item
	outcome.NextRetryAt=""
	resultPhase:="accepted"
	if sendErr!=nil{
		outcome.Status=DeliveryFailed
		outcome.NextRetryAt=now.Add(d.cfg.RetryInterval).Format(time.RFC3339Nano)
		resultPhase="failed"
	}else{
		outcome.Status=DeliveryAccepted
	}
	if err:=d.persist(in,outcome,resultPhase,now);err!=nil{return Delivery{},err}
	*item=outcome
	d.last=now
	if sendErr!=nil{return *item,ErrDeliveryTransport}
	return *item,nil
}

func(d *Dispatcher)Get(incidentID string)(Delivery,error){
	if d==nil{return Delivery{},ErrDeliveryConfig}
	d.mu.Lock();defer d.mu.Unlock()
	if d.failed{return Delivery{},ErrDeliveryStorage}
	item:=d.deliveries[incidentID]
	if item==nil{return Delivery{},ErrIncidentNotFound}
	return *item,nil
}
