package sentinel

import (
 "errors"
 "sync"
 "time"

 "github.com/Leonidas144k/kgaga/internal/audit"
 "github.com/Leonidas144k/kgaga/internal/ledger"
)

const IncidentSchema="kgaga.sentinel.incident.v1"
const (
 IncidentOpen="open"
 IncidentAcknowledged="acknowledged"
 IncidentResolved="resolved"
 ResolutionBenign="benign"
 ResolutionConfirmed="confirmed"
 ResolutionInconclusive="inconclusive"
)

var (
 ErrIncident=errors.New("invalid sentinel incident operation")
 ErrIncidentNotFound=errors.New("sentinel incident not found")
 ErrIncidentConflict=errors.New("sentinel incident revision or state conflict")
 ErrIncidentStorage=errors.New("sentinel incident ledger unavailable")
)

type Incident struct{
 Schema string `json:"schema"`
 ID string `json:"id"`
 State string `json:"state"`
 Revision uint64 `json:"revision"`
 Alert Alert `json:"alert"`
 OpenedAt string `json:"opened_at"`
 UpdatedAt string `json:"updated_at"`
 AcknowledgedBy string `json:"acknowledged_by,omitempty"`
 ResolvedBy string `json:"resolved_by,omitempty"`
 Resolution string `json:"resolution,omitempty"`
}

type incidentKey struct{vault,agent,owner,audience,signal string}

// IncidentLedger accepts a validated audit event and acknowledges it only
// after the underlying protected journal and checkpoint have been written.
// A real ledger.AnchoredJournal satisfies this interface. No fallback sink.
type IncidentLedger interface {
 Append(audit.Event)(ledger.Head,error)
 Head()(ledger.Head,error)
}

// IncidentManager is explicitly programmatic and advisory. A trusted caller
// must authenticate its operators; OperatorID is NOT independently verified.
// It cannot suspend agents, revoke credentials, or change Gateway policy.
type IncidentManager struct{
 mu sync.Mutex
 sink IncidentLedger
 clock func()time.Time
 last time.Time
 max int
 cases map[string]Incident
 active map[incidentKey]string
 failed bool
}

func NewIncidentManager(sink IncidentLedger,max int,clock func()time.Time)(*IncidentManager,error){
 if sink==nil || max<1 || max>4096{return nil,ErrIncident}
 if _,err:=sink.Head();err!=nil{return nil,ErrIncidentStorage}
 if clock==nil{clock=time.Now}
 return &IncidentManager{
  sink:sink,clock:clock,max:max,cases:make(map[string]Incident),
  active:make(map[incidentKey]string),
 },nil
}

func incidentClock(now time.Time,last time.Time)error{
 if now.IsZero() || (!last.IsZero() && now.Before(last)){return ErrClock}
 return nil
}
func validAlert(a Alert,now time.Time)bool{
 if a.Schema!=AlertSchema || !a.Advisory ||
 !metadataOK(a.VaultID)||!metadataOK(a.AgentID)||!metadataOK(a.Owner)||!metadataOK(a.Audience) ||
 a.Count<1||a.Count>512||a.WindowSeconds<1||a.WindowSeconds>86400{return false}
 if a.Signal!=DenialBurst && a.Signal!=ExchangeFailureBurst && a.Signal!=ResponseWithheldBurst{return false}
 if a.Severity!="warning" && a.Severity!="notice"{return false}
 if a.Signal==ResponseWithheldBurst && a.Severity!="notice"{return false}
 if a.Signal!=ResponseWithheldBurst && a.Severity!="warning"{return false}
 t,err:=time.Parse(time.RFC3339Nano,a.ObservedAt)
 return err==nil && t.UTC().Format(time.RFC3339Nano)==a.ObservedAt &&
  !t.Before(now.Add(-time.Minute)) && !t.After(now.Add(time.Minute))
}

func incidentSource(a Alert)incidentKey {
 return incidentKey{a.VaultID,a.AgentID,a.Owner,a.Audience,a.Signal}
}

// persist writes exactly one incident transition to the verified Ledger.
// A failed or ambiguous append permanently disables the manager until a
// controlled restart and recovery from an independently verified checkpoint.
func(m *IncidentManager)persist(in Incident,phase,actor,operator string,now time.Time)error{
 attempt,err:=audit.NewID()
 if err!=nil {m.failed=true;return ErrIncidentStorage}
 record:=audit.Event{
  Schema:"kgaga.vault.audit.v1",
  Timestamp:now.UTC().Format(time.RFC3339Nano),
  AttemptID:attempt,Action:"sentinel_incident",Phase:phase,Actor:actor,
  AgentID:in.Alert.AgentID,Owner:in.Alert.Owner,Audience:in.Alert.Audience,
  VaultID:in.Alert.VaultID,IncidentID:in.ID,IncidentSignal:in.Alert.Signal,
  IncidentState:in.State,IncidentRevision:in.Revision,
  IncidentResolution:in.Resolution,IncidentCount:in.Alert.Count,
  IncidentWindowSeconds:in.Alert.WindowSeconds,
  IncidentObservedAt:in.Alert.ObservedAt,OperatorID:operator,
 }
 if _,err:=m.sink.Append(record);err!=nil{m.failed=true;return ErrIncidentStorage}
 return nil
}

func(m *IncidentManager)Open(a Alert)(Incident,error){
 if m==nil{return Incident{},ErrIncident}
 now:=m.clock().UTC()
 m.mu.Lock();defer m.mu.Unlock()
 if m.failed{return Incident{},ErrIncidentStorage}
 if err:=incidentClock(now,m.last);err!=nil{return Incident{},err}
 if !validAlert(a,now){return Incident{},ErrIncident}
 key:=incidentSource(a)
 if id:=m.active[key];id!=""{
  existing,ok:=m.cases[id]
  if !ok{return Incident{},ErrIncidentStorage}
  return existing,nil
 }
 if len(m.cases)>=m.max{return Incident{},ErrCapacity}
 id,err:=audit.NewID()
 if err!=nil {m.failed=true;return Incident{},ErrIncidentStorage}
 stamp:=now.Format(time.RFC3339Nano)
 in:=Incident{Schema:IncidentSchema,ID:id,State:IncidentOpen,Revision:1,Alert:a,OpenedAt:stamp,UpdatedAt:stamp}
 if err:=m.persist(in,"opened","sentinel","",now);err!=nil{return Incident{},err}
 m.cases[id]=in
 m.active[key]=id
 m.last=now
 return in,nil
}

func(m *IncidentManager)transition(id,operator string,expected uint64,to,resolution string)(Incident,error){
 if m==nil{return Incident{},ErrIncident}
 now:=m.clock().UTC()
 m.mu.Lock();defer m.mu.Unlock()
 if m.failed{return Incident{},ErrIncidentStorage}
 if err:=incidentClock(now,m.last);err!=nil{return Incident{},err}
 if !metadataOK(operator)||len(operator)>128{return Incident{},ErrIncident}
 current,ok:=m.cases[id]
 if !ok{return Incident{},ErrIncidentNotFound}
 if current.Revision!=expected{return Incident{},ErrIncidentConflict}
 next:=current
 switch to{
 case IncidentAcknowledged:
  if current.State!=IncidentOpen{return Incident{},ErrIncidentConflict}
  next.AcknowledgedBy=operator
 case IncidentResolved:
  if current.State!=IncidentAcknowledged ||
  (resolution!=ResolutionBenign&&resolution!=ResolutionConfirmed&&resolution!=ResolutionInconclusive){
   return Incident{},ErrIncidentConflict
  }
  next.ResolvedBy=operator
  next.Resolution=resolution
 default:return Incident{},ErrIncident
 }
 next.State=to
 next.Revision++
 next.UpdatedAt=now.Format(time.RFC3339Nano)
 if err:=m.persist(next,to,"local_operator",operator,now);err!=nil{return Incident{},err}
 m.cases[id]=next
 if to==IncidentResolved{delete(m.active,incidentSource(next.Alert))}
 m.last=now
 return next,nil
}

func(m *IncidentManager)Acknowledge(id,operator string,expectedRevision uint64)(Incident,error){
 return m.transition(id,operator,expectedRevision,IncidentAcknowledged,"")
}
func(m *IncidentManager)Resolve(id,operator string,expectedRevision uint64,resolution string)(Incident,error){
 return m.transition(id,operator,expectedRevision,IncidentResolved,resolution)
}
func(m *IncidentManager)Get(id string)(Incident,error){
 if m==nil{return Incident{},ErrIncident}
 m.mu.Lock();defer m.mu.Unlock()
 if m.failed{return Incident{},ErrIncidentStorage}
 in,ok:=m.cases[id]
 if !ok{return Incident{},ErrIncidentNotFound}
 return in,nil
}
