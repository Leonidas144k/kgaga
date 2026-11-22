package sentinel

import (
 "time"

 "github.com/Leonidas144k/kgaga/internal/audit"
 "github.com/Leonidas144k/kgaga/internal/ledger"
)

type recoveredIncidentStage struct {
 state string
 revision uint64
}

func safeDeliveryMetadata(e audit.Event)bool{
 return e.Schema=="kgaga.vault.audit.v1" &&
  e.Action=="sentinel_delivery" && e.Actor=="sentinel" &&
  incidentHexID(e.AttemptID) && incidentHexID(e.IncidentID) &&
  incidentHexID(e.DeliveryID) &&
  metadataOK(e.VaultID) && metadataOK(e.AgentID) &&
  metadataOK(e.Owner) && metadataOK(e.Audience) &&
  e.DeliveryChannel==DeliveryChannel &&
  e.DeliveryPhase==e.Phase &&
  (e.Phase=="queued"||e.Phase=="attempted"||
   e.Phase=="accepted"||e.Phase=="failed") &&
  e.IncidentSignal!="" &&
  (e.IncidentState==IncidentOpen || e.IncidentState==IncidentAcknowledged) &&
  e.IncidentRevision>=1 && e.IncidentRevision<=2 &&
  e.DeliveryAttempt>=0 && e.DeliveryAttempt<=5 &&
  e.Name=="" && e.Version==0 && e.Origin=="" &&
  e.Method=="" && e.Target=="" && e.PassportID=="" &&
  e.MCPMethod=="" && e.Tool=="" && e.Provider=="" &&
  e.ProviderVersion==0 && e.Status==0 &&
  e.OperatorID=="" && e.IncidentResolution=="" &&
  e.IncidentCount==0 && e.IncidentWindowSeconds==0 &&
  e.IncidentObservedAt==""
}

// RestoreDispatcher reconstructs the incident manager AND the delivery
// dispatcher from one checkpoint-verified Ledger. The caller must provide
// the same independently trusted Head to OpenAnchoredJournal beforehand.
// No transport call or new audit record is made during restoration.
//
// An "attempted" event without a verified terminal outcome is retained as
// DeliveryUncertain and can NEVER be automatically resent. Only an
// independent operator/provider reconciliation can determine what happened;
// there is deliberately no unsafe override/retry API in this preview.
func RestoreDispatcher(j *ledger.AnchoredJournal,maxIncidents int,transport Transport,cfg DeliveryConfig,clock func()time.Time)(*IncidentManager,*Dispatcher,error){
 if j==nil || transport==nil || !validDeliveryConfig(cfg) ||
 maxIncidents<1 || maxIncidents>4096{return nil,nil,ErrDeliveryConfig}
 if clock==nil{clock=time.Now}
 before,err:=j.Head()
 if err!=nil{return nil,nil,ErrDeliveryStorage}
 manager,err:=RestoreIncidentManager(j,maxIncidents,clock)
 if err!=nil{return nil,nil,ErrDeliveryStorage}
 events,verified,err:=j.SentinelHistory(16384)
 if err!=nil || verified!=before{return nil,nil,ErrDeliveryStorage}
 d:=&Dispatcher{
  incidents:manager,sink:j,transport:transport,cfg:cfg,clock:clock,
  deliveries:make(map[string]*Delivery),
 }
 fail:=func()(*IncidentManager,*Dispatcher,error){return nil,nil,ErrDeliveryStorage}
 seen:=make(map[string]struct{},len(events))
 active:=make(map[string]recoveredIncidentStage)
 var last time.Time
 for _,ev:=range events{
  at,err:=replayTime(ev.Timestamp)
  if err!=nil || (!last.IsZero() && at.Before(last)) {return fail()}
  last=at
  if !incidentHexID(ev.AttemptID){return fail()}
  if _,ok:=seen[ev.AttemptID];ok{return fail()}
  seen[ev.AttemptID]=struct{}{}
  switch ev.Action{
  case "sentinel_incident":
   // RestoreIncidentManager validates full incident transitions. Track
   // their historical stage so notifications cannot predate a case or
   // be sent after its resolution.
   active[ev.IncidentID]=recoveredIncidentStage{
    state:ev.IncidentState,revision:ev.IncidentRevision,
   }
  case "sentinel_delivery":
   if !safeDeliveryMetadata(ev){return fail()}
   stage,ok:=active[ev.IncidentID]
   in,exists:=manager.cases[ev.IncidentID]
   if !ok || !exists || stage.state==IncidentResolved ||
    stage.state!=ev.IncidentState ||
    ev.VaultID!=in.Alert.VaultID ||
    ev.AgentID!=in.Alert.AgentID ||
    ev.Owner!=in.Alert.Owner ||
    ev.Audience!=in.Alert.Audience ||
    ev.IncidentSignal!=in.Alert.Signal{return fail()}
   item:=d.deliveries[ev.IncidentID]
   switch ev.Phase{
   case "queued":
    if item!=nil || len(d.deliveries)>=cfg.MaxPending ||
     ev.DeliveryAttempt!=0 || ev.IncidentRevision!=stage.revision{return fail()}
    d.deliveries[ev.IncidentID]=&Delivery{
     ID:ev.DeliveryID,IncidentID:ev.IncidentID,
     IncidentRevision:ev.IncidentRevision,Status:DeliveryQueued,
    }
   case "attempted":
    if item==nil || item.ID!=ev.DeliveryID ||
     item.IncidentRevision!=ev.IncidentRevision ||
     (item.Status!=DeliveryQueued && item.Status!=DeliveryFailed) ||
     item.Attempts>=cfg.MaxAttempts ||
     ev.DeliveryAttempt!=item.Attempts+1{return fail()}
    if item.Status==DeliveryFailed {
     retry,err:=replayTime(item.NextRetryAt)
     if err!=nil || at.Before(retry){return fail()}
    }
    item.Attempts=ev.DeliveryAttempt
    item.LastAttemptAt=ev.Timestamp
    item.NextRetryAt=""
    item.Status=DeliveryUncertain
   case "accepted","failed":
    if item==nil || item.ID!=ev.DeliveryID ||
     item.IncidentRevision!=ev.IncidentRevision ||
     item.Status!=DeliveryUncertain ||
     ev.DeliveryAttempt!=item.Attempts{return fail()}
    if ev.Phase=="accepted"{
     item.Status=DeliveryAccepted
     item.NextRetryAt=""
    }else{
     item.Status=DeliveryFailed
     item.NextRetryAt=at.Add(cfg.RetryInterval).Format(time.RFC3339Nano)
    }
   default:return fail()
   }
  default:return fail()
  }
 }
 after,err:=j.Head()
 if err!=nil || after!=before{return fail()}
 d.last=last
 return manager,d,nil
}
