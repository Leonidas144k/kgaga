// Package sentinel provides bounded advisory analysis of trusted Vault audit
// events. It cannot suspend agents, revoke credentials or enforce policy.
package sentinel

import(
 "encoding/hex"
 "errors"
 "sync"
 "time"
 "github.com/Leonidas144k/kgaga/internal/audit"
)

var (
 ErrConfig=errors.New("sentinel configuration invalid")
 ErrEvent=errors.New("sentinel event invalid or untrusted")
 ErrCapacity=errors.New("sentinel memory capacity exhausted")
 ErrClock=errors.New("sentinel clock moved backwards")
)
const AlertSchema="kgaga.sentinel.alert.v1"
const (
 DenialBurst="credential_denial_burst"
 ExchangeFailureBurst="exchange_failure_burst"
 ResponseWithheldBurst="response_withheld_burst"
)

type Config struct{
 Window time.Duration
 DenialThreshold int
 ExchangeFailureThreshold int
 WithheldThreshold int
 MaxIdentities int
 MaxFailuresPerIdentity int
}
func DefaultConfig()Config{return Config{
 Window:5*time.Minute,DenialThreshold:5,ExchangeFailureThreshold:5,
 WithheldThreshold:3,MaxIdentities:512,MaxFailuresPerIdentity:128,
}}
type Alert struct{
 Schema string `json:"schema"`
 ObservedAt string `json:"observed_at"`
 Signal string `json:"signal"`
 Severity string `json:"severity"`
 VaultID string `json:"vault_id"`
 AgentID string `json:"agent_id"`
 Owner string `json:"owner"`
 Audience string `json:"audience"`
 Count int `json:"count"`
 WindowSeconds int64 `json:"window_seconds"`
 Advisory bool `json:"advisory"`
}
type identity struct{vault,agent,owner,audience string}
type failure struct{at time.Time; attempt,signal string}
type state struct{failures []failure; active map[string]bool}

// Engine uses process-local in-memory windows. It assumes incoming events
// were verified by their trusted source; this function does not check MACs.
// No persistence, global coordination or automatic response is provided.
type Engine struct{
 mu sync.Mutex
 cfg Config
 clock func()time.Time
 last time.Time
 states map[identity]*state
}
func NewEngine(cfg Config,clock func()time.Time)(*Engine,error){
 if cfg.Window<time.Second || cfg.Window>24*time.Hour || cfg.Window%time.Second!=0 ||
 cfg.MaxIdentities<1 || cfg.MaxIdentities>4096 ||
 cfg.MaxFailuresPerIdentity<1 || cfg.MaxFailuresPerIdentity>512 ||
 cfg.DenialThreshold<1 || cfg.DenialThreshold>cfg.MaxFailuresPerIdentity ||
 cfg.ExchangeFailureThreshold<1 || cfg.ExchangeFailureThreshold>cfg.MaxFailuresPerIdentity ||
 cfg.WithheldThreshold<1 || cfg.WithheldThreshold>cfg.MaxFailuresPerIdentity{return nil,ErrConfig}
 if clock==nil{clock=time.Now}
 return &Engine{cfg:cfg,clock:clock,states:make(map[identity]*state)},nil
}
func metadataOK(s string)bool{
 if len(s)==0 || len(s)>128{return false}
 for i:=0;i<len(s);i++{if s[i]<33 || s[i]>126{return false}}
 return true
}
func eventSignal(phase string)(string,bool){
 switch phase {
 case "denied","denied_before_dispatch":return DenialBurst,true
 case "credential_unavailable","exchange_failed_or_rejected":return ExchangeFailureBurst,true
 case "response_withheld":return ResponseWithheldBurst,true
 case "attempt","dispatch_intent","response_release_intent":return "",true
 default:return "",false
 }
}
func validateEvent(ev audit.Event,now time.Time)(string,error){
 if ev.Schema!="kgaga.vault.audit.v1" || !metadataOK(ev.VaultID) ||
 len(ev.AttemptID)!=32{return "",ErrEvent}
 id,err:=hex.DecodeString(ev.AttemptID)
 if err!=nil || len(id)!=16 || hex.EncodeToString(id)!=ev.AttemptID{return "",ErrEvent}
 ts,err:=time.Parse(time.RFC3339Nano,ev.Timestamp)
 if err!=nil || ts.UTC().Format(time.RFC3339Nano)!=ev.Timestamp ||
 ts.Before(now.Add(-time.Minute)) || ts.After(now.Add(time.Minute)){return "",ErrEvent}
 if ev.Actor=="local_operator"{return "",nil}
 if ev.Actor!="agent" || ev.Action!="credential_use" ||
 !metadataOK(ev.AgentID) || !metadataOK(ev.Owner) || !metadataOK(ev.Audience){return "",ErrEvent}
 signal,ok:=eventSignal(ev.Phase)
 if !ok{return "",ErrEvent}
 return signal,nil
}
func threshold(cfg Config,signal string)int{
 switch signal {
 case DenialBurst:return cfg.DenialThreshold
 case ExchangeFailureBurst:return cfg.ExchangeFailureThreshold
 case ResponseWithheldBurst:return cfg.WithheldThreshold
 default:return 0
 }
}
func prune(st *state,now time.Time,window time.Duration,cfg Config){
 index:=0
 for index<len(st.failures) && !now.Before(st.failures[index].at.Add(window)){index++}
 if index>0{
  copy(st.failures,st.failures[index:])
  n:=len(st.failures)-index
  for i:=n;i<len(st.failures);i++{st.failures[i]=failure{}}
  st.failures=st.failures[:n]
 }
 counts:=map[string]int{}
 for _,r:=range st.failures{counts[r.signal]++}
 for _,s:=range []string{DenialBurst,ExchangeFailureBurst,ResponseWithheldBurst}{
  if counts[s]<threshold(cfg,s){delete(st.active,s)}
 }
}
func countSignal(st *state,signal string)int{
 n:=0
 for _,r:=range st.failures{if r.signal==signal{n++}}
 return n
}

// Observe counts one terminal failure per random attempt_id, irrespective
// of multiple failure phases. Alerts fire once per threshold crossing,
// and re-arm after the window decays below threshold. Clocks going
// backwards or memory quotas being exceeded return explicit errors.
func(e *Engine)Observe(ev audit.Event)(*Alert,error){
 if e==nil || e.clock==nil{return nil,ErrConfig}
 now:=e.clock().UTC()
 if now.IsZero(){return nil,ErrClock}
 signal,err:=validateEvent(ev,now)
 if err!=nil{return nil,err}
 e.mu.Lock();defer e.mu.Unlock()
 if !e.last.IsZero() && now.Before(e.last){return nil,ErrClock}
 e.last=now
 if signal==""{return nil,nil}
 key:=identity{ev.VaultID,ev.AgentID,ev.Owner,ev.Audience}
 st:=e.states[key]
 if st==nil {
  if len(e.states)>=e.cfg.MaxIdentities {
   for k,v:=range e.states {
    prune(v,now,e.cfg.Window,e.cfg)
    if len(v.failures)==0{delete(e.states,k)}
   }
  }
  if len(e.states)>=e.cfg.MaxIdentities{return nil,ErrCapacity}
  st=&state{active:make(map[string]bool)}
  e.states[key]=st
 }
 prune(st,now,e.cfg.Window,e.cfg)
 for _,r:=range st.failures{if r.attempt==ev.AttemptID{return nil,nil}}
 if len(st.failures)>=e.cfg.MaxFailuresPerIdentity{return nil,ErrCapacity}
 st.failures=append(st.failures,failure{now,ev.AttemptID,signal})
 count:=countSignal(st,signal)
 required:=threshold(e.cfg,signal)
 if count<required || st.active[signal]{return nil,nil}
 st.active[signal]=true
 severity:="warning"
 if signal==ResponseWithheldBurst{severity="notice"}
 return &Alert{
  Schema:AlertSchema,ObservedAt:now.Format(time.RFC3339Nano),
  Signal:signal,Severity:severity,VaultID:key.vault,AgentID:key.agent,
  Owner:key.owner,Audience:key.audience,Count:count,
  WindowSeconds:int64(e.cfg.Window/time.Second),Advisory:true,
 },nil
}
