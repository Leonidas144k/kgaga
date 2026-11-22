package demo

import (
 "bytes"
 "encoding/json"
 "errors"
 "testing"
)

func TestSyntheticSentinelLifecycle(t *testing.T){
 for i:=0;i<3;i++{
  var buf bytes.Buffer
  if err:=RunSentinel(&buf);err!=nil{t.Fatal(err)}
  var got Summary
  if err:=json.Unmarshal(buf.Bytes(),&got);err!=nil{t.Fatal(err)}
  if got.Mode!="synthetic" || got.AdvisorySignals!=1 ||
   got.IncidentTransitions!=3 || got.VerifiedLedgerRecords!=8 ||
   got.RecoveredState!="resolved" || got.NotificationsSent!=0 ||
   got.ProductionConfigured {t.Fatal("unsafe or incomplete summary")}
 }
}
func TestNilOutputRejected(t *testing.T){
 if err:=RunSentinel(nil);!errors.Is(err,ErrDemo){t.Fatal("nil output accepted")}
}
